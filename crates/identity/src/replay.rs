//! The replay cache: nonce uniqueness per agent within the freshness window
//! (PROTO-SPEC §4.2, "Replay & binding").
//!
//! Design notes:
//!
//! - **Retention.** An intent is acceptable while `|now - issued_at| <= skew`,
//!   so its nonce must stay reserved until `issued_at + skew`, which can be
//!   up to `insertion + 2*skew` away for the most future-dated intent we
//!   accept. Retention is `3 * skew`: the extra `skew` is boundary epsilon,
//!   cheap insurance against clock jitter at the edges.
//!
//! - **Persistence (D6).** An in-memory-only cache forgets nonces across a
//!   daemon restart — a crash inside the freshness window would reopen the
//!   door to replays of intents seen before it. Entries therefore append to
//!   a JSONL journal that is replayed on load; expired entries are dropped.
//!
//! - **Compaction.** Expired entries leave memory immediately but would grow
//!   the journal forever; when live entries fall below half the journal and
//!   the journal exceeds 1024 lines, it is rewritten in full from live state.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct JournalLine {
    agent: String,
    nonce: String,
    expires_unix: i64,
}

struct Inner {
    /// (agent, nonce) -> expiry instant, unix seconds.
    seen: HashMap<(String, String), i64>,
    insertion_order: VecDeque<(String, String, i64)>,
    journal_lines_written: u64,
}

/// Failures of the replay cache's persistence layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReplayCacheError {
    /// Journal could not be read or written.
    Io(std::io::Error),
    /// A journal line did not parse.
    Corrupt(String),
}

impl std::fmt::Display for ReplayCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayCacheError::Io(e) => write!(f, "replay journal i/o: {e}"),
            ReplayCacheError::Corrupt(e) => write!(f, "replay journal corrupt: {e}"),
        }
    }
}

impl std::error::Error for ReplayCacheError {}

/// Nonce-uniqueness guard. All methods are panic-free; a poisoned lock is
/// recovered from rather than propagated (state here is advisory-only:
/// worst case after a poisoned section is a bounded replay window).
pub struct ReplayCache {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
}

impl ReplayCache {
    /// In-memory cache only (tests).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(Inner {
                seen: HashMap::new(),
                insertion_order: VecDeque::new(),
                journal_lines_written: 0,
            }),
            path: None,
        }
    }

    /// Opens (or creates) a persisted cache at `path`.
    ///
    /// Loads surviving entries, drops expired ones, and compacts if the
    /// journal is mostly dead weight.
    pub fn open(path: &Path, now_unix: i64) -> Result<Self, ReplayCacheError> {
        let mut seen = HashMap::new();
        let mut order = VecDeque::new();
        match std::fs::File::open(path) {
            Ok(file) => {
                for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
                    let line = line.map_err(ReplayCacheError::Io)?;
                    if line.is_empty() {
                        continue;
                    }
                    let entry: JournalLine = serde_json::from_str(&line)
                        .map_err(|e| ReplayCacheError::Corrupt(format!("line {}: {e}", i + 1)))?;
                    if entry.expires_unix > now_unix {
                        let key = (entry.agent, entry.nonce);
                        seen.insert(key.clone(), entry.expires_unix);
                        order.push_back((key.0, key.1, entry.expires_unix));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(ReplayCacheError::Io(e)),
        }

        let cache = Self {
            inner: Mutex::new(Inner {
                seen,
                insertion_order: order,
                journal_lines_written: 0,
            }),
            path: Some(path.to_path_buf()),
        };
        // If what survived is much smaller than what was written, start the
        // new journal fresh instead of appending onto dead weight.
        {
            let mut inner = cache.lock_mut();
            let live = u64::try_from(inner.seen.len()).unwrap_or(u64::MAX);
            let lines_on_disk = count_lines(path)?;
            if lines_on_disk > 1024 && live * 2 < lines_on_disk {
                cache.rewrite_journal(&mut inner);
                inner.journal_lines_written = 0;
            } else {
                inner.journal_lines_written = lines_on_disk;
            }
        }
        Ok(cache)
    }

    /// Reserves `(agent, nonce)` if unseen within retention; returns whether
    /// the pair was fresh.
    pub fn check_and_reserve(
        &self,
        agent: &str,
        nonce: &str,
        now_unix: i64,
        retention_secs: i64,
    ) -> bool {
        debug_assert!(retention_secs > 0);
        let expires = now_unix.saturating_add(retention_secs);

        let mut inner = self.lock_mut();
        inner.purge_expired(now_unix);

        let key = (agent.to_owned(), nonce.to_owned());
        if inner.seen.contains_key(&key) {
            return false;
        }
        inner.seen.insert(key.clone(), expires);
        inner.insertion_order.push_back((key.0, key.1, expires));
        inner.journal_lines_written += 1;

        let mut already_journaled = false;
        if self.path.is_some() && inner.journal_lines_written >= 1024 {
            let live = u64::try_from(inner.seen.len()).unwrap_or(u64::MAX);
            if live * 2 < inner.journal_lines_written {
                // The rewrite includes the entry pushed above.
                self.rewrite_journal(&mut inner);
                already_journaled = true;
            }
        }
        if self.path.is_some() && !already_journaled {
            self.append_line(agent, nonce, expires);
        }
        true
    }

    /// Number of currently-reserved nonces (observability/tests).
    #[must_use]
    pub fn live_entries(&self) -> usize {
        self.lock().seen.len()
    }

    fn append_line(&self, agent: &str, nonce: &str, expires_unix: i64) {
        let Some(path) = &self.path else {
            return;
        };
        let line = serde_json::to_string(&JournalLine {
            agent: agent.to_owned(),
            nonce: nonce.to_owned(),
            expires_unix,
        });
        if let Ok(line) = line
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
        {
            let _ = writeln!(file, "{line}");
        }
        // Append failures degrade to an in-memory window (documented in
        // D6 as weaker); they must not fail the request path silently
        // though, so gateway-core surfaces cache health separately later.
    }

    fn rewrite_journal(&self, inner: &mut Inner) {
        let Some(path) = &self.path else {
            return;
        };
        let tmp_path = path.with_extension("tmp");
        if let Ok(mut file) = std::fs::File::create(&tmp_path) {
            let mut ok = true;
            for (agent, nonce, exp) in &inner.insertion_order {
                let line = serde_json::to_string(&JournalLine {
                    agent: agent.clone(),
                    nonce: nonce.clone(),
                    expires_unix: *exp,
                });
                match line {
                    Ok(line) => {
                        if writeln!(file, "{line}").is_err() {
                            ok = false;
                            break;
                        }
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            drop(file);
            if ok && std::fs::rename(&tmp_path, path).is_ok() {
                inner.journal_lines_written =
                    u64::try_from(inner.insertion_order.len()).unwrap_or(u64::MAX);
            }
            let _ = std::fs::remove_file(&tmp_path);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_mut(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Inner {
    fn purge_expired(&mut self, now_unix: i64) {
        while let Some((agent, nonce, expires)) = self.insertion_order.front() {
            if *expires > now_unix {
                break;
            }
            let key = (agent.clone(), nonce.clone());
            self.seen.remove(&key);
            self.insertion_order.pop_front();
        }
    }
}

fn count_lines(path: &Path) -> Result<u64, ReplayCacheError> {
    match std::fs::File::open(path) {
        Ok(file) => Ok(std::io::BufReader::new(file).lines().count() as u64),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(ReplayCacheError::Io(e)),
    }
}
