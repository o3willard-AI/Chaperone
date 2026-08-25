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

/// Outcome of a reservation attempt (PROTO-SPEC §4 step 2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    /// Nonce unseen: reserved locally and journaled.
    Fresh,
    /// Nonce already reserved within retention: REPLAY.
    Duplicate,
    /// The persisted journal exceeded its size cap and compaction could not
    /// reclaim enough space. The reservation was NOT made; the caller must
    /// refuse the intent. Self-heals as entries age out (D34).
    CapacityFull,
}

impl Reservation {
    /// True only for [`Reservation::Fresh`].
    #[must_use]
    pub fn is_fresh(self) -> bool {
        matches!(self, Reservation::Fresh)
    }
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
    max_journal_bytes: u64,
}

/// Default hard cap on the persisted journal (DESIGN-DECISIONS D34):
/// bounds disk growth from unverified input. When exceeded, new intents
/// are refused until entries age out and compaction reclaims space.
pub const DEFAULT_MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

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
            max_journal_bytes: DEFAULT_MAX_JOURNAL_BYTES,
        }
    }

    /// Overrides the journal size cap (testing, constrained disks).
    #[must_use]
    pub fn with_journal_cap(mut self, bytes: u64) -> Self {
        self.max_journal_bytes = bytes;
        self
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
            max_journal_bytes: DEFAULT_MAX_JOURNAL_BYTES,
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

    /// Reserves `(agent, nonce)` if unseen within retention.
    ///
    /// Capacity policy (DESIGN-DECISIONS D34): if the persisted journal is
    /// over its byte cap, compaction runs once; if it is STILL over (a flood
    /// of not-yet-expired reservations), the reservation is rolled back and
    /// [`Reservation::CapacityFull`] returned — fail closed, bounded disk,
    /// self-healing as entries age out.
    pub fn check_and_reserve(
        &self,
        agent: &str,
        nonce: &str,
        now_unix: i64,
        retention_secs: i64,
    ) -> Reservation {
        debug_assert!(retention_secs > 0);
        let expires = now_unix.saturating_add(retention_secs);

        let mut inner = self.lock_mut();
        inner.purge_expired(now_unix);

        let agent_owned = agent.to_owned();
        let nonce_owned = nonce.to_owned();
        if inner
            .seen
            .contains_key(&(agent_owned.clone(), nonce_owned.clone()))
        {
            return Reservation::Duplicate;
        }
        inner
            .seen
            .insert((agent_owned.clone(), nonce_owned.clone()), expires);
        inner
            .insertion_order
            .push_back((agent_owned, nonce_owned, expires));
        inner.journal_lines_written += 1;

        let journaled = if let Some(path) = self.path.as_deref() {
            // Compact when the journal is mostly dead weight, or when it has
            // blown through the size cap.
            let len = journal_len(path);
            let live = u64::try_from(inner.seen.len()).unwrap_or(u64::MAX);
            let due = inner.journal_lines_written >= 1024 && live * 2 < inner.journal_lines_written;
            if len > self.max_journal_bytes || due {
                self.rewrite_journal(&mut inner);
                true
            } else {
                false
            }
        } else {
            false
        };

        if let Some(path) = self.path.as_deref() {
            let len = journal_len(path);
            if len > self.max_journal_bytes {
                // Still over after compaction: roll back this reservation
                // entirely and refuse. Nothing was appended for it.
                inner.seen.remove(&(agent.to_owned(), nonce.to_owned()));
                inner.insertion_order.pop_back();
                return Reservation::CapacityFull;
            }
            if !journaled {
                self.append_line(agent, nonce, expires);
            }
        }
        Reservation::Fresh
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

fn journal_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn count_lines(path: &Path) -> Result<u64, ReplayCacheError> {
    match std::fs::File::open(path) {
        Ok(file) => Ok(std::io::BufReader::new(file).lines().count() as u64),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(ReplayCacheError::Io(e)),
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn journal_cap_refuses_when_full_and_self_heals_after_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.jsonl");
        let now: i64 = 1_000_000;
        // Tiny cap so ~a handful of entries blow through it.
        let cache = ReplayCache::open(&path, now)
            .unwrap()
            .with_journal_cap(1024);

        let mut reserved = 0;
        let mut hit_cap = false;
        for i in 0..500 {
            let nonce = format!("flood-{i}");
            match cache.check_and_reserve("agent:a", &nonce, now, 300) {
                Reservation::Fresh => reserved += 1,
                Reservation::CapacityFull => {
                    hit_cap = true;
                    break;
                }
                Reservation::Duplicate => unreachable!("unique nonces"),
            }
        }
        assert!(
            hit_cap,
            "flood must eventually hit the cap (reserved={reserved})"
        );

        // Refusals must not have journaled the refused entry: file stays
        // bounded.
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len <= 2048, "journal grew past cap: {len}");

        // After entries age out, compaction reclaims and reservations resume.
        let later = now + 301;
        match cache.check_and_reserve("agent:a", "post-expiry", later, 300) {
            Reservation::Fresh => {}
            other => panic!("expected Fresh after expiry, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_still_detected_alongside_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.jsonl");
        let now: i64 = 2_000_000;
        let cache = ReplayCache::open(&path, now)
            .unwrap()
            .with_journal_cap(1024);

        assert!(
            cache
                .check_and_reserve("agent:b", "keep-me", now, 600)
                .is_fresh()
        );
        assert_eq!(
            cache.check_and_reserve("agent:b", "keep-me", now + 1, 600),
            Reservation::Duplicate,
            "duplicate detection survives capacity pressure"
        );
    }
}
