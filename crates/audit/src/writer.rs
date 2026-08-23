//! The append-only writer (ARCH-SPEC §2.8: write-only from inside the
//! gateway; reading and export are operator functions).
//!
//! Encoding per DESIGN-DECISIONS D7 — JSONL, one record per line:
//!
//! ```text
//! body      = canonical JCS bytes of the record minus {this_hash, sig}
//! this_hash = hex(SHA-256(prev_hash_raw || body))
//! sig       = base64url(Ed25519 sign(this_hash_raw))
//! ```
//!
//! The genesis record anchors the chain (`prev_hash` = 32 zero bytes). Every
//! record including genesis is signed, so key substitution is caught at line
//! one. Appends flush and `sync_data` before returning: a crash cannot leave
//! a half-written last record that later looks valid.
//!
//! A writer refuses to open a journal whose existing contents fail chain
//! verification — extending a broken chain would be laundering the break.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use chaperone_protocol::canonical_form_excluding;

use crate::event::AuditEvent;
use crate::keys::AuditKey;

/// Chain format version (bumped only by a deliberate migration).
pub const CHAIN_VERSION: u64 = 1;

/// Fields excluded from the hashed/signature-covered body.
const UNHASHED_FIELDS: &[&str] = &["this_hash", "sig"];

/// Failures of the audit subsystem.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuditError {
    /// Journal could not be read or written.
    Io(std::io::Error),
    /// Existing journal failed verification; refusing to extend it.
    BrokenChain(crate::verify::Break),
    /// Serialization failed (cannot happen for Value-shaped records, kept
    /// for totality).
    Serialize(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(e) => write!(f, "audit journal i/o: {e}"),
            AuditError::BrokenChain(b) => {
                write!(f, "audit journal failed verification; not extending: {b}")
            }
            AuditError::Serialize(e) => write!(f, "audit record serialization: {e}"),
        }
    }
}

impl std::error::Error for AuditError {}

/// Hex-encode bytes lowercase.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0xF), 16).unwrap_or('0'));
    }
    out
}

/// Decode lowercase hex into bytes.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

/// Position in the chain after the most recent append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// Sequence number of the newest record.
    pub seq: u64,
    /// Its hash, hex-encoded.
    pub hash_hex: String,
}

struct State {
    seq: u64,
    prev_hash: [u8; 32],
}

/// Append-only audit journal bound to one signing key.
pub struct AuditWriter {
    file: Mutex<File>,
    state: Mutex<State>,
    path: PathBuf,
    key: AuditKey,
}

impl AuditWriter {
    /// Opens (or creates) a journal at `path`.
    ///
    /// Existing content must verify under `key`, or this fails with
    /// [`AuditError::BrokenChain`]: never extend a chain you cannot vouch
    /// for. An empty or missing file starts fresh; the first append writes
    /// the signed genesis anchor.
    pub fn open(path: &Path, key: AuditKey) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(AuditError::Io)?;
        }

        let mut state = State {
            seq: 0,
            prev_hash: [0u8; 32],
        };
        let fresh;
        if path.exists() {
            let existing = std::fs::read_to_string(path).map_err(AuditError::Io)?;
            if existing.trim().is_empty() {
                fresh = true;
            } else {
                // Verify-and-resume: reuse the public verifier logic so the
                // writer's notion of "intact" is exactly the operator's.
                // A partial tail is NOT a resume point: any break means the
                // journal is quarantined until an operator rules on it.
                let report = crate::verify::walk_lines(&existing, &key.verifying_key());
                match report.error {
                    Some(brk) => return Err(AuditError::BrokenChain(brk)),
                    None => {
                        let tail = report.tail.ok_or_else(|| {
                            AuditError::BrokenChain(crate::verify::Break {
                                line: 0,
                                reason: "journal is neither empty nor verifiable".to_owned(),
                            })
                        })?;
                        let decoded = unhex(&tail.hash_hex).ok_or_else(|| {
                            AuditError::BrokenChain(crate::verify::Break {
                                line: usize::try_from(tail.seq).unwrap_or(usize::MAX) + 1,
                                reason: "tail hash is not hex".to_owned(),
                            })
                        })?;
                        let decoded: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
                            AuditError::BrokenChain(crate::verify::Break {
                                line: usize::try_from(tail.seq).unwrap_or(usize::MAX) + 1,
                                reason: "tail hash is not 32 bytes".to_owned(),
                            })
                        })?;
                        state.seq = tail.seq;
                        state.prev_hash = decoded;
                        fresh = false;
                    }
                }
            }
        } else {
            fresh = true;
        }

        let mut opts = OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let file = opts.open(path).map_err(AuditError::Io)?;

        let writer = Self {
            file: Mutex::new(file),
            state: Mutex::new(state),
            path: path.to_path_buf(),
            key,
        };
        if fresh {
            writer.append_genesis()?;
        }
        Ok(writer)
    }

    /// The journal path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current head: newest sequence number and its hash (for operators to
    /// monitor externally - see the tail-truncation note in D18).
    pub fn head(&self) -> Result<Head, AuditError> {
        let st = self.lock_state();
        Ok(Head {
            seq: st.seq,
            hash_hex: hex(&st.prev_hash),
        })
    }

    /// Appends one terminal outcome as the next chained, signed record.
    ///
    /// Returns the new head `(seq, hash-hex)` on success.
    pub fn append(&self, event: &AuditEvent<'_>) -> Result<Head, AuditError> {
        let now_rfc3339 = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| AuditError::Serialize(e.to_string()))?;

        let record = {
            let mut st = self.lock_state();
            let next_seq = st.seq.saturating_add(1);
            let body = json!({
                "chain_version": CHAIN_VERSION,
                "seq": next_seq,
                "kind": "intent_decision",
                "ts": now_rfc3339,
                "prev_hash": hex(&st.prev_hash),
                "agent_id": event.agent_id,
                "msg_id": event.msg_id,
                "mechanism": event.mechanism,
                "target_uri": event.target_uri,
                "target_label": event.target_label,
                "cred_ref": event.cred_ref,
                "effect": event.effect,
                "outcome": event.outcome.to_value(),
                "intent": event.intent_envelope,
            });
            let (this_hash, line) = seal_record(&body, &st.prev_hash, &self.key)?;
            st.seq = next_seq;
            st.prev_hash = this_hash;
            write_line(&self.file, &line)?;
            Head {
                seq: next_seq,
                hash_hex: hex(&this_hash),
            }
        };
        Ok(record)
    }

    fn append_genesis(&self) -> Result<(), AuditError> {
        let now_rfc3339 = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| AuditError::Serialize(e.to_string()))?;
        let zeros = [0u8; 32];
        let body = json!({
            "chain_version": CHAIN_VERSION,
            "seq": 0,
            "kind": "genesis",
            "ts": now_rfc3339,
            "prev_hash": hex(&zeros),
        });
        let (hash, line) = seal_record(&body, &zeros, &self.key)?;
        {
            let mut st = self.lock_state();
            st.seq = 0;
            st.prev_hash = hash;
            write_line(&self.file, &line)?;
        }
        Ok(())
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Canonical body -> raw hash -> signature -> final JSON line.
fn seal_record(
    body: &Value,
    prev_hash: &[u8; 32],
    key: &AuditKey,
) -> Result<([u8; 32], String), AuditError> {
    let this_hash = compute_hash(body, prev_hash);
    let signature = key.sign_raw(&this_hash);

    let mut full = body.clone();
    if let Some(obj) = full.as_object_mut() {
        obj.insert("this_hash".to_owned(), json!(hex(&this_hash)));
        obj.insert("sig".to_owned(), json!(signature));
    }
    let canonical_line =
        canonical_form_excluding(&full, &[]).map_err(|e| AuditError::Serialize(e.to_string()))?;
    Ok((
        this_hash,
        String::from_utf8(canonical_line).map_err(|e| AuditError::Serialize(e.to_string()))?,
    ))
}

/// `SHA-256(prev_hash_raw || canonical_body_bytes)`
#[must_use]
pub fn compute_hash(body: &Value, prev_hash: &[u8; 32]) -> [u8; 32] {
    let canonical = canonical_form_excluding(body, UNHASHED_FIELDS).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(&canonical);
    hasher.finalize().into()
}

fn write_line(file: &Mutex<File>, line: &str) -> Result<(), AuditError> {
    let mut f = file
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f.write_all(line.as_bytes()).map_err(AuditError::Io)?;
    f.write_all(b"\n").map_err(AuditError::Io)?;
    f.flush().map_err(AuditError::Io)?;
    f.sync_data().map_err(AuditError::Io)
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}
