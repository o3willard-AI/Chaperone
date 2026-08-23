//! Chain verification: the operator's tamper-evidence check (ARCH-SPEC §2.8,
//! "reading and export are operator functions").
//!
//! Walks the journal line by line, recomputing for every record:
//!
//! 1. `this_hash = SHA-256(prev_hash_raw || canonical_body)` where the body
//!    excludes exactly `{this_hash, sig}`;
//! 2. `prev_hash` equals the previous record's `this_hash` (zeros at genesis);
//! 3. sequence numbers are contiguous from 0;
//! 4. the Ed25519 signature over the raw hash verifies under the gateway's
//!    audit public key.
//!
//! The first violation is reported with its line number and reason.
//!
//! HONEST LIMIT (D18): deleting the LAST record(s) leaves a perfectly valid
//! shorter chain — pure tail truncation is undetectable from inside the file.
//! That is inherent to hash chains, not an implementation gap; operators
//! close it by monitoring [`crate::AuditWriter::head`] / `audit-verify`
//! output against an externally-known head hash.

use ed25519_dalek::VerifyingKey;
use serde_json::Value;

use chaperone_protocol::canonical_form_excluding;

/// Where and why verification stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Break {
    /// Zero-based line number in the journal.
    pub line: usize,
    /// Human-legible reason.
    pub reason: String,
}

impl std::fmt::Display for Break {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line + 1, self.reason)
    }
}

/// A healthy tail: last valid sequence number and its hex hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tail {
    /// Sequence of the newest valid record.
    pub seq: u64,
    /// Its `this_hash`, hex-encoded.
    pub hash_hex: String,
}

/// Result of walking a whole journal.
#[derive(Debug)]
pub struct Report {
    /// Valid tail when the entire chain verified; else the last good state.
    pub tail: Option<Tail>,
    /// First break encountered, if any.
    pub error: Option<Break>,
    /// Number of records that validated before any error.
    pub records_ok: usize,
}

const UNHASHED_FIELDS: &[&str] = &["this_hash", "sig"];
const GENESIS_PREV_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn field_str<'a>(obj: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a str> {
    obj.get(name).and_then(Value::as_str)
}

fn field_u64(obj: &serde_json::Map<String, Value>, name: &str) -> Option<u64> {
    obj.get(name).and_then(Value::as_u64)
}

/// Verifies one record line given the expected previous hash and sequence.
///
/// Returns the record's own `(seq, this_hash-hex)` on success.
fn verify_line(
    line: &str,
    expect_prev_hex: &str,
    expect_seq: u64,
    vk: &VerifyingKey,
) -> Result<(u64, String), String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("not JSON: {e}"))?;
    let obj = value.as_object().ok_or("record is not a JSON object")?;

    if field_u64(obj, "chain_version") != Some(crate::writer::CHAIN_VERSION) {
        return Err(format!(
            "chain_version mismatch: {:?}",
            obj.get("chain_version")
        ));
    }
    let seq = field_u64(obj, "seq").ok_or("missing seq")?;
    if seq != expect_seq {
        return Err(format!("expected seq {expect_seq}, found {seq}"));
    }

    let this_hash_hex = field_str(obj, "this_hash")
        .ok_or("missing this_hash")?
        .to_owned();
    let prev_hash = field_str(obj, "prev_hash")
        .ok_or("missing prev_hash")?
        .to_owned();
    if prev_hash != expect_prev_hex {
        return Err(format!(
            "prev_hash {prev_hash} does not match predecessor {expect_prev_hex}"
        ));
    }

    // Recompute the hash over the canonical body.
    let canonical = canonical_form_excluding(&value, UNHASHED_FIELDS)
        .map_err(|e| format!("body canonicalization failed: {e}"))?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(crate::writer::unhex(expect_prev_hex).ok_or("predecessor hash is not hex")?);
    hasher.update(&canonical);
    let recomputed: [u8; 32] = hasher.finalize().into();
    let stored = crate::writer::unhex(&this_hash_hex).ok_or("this_hash is not hex")?;
    if stored.as_slice() != recomputed.as_slice() {
        return Err("this_hash does not match recomputed content hash".to_owned());
    }

    // Signature over the raw hash.
    let sig = field_str(obj, "sig").ok_or("missing sig")?;
    if !crate::keys::AuditKey::verify_raw(vk, &recomputed, sig) {
        return Err("signature does not verify under the audit key".to_owned());
    }

    Ok((seq, this_hash_hex))
}

/// Core walk over pre-split lines (shared by CLI verify and writer resume).
pub(crate) fn walk_lines(journal: &str, vk: &VerifyingKey) -> Report {
    let mut records_ok = 0usize;
    let mut expect_prev = GENESIS_PREV_HEX.to_owned();
    let mut tail: Option<Tail> = None;

    for (i, line) in journal.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let expect_seq = u64::try_from(records_ok).unwrap_or(u64::MAX);
        match verify_line(line, &expect_prev, expect_seq, vk) {
            Ok((seq, hash)) => {
                expect_prev = hash.clone();
                tail = Some(Tail {
                    seq,
                    hash_hex: hash,
                });
                records_ok += 1;
            }
            Err(reason) => {
                return Report {
                    tail,
                    error: Some(Break { line: i, reason }),
                    records_ok,
                };
            }
        }
    }

    Report {
        tail,
        error: None,
        records_ok,
    }
}

/// Verifies a journal file under the given audit public key.
pub fn verify_file(path: &std::path::Path, vk: &VerifyingKey) -> Result<Report, std::io::Error> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(walk_lines(&content, vk)),
        Err(e) => Err(e),
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_journal_verifies_to_no_tail() {
        let vk = crate::AuditKey::generate().verifying_key();
        let report = walk_lines("", &vk);
        assert!(report.error.is_none());
        assert_eq!(report.records_ok, 0);
        assert!(report.tail.is_none());
    }
}
