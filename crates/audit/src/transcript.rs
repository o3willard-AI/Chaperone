//! B-3: the transcript sidecar — a per-run hash-chained, Ed25519-signed
//! recording of the agent channel, reusing the audit crate's chain
//! machinery (NO new crypto; the "no new dependency" rule is satisfied the
//! same way: this file lives in the audit crate and reuses its primitives).
//!
//! Format (RULED spec, TD-2): `transcript.jsonl`, one chain record per
//! frame. Genesis body binds the recording to the audited run:
//! `evidence_class: "self-produced"` (the artifact says what it is, on the
//! artifact — Heph ruling 3), the audit journal's head hash at serve start,
//! the audit public key, the protocol version, and the start timestamp. A
//! `transcript_end` record closes a graceful shutdown; a crashed run leaves
//! the journal unterminated (a WARNING at verification, never a failure —
//! the chain is the anchor; Heph ruling 2).
//!
//! The writer is generic over the record body: the audit journal's
//! `AuditWriter` stays untouched; this module composes the same
//! `seal_record` primitive with its own body shapes.

use crate::keys::AuditKey;
use crate::{AuditError, Head};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The evidence-class marker (Heph ruling 3): the artifact declares, on
/// itself, that it is operator-signed and not third-party notarized.
pub const EVIDENCE_CLASS: &str = "self-produced";
/// The custody clause carried in the genesis body beside the marker.
pub const EVIDENCE_CLAUSE: &str = "signed by the operator's audit key; not third-party notarized; trust rests on operator key custody";

struct TxState {
    seq: u64,
    prev_hash: [u8; 32],
}

/// A transcript journal bound to the run's audit key.
pub struct TranscriptWriter {
    file: Mutex<std::fs::File>,
    state: Mutex<TxState>,
    #[allow(dead_code)]
    path: PathBuf,
    key: AuditKey,
}

impl TranscriptWriter {
    /// Opens a fresh transcript at `path`. Refuses to extend an existing
    /// file (TD-4 fail-closed: appending across runs forges a chain across
    /// two runs) — the caller surfaces the refusal to the operator.
    ///
    /// `audit_head_hash_hex` is the companion audit journal's head hash at
    /// serve start; `audit_pubkey_b64url` the audit key's public half. Both
    /// go into the genesis body (TD-2 binding).
    pub fn create(
        path: &Path,
        key: AuditKey,
        audit_head_hash_hex: &str,
        audit_pubkey_b64url: &str,
        protocol_version: &str,
    ) -> Result<Self, AuditError> {
        if path.exists() {
            // Fail closed — the caller has already been told; this is the
            // structural guard (no "append to existing" path exists at all).
            return Err(AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "transcript file exists; move it first (refusing to extend a \
                 chain across runs)",
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(AuditError::Io)?;
        }
        let file = std::fs::File::create(path).map_err(AuditError::Io)?;
        let writer = Self {
            file: Mutex::new(file),
            state: Mutex::new(TxState {
                seq: 0,
                prev_hash: [0u8; 32],
            }),
            path: path.to_path_buf(),
            key,
        };
        let now = now_rfc3339()?;
        let body = json!({
            "chain_version": crate::writer::chain_version(),
            "seq": 0,
            "kind": "transcript_genesis",
            "ruleset_hash": "",
            "ts": now,
            "prev_hash": crate::writer::zero_hash_hex(),
            "evidence_class": EVIDENCE_CLASS,
            "evidence_clause": EVIDENCE_CLAUSE,
            "audit_head_hash": audit_head_hash_hex,
            "audit_pubkey": audit_pubkey_b64url,
            "protocol_version": protocol_version,
        });
        writer.seal_and_write(body)?;
        Ok(writer)
    }

    /// Appends one recorded frame (TD-1: verbatim bytes, base64'd for JSONL
    /// line-safety). `direction` is `"request"` (agent → gateway) or
    /// `"response"` (gateway → agent).
    pub fn append_frame(
        &self,
        direction: &str,
        frame_b64: &str,
        content_length: usize,
    ) -> Result<Head, AuditError> {
        let now = now_rfc3339()?;
        let body = {
            let st = self.state.lock().map_err(poison)?;
            json!({
                "chain_version": crate::writer::chain_version(),
                "seq": st.seq.saturating_add(1),
                "kind": "transcript_frame",
                "ruleset_hash": "",
                "ts": now,
                "prev_hash": crate::writer::hex(&st.prev_hash),
                "direction": direction,
                "content_length": content_length,
                "frame_b64": frame_b64,
            })
        };
        self.seal_and_write(body)
    }

    /// Closes a graceful shutdown: the `transcript_end` marker (frame count,
    /// end timestamp, final chain hash). Idempotent-safe: a second end after
    /// the first is rejected by the caller's lifecycle, not here.
    pub fn end(&self, frame_count: u64) -> Result<Head, AuditError> {
        let now = now_rfc3339()?;
        let body = {
            let st = self.state.lock().map_err(poison)?;
            json!({
                "chain_version": crate::writer::chain_version(),
                "seq": st.seq.saturating_add(1),
                "kind": "transcript_end",
                "ruleset_hash": "",
                "ts": now,
                "prev_hash": crate::writer::hex(&st.prev_hash),
                "frame_count": frame_count,
            })
        };
        self.seal_and_write(body)
    }

    /// The chain head after the last append (the caller records it for
    /// cross-artifact reporting).
    pub fn head(&self) -> Result<Head, AuditError> {
        let st = self.state.lock().map_err(poison)?;
        Ok(Head {
            seq: st.seq,
            hash_hex: crate::writer::hex(&st.prev_hash),
        })
    }

    /// Shared tail: hash, sign, stamp, write. Identical mechanics to the
    /// audit journal's `append` — the same `seal_record` primitive. The
    /// body's `seq` is authoritative (genesis is 0 by definition; appends
    /// precompute seq+1 in their bodies BEFORE sealing — the sealed bytes
    /// must contain the seq the hash covers).
    fn seal_and_write(&self, body: Value) -> Result<Head, AuditError> {
        let seq = body
            .as_object()
            .and_then(|o| o.get("seq"))
            .and_then(|s| s.as_u64())
            .ok_or_else(|| AuditError::Serialize("body missing seq".into()))?;
        let mut st = self.state.lock().map_err(poison)?;
        let (this_hash, line) = crate::writer::seal_record_pub(&body, &st.prev_hash, &self.key)?;
        st.seq = seq;
        st.prev_hash = this_hash;
        {
            use std::io::Write as _;
            let mut f = self.file.lock().map_err(poison)?;
            f.write_all(line.as_bytes()).map_err(AuditError::Io)?;
            f.write_all(b"\n").map_err(AuditError::Io)?;
            f.flush().map_err(AuditError::Io)?;
        }
        Ok(Head {
            seq,
            hash_hex: crate::writer::hex(&this_hash),
        })
    }
}

/// A poisoned lock is an internal invariant break; surface it as an IO
/// error rather than panicking (the transcript must fail closed, not take
/// the gateway down).
fn poison<T>(p: std::sync::PoisonError<T>) -> AuditError {
    AuditError::Io(std::io::Error::other(format!(
        "transcript lock poisoned: {p}"
    )))
}

fn now_rfc3339() -> Result<String, AuditError> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| AuditError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn verify_file(path: &Path, key: &AuditKey) -> crate::verify::Report {
        crate::verify::verify_file(path, &key.verifying_key()).unwrap()
    }

    #[test]
    fn genesis_carries_evidence_class_and_audit_binding() {
        let dir = tempfile::tempdir().unwrap();
        let key = AuditKey::generate();
        let path = dir.path().join("transcript.jsonl");
        let w = TranscriptWriter::create(&path, key.clone(), "audit-head-abc", "pub-key-x", "0.1")
            .unwrap();
        w.end(0).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let genesis: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(genesis["kind"], "transcript_genesis");
        assert_eq!(genesis["evidence_class"], "self-produced");
        assert_eq!(genesis["audit_head_hash"], "audit-head-abc");
        assert_eq!(genesis["audit_pubkey"], "pub-key-x");
        assert!(
            genesis["evidence_clause"]
                .as_str()
                .unwrap()
                .contains("operator key custody")
        );
        // The chain verifies under the audit key (no new crypto).
        let report = verify_file(&path, &key);
        assert!(report.error.is_none(), "{:?}", report.error);
    }

    #[test]
    fn frames_chain_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let key = AuditKey::generate();
        let path = dir.path().join("transcript.jsonl");
        let w = TranscriptWriter::create(&path, key.clone(), "h", "p", "0.1").unwrap();
        w.append_frame("request", "eyJhIjoxfQ==", 7).unwrap();
        w.append_frame("response", "eyJiIjoyfQ==", 7).unwrap();
        w.end(2).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let kinds: Vec<String> = text
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "transcript_genesis",
                "transcript_frame",
                "transcript_frame",
                "transcript_end"
            ]
        );
        let report = verify_file(&path, &key);
        assert!(report.error.is_none(), "{:?}", report.error);
    }

    #[test]
    fn refuses_existing_path_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let key = AuditKey::generate();
        let path = dir.path().join("transcript.jsonl");
        std::fs::write(&path, "x").unwrap();
        let err = match TranscriptWriter::create(&path, key, "h", "p", "0.1") {
            Err(e) => e,
            Ok(_) => panic!("create on an existing path must fail"),
        };
        assert!(err.to_string().contains("transcript file exists"), "{err}");
    }

    #[test]
    fn tampered_frame_is_detected_by_the_verifier() {
        // Falsifiability: rewrite a frame's payload in place → chain breaks.
        let dir = tempfile::tempdir().unwrap();
        let key = AuditKey::generate();
        let path = dir.path().join("transcript.jsonl");
        let w = TranscriptWriter::create(&path, key.clone(), "h", "p", "0.1").unwrap();
        w.append_frame("request", "eyJhIjoxfQ==", 7).unwrap();
        w.end(1).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("eyJhIjoxfQ==", "eyJ6Ijo5fQ==");
        std::fs::write(&path, tampered).unwrap();
        let report = verify_file(&path, &key);
        assert!(
            report.error.is_some(),
            "a tampered frame must break the chain"
        );
    }
}
