//! End-to-end taste of the audit chain:
//!
//! ```text
//! cargo run -p chaperone-audit --example local_chain
//! ```
//!
//! Demonstrates the intended division of labor: the GATEWAY appends
//! (write-only); OPERATORS verify and export.

#![allow(clippy::unwrap_used)]

use chaperone_audit::{
    AuditEvent, AuditKey, AuditWriter, Outcome, verify_file, verifying_key_from_b64url,
};
use serde_json::json;

fn main() {
    let dir = std::env::temp_dir().join("chaperone-audit-example");
    std::fs::create_dir_all(&dir).unwrap();

    // Operator side: one-time key generation.
    let key = AuditKey::generate();
    let pubkey = key.public_key_b64url();

    // Gateway side: append-only writes, references only.
    let writer = AuditWriter::open(&dir.join("journal.jsonl"), key.clone()).unwrap();
    let envelope = json!({
        "chaperone": "0.1", "msg_id": "a3f1c9", "type": "intent",
        "agent_id": "agent:planner-7",
        "issued_at": "2026-08-22T17:04:03Z", "nonce": "9f2b7c1e5a",
        "target": {"uri": "https://api.stripe.com/v1/charges", "label": "stripe-prod"},
        "mechanism": "http-bearer", "cred_ref": "vault://prod/stripe/secret_key",
        "operation": {"method": "POST"}, "sig": "evidence-bytes"
    });
    let event = AuditEvent {
        agent_id: "agent:planner-7",
        msg_id: "a3f1c9",
        mechanism: "http-bearer",
        target_uri: "https://api.stripe.com/v1/charges",
        target_label: "stripe-prod",
        cred_ref: "vault://prod/stripe/secret_key",
        effect: "allow",
        outcome: Outcome::Proceeded,
        intent_envelope: &envelope,
    };
    let head = writer.append(&event).unwrap();
    println!("appended seq={} hash={}", head.seq, &head.hash_hex[..16]);

    // Operator side: verify under the published public key.
    let vk = verifying_key_from_b64url(&pubkey).unwrap();
    let report = verify_file(writer.path(), &vk).unwrap();
    println!(
        "verify: ok={} records={} head_seq={}",
        report.error.is_none(),
        report.records_ok,
        report.tail.as_ref().unwrap().seq
    );
}
