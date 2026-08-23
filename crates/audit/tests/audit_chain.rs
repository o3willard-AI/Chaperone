//! Phase 4 acceptance tests (docs/PLAN.md M4).
//!
//! Proven here, per the plan:
//! - a run produces a verifiable chain (append N events, verify OK);
//! - ANY edit, deletion (non-tail), or reorder breaks verification with a
//!   precise line + reason;
//! - no secret material appears anywhere in records: the API cannot accept
//!   it, and the simulated resolved secret is provably absent while its
//!   cred_ref reference is present;
//! - the record schema is PINNED: top-level keys must equal the allow-list,
//!   so any future field lands in review.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use chaperone_audit::{AuditEvent, AuditKey, AuditWriter, Outcome, verify_file};
use serde_json::{Value, json};

const AGENT: &str = "agent:planner-7";

fn signed_intent_envelope() -> Value {
    // A realistic http-bearer intent as an agent would send it - signature
    // and all. (Signature correctness is identity's business; here it is
    // opaque evidence bytes.)
    json!({
        "chaperone": "0.1",
        "msg_id": "a3f1c9",
        "type": "intent",
        "agent_id": AGENT,
        "issued_at": "2026-08-22T17:04:03Z",
        "nonce": "9f2b7c1e5a",
        "target": {"uri": "https://api.stripe.com/v1/charges", "label": "stripe-prod"},
        "mechanism": "http-bearer",
        "cred_ref": "vault://prod/stripe/secret_key",
        "operation": {"method": "POST", "headers": {"Content-Type": "application/json"},
                      "body_b64": "eyJhbW91bnQiOjIwMDAsImN1cnJlbmN5IjoidXNkIn0="},
        "sig": "c2lnbmF0dXJlLWJ5dGVzLWZyb20tdGhlLWFnZW50"
    })
}

fn stripe_event<'a>(envelope: &'a Value) -> AuditEvent<'a> {
    AuditEvent {
        agent_id: envelope["agent_id"].as_str().unwrap(),
        msg_id: envelope["msg_id"].as_str().unwrap(),
        mechanism: envelope["mechanism"].as_str().unwrap(),
        target_uri: envelope["target"]["uri"].as_str().unwrap(),
        target_label: envelope["target"]["label"].as_str().unwrap(),
        cred_ref: envelope["cred_ref"].as_str().unwrap(),
        effect: "allow",
        outcome: Outcome::Proceeded,
        intent_envelope: envelope,
    }
}

fn open_writer(dir: &Path) -> (AuditWriter, AuditKey) {
    let key = AuditKey::generate();
    let writer = AuditWriter::open(&dir.join("audit.jsonl"), key.clone()).unwrap();
    (writer, key)
}

#[test]
fn run_produces_verifiable_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, key) = open_writer(dir.path());

    let envelope = signed_intent_envelope();
    for i in 0..10 {
        let mut env = envelope.clone();
        env["msg_id"] = json!(format!("m-{i}"));
        let head = writer.append(&stripe_event(&env)).unwrap();
        let want = u64::try_from(i).unwrap() + 1;
        assert_eq!(head.seq, want); // seq 0 is genesis
    }

    let report = verify_file(writer.path(), &key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.records_ok, 11); // genesis + 10
    assert_eq!(
        report.tail.as_ref().unwrap().seq,
        writer.head().unwrap().seq
    );
}

#[test]
fn editing_any_field_breaks_the_chain_at_that_line() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, key) = open_writer(dir.path());
    let envelope = signed_intent_envelope();
    for i in 0..5 {
        let mut env = envelope.clone();
        env["msg_id"] = json!(format!("m-{i}"));
        writer.append(&stripe_event(&env)).unwrap();
    }

    // Tamper: rewrite record 3's target URI (an attacker laundering where a
    // charge was sent).
    let path = writer.path();
    let content = std::fs::read_to_string(path).unwrap();
    let tampered = content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == 3 {
                line.replace("api.stripe.com", "api.stripe.evil")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, tampered).unwrap();

    let report = verify_file(path, &key.verifying_key()).unwrap();
    let brk = report.error.expect("tampering must be detected");
    assert_eq!(brk.line, 3);
    assert!(brk.reason.contains("hash"), "got: {}", brk.reason);

    // And the gateway refuses to extend a broken journal.
    assert!(AuditWriter::open(path, key).is_err());
}

#[test]
fn deleting_a_middle_record_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, key) = open_writer(dir.path());
    let envelope = signed_intent_envelope();
    for i in 0..6 {
        let mut env = envelope.clone();
        env["msg_id"] = json!(format!("m-{i}"));
        writer.append(&stripe_event(&env)).unwrap();
    }

    let path = writer.path();
    let binding = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = binding.lines().collect();
    let deleted: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .map(|(_, l)| *l)
        .collect();
    std::fs::write(path, format!("{}\n", deleted.join("\n"))).unwrap();

    let report = verify_file(path, &key.verifying_key()).unwrap();
    let brk = report.error.expect("deletion must be detected");
    assert_eq!(brk.line, 4);
    assert!(brk.reason.contains("seq"), "got: {}", brk.reason);
}

#[test]
fn reordering_records_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, key) = open_writer(dir.path());
    let envelope = signed_intent_envelope();
    for i in 0..5 {
        let mut env = envelope.clone();
        env["msg_id"] = json!(format!("m-{i}"));
        writer.append(&stripe_event(&env)).unwrap();
    }

    let path = writer.path();
    let mut lines: Vec<String> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    lines.swap(2, 3);
    std::fs::write(path, lines.join("\n") + "\n").unwrap();

    let report = verify_file(path, &key.verifying_key()).unwrap();
    assert!(report.error.is_some(), "reorder must be detected");
}

#[test]
fn wrong_audit_key_fails_at_first_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, _real_key) = open_writer(dir.path());
    let envelope = signed_intent_envelope();
    writer.append(&stripe_event(&envelope)).unwrap();

    let impostor = AuditKey::generate();
    let report = verify_file(writer.path(), &impostor.verifying_key()).unwrap();
    let brk = report.error.expect("key substitution must be caught");
    assert_eq!(brk.line, 0, "genesis itself is signed");
    assert!(brk.reason.contains("signature"), "got: {}", brk.reason);
}

// D18's honest limit, asserted so it can never be quietly "fixed" away:
// dropping the LAST record leaves a valid shorter chain. Detection of tail
// truncation requires monitoring the published head hash externally.
#[test]
fn tail_truncation_is_undetectable_from_inside_the_file_documented_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, key) = open_writer(dir.path());
    let envelope = signed_intent_envelope();
    for i in 0..3 {
        let mut env = envelope.clone();
        env["msg_id"] = json!(format!("m-{i}"));
        writer.append(&stripe_event(&env)).unwrap();
    }
    let observed_head = writer.head().unwrap(); // what an operator WOULD export

    let path = writer.path();
    let binding = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = binding.lines().collect();
    std::fs::write(path, format!("{}\n", lines[..lines.len() - 1].join("\n"))).unwrap();

    let report = verify_file(path, &key.verifying_key()).unwrap();
    assert!(report.error.is_none());
    assert_ne!(
        report.tail.as_ref().unwrap().hash_hex,
        observed_head.hash_hex,
        "external head-hash comparison is the mitigation (D18)"
    );
}

#[test]
fn resolved_secrets_never_reach_the_journal_references_do() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, key) = open_writer(dir.path());

    // Simulate the one-shot flow: policy allows; the vault resolves
    // cred_ref to THIS secret; injection happens; audit records.
    let cred_ref = "vault://prod/stripe/secret_key";
    // Marker shaped like NO real provider key (push protection scans for
    // patterns such as sk_live_*); the property under test is absence of any
    // resolved-material string, not its format.
    let simulated_resolved_secret = "SIMULATED-RESOLVED-SECRET-NOT-A-REAL-CREDENTIAL";

    let envelope = signed_intent_envelope();
    let event = AuditEvent {
        agent_id: AGENT,
        msg_id: "a3f1c9",
        mechanism: "http-bearer",
        target_uri: "https://api.stripe.com/v1/charges",
        target_label: "stripe-prod",
        cred_ref,
        effect: "allow",
        outcome: Outcome::Proceeded,
        intent_envelope: &envelope,
    };
    // Note what append() accepts: there is NO parameter that could carry
    // `simulated_resolved_secret`. The compiler enforces the tenet.
    let _head = writer.append(&event).unwrap();

    let content = std::fs::read_to_string(writer.path()).unwrap();
    assert!(
        content.contains(cred_ref),
        "reference recorded for forensics"
    );
    assert!(
        !content.contains(simulated_resolved_secret),
        "resolved secret material must never appear in the chain"
    );

    // Belt and suspenders across every outcome kind.
    let outcomes = [
        Outcome::Denied,
        Outcome::ConfirmationTimeout,
        Outcome::CredentialUnresolved,
        Outcome::MechanismError,
        Outcome::SessionClosed {
            reason: "client_close".into(),
            exit_code: Some(0),
        },
    ];
    for oc in outcomes {
        let ev = AuditEvent {
            outcome: oc,
            ..stripe_event(&envelope)
        };
        writer.append(&ev).unwrap();
    }
    let content = std::fs::read_to_string(writer.path()).unwrap();
    assert!(!content.contains(simulated_resolved_secret));
    let report = verify_file(writer.path(), &key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
}

#[test]
fn record_schema_is_pinned_top_level_keys_are_allowlisted() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, _key) = open_writer(dir.path());
    let envelope = signed_intent_envelope();
    writer.append(&stripe_event(&envelope)).unwrap();

    let content = std::fs::read_to_string(writer.path()).unwrap();
    let mut lines = content.lines();
    let genesis: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let first: Value = serde_json::from_str(lines.next().unwrap()).unwrap();

    let mut genesis_keys: Vec<&str> = genesis
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    genesis_keys.sort_unstable();
    assert_eq!(
        genesis_keys,
        vec![
            "chain_version",
            "kind",
            "prev_hash",
            "seq",
            "sig",
            "this_hash",
            "ts"
        ]
    );

    let mut keys: Vec<&str> = first
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "agent_id",
            "chain_version",
            "cred_ref",
            "effect",
            "intent",
            "kind",
            "mechanism",
            "msg_id",
            "outcome",
            "prev_hash",
            "seq",
            "sig",
            "target_label",
            "target_uri",
            "this_hash",
            "ts"
        ],
        "any new field must consciously pass schema review (no-secret surface)"
    );
}

#[test]
fn writer_resumes_across_reopen_with_contiguous_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let key = AuditKey::generate();
    let path = dir.path().join("audit.jsonl");

    {
        let w = AuditWriter::open(&path, key.clone()).unwrap();
        let envelope = signed_intent_envelope();
        w.append(&stripe_event(&envelope)).unwrap();
    }
    {
        let w = AuditWriter::open(&path, key.clone()).unwrap();
        assert_eq!(w.head().unwrap().seq, 1, "resume at stored tail");
        let envelope = signed_intent_envelope();
        w.append(&stripe_event(&envelope)).unwrap();
    }

    let report = verify_file(&path, &key.verifying_key()).unwrap();
    assert!(report.error.is_none());
    assert_eq!(report.records_ok, 3);
}

#[test]
fn concurrent_appends_serialize_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let key = AuditKey::generate();
    let writer = std::sync::Arc::new(
        AuditWriter::open(&dir.path().join("audit.jsonl"), key.clone()).unwrap(),
    );
    let envelope = signed_intent_envelope();

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let w = std::sync::Arc::clone(&writer);
            let mut env = envelope.clone();
            env["msg_id"] = json!(format!("t-{i}"));
            std::thread::spawn(move || w.append(&stripe_event(&env)).unwrap())
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    // Contiguous seq verification proves uniqueness + ordering under
    // concurrency.
    let report = verify_file(writer.path(), &key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.records_ok, 9); // genesis + 8
}
