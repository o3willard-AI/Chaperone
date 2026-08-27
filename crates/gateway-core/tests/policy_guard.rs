//! Phase 14c-pre acceptance tests (docs/PLAN.md): the policy-file
//! integrity guard (DESIGN-DECISIONS D39).
//!
//! Pinned behaviors:
//! - A halted gateway brokers nothing: every message type answers
//!   E_GATEWAY_HALTED carrying the reason.
//! - Content drift / deletion under a running gateway halts brokering,
//!   appends one signed `policy_drift` record to the SAME audit chain the
//!   gateway writes, and broadcasts on the events feed.
//! - An untouched file never trips the guard.
//! - The permission gate refuses group/other-writable policy files.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use chaperone_audit::{AuditKey, AuditWriter};
#[cfg(unix)]
use chaperone_gateway_core::verify_permissions;
use chaperone_gateway_core::{
    AlwaysTimeoutGate, EventHub, Gateway, GatewayConfig, PolicyWatch, hash_doc_bytes,
};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_vault::VaultRouter;
#[cfg(unix)]
use serde_json::Value;
use serde_json::json;

const DOC: &str = r#"
    [[rule]]
    name = "allow stripe for planner"
    effect = "allow"
    agent_id = "agent:p"
    cred_ref = "local://prod/stripe"
    target_uri = "https://api.stripe.com/*"
    mechanism = "http-bearer"
"#;

const WATCH_TICK: Duration = Duration::from_millis(25);

struct Spine {
    gateway: Arc<Gateway>,
    audit: Arc<AuditWriter>,
    #[cfg(unix)]
    audit_path: std::path::PathBuf,
    policy_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn build(doc: &str) -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };

    let enrollment = Arc::new(EnrollmentStore::load(&dir.path().join("e.json")).unwrap());
    let signer = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
    enrollment
        .enroll(
            "agent:p",
            &chaperone_protocol::encode_signature(&signer.verifying_key().to_bytes()),
            &rfc(),
            false,
        )
        .unwrap();
    let attestor = Attestor::new(
        enrollment,
        Arc::new(ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp()).unwrap()),
        IdentityConfig { max_skew_secs: 30 },
    );

    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, AuditKey::generate()).unwrap());

    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, doc).unwrap();

    let gateway = Arc::new(
        Gateway::new(
            attestor,
            Policy::from_toml(doc).unwrap(),
            VaultRouter::new(),
            Arc::clone(&audit),
            Arc::new(AlwaysTimeoutGate),
            GatewayConfig::default(),
        )
        .unwrap(),
    );

    Spine {
        gateway,
        audit,
        #[cfg(unix)]
        audit_path,
        policy_path,
        _dir: dir,
    }
}

fn spawn_watch(spine: &Spine, hub: Option<Arc<EventHub>>) {
    let watch = PolicyWatch::new(spine.policy_path.clone(), hash_doc_bytes(DOC.as_bytes()))
        .with_interval(WATCH_TICK);
    tokio::spawn(watch.run(Arc::clone(&spine.gateway), Arc::clone(&spine.audit), hub));
}

/// Waits until `pred` holds or the deadline passes (timing-safe asserts).
#[cfg(unix)]
fn wait_until(deadline_ms: u128, pred: impl Fn() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < deadline_ms {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pred()
}

#[tokio::test(flavor = "current_thread")]
async fn halted_gateway_refuses_everything_with_reason() {
    let spine = build(DOC);
    assert!(!spine.gateway.is_halted());

    // Control: un-halted gateway answers normally (unknown agent here).
    let probe = json!({"type": "intent", "msg_id": "m1"});
    let live = spine.gateway.handle_message(&probe).await;
    assert_ne!(live["code"], "E_GATEWAY_HALTED");

    spine
        .gateway
        .halt("policy integrity guard: content changed");

    for kind in ["intent", "session.command", "session.close"] {
        let msg = json!({"type": kind, "msg_id": "m2"});
        let resp = spine.gateway.handle_message(&msg).await;
        assert_eq!(resp["code"], "E_GATEWAY_HALTED", "{kind}");
        assert!(resp["reason"].as_str().unwrap().contains("content changed"));
    }
    assert!(spine.gateway.is_halted());
    assert_eq!(
        spine.gateway.halt_reason().as_deref(),
        Some("policy integrity guard: content changed")
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn content_drift_halts_records_and_broadcasts() {
    let spine = build(DOC);

    let events_path = spine._dir.path().join("events.sock");
    let hub = EventHub::spawn(&events_path).unwrap();
    let mut subscriber = std::os::unix::net::UnixStream::connect(&events_path).unwrap();

    spawn_watch(&spine, Some(Arc::clone(&hub)));

    // Give the watch a few healthy ticks first...
    std::thread::sleep(Duration::from_millis(80));
    assert!(!spine.gateway.is_halted(), "guard tripped on no change");

    // ...then tamper.
    std::fs::write(
        &spine.policy_path,
        DOC.replace("agent_id = \"agent:p\"", "agent_id = \"*\""),
    )
    .unwrap();

    assert!(
        wait_until(2_000, || spine.gateway.is_halted()),
        "gateway did not halt after content drift"
    );

    // The drift record landed on the shared chain, after the genesis +
    // policy_load anchors.
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    let drift_line = journal
        .lines()
        .find(|l| l.contains("\"policy_drift\""))
        .expect("no policy_drift record appended");
    let record: Value = serde_json::from_str(drift_line).unwrap();
    assert_eq!(record["outcome"]["status"], "policy_drift");
    assert_eq!(record["outcome"]["detail"], "content changed");
    assert_eq!(record["ruleset_hash"], hash_doc_bytes(DOC.as_bytes()));
    assert_ne!(record["observed_hash"], "");

    // Exactly one drift record: sticky halt suppresses repeats.
    std::thread::sleep(Duration::from_millis(100));
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert_eq!(
        journal
            .lines()
            .filter(|l| l.contains("\"policy_drift\""))
            .count(),
        1,
        "watch re-fired after halting"
    );

    // A subscriber received the broadcast line.
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    subscriber
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    use std::io::Read as _;
    loop {
        subscriber.read_exact(&mut byte).unwrap();
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let line: Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(line["type"], "policy_drift");
    assert_eq!(line["halted"], true);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn deleted_policy_file_halts() {
    let spine = build(DOC);
    spawn_watch(&spine, None);

    std::thread::sleep(Duration::from_millis(60));
    std::fs::remove_file(&spine.policy_path).unwrap();

    assert!(
        wait_until(2_000, || spine.gateway.is_halted()),
        "gateway did not halt after policy deletion"
    );
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    let drift_line = journal
        .lines()
        .find(|l| l.contains("\"policy_drift\""))
        .expect("no policy_drift record");
    let record: Value = serde_json::from_str(drift_line).unwrap();
    assert_eq!(record["outcome"]["detail"], "file missing");
}

#[tokio::test(flavor = "multi_thread")]
async fn untouched_file_never_trips_the_guard() {
    let spine = build(DOC);
    spawn_watch(&spine, None);

    std::thread::sleep(Duration::from_millis(250));
    assert!(
        !spine.gateway.is_halted(),
        "guard fired without any file change"
    );

    // And the gateway still brokers (answers non-halted errors).
    let resp = spine
        .gateway
        .handle_message(&json!({"type": "intent"}))
        .await;
    assert_ne!(resp["code"], "E_GATEWAY_HALTED");
}

#[cfg(unix)]
#[test]
fn permission_gate_refuses_loose_modes_and_missing_files() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    std::fs::write(&p, DOC).unwrap();

    {
        use std::os::unix::fs::PermissionsExt;
        // Readable-by-others is fine; WRITABLE-by-others is the threat.
        for mode in [0o600u32, 0o400, 0o644] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(verify_permissions(&p).is_ok(), "mode {mode:04o} must pass");
        }
        for mode in [0o646u32, 0o664, 0o666, 0o622] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                verify_permissions(&p).is_err(),
                "mode {mode:04o} must be refused"
            );
        }
    }
    assert!(verify_permissions(&dir.path().join("absent.toml")).is_err());
}
