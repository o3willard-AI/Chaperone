//! P0-3 — `notify_on_use` governs the live event feed.
//!
//! The gap review's acceptance, verbatim:
//!   * a rule with `on_use = false` produces an audit record and NO event-feed
//!     line;
//!   * the same rule with `on_use = true` produces BOTH;
//!   * a deny produces BOTH regardless of the flag.
//!
//! The third case is the sharp one: an *explicit deny rule* with `on_use = false`
//! must still broadcast, because D35 treats repeated quiet refusals as signal,
//! and default-deny lands on the structural floor where the flag is false — so
//! gating the feed on the flag alone would wrongly silence denials. The fix
//! gates on `effect == deny || notify_on_use`.
//!
//! Audit records are written in ALL cases (the flag governs the live feed only,
//! never evidence — a notification preference must not become an evidence
//! preference).
//!
//! The events feed is a unix-domain socket (P1-1; no Windows transport yet), so
//! these observation tests are `#[cfg(unix)]`, matching policy_guard.rs. The
//! gating logic itself is platform-independent.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use chaperone_audit::{AuditKey, AuditWriter};
use chaperone_gateway_core::{AlwaysTimeoutGate, EventHub, Gateway, GatewayConfig};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:notify-probe";
const SPONSOR_ID: &str = "human@example.org";
const SPONSOR_NAME: &str = "Pat Human";
const TOKEN: &str = "notify-probe-token-not-a-real-credential";

// ---------- a target that just answers 200 (the allow path must complete) ----

async fn spawn_ok_target() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = b"{\"ok\":true}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.write_all(body).await.unwrap();
            });
        }
    });
    format!("http://{addr}")
}

// ---------- spine ----------

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
    audit_path: std::path::PathBuf,
    events_path: std::path::PathBuf,
    audit_key: AuditKey,
    _dir: tempfile::TempDir,
}

async fn build(policy_doc: &str) -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };

    let signer = SigningKey::from_bytes(&[83u8; 32]);
    let enrollment = Arc::new(EnrollmentStore::load(&dir.path().join("e.json")).unwrap());
    enrollment
        .enroll(
            AGENT,
            &chaperone_protocol::encode_signature(&signer.verifying_key().to_bytes()),
            SPONSOR_ID,
            SPONSOR_NAME,
            &rfc(),
            false,
        )
        .unwrap();
    let attestor = Attestor::new(
        enrollment,
        Arc::new(ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp()).unwrap()),
        IdentityConfig { max_skew_secs: 30 },
    );

    let mut store = LocalVault::create(
        &dir.path().join("v.bin"),
        "passphrase",
        Zeroizing::new("np-pass".into()),
    )
    .unwrap();
    store
        .set("prod/probe/token", SecretString::new(TOKEN.to_owned()))
        .unwrap();
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_key = AuditKey::generate();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, audit_key.clone()).unwrap());

    let events_path = dir.path().join("events.sock");
    let hub = EventHub::spawn(&events_path).unwrap();

    let mut gateway = Gateway::new(
        attestor,
        Policy::from_toml(policy_doc).unwrap(),
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        GatewayConfig::default(),
    )
    .unwrap();
    gateway.with_event_hub(hub);

    Spine {
        gateway,
        signer,
        audit_path,
        events_path,
        audit_key,
        _dir: dir,
    }
}

impl Spine {
    fn bearer_intent(&self, nonce: &str, target_uri: &str) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": format!("np-{nonce}"), "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "target": {"uri": target_uri, "label": "probe"},
            "mechanism": "http-bearer",
            "cred_ref": "local://prod/probe/token",
            "operation": {"method": "GET", "headers": {}},
        });
        sign_envelope(&self.signer, &mut env);
        env
    }

    fn journal(&self) -> String {
        std::fs::read_to_string(&self.audit_path).unwrap()
    }
}

/// Connect a feed subscriber and give the hub's accept loop a moment to register
/// it before the decision broadcasts (same pattern as policy_guard.rs).
fn subscribe(events_path: &std::path::Path) -> std::os::unix::net::UnixStream {
    let sub = std::os::unix::net::UnixStream::connect(events_path).unwrap();
    std::thread::sleep(Duration::from_millis(120));
    sub
}

/// Reads one newline-terminated feed line, or None on timeout (no broadcast).
fn read_line_opt(sub: &std::os::unix::net::UnixStream) -> Option<String> {
    use std::io::Read as _;
    sub.set_read_timeout(Some(Duration::from_millis(700)))
        .unwrap();
    let mut reader = sub;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while reader.read_exact(&mut byte).is_ok() {
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

// ---------- the three acceptance cases ----------

/// on_use = true: BOTH an audit record and an event-feed line.
#[tokio::test]
async fn on_use_true_broadcasts_and_audits() {
    let url = spawn_ok_target().await;
    let policy = format!(
        r#"
        [[rule]]
        name = "allow with notify"
        effect = "allow"
        agent_id = "{AGENT}"
        cred_ref = "local://prod/probe/token"
        target_uri = "http://127.0.0.1:*/*"
        [rule.notify]
        on_use = true
        "#
    );
    let spine = build(&policy).await;
    let sub = subscribe(&spine.events_path);

    let resp = spine
        .gateway
        .handle_message(&spine.bearer_intent("t1", &format!("{url}/x")))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");

    // Event-feed line present.
    let line = read_line_opt(&sub).expect("on_use=true must broadcast a feed line");
    let ev: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(ev["effect"], "allow", "{ev}");

    // Audit record present.
    assert!(
        spine.journal().contains("\"effect\":\"allow\""),
        "audit record missing: {}",
        spine.journal()
    );
}

/// on_use = false: an audit record but NO event-feed line.
#[tokio::test]
async fn on_use_false_suppresses_feed_but_still_audits() {
    let url = spawn_ok_target().await;
    let policy = format!(
        r#"
        [[rule]]
        name = "allow without notify"
        effect = "allow"
        agent_id = "{AGENT}"
        cred_ref = "local://prod/probe/token"
        target_uri = "http://127.0.0.1:*/*"
        [rule.notify]
        on_use = false
        "#
    );
    let spine = build(&policy).await;
    let sub = subscribe(&spine.events_path);

    let resp = spine
        .gateway
        .handle_message(&spine.bearer_intent("f1", &format!("{url}/x")))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");

    // No feed line within the read window.
    assert!(
        read_line_opt(&sub).is_none(),
        "on_use=false must NOT broadcast a feed line"
    );

    // But the audit record is STILL written — the flag governs the feed only.
    assert!(
        spine.journal().contains("\"effect\":\"allow\""),
        "audit record must be written even when the feed is suppressed: {}",
        spine.journal()
    );

    // And the chain still verifies: suppressing a notification never touches
    // the evidence (a notification preference must not become an evidence
    // preference).
    let report =
        chaperone_audit::verify_file(&spine.audit_path, &spine.audit_key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
}

/// The sharp case: an EXPLICIT DENY rule with on_use = false must STILL
/// broadcast (denials are never silenced by the flag) and must audit.
#[tokio::test]
async fn deny_broadcasts_even_with_notify_off() {
    let policy = format!(
        r#"
        [[rule]]
        name = "explicit deny, notify off"
        effect = "deny"
        agent_id = "{AGENT}"
        cred_ref = "local://prod/probe/token"
        target_uri = "http://127.0.0.1:*/*"
        [rule.notify]
        on_use = false
        "#
    );
    let spine = build(&policy).await;
    let sub = subscribe(&spine.events_path);

    // Any target; the deny happens before the mechanism runs.
    let resp = spine
        .gateway
        .handle_message(&spine.bearer_intent("d1", "http://127.0.0.1:9/x"))
        .await;
    assert_eq!(resp["code"], "E_DENIED", "{resp}");

    // Denials broadcast regardless of on_use.
    let line = read_line_opt(&sub).expect("a denial must broadcast even with on_use=false");
    let ev: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(ev["effect"], "deny", "{ev}");

    assert!(
        spine.journal().contains("\"effect\":\"deny\""),
        "deny must be audited: {}",
        spine.journal()
    );
}

/// Default-deny (no matching rule) also broadcasts: it lands on the structural
/// floor where notify_on_use is false, and the effect==deny arm covers it.
#[tokio::test]
async fn default_deny_broadcasts() {
    // A policy with a rule that does NOT match this agent.
    let policy = r#"
        [[rule]]
        name = "unrelated"
        effect = "allow"
        agent_id = "agent:someone-else"
        cred_ref = "local://prod/probe/token"
        target_uri = "http://127.0.0.1:*/*"
    "#;
    let spine = build(policy).await;
    let sub = subscribe(&spine.events_path);

    let resp = spine
        .gateway
        .handle_message(&spine.bearer_intent("dd1", "http://127.0.0.1:9/x"))
        .await;
    assert_eq!(resp["code"], "E_DENIED", "{resp}");

    let line = read_line_opt(&sub).expect("default-deny must broadcast");
    let ev: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(ev["effect"], "deny", "{ev}");
}
