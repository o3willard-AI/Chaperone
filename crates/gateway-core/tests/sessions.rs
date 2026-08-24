//! Phase 8 acceptance tests (docs/PLAN.md M8): brokered-session lifecycle.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chaperone_audit::{AuditKey, AuditWriter, verify_file};
use chaperone_gateway_core::{
    AlwaysTimeoutGate, Gateway, GatewayConfig, OutputBatch, SessionBackend, SessionChannel,
};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, Provider, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:sess-1";
const PEER: &str = "agent:peer-9";
const SECRET_KEY_PEM: &str = "SIMULATED-SSH-PRIVATE-KEY-BODY-NOT-A-REAL-CREDENTIAL";
const PASSPHRASE: &str = "sess-vault-pass";

// ---------- mock backend: the lifecycle oracle ----------

#[derive(Debug)]
struct EchoChannel {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    pending_out: Mutex<Vec<u8>>,
}

impl SessionChannel for EchoChannel {
    fn write(
        &self,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(data.clone());
            let text = String::from_utf8_lossy(&data).to_uppercase();
            self.pending_out
                .lock()
                .unwrap()
                .extend_from_slice(text.as_bytes());
            Ok(())
        })
    }

    fn read_batch(
        &self,
        _max_wait: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutputBatch> + Send + '_>> {
        Box::pin(async move {
            let mut out = self.pending_out.lock().unwrap();
            let chunks = if out.is_empty() {
                vec![]
            } else {
                vec![chaperone_gateway_core::OutputChunk {
                    stream: "stdout",
                    data: std::mem::take(&mut *out),
                }]
            };
            let closed = chunks.is_empty(); // quiet => treat as still-open? keep open
            if closed {
                return OutputBatch {
                    chunks: vec![],
                    closed: false,
                    exit_code: None,
                };
            }
            OutputBatch {
                chunks,
                closed: false,
                exit_code: None,
            }
        })
    }

    fn shutdown(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async {})
    }
}

#[derive(Debug)]
struct MockSsh {
    connect_calls: Arc<std::sync::atomic::AtomicUsize>,
    seen_secrets: Arc<Mutex<Vec<String>>>,
}

impl SessionBackend for MockSsh {
    fn connect<'a>(
        &'a self,
        _target_uri: &'a str,
        operation: &'a Value,
        secret: &'a SecretString,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn SessionChannel>, String>> + Send + 'a>,
    > {
        use std::sync::atomic::Ordering;
        self.connect_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(operation["host"], json!("app-01.internal"));
        // The ONE moment a secret exists in this whole test.
        self.seen_secrets
            .lock()
            .unwrap()
            .push(secret.expose().to_owned());
        Box::pin(async move {
            Ok(Box::new(EchoChannel {
                sent: Arc::new(Mutex::new(Vec::new())),
                pending_out: Mutex::new(Vec::new()),
            }) as Box<dyn SessionChannel>)
        })
    }
}

// ---------- spine ----------

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
    peer_signer: SigningKey,
    connect_calls: Arc<std::sync::atomic::AtomicUsize>,
    seen_secrets: Arc<Mutex<Vec<String>>>,
    audit_path: std::path::PathBuf,
    audit_key: AuditKey,
    _dir: tempfile::TempDir,
}

async fn build() -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };

    let signer = SigningKey::from_bytes(&[21u8; 32]);
    let peer_signer = SigningKey::from_bytes(&[22u8; 32]);
    let enrollment = Arc::new(EnrollmentStore::load(&dir.path().join("e.json")).unwrap());
    for (id, key) in [(AGENT, &signer), (PEER, &peer_signer)] {
        enrollment
            .enroll(
                id,
                &chaperone_protocol::encode_signature(&key.verifying_key().to_bytes()),
                &rfc(),
                false,
            )
            .unwrap();
    }
    let attestor = Attestor::new(
        enrollment,
        Arc::new(ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp()).unwrap()),
        IdentityConfig { max_skew_secs: 30 },
    );

    let mut store = LocalVault::create(
        &dir.path().join("v.bin"),
        Zeroizing::new(PASSPHRASE.to_owned()),
    )
    .unwrap();
    store
        .set(
            "deploy/app-01",
            SecretString::new(SECRET_KEY_PEM.to_owned()),
        )
        .unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    struct Counting(Arc<LocalVault>, Arc<std::sync::atomic::AtomicUsize>);
    impl Provider for Counting {
        fn resolve<'a>(&'a self, entry: &'a str) -> chaperone_vault::provider::SecretFuture<'a> {
            use std::sync::atomic::Ordering;
            self.1.fetch_add(1, Ordering::SeqCst);
            let inner = Arc::clone(&self.0);
            Box::pin(async move {
                <chaperone_vault::LocalVault as Provider>::resolve(inner.as_ref(), entry).await
            })
        }
    }
    let vault_calls = Arc::clone(&calls);
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(Counting(Arc::new(store), vault_calls)));

    let audit_key = AuditKey::generate();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, audit_key.clone()).unwrap());

    let policy_doc = r#"
        [[rule]]
        effect = "allow"
    "#;
    let policy = Policy::from_toml(policy_doc).unwrap();

    let mut gateway = Gateway::new(
        attestor,
        policy,
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        GatewayConfig::default(),
    )
    .unwrap();

    let seen_secrets = Arc::new(Mutex::new(Vec::new()));
    let connect_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    gateway.with_session_backend(
        "ssh",
        Arc::new(MockSsh {
            connect_calls: Arc::clone(&connect_calls),
            seen_secrets: Arc::clone(&seen_secrets),
        }),
    );

    Spine {
        gateway,
        signer,
        peer_signer,
        connect_calls,
        seen_secrets,
        audit_path,
        audit_key,
        _dir: dir,
    }
}

fn sign(key: &SigningKey, msg: &mut Value) {
    sign_envelope(key, msg);
}

fn opener(spine: &Spine, key: &SigningKey, agent: &str, nonce: &str) -> Value {
    opener_with(spine, key, agent, nonce, json!({}))
}

fn opener_with(_spine: &Spine, key: &SigningKey, agent: &str, nonce: &str, tweaks: Value) -> Value {
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut env = json!({
        "chaperone": "0.1", "msg_id": format!("open-{nonce}"), "type": "intent",
        "agent_id": agent,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": nonce,
        "target": {"uri": "ssh://app-01.internal", "label": "app-01"},
        "mechanism": "ssh",
        "cred_ref": "local://deploy/app-01",
        "operation": {"host": "app-01.internal", "port": 22, "user": "deploy", "pty": true},
    });
    if let Some(obj) = tweaks.as_object() {
        for (k, v) in obj {
            env[k.as_str()] = v.clone();
        }
    }
    sign(key, &mut env);
    env
}

fn command_frame(
    _spine: &Spine,
    key: &SigningKey,
    agent: &str,
    handle: &str,
    nonce: &str,
    input: &str,
) -> Value {
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut env = json!({
        "chaperone": "0.1", "msg_id": format!("cmd-{nonce}"), "type": "session.command",
        "agent_id": agent,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": nonce,
        "session_handle": handle,
        "input_b64": base64(input.as_bytes()),
    });
    sign(key, &mut env);
    env
}

fn base64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn decode_b64(s: &Value) -> String {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.as_str().unwrap())
        .unwrap();
    String::from_utf8(raw).unwrap()
}

// ---------- acceptance ----------

#[tokio::test]
async fn session_lifecycle_open_drive_close() {
    let spine = build().await;

    // Open.
    let resp = spine
        .gateway
        .handle_message(&opener(&spine, &spine.signer, AGENT, "o1"))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");
    assert!(
        resp["session_handle"]
            .as_str()
            .unwrap()
            .starts_with("sess_"),
        "{resp}"
    );
    assert_eq!(resp["session_ttl"], 300);
    let handle = resp["session_handle"].as_str().unwrap().to_owned();

    // Drive.
    let cmd = command_frame(
        &spine,
        &spine.signer,
        AGENT,
        &handle,
        "c1",
        "ls -la /var/log",
    );
    let resp = spine.gateway.handle_message(&cmd).await;
    assert_eq!(resp["type"], "session.output", "{resp}");
    assert_eq!(resp["closed"], false);
    let outputs = resp["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 1);
    assert_eq!(decode_b64(&outputs[0]["data_b64"]), "LS -LA /VAR/LOG");
    assert_eq!(outputs[0]["seq"], 1);

    // Close.
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut close = json!({
        "chaperone": "0.1", "msg_id": "close-1", "type": "session.close",
        "agent_id": AGENT,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": "cl1", "session_handle": handle,
    });
    sign(&spine.signer, &mut close);
    let resp = spine.gateway.handle_message(&close).await;
    assert_eq!(resp["type"], "session.closed", "{resp}");
    assert_eq!(resp["reason"], "client_close");
    assert!(resp["audit_id"].as_str().unwrap().starts_with("aud_"));

    // Audit chain intact; the secret never appears in it.
    let report = verify_file(&spine.audit_path, &spine.audit_key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(
        !journal.contains(SECRET_KEY_PEM),
        "secret leaked into journal"
    );

    assert_eq!(
        spine.connect_calls.load(Ordering::SeqCst),
        1,
        "authenticate once"
    );
    assert_eq!(spine.seen_secrets.lock().unwrap().len(), 1);
    assert_eq!(
        spine.seen_secrets.lock().unwrap().len(),
        1,
        "secret materialized exactly once"
    );
}

use std::sync::atomic::Ordering;

#[tokio::test]
async fn foreign_signed_frame_rejected_e_session_owner() {
    let spine = build().await;
    let resp = spine
        .gateway
        .handle_message(&opener(&spine, &spine.signer, AGENT, "o2"))
        .await;
    let handle = resp["session_handle"].as_str().unwrap().to_owned();

    // Peer signs with THEIR key but claims AGENT's id... that's E_BAD_SIGNATURE.
    // The owner attack proper: peer signs their OWN identity against OUR session.
    let frame = command_frame(&spine, &spine.peer_signer, PEER, &handle, "f1", "id");
    let resp = spine.gateway.handle_message(&frame).await;
    assert_eq!(resp["code"], "E_SESSION_OWNER", "{resp}");
}

#[tokio::test]
async fn tampered_owner_claim_breaks_signature_first() {
    let spine = build().await;
    let resp = spine
        .gateway
        .handle_message(&opener(&spine, &spine.signer, AGENT, "o3"))
        .await;
    let handle = resp["session_handle"].as_str().unwrap().to_owned();

    // Frame claims AGENT but is signed by peer -> signature gate first.
    let frame = command_frame(&spine, &spine.peer_signer, AGENT, &handle, "t1", "whoami");
    let resp = spine.gateway.handle_message(&frame).await;
    assert_eq!(resp["code"], "E_BAD_SIGNATURE");
}

#[tokio::test]
async fn unknown_and_closed_handles_expire() {
    let spine = build().await;
    // Unknown handle.
    let frame = command_frame(&spine, &spine.signer, AGENT, "sess_doesnotexist", "u1", "x");
    let resp = spine.gateway.handle_message(&frame).await;
    assert_eq!(resp["code"], "E_SESSION_EXPIRED");

    // Closed handle.
    let resp = spine
        .gateway
        .handle_message(&opener(&spine, &spine.signer, AGENT, "o4"))
        .await;
    let handle = resp["session_handle"].as_str().unwrap().to_owned();
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut close = json!({
        "chaperone": "0.1", "msg_id": "cx", "type": "session.close", "agent_id": AGENT,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": "cxn", "session_handle": handle,
    });
    sign(&spine.signer, &mut close);
    spine.gateway.handle_message(&close).await;

    let again = command_frame(&spine, &spine.signer, AGENT, &handle, "u2", "x");
    let resp = spine.gateway.handle_message(&again).await;
    assert_eq!(resp["code"], "E_SESSION_EXPIRED");
}

#[tokio::test]
async fn ttl_expiry_closes_the_channel() {
    let spine = build().await;
    // Opener with constraints.session_ttl_s = 1s... minimum granularity is
    // seconds; use 1 and sleep past it.
    let env = opener_with(
        &spine,
        &spine.signer,
        AGENT,
        "o5",
        json!({"constraints": {"session_ttl_s": 1}}),
    );
    let resp = spine.gateway.handle_message(&env).await;
    let handle = resp["session_handle"].as_str().unwrap().to_owned();
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let frame = command_frame(&spine, &spine.signer, AGENT, &handle, "e1", "x");
    let resp = spine.gateway.handle_message(&frame).await;
    assert_eq!(resp["code"], "E_SESSION_EXPIRED", "{resp}");
}
