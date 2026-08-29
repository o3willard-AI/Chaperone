//! Phase 6 acceptance tests (docs/PLAN.md M6): the first full path.
//!
//! signed intent -> verify -> policy -> [gate] -> resolve (FETCH-LATE)
//!   -> inject -> result/error -> audit
//!
//! The "capture layer" is a real local HTTP server recording the exact
//! Authorization header the gateway sent - proving the secret crossed the
//! outbound side without appearing in any agent-visible artifact.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chaperone_audit::{AuditKey, AuditWriter, verify_file};
use chaperone_gateway_core::{
    AlwaysTimeoutGate, ConfirmContext, ConfirmOutcome, ConfirmationGate, Gateway, GatewayConfig,
};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, Provider, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:e2e-1";
const SECRET: &str = "simulated-vault-bearer-value-NOT-A-REAL-CREDENTIAL";
const PASSPHRASE: &str = "e2e-vault-passphrase";

// ---------- local HTTP capture server ----------

struct Captured {
    auth: Mutex<Option<String>>,
    body: Vec<u8>,
}

impl Captured {
    fn new(body: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            auth: Mutex::new(None),
            body,
        })
    }
    fn auth_seen(&self) -> Option<String> {
        self.auth.lock().unwrap().clone()
    }
}

/// HTTP/1.1 server on 127.0.0.1:0 recording each request's Authorization
/// header and answering with the configured body.
async fn spawn_target(captured: Arc<Captured>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let captured = Arc::clone(&captured);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let header_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                        break pos + 4;
                    }
                    if n == 0 {
                        return;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + content_length {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }

                for line in head.lines() {
                    if let Some((name, value)) = line.split_once(':')
                        && name.trim().eq_ignore_ascii_case("authorization")
                    {
                        *captured.auth.lock().unwrap() = Some(value.trim().to_owned());
                    }
                }

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    captured.body.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.write_all(&captured.body).await.unwrap();
            });
        }
    });
    format!("http://{addr}/v1/charges")
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------- gateway assembly ----------

struct Spine {
    gateway: Gateway,
    vault_calls: Arc<AtomicUsize>,
    audit_path: std::path::PathBuf,
    audit_key: AuditKey,
    signer: SigningKey,
    target_url: String,
    _dir: tempfile::TempDir,
}

const ALLOW_ALL_POLICY: &str = r#"
    [[rule]]
    name = "e2e allow"
    effect = "allow"
"#;

async fn build_spine(target_url: String, policy_doc: &'static str) -> Spine {
    build_spine_with_gate(target_url, policy_doc, None).await
}

async fn build_spine_with_gate(
    target_url: String,
    policy_doc: &'static str,
    gate: Option<Arc<dyn ConfirmationGate>>,
) -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();

    let signer = SigningKey::from_bytes(&[42u8; 32]);
    let enrollment = Arc::new(EnrollmentStore::load(&dir.path().join("enrollment.json")).unwrap());
    enrollment
        .enroll(
            AGENT,
            &chaperone_protocol::encode_signature(&signer.verifying_key().to_bytes()),
            &now.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            false,
        )
        .unwrap();
    let attestor = Attestor::new(
        enrollment,
        Arc::new(
            ReplayCache::open(&dir.path().join("replay.jsonl"), now.unix_timestamp()).unwrap(),
        ),
        IdentityConfig { max_skew_secs: 30 },
    );

    let mut store = LocalVault::create(
        &dir.path().join("vault.bin"),
        "passphrase",
        Zeroizing::new(PASSPHRASE.to_owned()),
    )
    .unwrap();
    store
        .set("prod/stripe/key", SecretString::new(SECRET.to_owned()))
        .unwrap();
    let store = Arc::new(store);
    let vault_calls = Arc::new(AtomicUsize::new(0));
    struct Counting {
        inner: Arc<LocalVault>,
        calls: Arc<AtomicUsize>,
    }
    impl Provider for Counting {
        fn resolve<'a>(&'a self, entry: &'a str) -> chaperone_vault::provider::SecretFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let inner = Arc::clone(&self.inner);
            Box::pin(async move {
                <chaperone_vault::LocalVault as Provider>::resolve(inner.as_ref(), entry).await
            })
        }
    }
    let mut router = VaultRouter::new();
    router.register(
        "local",
        Arc::new(Counting {
            inner: store,
            calls: Arc::clone(&vault_calls),
        }),
    );

    let audit_key = AuditKey::generate();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, audit_key.clone()).unwrap());

    let gateway = Gateway::new(
        attestor,
        Policy::from_toml(policy_doc).unwrap(),
        router,
        audit,
        gate.unwrap_or_else(|| Arc::new(AlwaysTimeoutGate)),
        GatewayConfig::default(),
    )
    .unwrap();

    let _ = policy_doc;
    Spine {
        gateway,
        vault_calls,
        audit_path,
        audit_key,
        signer,
        target_url,
        _dir: dir,
    }
}

impl Spine {
    fn sign_intent(&self, nonce: &str, tweaks: Value) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let issued_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let mut env = json!({
            "chaperone": "0.1",
            "msg_id": format!("m-{nonce}"),
            "type": "intent",
            "agent_id": AGENT,
            "issued_at": issued_at,
            "nonce": nonce,
            "target": {"uri": self.target_url, "label": "e2e-target"},
            "mechanism": "http-bearer",
            "cred_ref": "local://prod/stripe/key",
            "operation": {"method": "POST", "headers": {"Content-Type": "application/json"},
                          "body_b64": base64_of(br#"{"amount":2000}"#)},
        });
        if let Some(obj) = tweaks.as_object() {
            for (k, v) in obj {
                env[k.as_str()] = v.clone();
            }
        }
        sign_envelope(&self.signer, &mut env);
        env
    }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------- acceptance ----------

#[tokio::test]
async fn happy_path_bearer_secret_crosses_outbound_only() {
    let captured = Captured::new(br#"{"ok":true}"#.to_vec());
    let url = spawn_target(captured.clone()).await;
    let spine = build_spine(url, ALLOW_ALL_POLICY).await;

    let resp = spine
        .gateway
        .handle_message(&spine.sign_intent("n1", json!({})))
        .await;

    assert_eq!(resp["type"], "result", "{resp}");
    assert_eq!(resp["decision"], "allow");
    assert_eq!(resp["status"], 200);
    assert_eq!(
        captured.auth_seen().as_deref(),
        Some(format!("Bearer {SECRET}").as_str()),
        "the real credential must reach the target"
    );

    // Agent-visible artifacts contain NO secret.
    let rendered = resp.to_string();
    assert!(
        !rendered.contains(SECRET),
        "secret leaked into agent response"
    );

    // Audit chain verifies and contains no secret either.
    let report = verify_file(&spine.audit_path, &spine.audit_key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(!journal.contains(SECRET), "secret leaked into audit chain");
    assert!(
        journal.contains("local://prod/stripe/key"),
        "reference recorded"
    );
    assert!(journal.contains("\"status\":\"proceeded\""));

    assert_eq!(spine.vault_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn denied_intent_never_touches_vault_or_target() {
    let captured = Captured::new(b"{}".to_vec());
    let url = spawn_target(captured.clone()).await;
    let spine = build_spine(url, "").await; // empty ruleset: default-deny

    let resp = spine
        .gateway
        .handle_message(&spine.sign_intent("n2", json!({})))
        .await;

    assert_eq!(resp["type"], "error");
    assert_eq!(resp["code"], "E_DENIED");
    assert_eq!(resp["msg_id"], "m-n2");
    assert_eq!(
        spine.vault_calls.load(Ordering::SeqCst),
        0,
        "fetch-late: denial resolves nothing"
    );
    assert_eq!(captured.auth_seen(), None, "denied intents never inject");

    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(journal.contains("\"status\":\"denied\""));
}

#[tokio::test]
async fn identity_failures_record_evidence_and_fetch_nothing() {
    let captured = Captured::new(b"{}".to_vec());
    let url = spawn_target(captured.clone()).await;
    let spine = build_spine(url, ALLOW_ALL_POLICY).await;

    // Forged intent: right agent id, wrong key.
    let impostor = SigningKey::from_bytes(&[7u8; 32]);
    let mut env = json!({
        "chaperone": "0.1", "msg_id": "m-forged", "type": "intent",
        "agent_id": AGENT, "issued_at": chaperone_gateway_core::chaperone_time_now()
            .format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": "forged-1",
        "target": {"uri": spine.target_url, "label": "x"},
        "mechanism": "http-bearer", "cred_ref": "local://prod/stripe/key",
        "operation": {"method": "GET"},
    });
    chaperone_protocol::testutil::sign_envelope(&impostor, &mut env);
    let resp = spine.gateway.handle_message(&env).await;
    assert_eq!(resp["code"], "E_BAD_SIGNATURE");
    assert_eq!(spine.vault_calls.load(Ordering::SeqCst), 0);

    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(
        journal.contains("\"code\":\"E_BAD_SIGNATURE\""),
        "rejections are evidence too"
    );
}

#[tokio::test]
async fn confirmation_gate_blocks_until_resolved() {
    struct ApprovingGate;
    impl ConfirmationGate for ApprovingGate {
        fn confirm<'a>(
            &'a self,
            ctx: ConfirmContext,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ConfirmOutcome> + Send + 'a>>
        {
            assert_eq!(ctx.mechanism, "http-bearer");
            assert!(!ctx.summary.is_empty(), "prompt carries operation context");
            Box::pin(async { ConfirmOutcome::Approved })
        }
    }

    let captured = Captured::new(b"{}".to_vec());
    let url = spawn_target(captured.clone()).await;
    let needs_confirm_policy = r#"
        [[rule]]
        effect = "needs_confirmation"
    "#;
    let spine =
        build_spine_with_gate(url, needs_confirm_policy, Some(Arc::new(ApprovingGate))).await;
    let resp = spine
        .gateway
        .handle_message(&spine.sign_intent("n3", json!({})))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");
    assert_eq!(
        captured.auth_seen().as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );
}

#[tokio::test]
async fn unconfirmed_gate_times_out_without_fetching() {
    let captured = Captured::new(b"{}".to_vec());
    let url = spawn_target(captured.clone()).await;
    let needs_confirm_policy = r#"
        [[rule]]
        effect = "needs_confirmation"
    "#;
    let spine = build_spine_with_gate(url, needs_confirm_policy, None).await; // AlwaysTimeout

    let resp = spine
        .gateway
        .handle_message(&spine.sign_intent("n4", json!({})))
        .await;
    assert_eq!(resp["code"], "E_CONFIRM_TIMEOUT");
    assert_eq!(
        spine.vault_calls.load(Ordering::SeqCst),
        0,
        "unconfirmed never fetches"
    );
    assert_eq!(captured.auth_seen(), None);
}

#[tokio::test]
async fn basic_auth_flow_rfc7617() {
    let captured = Captured::new(b"{}".to_vec());
    let url = spawn_target(captured.clone()).await;
    let spine = build_spine(url, ALLOW_ALL_POLICY).await;

    let msg = spine.sign_intent(
        "n5",
        json!({
            "mechanism": "http-basic",
            "operation": {"method": "GET", "username": "deploy-bot"},
        }),
    );
    let resp = spine.gateway.handle_message(&msg).await;
    assert_eq!(resp["type"], "result", "{resp}");

    use base64::Engine as _;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("deploy-bot:{SECRET}"))
    );
    assert_eq!(captured.auth_seen().as_deref(), Some(expected.as_str()));
}

#[tokio::test]
async fn oversized_response_is_aborted_not_truncated() {
    // Target returns 2 MiB; declared ceiling is 1024 bytes.
    let big_body = vec![b'x'; 2 * 1024 * 1024];
    let captured = Captured::new(big_body);
    let url = spawn_target(captured.clone()).await;
    let spine = build_spine(url, ALLOW_ALL_POLICY).await;

    let msg = spine.sign_intent(
        "n6",
        json!({"operation": {"method": "GET"},
               "constraints": {"max_response_bytes": 1024}}),
    );
    let resp = spine.gateway.handle_message(&msg).await;
    assert_eq!(resp["type"], "error", "{resp}");
    assert_eq!(resp["code"], "E_MECHANISM");
    assert!(resp["reason"].as_str().unwrap().contains("ceiling"));
    assert_eq!(
        spine.vault_calls.load(Ordering::SeqCst),
        1,
        "fetch happened, cap applied after"
    );
}

#[tokio::test]
async fn unknown_mechanism_fails_after_policy_without_fetch() {
    let captured = Captured::new(b"{}".to_vec());
    let url = spawn_target(captured.clone()).await;
    let spine = build_spine(url, ALLOW_ALL_POLICY).await;

    let msg = spine.sign_intent("n7", json!({"mechanism": "browser-session"}));
    let resp = spine.gateway.handle_message(&msg).await;
    assert_eq!(resp["code"], "E_MECHANISM");
    assert!(resp["reason"].as_str().unwrap().contains("not available"));
    assert_eq!(spine.vault_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agents_cannot_supply_their_own_authorization() {
    let captured = Captured::new(b"{}".to_vec());
    let url = spawn_target(captured.clone()).await;
    let spine = build_spine(url, ALLOW_ALL_POLICY).await;

    let msg = spine.sign_intent(
        "n8",
        json!({"operation": {"method": "GET",
                             "headers": {"Authorization": "Bearer attacker-token"}}}),
    );
    let resp = spine.gateway.handle_message(&msg).await;
    assert_eq!(resp["code"], "E_MECHANISM");
    assert!(resp["reason"].as_str().unwrap().contains("cred_ref"));
    assert_eq!(
        captured.auth_seen(),
        None,
        "smuggled credentials never leave"
    );
}
