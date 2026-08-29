//! GitHub API over `http-bearer` — the flagship connectivity example
//! (docs/CONNECTIVITY-MATRIX.md row "GitHub REST API").
//!
//! Part 1 (always runs): a local capture server emulating api.github.com
//! proves the complete flow — policy scoping by target glob, bearer
//! injection outbound, credential-free response relay, clean audit chain.
//!
//! Part 2 (gated): with CHAPERONE_TEST_GH_TOKEN set to a fine-grained PAT,
//! the identical flow runs against the REAL api.github.com and expects 200
//! plus an authenticated-user payload:
//!
//! ```text
//! CHAPERONE_TEST_GH_TOKEN=github_pat_xxx \
//!   cargo test -p chaperone-gateway-core --test github_api live_ -- --include-ignored
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use chaperone_audit::{AuditKey, AuditWriter};
use chaperone_gateway_core::{AlwaysTimeoutGate, Gateway, GatewayConfig};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:github-1";
const FAKE_TOKEN: &str = "github_pat_simulated-NOT-A-REAL-CREDENTIAL";

// ---------- capture server emulating api.github.com ----------

#[derive(Default)]
struct Captured {
    auth: Mutex<Option<String>>,
    path: Mutex<Option<String>>,
}

impl Captured {
    fn auth(&self) -> Option<String> {
        self.auth.lock().unwrap().clone()
    }
    fn path(&self) -> Option<String> {
        self.path.lock().unwrap().clone()
    }
}

async fn spawn_github_emulator(captured: Arc<Captured>) -> String {
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
                    if let Some(p) = find(&buf, b"\r\n\r\n") {
                        break p + 4;
                    }
                    if n == 0 {
                        return;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let request_line = head.lines().next().unwrap_or("");
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .to_owned();
                for line in head.lines() {
                    if let Some((name, value)) = line.split_once(':')
                        && name.trim().eq_ignore_ascii_case("authorization")
                    {
                        *captured.auth.lock().unwrap() = Some(value.trim().to_owned());
                    }
                }
                *captured.path.lock().unwrap() = Some(path);

                let body = serde_json::to_vec(&json!({
                    "login": "chaperone-test-agent",
                    "type": "Bot",
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-GitHub-Media-Type: github.v3\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.write_all(&body).await.unwrap();
            });
        }
    });
    format!("http://{addr}")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------- spine ----------

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
    audit_path: std::path::PathBuf,
    audit_key: AuditKey,
    _dir: tempfile::TempDir,
}

async fn build(policy_doc: &str, vault_token: &str) -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };

    let signer = SigningKey::from_bytes(&[81u8; 32]);
    let enrollment = Arc::new(EnrollmentStore::load(&dir.path().join("e.json")).unwrap());
    enrollment
        .enroll(
            AGENT,
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

    let mut store =
        LocalVault::create(&dir.path().join("v.bin"), "passphrase", Zeroizing::new("gh-pass".into())).unwrap();
    store
        .set(
            "prod/github/token",
            SecretString::new(vault_token.to_owned()),
        )
        .unwrap();
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_key = AuditKey::generate();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, audit_key.clone()).unwrap());

    let gateway = Gateway::new(
        attestor,
        Policy::from_toml(policy_doc).unwrap(),
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        GatewayConfig::default(),
    )
    .unwrap();

    Spine {
        gateway,
        signer,
        audit_path,
        audit_key,
        _dir: dir,
    }
}

impl Spine {
    /// The intent-catalog-shaped GET /user call against an arbitrary host.
    fn get_user_intent(&self, nonce: &str, target_uri: &str) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": format!("gh-{nonce}"), "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "target": {"uri": target_uri, "label": "github-api"},
            "mechanism": "http-bearer",
            "cred_ref": "local://prod/github/token",
            "operation": {"method": "GET",
                          "headers": {"Accept": "application/vnd.github+json"}},
        });
        sign_envelope(&self.signer, &mut env);
        env
    }

    fn decoded_body(resp: &Value) -> String {
        use base64::Engine as _;
        resp["body_b64"]
            .as_str()
            .map(|b| base64::engine::general_purpose::STANDARD.decode(b).unwrap())
            .map(|b| String::from_utf8(b).unwrap_or_default())
            .unwrap_or_default()
    }
}

const OFFLINE_POLICY: &str = r#"
    [[rule]]
    name = "agent may call the local github emulator"
    effect = "allow"
    agent_id = "agent:github-1"
    cred_ref = "local://prod/github/token"
    target_uri = "http://127.0.0.1:*/*"
"#;

// ---------- offline acceptance (always runs) ----------

#[tokio::test]
async fn github_rest_call_bearer_injected_and_scoped() {
    let captured = Arc::new(Captured::default());
    let url = spawn_github_emulator(Arc::clone(&captured)).await;
    let spine = build(OFFLINE_POLICY, FAKE_TOKEN).await;

    let resp = spine
        .gateway
        .handle_message(&spine.get_user_intent("u1", &format!("{url}/user")))
        .await;

    assert_eq!(resp["type"], "result", "{resp}");
    assert_eq!(resp["status"], 200);
    assert_eq!(captured.path(), Some("/user".to_owned()));
    assert_eq!(
        captured.auth().as_deref(),
        Some(format!("Bearer {FAKE_TOKEN}").as_str()),
        "fine-grained PAT injected outbound"
    );

    // Agent sees API data, never the credential.
    let body = Spine::decoded_body(&resp);
    assert!(body.contains("chaperone-test-agent"), "{body}");
    assert!(
        !resp.to_string().contains(FAKE_TOKEN),
        "token leaked to agent"
    );

    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(
        journal.contains("local://prod/github/token"),
        "reference recorded"
    );
    assert!(
        !journal.contains(FAKE_TOKEN),
        "token leaked into audit chain"
    );

    let report =
        chaperone_audit::verify_file(&spine.audit_path, &spine.audit_key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
}

/// Policy twin proving scope: the SAME token cannot be steered at a
/// different host — denied before the vault is touched.
#[tokio::test]
async fn github_token_cannot_be_steered_off_policy() {
    let steered_policy = r#"
        [[rule]]
        name = "only the real api host"
        effect = "allow"
        cred_ref = "local://prod/github/token"
        target_uri = "https://api.github.com/*"
    "#;
    let spine = build(steered_policy, FAKE_TOKEN).await;

    let evil = spine.get_user_intent("s1", "https://evil.example/exfil");
    let resp = spine.gateway.handle_message(&evil).await;
    assert_eq!(resp["code"], "E_DENIED", "{resp}");
}

// ---------- live acceptance (gated) ----------

/// Runs only when CHAPERONE_TEST_GH_TOKEN holds a fine-grained PAT
/// (read-only scope suffices for GET /user):
///
/// ```sh
/// CHAPERONE_TEST_GH_TOKEN=$(gh auth token) \
///   cargo test -p chaperone-gateway-core --test github_api live -- --include-ignored
/// ```
#[tokio::test]
async fn live_github_api_round_trip_with_real_pat() {
    let Some(real_token) = std::env::var("CHAPERONE_TEST_GH_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("SKIP: CHAPERONE_TEST_GH_TOKEN not set");
        return;
    };

    let live_policy = r#"
        [[rule]]
        effect = "allow"
        agent_id = "agent:github-1"
        cred_ref = "local://prod/github/token"
        target_uri = "https://api.github.com/*"
    "#;
    let spine = build(live_policy, &real_token).await;

    let resp = spine
        .gateway
        .handle_message(&spine.get_user_intent("live1", "https://api.github.com/user"))
        .await;

    assert_eq!(resp["type"], "result", "{resp}");
    assert_eq!(resp["status"], 200, "{resp}");

    let body = Spine::decoded_body(&resp);
    let parsed: Value = serde_json::from_str(&body).expect("GitHub /user returns JSON");
    assert!(
        parsed.get("login").and_then(Value::as_str).is_some(),
        "authenticated user payload expected: {parsed}"
    );

    // The real PAT must not appear in the agent-visible response or journal.
    assert!(!resp.to_string().contains(&real_token));
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(
        !journal.contains(&real_token),
        "real PAT leaked into journal"
    );
}
