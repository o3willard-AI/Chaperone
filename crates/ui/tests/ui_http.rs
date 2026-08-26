//! Phase 14c acceptance tests: the operator config UI over real HTTP.
//!
//! Drives the actual axum server bound to an ephemeral loopback port and
//! pins the behaviors the spec calls for: setup wizard artifact creation,
//! secret CRUD without redaction leaks, agent enrollment validation,
//! rule editing through the ONE validator/writer pair (\u00A73.2), and the
//! loopback Host/Origin guard.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use chaperone_identity::EnrollmentStore;
use chaperone_ui::UiState;

struct TestApp {
    port: u16,
    dir: tempfile::TempDir,
    _guard: tokio::task::JoinHandle<Result<(), String>>,
}

async fn app() -> TestApp {
    let dir = tempfile::tempdir().unwrap();

    // Bind on port 0 FIRST so the state can carry the real port (the
    // loopback guard checks Host against it).
    let listener = chaperone_ui::bind(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let state = Arc::new(UiState {
        policy_path: dir.path().join("policy.toml"),
        vault_path: dir.path().join("vault.bin"),
        enrollment_path: dir.path().join("enrollment.json"),
        audit_key_path: dir.path().join("audit.key"),
        journal_path: dir.path().join("audit.jsonl"),
        vault: std::sync::RwLock::new(None),
        enrollment: Arc::new(EnrollmentStore::load(&dir.path().join("enrollment.json")).unwrap()),
        gateway: None,
        event_hub: None,
        events_socket_path: None,
        schemes: vec!["local".to_owned()],
        port,
    });

    let handle = tokio::spawn(chaperone_ui::serve_on(listener, state));
    tokio::time::sleep(Duration::from_millis(50)).await;
    TestApp {
        port,
        dir,
        _guard: handle,
    }
}

/// Minimal HTTP/1.1 client over raw TCP (no extra deps).
async fn http(
    port: u16,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n",
        host = extra_headers
            .iter()
            .find(|(k, _)| *k == "Host")
            .map_or(format!("127.0.0.1:{port}"), |(_, v)| v.to_string()),
    );
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    }
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    if let Some(b) = body {
        stream.write_all(b.as_bytes()).await.unwrap();
    }
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, text)
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn wizard_creates_all_broker_artifacts() {
    let t = app().await;
    assert!(!t.dir.path().join("policy.toml").exists());

    // Policy scaffold through the one writer.
    let (status, _) = http(t.port, "POST", "/setup/policy", &[], Some("")).await;
    assert_eq!(status, 303);
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    chaperone_policy::Policy::from_toml(&doc).unwrap();

    // Vault creation: mismatched double-entry refuses; matching creates.
    let (_, loc) = http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[("passphrase", "pw"), ("confirm", "different")])),
    )
    .await;
    assert!(loc.contains("err="));
    assert!(!t.dir.path().join("vault.bin").exists());

    let (status, loc) = http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[
            ("passphrase", "hunter22"),
            ("confirm", "hunter22"),
        ])),
    )
    .await;
    assert_eq!(status, 303);
    assert!(loc.contains("msg="));
    assert!(t.dir.path().join("vault.bin").exists());

    // Audit key generation - same on-disk shape audit-keygen writes.
    let (status, _) = http(t.port, "POST", "/setup/audit-key", &[], Some("")).await;
    assert_eq!(status, 303);
    let seed = std::fs::read_to_string(t.dir.path().join("audit.key")).unwrap();
    assert_eq!(seed.len(), 43); // base64url of exactly 32 bytes

    // Second attempt refuses to overwrite an audit key.
    let (_, loc) = http(t.port, "POST", "/setup/audit-key", &[], Some("")).await;
    assert!(loc.contains("err="));

    // Setup page now reports completion.
    let (_, page) = http(t.port, "GET", "/setup", &[], None).await;
    assert!(page.contains("All required artifacts exist"));
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_store_list_and_never_leak_values() {
    let t = app().await;

    // Open a vault through the wizard endpoint (stashes the shared handle).
    let (status, _) = http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[("passphrase", "pw"), ("confirm", "pw")])),
    )
    .await;
    assert_eq!(status, 303);

    const SECRET: &str = "ghp_SUPERsecret_value_42";
    let (status, loc) = http(
        t.port,
        "POST",
        "/secrets",
        &[],
        Some(&form(&[("path", "prod/github/token"), ("value", SECRET)])),
    )
    .await;
    assert_eq!(status, 303);
    assert!(loc.contains("stored"));

    // Page shows path + redaction, never the value.
    let (_, page) = http(t.port, "GET", "/secrets", &[], None).await;
    assert!(
        !page.contains(SECRET),
        "the UI must never re-display stored values"
    );
    assert!(page.contains("[redacted]"));
    assert!(page.contains("prod/github/token"));
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_enroll_validates_and_revoke_works() {
    let t = app().await;

    // A JSON blob gets a SPECIFIC validation error before enroll runs.
    let (_, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[
            ("agent_id", "agent:x"),
            ("public_key", "{\"kty\":\"OKP\"}"),
        ])),
    )
    .await;
    assert!(loc.contains("err="));
    assert!(!loc.contains("enrolled"));

    // A valid bare base64url key enrolls.
    let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let b64url = chaperone_protocol::encode_signature(&signer.verifying_key().to_bytes());
    let (status, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[
            ("agent_id", "agent:test-1"),
            ("public_key", &b64url),
        ])),
    )
    .await;
    assert_eq!(status, 303);
    assert!(loc.contains("enrolled"));

    let (_, page) = http(t.port, "GET", "/agents", &[], None).await;
    assert!(page.contains("agent:test-1"));

    // Duplicate enrollment without --force semantics is refused loudly.
    let (_, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[
            ("agent_id", "agent:test-1"),
            ("public_key", &b64url),
        ])),
    )
    .await;
    assert!(loc.contains("err="));

    // Revoke flips the badge immediately.
    let (status, _) = http(
        t.port,
        "POST",
        "/agents/revoke",
        &[],
        Some(&form(&[("agent_id", "agent:test-1")])),
    )
    .await;
    assert_eq!(status, 303);
    let (_, page) = http(t.port, "GET", "/agents", &[], None).await;
    assert!(page.contains("REVOKED"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_editor_round_trips_through_the_one_validator() {
    let t = app().await;

    // Start from a scaffolded policy.
    http(t.port, "POST", "/setup/policy", &[], Some("")).await;

    // Template picker renders prefilled targets (server-rendered stage 1).
    let (_, page) = http(
        t.port,
        "GET",
        "/rules/new?mechanism=http-bearer&template=GitHub%20REST%20API%20v3",
        &[],
        None,
    )
    .await;
    assert!(
        page.contains("https://api.github.com/*"),
        "template must prefill the target_uri"
    );
    assert!(
        page.contains("fine-grained PAT"),
        "matrix caveat must be visible inline"
    );

    let (status, _) = http(
        t.port,
        "POST",
        "/rules/add",
        &[],
        Some(&form(&[
            ("name", "ci may read github"),
            ("mechanism", "http-bearer"),
            ("target_uri", "https://api.github.com/*"),
            ("agent_id", ""),
            ("cred_ref", "local://prod/github/token"),
            ("effect", "allow"),
            ("notify_on_use", "on"),
            ("max_response_bytes", "262144"),
            ("session_ttl_s", ""),
        ])),
    )
    .await;
    assert_eq!(status, 303);

    // What landed on disk is exactly what the gateway would parse.
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    let policy = chaperone_policy::Policy::from_toml(&doc).unwrap();
    assert_eq!(policy.len(), 1);
    let rule = &policy.rules()[0];
    assert_eq!(rule.effect.as_str(), "allow");
    assert!(rule.notify_on_use);
    assert_eq!(rule.limits.max_response_bytes, Some(262144));
    assert_eq!(
        rule.target_uri.source().as_deref(),
        Some("https://api.github.com/*")
    );
    assert_eq!(rule.agent_id.source(), None, "empty input = Any");

    // Unknown mechanism refused before anything is written.
    let (_, loc) = http(
        t.port,
        "POST",
        "/rules/add",
        &[],
        Some(&form(&[
            ("mechanism", "telepathy"),
            ("effect", "allow"),
            ("target_uri", ""),
            ("agent_id", ""),
            ("cred_ref", ""),
        ])),
    )
    .await;
    assert!(loc.contains("err=unknown+mechanism"));
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    assert_eq!(chaperone_policy::Policy::from_toml(&doc).unwrap().len(), 1);

    // Delete removes exactly that index.
    let (status, _) = http(
        t.port,
        "POST",
        "/rules/delete",
        &[],
        Some(&form(&[("index", "0")])),
    )
    .await;
    assert_eq!(status, 303);
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    assert!(
        chaperone_policy::Policy::from_toml(&doc)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_editor_refuses_invalid_toml_without_writing() {
    let t = app().await;
    let before = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap_or_default();

    let garbage = "[[rule]]\neffect = \"definitely_not_an_effect\"\n";
    let (_, loc) = http(
        t.port,
        "POST",
        "/policy/raw",
        &[],
        Some(&form(&[("doc", garbage)])),
    )
    .await;
    assert!(loc.contains("NOT+saved") || loc.contains("err="));
    let after = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap_or_default();
    assert_eq!(before, after, "invalid document must not touch disk");

    // Valid document saves.
    let good = "[[rule]]\neffect = \"deny\"\nname = \"floor\"\n";
    let (_, loc) = http(
        t.port,
        "POST",
        "/policy/raw",
        &[],
        Some(&form(&[("doc", good)])),
    )
    .await;
    assert!(loc.contains("/rules"));
    assert_eq!(
        std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap(),
        good
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn loopback_guard_blocks_foreign_host_and_origin() {
    let t = app().await;

    // DNS-rebinding style Host.
    let (status, _) = http(t.port, "GET", "/", &[("Host", "evil.example")], None).await;
    assert_eq!(status, 403);

    // Cross-site form post (browser CSRF sends Origin).
    let (status, _) = http(
        t.port,
        "POST",
        "/setup/policy",
        &[
            ("Host", &format!("127.0.0.1:{}", t.port)),
            ("Origin", "http://evil.example"),
        ],
        Some(""),
    )
    .await;
    assert_eq!(status, 403);

    // Matching Origin passes.
    let (status, _) = http(
        t.port,
        "POST",
        "/setup/policy",
        &[
            ("Host", &format!("127.0.0.1:{}", t.port)),
            ("Origin", &format!("http://127.0.0.1:{}", t.port)),
        ],
        Some(""),
    )
    .await;
    assert_eq!(status, 303);
}

#[test]
fn html_escaper_neutralizes_markup() {
    let escaped = chaperone_ui::render::esc("<img src=x onerror=\"alert('1')\">&");
    assert!(!escaped.contains('<'));
    assert!(!escaped.contains('\''));
    assert!(escaped.contains("&amp;"));
}
