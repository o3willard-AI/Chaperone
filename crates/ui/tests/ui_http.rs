//! Phase 14c + D41 acceptance tests: the operator config UI over real HTTP.
//!
//! Drives the actual axum server bound to an ephemeral loopback port and
//! pins the behaviors the spec calls for: setup wizard artifact creation,
//! secret CRUD without redaction leaks, agent enrollment validation, rule
//! editing through the ONE validator/writer pair (\u00A73.2), the loopback
//! Host/Origin guard (D40), and the per-instance access token gate (D41).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use chaperone_identity::EnrollmentStore;
use chaperone_ui::UiState;

struct TestApp {
    port: u16,
    token: String,
    dir: tempfile::TempDir,
    _guard: tokio::task::JoinHandle<Result<(), String>>,
}

impl TestApp {
    /// Cookie header value for authenticated requests.
    fn cookie(&self) -> String {
        format!("chaperone_ui={}", self.token)
    }
}

async fn app() -> TestApp {
    let dir = tempfile::tempdir().unwrap();

    // Bind on port 0 FIRST so the state can carry the real port (the
    // loopback guard checks Host against it).
    let listener = chaperone_ui::bind(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // D41: a token is required before the UI serves.
    let token = chaperone_ui::rotate(&dir.path().join("ui.token")).unwrap();
    let ui_token = chaperone_ui::load(&dir.path().join("ui.token")).unwrap();

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
        token: ui_token,
        port,
    });

    let handle = tokio::spawn(chaperone_ui::serve_on(listener, state));
    tokio::time::sleep(Duration::from_millis(50)).await;
    TestApp {
        port,
        token,
        dir,
        _guard: handle,
    }
}

/// Minimal HTTP/1.1 client over raw TCP (no extra deps).
///
/// `cookie` is sent as the `Cookie:` header when `Some`.
async fn http(
    port: u16,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
    cookie: Option<&str>,
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
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
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

// ---------- existing flows, now cookie-authenticated ----------

#[tokio::test(flavor = "multi_thread")]
async fn wizard_creates_all_broker_artifacts() {
    let t = app().await;
    let c = t.cookie();
    assert!(!t.dir.path().join("policy.toml").exists());

    let (status, _) = http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;
    assert_eq!(status, 303);
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    chaperone_policy::Policy::from_toml(&doc).unwrap();

    let (_, loc) = http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[("passphrase", "pw"), ("confirm", "different")])),
        Some(&c),
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
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);
    assert!(loc.contains("msg="));
    assert!(t.dir.path().join("vault.bin").exists());

    let (status, _) = http(t.port, "POST", "/setup/audit-key", &[], Some(""), Some(&c)).await;
    assert_eq!(status, 303);
    let seed = std::fs::read_to_string(t.dir.path().join("audit.key")).unwrap();
    assert_eq!(seed.len(), 43);

    let (_, loc) = http(t.port, "POST", "/setup/audit-key", &[], Some(""), Some(&c)).await;
    assert!(loc.contains("err="));

    let (_, page) = http(t.port, "GET", "/setup", &[], None, Some(&c)).await;
    assert!(page.contains("All required artifacts exist"));
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_store_list_and_never_leak_values() {
    let t = app().await;
    let c = t.cookie();

    let (status, _) = http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[("passphrase", "pw"), ("confirm", "pw")])),
        Some(&c),
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
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);
    assert!(loc.contains("stored"));

    let (_, page) = http(t.port, "GET", "/secrets", &[], None, Some(&c)).await;
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
    let c = t.cookie();

    let (_, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[
            ("agent_id", "agent:x"),
            ("public_key", "{\"kty\":\"OKP\"}"),
        ])),
        Some(&c),
    )
    .await;
    assert!(loc.contains("err="));

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
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);
    assert!(loc.contains("enrolled"));

    let (_, page) = http(t.port, "GET", "/agents", &[], None, Some(&c)).await;
    assert!(page.contains("agent:test-1"));

    let (_, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[
            ("agent_id", "agent:test-1"),
            ("public_key", &b64url),
        ])),
        Some(&c),
    )
    .await;
    assert!(loc.contains("err="));

    let (status, _) = http(
        t.port,
        "POST",
        "/agents/revoke",
        &[],
        Some(&form(&[("agent_id", "agent:test-1")])),
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);
    let (_, page) = http(t.port, "GET", "/agents", &[], None, Some(&c)).await;
    assert!(page.contains("REVOKED"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_editor_round_trips_through_the_one_validator() {
    let t = app().await;
    let c = t.cookie();

    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;

    let (_, page) = http(
        t.port,
        "GET",
        "/rules/new?mechanism=http-bearer&template=GitHub%20REST%20API%20v3",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        page.contains("https://api.github.com/*"),
        "template must prefill"
    );
    assert!(
        page.contains("fine-grained PAT"),
        "matrix caveat must be visible"
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
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);

    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    let policy = chaperone_policy::Policy::from_toml(&doc).unwrap();
    assert_eq!(policy.len(), 1);
    let rule = &policy.rules()[0];
    assert_eq!(rule.effect.as_str(), "allow");
    assert!(rule.notify_on_use);
    assert_eq!(rule.limits.max_response_bytes, Some(262144));
    assert_eq!(rule.agent_id.source(), None, "empty input = Any");

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
        Some(&c),
    )
    .await;
    assert!(loc.contains("err=unknown+mechanism"));
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    assert_eq!(chaperone_policy::Policy::from_toml(&doc).unwrap().len(), 1);

    let (status, _) = http(
        t.port,
        "POST",
        "/rules/delete",
        &[],
        Some(&form(&[("index", "0")])),
        Some(&c),
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
    let c = t.cookie();
    let before = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap_or_default();

    let garbage = "[[rule]]\neffect = \"definitely_not_an_effect\"\n";
    let (_, loc) = http(
        t.port,
        "POST",
        "/policy/raw",
        &[],
        Some(&form(&[("doc", garbage)])),
        Some(&c),
    )
    .await;
    assert!(loc.contains("NOT+saved") || loc.contains("err="));
    let after = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap_or_default();
    assert_eq!(before, after, "invalid document must not touch disk");

    let good = "[[rule]]\neffect = \"deny\"\nname = \"floor\"\n";
    let (_, loc) = http(
        t.port,
        "POST",
        "/policy/raw",
        &[],
        Some(&form(&[("doc", good)])),
        Some(&c),
    )
    .await;
    assert!(loc.contains("/rules"));
    assert_eq!(
        std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap(),
        good
    );
}

// ---------- D41: token gate ----------

#[tokio::test(flavor = "multi_thread")]
async fn no_cookie_redirects_to_paste_page() {
    let t = app().await;

    // GET without a cookie \u{2192} 303 to /token.
    let (status, text) = http(t.port, "GET", "/", &[], None, None).await;
    assert_eq!(status, 303);
    assert!(
        text.to_lowercase().contains("location: /token"),
        "must redirect to paste page, got: {text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_cookie_passes_through() {
    let t = app().await;
    let c = t.cookie();
    let (status, _) = http(t.port, "GET", "/", &[], None, Some(&c)).await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn post_without_cookie_is_403() {
    let t = app().await;

    let (status, _) = http(t.port, "POST", "/setup/policy", &[], Some(""), None).await;
    assert_eq!(
        status, 403,
        "mutations without a token must be refused, not redirected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn token_param_sets_cookie_and_strips_from_url() {
    let t = app().await;

    // GET /?token=X \u{2192} 303 with Set-Cookie, Location strips the token.
    let path = format!("/?token={}", t.token);
    let (status, text) = http(t.port, "GET", &path, &[], None, None).await;
    assert_eq!(status, 303);
    assert!(
        text.to_ascii_lowercase()
            .contains("set-cookie: chaperone_ui="),
        "must set cookie"
    );
    // Location must not contain the token param.
    let loc_line = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .unwrap();
    assert!(
        !loc_line.contains("token="),
        "token must be stripped from redirect URL"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn paste_page_renders_without_token() {
    let t = app().await;

    // /token is the one path served without a token.
    let (status, page) = http(t.port, "GET", "/token", &[], None, None).await;
    assert_eq!(status, 200);
    assert!(page.contains("Chaperone UI access"));
    assert!(page.contains("chaperone ui-token show"));
}

#[tokio::test(flavor = "multi_thread")]
async fn paste_submit_valid_token_sets_cookie_and_redirects() {
    let t = app().await;

    let (status, text) = http(
        t.port,
        "POST",
        "/token",
        &[],
        Some(&form(&[("token", &t.token), ("next", "/secrets")])),
        None,
    )
    .await;
    assert_eq!(status, 303);
    assert!(
        text.to_ascii_lowercase()
            .contains("set-cookie: chaperone_ui="),
        "must set cookie on success"
    );
    assert!(
        text.to_ascii_lowercase().contains("location: /secrets"),
        "must redirect to next"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn paste_submit_invalid_token_rejects() {
    let t = app().await;

    let (status, text) = http(
        t.port,
        "POST",
        "/token",
        &[],
        Some(&form(&[("token", "not-the-token"), ("next", "/secrets")])),
        None,
    )
    .await;
    assert_eq!(status, 303);
    assert!(
        text.to_lowercase().contains("location: /token?err="),
        "must redirect back with error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn open_redirect_rejected() {
    let t = app().await;

    let (status, text) = http(
        t.port,
        "POST",
        "/token",
        &[],
        Some(&form(&[("token", &t.token), ("next", "//evil.example")])),
        None,
    )
    .await;
    assert_eq!(status, 303);
    // Must redirect to /, not to the evil URL.
    let loc_line = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .unwrap();
    assert!(
        loc_line.contains("location: /"),
        "open redirect must be neutralized"
    );
    assert!(!loc_line.contains("evil"));
}

// ---------- D40: loopback guard (layered with token) ----------

#[tokio::test(flavor = "multi_thread")]
async fn foreign_host_still_403_even_with_valid_cookie() {
    let t = app().await;
    let c = t.cookie();

    // The Host/Origin guard is the OUTER layer: even with a valid cookie,
    // a foreign Host is refused before the token gate even runs.
    let (status, _) = http(
        t.port,
        "GET",
        "/",
        &[("Host", "evil.example")],
        None,
        Some(&c),
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_origin_post_403_even_with_cookie() {
    let t = app().await;
    let c = t.cookie();

    let host = format!("127.0.0.1:{}", t.port);
    let (status, _) = http(
        t.port,
        "POST",
        "/setup/policy",
        &[("Host", host.as_str()), ("Origin", "http://evil.example")],
        Some(""),
        Some(&c),
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn matching_origin_and_cookie_passes() {
    let t = app().await;
    let c = t.cookie();
    let host = format!("127.0.0.1:{}", t.port);
    let origin = format!("http://127.0.0.1:{}", t.port);

    let (status, _) = http(
        t.port,
        "POST",
        "/setup/policy",
        &[("Host", host.as_str()), ("Origin", origin.as_str())],
        Some(""),
        Some(&c),
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
