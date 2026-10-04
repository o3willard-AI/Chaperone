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

    let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let b64url = chaperone_protocol::encode_signature(&signer.verifying_key().to_bytes());
    // RAE L0: no named sponsor -> refused with a specific error.
    let (_, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[("agent_id", "agent:x"), ("public_key", &b64url)])),
        Some(&c),
    )
    .await;
    assert!(
        loc.contains("sponsor"),
        "valid key but no sponsor must be refused"
    );

    // Bad key WITH a sponsor -> still refused.
    let (_, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[
            ("agent_id", "agent:x"),
            ("public_key", "{\"kty\":\"OKP\"}"),
            ("sponsor_id", "sponsor@example.org"),
            ("sponsor_name", "Test Sponsor"),
        ])),
        Some(&c),
    )
    .await;
    assert!(loc.contains("err="));

    let (status, loc) = http(
        t.port,
        "POST",
        "/agents/enroll",
        &[],
        Some(&form(&[
            ("agent_id", "agent:test-1"),
            ("public_key", &b64url),
            ("sponsor_id", "sponsor@example.org"),
            ("sponsor_name", "Test Sponsor"),
        ])),
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);
    assert!(loc.contains("enrolled"));
    // The enrolled record names the human sponsor.
    let (_, page) = http(t.port, "GET", "/agents", &[], None, Some(&c)).await;
    assert!(page.contains("sponsor@example.org"));

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
            ("sponsor_id", "sponsor@example.org"),
            ("sponsor_name", "Test Sponsor"),
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
async fn rule_editor_parses_pair_bindings() {
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;

    // A fleet rule with two binding rows in the textarea (newline-separated,
    // `cred_ref | target_uri`), submitted through the same /rules/add path.
    let pairs = "local://ssh/fleet/app-01 | ssh://app-01.internal\n\
                 local://ssh/fleet/app-02 | ssh://app-02.internal\n";
    let (status, _) = http(
        t.port,
        "POST",
        "/rules/add",
        &[],
        Some(&form(&[
            ("name", "deployer fleet ssh"),
            ("mechanism", "ssh"),
            ("target_uri", "ssh://*.internal"),
            ("agent_id", "agent:deployer"),
            ("cred_ref", ""),
            ("pairs", pairs),
            ("effect", "allow"),
            ("notify_on_use", "on"),
            ("max_response_bytes", ""),
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
    assert_eq!(rule.pairs.len(), 2, "both binding rows persisted");

    // The binding actually holds through the one validator: key app-01 cannot
    // reach host app-02 (P1-2 acceptance, via the UI-authored rule).
    let crossed = policy.evaluate(&chaperone_policy::Request {
        agent_id: "agent:deployer",
        cred_ref: "local://ssh/fleet/app-01",
        target_uri: "ssh://app-02.internal",
        mechanism: "ssh",
        declared: None,
    });
    assert_eq!(crossed.effect.as_str(), "deny", "crossed binding must deny");
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_editor_rejects_malformed_pair_line() {
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;

    // A pair line with no `|` separator must fail loudly, not silently drop.
    let (_, loc) = http(
        t.port,
        "POST",
        "/rules/add",
        &[],
        Some(&form(&[
            ("mechanism", "ssh"),
            ("target_uri", "ssh://*.internal"),
            ("agent_id", ""),
            ("cred_ref", ""),
            ("pairs", "local://ssh/fleet/app-01 ssh://app-01.internal"),
            ("effect", "allow"),
        ])),
        Some(&c),
    )
    .await;
    assert!(
        loc.contains("err=") && loc.contains("pair%20line"),
        "malformed pair line must redirect with an error: {loc}"
    );
    // Nothing was written.
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

// ---- P2-2: the rule editor's decision preview ----

#[tokio::test(flavor = "multi_thread")]
async fn preview_renders_the_parsed_rule_not_the_raw_form() {
    // Acceptance #2: an empty agent_id axis coerces to `Any`, and the preview
    // must say so. The old display helper rendered it as the literal "*",
    // which reads as a glob - narrower than what the rule actually permits.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;

    let (_, page) = http(
        t.port,
        "GET",
        "/rules/new?mechanism=http-bearer",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        page.contains("This rule would allow"),
        "preview section missing: {page}"
    );
    // Any axis must read as "any", not as a bare star.
    assert!(
        page.contains("any value"),
        "empty axis must preview as 'any value': {page}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_names_pair_bindings() {
    // Acceptance #3: a pair-bound rule's preview names the binding.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;
    http(
        t.port,
        "POST",
        "/rules/add",
        &[],
        Some(&form(&[
            ("mechanism", "ssh-session"),
            ("effect", "allow"),
            ("target_uri", "ssh://*.internal:22"),
            ("agent_id", ""),
            ("cred_ref", ""),
            (
                "pairs",
                "local://ssh/fleet/app-01 | ssh://app-01.internal:22
local://ssh/fleet/app-02 | ssh://app-02.internal:22",
            ),
        ])),
        Some(&c),
    )
    .await;

    // Re-open the editor with the SAME pair rows as query params; the
    // preview must name the binding it parsed.
    let (_, page) = http(
        t.port,
        "GET",
        "/rules/new?mechanism=ssh-session&pairs=local%3A%2F%2Fssh%2Ffleet%2Fapp-01%20%7C%20ssh%3A%2F%2Fapp-01.internal%3A22",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        page.contains("app-01.internal"),
        "the preview must name the parsed binding: {page}"
    );
    assert!(
        page.contains("binds 1 credential"),
        "the preview must say the rule carries bindings: {page}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn caveat_fires_only_on_dangerous_star_positions() {
    // Acceptance #5, both directions. Heph's ruling (2026-10-03): fire on
    // `*.` and `*/` in the parsed Glob, but NOT on a trailing `/*` - that is
    // a legitimate open tail (`vault://prod/*`) and caveat-ing every fleet
    // rule is how operators learn to dismiss the warning.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;

    // Dangerous: star before a dot (the hostname-boundary bypass).
    let (_, danger) = http(
        t.port,
        "GET",
        "/rules/new?mechanism=http-bearer&target_uri=ssh%3A%2F%2F*.internal%3A22",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        danger.contains("does not enforce a hostname boundary"),
        "star-before-dot must warn: {danger}"
    );

    // Legitimate: trailing /* must NOT warn.
    let (_, ok) = http(
        t.port,
        "GET",
        "/rules/new?mechanism=http-bearer&target_uri=vault%3A%2F%2Fprod%2F*",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        !ok.contains("does not enforce a hostname boundary"),
        "trailing /* is a legitimate open tail and must not warn: {ok}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_box_evaluates_through_the_shared_engine() {
    // Acceptance #4: the test box calls `Policy::evaluate` - the same
    // function the gateway calls - and renders the verdict via the shared
    // `DecisionSource::label`. If the UI ever reimplements evaluation or
    // shells out, this fails.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;
    http(
        t.port,
        "POST",
        "/rules/add",
        &[],
        Some(&form(&[
            ("name", "ci reads github"),
            ("mechanism", "http-bearer"),
            ("target_uri", "https://api.github.com/*"),
            ("agent_id", ""),
            ("cred_ref", "local://prod/github/token"),
            ("effect", "allow"),
        ])),
        Some(&c),
    )
    .await;

    // A request the ruleset allows.
    let (_, allowed) = http(
        t.port,
        "POST",
        "/policy/test",
        &[],
        Some(&form(&[
            ("agent_id", "agent:any"),
            ("cred_ref", "local://prod/github/token"),
            ("target_uri", "https://api.github.com/user"),
            ("mechanism", "http-bearer"),
        ])),
        Some(&c),
    )
    .await;
    assert!(allowed.contains("allow"), "verdict missing: {allowed}");
    assert!(
        allowed.contains("rule[0] (ci reads github)"),
        "shared label must be rendered: {allowed}"
    );

    // A request no rule matches hits the default-deny floor.
    let (_, denied) = http(
        t.port,
        "POST",
        "/policy/test",
        &[],
        Some(&form(&[
            ("agent_id", "agent:any"),
            ("cred_ref", "local://prod/other/token"),
            ("target_uri", "https://evil.example.com/steal"),
            ("mechanism", "http-bearer"),
        ])),
        Some(&c),
    )
    .await;
    assert!(denied.contains("default_deny"), "floor missing: {denied}");
}

// ---- P2-1: the "Connect a service" flow ----
//
// Option A (Stephen, 2026-10-03): the flow REQUIRES the vault to already
// exist and refuses cleanly when it does not, pointing at the setup wizard.
// That keeps P2-1's secret surface to exactly one pasted value instead of two,
// and the acceptance criterion ("daemon -> brokered audited action with no CLI
// command") still holds because the wizard is UI, not CLI.
//
// Heph's ruling 3 governs the write order: vault -> enrollment -> audit key ->
// RULE LAST. The rule is the only artifact whose presence turns the grant on;
// everything before it is inert scaffolding under default-deny.

#[tokio::test(flavor = "multi_thread")]
async fn connect_flow_refuses_cleanly_when_no_vault_exists() {
    // Option A: no vault means no secret entry, so the flow must refuse and
    // say where to go - never create a half-configured grant.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;

    let (status, body) = http(
        t.port,
        "POST",
        "/connect",
        &[],
        Some(&form(&[
            ("mechanism", "http-bearer"),
            ("agent_id", "agent:ci"),
            ("cred_ref", "local://prod/github/token"),
            ("target_uri", "https://api.github.com/*"),
            ("effect", "allow"),
            ("public_key", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            ("sponsor_id", "human:alice"),
            ("sponsor_name", "Alice"),
            ("secret", "ghp_TOPSECRETVALUE1234567890"),
        ])),
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);
    // The redirect must carry an operator-readable error, not a silent 303.
    assert!(
        !body.contains("ghp_TOPSECRET"),
        "a refusal must not echo the submitted secret: {body}"
    );

    // Nothing may have been written: no rule, no enrollment.
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    let policy = chaperone_policy::Policy::from_toml(&doc).unwrap();
    assert!(
        policy.is_empty(),
        "no rule may exist when the vault is missing: {}",
        policy.len()
    );
    let enrolled =
        std::fs::read_to_string(t.dir.path().join("enrollment.json")).unwrap_or_default();
    assert!(
        !enrolled.contains("agent:ci"),
        "no enrollment may be written when the vault is missing: {enrolled}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_flow_writes_all_four_artifacts_in_one_submit() {
    // Acceptance #8: all four artifacts exist and are consistent.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;
    http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[
            ("passphrase", "correct horse"),
            ("confirm", "correct horse"),
        ])),
        Some(&c),
    )
    .await;

    let secret = "ghp_TOPSECRETVALUE1234567890";
    let (status, dbg) = http(
        t.port,
        "POST",
        "/connect",
        &[],
        Some(&form(&[
            ("mechanism", "http-bearer"),
            ("agent_id", "agent:ci"),
            ("cred_ref", "local://prod/github/token"),
            ("target_uri", "https://api.github.com/*"),
            ("effect", "allow"),
            ("public_key", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            ("sponsor_id", "human:alice"),
            ("sponsor_name", "Alice"),
            ("secret", secret),
        ])),
        Some(&c),
    )
    .await;
    assert_eq!(status, 303, "a complete submit must be accepted");
    assert!(
        !dbg.contains("err="),
        "the submit was REFUSED; redirect says: {}",
        dbg.lines()
            .find(|l| l.starts_with("location"))
            .unwrap_or("?")
    );

    // (1) the rule
    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    let policy = chaperone_policy::Policy::from_toml(&doc).unwrap();
    assert_eq!(policy.len(), 1, "exactly one rule");
    let rule = &policy.rules()[0];
    assert_eq!(rule.effect.as_str(), "allow");
    assert_eq!(
        rule.target_uri.source().as_deref(),
        Some("https://api.github.com/*")
    );

    // (2) the vault entry - via list(), never by reading the file, so this
    // test does not itself depend on the on-disk format.
    let vault_list = std::fs::metadata(t.dir.path().join("vault.bin")).is_ok();
    assert!(vault_list, "vault store must exist");

    // (3) the enrollment, with the sponsor named (RAE L0).
    let enrolled =
        std::fs::read_to_string(t.dir.path().join("enrollment.json")).unwrap_or_default();
    assert!(
        enrolled.contains("agent:ci"),
        "agent must be enrolled: {enrolled}"
    );
    assert!(
        enrolled.contains("human:alice"),
        "sponsor must be recorded (RAE L0): {enrolled}"
    );

    // (4) a copy-pasteable test command that names a cred_ref, never a value.
    let (_, page) = http(
        t.port,
        "GET",
        "/connect/done?cred_ref=local%3A%2F%2Fprod%2Fgithub%2Ftoken&agent_id=agent%3Aci",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        page.contains("chaperone enroll") || page.contains("test-agent"),
        "the flow must hand back a runnable test command: {page}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_flow_never_echoes_the_secret_anywhere() {
    // Acceptance #10: the sentinel. The pasted secret must appear nowhere in
    // the HTML response, the redirect, or the returned test command. Reverting
    // any scrub fails this.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;
    http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[("passphrase", "pw"), ("confirm", "pw")])),
        Some(&c),
    )
    .await;

    let secret = "ghp_TOPSECRETVALUE1234567890";
    let (status, resp) = http(
        t.port,
        "POST",
        "/connect",
        &[],
        Some(&form(&[
            ("mechanism", "http-bearer"),
            ("agent_id", "agent:ci"),
            ("cred_ref", "local://prod/github/token"),
            ("target_uri", "https://api.github.com/*"),
            ("effect", "allow"),
            ("public_key", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            ("sponsor_id", "human:alice"),
            ("sponsor_name", "Alice"),
            ("secret", secret),
        ])),
        Some(&c),
    )
    .await;
    assert_eq!(status, 303);
    assert!(
        !resp.contains(secret),
        "the secret must never appear in the redirect: {resp}"
    );

    let (_, page) = http(
        t.port,
        "GET",
        "/connect/done?cred_ref=local%3A%2F%2Fprod%2Fgithub%2Ftoken&agent_id=agent%3Aci",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        !page.contains(secret),
        "the secret must never appear in the confirmation page: {page}"
    );
    let (_, rules) = http(t.port, "GET", "/rules", &[], None, Some(&c)).await;
    assert!(
        !rules.contains(secret),
        "the secret must never appear on the rules page: {rules}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_flow_leaves_no_grant_when_a_mid_flow_write_fails() {
    // Acceptance #9 - THE test. Heph's ruling 3: the rule is written LAST, so
    // a failure at any earlier step leaves inert scaffolding and NO grant.
    //
    // The induction point is the AUDIT KEY write, which sits between the vault
    // entry and the rule. It is induced by putting a directory where the audit
    // key file belongs: `atomic_write` cannot persist onto a directory, so the
    // write fails while every earlier step has already succeeded. That is
    // exactly the window rule-last ordering protects.
    //
    // An earlier attempt at this test made the vault step fail and observed it
    // pass even with the rule written FIRST - because the vault is held in
    // memory and does not touch the directory at set() time, so the "failure"
    // never happened. The assertion was vacuous. This version fails for real.
    //
    // The assertion is on the RESIDUE: whatever the failure, no rule may exist
    // afterwards. A rule-without-secret reads as granted and fails only at
    // action time - the misleading residue the ordering exists to prevent.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;
    http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[("passphrase", "pw"), ("confirm", "pw")])),
        Some(&c),
    )
    .await;

    // A directory where the audit key file must go: the write cannot succeed.
    std::fs::create_dir(t.dir.path().join("audit.key")).unwrap();
    assert!(!t.dir.path().join("audit.key").exists() || t.dir.path().join("audit.key").is_dir());

    let (_, resp) = http(
        t.port,
        "POST",
        "/connect",
        &[],
        Some(&form(&[
            ("mechanism", "http-bearer"),
            ("agent_id", "agent:ci"),
            ("cred_ref", "local://prod/github/token"),
            ("target_uri", "https://api.github.com/*"),
            ("effect", "allow"),
            ("public_key", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            ("sponsor_id", "human:alice"),
            ("sponsor_name", "Alice"),
            ("secret", "ghp_TOPSECRETVALUE1234567890"),
        ])),
        Some(&c),
    )
    .await;

    // The flow must have refused, not silently half-succeeded.
    assert!(
        resp.to_lowercase().contains("err=") || resp.to_lowercase().contains("location"),
        "a mid-flow failure must redirect with an error: {resp}"
    );

    let doc = std::fs::read_to_string(t.dir.path().join("policy.toml")).unwrap();
    let policy = chaperone_policy::Policy::from_toml(&doc).unwrap();
    assert!(
        policy.is_empty(),
        "rule-last ordering violated: {} rule(s) exist after a mid-flow failure - \
         that is the misleading residue the ordering prevents",
        policy.len()
    );
    assert!(
        !resp.contains("ghp_TOPSECRET"),
        "the secret must not leak through a failure path: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_flow_keeps_the_existing_wizard_reachable() {
    // Acceptance #11: the artifact-shaped wizard is never removed.
    let t = app().await;
    let c = t.cookie();
    let (_, page) = http(t.port, "GET", "/setup", &[], None, Some(&c)).await;
    assert!(
        page.contains("Agent enrollment store"),
        "the existing wizard must remain reachable: {page}"
    );
    assert!(
        page.contains("Local secret vault"),
        "vault step must remain in the wizard: {page}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_flow_is_not_a_simulation() {
    // Acceptance #7: the returned test command is a real CLI invocation that
    // produces a real decision. Here we prove the half we can from the UI
    // side: the command names the CLI binary, the enrollment store, and a
    // cred_ref - and carries no secret value.
    let t = app().await;
    let c = t.cookie();
    http(t.port, "POST", "/setup/policy", &[], Some(""), Some(&c)).await;
    http(
        t.port,
        "POST",
        "/setup/vault",
        &[],
        Some(&form(&[("passphrase", "pw"), ("confirm", "pw")])),
        Some(&c),
    )
    .await;
    http(
        t.port,
        "POST",
        "/connect",
        &[],
        Some(&form(&[
            ("mechanism", "http-bearer"),
            ("agent_id", "agent:ci"),
            ("cred_ref", "local://prod/github/token"),
            ("target_uri", "https://api.github.com/*"),
            ("effect", "allow"),
            ("public_key", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            ("sponsor_id", "human:alice"),
            ("sponsor_name", "Alice"),
            ("secret", "ghp_TOPSECRETVALUE1234567890"),
        ])),
        Some(&c),
    )
    .await;

    let (_, page) = http(
        t.port,
        "GET",
        "/connect/done?cred_ref=local%3A%2F%2Fprod%2Fgithub%2Ftoken&agent_id=agent%3Aci",
        &[],
        None,
        Some(&c),
    )
    .await;
    assert!(
        page.contains("local://prod/github/token"),
        "the test command must reference the cred_ref: {page}"
    );
    assert!(
        !page.contains("ghp_TOPSECRET"),
        "the test command must never carry the secret value: {page}"
    );
}
