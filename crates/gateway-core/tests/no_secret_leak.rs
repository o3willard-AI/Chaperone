//! `no_secret_leak` — the falsifiable form of the README's central claim
//! (P0-2): *"without any credential ever entering the agent's context,
//! transport, or logs."*
//!
//! This is the test we point a skeptical buyer at. It does not assert an
//! architecture; it asserts an observable negative against a **hostile,
//! reflecting target** — the httpbin.org/headers case, where the endpoint
//! echoes the received `Authorization` header back into BOTH a response header
//! and the response body. A credential broker that merely "doesn't log the
//! secret" passes against a well-behaved target; it fails here unless the
//! relay path actively scrubs (P0-1).
//!
//! Surfaces asserted (per the S-2 / S-3 rulings):
//!
//! - agent-facing response frame — mechanically asserted, all platforms.
//! - audit chain records (journal) — mechanically asserted, all platforms.
//! - error responses — mechanically asserted, all platforms.
//! - policy file — mechanically asserted, all platforms.
//! - events feed — asserted on every platform. P1-1 item 3 gave Windows a
//!   real owner-only named-pipe transport (D44), so the former S-2
//!   "SKIPPED-WITH-RECORD on Windows" posture and the stub's
//!   loud-failure-string assertion are both gone: surface 4 is now mechanically
//!   asserted everywhere, and the S-2 skip list is empty.
//! - outbound wire — asserted EXACTLY-ONE: the target proves it received the
//!   real credential, so the test would fail if injection silently stopped.
//! - gateway stdout/stderr — the http injection path emits no diagnostics by
//!   construction; the `http_path_emits_no_diagnostics` guard below fails the
//!   build if that invariant is ever broken.
//!
//! Run it:
//! ```text
//! cargo test --test no_secret_leak
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chaperone_audit::{AuditKey, AuditWriter};
use chaperone_gateway_core::{AlwaysTimeoutGate, Gateway, GatewayConfig};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:leak-probe";
const SPONSOR_ID: &str = "human@example.org";
const SPONSOR_NAME: &str = "Pat Human";

/// A distinctive high-entropy sentinel — exactly what P0-2 prescribes, so a
/// stray match anywhere is unambiguous. Not a real credential, never a prefix
/// of one.
const SENTINEL: &str = "ZZ-sentinel-9f3aC7e1B2d4-NOT-A-REAL-CREDENTIAL";

/// A reflecting target: records the `Authorization` header it received (the
/// outbound-wire proof) and echoes it back into a response header AND the body
/// (the hostile reflection P0-1 must scrub).
#[derive(Default)]
struct Reflector {
    received_auth: Mutex<Option<String>>,
}

impl Reflector {
    fn received(&self) -> Option<String> {
        self.received_auth.lock().unwrap().clone()
    }
}

async fn spawn_reflector(r: Arc<Reflector>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let r = Arc::clone(&r);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let header_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = find(&buf, b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                // Capture the Authorization value the gateway injected.
                let mut auth = String::new();
                for line in head.lines() {
                    if let Some((name, value)) = line.split_once(':')
                        && name.trim().eq_ignore_ascii_case("authorization")
                    {
                        auth = value.trim().to_owned();
                    }
                }
                *r.received_auth.lock().unwrap() = Some(auth.clone());

                // Reflect it back: in a response header AND in the JSON body.
                let body = serde_json::to_vec(&json!({
                    "reflected_authorization": auth,
                    "note": "hostile echo endpoint",
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Reflected-Auth: {auth}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
    audit_path: std::path::PathBuf,
    policy_path: std::path::PathBuf,
    audit_key: AuditKey,
    _dir: tempfile::TempDir,
}

async fn build(vault_token: &str, events_path: Option<&std::path::Path>) -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };

    let signer = SigningKey::from_bytes(&[82u8; 32]);
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
        Zeroizing::new("probe-pass".into()),
    )
    .unwrap();
    store
        .set(
            "prod/probe/token",
            SecretString::new(vault_token.to_owned()),
        )
        .unwrap();
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_key = AuditKey::generate();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, audit_key.clone()).unwrap());

    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, POLICY).unwrap();

    // `mut` is exercised only on unix (with_event_hub below); on Windows the
    // events-feed surface is skipped-with-record (S-2), so the binding stays
    // unmutated. Scoped allow rather than a cfg-duplicated construction.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut gateway = Gateway::new(
        attestor,
        Policy::from_toml(POLICY).unwrap(),
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        GatewayConfig::default(),
    )
    .unwrap();

    if let Some(path) = events_path {
        // P1-1 item 3: the feed has a Windows transport (named pipe, D44),
        // so the hub spawns — and surface 4 is asserted — on every platform.
        let hub = chaperone_gateway_core::EventHub::spawn(path).unwrap();
        gateway.with_event_hub(hub);
    }

    Spine {
        gateway,
        signer,
        audit_path,
        policy_path,
        audit_key,
        _dir: dir,
    }
}

const POLICY: &str = r#"
    [[rule]]
    name = "leak probe may call the local reflector"
    effect = "allow"
    agent_id = "agent:leak-probe"
    cred_ref = "local://prod/probe/token"
    target_uri = "http://127.0.0.1:*/*"
"#;

impl Spine {
    fn bearer_intent(&self, nonce: &str, target_uri: &str) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": format!("leak-{nonce}"), "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "target": {"uri": target_uri, "label": "reflector"},
            "mechanism": "http-bearer",
            "cred_ref": "local://prod/probe/token",
            "operation": {"method": "GET", "headers": {"Accept": "application/json"}},
        });
        sign_envelope(&self.signer, &mut env);
        env
    }

    fn basic_intent(&self, nonce: &str, target_uri: &str) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": format!("leak-{nonce}"), "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "target": {"uri": target_uri, "label": "reflector"},
            "mechanism": "http-basic",
            "cred_ref": "local://prod/probe/token",
            "operation": {"method": "GET", "headers": {}, "username": "probe-bot"},
        });
        sign_envelope(&self.signer, &mut env);
        env
    }

    fn decoded_body(resp: &Value) -> String {
        resp["body_b64"]
            .as_str()
            .map(|b| base64::engine::general_purpose::STANDARD.decode(b).unwrap())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }
}

/// Reads one line from a connected events subscriber (any platform; the
/// operator-pipe facade's deadline read replaces UnixStream::set_read_timeout).
fn read_one_event_line(sub: &chaperone_transport::operator_pipe::OperatorStream) -> String {
    let timeout = std::time::Duration::from_secs(5);
    let mut buf = Vec::new();
    while let Ok(b) = sub.read_byte_timeout(timeout) {
        buf.push(b);
        if b == b'\n' {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

// ---------- the assertion ----------

/// Asserts `needle` appears in NONE of the agent-visible / persisted surfaces,
/// returning a per-surface report so a failure names the leak rather than just
/// failing. `outbound_wire` is the value the reflector actually received and is
/// asserted separately (exactly-once).
fn assert_absent_everywhere(needle: &str, resp: &Value, spine: &Spine, event_line: Option<&str>) {
    let mut leaks: Vec<&'static str> = Vec::new();

    // Surface 1: agent-facing response frame (headers, body, status, all of it).
    if resp.to_string().contains(needle) {
        leaks.push("agent-response-frame");
    }
    // The decoded body specifically (the reflection lands here).
    if Spine::decoded_body(resp).contains(needle) {
        leaks.push("agent-response-body");
    }
    // Reflected response headers specifically.
    if let Some(obj) = resp.get("headers").and_then(Value::as_object) {
        for v in obj.values() {
            if v.as_str().is_some_and(|s| s.contains(needle)) {
                leaks.push("agent-response-header");
            }
        }
    }

    // Surface 2: audit chain records.
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    if journal.contains(needle) {
        leaks.push("audit-journal");
    }

    // Surface 3: policy file.
    let policy = std::fs::read_to_string(&spine.policy_path).unwrap();
    if policy.contains(needle) {
        leaks.push("policy-file");
    }

    // Surface 4: events feed (unix). On Windows this is None and recorded as
    // skipped by the caller (S-2).
    if let Some(line) = event_line
        && line.contains(needle)
    {
        leaks.push("events-feed");
    }

    assert!(
        leaks.is_empty(),
        "SENTINEL LEAKED into agent-visible/persisted surfaces: {leaks:?}\n\
         response frame: {resp}\n\
         decoded body: {:?}\n\
         journal tail: {:?}",
        Spine::decoded_body(resp),
        journal.lines().last().unwrap_or("")
    );
}

#[tokio::test]
async fn no_secret_leak_bearer_against_reflecting_target() {
    let reflector = Arc::new(Reflector::default());
    let url = spawn_reflector(Arc::clone(&reflector)).await;

    // Events-feed subscriber (unix only). The hub binds inside build(); we
    // connect after it returns, then read the one broadcast line for our
    // decision after the call.
    let dir = tempfile::tempdir().unwrap();
    let events_path = dir.path().join("events.sock");
    let spine = build(SENTINEL, Some(&events_path)).await;

    let sub =
        chaperone_transport::operator_pipe::OperatorStream::connect(events_path.to_str().unwrap())
            .ok();

    let resp = spine
        .gateway
        .handle_message(&spine.bearer_intent("b1", &format!("{url}/echo")))
        .await;

    assert_eq!(resp["type"], "result", "{resp}");
    assert_eq!(resp["status"], 200, "{resp}");

    // Outbound wire: the reflector received the REAL credential, exactly once.
    let wire = reflector.received().expect("reflector saw no request");
    assert_eq!(
        wire,
        format!("Bearer {SENTINEL}"),
        "the real secret must reach the target on the outbound wire"
    );

    // The events-feed line: asserted on every platform since P1-1 item 3
    // gave Windows a real transport (S-2's skip list is now empty).
    let event_line = sub.as_ref().map(read_one_event_line);

    assert_absent_everywhere(SENTINEL, &resp, &spine, event_line.as_deref());

    // The scrub leaves the fixed marker, proving redaction occurred rather than
    // the reflection simply not happening.
    let body = Spine::decoded_body(&resp);
    assert!(
        body.contains("[REDACTED-CREDENTIAL]"),
        "expected the reflection to be scrubbed to the marker; body was {body:?}"
    );

    // Audit chain still verifies (the scrub didn't corrupt evidence).
    let report =
        chaperone_audit::verify_file(&spine.audit_path, &spine.audit_key.verifying_key()).unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
}

#[tokio::test]
async fn no_secret_leak_basic_base64_form_scrubbed() {
    let reflector = Arc::new(Reflector::default());
    let url = spawn_reflector(Arc::clone(&reflector)).await;
    let spine = build(SENTINEL, None).await;

    let resp = spine
        .gateway
        .handle_message(&spine.basic_intent("c1", &format!("{url}/echo")))
        .await;

    assert_eq!(resp["type"], "result", "{resp}");

    // For http-basic the wire carries `Basic <b64(user:secret)>` — the RAW
    // sentinel is NOT present in that form. Compute the reflected base64 and
    // assert IT is scrubbed (the case a raw-secret-only scan would miss).
    let wire = reflector.received().expect("reflector saw no request");
    let expected_b64 = base64::engine::general_purpose::STANDARD
        .encode(format!("probe-bot:{SENTINEL}").as_bytes());
    assert_eq!(
        wire,
        format!("Basic {expected_b64}"),
        "real basic auth on the wire"
    );

    // Neither the raw sentinel nor its base64 form may reach the agent.
    assert_absent_everywhere(SENTINEL, &resp, &spine, None);
    assert_absent_everywhere(&expected_b64, &resp, &spine, None);

    let body = Spine::decoded_body(&resp);
    assert!(
        body.contains("[REDACTED-CREDENTIAL]"),
        "expected the reflected basic credential to be scrubbed; body was {body:?}"
    );
}

/// Guards the stdout/stderr surface claim: the http injection + decision path
/// emits no diagnostics, so it cannot carry the sentinel. This re-verifies the
/// grep-based invariant the test header relies on; if a future change adds a
/// println/eprintln/log/tracing call to the http path, fail loudly here rather
/// than silently weakening the surface list.
#[test]
fn http_path_emits_no_diagnostics() {
    let http = include_str!("../../injectors/src/http.rs");
    for needle in ["println!", "eprintln!", "dbg!", "log::", "tracing::"] {
        // The only allowed occurrence is inside this guard's own needle list
        // conceptually; in the injector source there must be none outside tests.
        let outside_tests = http
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(http)
            .contains(needle);
        assert!(
            !outside_tests,
            "http injector gained a diagnostic site ({needle}) on the non-test path; \
             the no_secret_leak stdout/stderr surface claim must be re-evaluated"
        );
    }
}

/// S-3 surface: ERROR responses. A failed outbound call must carry no secret
/// material either — and as of B-4 the error path is not merely *redacted*
/// but STRUCTURALLY incapable of carrying free-form text: `InjectorError::
/// Transport` takes a `TransportError`, a closed enum of classified causes
/// whose `detail()` is a `&'static str`. There is no longer a string to
/// redact. This test still proves the observable negative end to end, because
/// a structural argument is only worth as much as the behaviour it produces.
/// Connection-refused (port 1, nothing listening) forces the E_MECHANISM path
/// with the credential already resolved and injected into
/// the request build.
#[tokio::test]
async fn no_secret_leak_in_error_response() {
    let spine = build(SENTINEL, None).await;

    let resp = spine
        .gateway
        .handle_message(&spine.bearer_intent("e1", "http://127.0.0.1:1/echo"))
        .await;

    assert_eq!(resp["code"], "E_MECHANISM", "{resp}");
    assert!(
        !resp.to_string().contains(SENTINEL),
        "sentinel leaked into an error response: {resp}"
    );
    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(
        !journal.contains(SENTINEL),
        "sentinel leaked into the audit journal on the error path"
    );
}

// NOTE (P1-1 item 3): the S-2 Windows skip and the
// `windows_eventhub_stub_strings_are_secret_free` test lived here while the
// events feed had no Windows transport. The stub is gone — the feed is a
// real owner-only named pipe (D44) — so surface 4 is asserted in the bearer
// test on every platform and the skip list is empty.

/// B-4 structural pin: the error path cannot carry free-form text.
///
/// This is the difference between S-3 option 1 (a normative sentence plus this
/// sentinel) and S-3 option 2 (B-4: the property is a type fact). Before B-4,
/// `InjectorError::Transport(String)` existed and a runtime word filter
/// stripped URLs from it on the way out. Now the variant holds a
/// `TransportError` enum, which has no payload and renders a `&'static str`.
///
/// The assertion here is deliberately weak on its own - it checks the rendered
/// text of each class - because the STRONG assertion is not expressible at
/// runtime: it is that `InjectorError::Transport("...")` does not compile.
/// Verified by running that exact probe during implementation; rustc rejected
/// it with `expected TransportError, found &str`. A future contributor who
/// tries to widen the variant back to a string will be stopped by the compiler,
/// not by a failing test.
#[test]
fn error_classes_are_closed_and_render_static_text() {
    use chaperone_injectors::TransportError as T;
    for t in [
        T::ConnectionRefused,
        T::Timeout,
        T::TlsFailure,
        T::DnsFailure,
        T::BodyReadFailed,
        T::RequestBuildFailed,
        T::AuditAppendFailed,
    ] {
        let d = t.detail();
        assert!(!d.is_empty());
        assert!(
            !d.contains("://") && !d.contains('/'),
            "no class may render a URL or path: {d:?}"
        );
    }
}

/// B-1 mint-path surface (Heph review 2026-10-05, folded in): a `ca://`
/// intent runs the full open_session path — mint happens, the SSH backend
/// then fails against an unreachable host — and the resulting error response,
/// the audit journal, and the response frame carry neither the minted cert
/// text nor the CA key material.
#[tokio::test]
async fn mint_path_never_leaks_cert_or_ca_text() {
    // Build the standard spine, then add a CA to the vault and wire the minter.
    let sentinel_cert_marker = "chaperone-mint-marker";
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let signer = SigningKey::from_bytes(&[82u8; 32]);
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
        enrollment.clone(),
        Arc::new(ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp()).unwrap()),
        IdentityConfig { max_skew_secs: 30 },
    );

    let mut store = LocalVault::create(
        &dir.path().join("v.bin"),
        "passphrase",
        Zeroizing::new("probe-pass".into()),
    )
    .unwrap();
    // The CA entry: a REAL parseable key (so mint succeeds), plus the
    // sentinel the leak assertions scan for.
    let (ca_key, ca_text) = mint_test_ca();
    store
        .set(
            "chaperone/ca/ssh",
            SecretString::new(format!("{ca_text}\n{sentinel_cert_marker}")),
        )
        .unwrap();
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, AuditKey::generate()).unwrap());
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, CA_POLICY).unwrap();

    let mut gateway = Gateway::new(
        attestor,
        Policy::from_toml(CA_POLICY).unwrap(),
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        GatewayConfig::default(),
    )
    .unwrap();
    gateway = gateway.with_ssh_ca(Arc::new(
        chaperone_gateway_core::ssh_ca_provider::SshCaProvider::new(Arc::new(
            chaperone_gateway_core::ssh_ca_gateway::GatewayCaContext {
                vault: Arc::new(VaultRouter::new()),
                local_entry_secret: Arc::new(std::sync::RwLock::new(Some(
                    chaperone_vault::SharedVault::new(ca_reopen(&dir)),
                ))),
                enrollment,
            },
        )),
    ));

    // An ssh-session intent naming ca://app-01.internal. The mint succeeds;
    // the SSH backend then fails to connect (nothing listens on :1) — which
    // is exactly the path whose error text must stay clean.
    let now2 = chaperone_gateway_core::chaperone_time_now();
    let mut env = json!({
        "chaperone": "0.1", "msg_id": "leak-ca-1", "type": "intent",
        "agent_id": AGENT,
        "issued_at": now2.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": "ca-1",
        "target": {"uri": "ssh://app-01.internal:22", "label": "fleet host"},
        "mechanism": "ssh",
        "cred_ref": "ca://app-01.internal",
        "operation": {"host": "127.0.0.1", "port": 1, "user": "deploy", "pty": false},
    });
    sign_envelope(&signer, &mut env);

    let resp = gateway.handle_message(&env).await;
    let resp_text = resp.to_string();
    let journal = std::fs::read_to_string(&audit_path).unwrap();

    // The cert (minted or not) and the CA entry text must not appear in:
    // the response frame, or the audit journal.
    for surface in [resp_text.as_str(), journal.as_str()] {
        assert!(
            !surface.contains(sentinel_cert_marker),
            "CA vault text must never reach a surface: {surface}"
        );
        assert!(
            !surface.contains("ssh-ed25519-cert-v01@openssh.com"),
            "cert text must never reach a surface: {surface}"
        );
    }
    // The failure is honest and classified (B-4 discipline), not a leak.
    assert!(
        resp["type"] == "error",
        "an unreachable host must yield an error frame: {resp}"
    );
    let _ = ca_key;
}

fn mint_test_ca() -> (russh::keys::PrivateKey, String) {
    use rand_core::RngCore as _;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let kp = russh::keys::ssh_key::private::Ed25519Keypair {
        public: russh::keys::ssh_key::public::Ed25519PublicKey(signing.verifying_key().to_bytes()),
        private: russh::keys::ssh_key::private::Ed25519PrivateKey::from_bytes(&seed),
    };
    let key = russh::keys::PrivateKey::from(kp);
    let text = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    (key, text)
}

fn ca_reopen(dir: &tempfile::TempDir) -> chaperone_vault::LocalVault {
    chaperone_vault::LocalVault::open(
        &dir.path().join("v.bin"),
        Zeroizing::new("probe-pass".into()),
    )
    .unwrap()
}

const CA_POLICY: &str = r#"
    [[rule]]
    name = "leak probe may ssh via ca"
    effect = "allow"
    agent_id = "agent:leak-probe"
    cred_ref = "ca://app-01.internal"
    target_uri = "ssh://app-01.internal:*"
    mechanism = "ssh"
"#;
