//! REV-E2E: prove `revoke` is effective immediately through a LIVE gateway.
//!
//! The claim (ARCH-SPEC §2.2): "a revoked key fails at step 1 of
//! verification." Until now that was enforced by a unit-level
//! `revoked_at.is_none()` filter (`crates/identity/src/enrollment.rs:201`,
//! `lookup()`), never proven through a live gateway with signed intents.
//!
//! One run: enroll → baseline positive (signed intent verifies) → revoke →
//! baseline negative (the SAME signed intent is refused at step 1 — the
//! unknown-key error, BEFORE any policy evaluation).
//!
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! ANTI-GAMING (the comment the work order requires): this test's negative
//! baseline goes RED if the production revocation filter is deleted —
//! delete the `.filter(|stored| stored.record.revoked_at.is_none())` in
//! `EnrollmentStore::lookup` (`crates/identity/src/enrollment.rs:201`,
//! the step-1 verification path) and step 4 finds the key again, signature
//! verification succeeds, and the request proceeds to policy instead of
//! being refused. No other deletion turns this test red.

use chaperone_gateway_core::Gateway;
use chaperone_identity::{EnrollmentStore, ReplayCache};
use chaperone_vault::{LocalVault, SecretString};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use serde_json::json;
use std::sync::Arc;

const AGENT: &str = "agent:rev-e2e";
const SPONSOR_ID: &str = "sponsor:rev-e2e";
const SPONSOR_NAME: &str = "Rev E2E";
const SENTINEL: &str = "rev-e2e-vault-token";

/// A live TCP listener (accept-and-drop) so the http-bearer outbound has a
/// real endpoint to connect to; returns the URL. The revocation test only
/// needs the request to REACH the policy decision — it never asserts on the
/// target's response.
async fn spawn_listener() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Read the request head, answer 200 with an empty JSON body: the
            // revocation test only needs the outbound call to COMPLETE.
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}")
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}/x")
}

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
    enrollment: Arc<EnrollmentStore>,
    _dir: tempfile::TempDir,
}

async fn build() -> Spine {
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
    let attestor = chaperone_identity::Attestor::new(
        enrollment.clone(),
        Arc::new(ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp()).unwrap()),
        chaperone_identity::IdentityConfig { max_skew_secs: 30 },
    );

    let mut store = LocalVault::create(
        &dir.path().join("v.bin"),
        "passphrase",
        Zeroizing::new("probe-pass".into()),
    )
    .unwrap();
    store
        .set("prod/probe/token", SecretString::new(SENTINEL.to_owned()))
        .unwrap();
    let mut router = chaperone_vault::VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(
        chaperone_audit::AuditWriter::open(&audit_path, chaperone_audit::AuditKey::generate())
            .unwrap(),
    );
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
    [[rule]]
    name = "rev-e2e may call the listener"
    effect = "allow"
    agent_id = "agent:rev-e2e"
    cred_ref = "local://prod/probe/token"
    target_uri = "http://127.0.0.1:*/*"
"#,
    )
    .unwrap();

    let gateway = Gateway::new(
        attestor,
        chaperone_policy::Policy::from_toml(&std::fs::read_to_string(&policy_path).unwrap())
            .unwrap(),
        router,
        audit,
        Arc::new(chaperone_gateway_core::AlwaysTimeoutGate),
        chaperone_gateway_core::GatewayConfig::default(),
    )
    .unwrap();

    Spine {
        gateway,
        signer,
        enrollment,
        _dir: dir,
    }
}

impl Spine {
    fn bearer_intent(&self, nonce: &str, target_uri: &str) -> serde_json::Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1",
            "msg_id": format!("rev-{nonce}"),
            "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "target": {"uri": target_uri, "label": "rev e2e"},
            "mechanism": "http-bearer",
            "cred_ref": "local://prod/probe/token",
            "operation": {"method": "GET", "headers": {"Accept": "application/json"}},
        });
        chaperone_protocol::testutil::sign_envelope(&self.signer, &mut env);
        env
    }
}

/// ANTI-GAMING: the negative baseline below goes RED if the production
/// revocation filter is deleted — remove
/// `.filter(|stored| stored.record.revoked_at.is_none())` from
/// `EnrollmentStore::lookup` (crates/identity/src/enrollment.rs:201, the
/// step-1 verification path) and the revoked key is found again, signature
/// verification succeeds, and the request proceeds to policy instead of
/// being refused at step 1. No other deletion turns this test red.
#[tokio::test]
async fn revoked_agent_fails_at_step1_immediately() {
    let spine = build().await;
    let url = spawn_listener().await;

    // Baseline positive: the signed intent verifies end-to-end.
    let before = spine
        .gateway
        .handle_message(&spine.bearer_intent("pre", url.as_str()))
        .await;
    assert_eq!(before["type"], "result", "baseline must verify: {before}");
    assert_eq!(before["status"], 200, "{before}");

    // Revoke.
    let now = chaperone_gateway_core::chaperone_time_now();
    let revoked = spine
        .enrollment
        .revoke(
            AGENT,
            &now.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        )
        .unwrap();
    assert!(revoked, "revoke of a live agent must report true");

    // Baseline negative: the SAME signed intent is now refused at step 1 —
    // the unknown-key error, before any policy decision.
    let after = spine
        .gateway
        .handle_message(&spine.bearer_intent("post", url.as_str()))
        .await;
    assert_eq!(after["type"], "error", "{after}");
    let code = after["code"].as_str().unwrap_or("");
    // A revoked agent resolves to NO key at step 1 (lookup filters
    // revoked_at), so the gateway reports E_UNKNOWN_AGENT — the honest
    // claim "this agent presents no verifiable key", before any policy
    // evaluation.
    assert_eq!(
        code, "E_UNKNOWN_AGENT",
        "a revoked key must fail at step 1 (unknown-key), got: {after}"
    );
}

/// Repeat-friendly variant (fresh spine per case) proving the ordering
/// negative-then-positive also holds — guards against the filter being
/// order-sensitive (e.g. caching the lookup result across requests).
#[tokio::test]
async fn revoked_before_first_use_is_refused() {
    let spine = build().await;
    let url = spawn_listener().await;
    let now = chaperone_gateway_core::chaperone_time_now();
    spine
        .enrollment
        .revoke(
            AGENT,
            &now.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        )
        .unwrap();
    let resp = spine
        .gateway
        .handle_message(&spine.bearer_intent("first", url.as_str()))
        .await;
    assert_eq!(resp["type"], "error", "{resp}");
    assert_eq!(resp["code"], "E_UNKNOWN_AGENT", "{resp}");
}

/// B2-FIX correction (Heph, PR #90 review): NO CA mint path exists in the
/// repo yet — there is no `ca://` provider wired to the gateway intent
/// path, so this test does NOT and CANNOT prove revocation-on-mint. With
/// the revocation filter deleted, this request fails at credential
/// resolution (E_CRED_UNRESOLVED, "no provider for scheme ca"), not at a
/// mint. What it IS: a third step-1 refusal using a `ca://` cred_ref,
/// confirming the revoked-agent refusal is scheme-independent (the filter
/// runs before any scheme routing). Real revocation-on-mint coverage must
/// wait until a mint path exists. ANTI-GAMING: same deletion as the
/// primary test — the filter removed, this request resolves and proceeds.
#[tokio::test]
async fn revoked_agent_ca_mint_is_refused() {
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
    let attestor = chaperone_identity::Attestor::new(
        enrollment.clone(),
        Arc::new(ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp()).unwrap()),
        chaperone_identity::IdentityConfig { max_skew_secs: 30 },
    );

    let mut store = LocalVault::create(
        &dir.path().join("v.bin"),
        "passphrase",
        Zeroizing::new("probe-pass".into()),
    )
    .unwrap();
    store
        .set("prod/probe/token", SecretString::new(SENTINEL.to_owned()))
        .unwrap();
    let mut router = chaperone_vault::VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit = Arc::new(
        chaperone_audit::AuditWriter::open(
            &dir.path().join("audit.jsonl"),
            chaperone_audit::AuditKey::generate(),
        )
        .unwrap(),
    );
    let policy = r#"
    [[rule]]
    name = "rev-e2e may mint"
    effect = "allow"
    agent_id = "agent:rev-e2e"
    cred_ref = "ca://rev-host"
    target_uri = "http://127.0.0.1:*/*"
"#;
    let gateway = Gateway::new(
        attestor,
        chaperone_policy::Policy::from_toml(policy).unwrap(),
        router,
        audit,
        Arc::new(chaperone_gateway_core::AlwaysTimeoutGate),
        chaperone_gateway_core::GatewayConfig::default(),
    )
    .unwrap();

    // Revoke BEFORE the mint.
    enrollment.revoke(AGENT, &rfc()).unwrap();

    // A ca:// intent from the revoked agent: step 1 (identity verify) fails
    // first — the revoked agent presents no verifying key at all. (No mint
    // path exists yet; see the header comment.)
    let url = spawn_listener().await;
    let now2 = chaperone_gateway_core::chaperone_time_now();
    let mut env = json!({
        "chaperone": "0.1",
        "msg_id": "rev-ca-1",
        "type": "intent",
        "agent_id": AGENT,
        "issued_at": now2.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": "ca-1",
        "target": {"uri": url, "label": "rev e2e"},
        "mechanism": "http-bearer",
        "cred_ref": "ca://rev-host",
        "operation": {"method": "GET", "headers": {"Accept": "application/json"}},
    });
    chaperone_protocol::testutil::sign_envelope(&signer, &mut env);

    let resp = gateway.handle_message(&env).await;
    assert_eq!(resp["type"], "error", "{resp}");
    assert_eq!(
        resp["code"], "E_UNKNOWN_AGENT",
        "a revoked agent must fail at step 1 before any mint: {resp}"
    );
}
