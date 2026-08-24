//! Phase 12 (post-v1) acceptance tests: the db-scram mechanism.
//!
//! GATED: these drive a REAL PostgreSQL server. Set CHAPERONE_TEST_PG to a
//! libpq-style connection string for the test database, e.g.
//!
//! ```text
//! CHAPERONE_TEST_PG=postgres://pgtest:pgpass@localhost:5432/pgtest \
//!   cargo test -p chaperone-gateway-core --test db_scram
//! ```
//!
//! CI runs this against a `postgres:16` service container; without the env
//! var every test reports SKIP and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chaperone_audit::{AuditKey, AuditWriter};
use chaperone_gateway_core::{AlwaysTimeoutGate, Gateway, GatewayConfig};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:db-1";

fn pg_uri() -> Option<String> {
    std::env::var("CHAPERONE_TEST_PG")
        .ok()
        .filter(|s| !s.is_empty())
}

fn target_uri() -> String {
    // Rewrite credentials out of the env string into our own shape: the
    // password lives in the vault, not the URI.
    let raw = pg_uri().unwrap();
    // postgres://user:password@host:port/db  ->  postgres://user@host:port/db
    if let Some(after_scheme) = raw.strip_prefix("postgres://")
        && let Some((userinfo, rest)) = after_scheme.split_once('@')
        && let Some((user, _pw)) = userinfo.split_once(':')
    {
        return format!("postgres://{user}@{rest}");
    }
    raw
}

fn db_password() -> String {
    let raw = pg_uri().unwrap();
    raw.strip_prefix("postgres://")
        .and_then(|r| r.split('@').next())
        .and_then(|u| u.split_once(':'))
        .map(|(_, pw)| pw.to_owned())
        .unwrap_or_default()
}

fn db_user() -> String {
    let raw = pg_uri().unwrap();
    raw.strip_prefix("postgres://")
        .and_then(|r| r.split('@').next())
        .and_then(|u| u.split(':').next())
        .unwrap_or("postgres")
        .to_owned()
}

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
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

    let signer = SigningKey::from_bytes(&[71u8; 32]);
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

    let mut store = LocalVault::create(
        &dir.path().join("v.bin"),
        Zeroizing::new("db-pass".to_owned()),
    )
    .unwrap();
    store
        .set("prod/db/password", SecretString::new(db_password()))
        .unwrap();
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_key = AuditKey::generate();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, audit_key.clone()).unwrap());

    let mut gw = Gateway::new(
        attestor,
        Policy::from_toml("[[rule]]\neffect = \"allow\"\n").unwrap(),
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        GatewayConfig::default(),
    )
    .unwrap();
    gw.with_session_backend("db-scram", Arc::new(chaperone_gateway_core::DbBackend));

    Spine {
        gateway: gw,
        signer,
        audit_path,
        audit_key,
        _dir: dir,
    }
}

impl Spine {
    fn db_intent(&self, nonce: &str, extra: Value) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": format!("m-{nonce}"), "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "target": {"uri": target_uri(), "label": "pg-test"},
            "mechanism": "db-scram",
            "cred_ref": "local://prod/db/password",
            "operation": {"engine": "postgres", "username": db_user()},
        });
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                env["operation"][k.as_str()] = v.clone();
            }
        }
        sign_envelope(&self.signer, &mut env);
        env
    }

    fn signed_frame(&self, kind: &str, handle: &str, nonce: &str, input_b64: &str) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": format!("f-{nonce}"), "type": kind,
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "session_handle": handle,
        });
        if !input_b64.is_empty() {
            use base64::Engine as _;
            env["input_b64"] = json!(base64::engine::general_purpose::STANDARD.encode(input_b64));
        }
        sign_envelope(&self.signer, &mut env);
        env
    }
}

#[tokio::test]
async fn one_shot_query_returns_rows_via_scram() {
    let Some(_uri) = pg_uri() else {
        eprintln!("SKIP: CHAPERONE_TEST_PG not set");
        return;
    };
    let spine = build().await;
    let resp = spine
        .gateway
        .handle_message(&spine.db_intent("q1", json!({"statement": "select 41 + 1 as answer"})))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");
    let rows = resp["rows"].as_array().expect("rows array");
    let found_42 = rows
        .iter()
        .any(|r| r.as_array().and_then(|a| a.first()).and_then(Value::as_str) == Some("42"));
    assert!(found_42, "select 41+1 must yield 42; rows={rows:?}");
    assert_eq!(resp["decision"], "allow");

    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(
        !journal.contains(&db_password()),
        "SCRAM secret never reaches journal"
    );
}

#[tokio::test]
async fn parameterized_query_binds_as_text() {
    let Some(_uri) = pg_uri() else {
        eprintln!("SKIP");
        return;
    };
    let spine = build().await;
    let resp = spine
        .gateway
        .handle_message(&spine.db_intent(
            "q2",
            json!({
                "statement": "select $1::text as greeting",
                "params": ["hola"],
            }),
        ))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");
    let rendered = resp.to_string();
    assert!(rendered.contains("hola"), "{rendered}");
}

#[tokio::test]
async fn session_drive_by_sql_frames() {
    let Some(_uri) = pg_uri() else {
        eprintln!("SKIP");
        return;
    };
    let spine = build().await;
    let resp = spine
        .gateway
        .handle_message(&spine.db_intent("s1", json!({})))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");
    let handle = resp["session_handle"].as_str().unwrap().to_owned();

    let cmd = spine.signed_frame("session.command", &handle, "c1", "select 'live' as status;");
    let resp = spine.gateway.handle_message(&cmd).await;
    assert_eq!(resp["type"], "session.output", "{resp}");
    // Output chunks arrive base64url-encoded (D24 batching); decode and
    // inspect as data.
    use base64::Engine as _;
    let decoded = resp["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["data_b64"].as_str())
        .map(|b| base64::engine::general_purpose::STANDARD.decode(b).unwrap())
        .fold(String::new(), |acc, b| {
            acc + &String::from_utf8(b).unwrap_or_default()
        });
    assert!(decoded.contains("live"), "decoded={decoded:?} resp={resp}");

    let close = spine.signed_frame("session.close", &handle, "x1", "");
    let resp = spine.gateway.handle_message(&close).await;
    assert_eq!(resp["type"], "session.closed", "{resp}");

    let report = verify_file_checked(&spine).await;
    assert!(report.error.is_none(), "{:?}", report.error);
}

async fn verify_file_checked(spine: &Spine) -> chaperone_audit::Report {
    chaperone_audit::verify_file(&spine.audit_path, &spine.audit_key.verifying_key()).unwrap()
}
