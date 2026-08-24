//! Phase 9 acceptance tests (docs/PLAN.md M9), gateway-side.
//!
//! Drives the REAL `chaperone-helper` binary end-to-end through the
//! gateway's local-privilege mechanism:
//! - allowlisted command runs unattended (policy allow + pinned);
//! - non-pinned command is FORCE-CONFIRMED: with the timeout gate it fails
//!   closed without spawning anything;
//! - with no helper configured at all, the mechanism answers E_MECHANISM.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use chaperone_audit::{AuditKey, AuditWriter};
use chaperone_gateway_core::{
    AlwaysTimeoutGate, Gateway, GatewayConfig, LocalPrivBackend, PrivilegeAllowlist,
};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:priv-1";

fn helper_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHAPERONE_HELPER_BIN") {
        return Some(PathBuf::from(p));
    }
    // Workspace target dir relative to this crate's manifest.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|w| w.join("target/debug/chaperone-helper"));
    workspace.filter(|p| p.exists())
}

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
    audit_path: PathBuf,
    #[allow(dead_code)] // held so the writer's key outlives the run
    audit_key: AuditKey,
    _dir: tempfile::TempDir,
}

async fn build(privilege: bool) -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };

    let signer = SigningKey::from_bytes(&[31u8; 32]);
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
        Zeroizing::new("priv-pass".to_owned()),
    )
    .unwrap();
    store
        .set(
            "sudo",
            SecretString::new("unused-for-nopasswd-helper".into()),
        )
        .unwrap();
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_key = AuditKey::generate();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditWriter::open(&audit_path, audit_key.clone()).unwrap());

    let policy = Policy::from_toml("[[rule]]\neffect = \"allow\"\n").unwrap();

    let mut gw = Gateway::new(
        attestor,
        policy,
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        GatewayConfig::default(),
    )
    .unwrap();

    if privilege {
        let bin = helper_bin().expect("helper binary must be built");
        gw.with_session_backend(
            "local-privilege",
            Arc::new(LocalPrivBackend::new(
                vec![bin.display().to_string()],
                dir.path().join("allow.toml"),
            )),
        );
        let al_text = "[[allow]]\ncommand = \"/bin/echo\"\nargs = [\"hello\"]\n";
        std::fs::write(dir.path().join("allow.toml"), al_text).unwrap();
        gw.set_privilege_allowlist(
            PrivilegeAllowlist::load(&dir.path().join("allow.toml")).unwrap(),
        );
    }

    Spine {
        gateway: gw,
        signer,
        audit_path,
        audit_key,
        _dir: dir,
    }
}

impl Spine {
    fn priv_intent(&self, nonce: &str, command: &str, args: &[&str]) -> Value {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": format!("p-{nonce}"), "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": nonce,
            "target": {"uri": "local://host", "label": "this-host"},
            "mechanism": "local-privilege",
            "cred_ref": "local://sudo",
            "operation": {"command": command, "args": args},
        });
        sign_envelope(&self.signer, &mut env);
        env
    }
}

#[tokio::test]
async fn allowlisted_command_runs_unattended() {
    let Some(_bin) = helper_bin() else {
        eprintln!("SKIP: helper binary not built yet");
        return;
    };
    let spine = build(true).await;
    let resp = spine
        .gateway
        .handle_message(&spine.priv_intent("a1", "/bin/echo", &["hello"]))
        .await;
    assert_eq!(resp["type"], "result", "{resp}");
    assert_eq!(resp["session_ttl"], 300);
    let handle = resp["session_handle"].as_str().unwrap().to_owned();

    // Drive: one read_batch delivers the completed batch then closes.
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut cmd = json!({
        "chaperone": "0.1", "msg_id": "p-c1", "type": "session.command",
        "agent_id": AGENT,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": "c1",
        "session_handle": handle,
        "input_b64": "",
    });
    sign_envelope(&spine.signer, &mut cmd);
    let resp = spine.gateway.handle_message(&cmd).await;
    assert_eq!(resp["type"], "session.output", "{resp}");
    assert_eq!(resp["closed"], true);
    assert_eq!(resp["exit_code"], 0);
    use base64::Engine as _;
    let out = resp["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["stream"] == "stdout")
        .find_map(|o| o["data_b64"].as_str())
        .map(|b| base64::engine::general_purpose::STANDARD.decode(b).unwrap())
        .map(|b| String::from_utf8(b).unwrap())
        .unwrap_or_default();
    assert!(out.contains("hello"), "{out:?}");

    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(journal.contains("\"status\":\"session_opened\""));
}

#[tokio::test]
async fn non_allowlisted_privilege_is_force_confirmed_and_times_out_closed() {
    let Some(_bin) = helper_bin() else {
        eprintln!("SKIP: helper binary not built yet");
        return;
    };
    let spine = build(true).await;
    let resp = spine
        .gateway
        .handle_message(&spine.priv_intent("a2", "/usr/bin/poweroff", &[]))
        .await;
    assert_eq!(resp["code"], "E_CONFIRM_TIMEOUT", "{resp}");

    let journal = std::fs::read_to_string(&spine.audit_path).unwrap();
    assert!(journal.contains("\"status\":\"confirm_timeout\""));
    assert!(!journal.contains("session_opened"), "nothing opened");
}

#[tokio::test]
async fn no_helper_configured_is_an_honest_e_mechanism() {
    let spine = build(false).await;
    let resp = spine
        .gateway
        .handle_message(&spine.priv_intent("a3", "/bin/echo", &["hello"]))
        .await;
    assert_eq!(resp["code"], "E_MECHANISM");
    assert!(
        resp["reason"]
            .as_str()
            .unwrap()
            .contains("no session backend")
    );

    // And ssh too, in this spine without backends:
    let env = {
        let now = chaperone_gateway_core::chaperone_time_now();
        let mut env = json!({
            "chaperone": "0.1", "msg_id": "p-s1", "type": "intent",
            "agent_id": AGENT,
            "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
            "nonce": "s1",
            "target": {"uri": "ssh://x", "label": "x"}, "mechanism": "ssh",
            "cred_ref": "local://sudo",
            "operation": {"host": "x", "user": "u"},
        });
        sign_envelope(&spine.signer, &mut env);
        env
    };
    let resp = spine.gateway.handle_message(&env).await;
    assert_eq!(resp["code"], "E_MECHANISM");
}
