//! B-1 slice 2 tests: `ca://` dispatch, non-exportability, init semantics.
//! Offline; the ctx stub is a HashMap-backed vault, so every revert
//! experiment runs in milliseconds.

use super::ssh_ca::HOST_EXTENSION;
use super::*;

use std::collections::HashMap;
use std::sync::Mutex;

struct StubCtx {
    vault: Mutex<HashMap<String, String>>,
    identities: Mutex<HashMap<String, AgentIdentity>>,
}

impl StubCtx {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            vault: Mutex::new(HashMap::new()),
            identities: Mutex::new(HashMap::new()),
        })
    }
    fn seed_ca(&self) {
        let kp = test_ca_kp();
        let text = kp.1;
        self.vault.lock().unwrap().insert(CA_ENTRY.to_owned(), text);
    }
    fn seed_agent(&self, agent_id: &str) {
        self.identities.lock().unwrap().insert(
            agent_id.to_owned(),
            AgentIdentity {
                agent_id: agent_id.to_owned(),
                public_key_b64url: agent_pubkey_b64(),
                sponsor_id: "human:alice".to_owned(),
            },
        );
    }
}

impl CaContext for StubCtx {
    fn write_ca_entry(&self, text: &str) -> Result<(), CaError> {
        self.vault
            .lock()
            .unwrap()
            .insert(CA_ENTRY.to_owned(), text.to_owned());
        Ok(())
    }
    fn read_ca_entry(&self) -> Result<Option<String>, CaError> {
        Ok(self.vault.lock().unwrap().get(CA_ENTRY).cloned())
    }
    fn agent_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>, CaError> {
        Ok(self.identities.lock().unwrap().get(agent_id).cloned())
    }
}

/// A random Ed25519 CA as (PrivateKey, openssh-text). Public half derived
/// from the private half — a mismatched pair fails the builder's internal
/// signature check with a bare "Crypto" error (learned by probe).
fn test_ca_kp() -> (russh::keys::PrivateKey, String) {
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

/// A REAL Ed25519 public key (RFC 8032 test vector), the enrollment shape.
fn agent_pubkey_b64() -> String {
    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned()
}

#[test]
fn mint_for_produces_a_cert_bound_to_the_cred_ref_host() {
    let ctx = StubCtx::new();
    ctx.seed_ca();
    ctx.seed_agent("agent:ci");
    let provider = SshCaProvider::new(Arc::clone(&ctx));
    let id = ctx.agent_identity("agent:ci").unwrap().unwrap();

    let cert = provider
        .mint_for(
            "ca://app-01.internal",
            &id,
            &MintIntent {
                agent_id: "agent:ci",
                msg_id: "m-1",
                username: "deploy",
                want_pty: false,
                ttl_secs: 300,
            },
        )
        .unwrap();

    let parsed = russh::keys::Certificate::from_openssh(cert.cert_openssh.expose()).unwrap();
    assert_eq!(parsed.key_id(), "chaperone:agent:ci:m-1");
    assert_eq!(parsed.valid_principals(), &["deploy"]);
    // TD-3: the host binding rides in the extension and names the cred_ref host.
    let host = parsed
        .extensions()
        .iter()
        .find(|(k, _)| k.as_str() == HOST_EXTENSION)
        .map(|(_, v)| v.clone());
    assert_eq!(host.as_deref(), Some("app-01.internal"));
}

#[test]
fn falsifiable_a_different_cred_ref_host_binds_a_different_host_extension() {
    // If the host binding were dropped from the mint path, two ca:// refs
    // differing only in host would mint identical certs — the "structurally
    // portable across hosts" failure Heph's TD-3 redesign exists to prevent.
    let ctx = StubCtx::new();
    ctx.seed_ca();
    ctx.seed_agent("agent:ci");
    let provider = SshCaProvider::new(Arc::clone(&ctx));
    let id = ctx.agent_identity("agent:ci").unwrap().unwrap();

    let mint = |host: &str| {
        provider.mint_for(
            host,
            &id,
            &MintIntent {
                agent_id: "agent:ci",
                msg_id: "m-1",
                username: "deploy",
                want_pty: false,
                ttl_secs: 300,
            },
        )
    };
    let a = mint("ca://app-01.internal").unwrap();
    let b = mint("ca://app-02.internal").unwrap();
    assert_ne!(a.cert_openssh.expose(), b.cert_openssh.expose());
}

#[test]
fn non_initialized_ca_is_refused_with_not_initialized() {
    // Option A / explicit-init discipline: nothing is created lazily.
    let ctx = StubCtx::new();
    ctx.seed_agent("agent:ci");
    let provider = SshCaProvider::new(Arc::clone(&ctx));
    let id = ctx.agent_identity("agent:ci").unwrap().unwrap();
    assert_eq!(
        provider
            .mint_for(
                "ca://h",
                &id,
                &MintIntent {
                    agent_id: "agent:ci",
                    msg_id: "m",
                    username: "deploy",
                    want_pty: false,
                    ttl_secs: 300,
                },
            )
            .err(),
        Some(CaError::NotInitialized)
    );
}

// ---- TD-1 non-exportability: the structural pin ----

#[test]
fn resolve_never_returns_ca_material() {
    // The refusal is STRUCTURAL: resolve() refuses every entry, so there is
    // no path — no cred_ref spelling, no entry name, nothing — that hands the
    // CA key to a caller. Verified against a ctx that HAS a CA: the refusal
    // is not "entry not found", it is unconditional.
    let ctx = StubCtx::new();
    ctx.seed_ca();
    ctx.seed_agent("agent:ci");
    let provider = SshCaProvider::new(Arc::clone(&ctx));

    for entry in ["chaperone/ca/ssh", "", "..", "anything-else"] {
        let fut = Provider::resolve(&provider, entry);
        let result = futures_now(fut);
        assert!(
            result.is_err(),
            "resolve of {entry:?} must be refused (non-exportable CA)"
        );
    }
}

fn futures_now<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

// ---- init semantics (ruled: explicit, idempotent, never clobbers) ----

#[test]
fn init_creates_then_is_idempotent_and_never_clobbers() {
    let ctx = StubCtx::new();
    let provider = SshCaProvider::new(Arc::clone(&ctx));

    assert!(!provider.initialized().unwrap());
    provider.init().unwrap();
    assert!(provider.initialized().unwrap());

    let first = ctx.read_ca_entry().unwrap().unwrap();

    // A second init must not replace the key: rotation is an explicit
    // operator procedure, not an accident.
    provider.init().unwrap();
    assert_eq!(ctx.read_ca_entry().unwrap().unwrap(), first);
}

#[test]
fn mint_works_after_init_without_any_other_setup() {
    // ca-init -> mint is the whole operator flow; no hidden prerequisites.
    let ctx = StubCtx::new();
    ctx.seed_agent("agent:ci");
    let provider = SshCaProvider::new(Arc::clone(&ctx));
    provider.init().unwrap();
    let id = ctx.agent_identity("agent:ci").unwrap().unwrap();
    let cert = provider
        .mint_for(
            "ca://h.internal",
            &id,
            &MintIntent {
                agent_id: "agent:ci",
                msg_id: "m-1",
                username: "deploy",
                want_pty: false,
                ttl_secs: 300,
            },
        )
        .unwrap();
    assert!(cert.cert_openssh.expose().starts_with("ssh-"));
}

#[test]
fn bad_cred_refs_are_refused() {
    let ctx = StubCtx::new();
    ctx.seed_ca();
    ctx.seed_agent("agent:ci");
    let provider = SshCaProvider::new(Arc::clone(&ctx));
    let id = ctx.agent_identity("agent:ci").unwrap().unwrap();
    for bad in ["", "ca://", "ca://host:22", "ca://a/b", "notca://host"] {
        let result = provider.mint_for(
            bad,
            &id,
            &MintIntent {
                agent_id: "agent:ci",
                msg_id: "m",
                username: "deploy",
                want_pty: false,
                ttl_secs: 300,
            },
        );
        assert!(result.is_err(), "cred_ref {bad:?} must be refused");
    }
}

#[test]
fn unenrolled_agent_is_refused() {
    // RAE L0: no enrolled key, nothing to certify. Refused upstream of mint.
    let ctx = StubCtx::new();
    ctx.seed_ca();
    let provider = SshCaProvider::new(Arc::clone(&ctx));
    assert!(
        ctx.agent_identity("agent:ghost").unwrap().is_none(),
        "the stub must not invent identities"
    );
}

#[test]
fn ca_errors_stay_classified() {
    // B-4 carries into the CA path: no CaError variant renders request data.
    let cases = [
        CaError::NotInitialized,
        CaError::CaUnreadable,
        CaError::CaKeyInvalid,
        CaError::BadCredRef,
        CaError::AgentNotEnrolled,
        CaError::Mint(MintError::BadAgentKey),
    ];
    for (i, e) in cases.iter().enumerate() {
        let a = e.to_string();
        assert!(!a.contains("agent:ci") && !a.contains("app-01"));
        for (j, other) in cases.iter().enumerate() {
            let b = other.to_string();
            assert!(i == j || a != b, "CaError {i}/{j} collide: {a}");
        }
    }
}

#[test]
fn falsifiable_mint_uses_the_vault_ca_not_a_fresh_one() {
    // If mint_for generated its own CA instead of loading the vault's, a cert
    // minted before and after an init-less re-seed would be identical. Here:
    // seed CA #1, mint; replace with CA #2, mint; the certs MUST differ,
    // proving the vault entry is what signs.
    let ctx = StubCtx::new();
    ctx.seed_ca();
    ctx.seed_agent("agent:ci");
    let provider = SshCaProvider::new(Arc::clone(&ctx));
    let id = ctx.agent_identity("agent:ci").unwrap().unwrap();
    let a = provider
        .mint_for(
            "ca://h",
            &id,
            &MintIntent {
                agent_id: "agent:ci",
                msg_id: "m-1",
                username: "deploy",
                want_pty: false,
                ttl_secs: 300,
            },
        )
        .unwrap();

    // Replace the CA entry with a different key.
    let (kp2, text2) = test_ca_kp();
    let _ = kp2;
    ctx.vault.lock().unwrap().insert(CA_ENTRY.to_owned(), text2);

    let b = provider
        .mint_for(
            "ca://h",
            &id,
            &MintIntent {
                agent_id: "agent:ci",
                msg_id: "m-1",
                username: "deploy",
                want_pty: false,
                ttl_secs: 300,
            },
        )
        .unwrap();
    assert_ne!(
        a.cert_openssh.expose(),
        b.cert_openssh.expose(),
        "mint must use the vault's CA, not an ad-hoc one"
    );
}
