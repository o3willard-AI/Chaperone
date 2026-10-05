//! B-1 slice 2: the `ca://` scheme — gateway-side minting (spec §2).
//!
//! Flow per SSH intent whose `cred_ref` is `ca://<host>`:
//! 1. the rule allowed (existing policy path, unchanged);
//! 2. instead of `resolve(cred_ref)`, the gateway mints: loads the CA keypair
//!    from the vault entry `local://chaperone/ca/ssh` (fresh per mint — D5's
//!    no-caching rule), signs the agent's ENROLLED public key, returns the
//!    cert as the credential;
//! 3. the cert carries the ruled fields: principal = username (TD-3), the
//!    `host@chaperone` extension = the `ca://` host, key ID embedding
//!    agent_id + msg_id for audit correlation.
//!
//! NON-EXPORTABILITY (TD-1, ruled): `resolve("chaperone/ca/ssh")` is REFUSED.
//! The CA key never leaves the mint call. Acceptance test 5 asserts this
//! directly via [`CaMaterialRefused`] — the resolve path cannot hand back CA
//! key material because the CA entry is not visible to resolve at all.
//!
//! `ca-init` is EXPLICIT (ruled): an auto-created, un-backed-up CA is the one
//! unrecoverable state, so [`SshCaProvider::init`] exists and the UI/CLI
//! surface carries the P2-3 irreversibility statement.

use rand_core::RngCore as _;
use std::sync::Arc;

use chaperone_vault::provider::{Provider, ResolveError, SecretFuture};

use super::ssh_ca::{self, MintError, MintRequest, MintedCert};

/// The vault entry holding the CA keypair (TD-1, ruled).
pub const CA_ENTRY: &str = "chaperone/ca/ssh";
/// The `cred_ref` scheme this provider serves.
pub const CA_SCHEME: &str = "ca";

/// Errors from the CA mint path. B-4 discipline: classified causes, never
/// free-form text that could echo target-controlled bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaError {
    /// The CA keypair has not been created yet — run `ca-init` first.
    NotInitialized,
    /// The CA entry could not be read from the vault (sealed wrong, corrupt).
    CaUnreadable,
    /// The vault's CA entry is not a parseable SSH private key.
    CaKeyInvalid,
    /// The intent's `cred_ref` was not a plain `ca://<host>`.
    BadCredRef,
    /// The agent named in the intent is not enrolled (RAE L0).
    AgentNotEnrolled,
    /// The mint itself failed (see [`MintError`] for the cause class).
    Mint(MintError),
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CaError::NotInitialized => {
                "the SSH CA has not been initialized; run chaperone ca-init first"
            }
            CaError::CaUnreadable => "the CA key could not be read from the vault",
            CaError::CaKeyInvalid => "the stored CA key is not a parseable SSH private key",
            CaError::BadCredRef => "ca:// references take exactly one host",
            CaError::AgentNotEnrolled => "the agent is not enrolled; no key to certify",
            CaError::Mint(e) => e.detail(),
        })
    }
}

impl CaError {
    /// The fixed detail text (mirrors Display; B-4 const-shaped).
    #[must_use]
    pub const fn detail_text(&self) -> &'static str {
        match self {
            CaError::NotInitialized => "SSH CA not initialized; run chaperone ca-init first",
            CaError::CaUnreadable => "CA key unreadable from the vault",
            CaError::CaKeyInvalid => "stored CA key is not a parseable SSH private key",
            CaError::BadCredRef => "ca:// references take exactly one host",
            CaError::AgentNotEnrolled => "agent not enrolled; no key to certify",
            CaError::Mint(m) => m.detail(),
        }
    }
}

impl std::error::Error for CaError {}

impl From<MintError> for CaError {
    fn from(e: MintError) -> Self {
        CaError::Mint(e)
    }
}

/// One resolved agent identity for minting: the enrolled key text plus the
/// sponsor's stable id (RAE L0 evidence in the key id path).
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: String,
    /// The enrolled public key, base64url Ed25519 (32 bytes).
    pub public_key_b64url: String,
    /// The enrolled sponsor's stable id (attribution context for the audit
    /// record; the cert itself carries agent_id + msg_id only).
    pub sponsor_id: String,
}

/// What a CA provider needs to mint: the vault (to load the CA key fresh),
/// and a way to look up the agent's enrolled identity.
///
/// The trait indirection keeps this pure and testable: tests supply a stub
/// vault holding a test CA and a fixed identity table.
pub trait CaContext: Send + Sync {
    /// Reads the CA key text from the vault entry. Errors here are classified
    /// by the caller into [`CaError::NotInitialized`] / [`CaError::CaUnreadable`].
    fn read_ca_entry(&self) -> Result<Option<String>, CaError>;
    /// Looks up the agent's enrolled identity.
    fn agent_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>, CaError>;
    /// Persists the CA key text (explicit `ca-init` only).
    fn write_ca_entry(&self, text: &str) -> Result<(), CaError>;
}

/// The SSH CA provider. Registered under `ca` in the gateway's `VaultRouter`;
/// `mint()` is the real operation, `resolve()` is structurally refused for the
/// CA entry (TD-1 non-exportability).
pub struct SshCaProvider<C: CaContext> {
    ctx: Arc<C>,
}

impl<C: CaContext> SshCaProvider<C> {
    #[must_use]
    pub fn new(ctx: Arc<C>) -> Self {
        Self { ctx }
    }

    /// Mints a short-lived cert for `ca://<host>`.
    ///
    /// `cred_ref` must be exactly `ca://<host>`; username comes from the
    /// intent's target (TD-3), passed in via `username`.
    pub fn mint_for(
        &self,
        cred_ref: &str,
        identity: &AgentIdentity,
        agent_id: &str,
        msg_id: &str,
        username: &str,
        want_pty: bool,
        ttl_secs: u64,
    ) -> Result<MintedCert, CaError> {
        let host = cred_ref.strip_prefix("ca://").ok_or(CaError::BadCredRef)?;
        let host = host.trim();
        if host.is_empty() || host.contains(':') || host.contains('/') {
            return Err(CaError::BadCredRef);
        }

        let ca_text = self.ctx.read_ca_entry()?.ok_or(CaError::NotInitialized)?;
        let ca_key = russh::keys::PrivateKey::from_openssh(ca_text.as_bytes())
            .map_err(|_| CaError::CaKeyInvalid)?;

        let req = MintRequest {
            agent_id,
            msg_id,
            username,
            host,
            want_pty,
            ttl_secs,
        };
        Ok(ssh_ca::sign_crt(
            &ca_key,
            &identity.public_key_b64url,
            &req,
        )?)
    }

    /// Whether the CA exists. The UI/CLI `ca-init` gate consults this.
    pub fn initialized(&self) -> Result<bool, CaError> {
        Ok(self.ctx.read_ca_entry()?.is_some())
    }

    /// Creates the CA keypair in the vault entry. EXPLICIT bootstrap (ruled):
    /// called from `chaperone ca-init` / the setup wizard, never lazily. The
    /// caller owns the irreversibility warning (P2-3 discipline).
    pub fn init(&self) -> Result<(), CaError> {
        if self.initialized()? {
            return Ok(()); // idempotent: an existing CA is never clobbered
        }
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let kp = russh::keys::ssh_key::private::Ed25519Keypair {
            public: russh::keys::ssh_key::public::Ed25519PublicKey(
                ed25519_dalek::SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .to_bytes(),
            ),
            private: russh::keys::ssh_key::private::Ed25519PrivateKey::from_bytes(&seed),
        };
        let key = russh::keys::PrivateKey::from(kp);
        let text = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .map_err(|_| CaError::CaUnreadable)?;
        self.ctx.write_ca_entry(&text)
    }
}

impl<C: CaContext> Provider for SshCaProvider<C> {
    fn resolve<'a>(&'a self, entry: &'a str) -> SecretFuture<'a> {
        // TD-1 NON-EXPORTABILITY, structurally: there is no path from this
        // provider to the CA key material. Every entry is refused; the CA key
        // exists only inside mint_for's frame.
        Box::pin(async move {
            let _ = entry;
            Err(ResolveError::Backend(
                "the SSH CA key is non-exportable; minting is the only operation \
                 it serves"
                    .to_owned(),
            ))
        })
    }
}

#[cfg(test)]
#[path = "ssh_ca_provider_tests.rs"]
mod tests;
