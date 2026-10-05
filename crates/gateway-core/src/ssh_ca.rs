//! B-1: the SSH certificate authority (spec
//! `docs/specs/b1-ssh-ca-spec.md`, ruled by Stephen 2026-10-05).
//!
//! Pure signing logic, offline-testable. Nothing here touches the network;
//! [`sign_crt_at`] is a pure function over `(ca_key, agent_pubkey, fields)`,
//! which is what makes the spec's falsifiability note real: a test can break
//! the signer and observe the failure, rather than reasoning about it.
//!
//! Rulings in force (all Stephen, 2026-10-05):
//! - **TD-1**: the CA key is a Chaperone-owned keypair in the vault,
//!   NON-EXPORTABLE (mint-only; a resolve of the CA entry is refused).
//! - **TD-2**: sign the agent's ENROLLED public key; TTL 300 s default with a
//!   3600 s hard ceiling (down-only — a request above the ceiling is an ERROR,
//!   not a clamp); forwarding extensions NEVER; key ID embeds agent_id+msg_id.
//! - **TD-3**: principal = the USERNAME from the rule-bound target_uri (a user
//!   certificate has no destination-host field); host binding = the
//!   `host@chaperone` custom extension, enforced host-side by the recipe's
//!   `AuthorizedPrincipalsCommand`.
//! - `all_principals_valid()` is the golden-ticket escape hatch and is never
//!   called here; a CI grep-assert (acceptance test 9) keeps it that way.

use chaperone_vault::SecretString;
use rand_core::{OsRng, RngCore};

/// The minted credential: cert text in OpenSSH format, zeroized on drop like
/// any secret. Short-lived is not permission to leak it.
pub struct MintedCert {
    /// The cert in OpenSSH one-line format. Credential material: zeroized on
    /// drop, never logged, never serialized by mistake.
    pub cert_openssh: SecretString,
    /// The `chaperone:<agent_id>:<msg_id>` correlation id; the audit chain
    /// can join a cert to its decision through this.
    pub key_id: String,
}

/// One mint request, all reference-shaped (B-4 discipline: the constructor
/// cannot receive response bytes or secrets — only IDs and parsed fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequest<'a> {
    /// Enrolled agent identity (RAE L0).
    pub agent_id: &'a str,
    /// Correlation id from the intent envelope.
    pub msg_id: &'a str,
    /// The username/account parsed from the rule-bound target_uri (TD-3).
    pub username: &'a str,
    /// The canonical host form the rule binds (TD-3, via the extension).
    pub host: &'a str,
    /// Whether the intent requested a pty (controls permit-pty only).
    pub want_pty: bool,
    /// Requested TTL seconds. Above [`TTL_CEILING_SECS`] is an error.
    pub ttl_secs: u64,
}

/// The ruled ceiling (TD-2). Above this is refused, never clamped: an operator
/// cannot drift into a long-lived cert by misconfiguration.
pub const TTL_CEILING_SECS: u64 = 3600;

/// The exact extension name carrying the host binding (TD-3). The host-side
/// `AuthorizedPrincipalsCommand` in the deployment recipe validates this.
pub const HOST_EXTENSION: &str = "host@chaperone";

/// Errors minting a certificate. B-4 discipline: classified, never free-form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MintError {
    /// The request was above the ruled TTL ceiling.
    TtlAboveCeiling,
    /// The enrolled agent key was not a parseable Ed25519 point.
    BadAgentKey,
    /// A required identity field was empty.
    EmptyField,
    /// The CA key material did not parse.
    BadCaKey,
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MintError::TtlAboveCeiling => "requested TTL exceeds the ruled ceiling",
            MintError::BadAgentKey => "agent key is not a parseable Ed25519 public key",
            MintError::EmptyField => "agent id, username, and host are all required",
            MintError::BadCaKey => "CA key material did not parse",
        })
    }
}

impl std::error::Error for MintError {}

impl MintError {
    /// The fixed detail text (the Display mapping, exposed as a const-shaped
    /// accessor for callers that compose classified messages).
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        match self {
            MintError::TtlAboveCeiling => "requested TTL exceeds the ruled ceiling",
            MintError::BadAgentKey => "agent key is not a parseable Ed25519 public key",
            MintError::EmptyField => "agent id, username, and host are all required",
            MintError::BadCaKey => "CA key material did not parse",
        }
    }
}

/// Generates a fresh CA keypair, returned as OpenSSH text (the vault entry
/// format) plus the public key line (for sshd `TrustedUserCAKeys`).
///
/// Used by `chaperone ca-init` only — never called on the mint path.
pub fn generate_ca() -> Result<(String, String), MintError> {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let kp = russh::keys::ssh_key::private::Ed25519Keypair {
        public: russh::keys::ssh_key::public::Ed25519PublicKey(signing.verifying_key().to_bytes()),
        private: russh::keys::ssh_key::private::Ed25519PrivateKey::from_bytes(&seed),
    };
    let key = russh::keys::PrivateKey::from(kp);
    let private_text = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|_| MintError::BadCaKey)?
        .to_string();
    let public_line = key
        .public_key()
        .to_openssh()
        .map_err(|_| MintError::BadCaKey)?;
    Ok((private_text, public_line))
}

/// The public key line for a stored CA private key (for sshd
/// `TrustedUserCAKeys`). Refuses non-parsing material.
#[must_use]
pub fn ca_public_line(private_text: &str) -> Option<String> {
    let key = russh::keys::PrivateKey::from_openssh(private_text.as_bytes()).ok()?;
    key.public_key().to_openssh().ok()
}

/// Mints a user certificate binding the agent's enrolled public key to the
/// request's identity fields, signed by the CA key.
///
/// Wall-clock lives HERE and only here, so tests use [`sign_crt_at`] with an
/// explicit epoch anchor and never sleep.
pub fn sign_crt(
    ca_key: &russh::keys::PrivateKey,
    agent_public_key_b64url: &str,
    req: &MintRequest<'_>,
) -> Result<MintedCert, MintError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| MintError::BadCaKey)? // clock went backwards: refuse
        .as_secs();
    sign_crt_at(ca_key, agent_public_key_b64url, req, now)
}

/// [`sign_crt`] with an explicit anchor epoch — the testable core.
///
/// TD-2 notes: `valid_after` is set `anchor - 60` (clock-skew grace), so the
/// window is [anchor-60, anchor+ttl]. The tests assert against the anchor and
/// `anchor + ttl` accordingly.
pub fn sign_crt_at(
    ca_key: &russh::keys::PrivateKey,
    agent_public_key_b64url: &str,
    req: &MintRequest<'_>,
    anchor_epoch: u64,
) -> Result<MintedCert, MintError> {
    use base64::Engine as _;

    if req.ttl_secs == 0 || req.ttl_secs > TTL_CEILING_SECS {
        return Err(MintError::TtlAboveCeiling);
    }
    if req.agent_id.trim().is_empty()
        || req.username.trim().is_empty()
        || req.host.trim().is_empty()
        || req.msg_id.trim().is_empty()
    {
        return Err(MintError::EmptyField);
    }

    // The agent's ENROLLED key (RAE L0): base64url Ed25519, exactly what the
    // enrollment store holds. Not 32 bytes => refused, not minted. (SSH
    // Ed25519 public keys are raw 32-byte encodings; the signature check at
    // auth time is what proves possession, so length/decodability is the
    // mint-time gate.)
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(agent_public_key_b64url.trim())
        .map_err(|_| MintError::BadAgentKey)?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| MintError::BadAgentKey)?;
    let subject = russh::keys::PublicKey::from(russh::keys::ssh_key::public::KeyData::from(
        russh::keys::ssh_key::public::Ed25519PublicKey(bytes),
    ));

    let key_id = format!("chaperone:{}:{}", req.agent_id.trim(), req.msg_id.trim());

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let mut builder = russh::keys::ssh_key::certificate::Builder::new(
        nonce,
        subject.key_data().clone(),
        anchor_epoch.saturating_sub(60),
        anchor_epoch + req.ttl_secs,
    )
    .map_err(|_| MintError::BadCaKey)?;

    builder
        .cert_type(russh::keys::ssh_key::certificate::CertType::User)
        .map_err(|_| MintError::BadCaKey)?;
    builder
        .key_id(key_id.clone())
        .map_err(|_| MintError::BadCaKey)?;
    // TD-3: exactly one principal — the username. valid_principal() appends;
    // calling it once gives exactly one. all_principals_valid() is NEVER used.
    builder
        .valid_principal(req.username.trim().to_owned())
        .map_err(|_| MintError::BadCaKey)?;
    // TD-3: the host binding rides as an extension.
    builder
        .extension(HOST_EXTENSION, req.host.trim().to_owned())
        .map_err(|_| MintError::BadCaKey)?;
    // TD-2: pty only when the intent asked; forwarding NEVER (the extensions
    // map starts empty, so omission is the enforcement — plus a test).
    if req.want_pty {
        builder
            .extension("permit-pty", "".to_owned())
            .map_err(|_| MintError::BadCaKey)?;
    }

    let cert = builder.sign(ca_key).map_err(|_| MintError::BadCaKey)?;
    let text = cert.to_openssh().map_err(|_| MintError::BadCaKey)?;
    Ok(MintedCert {
        cert_openssh: SecretString::new(text),
        key_id,
    })
}

#[cfg(test)]
#[path = "ssh_ca_tests.rs"]
mod tests;
