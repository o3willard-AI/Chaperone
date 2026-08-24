//! The gateway's audit signing identity.
//!
//! The chain is only as trustworthy as the key that signs it. v0 ships a
//! software-only key: 32 random bytes, generated once, persisted by the
//! operator at `0600`. The upgrade path to platform-key-store / hardware
//! backing is the hardening phase (PLAN M10); until then this file is part
//! of the trusted computing base and MUST be protected accordingly.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

use chaperone_protocol::encode_signature;

/// Parses a base64url public key into a verifying key (operator input to
/// `audit-verify`).
///
/// Errors carry no sensitive data - there is none in a public key.
pub fn verifying_key_from_b64url(encoded: &str) -> Result<VerifyingKey, String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|e| format!("public key is not valid base64url: {e}"))?;
    let bytes: &[u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", raw.len()))?;
    VerifyingKey::from_bytes(bytes).map_err(|e| e.to_string())
}

/// An Ed25519 key that signs audit records.
#[derive(Clone)]
pub struct AuditKey {
    signing: SigningKey,
}

impl AuditKey {
    /// Generates a fresh random key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Reconstructs a key from its 32 seed bytes (loading persistence).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32 seed bytes (persisting).
    #[must_use]
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The public half, for verifiers.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Public key as base64url (CLI display, verifier input).
    #[must_use]
    pub fn public_key_b64url(&self) -> String {
        encode_signature(self.verifying_key().as_bytes())
    }

    /// Signs a raw 32-byte record hash; base64url-encoded.
    #[must_use]
    pub(crate) fn sign_raw(&self, hash: &[u8; 32]) -> String {
        use ed25519_dalek::Signer;
        encode_signature(&self.signing.sign(hash).to_bytes())
    }

    /// Signs arbitrary bytes (release artifacts); base64url-encoded.
    #[must_use]
    pub fn sign_message(&self, bytes: &[u8]) -> String {
        use ed25519_dalek::Signer;
        encode_signature(&self.signing.sign(bytes).to_bytes())
    }

    /// Verifies arbitrary bytes against a detached signature.
    pub fn verify_message(vk: &VerifyingKey, bytes: &[u8], sig_b64url: &str) -> bool {
        use ed25519_dalek::{Signature, Verifier};
        chaperone_protocol::decode_signature(sig_b64url)
            .ok()
            .and_then(|raw| {
                let sig: &[u8; 64] = raw.as_slice().try_into().ok()?;
                Some(Signature::from_bytes(sig))
            })
            .is_some_and(|sig| vk.verify(bytes, &sig).is_ok())
    }

    /// Verifies a raw 32-byte record hash against its signature.
    pub(crate) fn verify_raw(vk: &VerifyingKey, hash: &[u8; 32], sig_b64url: &str) -> bool {
        use ed25519_dalek::{Signature, Verifier};
        chaperone_protocol::decode_signature(sig_b64url)
            .ok()
            .and_then(|bytes| {
                let sig: &[u8; 64] = bytes.as_slice().try_into().ok()?;
                Some(Signature::from_bytes(sig))
            })
            .is_some_and(|sig| vk.verify(hash, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trip_preserves_public_key() {
        let k1 = AuditKey::generate();
        let seed = k1.to_seed();
        let k2 = AuditKey::from_seed(&seed);
        assert_eq!(k1.public_key_b64url(), k2.public_key_b64url());
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = AuditKey::generate();
        let b = AuditKey::generate();
        assert_ne!(a.public_key_b64url(), b.public_key_b64url());
    }
}
