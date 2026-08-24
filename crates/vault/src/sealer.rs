//! Key-sealing: how the local vault's data-encryption key is protected at
//! rest (DESIGN-DECISIONS D5).
//!
//! Two sealers ship:
//!
//! 1. **[`PassphraseSealer`]** - the operator's passphrase derives a key-
//!    encryption key via argon2id; the DEK is wrapped with AES-256-GCM.
//!    Works everywhere (headless servers included) and is therefore the v0
//!    DEFAULT. Documented-weaker than hardware/OS sealing: the KEK lives in
//!    process memory while the store is open.
//!
//! 2. **[`KeyringSealer`]** (feature `keyring`) - the DEK is stored in the
//!    platform credential store (secret-service / Keychain / Credential
//!    Manager). Preferred where the service is available and running.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

/// Failures of sealing or unsealing.
#[derive(Debug)]
#[non_exhaustive]
pub enum SealerError {
    /// The OS credential store was unreachable or refused.
    Keyring(String),
    /// Internal cryptographic failure (nonce reuse, RNG, ...). Must never
    /// happen; loud if it does.
    Crypto(String),
}

impl std::fmt::Display for SealerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealerError::Keyring(e) => write!(f, "platform key store: {e}"),
            SealerError::Crypto(e) => write!(f, "crypto failure in sealer: {e}"),
        }
    }
}

impl std::error::Error for SealerError {}

/// Wraps (seals) and unwraps (unseals) the vault's data-encryption key.
///
/// `Send + Sync` so sealed stores can sit behind shared provider handles.
pub trait Sealer: Send + Sync {
    /// Human-legible name recorded in the store header.
    fn name(&self) -> &'static str;

    /// Protects the raw DEK for at-rest storage.
    fn seal(&self, dek: &[u8; 32]) -> Result<Vec<u8>, SealerError>;

    /// Recovers the DEK into a zeroizing buffer.
    fn unseal(&self, sealed: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, SealerError>;
}

// ---------- PassphraseSealer ----------

const ARGON_M_COST_KIB: u32 = 65_536; // 64 MiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

use base64::Engine as _;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn unb64(text: &str) -> Result<Vec<u8>, SealerError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| SealerError::Crypto(format!("base64: {e}")))
}

/// Everything needed to re-derive the KEK on open; persisted in the header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Argon2 salt, base64url.
    pub salt_b64: String,
    /// Memory cost, KiB.
    pub m_cost_kib: u32,
    /// Time cost (passes).
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

/// Argon2id + AES-256-GCM wrapping under an operator passphrase.
///
/// The derived KEK is itself held zeroizing and only inside call frames -
/// it is NOT retained by this struct.
#[derive(Debug)]
pub struct PassphraseSealer {
    params: KdfParams,
    passphrase: zeroize::Zeroizing<String>,
}

impl PassphraseSealer {
    /// Creates a sealer with a fresh random salt at recommended parameters.
    #[must_use]
    pub fn new(passphrase: zeroize::Zeroizing<String>) -> Self {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            params: KdfParams {
                salt_b64: b64(&salt),
                m_cost_kib: ARGON_M_COST_KIB,
                t_cost: ARGON_T_COST,
                p_cost: ARGON_P_COST,
            },
            passphrase,
        }
    }

    /// Rebuilds from persisted header parameters (opening an existing store).
    #[must_use]
    pub fn from_params(params: KdfParams, passphrase: zeroize::Zeroizing<String>) -> Self {
        Self { params, passphrase }
    }

    /// Parameters to persist in the store header.
    #[must_use]
    pub fn params(&self) -> &KdfParams {
        &self.params
    }

    fn derive_kek(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, SealerError> {
        let salt = unb64(&self.params.salt_b64)?;
        let params = argon2::Params::new(
            self.params.m_cost_kib,
            self.params.t_cost,
            self.params.p_cost,
            Some(32),
        )
        .map_err(|e| SealerError::Crypto(format!("argon2 params: {e}")))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut kek: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(self.passphrase.as_bytes(), &salt, kek.as_mut())
            .map_err(|e| SealerError::Crypto(format!("argon2id: {e}")))?;
        Ok(kek)
    }

    fn wrap(
        &self,
        kek: &zeroize::Zeroizing<[u8; 32]>,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_LEN]), SealerError> {
        let cipher = Aes256Gcm::new(kek.as_ref().into());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| SealerError::Crypto("encrypt failed".to_owned()))?;
        Ok((ct, nonce_bytes))
    }

    fn unwrap(
        &self,
        kek: &zeroize::Zeroizing<[u8; 32]>,
        nonce: &[u8; NONCE_LEN],
        sealed: &[u8],
    ) -> Result<Vec<u8>, SealerError> {
        let cipher = Aes256Gcm::new(kek.as_ref().into());
        cipher
            .decrypt(Nonce::from_slice(nonce), sealed)
            .map_err(|_| SealerError::Crypto("authentication failed".to_owned()))
    }
}

impl Sealer for PassphraseSealer {
    fn name(&self) -> &'static str {
        "passphrase"
    }

    fn seal(&self, dek: &[u8; 32]) -> Result<Vec<u8>, SealerError> {
        let kek = self.derive_kek()?;
        // Encoded as nonce || ciphertext, self-describing per write.
        let (ct, nonce) = self.wrap(&kek, dek)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, SealerError> {
        if sealed.len() <= NONCE_LEN {
            return Err(SealerError::Crypto("sealed DEK too short".to_owned()));
        }
        let kek = self.derive_kek()?;
        let (nonce_raw, ct) = sealed.split_at(NONCE_LEN);
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(nonce_raw);
        let plain = self.unwrap(&kek, &n, ct)?;
        let arr: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| SealerError::Crypto("DEK is not 32 bytes".to_owned()))?;
        Ok(zeroize::Zeroizing::new(arr))
    }
}

// ---------- KeyringSealer ----------

/// Stores the DEK in the platform credential store behind the `keyring`
/// feature. Service/user naming keeps multiple stores distinct.
#[cfg(feature = "keyring")]
#[derive(Debug)]
pub struct KeyringSealer {
    service: String,
    user: String,
}

#[cfg(feature = "keyring")]
impl KeyringSealer {
    /// Targets `<service>` / `<user>` in the platform credential store.
    #[must_use]
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, SealerError> {
        keyring::Entry::new(&self.service, &self.user)
            .map_err(|e| SealerError::Keyring(e.to_string()))
    }
}

#[cfg(feature = "keyring")]
impl Sealer for KeyringSealer {
    fn name(&self) -> &'static str {
        "keyring"
    }

    fn seal(&self, dek: &[u8; 32]) -> Result<Vec<u8>, SealerError> {
        let entry = self.entry()?;
        entry
            .set_password(&b64(dek))
            .map_err(|e| SealerError::Keyring(e.to_string()))?;
        // The "sealed" blob is a marker only: material lives in the OS store.
        Ok(b"keyring-backed".to_vec())
    }

    fn unseal(&self, marker: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, SealerError> {
        if marker != b"keyring-backed" {
            return Err(SealerError::Crypto(
                "journal/sealed blob mismatch".to_owned(),
            ));
        }
        let entry = self.entry()?;
        let stored = entry
            .get_password()
            .map_err(|e| SealerError::Keyring(e.to_string()))?;
        let raw = unb64(&stored)?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| SealerError::Crypto("DEK is not 32 bytes".to_owned()))?;
        Ok(zeroize::Zeroizing::new(arr))
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn sealer_with(pass: &str) -> PassphraseSealer {
        PassphraseSealer::new(zeroize::Zeroizing::new(pass.to_owned()))
    }

    #[test]
    fn round_trips_a_dek() {
        let s = sealer_with("correct horse battery staple");
        let dek = [7u8; 32];
        let sealed = s.seal(&dek).unwrap();
        assert_ne!(sealed.as_slice(), dek.as_slice(), "must not be plaintext");
        let back = s.unseal(&sealed).unwrap();
        assert_eq!(*back, dek);
    }

    #[test]
    fn wrong_passphrase_fails_authentication() {
        let s = sealer_with("right");
        let sealed = s.seal(&[9u8; 32]).unwrap();

        let other = PassphraseSealer::from_params(
            s.params().clone(),
            zeroize::Zeroizing::new("wrong".to_owned()),
        );
        assert!(other.unseal(&sealed).is_err());
    }

    #[test]
    fn same_passphrase_different_salt_differs() {
        let a = sealer_with("same");
        let b = sealer_with("same"); // fresh random salt
        let sealed_a = a.seal(&[1u8; 32]).unwrap();
        // b cannot unseal a's blob: different salt => different KEK.
        assert!(b.unseal(&sealed_a).is_err());
        assert_ne!(a.params().salt_b64, b.params().salt_b64);
    }
}
