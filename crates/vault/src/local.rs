//! The built-in encrypted local vault (ARCH-SPEC §2.4).
//!
//! Design, in ephemerality terms (ARCH-SPEC §2.9):
//!
//! - **At rest**: one file, `0600`: header (KDF params + sealed DEK) and an
//!   AES-256-GCM-encrypted JSON body of `{path: secret}`.
//! - **In memory**: the store holds NON-SECRET header material and the
//!   encrypted body, plus the unsealed DEK in a zeroizing buffer. No entry
//!   plaintext is ever retained between operations - [`LocalVault::get`]
//!   decrypts, extracts ONE value into a [`SecretString`], and drops the
//!   rest of the plaintext within the call frame.
//! - **Writes** are atomic temp-file + rename: a crash cannot shred the
//!   store.
//!
//! Static by design (ARCH table: "User-only CRUD; static by default");
//! least-privilege minting belongs to dynamic backends via [`crate::Provider`].

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::sealer::{KdfParams, PassphraseSealer, Sealer};
use crate::secret::SecretString;

const MAGIC: &[u8; 10] = b"CHAPVAULT1";
const BODY_NONCE_LEN: usize = 12;

/// Failures of the built-in vault.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// Underlying file i/o.
    Io(std::io::Error),
    /// File did not parse as a chaperone vault.
    Corrupt(String),
    /// The passphrase does not open this store.
    WrongPassphrase,
    /// Sealing layer failed.
    Seal(crate::sealer::SealerError),
    /// A store already exists at this path.
    AlreadyExists(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "vault i/o: {e}"),
            VaultError::Corrupt(e) => write!(f, "vault corrupt: {e}"),
            VaultError::WrongPassphrase => write!(f, "passphrase does not open this vault"),
            VaultError::Seal(e) => write!(f, "{e}"),
            VaultError::AlreadyExists(p) => write!(f, "a vault already exists at {p}"),
        }
    }
}

impl std::error::Error for VaultError {}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    version: u32,
    sealer_name: String,
    #[serde(flatten)]
    kdf: KdfParams,
    sealed_dek_b64: String,
    body_nonce_b64: String,
    body_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Body {
    entries: BTreeMap<String, String>,
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn unb64(text: &str) -> Result<Vec<u8>, VaultError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| VaultError::Corrupt(format!("base64: {e}")))
}

fn encrypt_body(dek: &[u8; 32], nonce: &[u8; 12], body: &Body) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new(dek.into());
    let plaintext = serde_json::to_vec(body).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext.as_slice())
        .map_err(|_| VaultError::Corrupt("body encryption failed".to_owned()))
}

fn decrypt_body(dek: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Result<Body, VaultError> {
    let cipher = Aes256Gcm::new(dek.into());
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| VaultError::Corrupt("body authentication failed".to_owned()))?;
    serde_json::from_slice(&plain).map_err(|e| VaultError::Corrupt(format!("body: {e}")))
}

fn persist(path: &Path, header: &Header) -> Result<(), VaultError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(VaultError::Io)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(
        &serde_json::to_vec(header).map_err(|e| VaultError::Corrupt(e.to_string()))?,
    );
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(VaultError::Io)?;
    tmp.write_all(&bytes)
        .and_then(|_| tmp.flush())
        .map_err(VaultError::Io)?;
    // tempfile creates 0600 on unix; rename preserves.
    tmp.persist(path).map_err(|pe| VaultError::Io(pe.error))?;
    Ok(())
}

/// An opened local vault. Holds NO entry plaintext between operations.
///
/// `Debug` output is deliberately minimal: the DEK, ciphertext, and sealer
/// internals are all non-exhaustive fields that never render.
pub struct LocalVault {
    path: PathBuf,
    sealer_name: String,
    /// Opaque sealed DEK blob - kept verbatim so writes need not touch the
    /// sealing layer (and for keyring stores, need not reach the OS store).
    sealed_dek: Vec<u8>,
    kdf: KdfParams,
    /// Unsealed data-encryption key. Zeroized on drop.
    dek: zeroize::Zeroizing<[u8; 32]>,
    body_nonce: [u8; BODY_NONCE_LEN],
    /// Encrypted body bytes. NOT plaintext.
    body_ciphertext: Vec<u8>,
}

impl std::fmt::Debug for LocalVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVault")
            .field("path", &self.path)
            .field("sealer", &self.sealer_name)
            .finish_non_exhaustive()
    }
}

impl LocalVault {
    /// Creates a fresh empty store sealed with `sealer`. Fails if one
    /// already exists at `path`.
    ///
    /// The default `passphrase` sealer works everywhere; the `keyring`
    /// sealer (feature `keyring`) backs the DEK with the platform
    /// credential store so no passphrase is needed to open the store
    /// (issue #50). See [`crate::sealer`] for the security trade-offs.
    ///
    /// # Errors
    /// A store already exists at `path`, the sealer is unknown to this
    /// build, or the sealing layer failed (e.g. the OS credential store
    /// is unreachable).
    pub fn create(path: &Path, sealer_choice: &str, passphrase: zeroize::Zeroizing<String>) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.display().to_string()));
        }
        let (sealer_name, header_kdf, sealed, sealed_dek_for_handle): (String, KdfParams, Vec<u8>, Option<zeroize::Zeroizing<[u8; 32]>>) = match sealer_choice {
            "passphrase" => {
                let sealer = PassphraseSealer::new(passphrase);
                let mut dek = zeroize::Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(dek.as_mut());
                let sealed = sealer.seal(&dek).map_err(VaultError::Seal)?;
                (sealer.name().to_owned(), sealer.params().clone(), sealed, Some(dek))
            }
            #[cfg(feature = "keyring")]
            "keyring" => {
                let sealer = crate::sealer::KeyringSealer::new("chaperone-vault", "dek");
                let mut dek = zeroize::Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(dek.as_mut());
                let sealed = sealer.seal(&dek).map_err(VaultError::Seal)?;
                (sealer.name().to_owned(), KdfParams {
                    salt_b64: String::new(),
                    m_cost_kib: 0,
                    t_cost: 0,
                    p_cost: 0,
                }, sealed, Some(dek))
            }
            other => {
                return Err(VaultError::Corrupt(format!(
                    "unknown sealer {other:?}{}",
                    if cfg!(feature = "keyring") {
                        " (this build supports: passphrase, keyring)"
                    } else {
                        " (this build supports: passphrase; rebuild with --features keyring for keyring support)"
                    }
                )));
            }
        };
        let dek = sealed_dek_for_handle.expect("sealer match arms always produce a DEK");

        let mut body_nonce = [0u8; BODY_NONCE_LEN];
        OsRng.fill_bytes(&mut body_nonce);
        let body_ct = encrypt_body(
            &dek,
            &body_nonce,
            &Body {
                entries: BTreeMap::new(),
            },
        )?;

        let header = Header {
            version: 1,
            sealer_name: sealer_name.clone(),
            kdf: header_kdf.clone(),
            sealed_dek_b64: b64(&sealed),
            body_nonce_b64: b64(&body_nonce),
            body_b64: b64(&body_ct),
        };
        persist(path, &header)?;
        Ok(Self {
            path: path.to_path_buf(),
            sealer_name,
            sealed_dek: sealed,
            kdf: header_kdf,
            dek,
            body_nonce,
            body_ciphertext: body_ct,
        })
    }

    /// Opens an existing store.
    ///
    /// Both the sealed DEK tag AND the body tag must authenticate before the
    /// handle exists: an open handle vouches for the whole store's integrity.
    pub fn open(path: &Path, passphrase: zeroize::Zeroizing<String>) -> Result<Self, VaultError> {
        let raw = std::fs::read(path).map_err(VaultError::Io)?;
        if !raw.starts_with(MAGIC) {
            return Err(VaultError::Corrupt("not a chaperone vault file".to_owned()));
        }
        let header: Header = serde_json::from_slice(&raw[MAGIC.len()..])
            .map_err(|e| VaultError::Corrupt(format!("header: {e}")))?;
        if header.version != 1 {
            return Err(VaultError::Corrupt(format!(
                "unknown vault version {}",
                header.version
            )));
        }

        let sealed = unb64(&header.sealed_dek_b64)?;
        let body_nonce_raw = unb64(&header.body_nonce_b64)?;
        let body_nonce: [u8; BODY_NONCE_LEN] = body_nonce_raw
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt("body nonce length".to_owned()))?;
        let body_ct = unb64(&header.body_b64)?;

        match header.sealer_name.as_str() {
            "passphrase" => {
                let sealer = PassphraseSealer::from_params(header.kdf.clone(), passphrase);
                let dek = sealer.unseal(&sealed).map_err(|e| match e {
                    crate::sealer::SealerError::Crypto(ref m)
                        if m.contains("authentication failed") =>
                    {
                        VaultError::WrongPassphrase
                    }
                    other => VaultError::Seal(other),
                })?;
                let _probe = decrypt_body(&dek, &body_nonce, &body_ct)?;
                Ok(Self {
                    path: path.to_path_buf(),
                    sealer_name: header.sealer_name.clone(),
                    sealed_dek: sealed,
                    kdf: header.kdf.clone(),
                    dek,
                    body_nonce,
                    body_ciphertext: body_ct,
                })
            }
            #[cfg(feature = "keyring")]
            "keyring" => {
                let sealer = crate::sealer::KeyringSealer::new("chaperone-vault", "dek");
                let dek = sealer.unseal(&sealed).map_err(VaultError::Seal)?;
                let _probe = decrypt_body(&dek, &body_nonce, &body_ct)?;
                Ok(Self {
                    path: path.to_path_buf(),
                    sealer_name: header.sealer_name.clone(),
                    sealed_dek: sealed,
                    kdf: header.kdf.clone(),
                    dek,
                    body_nonce,
                    body_ciphertext: body_ct,
                })
            }
            other => Err(VaultError::Corrupt(format!(
                "this build cannot unseal {other:?} stores"
            ))),
        }
    }

    /// Store file location.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Which sealer this store uses ("passphrase", or "keyring").
    #[must_use]
    pub fn sealer_name(&self) -> &str {
        &self.sealer_name
    }

    /// Reads only the header of the store at `path` and returns its sealer
    /// name ("passphrase" | "keyring"). Lets callers (e.g. the CLI) know
    /// whether opening will need a passphrase WITHOUT any secret material.
    ///
    /// # Errors
    /// The file is missing, unreadable, or not a chaperone vault.
    pub fn sealer_of(path: &Path) -> Result<String, VaultError> {
        let raw = std::fs::read(path).map_err(VaultError::Io)?;
        if !raw.starts_with(MAGIC) {
            return Err(VaultError::Corrupt("not a chaperone vault file".to_owned()));
        }
        let header: Header = serde_json::from_slice(&raw[MAGIC.len()..])
            .map_err(|e| VaultError::Corrupt(format!("header: {e}")))?;
        Ok(header.sealer_name)
    }

    /// Stores (or overwrites) the secret at `path`.
    ///
    /// The value lives in a [`SecretString`] until this call ends.
    pub fn set(&mut self, entry_path: &str, value: SecretString) -> Result<(), VaultError> {
        let mut body = self.decrypt_entries()?;
        body.entries
            .insert(entry_path.to_owned(), value.expose().to_owned());
        self.rewrite(body)
    }

    /// Resolves one entry into a fresh [`SecretString`].
    ///
    /// The decrypted body exists ONLY inside this call frame; every call is
    /// a fresh fetch (no caching anywhere - ARCH §2.9).
    pub fn get(&self, entry_path: &str) -> Result<Option<SecretString>, VaultError> {
        let body = self.decrypt_entries()?;
        Ok(body
            .entries
            .get(entry_path)
            .map(|v| SecretString::new(v.clone())))
    }

    /// Removes an entry; returns whether it existed.
    pub fn delete(&mut self, entry_path: &str) -> Result<bool, VaultError> {
        let mut body = self.decrypt_entries()?;
        let existed = body.entries.remove(entry_path).is_some();
        if existed {
            self.rewrite(body)?;
        }
        Ok(existed)
    }

    /// All stored entry paths (names only; no decryption of values needed
    /// beyond the body they live inside).
    pub fn list(&self) -> Result<Vec<String>, VaultError> {
        let body = self.decrypt_entries()?;
        Ok(body.entries.keys().cloned().collect())
    }

    fn decrypt_entries(&self) -> Result<Body, VaultError> {
        decrypt_body(&self.dek, &self.body_nonce, &self.body_ciphertext)
    }

    fn rewrite(&mut self, body: Body) -> Result<(), VaultError> {
        // Fresh nonce per write: GCM nonce reuse would be catastrophic.
        OsRng.fill_bytes(&mut self.body_nonce);
        self.body_ciphertext = encrypt_body(&self.dek, &self.body_nonce, &body)?;
        let header = Header {
            version: 1,
            sealer_name: self.sealer_name.clone(),
            kdf: self.kdf.clone(),
            sealed_dek_b64: b64(&self.sealed_dek),
            body_nonce_b64: b64(&self.body_nonce),
            body_b64: b64(&self.body_ciphertext),
        };
        persist(&self.path, &header)
    }
}
