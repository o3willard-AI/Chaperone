//! Enrollment: the operator-controlled binding of `agent_id` to a public key.
//!
//! Enrollment is an operator action (ARCH-SPEC §2.2); this store is read-only
//! at request time and written only through operator commands. Revocation is
//! effective immediately: a revoked key resolves to nothing, so it fails at
//! step 1 of verification with `E_UNKNOWN_AGENT`.
//!
//! Persistence is an atomically-replaced JSON file (temp file + rename) so a
//! crash mid-write can never leave a half-written store behind.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// One agent identity, in memory and on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    /// Stable agent identity string (e.g. `agent:planner-7`).
    pub agent_id: String,
    /// Ed25519 public key, base64url of the 32-byte compressed point.
    pub public_key: String,
    /// RFC 3339 UTC enrollment timestamp.
    pub enrolled_at: String,
    /// RFC 3339 UTC revocation timestamp, set when revoked. Absent while live.
    #[serde(default)]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    agents: Vec<EnrollmentRecord>,
}

struct StoredAgent {
    key: VerifyingKey,
    record: EnrollmentRecord,
}

struct Inner {
    agents: HashMap<String, StoredAgent>,
}

/// Failures of enrollment operations (operator-side, never request-path).
#[derive(Debug)]
#[non_exhaustive]
pub enum EnrollmentError {
    /// The underlying file could not be read or written.
    Io(std::io::Error),
    /// Persisted data did not parse or is from an unknown era.
    Corrupt(String),
    /// Public key was not valid base64url of exactly 32 bytes.
    BadPublicKey(String),
    /// A live (non-revoked) enrollment already exists for this id; revoke
    /// first, or rotate explicitly.
    Duplicate(String),
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollmentError::Io(e) => write!(f, "enrollment store i/o: {e}"),
            EnrollmentError::Corrupt(e) => write!(f, "enrollment store corrupt: {e}"),
            EnrollmentError::BadPublicKey(e) => {
                write!(f, "public key must be base64url of 32 bytes: {e}")
            }
            EnrollmentError::Duplicate(id) => {
                write!(
                    f,
                    "agent {id} is already enrolled and live; revoke first to rotate"
                )
            }
        }
    }
}

impl std::error::Error for EnrollmentError {}

/// Decodes and validates a base64url-encoded Ed25519 public key.
///
/// Shared by the CLI so the operator path validates exactly what the store
/// accepts.
pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey, EnrollmentError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let raw = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|e| EnrollmentError::BadPublicKey(e.to_string()))?;
    let bytes: &[u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| EnrollmentError::BadPublicKey(format!("got {} bytes", raw.len())))?;
    VerifyingKey::from_bytes(bytes).map_err(|e| EnrollmentError::BadPublicKey(e.to_string()))
}

fn encode_public_key(key: &VerifyingKey) -> String {
    chaperone_protocol::encode_signature(&key.to_bytes())
}

/// The enrollment store: reads are snapshots, writes are operator actions.
pub struct EnrollmentStore {
    path: Option<PathBuf>,
    inner: RwLock<Inner>,
}

impl EnrollmentStore {
    /// An empty in-memory store (tests, ephemeral runs).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            inner: RwLock::new(Inner {
                agents: HashMap::new(),
            }),
        }
    }

    /// Loads a persisted store. A missing file yields an empty store (first
    /// run); anything present must parse or this fails loudly — silently
    /// forgetting enrolled agents would silently widen nothing but would
    /// break attribution, and attribution failures must be loud.
    pub fn load(path: &Path) -> Result<Self, EnrollmentError> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let file: StoreFile = serde_json::from_slice(&bytes)
                    .map_err(|e| EnrollmentError::Corrupt(e.to_string()))?;
                if file.version != 1 {
                    return Err(EnrollmentError::Corrupt(format!(
                        "unsupported store version {}",
                        file.version
                    )));
                }
                let mut agents = HashMap::with_capacity(file.agents.len());
                for rec in &file.agents {
                    let key = decode_public_key(&rec.public_key)?;
                    agents.insert(
                        rec.agent_id.clone(),
                        StoredAgent {
                            key,
                            record: rec.clone(),
                        },
                    );
                }
                Ok(Self {
                    path: Some(path.to_path_buf()),
                    inner: RwLock::new(Inner { agents }),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: Some(path.to_path_buf()),
                inner: RwLock::new(Inner {
                    agents: HashMap::new(),
                }),
            }),
            Err(e) => Err(EnrollmentError::Io(e)),
        }
    }

    /// Resolves an `agent_id` to its verifying key at request time.
    ///
    /// Revoked identities resolve to `None`, indistinguishable from unknown,
    /// per ARCH-SPEC §2.2 ("a revoked key fails at step 1").
    #[must_use]
    pub fn lookup(&self, agent_id: &str) -> Option<VerifyingKey> {
        self.lock()
            .agents
            .get(agent_id)
            .filter(|stored| stored.record.revoked_at.is_none())
            .map(|stored| stored.key)
    }

    /// Enrolls an agent's public key; rotates only across a revoked entry or
    /// with explicit force.
    pub fn enroll(
        &self,
        agent_id: &str,
        public_key_b64url: &str,
        now_rfc3339: &str,
        force_rotate: bool,
    ) -> Result<(), EnrollmentError> {
        let key = decode_public_key(public_key_b64url)?;
        let record = EnrollmentRecord {
            agent_id: agent_id.to_owned(),
            public_key: encode_public_key(&key),
            enrolled_at: now_rfc3339.to_owned(),
            revoked_at: None,
        };

        {
            let mut guard = self.lock_mut();
            if let Some(existing) = guard.agents.get(agent_id)
                && existing.record.revoked_at.is_none()
                && !force_rotate
            {
                return Err(EnrollmentError::Duplicate(agent_id.to_owned()));
            }
            let _ = guard
                .agents
                .insert(agent_id.to_owned(), StoredAgent { key, record });
        }

        self.persist()
    }

    /// Revokes an agent, effective immediately. Returns whether an entry
    /// existed (already-revoked entries count as existing).
    pub fn revoke(&self, agent_id: &str, now_rfc3339: &str) -> Result<bool, EnrollmentError> {
        let existed = {
            let mut guard = self.lock_mut();
            match guard.agents.get_mut(agent_id) {
                Some(stored) => {
                    stored
                        .record
                        .revoked_at
                        .get_or_insert_with(|| now_rfc3339.to_owned());
                    true
                }
                None => false,
            }
        };
        if existed {
            self.persist()?;
        }
        Ok(existed)
    }

    /// All records, sorted by agent id (operator listing).
    #[must_use]
    pub fn list(&self) -> Vec<EnrollmentRecord> {
        let mut out: Vec<EnrollmentRecord> = self
            .lock()
            .agents
            .values()
            .map(|stored| stored.record.clone())
            .collect();
        out.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        out
    }

    fn lock(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_mut(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Rewrites the store atomically from in-memory truth.
    fn persist(&self) -> Result<(), EnrollmentError> {
        let Some(path) = &self.path else {
            return Ok(()); // in-memory store: nothing to persist
        };

        let snapshot: Vec<EnrollmentRecord> = {
            // Take read data under lock, drop it before doing file I/O.
            self.list()
        };

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(EnrollmentError::Io)?;

        let file = StoreFile {
            version: 1,
            agents: snapshot,
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| EnrollmentError::Corrupt(e.to_string()))?;

        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(EnrollmentError::Io)?;
        // Temp files are created 0600 by tempfile; the rename keeps those
        // bits on the final path.
        if let Err(e) = tmp.write_all(&bytes) {
            return Err(EnrollmentError::Io(e));
        }
        if let Err(pe) = tmp.persist(path) {
            return Err(EnrollmentError::Io(pe.error));
        }
        Ok(())
    }
}
