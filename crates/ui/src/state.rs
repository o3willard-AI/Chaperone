//! Shared UI state and small filesystem helpers.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chaperone_gateway_core::{EventHub, Gateway};
use chaperone_identity::EnrollmentStore;
use chaperone_vault::SharedVault;

/// Everything the pages need. One instance per daemon, shared by all
/// handlers behind `Arc`.
pub struct UiState {
    /// Governing policy file (the one the gateway loaded / will load).
    pub policy_path: PathBuf,
    /// Vault store file.
    pub vault_path: PathBuf,
    /// Agent enrollment store.
    pub enrollment_path: PathBuf,
    /// Audit signing-key seed file.
    pub audit_key_path: PathBuf,
    /// Audit journal (status display only).
    pub journal_path: PathBuf,

    /// The opened vault, present in broker mode and after the wizard
    /// creates it; absent before first-run setup completes.
    pub vault: RwLock<Option<SharedVault>>,
    /// Enrollment store (auto-provisions on first enroll).
    pub enrollment: Arc<EnrollmentStore>,
    /// Live gateway handle - `None` in setup-only mode.
    pub gateway: Option<Arc<Gateway>>,
    /// Event hub for subscriber counts + feed hint.
    pub event_hub: Option<Arc<EventHub>>,
    /// Bound events socket path, when one was requested.
    pub events_socket_path: Option<PathBuf>,

    /// Registered `cred_ref` schemes (picker suggestions).
    pub schemes: Vec<String>,

    /// Loopback port this UI is bound to (host/origin checks).
    pub port: u16,
}

impl UiState {
    /// Number of setup artifacts still missing.
    #[must_use]
    pub fn setup_pending(&self) -> usize {
        self.provisioned().missing()
    }

    /// Which required artifacts exist on disk.
    ///
    /// The broker needs all three to start; the enrollment store
    /// self-provisions on first enroll and is therefore informational.
    pub fn provisioned(&self) -> Provision {
        Provision {
            policy: self.policy_path.exists(),
            vault: self.vault_path.exists(),
            audit_key: self.audit_key_path.exists(),
            enrollment: self.enrollment_path.exists(),
        }
    }

    /// Current policy parsed best-effort.
    pub fn current_policy(&self) -> Result<chaperone_policy::Policy, String> {
        let doc = std::fs::read_to_string(&self.policy_path)
            .map_err(|e| format!("cannot read {}: {e}", self.policy_path.display()))?;
        chaperone_policy::Policy::from_toml(&doc).map_err(|e| e.to_string())
    }
}

/// Presence of each operator artifact.
#[derive(Debug, Clone, Copy)]
pub struct Provision {
    /// policy.toml exists.
    pub policy: bool,
    /// vault store exists.
    pub vault: bool,
    /// audit key seed exists.
    pub audit_key: bool,
    /// enrollment store exists.
    pub enrollment: bool,
}

impl Provision {
    /// All broker-required artifacts present.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.policy && self.vault && self.audit_key
    }

    /// Count of missing broker-required artifacts.
    #[must_use]
    pub fn missing(&self) -> usize {
        usize::from(!self.policy) + usize::from(!self.vault) + usize::from(!self.audit_key)
    }
}

/// Atomic replace-at-0600 write: temp file in the same directory, fsynced
/// by persist, so a crash cannot leave a half-written artifact.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("temp file in {}: {e}", parent.display()))?;
    tmp.write_all(contents).map_err(|e| e.to_string())?;
    tmp.flush().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    tmp.persist(path)
        .map_err(|pe| format!("persist {}: {}", path.display(), pe.error))?;
    Ok(())
}
