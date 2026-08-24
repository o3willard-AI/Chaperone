//! SSH host-key pin store (DESIGN-DECISIONS D31).
//!
//! Replaces the D23 stopgap ("refuse all / trust-all opt-out") with a real
//! trust-on-first-use journal plus OpenSSH `known_hosts` import:
//!
//! - **First contact**: with TOFU enabled, an unseen host's key is recorded
//!   and accepted; without TOFU it is refused (strict default).
//! - **Pinned match**: accepted.
//! - **Changed key**: REFUSED and reported - a changed key on a pinned host
//!   is exactly the man-in-the-middle signal this store exists to catch.
//!
//! File format is JSON (atomic temp+rename writes, owner-only perms), one
//! document listing pins. OpenSSH-format import covers the migration path;
//! wildcard host patterns are rejected on import (they widen authority).

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// One pinned host key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pin {
    /// `host` or `host:port` identity the key is pinned under.
    pub hostport: String,
    /// OpenSSH public-key line (e.g. `ssh-ed25519 AAAA... comment`).
    pub openssh_key: String,
    /// RFC 3339 UTC time the pin was created.
    pub first_seen: String,
    /// How the pin arrived: `import` or `tofu`.
    pub source: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    pins: Vec<Pin>,
}

/// Failures of pin-store operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum PinStoreError {
    /// Underlying file i/o.
    Io(std::io::Error),
    /// Persisted data did not parse.
    Corrupt(String),
    /// Serialization failed.
    Serialize(String),
}

impl std::fmt::Display for PinStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinStoreError::Io(e) => write!(f, "known-hosts i/o: {e}"),
            PinStoreError::Corrupt(e) => write!(f, "known-hosts corrupt: {e}"),
            PinStoreError::Serialize(e) => write!(f, "known-hosts serialize: {e}"),
        }
    }
}

impl std::error::Error for PinStoreError {}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "<time-error>".to_owned())
}

/// The pin store: reads are snapshots; writes are atomic replacements.
pub struct PinStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, Pin>>,
}

impl PinStore {
    /// Loads (or creates) the store at `path`.
    pub fn load(path: &Path) -> Result<Self, PinStoreError> {
        let mut map = HashMap::new();
        match std::fs::read_to_string(path) {
            Ok(text) if text.trim().is_empty() => {}
            Ok(text) => {
                let file: StoreFile = serde_json::from_str(&text)
                    .map_err(|e| PinStoreError::Corrupt(e.to_string()))?;
                if file.version != 1 {
                    return Err(PinStoreError::Corrupt(format!(
                        "unknown known-hosts version {}",
                        file.version
                    )));
                }
                for pin in file.pins {
                    map.insert(pin.hostport.clone(), pin);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(PinStoreError::Io(e)),
        }
        Ok(Self {
            path: path.to_path_buf(),
            inner: Mutex::new(map),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pin>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Looks up the pin for a `host[:port]` identity.
    #[must_use]
    pub fn get(&self, hostport: &str) -> Option<Pin> {
        self.lock().get(hostport).cloned()
    }

    /// Records a new pin. Fails if one already exists for the identity
    /// (changing a pin is an explicit operator action, see [`Self::replace`]).
    pub fn insert(
        &self,
        hostport: &str,
        openssh_key: &str,
        source: &str,
    ) -> Result<(), PinStoreError> {
        {
            let guard = self.lock();
            if guard.contains_key(hostport) {
                // Idempotent for identical keys; conflict otherwise.
                if guard[hostport].openssh_key == openssh_key {
                    return Ok(());
                }
                return Err(PinStoreError::Corrupt(format!(
                    "{hostport} is already pinned to a DIFFERENT key; \
                     an operator must review and replace the pin"
                )));
            }
        }
        self.lock().insert(
            hostport.to_owned(),
            Pin {
                hostport: hostport.to_owned(),
                openssh_key: openssh_key.to_owned(),
                first_seen: now_rfc3339(),
                source: source.to_owned(),
            },
        );
        self.persist()
    }

    /// Operator-reviewed replacement of an existing pin.
    pub fn replace(
        &self,
        hostport: &str,
        openssh_key: &str,
        reason: &str,
    ) -> Result<bool, PinStoreError> {
        let replaced = {
            let mut guard = self.lock();
            match guard.get_mut(hostport) {
                Some(pin) => {
                    pin.openssh_key = openssh_key.to_owned();
                    pin.first_seen = now_rfc3339();
                    pin.source = format!("replace:{reason}");
                    true
                }
                None => false,
            }
        };
        if replaced {
            self.persist()?;
        }
        Ok(replaced)
    }

    /// All pins, sorted by hostport (operator listing).
    #[must_use]
    pub fn list(&self) -> Vec<Pin> {
        let mut out: Vec<Pin> = self.lock().values().cloned().collect();
        out.sort_by(|a, b| a.hostport.cmp(&b.hostport));
        out
    }

    fn persist(&self) -> Result<(), PinStoreError> {
        let snapshot = self.list();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(PinStoreError::Io)?;
        }
        let file = StoreFile {
            version: 1,
            pins: snapshot,
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| PinStoreError::Serialize(e.to_string()))?;
        let mut tmp =
            tempfile::NamedTempFile::new_in(self.path.parent().unwrap_or_else(|| Path::new(".")))
                .map_err(PinStoreError::Io)?;
        tmp.write_all(&bytes)
            .and_then(|_| tmp.flush())
            .map_err(PinStoreError::Io)?;
        tmp.persist(&self.path)
            .map_err(|pe| PinStoreError::Io(pe.error))?;
        Ok(())
    }
}

/// Parses an OpenSSH `known_hosts` file into pins.
///
/// Only plain `host` / `host:port` patterns are imported: wildcards and
/// hashed entries are skipped and REPORTED (wildcards would widen exactly
/// the authority this store exists to constrain).
pub fn parse_openssh_known_hosts(text: &str) -> (Vec<Pin>, Vec<String>) {
    let mut pins = Vec::new();
    let mut skipped = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(patterns) = fields.next() else {
            continue;
        };
        let Some(keytype) = fields.next() else {
            continue;
        };
        let Some(keybody) = fields.next() else {
            continue;
        };
        if patterns.starts_with('|')
            || patterns.contains(',')
            || patterns.contains('*')
            || patterns.contains('?')
            || patterns.starts_with('!')
        {
            skipped.push(format!("line {}: patterned/hashed entry", i + 1));
            continue;
        }
        pins.push(Pin {
            hostport: normalize_hostport(patterns),
            openssh_key: format!("{keytype} {keybody}"),
            first_seen: now_rfc3339(),
            source: "import".to_owned(),
        });
    }
    (pins, skipped)
}

/// Normalizes bare-host entries to `host` (default port implied); explicit
/// `host:port` entries keep their port suffix.
#[must_use]
pub fn normalize_hostport(pattern: &str) -> String {
    pattern.to_owned()
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    const ED_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1234567890abcdefghijklmnopqrstuvwxyz1234567890";

    #[test]
    fn insert_get_and_conflict_detection() {
        let dir = tempfile::tempdir().unwrap();
        let store = PinStore::load(&dir.path().join("kh.json")).unwrap();
        assert!(store.get("app-01").is_none());
        store.insert("app-01", ED_KEY, "tofu").unwrap();
        assert_eq!(store.get("app-01").unwrap().openssh_key, ED_KEY);

        let different = &ED_KEY.replace("AAAA", "BBBB");
        assert!(store.insert("app-01", different, "tofu").is_err());
        // Identical re-insert is idempotent.
        store.insert("app-01", ED_KEY, "tofu").unwrap();
    }

    #[test]
    fn replace_requires_existing_pin_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kh.json");
        let store = PinStore::load(&path).unwrap();
        assert!(!store.replace("app-01", ED_KEY, "reviewed").unwrap());

        store.insert("app-01", ED_KEY, "tofu").unwrap();
        let rotated = &ED_KEY.replace("AAAA", "CCCC");
        assert!(store.replace("app-01", rotated, "reviewed").unwrap());

        let reopened = PinStore::load(&path).unwrap();
        assert_eq!(reopened.get("app-01").unwrap().openssh_key, *rotated);
        assert!(
            reopened
                .get("app-01")
                .unwrap()
                .source
                .starts_with("replace:")
        );
    }

    #[test]
    fn openssh_import_skips_wildcards_and_hashed_entries() {
        let text = "\
# a comment
app-01.internal ssh-ed25519 AAAAK1
app-*.internal ssh-ed25519 AAAAWILDCARD
|1|hashed=entry ssh-rsa AAAAHASHED
bastion.internal:2222 ssh-ed25519 AAAABASTION
";
        let (pins, skipped) = parse_openssh_known_hosts(text);
        assert_eq!(pins.len(), 2, "plain entries only");
        assert_eq!(pins[0].hostport, "app-01.internal");
        assert_eq!(pins[1].hostport, "bastion.internal:2222");
        assert_eq!(skipped.len(), 2, "wildcard + hashed skipped");
    }

    #[test]
    fn persistence_round_trips_sorted_listing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kh.json");
        {
            let s = PinStore::load(&path).unwrap();
            s.insert("zebra", ED_KEY, "import").unwrap();
            s.insert("alpha", ED_KEY, "import").unwrap();
        }
        let s = PinStore::load(&path).unwrap();
        let hosts: Vec<String> = s.list().into_iter().map(|p| p.hostport).collect();
        assert_eq!(hosts, vec!["alpha", "zebra"]);
    }
}
