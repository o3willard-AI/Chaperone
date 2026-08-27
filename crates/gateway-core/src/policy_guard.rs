//! Policy-file integrity guard (DESIGN-DECISIONS D39).
//!
//! Two layers over the anchored-hash work of D38:
//!
//! 1. **Load-time permission gate** ([`verify_permissions`]): a policy file
//!    that is group/other-writable or owned by a different account is
//!    refused at startup with a remediation-shaped message. Same discipline
//!    ssh applies to `authorized_keys`: cheap, portable, and loud.
//!
//! 2. **Live drift watch** ([`PolicyWatch`]): while serving, the file's
//!    SHA-256 is periodically recomputed against the hash the gateway
//!    loaded (the same value every audit decision carries). Any divergence -
//!    edit, replacement, deletion - appends one signed `policy_drift` audit
//!    record, broadcasts on the events feed, and **halts brokering** until
//!    an operator restarts the process with an intact policy. Fail-closed:
//!    a tampered file can never take effect silently, because the rules in
//!    memory stop being consulted at all.
//!
//! Honest limits (per-user threat model): this detects and stops; it does
//! not physically prevent a same-user writer from editing the file. The
//! restart that follows re-runs the permission gate and re-anchors the
//! chain, so what survives is exactly what an operator re-approved by
//! starting the daemon again.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use chaperone_audit::{AuditEvent, AuditWriter, Outcome, RecordKind};

use crate::Gateway;
use crate::events::EventHub;

/// Default cadence for the drift watch.
#[must_use]
pub fn default_watch_interval() -> Duration {
    Duration::from_secs(5)
}

/// Lowercase hex SHA-256 of raw document bytes - identical to how
/// [`chaperone_policy::Policy`] hashes its source, so the two agree.
#[must_use]
pub fn hash_doc_bytes(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Load-time permission gate for the governing policy file (D39).
///
/// Unix: refuses when the file is group/other-writable (`chmod go-w`) or
/// not owned by the running user. Non-unix: a documented no-op for now -
/// the Windows ACL story is the same tracked gap as the named-pipe socket
/// work, not silently claimed as covered.
pub fn verify_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta =
            std::fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "{} is group/other-writable (mode {:04o}); a policy file must be \
                 writable only by its owner. fix: chmod go-w {}",
                path.display(),
                mode & 0o7777,
                path.display()
            ));
        }
        if meta.uid() != rustix::process::geteuid().as_raw() {
            return Err(format!(
                "{} is owned by uid {} but the gateway runs as uid {}; refusing a \
                 policy someone else controls",
                path.display(),
                meta.uid(),
                rustix::process::geteuid().as_raw()
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// One observed divergence between disk and the loaded ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    /// Hex SHA-256 of the file as now observed ('' when unreadable).
    pub observed_hash: String,
    /// What kind of divergence was seen.
    pub detail: &'static str,
}

/// Result of a single observation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// File present, hash matches the loaded baseline.
    Consistent,
    /// Read failed once without priors - could be an editor mid-rename;
    /// one more failing tick confirms.
    Unconfirmed,
    /// A confirmed divergence worth halting over.
    Drift(Drift),
}

/// The running watch: baseline hash + poll cadence. Cheap to clone-free
/// move into the spawned task.
pub struct PolicyWatch {
    path: PathBuf,
    baseline: String,
    interval: Duration,
}

impl PolicyWatch {
    /// Watches `path`, whose content hashed to `baseline_hex` at load.
    #[must_use]
    pub fn new(path: PathBuf, baseline_hex: String) -> Self {
        Self {
            path,
            baseline: baseline_hex,
            interval: default_watch_interval(),
        }
    }

    /// Overrides the poll cadence (tests use small values).
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Single observation, no side effects.
    ///
    /// Content mismatch and file-missing are immediate drift. Other read
    /// failures are [`Observation::Unconfirmed`] the first time (editors
    /// mid-rename) and drift on a consecutive failure - unreadable is
    /// indistinguishable from tampered-from-here.
    #[must_use]
    pub fn check_once(&self, prior_failures: u32) -> Observation {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let observed = hash_doc_bytes(&bytes);
                if observed == self.baseline {
                    Observation::Consistent
                } else {
                    Observation::Drift(Drift {
                        observed_hash: observed,
                        detail: "content changed",
                    })
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Observation::Drift(Drift {
                observed_hash: String::new(),
                detail: "file missing",
            }),
            Err(_) if prior_failures >= 1 => Observation::Drift(Drift {
                observed_hash: String::new(),
                detail: "file unreadable",
            }),
            Err(_) => Observation::Unconfirmed,
        }
    }

    /// Runs until the task is dropped: polls, and on first drift records,
    /// broadcasts, and halts the gateway. Halting is sticky; subsequent
    /// ticks do nothing.
    pub async fn run(
        self,
        gateway: Arc<Gateway>,
        audit: Arc<AuditWriter>,
        event_hub: Option<Arc<EventHub>>,
    ) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failures: u32 = 0;
        loop {
            ticker.tick().await;
            if gateway.is_halted() {
                continue;
            }
            match self.check_once(failures) {
                // Consecutive-failure counting only: a healthy read clears
                // the streak, a second failing read confirms drift.
                Observation::Consistent => failures = 0,
                Observation::Unconfirmed => failures += 1,
                Observation::Drift(drift) => {
                    fire_drift(&gateway, &audit, event_hub.as_ref(), &self.baseline, &drift);
                }
            }
        }
    }
}

/// Halt + signed audit record + events broadcast + loud stderr. One place,
/// so the four effects cannot drift apart.
fn fire_drift(
    gateway: &Arc<Gateway>,
    audit: &Arc<AuditWriter>,
    event_hub: Option<&Arc<EventHub>>,
    baseline: &str,
    drift: &Drift,
) {
    let reason = format!(
        "policy integrity guard: {} (loaded {}, observed {})",
        drift.detail,
        short(baseline),
        short(&drift.observed_hash),
    );
    gateway.halt(&reason);

    let event = AuditEvent {
        record_kind: RecordKind::PolicyDrift,
        ruleset_hash: baseline.to_owned(),
        agent_id: "",
        msg_id: "",
        mechanism: "policy",
        target_uri: "",
        target_label: "",
        cred_ref: "",
        effect: "",
        outcome: Outcome::PolicyDrift {
            observed_hash: drift.observed_hash.clone(),
            detail: drift.detail.to_owned(),
        },
        intent_envelope: &serde_json::Value::Null,
    };
    let seq = audit.append(&event).ok().map(|h| h.seq);

    if let Some(hub) = event_hub {
        hub.broadcast(
            &serde_json::json!({
                "type": "policy_drift",
                "audit_id": format!("aud_{}", seq.unwrap_or(0)),
                "ruleset_hash": baseline,
                "observed_hash": drift.observed_hash,
                "detail": drift.detail,
                "halted": true,
            })
            .to_string(),
        );
    }

    eprintln!(
        "\nCHAPERONE POLICY INTEGRITY ALERT\n  {reason}\n  brokering halted; review the file, then restart the gateway"
    );
}

fn short(hex: &str) -> String {
    hex.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn hash_matches_policy_crate_convention() {
        // Same document, same hash the parser records as source_hash.
        let doc = "[[rule]]\neffect = \"deny\"\n";
        let policy = chaperone_policy::Policy::from_toml(doc).unwrap();
        assert_eq!(hash_doc_bytes(doc.as_bytes()), policy.source_hash());
    }

    #[cfg(unix)]
    #[test]
    fn permissions_reject_writable_modes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.toml");
        std::fs::write(&p, "").unwrap();

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify_permissions(&p).is_ok());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(verify_permissions(&p).is_ok());
        // Readable-by-others is fine; only WRITE bits are refused.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o604)).unwrap();
        assert!(verify_permissions(&p).is_ok());

        for bad in [0o646u32, 0o666, 0o662, 0o626] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(bad)).unwrap();
            let err = verify_permissions(&p).unwrap_err();
            assert!(err.contains("writable"), "mode {bad:04o}: {err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn permissions_missing_file_is_error() {
        assert!(verify_permissions(Path::new("/nonexistent/policy.toml")).is_err());
    }

    #[test]
    fn check_once_reports_content_and_deletion_drift() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.toml");
        std::fs::write(&p, "a = 1\n").unwrap();
        let watch = PolicyWatch::new(p.clone(), hash_doc_bytes(b"a = 1\n"));

        assert_eq!(watch.check_once(0), Observation::Consistent);

        std::fs::write(&p, "a = 2\n").unwrap();
        assert_eq!(
            watch.check_once(0),
            Observation::Drift(Drift {
                observed_hash: hash_doc_bytes(b"a = 2\n"),
                detail: "content changed",
            })
        );

        std::fs::remove_file(&p).unwrap();
        assert_eq!(
            watch.check_once(0),
            Observation::Drift(Drift {
                observed_hash: String::new(),
                detail: "file missing",
            })
        );
    }

    #[test]
    fn transient_read_failure_needs_two_ticks() {
        // A directory: exists, but read(2) fails with EISDIR - the
        // "unreadable but not missing" branch.
        let dir = tempfile::tempdir().unwrap();
        let watch = PolicyWatch::new(dir.path().to_path_buf(), "x".repeat(64));
        // First tick: tolerated (could be an editor mid-replace).
        assert_eq!(watch.check_once(0), Observation::Unconfirmed);
        // Second consecutive failure: drift.
        assert_eq!(
            watch.check_once(1),
            Observation::Drift(Drift {
                observed_hash: String::new(),
                detail: "file unreadable",
            })
        );
    }
}
