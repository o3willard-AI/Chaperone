//! Sharing one opened [`LocalVault`] between the gateway's router and the
//! operator config UI (D40).
//!
//! The daemon opens the vault once (one passphrase prompt) and hands the
//! SAME sealed handle to both consumers. There is still exactly one
//! implementation of the vault format and one live instance - the wrapper
//! here only arbitrates interior access.

use std::sync::{Arc, Mutex, MutexGuard};

use crate::local::LocalVault;
use crate::provider::{Provider, ResolveError, SecretFuture};

/// A [`LocalVault`] behind a mutex, usable as a [`Provider`].
#[derive(Clone)]
pub struct SharedVault {
    inner: Arc<Mutex<LocalVault>>,
}

impl SharedVault {
    /// Wraps an already-opened vault.
    #[must_use]
    pub fn new(vault: LocalVault) -> Self {
        Self {
            inner: Arc::new(Mutex::new(vault)),
        }
    }

    /// The underlying shared handle for operator-side CRUD (the UI holds
    /// this same Arc; mutations lock, rewrite the file, and release).
    #[must_use]
    pub fn handle(&self) -> Arc<Mutex<LocalVault>> {
        Arc::clone(&self.inner)
    }

    /// Locks the vault for operator use, recovering a poisoned guard:
    /// a panicked mutation must not permanently brick configuration.
    pub fn lock(&self) -> MutexGuard<'_, LocalVault> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The reserved entry namespace holding the B-1 SSH CA keypair. NON-EXPORTABLE
/// (TD-1): resolves are refused here, and the operator CLI refuses get/set/del
/// on it. Defined here — exactly one place.
pub const CA_NAMESPACE: &str = "chaperone/ca/";

impl Provider for SharedVault {
    fn resolve<'a>(&'a self, entry: &'a str) -> SecretFuture<'a> {
        // B-1 / TD-1 NON-EXPORTABILITY: the SSH CA private key lives in this
        // vault, and a resolve through `local://` would hand it to any intent
        // that names it — the exact leak the ca:// provider's own refusal
        // cannot catch, because intents bypass that provider via the `local`
        // scheme. Refused at THIS boundary (Heph, review 2026-10-05: the
        // refusal belongs where the CA can actually be reached). Minting is
        // unaffected: GatewayCaContext reads through the direct SharedVault
        // handle (get/set), never through this Provider impl.
        if entry.starts_with(CA_NAMESPACE) {
            return Box::pin(async move {
                Err(ResolveError::Backend(
                    "the SSH CA key is non-exportable; minting is the only \
                     operation it serves"
                        .to_owned(),
                ))
            });
        }
        Box::pin(async move {
            let vault = self.lock();
            vault
                .get(entry)
                .map_err(|e| ResolveError::Backend(e.to_string()))?
                .ok_or_else(|| ResolveError::EntryNotFound(entry.to_owned()))
        })
    }
}

/// Convenience so callers never hand-build `Arc<Mutex<..>>` shapes.
impl From<LocalVault> for SharedVault {
    fn from(vault: LocalVault) -> Self {
        Self::new(vault)
    }
}

impl std::fmt::Debug for SharedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedVault")
            .field("locked_entries", &"<vault>")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::secret::SecretString;
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn resolves_through_the_shared_handle() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = LocalVault::create(
            &dir.path().join("v.bin"),
            "passphrase",
            Zeroizing::new("pass".to_owned()),
        )
        .unwrap();
        vault
            .set("a/b", SecretString::new("s3cret".to_owned()))
            .unwrap();

        let shared = SharedVault::new(vault);
        assert_eq!(shared.resolve("a/b").await.unwrap().expose(), "s3cret");
        assert!(matches!(
            shared.resolve("missing").await,
            Err(ResolveError::EntryNotFound(_))
        ));

        // Operator CRUD through the same handle stays consistent.
        shared
            .lock()
            .set("a/c", SecretString::new("x".to_owned()))
            .unwrap();
        assert_eq!(shared.resolve("a/c").await.unwrap().expose(), "x");
    }

    #[tokio::test]
    async fn ca_namespace_is_never_resolvable_through_local() {
        // B-1 / TD-1 regression (Heph review 2026-10-05, merge blocker):
        // an intent naming `local://chaperone/ca/ssh` must NOT hand the CA
        // private key to the caller. The guard lives in SharedVault's
        // Provider impl — the boundary an intent actually reaches — and is
        // asserted here through a REAL VaultRouter with a seeded CA, exactly
        // as the gateway's router is wired.
        let dir = tempfile::tempdir().unwrap();
        let mut vault = LocalVault::create(
            &dir.path().join("v.bin"),
            "passphrase",
            Zeroizing::new("pass".to_owned()),
        )
        .unwrap();
        vault
            .set(
                "chaperone/ca/ssh",
                SecretString::new("FAKE-CA-PRIVATE-KEY".to_owned()),
            )
            .unwrap();
        vault
            .set("normal/entry", SecretString::new("ok".to_owned()))
            .unwrap();

        let mut router = crate::VaultRouter::new();
        router.register("local", std::sync::Arc::new(SharedVault::new(vault)));

        for ref_name in ["local://chaperone/ca/ssh", "local://chaperone/ca/other"] {
            let err = router.resolve(ref_name).await.unwrap_err().to_string();
            assert!(
                err.contains("non-exportable"),
                "resolve of {ref_name} must be refused as non-exportable, got: {err}"
            );
        }

        // The guard is namespace-scoped, not vault-wide: a non-CA entry in
        // the same vault still resolves.
        assert!(router.resolve("local://normal/entry").await.is_ok());
    }
}
