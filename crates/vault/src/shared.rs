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

impl Provider for SharedVault {
    fn resolve<'a>(&'a self, entry: &'a str) -> SecretFuture<'a> {
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
        let mut vault =
            LocalVault::create(&dir.path().join("v.bin"), Zeroizing::new("pass".to_owned()))
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
}
