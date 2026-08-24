//! The provider abstraction and `cred_ref` dispatch (ARCH-SPEC §2.4).
//!
//! A `cred_ref` is `scheme://rest`; the [`VaultRouter`] hands `rest` to the
//! provider registered for `scheme`. The router holds NO secret state and
//! performs no caching - every resolve is a fresh backend call (ARCH §2.9),
//! which is what makes "a retry is a fresh fetch" true by construction.

use crate::secret::SecretString;

/// Failures resolving a credential reference.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResolveError {
    /// The reference was not of the form `scheme://rest`.
    MalformedCredRef(String),
    /// No provider is configured for that scheme.
    UnsupportedScheme {
        /// The unknown scheme.
        scheme: String,
        /// Schemes this gateway can serve.
        supported: Vec<String>,
    },
    /// The provider knows the scheme but not this entry.
    EntryNotFound(String),
    /// Backend failure.
    Backend(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Deliberately does NOT echo the raw value: agents that paste
            // secret-shaped strings here must not have them amplified into
            // logs via error reasons.
            ResolveError::MalformedCredRef(_) => {
                write!(f, "cred_ref must look like scheme://entry-path")
            }
            ResolveError::UnsupportedScheme { scheme, supported } => write!(
                f,
                "no provider for scheme {scheme:?} (supported: {})",
                supported.join(", ")
            ),
            ResolveError::EntryNotFound(path) => write!(f, "credential {path:?} does not exist"),
            ResolveError::Backend(e) => write!(f, "vault backend: {e}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// One secret backend behind a `scheme`.
///
/// Implementations MUST return a fresh fetch on every call: caching inside a
/// provider would defeat ARCH §2.9's re-fetch-on-retry tenet.
pub trait Provider: Send + Sync {
    /// Freshly resolves one entry into a zeroizing handle.
    fn resolve(&self, entry: &str) -> Result<SecretString, ResolveError>;

    /// Mints the narrowest short-lived credential for an operation where the
    /// backend supports dynamic secrets (ARCH §2.4). Static backends report
    /// unsupported rather than pretending to scope.
    fn mint(&self, _entry: &str, _ttl_secs: u64) -> Result<SecretString, ResolveError> {
        Err(ResolveError::Backend(
            "backend does not support short-lived minting".to_owned(),
        ))
    }
}

impl Provider for crate::local::LocalVault {
    fn resolve(&self, entry: &str) -> Result<SecretString, ResolveError> {
        self.get(entry)
            .map_err(|e| ResolveError::Backend(e.to_string()))?
            .ok_or_else(|| ResolveError::EntryNotFound(entry.to_owned()))
    }
}

/// Dispatches `cred_ref`s across registered providers.
#[derive(Default)]
pub struct VaultRouter {
    providers: std::collections::BTreeMap<String, std::sync::Arc<dyn Provider>>,
}

impl VaultRouter {
    /// Empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a provider under its URI scheme.
    pub fn register(&mut self, scheme: &str, provider: std::sync::Arc<dyn Provider>) {
        self.providers.insert(scheme.to_owned(), provider);
    }

    /// Schemes currently served.
    #[must_use]
    pub fn schemes(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    /// Splits `scheme://entry` and resolves it fresh through the provider.
    pub fn resolve(&self, cred_ref: &str) -> Result<SecretString, ResolveError> {
        let (scheme, entry) = cred_ref
            .split_once("://")
            .ok_or_else(|| ResolveError::MalformedCredRef(cred_ref.to_owned()))?;
        if scheme.is_empty() || entry.is_empty() {
            return Err(ResolveError::MalformedCredRef(cred_ref.to_owned()));
        }
        let provider =
            self.providers
                .get(scheme)
                .ok_or_else(|| ResolveError::UnsupportedScheme {
                    scheme: scheme.to_owned(),
                    supported: self.schemes(),
                })?;
        provider.resolve(entry)
    }
}
