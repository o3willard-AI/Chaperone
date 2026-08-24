//! Chaperone vault abstraction.
//!
//! A uniform interface over heterogeneous secret backends (ARCH-SPEC §2.4):
//! a `cred_ref` URI names a backend and path; the configured provider driver
//! resolves it, requesting the narrowest, shortest-lived credential the
//! backend can mint. Includes the built-in encrypted local vault (`local://`),
//! sealed to the platform key store, so the system works with no external
//! dependency.
//!
//! This layer also implements the ephemerality contract (ARCH-SPEC §2.9):
//! fetch late, hold minimally in zeroize-on-drop buffers, scrub always on
//! success or failure, re-fetch fresh on every retry. Caching a secret to
//! smooth a retry is prohibited here and everywhere downstream.
//!
//! Layer contract (ARCH-SPEC §1.1): injectors depend on its handle type;
//! the policy engine never touches it.
//!
//! Implemented in PLAN Phase 5 ([PLAN](../../docs/PLAN.md) M5).

mod local;
pub mod provider;
pub mod sealer;
mod secret;

pub use local::{LocalVault, VaultError};
pub use provider::{Provider, ResolveError, VaultRouter};
#[cfg(feature = "keyring")]
pub use sealer::KeyringSealer;
pub use sealer::{KdfParams, PassphraseSealer, Sealer, SealerError};
pub use secret::SecretString;
