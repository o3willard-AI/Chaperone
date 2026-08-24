//! Chaperone mechanism injectors.
//!
//! One module per mechanism (ARCH-SPEC §2.5). An injector receives a
//! [`chaperone_vault::SecretString`] handle plus the verified operation and
//! completes the mechanism on the outbound side. Injectors are the ONLY
//! components that touch secret material, and each touches only its own.
//!
//! Layer contract (ARCH-SPEC §1.1): depends on the vault handle type and the
//! policy decision; never on signing keys or other injectors. Compiled-in
//! for v1; the prepare/inject/teardown plugin ABI arrives later (ARCH §2.5).
//!
//! Implemented in PLAN Phase 6 ([PLAN](../../docs/PLAN.md) M6): `http`.
//! `ssh` / `db-scram` / `local-privilege` land in M8/M9.

pub mod http;

/// Why an injection failed (PROTO-SPEC `E_MECHANISM` territory).
#[derive(Debug)]
#[non_exhaustive]
pub enum InjectorError {
    /// The operation was structurally invalid for this mechanism.
    BadOperation(String),
    /// The credential could not be attached (e.g. non-header-safe bytes).
    CredentialUnusable,
    /// The outbound call failed at transport level.
    Transport(String),
    /// The target's response violated a ceiling (T3 defenses).
    ResponseTooLarge {
        /// The cap that was exceeded, bytes.
        limit: u64,
    },
}

impl std::fmt::Display for InjectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectorError::BadOperation(e) => write!(f, "invalid operation: {e}"),
            InjectorError::CredentialUnusable => {
                write!(f, "credential cannot be attached to this request")
            }
            InjectorError::Transport(e) => write!(f, "outbound call failed: {e}"),
            InjectorError::ResponseTooLarge { limit } => {
                write!(f, "response exceeded the {limit}-byte ceiling")
            }
        }
    }
}

impl std::error::Error for InjectorError {}
