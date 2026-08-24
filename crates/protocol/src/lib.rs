//! Chaperone wire-contract types.
//!
//! This crate mirrors [`docs/01-protocol-spec.md`](../../docs/01-protocol-spec.md)
//! (PROTO-SPEC v0.1), which governs all other artifacts. It holds the pieces of
//! the contract every layer must agree on: the protocol version and the error
//! taxonomy. The intent envelope itself lands here in Phase 1/2
//! ([PLAN](../../docs/PLAN.md) M1/M2).
//!
//! Dependency direction: everything may depend on this crate; it depends on
//! nothing (ARCH-SPEC §1.1).

pub mod envelope;
pub mod ops;
pub use ops::{DbOperation, PgEndpoint, parse_pg_uri};
#[cfg(feature = "test-util")]
pub mod testutil;

pub use envelope::{
    CanonicalError, Constraints, Envelope, EnvelopeKind, Target, canonical_form,
    canonical_form_excluding, decode_signature, encode_signature,
};

/// Protocol version implemented by this codebase (PROTO-SPEC §5, §10.2).
///
/// `chaperone` is `MAJOR.MINOR`; a gateway MUST reject a MAJOR it does not
/// implement with `E_VERSION`. MINOR additions are backward-compatible.
pub const PROTOCOL_VERSION: &str = "0.1";

/// Major version component of [`PROTOCOL_VERSION`].
pub const PROTOCOL_MAJOR: u64 = 0;

/// Minor version component of [`PROTOCOL_VERSION`].
pub const PROTOCOL_MINOR: u64 = 1;

/// Every terminal failure the gateway can report, with its wire string.
///
/// Source of truth: PROTO-SPEC §10.1. Errors never carry secret material and
/// never echo resolved credentials; they echo `msg_id`, `code`, and a
/// human-legible `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Identity: `agent_id` not enrolled.
    UnknownAgent,
    /// Identity: signature failed verification over the canonical form.
    BadSignature,
    /// Identity: stale `issued_at` or reused `nonce`.
    Replay,
    /// Policy: no explicit allow (default-deny) or an explicit deny.
    Denied,
    /// Confirmation: human confirmation not granted within the window.
    ConfirmTimeout,
    /// Vault: `cred_ref` did not resolve, or vault declined to mint.
    CredUnresolved,
    /// Injection: outbound mechanism failed (target refused auth, channel error).
    Mechanism,
    /// Session: session frame signed by an identity other than the opener.
    SessionOwner,
    /// Session: `session_handle` unknown or past TTL.
    SessionExpired,
    /// Envelope: unsupported `chaperone` version.
    Version,
}

impl ErrorCode {
    /// The exact wire string for this code (PROTO-SPEC §10.1).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownAgent => "E_UNKNOWN_AGENT",
            ErrorCode::BadSignature => "E_BAD_SIGNATURE",
            ErrorCode::Replay => "E_REPLAY",
            ErrorCode::Denied => "E_DENIED",
            ErrorCode::ConfirmTimeout => "E_CONFIRM_TIMEOUT",
            ErrorCode::CredUnresolved => "E_CRED_UNRESOLVED",
            ErrorCode::Mechanism => "E_MECHANISM",
            ErrorCode::SessionOwner => "E_SESSION_OWNER",
            ErrorCode::SessionExpired => "E_SESSION_EXPIRED",
            ErrorCode::Version => "E_VERSION",
        }
    }

    /// The pipeline stage at which this error arises (PROTO-SPEC §10.1).
    ///
    /// The stage ordering mirrors the load-bearing verification order of §4:
    /// identity before policy before vault before injection.
    pub fn stage(self) -> Stage {
        match self {
            ErrorCode::UnknownAgent | ErrorCode::BadSignature | ErrorCode::Replay => {
                Stage::Identity
            }
            ErrorCode::Denied => Stage::Policy,
            ErrorCode::ConfirmTimeout => Stage::Confirmation,
            ErrorCode::CredUnresolved => Stage::Vault,
            ErrorCode::Mechanism => Stage::Injection,
            ErrorCode::SessionOwner | ErrorCode::SessionExpired => Stage::Session,
            ErrorCode::Version => Stage::Envelope,
        }
    }
}

/// Pipeline stage at which an error arises (PROTO-SPEC §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// Signature / freshness / enrollment checks.
    Identity,
    /// Default-deny adjudication.
    Policy,
    /// The single human confirmation gate.
    Confirmation,
    /// Credential resolution / minting.
    Vault,
    /// Outbound mechanism execution.
    Injection,
    /// Brokered-session frame handling.
    Session,
    /// Envelope-level problems (e.g. version).
    Envelope,
}

impl Stage {
    /// Wire string for this stage, as named in PROTO-SPEC §10.1.
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Identity => "Identity",
            Stage::Policy => "Policy",
            Stage::Confirmation => "Confirmation",
            Stage::Vault => "Vault",
            Stage::Injection => "Injection",
            Stage::Session => "Session",
            Stage::Envelope => "Envelope",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parses a wire string like `"E_REPLAY"` into its code.
///
/// Unknown strings are rejected rather than coerced into a catch-all variant:
/// silently relabeling an unknown error would corrupt attribution downstream.
impl core::str::FromStr for ErrorCode {
    type Err = UnknownErrorCode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "E_UNKNOWN_AGENT" => Ok(ErrorCode::UnknownAgent),
            "E_BAD_SIGNATURE" => Ok(ErrorCode::BadSignature),
            "E_REPLAY" => Ok(ErrorCode::Replay),
            "E_DENIED" => Ok(ErrorCode::Denied),
            "E_CONFIRM_TIMEOUT" => Ok(ErrorCode::ConfirmTimeout),
            "E_CRED_UNRESOLVED" => Ok(ErrorCode::CredUnresolved),
            "E_MECHANISM" => Ok(ErrorCode::Mechanism),
            "E_SESSION_OWNER" => Ok(ErrorCode::SessionOwner),
            "E_SESSION_EXPIRED" => Ok(ErrorCode::SessionExpired),
            "E_VERSION" => Ok(ErrorCode::Version),
            other => Err(UnknownErrorCode(other.to_owned())),
        }
    }
}

/// Returned when a wire string does not name any known error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownErrorCode(pub String);

impl core::fmt::Display for UnknownErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown chaperone error code: {:?}", self.0)
    }
}

impl std::error::Error for UnknownErrorCode {}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// All codes, in PROTO-SPEC §10.1 table order, with their exact strings.
    const SPEC_TABLE: &[(ErrorCode, &str, &str)] = &[
        (ErrorCode::UnknownAgent, "E_UNKNOWN_AGENT", "Identity"),
        (ErrorCode::BadSignature, "E_BAD_SIGNATURE", "Identity"),
        (ErrorCode::Replay, "E_REPLAY", "Identity"),
        (ErrorCode::Denied, "E_DENIED", "Policy"),
        (
            ErrorCode::ConfirmTimeout,
            "E_CONFIRM_TIMEOUT",
            "Confirmation",
        ),
        (ErrorCode::CredUnresolved, "E_CRED_UNRESOLVED", "Vault"),
        (ErrorCode::Mechanism, "E_MECHANISM", "Injection"),
        (ErrorCode::SessionOwner, "E_SESSION_OWNER", "Session"),
        (ErrorCode::SessionExpired, "E_SESSION_EXPIRED", "Session"),
        (ErrorCode::Version, "E_VERSION", "Envelope"),
    ];

    #[test]
    fn error_codes_match_spec_table_exactly() {
        assert_eq!(SPEC_TABLE.len(), 10);
        for (code, wire, _stage) in SPEC_TABLE {
            assert_eq!(code.as_str(), *wire);
            let parsed: ErrorCode = wire.parse().expect("roundtrip");
            assert_eq!(parsed, *code);
        }
    }

    #[test]
    fn stages_match_spec_table() {
        for (code, _wire, stage) in SPEC_TABLE {
            assert_eq!(code.stage().as_str(), *stage);
        }
    }

    #[test]
    fn version_is_major_minor() {
        let (major, minor) = ("0", "1");
        assert_eq!(PROTOCOL_MAJOR.to_string(), major);
        assert_eq!(PROTOCOL_MINOR.to_string(), minor);
        assert_eq!(PROTOCOL_VERSION, format!("{major}.{minor}"));
    }
}
