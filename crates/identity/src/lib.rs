//! Chaperone identity and attestation — the security spine (PROTO-SPEC §4).
//!
//! The gateway extends real credentials on an agent's behalf; it therefore
//! MUST know, provably, which agent asked. This crate implements the exact
//! verification sequence, in order, stopping at the first failure:
//!
//! 0. **Version gate** (envelope-level; see D15 for placement).
//! 1. **Resolve** `agent_id` to an enrolled public key → else `E_UNKNOWN_AGENT`.
//! 2. **Freshness & replay**: `issued_at` within skew, `nonce` unseen → else
//!    `E_REPLAY`. The nonce is reserved here, before the signature is even
//!    examined: an attacker who could otherwise race two identical intents
//!    past concurrent verifications gets exactly one through.
//! 3. **Verify** the Ed25519 signature over the JCS canonical form of every
//!    field except `sig` → else `E_BAD_SIGNATURE`.
//! 4. Only now may the caller parse mechanism bodies.
//!
//! Steps 1–3 run strictly before any body interpretation; the acceptance
//! tests prove precedence with deliberately-broken intents that violate
//! several rules at once and assert which error wins.
//!
//! Layer contract (ARCH-SPEC §1.1): depends on the enrollment store; never
//! touches vault secrets or injectors. No secret material passes through
//! this crate at all.

use std::sync::Arc;

use chaperone_protocol::{ErrorCode, canonical_form, decode_signature};
use ed25519_dalek::Signature;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub mod enrollment;
pub mod replay;

pub use enrollment::{EnrollmentError, EnrollmentStore};
pub use replay::ReplayCache;

/// Verification parameters.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Allowed clock skew around `issued_at`, seconds (PROTO-SPEC §4.2:
    /// default ±30). Replay-cache retention derives from this.
    pub max_skew_secs: i64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self { max_skew_secs: 30 }
    }
}

/// Why verification failed, in verification-order terms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// Unsupported or malformed protocol version (step 0).
    UnsupportedVersion(String),
    /// Agent not enrolled — or revoked, indistinguishably (step 1).
    UnknownAgent(String),
    /// Stale `issued_at`, unparsable timestamp, reused nonce, or missing
    /// nonce (step 2).
    Replay(&'static str),
    /// Missing/undecodable signature, or signature failed over the canonical
    /// form (step 3).
    BadSignature,
}

impl IdentityError {
    /// The PROTO-SPEC §10.1 code this failure reports to the agent.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            IdentityError::UnsupportedVersion(_) => ErrorCode::Version,
            IdentityError::UnknownAgent(_) => ErrorCode::UnknownAgent,
            IdentityError::Replay(_) => ErrorCode::Replay,
            IdentityError::BadSignature => ErrorCode::BadSignature,
        }
    }

    /// Human-legible reason string for the error response body. Contains no
    /// secret material by construction — nothing in this crate sees any.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            IdentityError::UnsupportedVersion(v) => format!("unsupported protocol version {v:?}"),
            IdentityError::UnknownAgent(id) => format!("agent {id} is not enrolled"),
            IdentityError::Replay(why) => format!("freshness check failed: {why}"),
            IdentityError::BadSignature => "signature did not verify".to_owned(),
        }
    }
}

/// A fully-verified inbound message: attribution established, freshness
/// proven, signature sound. Mechanism bodies may now be parsed.
#[derive(Debug, Clone)]
pub struct VerifiedIntent {
    /// The authenticated agent identity.
    pub agent_id: String,
    /// The complete message as received (including `sig`) — this is the
    /// evidence object the audit chain stores.
    pub envelope: Value,
    /// Parsed issue time, normalized to UTC.
    pub issued_at: OffsetDateTime,
    /// The reserved nonce.
    pub nonce: String,
}

/// The attestation front door. Shared across connections; internally locked
/// where mutation happens.
pub struct Attestor {
    enrollment: Arc<EnrollmentStore>,
    replay: Arc<ReplayCache>,
    config: IdentityConfig,
}

impl Attestor {
    /// Builds an attestor over the given enrollment store and replay cache.
    #[must_use]
    pub fn new(
        enrollment: Arc<EnrollmentStore>,
        replay: Arc<ReplayCache>,
        config: IdentityConfig,
    ) -> Self {
        Self {
            enrollment,
            replay,
            config,
        }
    }

    /// Verifies one inbound JSON-object message per the §4 sequence.
    ///
    /// `now` comes from the caller so tests are deterministic and a future
    /// daemon can source time consistently in one place.
    pub fn verify(
        &self,
        message: &Value,
        now: OffsetDateTime,
    ) -> Result<VerifiedIntent, IdentityError> {
        let Some(obj) = message.as_object() else {
            // Transport guarantees objects; treat anything else as unsigned
            // garbage failing the earliest gate it can.
            return Err(IdentityError::BadSignature);
        };

        // ---- Step 0: version gate -------------------------------------
        let version = obj.get("chaperone").and_then(Value::as_str);
        check_version(version)?;

        // ---- Step 1: resolve the agent ---------------------------------
        let agent_id = match obj.get("agent_id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_owned(),
            _ => return Err(IdentityError::UnknownAgent(String::from("<unnamed>"))),
        };
        let verifying_key = self
            .enrollment
            .lookup(&agent_id)
            .ok_or_else(|| IdentityError::UnknownAgent(agent_id.clone()))?;

        // ---- Step 2: freshness + replay ---------------------------------
        let issued_at_raw = obj.get("issued_at").and_then(Value::as_str);
        let issued_at = check_freshness(issued_at_raw, now, self.config.max_skew_secs)?;
        let nonce = match obj.get("nonce").and_then(Value::as_str) {
            Some(n) if !n.is_empty() => n.to_owned(),
            _ => return Err(IdentityError::Replay("missing nonce")),
        };
        let retention = self.config.max_skew_secs.saturating_mul(3);
        if !self
            .replay
            .check_and_reserve(&agent_id, &nonce, now.unix_timestamp(), retention)
        {
            return Err(IdentityError::Replay("nonce already used"));
        }

        // ---- Step 3: signature over the canonical form ------------------
        let encoded_sig = obj
            .get("sig")
            .and_then(Value::as_str)
            .ok_or(IdentityError::BadSignature)?;
        let sig_bytes = decode_signature(encoded_sig).map_err(|_| IdentityError::BadSignature)?;
        let sig: &[u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::BadSignature)?;
        let signature = Signature::from_bytes(sig);
        let canonical = canonical_form(message).map_err(|_| IdentityError::BadSignature)?;
        verifying_key
            .verify_strict(&canonical, &signature)
            .map_err(|_| IdentityError::BadSignature)?;

        Ok(VerifiedIntent {
            agent_id,
            envelope: message.clone(),
            issued_at,
            nonce,
        })
    }
}

/// Step 0: MAJOR must match; any MINOR within the MAJOR is accepted
/// (additive-only evolution per §10.2 and SPEC-ISSUES SI-7).
fn check_version(version: Option<&str>) -> Result<(), IdentityError> {
    const EXPECTED_MAJOR: &str = "0";

    let Some(version) = version else {
        return Err(IdentityError::UnsupportedVersion("<missing>".to_owned()));
    };
    let mut parts = version.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(major), Some(_minor), None) if major == EXPECTED_MAJOR => Ok(()),
        _ => Err(IdentityError::UnsupportedVersion(version.to_owned())),
    }
}

/// Step 2a: `issued_at` parses as RFC 3339 and sits within ±skew of now.
///
/// Well-formed non-zero offsets are accepted and normalized to their UTC
/// instant — freshness compares instants, and rejecting e.g. `+02:00` would
/// buy nothing beyond what the skew bound already bounds.
fn check_freshness(
    issued_at: Option<&str>,
    now: OffsetDateTime,
    max_skew_secs: i64,
) -> Result<OffsetDateTime, IdentityError> {
    let Some(raw) = issued_at else {
        return Err(IdentityError::Replay("missing issued_at"));
    };
    let parsed = OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|_| IdentityError::Replay("issued_at is not RFC 3339"))?;
    let delta_secs = (now - parsed).whole_seconds();
    if delta_secs.abs() > max_skew_secs {
        return Err(IdentityError::Replay("issued_at outside allowed skew"));
    }
    Ok(parsed)
}
