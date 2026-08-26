//! What gets recorded (PROTO-SPEC §9.3, ARCH-SPEC §2.8).
//!
//! Every terminal outcome appends one record binding: the full signed intent
//! as evidence, the decision and who/what confirmed it, the `cred_ref` used —
//! NEVER the secret — plus mechanism, target, timing, and outcome.
//!
//! The no-secret property is structural: [`AuditEvent`] has no field that can
//! carry resolved credential material, and `append()` accepts nothing of the
//! sort. Records hold references so the journal can be exported, reviewed,
//! and retained without itself becoming a leak vector.

use serde_json::Value;

/// How the brokered action ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(serde::Serialize)]
pub enum Outcome {
    /// Policy allowed and injection completed.
    Proceeded,
    /// Policy denied (default-deny or explicit rule).
    Denied,
    /// The single confirmation gate was not satisfied in time.
    ConfirmationTimeout,
    /// The credential reference did not resolve.
    CredentialUnresolved,
    /// The outbound mechanism failed.
    MechanismError,
    /// The intent failed identity verification (unknown/stale/forged).
    /// Carries the wire error code; the "intent evidence" stored alongside
    /// is whatever was received.
    IdentityFailed {
        /// E_UNKNOWN_AGENT | E_REPLAY | E_BAD_SIGNATURE | E_VERSION.
        code: String,
    },
    /// A session opened successfully; records the handle reference.
    SessionOpened {
        /// The opaque handle (safe to journal - it is not an authority).
        handle: String,
    },
    /// A brokered session closed; carries reason and exit code when known.
    SessionClosed {
        /// Why: client_close | ttl_expired | connection_dropped | error.
        reason: String,
        /// Exit code if the channel reported one.
        exit_code: Option<i32>,
    },
}

impl Outcome {
    /// Wire representation inside the record's `outcome` field.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Outcome::Proceeded => serde_json::json!({ "status": "proceeded" }),
            Outcome::Denied => serde_json::json!({ "status": "denied" }),
            Outcome::ConfirmationTimeout => serde_json::json!({ "status": "confirm_timeout" }),
            Outcome::CredentialUnresolved => serde_json::json!({ "status": "cred_unresolved" }),
            Outcome::IdentityFailed { code } => {
                serde_json::json!({ "status": "identity_failed", "code": code })
            }
            Outcome::MechanismError => serde_json::json!({ "status": "mechanism_error" }),
            Outcome::SessionOpened { handle } => {
                serde_json::json!({ "status": "session_opened", "session_handle": handle })
            }
            Outcome::SessionClosed { reason, exit_code } => serde_json::json!({
                "status": "session_closed",
                "reason": reason,
                "exit_code": exit_code,
            }),
        }
    }
}

/// What kind of chain record this is (PROTO-SPEC §9.3 + D38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// Chain anchor (written once per journal).
    Genesis,
    /// A completed intent decision or identity rejection.
    IntentDecision,
    /// The gateway loaded a policy ruleset; carries its hash so any
    /// post-hoc widening is detectable across restarts.
    PolicyLoad,
}

impl RecordKind {
    /// Wire string for the record's `kind` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Genesis => "genesis",
            RecordKind::IntentDecision => "intent_decision",
            RecordKind::PolicyLoad => "policy_load",
        }
    }
}

/// One terminal outcome to be recorded.
///
/// Everything here is reference-shaped by construction: ids, URIs, labels,
/// the credential REFERENCE, the signed envelope as evidence, and the
/// policy effect string (`allow` / `deny` / `needs_confirmation`).
#[derive(Debug, Clone)]
pub struct AuditEvent<'a> {
    /// Which chain-record shape to emit.
    pub record_kind: RecordKind,
    /// Hex SHA-256 of the governing policy document ('' when N/A, D38).
    pub ruleset_hash: String,
    /// Hex SHA-256 of the governing policy document ('' when not applicable,
    /// e.g. genesis). D38: decisions bind to the ruleset that governed them.
    /// Authenticated agent identity.
    pub agent_id: &'a str,
    /// Correlation id from the envelope.
    pub msg_id: &'a str,
    /// Mechanism selector from the envelope.
    pub mechanism: &'a str,
    /// Target URI from the envelope.
    pub target_uri: &'a str,
    /// Human-legible target label.
    pub target_label: &'a str,
    /// Credential REFERENCE. Never the secret itself.
    pub cred_ref: &'a str,
    /// Policy effect as its wire string.
    pub effect: &'a str,
    /// How the action ended.
    pub outcome: Outcome,
    /// The full signed intent as received — evidence, verbatim.
    pub intent_envelope: &'a Value,
}
