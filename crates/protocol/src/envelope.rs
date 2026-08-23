//! The intent envelope (PROTO-SPEC §4–§5) and its canonical form.
//!
//! The envelope is what an agent signs: every field together, `sig` excepted,
//! so none can be swapped after signing without detection. This module owns:
//!
//! - the typed [`Envelope`] for consumers past verification,
//! - [`canonical_form`], the exact byte sequence signatures cover, computed
//!   over the raw JSON object so unknown fields participate in the signature
//!   (forward-compat per DESIGN-DECISIONS D9),
//! - the base64url signature encoding rule (§4.2).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a message is, selected by the wire field `type` (PROTO-SPEC §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// A new request.
    Intent,
    /// Drives an open session.
    SessionCommand,
    /// Tears down an open session.
    SessionClose,
}

impl EnvelopeKind {
    /// Wire string for this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EnvelopeKind::Intent => "intent",
            EnvelopeKind::SessionCommand => "session.command",
            EnvelopeKind::SessionClose => "session.close",
        }
    }
}

impl serde::Serialize for EnvelopeKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EnvelopeKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "intent" => Ok(EnvelopeKind::Intent),
            "session.command" => Ok(EnvelopeKind::SessionCommand),
            "session.close" => Ok(EnvelopeKind::SessionClose),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["intent", "session.command", "session.close"],
            )),
        }
    }
}

/// The operation target: where the request acts, plus the label the human
/// sees at confirmation (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// URI the operation acts on.
    pub uri: String,
    /// Human-legible name shown on the confirmation surface.
    pub label: String,
}

/// Agent-declared self-limits. Ceilings only — never grants (§5.1): the
/// gateway takes the minimum of these and policy's own limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraints {
    /// Upper bound on relayed response size, bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    /// Upper bound on brokered-session lifetime, seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ttl_s: Option<u64>,
}

/// The signed envelope shared by every request (PROTO-SPEC §5).
///
/// Typed view for code that runs AFTER identity verification. Verification
/// itself operates on the raw JSON object via [`canonical_form`], because
/// unknown fields are part of what was signed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version (`MAJOR.MINOR`), e.g. `"0.1"`.
    pub chaperone: String,
    /// Agent-chosen correlation id, unique per connection; echoed in replies.
    pub msg_id: String,
    /// Message type (wire field `type`).
    #[serde(rename = "type")]
    pub kind: EnvelopeKind,
    /// Stable enrolled identity; resolves to a public key.
    pub agent_id: String,
    /// RFC 3339 UTC issue time; freshness-checked.
    pub issued_at: String,
    /// Unique-per-agent-within-window anti-replay value.
    pub nonce: String,
    /// Where the operation acts.
    pub target: Target,
    /// Selects the injector and the `operation` body schema.
    pub mechanism: String,
    /// Opaque vault reference. Never a secret.
    pub cred_ref: String,
    /// Mechanism-specific body; opaque at this layer.
    pub operation: Value,
    /// Optional self-limits; ceilings only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// Ed25519 signature over the JCS canonical form of every other field,
    /// base64url-encoded without padding (§4.2).
    pub sig: String,
}

/// Why the canonical form could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalError {
    /// Input was valid JSON but not an object.
    NotAnObject,
    /// Serialization of the stripped object failed.
    Serialize(String),
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalError::NotAnObject => write!(f, "envelope is not a JSON object"),
            CanonicalError::Serialize(e) => write!(f, "canonical serialization failed: {e}"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Computes the JCS (RFC 8785) canonical bytes that a signature covers
/// (PROTO-SPEC §4.2): the whole envelope object minus `sig`.
///
/// Works on the raw JSON object rather than a typed struct so that unknown
/// fields — which the agent's signature covered — remain covered here too.
pub fn canonical_form(envelope: &Value) -> Result<Vec<u8>, CanonicalError> {
    let Some(map) = envelope.as_object() else {
        return Err(CanonicalError::NotAnObject);
    };
    let mut stripped = map.clone();
    stripped.remove("sig");
    let mut buf = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut buf, canon_json::CanonicalFormatter::new());
    Value::Object(stripped)
        .serialize(&mut ser)
        .map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    Ok(buf)
}

/// Decodes the `sig` field: base64url, unpadded (§4.2), into raw bytes.
pub fn decode_signature(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(encoded)
}

/// Encodes raw signature bytes as base64url without padding (§4.2).
#[must_use]
pub fn encode_signature(raw: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(raw)
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_form_sorts_keys_and_strips_sig() {
        let env = json!({"sig": "zzz", "b": 2, "a": 1});
        assert_eq!(canonical_form(&env).unwrap(), br#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_form_keeps_unknown_signed_fields() {
        // D9: unknown fields were part of what the agent signed; they stay
        // part of what we verify against.
        let env = json!({"msg_id": "m", "future_field": {"z": true, "a": [1, 2]}});
        let bytes = canonical_form(&env).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(r#""future_field":{"a":[1,2],"z":true}"#));
        assert!(text.contains(r#""msg_id":"m""#));
    }

    #[test]
    fn canonical_form_is_deterministic() {
        let e1 = json!({"x": 1, "y": "s", "nested": {"q": [3, 1, 2]}});
        let e2 = json!({"nested": {"q": [3, 1, 2]}, "y": "s", "x": 1});
        assert_eq!(canonical_form(&e1).unwrap(), canonical_form(&e2).unwrap());
    }

    #[test]
    fn canonical_form_uses_minimal_escaping_utf8() {
        // RFC 8785 escapes only C0 controls, quote, and backslash; other
        // characters appear as UTF-8.
        let env = json!({"k": "\u{20ac}\u{001f}"});
        let bytes = canonical_form(&env).unwrap();
        assert_eq!(bytes, b"{\"k\":\"\xe2\x82\xac\\u001f\"}" as &[u8]);
    }

    #[test]
    fn canonical_form_rejects_non_objects() {
        assert_eq!(
            canonical_form(&json!([1])),
            Err(CanonicalError::NotAnObject)
        );
    }

    #[test]
    fn signature_round_trips_base64url_unpadded() {
        let raw = [0u8; 64];
        let encoded = encode_signature(&raw);
        assert!(!encoded.contains('='), "no padding per §4.2");
        assert!(!encoded.contains('+'), "url-safe alphabet");
        assert_eq!(decode_signature(&encoded).unwrap(), raw.to_vec());
    }

    #[test]
    fn envelope_typed_round_trip() {
        let env = Envelope {
            chaperone: PROTOCOL_VERSION_STR.to_owned(),
            msg_id: "a3f1c9".to_owned(),
            kind: EnvelopeKind::Intent,
            agent_id: "agent:planner-7".to_owned(),
            issued_at: "2026-08-22T17:04:03Z".to_owned(),
            nonce: "9f2b7c1e5a".to_owned(),
            target: Target {
                uri: "https://api.stripe.com/v1/charges".to_owned(),
                label: "stripe-prod".to_owned(),
            },
            mechanism: "http-bearer".to_owned(),
            cred_ref: "vault://prod/stripe/secret_key".to_owned(),
            operation: serde_json::json!({"method": "POST"}),
            constraints: Some(Constraints {
                max_response_bytes: Some(1_048_576),
                session_ttl_s: None,
            }),
            sig: "abc".to_owned(),
        };
        let text = serde_json::to_string(&env).unwrap();
        assert!(text.contains(r#""type":"intent""#));
        assert!(!text.contains("session_ttl_s"), "None fields omitted");
        let back: Envelope = serde_json::from_str(&text).unwrap();
        assert_eq!(back, env);
    }

    const PROTOCOL_VERSION_STR: &str = super::super::PROTOCOL_VERSION;
}
