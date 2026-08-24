//! Mechanism-specific `operation` bodies (PROTO-SPEC §7).
//!
//! These are parsed ONLY after identity verification succeeds (§4 step 4):
//! before that, the operation is opaque bytes covered by a signature.

use serde::{Deserialize, Serialize};

/// `http-bearer` / `http-basic` operation body (§7.1).
///
/// The agent supplies everything except the credential; the gateway supplies
/// the `Authorization` header. An agent-supplied `authorization` header is
/// rejected - agents do not attach credentials, that is the entire point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpOperation {
    /// HTTP method (GET, POST, ...).
    pub method: String,
    /// Agent-supplied headers. Case-insensitive names; `authorization`
    /// (any case) is rejected.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Base64 (standard) of the request body; omit for bodiless methods.
    #[serde(default)]
    pub body_b64: Option<String>,
    /// Username for `http-basic` only (non-secret, signed like everything
    /// else - SPEC-ISSUES SI-2 / DESIGN-DECISIONS D14). The password half
    /// comes from the vault at injection time and never appears here.
    #[serde(default)]
    pub username: Option<String>,
}

impl HttpOperation {
    /// True when the agent tried to smuggle their own credential header.
    #[must_use]
    pub fn has_agent_authorization(&self) -> bool {
        self.headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("authorization"))
    }

    /// Human-legible operation summary for the confirmation surface (§9.2).
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.body_b64 {
            Some(_) => format!("{} with body", self.method),
            None => self.method.clone(),
        }
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_bearer_body() {
        let op: HttpOperation = serde_json::from_value(json!({
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body_b64": "eyJhbW91bnQiOjIwMDB9"
        }))
        .unwrap();
        assert_eq!(op.method, "POST");
        assert!(!op.has_agent_authorization());
        assert_eq!(op.summary(), "POST with body");
    }

    #[test]
    fn detects_agent_supplied_authorization_any_case() {
        for key in ["Authorization", "authorization", "AUTHORIZATION"] {
            let op: HttpOperation = serde_json::from_value(json!({
                "method": "GET",
                "headers": {key: "Bearer attacker-token"}
            }))
            .unwrap();
            assert!(op.has_agent_authorization(), "{key}");
        }
    }

    #[test]
    fn unknown_fields_tolerated_forward_compat() {
        let op: HttpOperation = serde_json::from_value(json!({
            "method": "GET",
            "new_in_minor": {"x": 1}
        }))
        .unwrap();
        assert_eq!(op.method, "GET");
    }
}
