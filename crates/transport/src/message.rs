//! JSON messages riding inside frames (PROTO-SPEC §3).
//!
//! Transport parses inbound frames only far enough to confirm they are JSON
//! objects and to expose `msg_id` for correlation (§3.3). This is framing
//! plumbing, not trust evaluation: an authenticated socket peer is still an
//! unauthenticated agent until the identity layer verifies its signature
//! (ARCH-SPEC §2.1).

use serde_json::Value;

/// A parsed inbound message.
#[derive(Debug, Clone)]
pub struct Request {
    msg_id: Option<String>,
    value: Value,
}

impl Request {
    /// Parses a framed UTF-8 payload as a JSON object message.
    pub fn parse(text: &str) -> Result<Request, MessageError> {
        let value: Value =
            serde_json::from_str(text).map_err(|e| MessageError::InvalidJson(e.to_string()))?;
        if !value.is_object() {
            return Err(MessageError::NotAnObject);
        }
        let msg_id = value
            .get("msg_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(Request { msg_id, value })
    }

    /// The agent-chosen correlation id, if present (§3.3).
    pub fn msg_id(&self) -> Option<&str> {
        self.msg_id.as_deref()
    }

    /// The full message object.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Consumes the request into its raw JSON value.
    pub fn into_value(self) -> Value {
        self.value
    }

    /// Stamps a response so it echoes this request's correlation id (§3.3).
    ///
    /// The echo is applied unconditionally: a handler cannot accidentally
    /// answer with another request's `msg_id`, because the transport owns
    /// correlation. Handlers that deliberately set a different `msg_id` get
    /// overwritten — correlation is not theirs to forge.
    pub fn reply(&self, mut response: Value) -> Value {
        if !response.is_object() {
            return response;
        }
        if let Some(id) = self.msg_id.clone() {
            response["msg_id"] = Value::String(id);
        }
        response
    }
}

/// Why a framed payload was not a valid message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageError {
    /// Payload parsed as JSON but was not an object.
    NotAnObject,
    /// Payload was not valid JSON at all.
    InvalidJson(String),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::NotAnObject => write!(f, "message is not a JSON object"),
            MessageError::InvalidJson(e) => write!(f, "message is not valid JSON: {e}"),
        }
    }
}

impl std::error::Error for MessageError {}

/// Builds a transport-level error frame (DESIGN-DECISIONS D12).
///
/// These frames report framing/parsing problems on connections that never got
/// far enough to carry a valid message, so they deliberately do NOT use the
/// protocol's `E_*` taxonomy (PROTO-SPEC §10.1) — inventing codes there would
/// risk colliding with future spec revisions. They carry a human-legible
/// reason and never echo message content.
pub fn transport_error_frame(reason: &str) -> Value {
    serde_json::json!({
        "type": "error",
        "scope": "transport",
        "reason": reason,
    })
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_and_extracts_msg_id() {
        let req = Request::parse(r#"{"msg_id":"m1","type":"intent"}"#).unwrap();
        assert_eq!(req.msg_id(), Some("m1"));
        assert_eq!(req.value()["type"], "intent");
    }

    #[test]
    fn tolerates_missing_msg_id() {
        let req = Request::parse("{}").unwrap();
        assert_eq!(req.msg_id(), None);
    }

    #[test]
    fn rejects_arrays_and_scalars() {
        assert!(matches!(
            Request::parse("[1,2]"),
            Err(MessageError::NotAnObject)
        ));
        assert!(matches!(
            Request::parse("42"),
            Err(MessageError::NotAnObject)
        ));
        assert!(matches!(
            Request::parse("\"x\""),
            Err(MessageError::NotAnObject)
        ));
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            Request::parse("{not json"),
            Err(MessageError::InvalidJson(_))
        ));
    }

    #[test]
    fn reply_stamps_echo_unconditionally() {
        let req = Request::parse(r#"{"msg_id":"m7"}"#).unwrap();
        let response = req.reply(serde_json::json!({"msg_id": "forged", "ok": true}));
        assert_eq!(response["msg_id"], "m7", "transport owns correlation");
        assert_eq!(response["ok"], true);
    }

    #[test]
    fn error_frame_uses_transport_scope_not_spec_codes() {
        let frame = transport_error_frame("declared length exceeds limit");
        assert_eq!(frame["scope"], "transport");
        assert_eq!(frame["reason"], "declared length exceeds limit");
        assert!(frame.get("code").is_none(), "no invented E_* codes (D12)");
    }
}
