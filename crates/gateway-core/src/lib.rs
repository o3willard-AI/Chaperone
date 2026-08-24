//! Chaperone gateway orchestration core.
//!
//! Owns the end-to-end one-shot sequence shared by both lifecycles
//! (ARCH-SPEC §3.1, PROTO-SPEC §6.1), in the spec's exact order:
//!
//! ```text
//! signed intent -> verify (identity) -> policy -> [single confirmation]
//!   -> resolve cred_ref (fetch-late) -> inject -> result -> audit
//! ```
//!
//! Load-bearing properties implemented here:
//! - **Fetch-late**: the vault is touched only AFTER identity and policy
//!   (and confirmation) pass - a denied intent provably never resolves a
//!   secret (tested with call counters).
//! - **One terminal outcome, one audit record** - including identity-stage
//!   rejections, which are recorded as evidence.
//! - **Errors carry codes, never content**: no path can echo resolved
//!   material because resolution happens in one scope that ends before
//!   response building.
//!
//! Implemented in PLAN Phase 6 ([PLAN](../../docs/PLAN.md) M6); sessions
//! arrive in M8, the real confirmation UX in M7.

use std::sync::Arc;

use chaperone_audit::{AuditEvent, AuditWriter, Outcome};
use chaperone_injectors::http::HttpInjector;
use chaperone_policy::{DecisionSource, Effect};
use chaperone_protocol::ops::HttpOperation;
use chaperone_vault::VaultRouter;
use serde_json::{Value, json};

/// Knobs that are gateway policy, not agent choice.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Ceiling applied when neither rule nor agent declared one (D20).
    pub default_max_response_bytes: u64,
    /// Outbound-call budget when unconfigured.
    pub default_timeout_secs: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            default_max_response_bytes: 1_048_576,
            default_timeout_secs: 30,
        }
    }
}

/// The verdict of the single human gate (PROTO-SPEC §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// The human approved; proceed to injection.
    Approved,
    /// The human explicitly refused.
    Refused,
    /// Nobody answered in time.
    TimedOut,
}

/// Full context for the one confirmation prompt (§9.2).
#[derive(Debug, Clone)]
pub struct ConfirmContext {
    /// Authenticated agent.
    pub agent_id: String,
    /// Human-legible target label.
    pub target_label: String,
    /// Target URI.
    pub target_uri: String,
    /// Mechanism.
    pub mechanism: String,
    /// Operation summary line.
    pub summary: String,
}

/// The single human gate. The gateway owns it; agents never see or answer
/// it. Real UX lands in Phase 7; tests inject deterministic gates.
pub trait ConfirmationGate: Send + Sync {
    /// Blocks until approval, refusal, or timeout.
    fn confirm<'a>(
        &'a self,
        ctx: ConfirmContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ConfirmOutcome> + Send + 'a>>;
}

/// Placeholder gate until M7: every needs_confirmation intent times out,
/// which is the safe direction to fail.
#[derive(Debug, Default)]
pub struct AlwaysTimeoutGate;

impl ConfirmationGate for AlwaysTimeoutGate {
    fn confirm<'a>(
        &'a self,
        _ctx: ConfirmContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ConfirmOutcome> + Send + 'a>> {
        Box::pin(async { ConfirmOutcome::TimedOut })
    }
}

/// The assembled gateway.
pub struct Gateway {
    attestor: chaperone_identity::Attestor,
    policy: chaperone_policy::Policy,
    router: VaultRouter,
    audit: Arc<AuditWriter>,
    gate: Arc<dyn ConfirmationGate>,
    http: HttpInjector,
    config: GatewayConfig,
}

impl Gateway {
    /// Assembles the gateway from its spine components. Fails only if the
    /// outbound HTTP client cannot be constructed.
    pub fn new(
        attestor: chaperone_identity::Attestor,
        policy: chaperone_policy::Policy,
        router: VaultRouter,
        audit: Arc<AuditWriter>,
        gate: Arc<dyn ConfirmationGate>,
        config: GatewayConfig,
    ) -> Result<Self, chaperone_injectors::InjectorError> {
        Ok(Self {
            attestor,
            policy,
            router,
            audit,
            gate,
            http: HttpInjector::new()?,
            config,
        })
    }

    /// Handles one inbound JSON-object message and produces the response
    /// value (`msg_id` stamping stays with the transport).
    pub async fn handle_message(&self, message: &Value) -> Value {
        match message.get("type").and_then(Value::as_str) {
            Some("intent") => self.handle_intent(message).await,
            // Sessions are Phase 8; refusing honestly beats pretending.
            Some(other) if other == "session.command" || other == "session.close" => Self::error(
                message,
                "E_MECHANISM",
                "brokered sessions are not available in this build",
            ),
            _ => Self::error(message, "E_MECHANISM", "unsupported message type"),
        }
    }

    async fn handle_intent(&self, message: &Value) -> Value {
        let now = chaperone_time_now();

        // ---- Step 1-3: identity, exactly per §4 ------------------------
        let verified = match self.attestor.verify(message, now) {
            Ok(v) => v,
            Err(e) => {
                let code = e.error_code();
                self.audit_identity_failure(message, &code).await;
                return Self::error(message, code.as_str(), &e.reason());
            }
        };

        // ---- Post-signature typed parse ---------------------------------
        let envelope: chaperone_protocol::Envelope =
            match serde_json::from_value(verified.envelope.clone()) {
                Ok(e) => e,
                Err(e) => {
                    return Self::error(
                        message,
                        "E_MECHANISM",
                        &format!("signed intent failed schema validation: {e}"),
                    );
                }
            };

        // ---- Policy (before anything touches the vault) ------------------
        let request = chaperone_policy::Request {
            agent_id: &verified.agent_id,
            cred_ref: &envelope.cred_ref,
            target_uri: &envelope.target.uri,
            mechanism: &envelope.mechanism,
            declared: envelope.constraints,
        };
        let decision = self.policy.evaluate(&request);

        if decision.effect == Effect::Deny {
            self.audit_decision(&envelope, decision.effect.as_str(), Outcome::Denied)
                .await;
            return Self::error(
                message,
                "E_DENIED",
                &match &decision.source {
                    DecisionSource::DefaultDeny => {
                        "no policy rule permits this action (default-deny)".to_owned()
                    }
                    DecisionSource::Rule { index, name } => format!(
                        "denied by rule[{}]{}",
                        index,
                        name.as_deref()
                            .map(|n| format!(" ({n})"))
                            .unwrap_or_default()
                    ),
                },
            );
        }

        // ---- Mechanism support check (post-policy, pre-confirm/resolve) --
        if !matches!(envelope.mechanism.as_str(), "http-bearer" | "http-basic") {
            self.audit_decision(&envelope, decision.effect.as_str(), Outcome::MechanismError)
                .await;
            return Self::error(
                message,
                "E_MECHANISM",
                &format!(
                    "mechanism {:?} is not available in this build",
                    envelope.mechanism
                ),
            );
        }

        // ---- Single human gate -------------------------------------------
        if decision.effect == Effect::NeedsConfirmation {
            let ctx = ConfirmContext {
                agent_id: verified.agent_id.clone(),
                target_label: envelope.target.label.clone(),
                target_uri: envelope.target.uri.clone(),
                mechanism: envelope.mechanism.clone(),
                summary: serde_json::from_value::<HttpOperation>(envelope.operation.clone())
                    .map(|op| op.summary())
                    .unwrap_or_else(|_| "operation".to_owned()),
            };
            match self.gate.confirm(ctx).await {
                ConfirmOutcome::Approved => {}
                ConfirmOutcome::Refused | ConfirmOutcome::TimedOut => {
                    self.audit_decision(
                        &envelope,
                        decision.effect.as_str(),
                        Outcome::ConfirmationTimeout,
                    )
                    .await;
                    return Self::error(
                        message,
                        "E_CONFIRM_TIMEOUT",
                        "the human gate did not approve this action",
                    );
                }
            }
        }

        // ---- Operation body parse (still post-signature) ------------------
        let operation: HttpOperation = match serde_json::from_value(envelope.operation.clone()) {
            Ok(op) => op,
            Err(e) => {
                self.audit_decision(&envelope, decision.effect.as_str(), Outcome::MechanismError)
                    .await;
                return Self::error(
                    message,
                    "E_MECHANISM",
                    &format!("operation body invalid: {e}"),
                );
            }
        };
        if operation.has_agent_authorization() {
            self.audit_decision(&envelope, decision.effect.as_str(), Outcome::MechanismError)
                .await;
            return Self::error(
                message,
                "E_MECHANISM",
                "agents do not supply Authorization headers; name a cred_ref instead",
            );
        }

        // ---- Fetch-late vault resolution -----------------------------------
        let secret = match self.router.resolve(&envelope.cred_ref) {
            Ok(s) => s,
            Err(e) => {
                self.audit_decision(
                    &envelope,
                    decision.effect.as_str(),
                    Outcome::CredentialUnresolved,
                )
                .await;
                return Self::error(message, "E_CRED_UNRESOLVED", &e.to_string());
            }
        };

        // ---- Injection ------------------------------------------------------
        let limits = chaperone_injectors::http::HttpLimits {
            max_response_bytes: decision
                .limits
                .max_response_bytes
                .unwrap_or(self.config.default_max_response_bytes),
            timeout: std::time::Duration::from_secs(self.config.default_timeout_secs),
        };
        let injected = self
            .http
            .execute(
                &envelope.mechanism,
                &envelope.target.uri,
                &operation,
                &secret,
                &limits,
            )
            .await;
        drop(secret); // scrubbed here regardless of outcome

        match injected {
            Ok(resp) => {
                let audit_seq = self
                    .audit_decision(&envelope, decision.effect.as_str(), Outcome::Proceeded)
                    .await
                    .unwrap_or(0);
                json!({
                    "type": "result",
                    "decision": decision.effect.as_str(),
                    "status": resp.status,
                    "headers": object_from_pairs(resp.headers.iter().map(|(k,v)|(k.as_str(), v.as_str()))),
                    "body_b64": base64_standard(&resp.body),
                    "audit_id": audit_id(audit_seq),
                })
            }
            Err(e) => {
                self.audit_decision(&envelope, decision.effect.as_str(), Outcome::MechanismError)
                    .await;
                Self::error(message, "E_MECHANISM", &e.to_string())
            }
        }
    }

    /// Records an identity-stage rejection as evidence and returns nothing.
    async fn audit_identity_failure(&self, message: &Value, code: &chaperone_protocol::ErrorCode) {
        let event = AuditEvent {
            agent_id: message
                .get("agent_id")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>"),
            msg_id: message.get("msg_id").and_then(Value::as_str).unwrap_or(""),
            mechanism: message
                .get("mechanism")
                .and_then(Value::as_str)
                .unwrap_or(""),
            target_uri: message
                .get("target")
                .and_then(|t| t.get("uri"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            target_label: message
                .get("target")
                .and_then(|t| t.get("label"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            cred_ref: message
                .get("cred_ref")
                .and_then(Value::as_str)
                .unwrap_or(""),
            effect: "deny",
            outcome: Outcome::IdentityFailed {
                code: code.as_str().to_owned(),
            },
            intent_envelope: message,
        };
        let _ = self.audit.append(&event); // best-effort: identity failures still recorded
    }

    /// Records a post-policy terminal outcome; returns the new head seq.
    async fn audit_decision(
        &self,
        envelope: &chaperone_protocol::Envelope,
        effect: &str,
        outcome: Outcome,
    ) -> Option<u64> {
        let event = AuditEvent {
            agent_id: &envelope.agent_id,
            msg_id: &envelope.msg_id,
            mechanism: &envelope.mechanism,
            target_uri: &envelope.target.uri,
            target_label: &envelope.target.label,
            cred_ref: &envelope.cred_ref,
            effect,
            outcome,
            intent_envelope: &serde_json::to_value(envelope).ok()?,
        };
        self.audit.append(&event).ok().map(|h| h.seq)
    }

    /// Error response: echoes `msg_id`, carries a §10.1 code and a
    /// human-legible reason. No content, ever.
    fn error(message: &Value, code: &str, reason: &str) -> Value {
        json!({
            "type": "error",
            "msg_id": message.get("msg_id").cloned().unwrap_or(Value::Null),
            "code": code,
            "reason": reason,
        })
    }
}

fn audit_id(seq: u64) -> String {
    format!("aud_{seq}")
}

fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn object_from_pairs<I, K, V>(pairs: I) -> Value
where
    I: Iterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut map = serde_json::Map::new();
    for (k, v) in pairs {
        map.insert(k.as_ref().to_owned(), json!(v.as_ref()));
    }
    Value::Object(map)
}

/// Wall-clock source for verification freshness. One place, so tests and a
/// future daemon share the same notion of now.
#[must_use]
pub fn chaperone_time_now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}
