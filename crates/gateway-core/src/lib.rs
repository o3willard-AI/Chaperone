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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chaperone_audit::{AuditEvent, AuditWriter, Outcome};
use chaperone_injectors::http::HttpInjector;
use chaperone_policy::{DecisionSource, Effect};
use chaperone_protocol::ops::HttpOperation;
use chaperone_vault::VaultRouter;
use serde_json::{Value, json};

#[cfg(feature = "postgres")]
pub mod db;
pub mod privilege;
pub mod session;
#[cfg(feature = "ssh")]
pub mod ssh;

#[cfg(feature = "postgres")]
pub use db::DbBackend;
pub use privilege::{LocalPrivBackend, PrivilegeAllowlist};
pub use session::{OutputBatch, OutputChunk, SessionBackend, SessionChannel, SessionTable};
#[cfg(feature = "ssh")]
pub use ssh::{HostKeyPolicy, SshBackend};

/// Knobs that are gateway policy, not agent choice.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Ceiling applied when neither rule nor agent declared one (D20).
    pub default_max_response_bytes: u64,
    /// Brokered-session lifetime when neither rule nor agent set one.
    pub default_session_ttl_secs: u64,
    /// Outbound-call budget when unconfigured.
    pub default_timeout_secs: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            default_max_response_bytes: 1_048_576,
            default_session_ttl_secs: 300,
            default_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFrameKind {
    Command,
    Close,
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

/// Placeholder gate kept for non-interactive deployments: every
/// needs_confirmation intent times out - the safe direction to fail.
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

/// Renders ONE prompt per needs_confirmation intent to an operator channel
/// (PROTO-SPEC §9.2, ARCH-SPEC §2.6): full context, y/n answer, timeout ->
/// [`ConfirmOutcome::TimedOut`], EOF -> refused.
///
/// Duplicate prompting is prevented structurally, not here: a concurrent
/// duplicate intent fails identity verification at the replay cache before
/// any gate runs (§4 step 2), so one intent == at most one prompt ever.
pub struct OperatorGate {
    io: Arc<Mutex<Box<dyn OperatorIo>>>,
    timeout: Duration,
}

/// The operator side of the single gate: where prompts render and answers
/// come from. Production wires the daemon's TTY; tests pipe buffers.
pub trait OperatorIo: Send {
    /// Writes the rendered prompt block.
    fn write_prompt(&mut self, block: &str) -> std::io::Result<()>;
    /// Reads one answer line; Ok(None) = EOF.
    fn read_answer(&mut self) -> std::io::Result<Option<String>>;
}

impl OperatorIo for Box<dyn OperatorIo> {
    fn write_prompt(&mut self, block: &str) -> std::io::Result<()> {
        (**self).write_prompt(block)
    }
    fn read_answer(&mut self) -> std::io::Result<Option<String>> {
        (**self).read_answer()
    }
}

impl OperatorGate {
    /// Builds a gate over any operator channel with an answer timeout.
    pub fn new(io: Box<dyn OperatorIo>, timeout: Duration) -> Self {
        Self {
            io: Arc::new(Mutex::new(io)),
            timeout,
        }
    }

    fn render(ctx: &ConfirmContext) -> String {
        // One deliberate prompt, full context (§9.2).
        format!(
            "\nCHAPERONE CONFIRMATION\n  agent:     {}\n  target:    {} ({})\n  mechanism: {}\n  action:    {}\nApprove? [y/N]: ",
            ctx.agent_id, ctx.target_label, ctx.target_uri, ctx.mechanism, ctx.summary
        )
    }

    fn parse(answer: Option<String>) -> ConfirmOutcome {
        match answer.map(|a| a.trim().to_ascii_lowercase()) {
            Some(ref a) if a == "y" || a == "yes" => ConfirmOutcome::Approved,
            Some(ref a) if a == "n" || a == "no" || a.is_empty() => ConfirmOutcome::Refused,
            Some(_) => ConfirmOutcome::Refused,
            None => ConfirmOutcome::Refused, // EOF: no human, no approval
        }
    }
}

impl ConfirmationGate for OperatorGate {
    fn confirm<'a>(
        &'a self,
        ctx: ConfirmContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ConfirmOutcome> + Send + 'a>> {
        Box::pin(async move {
            let block = Self::render(&ctx);
            let timeout = self.timeout;
            let io = Arc::clone(&self.io);
            // Blocking I/O off the async workers.
            let join = tokio::task::spawn_blocking(move || {
                let mut guard = match io.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Err(_e) = guard.write_prompt(&block) {
                    return ConfirmOutcome::Refused;
                }
                match guard.read_answer() {
                    Ok(answer) => Self::parse(answer),
                    Err(_) => ConfirmOutcome::Refused,
                }
            });
            match tokio::time::timeout(timeout, join).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(_join_err)) => ConfirmOutcome::Refused,
                Err(_elapsed) => {
                    // The worker keeps blocking on stdin; its late answer is
                    // discarded. Log-free refusal keeps us honest.
                    ConfirmOutcome::TimedOut
                }
            }
        })
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
    sessions: SessionTable,
    backends: Mutex<HashMap<String, Arc<dyn SessionBackend>>>,
    privilege_allowlist: Mutex<Option<PrivilegeAllowlist>>,
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
            sessions: SessionTable::new(),
            backends: Mutex::new(HashMap::new()),
            privilege_allowlist: Mutex::new(None),
        })
    }

    /// Provides the daemon-side mirror of the operator allowlist used to
    /// decide whether local-privilege may proceed unattended. The helper
    /// re-checks authoritatively regardless.
    pub fn set_privilege_allowlist(&mut self, al: PrivilegeAllowlist) {
        *self
            .privilege_allowlist
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(al);
    }

    /// Registers a session backend for a mechanism (e.g. "ssh").
    pub fn with_session_backend(
        &mut self,
        mechanism: &str,
        backend: Arc<dyn SessionBackend>,
    ) -> &mut Self {
        self.backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(mechanism.to_owned(), backend);
        self
    }

    /// Handles one inbound JSON-object message and produces the response
    /// value (`msg_id` stamping stays with the transport).
    pub async fn handle_message(&self, message: &Value) -> Value {
        match message.get("type").and_then(Value::as_str) {
            Some("intent") => self.handle_intent(message).await,
            Some("session.command") => {
                self.handle_session_frame(message, SessionFrameKind::Command)
                    .await
            }
            Some("session.close") => {
                self.handle_session_frame(message, SessionFrameKind::Close)
                    .await
            }
            _ => Self::error(message, "E_MECHANISM", "unsupported message type"),
        }
    }

    fn session_backend(&self, mechanism: &str) -> Option<Arc<dyn SessionBackend>> {
        self.backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(mechanism)
            .map(Arc::clone)
    }

    /// Opener path for session mechanisms: the identical spine through
    /// resolution, then backend.connect spends the secret ONCE and a bound
    /// handle comes back. The secret is scrubbed here regardless of outcome.
    async fn open_session(
        &self,
        message: &Value,
        verified_agent_id: &str,
        envelope: &chaperone_protocol::Envelope,
        decision: chaperone_policy::Decision,
    ) -> Value {
        let Some(backend) = self.session_backend(&envelope.mechanism) else {
            self.audit_decision(envelope, decision.effect.as_str(), Outcome::MechanismError)
                .await;
            return Self::error(
                message,
                "E_MECHANISM",
                &format!(
                    "mechanism {:?} has no session backend configured in this build",
                    envelope.mechanism
                ),
            );
        };

        let secret = match self.router.resolve(&envelope.cred_ref).await {
            Ok(s) => s,
            Err(e) => {
                self.audit_decision(
                    envelope,
                    decision.effect.as_str(),
                    Outcome::CredentialUnresolved,
                )
                .await;
                return Self::error(message, "E_CRED_UNRESOLVED", &e.to_string());
            }
        };
        let operation = envelope.operation.clone();
        // NOTE: `secret` and `operation`/`target_uri` are still owned here;
        // the future borrows all three until the await below completes.
        let target_uri = envelope.target.uri.clone();
        let connect = backend.connect(&target_uri, &operation, &secret);
        let channel = match connect.await {
            Ok(c) => c,
            Err(e) => {
                self.audit_decision(envelope, decision.effect.as_str(), Outcome::MechanismError)
                    .await;
                return Self::error(
                    message,
                    "E_MECHANISM",
                    &format!("session establishment failed: {e}"),
                );
            }
        };

        let ttl = envelope
            .constraints
            .and_then(|c| c.session_ttl_s)
            .unwrap_or(self.config.default_session_ttl_secs);
        let handle = self
            .sessions
            .insert(verified_agent_id, channel, Duration::from_secs(ttl));
        let seq = self
            .audit_decision(
                envelope,
                decision.effect.as_str(),
                Outcome::SessionOpened {
                    handle: handle.clone(),
                },
            )
            .await
            .unwrap_or(0);
        json!({
            "type": "result",
            "decision": decision.effect.as_str(),
            "session_handle": handle,
            "session_ttl": ttl,
            "audit_id": audit_id(seq),
            "msg_id": message.get("msg_id").cloned().unwrap_or(Value::Null),
        })
    }

    /// Independently-signed owner-bound frames (PROTO-SPEC §8): full §4
    /// verification FIRST, then table lookup with ownership + TTL checks.
    async fn handle_session_frame(&self, message: &Value, kind: SessionFrameKind) -> Value {
        let now = chaperone_time_now();
        let verified = match self.attestor.verify(message, now) {
            Ok(v) => v,
            Err(e) => return Self::error(message, e.error_code().as_str(), &e.reason()),
        };
        let agent_id = verified.agent_id.clone();
        let Some(handle) = message
            .get("session_handle")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Self::error(
                message,
                "E_SESSION_EXPIRED",
                "frame carries no session_handle",
            );
        };

        if matches!(kind, SessionFrameKind::Close) {
            let Some(entry) = self.sessions.take(&handle, &agent_id) else {
                // Deliberately indistinguishable unknown vs expired vs foreign.
                return Self::error(
                    message,
                    "E_SESSION_EXPIRED",
                    "unknown or expired session_handle",
                );
            };
            let channel = entry.channel_arc();
            (**channel.lock().await).shutdown().await;
            let event = AuditEvent {
                agent_id: &agent_id,
                msg_id: message.get("msg_id").and_then(Value::as_str).unwrap_or(""),
                mechanism: "session.close",
                target_uri: "",
                target_label: "",
                cred_ref: "",
                effect: "allow",
                outcome: Outcome::SessionClosed {
                    reason: "client_close".into(),
                    exit_code: None,
                },
                intent_envelope: message,
            };
            let seq = self.audit.append(&event).ok().map(|h| h.seq).unwrap_or(0);
            return json!({
                "type": "session.closed",
                "session_handle": handle,
                "reason": "client_close",
                "exit_code": Value::Null,
                "audit_id": audit_id(seq),
                "msg_id": message.get("msg_id").cloned().unwrap_or(Value::Null),
            });
        }

        let input = match message.get("input_b64").and_then(Value::as_str) {
            Some(b64) => base64_std_decode(b64),
            None => Vec::new(),
        };

        let (entry, _remaining) = match self.sessions.access(&handle, &agent_id) {
            Ok(ok) => ok,
            Err((code, reason)) => return Self::error(message, code, reason),
        };
        {
            let channel = entry.channel().lock().await;
            if let Err(e) = channel.write(input).await {
                drop(channel);
                return Self::error(
                    message,
                    "E_MECHANISM",
                    &format!("channel write failed: {e}"),
                );
            }
            let batch = channel.read_batch(Duration::from_millis(400)).await;

            let outputs: Vec<Value> = batch
                .chunks
                .iter()
                .map(|c| {
                    json!({
                        "seq": entry.next_out_seq(),
                        "stream": c.stream,
                        "data_b64": base64_standard(&c.data),
                    })
                })
                .collect();
            let closed = batch.closed;
            let exit_code = batch.exit_code;
            drop(channel);

            if closed {
                if let Some(entry) = self.sessions.take(&handle, &agent_id) {
                    let channel = entry.channel_arc();
                    (**channel.lock().await).shutdown().await;
                }
                let event = AuditEvent {
                    agent_id: &agent_id,
                    msg_id: message.get("msg_id").and_then(Value::as_str).unwrap_or(""),
                    mechanism: "session.command",
                    target_uri: "",
                    target_label: "",
                    cred_ref: "",
                    effect: "allow",
                    outcome: Outcome::SessionClosed {
                        reason: "exited".into(),
                        exit_code,
                    },
                    intent_envelope: message,
                };
                let seq = self.audit.append(&event).ok().map(|h| h.seq).unwrap_or(0);
                return json!({
                    "type": "session.output",
                    "session_handle": handle,
                    "outputs": outputs,
                    "closed": true,
                    "exit_code": exit_code,
                    "audit_id": audit_id(seq),
                    "msg_id": message.get("msg_id").cloned().unwrap_or(Value::Null),
                });
            }
            json!({
                "type": "session.output",
                "session_handle": handle,
                "outputs": outputs,
                "closed": false,
                "msg_id": message.get("msg_id").cloned().unwrap_or(Value::Null),
            })
        }
    }

    async fn handle_intent(&self, message: &Value) -> Value {
        let now = chaperone_time_now();

        // ---- Steps 1-3: identity, exactly per §4 -----------------------
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

        // ---- Mechanism routing (post-policy; pre-confirm/resolve) --------
        const ONE_SHOT: [&str; 3] = ["http-bearer", "http-basic", "db-scram"];
        if !ONE_SHOT.contains(&envelope.mechanism.as_str()) {
            if matches!(envelope.mechanism.as_str(), "ssh" | "local-privilege") {
                // An unconfigured backend is an honest E_MECHANISM - it must
                // not hide behind a confirmation prompt that could never
                // lead anywhere.
                if self.session_backend(&envelope.mechanism).is_none() {
                    self.audit_decision(
                        &envelope,
                        decision.effect.as_str(),
                        Outcome::MechanismError,
                    )
                    .await;
                    return Self::error(
                        message,
                        "E_MECHANISM",
                        &format!(
                            "mechanism {:?} has no session backend configured in this build",
                            envelope.mechanism
                        ),
                    );
                }
                // local-privilege ALWAYS takes the human gate unless the
                // operator pinned exactly this command (PROTO-SPEC §7.2).
                let mut effect = decision.effect;
                let mut summary = String::new();
                if envelope.mechanism == "local-privilege" {
                    let command = envelope
                        .operation
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let args: Vec<String> = envelope
                        .operation
                        .get("args")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    summary = format!("run {command} {}", args.join(" "));
                    let pinned = self
                        .privilege_allowlist
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .as_ref()
                        .is_some_and(|al| al.permits(command, &args));
                    if !pinned && effect == Effect::Allow {
                        effect = Effect::NeedsConfirmation;
                    }
                }
                if effect == Effect::NeedsConfirmation {
                    let ctx = ConfirmContext {
                        agent_id: verified.agent_id.clone(),
                        target_label: envelope.target.label.clone(),
                        target_uri: envelope.target.uri.clone(),
                        mechanism: envelope.mechanism.clone(),
                        summary: if summary.is_empty() {
                            "operation".to_owned()
                        } else {
                            summary
                        },
                    };
                    match self.gate.confirm(ctx).await {
                        ConfirmOutcome::Approved => {}
                        _ => {
                            self.audit_decision(
                                &envelope,
                                decision.effect.as_str(),
                                Outcome::ConfirmationTimeout,
                            )
                            .await;
                            return Self::error(
                                message,
                                "E_CONFIRM_TIMEOUT",
                                "the human gate did not approve this privileged action",
                            );
                        }
                    }
                }
                return self
                    .open_session(message, &verified.agent_id.clone(), &envelope, decision)
                    .await;
            }
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
                    .or_else(|_| {
                        serde_json::from_value::<chaperone_protocol::DbOperation>(
                            envelope.operation.clone(),
                        )
                        .map(|op| op.summary())
                    })
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

        // ---- db-scram one-shot: statement present => run and return -------
        if envelope.mechanism == "db-scram" {
            let db_op: chaperone_protocol::DbOperation =
                match serde_json::from_value(envelope.operation.clone()) {
                    Ok(op) => op,
                    Err(e) => {
                        self.audit_decision(
                            &envelope,
                            decision.effect.as_str(),
                            Outcome::MechanismError,
                        )
                        .await;
                        return Self::error(
                            message,
                            "E_MECHANISM",
                            &format!("operation body invalid: {e}"),
                        );
                    }
                };
            if db_op.statement.is_some() {
                let secret = match self.router.resolve(&envelope.cred_ref).await {
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
                #[cfg(feature = "postgres")]
                {
                    match crate::db::execute_one_shot(
                        &envelope.target.uri.clone(),
                        &serde_json::to_value(&db_op).unwrap_or(Value::Null),
                        &secret,
                    )
                    .await
                    {
                        Ok(mut result) => {
                            drop(secret);
                            if let Some(obj) = result.as_object_mut() {
                                obj.insert("decision".into(), json!(decision.effect.as_str()));
                                obj.insert(
                                    "msg_id".into(),
                                    message.get("msg_id").cloned().unwrap_or(Value::Null),
                                );
                            }
                            let seq = self
                                .audit_decision(
                                    &envelope,
                                    decision.effect.as_str(),
                                    Outcome::Proceeded,
                                )
                                .await
                                .unwrap_or(0);
                            if let Some(obj) = result.as_object_mut() {
                                obj.insert("audit_id".into(), json!(audit_id(seq)));
                            }
                            return result;
                        }
                        Err(e) => {
                            drop(secret);
                            self.audit_decision(
                                &envelope,
                                decision.effect.as_str(),
                                Outcome::MechanismError,
                            )
                            .await;
                            return Self::error(message, "E_MECHANISM", &e);
                        }
                    }
                }
                #[cfg(not(feature = "postgres"))]
                {
                    drop(secret);
                    self.audit_decision(
                        &envelope,
                        decision.effect.as_str(),
                        Outcome::MechanismError,
                    )
                    .await;
                    return Self::error(
                        message,
                        "E_MECHANISM",
                        "db-scram is not compiled into this build",
                    );
                }
            }
            // statement-less opener falls through to session routing below.
            return self
                .open_session(message, &verified.agent_id.clone(), &envelope, decision)
                .await;
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
        let secret = match self.router.resolve(&envelope.cred_ref).await {
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
        drop(secret);

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
                    "msg_id": message.get("msg_id").cloned().unwrap_or(Value::Null),
                })
            }
            Err(e) => {
                self.audit_decision(&envelope, decision.effect.as_str(), Outcome::MechanismError)
                    .await;
                Self::error(message, "E_MECHANISM", &e.to_string())
            }
        }
    }

    /// Records an identity-stage rejection as evidence.
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
        let _ = self.audit.append(&event);
    }

    /// Records a post-policy terminal outcome; returns the new head seq.
    async fn audit_decision(
        &self,
        envelope: &chaperone_protocol::Envelope,
        effect: &str,
        outcome: Outcome,
    ) -> Option<u64> {
        let evidence = serde_json::to_value(envelope).ok()?;
        let event = AuditEvent {
            agent_id: &envelope.agent_id,
            msg_id: &envelope.msg_id,
            mechanism: &envelope.mechanism,
            target_uri: &envelope.target.uri,
            target_label: &envelope.target.label,
            cred_ref: &envelope.cred_ref,
            effect,
            outcome,
            intent_envelope: &evidence,
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

fn base64_std_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .unwrap_or_default()
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
