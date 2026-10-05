//! P2-1: the "Connect a service" flow.
//!
//! One submit produces four artifacts — a vault entry, an enrolled identity,
//! an audit key (when absent), and a rule — plus a copy-pasteable test
//! command. It is **composition, not new capability**: every primitive already
//! exists behind `/secrets/store`, `/agents/enroll`, `/setup/audit-key`, and
//! `/rules/add`.
//!
//! Two structural constraints, both load-bearing:
//!
//! **D36 — one validator path.** This calls the same code, in the same order,
//! that the four existing endpoints call. If it hand-built artifacts and wrote
//! files itself, we would have a fifth writer; if it wrote the policy and then
//! called the vault separately, a partial failure would leave a rule
//! referencing a missing secret.
//!
//! **Rule last (Heph, ruling 3).** The rule is the only artifact whose presence
//! turns the grant *on*; everything before it is inert scaffolding under
//! default-deny, and an orphaned secret/enrollment/audit key over-permits
//! nothing. So: validate all four in memory, then write vault -> enrollment ->
//! audit key -> rule. The residue of a mid-flow failure is therefore never
//! something that reads as configured but isn't.
//!
//! **Option A (Stephen, 2026-10-03).** The vault must already exist; this flow
//! refuses cleanly and points at the wizard when it does not. That keeps the
//! secret surface to exactly ONE pasted value rather than two.

use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use chaperone_policy::{Policy, Rule};
use chaperone_vault::SecretString;
use serde::Deserialize;

use crate::matrix;
use crate::preview;
use crate::render::{esc, field, layout};
use crate::setup::urlenc;
use crate::state::{UiState, atomic_write};

#[derive(Deserialize)]
/// Form body for the connect flow. Every field maps onto an artifact that
/// already exists; nothing here is new state.
pub struct ConnectForm {
    mechanism: String,
    agent_id: String,
    cred_ref: String,
    target_uri: String,
    effect: String,
    public_key: String,
    sponsor_id: String,
    sponsor_name: String,
    /// The one secret this flow accepts. Zeroized on drop; never rendered,
    /// never logged, never placed in a URL.
    secret: String,
}

/// GET /connect — the intent-shaped form.
///
/// The sentence an operator actually has is one line: "let this agent use this
/// credential against this thing, and tell me when it does." Every noun in it
/// is already a concept the system has; this page is organised around the
/// sentence rather than around the artifacts.
pub async fn page(
    State(state): State<Arc<UiState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Html<String> {
    let mech = params
        .get("mechanism")
        .cloned()
        .unwrap_or_else(|| "http-bearer".to_owned());

    let mut body = String::from("<h1>Connect a service</h1>");
    body.push_str(
        "<p class=\"muted\">One form, four artifacts: a rule, a vault entry, an \
         enrolled agent, and a test command you can paste. \
         <a href=\"/setup\">The step-by-step wizard</a> remains if you prefer it.</p>",
    );

    // Option A: say up front that the vault must exist, rather than accepting
    // a secret and failing afterwards.
    let vault_ready = state
        .vault
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some();
    if !vault_ready {
        body.push_str(
            "<div class=\"err\">No vault is open. Create one in \
             <a href=\"/setup\">Setup</a> first &mdash; this flow stores your \
             credential in it and will not create one implicitly.</div>",
        );
    }

    body.push_str("<form method=\"post\" action=\"/connect\">");
    body.push_str(
        "<p><label><strong>How does the agent reach it?</strong><br><select name=\"mechanism\">",
    );
    for m in matrix::MECHANISMS {
        let sel = if m.id == mech { " selected" } else { "" };
        body.push_str(&format!(
            "<option value=\"{}\"{sel}>{} [{}]</option>",
            esc(m.id),
            esc(m.label),
            m.maturity.badge()
        ));
    }
    body.push_str("</select></label></p>");

    if let Some(m) = matrix::mechanism(&mech) {
        body.push_str(&format!(
            "<div class=\"card\"><strong>{}</strong> <span class=\"badge\">{}</span><br>\
             <span class=\"muted\">Holds: {} &middot; Confirmation: {}</span></div>",
            esc(m.label),
            m.maturity.badge(),
            esc(m.credential_form),
            esc(m.confirmation),
        ));
    }

    body.push_str(&field(
        "Which agent? (the enrolled identity)",
        "<input name=\"agent_id\" placeholder=\"agent:my-agent\" spellcheck=\"false\" \
         required>",
    ));
    body.push_str(&field(
        "Whose credential is responsible? (RAE L0 — attribution must terminate at a named human)",
        "<input name=\"sponsor_id\" placeholder=\"human:alice\" spellcheck=\"false\" required>",
    ));
    body.push_str(&field(
        "Sponsor name",
        "<input name=\"sponsor_name\" placeholder=\"Alice\" spellcheck=\"false\" required>",
    ));
    body.push_str(&field(
        "Agent public key (base64url Ed25519, as the agent holds it)",
        "<input name=\"public_key\" placeholder=\"base64url\" spellcheck=\"false\" required>",
    ));
    body.push_str(&field(
        "Which credential? (scheme://path — the name, not the value)",
        "<input name=\"cred_ref\" placeholder=\"local://prod/github/token\" \
         spellcheck=\"false\" required>",
    ));
    body.push_str(&field(
        "The credential itself (stored in the vault; never shown again)",
        "<input name=\"secret\" type=\"password\" autocomplete=\"off\" required>",
    ));
    body.push_str(&field(
        "Against what target?",
        "<input name=\"target_uri\" placeholder=\"https://api.github.com/*\" \
         spellcheck=\"false\" required>",
    ));
    body.push_str(
        "<p><label><strong>Effect</strong><br><select name=\"effect\">\
         <option value=\"allow\">allow &mdash; proceed without prompting</option>\
         <option value=\"needs_confirmation\">needs_confirmation &mdash; human gate \
         each use</option>\
         <option value=\"deny\">deny &mdash; explicit refusal</option></select></label></p>",
    );
    body.push_str(
        "<p><button type=\"submit\">Connect</button> \
         <span class=\"muted\">validates everything first, then writes; the rule \
         goes last</span></p></form>",
    );

    Html(layout(
        "Connect a service",
        state.setup_pending(),
        crate::pages::halted(&state).as_deref(),
        None,
        None,
        &body,
    ))
}

fn err(msg: &str) -> Redirect {
    Redirect::to(&format!("/connect?err={}", urlenc(msg)))
}

/// POST /connect — validate all four, then write vault -> enrollment -> audit
/// key -> rule.
pub async fn submit(
    State(state): State<Arc<UiState>>,
    Form(form): Form<ConnectForm>,
) -> impl IntoResponse {
    // ---- Option A: the vault must already exist. ----
    let vault_guard = state
        .vault
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(vault) = vault_guard.as_ref() else {
        return err(
            "no vault is open - create one in Setup first; this flow never \
                    creates one implicitly because that would add a second secret \
                    to this form",
        );
    };
    let vault = vault.clone();

    // ---- Validate EVERYTHING in memory before touching a single file. ----
    // A validation failure must write nothing at all.
    let agent_id = form.agent_id.trim();
    let cred_ref = form.cred_ref.trim();
    if agent_id.is_empty() || cred_ref.is_empty() {
        return err("agent id and credential reference are both required");
    }
    if form.sponsor_id.trim().is_empty() || form.sponsor_name.trim().is_empty() {
        return err("a named sponsor is required - attribution must terminate at a human");
    }
    if form.secret.is_empty() {
        return err("the credential itself is required");
    }
    if let Err(e) = chaperone_identity::decode_public_key(form.public_key.trim()) {
        return err(&format!(
            "that is not a bare base64url Ed25519 public key: {e}"
        ));
    }
    if matrix::mechanism(form.mechanism.trim()).is_none() {
        return err("unknown mechanism");
    }

    // The rule is built through the SAME constructor the editor and this
    // crate's preview use, so the flow cannot write a rule the validator would
    // refuse (D36).
    let Some(candidate) = preview::candidate_rule(
        form.mechanism.trim(),
        form.target_uri.trim(),
        agent_id,
        cred_ref,
        form.effect.trim(),
        "",
    ) else {
        return err("the effect must be allow, needs_confirmation, or deny");
    };

    // Round-trip the candidate through the real parser + the ONE writer,
    // exactly as `rules_add` does, so a policy the gateway would reject never
    // reaches disk (D36). `Policy` is deliberately immutable - `rules()` is a
    // read-only view and mutation goes through a document rebuild.
    let mut rule: Rule = candidate;
    rule.name = Some(format!("connect: {cred_ref}"));
    let doc_policy = match state.current_policy() {
        Ok(p) => p,
        Err(e) => {
            return err(&format!(
                "the current policy does not parse, so nothing was written: {e}"
            ));
        }
    };
    let mut rules = doc_policy.rules().to_vec();
    rules.push(rule);
    let rendered = Policy::from_rules(rules).to_toml();
    if let Err(e) = Policy::from_toml(&rendered) {
        return err(&format!(
            "the generated policy failed validation, so nothing was written: {e}"
        ));
    }

    // ---- Writes begin here. Rule LAST (Heph, ruling 3). ----
    let cred_path = cred_ref
        .strip_prefix("local://")
        .unwrap_or(cred_ref)
        .trim_matches('/')
        .to_owned();
    if cred_path.is_empty() {
        return err("the credential reference needs a path after local://");
    }

    // (1) vault entry. Zeroizing wrapper: the plaintext does not outlive this
    // function even on an early return.
    let value = SecretString::new(form.secret.clone());
    drop(form.secret);
    if let Err(e) = vault.lock().set(&cred_path, value) {
        return err(&format!(
            "the secret could not be stored, so NO rule was written: {e}"
        ));
    }

    // (2) enrollment, with the sponsor named.
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    if let Err(e) = state.enrollment.enroll(
        agent_id,
        form.public_key.trim(),
        form.sponsor_id.trim(),
        form.sponsor_name.trim(),
        &now,
        false,
    ) {
        return err(&format!(
            "the agent could not be enrolled, so NO rule was written: {e}"
        ));
    }

    // (3) audit key, only when absent as a FILE (the wizard normally made
    // it). `Path::exists()` is true for a directory too, so a directory squatting
    // on this path would silently skip the key and let the rule land - which is
    // exactly the mid-flow residue the ordering exists to prevent.
    if !state.audit_key_path.is_file() {
        // Same on-disk shape `chaperone audit-keygen` and the wizard write.
        let key = chaperone_audit::AuditKey::generate();
        let text = chaperone_protocol::encode_signature(&key.to_seed());
        if let Err(e) = atomic_write(&state.audit_key_path, text.as_bytes()) {
            return err(&format!(
                "the audit key could not be written, so NO rule was written: {e}"
            ));
        }
    }

    // (4) RULE LAST. Everything above is inert scaffolding until this lands.
    if let Err(e) = atomic_write(&state.policy_path, rendered.as_bytes()) {
        return err(&format!("the policy could not be written: {e}"));
    }

    // Hand back the one thing that makes the operator's next step obvious. It
    // names a cred_ref and an enrollment store; it never carries the secret.
    Redirect::to(&format!(
        "/connect/done?cred_ref={}&agent_id={}",
        urlenc(cred_ref),
        urlenc(agent_id)
    ))
}

/// GET /connect/done — the test command. References only, never values.
pub async fn done(
    State(state): State<Arc<UiState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Html<String> {
    let cred_ref = params.get("cred_ref").cloned().unwrap_or_default();
    let agent_id = params.get("agent_id").cloned().unwrap_or_default();

    let mut body = String::from("<h1>Connected</h1>");
    body.push_str(
        "<div class=\"ok\">Rule, vault entry, and enrolled identity are in \
         place. Restart the gateway to load the new policy.</div>",
    );
    body.push_str(&format!(
        "<div class=\"card\"><strong>Prove it end to end</strong><br>\
         <span class=\"muted\">This enrolls a throwaway keypair and sends one \
         signed intent. It references your credential by name; it never carries \
         the value.</span><br><code>python3 docs/skill/test-agent.py \
         --enroll-store {} --agent-id {}</code></div>",
        esc(&state.enrollment_path.display().to_string()),
        esc(&agent_id)
    ));
    body.push_str(&format!(
        "<p class=\"muted\">Credential reference: <code>{}</code></p>\
         <p><a href=\"/rules\">Review the rule</a> &middot; \
         <a href=\"/policy/test\">Test a request</a> &middot; \
         <a href=\"/connect\">Connect another</a></p>",
        esc(&cred_ref)
    ));
    Html(layout(
        "Connected",
        state.setup_pending(),
        crate::pages::halted(&state).as_deref(),
        None,
        None,
        &body,
    ))
}
