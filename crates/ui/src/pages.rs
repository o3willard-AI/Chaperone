//! Operator pages: status, secrets, agents, rules, raw policy.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;

use chaperone_identity::decode_public_key;
use chaperone_policy::{Effect, Matcher, Policy, Rule};
use chaperone_vault::SecretString;

use crate::matrix;
use crate::render::{effect_badge, esc, field, layout};
use crate::setup::urlenc;
use crate::state::{UiState, atomic_write};

fn flash_from(flash: &HashMap<String, String>) -> (Option<String>, Option<String>) {
    (
        flash.get("msg").map(|m| m.replace('+', " ")),
        flash.get("err").map(|m| m.replace('+', " ")),
    )
}

// ---------- status ----------

/// GET / - what the gateway is doing right now.
pub async fn dashboard(
    State(state): State<Arc<UiState>>,
    Query(flash): Query<HashMap<String, String>>,
) -> Html<String> {
    let prov = state.provisioned();
    let (ok, err) = flash_from(&flash);

    let mut body = String::from("<h1>Status</h1>");

    match &state.gateway {
        Some(gw) => {
            body.push_str(&format!(
                "<p>Broker: <strong>{}</strong> \u{00B7} ruleset <code>{}</code></p>",
                if gw.is_halted() {
                    "HALTED"
                } else {
                    "brokering"
                },
                esc(&short_hash(gw.ruleset_hash())),
            ));
        }
        None => {
            body.push_str(
                "<p>Broker: <strong>not running</strong> (setup mode \u{2014} \
                 finish <a href=\"/setup\">setup</a>, then start \
                 <code>chaperone serve</code>).</p>",
            );
        }
    }

    if !prov.complete() {
        body.push_str(&format!(
            "<div class=\"err\">Setup incomplete: {} step{} pending. \
             <a href=\"/setup\">Continue setup</a>.</div>",
            prov.missing(),
            if prov.missing() == 1 { "" } else { "s" }
        ));
    }

    // Counters (each best-effort).
    let secrets = state
        .vault
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|v| v.lock().list().ok())
        .map(|l| l.len())
        .unwrap_or(0);
    let agents = state
        .enrollment
        .list()
        .iter()
        .filter(|r| r.revoked_at.is_none())
        .count();
    let rules = state.current_policy().map(|p| p.len()).unwrap_or(0);

    body.push_str(&format!(
        "<div class=\"grid\">\
         <div class=\"card\"><h2><a href=\"/rules\">Rules</a></h2><p style=\"font-size:2rem;margin:.2rem 0\">{rules}</p>\
         <p class=\"muted\">first-match-wins, default-deny underneath</p></div>\
         <div class=\"card\"><h2><a href=\"/secrets\">Secrets</a></h2><p style=\"font-size:2rem;margin:.2rem 0\">{secrets}</p>\
         <p class=\"muted\">values never displayed once stored</p></div>\
         </div>\
         <div class=\"card\"><h2><a href=\"/agents\">Agents</a></h2><p style=\"font-size:2rem;margin:.2rem 0\">{agents}</p>\
         <p class=\"muted\">live enrollments</p></div>"
    ));

    // Event feed hint.
    match (&state.event_hub, &state.events_socket_path) {
        (Some(hub), Some(path)) => {
            body.push_str(&format!(
                "<div class=\"card\"><h2>Event feed</h2><p>{} subscribers on <code>{}</code>.\
                 <br><span class=\"muted\">tail with: <code>chaperone tail --socket {}</code> or any stream reader.</span></p></div>",
                hub.subscriber_count(),
                esc(&path.display().to_string()),
                esc(&path.display().to_string()),
            ));
        }
        _ => {
            body.push_str(
                "<p class=\"muted\">Event feed not bound; start serve with \
                 <code>--events-socket PATH</code> to broadcast decisions live.</p>",
            );
        }
    }

    Html(layout(
        "Status",
        prov.missing(),
        halted(&state).as_deref(),
        ok.as_deref(),
        err.as_deref(),
        &body,
    ))
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

fn halted(state: &UiState) -> Option<String> {
    state
        .gateway
        .as_ref()
        .and_then(|g| g.is_halted().then(|| g.halt_reason().unwrap_or_default()))
}

// ---------- secrets ----------

/// GET /secrets.
pub async fn secrets_page(
    State(state): State<Arc<UiState>>,
    Query(flash): Query<HashMap<String, String>>,
) -> Html<String> {
    let (ok, err) = flash_from(&flash);
    let mut body = String::from("<h1>Secrets</h1>");
    let Some(vault) = state
        .vault
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    else {
        body.push_str(
            "<div class=\"err\">The vault is not open. Complete \
             <a href=\"/setup\">setup</a>, or restart the daemon and enter \
             its passphrase.</div>",
        );
        return Html(layout(
            "Secrets",
            state.setup_pending(),
            halted(&state).as_deref(),
            ok.as_deref(),
            err.as_deref(),
            &body,
        ));
    };

    let guard = vault.lock();
    match guard.list() {
        Ok(mut paths) => {
            paths.sort();
            if paths.is_empty() {
                body.push_str("<p class=\"muted\">No secrets stored yet.</p>");
            } else {
                body.push_str("<table><tr><th>Path</th><th>Held value</th><th></th></tr>");
                for path in paths {
                    let len = guard
                        .get(&path)
                        .ok()
                        .flatten()
                        .map(|s| s.len())
                        .unwrap_or(0);
                    body.push_str(&format!(
                        "<tr><td><code>{}</code></td><td class=\"muted\">[redacted] {} bytes present</td>\
                         <td><form class=\"inline\" method=\"post\" action=\"/secrets/delete\">\
                         <input type=\"hidden\" name=\"path\" value=\"{}\">\
                         <button class=\"danger\" type=\"submit\">delete</button></form></td></tr>",
                        esc(&path),
                        len,
                        esc(&path),
                    ));
                }
                body.push_str("</table>");
            }
        }
        Err(e) => body.push_str(&format!(
            "<div class=\"err\">vault list failed: {}</div>",
            esc(&e.to_string())
        )),
    }
    drop(guard);

    body.push_str(
        "<h2>Add or rotate a secret</h2>\
         <p class=\"muted\">Storing an existing path again rotates it in place \
         (same path, new value \u{2014} cred_refs never change). The value is never \
         re-displayed afterwards.</p>",
    );
    body.push_str("<form method=\"post\" action=\"/secrets\">");
    body.push_str(&field(
        "Vault path (e.g. prod/github/token)",
        "<input name=\"path\" required placeholder=\"prod/github/token\">",
    ));
    body.push_str(&field(
        "Value (paste once; never shown again)",
        "<textarea name=\"value\" rows=\"3\" required spellcheck=\"false\"></textarea>",
    ));
    body.push_str("<button type=\"submit\">Store secret</button></form>");

    Html(layout(
        "Secrets",
        state.setup_pending(),
        halted(&state).as_deref(),
        ok.as_deref(),
        err.as_deref(),
        &body,
    ))
}

#[derive(Deserialize)]
/// Form body for storing/rotating one secret.
pub struct SecretForm {
    path: String,
    value: String,
}

/// POST /secrets.
pub async fn secrets_store(
    State(state): State<Arc<UiState>>,
    Form(form): Form<SecretForm>,
) -> impl IntoResponse {
    let Some(vault) = state
        .vault
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    else {
        return Redirect::to("/secrets?err=vault+not+open");
    };
    let path = form.path.trim().trim_matches('/');
    if path.is_empty() || form.value.is_empty() {
        return Redirect::to("/secrets?err=path+and+value+are+required");
    }
    let result = vault.lock().set(path, SecretString::new(form.value));
    match result {
        Ok(()) => Redirect::to(&format!(
            "/secrets?msg={}",
            urlenc(&format!("stored local://{path}"))
        )),
        Err(e) => Redirect::to(&format!("/secrets?err={}", urlenc(&e.to_string()))),
    }
}

#[derive(Deserialize)]
/// Form body for deleting one secret.
pub struct SecretDelete {
    path: String,
}

/// POST /secrets/delete.
pub async fn secrets_delete(
    State(state): State<Arc<UiState>>,
    Form(form): Form<SecretDelete>,
) -> impl IntoResponse {
    let Some(vault) = state
        .vault
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    else {
        return Redirect::to("/secrets?err=vault+not+open");
    };
    match vault.lock().delete(form.path.trim()) {
        Ok(true) => Redirect::to("/secrets?msg=deleted"),
        Ok(false) => Redirect::to("/secrets?msg=was+not+present"),
        Err(e) => Redirect::to(&format!("/secrets?err={}", urlenc(&e.to_string()))),
    }
}

// ---------- agents ----------

/// GET /agents.
pub async fn agents_page(
    State(state): State<Arc<UiState>>,
    Query(flash): Query<HashMap<String, String>>,
) -> Html<String> {
    let (ok, err) = flash_from(&flash);
    let mut body = String::from("<h1>Agents</h1>");

    let records = state.enrollment.list();
    if records.is_empty() {
        body.push_str("<p class=\"muted\">No agents enrolled yet.</p>");
    } else {
        body.push_str(
            "<table><tr><th>Agent</th><th>Status</th><th>Enrolled</th><th>Key</th><th></th></tr>",
        );
        for rec in &records {
            let (status, class) = if rec.revoked_at.is_some() {
                ("REVOKED", "deny")
            } else {
                ("live", "allow")
            };
            let action = if rec.revoked_at.is_none() {
                format!(
                    "<form class=\"inline\" method=\"post\" action=\"/agents/revoke\">\
                     <input type=\"hidden\" name=\"agent_id\" value=\"{}\">\
                     <button class=\"danger\" type=\"submit\">revoke</button></form>",
                    esc(&rec.agent_id)
                )
            } else {
                String::new()
            };
            body.push_str(&format!(
                "<tr><td><code>{}</code></td><td><span class=\"badge {class}\">{status}</span></td>\
                 <td class=\"muted\">{}</td><td class=\"muted\">{}...</td><td>{action}</td></tr>",
                esc(&rec.agent_id),
                esc(&rec.enrolled_at),
                esc(rec.public_key.get(..12).unwrap_or(&rec.public_key)),
            ));
        }
        body.push_str("</table>");
    }

    body.push_str(
        "<h2>Enroll an agent</h2>\
         <p class=\"muted\">Paste the agent's public key: base64url of exactly 32 bytes \
         (what its key store publishes out-of-band), not a JSON blob.</p>",
    );
    body.push_str(&format!(
        "<form method=\"post\" action=\"/agents/enroll\">\
         {}\
         {}\
         <button type=\"submit\">Enroll</button></form>",
        field(
            "Agent id",
            "<input name=\"agent_id\" required placeholder=\"agent:my-agent\">"
        ),
        field(
            "Public key (base64url, 32 bytes)",
            "<input name=\"public_key\" required spellcheck=\"false\">"
        ),
    ));

    Html(layout(
        "Agents",
        state.setup_pending(),
        halted(&state).as_deref(),
        ok.as_deref(),
        err.as_deref(),
        &body,
    ))
}

#[derive(Deserialize)]
/// Form body for enrolling an agent.
pub struct EnrollForm {
    agent_id: String,
    public_key: String,
}

/// POST /agents/enroll.
///
/// Decodes client-side first (32 raw bytes, valid base64url) so the common
/// paste-the-whole-blob mistake gets a specific error instead of a generic
/// decode failure. `enroll` itself remains the authority.
pub async fn agents_enroll(
    State(state): State<Arc<UiState>>,
    Form(form): Form<EnrollForm>,
) -> impl IntoResponse {
    let agent_id = form.agent_id.trim();
    if agent_id.is_empty() {
        return Redirect::to("/agents?err=agent+id+required");
    }
    if let Err(e) = decode_public_key(form.public_key.trim()) {
        return Redirect::to(&format!(
            "/agents?err={}",
            urlenc(&format!(
                "that is not a bare base64url Ed25519 public key: {e}"
            ))
        ));
    }
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    match state
        .enrollment
        .enroll(agent_id, form.public_key.trim(), &now, false)
    {
        Ok(()) => Redirect::to(&format!(
            "/agents?msg={}",
            urlenc(&format!("enrolled {agent_id}"))
        )),
        Err(e) => Redirect::to(&format!("/agents?err={}", urlenc(&e.to_string()))),
    }
}

#[derive(Deserialize)]
/// Form body for revoking an agent.
pub struct RevokeForm {
    agent_id: String,
}

/// POST /agents/revoke.
pub async fn agents_revoke(
    State(state): State<Arc<UiState>>,
    Form(form): Form<RevokeForm>,
) -> impl IntoResponse {
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    match state.enrollment.revoke(form.agent_id.trim(), &now) {
        Ok(true) => Redirect::to(&format!(
            "/agents?msg={}",
            urlenc(&format!(
                "revoked {}; effective immediately",
                form.agent_id.trim()
            ))
        )),
        Ok(false) => Redirect::to("/agents?msg=was+not+enrolled"),
        Err(e) => Redirect::to(&format!("/agents?err={}", urlenc(&e.to_string()))),
    }
}

// ---------- rules ----------

/// GET /rules.
pub async fn rules_page(
    State(state): State<Arc<UiState>>,
    Query(flash): Query<HashMap<String, String>>,
) -> Html<String> {
    let (ok, err) = flash_from(&flash);
    let mut body = String::from("<h1>Rules</h1>");

    match state.current_policy() {
        Err(e) => {
            body.push_str(&format!(
                "<div class=\"err\">policy.toml does not parse: {} \
                 <a href=\"/policy/raw\">Fix it in the raw editor</a>.</div>",
                esc(&e)
            ));
        }
        Ok(policy) => {
            if policy.is_empty() {
                body.push_str(
                    "<p class=\"muted\">No rules: EVERYTHING is denied by the structural \
                     default-deny floor. Add your first rule below.</p>",
                );
            } else {
                body.push_str(
                    "<table><tr><th>#</th><th>Name</th><th>Effect</th><th>Match axes</th>\
                     <th>Notify</th><th>Limits</th><th></th></tr>",
                );
                for (index, rule) in policy.rules().iter().enumerate() {
                    let axes = format!(
                        "agent={} \u{00B7} cred={} \u{00B7} target={} \u{00B7} mech={}",
                        axis_text(&rule.agent_id),
                        axis_text(&rule.cred_ref),
                        axis_text(&rule.target_uri),
                        axis_text(&rule.mechanism),
                    );
                    let limits = format!(
                        "{}{}",
                        rule.limits
                            .max_response_bytes
                            .map(|v| format!("max_response={v}"))
                            .unwrap_or_default(),
                        rule.limits
                            .session_ttl_s
                            .map(|v| format!(" ttl={v}s"))
                            .unwrap_or_default(),
                    );
                    body.push_str(&format!(
                        "<tr><td>{index}</td><td>{}</td><td>{}</td><td class=\"muted\">{}</td>\
                         <td>{}</td><td class=\"muted\">{}</td>\
                         <td><form class=\"inline\" method=\"post\" action=\"/rules/delete\">\
                         <input type=\"hidden\" name=\"index\" value=\"{index}\">\
                         <button class=\"danger\" type=\"submit\">delete</button></form></td></tr>",
                        esc(rule.name.as_deref().unwrap_or("")),
                        effect_badge(rule.effect.as_str()),
                        esc(&axes),
                        if rule.notify_on_use {
                            "\u{2705}"
                        } else {
                            "\u{2014}"
                        },
                        esc(limits.trim()),
                    ));
                }
                body.push_str("</table>");
            }
            body.push_str(
                "<p><a href=\"/rules/new\"><button type=\"button\">Add a rule</button></a> \
                 or <a href=\"/policy/raw\">edit the TOML directly</a>.</p>",
            );
        }
    }

    Html(layout(
        "Rules",
        state.setup_pending(),
        halted(&state).as_deref(),
        ok.as_deref(),
        err.as_deref(),
        &body,
    ))
}

fn axis_text(m: &Matcher) -> String {
    m.source().unwrap_or_else(|| "*".to_owned())
}

/// GET /rules/new?mechanism=&template= - two-stage form: pick mechanism +
/// template (GET), then fill the rest (POST).
pub async fn rules_new(
    State(state): State<Arc<UiState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<String> {
    let mech = params.get("mechanism").cloned().unwrap_or_default();
    let template_id = params.get("template").cloned().unwrap_or_default();

    let mut body = String::from("<h1>Add a rule</h1>");
    body.push_str(
        "<p class=\"muted\">Step 1: choose how the agent reaches out. Badges are the \
         CONNECTIVITY-MATRIX maturity column \u{2014} read a \u{26A0}\u{FE0F} caveat BEFORE building on it.</p>",
    );

    // Stage 1: mechanism + template picker (plain GET form).
    body.push_str("<form method=\"get\" action=\"/rules/new\">");
    body.push_str("<p><label><strong>Mechanism</strong><br><select name=\"mechanism\">");
    for m in matrix::MECHANISMS {
        let selected = if m.id == mech { " selected" } else { "" };
        body.push_str(&format!(
            "<option value=\"{}\"{selected}>{} [{}]</option>",
            m.id,
            esc(m.label),
            m.maturity.badge()
        ));
    }
    body.push_str("</select></label></p>");

    let templates = matrix::templates_for(&mech);
    if !templates.is_empty() {
        body.push_str("<p><label><strong>Service template</strong><br><select name=\"template\">");
        body.push_str("<option value=\"\">custom (free-text target)</option>");
        for t in &templates {
            let selected = t.name == template_id;
            body.push_str(&format!(
                "<option value=\"{}\"{}>{}</option>",
                esc(t.name),
                if selected { " selected" } else { "" },
                esc(t.name)
            ));
        }
        body.push_str("</select></label></p>");
        body.push_str("<button type=\"submit\" formnovalidate>Load template \u{2192}</button>");
    } else {
        body.push_str("<button type=\"submit\">Choose \u{2192}</button>");
    }
    body.push_str("</form>");

    // Inline the chosen row's caveats.
    if let Some(m) = matrix::mechanism(&mech) {
        body.push_str(&format!(
            "<div class=\"card\"><strong>{}</strong> <span class=\"badge\">{}</span><br>\
             <span class=\"muted\">Lifecycle: {} \u{00B7} Vault holds: {} \u{00B7} Confirmation: {}</span></div>",
            esc(m.label),
            m.maturity.badge(),
            esc(m.lifecycle),
            esc(m.credential_form),
            esc(m.confirmation),
        ));
    }
    if let Some(note) = templates
        .iter()
        .find(|t| t.name == template_id)
        .and_then(|t| t.note)
    {
        body.push_str(&format!("<div class=\"err\">{}</div>", esc(note)));
    }

    // Stage 2: full rule form, prefilled from the template.
    let target_prefill = templates
        .iter()
        .find(|t| t.name == template_id)
        .map(|t| t.target_uri)
        .unwrap_or("");

    let agent_options = {
        let mut s = String::from("<datalist id=\"agent-ids\">");
        for rec in state.enrollment.list() {
            s.push_str(&format!("<option value=\"{}\">", esc(&rec.agent_id)));
        }
        s.push_str("</datalist>");
        s
    };
    let known_paths = state
        .vault
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|v| v.lock().list().ok())
        .unwrap_or_default();
    let cred_options = {
        let mut s = String::from("<datalist id=\"cred-refs\">");
        for p in known_paths {
            s.push_str(&format!("<option value=\"local://{}\">", esc(&p)));
        }
        s.push_str("</datalist>");
        s
    };

    body.push_str("<form method=\"post\" action=\"/rules/add\">");
    body.push_str(&format!(
        "<input type=\"hidden\" name=\"mechanism\" value=\"{}\">",
        esc(&mech)
    ));
    body.push_str(&field(
        "Rule name (optional)",
        "<input name=\"name\" placeholder=\"ci agent may read github\">",
    ));
    body.push_str(&field(
        "Target URI glob (free text; templates prefill a tested shape)",
        &format!(
            "<input name=\"target_uri\" placeholder=\"https://api.example.com/*\" value=\"{}\" spellcheck=\"false\">",
            esc(target_prefill)
        ),
    ));
    body.push_str(&format!(
        "{agent_options}{cred_options}\
         <div class=\"grid\">\
         <p><label><strong>Agent id</strong> (empty = any)<br>\
         <input name=\"agent_id\" list=\"agent-ids\" placeholder=\"agent:my-agent\" spellcheck=\"false\"></label></p>\
         <p><label><strong>Credential reference</strong> (scheme://path)<br>\
         <input name=\"cred_ref\" list=\"cred-refs\" placeholder=\"local://prod/github/token\" spellcheck=\"false\"></label></p>\
         </div>"
    ));
    body.push_str(&field(
        "Effect",
        "<select name=\"effect\">\
         <option value=\"allow\">allow \u{2014} proceed without prompting</option>\
         <option value=\"needs_confirmation\">needs_confirmation \u{2014} human gate each use</option>\
         <option value=\"deny\">deny \u{2014} explicit refusal</option></select>",
    ));
    body.push_str(
        "<p><label><input type=\"checkbox\" name=\"notify_on_use\" checked> notify me when this credential is used (on_use)</label></p>",
    );
    body.push_str(&format!(
        "<div class=\"grid\">{}{}</div>",
        field(
            "Max response bytes (optional)",
            "<input name=\"max_response_bytes\" inputmode=\"numeric\" placeholder=\"1048576\">"
        ),
        field(
            "Session TTL seconds (optional)",
            "<input name=\"session_ttl_s\" inputmode=\"numeric\" placeholder=\"300\">"
        ),
    ));
    body.push_str("<button type=\"submit\">Validate &amp; save rule</button></form>");

    Html(layout(
        "Add rule",
        state.setup_pending(),
        halted(&state).as_deref(),
        None,
        None,
        &body,
    ))
}

#[derive(Deserialize)]
/// Form body for the rule editor (all axes + limits).
pub struct RuleForm {
    #[serde(default)]
    name: String,
    mechanism: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    cred_ref: String,
    #[serde(default)]
    target_uri: String,
    effect: String,
    #[serde(default)]
    notify_on_use: Option<String>,
    #[serde(default)]
    max_response_bytes: String,
    #[serde(default)]
    session_ttl_s: String,
}

/// POST /rules/add - build the rule as real [`Rule`] values, serialize via
/// the ONE writer, validate through the ONE parser, then atomically save.
pub async fn rules_add(
    State(state): State<Arc<UiState>>,
    Form(form): Form<RuleForm>,
) -> impl IntoResponse {
    if matrix::mechanism(&form.mechanism).is_none() {
        return Redirect::to("/rules/new?err=unknown+mechanism");
    }
    if !matches!(
        form.effect.as_str(),
        "allow" | "deny" | "needs_confirmation"
    ) {
        return Redirect::to("/rules/new?err=unknown+effect");
    }
    let axis = |raw: &str| -> Matcher {
        if raw.is_empty() {
            Matcher::Any
        } else {
            Matcher::parse(raw).unwrap_or(Matcher::Exact(raw.to_owned()))
        }
    };

    let limits = chaperone_policy::Limits {
        max_response_bytes: form.max_response_bytes.trim().parse().ok(),
        session_ttl_s: form.session_ttl_s.trim().parse().ok(),
    };
    let rule = Rule {
        name: (!form.name.trim().is_empty()).then(|| form.name.trim().to_owned()),
        notify_on_use: form
            .notify_on_use
            .as_deref()
            .is_some_and(|v| v == "on" || v == "true"),
        effect: Effect::parse(&form.effect).unwrap_or(Effect::Deny),
        agent_id: axis(form.agent_id.trim()),
        cred_ref: axis(form.cred_ref.trim()),
        target_uri: axis(form.target_uri.trim()),
        mechanism: axis(&form.mechanism),
        limits,
    };

    let doc_policy = match state.current_policy() {
        Ok(p) => p,
        Err(e) => {
            return Redirect::to(&format!(
                "/rules?err={}",
                urlenc(&format!("current policy does not parse; fix it first: {e}"))
            ));
        }
    };
    let mut rules = doc_policy.rules().to_vec();
    rules.push(rule);
    let new_doc = Policy::from_rules(rules).to_toml();

    // Validate EXACTLY what will hit the disk, through the same parser the
    // gateway uses at load (the UI's policy-check).
    if let Err(e) = Policy::from_toml(&new_doc) {
        return Redirect::to(&format!(
            "/rules?err={}",
            urlenc(&format!(
                "generated policy failed validation (not saved): {e}"
            ))
        ));
    }

    match atomic_write(&state.policy_path, new_doc.as_bytes()) {
        Ok(()) => {
            if state.gateway.as_ref().is_some_and(|g| !g.is_halted()) {
                Redirect::to(&format!(
                    "/rules?msg={}",
                    urlenc(
                        "rule saved. The integrity guard will halt this daemon until you restart with the new policy."
                    )
                ))
            } else {
                Redirect::to("/rules?msg=rule+saved")
            }
        }
        Err(e) => Redirect::to(&format!("/rules?err={}", urlenc(&e))),
    }
}

#[derive(Deserialize)]
/// Form body for deleting a rule by index.
pub struct RuleDelete {
    index: usize,
}

/// POST /rules/delete.
pub async fn rules_delete(
    State(state): State<Arc<UiState>>,
    Form(form): Form<RuleDelete>,
) -> impl IntoResponse {
    let doc_policy = match state.current_policy() {
        Ok(p) => p,
        Err(e) => return Redirect::to(&format!("/rules?err={}", urlenc(&e))),
    };
    let mut rules = doc_policy.rules().to_vec();
    if form.index >= rules.len() {
        return Redirect::to("/rules?err=no+such+rule");
    }
    rules.remove(form.index);
    let new_doc = Policy::from_rules(rules).to_toml();
    if let Err(e) = Policy::from_toml(&new_doc) {
        return Redirect::to(&format!(
            "/rules?err={}",
            urlenc(&format!(
                "generated policy failed validation (not saved): {e}"
            ))
        ));
    }
    match atomic_write(&state.policy_path, new_doc.as_bytes()) {
        Ok(()) => Redirect::to("/rules?msg=rule+deleted%3B+restart+the+gateway+to+apply"),
        Err(e) => Redirect::to(&format!("/rules?err={}", urlenc(&e))),
    }
}

// ---------- raw policy ----------

/// GET /policy/raw.
pub async fn raw_page(
    State(state): State<Arc<UiState>>,
    Query(flash): Query<HashMap<String, String>>,
) -> Html<String> {
    let (_, err) = flash_from(&flash);
    let doc = std::fs::read_to_string(&state.policy_path).unwrap_or_default();
    let mut body = String::from("<h1>Policy TOML</h1>");
    if let Some(e) = err {
        body.push_str(&format!(
            "<div class=\"err\">{}</div>",
            esc(&e.replace('+', " "))
        ));
    }
    body.push_str(&format!(
        "<form method=\"post\" action=\"/policy/raw\">\
         <textarea name=\"doc\" rows=\"18\" spellcheck=\"false\">{}</textarea>\
         <p><button type=\"submit\">Validate &amp; save</button> \
         <span class=\"muted\">saved through the one validator; invalid documents are refused</span></p></form>",
        esc(&doc)
    ));
    Html(layout(
        "Policy TOML",
        state.setup_pending(),
        halted(&state).as_deref(),
        None,
        None,
        &body,
    ))
}

#[derive(Deserialize)]
/// Form body for raw policy editing.
pub struct RawForm {
    doc: String,
}

/// POST /policy/raw.
pub async fn raw_save(
    State(state): State<Arc<UiState>>,
    Form(form): Form<RawForm>,
) -> impl IntoResponse {
    match Policy::from_toml(&form.doc) {
        Ok(_) => match atomic_write(&state.policy_path, form.doc.as_bytes()) {
            Ok(()) => Redirect::to("/rules?msg=policy+saved%3B+restart+the+gateway+to+apply"),
            Err(e) => Redirect::to(&format!("/policy/raw?err={}", urlenc(&e))),
        },
        Err(e) => Redirect::to(&format!(
            "/policy/raw?err={}",
            urlenc(&format!("NOT saved, schema rejected it: {e}"))
        )),
    }
}
