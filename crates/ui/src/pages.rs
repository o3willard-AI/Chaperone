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
use crate::preview;
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
            "<table><tr><th>Agent</th><th>Status</th><th>Enrolled</th><th>Sponsor</th><th>Key</th><th></th></tr>",
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
                 <td class=\"muted\">{}</td><td class=\"muted\">{}</td><td class=\"muted\">{}...</td><td>{action}</td></tr>",
                esc(&rec.agent_id),
                esc(&rec.enrolled_at),
                esc(if rec.sponsor_id.is_empty() {
                    "<none: pre-RAE legacy>"
                } else {
                    &rec.sponsor_id
                }),
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
        field(
            "Sponsor id (RAE: the human vouching for this agent)",
            "<input name=\"sponsor_id\" required placeholder=\"you@example.com or @gh-handle\">"
        ),
        field(
            "Sponsor name",
            "<input name=\"sponsor_name\" required placeholder=\"Jane Q. Operator\">"
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
    /// RAE L0: the named human who sponsors this agent (self-declared).
    /// Option so a missing field reaches the explicit guard below (and
    /// gets a specific error) instead of a generic form-parse rejection.
    sponsor_id: Option<String>,
    sponsor_name: Option<String>,
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
    // RAE L0: attribution terminates at a named human sponsor; refuse
    // anonymous enrollments.
    let sponsor_id = form.sponsor_id.unwrap_or_default();
    let sponsor_name = form.sponsor_name.unwrap_or_default();
    if sponsor_id.trim().is_empty() || sponsor_name.trim().is_empty() {
        return Redirect::to("/agents?err=sponsor+id+and+name+required+(RAE)");
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
    match state.enrollment.enroll(
        agent_id,
        form.public_key.trim(),
        sponsor_id.trim(),
        sponsor_name.trim(),
        &now,
        false,
    ) {
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
                    // D43: show pair bindings so the over-permission gap
                    // P1-2 warned about is visible in the rule text, not
                    // hidden. Each row is `cred -> target`.
                    let pairs_text = if rule.pairs.is_empty() {
                        String::new()
                    } else {
                        let rows: Vec<String> = rule
                            .pairs
                            .iter()
                            .map(|p| {
                                format!(
                                    "{} \u{2192} {}",
                                    axis_text(&p.cred_ref),
                                    axis_text(&p.target_uri)
                                )
                            })
                            .collect();
                        format!(" \u{00B7} {} pair(s): {}", rows.len(), rows.join("; "))
                    };
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
                        esc(&format!("{axes}{pairs_text}")),
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
    // P2-2: the preview describes the candidate rule as currently filled in.
    // Each field falls back to the template prefill, then to empty (= `Any`),
    // and is echoed back into the input so what the preview describes is
    // exactly what the operator sees and what `rules_add` will save.
    let q = |k: &str| params.get(k).cloned().unwrap_or_default();
    let target_prefill = {
        let from_query = q("target_uri");
        if from_query.is_empty() {
            templates
                .iter()
                .find(|t| t.name == template_id)
                .map_or_else(String::new, |t| t.target_uri.to_owned())
        } else {
            from_query
        }
    };
    let agent_prefill = q("agent_id");
    let cred_prefill = q("cred_ref");
    let pairs_prefill = q("pairs");
    let effect_prefill = {
        let e = q("effect");
        if e.is_empty() { "allow".to_owned() } else { e }
    };

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
            esc(&target_prefill)
        ),
    ));
    body.push_str(&format!(
        "{agent_options}{cred_options}\
         <div class=\"grid\">\
         <p><label><strong>Agent id</strong> (empty = any)<br>\
         <input name=\"agent_id\" list=\"agent-ids\" value=\"{}\" placeholder=\"agent:my-agent\" spellcheck=\"false\"></label></p>\
         <p><label><strong>Credential reference</strong> (scheme://path)<br>\
         <input name=\"cred_ref\" list=\"cred-refs\" value=\"{}\" placeholder=\"local://prod/github/token\" spellcheck=\"false\"></label></p>\
         </div>",
        esc(&agent_prefill),
        esc(&cred_prefill)
    ));
    body.push_str(&field(
        "Effect",
            &format!(
                "<select name=\"effect\">\n         <option value=\"allow\"{}>allow \u{2014} proceed without prompting</option>\n         <option value=\"needs_confirmation\"{}>needs_confirmation \u{2014} human gate each use</option>\n         <option value=\"deny\"{}>deny \u{2014} explicit refusal</option></select>",
                if effect_prefill == "allow" { " selected" } else { "" },
                if effect_prefill == "needs_confirmation" { " selected" } else { "" },
                if effect_prefill == "deny" { " selected" } else { "" },
            )
    ));
    body.push_str(
        "<p><label><input type=\"checkbox\" name=\"notify_on_use\" checked> notify me when this credential is used (on_use)</label></p>",
    );
    body.push_str(&field(
        "Credential-to-endpoint bindings (optional; one per line: cred_ref | target_uri)",
            &format!(
                "<textarea name=\"pairs\" rows=\"4\" spellcheck=\"false\" \
         placeholder=\"local://ssh/fleet/app-01 | ssh://app-01.internal:22&#10;\
         local://ssh/fleet/app-02 | ssh://app-02.internal:22\">{}</textarea>\
         <p class=\"muted\">Leave blank for a plain axis rule. When set, the request must match \
         one binding <em>in addition</em> to the axes above \u{2014} this is how one rule binds each \
         fleet key to its own host (D43). Each field takes the same <code>glob:</code>/<code>prefix:</code>/\
         <code>exact:</code> tags as the axes; a bare value is an exact match.</p>",
                esc(&pairs_prefill)
            )
    ));
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
    // P2-2: the decision preview, built from the PARSED candidate rule via
    // the same construction `rules_add` performs - so it cannot describe a
    // rule the validator would not actually produce. Labelled "not saved
    // yet" so an operator cannot read it as current state.
    if let Some(candidate) = preview::candidate_rule(
        &mech,
        &target_prefill,
        &agent_prefill,
        &cred_prefill,
        &effect_prefill,
        &pairs_prefill,
    ) {
        body.push_str(&preview::preview_block(&candidate));
    } else {
        body.push_str(
            "<div class=\"card\"><strong>Preview unavailable</strong><br>\
             <span class=\"muted\">the effect is not one of allow / \
             needs_confirmation / deny, so there is nothing valid to describe              yet.</span></div>",
        );
    }
    body.push_str(
        "<p><button type=\"submit\">Validate &amp; save rule</button> \
         <a href=\"/policy/test\">Test a request against the saved rules \u{2192}</a></p></form>",
    );

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
    /// D43 pair rows, one per line: `cred_ref | target_uri`. Blank means no
    /// pair clause. Parsed through the same `Matcher::parse` as the axes, so
    /// the form cannot express anything the file format cannot (D36).
    #[serde(default)]
    pairs: String,
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
    // D43 pair rows: one `cred_ref | target_uri` per line; blank lines
    // ignored; a malformed line fails the whole submit loudly (never
    // silently drops a binding — a dropped row would over-permit).
    let mut pairs = Vec::new();
    for (li, line) in form.pairs.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((cred_raw, target_raw)) = line.split_once('|') else {
            return Redirect::to(&format!(
                "/rules/new?err={}",
                urlenc(&format!(
                    "pair line {} must be `cred_ref | target_uri`",
                    li + 1
                ))
            ));
        };
        let cred_ref = match Matcher::parse(cred_raw.trim()) {
            Ok(m) => m,
            Err(e) => {
                return Redirect::to(&format!(
                    "/rules/new?err={}",
                    urlenc(&format!("pair line {} cred_ref: {e}", li + 1))
                ));
            }
        };
        let target_uri = match Matcher::parse(target_raw.trim()) {
            Ok(m) => m,
            Err(e) => {
                return Redirect::to(&format!(
                    "/rules/new?err={}",
                    urlenc(&format!("pair line {} target_uri: {e}", li + 1))
                ));
            }
        };
        pairs.push(chaperone_policy::Pair {
            cred_ref,
            target_uri,
        });
    }
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
        pairs,
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
/// Form body for the P2-2 decision test box.
pub struct TestForm {
    agent_id: String,
    cred_ref: String,
    target_uri: String,
    mechanism: String,
}

/// POST /policy/test — "what would this request do?"
///
/// D36: this calls `Policy::evaluate`, the SAME function the gateway calls on
/// the live path, and renders the provenance with `DecisionSource::label` —
/// the same string `chaperone policy-check` prints. It does not reimplement
/// evaluation and it does not shell out to the CLI. If that ever changes, the
/// shared impl makes the CLI/UI parity structural rather than test-enforced,
/// and `test_box_evaluates_through_the_shared_engine` in tests/ui_http.rs is
/// the backstop.
pub async fn policy_test(
    State(state): State<Arc<UiState>>,
    Form(form): Form<TestForm>,
) -> Html<String> {
    let doc = std::fs::read_to_string(&state.policy_path).unwrap_or_default();
    let mut body = String::from("<h1>Decision test</h1>");

    // An unparseable policy is reported, never silently treated as
    // default-deny: "your ruleset does not load" and "nothing permits this"
    // are very different messages and an operator must be able to tell them
    // apart.
    let policy = match Policy::from_toml(&doc) {
        Ok(p) => p,
        Err(e) => {
            body.push_str(&format!(
                "<div class=\"err\">The saved policy did not load, so no verdict \
                 can be given: {e}</div>"
            ));
            body.push_str("<p><a href=\"/rules\">Back to rules</a></p>");
            return Html(layout(
                "Decision test",
                state.setup_pending(),
                halted(&state).as_deref(),
                None,
                None,
                &body,
            ));
        }
    };

    let request = chaperone_policy::Request {
        agent_id: form.agent_id.trim(),
        cred_ref: form.cred_ref.trim(),
        target_uri: form.target_uri.trim(),
        mechanism: form.mechanism.trim(),
        declared: None,
    };
    let decision = policy.evaluate(&request);
    body.push_str(&preview::verdict_block(
        decision.effect.as_str(),
        &decision.source.label(),
    ));

    // The form repeats the request so the operator can vary one axis and
    // re-ask without retyping. Values are echoed back through the escaper.
    body.push_str(&format!(
        "<form method=\"post\" action=\"/policy/test\" class=\"card\">\
         <input name=\"agent_id\" value=\"{}\" placeholder=\"agent:my-agent\" \
         spellcheck=\"false\"><br>\
         <input name=\"cred_ref\" value=\"{}\" \
         placeholder=\"local://prod/github/token\" spellcheck=\"false\"><br>\
         <input name=\"target_uri\" value=\"{}\" \
         placeholder=\"https://api.github.com/user\" spellcheck=\"false\"><br>\
         <input name=\"mechanism\" value=\"{}\" placeholder=\"http-bearer\" \
         spellcheck=\"false\">\
         <p><button type=\"submit\">Evaluate</button> \
         <span class=\"muted\">runs the real engine against your saved rules; \
         nothing is enforced and nothing is contacted</span></p></form>",
        esc(&form.agent_id),
        esc(&form.cred_ref),
        esc(&form.target_uri),
        esc(&form.mechanism),
    ));
    body.push_str("<p><a href=\"/rules\">Back to rules</a></p>");
    Html(layout(
        "Decision test",
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
