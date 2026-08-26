//! First-run setup wizard (OPERATOR-UI-SPEC §3.3).
//!
//! Same artifacts GETTING-STARTED.md walks by hand, as forms instead of
//! copy-pasted commands. Each step names the real file it writes so a CLI
//! user reading over someone's shoulder recognizes it immediately.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;

use chaperone_audit::AuditKey;
use chaperone_policy::Policy;
use chaperone_vault::{LocalVault, SharedVault};

use crate::render::{esc, layout};
use crate::state::{UiState, atomic_write};
use std::collections::HashMap;

/// GET /setup - status of each artifact + forms for missing ones.
pub async fn page(
    State(state): State<Arc<UiState>>,
    Query(flash): Query<HashMap<String, String>>,
) -> Html<String> {
    let prov = state.provisioned();
    let mut body = String::from("<h1>Setup</h1>");
    body.push_str(
        "<p class=\"muted\">Each step writes the real file the gateway reads. \
         Nothing here is a simulation; re-run any step to replace an artifact.</p>",
    );

    if prov.complete() {
        body.push_str(
            "<div class=\"ok\">All required artifacts exist. Restart \
             <code>chaperone serve</code> (or it is already running) and the \
             broker will pick them up.</div>",
        );
    }

    // --- enrollment store (informational) ---
    body.push_str(&format!(
        "<h2>1 \u{B7} Agent enrollment store {}</h2><p class=\"muted\"><code>{}</code> \
         \u{2014} created automatically when you <a href=\"/agents\">enroll the first agent</a>.</p>",
        if prov.enrollment { "\u{2705}" } else { "\u{23F8}" },
        esc(&state.enrollment_path.display().to_string())
    ));

    // --- policy scaffold ---
    body.push_str(&format!(
        "<h2>2 \u{B7} Policy file {}</h2><p class=\"muted\"><code>{}</code></p>",
        if prov.policy { "\u{2705}" } else { "\u{23F8}" },
        esc(&state.policy_path.display().to_string())
    ));
    if prov.policy {
        body.push_str(
            "<p><a href=\"/rules\">Edit rules</a> or <a href=\"/policy/raw\">view the TOML</a>.</p>",
        );
    } else {
        body.push_str(
            "<form method=\"post\" action=\"/setup/policy\">\
             <button type=\"submit\">Write empty default-deny policy</button>\
             <span class=\"muted\"> (an empty document is a VALID pure default-deny ruleset: \
             every intent denied until you add rules)</span></form>",
        );
    }

    // --- vault ---
    body.push_str(&format!(
        "<h2>3 \u{B7} Local secret vault {}</h2><p class=\"muted\"><code>{}</code> \
         \u{2014} argon2id + AES-256-GCM, sealed with your passphrase (<a href=\"#\" title=\"LOCAL-VAULT-GUIDE.md\">guide</a>)</p>",
        if prov.vault { "\u{2705}" } else { "\u{23F8}" },
        esc(&state.vault_path.display().to_string())
    ));
    if !prov.vault {
        body.push_str(
            "<form method=\"post\" action=\"/setup/vault\">\
             <p><label>Passphrase<br><input type=\"password\" name=\"passphrase\" autocomplete=\"new-password\" required></label></p>\
             <p><label>Confirm passphrase<br><input type=\"password\" name=\"confirm\" autocomplete=\"new-password\" required></label></p>\
             <button type=\"submit\">Create vault</button></form>",
        );
    }

    // --- audit key ---
    body.push_str(&format!(
        "<h2>4 \u{B7} Audit chain signing key {}</h2><p class=\"muted\"><code>{}</code> \
         \u{2014} Ed25519 seed; every audit record is signed with it. Back this file up.</p>",
        if prov.audit_key {
            "\u{2705}"
        } else {
            "\u{23F8}"
        },
        esc(&state.audit_key_path.display().to_string())
    ));
    if !prov.audit_key {
        body.push_str(
            "<form method=\"post\" action=\"/setup/audit-key\">\
             <button type=\"submit\">Generate audit key</button></form>",
        );
    }

    let html = layout(
        "Setup",
        prov.missing(),
        halted_reason(&state).as_deref(),
        flash.get("msg").map(String::as_str),
        flash.get("err").map(String::as_str),
        &body,
    );
    Html(html)
}

/// Form body for vault creation (double passphrase entry).
#[derive(Deserialize)]
pub struct VaultForm {
    passphrase: String,
    confirm: String,
}

/// POST /setup/vault.
pub async fn create_vault(
    State(state): State<Arc<UiState>>,
    axum::Form(form): axum::Form<VaultForm>,
) -> impl IntoResponse {
    if form.passphrase.is_empty() {
        return Redirect::to("/setup?err=passphrase+must+not+be+empty");
    }
    if form.passphrase != form.confirm {
        return Redirect::to("/setup?err=passphrases+do+not+match");
    }
    match LocalVault::create(&state.vault_path, zeroize::Zeroizing::new(form.passphrase)) {
        Ok(vault) => {
            // The freshly-created vault is already unsealed in memory: hand
            // it to the UI immediately instead of demanding a restart just
            // to add secrets.
            *state
                .vault
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(SharedVault::new(vault));
            Redirect::to("/setup?msg=vault+created")
        }
        Err(e) => Redirect::to(&format!(
            "/setup?err={}",
            urlenc(&format!("vault create failed: {e}"))
        )),
    }
}

/// POST /setup/policy.
pub async fn create_policy(State(state): State<Arc<UiState>>) -> impl IntoResponse {
    if state.policy_path.exists() {
        return Redirect::to("/setup?err=policy+already+exists");
    }
    // Through the ONE writer (D36/D40); an empty ruleset parses back as a
    // valid pure default-deny document.
    let doc = Policy::empty().to_toml();
    match atomic_write(&state.policy_path, doc.as_bytes()) {
        Ok(()) => Redirect::to("/setup?msg=default-deny+policy+written"),
        Err(e) => Redirect::to(&format!("/setup?err={}", urlenc(&e))),
    }
}

/// POST /setup/audit-key.
pub async fn create_audit_key(State(state): State<Arc<UiState>>) -> impl IntoResponse {
    if state.audit_key_path.exists() {
        return Redirect::to("/setup?err=audit+key+already+exists%3B+refusing+to+overwrite");
    }
    let key = AuditKey::generate();
    // Same on-disk shape `chaperone audit-keygen` writes.
    let text = chaperone_protocol::encode_signature(&key.to_seed());
    match atomic_write(&state.audit_key_path, text.as_bytes()) {
        Ok(()) => Redirect::to(&format!(
            "/setup?msg={}",
            urlenc(&format!(
                "audit key written; public key: {}",
                key.public_key_b64url()
            ))
        )),
        Err(e) => Redirect::to(&format!("/setup?err={}", urlenc(&e))),
    }
}

fn halted_reason(state: &UiState) -> Option<String> {
    state
        .gateway
        .as_ref()
        .and_then(|g| g.is_halted().then(|| g.halt_reason().unwrap_or_default()))
}

/// Percent-encode for redirect query values (no external crate).
pub(crate) fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
