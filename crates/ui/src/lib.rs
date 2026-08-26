//! Chaperone operator config UI (OPERATOR-UI-SPEC Part A, D36/D40/D41).
//!
//! A loopback web UI served from the daemon: first-run setup, secret CRUD,
//! rule editing, agent enrollment. Server-rendered HTML only - no JS build
//! step, no client framework, no telemetry. Access is gated by a
//! per-instance token (D41): unlike a `0600` Unix domain socket, plain TCP
//! on 127.0.0.1 has no OS-level per-user ACL, so the token answers "which
//! local account" while the Host/Origin guard (D40) answers "which origin."
//!
//! Hard constraint (\u{A7}3.2 / D33/D36): this crate NEVER parses or writes policy
//! TOML, vault format, or enrollment JSON itself. Every mutation goes
//! through `chaperone-policy` / `chaperone-vault` / `chaperone-identity` -
//! one validator, two front ends. The TOML it saves is produced by
//! [`chaperone_policy::Policy::to_toml`] and re-validated with
//! [`chaperone_policy::Policy::from_toml`] before a byte hits disk.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};

pub mod matrix;
pub mod pages;
pub mod render;
pub mod setup;
pub mod state;
pub mod token;

pub use state::{Provision, UiState, atomic_write};
pub use token::{TOKEN_LEN, UiToken, load, rotate};

/// Cookie name carrying the session token.
const COOKIE_NAME: &str = "chaperone_ui";
/// Query parameter name for first-load token entry.
const TOKEN_PARAM: &str = "token";

/// Assembles the full router: Host/Origin guard (outer) \u{2192} token gate
/// (inner) \u{2192} handlers.
pub fn router(state: Arc<UiState>) -> Router {
    Router::new()
        .route("/token", get(token_page).post(token_submit))
        .route("/", get(pages::dashboard))
        .route("/setup", get(setup::page))
        .route("/setup/vault", post(setup::create_vault))
        .route("/setup/policy", post(setup::create_policy))
        .route("/setup/audit-key", post(setup::create_audit_key))
        .route(
            "/secrets",
            get(pages::secrets_page).post(pages::secrets_store),
        )
        .route("/secrets/delete", post(pages::secrets_delete))
        .route(
            "/agents",
            get(pages::agents_page).post(pages::agents_enroll),
        )
        .route("/agents/enroll", post(pages::agents_enroll))
        .route("/agents/revoke", post(pages::agents_revoke))
        .route("/rules", get(pages::rules_page))
        .route("/rules/new", get(pages::rules_new))
        .route("/rules/add", post(pages::rules_add))
        .route("/rules/delete", post(pages::rules_delete))
        .route("/policy/raw", get(pages::raw_page).post(pages::raw_save))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            token_gate,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            loopback_guard,
        ))
        .with_state(state)
}

// ---------- outer layer: Host/Origin guard (D40) ----------

/// CSRF / DNS-rebinding guard for a bare-localhost listener.
///
/// Stops a *remote* web page driving the operator's browser against
/// 127.0.0.1 (classic CSRF) or DNS-rebinding the origin. Refuses anything
/// whose Host is not the loopback address itself or whose Origin does not
/// match. Invisible to legitimate use.
async fn loopback_guard(
    State(state): State<Arc<UiState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let allowed_hosts = [
        format!("127.0.0.1:{}", state.port),
        format!("localhost:{}", state.port),
    ];
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| allowed_hosts.iter().any(|a| a == h));
    let origin_ok = match req.headers().get(header::ORIGIN) {
        None => true,
        Some(origin) => {
            let text = origin.to_str().unwrap_or_default();
            allowed_hosts.iter().any(|a| text == format!("http://{a}"))
        }
    };
    if !host_ok || !origin_ok {
        return (
            StatusCode::FORBIDDEN,
            "refused: this UI answers only on http://127.0.0.1\n",
        )
            .into_response();
    }
    next.run(req).await
}

// ---------- inner layer: access token gate (D41) ----------

/// Requires a valid token before rendering or accepting anything beyond
/// the paste page itself. The token reaches the gate via the `?token=`
/// query param (first load, then stripped with a cookie set) or the
/// `chaperone_ui` cookie (subsequent requests).
///
/// The `/token` path is always pass-through: the paste page is the one
/// place an unauthenticated request is supposed to land.
#[allow(clippy::collapsible_if)]
async fn token_gate(State(state): State<Arc<UiState>>, req: Request<Body>, next: Next) -> Response {
    // The paste page and its submit are the token-entry surface.
    if req.uri().path() == "/token" {
        return next.run(req).await;
    }

    // Cookie present and valid \u{2192} pass through.
    if let Some(cookie_token) = extract_cookie(req.headers().get(header::COOKIE)) {
        if state.token.verify(&cookie_token) {
            return next.run(req).await;
        }
    }

    // Query-param token on a GET \u{2192} set cookie, strip the param, 303.
    if req.method() == axum::http::Method::GET {
        if let Some(qs) = req.uri().query() {
            if let Some(provided) = parse_query_value(qs, TOKEN_PARAM) {
                if state.token.verify(&provided) {
                    let clean_path = strip_token_from_query(req.uri());
                    return cookie_redirect(&clean_path, &provided);
                }
            }
        }
        // No valid token: send to the paste page.
        let next_path = req.uri().path();
        return Redirect::to(&format!("/token?next={next_path}")).into_response();
    }

    // Non-GET without a valid token: refuse. We do NOT redirect mutations.
    (
        StatusCode::FORBIDDEN,
        "refused: a valid UI access token is required (run 'chaperone ui-token show')",
    )
        .into_response()
}

/// Builds a 303 redirect that also sets the session cookie.
fn cookie_redirect(location: &str, token: &str) -> Response {
    let cookie = format!("{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400");
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Extracts the value of `chaperone_ui` from a `Cookie:` header.
fn extract_cookie(header: Option<&axum::http::HeaderValue>) -> Option<String> {
    let line = header?.to_str().ok()?;
    for pair in line.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return Some(rest.to_owned());
        }
    }
    None
}

/// Parses a single value from a query string.
fn parse_query_value(qs: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for pair in qs.split('&') {
        if let Some(rest) = pair.strip_prefix(&prefix) {
            return Some(percent_decode(rest));
        }
    }
    None
}

/// Strips the `token=...` param from the query string, returns the clean
/// path (with remaining params, or no `?` if none remain).
fn strip_token_from_query(uri: &axum::http::Uri) -> String {
    let path = uri.path().to_owned();
    let Some(qs) = uri.query() else { return path };
    let kept: Vec<&str> = qs
        .split('&')
        .filter(|p| !p.starts_with(&format!("{TOKEN_PARAM}=")))
        .collect();
    if kept.is_empty() {
        path
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

/// Minimal percent-decoder for query values (handles the common encodings).
#[allow(clippy::collapsible_if)]
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(char::from_u32(hi * 16 + lo).unwrap_or('\u{FFFD}'));
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(' ');
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

/// Sanitizes a `next` redirect target: must start with `/`, not `//`
/// (protocol-relative), and not contain `//` after the leading slash
/// (open-redirect guard). Defaults to `/`.
fn safe_next(raw: &str) -> String {
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains('\n') {
        raw.to_owned()
    } else {
        "/".to_owned()
    }
}

// ---------- token paste page ----------

/// GET /token \u{2014} the one page served without a token.
async fn token_page(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Html<String> {
    let next = params
        .get("next")
        .map(|n| safe_next(n))
        .unwrap_or_else(|| "/".to_owned());
    let err = params.get("err").map(|e| e.replace('+', " "));
    let mut body = String::from("<h1>Chaperone UI access</h1>");
    body.push_str("<p>This UI is gated by a per-instance access token (D41). The token was created with <code>chaperone ui-token rotate</code> and lives at <code>0600</code> in your config directory alongside the audit key.</p>");
    body.push_str(
        "<p>To retrieve it: <code>chaperone ui-token show --token &lt;PATH&gt;</code></p>",
    );
    if let Some(e) = &err {
        body.push_str(&format!(
            "<div class=\"err\">{}</div>",
            crate::render::esc(e)
        ));
    }
    body.push_str("<form method=\"post\" action=\"/token\">");
    body.push_str("<p><label>Access token<br><input name=\"token\" required spellcheck=\"false\" autocomplete=\"off\"></label></p>");
    body.push_str(&format!(
        "<input type=\"hidden\" name=\"next\" value=\"{}\">",
        crate::render::esc(&next)
    ));
    body.push_str("<button type=\"submit\">Open</button></form>");
    axum::response::Html(crate::render::layout("Token", 0, None, None, None, &body))
}

/// POST /token \u{2014} validates the pasted token, sets a cookie, redirects.
#[derive(serde::Deserialize)]
struct TokenSubmit {
    token: String,
    #[serde(default)]
    next: String,
}

async fn token_submit(
    State(state): State<Arc<UiState>>,
    axum::Form(form): axum::Form<TokenSubmit>,
) -> Response {
    if state.token.verify(form.token.trim()) {
        let dest = safe_next(&form.next);
        cookie_redirect(&dest, form.token.trim())
    } else {
        Redirect::to(&format!(
            "/token?err={}",
            crate::setup::urlenc("that token does not match")
        ))
        .into_response()
    }
}

// ---------- serve ----------

/// Binds 127.0.0.1:`port` for the UI.
///
/// Binding separately lets the daemon fail loudly at startup when the
/// operator UI cannot listen (port taken), instead of failing silently on a
/// spawned task.
///
/// # Errors
/// The port could not be bound.
pub async fn bind(port: u16) -> Result<tokio::net::TcpListener, String> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("UI bind {addr}: {e}"))
}

/// Serves the UI on a previously-bound [`bind`] listener until dropped.
///
/// # Errors
/// The accept loop failed.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    state: Arc<UiState>,
) -> Result<(), String> {
    let app = router(state);
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("UI serve: {e}"))
}

/// Binds and serves in one call (tests, standalone use).
///
/// # Errors
/// See [`bind`].
pub async fn serve(state: Arc<UiState>) -> Result<(), String> {
    let port = state.port;
    let listener = bind(port).await?;
    serve_on(listener, state).await
}
