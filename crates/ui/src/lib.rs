//! Chaperone operator config UI (OPERATOR-UI-SPEC Part A, D36/D40).
//!
//! A loopback web UI served from the daemon: first-run setup, secret CRUD,
//! rule editing, agent enrollment. Server-rendered HTML only - no JS build
//! step, no client framework, no telemetry, no auth boundary beyond "this
//! is your own machine's loopback" (the same trust tier as the console
//! client).
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
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

pub mod matrix;
pub mod pages;
pub mod render;
pub mod setup;
pub mod state;

pub use state::{Provision, UiState, atomic_write};

/// Assembles the full router with the loopback guard.
pub fn router(state: Arc<UiState>) -> Router {
    Router::new()
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
            loopback_guard,
        ))
        .with_state(state)
}

/// CSRF / DNS-rebinding guard for a bare-localhost listener.
///
/// The UI trusts the loopback (D40): no login, no token. What that posture
/// must still resist is a *remote* web page driving the operator's browser
/// against 127.0.0.1 (classic CSRF) or DNS-rebinding the origin. Both are
/// refused by requiring the Host to be the loopback address itself and any
/// present Origin to match. This is invisible to legitimate use.
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
