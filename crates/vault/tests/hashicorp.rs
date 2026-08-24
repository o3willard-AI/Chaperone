//! Phase 12 acceptance tests: `vault://` scheme via a local KV-v2 emulator.
//!
//! The emulator is a hand-rolled HTTP server asserting the exact request
//! shape (path + X-Vault-Token header) and answering the documented KV-v2
//! read envelope. Proves scheme dispatch, token handling, 404/auth mapping,
//! single-key and #key-selector reads - without a real Vault instance.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chaperone_vault::{Provider, SecretString, VaultKv2, VaultRouter};
use serde_json::{Value, json};

#[derive(Default)]
struct EmulatorState {
    /// path -> (status, body-json)
    responses: Mutex<HashMap<String, (u16, Value)>>,
    seen_tokens: Mutex<Vec<String>>,
    seen_paths: Mutex<Vec<String>>,
}

async fn spawn_emulator(state: Arc<EmulatorState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                // headers
                let header_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = find(&buf, b"\r\n\r\n") {
                        break p + 4;
                    }
                    if n == 0 {
                        return;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or("");
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_owned();
                let token = lines
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-vault-token"))
                    .map(|(_, v)| v.trim().to_owned())
                    .unwrap_or_default();

                state.seen_paths.lock().unwrap().push(path.clone());
                state.seen_tokens.lock().unwrap().push(token.clone());

                let lookup = format!(
                    "/v1/secret/data{}",
                    path.trim_start_matches("/v1/secret/data")
                );
                let resp = state
                    .responses
                    .lock()
                    .unwrap()
                    .get(&lookup)
                    .cloned()
                    .unwrap_or_else(|| (404u16, json!({"errors": []})));
                let body = serde_json::to_vec(&resp.1).unwrap();
                let out = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp.0,
                    if resp.0 == 200 { "OK" } else { "ERR" },
                    body.len()
                );
                sock.write_all(out.as_bytes()).await.unwrap();
                sock.write_all(&body).await.unwrap();
            });
        }
    });
    format!("http://{addr}")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn kv2_body(value: &str) -> Value {
    json!({ "data": { "data": { "value": value }, "metadata": {"version": 1} } })
}

const TOKEN: &str = "test-vault-token";

#[tokio::test]
async fn resolves_single_key_secret_with_token_header() {
    let state = Arc::new(EmulatorState {
        responses: Mutex::new(HashMap::from([(
            "/v1/secret/data/prod/stripe/key".to_owned(),
            (200, kv2_body("sk-simulated-vault-value")),
        )])),
        ..Default::default()
    });
    let base = spawn_emulator(Arc::clone(&state)).await;
    let provider = VaultKv2::new(&base, "secret", SecretString::new(TOKEN.to_owned())).unwrap();

    let secret = Provider::resolve(&provider, "prod/stripe/key")
        .await
        .unwrap();
    assert_eq!(secret.expose(), "sk-simulated-vault-value");

    assert_eq!(state.seen_tokens.lock().unwrap().last().unwrap(), TOKEN);
    assert!(
        state
            .seen_paths
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .ends_with("/v1/secret/data/prod/stripe/key"),
        "KV-v2 read path"
    );
}

#[tokio::test]
async fn multi_key_secrets_require_key_selector() {
    let state = Arc::new(EmulatorState {
        responses: Mutex::new(HashMap::from([(
            "/v1/secret/data/app/creds".to_owned(),
            (
                200,
                json!({"data": {"data": {"username": "deploy", "password": "pw-simulated"}}}),
            ),
        )])),
        ..Default::default()
    });
    let base = spawn_emulator(Arc::clone(&state)).await;
    let provider = VaultKv2::new(&base, "secret", SecretString::new(TOKEN.to_owned())).unwrap();

    // No selector on multi-key: refused, teaching the shape.
    let err = Provider::resolve(&provider, "app/creds").await.unwrap_err();
    assert!(err.to_string().contains("#key"), "{err}");

    let pw = Provider::resolve(&provider, "app/creds#password")
        .await
        .unwrap();
    assert_eq!(pw.expose(), "pw-simulated");
}

#[tokio::test]
async fn auth_failure_maps_to_backend_error_without_echo() {
    let state = Arc::new(EmulatorState {
        responses: Mutex::new(HashMap::from([(
            "/v1/secret/data/x".to_owned(),
            (403, json!({"errors": ["permission denied"]})),
        )])),
        ..Default::default()
    });
    let base = spawn_emulator(Arc::clone(&state)).await;
    let provider = VaultKv2::new(&base, "secret", SecretString::new("wrong".to_owned())).unwrap();
    let err = Provider::resolve(&provider, "x").await.unwrap_err();
    assert!(err.to_string().contains("rejected the token"), "{err}");
}

#[tokio::test]
async fn missing_entry_maps_to_entry_not_found() {
    let base = spawn_emulator(Arc::new(EmulatorState::default())).await;
    let provider = VaultKv2::new(&base, "secret", SecretString::new(TOKEN.to_owned())).unwrap();
    let err = Provider::resolve(&provider, "nope").await.unwrap_err();
    assert!(matches!(
        err,
        chaperone_vault::ResolveError::EntryNotFound(_)
    ));
}

#[tokio::test]
async fn routes_through_vault_scheme_and_rejects_bad_mounts() {
    let state = Arc::new(EmulatorState {
        responses: Mutex::new(HashMap::from([(
            "/v1/secret/data/k".to_owned(),
            (200, kv2_body("router-value")),
        )])),
        ..Default::default()
    });
    let base = spawn_emulator(Arc::clone(&state)).await;

    let mut router = VaultRouter::new();
    router.register(
        "vault",
        Arc::new(VaultKv2::new(&base, "secret", SecretString::new(TOKEN.to_owned())).unwrap()),
    );
    let s = router.resolve("vault://k").await.unwrap();
    assert_eq!(s.expose(), "router-value");

    // Constructor guards.
    assert!(VaultKv2::new("ftp://x", "secret", SecretString::new("t".into())).is_err());
    assert!(VaultKv2::new("http://x", "../evil", SecretString::new("t".into())).is_err());
}
