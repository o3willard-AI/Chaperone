//! Minimal agent-side probe: connects to a running gateway over UDS, sends
//! one Content-Length-framed message, prints the framed response.
//!
//! ```text
//! cargo run -p chaperone-cli --example agent_probe -- <socket-path> '{"type":"intent","msg_id":"probe-1"}'
//! ```
//!
//! With an empty enrollment store this demonstrates the full identity gate
//! answering `E_UNKNOWN_AGENT` over the wire.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chaperone_transport::{Connection, ListenSpec};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "/tmp/chaperone-probe.sock".to_owned());
    let raw_message = args
        .next()
        .unwrap_or_else(|| json!({"type":"intent","msg_id":"probe-1"}).to_string());
    let message: serde_json::Value =
        serde_json::from_str(&raw_message).expect("message must be JSON");

    let spec = ListenSpec::UnixSocket { path: path.into() };
    let mut conn = Connection::connect(&spec).await.expect("connect");
    let response = conn.request(&message).await.expect("request");
    println!("{response}");
}
