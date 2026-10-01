//! Phase 12 acceptance tests: the operator console channel (D8/D32).
//!
//! - A connected operator's `y` approves through the full gateway flow.
//! - With NO operator connected, confirmations fail closed immediately
//!   (no hang, no auto-approve).
//! - The prompt block renders on the console with full context.
//!
//! Runs on every platform since P1-1 item 3: the console is a real endpoint
//! (UDS 0600 on unix, owner-only named pipe on Windows, D44) bound through
//! `ConsoleHub::spawn` — the same path `serve` uses — rather than a
//! unix-only `UnixStream::pair()` shortcut. Endpoint file names are unique
//! per test because Windows pipe names derive from the file-name component.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chaperone_gateway_core::{ConfirmationGate, ConsoleHub, OperatorGate};
use chaperone_transport::operator_pipe::OperatorStream;
use std::time::Duration;

const AGENT: &str = "agent:console-1";

fn ctx() -> chaperone_gateway_core::ConfirmContext {
    chaperone_gateway_core::ConfirmContext {
        agent_id: AGENT.into(),
        target_label: "stripe-prod".into(),
        target_uri: "https://api.stripe.com/v1/charges".into(),
        mechanism: "http-bearer".into(),
        summary: "POST with body".into(),
    }
}

/// Binds a real console endpoint and connects the operator side. Returns
/// (hub, operator stream, tempdir-keeper).
fn connected_pair(name: &str) -> (Arc<ConsoleHub>, OperatorStream, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    let hub = ConsoleHub::spawn(&path).unwrap();
    let operator = OperatorStream::connect(path.to_str().unwrap()).unwrap();
    // Let the acceptor thread register the connection before the gate runs.
    std::thread::sleep(Duration::from_millis(120));
    (hub, operator, dir)
}

/// Reads the rendered prompt back on the operator side (deadline-bounded so
/// a missing prompt fails instead of hanging).
fn read_prompt(operator: &OperatorStream) -> String {
    let timeout = Duration::from_secs(5);
    let mut seen = String::new();
    while let Ok(b) = operator.read_byte_timeout(timeout) {
        // Prompts end at the "[y/N]: " suffix; drain until the read
        // deadline expires of data (no more bytes => TimedOut => stop).
        seen.push(b as char);
        if seen.ends_with("[y/N]: ") {
            break;
        }
    }
    seen
}

#[tokio::test]
async fn connected_operator_y_approves() {
    let (hub, operator, _dir) = connected_pair("console-a.sock");

    // Operator pre-writes the approval; the gate reads it when it runs.
    operator.write_all(b"y\n").unwrap();

    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(5));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Approved
    );

    // The prompt reached the operator with full context.
    let seen = read_prompt(&operator);
    for needle in [AGENT, "stripe-prod", "http-bearer"] {
        assert!(seen.contains(needle), "prompt missing {needle}: {seen:?}");
    }
}

#[tokio::test]
async fn connected_operator_n_refuses() {
    let (hub, operator, _dir) = connected_pair("console-b.sock");
    operator.write_all(b"n\n").unwrap();

    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(5));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Refused
    );
}

#[tokio::test]
async fn no_operator_connected_fails_closed_fast() {
    let hub = ConsoleHub::new("unused-console-c".into());
    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(30));
    // Must NOT wait 30s: an absent console is a refusal, not a pause.
    let started = std::time::Instant::now();
    let outcome = gate.confirm(ctx()).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(outcome, chaperone_gateway_core::ConfirmOutcome::Refused);
}

#[tokio::test]
async fn disconnected_operator_mid_prompt_is_refusal() {
    let (hub, operator, _dir) = connected_pair("console-d.sock");
    drop(operator); // console vanished after connecting

    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(5));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Refused
    );
}
