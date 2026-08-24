//! Phase 12 acceptance tests: the operator console socket (D8/D32).
//!
//! - A connected operator's `y` approves through the full gateway flow.
//! - With NO operator connected, confirmations fail closed immediately
//!   (no hang, no auto-approve).
//! - The prompt block renders on the console with full context.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use chaperone_gateway_core::{ConfirmationGate, ConsoleHub, OperatorGate};
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

fn connected_pair(hub_path: &str) -> (Arc<ConsoleHub>, UnixStream) {
    let (client, server) = UnixStream::pair().unwrap();
    (ConsoleHub::from_stream(server, hub_path.into()), client)
}

#[tokio::test]
async fn connected_operator_y_approves() {
    let (hub, mut operator_side) = connected_pair("/tmp/unused-console-a");

    // Operator pre-writes the approval; the gate reads it when it runs.
    use std::io::Write as _;
    operator_side.write_all(b"y\n").unwrap();

    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(5));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Approved
    );

    // The prompt reached the operator with full context.
    let mut seen = String::new();
    use std::io::Read as _;
    operator_side.set_nonblocking(true).unwrap();
    let _ = operator_side.read_to_string(&mut seen);
    for needle in [AGENT, "stripe-prod", "http-bearer"] {
        assert!(seen.contains(needle), "prompt missing {needle}: {seen:?}");
    }
}

#[tokio::test]
async fn connected_operator_n_refuses() {
    let (hub, mut operator_side) = connected_pair("/tmp/unused-console-b");
    use std::io::Write as _;
    operator_side.write_all(b"n\n").unwrap();

    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(5));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Refused
    );
}

#[tokio::test]
async fn no_operator_connected_fails_closed_fast() {
    let hub = ConsoleHub::new("/tmp/unused-console-c".into());
    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(30));
    // Must NOT wait 30s: an absent console is a refusal, not a pause.
    let started = std::time::Instant::now();
    let outcome = gate.confirm(ctx()).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(outcome, chaperone_gateway_core::ConfirmOutcome::Refused);
}

#[tokio::test]
async fn disconnected_operator_mid_prompt_is_refusal() {
    let (hub, operator_side) = connected_pair("/tmp/unused-console-d");
    drop(operator_side); // console vanished after connecting

    let gate = OperatorGate::new(Box::new(hub), Duration::from_secs(5));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Refused
    );
}
