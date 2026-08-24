//! Phase 7 acceptance tests (docs/PLAN.md M7): one gate, well-placed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chaperone_gateway_core::{ConfirmationGate, OperatorGate, OperatorIo};

#[derive(Debug, Default)]
struct PipedChannel {
    prompt: Arc<Mutex<String>>,
    answers: Mutex<std::collections::VecDeque<String>>, // empty => EOF
}

impl PipedChannel {
    fn with_answers(answers: &[&str]) -> (Self, Arc<Mutex<String>>) {
        let ch = Self {
            prompt: Arc::new(Mutex::new(String::new())),
            answers: Mutex::new(answers.iter().map(|s| (*s).to_owned()).collect()),
        };
        let prompt = Arc::clone(&ch.prompt);
        (ch, prompt)
    }
}

impl OperatorIo for PipedChannel {
    fn write_prompt(&mut self, block: &str) -> std::io::Result<()> {
        self.prompt.lock().unwrap().push_str(block);
        Ok(())
    }
    fn read_answer(&mut self) -> std::io::Result<Option<String>> {
        Ok(self.answers.lock().unwrap().pop_front())
    }
}

fn ctx() -> chaperone_gateway_core::ConfirmContext {
    chaperone_gateway_core::ConfirmContext {
        agent_id: "agent:planner-7".into(),
        target_label: "stripe-prod".into(),
        target_uri: "https://api.stripe.com/v1/charges".into(),
        mechanism: "http-bearer".into(),
        summary: "POST with body".into(),
    }
}

#[tokio::test]
async fn prompt_renders_full_context_once() {
    let (ch, prompt) = PipedChannel::with_answers(&["y"]);
    let gate = OperatorGate::new(Box::new(ch), Duration::from_secs(2));
    let out = gate.confirm(ctx()).await;
    assert_eq!(out, chaperone_gateway_core::ConfirmOutcome::Approved);

    let text = prompt.lock().unwrap().clone();
    for needle in [
        "agent:planner-7",
        "stripe-prod",
        "https://api.stripe.com",
        "http-bearer",
        "POST",
    ] {
        assert!(text.contains(needle), "prompt missing {needle}: {text}");
    }
    assert_eq!(
        text.matches("CHAPERONE CONFIRMATION").count(),
        1,
        "ONE prompt"
    );
}

#[tokio::test]
async fn explicit_no_refuses() {
    let (ch, _p) = PipedChannel::with_answers(&["n"]);
    let gate = OperatorGate::new(Box::new(ch), Duration::from_secs(2));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Refused
    );
}

#[tokio::test]
async fn garbage_answer_defaults_to_refusal() {
    // Confirmation fatigue defense: ambiguity never approves.
    let (ch, _) = PipedChannel::with_answers(&["maybe"]);
    let gate = OperatorGate::new(Box::new(ch), Duration::from_secs(2));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Refused
    );
}

#[tokio::test]
async fn eof_is_refusal_not_approval() {
    let (ch, _) = PipedChannel::with_answers(&[]);
    let gate = OperatorGate::new(Box::new(ch), Duration::from_secs(2));
    assert_eq!(
        gate.confirm(ctx()).await,
        chaperone_gateway_core::ConfirmOutcome::Refused
    );
}

#[tokio::test]
async fn silence_times_out() {
    // A channel that never answers.
    struct Silent;
    impl OperatorIo for Silent {
        fn write_prompt(&mut self, _: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn read_answer(&mut self) -> std::io::Result<Option<String>> {
            std::thread::sleep(Duration::from_secs(2)); // far beyond the 150ms timeout
            Ok(Some("y".to_owned()))
        }
    }
    let gate = OperatorGate::new(Box::new(Silent), Duration::from_millis(150));
    let out = gate.confirm(ctx()).await;
    assert_eq!(out, chaperone_gateway_core::ConfirmOutcome::TimedOut);
}
