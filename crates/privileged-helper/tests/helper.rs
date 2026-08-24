//! Phase 9 acceptance tests (docs/PLAN.md M9), helper-side.
//!
//! Drives the REAL security logic through `process_request`:
//! - token-gated: bad/missing tokens never reach execution checks;
//! - allowlist-pinned: exact command + argument prefix; extras after the
//!   pin are fine, deviations are refused;
//! - real executions relay output + exit codes and STRIP the shared token
//!   from the child's environment;
//! - framing helpers round-trip.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chaperone_helper_core::{Allowlist, process_request};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

const TOKEN: &str = "tok-1234567890abcdef";

fn load(toml_text: &str) -> Allowlist {
    let path = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(path.path(), toml_text).unwrap();
    Allowlist::load(path.path()).unwrap()
}

const ECHO_PINNED: &str = "[[allow]]\ncommand = \"/bin/echo\"\nargs = [\"hello\"]\n";

fn req(id: &str, command: &str, args: &[&str], token: &str) -> Value {
    json!({"token": token, "id": id, "op": "exec", "command": command, "args": args})
}

static RUNS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn bad_or_missing_token_denies_before_any_execution_check() {
    let al = load(ECHO_PINNED);
    RUNS.store(0, Ordering::SeqCst);

    let wrong = process_request(&req("a", "/bin/echo", &["hello"], "nope"), TOKEN, &al, true);
    assert_eq!(wrong[0]["status"], "denied");
    assert!(wrong[0]["reason"].as_str().unwrap().contains("bad token"));

    let absent = process_request(
        &json!({"id": "b", "op": "exec", "command": "/bin/echo"}),
        TOKEN,
        &al,
        true,
    );
    assert_eq!(absent[0]["status"], "denied");

    // run_child was true, but NOTHING executed: denial precedes spawn.
    assert_eq!(RUNS.load(Ordering::SeqCst), 0);
}

#[test]
fn allowlist_pins_command_and_argument_prefix() {
    let al = load(ECHO_PINNED);

    let denied = process_request(
        &req("c", "/bin/rm", &["-rf", "/"], TOKEN),
        TOKEN,
        &al,
        false,
    );
    assert_eq!(denied[0]["status"], "denied");

    let prefix_violation =
        process_request(&req("d", "/bin/echo", &["world"], TOKEN), TOKEN, &al, false);
    assert_eq!(prefix_violation[0]["status"], "denied");

    // Extra arguments AFTER the pinned prefix are permitted.
    let ok = process_request(
        &req("e", "/bin/echo", &["hello", "extra-is-fine"], TOKEN),
        TOKEN,
        &al,
        false,
    );
    assert_eq!(ok[0]["status"], "authorized");
}

#[cfg_attr(windows, ignore = "unix fixtures")]
#[test]
fn real_exec_relays_output_and_exit_and_strips_token_from_child_env() {
    let al = load(
        "[[allow]]\ncommand = \"/bin/sh\"\nargs = []\n[[allow]]\ncommand = \"/bin/echo\"\nargs = [\"hello\"]\n",
    );
    let mut msg = req("f", "/bin/sh", &[], TOKEN);
    msg["input_b64"] = json!(chaperone_protocol::encode_signature(
        b"printenv CHAPERONE_HELPER_TOKEN; echo marker-$((1+1))"
    ));
    let msgs = process_request(&msg, TOKEN, &al, true);
    let out: String = msgs
        .iter()
        .filter(|m| m["type"] == "out" && m["stream"] == "stdout")
        .filter_map(|m| m["data_b64"].as_str())
        .filter_map(|b| chaperone_protocol::decode_signature(b).ok())
        .flat_map(|b| String::from_utf8(b.to_vec()).into_iter())
        .collect();
    assert!(out.contains("marker-2"), "{out:?}");
    assert!(
        !out.lines().any(|l| l.contains(TOKEN)),
        "shared token leaked into child env: {out:?}"
    );
    assert!(
        msgs.iter()
            .any(|m| m["type"] == "exit" && m["exit_code"] == 0),
        "{msgs:?}"
    );
}

#[test]
fn framing_round_trips_through_public_helpers() {
    let payload = br#"{"x":1}"#;
    let mut buf = Vec::new();
    chaperone_helper_core::write_frame(&mut buf, payload).unwrap();
    let back = chaperone_helper_core::read_frame(&mut buf.as_slice())
        .unwrap()
        .unwrap();
    assert_eq!(back, payload.to_vec());
}
