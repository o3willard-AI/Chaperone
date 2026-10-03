//! P1-1/P1-3 acceptance: the events feed names the accountable human on
//! decision events, and brokered sessions emit usage summaries at teardown
//! plus periodic heartbeats — all feed-only (the audit chain is unchanged).
//!
//! These tests pin the gap-review requirements:
//! - sponsor_id present in the broadcast payload (P0-3 follow-up / P1-1).
//! - session.summary at client close and at TTL reap, with accurate
//!   command/byte counters.
//! - session.heartbeat once a session is open past the threshold, and NOT
//!   again within the same window (idempotence).
//! - no relayed content in session events (counters + references only).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The events feed has a real transport on every platform (P1-1 item 3:
// Windows named pipe, D44), so this coverage runs everywhere via the
// cross-platform operator-pipe facade.
//
// CH-77-2: every test runs under `run_guarded` — a worker thread with its own
// tokio runtime, watched from outside with a 20s deadline that panics naming
// the last phase reached. This file is where the Windows CI hang actually
// lived (session close/reap broadcasting a summary while the broker call was
// still in flight — a feed write on the broker thread circular-waits with a
// subscriber that only drains AFTER the call returns). The watchdog converts
// any future recurrence into a fast, located failure instead of a 6-hour
// cancelled job; `watchdog_fires` below proves the watchdog itself works.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chaperone_audit::{AuditKey, AuditWriter};
use chaperone_gateway_core::{
    AlwaysTimeoutGate, EventHub, Gateway, GatewayConfig, OutputBatch, SessionBackend,
    SessionChannel,
};
use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, ReplayCache};
use chaperone_policy::Policy;
use chaperone_protocol::testutil::sign_envelope;
use chaperone_vault::{LocalVault, SecretString, VaultRouter};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const AGENT: &str = "agent:sess-events";
const SPONSOR_ID: &str = "human@example.org";
const SPONSOR_NAME: &str = "Pat Human";
const SECRET_KEY_PEM: &str = "SIMULATED-SSH-KEY-BODY-NOT-A-REAL-CREDENTIAL";

// ---------- echo channel (counts nothing; stats come from the gateway) -----

struct EchoChannel {
    pending_out: Mutex<Vec<u8>>,
}

impl SessionChannel for EchoChannel {
    fn write(
        &self,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let text = String::from_utf8_lossy(&data).to_uppercase();
            self.pending_out
                .lock()
                .unwrap()
                .extend_from_slice(text.as_bytes());
            Ok(())
        })
    }

    fn read_batch(
        &self,
        _max_wait: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutputBatch> + Send + '_>> {
        Box::pin(async move {
            let mut out = self.pending_out.lock().unwrap();
            let chunks = if out.is_empty() {
                vec![]
            } else {
                vec![chaperone_gateway_core::OutputChunk {
                    stream: "stdout",
                    data: std::mem::take(&mut *out),
                }]
            };
            OutputBatch {
                chunks,
                closed: false,
                exit_code: None,
            }
        })
    }

    fn shutdown(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async {})
    }
}

#[derive(Debug)]
struct MockSsh;

impl SessionBackend for MockSsh {
    fn connect<'a>(
        &'a self,
        _target_uri: &'a str,
        _operation: &'a Value,
        _secret: &'a SecretString,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn SessionChannel>, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            Ok(Box::new(EchoChannel {
                pending_out: Mutex::new(Vec::new()),
            }) as Box<dyn SessionChannel>)
        })
    }
}

// ---------- spine (short heartbeat + TTL so scans can be exercised) --------

struct Spine {
    gateway: Gateway,
    signer: SigningKey,
    events_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn build(config: GatewayConfig) -> Spine {
    let dir = tempfile::tempdir().unwrap();
    let now = chaperone_gateway_core::chaperone_time_now();
    let rfc = || {
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };

    let signer = SigningKey::from_bytes(&[41u8; 32]);
    let enrollment = Arc::new(EnrollmentStore::load(&dir.path().join("e.json")).unwrap());
    enrollment
        .enroll(
            AGENT,
            &chaperone_protocol::encode_signature(&signer.verifying_key().to_bytes()),
            SPONSOR_ID,
            SPONSOR_NAME,
            &rfc(),
            false,
        )
        .unwrap();
    let attestor = Attestor::new(
        enrollment,
        Arc::new(ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp()).unwrap()),
        IdentityConfig { max_skew_secs: 30 },
    );

    let mut store = LocalVault::create(
        &dir.path().join("v.bin"),
        "passphrase",
        Zeroizing::new("p".into()),
    )
    .unwrap();
    store
        .set(
            "deploy/app-01",
            SecretString::new(SECRET_KEY_PEM.to_owned()),
        )
        .unwrap();
    let mut router = VaultRouter::new();
    router.register("local", Arc::new(store));

    let audit_key = AuditKey::generate();
    let audit = Arc::new(AuditWriter::open(&dir.path().join("audit.jsonl"), audit_key).unwrap());

    let events_path = dir.path().join("events.sock");
    let hub = EventHub::spawn(&events_path).unwrap();

    let mut gateway = Gateway::new(
        attestor,
        Policy::from_toml("[[rule]]\neffect = \"allow\"\n").unwrap(),
        router,
        audit,
        Arc::new(AlwaysTimeoutGate),
        config,
    )
    .unwrap();
    gateway.with_session_backend("ssh", Arc::new(MockSsh));
    gateway.with_event_hub(hub);

    Spine {
        gateway,
        signer,
        events_path,
        _dir: dir,
    }
}

// ---------- frame builders ----------

fn opener(spine: &Spine, nonce: &str) -> Value {
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut env = json!({
        "chaperone": "0.1", "msg_id": format!("ev-open-{nonce}"), "type": "intent",
        "agent_id": AGENT,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": nonce,
        "target": {"uri": "ssh://app-01.internal", "label": "app-01"},
        "mechanism": "ssh",
        "cred_ref": "local://deploy/app-01",
        "operation": {"host": "app-01.internal", "port": 22, "user": "deploy"},
    });
    sign_envelope(&spine.signer, &mut env);
    env
}

fn command(spine: &Spine, handle: &str, nonce: &str, input: &str) -> Value {
    use base64::Engine as _;
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut env = json!({
        "chaperone": "0.1", "msg_id": format!("ev-cmd-{nonce}"), "type": "session.command",
        "agent_id": AGENT,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": nonce,
        "session_handle": handle,
        "input_b64": base64::engine::general_purpose::STANDARD.encode(input.as_bytes()),
    });
    sign_envelope(&spine.signer, &mut env);
    env
}

fn closer(spine: &Spine, handle: &str, nonce: &str) -> Value {
    let now = chaperone_gateway_core::chaperone_time_now();
    let mut env = json!({
        "chaperone": "0.1", "msg_id": format!("ev-close-{nonce}"), "type": "session.close",
        "agent_id": AGENT,
        "issued_at": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "nonce": nonce,
        "session_handle": handle,
    });
    sign_envelope(&spine.signer, &mut env);
    env
}

// ---------- feed subscription (same pattern as notify_on_use.rs) ----------

fn subscribe(events_path: &std::path::Path) -> chaperone_transport::operator_pipe::OperatorStream {
    let sub =
        chaperone_transport::operator_pipe::OperatorStream::connect(events_path.to_str().unwrap())
            .unwrap();
    std::thread::sleep(Duration::from_millis(120));
    sub
}

/// Reads feed lines until one has `type == want`, or None on timeout.
fn next_event_of(
    sub: &chaperone_transport::operator_pipe::OperatorStream,
    want: &str,
) -> Option<Value> {
    let timeout = Duration::from_millis(900);
    let mut buf: Vec<u8> = Vec::new();
    while let Ok(b) = sub.read_byte_timeout(timeout) {
        buf.push(b);
        if b == b'\n' {
            let line = String::from_utf8_lossy(&buf).trim().to_owned();
            buf.clear();
            if let Ok(v) = serde_json::from_str::<Value>(&line)
                && v["type"] == want
            {
                return Some(v);
            }
        }
    }
    None
}

fn config(session_ttl: u64, heartbeat: u64) -> GatewayConfig {
    GatewayConfig {
        default_session_ttl_secs: session_ttl,
        default_max_response_bytes: 1_048_576,
        default_timeout_secs: 30,
        session_heartbeat_secs: heartbeat,
    }
}

// ---------- CH-77-2 watchdog (same shape as operator_pipe.rs's) ----------

type Phase = Arc<Mutex<String>>;

fn set_phase(mark: &Phase, p: &str) {
    *mark.lock().unwrap() = p.to_owned();
}

/// Runs an async body on a worker thread with its own current-thread runtime,
/// panicking (naming the last phase) if it does not finish within `limit`.
/// Thread-based on purpose: a hang here is a synchronous block INSIDE an
/// awaited call (the original bug was a blocking pipe write on the runtime
/// thread), which a `tokio::time::timeout` around the body could never fire
/// on — the runtime itself is wedged. Panics inside the body propagate.
fn run_guarded(
    limit: Duration,
    body: impl FnOnce(Phase) -> Pin<Box<dyn Future<Output = ()>>> + Send + 'static,
) {
    let phase: Phase = Arc::new(Mutex::new("start".to_owned()));
    let phase_w = Arc::clone(&phase);
    let done = Arc::new(AtomicBool::new(false));
    let done_w = Arc::clone(&done);
    let worker = std::thread::spawn(move || {
        // Signal completion even if the body panics (an assertion failure),
        // so the watchdog loop joins immediately and propagates the real
        // panic instead of waiting out the full limit first.
        struct Done(Arc<AtomicBool>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _done = Done(done_w);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(body(phase_w));
    });
    let deadline = Instant::now() + limit;
    loop {
        if done.load(Ordering::SeqCst) {
            match worker.join() {
                Ok(()) => return,
                // Propagate the body's own panic (assertion failure) verbatim.
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    // Past the deadline and the worker never signaled: a real hang. We cannot
    // kill a blocked thread, so leave it detached (the process exits after the
    // panic) and fail loudly with the last phase reached.
    let reached = phase.lock().unwrap().clone();
    panic!(
        "HANG: session_events test deadlocked at phase '{reached}' (>{limit:?}) — feed I/O deadlock (CH-77-2 class)"
    );
}

const GUARD: Duration = Duration::from_secs(20);

// ---------- acceptance ----------

/// P1-1: every decision event on the feed names the accountable human.
#[test]
fn decision_events_carry_sponsor_id() {
    run_guarded(GUARD, |mark| {
        Box::pin(async move {
            set_phase(&mark, "build");
            let spine = build(config(300, 0)).await;
            set_phase(&mark, "subscribe");
            let sub = subscribe(&spine.events_path);

            // Opening a session is a decision event on the feed (session_opened).
            set_phase(&mark, "open");
            let resp = spine.gateway.handle_message(&opener(&spine, "s1")).await;
            assert_eq!(resp["type"], "result", "{resp}");

            set_phase(&mark, "read-decision");
            let ev = next_event_of(&sub, "decision").expect("decision must broadcast a feed event");
            assert_eq!(
                ev["sponsor_id"], SPONSOR_ID,
                "feed must name the accountable human: {ev}"
            );
            assert_eq!(ev["agent_id"], AGENT, "{ev}");
            assert_eq!(ev["mechanism"], "ssh", "{ev}");
            set_phase(&mark, "done");
        })
    });
}

/// P1-3: client close emits session.summary with accurate counters, and the
/// summary carries no relayed content (only counts + identifiers).
///
/// This is one of the two tests that HUNG on windows-latest pre-fix: the
/// close broadcast (summary, line #2) hit a full 512-byte pipe buffer while
/// the client had not yet read the open decision (line #1) and could not —
/// it was awaiting this very `handle_message`. The asynchronous hub writer
/// (CH-77-2) breaks that circular wait.
#[test]
fn client_close_emits_summary_with_stats() {
    run_guarded(GUARD, |mark| {
        Box::pin(async move {
            set_phase(&mark, "build");
            let spine = build(config(300, 0)).await;
            set_phase(&mark, "subscribe");
            let sub = subscribe(&spine.events_path);

            set_phase(&mark, "open");
            let resp = spine.gateway.handle_message(&opener(&spine, "c1")).await;
            let handle = resp["session_handle"].as_str().unwrap().to_owned();

            set_phase(&mark, "command-1");
            let r1 = spine
                .gateway
                .handle_message(&command(&spine, &handle, "c2", "uptime"))
                .await;
            assert_eq!(r1["type"], "session.output", "{r1}");
            set_phase(&mark, "command-2");
            let r2 = spine
                .gateway
                .handle_message(&command(&spine, &handle, "c3", "df -h"))
                .await;
            assert_eq!(r2["type"], "session.output", "{r2}");

            set_phase(&mark, "close");
            let r3 = spine
                .gateway
                .handle_message(&closer(&spine, &handle, "c4"))
                .await;
            assert_eq!(r3["type"], "session.closed", "{r3}");

            set_phase(&mark, "read-summary");
            let ev = next_event_of(&sub, "session.summary")
                .expect("client close must broadcast session.summary");
            assert_eq!(ev["session_handle"], handle, "{ev}");
            assert_eq!(ev["sponsor_id"], SPONSOR_ID, "{ev}");
            assert_eq!(ev["agent_id"], AGENT, "{ev}");
            assert_eq!(ev["mechanism"], "ssh", "{ev}");
            assert_eq!(ev["target_uri"], "ssh://app-01.internal", "{ev}");
            // Two command frames relayed; bytes_in == len("uptime") + len("df -h").
            assert_eq!(ev["commands"], 2, "{ev}");
            assert_eq!(ev["bytes_in"], 11, "{ev}");
            // Echo channel uppercases and returns everything: bytes_out == bytes_in.
            assert_eq!(ev["bytes_out"], 11, "{ev}");

            // No relayed content: the event must not contain the commands or output.
            let raw = serde_json::to_string(&ev).unwrap().to_uppercase();
            for leak in ["UPTIME", "DF -H", SECRET_KEY_PEM] {
                assert!(
                    !raw.contains(leak),
                    "session.summary must carry counters, not content ({leak}): {ev}"
                );
            }
            set_phase(&mark, "done");
        })
    });
}

/// P1-3: a session open past the heartbeat threshold gets exactly one
/// session.heartbeat per window (idempotent scan), and the beat carries the
/// same reference-only shape as the summary.
#[test]
fn heartbeat_fires_once_per_window() {
    run_guarded(GUARD, |mark| {
        Box::pin(async move {
            set_phase(&mark, "build");
            let spine = build(config(300, 1)).await; // 1s threshold
            set_phase(&mark, "subscribe");
            let sub = subscribe(&spine.events_path);

            set_phase(&mark, "open");
            let resp = spine.gateway.handle_message(&opener(&spine, "h1")).await;
            let handle = resp["session_handle"].as_str().unwrap().to_owned();
            set_phase(&mark, "command");
            let _ = spine
                .gateway
                .handle_message(&command(&spine, &handle, "h2", "whoami"))
                .await;

            // Under the threshold: no beat yet.
            set_phase(&mark, "scan-under-threshold");
            spine.gateway.emit_session_heartbeats().await;
            assert!(
                next_event_of(&sub, "session.heartbeat").is_none(),
                "heartbeat must not fire before the threshold"
            );

            // Past the threshold: exactly one beat, then idempotence within window.
            set_phase(&mark, "scan-past-threshold");
            tokio::time::sleep(Duration::from_millis(1100)).await;
            spine.gateway.emit_session_heartbeats().await;
            let ev = next_event_of(&sub, "session.heartbeat")
                .expect("session open past threshold must emit a heartbeat");
            assert_eq!(ev["session_handle"], handle, "{ev}");
            assert_eq!(ev["sponsor_id"], SPONSOR_ID, "{ev}");
            assert_eq!(ev["commands"], 1, "{ev}");

            // A second scan inside the same window must NOT beat again.
            set_phase(&mark, "scan-idempotent");
            spine.gateway.emit_session_heartbeats().await;
            assert!(
                next_event_of(&sub, "session.heartbeat").is_none(),
                "heartbeat must be idempotent within its window"
            );
            set_phase(&mark, "done");
        })
    });
}

/// P1-3: TTL-expired sessions are reaped by the liveness scan with a summary
/// event (lazy expiry alone would never surface an abandoned session), and
/// the reaped handle is dead afterwards.
///
/// The second of the two windows-latest hangs pre-fix: the reap broadcasts a
/// summary from inside `emit_session_heartbeats`, same full-buffer circular
/// wait as the client-close path.
#[test]
fn ttl_expiry_reaps_with_summary() {
    run_guarded(GUARD, |mark| {
        Box::pin(async move {
            set_phase(&mark, "build");
            let spine = build(config(1, 0)).await; // 1s TTL, heartbeats off
            set_phase(&mark, "subscribe");
            let sub = subscribe(&spine.events_path);

            set_phase(&mark, "open");
            let resp = spine.gateway.handle_message(&opener(&spine, "t1")).await;
            let handle = resp["session_handle"].as_str().unwrap().to_owned();
            set_phase(&mark, "command");
            let _ = spine
                .gateway
                .handle_message(&command(&spine, &handle, "t2", "id"))
                .await;

            set_phase(&mark, "wait-ttl");
            tokio::time::sleep(Duration::from_millis(1100)).await;
            set_phase(&mark, "reap");
            spine.gateway.emit_session_heartbeats().await;

            set_phase(&mark, "read-summary");
            let ev = next_event_of(&sub, "session.summary")
                .expect("reaped session must emit its summary");
            assert_eq!(ev["session_handle"], handle, "{ev}");
            assert_eq!(ev["commands"], 1, "{ev}");
            assert_eq!(ev["sponsor_id"], SPONSOR_ID, "{ev}");
            set_phase(&mark, "done");
        })
    });
}

/// CH-77-2 falsifiability: the watchdog this file relies on must actually
/// fire on a hang — an inert watchdog would let the real deadlock slip back
/// through as a silent 6-hour stall again. A body that outlives its (tiny)
/// limit must produce the located HANG panic.
#[test]
#[should_panic(expected = "HANG: session_events test deadlocked at phase 'stuck'")]
fn watchdog_fires_on_a_hanging_body() {
    run_guarded(Duration::from_millis(200), |mark| {
        Box::pin(async move {
            set_phase(&mark, "stuck");
            // Block the runtime thread synchronously — the exact shape of the
            // original bug (a blocking pipe write inside an awaited call),
            // which a tokio::time::timeout could NOT catch.
            std::thread::sleep(Duration::from_secs(30));
        })
    });
}
