//! Integration tests for the operator-channel facade. Run natively on Linux/
//! macOS (unix path); the Windows path is compile-verified locally and
//! execution-verified by windows-latest CI.
//!
//! The round-trip test runs its body on a worker thread under a watchdog so a
//! Windows-only I/O deadlock (the failure this test exists to catch) surfaces
//! as a fast, located panic rather than stalling the CI runner to its limit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chaperone_transport::operator_pipe::{OperatorListener, OperatorStream};

/// Runs `body` on a worker thread; if it does not finish within `limit`, panic
/// with a message naming the phase reached, so a hang is a fast located
/// failure (the whole point of this test on windows-latest).
///
/// A worker PANIC is distinguished from a HANG (CH-77-2 run 3 lesson): the
/// Done-guard sets the flag even on unwind, so an assertion failure
/// propagates immediately via `resume_unwind` instead of being mislabeled
/// "HANG" after the full limit expires. Windows run 3 lost the real error
/// (`code: 232` on a write) behind a 20s HANG banner for exactly this
/// reason; the session_events `run_guarded` already had the guard, this one
/// did not.
fn with_watchdog(
    limit: std::time::Duration,
    body: impl FnOnce(&dyn Fn(&'static str)) + Send + 'static,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let done = Arc::new(AtomicBool::new(false));
    let done_w = Arc::clone(&done);
    // Last phase reached, for the panic message if we hang.
    let phase = Arc::new(std::sync::Mutex::new("start"));
    let phase_w = Arc::clone(&phase);

    let worker = std::thread::spawn(move || {
        struct Done(Arc<AtomicBool>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _done = Done(done_w);
        let mark = move |p: &'static str| {
            *phase_w.lock().unwrap() = p;
        };
        let mark_ref: &dyn Fn(&'static str) = &mark;
        body(mark_ref);
    });

    let deadline = std::time::Instant::now() + limit;
    loop {
        if done.load(Ordering::SeqCst) {
            match worker.join() {
                Ok(()) => return,
                // Propagate the body's own panic verbatim — NOT a HANG label.
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let reached = phase.lock().unwrap().clone();
    panic!(
        "HANG: operator-pipe round-trip deadlocked at phase '{reached}' (>{limit:?}) — Windows pipe I/O deadlock"
    );
}

#[test]
fn bind_connect_roundtrip() {
    // 20s is generous for a local loopback round-trip yet far below the CI
    // job limit, so a deadlock fails the run fast and locates the phase.
    with_watchdog(std::time::Duration::from_secs(20), |mark| {
        mark("bind");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.sock");
        let name = path.to_str().unwrap().to_owned();
        let listener = OperatorListener::bind(&name, |p| format!("live feed owns {p}")).unwrap();

        // Owner-only: the socket file must be 0600 (unix).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "operator channel must be owner-only, got {mode:o}"
            );
        }

        // Server: accept one client, write one JSON line, then read one line
        // back — a true bidirectional round-trip. BOTH sides use BLOCKING
        // reads, matching the production console path (ConsoleHub::read_answer
        // uses blocking read_byte). CH-77-2 run 3: this test originally used
        // read_byte_timeout (NOWAIT) for the client read and then write_all on
        // the same handle, which on Windows failed with code 232 — a
        // NOWAIT-read-then-write combination no production path has (feed
        // clients are read-only per D35; console is blocking both ways).
        let server = std::thread::spawn(move || {
            let conn = listener.accept().unwrap();
            conn.write_all(b"{\"type\":\"decision\"}\n").unwrap();
            let mut got = Vec::new();
            // Push the terminator too, so `got` is the exact client bytes
            // (b"ack\n") — the assertion compares whole writes.
            while let Ok(b) = conn.read_byte() {
                got.push(b);
                if b == b'\n' {
                    break;
                }
            }
            got
        });

        mark("connect");
        let stream = OperatorStream::connect(&name).unwrap();

        mark("client-read");
        // Read the broadcast line byte-by-byte the way feed consumers do, but
        // BLOCKING: the server has already written the line (its write
        // completed before this read), so no deadline is needed to prove
        // delivery, and staying blocking keeps this handle in the same mode
        // for the write below (no NOWAIT-then-write mix — see server note).
        let mut line: Vec<u8> = Vec::new();
        while let Ok(b) = stream.read_byte() {
            if b == b'\n' {
                break;
            }
            line.push(b);
        }
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&String::from_utf8(line).unwrap()).unwrap()["type"],
            "decision"
        );

        mark("client-write");
        stream.write_all(b"ack\n").unwrap();

        mark("join");
        let got = server.join().unwrap();
        assert_eq!(
            got, b"ack\n",
            "server must receive exactly the client reply"
        );
    });
}

/// Heph's ask #1: bind and connect MUST derive the same pipe/socket name for
/// the same endpoint string, or the client connects to a different name than
/// the listener bound and the round-trip deadlocks. `windows_pipe_name` is the
/// mapping both sides use on Windows and is pure/platform-independent, so this
/// invariant is testable everywhere.
#[test]
fn listener_and_client_derive_same_pipe_name() {
    use chaperone_transport::operator_pipe::windows_pipe_name;
    for endpoint in [
        "chaperone-events",
        r"C:\ProgramData\Chaperone\events.sock",
        "/tmp/xyz/events.sock",
        r"\\.\pipe\chaperone-console",
    ] {
        // bind() and connect() both funnel the endpoint through
        // endpoint_name -> windows_pipe_name; same input, same output.
        let from_bind = windows_pipe_name(endpoint);
        let from_connect = windows_pipe_name(endpoint);
        assert_eq!(
            from_bind, from_connect,
            "bind and connect disagree on the pipe name for {endpoint:?}"
        );
        // Pipe names are separator-free (a name with a separator cannot be a
        // single pipe) and non-empty.
        assert!(
            !from_bind.is_empty() && !from_bind.contains(['\\', '/']),
            "derived pipe name must be a single namespace name: {from_bind:?}"
        );
    }
}

/// Falsifiability of the watchdog itself: the round-trip test's whole value on
/// windows-latest is that a deadlock fails FAST and LOCATED instead of
/// stalling the runner. That guarantee is worthless if `with_watchdog` never
/// fires, so prove it panics on a body that outlives its limit. (Reverting the
/// watchdog to a plain call, or breaking its deadline logic, turns this red.)
#[test]
#[should_panic(expected = "HANG: operator-pipe round-trip deadlocked")]
fn watchdog_fires_on_a_hanging_body() {
    with_watchdog(std::time::Duration::from_millis(150), |_mark| {
        std::thread::sleep(std::time::Duration::from_secs(10));
    });
}

/// Pins the contract of the primitive the CH-77 fix repairs, in isolation:
/// a read against a peer that stays connected but sends NOTHING must return
/// `TimedOut` after ~the deadline — it must NOT fast-fail with some other
/// error (the pre-fix Windows behavior: `ERROR_NO_DATA` fell through the
/// `WouldBlock` arm and returned immediately) and must NOT hang (the deeper
/// possibility the watchdog guards). Asserting both the error kind AND the
/// elapsed time distinguishes "polled to deadline correctly" from "returned
/// instantly with the wrong error," which the round-trip test alone cannot.
///
/// NOTE: on Linux this contract already held before the fix (unix
/// `no_data_yet` is the unchanged `WouldBlock` branch), so this test is green
/// here either way — it is NOT Linux-side proof of the Windows fix. Its value
/// is a permanent contract pin and, on windows-latest, a precise diagnostic:
/// if Windows still fast-fails, the elapsed-time assert names it; if it hangs,
/// the watchdog localizes it. The Windows fix itself is proven only by the
/// windows-latest leg.
#[test]
fn read_against_silent_peer_times_out_not_fast_fail() {
    with_watchdog(std::time::Duration::from_secs(15), |_mark| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("silent.sock");
        let name = path.to_str().unwrap().to_owned();
        let listener = OperatorListener::bind(&name, |p| format!("live owns {p}")).unwrap();

        // Server accepts and then stays silent (holds the connection open
        // without writing) for longer than the client's read deadline, so the
        // client sees a live-but-quiet peer — the exact case that must time
        // out rather than report EOF/BrokenPipe.
        let server = std::thread::spawn(move || {
            let _conn = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(3));
            // _conn drops here; the client has long since returned.
        });

        let stream = OperatorStream::connect(&name).unwrap();
        // Small settle so the server reaches accept() before the client reads.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let deadline = std::time::Duration::from_millis(400);
        let started = std::time::Instant::now();
        let result = stream.read_byte_timeout(deadline);
        let elapsed = started.elapsed();

        // Contract 1: TimedOut, and specifically NOT a fast-fail. The pre-fix
        // Windows path returned ~immediately with BrokenPipe; requiring the
        // elapsed time to be at least the deadline proves it actually polled.
        let err_kind = result.as_ref().err().map(|e| e.kind());
        assert_eq!(
            err_kind,
            Some(std::io::ErrorKind::TimedOut),
            "silent peer must yield TimedOut, got {result:?}"
        );
        assert!(
            elapsed >= deadline,
            "read returned in {elapsed:?} < {deadline:?}: fast-failed instead of polling to the deadline"
        );

        // Do not join the 3s-sleeping server; abandon it (killed at process
        // exit) so this test stays fast.
        drop(server);
    });
}

#[test]
fn live_peer_refuses_second_bind() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("console.sock");
    let name = path.to_str().unwrap().to_owned();

    let _first = OperatorListener::bind(&name, |p| format!("live console owns {p}")).unwrap();
    let err = OperatorListener::bind(&name, |p| format!("live console owns {p}")).unwrap_err();
    assert!(
        err.to_string().contains("live console owns"),
        "second bind over a live endpoint must fail loudly: {err}"
    );
}

#[test]
fn stale_endpoint_is_reclaimed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dead.sock");
    let name = path.to_str().unwrap().to_owned();

    {
        let _l = OperatorListener::bind(&name, |_| "busy".into()).unwrap();
        // Drop without connecting: leaves a corpse socket file behind.
    }
    // Rebind must succeed (try_overwrite) rather than error on the stale file.
    let _again = OperatorListener::bind(&name, |p| format!("live owns {p}")).unwrap();
}

#[test]
fn connect_without_listener_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nothing.sock");
    let err = OperatorStream::connect(path.to_str().unwrap()).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ),
        "connect with no listener must fail: {err}"
    );
}

// CH-77-2 note: the earlier `write_all_timeout` primitive (bounded NOWAIT
// write) and its two tests lived here. Windows CI run 2 showed NOWAIT writes
// via `interprocess` never actually reached a healthy subscriber, so the feed
// switched to plain BLOCKING writes on a per-subscriber delivery thread
// (see gateway-core/src/events.rs). A stalled peer therefore no longer needs
// a bounded transport write — the hub's bounded queue + drop-on-full handles
// it, pinned by `events::tests::broadcast_never_blocks_on_a_stalled_
// subscriber` and `..._healthy_subscriber_receives_queued_lines_in_order`.
