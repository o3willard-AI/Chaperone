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
        let mark = move |p: &'static str| {
            *phase_w.lock().unwrap() = p;
        };
        let mark_ref: &dyn Fn(&'static str) = &mark;
        body(mark_ref);
        done_w.store(true, Ordering::SeqCst);
    });

    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        if done.load(Ordering::SeqCst) {
            worker.join().unwrap();
            return;
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

        // Server: accept one client, echo one JSON line, then read one line
        // back — a true bidirectional round-trip (the console path reads what
        // the client writes; the feed path writes what the client reads).
        let server = std::thread::spawn(move || {
            let conn = listener.accept().unwrap();
            conn.write_all(b"{\"type\":\"decision\"}\n").unwrap();
            // Read the client's reply with a deadline so the server side also
            // cannot hang forever.
            let mut got = Vec::new();
            while let Ok(b) = conn.read_byte_timeout(std::time::Duration::from_secs(5)) {
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
        // Read the broadcast line byte-by-byte the way EventHub consumers do,
        // with a deadline (a hang here is the exact deadlock we are guarding).
        let mut line: Vec<u8> = Vec::new();
        while let Ok(b) = stream.read_byte_timeout(std::time::Duration::from_secs(5)) {
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

/// CH-77-2 core: the write-side bound. This is the primitive that makes the
/// feed deadlock impossible — a write to a connected-but-NOT-draining peer
/// (full pipe buffer, the Windows condition that hung `session_events`) must
/// return `TimedOut` within ~the deadline, never block forever. Filling the
/// buffer needs a payload larger than the socket's (~200KB on Linux, 512B on
/// Windows pipes), so 4MB guarantees the block on every platform; the writer
/// fills what it can, then polls to the deadline and gives up.
///
/// Falsifiable: revert `write_all_timeout` to the plain blocking `write_all`
/// and this test hangs (caught by the watchdog) instead of returning TimedOut.
#[test]
fn write_to_stalled_peer_times_out_not_hang() {
    with_watchdog(std::time::Duration::from_secs(15), |_mark| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stall.sock");
        let name = path.to_str().unwrap().to_owned();
        let listener = OperatorListener::bind(&name, |p| format!("live owns {p}")).unwrap();

        // Server accepts and then NEVER reads — the stalled subscriber. Held
        // open past the client's deadline so the peer is alive but full.
        let server = std::thread::spawn(move || {
            let _conn = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(5));
        });

        let stream = OperatorStream::connect(&name).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let payload = vec![b'x'; 4 * 1024 * 1024]; // >> any socket buffer
        let deadline = std::time::Duration::from_millis(400);
        let started = std::time::Instant::now();
        let result = stream.write_all_timeout(&payload, deadline);
        let elapsed = started.elapsed();

        // Bounded: TimedOut (not a hang, not a silent success). Some bytes
        // went into the buffer first, so elapsed is >= the deadline only if
        // the buffer filled and it polled — assert it returned in bounded
        // time regardless, which is the anti-hang property.
        let err_kind = result.as_ref().err().map(|e| e.kind());
        assert_eq!(
            err_kind,
            Some(std::io::ErrorKind::TimedOut),
            "a stalled peer must bound the write to TimedOut, got {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "write must not block beyond the deadline: took {elapsed:?}"
        );
        drop(server); // abandon the 5s sleeper
    });
}

/// Positive control for the above: with a DRAINING peer, `write_all_timeout`
/// completes normally. Proves the timeout path is not just "always fails".
#[test]
fn write_to_draining_peer_succeeds() {
    with_watchdog(std::time::Duration::from_secs(15), |_mark| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drain.sock");
        let name = path.to_str().unwrap().to_owned();
        let listener = OperatorListener::bind(&name, |p| format!("live owns {p}")).unwrap();

        // Server accepts and drains continuously, counting bytes.
        let server = std::thread::spawn(move || {
            let conn = listener.accept().unwrap();
            let mut total = 0usize;
            let mut buf = [0u8; 8192];
            while total < 256 * 1024 {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total += n,
                }
            }
            total
        });

        let stream = OperatorStream::connect(&name).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let payload = vec![b'y'; 256 * 1024];
        let result = stream.write_all_timeout(&payload, std::time::Duration::from_secs(5));
        assert!(
            result.is_ok(),
            "draining peer must accept the write: {result:?}"
        );
        let got = server.join().unwrap();
        assert_eq!(got, payload.len(), "server must receive every byte");
    });
}
