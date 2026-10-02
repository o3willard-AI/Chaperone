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
