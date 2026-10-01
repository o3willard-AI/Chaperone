//! Integration tests for the operator-channel facade. Run natively on Linux/
//! macOS (unix path); the Windows path is compile-verified locally and
//! execution-verified by windows-latest CI.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chaperone_transport::operator_pipe::{OperatorListener, OperatorStream};

#[test]
fn bind_connect_roundtrip() {
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

    let stream = OperatorStream::connect(&name).unwrap();
    let server = std::thread::spawn(move || {
        let conn = listener.accept().unwrap();
        conn.write_all(b"{\"type\":\"decision\"}\n").unwrap();
    });

    // Read the broadcast line byte-by-byte the way EventHub consumers do.
    let mut line: Vec<u8> = Vec::new();
    loop {
        let b = stream.read_byte().unwrap();
        if b == b'\n' {
            break;
        }
        line.push(b);
    }
    server.join().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&String::from_utf8(line).unwrap()).unwrap()["type"],
        "decision"
    );
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
