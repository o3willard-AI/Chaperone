//! Phase 1 acceptance tests (docs/PLAN.md M1).
//!
//! Proven here, per the plan:
//! - a test client round-trips a framed message over UDS (and named pipe /
//!   loopback TCP on their respective platforms);
//! - the socket is owner-only: mode `0600` inside a `0700` directory. The OS
//!   denies non-owner connects from exactly these bits — CI runs as a single
//!   user, so we assert the bits rather than fork identities;
//! - an oversized frame is rejected cleanly and the server survives;
//! - malformed payloads get one transport error frame, then disconnection.

// Tests are allowed to panic: a failing assert IS the test result.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

#[cfg(unix)]
use chaperone_transport::BindError;
use chaperone_transport::{Connection, Handler, ListenSpec, serve};
use serde_json::json;

fn echo_handler() -> Handler {
    Arc::new(|request| {
        Box::pin(async move {
            let mut value = request.into_value();
            value["echoed_by"] = json!("transport-test");
            value
        })
    })
}

#[cfg(unix)]
fn temp_socket_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("gw.sock")
}

#[cfg(unix)]
#[tokio::test]
async fn round_trips_framed_message_over_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let spec = ListenSpec::UnixSocket {
        path: temp_socket_path(dir.path()),
    };
    let server = serve(&spec, echo_handler()).unwrap();

    let mut conn = Connection::connect(&spec).await.unwrap();
    let response = conn
        .request(&json!({"msg_id": "m-1", "type": "intent", "ping": true}))
        .await
        .unwrap();

    assert_eq!(
        response["msg_id"], "m-1",
        "responses echo msg_id (PROTO-SPEC 3.3)"
    );
    assert_eq!(response["echoed_by"], "transport-test");

    server.shutdown();
}

#[cfg(unix)]
#[tokio::test]
async fn socket_and_directory_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = temp_socket_path(dir.path());
    let server = serve(
        &ListenSpec::UnixSocket { path: path.clone() },
        echo_handler(),
    )
    .unwrap();

    let sock_mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(
        sock_mode & 0o777,
        0o600,
        "socket must be owner-only rw (THREAT-MODEL T2)"
    );

    let parent = path.parent().unwrap();
    let dir_mode = std::fs::metadata(parent).unwrap().permissions().mode();
    assert_eq!(dir_mode & 0o777, 0o700, "parent dir must be owner-only");

    // With these bits, the kernel refuses connect() for any other uid; no
    // per-connection check is needed or possible at this layer.
    server.shutdown();
}

#[cfg(unix)]
#[tokio::test]
async fn second_bind_on_live_endpoint_reports_already_running() {
    let dir = tempfile::tempdir().unwrap();
    let spec = ListenSpec::UnixSocket {
        path: temp_socket_path(dir.path()),
    };
    let _server = serve(&spec, echo_handler()).unwrap();

    match serve(&spec, echo_handler()) {
        Err(e @ BindError::AlreadyRunning { .. }) => {
            assert!(e.to_string().contains("already owns"));
        }
        Err(e) => panic!("expected AlreadyRunning, got {e:?}"),
        Ok(_) => panic!("expected AlreadyRunning, but a second bind succeeded"),
    }
    _server.shutdown();
}

#[cfg(unix)]
#[tokio::test]
async fn stale_socket_file_is_rebound() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_socket_path(dir.path());

    // A plain file where a socket should be: unreachable, i.e. stale.
    std::fs::write(&path, b"crashed daemon leftovers").unwrap();

    let server = serve(&ListenSpec::UnixSocket { path }, echo_handler()).unwrap();
    let mut conn = Connection::connect(&ListenSpec::UnixSocket {
        path: temp_socket_path(dir.path()),
    })
    .await
    .unwrap();
    conn.request(&json!({"msg_id":"m"})).await.unwrap();
    server.shutdown();
}

#[tokio::test]
async fn oversized_frame_rejected_cleanly_and_server_survives() {
    // Loopback TCP keeps this platform-neutral; the codec guard is identical.
    let spec = ListenSpec::TcpV4 { port: 0 };
    let server = serve(&spec, echo_handler()).unwrap();
    let addr = server.tcp_local_addr().unwrap();
    let live_spec = ListenSpec::TcpV4 { port: addr.port() };

    // Raw socket: declare far more than MAX_FRAME_BYTES, send nothing else.
    let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
    let header = format!(
        "Content-Length: {}\r\n\r\n",
        chaperone_transport::MAX_FRAME_BYTES + 1
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    raw.write_all(header.as_bytes()).await.unwrap();

    // The transport answers with an error frame, then closes.
    let mut buf = Vec::new();
    raw.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.contains("\"scope\":\"transport\""), "got: {text}");
    assert!(text.contains("exceeds"), "got: {text}");

    // Server must still be healthy for well-behaved peers.
    let mut conn = Connection::connect(&live_spec).await.unwrap();
    let response = conn.request(&json!({"msg_id":"after"})).await.unwrap();
    assert_eq!(response["msg_id"], "after");
    server.shutdown();
}

#[tokio::test]
async fn malformed_json_gets_error_frame_then_disconnect() {
    let spec = ListenSpec::TcpV4 { port: 0 };
    let server = serve(&spec, echo_handler()).unwrap();
    let addr = server.tcp_local_addr().unwrap();

    let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = br#"[1,2,3]"#; // valid JSON, not an object
    raw.write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    raw.write_all(body.as_slice()).await.unwrap();

    // Read until the server closes: error frames may arrive split across
    // TCP segments.
    let mut buf = Vec::new();
    raw.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    assert!(text.contains("not a JSON object"), "got: {text}");
    assert!(text.contains("\"scope\":\"transport\""), "got: {text}");

    server.shutdown();
}

#[tokio::test]
async fn concurrent_clients_are_isolated() {
    let spec = ListenSpec::TcpV4 { port: 0 };
    let server = serve(&spec, echo_handler()).unwrap();
    let addr = server.tcp_local_addr().unwrap();
    let live_spec = ListenSpec::TcpV4 { port: addr.port() };

    let mut c1 = Connection::connect(&live_spec).await.unwrap();
    let mut c2 = Connection::connect(&live_spec).await.unwrap();

    let msg_a = json!({"msg_id":"a"});
    let msg_b = json!({"msg_id":"b"});
    let (r1, r2) = tokio::join!(c1.request(&msg_a), c2.request(&msg_b));
    assert_eq!(r1.unwrap()["msg_id"], "a");
    assert_eq!(r2.unwrap()["msg_id"], "b");
    server.shutdown();
}

#[cfg(windows)]
#[tokio::test]
async fn round_trips_over_named_pipe() {
    let spec = ListenSpec::NamedPipe {
        name: format!(r"\\.\pipe\chaperone-test-{}", std::process::id()),
    };
    let server = serve(&spec, echo_handler()).unwrap();
    let mut conn = Connection::connect(&spec).await.unwrap();
    let response = conn
        .request(&json!({"msg_id":"w1","ping":true}))
        .await
        .unwrap();
    assert_eq!(response["msg_id"], "w1");
    server.shutdown();
}
