//! The local channel listener and the unary request/response loop.
//!
//! Binds one of three transports per [`ListenSpec`] (PROTO-SPEC §3.1):
//! a Unix domain socket by default (owner-only `0600`), a named pipe on
//! Windows, or a loopback-only TCP port as an explicit fallback. The TCP
//! variant is type-constrained to `127.0.0.1` / `::1` — there is no way to
//! express binding any other interface, honoring "no network listener by
//! default" at the type level (ARCH-SPEC §4.3).
//!
//! The server makes no trust decisions: every inbound message is handed to
//! the caller-supplied handler verbatim, and responses get their `msg_id`
//! stamped by the transport so handlers cannot misattribute replies.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

use crate::codec::{self, FrameError};
use crate::message::{MessageError, Request, transport_error_frame};

/// How the gateway listens for agents (PROTO-SPEC §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenSpec {
    /// Unix domain socket at `path`. Default on POSIX platforms; created
    /// owner-only (`0600`) inside a `0700` directory. Binding it on Windows
    /// yields [`BindError::UnsupportedOnPlatform`].
    UnixSocket {
        /// Filesystem path of the socket.
        path: std::path::PathBuf,
    },
    /// Windows named pipe with the given name (e.g. `\\.\pipe\chaperone-gw`).
    /// Binding it on POSIX yields [`BindError::UnsupportedOnPlatform`].
    NamedPipe {
        /// Pipe name including the `\\.\pipe\` prefix.
        name: String,
    },
    /// Loopback TCP listener, IPv4 (`127.0.0.1`). Explicit fallback only.
    TcpV4 {
        /// Port to bind on 127.0.0.1.
        port: u16,
    },
    /// Loopback TCP listener, IPv6 (`[::1]`). Explicit fallback only.
    TcpV6 {
        /// Port to bind on ::1.
        port: u16,
    },
}

/// Errors when binding the local channel.
#[derive(Debug)]
#[non_exhaustive]
pub enum BindError {
    /// Underlying OS call failed.
    Io(std::io::Error),
    /// A live gateway already owns this endpoint.
    AlreadyRunning {
        /// Human-legible description of the contested endpoint.
        endpoint: String,
    },
    /// The chosen transport does not exist on this platform (e.g. named pipe
    /// requested on POSIX).
    UnsupportedOnPlatform {
        /// Which transport was requested.
        requested: &'static str,
    },
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::Io(e) => write!(f, "failed to bind local channel: {e}"),
            BindError::AlreadyRunning { endpoint } => {
                write!(f, "a live gateway already owns {endpoint}")
            }
            BindError::UnsupportedOnPlatform { requested } => {
                write!(f, "{requested} transport is not available on this platform")
            }
        }
    }
}

impl std::error::Error for BindError {}

/// An inbound-message handler producing exactly one response value.
///
/// Responses are stamped with the request's `msg_id` by the transport before
/// they are written; see [`Request::reply`].
pub type Handler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Value> + Send>> + Send + Sync>;

/// A running accept loop. Drop to detach, or call [`ServerHandle::shutdown`]
/// to abort it.
pub struct ServerHandle {
    task: JoinHandle<()>,
    socket_path: Option<std::path::PathBuf>,
    tcp_addr: Option<std::net::SocketAddr>,
}

impl ServerHandle {
    /// Aborts the accept loop and removes the socket file, if any.
    pub fn shutdown(self) {
        self.task.abort();
        if let Some(path) = self.socket_path {
            // Best effort: a lingering file is handled as stale on next bind.
            let _ = std::fs::remove_file(&path);
        }
    }

    /// Waits for the accept loop to finish.
    pub async fn joined(self) {
        let _ = self.task.await;
    }

    /// The concrete loopback address when listening on TCP with an
    /// OS-assigned (`0`) port; `None` on socket/pipe transports.
    #[must_use]
    pub fn tcp_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.tcp_addr
    }
}

/// Binds the chosen transport and spawns the accept loop.
///
/// Each accepted connection runs its own unary loop ([`drive_connection`]);
/// a protocol-violating peer is answered with a transport error frame
/// (DESIGN-DECISIONS D12) and disconnected without affecting other peers.
pub fn serve(spec: &ListenSpec, handler: Handler) -> Result<ServerHandle, BindError> {
    match spec {
        #[cfg(unix)]
        ListenSpec::UnixSocket { path } => {
            let listener = crate::uds::bind(path)?;
            Ok(ServerHandle {
                task: tokio::spawn(accept_unix(listener, handler)),
                socket_path: Some(path.clone()),
                tcp_addr: None,
            })
        }
        #[cfg(not(unix))]
        ListenSpec::UnixSocket { .. } => Err(BindError::UnsupportedOnPlatform {
            requested: "unix socket",
        }),
        #[cfg(windows)]
        ListenSpec::NamedPipe { name } => {
            let creator = crate::named_pipe::PipeListener::bind(name)?;
            Ok(ServerHandle {
                task: tokio::spawn(accept_windows_pipe(creator, handler)),
                socket_path: None,
                tcp_addr: None,
            })
        }
        #[cfg(not(windows))]
        ListenSpec::NamedPipe { .. } => Err(BindError::UnsupportedOnPlatform {
            requested: "named pipe",
        }),
        ListenSpec::TcpV4 { port } => {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], *port));
            let bound = addr;
            let listener = std::net::TcpListener::bind(addr).map_err(BindError::Io)?;
            listener.set_nonblocking(true).map_err(BindError::Io)?;
            let actual = listener.local_addr().map_err(BindError::Io)?;
            let listener = tokio::net::TcpListener::from_std(listener).map_err(BindError::Io)?;
            Ok(ServerHandle {
                task: tokio::spawn(accept_tcp(listener, handler)),
                socket_path: None,
                tcp_addr: Some(if bound.port() == 0 { actual } else { bound }),
            })
        }
        ListenSpec::TcpV6 { port } => {
            let addr = std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], *port));
            let bound = addr;
            let listener = std::net::TcpListener::bind(addr).map_err(BindError::Io)?;
            listener.set_nonblocking(true).map_err(BindError::Io)?;
            let actual = listener.local_addr().map_err(BindError::Io)?;
            let listener = tokio::net::TcpListener::from_std(listener).map_err(BindError::Io)?;
            Ok(ServerHandle {
                task: tokio::spawn(accept_tcp(listener, handler)),
                socket_path: None,
                tcp_addr: Some(if bound.port() == 0 { actual } else { bound }),
            })
        }
    }
}

/// The default listen spec for this platform (PROTO-SPEC §3.1).
#[must_use]
pub fn default_listen_spec() -> ListenSpec {
    #[cfg(windows)]
    return ListenSpec::NamedPipe {
        name: crate::named_pipe::DEFAULT_PIPE_NAME.to_owned(),
    };
    #[cfg(unix)]
    return ListenSpec::UnixSocket {
        path: default_socket_path(),
    };
}

/// Default UDS path: `$XDG_RUNTIME_DIR/chaperone/gw.sock`.
///
/// Where `XDG_RUNTIME_DIR` is unset (macOS commonly), falls back to a
/// user-named directory under the system temp dir. The directory is created
/// with `0700`, so the fallback keeps the socket reachable only by its owner.
#[cfg(unix)]
#[must_use]
pub fn default_socket_path() -> std::path::PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime_dir.is_empty()
    {
        return std::path::Path::new(&runtime_dir)
            .join("chaperone")
            .join("gw.sock");
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "default".to_owned());
    std::env::temp_dir()
        .join(format!("chaperone-{user}"))
        .join("gw.sock")
}

#[cfg(unix)]
async fn accept_unix(listener: tokio::net::UnixListener, handler: Handler) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(drive_connection(stream, Arc::clone(&handler)));
            }
            Err(e) => {
                // Transient accept errors (e.g. EINTR) should not kill the
                // listener; log-and-continue is the standard posture here.
                eprintln!("chaperone-transport: accept failed: {e}");
            }
        }
    }
}

#[cfg(windows)]
async fn accept_windows_pipe(mut listener: crate::named_pipe::PipeListener, handler: Handler) {
    while let Some(stream) = listener.next_client().await {
        tokio::spawn(drive_connection(stream, Arc::clone(&handler)));
    }
}

async fn accept_tcp(listener: tokio::net::TcpListener, handler: Handler) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(drive_connection(stream, Arc::clone(&handler)));
            }
            Err(e) => {
                eprintln!("chaperone-transport: accept failed: {e}");
            }
        }
    }
}

/// One connection's unary request/response loop (PROTO-SPEC §3.3).
///
/// Terminal outcomes per iteration:
/// - valid message → handler → response frame (loop continues)
/// - clean close → done
/// - anything malformed → one transport error frame, then disconnect
pub async fn drive_connection<S>(mut stream: S, handler: Handler)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let text = match codec::read_frame(&mut stream).await {
            Ok(text) => text,
            Err(FrameError::Closed) => return,
            Err(e) => {
                answer_protocol_violation(&mut stream, &e.to_string()).await;
                return;
            }
        };

        match Request::parse(&text) {
            Ok(request) => {
                let response = (handler)(request).await;
                let payload = match serde_json::to_vec(&response) {
                    Ok(bytes) => bytes,
                    // A Value round-trips losslessly; reaching this arm means
                    // a non-string object key snuck in. Fail closed loudly.
                    Err(_) => {
                        answer_protocol_violation(&mut stream, "response serialization failed")
                            .await;
                        return;
                    }
                };
                if codec::write_frame(&mut stream, &payload).await.is_err() {
                    return;
                }
            }
            Err(MessageError::NotAnObject | MessageError::InvalidJson(_)) => {
                answer_protocol_violation(&mut stream, "frame payload is not a JSON object").await;
                return;
            }
        }
    }
}

/// Answers a framing/parsing violation once, then the caller disconnects.
async fn answer_protocol_violation<S: AsyncWrite + Unpin>(stream: &mut S, reason: &str) {
    let frame = serde_json::to_vec(&transport_error_frame(reason)).unwrap_or_default();
    if !frame.is_empty() {
        let _ = codec::write_frame(stream, &frame).await;
    }
}
