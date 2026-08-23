//! Client side of the local channel.
//!
//! Used by tests, the operator CLI, and the protocol conformance suite to
//! exercise the gateway exactly the way a well-behaved agent would
//! ([Agent Skill](../../docs/skill/SKILL.md)): connect, send framed JSON,
//! read framed JSON back.

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::codec::{self, FrameError};
use crate::message::MessageError;
use crate::server::ListenSpec;

/// Object-safe stream bound so `Connection` can hide the platform type.
pub trait ConnectionStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ConnectionStream for T {}

/// A client connection to the gateway.
pub struct Connection {
    stream: Box<dyn ConnectionStream>,
}

/// Failures establishing or using a client connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// Endpoint could not be reached at all.
    Connect(std::io::Error),
    /// The chosen transport does not exist on this platform.
    UnsupportedOnPlatform {
        /// Which transport was requested.
        requested: &'static str,
    },
    /// Framing failed mid-exchange.
    Frame(FrameError),
    /// The peer's response was not a valid message.
    Message(MessageError),
    /// The outgoing message could not be serialized.
    Serialization(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connect(e) => write!(f, "connect failed: {e}"),
            ClientError::UnsupportedOnPlatform { requested } => {
                write!(f, "{requested} transport is not available on this platform")
            }
            ClientError::Frame(e) => write!(f, "framing error: {e}"),
            ClientError::Message(e) => write!(f, "invalid response message: {e}"),
            ClientError::Serialization(e) => write!(f, "failed to serialize request: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl Connection {
    /// Connects per the given listen spec.
    pub async fn connect(spec: &ListenSpec) -> Result<Connection, ClientError> {
        let boxed: Box<dyn ConnectionStream> = match spec {
            #[cfg(unix)]
            ListenSpec::UnixSocket { path } => Box::new(
                crate::uds::connect(path)
                    .await
                    .map_err(ClientError::Connect)?,
            ),
            #[cfg(not(unix))]
            ListenSpec::UnixSocket { .. } => {
                return Err(ClientError::UnsupportedOnPlatform {
                    requested: "unix socket",
                });
            }
            #[cfg(windows)]
            ListenSpec::NamedPipe { name } => Box::new(
                crate::named_pipe::connect(name)
                    .await
                    .map_err(ClientError::Connect)?,
            ),
            #[cfg(not(windows))]
            ListenSpec::NamedPipe { .. } => {
                return Err(ClientError::UnsupportedOnPlatform {
                    requested: "named pipe",
                });
            }
            ListenSpec::TcpV4 { port } => {
                let addr = std::net::SocketAddr::from(([127, 0, 0, 1], *port));
                Box::new(
                    tokio::net::TcpStream::connect(addr)
                        .await
                        .map_err(ClientError::Connect)?,
                )
            }
            ListenSpec::TcpV6 { port } => {
                let addr = std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], *port));
                Box::new(
                    tokio::net::TcpStream::connect(addr)
                        .await
                        .map_err(ClientError::Connect)?,
                )
            }
        };
        Ok(Connection { stream: boxed })
    }

    /// Sends one message and awaits its response (unary lifecycle).
    ///
    /// Returns the raw JSON object; interpretation lives above the transport.
    pub async fn request(&mut self, message: &Value) -> Result<Value, ClientError> {
        let payload =
            serde_json::to_vec(message).map_err(|e| ClientError::Serialization(e.to_string()))?;
        codec::write_frame(&mut self.stream, &payload)
            .await
            .map_err(FrameError::Io)
            .map_err(ClientError::Frame)?;
        let text = codec::read_frame(&mut self.stream)
            .await
            .map_err(ClientError::Frame)?;
        let response = crate::message::Request::parse(&text).map_err(ClientError::Message)?;
        Ok(response.into_value())
    }
}
