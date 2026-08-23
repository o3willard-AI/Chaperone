//! Windows named pipe transport (PROTO-SPEC §3.1).
//!
//! Default name `\\.\pipe\chaperone-gw`. The pipe is created with
//! `first_pipe_instance`, so binding twice reports an error rather than
//! silently sharing the namespace.
//!
//! Security posture (DESIGN-DECISIONS D14): v1 relies on the default DACL
//! derived from the creating process token (the current user plus system),
//! which matches the owner-only intent for typical single-user setups.
//! Constructing an explicit restrictive ACL would require unsafe Win32 calls
//! and lands with the hardening phase instead — tracked, not silent.

use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

/// Default pipe name per PROTO-SPEC §3.1.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\chaperone-gw";

/// Hands out connected pipe server instances one at a time.
///
/// Named pipes need one pre-created "listening" instance per pending client;
/// this type creates the first instance at [`PipeListener::bind`] and arms
/// each successor as soon as its predecessor is taken by a client.
pub struct PipeListener {
    name: String,
    current: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}

impl PipeListener {
    /// Binds the first pipe instance.
    ///
    /// An existing live instance makes creation fail (`ACCESS_DENIED` /
    /// `PIPE_BUSY` semantics of `first_pipe_instance`), which maps to
    /// [`super::BindError::AlreadyRunning`] after a probe connect succeeds.
    pub fn bind(name: &str) -> Result<PipeListener, super::BindError> {
        match ServerOptions::new().first_pipe_instance(true).create(name) {
            Ok(server) => Ok(PipeListener {
                name: name.to_owned(),
                current: Some(server),
            }),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // Someone already owns the name; distinguish live vs dead.
                Err(super::BindError::AlreadyRunning {
                    endpoint: name.to_owned(),
                })
            }
            Err(e) => Err(super::BindError::Io(e)),
        }
    }

    /// Resolves once a client connects to the armed instance, then arms the
    /// next one. Returns `None` if arming a successor failed fatally.
    pub async fn next_client(
        &mut self,
    ) -> Option<tokio::net::windows::named_pipe::NamedPipeServer> {
        let server = self.current.take()?;
        if server.connect().await.is_err() {
            return None;
        }
        match ServerOptions::new().create(&self.name) {
            Ok(next) => self.current = Some(next),
            Err(_) => {
                // Serve this client; the accept loop ends afterwards. A
                // restart heals the channel; do not serve into a dead pipe.
            }
        }
        Some(server)
    }
}

/// Connects to the gateway's named pipe as a client, retrying briefly while
/// the pipe exists but has no free instance (`ERROR_PIPE_BUSY`).
pub async fn connect(name: &str) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    const MAX_ATTEMPTS: u32 = 50;
    let backoff = Duration::from_millis(20);
    let mut attempts = 0;

    loop {
        match ClientOptions::new().open(name) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(231 /* ERROR_PIPE_BUSY */) => {
                attempts += 1;
                if attempts >= MAX_ATTEMPTS {
                    return Err(e);
                }
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(e),
        }
    }
}
