//! Unix domain socket listener (PROTO-SPEC §3.1).
//!
//! The filesystem socket makes OS permissions the first access-control
//! layer: the socket file is created `0600` inside a `0700` directory, so
//! only the gateway's own user can even attempt a connection. Those mode bits
//! are what the kernel enforces against other users — there is no code path
//! that needs to re-check them per connection.

use std::fs::Permissions;
use std::io;
use std::os::unix::fs::PermissionsExt;

use super::BindError;

/// Creates the socket's parent directory (`0700`) if needed.
fn prepare_parent_dir(path: &std::path::Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::other("socket path has no parent directory"));
    };
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, Permissions::from_mode(0o700))?;
    Ok(())
}

/// Binds a UDS listener with owner-only permissions.
///
/// If the path already exists: a live peer is reported as
/// [`BindError::AlreadyRunning`]; a stale socket left by a crashed daemon is
/// removed and rebound. The check-then-remove window is local-process race
/// only — both contenders are the same user by construction of the parent
/// directory's `0700` bits.
pub fn bind(path: &std::path::Path) -> Result<tokio::net::UnixListener, BindError> {
    prepare_parent_dir(path).map_err(BindError::Io)?;

    if path.exists() {
        // Probe: if something answers, it is a live gateway, not stale data.
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(BindError::AlreadyRunning {
                    endpoint: path.display().to_string(),
                });
            }
            Err(_) => {
                std::fs::remove_file(path).map_err(BindError::Io)?;
            }
        }
    }

    let listener = tokio::net::UnixListener::bind(path).map_err(BindError::Io)?;
    std::fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(BindError::Io)?;
    Ok(listener)
}

/// Connects to a UDS gateway as a client.
pub async fn connect(path: &std::path::Path) -> Result<tokio::net::UnixStream, std::io::Error> {
    tokio::net::UnixStream::connect(path).await
}
