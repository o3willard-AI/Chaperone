//! Chaperone local transport edge.
//!
//! Owns the local channel and message framing (PROTO-SPEC §3,
//! ARCH-SPEC §2.1): Unix domain socket by default (owner-only `0600`), named
//! pipe on Windows, loopback TCP only as an explicit fallback. Frames are
//! `Content-Length`-prefixed JSON blocks (LSP-style).
//!
//! Layer contract (ARCH-SPEC §1.1): depends on nothing internal; performs no
//! trust decisions — an authenticated socket peer is still unauthenticated
//! until the identity layer verifies its signature.
//!
//! Implemented in PLAN Phase 1 ([PLAN](../../docs/PLAN.md) M1).

mod client;
pub mod codec;
mod message;
mod server;

#[cfg(windows)]
mod named_pipe;
#[cfg(unix)]
mod uds;

pub use client::{ClientError, Connection, ConnectionStream};
pub use codec::{FrameError, MAX_FRAME_BYTES, read_frame, write_frame};
pub use message::{MessageError, Request, transport_error_frame};
#[cfg(unix)]
pub use server::default_socket_path;
pub use server::{
    BindError, Handler, ListenSpec, ServerHandle, default_listen_spec, drive_connection, serve,
};
