//! Cross-platform operator-channel pipes (P1-1 item 3).
//!
//! One facade for the two *operator-facing* local channels — the read-only
//! events feed (D35) and the 1:1 confirmation console (D8/D32) — so the
//! gateway uses a single code path on every platform. Unix-domain sockets
//! under the hood on Unix; named pipes on Windows. This is distinct from
//! [`crate::named_pipe`], which carries the *agent* request channel
//! (PROTO-SPEC §3) and follows D13's default-DACL posture.
//!
//! Security (D44): both operator channels are owner-only on every platform —
//! the named-pipe analogue of the Unix `0600` the UDS path sets:
//! - Unix: the socket file is `chmod 0600` after bind.
//! - Windows: the pipe is created with a protected security descriptor
//!   (`D:P(...)` — no inherited ACEs) granting full control to
//!   Creator-Owner, SYSTEM, and the local Administrators group only.
//!   Constructed through `interprocess`' safe `SecurityDescriptor` wrapper, so
//!   the workspace-wide `unsafe_code = "forbid"` is preserved.
//!
//! Naming: `printname` is the operator-supplied endpoint string. On Unix it is
//! a filesystem path (absolute, e.g. a tempdir socket); on Windows a pipe name
//! in the `\\.\pipe\` namespace. The Windows mapping ([`windows_pipe_name`])
//! preserves bare names exactly, and makes filesystem paths unique per PATH
//! (basename + hash of the full path) so same-basename endpoints in different
//! directories never collide in the single machine-wide pipe namespace.

use std::io::{self, Read, Write};

#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ConnectOptions, ListenerOptions, prelude::*};

/// A bound operator-channel listener: hands out connected streams.
#[derive(Debug)]
pub struct OperatorListener {
    inner: LocalSocketListener,
}

/// One connected operator-channel stream: bidirectional, byte-oriented.
///
/// Read/Write are available on both `OperatorStream` and `&OperatorStream`
/// (the shared-borrow form the fan-out hub and the console need), mirroring
/// `std::os::unix::net::UnixStream`.
#[derive(Debug)]
pub struct OperatorStream {
    inner: LocalSocketStream,
}

/// Maps an operator-supplied endpoint string to a Windows pipe name.
///
/// Pure and platform-independent ON PURPOSE: only the Windows bind/connect
/// path calls it, but compiling it everywhere lets the mapping be
/// unit-tested natively on Linux/macOS CI instead of only on windows-latest.
///
/// Rules:
/// 1. An explicit `\\.\pipe\<name>` resolves to `<name>` verbatim.
/// 2. A bare name (no path separators) maps to itself — operators wanting a
///    specific namespace name pass exactly that name.
/// 3. A filesystem-style path maps to `<sanitized-basename>-<hash16>`, where
///    the hash covers the FULL path string: pipe names live in one
///    machine-wide namespace and cannot contain separators, so uniqueness
///    must come from the path, not the basename. Two `...\events.sock` in
///    different tempdirs get different pipe names (the collision that broke
///    the first Windows CI run of the un-gated feed tests).
///
/// The basename keeps names human-legible in `\\.\pipe\` listings; 16 hex
/// chars of SHA-256 make accidental cross-path collisions negligible.
#[must_use]
pub fn windows_pipe_name(printname: &str) -> String {
    use sha2::{Digest, Sha256};

    const PIPE_PREFIX: &str = r"\\.\pipe\";
    if let Some(rest) = printname.strip_prefix(PIPE_PREFIX)
        && !rest.is_empty()
        && !rest.contains(['\\', '/'])
    {
        return rest.to_owned();
    }
    if !printname.contains(['\\', '/']) {
        return printname.to_owned();
    }
    // Split on BOTH separators manually (not std::path::Path, whose notion
    // of a separator is host-dependent): this function must behave
    // identically on every platform so the mapping is testable on Linux CI.
    let stem = printname
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(printname)
        .to_owned();
    // Sanitize to pipe-legal chars; keep it legible, bounded.
    let sanitized: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    let digest = Sha256::digest(printname.as_bytes());
    let hash16: String = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..16]
        .to_owned();
    format!("{sanitized}-{hash16}")
}

/// Resolves an operator-supplied endpoint string to a platform local-socket
/// name.
///
/// # Errors
/// The name is not representable on this platform.
pub fn endpoint_name(printname: &str) -> io::Result<interprocess::local_socket::Name<'static>> {
    #[cfg(windows)]
    {
        windows_pipe_name(printname)
            .to_ns_name::<GenericNamespaced>()
            .map(|n| n.into_owned())
    }
    #[cfg(not(windows))]
    {
        // Unix: the operator passes a filesystem path; require it to be
        // absolute so the UDS lands where the caller intends.
        printname
            .to_fs_name::<GenericFilePath>()
            .map(|n| n.into_owned())
    }
}

impl OperatorListener {
    /// Binds the operator channel at `printname`, owner-only.
    ///
    /// If a *live* peer already owns the endpoint, returns
    /// [`io::ErrorKind::AddrInUse`]-flavoured error text via the caller's
    /// message; a stale (dead) endpoint is reclaimed.
    ///
    /// # Errors
    /// The name is unusable, or a live listener already owns it.
    pub fn bind(printname: &str, busy_msg: impl FnOnce(&str) -> String) -> io::Result<Self> {
        let name = endpoint_name(printname)?;
        // Probe for a live peer first: a successful connect means another
        // process owns the endpoint and we must not stomp it.
        if ConnectOptions::new()
            .name(name.clone())
            .connect_sync()
            .is_ok()
        {
            return Err(io::Error::other(busy_msg(printname)));
        }
        let opts = ListenerOptions::new();
        // Windows: attach the owner-only security descriptor (D44). The
        // shadow-let keeps the unix path free of a needless `mut`.
        #[cfg(windows)]
        let opts = {
            use interprocess::os::windows::{
                local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
            };
            // Owner-only DACL: protected (no inheritance), full control for
            // Creator-Owner / SYSTEM / Administrators only.
            let sddl = widestring::u16cstr!("D:P(A;;GA;;;CO)(A;;GA;;;SY)(A;;GA;;;BA)");
            let sd = SecurityDescriptor::deserialize(sddl)?;
            opts.security_descriptor(sd)
        };
        // Reclaim a corpse endpoint (dead listener left a stale socket) —
        // mirrors the Unix path's remove-stale-then-bind.
        let inner = opts.name(name).try_overwrite(true).create_sync()?;
        #[cfg(not(windows))]
        {
            // Unix: interprocess does not set the mode; enforce 0600 so the
            // feed/console are owner-only exactly as the UDS path has always
            // been. Best-effort: a chmod failure must not silently widen
            // access, so propagate it.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(printname, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { inner })
    }

    /// Accepts the next connected operator stream (blocking).
    ///
    /// # Errors
    /// The accept failed.
    pub fn accept(&self) -> io::Result<OperatorStream> {
        self.inner.accept().map(|inner| OperatorStream { inner })
    }
}

impl OperatorStream {
    /// Connects to an operator channel at `printname`.
    ///
    /// Retries briefly while a Windows named pipe exists but has no armed
    /// instance (`ERROR_PIPE_BUSY`) — the same posture as the agent channel's
    /// [`crate::named_pipe`]. On Unix this is a plain connect.
    ///
    /// # Errors
    /// No live listener owns the endpoint, or the name is unusable.
    pub fn connect(printname: &str) -> io::Result<Self> {
        let name = endpoint_name(printname)?;
        Self::connect_name(name)
    }

    /// Windows: a named pipe exists but its single armed instance may be mid-
    /// handshake (`ERROR_PIPE_BUSY`); retry briefly, the same posture as the
    /// agent channel's [`crate::named_pipe`].
    #[cfg(windows)]
    fn connect_name(name: interprocess::local_socket::Name<'static>) -> io::Result<Self> {
        const MAX_ATTEMPTS: u32 = 50;
        let backoff = std::time::Duration::from_millis(20);
        let mut attempts = 0;
        loop {
            match ConnectOptions::new().name(name.clone()).connect_sync() {
                Ok(inner) => return Ok(Self { inner }),
                Err(e) if e.raw_os_error() == Some(231 /* ERROR_PIPE_BUSY */) => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(e);
                    }
                    std::thread::sleep(backoff);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Unix: plain connect; no busy-instance concept on UDS.
    #[cfg(not(windows))]
    fn connect_name(name: interprocess::local_socket::Name<'static>) -> io::Result<Self> {
        ConnectOptions::new()
            .name(name)
            .connect_sync()
            .map(|inner| Self { inner })
    }

    /// Writes all bytes (shared-borrow: usable from `&OperatorStream`, as the
    /// fan-out hub requires).
    ///
    /// # Errors
    /// The peer closed or the write failed.
    pub fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        let mut w = &self.inner;
        w.write_all(bytes)?;
        w.flush()
    }

    /// Reads exactly one byte (shared-borrow), the console's answer protocol.
    ///
    /// # Errors
    /// EOF (`UnexpectedEof`) or a read failure.
    pub fn read_byte(&self) -> io::Result<u8> {
        let mut r = &self.inner;
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        Ok(b[0])
    }

    /// Reads up to `buf.len()` bytes (shared-borrow); `Ok(0)` at EOF.
    ///
    /// # Errors
    /// The read failed (in nonblocking mode, `WouldBlock` when no data is
    /// ready).
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.inner).read(buf)
    }

    /// Enables or disables nonblocking mode (shared-borrow, mirroring
    /// `UnixStream::set_nonblocking`).
    ///
    /// # Errors
    /// The platform refused the mode change.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Reads one byte with a deadline (cross-platform replacement for
    /// `UnixStream::set_read_timeout`, which the Windows pipe path lacks).
    /// Polls in nonblocking mode; restores blocking mode before returning.
    ///
    /// # Errors
    /// `TimedOut` if no byte arrives before `timeout`; `UnexpectedEof` at
    /// peer close; any other read failure passes through.
    pub fn read_byte_timeout(&self, timeout: std::time::Duration) -> io::Result<u8> {
        self.set_nonblocking(true)?;
        let deadline = std::time::Instant::now() + timeout;
        let mut b = [0u8; 1];
        let result = loop {
            match (&self.inner).read(&mut b) {
                Ok(0) => break Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(_) => break Ok(b[0]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        break Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => break Err(e),
            }
        };
        // Best-effort restore; a failed restore only matters to later reads
        // on this stream, which would surface the error there.
        let _ = self.set_nonblocking(false);
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::windows_pipe_name;

    /// Rule 2: a bare name maps to itself — the operator-facing namespace
    /// property from the original design.
    #[test]
    fn bare_name_maps_to_itself() {
        assert_eq!(windows_pipe_name("chaperone-events"), "chaperone-events");
        assert_eq!(windows_pipe_name("console.sock"), "console.sock");
    }

    /// Rule 1: an explicit pipe path resolves to its name verbatim.
    #[test]
    fn explicit_pipe_prefix_resolves_verbatim() {
        assert_eq!(
            windows_pipe_name(r"\\.\pipe\chaperone-events"),
            "chaperone-events"
        );
    }

    /// Rule 3, the CI collision fix: same basename under different
    /// directories MUST yield different pipe names (the pipe namespace is
    /// machine-wide; four parallel tests each binding their own tempdir's
    /// `events.sock` collided under the old basename-only mapping).
    #[test]
    fn same_basename_different_dirs_never_collide() {
        let a = windows_pipe_name(r"C:\Users\ci\AppData\Local\Temp\.tmpAAA\events.sock");
        let b = windows_pipe_name(r"C:\Users\ci\AppData\Local\Temp\.tmpBBB\events.sock");
        let c = windows_pipe_name("/tmp/.tmpCCC/events.sock");
        assert_ne!(a, b, "tempdir A and B must not collide: {a} == {b}");
        assert_ne!(a, c, "windows and unix style paths must not collide");
        assert_ne!(b, c);
    }

    /// Rule 3 legibility: the basename stays recognizable and the name is
    /// pipe-legal (no separators) and bounded.
    #[test]
    fn path_mapping_is_legible_sanitized_and_bounded() {
        let n = windows_pipe_name(r"C:\ProgramData\Chaperone\events.sock");
        assert!(n.starts_with("events.sock-"), "{n}");
        assert!(
            !n.contains(['\\', '/']),
            "pipe name must be separator-free: {n}"
        );
        assert!(n.len() <= 40 + 1 + 16, "name too long: {} ({})", n, n.len());
    }

    /// Determinism: the same path always yields the same pipe name (bind and
    /// connect are separate calls in separate processes).
    #[test]
    fn mapping_is_deterministic() {
        let p = r"C:\Users\op\AppData\Local\Temp\.tmpXYZ\console.sock";
        assert_eq!(windows_pipe_name(p), windows_pipe_name(p));
    }
}
