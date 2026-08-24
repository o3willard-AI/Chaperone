//! The operator console channel (DESIGN-DECISIONS D8/D32).
//!
//! A second local socket (`chaperone-console.sock`, owner-only) that the
//! operator connects to from another terminal; confirmation prompts render
//! there and answers come back as single lines. Supersedes TTY prompting
//! when configured - the daemon no longer needs a controlling terminal,
//! which is how daemons are actually deployed.
//!
//! Protocol on the socket: plain UTF-8 lines. The gateway writes the full
//! prompt block ending in `Approve? [y/N]: `; the operator sends one line.
//! No framing ceremony - this channel carries nothing secret-shaped, only
//! the human decision.
//!
//! Fail-closed posture: with NO operator connected, every confirmation
//! times out immediately rather than hanging or auto-approving.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The operator side of the gate, backed by whichever console client is
/// currently connected.
pub struct ConsoleHub {
    current: Mutex<Option<UnixStream>>,
    #[allow(dead_code)] // kept so the acceptor can be traced to its hub
    path: PathBuf,
}

impl ConsoleHub {
    /// An empty hub: no operator attached yet.
    pub fn new(path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(None),
            path,
        })
    }

    /// Test/advanced constructor wrapping an already-connected stream.
    #[must_use]
    pub fn from_stream(stream: UnixStream, path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(Some(stream)),
            path,
        })
    }

    /// Accepts connections forever, replacing any previously attached
    /// operator (last writer wins - there is ONE console).
    /// Intended to run on a dedicated blocking thread.
    pub fn spawn_acceptor(listener: UnixListener2, hub: Arc<Self>) {
        std::thread::spawn(move || {
            for stream in listener.into_raw().incoming() {
                match stream {
                    Ok(s) => {
                        if let Ok(mut guard) = hub.current.lock() {
                            *guard = Some(s);
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

/// Thin wrapper so callers can pass a bound std listener without importing
/// os-unix types at the call site.
pub struct UnixListener2 {
    inner: std::os::unix::net::UnixListener,
}

impl UnixListener2 {
    /// Binds a blocking listener at `path` after removing stale files.
    pub fn bind(path: &Path) -> Result<Self, String> {
        if path.exists() {
            // Probe like the agent socket does: live peer => refuse.
            match UnixStream::connect(path) {
                Ok(_) => return Err(format!("a live console already owns {}", path.display())),
                Err(_) => {
                    std::fs::remove_file(path).map_err(|e| e.to_string())?;
                }
            }
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let listener = std::os::unix::net::UnixListener::bind(path)
            .map_err(|e| format!("console bind: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        Ok(Self { inner: listener })
    }

    /// Returns the raw listener for the acceptor thread.
    pub fn into_raw(self) -> std::os::unix::net::UnixListener {
        self.inner
    }
}

impl super::OperatorIo for Arc<ConsoleHub> {
    fn write_prompt(&self, block: &str) -> std::io::Result<()> {
        (**self).write_prompt(block)
    }
    fn read_answer(&self) -> std::io::Result<Option<String>> {
        (**self).read_answer()
    }
}

impl super::OperatorIo for ConsoleHub {
    fn write_prompt(&self, block: &str) -> std::io::Result<()> {
        let mut guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.as_mut() {
            Some(stream) => {
                stream.write_all(block.as_bytes())?;
                stream.flush()
            }
            None => Err(std::io::Error::other("no operator console connected")),
        }
    }

    fn read_answer(&self) -> std::io::Result<Option<String>> {
        let mut guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(stream) = guard.as_mut() else {
            return Ok(None);
        };
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte) {
                Ok(0) => {
                    // Operator disconnected; drop the dead stream so future
                    // prompts fail fast instead of reading EOF forever.
                    *guard = None;
                    return Ok(None);
                }
                Ok(_) => {}
                Err(e) => {
                    *guard = None;
                    return Err(e);
                }
            }
            if byte[0] == b'\n' {
                break;
            }
            if byte[0] != b'\r' {
                line.push(byte[0]);
            }
            if line.len() > 64 {
                return Ok(None); // absurd answer length: treat as noise
            }
        }
        Ok(Some(String::from_utf8_lossy(&line).to_string()))
    }
}
