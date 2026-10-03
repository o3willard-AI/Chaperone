//! The operator console channel (DESIGN-DECISIONS D8/D32).
//!
//! A second local endpoint (`chaperone-console.sock` on unix,
//! `chaperone-console` named pipe on Windows — both owner-only, D44) that
//! the operator connects to from another terminal; confirmation prompts
//! render there and answers come back as single lines. Supersedes TTY
//! prompting when configured - the daemon no longer needs a controlling
//! terminal, which is how daemons are actually deployed.
//!
//! Protocol on the channel: plain UTF-8 lines. The gateway writes the full
//! prompt block ending in `Approve? [y/N]: `; the operator sends one line.
//! No framing ceremony - this channel carries nothing secret-shaped, only
//! the human decision.
//!
//! Fail-closed posture: with NO operator connected, every confirmation
//! times out immediately rather than hanging or auto-approving.
//!
//! Transport: `chaperone_transport::operator_pipe` on every platform (P1-1
//! item 3 — Windows gains a real console channel instead of the "ignored on
//! this platform" note; issue #44's honesty posture no longer needs to
//! apply here).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chaperone_transport::operator_pipe::{OperatorListener, OperatorStream};

/// The operator side of the gate, backed by whichever console client is
/// currently connected.
pub struct ConsoleHub {
    current: Mutex<Option<OperatorStream>>,
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

    /// Binds the console endpoint (owner-only) and starts accepting.
    ///
    /// # Errors
    /// The endpoint is unusable, non-UTF-8, or a live console already owns it.
    pub fn spawn(path: &Path) -> Result<Arc<Self>, String> {
        let name = path.to_str().ok_or_else(|| {
            format!(
                "console endpoint path is not valid UTF-8: {}",
                path.display()
            )
        })?;
        let listener = OperatorListener::bind(name, |p| format!("a live console already owns {p}"))
            .map_err(|e| format!("console bind: {e}"))?;
        let hub = Self::new(path.to_path_buf());
        Self::spawn_acceptor(listener, Arc::clone(&hub));
        Ok(hub)
    }

    /// Accepts connections forever, replacing any previously attached
    /// operator (last writer wins - there is ONE console).
    /// Intended to run on a dedicated blocking thread.
    pub fn spawn_acceptor(listener: OperatorListener, hub: Arc<Self>) {
        std::thread::spawn(move || {
            while let Ok(s) = listener.accept() {
                if let Ok(mut guard) = hub.current.lock() {
                    *guard = Some(s);
                }
            }
        });
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
        let guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.as_ref() {
            Some(stream) => stream.write_all(block.as_bytes()),
            None => Err(std::io::Error::other("no operator console connected")),
        }
    }

    fn read_answer(&self) -> std::io::Result<Option<String>> {
        let mut guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(stream) = guard.as_ref() else {
            return Ok(None);
        };
        let mut line = Vec::new();
        loop {
            let byte = match stream.read_byte() {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Operator disconnected; drop the dead stream so future
                    // prompts fail fast instead of reading EOF forever.
                    *guard = None;
                    return Ok(None);
                }
                Err(e) => {
                    *guard = None;
                    return Err(e);
                }
            };
            if byte == b'\n' {
                break;
            }
            if byte != b'\r' {
                line.push(byte);
            }
            if line.len() > 64 {
                return Ok(None); // absurd answer length: treat as noise
            }
        }
        Ok(Some(String::from_utf8_lossy(&line).to_string()))
    }
}
