//! The operator event feed (OPERATOR-UI-SPEC Part B, D35).
//!
//! A read-only fan-out socket (`chaperone-events.sock`, owner-only) that
//! broadcasts one JSON line per terminal intent decision to any connected
//! subscriber. No new facts — a live tap on data the audit chain already
//! produces. Nothing is ever written back by subscribers.
//!
//! Unlike the console socket's 1:1 answer semantics, this supports unlimited
//! simultaneous readers (fan-out): a `chaperone tail` CLI, a menu-bar app,
//! and any other local observer can all subscribe without contending.

use std::io::Write as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The event hub: holds active subscriber streams and broadcasts lines.
pub struct EventHub {
    subscribers: Mutex<Vec<UnixStream>>,
}

impl EventHub {
    /// Binds the events socket at `path` and spawns the accept loop.
    pub fn spawn(path: &PathBuf) -> Result<Arc<EventHub>, String> {
        if path.exists() {
            match UnixStream::connect(path) {
                Ok(_) => return Err(format!("a live event feed already owns {}", path.display())),
                Err(_) => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let listener = UnixListener::bind(path).map_err(|e| format!("events bind: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(0o600),
            )
            .map_err(|e| e.to_string())?;
        }

        let hub = Arc::new(EventHub {
            subscribers: Mutex::new(Vec::new()),
        });

        let accept_hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                accept_hub.add_subscriber(stream);
            }
        });

        Ok(hub)
    }

    /// Broadcasts one JSON line to every connected subscriber.
    pub fn broadcast(&self, line: &str) {
        let wire = format!("{line}\n");
        let mut guard = self.lock_subscribers();
        guard.retain_mut(|stream| stream.write_all(wire.as_bytes()).is_ok());
    }

    /// Adds a subscriber stream (called by the accept loop).
    fn add_subscriber(&self, stream: UnixStream) {
        self.lock_subscribers().push(stream);
    }

    /// Number of currently connected subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.lock_subscribers().len()
    }

    fn lock_subscribers(&self) -> std::sync::MutexGuard<'_, Vec<UnixStream>> {
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
