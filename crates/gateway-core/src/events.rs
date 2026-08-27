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
//!
//! On non-unix platforms the events feed is a documented no-op: there is no
//! Unix-domain-socket type in `std::os::unix` (which does not exist on
//! Windows). `EventHub` is still a valid, referencable type so the rest of
//! the gateway (config UI, policy-integrity guard) compiles unchanged;
//! `broadcast` simply drops lines and `listen` binds nothing.

use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::sync::Mutex;

/// The event hub: holds active subscriber streams and broadcasts lines.
#[cfg(unix)]
pub struct EventHub {
    subscribers: Mutex<Vec<UnixStream>>,
}

/// Cross-platform stand-in: no subscribers, no socket, no-op broadcasts.
#[cfg(not(unix))]
pub struct EventHub {
    // Intentionally empty: the feed is a Unix-domain-socket feature.
}

#[cfg(unix)]
impl EventHub {
    /// An unbound hub: broadcasts are buffered to zero subscribers until
    /// [`EventHub::listen`] attaches a socket (or never - the in-process
    /// UI and the policy-integrity guard broadcast regardless).
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            subscribers: Mutex::new(Vec::new()),
        })
    }

    /// Binds the events socket at `path` and spawns its accept loop.
    ///
    /// # Errors
    /// The socket path is unusable or a live feed already owns it.
    pub fn listen(self: &Arc<Self>, path: &Path) -> Result<(), String> {
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
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }

        let accept_hub = Arc::clone(self);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                accept_hub.add_subscriber(stream);
            }
        });

        Ok(())
    }

    /// Convenience constructor that binds immediately (D35 shape).
    ///
    /// # Errors
    /// Same as [`EventHub::listen`].
    pub fn spawn(path: &Path) -> Result<Arc<EventHub>, String> {
        let hub = Self::new();
        hub.listen(path)?;
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

#[cfg(not(unix))]
impl EventHub {
    /// An unbound hub: broadcasts are dropped; there is no feed on this
    /// platform.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }

    /// No-op on platforms without Unix-domain sockets.
    ///
    /// # Errors
    /// Never: the feed is intentionally absent here.
    pub fn listen(self: &Arc<Self>, path: &Path) -> Result<(), String> {
        let _ = (self, path);
        Ok(())
    }

    /// Convenience constructor that binds immediately (D35 shape).
    ///
    /// # Errors
    /// Never: the feed is intentionally absent here.
    pub fn spawn(path: &Path) -> Result<Arc<EventHub>, String> {
        let hub = Self::new();
        hub.listen(path)?;
        Ok(hub)
    }

    /// No-op: there is no feed to broadcast to.
    pub fn broadcast(&self, _line: &str) {}

    /// Never any subscribers on this platform.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        0
    }
}
