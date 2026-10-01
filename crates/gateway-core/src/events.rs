//! The operator event feed (OPERATOR-UI-SPEC Part B, D35).
//!
//! A read-only fan-out endpoint (`chaperone-events.sock` on unix,
//! `chaperone-events` named pipe on Windows — both owner-only, D44) that
//! broadcasts one JSON line per terminal intent decision to any connected
//! subscriber. No new facts — a live tap on data the audit chain already
//! produces. Nothing is ever written back by subscribers.
//!
//! Unlike the console channel's 1:1 answer semantics, this supports unlimited
//! simultaneous readers (fan-out): a `chaperone tail` CLI, a menu-bar app,
//! and any other local observer can all subscribe without contending.
//!
//! Transport: `chaperone_transport::operator_pipe` on every platform
//! (P1-1 item 3 — the Windows stub that failed loudly per issue #43 is gone;
//! the feed now exists wherever the gateway runs). An unbound hub still
//! buffers to zero subscribers until [`EventHub::listen`] attaches an
//! endpoint, or never — the in-process UI and the policy-integrity guard
//! broadcast regardless.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chaperone_transport::operator_pipe::{OperatorListener, OperatorStream};

/// The event hub: holds active subscriber streams and broadcasts lines.
pub struct EventHub {
    subscribers: Mutex<Vec<OperatorStream>>,
}

impl EventHub {
    /// An unbound hub: broadcasts are buffered to zero subscribers until
    /// [`EventHub::listen`] attaches an endpoint (or never - the in-process
    /// UI and the policy-integrity guard broadcast regardless).
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            subscribers: Mutex::new(Vec::new()),
        })
    }

    /// Binds the events endpoint at `path` and spawns its accept loop.
    ///
    /// # Errors
    /// The endpoint is unusable, non-UTF-8, or a live feed already owns it.
    pub fn listen(self: &Arc<Self>, path: &Path) -> Result<(), String> {
        let name = path.to_str().ok_or_else(|| {
            format!(
                "events endpoint path is not valid UTF-8: {}",
                path.display()
            )
        })?;
        let listener =
            OperatorListener::bind(name, |p| format!("a live event feed already owns {p}"))
                .map_err(|e| format!("events bind: {e}"))?;

        let accept_hub = Arc::clone(self);
        std::thread::spawn(move || {
            while let Ok(stream) = listener.accept() {
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
    fn add_subscriber(&self, stream: OperatorStream) {
        self.lock_subscribers().push(stream);
    }

    /// Number of currently connected subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.lock_subscribers().len()
    }

    fn lock_subscribers(&self) -> std::sync::MutexGuard<'_, Vec<OperatorStream>> {
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
