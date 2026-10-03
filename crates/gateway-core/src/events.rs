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
//! the feed now exists wherever the gateway runs).
//!
//! **Delivery is asynchronous and per-subscriber (CH-77-2).** [`EventHub::
//! broadcast`] only `try_send`s the line into each subscriber's bounded
//! queue; it NEVER performs socket I/O and never blocks. Each subscriber has
//! a dedicated delivery thread doing conventional BLOCKING writes. Two
//! Windows failure modes drove this shape, both verified on windows-latest:
//!
//! 1. Inline writes on the broker thread circular-wait: delivery needs the
//!    client to drain, the client drains only after the broker call returns,
//!    the broker call returns only after the write completes. Windows pipes
//!    buffer 512 bytes, so the second unread line (session summary behind an
//!    unread decision) wedged `handle_message` forever — the 6-hour CI hang.
//!    Enqueue-only broadcast makes this structurally impossible.
//! 2. `PIPE_NOWAIT` writes via `interprocess` silently failed to deliver
//!    (a bounded-write experiment never reached healthy subscribers; the
//!    exact Win32 semantics are undocumented at this layer). Blocking writes
//!    are the codebase's empirically proven Windows path — the pre-fix inline
//!    hub delivered single lines fine — so the delivery threads stick to
//!    them and NO nonblocking mode is ever set on a write-side handle.
//!
//! A subscriber that cannot keep up fills its bounded queue and is dropped
//! (D35: the feed is a loss-tolerant tap; the audit chain is the evidence of
//! record). Its delivery thread may stay parked on a blocking write until
//! the peer closes — isolated: it affects neither the broker nor other
//! subscribers.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, MutexGuard};

use chaperone_transport::operator_pipe::{OperatorListener, OperatorStream};

/// Per-subscriber queue depth. Small: the feed is a live tap, and a
/// subscriber this far behind is already missing the picture. A full queue
/// drops the subscriber (D35), which is cheaper than unbounded memory or
/// back-pressure on the broker.
const SUB_QUEUE_LEN: usize = 256;

/// One registered subscriber: the send half of its delivery queue. The
/// receive half and the socket live on its dedicated delivery thread.
struct Sub {
    tx: SyncSender<String>,
}

/// Shared registry, kept alive by the hub handle(s) and the accept loop.
struct Shared {
    subs: Mutex<Vec<Sub>>,
    count: AtomicUsize,
}

/// The event hub: registers subscribers and fans broadcast lines out to
/// their delivery queues. Cheap to share (`Arc` inside).
pub struct EventHub {
    shared: Arc<Shared>,
}

impl EventHub {
    /// An unbound hub: broadcasts fan out to zero subscribers until
    /// [`EventHub::listen`] attaches an endpoint (or never — the in-process
    /// UI and the policy-integrity guard broadcast regardless).
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            shared: Arc::new(Shared {
                subs: Mutex::new(Vec::new()),
                count: AtomicUsize::new(0),
            }),
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

        let accept_shared = Arc::clone(&self.shared);
        std::thread::spawn(move || {
            while let Ok(stream) = listener.accept() {
                accept_shared.add_subscriber(stream);
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

    /// Queues one JSON line for delivery to every connected subscriber.
    ///
    /// Returns as soon as the line is enqueued — NEVER performs socket I/O
    /// and never blocks on a subscriber (CH-77-2; see module docs). Delivery
    /// is loss-tolerant by design: a subscriber whose queue is full, or whose
    /// delivery thread has died, is dropped on the spot.
    pub fn broadcast(&self, line: &str) {
        let wire = format!("{line}\n");
        let mut subs = self.lock_subs();
        subs.retain(|sub| match sub.tx.try_send(wire.clone()) {
            Ok(()) => true,
            // Full (stalled observer) or Disconnected (dead delivery thread):
            // both mean this subscriber is gone as far as the feed is
            // concerned — drop it, per D35's tap semantics.
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.shared.count.fetch_sub(1, Ordering::SeqCst);
                false
            }
        });
    }

    /// Number of currently connected subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.shared.count.load(Ordering::SeqCst)
    }

    fn lock_subs(&self) -> MutexGuard<'_, Vec<Sub>> {
        self.shared
            .subs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Shared {
    /// Registers a new subscriber and spawns its delivery thread: blocking
    /// writes, one per queued line, exiting when the queue disconnects (hub
    /// dropped / subscriber pruned) or a write fails (peer gone).
    fn add_subscriber(&self, stream: OperatorStream) {
        let (tx, rx): (SyncSender<String>, Receiver<String>) = sync_channel(SUB_QUEUE_LEN);
        let spawned = std::thread::Builder::new()
            .name("chaperone-events-sub".to_owned())
            .spawn(move || {
                for line in rx {
                    if stream.write_all(line.as_bytes()).is_err() {
                        break; // peer gone; the next broadcast prunes the registry
                    }
                }
            })
            .is_ok();
        if !spawned {
            // No thread to serve the queue: don't register a subscriber that
            // can never be delivered to (it would sit until pruned).
            return;
        }
        self.subs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Sub { tx });
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::EventHub;
    use chaperone_transport::operator_pipe::OperatorStream;

    fn wait_registered(hub: &EventHub, want: usize) -> bool {
        (0..100).any(|_| {
            if hub.subscriber_count() == want {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            false
        })
    }

    /// CH-77-2 regression pin: `broadcast` must NEVER block the caller on
    /// subscriber socket I/O — the windows-latest hang was exactly that (an
    /// inline feed write on the broker thread circular-waited with a
    /// subscriber that only drained after the broker call returned). Here a
    /// connected subscriber reads NOTHING while the hub floods far more than
    /// any pipe/socket buffer (Linux UDS ≈200KB, Windows pipe 512B); every
    /// broadcast call must still return immediately. The old inline
    /// implementation hangs this test; the queued per-subscriber design
    /// passes it by construction.
    ///
    /// FALSIFIABILITY (proven, not claimed): reverting `broadcast` to the
    /// inline blocking write made this test FAIL in ~5s with the located
    /// "REGRESSION: broadcast blocked on subscriber socket I/O" message —
    /// the flood runs on a worker behind a channel `recv_timeout`, so even
    /// the regression cannot stall the runner.
    #[test]
    fn broadcast_never_blocks_on_a_stalled_subscriber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flood.sock");
        let hub = EventHub::spawn(&path).unwrap();

        // Connect and then NEVER read: the stalled observer.
        let stalled = OperatorStream::connect(path.to_str().unwrap()).unwrap();
        assert!(
            wait_registered(&hub, 1),
            "accept loop never registered the subscriber"
        );

        // Flood: 4096 lines × ~200 bytes ≈ 800KB, over every platform's
        // buffer. The queue is bounded, so the stalled subscriber is dropped
        // mid-flood — the point is that EVERY call returns without socket
        // I/O. Worker + recv_timeout so a REGRESSION (inline write) fails as
        // a fast located panic instead of hanging the runner.
        let line = format!("{{\"type\":\"decision\",\"pad\":\"{}\"}}", "x".repeat(150));
        let flood_hub = std::sync::Arc::clone(&hub);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            for i in 0..4096 {
                flood_hub.broadcast(&format!("{line}{i}")); // keeps lines unique-ish
            }
            let _ = tx.send(started.elapsed());
        });
        let elapsed = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("REGRESSION: broadcast blocked on subscriber socket I/O (feed writes must be off the caller's thread — see CH-77-2)");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "broadcast loop took {elapsed:?} — enqueueing 4096 lines must be near-instant"
        );

        // D35 drop semantics: the stalled subscriber is pruned once its
        // bounded queue backs up, rather than retained forever.
        let dropped = (0..100).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            hub.subscriber_count() == 0
        });
        assert!(
            dropped,
            "a stalled subscriber must eventually be dropped, not retained forever"
        );
        drop(stalled);
    }

    /// Delivery still works with a healthy subscriber: broadcast lines are
    /// received in order and complete (one-object-per-line contract). This
    /// is the positive control that caught the Windows NOWAIT-write
    /// non-delivery (run 2 of CH-77-2): a stall-only test suite would have
    /// passed with a feed that never delivers anything.
    #[test]
    fn healthy_subscriber_receives_queued_lines_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("order.sock");
        let hub = EventHub::spawn(&path).unwrap();
        let sub = OperatorStream::connect(path.to_str().unwrap()).unwrap();
        assert!(wait_registered(&hub, 1));

        for i in 0..3 {
            hub.broadcast(&format!("{{\"type\":\"decision\",\"seq\":{i}}}"));
        }

        // Read three newline-terminated JSON lines back in order.
        let mut lines = Vec::new();
        let mut buf: Vec<u8> = Vec::new();
        while lines.len() < 3 {
            let b = sub
                .read_byte_timeout(std::time::Duration::from_secs(5))
                .expect("feed went silent before delivering all queued lines");
            if b == b'\n' {
                lines.push(String::from_utf8(buf.clone()).unwrap());
                buf.clear();
            } else {
                buf.push(b);
            }
        }
        for (i, l) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["type"], "decision");
            assert_eq!(v["seq"], i as u64, "lines must stay in broadcast order");
        }
    }
}
