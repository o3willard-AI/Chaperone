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
//! queues to zero subscribers until [`EventHub::listen`] attaches an
//! endpoint, or never — the in-process UI and the policy-integrity guard
//! broadcast regardless.
//!
//! **Delivery is asynchronous (CH-77-2).** [`EventHub::broadcast`] only
//! enqueues the line; a dedicated writer thread performs the socket writes
//! under a bounded deadline and drops subscribers that stall. This is not a
//! performance nicety — it is the deadlock fix. A feed write on the broker
//! thread circular-waits whenever a connected subscriber is not draining:
//! delivery needs the client to read, the client reads only after the broker
//! call returns, and the broker call returns only after the write completes.
//! Unix hid this (≈200 KB socket buffers absorbed queued lines); Windows
//! pipes buffer ~512 bytes, so the SECOND unread line blocked `handle_message`
//! forever (session summary on close/reap — the windows-latest hang). D35's
//! loss-tolerant tap semantics make the resolution clean: the feed never
//! gates brokering; a subscriber that cannot keep up within
//! [`SUBSCRIBER_WRITE_TIMEOUT`] is disconnected, exactly like a dead one.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use chaperone_transport::operator_pipe::{OperatorListener, OperatorStream};

/// Bounded per-line write deadline for one subscriber. A healthy reader
/// drains in milliseconds even on Windows' small pipe buffers; anything
/// slower than this for a single ~300-byte line is a stalled observer, and
/// D35 says the feed drops it rather than letting it wedge delivery to the
/// others (or, pre-CH-77-2, the broker itself).
const SUBSCRIBER_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum queued undelivered lines. The feed is a live tap, not a journal —
/// the audit chain is the evidence of record — so on overflow the NEW line is
/// dropped (oldest queued lines stay ordered and deliverable).
const MAX_QUEUED_LINES: usize = 4096;

/// Shared state between the hub handle, its accept loop, and its writer
/// thread. Outlives the `EventHub` drop via the shutdown flag: `Drop`
/// signals, the writer exits.
struct Shared {
    /// (pending lines, shutdown flag).
    queue: Mutex<(VecDeque<String>, bool)>,
    cv: Condvar,
    subscribers: Mutex<Vec<OperatorStream>>,
    count: AtomicUsize,
}

/// The event hub: queues broadcast lines and hands subscribers to a writer
/// thread. Cloning is by `Arc`; cheap to share.
pub struct EventHub {
    shared: Arc<Shared>,
}

impl EventHub {
    /// An unbound hub: broadcasts queue to zero subscribers until
    /// [`EventHub::listen`] attaches an endpoint (or never — the in-process
    /// UI and the policy-integrity guard broadcast regardless). Spawns the
    /// writer thread, which idles on the condvar until lines or subscribers
    /// exist and exits when the last hub handle drops.
    #[must_use]
    pub fn new() -> Arc<Self> {
        let shared = Arc::new(Shared {
            queue: Mutex::new((VecDeque::new(), false)),
            cv: Condvar::new(),
            subscribers: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
        });
        std::thread::Builder::new()
            .name("chaperone-events-writer".to_owned())
            .spawn({
                let shared = Arc::clone(&shared);
                move || writer_loop(&shared)
            })
            // A failed spawn leaves the hub functional minus delivery:
            // broadcast still enqueues (bounded), nothing blocks. Loud-ish
            // but non-fatal; the feed is not evidence-of-record.
            .ok();
        Arc::new(Self { shared })
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
    /// is loss-tolerant by design: the queue is bounded, and a subscriber
    /// that stalls is dropped by the writer.
    pub fn broadcast(&self, line: &str) {
        let mut guard = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.1 && guard.0.len() < MAX_QUEUED_LINES {
            guard.0.push_back(format!("{line}\n"));
        }
        drop(guard);
        self.shared.cv.notify_one();
    }

    /// Number of currently connected subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.shared.count.load(Ordering::SeqCst)
    }
}

impl Drop for EventHub {
    fn drop(&mut self) {
        // Signal the writer thread to exit and wake it. (Accept-loop threads
        // exit when the listener handle dies with the last Shared.)
        let mut guard = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.1 = true;
        drop(guard);
        self.shared.cv.notify_all();
    }
}

impl Shared {
    fn add_subscriber(&self, stream: OperatorStream) {
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(stream);
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

/// The writer thread: waits for queued lines, delivers each to every
/// subscriber under a bounded deadline, and drops subscribers whose write
/// fails or times out. Holding no lock while writing keeps `accept` and
/// `subscriber_count` responsive even during a slow delivery.
fn writer_loop(shared: &Arc<Shared>) {
    loop {
        // Wait for the next line (or shutdown).
        let line = {
            let mut guard = shared
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(line) = guard.0.pop_front() {
                    break Some(line);
                }
                if guard.1 {
                    break None; // shutdown with an empty queue
                }
                guard = shared
                    .cv
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        let Some(line) = line else { return };

        // Take the whole registry (short lock), write outside the lock, then
        // re-register the survivors. A subscriber added mid-write joins on
        // the next line — acceptable for a live tap (it missed at most the
        // in-flight line, same as connecting a moment later).
        let subs = std::mem::take(
            &mut *shared
                .subscribers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut alive = Vec::with_capacity(subs.len());
        for sub in subs {
            match sub.write_all_timeout(line.as_bytes(), SUBSCRIBER_WRITE_TIMEOUT) {
                Ok(()) => alive.push(sub),
                // Dead OR stalled: both are dropped, per D35's tap semantics.
                Err(_) => {
                    shared.count.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
        let mut guard = shared
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Merge: keep anything the accept loop added while we were writing.
        alive.append(&mut guard);
        *guard = alive;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::EventHub;
    use chaperone_transport::operator_pipe::OperatorStream;

    /// CH-77-2 regression pin: `broadcast` must NEVER block the caller on
    /// subscriber socket I/O — the windows-latest hang was exactly that (an
    /// inline feed write on the broker thread circular-waited with a
    /// subscriber that only drained after the broker call returned). Here a
    /// connected subscriber reads NOTHING while the hub floods far more than
    /// any pipe/socket buffer (Linux UDS ≈200KB, Windows pipe 512B); every
    /// broadcast call must still return immediately. The old inline
    /// implementation hangs this test; the queued writer-thread design passes
    /// it by construction.
    #[test]
    fn broadcast_never_blocks_on_a_stalled_subscriber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flood.sock");
        let hub = EventHub::spawn(&path).unwrap();

        // Connect and then NEVER read: the stalled observer.
        let stalled = OperatorStream::connect(path.to_str().unwrap()).unwrap();
        // Let the accept loop register it.
        let mut registered = false;
        for _ in 0..50 {
            if hub.subscriber_count() == 1 {
                registered = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(registered, "accept loop never registered the subscriber");

        // Flood: 4096 lines × ~200 bytes ≈ 800KB, over every platform's
        // buffer. The queue is bounded, so overflow lines are dropped — the
        // point is that EVERY call returns without socket I/O. The flood runs
        // on a worker reporting through a channel with recv_timeout, so a
        // REGRESSION (inline write) fails as a fast located panic here rather
        // than hanging the runner — the whole value of this pin is that it
        // catches the old blocking design without re-stalling CI.
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

        // D35 drop semantics: the stalled subscriber is eventually removed
        // by the writer (its bounded write times out) rather than wedging
        // delivery forever. The writer's per-line timeout is 2s, so allow a
        // generous window.
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
    /// received in order and complete (one-object-per-line contract).
    #[test]
    fn healthy_subscriber_receives_queued_lines_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("order.sock");
        let hub = EventHub::spawn(&path).unwrap();
        let sub = OperatorStream::connect(path.to_str().unwrap()).unwrap();
        for _ in 0..50 {
            if hub.subscriber_count() == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(hub.subscriber_count(), 1);

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
