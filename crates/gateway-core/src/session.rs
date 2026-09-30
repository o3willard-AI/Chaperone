//! Brokered sessions (PROTO-SPEC §6.2, §8; ARCH-SPEC §3.2).
//!
//! The credential authenticates the channel ONCE and is scrubbed; the live
//! channel persists and is driven by an opaque [`SESSION_PREFIX`]-prefixed
//! handle bound to the opening agent. Every subsequent frame is
//! independently signed (full §4 verification) AND owner-checked - a stolen
//! handle string is useless without the opener's key.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chaperone_vault::SecretString;
use rand_core::{OsRng, RngCore};
use serde_json::Value;

/// Handle prefix (DESIGN-DECISIONS D4).
pub const SESSION_PREFIX: &str = "sess_";

/// One direction of relayed output.
#[derive(Debug, Clone)]
pub struct OutputChunk {
    /// "stdout" | "stderr".
    pub stream: &'static str,
    /// Raw bytes from that stream.
    pub data: Vec<u8>,
}

/// What one read-batch produced.
#[derive(Debug, Default)]
pub struct OutputBatch {
    /// Everything read during the batch window.
    pub chunks: Vec<OutputChunk>,
    /// Channel reported end-of-life.
    pub closed: bool,
    /// Exit status if the channel reported one.
    pub exit_code: Option<i32>,
}

/// A live authenticated channel. Implementations hold NO reusable secret -
/// the handshake already happened.
pub trait SessionChannel: Send + Sync {
    /// Relays agent input into the channel.
    fn write(
        &self,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;

    /// Reads whatever is available, waiting at most `max_wait`; `closed`
    /// marks terminal state (after which reads keep returning empty-closed).
    fn read_batch(
        &self,
        max_wait: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutputBatch> + Send + '_>>;

    /// Best-effort teardown. Takes `&self`: implementations use interior
    /// mutability, so callers may hold their own locks while calling.
    fn shutdown(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

/// The boxed future `connect` returns.
pub type ConnectFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Box<dyn SessionChannel>, String>> + Send + 'a>,
>;

/// Connects a mechanism's channel, spending the resolved secret exactly
/// once at establishment.
pub trait SessionBackend: Send + Sync {
    /// Establishes the channel, consuming the secret exactly once.
    /// Establishes the channel, consuming the secret exactly once.
    /// `target_uri` is the signed intent's endpoint; mechanisms that keep
    /// their endpoint in the operation body may ignore it.
    fn connect<'a>(
        &'a self,
        target_uri: &'a str,
        operation: &'a Value,
        secret: &'a SecretString,
    ) -> ConnectFuture<'a>;
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

/// One live session: owner binding, TTL, output sequencing, channel, and the
/// P1-3 usage counters that feed the live event summary/heartbeat (in-memory
/// only — the audit chain is unchanged by these; see MVP-GAP-REVIEW P1-3).
pub struct Entry {
    pub(crate) agent_id: String,
    /// Mechanism this session brokers ("ssh" | "db-scram"); for feed context.
    pub(crate) mechanism: String,
    /// Target URI/label at open time; for feed context (never a secret).
    pub(crate) target_uri: String,
    pub(crate) target_label: String,
    pub(crate) expires_at: Instant,
    pub(crate) opened_at: Instant,
    pub(crate) out_seq: AtomicU64,
    /// Relay counters for the session-summary / heartbeat feed events.
    pub(crate) commands: AtomicU64,
    pub(crate) bytes_in: AtomicU64,
    pub(crate) bytes_out: AtomicU64,
    /// When the last heartbeat was emitted (None = none yet). A Mutex rather
    /// than an atomic because the heartbeat scan reads-modifies-writes it under
    /// the same table lock it already holds.
    pub(crate) last_beat: Mutex<Option<Instant>>,
    #[allow(dead_code)] // retained for future multi-channel sessions
    pub(crate) channel: Arc<tokio::sync::Mutex<Box<dyn SessionChannel>>>,
}

/// A point-in-time usage snapshot of a live session (P1-3 feed events).
#[derive(Debug, Clone, Copy)]
pub struct SessionStats {
    /// Command frames relayed into the session since open.
    pub commands: u64,
    /// Bytes written to the channel since open.
    pub bytes_in: u64,
    /// Bytes read back from the channel since open.
    pub bytes_out: u64,
    /// Wall-clock duration since the session opened.
    pub elapsed: Duration,
}

/// Handle -> live-session table.
pub struct SessionTable {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

impl SessionTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Entry>>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Issues a fresh unguessable handle bound to `agent_id`.
    ///
    /// Returns the handle AND the live [`Entry`] so the caller can attach a
    /// heartbeat scan (P1-3) without a second lookup.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        agent_id: &str,
        mechanism: &str,
        target_uri: &str,
        target_label: &str,
        channel: Box<dyn SessionChannel>,
        ttl: Duration,
    ) -> (String, Arc<Entry>) {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let handle = format!(
            "{SESSION_PREFIX}{}",
            chaperone_protocol::encode_signature(&raw)
        );
        let entry = Arc::new(Entry {
            agent_id: agent_id.to_owned(),
            mechanism: mechanism.to_owned(),
            target_uri: target_uri.to_owned(),
            target_label: target_label.to_owned(),
            expires_at: Instant::now() + ttl,
            opened_at: Instant::now(),
            out_seq: AtomicU64::new(0),
            commands: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            last_beat: Mutex::new(None),
            channel: Arc::new(tokio::sync::Mutex::new(channel)),
        });
        let mut guard = self.lock();
        guard.insert(handle.clone(), Arc::clone(&entry));
        (handle, entry)
    }

    /// Owner-checked lookup; maps every failure to its §10 code pair.
    ///
    /// Foreign identities and unknown/expired handles are deliberately
    /// distinguished here (PROTO-SPEC names E_SESSION_OWNER explicitly).
    #[allow(clippy::type_complexity)]
    pub fn access(
        &self,
        handle: &str,
        agent_id: &str,
    ) -> Result<(Arc<Entry>, Duration), (&'static str, &'static str)> {
        let guard = self.lock();
        let Some(entry) = guard.get(handle) else {
            return Err(("E_SESSION_EXPIRED", "unknown session_handle"));
        };
        if entry.agent_id != agent_id {
            return Err((
                "E_SESSION_OWNER",
                "frame identity differs from session opener",
            ));
        }
        let remaining = entry.expires_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(("E_SESSION_EXPIRED", "session past its TTL"));
        }
        Ok((Arc::clone(entry), remaining))
    }

    /// Removes a session deliberately (close path). Foreign identities get
    /// `None`, indistinguishable from unknown handles.
    pub fn take(&self, handle: &str, agent_id: &str) -> Option<Arc<Entry>> {
        let mut guard = self.lock();
        if let Some(entry) = guard.get(handle)
            && entry.agent_id != agent_id
        {
            return None;
        }
        guard.remove(handle)
    }

    /// Snapshot of all live sessions as (handle, entry) pairs, for the P1-3
    /// heartbeat scan. Holds the table lock only while cloning the Arc handles.
    pub fn snapshot(&self) -> Vec<(String, Arc<Entry>)> {
        self.lock()
            .iter()
            .map(|(h, e)| (h.clone(), Arc::clone(e)))
            .collect()
    }

    /// Removes sessions past their TTL and returns them (P1-3). TTL expiry is
    /// otherwise lazy — an abandoned session lingers until its agent touches
    /// it again — so the heartbeat scan is the reaping point, and the caller
    /// emits each reaped session's summary before it is forgotten.
    pub fn reap_expired(&self) -> Vec<(String, Arc<Entry>)> {
        let now = Instant::now();
        let mut guard = self.lock();
        let expired: Vec<String> = guard
            .iter()
            .filter(|(_, e)| now >= e.expires_at)
            .map(|(h, _)| h.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|h| guard.remove(&h).map(|e| (h, e)))
            .collect()
    }
}

impl Entry {
    /// Next monotonically increasing output sequence number (§8.2).
    pub fn next_out_seq(&self) -> u64 {
        self.out_seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The live channel behind this session.
    pub fn channel(&self) -> &tokio::sync::Mutex<Box<dyn SessionChannel>> {
        &self.channel
    }

    /// Clonable handle for async shutdown without holding the table lock.
    pub fn channel_arc(&self) -> Arc<tokio::sync::Mutex<Box<dyn SessionChannel>>> {
        Arc::clone(&self.channel)
    }

    /// The opening agent's id (feed context; already public via decisions).
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Mechanism this session brokers (feed context).
    #[must_use]
    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    /// Target URI at open time (feed context; a reference, never a secret).
    #[must_use]
    pub fn target_uri(&self) -> &str {
        &self.target_uri
    }

    /// Human target label at open time (feed context).
    #[must_use]
    pub fn target_label(&self) -> &str {
        &self.target_label
    }

    /// Records one relayed command frame with its byte counts (P1-3).
    pub fn record_relay(&self, bytes_in: u64, bytes_out: u64) {
        self.commands.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }

    /// Point-in-time usage snapshot (P1-3 feed events).
    #[must_use]
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            commands: self.commands.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            elapsed: self.opened_at.elapsed(),
        }
    }

    /// Heartbeat bookkeeping: true when a beat is due (session open longer
    /// than `threshold` and none emitted within the last `threshold`);
    /// records the beat time when it returns true.
    pub fn heartbeat_due(&self, threshold: Duration) -> bool {
        let now = Instant::now();
        if now.duration_since(self.opened_at) < threshold {
            return false;
        }
        let mut guard = self
            .last_beat
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let due = match *guard {
            None => true,
            Some(last) => now.duration_since(last) >= threshold,
        };
        if due {
            *guard = Some(now);
        }
        due
    }
}
