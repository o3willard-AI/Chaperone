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

/// One live session: owner binding, TTL, output sequencing, channel.
pub struct Entry {
    pub(crate) agent_id: String,
    pub(crate) expires_at: Instant,
    pub(crate) out_seq: AtomicU64,
    #[allow(dead_code)] // retained for future multi-channel sessions
    pub(crate) channel: Arc<tokio::sync::Mutex<Box<dyn SessionChannel>>>,
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
    pub fn insert(
        &self,
        agent_id: &str,
        channel: Box<dyn SessionChannel>,
        ttl: Duration,
    ) -> String {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let handle = format!(
            "{SESSION_PREFIX}{}",
            chaperone_protocol::encode_signature(&raw)
        );
        let mut guard = self.lock();
        guard.insert(
            handle.clone(),
            Arc::new(Entry {
                agent_id: agent_id.to_owned(),
                expires_at: Instant::now() + ttl,
                out_seq: AtomicU64::new(0),
                channel: Arc::new(tokio::sync::Mutex::new(channel)),
            }),
        );
        handle
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
}
