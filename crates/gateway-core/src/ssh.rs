//! The `ssh` session backend (PROTO-SPEC §7 `ssh`, ARCH-SPEC §2.5).
//!
//! The vault-held key authenticates ONCE at establishment; the resulting
//! channel persists and is driven by handle (§6.2). The secret does not
//! survive this module's call frame - it can never travel again.
//!
//! Host-key policy (DESIGN-DECISIONS D23): unknown host keys REFUSE by
//! default. TrustOnFirstUseAll exists for tests and explicitly configured
//! environments and is a documented-weaker tradeoff, never a silent default.

use std::sync::Arc;
use std::time::Duration;

use chaperone_vault::SecretString;
use russh::ChannelMsg;
use russh::client::{self, Handle};
use serde_json::Value;

use crate::session::{OutputBatch, OutputChunk, SessionBackend, SessionChannel};

/// Host-key verification posture.
#[derive(Debug, Clone, Copy)]
pub enum HostKeyPolicy {
    /// Refuse any unpinned host key (secure default).
    RefuseUnknown,
    /// Accept every host key. Tests and explicit opt-in configurations only;
    /// see D23 for why this must stay loud.
    TrustOnFirstUseAll,
}

struct ClientHandler {
    policy: HostKeyPolicy,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(self.policy, HostKeyPolicy::TrustOnFirstUseAll))
    }
}

/// SSH session opener.
pub struct SshBackend {
    policy: HostKeyPolicy,
}

impl SshBackend {
    /// Builds the backend under the given host-key policy.
    #[must_use]
    pub fn new(policy: HostKeyPolicy) -> Self {
        Self { policy }
    }
}

impl SessionBackend for SshBackend {
    fn connect<'a>(
        &'a self,
        operation: &'a Value,
        secret: &'a SecretString,
    ) -> crate::session::ConnectFuture<'a> {
        Box::pin(async move {
            let host = operation
                .get("host")
                .and_then(Value::as_str)
                .ok_or("operation.host missing")?
                .to_owned();
            let port = u16::try_from(operation.get("port").and_then(Value::as_u64).unwrap_or(22))
                .unwrap_or(22);
            let user = operation
                .get("user")
                .and_then(Value::as_str)
                .ok_or("operation.user missing")?
                .to_owned();
            let want_pty = operation
                .get("pty")
                .and_then(Value::as_bool)
                .unwrap_or(true);

            // The secret IS the private key text (PEM / OpenSSH format),
            // parsed IN MEMORY - it never touches disk.
            let private_key = russh::keys::PrivateKey::from_openssh(secret.expose())
                .map_err(|e| format!("vault entry is not a parseable SSH private key: {e}"))?;
            let key_pair = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(private_key), None);

            let config = Arc::new(client::Config::default());
            let mut handle: Handle<ClientHandler> = client::connect(
                config,
                (host.as_str(), port),
                ClientHandler {
                    policy: self.policy,
                },
            )
            .await
            .map_err(|e| format!("connect to {host}:{port} failed: {e}"))?;

            match handle
                .authenticate_publickey(user.as_str(), key_pair)
                .await
                .map_err(|e| format!("auth exchange failed: {e}"))?
            {
                russh::client::AuthResult::Success => {}
                russh::client::AuthResult::Failure { .. } => {
                    return Err(format!("public key rejected for {user}@{host}"));
                }
            }

            let channel = handle
                .channel_open_session()
                .await
                .map_err(|e| format!("channel open failed: {e}"))?;
            if want_pty {
                channel
                    .request_pty(false, "xterm", 120, 40, 0, 0, &[])
                    .await
                    .map_err(|e| format!("pty request failed: {e}"))?;
                channel
                    .request_shell(false)
                    .await
                    .map_err(|e| format!("shell request failed: {e}"))?;
            }

            Ok(Box::new(SshChannel {
                handle,
                channel: tokio::sync::Mutex::new(Some(channel)),
                closed: std::sync::atomic::AtomicBool::new(false),
            }) as Box<dyn SessionChannel>)
        })
    }
}

struct SshChannel {
    #[allow(dead_code)] // kept alive: dropping the Handle would kill the session
    handle: Handle<ClientHandler>,
    channel: tokio::sync::Mutex<Option<russh::Channel<client::Msg>>>,
    closed: std::sync::atomic::AtomicBool,
}

impl SessionChannel for SshChannel {
    fn write(
        &self,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let mut guard = self.channel.lock().await;
            match guard.as_mut() {
                Some(channel) => channel.data(&data[..]).await.map_err(|e| e.to_string()),
                None => Err("channel already closed".to_owned()),
            }
        })
    }

    fn read_batch(
        &self,
        max_wait: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutputBatch> + Send + '_>> {
        Box::pin(async move {
            let mut batch = OutputBatch::default();
            let mut guard = self.channel.lock().await;
            let Some(channel) = guard.as_mut() else {
                batch.closed = true;
                return batch;
            };
            let deadline = tokio::time::Instant::now() + max_wait;

            loop {
                match tokio::time::timeout_at(deadline, channel.wait()).await {
                    Err(_quiet) => return batch,
                    Ok(None) => {
                        batch.closed = true;
                        return batch;
                    }
                    Ok(Some(ChannelMsg::Data { ref data })) => {
                        batch.chunks.push(OutputChunk {
                            stream: "stdout",
                            data: data.to_vec(),
                        });
                    }
                    Ok(Some(ChannelMsg::ExtendedData { ref data, .. })) => {
                        batch.chunks.push(OutputChunk {
                            stream: "stderr",
                            data: data.to_vec(),
                        });
                    }
                    Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                        batch.exit_code = i32::try_from(exit_status).ok();
                    }
                    Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) => {
                        batch.closed = true;
                        return batch;
                    }
                    Ok(Some(_)) => {}
                }
                if batch.chunks.len() >= 64 || tokio::time::Instant::now() >= deadline {
                    return batch;
                }
            }
        })
    }

    fn shutdown(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        // Mark the channel dead; the Handle drops when our Arc does. The
        // graceful close() path needs &mut access we cannot take without
        // risking deadlock against a concurrent read_batch.
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut guard) = self.channel.try_lock() {
            *guard = None;
        }
        Box::pin(async move {})
    }
}
