//! The `local-privilege` mechanism (PROTO-SPEC §7.2, ARCH-SPEC §2.7).
//!
//! Daemon-side wiring for the SEPARATE privileged helper process: the
//! gateway spawns `chaperone-helper` with a fresh random token and an
//! operator allowlist, sends ONE exec request, and relays the result as a
//! completed session batch. The helper authoritatively re-checks the
//! allowlist - the daemon's own copy is advisory pre-flight used only to
//! decide whether unattended operation may proceed (PROTO §7.2: policy MUST
//! NOT run it unattended unless the operator pinned this exact command).

use chaperone_vault::SecretString;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::session::{OutputBatch, OutputChunk, SessionBackend, SessionChannel};

/// Daemon-side view of the operator allowlist (same TOML format the helper
/// enforces; single file, two readers).
#[derive(Debug, Clone)]
pub struct PrivilegeAllowlist {
    entries: Vec<(String, Vec<String>)>,
}

impl PrivilegeAllowlist {
    /// Loads the operator allowlist file.
    pub fn load(path: &Path) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            #[serde(default)]
            allow: Vec<E>,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct E {
            command: String,
            #[serde(default)]
            args: Vec<String>,
        }
        let raw = std::fs::read_to_string(path).map_err(|e| format!("allowlist: {e}"))?;
        let file: File = toml::from_str(&raw).map_err(|e| format!("allowlist schema: {e}"))?;
        Ok(Self {
            entries: file
                .allow
                .into_iter()
                .map(|e| (e.command, e.args))
                .collect(),
        })
    }

    /// Advisory pre-flight mirroring the helper's authoritative check.
    #[must_use]
    pub fn permits(&self, command: &str, args: &[String]) -> bool {
        self.entries
            .iter()
            .any(|(c, pin)| c == command && args.len() >= pin.len() && args[..pin.len()] == *pin)
    }
}

/// Spawns and speaks to the privileged helper.
pub struct LocalPrivBackend {
    /// Full argv of the helper invocation, e.g.
    /// ["/usr/bin/sudo", "-n", "/usr/local/bin/chaperone-helper"] or just
    /// ["chaperone-helper"]. The operator owns elevation mechanics.
    pub helper_argv: Vec<String>,
    /// Operator allowlist file; the helper enforces it authoritatively.
    pub allowlist_path: PathBuf,
}

impl LocalPrivBackend {
    /// Fresh shared token per gateway process.
    pub fn new(helper_argv: Vec<String>, allowlist_path: PathBuf) -> Self {
        Self {
            helper_argv,
            allowlist_path,
        }
    }

    fn token() -> String {
        let mut t = [0u8; 32];
        OsRng.fill_bytes(&mut t);
        chaperone_protocol::encode_signature(&t)
    }
}

impl SessionBackend for LocalPrivBackend {
    fn connect<'a>(
        &'a self,
        operation: &'a Value,
        _secret: &'a SecretString,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn SessionChannel>, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let command = operation
                .get("command")
                .and_then(Value::as_str)
                .ok_or("operation.command missing")?
                .to_owned();
            let args: Vec<String> = operation
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let input_b64 = operation.get("input_b64").and_then(Value::as_str);

            let token = Self::token();
            let (program, rest) = self
                .helper_argv
                .split_first()
                .ok_or("empty helper command")?;
            let mut child = tokio::process::Command::new(program)
                .args(rest)
                .arg("--allowlist")
                .arg(&self.allowlist_path)
                .env("CHAPERONE_HELPER_TOKEN", &token)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| format!("spawning helper failed: {e}"))?;

            let mut stdin = child.stdin.take().ok_or("helper stdin missing")?;
            let request = json!({ // framed below

                "token": token,
                "id": "exec-1",
                "op": "exec",
                "command": command,
                "args": args,
                "input_b64": input_b64,
            });
            write_frame_async(&mut stdin, &request.to_string().into_bytes())
                .await
                .map_err(|e| format!("helper write: {e}"))?;
            drop(stdin); // EOF after our single request

            // Collect responses until exit/status or a bounded window ends.
            let mut stdout = child.stdout.take().ok_or("helper stdout missing")?;
            let mut batch = OutputBatch::default();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                match tokio::time::timeout(remaining, read_frame_async(&mut stdout)).await {
                    Err(_) => break,
                    Ok(Err(_)) => break,
                    Ok(Ok(None)) => break,
                    Ok(Ok(Some(body))) => {
                        let msg: Value =
                            serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
                        if msg.get("status").and_then(Value::as_str).is_some() {
                            batch.chunks.push(OutputChunk {
                                stream: "stderr",
                                data: msg.to_string().into_bytes(),
                            });
                            batch.closed = true;
                            batch.exit_code = Some(-1);
                            break;
                        }
                        if msg.get("type").and_then(Value::as_str) == Some("out")
                            && let Some(b64s) = msg.get("data_b64").and_then(Value::as_str)
                            && let Ok(data) = chaperone_protocol::decode_signature(b64s)
                        {
                            let stream = if msg["stream"] == "stderr" {
                                "stderr"
                            } else {
                                "stdout"
                            };
                            batch.chunks.push(OutputChunk { stream, data });
                        }
                        if msg.get("type").and_then(Value::as_str) == Some("exit") {
                            batch.exit_code = msg
                                .get("exit_code")
                                .and_then(Value::as_i64)
                                .and_then(|c| i32::try_from(c).ok());
                            batch.closed = true;
                            break;
                        }
                    }
                }
            }
            Ok(Box::new(CompletedChannel {
                batch: StdMutex::new(Some(batch)),
            }) as Box<dyn SessionChannel>)
        })
    }
}

use std::sync::Mutex as StdMutex;
use std::time::Duration;

/// A channel whose entire output arrived during establishment.
struct CompletedChannel {
    batch: StdMutex<Option<OutputBatch>>,
}

impl SessionChannel for CompletedChannel {
    fn write(
        &self,
        _data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        // The command+stdin were part of establishment; nothing further to
        // relay, so subsequent writes are accepted and ignored.
        Box::pin(async { Ok(()) })
    }

    fn read_batch(
        &self,
        _max_wait: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutputBatch> + Send + '_>> {
        Box::pin(async move {
            let mut guard = self
                .batch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take().unwrap_or_default()
        })
    }

    fn shutdown(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async {})
    }
}

// ---------- async framed I/O over the helper's stdio ----------

async fn write_frame_async<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    const MAX: usize = 1024 * 1024;
    assert!(payload.len() <= MAX, "helper request frame too large");
    let header = format!("Content-Length: {}\r\n\r\n", payload.len());
    w.write_all(header.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    w.write_all(payload).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())
}

async fn read_frame_async<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<Vec<u8>>, String> {
    use tokio::io::AsyncReadExt;
    const TERM: &[u8] = b"\r\n\r\n";
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(None);
        }
        header.push(byte[0]);
        if header.len() > 256 {
            return Err("header too large".to_owned());
        }
        if header.ends_with(TERM) {
            break;
        }
    }
    let text = str::from_utf8(&header).map_err(|_| "header not ASCII".to_owned())?;
    let len: usize = text
        .trim_end_matches("\r\n\r\n")
        .split("\r\n")
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse().ok())
        })
        .ok_or("missing content-length")?;
    if len > 1024 * 1024 {
        return Err("frame too large".to_owned());
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(|e| e.to_string())?;
    Ok(Some(body))
}
