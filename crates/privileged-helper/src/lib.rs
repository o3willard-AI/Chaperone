//! Privileged-helper core logic (ARCH-SPEC §7.2/§2.7).
//!
//! Kept as a library so the SECURITY decisions - token gate, allowlist
//! pinning, token-free child environment - are testable without process
//! plumbing; the binary is thin glue over [`process_request`].

use serde_json::{Value, json};

pub use allowlist::{Allowlist, AllowlistEntry};
pub use frame_io::{read_frame, write_frame};

/// Fail-safe caps.
/// Hard cap on any single framed message (bytes).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Hard wall-clock bound on any single child execution.
pub const MAX_CHILD_RUNTIME: std::time::Duration = std::time::Duration::from_secs(600);

mod allowlist;

/// Framed stdio helpers mirroring PROTO-SPEC §3.2.
pub mod frame_io {
    use std::io::{Read, Write};

    /// Reads one Content-Length-framed body; Ok(None) on clean EOF.
    pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = reader.read(&mut byte).map_err(|e| e.to_string())?;
            if n == 0 {
                return if header.is_empty() {
                    Ok(None)
                } else {
                    Err("truncated header".to_owned())
                };
            }
            header.push(byte[0]);
            if header.len() > 256 {
                return Err("header too large".to_owned());
            }
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&header).map_err(|_| "header not ASCII".to_owned())?;
        let len: usize = text
            .trim_end_matches("\r\n\r\n")
            .split("\r\n")
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse().ok())
            })
            .ok_or_else(|| "missing content-length".to_owned())?;
        if len > super::MAX_FRAME_BYTES {
            return Err("frame too large".to_owned());
        }
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
        Ok(Some(body))
    }

    /// Writes one framed message.
    pub fn write_frame(writer: &mut dyn Write, payload: &[u8]) -> Result<(), String> {
        writer
            .write_all(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes())
            .and_then(|_| writer.write_all(payload))
            .and_then(|_| writer.flush())
            .map_err(|e| e.to_string())
    }
}

fn b64(data: &[u8]) -> String {
    chaperone_protocol::encode_signature(data)
}

/// Processes ONE request end-to-end: token gate first, then allowlist,
/// then (optionally) real execution. Returns response messages in order.
///
/// With `run_child == false` this is a pure AUTHORIZATION PROBE: nothing is
/// spawned regardless of the decision, which is how tests and the daemon's
/// pre-flight check reuse the exact same policy code.
pub fn process_request(
    msg: &Value,
    expected_token: &str,
    allowlist: &Allowlist,
    run_child: bool,
) -> Vec<Value> {
    let id = msg
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let stamp = |mut v: Value| {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("id".to_owned(), json!(id));
        }
        v
    };

    if msg.get("token").and_then(Value::as_str) != Some(expected_token) {
        return vec![stamp(json!({"status": "denied", "reason": "bad token"}))];
    }
    if msg.get("op").and_then(Value::as_str) != Some("exec") {
        return vec![stamp(
            json!({"status": "error", "reason": "unsupported op"}),
        )];
    }
    let Some(command) = msg.get("command").and_then(Value::as_str) else {
        return vec![stamp(
            json!({"status": "error", "reason": "missing command"}),
        )];
    };
    let args: Vec<String> = msg
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    if !allowlist.permits(command, &args) {
        return vec![stamp(
            json!({"status": "denied", "reason": "command not allowlisted"}),
        )];
    }
    if !run_child {
        return vec![stamp(json!({"status": "authorized"}))];
    }

    // Spawn with the shared token STRIPPED from the child's environment:
    // the child inherits exactly what its command line says, nothing more.
    let input = msg
        .get("input_b64")
        .and_then(Value::as_str)
        .map(|s| {
            chaperone_protocol::decode_signature(s.replace(['\n', '\r'], "").trim_end_matches('='))
        })
        .map(|r| r.unwrap_or_default());

    let mut cmd = std::process::Command::new(command);
    cmd.args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_remove("CHAPERONE_HELPER_TOKEN");

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return vec![stamp(
                json!({"status": "error", "reason": format!("spawn: {e}")}),
            )];
        }
    };
    if let Some(bytes) = &input {
        use std::io::Write as _;
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(bytes);
        }
    }

    let started = std::time::Instant::now();
    let output = loop {
        match child.try_wait() {
            Ok(Some(_)) => break child.wait_with_output().map_err(|e| e.to_string()),
            Ok(None) => {
                if started.elapsed() > MAX_CHILD_RUNTIME {
                    let _ = child.kill();
                    break child.wait_with_output().map_err(|e| e.to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => break Err(e.to_string()),
        }
    };

    match output {
        Ok(out) => {
            let mut msgs = Vec::new();
            if !out.stdout.is_empty() {
                msgs.push(stamp(json!({
                    "type": "out", "stream": "stdout", "data_b64": b64(&out.stdout),
                })));
            }
            if !out.stderr.is_empty() {
                msgs.push(stamp(json!({
                    "type": "out", "stream": "stderr", "data_b64": b64(&out.stderr),
                })));
            }
            msgs.push(stamp(json!({
                "type": "exit",
                "exit_code": out.status.code().unwrap_or(-1),
            })));
            msgs
        }
        Err(e) => vec![stamp(json!({"status": "error", "reason": e}))],
    }
}
