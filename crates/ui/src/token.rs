//! Per-instance access token for the loopback config UI (D41).
//!
//! Parts A/B shipped with D40's "bare loopback trust: no login, no token"
//! posture, which the spec's §8 addendum corrects: a plain TCP listener on
//! `127.0.0.1` has no OS-level per-user ACL the way a `0600` Unix domain
//! socket does, so any local OS account - not just the one that configured
//! Chaperone - could reach the port and drive the full config surface. The
//! fix is a persistent per-instance access token, stored beside `audit.key`
//! at the same `0600` discipline (the config directory is already
//! owner-restricted on all three target platforms), required before the UI
//! renders or accepts anything beyond the token-entry page.
//!
//! The token never auto-generates at `serve` startup: the operator creates
//! it with `chaperone ui-token rotate` first, and `serve` refuses to start
//! the UI until it exists. This keeps the browser-based wizard from having
//! to create its own gate (chicken-and-egg) and keeps the token out of
//! serve's stdout/logs.

use std::path::Path;

use rand_core::RngCore;

use crate::state::atomic_write;

/// Token length in raw bytes.
const TOKEN_BYTES: usize = 32;
/// base64url of 32 bytes, no padding.
pub const TOKEN_LEN: usize = 43;

/// A loaded UI access token held in memory while the UI is running.
///
/// Constant-time comparison on [`UiToken::verify`] so a timing oracle can
/// not recover the token one byte at a time.
#[derive(Debug, Clone)]
pub struct UiToken {
    raw: String,
}

impl UiToken {
    /// The base64url token string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Constant-time comparison against a candidate.
    #[must_use]
    pub fn verify(&self, candidate: &str) -> bool {
        constant_time_eq(self.raw.as_bytes(), candidate.as_bytes())
    }
}

/// Generates a fresh 32-byte random token, persists it at `path` (atomic,
/// `0600`), and returns the base64url string.
///
/// # Errors
/// The file could not be written.
pub fn rotate(path: &Path) -> Result<String, String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let token = chaperone_protocol::encode_signature(&bytes);
    atomic_write(path, token.as_bytes())?;
    Ok(token)
}

/// Loads a token from `path`. The file must hold a valid base64url encoding
/// of exactly 32 bytes.
///
/// # Errors
/// The file is missing, unreadable, or not a valid token.
pub fn load(path: &Path) -> Result<UiToken, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read UI token at {}: {e}", path.display()))?;
    let raw = text.trim();
    let decoded = chaperone_protocol::decode_signature(raw)
        .map_err(|e| format!("UI token at {} is not valid base64url: {e}", path.display()))?;
    if decoded.len() != TOKEN_BYTES {
        return Err(format!(
            "UI token at {} decodes to {} bytes, not {TOKEN_BYTES}",
            path.display(),
            decoded.len()
        ));
    }
    Ok(UiToken {
        raw: raw.to_owned(),
    })
}

/// Constant-time byte comparison (same length fast-path is intentional and
/// safe: a length mismatch leaks no per-byte information).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn rotate_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ui.token");
        assert!(!path.exists());

        let token = rotate(&path).unwrap();
        assert_eq!(token.len(), TOKEN_LEN);
        assert!(path.exists());

        let loaded = load(&path).unwrap();
        assert!(loaded.verify(&token));
        assert!(!loaded.verify("not-the-token"));
        assert!(!loaded.verify(""));
        assert!(!loaded.verify(&format!("{token}x")));
    }

    #[cfg(unix)]
    #[test]
    fn rotate_writes_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ui.token");
        rotate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn load_rejects_wrong_lengths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ui.token");
        // 16 bytes, not 32.
        let short = chaperone_protocol::encode_signature(&[0u8; 16]);
        std::fs::write(&path, short).unwrap();
        assert!(load(&path).is_err());

        // Non-base64url.
        std::fs::write(&path, "!!!not valid base64url!!!").unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn constant_time_eq_is_correct() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
