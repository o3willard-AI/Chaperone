//! Content-Length frame codec (PROTO-SPEC §3.2).
//!
//! Each message is an ASCII header block terminated by a blank line,
//! containing exactly one `Content-Length: N` header, followed by exactly `N`
//! bytes of UTF-8 JSON:
//!
//! ```text
//! Content-Length: 42\r\n\r\n<42 bytes of JSON>
//! ```
//!
//! This is the LSP-style framing the protocol mandates; it avoids delimiter
//! ambiguity in streamed session output.
//!
//! Security posture: the codec enforces a HARD maximum frame size
//! ([`MAX_FRAME_BYTES`], DESIGN-DECISIONS D10) before any body bytes are
//! read, so a hostile or buggy peer cannot make the gateway allocate against
//! a giant declared length. The limit is deliberately not configurable —
//! there is no flag to weaken it accidentally.

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard ceiling on any single frame's body, in bytes (DESIGN-DECISIONS D10).
///
/// 8 MiB bounds what a local peer can force the gateway to buffer per
/// message. Agent-declared and policy-declared `max_response_bytes` are
/// separate, smaller caps applied later, on relayed target output; this
/// constant is only the transport-level DoS guard.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Ceiling on the header block itself. Real headers are one short line;
/// anything near this bound is already abuse.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The exact byte sequence that terminates the header block.
const HEADER_TERMINATOR: &str = "\r\n\r\n";

/// Failures while reading a framed message.
#[derive(Debug)]
#[non_exhaustive]
pub enum FrameError {
    /// Peer closed the connection cleanly at a message boundary.
    Closed,
    /// Underlying transport failed.
    Io(std::io::Error),
    /// Header block was not parseable; carries a human-legible reason.
    MalformedHeader(&'static str),
    /// Header block exceeded [`MAX_HEADER_BYTES`] without terminating.
    HeaderTooLarge,
    /// Declared `Content-Length` exceeded [`MAX_FRAME_BYTES`]. The body was
    /// NOT read; the connection should be answered with an error frame and
    /// closed.
    FrameTooLarge(u64),
    /// Connection ended partway through header or body.
    UnexpectedEof,
    /// Body was valid length-wise but not UTF-8.
    InvalidUtf8,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Closed => write!(f, "connection closed"),
            FrameError::Io(e) => write!(f, "transport i/o error: {e}"),
            FrameError::MalformedHeader(why) => write!(f, "malformed frame header: {why}"),
            FrameError::HeaderTooLarge => {
                write!(f, "frame header exceeds {MAX_HEADER_BYTES} bytes")
            }
            FrameError::FrameTooLarge(n) => {
                write!(
                    f,
                    "declared frame of {n} bytes exceeds hard limit of {MAX_FRAME_BYTES}"
                )
            }
            FrameError::UnexpectedEof => write!(f, "connection ended mid-frame"),
            FrameError::InvalidUtf8 => write!(f, "frame body is not valid UTF-8"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        // A zero-byte read at a message boundary is a clean close; anywhere
        // else it is truncation. `read_exact` maps early EOF to
        // UnexpectedEof, and the header loop below detects the boundary case.
        FrameError::Io(e)
    }
}

/// Reads one complete framed message body as UTF-8 text.
///
/// Enforces the hard frame limit BEFORE reading body bytes: a declared
/// length over [`MAX_FRAME_BYTES`] returns [`FrameError::FrameTooLarge`]
/// without buffering anything from the body.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String, FrameError> {
    let header = read_header(reader).await?;
    let content_length = parse_content_length(&header)?;

    if content_length > MAX_FRAME_BYTES as u64 {
        return Err(FrameError::FrameTooLarge(content_length));
    }

    let mut buf = vec![0u8; content_length as usize];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => FrameError::UnexpectedEof,
            _ => FrameError::Io(e),
        })?;

    String::from_utf8(buf).map_err(|_| FrameError::InvalidUtf8)
}

/// Reads the raw header block, up to and including its blank-line terminator.
async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let terminator = HEADER_TERMINATOR.as_bytes();
    let mut buf = Vec::with_capacity(64);

    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await.map_err(FrameError::Io)?;
        if n == 0 {
            return if buf.is_empty() {
                Err(FrameError::Closed)
            } else {
                Err(FrameError::UnexpectedEof)
            };
        }

        buf.push(byte[0]);

        if buf.len() > MAX_HEADER_BYTES {
            return Err(FrameError::HeaderTooLarge);
        }
        if buf.ends_with(terminator) {
            return Ok(buf);
        }
    }
}

/// Extracts exactly one `Content-Length` value from the header block.
///
/// Other LSP-style headers are tolerated and ignored (liberal in what we
/// accept); duplicate or conflicting `Content-Length` headers are rejected
/// (conservative about what we trust).
fn parse_content_length(header: &[u8]) -> Result<u64, FrameError> {
    let text = std::str::from_utf8(header)
        .map_err(|_| FrameError::MalformedHeader("header block is not ASCII"))?;

    let mut content_length: Option<u64> = None;
    for line in text.trim_end_matches(HEADER_TERMINATOR).split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(FrameError::MalformedHeader("line without ':' separator"));
        };
        if !name.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        let parsed: u64 = value
            .trim()
            .parse()
            .map_err(|_| FrameError::MalformedHeader("content-length is not a number"))?;
        if content_length.replace(parsed).is_some() {
            return Err(FrameError::MalformedHeader("duplicate content-length"));
        }
    }

    content_length.ok_or(FrameError::MalformedHeader("missing content-length"))
}

/// Writes one framed message: header line, blank line, then the payload.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    writer
        .write_all(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn encode_then_read(wire: &[u8]) -> Result<String, FrameError> {
        // Buffer large enough to hold the whole oversized-header fixture so
        // the writer never blocks on a reader that is about to bail out.
        let (mut client, mut server) = duplex(MAX_HEADER_BYTES + 4096);
        client.write_all(wire).await.unwrap();
        drop(client);
        read_frame(&mut server).await
    }

    #[tokio::test]
    async fn round_trips_a_frame() {
        let (mut a, mut b) = duplex(4096);
        write_frame(&mut a, br#"{"ping":true}"#).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), r#"{"ping":true}"#);
    }

    #[tokio::test]
    async fn tolerates_extra_headers_and_case() {
        let wire = b"content-type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(encode_then_read(wire).await.unwrap(), "{}");
    }

    #[tokio::test]
    async fn rejects_missing_content_length() {
        let err = encode_then_read(b"X-Mistaken: 5\r\n\r\nhello")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameError::MalformedHeader("missing content-length")
        ));
    }

    #[tokio::test]
    async fn rejects_duplicate_content_length() {
        let wire = b"Content-Length: 2\r\ncontent-length: 3\r\n\r\n{}abc";
        let err = encode_then_read(wire).await.unwrap_err();
        assert!(matches!(
            err,
            FrameError::MalformedHeader("duplicate content-length")
        ));
    }

    #[tokio::test]
    async fn rejects_non_numeric_length() {
        let err = encode_then_read(b"Content-Length: many\r\n\r\n")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameError::MalformedHeader("content-length is not a number")
        ));
    }

    #[tokio::test]
    async fn rejects_header_line_without_colon() {
        let err = encode_then_read(b"garbage\r\n\r\n").await.unwrap_err();
        assert!(matches!(
            err,
            FrameError::MalformedHeader("line without ':' separator")
        ));
    }

    #[tokio::test]
    async fn rejects_declared_oversize_without_reading_body() {
        // Declares ~9 MiB; body never follows. Must fail with FrameTooLarge
        // WITHOUT buffering any body bytes.
        let wire = format!("Content-Length: {}\r\n\r\n", MAX_FRAME_BYTES + 1);
        let err = encode_then_read(wire.as_bytes()).await.unwrap_err();
        assert!(matches!(err, FrameError::FrameTooLarge(n) if n == (MAX_FRAME_BYTES + 1) as u64));
    }

    #[tokio::test]
    async fn rejects_oversized_header_block() {
        let mut wire = vec![b'x'; MAX_HEADER_BYTES + 1];
        wire.extend_from_slice(b"\r\n\r\n");
        let err = encode_then_read(&wire).await.unwrap_err();
        assert!(matches!(err, FrameError::HeaderTooLarge));
    }

    #[tokio::test]
    async fn detects_clean_close_at_boundary() {
        let (client, mut server) = duplex(64);
        drop(client);
        let err = read_frame(&mut server).await.unwrap_err();
        assert!(matches!(err, FrameError::Closed));
    }

    #[tokio::test]
    async fn detects_truncation_mid_frame() {
        let (mut client, mut server) = duplex(64);
        client
            .write_all(b"Content-Length: 10\r\n\r\nshort")
            .await
            .unwrap();
        drop(client);
        let err = read_frame(&mut server).await.unwrap_err();
        assert!(matches!(err, FrameError::UnexpectedEof));
    }

    #[tokio::test]
    async fn rejects_non_utf8_body() {
        let (mut client, mut server) = duplex(64);
        client
            .write_all(b"Content-Length: 2\r\n\r\n\xff\xfe")
            .await
            .unwrap();
        drop(client);
        let err = read_frame(&mut server).await.unwrap_err();
        assert!(matches!(err, FrameError::InvalidUtf8));
    }
}
