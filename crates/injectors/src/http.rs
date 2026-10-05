//! The `http-bearer` / `http-basic` injector (PROTO-SPEC §7.1).
//!
//! Attaches the credential as an `Authorization` header, performs the
//! request to `target.uri` over freshly-originated TLS, and returns status,
//! headers, and body. The agent supplied everything except the credential;
//! the response is relayed as untrusted DATA (THREAT-MODEL §2.3), never
//! interpreted.
//!
//! Hostile-target defenses:
//! - **No redirects** (D21): the signed intent names one target; a 30x must
//!   not launder those credentials to whatever answers next.
//! - **Hard response ceiling**: bytes are streamed and counted; exceeding
//!   `max_response_bytes` aborts with [`InjectorError::ResponseTooLarge`]
//!   rather than truncating silently (D20).
//! - **Total-call timeout**: a stuck target cannot pin the gateway.

use base64::Engine as _;
use chaperone_protocol::ops::HttpOperation;
use chaperone_vault::SecretString;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::time::Duration;
use zeroize::Zeroizing;

/// Fixed marker substituted for any credential bytes a target reflects back
/// (P0-1). Stable and credential-free so it is safe to relay to the agent and
/// to journal.
const REDACTION_MARKER: &[u8] = b"[REDACTED-CREDENTIAL]";

/// Streams the response body under a hard byte ceiling (THREAT-MODEL §2.3):
/// a Content-Length lie cannot buy an unbounded buffer, and exceeding the
/// ceiling aborts loudly instead of truncating silently (D20).
async fn read_body_capped(
    mut response: reqwest::Response,
    cap_bytes: u64,
) -> Result<Vec<u8>, InjectorError> {
    let mut body = Vec::new();
    loop {
        let Some(chunk) = response
            .chunk()
            .await
            // B-4: classified, not stringified. A body-read failure reports
            // "response body unreadable" and nothing else - the chunk error's
            // text is never relayed.
            .map_err(|e| InjectorError::Transport(TransportError::classify(&e)))?
        else {
            return Ok(body);
        };
        let next_len = body.len().saturating_add(chunk.len());
        if u64::try_from(next_len).unwrap_or(u64::MAX) > cap_bytes {
            return Err(InjectorError::ResponseTooLarge { limit: cap_bytes });
        }
        body.extend_from_slice(&chunk);
    }
}

use crate::{InjectorError, TransportError};

/// Knobs the gateway configures; no per-request overrides exist that could
/// weaken the ceilings (D20).
#[derive(Debug, Clone)]
pub struct HttpLimits {
    /// Hard cap on relayed response bytes.
    pub max_response_bytes: u64,
    /// Total wall-clock budget for the outbound call.
    pub timeout: Duration,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 1_048_576,
            timeout: Duration::from_secs(30),
        }
    }
}

/// What came back from the target - data, never instructions.
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers, lowercased names.
    pub headers: Vec<(String, String)>,
    /// Response body bytes (already ceiling-checked).
    pub body: Vec<u8>,
}

/// The http mechanism, bound to one shared client.
///
/// One client per gateway process: connection pooling is fine - secrets are
/// NOT pooled, they live only inside individual request builds.
pub struct HttpInjector {
    client: reqwest::Client,
}

impl HttpInjector {
    /// Builds the injector with redirects disabled (D21).
    pub fn new() -> Result<Self, InjectorError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            // B-4: client construction failure is a fixed class.
            .map_err(|e| InjectorError::Transport(TransportError::classify(&e)))?;
        Ok(Self { client })
    }

    /// Executes one authenticated request end-to-end on the outbound side.
    ///
    /// `secret` exists only within this call frame; it never enters the
    /// response, errors, or logs.
    pub async fn execute(
        &self,
        mechanism: &str,
        target_uri: &str,
        operation: &HttpOperation,
        secret: &SecretString,
        limits: &HttpLimits,
    ) -> Result<HttpResponse, InjectorError> {
        let auth_value = assemble_authorization(mechanism, operation, secret)?;
        // P0-1: remember every byte form a reflecting target could echo back —
        // the assembled header value (e.g. `Basic <b64(user:secret)>`) and the
        // raw secret. Both are scrubbed from the response before relay so a
        // hostile endpoint cannot launder the credential into agent space.
        // Held as Zeroizing buffers; wiped at end of this frame.
        let mut reflectable: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(2);
        reflectable.push(Zeroizing::new(auth_value.as_bytes().to_vec()));
        if !secret.is_empty() {
            reflectable.push(Zeroizing::new(secret.expose().as_bytes().to_vec()));
        }

        if !target_uri.starts_with("http://") && !target_uri.starts_with("https://") {
            return Err(InjectorError::BadOperation(format!(
                "unsupported target scheme in {target_uri:?}"
            )));
        }

        let mut headers = HeaderMap::new();
        for (name, value) in &operation.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                InjectorError::BadOperation(format!("invalid header name {name:?}"))
            })?;
            let value = HeaderValue::from_str(value).map_err(|_| {
                InjectorError::BadOperation(format!("invalid header value for {name:?}"))
            })?;
            headers.insert(name, value);
        }
        // Inserted after agent headers: even if validation above ever
        // loosened, ours wins.
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let method = reqwest::Method::from_bytes(operation.method.as_bytes()).map_err(|_| {
            InjectorError::BadOperation(format!("unknown method {:?}", operation.method))
        })?;

        let mut builder = self
            .client
            .request(method, target_uri)
            .headers(headers)
            .timeout(limits.timeout);

        if let Some(body_b64) = &operation.body_b64 {
            let body = base64::engine::general_purpose::STANDARD
                .decode(body_b64.trim())
                .map_err(|_| {
                    InjectorError::BadOperation("body_b64 is not valid base64".to_owned())
                })?;
            builder = builder.body(body);
        }

        let response = builder.send().await.map_err(|e| {
            // B-4: the reqwest message is where URLs and other
            // target-influenced text live, so it is never read. `classify`
            // reads only the error's KIND.
            InjectorError::Transport(TransportError::classify(&e))
        })?;

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.as_str().to_ascii_lowercase(), val.to_owned()))
            })
            .collect();

        let body = read_body_capped(response, limits.max_response_bytes).await?;

        // P0-1: scrub reflected credential bytes from BOTH the headers and the
        // body before they leave this frame. The response is untrusted data
        // (THREAT-MODEL §2.3); untrusted data that happens to contain our own
        // credential is still our credential, so it is redacted here — in the
        // one place that legitimately holds the material — and nothing secret
        // is retained past the wipe at frame end.
        let resp_headers = scrub_header_pairs(resp_headers, &reflectable);
        let body = scrub_bytes(body, &reflectable);
        // reflectable buffers wipe on drop (Zeroizing).

        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body,
        })
    }
}

/// Replaces every occurrence of any reflectable credential form in `data`
/// with [`REDACTION_MARKER`]. Longest-first ordering prevents a shorter form
/// that is a substring of a longer one from being redacted first and leaving
/// a fragment of the longer form behind.
fn scrub_bytes(mut data: Vec<u8>, secrets: &[Zeroizing<Vec<u8>>]) -> Vec<u8> {
    let mut forms: Vec<&[u8]> = secrets
        .iter()
        .map(|s| s.as_slice())
        .filter(|s| !s.is_empty())
        .collect();
    forms.sort_by_key(|s| std::cmp::Reverse(s.len()));

    for form in forms {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if data.len() - i >= form.len() && &data[i..i + form.len()] == form {
                out.extend_from_slice(REDACTION_MARKER);
                i += form.len();
            } else {
                out.push(data[i]);
                i += 1;
            }
        }
        data = out;
    }
    data
}

/// Applies [`scrub_bytes`] to each header value, leaving names untouched.
fn scrub_header_pairs(
    pairs: Vec<(String, String)>,
    secrets: &[Zeroizing<Vec<u8>>],
) -> Vec<(String, String)> {
    pairs
        .into_iter()
        .map(|(name, value)| {
            let scrubbed = scrub_bytes(value.into_bytes(), secrets);
            // Header values are ASCII by construction (reqwest `to_str()`
            // succeeded above); lossy conversion is a safety net, not a path
            // that should alter bytes here.
            (name, String::from_utf8_lossy(&scrubbed).into_owned())
        })
        .collect()
}

// B-4 REMOVED: `redacted_error`, the runtime URL-stripping word filter that
// used to guard transport error text. It is gone because the text it filtered
// is gone: `InjectorError::Transport` now holds a classified `TransportError`
// whose `detail()` is a `&'static str`. There is nothing left to filter.

/// Builds the Authorization header value for the mechanism at hand.
///
/// Pure function so the credential-handling rules are unit-testable without
/// any network.
pub(crate) fn assemble_authorization(
    mechanism: &str,
    operation: &HttpOperation,
    secret: &SecretString,
) -> Result<HeaderValue, InjectorError> {
    match mechanism {
        "http-bearer" => {
            let value = format!("Bearer {}", secret.expose());
            HeaderValue::from_str(&value).map_err(|_| InjectorError::CredentialUnusable)
        }
        "http-basic" => {
            let username = operation.username.as_deref().ok_or_else(|| {
                InjectorError::BadOperation("http-basic requires a username field (D14)".to_owned())
            })?;
            if username.contains(':') {
                return Err(InjectorError::BadOperation(
                    "username must not contain ':' (RFC 7617)".to_owned(),
                ));
            }
            // RFC 7617: standard base64 WITH padding of "user:password".
            let combined = format!("{username}:{}", secret.expose());
            let encoded = base64::engine::general_purpose::STANDARD.encode(combined.as_bytes());
            // combined is dropped here; SecretString scrubbed by caller.
            drop(combined);
            HeaderValue::from_str(&format!("Basic {encoded}"))
                .map_err(|_| InjectorError::CredentialUnusable)
        }
        other => Err(InjectorError::BadOperation(format!(
            "{other:?} is not an http mechanism"
        ))),
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "simulated-vault-secret-never-a-real-key";

    #[test]
    fn bearer_header_carries_secret_exactly_once() {
        let op = HttpOperation {
            method: "GET".into(),
            headers: Default::default(),
            body_b64: None,
            username: None,
        };
        let s = SecretString::new(SECRET.to_owned());
        let hv = assemble_authorization("http-bearer", &op, &s).unwrap();
        assert_eq!(hv, format!("Bearer {SECRET}"));
    }

    #[test]
    fn basic_header_is_rfc7617_standard_base64() {
        let op = HttpOperation {
            method: "GET".into(),
            headers: Default::default(),
            body_b64: None,
            username: Some("deploy-bot".into()),
        };
        let s = SecretString::new(SECRET.to_owned());
        let hv = assemble_authorization("http-basic", &op, &s).unwrap();
        let expected = base64::engine::general_purpose::STANDARD
            .encode(format!("deploy-bot:{SECRET}").as_bytes());
        assert_eq!(hv, format!("Basic {expected}"));
    }

    #[test]
    fn basic_requires_username_and_rejects_colon() {
        let s = SecretString::new(SECRET.to_owned());
        let no_user = HttpOperation {
            method: "GET".into(),
            headers: Default::default(),
            body_b64: None,
            username: None,
        };
        assert!(assemble_authorization("http-basic", &no_user, &s).is_err());

        let colon_user = HttpOperation {
            method: "GET".into(),
            headers: Default::default(),
            body_b64: None,
            username: Some("bad:name".into()),
        };
        assert!(assemble_authorization("http-basic", &colon_user, &s).is_err());
    }

    #[test]
    fn non_http_mechanisms_rejected_here() {
        let op = HttpOperation {
            method: "GET".into(),
            headers: Default::default(),
            body_b64: None,
            username: None,
        };
        let s = SecretString::new(SECRET.to_owned());
        assert!(assemble_authorization("ssh", &op, &s).is_err());
        assert!(assemble_authorization("db-scram", &op, &s).is_err());
    }

    #[test]
    fn crlf_laden_credentials_cannot_inject_headers() {
        let op = HttpOperation {
            method: "GET".into(),
            headers: Default::default(),
            body_b64: None,
            username: None,
        };
        // A hostile vault entry attempting header injection via CRLF.
        let evil = SecretString::new("token\r\nX-Evil: injected".to_owned());
        assert!(
            matches!(
                assemble_authorization("http-bearer", &op, &evil),
                Err(InjectorError::CredentialUnusable)
            ),
            "CRLF credentials must be refused, not injected"
        );
    }

    // ---- B-4: type-level secret-free audit/error paths (S-3 option 2) ----
    //
    // S-3 option 1 (shipped) holds the line with a NORMATIVE SENTENCE plus a
    // sentinel test. B-4 makes the property STRUCTURAL: the constructors on the
    // audit/error path accept only reference-shaped facts, so response bytes are
    // unreachable by construction rather than by scrub.
    //
    // The philosophy is the licensing design's: "no `disable()` exists to call."
    // A test asserts a scrub works; a type asserts there is nothing to scrub.
    //
    // The two enforcement points this pins:
    //   1. `AuditEvent` accepts no field that can carry resolved credential or
    //      response bytes.
    //   2. `TransportError` (replacing `Transport(String)`) carries a CLASSIFIED
    //      DIAGNOSTIC, not a free-form string. The old filter was a runtime
    //      string filter. It stripped URLs in practice, but nothing prevented a
    //      caller from putting response bytes in an unfiltered field.

    #[test]
    fn transport_errors_cannot_carry_free_form_text() {
        // The structural pin. `TransportError` is built only from a closed set of
        // classified constructors, so there is no `Transport(String)` to fill with
        // whatever a transport error happened to stringify to.
        let e = crate::TransportError::ConnectionRefused;
        assert_eq!(e.detail(), "connection refused");
        // And it exposes no API to attach arbitrary text.
        assert!(
            !e.detail().contains("https://"),
            "classified diagnostics carry no URL: {}",
            e.detail()
        );
    }

    #[test]
    fn transport_error_variants_are_all_classified() {
        // Each variant's detail is a fixed literal. If this test needs updating
        // when a variant is added, that is the POINT: a new variant forces a
        // decision about what it may say.
        use crate::TransportError as T;
        let all = [
            T::ConnectionRefused,
            T::Timeout,
            T::TlsFailure,
            T::DnsFailure,
            T::BodyReadFailed,
            T::RequestBuildFailed,
        ];
        for e in &all {
            let d = e.detail();
            assert!(!d.is_empty(), "every classified error must say something");
            assert!(
                !d.contains("://") && !d.contains('/'),
                "no classified diagnostic may embed a path or URL: {d:?}"
            );
            assert!(d.len() <= 40, "classified diagnostics stay short: {d:?}");
        }
        // Distinct variants must be distinguishable in the audit chain.
        let rendered: Vec<&str> = all.iter().map(|e| e.detail()).collect();
        for (i, a) in rendered.iter().enumerate() {
            for (j, b) in rendered.iter().enumerate() {
                assert!(i == j || a != b, "variants {i}/{j} collide: {a}");
            }
        }
    }

    #[test]
    fn injector_error_displays_only_classified_text() {
        // The Display path is what reaches the agent as an error string, so it is
        // the boundary that matters. A Transport error built from a classified
        // diagnostic can only render that diagnostic.
        let e = crate::InjectorError::Transport(crate::TransportError::Timeout);
        let shown = e.to_string();
        assert!(
            shown.contains("timed out") || shown.contains("timeout"),
            "classified timeout must render recognizably: {shown}"
        );
    }

    // ---- B-4 structural pin ----

    /// B-4's guarantee, expressed as a type fact rather than a string check:
    /// `InjectorError::Transport` accepts a `TransportError`, and
    /// `TransportError` is a closed enum with no payload. There is no
    /// constructor anywhere that accepts free-form text, so the class of bug
    /// "someone formats response bytes into an error and logs it" is not
    /// representable rather than merely discouraged.
    ///
    /// The compile-fail evidence: attempting
    /// `InjectorError::Transport("reflected-secret")` is rejected by rustc with
    /// `expected TransportError, found &str`. Verified by running that exact
    /// probe during implementation.
    #[test]
    fn transport_variant_has_no_string_payload() {
        // A function that would be required to construct a Transport error from
        // arbitrary text does not exist and cannot be written.
        fn accepts_only_classes(e: crate::InjectorError) -> &'static str {
            match e {
                crate::InjectorError::Transport(t) => t.detail(),
                _ => "not a transport error",
            }
        }
        // Every transport error's rendered detail is a 'static str: no borrow of
        // caller-supplied data can survive.
        let d: &'static str = accepts_only_classes(crate::InjectorError::Transport(
            crate::TransportError::ConnectionRefused,
        ));
        assert_eq!(d, "connection refused");
    }

    // ---- P0-1: reflected-credential scrub ----

    #[test]
    fn scrub_removes_raw_secret_from_body_and_headers() {
        let secret = Zeroizing::new(b"s3cr3t-sentinel-value".to_vec());
        let forms = vec![secret];
        let body = br#"{"echo":"s3cr3t-sentinel-value","ok":true}"#.to_vec();
        let cleaned = scrub_bytes(body, &forms);
        let text = String::from_utf8(cleaned).unwrap();
        assert!(!text.contains("s3cr3t-sentinel-value"), "{text}");
        assert!(text.contains("[REDACTED-CREDENTIAL]"), "{text}");
        assert!(
            text.contains("\"ok\":true"),
            "non-secret bytes kept: {text}"
        );

        let pairs = vec![(
            "www-authenticate".to_owned(),
            "Bearer s3cr3t-sentinel-value".to_owned(),
        )];
        let scrubbed = scrub_header_pairs(pairs, &forms);
        assert!(
            !scrubbed[0].1.contains("s3cr3t-sentinel-value"),
            "{:?}",
            scrubbed[0]
        );
        assert_eq!(scrubbed[0].0, "www-authenticate", "header name untouched");
    }

    #[test]
    fn scrub_catches_basic_base64_form_via_auth_value() {
        // A reflecting target echoes the Authorization VALUE, which for
        // http-basic is `Basic <b64(user:secret)>` — the raw secret bytes are
        // NOT present. Scrubbing the assembled value catches it.
        let secret = SecretString::new("pw-sentinel".to_owned());
        let op = HttpOperation {
            method: "GET".into(),
            headers: Default::default(),
            body_b64: None,
            username: Some("deploy-bot".into()),
        };
        let auth = assemble_authorization("http-basic", &op, &secret).unwrap();
        let auth_bytes = auth.as_bytes().to_vec();
        let forms = vec![Zeroizing::new(auth_bytes)];

        // Body reflects exactly what the target received in the header.
        let reflected = format!("you sent: {}", auth.to_str().unwrap());
        let cleaned = scrub_bytes(reflected.into_bytes(), &forms);
        let text = String::from_utf8(cleaned).unwrap();
        assert!(!text.contains(auth.to_str().unwrap()), "{text}");
        assert!(text.contains("[REDACTED-CREDENTIAL]"), "{text}");
    }

    #[test]
    fn scrub_handles_multiple_and_adjacent_occurrences() {
        let secret = Zeroizing::new(b"AA".to_vec());
        let forms = vec![secret];
        let cleaned = scrub_bytes(b"xAAAAy".to_vec(), &forms); // "AA""AA"
        let text = String::from_utf8(cleaned).unwrap();
        assert_eq!(text, "x[REDACTED-CREDENTIAL][REDACTED-CREDENTIAL]y");
    }

    #[test]
    fn scrub_is_noop_when_secret_absent() {
        let secret = Zeroizing::new(b"needle".to_vec());
        let forms = vec![secret];
        let body = b"nothing to see here".to_vec();
        let cleaned = scrub_bytes(body.clone(), &forms);
        assert_eq!(cleaned, body);
    }
}
