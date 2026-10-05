//! Chaperone mechanism injectors.
//!
//! One module per mechanism (ARCH-SPEC §2.5). An injector receives a
//! [`chaperone_vault::SecretString`] handle plus the verified operation and
//! completes the mechanism on the outbound side. Injectors are the ONLY
//! components that touch secret material, and each touches only its own.
//!
//! Layer contract (ARCH-SPEC §1.1): depends on the vault handle type and the
//! policy decision; never on signing keys or other injectors. Compiled-in
//! for v1; the prepare/inject/teardown plugin ABI arrives later (ARCH §2.5).
//!
//! Implemented in PLAN Phase 6 ([PLAN](../../docs/PLAN.md) M6): `http`.
//! `ssh` / `db-scram` / `local-privilege` land in M8/M9.

pub mod http;

/// A transport failure, described by CLASS rather than by text.
///
/// B-4 (S-3 option 2). This type exists to remove `Transport(String)`.
///
/// The previous shape carried whatever the HTTP client's error happened to
/// stringify to, and relied on a runtime word filter - to
/// strip URLs before the text reached an audit record or an agent-visible
/// error. That filter is a mitigation, not a guarantee: it works on the strings
/// it has seen, and nothing stops a future caller from putting bytes that do
/// not match its pattern into the field. A test asserts the filter works; a
/// type asserts there is nothing to filter.
///
/// So the error carries a closed set of classes. Each renders a fixed literal
/// chosen at the call site, never derived from a URL, a header, or a response
/// body. `detail()` is the only accessor, and it returns a `&'static str` - there
/// is no API for attaching text to it.
///
/// Adding a variant is deliberately a decision: it forces an author to choose
/// wording that cannot carry target-controlled data. Pinned by
/// `transport_error_variants_are_all_classified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// The peer refused the connection.
    ConnectionRefused,
    /// The request exceeded its deadline.
    Timeout,
    /// The TLS handshake or certificate validation failed.
    TlsFailure,
    /// The hostname did not resolve.
    DnsFailure,
    /// The response body could not be read to completion.
    BodyReadFailed,
    /// The request could not be constructed.
    RequestBuildFailed,
    /// An internal record could not be appended to the audit chain.
    ///
    /// B-4: added when the gateway's startup audit-append failure was found
    /// misfiled under `BodyReadFailed`. That looked locally plausible and was
    /// operator-misleading: "response body unreadable" describes an outbound
    /// read, not a failed genesis write. A classified vocabulary is only useful
    /// if each class names what actually happened.
    AuditAppendFailed,
}

impl TransportError {
    /// The fixed, operator-legible text for this class.
    ///
    /// `&'static str` by construction: a caller cannot widen this to include
    /// target-controlled bytes.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            TransportError::ConnectionRefused => "connection refused",
            TransportError::Timeout => "timed out",
            TransportError::TlsFailure => "TLS failure",
            TransportError::DnsFailure => "host not resolved",
            TransportError::BodyReadFailed => "response body unreadable",
            TransportError::RequestBuildFailed => "request could not be built",
            TransportError::AuditAppendFailed => "audit record could not be appended",
        }
    }

    /// Classifies a client error into one of the fixed buckets.
    ///
    /// The classification deliberately reads only the error's KIND and status,
    /// never its message: the message is where URLs and other target-influenced
    /// text live, which is exactly what must not survive.
    #[must_use]
    pub fn classify(e: &reqwest::Error) -> Self {
        if e.is_timeout() {
            TransportError::Timeout
        } else if e.is_connect() {
            TransportError::ConnectionRefused
        } else if e.is_body() || e.is_decode() {
            TransportError::BodyReadFailed
        } else if e.is_builder() || e.is_request() {
            TransportError::RequestBuildFailed
        } else {
            TransportError::TlsFailure
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

/// Why an injection failed (PROTO-SPEC `E_MECHANISM` territory).
#[derive(Debug)]
#[non_exhaustive]
pub enum InjectorError {
    /// The operation was structurally invalid for this mechanism.
    BadOperation(String),
    /// The credential could not be attached (e.g. non-header-safe bytes).
    CredentialUnusable,
    /// The outbound call failed at transport level. B-4: carries a CLASS, not
    /// free-form text.
    Transport(TransportError),
    /// The target's response violated a ceiling (T3 defenses).
    ResponseTooLarge {
        /// The cap that was exceeded, bytes.
        limit: u64,
    },
}

impl std::fmt::Display for InjectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectorError::BadOperation(e) => write!(f, "invalid operation: {e}"),
            InjectorError::CredentialUnusable => {
                write!(f, "credential cannot be attached to this request")
            }
            InjectorError::Transport(e) => write!(f, "outbound call failed: {e}"),
            InjectorError::ResponseTooLarge { limit } => {
                write!(f, "response exceeded the {limit}-byte ceiling")
            }
        }
    }
}

impl std::error::Error for InjectorError {}
