//! Chaperone audit chain.
//!
//! Every terminal outcome appends one signed, hash-chained record
//! (PROTO-SPEC §9.3, ARCH-SPEC §2.8): the full signed intent as evidence,
//! the decision and who/what confirmed it, the `cred_ref` used — never the
//! secret — plus mechanism, target, timing, and outcome.
//!
//! Tamper-evidence: each record carries its predecessor's hash and a gateway
//! signature, so deletion or modification breaks the chain and is detectable.
//! Write-only from inside the gateway; verification and export are operator
//! functions ([`verify::verify_file`], CLI `chaperone audit-*`).
//!
//! Layer contract (ARCH-SPEC §1.1): every layer writes in; nothing reads it
//! back internally; records hold references only. The no-secret property is
//! structural: no API here accepts credential material.
//!
//! Encoding: DESIGN-DECISIONS D7. Honest limit: tail truncation is not
//! detectable from inside the file (D18) - monitor the head hash externally.

pub mod event;
mod keys;
mod verify;
mod writer;

pub use event::{AuditEvent, Outcome, RecordKind};
pub use keys::{AuditKey, verifying_key_from_b64url};
pub use verify::{Break, Report, Tail, verify_file};
pub use writer::{AuditError, AuditWriter, CHAIN_VERSION, Head, compute_hash, hex, unhex};
