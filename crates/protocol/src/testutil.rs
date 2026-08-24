//! Test-only signing helpers (feature `test-util`).
//!
//! Real agents never handle private keys - their platform key stores sign
//! (PROTO-SPEC §4.1). These helpers exist for integration tests and the
//! conformance suite, which must construct valid signed intents without a
//! key-store service.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

/// Signs `envelope` in place over its canonical form, exactly as a
/// well-behaved agent would.
#[allow(clippy::expect_used)] // test utility: panicking IS the failure signal
pub fn sign_envelope(key: &SigningKey, envelope: &mut Value) {
    use crate::canonical_form;
    let canonical = canonical_form(envelope).expect("test envelope must canonicalize");
    let sig = key.sign(&canonical);
    envelope["sig"] = serde_json::json!(crate::encode_signature(&sig.to_bytes()));
}
