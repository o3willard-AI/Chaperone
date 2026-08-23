//! Chaperone vault abstraction.
//!
//! A uniform interface over heterogeneous secret backends (ARCH-SPEC §2.4):
//! a `cred_ref` URI names a backend and path; the configured provider driver
//! resolves it, requesting the narrowest, shortest-lived credential the
//! backend can mint. Includes the built-in encrypted local vault (`local://`),
//! sealed to the platform key store, so the system works with no external
//! dependency.
//!
//! This layer also implements the ephemerality contract (ARCH-SPEC §2.9):
//! fetch late, hold minimally in zeroize-on-drop buffers, scrub always on
//! success or failure, re-fetch fresh on every retry. Caching a secret to
//! smooth a retry is prohibited here and everywhere downstream.
//!
//! Layer contract (ARCH-SPEC §1.1): injectors depend on its handle type;
//! the policy engine never touches it.
//!
//! Implementation lands in PLAN Phase 5 ([PLAN](../../docs/PLAN.md) M5).

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        // Replaced by zeroize/re-fetch acceptance tests in Phase 5.
    }
}
