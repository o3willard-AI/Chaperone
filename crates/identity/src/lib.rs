//! Chaperone identity and attestation.
//!
//! The load-bearing layer (PROTO-SPEC §4, ARCH-SPEC §2.2): resolves
//! `agent_id` to an enrolled public key, checks freshness and the replay
//! cache, verifies the Ed25519 signature over the JCS-canonical envelope,
//! and only then admits the mechanism body.
//!
//! Layer contract (ARCH-SPEC §1.1): depends on the enrollment key store;
//! never touches vault secrets or injectors.
//!
//! Implementation lands in PLAN Phase 2 ([PLAN](../../docs/PLAN.md) M2).

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        // Replaced by verification-order tests in Phase 2.
    }
}
