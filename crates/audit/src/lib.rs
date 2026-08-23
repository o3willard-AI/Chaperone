//! Chaperone audit chain.
//!
//! Every terminal outcome appends one signed, hash-chained record
//! (PROTO-SPEC §9.3, ARCH-SPEC §2.8): the full signed intent as evidence,
//! the decision and who/what confirmed it, the `cred_ref` used — never the
//! secret — plus mechanism, target, timing, and outcome.
//!
//! Tamper-evidence: each record carries its predecessor's hash, so deletion
//! or modification breaks the chain and is detectable. Write-only from
//! inside the gateway; reading and export are operator functions.
//!
//! Layer contract (ARCH-SPEC §1.1): every layer writes in; nothing reads
//! it back internally; records hold references only.
//!
//! Implementation lands in PLAN Phase 4 ([PLAN](../../docs/PLAN.md) M4).

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        // Replaced by chain-integrity and no-secret-in-records tests in Phase 4.
    }
}
