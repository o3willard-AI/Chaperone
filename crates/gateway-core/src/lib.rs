//! Chaperone gateway orchestration core.
//!
//! Owns the end-to-end request sequence shared by both lifecycles
//! (ARCH-SPEC §3): identity verification -> policy decision ->
//! (single confirmation) -> vault resolution -> injection -> audit record.
//!
//! Layer contract (ARCH-SPEC §1.1): depends inward on identity, policy,
//! injectors, vault, and audit; never on transport.
//!
//! Implementation lands in PLAN Phase 2+ ([PLAN](../../docs/PLAN.md) M2).
