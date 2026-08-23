//! Chaperone policy engine.
//!
//! The component that makes the gateway an authority rather than a proxy
//! (ARCH-SPEC §2.3): evaluates each verified intent against the four axes —
//! agent × cred_ref × target × operation — and emits exactly one verdict:
//! allow / deny / needs_confirmation.
//!
//! Invariants: default-deny (absent an explicit allow, deny); total (every
//! intent yields a verdict); side-effect-free (evaluation never mints or
//! touches a secret).
//!
//! Implementation lands in PLAN Phase 3 ([PLAN](../../docs/PLAN.md) M3).

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        // Replaced by default-deny acceptance tests in Phase 3.
    }
}
