//! Chaperone mechanism injectors.
//!
//! One module per mechanism (ARCH-SPEC §2.5): an injector receives a resolved
//! credential handle (never a raw secret outside its own scope) plus the
//! operation body and completes the mechanism on the outbound side.
//!
//! Injectors are the ONLY components that touch secret material, and each
//! touches only its own (ARCH-SPEC §1 invariant). Compiled-in for v1 behind
//! a stable internal ABI (`prepare` / `inject` / `teardown`).
//!
//! Layer contract (ARCH-SPEC §1.1): depends on the vault handle and the
//! policy decision; never on signing keys or other injectors.
//!
//! Implementation lands in PLAN Phases 6–9 ([PLAN](../../docs/PLAN.md)
//! M6–M9), http first.

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        // Replaced by end-to-end injector tests from Phase 6 onward.
    }
}
