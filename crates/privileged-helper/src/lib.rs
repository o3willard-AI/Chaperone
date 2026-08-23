//! Chaperone privileged helper.
//!
//! A deliberately separate subsystem (ARCH-SPEC §2.7): privilege escalation
//! is "run this as root", not "attach a secret to a request". It runs in a
//! separate elevated process — polkit-authorized on Linux, launchd-authorized
//! on macOS, an equivalent service on Windows — sharing the vault + policy +
//! audit core but NOT the network-injection code path.
//!
//! It always takes the single deliberate human confirmation, and runs
//! unattended only against an operator-defined, argument-pinned allowlist.
//! Isolation guarantees that a compromise of any network injector cannot
//! reach root.
//!
//! Implementation lands in PLAN Phase 9 ([PLAN](../../docs/PLAN.md) M9).

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        // Replaced by allowlist/isolation acceptance tests in Phase 9.
    }
}
