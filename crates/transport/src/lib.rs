//! Chaperone local transport edge.
//!
//! Owns the local channel and message framing (PROTO-SPEC §3,
//! ARCH-SPEC §2.1): Unix domain socket by default (owner-only `0600`),
//! named pipe on Windows, loopback TCP only as an explicit fallback.
//! Frames are `Content-Length`-prefixed JSON blocks (LSP-style).
//!
//! Layer contract (ARCH-SPEC §1.1): depends on nothing internal; performs no
//! trust decisions — an authenticated socket peer is still unauthenticated
//! until the identity layer verifies its signature.
//!
//! Implementation lands in PLAN Phase 1 ([PLAN](../../docs/PLAN.md) M1).

#[cfg(test)]
mod tests {
    #[test]
    fn harness() {
        // Placeholder so CI proves the test harness links on every platform
        // from day one. Replaced by framing codec tests in Phase 1.
    }
}
