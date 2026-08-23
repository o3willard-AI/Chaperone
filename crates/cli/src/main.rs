//! Chaperone operator CLI.
//!
//! Operator actions live here, out of the request path (ARCH-SPEC §2.2):
//! agent-key enrollment, policy authoring, local-vault CRUD, audit-chain
//! verification and export. The gateway daemon binary arrives with Phase 1.
//!
//! Implementation grows from PLAN Phases 2–5 ([PLAN](../../docs/PLAN.md)).

fn main() {
    // Phase 0 stub: prove the workspace links a binary against the protocol
    // contract. Subcommands land with their phases (enrollment first).
    println!(
        "chaperone operator CLI (protocol {})",
        chaperone_protocol::PROTOCOL_VERSION
    );
}
