# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** via
[GitHub private vulnerability reporting]
(https://github.com/o3willard-AI/Chaperone/security/advisories/new) for this
repository.

Do **not** open a public issue, pull request, or discussion for anything you
believe is exploitable.

Include what you can of: affected component/crate, version or commit, a
minimal reproduction or proof of concept, impact assessment, and any known
mitigations. Please keep findings confidential until a fix is released and a
disclosure is coordinated with you.

You will receive an acknowledgment promptly and a status update as triage
proceeds. Coordinated disclosure is the default; we will credit reporters who
wish to be credited.

## Scope

In scope:

- The gateway daemon, privileged helper, CLI, and all workspace crates.
- The wire protocol as implemented (`chaperone` protocol `0.x`), including
  identity verification, policy evaluation, vault resolution, injectors, and
  the audit chain.
- The packaged agent skill, where it could induce unsafe behavior.

Out of scope (see the [Threat Model](docs/03-threat-model.md) §1.2 and §5 for
the reasoning):

- A subverted gateway binary or compromised build pipeline — defended by
  supply-chain controls (reproducible builds, signed releases), not by the
  running code.
- Root-level local attackers. The gateway is user-space software; root owns
  the machine. We reduce blast radius (short-lived secrets, zeroize-on-drop,
  optional hardware backing) but do not claim defense.
- Misuse of legitimately granted credentials by their holder.

The trusted computing base is stated plainly in the Threat Model; reports that
demonstrate the TCB boundary itself being crossed are exactly what we want.

## Supported versions

Pre-release: only the latest tagged preview and `main` receive security
fixes.

**Artifact trust boundary, stated plainly:** release binaries carry our
ed25519 detached signatures and reproduce bit-for-bit from source, but they
are NOT signed with corporate OS code-signing certificates yet (no entity to
own those). On macOS/Windows expect Gatekeeper/SmartScreen prompts - verify
via [docs/RELEASE.md](docs/RELEASE.md) instead of clicking through.

## Hardening commitments

Dependency advisories (`cargo audit`) run in CI on every change and weekly;
builds are locked (`--locked`) and the toolchain is pinned. Reproducible
releases are tracked in [docs/PLAN.md](docs/PLAN.md) Phase 10.
