# Chaperone — Implementation Plan

This is the working breakdown derived from [IMPLEMENTATION_AGENT_BRIEF.md](IMPLEMENTATION_AGENT_BRIEF.md)
§5. Each phase states its goal, the spec sections it implements, the acceptance
tests that prove it, and the security rules from Brief §3 it must uphold.

> **Tracking note:** this file is the canonical text. On GitHub, each phase maps
> 1:1 to a milestone (M0–M11) and to **one tracking issue** carrying that phase's
> checklist as a task list — granular enough to track, coarse enough to survive
> refinement as implementation details land. Spec discrepancies live as separate
> issues labeled `spec-drift`, mirroring [SPEC-ISSUES.md](SPEC-ISSUES.md).

**Organizing principle:** build the security spine before the conveniences.
Identity, policy, and audit come *before* the first working injector.

Legend for "Rules": **NS** = No secret in agent space · **DD** = Default-deny ·
**AA** = Attribution before action · **SF** = Secure fragility / re-fetch on retry ·
**NC** = Channel persists, secret never reused · **LP** = Least-privilege time-boxed ·
**OG** = One gate well-placed · **IP** = Isolate privilege ·
**TCB** = Gateway is TCB; defend everything else honestly.

---

## Phase 0 — Repository and project scaffolding *(milestone: M0)*

- [x] Cargo workspace with crate boundaries: `protocol`, `gateway-core`,
      `transport`, `identity`, `policy`, `vault`, `injectors`, `audit`,
      `privileged-helper`, `cli` (see [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) D1).
- [x] Specs under `docs/` (already present) linked from README.
- [x] CI from the very first commit: build + test + clippy + rustfmt + `cargo audit`.
- [x] README stating what Chaperone is, linking specs, honest pre-release status.
- [x] CONTRIBUTING, SECURITY.md (vulnerability reporting), `.gitignore`,
      pinned toolchain (`rust-toolchain.toml`), committed `Cargo.lock`
      (reproducible-build posture, minimal).

**Spec sections:** Brief §4/§5; ARCH-SPEC §1.1 (crate boundaries mirror layers).
**Acceptance:** fresh clone builds and tests green locally and in CI.
**Rules:** all rules are structurally respected by boundaries; nothing to test yet.

## Phase 1 — Transport and message framing *(M1)*

Goal: local channel + Content-Length-framed JSON envelope; no auth yet.

- [ ] UDS listener, owner-only perms (`0600`), default path
      `$XDG_RUNTIME_DIR/chaperone/gw.sock`; named-pipe equivalent on Windows;
      loopback TCP fallback behind explicit config only.
- [ ] Frame codec: `Content-Length: N\r\n\r\n` + N bytes UTF-8 JSON; max-frame guard.
- [ ] Unary request/response loop with `msg_id` echo.

**Spec sections:** PROTO-SPEC §3; ARCH-SPEC §2.1, §4.2–4.3.
**Acceptance:** test client round-trips a framed message over UDS; non-owner
cannot open the socket; oversized frame rejected cleanly.
**Rules:** TCB (transport makes no trust decisions).

## Phase 2 — Identity and attestation *(M2)*

Goal: the security spine begins. Ed25519 + JCS + exact verification sequence.

- [ ] Ed25519 verification; JCS (RFC 8785) canonicalization of envelope minus `sig`.
- [ ] Verification order enforced literally: resolve agent → freshness/replay →
      signature → *only then* parse body; stop at first failure.
- [ ] Replay cache covering ≥ freshness window (±30 s default skew); RFC 3339 UTC parsing.
- [ ] Enrollment store (public keys; operator action via minimal CLI).
- [ ] Revocation effective immediately.

**Spec sections:** PROTO-SPEC §4, §5, §10.1 (E_UNKNOWN_AGENT/E_REPLAY/E_BAD_SIGNATURE); ARCH-SPEC §2.2.
**Acceptance:** signed fresh intent verifies; forged / stale / replayed /
wrong-agent intent rejected with correct error **before any body parsing**
(proven by tests that assert body-parse side effects did not occur).
**Rules:** NS, AA, TCB.

## Phase 3 — Policy engine, default-deny *(M3)*

Goal: the decision layer that makes this an authority, not a proxy.

- [ ] Total, side-effect-free evaluation: agent × cred_ref × target × operation
      (+ optional constraints later); emits exactly one verdict:
      allow / deny / needs_confirmation.
- [ ] Explicit rule representation (see DESIGN-DECISIONS D3); default-deny when
      no rule matches; explicit deny supported.
- [ ] Constraints can only narrow (min of agent-declared and policy-declared limits).

**Spec sections:** PROTO-SPEC §5.1 (constraints note), §9.1; ARCH-SPEC §2.3; THREAT-MODEL §2.1 (T1 elevation), §3.
**Acceptance:** unlisted request → deny; explicitly allowed → allow; evaluation
provably never touches vault (test with a vault handle that counts calls).
**Rules:** DD, OG (verdict only; gate itself is Phase 7), TCB.

## Phase 4 — Audit chain *(M4)*

Goal: tamper-evident evidence.

- [ ] Append-only, hash-chained records: full signed intent as evidence, decision,
      confirmer identity, cred_ref (never secret), mechanism, target, timing, outcome.
- [ ] Chain: each record carries predecessor hash; gateway-signed records.
- [ ] Verify/export as operator CLI functions (write-only from inside the gateway).

**Spec sections:** PROTO-SPEC §9.3; ARCH-SPEC §2.8; THREAT-MODEL §6 (detection row).
**Acceptance:** a run produces a verifiable chain; any edit/deletion breaks
verification; fuzz/grep-style test asserts no secret material ever appears in records.
**Rules:** NS (records hold references only), AA, TCB.

## Phase 5 — Vault abstraction + built-in local vault *(M5)*

Goal: provider interface + zero-dependency usable store; ephemerality contract lands here.

- [ ] Provider trait; `cred_ref` scheme dispatch (`local://` in v1; `vault://` etc. shaped but not shipped).
- [ ] Built-in encrypted local vault: user-only CRUD, sealed to platform key store
      (kernel keyring / Keychain / DPAPI); software fallback per D5.
- [ ] Least-privilege/short-lived minting path where backend supports it.
- [ ] Ephemerality contract (ARCH §2.9): fetch-late, hold-minimally (zeroize-on-drop),
      scrub-always on success AND failure, re-fetch-on-retry; no cache anywhere.

**Spec sections:** ARCH-SPEC §2.4, §2.9; THREAT-MODEL §1.3, §5.2; PROTO-SPEC §6.1 step 5.
**Acceptance:** cred_ref resolves; secret zeroized after use on both paths; retry
re-fetches (test asserts two vault calls, no cache hit); no cache survives restart.
**Rules:** SF, NC, LP, NS.

## Phase 6 — First injector: `http` one-shot end-to-end *(M6)*

Goal: first full path with all spine components in place — and not before.

- [ ] `http-bearer`/`http-basic`: attach Authorization, re-originate TLS to real
      target, return status/headers/body honoring `max_response_bytes` + timeouts.
- [ ] Full path: signed intent → verify → policy → (confirm hook) → fetch → inject
      → result → audit.
- [ ] Hostile-target defenses: output treated as untrusted data; size/time caps.

**Spec sections:** PROTO-SPEC §6.1, §7.1; ARCH-SPEC §2.5, §3.1; THREAT-MODEL §2.3 (T3).
**Acceptance:** real authenticated HTTPS call succeeds with no secret in
agent-visible I/O or logs (asserted by capture-layer test); denied intent never
fetches (vault call-count == 0); oversized/malformed responses handled safely.
**Rules:** NS, DD, AA, SF, LP, TCB.

## Phase 7 — The single confirmation gate *(M7)*

Goal: one human gate, owned by the gateway, at injection time.

- [ ] On `needs_confirmation`: surface ONE prompt via operator channel with full
      context (target label, agent_id, mechanism, operation summary).
- [ ] Approval proceeds; denial/timeout → `E_CONFIRM_TIMEOUT`; no duplicate prompts;
      agent-side prompting explicitly not required (skill already teaches this).

**Spec sections:** PROTO-SPEC §9.2; ARCH-SPEC §2.6; THREAT-MODEL §3 (property 4), §4 (fatigue tension).
**Acceptance:** needs_confirmation intent blocks on exactly one prompt; approve →
proceeds; deny/timeout → correct error; concurrent duplicate intents do not double-prompt.
**Rules:** OG, DD, TCB.

## Phase 8 — Sessions: `db-scram` and `ssh` *(M8)*

Goal: brokered-session lifecycle proving secret-vs-channel distinction.

- [ ] Session establishment → `session_handle` + TTL; credential completes one
      handshake then scrubbed; channel persists, driven by handle.
- [ ] Independently-signed owner-bound session frames (`session.command/close`);
      full §4 verification on every frame.
- [ ] Streaming `session.output`, seq-ordered; `session.closed` with final audit_id;
      teardown on close/TTL/drop.

**Spec sections:** PROTO-SPEC §6.2, §7 (db-scram/ssh rows), §8; ARCH-SPEC §2.5, §2.9 (secret vs channel), §3.2.
**Acceptance:** multi-command SSH session runs; frame signed by other identity →
`E_SESSION_OWNER`; expired/unknown handle → `E_SESSION_EXPIRED`; secret re-transmit
count across session lifetime == 0 (wire-capture test).
**Rules:** NC, SF, NS, AA, LP.

## Phase 9 — Privileged helper: `local-privilege` *(M9)*

Goal: separate elevated process; never in the network path.

- [ ] Helper process sharing vault+policy+audit core, NOT network-injection code path
      (separate binary/crate boundary; authenticated local channel daemon↔helper).
- [ ] Always single deliberate confirmation; unattended only vs operator-defined,
      argument-pinned allowlist.
- [ ] Platform authorization: polkit (Linux), launchd-authorized (macOS), service+UAC (Windows).

**Spec sections:** PROTO-SPEC §7.2; ARCH-SPEC §2.7; THREAT-MODEL §2.5 (T6), §6 (helper row).
**Acceptance:** allowlisted command runs with confirmation; non-allowlisted denied;
fault-injected network injector cannot invoke helper (cross-path test);
no root code in main daemon path.
**Rules:** IP, OG, DD, LP.

## Phase 10 — Hardening and high-assurance *(M10)*

Goal: make the TCB handoffs real controls.

- [ ] Reproducible builds verified byte-for-byte from source; signed releases.
- [ ] Optional hardware-backed mode as install switch (TPM/Secure Enclave/HSM/enclave);
      software-only default preserved.
- [ ] Supply-chain checks in CI (cargo audit + cargo-deny style checks, locked deps).
- [ ] Threat Model §5 controls filled in as testable artifacts.

**Spec sections:** THREAT-MODEL §5 (all), §1.2 handoffs; ARCH-SPEC §4.4; Brief §3 TCB bullet.
**Acceptance:** third party reproduces release binary; enclave mode (where available)
keeps secrets out of introspectable memory; CI blocks on advisory matches.
**Rules:** TCB, SF (enclave composes with ephemerality per ARCH §4.4).

## Phase 11 — Conformance, fuzzing, agent-facing loop *(M11)*

Goal: prove the contract, break it before anyone else does.

- [ ] Protocol conformance suite runnable against any client incl. packaged skill.
- [ ] Fuzzing: envelope parser, framing codec, injectors (malformed intents; hostile
      target responses T3). No panics, no secret leaks.
- [ ] Validate shipped Agent Skill examples run end-to-end against gateway.

**Spec sections:** PROTO-SPEC (whole, as oracle); AGENT-SKILL validation table; THREAT-MODEL §2.3.
**Acceptance:** conformance suite passes; fuzzing clean; skill worked examples
(the four prompts in AGENT-SKILL §Validation) pass end-to-end.
**Rules:** every §3 rule has a guarding test by now — gaps are release blockers.

---

## Definition of done (v1)

Brief §7 verbatim as the bar: working cross-platform Rust gateway accepting signed
intents over a local socket; identity verified before anything else; default-deny
policy; four v1 mechanisms across both lifecycles; single confirmation gate;
tamper-evident secret-free audit chain; ephemerality contract everywhere; isolated
privileged helper; software-only ship with optional enclave mode; conformance suite
the Agent Skill examples pass against; CI green; every §3 rule test-guarded.
