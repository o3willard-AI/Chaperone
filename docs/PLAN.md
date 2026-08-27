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

- [x] UDS listener, owner-only perms (`0600`), default path
      `$XDG_RUNTIME_DIR/chaperone/gw.sock`; named-pipe equivalent on Windows;
      loopback TCP fallback behind explicit config only (type-constrained to
      127.0.0.1 / ::1).
- [x] Frame codec: `Content-Length: N\r\n\r\n` + N bytes UTF-8 JSON; hard
      8 MiB max-frame guard checked before body read (D10).
- [x] Unary request/response loop with transport-owned `msg_id` echo.

**Spec sections:** PROTO-SPEC §3; ARCH-SPEC §2.1, §4.2–4.3.
**Acceptance:** test client round-trips a framed message over UDS; non-owner
cannot open the socket; oversized frame rejected cleanly.
**Rules:** TCB (transport makes no trust decisions).

## Phase 2 — Identity and attestation *(M2)*

Goal: the security spine begins. Ed25519 + JCS + exact verification sequence.

- [x] Ed25519 verification; JCS (RFC 8785) canonicalization of envelope minus `sig`.
- [x] Verification order enforced literally: resolve agent → freshness/replay →
      signature → *only then* parse body; stop at first failure.
- [x] Replay cache covering ≥ freshness window (±30 s default skew); RFC 3339 UTC parsing.
- [x] Enrollment store (public keys; operator action via minimal CLI).
- [x] Revocation effective immediately.

**Spec sections:** PROTO-SPEC §4, §5, §10.1 (E_UNKNOWN_AGENT/E_REPLAY/E_BAD_SIGNATURE); ARCH-SPEC §2.2.
**Acceptance:** signed fresh intent verifies; forged / stale / replayed /
wrong-agent intent rejected with correct error **before any body parsing**
(proven by tests that assert body-parse side effects did not occur).
**Rules:** NS, AA, TCB.

## Phase 3 — Policy engine, default-deny *(M3)*

Goal: the decision layer that makes this an authority, not a proxy.

- [x] Total, side-effect-free evaluation: agent × cred_ref × target × operation
      (+ optional constraints later); emits exactly one verdict:
      allow / deny / needs_confirmation.
- [x] Explicit rule representation (see DESIGN-DECISIONS D3); default-deny when
      no rule matches; explicit deny supported.
- [x] Constraints can only narrow (min of agent-declared and policy-declared limits).

**Spec sections:** PROTO-SPEC §5.1 (constraints note), §9.1; ARCH-SPEC §2.3; THREAT-MODEL §2.1 (T1 elevation), §3.
**Acceptance:** unlisted request → deny; explicitly allowed → allow; evaluation
provably never touches vault (test with a vault handle that counts calls).
**Rules:** DD, OG (verdict only; gate itself is Phase 7), TCB.

## Phase 4 — Audit chain *(M4)*

Goal: tamper-evident evidence.

- [x] Append-only, hash-chained records: full signed intent as evidence, decision,
      confirmer identity, cred_ref (never secret), mechanism, target, timing, outcome.
- [x] Chain: each record carries predecessor hash; gateway-signed records.
- [x] Verify/export as operator CLI functions (write-only from inside the gateway).

**Spec sections:** PROTO-SPEC §9.3; ARCH-SPEC §2.8; THREAT-MODEL §6 (detection row).
**Acceptance:** a run produces a verifiable chain; any edit/deletion breaks
verification; fuzz/grep-style test asserts no secret material ever appears in records.
**Rules:** NS (records hold references only), AA, TCB.

## Phase 5 — Vault abstraction + built-in local vault *(M5)*

Goal: provider interface + zero-dependency usable store; ephemerality contract lands here.

- [x] Provider trait; `cred_ref` scheme dispatch (`local://` in v1; `vault://` etc. shaped but not shipped).
- [x] Built-in encrypted local vault: user-only CRUD, sealed to platform key store
      (kernel keyring / Keychain / DPAPI); software fallback per D5.
- [x] Least-privilege/short-lived minting path where backend supports it.
- [x] Ephemerality contract (ARCH §2.9): fetch-late, hold-minimally (zeroize-on-drop),
      scrub-always on success AND failure, re-fetch-on-retry; no cache anywhere.

**Spec sections:** ARCH-SPEC §2.4, §2.9; THREAT-MODEL §1.3, §5.2; PROTO-SPEC §6.1 step 5.
**Acceptance:** cred_ref resolves; secret zeroized after use on both paths; retry
re-fetches (test asserts two vault calls, no cache hit); no cache survives restart.
**Rules:** SF, NC, LP, NS.

## Phase 6 — First injector: `http` one-shot end-to-end *(M6)*

Goal: first full path with all spine components in place — and not before.

- [x] `http-bearer`/`http-basic`: attach Authorization, re-originate TLS to real
      target, return status/headers/body honoring `max_response_bytes` + timeouts.
- [x] Full path: signed intent → verify → policy → (confirm hook) → fetch → inject
      → result → audit.
- [x] Hostile-target defenses: output treated as untrusted data; size/time caps.

**Spec sections:** PROTO-SPEC §6.1, §7.1; ARCH-SPEC §2.5, §3.1; THREAT-MODEL §2.3 (T3).
**Acceptance:** real authenticated HTTPS call succeeds with no secret in
agent-visible I/O or logs (asserted by capture-layer test); denied intent never
fetches (vault call-count == 0); oversized/malformed responses handled safely.
**Rules:** NS, DD, AA, SF, LP, TCB.

## Phase 7 — The single confirmation gate *(M7)*

Goal: one human gate, owned by the gateway, at injection time.

- [x] On `needs_confirmation`: surface ONE prompt via operator channel with full
      context (target label, agent_id, mechanism, operation summary).
- [x] Approval proceeds; denial/timeout → `E_CONFIRM_TIMEOUT`; no duplicate prompts;
      agent-side prompting explicitly not required (skill already teaches this).

**Spec sections:** PROTO-SPEC §9.2; ARCH-SPEC §2.6; THREAT-MODEL §3 (property 4), §4 (fatigue tension).
**Acceptance:** needs_confirmation intent blocks on exactly one prompt; approve →
proceeds; deny/timeout → correct error; concurrent duplicate intents do not double-prompt.
**Rules:** OG, DD, TCB.

## Phase 8 — Sessions: `db-scram` and `ssh` *(M8)*

Goal: brokered-session lifecycle proving secret-vs-channel distinction.

- [x] Session establishment → `session_handle` + TTL; credential completes one
      handshake then scrubbed; channel persists, driven by handle.
- [x] Independently-signed owner-bound session frames (`session.command/close`);
      full §4 verification on every frame.
- [x] Streaming `session.output`, seq-ordered; `session.closed` with final audit_id;
      teardown on close/TTL/drop.

**Spec sections:** PROTO-SPEC §6.2, §7 (db-scram/ssh rows), §8; ARCH-SPEC §2.5, §2.9 (secret vs channel), §3.2.
**Acceptance:** multi-command SSH session runs; frame signed by other identity →
`E_SESSION_OWNER`; expired/unknown handle → `E_SESSION_EXPIRED`; secret re-transmit
count across session lifetime == 0 (wire-capture test).
**Rules:** NC, SF, NS, AA, LP.

## Phase 9 — Privileged helper: `local-privilege` *(M9)*

Goal: separate elevated process; never in the network path.

- [x] Helper process sharing vault+policy+audit core, NOT network-injection code path
      (separate binary/crate boundary; authenticated local channel daemon↔helper).
- [x] Always single deliberate confirmation; unattended only vs operator-defined,
      argument-pinned allowlist.
- [x] Platform authorization: polkit (Linux), launchd-authorized (macOS), service+UAC (Windows).

**Spec sections:** PROTO-SPEC §7.2; ARCH-SPEC §2.7; THREAT-MODEL §2.5 (T6), §6 (helper row).
**Acceptance:** allowlisted command runs with confirmation; non-allowlisted denied;
fault-injected network injector cannot invoke helper (cross-path test);
no root code in main daemon path.
**Rules:** IP, OG, DD, LP.

## Phase 10 — Hardening and high-assurance *(M10)*

Goal: make the TCB handoffs real controls.

- [x] Reproducible builds verified byte-for-byte from source; hash-verified releases (no signing).
- [x] Optional hardware-backed mode as install switch (TPM/Secure Enclave/HSM/enclave);
      software-only default preserved.
- [x] Supply-chain checks in CI (cargo audit + cargo-deny style checks, locked deps).
- [x] Threat Model §5 controls filled in as testable artifacts.

**Spec sections:** THREAT-MODEL §5 (all), §1.2 handoffs; ARCH-SPEC §4.4; Brief §3 TCB bullet.
**Acceptance:** third party reproduces release binary; enclave mode (where available)
keeps secrets out of introspectable memory; CI blocks on advisory matches.
**Rules:** TCB, SF (enclave composes with ephemerality per ARCH §4.4).

## Phase 11 — Conformance, fuzzing, agent-facing loop *(M11)*

Goal: prove the contract, break it before anyone else does.

- [x] Protocol conformance suite runnable against any client incl. packaged skill.
- [x] Fuzzing: envelope parser, framing codec, injectors (malformed intents; hostile
      target responses T3). No panics, no secret leaks.
- [x] Validate shipped Agent Skill examples run end-to-end against gateway.

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

---

### Backlog item C1 (discovered while writing the connectivity matrix)

Custom/private CA roots for outbound HTTPS are not configurable yet
(webpki bundle via reqwest rustls-tls). This blocks "internal HTTPS services
behind a private PKI" — a first-class enterprise use case. Fix: a gateway
config knob supplying extra root certificates to the shared reqwest client,
with tests against a locally generated CA. Tracked here rather than silently
shipped.

## Phase 12 - Technology-spectrum completion *(milestone: M12)*

Post-v1 backlog items pulled forward. Status:

- [x] **db-scram wire implementation** (was M8's honest deferral): real
      PostgreSQL SCRAM-SHA-256 via tokio-postgres; one-shot statements +
      SQL-driven sessions; endpoint rules per D27; params bound as text;
      NoTls gap documented. Env-gated live tests (`CHAPERONE_TEST_PG`) +
      CI postgres service job.
- [x] **HashiCorp Vault provider** (`vault://`): first remote backend,
      KV-v2 reads, #key selectors for multi-key secrets, auth/404 mapping,
      redirects off; proves scheme dispatch + migration story of ARCH §2.4.
      Provider trait promoted to async (D28) - required by any HTTP backend.
- [x] **db-scram wire implementation** — SHIPPED in M12 (see above).
- [x] **HashiCorp Vault provider** (`vault://`) — SHIPPED in M12 (see above).
- [ ] Enterprise cloud backends (AWS Secrets Manager / GCP / Azure) behind
      the same provider trait, with least-privilege mint() implementations.
      DISPOSITION: deferred until verifiable test surfaces exist - each
      needs either live credentials or a faithful emulator; per project
      discipline we do not ship untestable integrations. Vault provider
      demonstrates the full integration pattern awaiting them.
- [x] **Host-key pin store** shipped: PinStore (TOFU journal + changed-key
      refusal + openssh import w/ pattern reporting) wired into serve via
      --ssh-known-hosts [--ssh-tofu]; supersedes D23 stopgap (D31).
- [x] **Operator console socket** shipped: ConsoleHub + `chaperone console`
      client supersede TTY prompting (D32); fail-closed with no operator.
- [x] **cargo-fuzz targets** shipped as standalone workspace artifacts
      (D33): frame codec, envelope verification, policy parse+eval.
- [ ] True streaming session.output transport extension (beyond D24 batching).
      DISPOSITION: requires a protocol revision (unsolicited server frames
      change the unary wire contract), client background-read support, and
      skill-doc updates together - bundled as one coordinated v0.2 item
      rather than a piecemeal transport hack.
- [ ] cargo-fuzz targets layered over the deterministic harness.
- [ ] Enclave runtime (TPM/SGX) per THREAT-MODEL §5 - the explicit honesty
      line. DISPOSITION: unverifiable in CI without hardware; stays roadmap
      with the software-only default as the shipped truth.
- [ ] Plugin ABI for injectors + browser-session reference mechanism.
      DISPOSITION: an architecture project (stable internal ABI, plugin
      capability boundary per ARCH §2.5) - sequenced after the streaming
      protocol work it depends on for session-shaped plugins.
- [ ] Operator console socket superseding TTY prompting (D8).

---

## Phase 13 - Installer-grade release *(milestone: M13 — SCOPED, AWAITING DECISIONS)*

Goal: move from "archives you unzip by hand" to a real install experience —
service definitions, elevation packaging, upgrade/uninstall semantics —
while staying inside the no-signing, no-entity reality. Native package
formats (deb/rpm/msi/pkg) collide with that reality: apt/rpm/dpkg expect
GPG-signed repos and Apple pkg wants Developer ID. **Proposed middle path:
reviewed, idempotent install scripts** that do the right things without new
signing infrastructure, keeping native packages as a later step once an
entity exists.

### Phased breakdown

| # | Item | Deliverable | Notes |
|---|---|---|---|
| 13a | **Helper allowlist hardening** | When the helper runs elevated (euid 0), it REFUSES to honor an allowlist file that is not root-owned / not group-or-other-writable. Otherwise a user-editable allowlist behind a sudoers rule becomes arbitrary-root-exec. Predicate unit-tested; enforcement active only when elevated (dev/test runs unaffected). | Security fix, ships first regardless of other decisions |
| 13b | **POSIX install script** (`install.sh`, `uninstall.sh`) | Binaries → `~/.local/bin`; systemd *user* unit (Linux) + launchd *agent* plist (macOS); config skeleton `~/.config/chaperone/`; prints post-install checklist incl. the exact sudoers line for the operator to review — never writes sudoers itself | Scripts ship inside release archives too |
| 13c | **Windows install script** (`install.ps1`) | Binaries → `%LOCALAPPDATA%\Programs\chaperone`; logon Scheduled Task instead of a service (honest: no service account story without codesigning); PATH update | Weakest platform; explicitly labeled preview |
| 13d | **INSTALL.md** | Per-OS install/upgrade/uninstall/rollback, service management commands, elevation setup walkthrough (sudoers example w/ root-owned allowlist), Gatekeeper/SmartScreen guidance, upgrade semantics (vault/journal formats versioned; installers never touch data) | |
| 13e | **Pipeline + release** | release.yml bundles scripts in archives; tag `v0.1.0-alpha.2`; published & verified end-to-end | Includes 13a fix |

### Explicitly out of scope for M13

Native packages (.deb/.rpm/.msi/.pkg) — blocked on repo-signing /
Developer-ID infrastructure (same entity dependency as codesigning).
Auto-update mechanism. System-wide multi-user daemon mode. Notarization.

### Decisions required before execution

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| DA | Distribution format this round | (1) install-scripts-only (2) also attempt native pkgs | (1) — native packaging inherits the same signing bureaucracy we just deferred |
| DB | Daemon service model | (1) per-user services everywhere (2) system-wide daemon | (1) — matches the same-user security model exactly; system-wide changes the trust boundary |
| DC | macOS helper elevation | (1) sudoers-snippet walkthrough now (2) defer macOS elevation entirely this round | (1) — works without Developer ID; SMJobBless path needs it |
| DD | Elevated allowlist ownership enforcement (13a) | (1) refuse non-root-owned allowlist when euid=0 (2) warn only | (1) — warn-only leaves an arbitrary-root-exec footgun |

Rough shape once approved: 13a (small, security) → 13b/13c in parallel →
13d/13e docs+pipeline → alpha.2 tag. Each lands as its own commit set with
tests/gates green; nothing executes until decisions land here.

---

## Phase 14 - Operator UI, notifications, and policy integrity *(milestone: M14)*

Goal: close the front-door failure mode from user acceptance testing — the
security model's first real-world failure was a cooperative user asking
their agent to hand-write `policy.toml` for them (OPERATOR-UI-SPEC §1) —
and the silence-after-approval gap (§1.2). Two additive client surfaces
(config UI + live event feed), one integrity guard that makes them honest,
zero changes to wire protocol or security semantics. Decisions E1–E5 were
ratified as recommended: E1=(2) loopback web UI, E2=(1) dedicated events
socket, E3=(1) notify-default-true, E4 resolved by 14c-pre below rather
than an ownership check, E5=(1) in-tree crate.

### Phased breakdown

| # | Item | Deliverable | Notes |
|---|---|---|---|
| 14a | **Ruleset hash anchoring** (D38) | Every gateway start appends a `policy_load` record carrying SHA-256 of the governing policy TOML; every decision carries the same hash; post-hoc widening is detectable as a hash break at next restart. Detection-over-prevention matches D7/D18. | ✅ shipped |
| 14b | **Events feed socket + notify knob** (D35/D37) | `EventHub`: read-only fan-out UDS broadcasting one JSON line per terminal intent decision. `[rule.notify] on_use` per rule (default true). Emission at the `audit_decision` choke point. | ✅ shipped |
| 14c-pre | **Policy-file integrity guard** (D39) | Load-time permission gate (refuse group/other-writable or foreign-owned policy.toml); live drift watch while serving: any content change/deletion under a running gateway appends a signed `policy_drift` record, broadcasts on the feed, and HALTS brokering until operator restart. Restart re-runs the gate and re-anchors the chain. | ✅ shipped |
| 14c | **Config UI web crate** (D36/D40) | `chaperone-ui`: axum, server-rendered HTML/CSS, zero JS build step, loopback-only with Host/Origin guard. Setup wizard (creates vault.bin / audit.key / default-deny policy scaffold), secret CRUD (never re-displays values), rule editor (mechanism picker + service templates + maturity badges from CONNECTIVITY-MATRIX; saves through `Policy::to_toml`, validated via `Policy::from_toml` before disk), raw TOML editor, agent enroll/revoke with client-side key decode. Served from `chaperone serve`; missing artifacts ⇒ setup-only mode. Hard constraint §3.2: no second parser anywhere. | ✅ shipped |
| 14d | **GETTING-STARTED.md + release** | On-ramp doc (UI-first, CLI equivalents at every step); tag `v0.1.0-alpha.4`. | ✅ shipped |

### Acceptance tests

- Guard: loose modes refused at load (`0646/666/622` fail, `600/400/644/604` pass);
  content drift halts within one watch tick, appends exactly one signed
  `policy_drift` record to the SAME chain, broadcasts on the feed; deletion halts;
  untouched files never trip it; halted gateway answers every message type
  with `E_GATEWAY_HALTED`.
- Policy crate: canonical writer round-trips every matcher kind through
  `source()`/`parse()`; regenerated rulesets evaluate identically; empty
  policy serializes to empty document.
- UI: wizard creates all three broker artifacts (audit key refuses overwrite);
  secrets stored via UI never appear in page HTML; enrollment rejects JSON-blob
  keys with a specific error before calling enroll; rule editor output parses
  under the real schema with expected effect/notify/limits; unknown mechanisms
  refused pre-write; invalid raw TOML never touches disk; foreign Host/Origin → 403.
