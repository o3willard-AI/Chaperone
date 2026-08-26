# Chaperone — Session Handoff & Status Document

**Last updated:** 2026-08-26 (post-D41 session)
**Branch:** `main` — Phase 14 + D41 security fix complete, awaiting `v0.1.0-alpha.4` tag
**Tests:** 199 passed / 0 failed · clippy `-D warnings` clean · fmt clean · cargo audit (CI ignore list) + cargo deny green

---

## What Chaperone Is

A local-first authentication broker for AI agents. The agent sends a signed
intent naming a credential *reference*; the gateway verifies who's asking,
decides whether policy allows it, fetches the real secret at the last moment,
injects it on the outbound side, and returns results. The agent holds a
reference, never a secret.

Four v1 mechanisms: `http-bearer`/`http-basic` (one-shot HTTPS), `db-scram`
(PostgreSQL SCRAM-SHA-256), `ssh` sessions, `local-privilege` (isolated
helper). Plus HashiCorp Vault KV-v2 as a credential backend alongside the
built-in sealed local vault.

---

## Current State: Phase 14 COMPLETE

The OPERATOR-UI-SPEC (`/home/sblanken/workspace/OPERATOR-UI-SPEC.md`, not
yet in repo) is fully implemented. E1–E5 ratified: E1=(2) loopback web UI,
E2=(1) dedicated events socket, E3=(1) notify-default-true, E4 resolved via
14c-pre (detection + fail-closed halt, not an ownership check), E5=(1)
in-tree crate.

### ✅ 14a — Ruleset hash anchoring (D38)

Every gateway start appends a `policy_load` record carrying SHA-256 of the
governing policy TOML; every decision carries the same hash.

### ✅ 14b — Events feed socket + notify knob (D35/D37)

`EventHub` fan-out UDS; `[rule.notify] on_use` default true. **This session:
serve now actually binds it via `--events-socket PATH`** (previously built
but unreachable from the CLI).

### ✅ 14c-pre — Policy-file integrity guard (D39) [NEW this session]

E4 revisit decided BEFORE the UI shipped:

- Load gate: refuse group/other-writable or foreign-owned `policy.toml`.
- Live drift watch (`PolicyWatch` in gateway-core): content change/deletion/
  persistent unreadability under a running gateway ⇒ signed `policy_drift`
  audit record + events broadcast + loud banner + **halt brokering**
  (`Gateway::halt`, every message type answers `E_GATEWAY_HALTED`) until
  restart. Restart re-runs the gate and re-anchors.
- Rejected alternative recorded in D39: updating the watch baseline on UI
  saves would trade a loud halt for a silent widening path.

Files: `crates/gateway-core/src/policy_guard.rs`, `Gateway` halt machinery,
audit `RecordKind::PolicyDrift`/`Outcome::PolicyDrift`,
CLI perm-gate + watch wiring. rustix (safe geteuid; workspace forbids
unsafe) + sha2 added to gateway-core.

### ✅ 14c — Config UI web crate (D36/D40) [NEW this session]

New workspace crate **`chaperone-ui`** (axum, server-rendered HTML/CSS,
zero JS build step):

- Served from `chaperone serve` (default 127.0.0.1:8720; `--ui-port`,
  `--no-ui`). Missing broker artifacts ⇒ setup-only mode (wizard only).
- Wizard creates vault.bin / audit.key / empty default-deny policy through
  the real crates; vault handle is SHARED with the gateway via
  `SharedVault` (vault crate) — one open vault, two consumers.
- Secrets CRUD (never re-displays values), agents enroll/revoke (client-side
  b64url key decode before calling enroll), rule editor driven by an
  embedded CONNECTIVITY-MATRIX snapshot (`matrix.rs`: mechanisms with
  maturity badges + service templates prefilling target_uri globs).
- §3.2 honored structurally: rule docs are serialized by the NEW
  `Policy::to_toml` (canonical writer living IN chaperone-policy) and
  re-validated by `Policy::from_toml` before atomic 0600 write. Also new:
  `Policy::rules()` accessor, `exact:` matcher tag for lossless matcher
  round-trip.
- Loopback guard middleware: Host must be 127.0.0.1/localhost(:port),
  Origin must match when present ⇒ CSRF + DNS-rebinding refused without
  operator-visible friction. Residual same-user-process risk accepted and
  documented in D40.

### ✅ 14d — Docs + release

GETTING-STARTED.md written (UI-first, CLI equivalents per step). PLAN.md
Phase 14 entry with acceptance tests. DESIGN-DECISIONS.md backfilled
D35–D38 (were referenced but never written!) + new D39/D40. Release notes
at `docs/release-notes/v0.1.0-alpha.3.md`. **Tag v0.1.0-alpha.3 next.**

## Complete Phase History

| Phase | What | Status |
|---|---|---|
| M0 | Repo scaffolding, CI pipeline, specs committed | ✅ |
| M1 | Transport: UDS/named-pipe/TCP framing, Content-Length codec, unary loop | ✅ |
| M2 | Identity: Ed25519 attestation, JCS canonicalization, replay cache, enrollment store + CLI | ✅ |
| M3 | Policy: default-deny TOML engine, exact/prefix/glob matchers, strict schema | ✅ |
| M4 | Audit chain: hash-chained signed records, tamper detection, CLI verify/export | ✅ |
| M5 | Vault: SecretString type, LocalVault (argon2id+AES-GCM), provider abstraction, ephemerality tests | ✅ |
| M6 | Gateway: full path wired end-to-end, http injector, hostile-target defenses, capture-layer tests, serve command | ✅ |
| M7 | Confirmation gate: OperatorGate with full-context prompt, fail-closed everywhere | ✅ |
| M8 | Sessions: SessionTable, owner-bound frames, ssh backend via russh, db-scram deferred honestly | ✅ |
| M9 | Privileged helper: separate binary, token-gated allowlist, elevated ownership enforcement | ✅ |
| M10 | Hardening: reproducible builds verified, cargo-deny, russh CVE response, release-sign/verify | ✅ |
| M11 | Conformance suite, fuzz harness, skill examples validated | ✅ |
| M12a | db-scram wire implementation (PostgreSQL SCRAM-SHA-256) | ✅ |
| M12b | HashiCorp Vault KV-v2 provider | ✅ |
| M13 | Installer-grade release: install scripts, service definitions, elevated allowlist enforcement | ✅ |
| M14a | Ruleset hash anchoring (D38) | ✅ |
| M14b | Events feed socket + notify knob (D35); CLI binding landed with 14c work | ✅ |
| M14c-pre | Policy-file integrity guard: perm gate + drift watch + halt (D39) | ✅ |
| M14c | Config UI web crate `chaperone-ui` (D36/D40) | ✅ |
| M14d | GETTING-STARTED.md, PLAN/DESIGN-DECISIONS updates, tag v0.1.0-alpha.3 | ✅ |
| D41 | UI access token gate (supersedes D40's bare-loopback trust; §8 fix) | ✅ |
| D41-release | Tag v0.1.0-alpha.4 | ⏳ TAG NEXT |

## Post-v1 Backlog (dispositioned)

| Item | Disposition |
|---|---|
| Cloud backends (AWS/GCP/Azure) | Deferred until verifiable test surfaces exist; Vault provider demonstrates the pattern awaiting them |
| Custom CA roots for outbound HTTPS | Blocks internal-services use case; logged as C1 with fix shape |
| Streaming session.output | Requires protocol revision (unsolicited server frames); bundled as coordinated v0.2 item |
| Enclave runtime (TPM/SGX) | Unverifiable in CI without hardware; stays roadmap |
| Plugin ABI + browser-session | Architecture project sequenced after streaming |
| Git relay mechanism | Needed for full PAT retirement when Chaperone runs on the builder's own system |

---

## Design Decisions Index (D1–D38)

All recorded in [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md). Highlights:

| D | Topic |
|---|---|
| D1–D10 | Crate layout, JCS canon-json, policy TOML language, session handles, vault sealing, replay persistence, audit encoding, frame caps, async runtime, transport errors |
| D11–D17 | tokio adoption, Windows pipe ACLs, pre-schema failure mapping, enrollment shape, GitHub example, installer posture, http-basic username |
| D18–D24 | Audit chain encoding + tail-truncation honesty, vault sealing posture, db-scram endpoint rules, response ceilings abort-not-truncate, redirects disabled, post-signature schema failures → E_MECHANISM, SSH host-key pin store |
| D25–D33 | Privilege confirmation posture, error reasons never amplify secret-shaped input, events fan-out socket, UI thin-client constraint, notify-default-true, integrity-first sequencing, UI in-tree, replay-journal capacity |
| D34–D38 | Replay capacity policy, ruleset hash anchoring, event feed transport, UI thin-client constraint, notify-default-true |

Full text for each: see DESIGN-DECISIONS.md §D1–§D38.

## Known Gaps (documented, tracked, not hidden)

| Gap | Where tracked | Why not fixed yet |
|---|---|---|
| No TLS to PostgreSQL (NoTls) | D27 | rustls connector work tracked post-v1 |
| Private-CA roots unconfigurable | PLAN C1 | Needs gateway config knob + locally generated CA test |
| db-scram TLS absent | Same as above | Same fix |
| Windows console/events sockets | cfg(unix) gates | Named pipe implementation needed |
| Policy hot-reload without restart | OPERATOR-UI-SPEC §6 | Sequenced AFTER policy.toml integrity fix |
| Streaming session output | D24 | Requires protocol revision |
| Wrapping curl/gh processes | Anti-goal | Would defeat the entire model |

## Key Files

| File | Purpose |
|---|---|
| `docs/PLAN.md` | Phased plan with acceptance tests (canonical tracking) |
| `docs/DESIGN-DECISIONS.md` | All 38 design decisions with rationale |
| `docs/SPEC-ISSUES.md` | Spec discrepancies found during implementation |
| `docs/CONNECTIVITY-MATRIX.md` | Living table of what agents can reach |
| `docs/RELEASE.md` | Artifact verification instructions + public key |
| `docs/BUILDER-NOTES-MACOS.md` | Apple hardware build/validation brief |
| `docs/GETTING-STARTED.md` | The friendly on-ramp (wizard-first, CLI equivalents) |
| `docs/LOCAL-VAULT-GUIDE.md` | User guide for built-in encrypted vault |
| `docs/INSTALL.md` | Per-OS installation instructions |
| `docs/release-notes/` | Per-tag release notes |
| `scripts/repro-check.sh` | Reproducible-build verification (--target flag for cross) |
