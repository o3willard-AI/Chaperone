# Chaperone — Session Handoff & Status Document

**Last updated:** 2026-08-26
**Branch:** `main` @ `44572a9` — all commits pushed, CI green across Linux/macOS/Windows
**Latest published release:** [`v0.1.0-alpha.2`](https://github.com/o3willard-AI/Chaperone/releases/tag/v0.1.0-alpha.2)
**Tests:** 165 passed / 0 failed · clippy `-D warnings` clean · fmt clean · cargo audit + cargo deny green

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

## Current State: Phase 14 In Progress

Phase 14 implements the OPERATOR-UI-SPEC (`/home/sblanken/workspace/
OPERATOR-UI-SPEC.md`, not yet in repo) which was derived from user acceptance
testing on macOS. It has two parts:

### ✅ DONE: 14a — Ruleset hash anchoring (D38)

Every gateway start appends a `policy_load` record carrying SHA-256 of the
governing policy TOML. Every intent_decision record carries the same hash.
Any post-hoc policy widening is detectable as a hash break in the audit
chain at next restart. Detection-over-prevention matches D7/D18 philosophy
(ownership checks are no-ops in the per-user model).

Files touched: `crates/policy/src/lib.rs` (source_hash field),
`crates/gateway-core/src/lib.rs` (ruleset_hash on Gateway, policy_load
record at construction), `crates/audit/src/event.rs` (+RecordKind enum,
+ruleset_hash field), schema-pin test updated.

### ✅ DONE: 14b — Events feed socket + notify knob (D35)

`EventHub`: read-only fan-out Unix domain socket broadcasting one JSON line
per terminal intent decision to any connected subscriber. Unlike the console
socket's 1:1 answer semantics, supports unlimited simultaneous readers.

Policy schema gains `[rule.notify]` with `on_use` field (default true per
E3 — quiet is opt-out). Decision carries `notify_on_use` so the gateway
knows whether to broadcast. Emission happens at the same `audit_decision`
choke point that already centralizes every terminal outcome.

Files: `crates/gateway-core/src/events.rs` (EventHub), policy schema
extension in `crates/policy/src/lib.rs`, `Gateway::with_event_hub()` wiring.

### ⏳ TODO: 14c — Config UI web crate

Loopback HTTP server with forms for first-run setup, vault CRUD, rule
editing (mechanism picker populated from CONNECTIVITY-MATRIX), agent
enrollment. **Hard constraint (§3.2): drives existing crates directly — no
second TOML parser.** Recommended shape: loopback web UI served from daemon
(E1=2). Also needs GETTING-STARTED.md written (referenced by spec but never
created).

This is the biggest remaining item. Suggest new crate `chaperone-ui` in the
workspace using axum or tiny_http, calling chaperone-policy/vault/identity
directly in-process (satisfies §3.2 even stronger than subprocess).

### ⏳ TODO: 14d — Release v0.1.0-alpha.3

Tag after 14c lands. Pipeline is fully automated (release.yml): locked
builds on 3 platforms, ed25519 signatures via RELEASE_KEY_SEED secret,
GitHub release with notes from `docs/release-notes/<tag>.md`.

---

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
| M14b | Events feed socket + notify knob (D35) | ✅ |
| M14c | Config UI web crate | ⏳ NEXT |
| M14d | Tag v0.1.0-alpha.3 | ⏳ AFTER 14c |

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
| `docs/LOCAL-VAULT-GUIDE.md` | User guide for built-in encrypted vault |
| `docs/INSTALL.md` | Per-OS installation instructions |
| `docs/release-notes/` | Per-tag release notes |
| `scripts/repro-check.sh` | Reproducible-build verification (--target flag for cross) |
