# Chaperone — Gaps A/B/C: Phased Implementation Plan (post-`v0.1.0-alpha.5`)

> **For Hephaestus/Stephen:** this roadmap decomposes Gaps A (keyring vault
> sealing), B (glibc portability), and C (Windows hardening) into
> independently-verifiable phases, each with a hard `[DONE]` gate. Phase 0 is
> the UAT fold-in — new issues from acceptance testing get triaged into A/B/C
> (or closed). Phases 1–3 are zero-dependency and can run in parallel.

**Goal:** close the three known gaps so Chaperone's "no secret reachable on
disk" promise holds on headless Linux, RHEL-family Linux, and Windows — without
introducing third-party dependencies.

**Current release:** `v0.1.0-alpha.5` (3 platforms, reproducible, unsigned/SLSA).

---

## 0. Key findings that shape this plan (verified against code today)

These are facts, not assumptions — each was traced to source:

1. **Gap A is subtler than "use the persistent keyring."** The `keyring` crate's
   `linux-native` backend (`Cargo.toml:32-36`, native backends only) *already*
   links secrets into the **persistent keyring** on `Entry::new()` (crate
   `src/keyutils.rs`, lines 71–129, 154–195). But:
   - **A reboot clears ALL kernel keyrings** (session *and* persistent).
   - The persistent keyring **expires** after
     `/proc/sys/kernel/keys/persistent_keyring_expiry` seconds (default
     259200 = 3 days), reset only when `Entry::new()` is called.
   - The persistent link is **best-effort** (`Option<KeyRing>`), so on a minimal
     box where `get_persistent` fails there is no persistence at all.
   - D5 already specifies a **passphrase+argon2id fallback** — keyring sealing is
     auto-unlock convenience, passphrase is the recovery path.
2. **Gap B** is a build-target problem: Linux releases build on `ubuntu-latest`
   (glibc ~2.39), so they won't launch on RHEL-family (glibc 2.34).
   (`release.yml:25-26`.)
3. **Gap C** is three independent Windows surfaces: privilege elevation,
   named-pipe ACLs, and Credential-Manager keyring (the last overlaps Gap A).

The Linux keyring probe already exists and was validated on a live kernel:
`scripts/linux-keyring-probe.py` (raw `syscall()` via ctypes — no `keyctl`
CLI, no `libkeyutils`). Output confirmed: persistent keyring serial available,
add/read round-trip works, session keyring shared within the user session.

---

## Phase 0 — UAT + issue triage (fold-in)

**Goal:** exercise alpha.5, collect issues, triage them into A/B/C or close them.

### Task 0.1 — Define the UAT checklist
- **Files:** create `docs/UAT-CHECKLIST.md`
- Cover: fresh `install.sh` on Ubuntu 24.04; `chaperone vault-init/set/get/list/del`;
  `systemctl --user enable --now chaperoned`; `chaperone console --socket`; the
  `--events-socket` feed; `http-bearer`/`http-basic` injectors; `db-scram`
  (Postgres); SSH host-key pin; `local-privilege` helper; audit keygen/verify;
  `ui-token rotate` (D41); `chaperone version`.
- **`[DONE]` gate:** checklist lists each command + expected output, verified
  against `--help`/code (no plausible prose).

### Task 0.2 — Run UAT (Stephen drives; agents execute)
- Stephen exercises the build (he reports precise repro steps); agents run the
  checklist and file one GitHub issue per defect with repro + expected/actual.

### Task 0.3 — Triage the 9 open issues + new UAT issues
- **Close** any SI-* already fixed in code (e.g. SI-1 `../skill` refs removed in
  hygiene sweep; SI-2/D14 backfilled in `0885f0e`).
- **Map** the rest: spec-issues → a "spec hygiene" bucket (not A/B/C); anything
  touching keyring/sealing → Phase 1; build/distro → Phase 2; Windows surfaces
  → Phase 3.
- **`[DONE]` gate:** every issue is `closed`, `assigned-to-phase`, or `deferred`
  with a written reason.

---

## Phase 1 — Gap A: Keyring-backed vault sealing

**Goal:** keyring sealing works end-to-end on Linux (headless, across restart),
macOS (Keychain), and Windows (Credential Manager), with the reboot/expiry
limitations documented and a passphrase recovery path intact.

### Task 1.1 — Investigate + probe (mostly done; fold in)
- **Files:** `scripts/linux-keyring-probe.py` (written + validated).
- Remaining: extend the probe to assert the expiry value is *not* silently 0 and
  to print a one-line recommendation (already added: expiry + reboot note).
- **`[DONE]` gate:** `python3 scripts/linux-keyring-probe.py probe` exits 0 and
  prints the persistent-serial, expiry, and reboot caveat on a real box.

### Task 1.2 — End-to-end seal → restart → unseal (the real test)
- **Files:** none yet; drives `crates/cli/src/main.rs` `vault-init --sealer keyring`.
- Build `--features keyring`; `chaperone vault-init --store /tmp/v.bin --sealer keyring`;
  `vault-set/get`; restart `chaperoned.service`; `vault-get` again — assert the
  DEK unseals after restart *within* the session.
- **`[DONE]` gate:** a scripted test (extend the probe or a shell script) that
  seals, `systemctl --user restart chaperoned`, and unseals, reporting PASS/FAIL.

### Task 1.3 — Decide + document the Linux reboot/expiry story
- **Decision for Stephen (recommended):** keep `keyring` **off by default**;
  ship it as an opt-in auto-unlock layer with passphrase always available as
  recovery. Document, loudly, that on Linux: (a) reboot clears the DEK from the
  kernel keyring, (b) 3-day expiry unless `persistent_keyring_expiry` is raised
  and the daemon re-touches `Entry::new()`, (c) raise
  `persistent_keyring_expiry` via a documented `sysctl`/systemd drop-in if the
  operator wants longer. File a follow-up for TPM-based sealing (the arch spec's
  aspirational "kernel keyring / TPM" row) as a *separate* future milestone.
- **Files:** `docs/LOCAL-VAULT-GUIDE.md` (§ sealing), `docs/DESIGN-DECISIONS.md`
  (D5 addendum with the reboot/expiry finding).
- **`[DONE]` gate:** the reboot-clears-keyrings + expiry behavior is stated in
  the user guide, not buried in a builder note.

### Task 1.4 — Validate macOS + Windows native stores
- macOS: `--features keyring`, exercise Keychain prompt, confirm seal/unseal and
  that Keychain persists across reboot (it does — no kernel-keyring equivalent).
- Windows: same against Credential Manager (overlaps Task 3.3).
- **`[DONE]` gate:** a short per-platform findings note in the builder notes
  ("untested" → "validated, caveats below").

### Task 1.5 — Documentation sweep
- Update `docs/BUILDER-NOTES-{LINUX,MACOS,WINDOWS}.md` "Keyring-backed vault
  sealing" rows from "UNTESTED" to actual findings; update
  `docs/CONNECTIVITY-MATRIX.md` and `docs/LOCAL-VAULT-GUIDE.md` accordingly.
- **`[DONE]` gate:** no doc still claims "untested" after a pass that actually
  tested it.

---

## Phase 2 — Gap B: glibc portability

**Goal:** the published Linux binary runs on RHEL-family (glibc 2.34) and
Ubuntu 22.04+ (glibc 2.35+) — i.e. one binary, not two.

### Task 2.1 — Decide the glibc floor
- **Decision (recommended):** glibc **2.34** (Alma/Rocky 9, RHEL 9). This covers
  RHEL 9 + Ubuntu 22.04+ + Debian 12+. Going lower (2.28 for RHEL 8) is a
  separate, bigger decision — defer unless a customer asks.
- **`[DONE]` gate:** the floor is recorded in `DESIGN-DECISIONS.md` (new D#) and
  `docs/BUILDER-NOTES-LINUX.md` §4.

### Task 2.2 — Build the Linux release in a glibc-2.34 container
- **Files:** `.github/workflows/release.yml` (matrix + build step),
  `scripts/` if a helper is needed.
- Add a containerized build (e.g. `quay.io/almalinux:9` or `rockylinux:9`,
  `runs-on: ubuntu-latest` + `container:`), or a second matrix row building on
  the older-glibc base. The binary built there is backward-compatible
  (glibc ≥ 2.34).
- **`[DONE]` gate:** release workflow produces a Linux tarball whose `ldd`/`file`
  output shows `GLIBC_2.34` (not 2.38/2.39) as the max required symbol version.

### Task 2.3 — Make `repro-check.sh` run in that target
- `scripts/repro-check.sh` must build twice from clean state *in the same
  glibc-2.34 environment* and assert byte-identity. Wire it into the container.
- **`[DONE]` gate:** `[repro] OK` in the container; two clean builds byte-identical.

### Task 2.4 — Validate the binary on real RHEL-family
- Boot Alma 9 / Rocky 9 (VM on Proxmox or the existing fleet); run
  `chaperone version`, `vault-init`, `install.sh` + systemd unit; confirm no
  `GLIBC_* not found`.
- **`[DONE]` gate:** the exact commands run green on Alma 9 and Ubuntu 22.04,
  captured in `docs/BUILDER-NOTES-LINUX.md` §4.

### Task 2.5 — Docs
- Update `release.yml` comments, `RELEASE.md` verification section, and the
  Linux builder note's "known gap" row (glibc portability → resolved).

---

## Phase 3 — Gap C: Windows hardening

**Goal:** the Windows port is a first-class target, not just a cross-compiled
binary — elevation, IPC ACLs, and Credential-Manager sealing all hardened.

### Task 3.1 — Privilege elevation (the hard one)
- **Files:** `crates/*` privileged-helper path, `packaging/` (Windows service or
  elevation manifest).
- Investigate + decide the elevation model: a pre-installed elevated helper
  service (allowlist enforced server-side) vs. UAC prompt vs. a scheduled task.
  Document the choice in a new `DESIGN-DECISIONS` entry.
- **`[DONE]` gate:** the local-privilege mechanism has a concrete Windows design
  + a task breakdown; no `sudo`-equivalence left as a magic TODO.

### Task 3.2 — Named-pipe ACLs (console + event feed)
- **Files:** `crates/cli/src/main.rs` (console), `crates/gateway-core/src/events.rs`
  (event feed) — add Windows named-pipe ACLs so only the owning user can connect
  (parity with the Unix `0700` socket + owner-only fallback).
- **`[DONE]` gate:** a Windows integration test asserts a second user cannot
  connect to the console/event pipes.

### Task 3.3 — Credential Manager keyring validation (overlaps 1.4)
- Build `--features keyring` on `windows-latest`; seal/unseal against Credential
  Manager; confirm persistence across logout/login.
- **`[DONE]` gate:** findings recorded in `docs/BUILDER-NOTES-WINDOWS.md`.

### Task 3.4 — Docs
- `BUILDER-NOTES-WINDOWS.md` §4 open-tasks table updated; `CONNECTIVITY-MATRIX.md`
  Windows rows reflect the hardened state.

---

## Sequencing + agent assignment (recommendation)

| Phase | Primary agent (model) | Rationale | Parallel? |
|---|---|---|---|
| 0 UAT/triage | Hephaestus (verify) + Stephen (drive) | Stephen reports repros; Hephaestus triages | — |
| 1 Gap A | **Mark** (deepseek-v4-flash) | security-sensitive Rust + careful keyring reasoning | yes |
| 2 Gap B | **Mike** (laguna) | build/CI matrix change, pattern-matching | yes |
| 3 Gap C | **Windows-capable agent** (CI `windows-latest`, or a Windows builder) | needs a Windows surface | yes |

A, B, C are zero-dependency — dispatch in parallel after Phase 0 triage. Keep
each task as a **self-contained paste-ready prompt with its own `[DONE]` gate**;
verify on-node (Hephaestus SSH/reads the CI artifacts) rather than trusting the
self-report.

## Global definition of done

- No third-party utility/application introduced (the whole point of Gap A).
- Every "untested" row in the three builder notes either flipped to "validated"
  or explicitly documented as out-of-scope with a reason.
- The Linux reboot/expiry caveat is in the *user-facing* guide, not just dev notes.
- One published binary per OS runs on the stated floor (glibc 2.34 for Linux).
- Each phase's `[DONE]` gates are independently verified before merge.
