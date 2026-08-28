# Builder Notes — Windows

You are building and validating Chaperone on Windows. This document is your
brief: what the project is, what "done" means for the Windows binary, the
rules you must not break, and the specific work we need from you. Read it
fully before building anything.

> **Preview quality.** The Windows build is CI-verified (the `windows-latest`
> runner in `.github/workflows/release.yml` is the authoritative gate) but has
> no dedicated hardware pass yet. Some surfaces are stubbed or deferred. This
> document states the honest boundaries — do not "fix" them by inventing
> behavior the code does not have.

---

## 1. What you are building (one paragraph)

Chaperone is a local-first authentication broker: an AI agent sends a signed
intent naming a credential *reference*; our gateway daemon verifies who is
asking, adjudicates against default-deny policy, resolves the real secret at
the last moment, injects it on the outbound side, and returns results — so no
credential ever enters the agent's context, transport, or logs. The Windows
build ships two binaries: `chaperone.exe` (operator CLI + gateway daemon) and
`chaperone-helper.exe` (an isolated process that executes pinned privileged
commands). Everything is Apache-2.0, built in the open.

**Read in this order before coding:**
1. [`docs/IMPLEMENTATION_AGENT_BRIEF.md`](IMPLEMENTATION_AGENT_BRIEF.md) — operating brief and non-negotiable rules
2. [`docs/01-protocol-spec.md`](01-protocol-spec.md) — the wire contract that governs all other docs
3. [`docs/02-architecture-spec.md`](02-architecture-spec.md) §4 — platform matrix, Rust rationale
4. [`docs/RELEASE.md`](RELEASE.md) — how releases are produced and verified
5. [`docs/PLAN.md`](PLAN.md) — where we are and what remains
6. [`docs/CONNECTIVITY-MATRIX.md`](CONNECTIVITY-MATRIX.md) — what agents can reach today, and what is missing
7. [`docs/HANDOFF.md`](HANDOFF.md) — known gaps and current state

---

## 2. Toolchain and build

```powershell
git clone https://github.com/o3willard-AI/Chaperone
cd Chaperone
. ./scripts/repro-env.sh   # REQUIRED: sets the --remap-path-prefix RUSTFLAGS
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
```

- **Source `scripts/repro-env.sh` before building.** rustc embeds absolute
  build-time paths (the checkout root and `$CARGO_HOME` registry sources)
  into the binaries; without the remap env your rebuild embeds
  `C:\Users\<you>\...` and can never match CI's bytes. The script converts
  both prefixes to the native Windows form (`cygpath -w`) when run under
  Git Bash/MSYS so the remap actually matches what rustc embeds; under WSL
  it correctly keeps POSIX paths. This affects Windows too — it is a
  cargo/rustc behavior, not a macOS one.

- `rust-toolchain.toml` pins **exactly 1.98.0**; rustup provisions it on first
  build. Do not bump it unilaterally — reproducibility depends on it.
- **`--locked` always.** Dependency drift is a supply-chain event, not a
  convenience. If a dependency genuinely must change, that is a reviewed
  commit updating `Cargo.toml` + `Cargo.lock` together with rationale.
- The release pipeline builds Windows with target
  `x86_64-pc-windows-msvc` on `windows-latest` (`.github/workflows/release.yml`
  line 29–30). **MSVC is the only supported toolchain** for the release binary.
  The `ring` and `aws-lc-sys` crates (pulled in transitively) require
  MSVC's `lib.exe` and will fail under the GNU target — so do not attempt to
  substitute `x86_64-pc-windows-gnu` for release builds. The `windows-latest` CI
  job is the authoritative gate; local builds must match it to stay
  reproducible.
- The `windows-latest` runner ships MSVC + the Windows SDK pre-installed;
  `actions-rust-lang/setup-rust-toolchain@v1` installs the pinned Rust toolchain. For a local build, install **Visual
  Studio 2022 Build Tools** with the "Desktop development with C++" workload
  (includes MSVC v143 and the Windows 10/11 SDK), then build with the
  `x64 Native Tools Command Prompt`.

### Reproducibility discipline (non-negotiable)

`scripts/repro-check.sh` (default mode) is a **two-path** check: build A in
this checkout, build B in a second copy of the tree at a different path, both
with the canonical remap env from `scripts/repro-env.sh` (checkout →
`/workspace/`, `$CARGO_HOME` → `/cargo/`), then byte-compare and assert no
absolute source paths remain embedded. On Windows this script runs under
`bash` (Git Bash or WSL) — but the underlying `cargo build` invokes the
MSVC toolchain:

```sh
./scripts/repro-check.sh   # must print "[repro] OK: byte-for-byte identical
                           #  across two checkout paths" + "leak gate OK"
```

Consequences you must respect:
- No post-build mutation of binaries (no `strip`, no re-signing, no
  resource edits) — bytes are the release artifact.
- No nondeterminism into the build: no timestamps, no absolute paths in
  code, no env-dependent features.
- Windows binaries do **not** carry an ad-hoc signature by default (unlike
  macOS arm64). Leave linker defaults alone.
- Never add a signing step: this project ships unsigned, permanently. Any
  signing belongs to the downstream corporate project, not this repository.

---

## 3. Signing reality — read before "fixing" warnings

Chaperone ships **unsigned by design, permanently** (`.github/workflows/release.yml`,
`docs/RELEASE.md` §1). Code signing — a Windows Authenticode certificate or
any project-held release key — requires an entity to own the certificate or
key. This project has none: it is open source, maintained in the open, with
no company behind it. A corporate downstream project will add
identity/provenance signing later; for this repository the guarantee is
*verifiability by reconstruction*, not *trust in a signature*.

Verification follows SLSA principles (`.github/workflows/release.yml` lines
95–99, `docs/RELEASE.md` §1):

- **Reproducible build.** CI and local rebuilds normalize build-time paths
  with `--remap-path-prefix` (see `scripts/repro-env.sh` — checkout →
  `/workspace/`, `CARGO_HOME` → `/cargo/`); `scripts/repro-check.sh` builds
  from two different checkout paths and asserts byte-for-byte identity plus
  no leaked absolute paths. With the toolchain pinned
  (`rust-toolchain.toml`) and the build locked (`--locked`), anyone can
  reproduce the exact bytes from the exact source.
- **Hash manifest.** Every release publishes `SHA256SUMS.txt` and per-archive
  `.sha256` (`.github/workflows/release.yml` lines 68–72, 95–99).
  `sha256sum -c` confirms your download arrived intact.
- **The strongest check — build it yourself.** Clone the repository, run the
  same locked release build, and compare hashes against the published
  manifest. If they match, the binary provably came from this source — no
  key, no trust in a maintainer, no company.

Downloaded binaries trigger **SmartScreen** warnings because there is no
Authenticode signature. Users are instructed to verify by rebuilding (or by
hash) rather than click-through blindly. Do NOT "fix" this by ad-hoc
signing, adding a release key, or telling users to disable protections.

---

## 4. Platform status on Windows — what works, what is open

**Working today:**
- Full gateway + CLI over the named-pipe transport (default
  `\\.\pipe\chaperone-gw`, see `crates/transport/src/named_pipe.rs`).
- One-shot `http-bearer` / `http-basic` injectors (HTTPS via rustls).
- Local sealed vault (argon2id + AES-256-GCM, passphrase fallback) — the
  `keyring` crate's `windows-native` backend is wired behind the `keyring`
  feature but OFF by default and UNTESTED on hardware.
- `db-scram` against PostgreSQL (tokio-postgres — see
  `docs/CONNECTIVITY-MATRIX.md`).
- SSH sessions (russh), owner-bound session handles.
- `local-privilege` via the isolated privileged-helper (allowlist-pin
  mechanism, always confirmed unless pinned).
- Reproducible release build + packaging (`install.ps1` installs to
  `%LOCALAPPDATA%\Programs\chaperone`, registers a logon Scheduled Task).

**Open — these are exactly your first tasks:**

| Task | Notes |
|---|---|
| **Named-pipe security hardening** | `crates/transport/src/named_pipe.rs` §7–11 documents that v1 relies on the default DACL (D13) derived from the creating process token. Explicit restrictive ACLs require unsafe Win32 calls (`PSECURITY_DESCRIPTOR`, `SetNamedPipeHandleState`) which the workspace forbids (`unsafe_code = "forbid"` in `Cargo.toml`). Track this; do not bypass the safety gate. |
| **Keyring-backed vault sealing** | The `keyring` crate's `windows-native` backend is wired behind `feature = "keyring"` but OFF by default and UNTESTED. Enable it locally (`--features chaperone-vault/keyring`), exercise Windows Credential Manager prompts, report behavior. |
| **Scheduled Task deployment guide** | `install.ps1` registers a logon Scheduled Task (`ChaperoneGateway`), not a Windows service. Draft the deployment walkthrough: when the task starts, how the vault passphrase file (`vault.pass`) is read, and how the operator confirms the daemon bound the pipe. |
| **SmartScreen / no-Authenticode walkthrough** | Download the published v0.1.0-alpha.4 artifact (once tagged), document the exact SmartScreen prompts and the verification flow from `docs/RELEASE.md` on a clean Windows machine. |
| **Privilege elevation story** | The `chaperone-helper.exe` performs NO elevation by itself. On Windows, elevation mechanics (service/UAC) are undocumented. Draft the operator walkthrough: how to grant the helper authority through a service account or UAC bypass, pin commands in the allowlist, and configure `--helper-argv` in the serve config. |
| **Full test matrix on hardware** | `cargo test --locked --workspace` — 203 green as of the 2026-08-26 workspace pass (see `docs/HANDOFF.md` §3). Report ANY failure with full log; do not patch around a failing test silently. |

**Known gaps (NOT shipped, documented honestly):**
- **Event feed socket** — `crates/gateway-core/src/events.rs` (lines 12–17,
  34–38, 118–154): `EventHub` is `#[cfg(not(unix))]` a no-op on Windows. The
  `broadcast` method drops lines, `listen` binds nothing, `subscriber_count`
  returns 0. The config UI and policy-integrity guard still compile and
  function — they just cannot push real-time events to a socket. Track in
  `docs/HANDOFF.md` §"Known Gaps" (line 152: "Windows console/events sockets —
  cfg(unix) gates — named pipe implementation needed").
- **Console socket** — operator console (`chaperone console`) is Unix-only
  (UDS). No Windows equivalent exists yet; the confirmation gate falls back to
  the controlling-TTY prompt pattern from D8 where a console is attached.
- **Windows privileged commands** — `docs/CONNECTIVITY-MATRIX.md` (line 63)
  marks these as **🗺️ planned**: "helper protocol is platform-neutral;
  elevation story = service/UAC, untested."

---

## 5. The cross-check blocker: MSVC is mandatory

Unlike macOS (where CI builds on `macos-latest` and local Apple Silicon is
first-class), Windows builds depend on crates that need MSVC's `lib.exe`:

- `ring` (via `docs/RELEASE.md`, `Cargo.lock`) requires a C compiler +
  linker from the MSVC toolchain.
- `aws-lc-sys` (if pulled in transitively) has the same constraint.

The GNU target (`x86_64-pc-windows-gnu`) will fail to link these crates. The
`windows-latest` CI runner is the **authoritative** gate for reproducibility
because it installs MSVC + Windows SDK in a known-good configuration. Local
builds must match: use the `x64 Native Tools Command Prompt for VS 2022` or
`rustup` with the MSVC host triple. If `cargo build` fails on `ring` or
`aws-lc-sys`, that is almost certainly an MSVC/toolchain mismatch, not a
code problem.

---

## 6. Rules you must not break

From the [brief](IMPLEMENTATION_AGENT_BRIEF.md) §3 — violating any of these
silently is the worst thing you can do here:

- **No secret in logs, errors, debug output, or audit records. Ever.**
- **Default-deny holds.** There is no permissive mode to "help testing".
- **Attribution before action**: signature + freshness verified before any
  body parsing. Never reorder for convenience.
- **Secure fragility**: secrets live in zeroize-on-drop buffers for one use;
  retries re-fetch; caching secrets to smooth anything is prohibited — even
  "just on Windows", even "just temporarily".
- **Never weaken a security property to make a test pass.** Fix the test.

Working discipline: small legible commits with honest messages; tests written
against the spec first where possible; when the spec is silent, decide
explicitly and record it in `docs/DESIGN-DECISIONS.md` (follow the D1–D38
format); when the spec is wrong, file it in `docs/SPEC-ISSUES.md`.

---

## 7. Repo mechanics and hygiene

- Branch + pull request is preferred over direct pushes to `main` while you
  find your footing; keep PRs small and reviewable.
- Commit message style: imperative subject, blank line, body explaining the
  *why* — security-relevant tradeoffs stated explicitly. See `git log` for
  the house voice.
- Never commit: audit key seeds, tokens, VAULT_TOKEN values, local vault
  files, audit journals. The `.gitignore` covers common names; treat
  anything credential-shaped as radioactive anyway.
- Vulnerabilities go through [SECURITY.md](../SECURITY.md) privately — never
  public issues.

---

## 8. Definition of done for the Windows engagement

1. `scripts/repro-check.sh` green on Windows (built with MSVC, matching the
   `windows-latest` CI configuration), with findings documented (toolchain
   notes, any nondeterminism sources).
2. Full workspace tests green on hardware; failures (if any) reported as
   issues with reproduction steps.
3. Named-pipe transport validated end-to-end (connect/disconnect,
   pipe-busy backoff from `named_pipe.rs:75-93`, owner-only permissions).
4. SmartScreen workaround documented: a step-by-step walkthrough of
   downloading a release artifact, seeing the SmartScreen prompt, and
   verifying by hash or rebuild per `docs/RELEASE.md`.
5. Scheduled Task deployment guide drafted: install.ps1 behavior, vault.pass
   file placement, task start verification, pipe binding confirmation.
6. A short findings memo: everything surprising, everything broken,
   everything that made you double-take. That memo drives the next milestone.
