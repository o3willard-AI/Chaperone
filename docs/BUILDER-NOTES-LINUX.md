# Builder Notes — Linux

You are building and validating Chaperone on Linux. This document is your
brief: what the project is, what "done" means for the Linux build, the
rules you must not break, and the specific work we need from you. Read it
fully before building anything.

---

## 1. What you are building (one paragraph)

Chaperone is a local-first authentication broker: an AI agent sends a signed
intent naming a credential *reference*; our gateway daemon verifies who is
asking, adjudicates against default-deny policy, resolves the real secret at
the last moment, injects it on the outbound side, and returns results — so no
credential ever enters the agent's context, transport, or logs. The Linux
build ships two binaries: `chaperone` (operator CLI + gateway daemon) and
`chaperone-helper` (an isolated process that executes pinned privileged
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

```sh
git clone https://github.com/o3willard-AI/Chaperone
cd Chaperone
. ./scripts/repro-env.sh   # REQUIRED: sets the --remap-path-prefix RUSTFLAGS
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
```

- **Source `scripts/repro-env.sh` before building.** rustc embeds absolute
  build-time paths (your checkout root and `$CARGO_HOME` registry sources)
  into the binaries via `file!()`/panic locations and debuginfo; without the
  remap env your rebuild embeds `/home/<you>/...` and can never match CI's
  bytes. This affects Linux too — it is a cargo/rustc behavior, not a macOS
  or Windows one.

- `rust-toolchain.toml` pins **exactly 1.98.0**; rustup provisions it on first
  build. Do not bump it unilaterally — reproducibility depends on it.
- **`--locked` always.** Dependency drift is a supply-chain event, not a
  convenience. If a dependency genuinely must change, that is a reviewed
  commit updating `Cargo.toml` + `Cargo.lock` together with rationale.
- The release pipeline builds Linux with target `x86_64-unknown-linux-gnu`
  on `ubuntu-latest` (`.github/workflows/release.yml` lines 25–26). The
  toolchain here must match that target: a glibc 2.x host with a working
  C linker (CC=cc). No cross-compilation flags or special features are
  needed — the workspace is pure-Rust with standard Linux libc bindings.
- On disk-constrained hosts: `cargo clean` first. The full workspace build
  (release + test artifacts) pulls in `ring` (needs a C compiler) and
  `rustix` (Linux raw-sys syscalls); ensure `cc`, `make`, and the kernel
  headers are present for any native build scripts.

### Reproducibility discipline (non-negotiable)

`scripts/repro-check.sh` (default mode) is a **two-path** check: build A in
this checkout, build B in a second copy of the tree at a different path, both
with the canonical remap env from `scripts/repro-env.sh` (checkout →
`/workspace/`, `$CARGO_HOME` → `/cargo/`), then byte-compare and assert no
`/home/`, `/root/`, or `/Users/` paths remain embedded:

```sh
./scripts/repro-check.sh   # must print "[repro] OK: byte-for-byte identical
                           #  across two checkout paths" + "leak gate OK"
```

ELF does not carry a build `TimeDateStamp` field (unlike Windows PE, where
MSVC's `link.exe` stamps one by default — see D42), so a same-machine
rebuild always matched; that was never the whole story. rustc still embeds
absolute source paths on Linux, and a rebuild in a different `$HOME`
produced different bytes (found via the 2026-08-27 macOS QA pass on
alpha.5). The path-remap env fixes that on every platform; D42's
`.cargo/config.toml` `/Brepro` link-arg stays scoped to
`x86_64-pc-windows-msvc` and remains required there.

Consequences you must respect:
- No post-build mutation of binaries (no `strip`, no re-signing, no
  resource edits) — bytes are the release artifact.
- No nondeterminism into the build: no timestamps, no absolute paths in
  code, no env-dependent features.
- Never add a signing step: this project ships unsigned, permanently. Any
  signing belongs to the downstream corporate project, not this repository.

---

## 3. Signing reality — read before "fixing" warnings

Chaperone ships **unsigned by design, permanently**
(`.github/workflows/release.yml`, `docs/RELEASE.md` §1). Code signing — any
project-held release key — requires an entity to own the key. This project
has none: it is open source, maintained in the open, with no company behind
it. A corporate downstream project will add identity/provenance signing
later; for this repository the guarantee is *verifiability by reconstruction*,
not *trust in a signature*.

Verification follows SLSA principles (`docs/RELEASE.md` §1–2,
`.github/workflows/release.yml` lines 95–99):

- **Reproducible build.** CI and local rebuilds normalize build-time paths
  with `--remap-path-prefix` (see `scripts/repro-env.sh` — checkout →
  `/workspace/`, `CARGO_HOME` → `/cargo/`); `scripts/repro-check.sh` builds
  from two different checkout paths and asserts byte-for-byte identity plus
  no leaked absolute paths. With the toolchain pinned
  (`rust-toolchain.toml`) and the build locked (`--locked`), anyone can
  reproduce the exact bytes from the exact source.
- **Hash manifest.** Every release publishes `SHA256SUMS.txt` (sha256 of
  each archive) plus a per-archive `.sha256` file
  (`.github/workflows/release.yml` lines 68–72, 95–99).
  `sha256sum -c` confirms your download arrived intact.
- **The strongest check — build it yourself.** Clone the repository, run the
  same locked release build, and compare hashes against the published
  manifest. If they match, the binary provably came from this source — no
  key, no trust in a maintainer, no company.

---

## 4. Platform status on Linux — what works, what is open

**Working today:**
- Full gateway + CLI over the Unix-domain socket at
  `$XDG_RUNTIME_DIR/chaperone/gw.sock`, falling back to
  `$TMPDIR/chaperone-$USER/gw.sock` (XDG is typically unset on minimal
  containers — this path is created `0700`). See
  `crates/transport/src/server.rs` lines 206–220.
- Operator console socket (`chaperone console --socket …`) —
  `cfg(unix)` active; see `crates/cli/src/main.rs` lines 232–269.
- Event feed socket (`--events-socket PATH`) — `EventHub` is
  `#[cfg(unix)]` with a real UnixListener + thread accept loop
  (`crates/gateway-core/src/events.rs` lines 21–29, 40–116).
- One-shot `http-bearer` / `http-basic` injectors (HTTPS via rustls).
- `db-scram` against PostgreSQL (tokio-postgres, SCRAM-SHA-256).
- SSH host-key pin store + TOFU; OpenSSH `known_hosts` import.
- Local vault sealed with argon2id + AES-256-GCM (passphrase) or
  keyring (D5); `keyring` crate's `linux-native` backend behind a feature
  flag.
- `local-privilege` via the isolated privileged-helper (allowlist-pin
  mechanism, always confirmed unless pinned).
- systemd user service (`chaperoned.service`) — see
  `packaging/chaperoned.service`; `install.sh` handles installation.
- Reproducible build + packaging (`install.sh` installs to
  `~/.local/bin`, registers the systemd user unit).

**Open — items for the hardware pass:**

| Task | Notes |
|---|---|
| **glibc portability** | The release binary is built on `ubuntu-latest` (glibc ~2.39). It will **not** run on distros with an older glibc (e.g. Alma/Rocky 9 / RHEL-family at glibc 2.34). A `build-alma-style` (glibc 2.34) build host would broaden compatibility; track, don't silently accept. |
| **Non-systemd distros** | `install.sh` only installs the systemd user unit when `systemctl` is present
  (`install.sh` lines 59–68). **Alpine, NixOS, and other non-systemd distros
  are out of scope** — no OpenRC/init.d/Supervisor template ships. Run the
  daemon manually (`chaperone serve …`) or use your distro's own service
  manager. |
| **Keyring-backed vault sealing** | The `keyring` crate's `linux-native` backend (kernel keyring) is wired
  behind `feature = "keyring"` but OFF by default and UNTESTED on hardware.
  Enable locally (`--features chaperone-vault/keyring`), exercise prompts,
  report behavior. |
| **Full test matrix on hardware** | `cargo test --locked --workspace` — 203 passed / 0 failed as of the
  2026-08-26 workspace pass (`docs/HANDOFF.md` line 5). Report ANY failure
  with full log; do not patch around a failing test silently. |

**Known gaps (NOT shipped, documented honestly):**
- **Cross-distro binary portability** — no musl-static or glibc-2.34
  build target exists in `release.yml`'s three-platform matrix
  (ubuntu-latest, macos-latest, windows-latest). The single glibc target
  means the published binary assumes the runner's glibc version. See the
  "glibc portability" task above.

---

## 5. The systemd service and install flow

`install.sh` (lines 59–68) detects Linux + `systemctl` and installs the
`chaperoned.service` user unit from `packaging/chaperoned.service`, substituting
`%H` with `$HOME`. The unit starts `chaperone serve` with the full set of
paths:

```
--enrollment %H/.config/chaperone/enrollment.json
--policy     %H/.config/chaperone/policy.toml
--store      %H/.config/chaperone/vault.bin
--audit-journal %H/.config/chaperone/audit.jsonl
--audit-key  %H/.config/chaperone/audit.key
--passphrase-file %H/.config/chaperone/vault.pass
--console-socket %H/.config/chaperone/console.sock
```

The `--console-socket` flag is `#[cfg(unix)]`-gated (`crates/cli/src/main.rs`
line 647): on non-Unix platforms it falls back to the stdio gate
(lines 643–653). On Linux the console socket is the default confirmation
surface for headless operation.

The post-install checklist (`install.sh` lines 93–109) tells the operator to:
1. Write the vault passphrase to `~/.config/chaperone/vault.pass` (`0600`)
2. Create enrollment/policy/vault
3. Run `chaperone ui-token rotate --token ~/.config/chaperone/ui.token` (D41)
4. `systemctl --user enable --now chaperoned`
5. `chaperone version`

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
  "just on Linux", even "just temporarily".
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

## 8. Definition of done for the Linux engagement

1. `scripts/repro-check.sh` green on Linux (matching the `ubuntu-latest` CI
   configuration), with findings documented (toolchain notes, any
   nondeterminism sources).
2. Full workspace tests green on hardware; failures (if any) reported as
   issues with reproduction steps.
3. systemd service validated end-to-end: install via `install.sh`, start via
   `systemctl --user enable --now chaperoned`, confirm pipe/socket binding
   and the D41 UI-token gate behavior.
4. Operator console socket validated: `chaperone console --socket` connects
   and the confirmation gate works over UDS.
5. Event feed socket validated: `--events-socket` binds and `broadcast`
   reaches a subscriber (a small stream reader, per D35).
6. A short findings memo: everything surprising, everything broken,
   everything that made you double-take. That memo drives the next milestone.
