# Builder Notes — macOS

You are building and validating Chaperone on Apple hardware. This document
is your brief: what the project is, what "done" means for the Mac binary,
the rules you must not break, and the specific work we need from you. Read
it fully before building anything.

---

## 1. What you are building (one paragraph)

Chaperone is a local-first authentication broker: an AI agent sends a signed
intent naming a credential *reference*; our gateway daemon verifies who is
asking, adjudicates against default-deny policy, resolves the real secret at
the last moment, injects it on the outbound side, and returns results — so no
credential ever enters the agent's context, transport, or logs. The Mac build
ships two binaries: `chaperone` (operator CLI + gateway daemon) and
`chaperone-helper` (an isolated process that executes pinned privileged
commands). Everything is Apache-2.0, built in the open.

**Read in this order before coding:**
1. [`docs/IMPLEMENTATION_AGENT_BRIEF.md`](IMPLEMENTATION_AGENT_BRIEF.md) — operating brief and non-negotiable rules
2. [`docs/01-protocol-spec.md`](01-protocol-spec.md) — the wire contract that governs all other docs
3. [`docs/02-architecture-spec.md`](02-architecture-spec.md) §4 — platform matrix, Rust rationale
4. [`docs/RELEASE.md`](RELEASE.md) — how releases are produced and verified
5. [`docs/PLAN.md`](PLAN.md) — where we are and what remains

## 2. Toolchain and build

```sh
git clone https://github.com/o3willard-AI/Chaperone && cd Chaperone
. ./scripts/repro-env.sh   # REQUIRED: sets the --remap-path-prefix RUSTFLAGS
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
```

- **Source `scripts/repro-env.sh` before building.** rustc embeds absolute
  build-time paths (your checkout root and `$CARGO_HOME` registry sources)
  into the binaries; without the remap env your rebuild embeds `/Users/<you>/...`
  and can never match CI's bytes (found 2026-08-27: the alpha.5 binary embeds
  `/Users/runner/.cargo/registry/...`).

- `rust-toolchain.toml` pins **exactly 1.98.0**; rustup provisions it on
  first build. Do not bump it unilaterally — reproducibility depends on it.
- **`--locked` always.** Dependency drift is a supply-chain event, not a
  convenience. If a dependency genuinely must change, that is a reviewed
  commit updating `Cargo.toml` + `Cargo.lock` together with rationale.
- CI already builds `aarch64-apple-darwin` on GitHub runners. Your value-add
  is *real hardware*: does it run, does Gatekeeper behave as documented, do
  Keychain/launchd integrations actually work?

### Reproducibility discipline (non-negotiable)

rustc bakes absolute build paths (checkout root + `$CARGO_HOME` registry
sources) into every binary via `file!()`/panic locations and debuginfo. A
rebuild on the SAME machine at the SAME path is self-consistent by
construction and proves nothing about what a third party gets.

`scripts/repro-check.sh` (default mode) is therefore a **two-path** check:
build A in this checkout, build B in a second copy of the tree at a different
path, both with the canonical remap env from `scripts/repro-env.sh`
(checkout → `/workspace/`, `$CARGO_HOME` → `/cargo/`), then byte-compare and
assert no `/Users/`, `/home/`, or `/root/` paths remain embedded. On your Mac:

```sh
./scripts/repro-check.sh   # must print "[repro] OK: byte-for-byte identical
                           #  across two checkout paths" + "leak gate OK"
```

Consequences you must respect:
- No post-build mutation of binaries (no `strip`, no re-codesign, no
  resource edits) — bytes are the release artifact.
- No nondeterminism into the build: no timestamps, no absolute paths in
  code, no env-dependent features.
- arm64 macOS links with an **ad-hoc signature by default**; that signature
  is content-derived and therefore reproduces. Leave linker defaults alone.
- Never add a signing step: this project ships unsigned, permanently. Any
  signing belongs to the downstream corporate project, not this repository.

## 3. Signing reality — read before "fixing" warnings

Chaperone ships **unsigned, by design, permanently**. Code signing — a
Developer ID, notarization, or any project-held release key — requires an
entity to own the certificate or key. This project has none: it is open source
with no company behind it. A downstream corporate project will own
identity/provenance signing later.

Verification is *by reconstruction* instead (SLSA principles):

- **Reproducible builds**: bit-for-bit identical from source (see
  [docs/RELEASE.md](RELEASE.md)).
- **Hash manifests**: `SHA256SUMS.txt` + per-archive `.sha256`.
- The strongest check is to rebuild and compare the bytes yourself — no key,
  no trust in a maintainer.

Downloaded files get the `com.apple.quarantine` xattr; Gatekeeper will warn.
Users are instructed to verify by rebuilding (or by hash) rather than click
through blindly. Do NOT "fix" this by ad-hoc notarizing, adding a release key,
or telling users to disable protections.

## 4. Platform status on macOS — what works, what is open

Working today:
- Full gateway + CLI; Unix domain socket at
  `$XDG_RUNTIME_DIR/chaperone/gw.sock`, falling back to
  `$TMPDIR/chaperone-$USER/gw.sock` (XDG is typically unset on macOS — this
  path is created 0700).
- Operator console socket (`chaperone console --socket …`) — cfg(unix) ✓.
- SSH host-key pin store + TOFU; OpenSSH `known_hosts` import.
- Local vault sealed with argon2id + AES-GCM (passphrase).

Open — these are exactly your first tasks:

| Task | Notes |
|---|---|
| **Keychain-backed vault sealing** | The `keyring` crate's `apple-native` backend is wired behind the `keyring` feature but OFF by default. **VERIFIED on hardware (2026-08-29)**: `vault-init --sealer keyring` round-trips with no passphrase prompt and survives restart. Caveat — the Keychain item's default ACL allows silent read by the exact binary (cdhash) and by Apple-signed tools; the cdhash is unstable across rebuilds, so an upgraded binary triggers a fresh approval prompt (see LOCAL-VAULT-GUIDE.md). |
| **launchd integration** | ARCH-SPEC assigns launchd to the privileged-helper role. We ship the helper binary but elevation mechanics are deployment config. Draft the launchd plist(s) + sudoers/pin allowlist walkthrough for a real Mac. |
| **Gatekeeper/quarantine validation** | Download the published v0.1.0-alpha.1 asset, document the exact prompts and the verification flow from docs/RELEASE.md on a clean machine. |
| **Universal2 option** | Evaluate `lipo` of aarch64+x86_64 builds for one fat archive; only if both halves stay reproducible. |
| **Full test matrix on hardware** | `cargo test --locked --workspace` — 203 green as of the 2026-08-26 workspace pass (QA report: all suites incl. end_to_end, conformance, github_api, db_scram, sessions, privilege, console). Report ANY failure with full log; do not patch around a failing test silently. |

## 5. Rules you must not break

From the [brief](IMPLEMENTATION_AGENT_BRIEF.md) §3 — violating any of these
silently is the worst thing you can do here:

- **No secret in logs, errors, debug output, or audit records. Ever.**
- **Default-deny holds.** There is no permissive mode to "help testing".
- **Attribution before action**: signature + freshness verified before any
  body parsing. Never reorder for convenience.
- **Secure fragility**: secrets live in zeroize-on-drop buffers for one use;
  retries re-fetch; caching secrets to smooth anything is prohibited — even
  "just on macOS", even "just temporarily".
- **Never weaken a security property to make a test pass.** Fix the test.

Working discipline: small legible commits with honest messages; tests written
against the spec first where possible; when the spec is silent, decide
explicitly and record it in `docs/DESIGN-DECISIONS.md` (D1–D33 exist — follow
the format); when the spec is wrong, file it in `docs/SPEC-ISSUES.md`.

## 6. Repo mechanics and hygiene

- Branch + pull request is preferred over direct pushes to `main` while you
  find your footing; keep PRs small and reviewable.
- Commit message style: imperative subject, blank line, body explaining the
  *why* — security-relevant tradeoffs stated explicitly. See `git log` for
  the house voice.
- You will need your OWN GitHub account/access; do not ask for ours. Least
  privilege: read + branch access suffices to start.
- Never commit: audit key seeds, tokens, VAULT_TOKEN values, local vault
  files, audit journals. The `.gitignore` covers common names; treat
  anything credential-shaped as radioactive anyway.
- Vulnerabilities go through [SECURITY.md](../SECURITY.md) privately — never
  public issues.

## 6b. Hardware-pass findings (2026-08-25 QA) — already folded in

The first hardware pass verified arm64 AND x86_64 builds (both reproducible
under the pre-2026-08-28 same-path check; see the §6c addendum — same-path
verification could not detect embedded build paths, which the remap flags
now normalize);
x86_64 via Rosetta), full workspace tests green on macOS, and a real
install/smoke run. Items it surfaced, now addressed or tracked:

- **install.sh repo-root fallback** missed `$SCRIPT_DIR/target/release` —
  fixed (child-first candidate order).
- **Cross-target repro checks**: `repro-check.sh --target <triple>` now makes
  the manual two-clean-builds procedure scriptable for x86_64.
- Machine provisioning (rustup/Go/Rosetta was missing entirely): formalize a
  setup script if this becomes the standing build host.
- Still open for the next hardware pass: launchd guide beyond the installer
  plist, Gatekeeper walkthrough of a PUBLISHED artifact, Universal2 lipo
  packaging. (Keychain-sealed vault validation is DONE — verified 2026-08-29;
  see the caveat above.)

## 6c. Hardware-pass findings (2026-08-27 QA, v0.1.0-alpha.5 verification)

Full verification of current `main` (Phase 14 + D41/D42-era code — events
feed, policy-file integrity guard, `chaperone-ui`, per-instance UI access
token) on Apple Silicon (`aarch64-apple-darwin`), ahead of the alpha.5 tag
that fixes the Windows build break:

- `cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper` — clean.
- `cargo test --locked --workspace` — **203 passed, 0 failed**, matching the
  count in `docs/HANDOFF.md`.
- `scripts/repro-check.sh` — **OK: byte-for-byte identical** across two clean
  builds, both binaries. (Addendum 2026-08-28: this check compared two builds
  at the SAME path and could not see path embedding; the published alpha.5
  Mac binary embeds `/Users/runner/.cargo/registry/...`. Fixed by the
  path-remap flags — see `scripts/repro-env.sh` and docs/RELEASE.md; the
  check now compares two different checkout paths and gates on leaked paths.)

No fixes required — macOS was never blocking this release. The items listed
in §6b as "still open for the next hardware pass" remain open and don't
block v0.1.0-alpha.5; they're future-milestone work, not release gates.

## 7. Definition of done for the Mac engagement

1. `scripts/repro-check.sh` green on Apple silicon, with findings documented
   (toolchain notes, any nondeterminism sources).
2. Full workspace tests green on hardware; failures (if any) reported as
   issues with reproduction steps.
3. Keychain-sealed vault validated end-to-end (create/set/get across daemon
   restarts) — DONE 2026-08-29 through the shipped CLI (`vault-init --sealer
   keyring`, zero prompts, survives restart). Recommendation: keep it behind
   the feature flag; document the Apple-native ACL caveat (silent read by
   Apple-signed tools; cdhash instability on rebuild → approval prompt on
   upgrade) rather than promoting blindly.
4. launchd deployment guide drafted: plist for the daemon, authorization path
   for the helper, pin-allowlist bootstrap commands.
5. Gatekeeper/quarantine walkthrough of the published alpha artifact written
   up for end users (screenshots welcome).
6. A short findings memo: everything surprising, everything broken, everything
   that made you double-take. That memo drives the next milestone.
