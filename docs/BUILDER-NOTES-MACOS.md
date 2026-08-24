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
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
```

- `rust-toolchain.toml` pins **exactly 1.98.0**; rustup provisions it on
  first build. Do not bump it unilaterally — reproducibility depends on it.
- **`--locked` always.** Dependency drift is a supply-chain event, not a
  convenience. If a dependency genuinely must change, that is a reviewed
  commit updating `Cargo.toml` + `Cargo.lock` together with rationale.
- CI already builds `aarch64-apple-darwin` on GitHub runners. Your value-add
  is *real hardware*: does it run, does Gatekeeper behave as documented, do
  Keychain/launchd integrations actually work?

### Reproducibility discipline (non-negotiable)

`scripts/repro-check.sh` builds both release binaries twice from clean state
and asserts byte-for-byte identity. On your Mac:

```sh
./scripts/repro-check.sh   # must print "[repro] OK"
```

Consequences you must respect:
- No post-build mutation of binaries (no `strip`, no re-codesign, no
  resource edits) — bytes are the release artifact.
- No nondeterminism into the build: no timestamps, no absolute paths in
  code, no env-dependent features.
- arm64 macOS links with an **ad-hoc signature by default**; that signature
  is content-derived and therefore reproduces. Leave linker defaults alone.
- If you enable a Developer ID certificate later, codesigning MUST happen
  inside the release pipeline *before* checksums and ed25519 signatures are
  computed — never after distribution. Changing bytes post-signature breaks
  every published verification.

## 3. Signing reality — read before "fixing" warnings

We ship **without corporate OS code signing** (no Developer ID, no
notarization): that requires an entity and budget we have deliberately not
spent before gauging community interest. Instead:

- Artifacts carry sha256 manifests plus **our own ed25519 detached
  signatures**, produced by `chaperone release-sign`, verifiable per
  [docs/RELEASE.md](RELEASE.md).
- Builds are bit-for-bit reproducible from source.
- Downloaded files get the `com.apple.quarantine` xattr; Gatekeeper will
  warn. Users are instructed to verify hash+signature rather than click
  through blindly. Do NOT "fix" this by ad-hoc notarizing or telling users
  to disable protections.

If/when the organization obtains a Developer ID, the integration order is:
codesign in-pipeline → notarize → staple → then checksums/signatures → then
publish. Nothing ships between steps.

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
| **Keychain-backed vault sealing** | The `keyring` crate's `apple-native` backend is wired behind the `keyring` feature but OFF by default and UNTESTED on hardware. Enable locally (`--features keyring`), exercise Keychain prompts, report behavior. |
| **launchd integration** | ARCH-SPEC assigns launchd to the privileged-helper role. We ship the helper binary but elevation mechanics are deployment config. Draft the launchd plist(s) + sudoers/pin allowlist walkthrough for a real Mac. |
| **Gatekeeper/quarantine validation** | Download the published v0.1.0-alpha.1 asset, document the exact prompts and the verification flow from docs/RELEASE.md on a clean machine. |
| **Universal2 option** | Evaluate `lipo` of aarch64+x86_64 builds for one fat archive; only if both halves stay reproducible. |
| **Full test matrix on hardware** | `cargo test --locked --workspace` — expect ~154 green. db-scram tests skip without `CHAPERONE_TEST_PG`; console/fuzz unix-gated ✓. Report ANY failure with full log; do not patch around a failing test silently. |

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
- Never commit: signing seeds, tokens, VAULT_TOKEN values, local vault
  files, audit journals. The `.gitignore` covers common names; treat
  anything credential-shaped as radioactive anyway.
- Vulnerabilities go through [SECURITY.md](../SECURITY.md) privately — never
  public issues.

## 7. Definition of done for the Mac engagement

1. `scripts/repro-check.sh` green on Apple silicon, with findings documented
   (toolchain notes, any nondeterminism sources).
2. Full workspace tests green on hardware; failures (if any) reported as
   issues with reproduction steps.
3. Keychain-sealed vault validated end-to-end (create/set/get across daemon
   restarts) with a written recommendation: promote out of feature flag or
   document why not.
4. launchd deployment guide drafted: plist for the daemon, authorization path
   for the helper, pin-allowlist bootstrap commands.
5. Gatekeeper/quarantine walkthrough of the published alpha artifact written
   up for end users (screenshots welcome).
6. A short findings memo: everything surprising, everything broken, everything
   that made you double-take. That memo drives the next milestone.
