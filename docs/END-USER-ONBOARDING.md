# End-User Onboarding — Findings and Directives

Written after the first live install-and-QA pass of the Windows build on
real hardware (2026-08-28): fresh box, no prior Rust/Chaperone install,
following the project's own docs as a first-time operator would. This is
not a code review — it's what actually happened trying to go from a
release archive to a working, verified, brokered credential. Every claim
below was reproduced, not inferred from reading source.

**Audience: implementation agents.** This document is the brief for the
next milestone — closing the gap between "the Windows build compiles and
passes its test suite" (true today) and "a non-contributor can install
this and trust it in under ten minutes" (not true today). Read
[BUILDER-NOTES-WINDOWS.md](BUILDER-NOTES-WINDOWS.md) first if you haven't;
this document picks up where its Definition of Done leaves off.

**Who "first true end-user" means here:** someone who is not a Chaperone
contributor, has never read PROTO-SPEC or ARCH-SPEC, downloaded a release
archive because someone told them it solves a real problem (agent has my
Stripe key in its context and that's terrifying), and wants working
brokering before they lose patience. They will not read DESIGN-DECISIONS.md
to understand why the vault has no recovery path. They will not write Rust
to prove the install works. Every recommendation below is filtered through
that bar.

---

## Already fixed this pass (context, not open work)

So the priority list below isn't read against a stale baseline:

- Windows build was fundamentally broken (`cfg(unix)` leakage) for the
  `v0.1.0-alpha.3`/`v0.1.0-alpha.4` tags — neither ever actually published;
  fixed on `main` before this pass started.
- Windows release builds were not byte-reproducible (MSVC linker
  timestamp) — fixed, [PR #30](https://github.com/o3willard-AI/Chaperone/pull/30), D42.
- `install.ps1` pointed the Scheduled Task at the wrong enrollment
  filename (`enrollment.json` vs. the `agents.json` every other doc uses)
  and never mentioned the required D41 `ui-token rotate` step — fixed,
  [PR #35](https://github.com/o3willard-AI/Chaperone/pull/35).
- `install.ps1` crashed opaquely (bare HRESULT) when Scheduled Task
  registration hit Windows' UAC token-filtering wall — now caught, warned,
  and degrades to an actionable direct-`serve` instruction — same PR.

None of this was caught before because **nothing had run `install.ps1`
against a live daemon on real Windows hardware before this pass.** That
fact is itself the highest-priority finding — see P1-1.

---

## Priority-ranked issues

| # | Issue | Tier | One-liner |
|---|---|---|---|
| P0-1 | No self-verification path | Blocking | A first-time user has no way to confirm "it's actually working" short of writing a signed-intent client by hand (which is what this QA pass had to do) |
| P0-2 | Scheduled Task requires elevation the installer doesn't ask for | Blocking | The only persistence mechanism silently doesn't work for the common case (personal machine, Administrators-group account, non-elevated shell) |
| P0-3 | SmartScreen walkthrough still doesn't exist — **fixed, issue #39** | Blocking | First thing a real downloader sees is "Windows protected your PC"; current plan (BUILDER-NOTES-WINDOWS.md §4) is a doc a developer would write for developers |
| P0-4 | Post-install is a 7-command manual CLI sequence | Blocking | `install.ps1` prints instructions; nothing launches the wizard that already exists to do this by pointing and clicking |
| P1-1 | No install/serve integration test exists | High | Every bug found this pass (enrollment.json, missing ui-token step, elevation crash) would have been caught by a script running `install.ps1` + one signed intent in CI |
| P1-2 | Vault unlock is a plaintext passphrase file for any headless run | High | `keyring`/Windows Credential Manager backend exists, is OFF by default, UNTESTED |
| P1-3 | `--events-socket` silently lies about success on Windows — **fixed in PR #52** | High | Prints "event feed listening on ..." and returns `Ok(())` while doing nothing — confirmed by reading `events.rs`, not a guess |
| P2-1 | `--console-socket` silently ignored on Windows — **fixed in PR #52** | Follow-up | No message; falls back to stdio_gate with no explanation |
| P2-2 | GETTING-STARTED.md's Windows path isn't actually written | Follow-up | Every example uses `~/.config/chaperone` and Unix tools (`nc -U`, nonexistent on Windows) with no Windows-specific callout |

---

## P0-1 — No self-verification path

**What happened:** to confirm the Windows build actually brokers a
credential (not just "the process didn't crash"), this QA pass had to:
read `crates/gateway-core/tests/conformance.rs` to learn the wire shape of
a signed intent, temporarily add `ed25519-dalek`/`base64` as dependencies
and `chaperone-protocol/test-util` as a feature to `crates/cli/Cargo.toml`,
hand-write a throwaway example binary, and run it against a hand-rolled
local HTTP capture server. That is not something a real end-user can or
should do. The operator CLI has enrollment, vault, audit, and policy
tooling — nothing that plays the *agent* role even minimally, and nothing
that answers "is my install healthy" beyond `chaperone version` (which
only proves the binary runs, not that it can broker anything).

**Why it matters:** the entire value proposition is "prove your agent
never saw the secret." A user who can't self-verify that claim has to
trust it blind, which undermines the exact thing the reproducible-build
posture (RELEASE.md) is trying to earn.

**Recommended fix shape (two complementary pieces, both needed):**

1. `chaperone doctor` (or `selftest`): checks binary version, transport
   endpoint reachable (connect/disconnect only, no real intent), vault
   unlocks with the configured passphrase source, policy.toml parses,
   enrollment store is readable, audit chain's tail verifies. Exits
   non-zero with a specific, actionable line per failed check — this is
   diagnostic tooling, not a new trust surface, so it does not need to
   touch the signing/policy path at all.
2. A minimal, *sanctioned* test-agent script — not a Rust example
   requiring a full workspace checkout, but something an end-user with
   just the release archive can run: a ~30-line Python or Node script
   (no extra dependencies beyond a JSON/Ed25519 lib both ecosystems ship
   natively-adjacent) that enrolls itself, sends one intent against a
   policy the wizard just created, and prints pass/fail. This is the
   thing `docs/skill/` should probably own, since the agent-skill and
   "how do I know this works" answer are the same audience.

Both together close the loop the wizard's "Setup complete" screen
currently can't: right now the wizard can tell you the *files* exist, not
that the *daemon* will actually broker anything for them.

## P0-2 — Scheduled Task requires elevation the installer doesn't ask for [FIXED — issue #38, PR #59]

**Fixed:** `install.ps1` now tries the direct (non-elevated) registration
first, offers one scoped elevation prompt with clear consent text if that
fails (a short-lived hidden helper process that does nothing but the
`Register-ScheduledTask` call — the daemon and wizard never run elevated),
and falls back to a Startup-folder shortcut (no elevation at all) if
elevation is declined or unavailable. Verified on hardware in both
outcomes. `uninstall.ps1` updated to match (deleting hit the identical UAC
wall). Original finding preserved below for context.

**What happened:** `Register-ScheduledTask` (and legacy `schtasks.exe`)
return Access Denied when the invoking shell isn't elevated — including
for accounts that ARE local Administrators, because UAC token-filtering
denies Task Scheduler writes to the filtered (non-elevated) token
regardless of group membership. This is not an edge case: a personal
Windows machine with one user account almost always has that account in
Administrators. [PR #35](https://github.com/o3willard-AI/Chaperone/pull/35)
stops the installer from crashing opaquely on this and gives a clear
fallback message, but **the underlying product gap is unresolved**: a
real end-user still ends up with no persistent background gateway unless
they know what "run PowerShell as Administrator" means and choose to do
it, or manually re-run `chaperone serve` every session.

**Recommended fix shape (pick one, this needs a product decision, not
just an engineering one — flag for a design decision, D-numbered):**

- (a) **Installer self-elevation prompt**: detect non-elevated context
  before doing any work, and offer `Start-Process -Verb RunAs` to relaunch
  itself elevated with clear, upfront consent language (what it will do,
  why it needs it) — one UAC prompt, not a silent surprise.
- (b) **Different persistence mechanism that doesn't need Task Scheduler
  writes**: e.g., a Startup-folder shortcut (`shell:startup`, pure
  per-user, no elevation, no admin API) trading "restarts on crash" for
  "simpler, always works." Given `install.ps1`'s own comment says "PREVIEW
  quality... no service account story without codesigning," a
  no-elevation-required fallback may be the more honest v1 posture than a
  Scheduled Task that quietly doesn't work for the majority case.
- (c) Both: try (a) once, fall back to (b) if the user declines elevation.

Whichever is chosen, update the "Idempotent. Per-user only." claim at the
top of `install.ps1` — it currently reads as a promise that no elevation
is ever needed, which this pass proved false.

## P0-3 — SmartScreen walkthrough still doesn't exist [FIXED — issue #39]

**Fixed:** [INSTALL.md](../INSTALL.md)'s Windows section now opens with the
exact browser and SmartScreen prompt text, a hash-only `Get-FileHash`
verification path requiring no Rust toolchain (tested against a real
multi-platform `SHA256SUMS.txt` shape — both the match and mismatch cases
before trusting it), and plain-language reasoning for why unsigned is
permanent — positioned as the primary first-time path, ahead of the
rebuild-from-source instructions. Original finding preserved below for
context.

`BUILDER-NOTES-WINDOWS.md` §4 already lists this as an open item
("Download the published artifact... document the exact SmartScreen
prompts and the verification flow... on a clean Windows machine") and it
is still open. This is the literal first moment of trust for anyone who
finds this project through a link rather than a git clone. `RELEASE.md`'s
answer ("verify by rebuilding instead of clicking through") is correct
and honest, but it is written for a developer with a Rust toolchain
already installed — exactly the audience that does NOT need convincing,
because they already read past the warning. The actual first-time
non-developer downloader needs:

- Screenshots (or precise, copy-pasteable prompt text) of exactly what
  SmartScreen says for this specific unsigned binary, so they can
  recognize "this is the expected warning, not a sign something's wrong"
  vs. "this is actually flagged as malware."
- A one-line hash-check they can run **without installing a Rust
  toolchain** — `Get-FileHash` against `SHA256SUMS.txt` is already
  possible with tools every Windows box has; the current docs jump
  straight to "rebuild from source," skipping the much lower-friction
  hash-only check that's already true today.
- Plain language about *why* it's unsigned (open-source, no owning
  entity) pre-empting the "this looks sketchy" reaction, not just
  documenting it for people who already trust the project enough to read
  RELEASE.md.

**macOS analogue (issue #51) — closed.** Gatekeeper is macOS's version of
this same first-moment-of-trust problem, and it had the identical gap:
`INSTALL.md` used to say only "Gatekeeper will warn... verify by
rebuilding from source instead of bypassing blindly," which is the same
developer-audience answer called out above, and doubly unhelpful on
macOS specifically because rebuilding from source didn't even reproduce
the published bytes until the `LC_UUID` fix (see the reproducible-build
finding). `INSTALL.md`'s [macOS section](../INSTALL.md#gatekeeper-unsigned-binaries)
now documents, verified directly rather than assumed: the exact
difference in behavior between double-clicking in Finder (blocked),
`spctl` (reports `rejected`), and running from Terminal (not blocked —
relevant because that's how `install.sh` and the launchd service actually
invoke it), plus both a no-Terminal fix (System Settings → Privacy &
Security → "Open Anyway") and a Terminal one (`xattr -dr
com.apple.quarantine`), distinct from "rebuild from source."

## P0-4 — Post-install is a 7-command manual CLI sequence [FIXED — issue #40, PR #59]

**Fixed:** `install.ps1` now mirrors `install.sh` (from PR #56's Unix
half): generates the D41 ui-token itself, starts `serve` in setup-only
mode, and opens the wizard URL in the default browser — verified on
hardware, including the token → `303` redirect and cookie set exactly per
D41. Skips cleanly with `CHAPERONE_NO_WIZARD=1` or when broker artifacts
already exist. Original finding preserved below for context.

Even after [PR #35](https://github.com/o3willard-AI/Chaperone/pull/35)'s
fix, `install.ps1` finishes by printing text: set a passphrase file,
generate a ui-token, then (per GETTING-STARTED.md) run `serve`, open a
URL, click through a wizard, restart `serve`. The wizard itself is good —
server-rendered, no build step, walks through vault/audit-key/policy
creation — but nothing in the installer *launches* it. A first-time user
has to correctly execute a documented sequence of terminal commands to
even reach the point-and-click experience that already exists.

**Recommended fix shape:** `install.ps1` (and the Unix `install.sh`)
should, after a successful install: generate the ui-token automatically
(silently, no operator action — this is not secret material an operator
chooses, D41 just needs *a* random token to exist), start `serve` in
setup-only mode itself, and open the wizard URL in the default browser
(`Start-Process` on Windows, `xdg-open`/`open` elsewhere). The manual CLI
path documented in GETTING-STARTED.md should remain and stay accurate —
it's the right on-ramp for people who want it — but it should not be the
*only* path, and it should not be the default result of running the
installer.

## P1-1 — No install/serve integration test exists

**This is the highest-leverage recommendation in this document.** Every
bug this pass found and fixed — the `enrollment.json`/`agents.json`
mismatch, the missing ui-token step, the opaque elevation crash — is
exactly the class of bug that a script running `install.ps1` → `serve` →
one signed test intent → assert `decision: allow` would catch
automatically, on every PR, forever. The fact that `install.ps1` shipped
with a filename bug that would have broken every Scheduled Task-based
install is direct evidence this path has never been exercised end-to-end
before a human (well, an agent) sat down and manually ran it.

**Recommended fix shape:** productionize the throwaway probe this QA pass
used (a signed-intent client built on `chaperone_protocol::testutil` +
`chaperone_transport`, same shape as `crates/gateway-core/tests/
conformance.rs`) into a real workspace tool — either a `#[cfg(test)]`
integration test in a new `crates/cli/tests/install_smoke.rs` that shells
out to `install.ps1`/`install.sh`, or a `scripts/smoke-test.sh` /
`.ps1` companion to `scripts/repro-check.sh`, wired into
`.github/workflows/release.yml` (or a separate workflow) so it runs on
every platform CI already builds for. This closes both P0-1 (gives the
project itself the self-verification tool P0-1 asks for end-users) and
prevents every future regression in this exact class.

## P1-2 — Vault unlock is a plaintext passphrase file for any headless run

Documented, reasoned-about, and explicitly flagged as weaker
(`LOCAL-VAULT-GUIDE.md` §6, D5, D19) — this is not a silent gap. But for
a first-time end-user running the gateway unattended (which the Scheduled
Task / any real deployment requires), the only path today is
`vault.pass` sitting on disk. `BUILDER-NOTES-WINDOWS.md`'s own open-items
table already lists "Keyring-backed vault sealing... wired behind
`feature = "keyring"` but OFF by default and UNTESTED" — this pass didn't
re-test it, but flags it here because it's the direct answer to the P1-2
friction: enabling and validating it on Windows Credential Manager removes
the plaintext-file requirement for the default path, not just as an
opt-in.

## P1-3 — `--events-socket` silently lies about success on Windows

**Confirmed by reading the code, not inferred.** In
`crates/gateway-core/src/events.rs`, the `#[cfg(not(unix))] impl
EventHub::listen()` is:

```rust
pub fn listen(self: &Arc<Self>, path: &Path) -> Result<(), String> {
    let _ = (self, path);
    Ok(())
}
```

And `crates/cli/src/main.rs` (~line 689-692):

```rust
if let Some(path) = flags.values.get("events-socket") {
    event_hub.listen(std::path::Path::new(path))?;
    println!("event feed listening on {path} (tail with any stream reader)");
}
```

On Windows, passing `--events-socket PATH` — exactly as
`GETTING-STARTED.md` Step 10 instructs, on every platform, with no
Windows callout — prints `event feed listening on PATH (tail with any
stream reader)` and then does nothing. This is a step beyond the already
-documented "known gap" (`HANDOFF.md`'s "Windows console/events sockets"
entry, `BUILDER-NOTES-WINDOWS.md` §4): the gap is honestly documented in
project docs, but the **runtime behavior actively tells the operator it
worked.** A user who tails a socket that will never receive anything, with
no error, has no way to know their monitoring setup is broken versus just
quiet.

**Recommended fix shape:** on `not(unix)`, either reject
`--events-socket` outright at the CLI layer with a clear "not implemented
on this platform" error (fail loud, matching the project's own stated
default-deny/fail-closed posture elsewhere), or have `listen()` return an
`Err` that the CLI surfaces instead of swallowing. Given the project's own
rule ("never weaken a security property... fix the test," IMPLEMENTATION
_AGENT_BRIEF.md §3) is really an instance of a broader "don't claim
success you didn't earn" principle, this should be a quick, uncontroversial
fix — smaller in scope than the actual Windows named-pipe implementation
of the events feed, which can stay roadmap.

## P2-1 — `--console-socket` silently ignored on Windows

Same shape as P1-3 but lower severity (no false success message — it
just silently falls back to `stdio_gate`, per
`crates/cli/src/main.rs:646-651`). Worth a one-line stderr note when the
flag is passed but ignored, for the same "don't let the operator believe
something happened that didn't" reason.

## P2-2 — GETTING-STARTED.md's Windows path isn't actually written

Every example in the guide uses `~/.config/chaperone` (works in
PowerShell 7+ via `$HOME`, but untested phrasing for anyone on Windows
PowerShell 5.1 where `~` doesn't expand the same way) and Unix-only
verification tools for the events feed (`nc -U`, `socat` on a Unix
socket — neither applies to the Windows named-pipe/no-op-socket reality).
`BUILDER-NOTES-WINDOWS.md` already exists as the Windows-specific
*builder* brief; `GETTING-STARTED.md` has no equivalent callout for
Windows *operators*. Doesn't need a parallel document — a few inline
"On Windows:" asides at the path-expansion and events-feed steps would
close this.

---

## Definition of done for this milestone

1. `chaperone doctor` (or equivalent) ships and a fresh install can be
   verified without writing code (P0-1).
2. Installer either self-elevates with clear consent or uses a
   no-elevation persistence mechanism; `install.ps1`'s "no elevation
   needed" claim is true or removed (P0-2). **Done — issue #38, PR #59.**
3. SmartScreen walkthrough exists with actual prompt text and
   a hash-only (no-toolchain-required) verification path (P0-3).
   **Done — issue #39.**
4. Running the installer gets a first-time user to the setup wizard
   without them typing CLI commands first (P0-4). **Done — issue #40, PR #59.**
5. An install → serve → one signed intent smoke test runs in CI on every
   platform (P1-1) — this one item would have caught three of the four
   bugs this pass found, before a human ever saw them.
6. `--events-socket` and `--console-socket` never claim success on a
   platform where they're no-ops (P1-3, P2-1).

Everything above is traceable to this pass's actual QA session — a real
install, a real signed intent, a real capture server, a real audit-chain
verification — not a hypothetical review. Treat P0 items as blocking the
next tagged release to anyone outside the current contributor set.
