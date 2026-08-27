# Release & verification

How Chaperone artifacts are produced and how you verify that a binary you
downloaded is exactly the open source in this repository — stated plainly,
including the honest limits.

## The verification model: no signing, prove it yourself

Chaperone ships **unsigned by design, permanently**. Code signing — a Windows
Authenticode certificate, an Apple Developer ID / notarization, or a
project-held release key — requires an entity to own the certificate or key.
This project has none: it is open source, maintained in the open, with no
company behind it. A corporate downstream project will add
identity/provenance signing later; for this repository the guarantee is
*verifiability by reconstruction*, not *trust in a signature*.

Verification follows SLSA principles (Supply-chain Levels for Software
Artifacts — the "salsa" framework), specifically **reproducible builds** and
**hash manifests**:

1. **Reproducible build.** `scripts/repro-check.sh` builds both release
   binaries twice from clean state and asserts byte-for-byte identity. Because
   the toolchain is pinned and the build is locked (`--locked`), anyone can
   reproduce the exact bytes from the exact source.
2. **Hash manifest.** Every release publishes `SHA256SUMS.txt` (the sha256 of
   each archive) plus a per-archive `.sha256` file. `sha256sum -c` confirms
   your download arrived intact.
3. **The strongest check — build it yourself.** Clone the repository, run the
   same locked release build, and compare hashes against the published
   manifest. If they match, the binary provably came from this source — no
   key, no trust in a maintainer, no company.

Download releases from the
[GitHub releases page](https://github.com/o3willard-AI/Chaperone/releases).

## What ships

Tagged releases (`v*`) run the automated pipeline (`.github/workflows/
release.yml`): locked release builds on Linux (x86_64), macOS (aarch64) and
Windows (x86_64), packaged with README + LICENSE + the install scripts, plus:

- `SHA256SUMS.txt` — sha256 of every archive
- `<archive>.sha256` — sha256 of that archive

Binaries included: `chaperone` (operator CLI + gateway daemon) and
`chaperone-helper` (the isolated local-privilege helper).

## Verifying an artifact

```sh
# 1. Your download matches the published manifest
sha256sum -c SHA256SUMS.txt

# 2. (Strongest) Rebuild from source and confirm the same bytes
git clone https://github.com/o3willard-AI/Chaperone && cd Chaperone
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
sha256sum target/release/chaperone target/release/chaperone-helper
# ...compare against SHA256SUMS.txt / the per-archive .sha256
```

Or use the scripted reproducibility check:

```sh
./scripts/repro-check.sh   # two clean builds, byte-for-byte assertion
```

## What is NOT covered yet (honest boundary)

- **No OS-level code signing, ever.** No Authenticode certificate on Windows,
  no Apple Developer ID / notarization on macOS. Expect Gatekeeper and
  SmartScreen prompts. The point is that you *don't* need to trust a
  signature: verify by rebuilding (above) instead of clicking through.
- **A hash manifest alone does not defeat a hostile release channel.** The
  `SHA256SUMS.txt` lives next to the binaries, so a channel that can swap the
  binary can swap the manifest too. The reproducible build closes that gap: it
  binds the published bytes to the published *source*, which lives in this
  repository and in your clone. If you care about provenance against an
  adversary in the middle, rebuild and compare.
- **No installer packages** (deb/rpm/msi). Archives are portable; put the two
  binaries on PATH manually.
- The `chaperone-helper` performs NO privilege escalation by itself: grant it
  authority through your OS mechanism (sudoers rule invoking the binary,
  setuid bit, polkit wrapper) and pin commands in its allowlist.

## Reproducibility

`scripts/repro-check.sh` builds both release binaries twice from clean state
and asserts byte-for-byte identity. Anyone can re-run it against a tag and
confirm their locally built binaries match the published ones bit-for-bit —
stronger provenance than any signature, because it requires no key and no
trust in whoever holds one.
