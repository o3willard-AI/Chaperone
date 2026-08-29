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

1. **Reproducible build.** rustc embeds absolute build-time paths (the
   checkout root and `$CARGO_HOME` registry sources) into binaries via
   `file!()`/panic locations and debuginfo, so a naive `cargo build` produces
   different bytes on every machine. Both CI and local rebuilds therefore
   normalize those paths with `--remap-path-prefix` (checkout → `/workspace/`,
   `CARGO_HOME` → `/cargo/`), via `scripts/repro-env.sh` — the single source
   of truth for the flags, sourced by CI and by `scripts/repro-check.sh`.
   The check builds from TWO DIFFERENT checkout paths (a same-path rebuild
   is self-consistent by construction and once masked exactly this bug) and
   asserts byte-for-byte identity plus the absence of any embedded `/home/`,
   `/root/`, or `/Users/` paths. With the pinned toolchain
   (`rust-toolchain.toml`), `--locked`, and the remap env, anyone can
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

# 2. (Strongest) Rebuild from source and confirm the same bytes.
#    The env script sets the REQUIRED --remap-path-prefix RUSTFLAGS
#    (checkout -> /workspace/, CARGO_HOME -> /cargo/); without them your
#    rebuild embeds YOUR absolute paths and cannot match anyone else's bytes.
git clone https://github.com/o3willard-AI/Chaperone && cd Chaperone
. ./scripts/repro-env.sh
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
# macOS ONLY: also run the deterministic-UUID post-link step, or your
# hashes will never match (see "Reproducibility" below for why).
python3 scripts/macho-deterministic-uuid.py \
    target/release/chaperone target/release/chaperone-helper
sha256sum target/release/chaperone target/release/chaperone-helper
# ...compare against SHA256SUMS.txt / the per-archive .sha256
```

Or use the scripted reproducibility check:

```sh
./scripts/repro-check.sh
#   default: rebuild from two DIFFERENT checkout paths + no-leaked-paths gate
./scripts/repro-check.sh --against-release <tag>
#   rebuild locally and byte-compare the published asset for that tag
#   (only meaningful for releases cut AFTER the remap flags landed —
#   see "What is NOT covered yet" below)
```

## What is NOT covered yet (honest boundary)

- **Releases tagged before the 2026-08-28 path-remap fix are NOT
  rebuildable byte-for-byte.** Binaries through v0.1.0-alpha.5 embed the CI
  runner's absolute build paths (`/Users/runner/.cargo/registry/...` — found
  in the 2026-08-27 macOS QA pass), so a fresh rebuild produces different
  bytes for those tags. That is expected, and `repro-check.sh
  --against-release` will report it as such. The two-path check is the proof
  of reproducibility for post-remap releases.
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

`scripts/repro-check.sh` (default mode) builds both release binaries from
TWO DIFFERENT checkout paths using the canonical build environment in
`scripts/repro-env.sh`, asserts byte-for-byte identity, and then gates on a
strings scan: no `/home/`, `/root/`, or `/Users/` paths may remain embedded —
only the canonical `/workspace/` and `/cargo/` prefixes. Building twice at the
same path is self-consistent by construction and proves nothing about what a
third party gets; the second checkout path is what makes the check honest.

`./scripts/repro-check.sh --against-release <tag>` additionally downloads the
published archive for a tag, rebuilds it locally, and byte-compares the
binaries. For post-remap releases, a MATCH is the full SLSA-style proof: the
published bytes provably correspond to the public source, with no key and no
trust in whoever holds one.

Rebuilder requirements (all three platforms): the pinned toolchain (rustup
provisions it), `--locked`, the **default crates.io registry** (a mirror
changes the embedded registry-index hash, and therefore the bytes), and the
remap environment from `scripts/repro-env.sh` — the release workflow exports
the same flags, so CI and local builds agree.

Mechanism note (1.98.0, release profile): the dominant embedding vector is
`$CARGO_HOME/registry/src/...` (hundreds of paths via dependency panic
locations); the checkout root itself appears only as workspace-relative
paths in default release builds, but IS embedded absolutely in
debuginfo-bearing configs — the `/workspace/` remap exists so those builds
stay byte-identical too. Both remaps are no-ops for bytes when their prefix
never appears.

**macOS-specific: Mach-O `LC_UUID`.** Even with both remaps applied, two
macOS builds from different checkout paths still differed — found in the
2026-08-28/29 QA pass. `cmp` isolated the entire divergence to 48 bytes in a
multi-megabyte binary: the 16-byte `LC_UUID` load command ld64 embeds at
link time (not derived from the linked content) plus the 32 bytes of
ad-hoc code-signature hash that cover it. Neither is a source path, so the
leak gate can't see it and `strings` won't show it. `scripts/build()` (in
`repro-check.sh`) now runs `scripts/macho-deterministic-uuid.py` on macOS
after every build: it strips the existing signature (its bytes otherwise
still carry the old random UUID into any hash computed before stripping),
computes a SHA-256 of the binary with the UUID field zeroed, writes the
first 16 bytes of that digest back as the UUID, and re-signs ad-hoc — see
that script's docstring for the full mechanism, verified order of
operations, and why `-Wl,-no_uuid` is not used (dyld refuses to launch a
binary missing `LC_UUID` entirely). `release.yml` runs the same step before
packaging, so published macOS binaries and a from-source rebuild agree.
