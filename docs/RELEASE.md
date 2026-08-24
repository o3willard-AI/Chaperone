# Release & verification

How Chaperone artifacts are produced and how to verify them, stated plainly
including what is NOT yet covered.

## What ships

Tagged releases (`v*`) run the automated pipeline (`.github/workflows/
release.yml`): locked release builds on Linux (x86_64), macOS (aarch64) and
Windows (x86_64), packaged with README + LICENSE, plus:

- `SHA256SUMS.txt` — sha256 of every archive
- `<archive>.sig` — ed25519 detached signature over the exact archive bytes

Binaries included: `chaperone` (operator CLI + gateway daemon) and
`chaperone-helper` (the isolated local-privilege helper).

## Verifying an artifact

```sh
# 1. Hash matches the published manifest
sha256sum -c SHA256SUMS.txt          # lists each archive

# 2. Ed25519 signature verifies against the release public key below
chaperone release-verify \
  --file chaperone-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz \
  --sig   chaperone-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sig \
  --public-key XQLn2R7togqRBYPj0z3fuUX33VzOeM0Jg9Epcnh9P_E   # see "Release public key"
```

You need a `chaperone` binary to run step 2 — for a first install, either
build from source (`cargo build --release --locked`, reproducibly identical
to the shipped bits per `scripts/repro-check.sh`) or verify via the sha256
manifest alone.

## Release public key

The ed25519 public key of the current release signing key:

```
XQLn2R7togqRBYPj0z3fuUX33VzOeM0Jg9Epcnh9P_E
```

This key signs every artifact of every tag. If it ever rotates, the rotation
will be committed to this file with an explanation; git history is the audit
trail. Keep the corresponding seed offline — anyone holding it can sign
malicious artifacts that this page would vouch for.

## What is NOT covered yet (honest boundary)

- **No OS-level code signing**: no Authenticode certificate on Windows, no
  Apple Developer ID/notarization on macOS. Expect Gatekeeper and SmartScreen
  prompts; use the hash/signature checks above instead of clicking through
  blindly. Corporate codesigning requires a legal entity and is deliberately
  deferred until there is one to own it.
- **No installer packages** (deb/rpm/msi). Archives are portable; put the two
  binaries on PATH manually.
- The `chaperone-helper` performs NO privilege escalation by itself: grant it
  authority through your OS mechanism (sudoers rule invoking the binary,
  setuid bit, polkit wrapper) and pin commands in its allowlist.

## Reproducibility

`scripts/repro-check.sh` builds both release binaries twice from clean state
and asserts byte-for-byte identity. Anyone can re-run it against a tag and
confirm their locally built binaries match the published ones bit-for-bit -
stronger provenance than a signature alone.
