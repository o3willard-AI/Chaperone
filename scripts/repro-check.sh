#!/usr/bin/env bash
# Reproducible-build posture check for Chaperone.
#
# MODE 1 (default) — two builds from two DIFFERENT checkout paths
#
#   ./repro-check.sh [--target <triple>]
#
#   Builds the release binaries once in this checkout, then again from a
#   second copy of the tree exported to a different path (default under
#   /tmp), with the documented canonical build environment
#   (scripts/repro-env.sh). The two binaries MUST be byte-identical.
#
#   WHY TWO PATHS: a rebuild on the same machine at the same path is
#   self-consistent by construction and once masked exactly this class of
#   bug — rustc embeds absolute build-time paths (checkout root + CARGO_HOME
#   registry sources) into the binary, so two builds in the same $HOME match
#   while a rebuild by ANYONE ELSE does not (found in the 2026-08-27 macOS QA
#   pass on v0.1.0-alpha.5). Different checkout paths is the smallest test
#   that actually exercises path normalization. It runs on a plain host:
#   needs git, cargo, sha256sum, tar.
#
#   The script also asserts the LEAK GATE: neither binary may contain any
#   absolute /home/, /root/ or /Users/ path. Only the canonical /workspace/
#   and /cargo/ prefixes may appear.
#
# MODE 2 — verify against a PUBLISHED release artifact
#
#   ./repro-check.sh --against-release <tag> [--target <triple>]
#
#   Downloads the release archive for <tag>/<target>, builds locally with the
#   canonical environment, and byte-compares the binaries. NOTE: this can
#   only pass for releases CUT AFTER the remap flags landed (earlier
#   artifacts embed the CI runner's real paths); a mismatch against an older
#   tag is EXPECTED and reported as such, not a script failure.
#
#   Needs network access (curl) plus a writable temp dir. On Windows targets
#   the asset is a .zip; extraction tries unzip, then falls back to python3.

set -euo pipefail
cd "$(dirname "$0")/.."
# Ensure the rustup-shimmed cargo (which honors rust-toolchain.toml) wins
# over any distro cargo. Prepend explicitly: ~/.cargo/env alone may APPEND
# on some setups, leaving /usr/bin/cargo shadowing the shim.
case ":$PATH:" in
    *":$HOME/.cargo/bin:"*) ;;
    *) export PATH="$HOME/.cargo/bin:$PATH" ;;
esac
source "$HOME/.cargo/env" 2>/dev/null || true

TARGET_ARG=""
AGAINST_RELEASE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            TARGET_ARG="${2:?--target requires a triple}"
            shift 2 ;;
        --against-release)
            AGAINST_RELEASE="${2:?--against-release requires a tag}"
            shift 2 ;;
        *)
            echo "usage: $0 [--target <triple>] [--against-release <tag>]" >&2
            exit 2 ;;
    esac
done

bins=(chaperone chaperone-helper)
EXE_SUFFIX=""
case "${TARGET_ARG:-}" in
    *windows*) EXE_SUFFIX=".exe" ;;
esac
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) [ -z "$TARGET_ARG" ] && EXE_SUFFIX=".exe" ;;
esac

bindir() {
    if [ -n "$TARGET_ARG" ]; then
        printf 'target/%s/release' "$TARGET_ARG"
    else
        printf 'target/release'
    fi
}

canonical_env() {
    # The one source of truth for rebuild flags. Sourced, not executed.
    . "./scripts/repro-env.sh"
}

build() {
    if [ -n "$TARGET_ARG" ]; then
        cargo build --release --locked --target "$TARGET_ARG" \
            -p chaperone-cli -p chaperone-privileged-helper
    else
        cargo build --release --locked \
            -p chaperone-cli -p chaperone-privileged-helper
    fi
    postprocess_macos_uuid
}

postprocess_macos_uuid() {
    # macOS only: ld64 embeds a non-content-derived Mach-O LC_UUID at link
    # time (confirmed: two builds of identical source from different
    # checkout paths, with repro-env.sh's remap already applied, differ in
    # ONLY the 16-byte LC_UUID plus the 32 bytes of ad-hoc signature that
    # cover it -- nothing else). scripts/macho-deterministic-uuid.py makes
    # the UUID a function of the binary's own content instead, then
    # re-signs. See that script's module docstring for the full mechanism
    # and why order of operations matters (signature must be stripped
    # before hashing, and reapplied only after the UUID rewrite).
    case "$(uname -s)" in
        Darwin)
            local dir
            dir="$(bindir)"
            python3 "$(dirname "$0")/macho-deterministic-uuid.py" \
                "$dir/chaperone" "$dir/chaperone-helper"
            ;;
    esac
}

hash_binaries() {
    # Output "<sha256> <binname>" per binary. Hash-only comparison: the
    # sha256sum path column differs between the two trees by design.
    local dir out=""
    dir="$(bindir)"
    for b in "${bins[@]}"; do
        out+="$(sha256sum "$dir/$b$EXE_SUFFIX" | cut -d' ' -f1)  $b"$'\n'
    done
    printf '%s' "$out"
}

leak_gate() {
    # POSIX pattern catches /home, /root, macOS /Users. Windows paths never
    # match that pattern (drive letter + backslashes), so a leak specific to
    # the msvc target -- e.g. repro-env.sh's remap silently not applying --
    # would pass this gate undetected without the second pattern below.
    #
    # `strings` is NOT assumed present -- confirmed absent on a plain Git
    # for Windows install (no full MinGW/binutils) on 2026-08-28. `grep -a`
    # searches the binary directly instead; every path this project embeds
    # is ASCII, so no printable-run extraction step is needed.
    local dir name where posix_pat win_pat
    dir="$(bindir)"
    posix_pat='/home/|/root/|/Users/'
    # One escaped backslash (\\) per separator -- matches one literal `\`
    # in the binary. A prior draft of this pattern used \\\\ here, which
    # requires TWO literal backslashes in a row and would never match a
    # real single-backslash Windows path; caught by actually running this
    # against a binary rather than trusting the regex by inspection.
    #
    # Deliberately does NOT include a C:\a\|D:\a\ alternative for the
    # GitHub Actions windows-latest runner checkout convention (D:\a\...).
    # A prior draft did, and it broke streaming output for this entire
    # pattern on the grep bundled with a plain Git for Windows install
    # (confirmed: `grep -c` still silently counted real matches while `grep`
    # in normal/`-o` mode emitted zero bytes for ALL alternatives, not just
    # the added one -- a real grep bug, not a regex logic error; verified
    # by isolating each alternative individually). \Users\ alone already
    # catches the actual leak class that matters (a developer's home
    # directory); re-add a CI-runner-specific pattern only after confirming
    # it doesn't retrigger this on the grep build in use.
    win_pat='[A-Za-z]:\\Users\\|\\Users\\'
    for b in "${bins[@]}"; do
        name="$b$EXE_SUFFIX"
        where="$dir/$name"
        if grep -aE "$posix_pat" "$where" | head -3 | grep -q .; then
            echo "[repro] LEAK GATE FAILED: $where embeds absolute POSIX source paths:" >&2
            grep -aE "$posix_pat" "$where" | head -5 >&2
            return 1
        fi
        if grep -aE "$win_pat" "$where" | head -3 | grep -q .; then
            echo "[repro] LEAK GATE FAILED: $where embeds absolute Windows source paths:" >&2
            grep -aE "$win_pat" "$where" | head -5 >&2
            return 1
        fi
    done
    echo "[repro] leak gate OK: no absolute source paths (POSIX or Windows) in binaries"
}

export_second_tree() {
    # Export the CURRENT WORKING TREE (tracked + untracked, minus ignored
    # files like target/) so the second build tests exactly what a rebuilder
    # would get, including any uncommitted changes under test.
    local dest="$1"
    mkdir -p "$dest"
    git ls-files -co --exclude-standard -z \
        | tar --null -T - -cf - \
        | tar -xf - -C "$dest"
}

die() { echo "[repro] FAILED: $*" >&2; exit 1; }

if [ -n "$AGAINST_RELEASE" ]; then
    # ------------------------------------------------------------------
    # MODE 2: build locally, compare with the published artifact bytes.
    # ------------------------------------------------------------------
    TAG="$AGAINST_RELEASE"
    TRIPLE="${TARGET_ARG:-$(rustc -vV | awk '/^host:/ {print $2}')}"
    case "$TRIPLE" in
        *windows*) ARCHIVE="chaperone-$TAG-$TRIPLE.zip" ;;
        *)         ARCHIVE="chaperone-$TAG-$TRIPLE.tar.gz" ;;
    esac
    BASE="https://github.com/o3willard-AI/Chaperone/releases/download/$TAG"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    echo "[repro] downloading $BASE/$ARCHIVE"
    curl -fsSL -o "$TMP/$ARCHIVE" "$BASE/$ARCHIVE" \
        || die "could not download $ARCHIVE (does the release exist?)"

    mkdir -p "$TMP/asset"
    case "$ARCHIVE" in
        *.tar.gz) tar -xzf "$TMP/$ARCHIVE" -C "$TMP/asset" ;;
        *.zip)
            if command -v unzip >/dev/null 2>&1; then
                unzip -q "$TMP/$ARCHIVE" -d "$TMP/asset"
            else
                python3 - "$TMP/$ARCHIVE" "$TMP/asset" <<'PY'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PY
            fi ;;
    esac

    echo "[repro] building locally with canonical env (target: $TRIPLE)"
    canonical_env
    if [ -n "$TARGET_ARG" ]; then
        build
    else
        cargo build --release --locked --target "$TRIPLE" \
            -p chaperone-cli -p chaperone-privileged-helper
    fi

    rc=0
    for b in "${bins[@]}"; do
        local_bin="$(bindir)/$b$EXE_SUFFIX"
        pub_bin="$TMP/asset/$b$EXE_SUFFIX"
        [ -f "$pub_bin" ] || die "published archive is missing $b$EXE_SUFFIX"
        if cmp -s "$local_bin" "$pub_bin"; then
            echo "[repro] MATCH: $b == published $TAG artifact"
        else
            echo "[repro] DIFFER: $b != published $TAG artifact" >&2
            echo "        expected for tags cut BEFORE the path-remap flags" >&2
            echo "        (published binary embeds the CI runner's build paths)." >&2
            rc=1
        fi
    done
    leak_gate || rc=1
    exit $rc
fi

# --------------------------------------------------------------------------
# MODE 1 (default): two builds from two different checkout paths.
# --------------------------------------------------------------------------
if [ -n "$TARGET_ARG" ]; then
    # Cross-target second path works the same way; no extra handling.
    :
fi

echo "[repro] target: ${TARGET_ARG:-host default}"
echo "[repro] build A: this checkout ($(pwd -P))"
canonical_env
build
A="$(hash_binaries)"
echo "$A" | sed 's/^/[repro] A /'

SECOND_PARENT="$(mktemp -d /tmp/chaperone-repro.XXXXXX)"
trap 'rm -rf "$SECOND_PARENT"' EXIT
SECOND_TREE="$SECOND_PARENT/Chaperone"
export_second_tree "$SECOND_TREE"

echo "[repro] build B: second checkout ($SECOND_TREE)"
(
    cd "$SECOND_TREE"
    canonical_env
    build
)
B="$(cd "$SECOND_TREE" && hash_binaries)"
echo "$B" | sed 's/^/[repro] B /'

if [ "$A" = "$B" ]; then
    echo "[repro] OK: byte-for-byte identical across two checkout paths"
else
    echo "[repro] FAILED: builds from different checkout paths differ" >&2
    diff <(echo "$A") <(echo "$B") >&2 || true
    echo "[repro] hint: is the checkout/CARGO_HOME prefix actually covered" >&2
    echo "[repro]       by scripts/repro-env.sh remaps on this machine?" >&2
    exit 1
fi

leak_gate
echo "[repro] two-path + leak-gate verification passed"
