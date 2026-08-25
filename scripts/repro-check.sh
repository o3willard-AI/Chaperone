#!/usr/bin/env bash
# Reproducible-build posture check (PLAN Phase 10): two clean locked
# release builds of the shipped binaries MUST hash identically.
set -euo pipefail
cd "$(dirname "$0")/.."
source "$HOME/.cargo/env" 2>/dev/null || true

# Usage: repro-check.sh [--target <triple>]
#   No argument: verify the host target (default).
#   --target <triple>: verify a cross-target (e.g. x86_64-apple-darwin on an
#   arm64 Mac). Requires the rustup target to be installed. Added after the
#   2026-08-25 macOS QA pass verified both darwin targets manually; this
#   flag makes that procedure scriptable (follow-up of issue #24).

TARGET_ARG=""
if [ "${1:-}" = "--target" ]; then
    TARGET_ARG="${2:?--target requires a triple}"
    shift 2
fi

bins=(chaperone chaperone-helper)

bindir() {
    if [ -n "$TARGET_ARG" ]; then
        printf 'target/%s/release' "$TARGET_ARG"
    else
        printf 'target/release'
    fi
}

build() {
    if [ -n "$TARGET_ARG" ]; then
        cargo build --release --locked --target "$TARGET_ARG" \
            -p chaperone-cli -p chaperone-privileged-helper
    else
        cargo build --release --locked \
            -p chaperone-cli -p chaperone-privileged-helper
    fi
}

hash() {
    local dir bindir_out out=""
    dir=$(bindir)
    for b in "${bins[@]}"; do
        out+="$(sha256sum "$dir/$b")"$'\n'
    done
    printf '%s' "$out"
}

clean() {
    if [ -n "$TARGET_ARG" ]; then
        rm -rf "target/$TARGET_ARG/release"
    else
        rm -rf target/release
    fi
}

echo "[repro] target: ${TARGET_ARG:-host default}"
echo "[repro] build 1/2"
build
A=$(hash)

echo "[repro] clean rebuild 2/2"
clean
build
B=$(hash)

if [ "$A" = "$B" ]; then
    echo "[repro] OK: byte-for-byte identical"
    echo "$A"
else
    echo "[repro] FAILED: builds differ" >&2
    diff <(echo "$A") <(echo "$B") >&2 || true
    exit 1
fi
