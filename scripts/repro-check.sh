#!/usr/bin/env bash
# Reproducible-build posture check (PLAN Phase 10): two clean locked
# release builds of the shipped binaries MUST hash identically.
set -euo pipefail
cd "$(dirname "$0")/.."
source "$HOME/.cargo/env" 2>/dev/null || true

bins=(chaperone chaperone-helper)

hash() {
    local out=""
    for b in "${bins[@]}"; do
        out+="$(sha256sum "target/release/$b")"$'\n'
    done
    printf '%s' "$out"
}

echo "[repro] build 1/2"
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
A=$(hash)

echo "[repro] clean rebuild 2/2"
rm -rf target/release
cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
B=$(hash)

if [ "$A" = "$B" ]; then
    echo "[repro] OK: byte-for-byte identical"
    echo "$A"
else
    echo "[repro] FAILED: builds differ" >&2
    diff <(echo "$A") <(echo "$B") >&2 || true
    exit 1
fi
