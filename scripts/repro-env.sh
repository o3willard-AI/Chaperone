#!/usr/bin/env bash
# Canonical rebuild environment for byte-identical Chaperone binaries.
#
# Source it, then run the normal locked release build:
#
#     . ./scripts/repro-env.sh
#     cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper
#
# WHY THIS EXISTS
#
# rustc embeds absolute build-time paths into binaries (file!()/panic
# locations, debuginfo): the checkout root and $CARGO_HOME/registry sources.
# Every builder has a different $HOME, so a "rebuild from source" produced
# DIFFERENT BYTES on every machine. Found in the 2026-08-27 macOS QA pass
# while verifying v0.1.0-alpha.5 (the published binary embeds
# /Users/runner/.cargo/registry/...). The issue is generic to cargo/rustc —
# Linux and Windows are affected too — and it is NOT the MSVC TimeDateStamp
# problem that D42's /Brepro link-arg fixed (.cargo/config.toml, kept).
#
# THE FIX
#
# --remap-path-prefix maps each machine-specific prefix to a fixed canonical
# string that is identical for every builder:
#
#     <your checkout>/...   ->  /workspace/...
#     $CARGO_HOME/...       ->  /cargo/...
#
# The source prefixes differ per machine; the canonical TARGET strings are
# what make bytes match. Set via RUSTFLAGS (env) rather than .cargo/config.toml
# so the value is derived from the actual machine layout at build time.
#
# PLATFORM NOTES
#
# - Linux/macOS/WSL: prefixes are used in POSIX form (/home/you/.cargo/...).
# - Git Bash / MSYS on Windows: rustc embeds native Windows paths
#   (C:\a\Chaperone\...), which `pwd` alone would never match, so this script
#   converts both prefixes via `cygpath -w` (drive-letter form, backslashes).
#   WSL has no cygpath and correctly keeps the POSIX branch.
#
# CAVEATS (see docs/RELEASE.md "Reproducibility"):
# - The registry directory name (index.crates.io-<hash>) is embedded in the
#   canonical path. The hash is derived from the registry URL, so builds must
#   use the default crates.io registry — a mirror/override in
#   .cargo/config.toml changes the hash and therefore the bytes.
# - Both the checkout and CARGO_HOME must be captured by the two remapped
#   prefixes. If you build from an exotic layout (checkout outside cwd,
#   relocated CARGO_HOME), set CHAPERONE_BUILD_ROOT and/or export CARGO_HOME
#   before sourcing this script.

set -euo pipefail

: "${CARGO_HOME:=$HOME/.cargo}"
export CARGO_HOME

native_path() {
    # Print $1 in the form the toolchain embeds on this platform.
    local p="$1"
    if command -v cygpath >/dev/null 2>&1; then
        case "$p" in
            /*) cygpath -w "$p" ;;   # POSIX form -> Windows drive form
            *)  printf '%s' "$p" ;;  # already native (e.g. C:\Users\...)
        esac
    else
        printf '%s' "$p"
    fi
}

_WS_ROOT="${CHAPERONE_BUILD_ROOT:-$(pwd -P)}"

if command -v cygpath >/dev/null 2>&1; then
    # Windows (MSYS/Git Bash): native backslash form, trailing backslash.
    _CARGO_PREFIX="$(cygpath -w "$CARGO_HOME")\\"
    _WS_PREFIX="$(cygpath -w "$_WS_ROOT")\\"
else
    # Linux / macOS / WSL: POSIX form, trailing slash.
    _CARGO_PREFIX="${CARGO_HOME%/}/"
    _WS_PREFIX="${_WS_ROOT%/}/"
fi

_RUSTFLAGS_REMAP="--remap-path-prefix=${_CARGO_PREFIX}=/cargo/ --remap-path-prefix=${_WS_PREFIX}=/workspace/"

# Prepend to any user-provided RUSTFLAGS instead of clobbering them.
export RUSTFLAGS="${RUSTFLAGS:-} ${_RUSTFLAGS_REMAP}"

# Loud warning if the registry layout is non-default (would break byte
# equality against every other builder; see CAVEATS above).
if [ -d "$CARGO_HOME/registry/src" ]; then
    _reg_dirs=$(ls "$CARGO_HOME/registry/src" 2>/dev/null | wc -l)
    if [ "$_reg_dirs" -gt 1 ]; then
        echo "[repro-env] WARNING: multiple registry source dirs under $CARGO_HOME/registry/src:" >&2
        ls "$CARGO_HOME/registry/src" >&2
        echo "[repro-env] WARNING: non-default/mirror registries change the embedded index hash and break byte-equality." >&2
    fi
fi

unset _CARGO_PREFIX _WS_PREFIX _WS_ROOT _RUSTFLAGS_REMAP _reg_dirs
