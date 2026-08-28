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
# TWO WINDOWS-SPECIFIC BUGS FOUND VERIFYING THIS ON HARDWARE (2026-08-28),
# both now fixed below -- neither is the double-backslash question this
# script's cygpath handling was originally suspected of; that part was
# already correct (single trailing backslash).
#
# 1. RUSTFLAGS is whitespace-split by cargo before reaching rustc. A Windows
#    account whose display name contains a space (e.g. "C:\Users\Stephen
#    Blankenship\...", a common Windows default -- full name, not a login
#    id) breaks a single `--remap-path-prefix=FROM=TO` flag into two
#    malformed tokens, and rustc fails outright:
#      error: --remap-path-prefix must contain '=' between FROM and TO
#    Fixed by using CARGO_ENCODED_RUSTFLAGS instead of RUSTFLAGS: cargo
#    documents this variable specifically for flags containing spaces --
#    entries are joined with ASCII Unit Separator (0x1F) instead of
#    whitespace, so an embedded space in a path never gets mis-split.
#
# 2. Setting RUSTFLAGS (or CARGO_ENCODED_RUSTFLAGS) as an environment
#    variable REPLACES .cargo/config.toml's rustflags entirely -- cargo
#    does not merge env-level and config-level rustflags, it picks exactly
#    one source. Confirmed on hardware: with RUSTFLAGS set, `cargo build
#    -vv`'s link invocation contains no `/Brepro` at all. That means
#    sourcing this script for a Windows release build was silently
#    reintroducing the exact MSVC TimeDateStamp non-determinism D42 fixed
#    (.cargo/config.toml's `[target.x86_64-pc-windows-msvc] rustflags =
#    ["-C", "link-arg=/Brepro"]`) -- masked in the two-path repro-check
#    because both throwaway builds would just as consistently fail to
#    match for an unrelated reason (differing wall-clock timestamps) rather
#    than by successfully matching for the wrong reason, but a real
#    rebuilder comparing against a published artifact would see silent,
#    unexplained byte drift. Fixed by re-asserting `-C link-arg=/Brepro`
#    inside this script's own flag set whenever targeting MSVC, rather
#    than depending on it surviving from the config file.
#
# 3. Even with bugs 1-2 fixed, registry-dependency source paths (tokio,
#    axum, aws-lc-sys, and most other crates.io deps -- not just C code)
#    were STILL leaking. Root cause, confirmed by capturing the actual
#    `rustc.exe --crate-name tokio ...` invocation via `cargo build -vv`:
#    Cargo hands rustc a MIXED-separator source path for registry crates --
#    forward slashes through the CARGO_HOME portion, backslashes after:
#      C:/Users/<you>/.cargo\registry\src\index.crates.io-.../tokio-.../src/lib.rs
#    `cygpath -w` only produces the all-backslash form
#    (C:\Users\<you>\.cargo\...), which is never a prefix of that string, so
#    the remap silently never matched for this entire path shape -- while
#    OUT_DIR and other native-Windows-API-sourced paths, which really are
#    all-backslash, matched fine. `cygpath -m` (drive-letter form, forward
#    slashes -- cygpath's "mixed" mode) produces exactly
#    `C:/Users/<you>/.cargo`, matching the real embedded prefix byte for
#    byte. Fixed by remapping BOTH forms for both prefixes.
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

_IS_WINDOWS=false
if command -v cygpath >/dev/null 2>&1; then
    _IS_WINDOWS=true
    # Windows (MSYS/Git Bash): native backslash form, trailing backslash --
    # matches paths built from native Win32 APIs (e.g. OUT_DIR).
    _CARGO_PREFIX_BS="$(cygpath -w "$CARGO_HOME")\\"
    _WS_PREFIX_BS="$(cygpath -w "$_WS_ROOT")\\"
    # Mixed form (drive letter, forward slashes, no trailing separator --
    # the real embedded string continues with a backslash already, see bug
    # 3 above) -- matches Cargo's own registry-source path construction.
    _CARGO_PREFIX_MIXED="$(cygpath -m "$CARGO_HOME")"
    _WS_PREFIX_MIXED="$(cygpath -m "$_WS_ROOT")"
else
    # Linux / macOS / WSL: POSIX form, trailing slash. No mixed-separator
    # variant exists on these platforms.
    _CARGO_PREFIX_BS="${CARGO_HOME%/}/"
    _WS_PREFIX_BS="${_WS_ROOT%/}/"
fi

# Build the flag list as an array so each --remap-path-prefix=FROM=TO stays
# one element even when FROM contains a space (bug 1 above) -- joined below
# with the ASCII Unit Separator for CARGO_ENCODED_RUSTFLAGS, never with a
# plain space.
_FLAGS=(
    "--remap-path-prefix=${_CARGO_PREFIX_BS}=/cargo/"
    "--remap-path-prefix=${_WS_PREFIX_BS}=/workspace/"
)
if [ "$_IS_WINDOWS" = true ]; then
    _FLAGS+=(
        "--remap-path-prefix=${_CARGO_PREFIX_MIXED}=/cargo"
        "--remap-path-prefix=${_WS_PREFIX_MIXED}=/workspace"
    )
fi

# Re-assert /Brepro explicitly: an env-level *RUSTFLAGS below fully
# replaces .cargo/config.toml's rustflags rather than merging with it, so
# without this line a Windows build under this script silently loses D42's
# MSVC deterministic-linking fix (bug 2 above).
if [ "$_IS_WINDOWS" = true ]; then
    _FLAGS+=("-C" "link-arg=/Brepro")
fi

_US=$'\x1f'
_ENCODED_REMAP="$(IFS="$_US"; printf '%s' "${_FLAGS[*]}")"

# CARGO_ENCODED_RUSTFLAGS entries are Unit-Separator-delimited specifically
# so a space inside a flag value (a path, here) can never be mistaken for a
# flag boundary -- unlike RUSTFLAGS, which cargo splits on whitespace.
# Cargo rejects RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS being set together, so
# fold any pre-existing value from either into the encoded form rather than
# exporting both.
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS}${_US}${_ENCODED_REMAP}"
elif [ -n "${RUSTFLAGS:-}" ]; then
    _PRIOR_ENCODED="$(IFS=' '; set -- $RUSTFLAGS; IFS="$_US"; printf '%s' "$*")"
    export CARGO_ENCODED_RUSTFLAGS="${_PRIOR_ENCODED}${_US}${_ENCODED_REMAP}"
    unset RUSTFLAGS
else
    export CARGO_ENCODED_RUSTFLAGS="$_ENCODED_REMAP"
fi

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

# KNOWN UNFIXED GAP (Windows, confirmed 2026-08-28 via scripts/repro-check.sh
# leak_gate on real hardware): `aws-lc-sys`'s C sources are compiled by
# cl.exe (invoked by the `cc` crate), NOT by rustc. `--remap-path-prefix` is
# a rustc flag -- it has NO EFFECT on what cl.exe embeds via the C
# preprocessor's `__FILE__` macro (used throughout aws-lc's assert/debug
# messages), regardless of slash form. This is a structurally different
# problem from bugs 1-3 above, not a variant of them:
#   - Confirmed leaking in the LONG backslash form (e.g.
#     C:\Users\<you>\.cargo\registry\...\aws-lc-sys-0.44.0\aws-lc\crypto\
#     fipsmodule\../internal.h) -- the exact form bug-1's fix already
#     covers for rustc-embedded paths, proving this is NOT a slash-form or
#     escaping issue; it is cl.exe never seeing our flag at all.
#   - ALSO confirmed leaking in the Windows 8.3 SHORT name (e.g.
#     C:\Users\STEPHE~1\CARGO~1\...) for other translation units in the
#     same crate, when CARGO_HOME or the checkout path contains a space --
#     the `cc` crate or cl.exe itself appears to fall back to the
#     space-free short form for some (not all) of its own path
#     construction. The short form is machine-specific and non-
#     deterministic (depends on account name; disabled outright by
#     `fsutil 8dot3name` on some systems), so remapping the exact string
#     found on one machine would not generalize to any other builder.
# No fix attempted here -- would need cl.exe's own path-remap mechanism
# (MSVC's `/pathmap`, unverified whether it covers `__FILE__` expansion,
# threaded through the `cc` crate's CFLAGS_x86_64_pc_windows_msvc override)
# or accepting this as a documented boundary of Windows reproducibility.
# Building from a space-free CARGO_HOME/checkout path removes the
# short-name variant specifically but NOT the long-form leak above.
if [ "$_IS_WINDOWS" = true ]; then
    echo "[repro-env] WARNING: aws-lc-sys's C sources (compiled by cl.exe, not rustc)" >&2
    echo "[repro-env] WARNING: embed raw __FILE__ paths that --remap-path-prefix cannot" >&2
    echo "[repro-env] WARNING: touch. Byte-for-byte reproducibility against a different" >&2
    echo "[repro-env] WARNING: builder's CARGO_HOME is NOT guaranteed until this is" >&2
    echo "[repro-env] WARNING: addressed separately (see comment above this warning)." >&2
    case "$CARGO_HOME$_WS_ROOT" in
        *' '*)
            echo "[repro-env] WARNING: additionally, CARGO_HOME or the checkout path" >&2
            echo "[repro-env] WARNING: contains a space, which triggers a SECOND, 8.3" >&2
            echo "[repro-env] WARNING: short-name variant of the same class of leak." >&2
            ;;
    esac
fi

unset _CARGO_PREFIX_BS _WS_PREFIX_BS _CARGO_PREFIX_MIXED _WS_PREFIX_MIXED _WS_ROOT _reg_dirs
unset _IS_WINDOWS _FLAGS _US _ENCODED_REMAP _PRIOR_ENCODED
