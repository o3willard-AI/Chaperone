#!/usr/bin/env bash
# Chaperone installer — Linux/macOS (PLAN Phase 13, decision DA: script-first).
#
# Run from an extracted release archive (binaries + this script together):
#   ./install.sh
#
# Idempotent. Installs per-USER (decision DB): no root required, nothing
# system-wide. Data files are NEVER touched by install/uninstall.
set -euo pipefail

PREFIX="${HOME}/.local/bin"
CONFIG="${HOME}/.config/chaperone"
OS="$(uname -s)"

echo "== Chaperone installer (${OS})"

# --- locate binaries ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR"
if [ ! -x "$BIN_DIR/chaperone" ]; then
    # Fallback: already-installed repo build.
    for cand in "$SCRIPT_DIR/../target/release" "$SCRIPT_DIR/../../target/release"; do
        if [ -x "$cand/chaperone" ]; then BIN_DIR="$(cd "$cand" && pwd)"; break; fi
    done
fi
[ -x "$BIN_DIR/chaperone" ] || { echo "error: chaperone binary not found beside installer" >&2; exit 1; }

mkdir -p "$PREFIX"
install -m 0755 "$BIN_DIR/chaperone" "$PREFIX/"
if [ -x "$BIN_DIR/chaperone-helper" ]; then
    install -m 0755 "$BIN_DIR/chaperone-helper" "$PREFIX/"
fi

# --- PATH hint ----------------------------------------------------------------
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) echo "NOTE: add to your shell profile:  export PATH=\"$PREFIX:\$PATH\"" ;;
esac

# --- config skeleton ----------------------------------------------------------
mkdir -p "$CONFIG"
chmod 700 "$CONFIG"

# --- service definitions (per-user; DB=per-user everywhere) -------------------
find_pack_file() {
    # Templates ship either flat beside the installer (release archive) or
    # under packaging/ (repo checkout).
    for base in "$SCRIPT_DIR" "$SCRIPT_DIR/packaging"; do
        if [ -f "$base/$1" ]; then printf '%s' "$base/$1"; return 0; fi
    done
    return 1
}

if [ "$OS" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
    UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$UNIT_DIR"
    if tmpl=$(find_pack_file "chaperoned.service"); then
        sed "s|%H|$HOME|g" "$tmpl" > "$UNIT_DIR/chaperoned.service"
        systemctl --user daemon-reload 2>/dev/null || true
        echo "installed systemd user unit: chaperoned.service"
    else
        echo "NOTE: chaperoned.service template missing; skipped service install" >&2
    fi
elif [ "$OS" = "Darwin" ]; then
    PLIST_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$PLIST_DIR"
    if tmpl=$(find_pack_file "ai.chaperone.gw.plist"); then
        sed "s|%H|$HOME|g" "$tmpl" > "$PLIST_DIR/ai.chaperone.gw.plist"
        echo "installed launchd agent: ai.chaperone.gw"
    else
        echo "NOTE: ai.chaperone.gw.plist template missing; skipped service install" >&2
    fi
fi

# --- helper elevation snippet (DC: sudoers walkthrough; never auto-written) ---
if sudoers_tmpl=$(find_pack_file "sudoers.chaperone-helper.example"); then
    echo
    echo "OPTIONAL - privileged local commands (local-privilege mechanism):"
    echo "  review then install the sudoers rule:"
    echo "    sudo cp $sudoers_tmpl /etc/sudoers.d/chaperone-helper"
    if allow_tmpl=$(find_pack_file "helper-allow.toml.example"); then
        echo "  and create the ROOT-OWNED allowlist it references:"
        echo "      sudo install -m 0444 -o root $allow_tmpl /etc/chaperone/helper-allow.toml"
    fi
    echo "  (root ownership is ENFORCED when the helper runs elevated)"
fi

cat <<'EOF'

== Installed. Next steps:
1. Put your vault passphrase where the service can read it (0600 file):
     umask 077; printf 'YOUR-PASSPHRASE\n' > ~/.config/chaperone/vault.pass
   (or edit the unit/plist to drop --passphrase-file and run interactively)
2. Create enrollment/policy/vault if you have not yet (see docs/LOCAL-VAULT-GUIDE.md).
3. Start the service:
     Linux:  systemctl --user enable --now chaperoned
     macOS:  launchctl load ~/Library/LaunchAgents/ai.chaperone.gw.plist
4. Verify: chaperone version

Uninstall: ./uninstall.sh  (keeps all data in ~/.config/chaperone)
EOF
