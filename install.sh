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
    # Fallback: repo checkout builds. When the script lives at the repo root,
    # target/release is a CHILD of SCRIPT_DIR - checked first (QA report
    # 2026-08-25 found this gap), then parent-dir layouts for scripts run
    # from crates/<name> style locations.
    for cand in "$SCRIPT_DIR/target/release" \
                "$SCRIPT_DIR/../target/release" \
                "$SCRIPT_DIR/../../target/release"; do
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
EOF

# --- one-shot setup wizard (issue #40, Unix half) -----------------------------
# If the broker artifacts don't exist yet, install.sh can drive the first-run
# flow itself: generate the D41 UI token (it is a random per-instance secret),
# start `serve` in setup-only mode (no artifacts = wizard only), and open the
# wizard in the default browser. Skipped with CHAPERONE_NO_WIZARD=1 or when
# neither xdg-open nor open exists (headless); the manual CLI path in
# docs/GETTING-STARTED.md remains the documented alternative.
WIZARD_SKIPPED=""
if [ "${CHAPERONE_NO_WIZARD:-0}" = "1" ]; then
    WIZARD_SKIPPED="CHAPERONE_NO_WIZARD=1"
elif ! [ -f "$CONFIG/policy.toml" ] && ! [ -f "$CONFIG/vault.bin" ]; then
    if command -v xdg-open >/dev/null 2>&1 || command -v open >/dev/null 2>&1; then
        echo "== Starting the setup wizard (first-run) =="
        "$PREFIX/chaperone" ui-token rotate --token "$CONFIG/ui.token"
        UI_TOKEN="$("$PREFIX/chaperone" ui-token show --token "$CONFIG/ui.token" | sed -n 's/^UI token:[[:space:]]*//p')"
        UI_PORT="${CHAPERONE_UI_PORT:-8720}"
        echo
        echo "Launching setup wizard in your browser (Ctrl-C the daemon when done):"
        echo "  http://127.0.0.1:${UI_PORT}/?token=${UI_TOKEN}"
        echo
        # serve with no broker artifacts runs SETUP MODE ONLY: wizard on
        # loopback, no passphrase prompt, no gateway socket.
        "$PREFIX/chaperone" serve \
            --socket "$CONFIG/agent.sock" \
            --enrollment "$CONFIG/agents.json" \
            --policy "$CONFIG/policy.toml" \
            --store "$CONFIG/vault.bin" \
            --audit-journal "$CONFIG/audit.jsonl" \
            --audit-key "$CONFIG/audit.key" \
            --ui-port "$UI_PORT" &
        SERVE_PID=$!
        sleep 1
        if xdg-open "http://127.0.0.1:${UI_PORT}/?token=${UI_TOKEN}" >/dev/null 2>&1 \
            || open "http://127.0.0.1:${UI_PORT}/?token=${UI_TOKEN}" >/dev/null 2>&1; then
            : # browser opened
        else
            echo "could not open a browser automatically; use the URL above." >&2
        fi
        wait "$SERVE_PID"
    else
        WIZARD_SKIPPED="no xdg-open/open (headless host)"
    fi
fi

if [ -n "$WIZARD_SKIPPED" ]; then
    echo "(setup wizard not launched: $WIZARD_SKIPPED)"
    cat <<'EOF'
1. Create the per-instance UI access token (D41 requires it; the config UI
   refuses to start without one):
     chaperone ui-token rotate --token ~/.config/chaperone/ui.token
2. Run `chaperone serve` once to go through the setup wizard, or see
   docs/GETTING-STARTED.md for the manual CLI path.
EOF
fi

cat <<'EOF'
3. Start the service:
     Linux:  systemctl --user enable --now chaperoned
     macOS:  launchctl load ~/Library/LaunchAgents/ai.chaperone.gw.plist
4. Verify: chaperone version

Uninstall: ./uninstall.sh  (keeps all data in ~/.config/chaperone)
EOF
