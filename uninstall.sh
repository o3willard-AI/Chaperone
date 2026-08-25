#!/usr/bin/env bash
# Chaperone uninstaller — removes binaries and service definitions.
# NEVER touches your data: ~/.config/chaperone (vault, audit chain,
# enrollment, keys) is preserved. Delete it manually if you truly mean it.
set -euo pipefail

PREFIX="${HOME}/.local/bin"
OS="$(uname -s)"

echo "== Chaperone uninstaller"

if [ "$OS" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now chaperoned 2>/dev/null || true
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/chaperoned.service"
    systemctl --user daemon-reload 2>/dev/null || true
    echo "removed systemd user unit (data untouched)"
elif [ "$OS" = "Darwin" ]; then
    PLIST="$HOME/Library/LaunchAgents/ai.chaperone.gw.plist"
    if [ -f "$PLIST" ]; then
        launchctl unload "$PLIST" 2>/dev/null || true
        rm -f "$PLIST"
        echo "removed launchd agent (data untouched)"
    fi
fi

for b in chaperone chaperone-helper; do
    if [ -f "$PREFIX/$b" ] && [ "${KEEP_BINARIES:-0}" != "1" ]; then
        rm -f "$PREFIX/$b"
    fi
done

echo "== removed: binaries + service definitions"
echo "== KEPT: $HOME/.config/chaperone  (vault, audit journal, enrollment, keys)"
echo "   delete manually ONLY if you are certain:"
echo "     rm -rf $HOME/.config/chaperone"
