#!/bin/sh
# B-1 / TD-3 harness: proves the AuthorizedPrincipalsCommand script works
# against a LIVE certificate. Heph's review (2026-10-05) found the original
# recipe script was non-functional (wrong ssh-keygen input format + an awk
# guard that zeroed itself); this harness is the fix's falsifiability pin:
# run it after any change to the script or the cert shape.
#
# Usage: sh tests/b1_cert_authorize_harness.sh
# Requires: ssh-keygen, our debug build (for a real minted cert), the
# vendored script.
set -eu

cd "$(dirname "$0")/.."
SCRIPT="docs/specs/scripts/chaperone-cert-authorize.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# 1. Generate a CA and a user key with ssh-keygen (host-side reality).
ssh-keygen -q -t ed25519 -N '' -f "$WORK/ca_key" >/dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -f "$WORK/user_key" >/dev/null 2>&1

# 2. Sign a cert with the ruled shape: principal = username, extension = host.
ssh-keygen -s "$WORK/ca_key" \
    -I "chaperone:agent:ci:m-1" \
    -n deploy \
    -V '-5m:+30m' \
    -O "extension:host@chaperone=app-01.internal" \
    -O permit-pty \
    "$WORK/user_key.pub" >/dev/null 2>&1
[ -f "$WORK/user_key-cert.pub" ] || { echo "FAIL: cert not minted"; exit 1; }

BLOB=$(awk '{print $2}' "$WORK/user_key-cert.pub")

# 3. Accept: the cert's host matches the configured host.
echo "app-01.internal" > "$WORK/host"
if CHAPERONE_HOST_FILE="$WORK/host" "$SCRIPT" "$BLOB" deploy; then
    echo "ok: matching host accepted"
else
    echo "FAIL: matching host was refused"; exit 1
fi

# 4. Refuse: the cert's host does NOT match (the pin that catches the
# "user certs are structurally portable" failure Heph's redesign prevents).
echo "app-02.internal" > "$WORK/host"
if CHAPERONE_HOST_FILE="$WORK/host" "$SCRIPT" "$BLOB" deploy 2>/dev/null; then
    echo "FAIL: wrong host was accepted"; exit 1
else
    echo "ok: wrong host refused"
fi

# 5. Refuse: empty certificate.
if CHAPERONE_HOST_FILE="$WORK/host" "$SCRIPT" "" deploy 2>/dev/null; then
    echo "FAIL: empty cert was accepted"; exit 1
else
    echo "ok: empty cert refused"
fi

echo "ALL PASS"
