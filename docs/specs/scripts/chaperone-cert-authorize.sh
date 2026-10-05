#!/bin/sh
# Chaperone B-1 certificate authorization (TD-3, ruled 2026-10-05).
#
# Invoked by sshd as:
#   AuthorizedPrincipalsCommand /usr/local/bin/chaperone-cert-authorize %k %u
#
# stdin and $1 both carry the certificate blob (base64, no type prefix).
# Accepts (exit 0) only if the certificate:
#   - parses as an OpenSSH user certificate, and
#   - carries a host@chaperone extension equal to THIS host.
#
# Without the host check, a cert minted for any host trusting the same CA
# would authenticate here (a user certificate has no destination-host field).
# Fails closed: any parse error or mismatch refuses.
set -eu

CERT_B64="${1:-}"
HOST_FILE="${CHAPERONE_HOST_FILE:-/etc/chaperone/host}"

if [ -z "$CERT_B64" ]; then
    exit 1
fi

# The canonical host this sshd serves. Set per host; falls back to hostname -f.
if [ -s "$HOST_FILE" ]; then
    CHAPERONE_HOST=$(cat "$HOST_FILE")
else
    CHAPERONE_HOST=$(hostname -f)
fi
[ -n "$CHAPERONE_HOST" ] || exit 1

# Write the blob with its wire type prefix so ssh-keygen can parse it.
# (%k is the bare base64; ssh-keygen needs "type blob".)
TMP_CERT=$(mktemp /tmp/chaperone-cert.XXXXXX)
trap 'rm -f "$TMP_CERT"' EXIT
printf 'ssh-ed25519-cert-v01@openssh.com %s\n' "$CERT_B64" > "$TMP_CERT"

# Dump the certificate's fields. (Verified against ssh-keygen -L behavior:
# extensions print after the "Extensions:" header, one per line.)
EXTS=$(ssh-keygen -L -f "$TMP_CERT" 2>/dev/null | awk '
    /^        Extensions:/ { f = 1; next }
    /^        [A-Z]/      { f = 0 }
    f && NF               { print }
') || exit 1
[ -n "$EXTS" ] || exit 1

# The host binding must be present and exact.
HOST_VALUE=$(printf '%s\n' "$EXTS" | while IFS= read -r line; do
    case "$line" in
        *host@chaperone*)
            # "host@chaperone UNKNOWN OPTION: <hex>" or "host@chaperone <val>"
            val=$(printf '%s\n' "$line" | sed 's/.*host@chaperone[ :]*//; s/UNKNOWN OPTION: *//')
            # ssh-keygen prints unknown options as hex bytes; decode to text.
            case "$val" in
                *'('*[0-9a-f]*) ;;
                *) printf '%s\n' "$val" ;;
            esac
            ;;
    esac
done)

# If the extension printed as plain text, we already have the value. If it
# printed as "UNKNOWN OPTION: <hex>" (unknown to this ssh-keygen), decode it:
# the hex is the length-prefixed SSH string encoding of the hostname.
if [ -z "$HOST_VALUE" ]; then
    HEX=$(printf '%s\n' "$EXTS" | grep 'host@chaperone' | sed 's/.*UNKNOWN OPTION: *//; s/ .*//')
    [ -n "$HEX" ] || exit 1
    # strip the 4-byte length prefix, hex-decode the rest
    HOST_VALUE=$(printf '%s' "$HEX" | tail -c $(( $(printf '%s' "$HEX" | wc -c) - 8 )) | xxd -r -p 2>/dev/null || true)
fi

[ -n "$HOST_VALUE" ] || exit 1
[ "$HOST_VALUE" = "$CHAPERONE_HOST" ] || exit 1

exit 0
