# B-1 host-side recipe: trusting the Chaperone CA (TD-4, Option A)

For each SSH host that will accept Chaperone-minted certificates. Customer-
applied, per the ruled decision: **Chaperone is a credential broker, not a
fleet-management product** — it never reconfigures sshd on your machines. This
runbook is how you apply the change yourself, the same way you apply any sshd
change today.

Rulings in force: TD-3 (principal = username; host binding = the
`host@chaperone` extension, validated here), TD-4 (documented recipe),
TD-5 (per-host keys keep working — this recipe is additive).

---

## 1. Export the CA public key (gateway machine)

```sh
chaperone ca-init   --store ~/.config/chaperone/vault.bin    # once
chaperone ca-export --store ~/.config/chaperone/vault.bin
# → ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI…   (one line; copy it)
```

The private key never leaves the vault; `ca-export` prints the public line
only. The `ca-init` output warns that there is no recovery path — back the
sealed vault file up (LOCAL-VAULT-GUIDE §6) before you rely on the CA.

## 2. Install the CA on the host

```sh
# /etc/ssh/ca_public_key.pub  (mode 0644; a copy of the exported line)
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… chaperone-ca
```

## 3. sshd_config additions

Two directives, both required:

```
# Trust certificates signed by the Chaperone CA.
TrustedUserCAKeys /etc/ssh/ca_public_key.pub

# Validate the host binding (the cert's host@chaperone extension) against
# the host this sshd runs on. Without THIS check, a cert minted for any
# host that trusts the same CA would authenticate here — the failure the
# ruled TD-3 redesign exists to prevent.
AuthorizedPrincipalsCommand /usr/local/bin/chaperone-cert-authorize %k %u
```

## 4. The `AuthorizedPrincipalsCommand` script

`/usr/local/bin/chaperone-cert-authorize` (mode 0755, owner root). stdin
receives the certificate; arguments are `%k` (the base64 certificate) and `%u`
(the requested username). Exit 0 = accept, non-zero = refuse.

```sh
#!/bin/sh
# Chaperone B-1 certificate authorization (TD-3).
# stdin: the OpenSSH certificate line; $1: cert (b64), $2: username.
# Accepts only if the cert's host@chaperone extension names THIS host.
set -eu

# The canonical host this sshd serves. Edit per host, or derive from
# `hostname -f` if your DNS is the source of truth.
CHAPERONE_HOST="$(cat /etc/chaperone/host 2>/dev/null || hostname -f)"

CERT_B64="$1"
REQUESTED_USER="$2"

EXT_LINE=$(/usr/bin/ssh-keygen -L -f /dev/stdin <<< "ssh-cert $CERT_B64" \
    | awk '/Critical|Extensions:/{f=1;next} /^/{f=0} f && /host@chaperone:/')

# host@chaperone present?
[ -n "$EXT_LINE" ] || exit 1

# …and equal to THIS host? (exact match, no prefix games)
HOST_VALUE=$(printf '%s\n' "$EXT_LINE" | sed 's/.*host@chaperone: *//')
[ "$HOST_VALUE" = "$CHAPERONE_HOST" ] || exit 1

# The principal is the username (sshd already matched it to $2); accept.
exit 0
```

## 5. Verify the chain

1. `sshd -t` — config parses.
2. Reload sshd (`systemctl reload sshd`).
3. Mint a cert on the gateway for a rule whose target is this host, and run
   the authorizer against it by hand:

```sh
/usr/local/bin/chaperone-cert-authorize "$CERT_B64" deploy && echo ACCEPT
```

4. Negative check (the one that matters): take a cert minted for host
   `app-01.internal`, run the authorizer on host `app-02.internal` — it must
   refuse. That is acceptance test 2 from the spec, executed on real hosts.

## 6. Notes and boundaries

- **Per-host keys keep working** (TD-5): nothing here disables
  `authorized_keys` authentication; the CA is an additional path.
- **Host-key pinning is orthogonal** (D31): the CA vouches for the agent; the
  Chaperone gateway still pins/validates the host's own SSH host key.
- **A cert is bound to exactly one host and expires ≤ 3600 s** (ruled
  ceiling); there is no renewal — mint again per action, which is the point.
- **Rotation**: generate a new CA (`chaperone ca-init` refuses to clobber —
  use the dual-trust procedure in `docs/specs/b1-ssh-ca-spec.md` §rotation:
  new CA → add its public key alongside the old in
  `TrustedUserCAKeys`-referenced file → re-export → drop the old line after
  the transition window).
- **What this recipe does NOT do**: it does not create users, manage
  `AuthorizedPrincipalsFile`, or touch host keys. If your fleet wants that,
  that is the `host-enroll` future-product decision (ruled: not built).
