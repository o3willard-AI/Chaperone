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

Install the shipped, tested script:

```sh
cp docs/specs/scripts/chaperone-cert-authorize.sh /usr/local/bin/chaperone-cert-authorize
chmod 0755 /usr/local/bin/chaperone-cert-authorize
```

(The original recipe inlined a hand-rolled awk parse that was **non-
functional** — wrong ssh-keygen input format and a self-zeroing guard; caught
in review and replaced by the shipped script, which has a harness.)

What it does, per invocation (sshd passes `%k %u`):

- Writes the cert blob (base64) to a temp file prefixed with its wire type —
  `ssh-keygen -L` cannot parse a bare blob.
- Extracts the extension list with an awk that anchors on the `Extensions:`
  header and stops at the next capitalized field — no self-zeroing.
- Reads the `host@chaperone` value. Note: OpenSSH's `ssh-keygen -L` renders
  unknown extensions as `UNKNOWN OPTION: <hex>`; the script hex-decodes that
  (stripping the 4-byte length prefix) and compares the plain hostname.
- Accepts (exit 0) only when the value equals this host — exact match.

Fails closed on every error: missing blob, unparseable cert, missing or
mismatched host binding, unset hostname.

**Tested.** `tests/b1_cert_authorize_harness.sh` runs the script against a
live certificate: matching host → ACCEPT, wrong host → REFUSE, empty blob →
REFUSE. Run it after any change to the script or the certificate shape:

```sh
sh tests/b1_cert_authorize_harness.sh
```

Configure the host name per machine (one of):

```sh
echo 'app-01.internal' > /etc/chaperone/host   # explicit, preferred
# or rely on the hostname -f fallback if your DNS is the source of truth
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
