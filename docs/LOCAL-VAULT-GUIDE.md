# The Built-in Local Vault — User Guide

Everything you need to store, read, rotate, and delete secrets using
Chaperone's built-in encrypted vault — **no third-party service required**.
This is the `local://` credential backend; it works offline and is the
default for individual users.

> Design rationale lives in [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md)
> (D5 sealing, D19 format/posture). This page is the *how-to*.

---

## 1. What it is

One encrypted file on your machine (`0600` permissions) holding named
secrets — API tokens, database passwords, SSH private keys. It is sealed
with **argon2id + AES-256-GCM** under a passphrase you choose:

- At rest: only ciphertext. No plaintext ever touches disk.
- In memory: the gateway holds ciphertext plus one derived key; entry
  plaintext exists only for the instant an injection needs it.
- No plaintext recovery path: **if you lose the passphrase, the contents are
  gone.** There is no backdoor, reset, or support escalation — that absence
  is the security model working.

When to step up to [HashiCorp Vault](CONNECTIVITY-MATRIX.md#credential-backends-where-secrets-live--the-cred_ref-targets):
shared teams, dynamic/short-lived credentials, centralized revocation.
Migrating later changes configuration only — agents keep using the same
`cred_ref` shape.

## 2. Creating a vault

```sh
chaperone vault-init --store ~/.config/chaperone/vault.bin
```

You will be prompted twice for a passphrase (hidden input). For scripts,
pipe it instead — see §3.3.

Output: `created vault at … (sealed with: passphrase)`.

Rules:
- The path is yours to choose; parent directories are created as needed and
  the file is written `0600` atomically (temp file + rename).
- Creating over an existing vault fails loudly — we never clobber secrets.
- A **zero-length or missing** file is treated as a fresh store; anything
  else must parse or startup fails rather than guessing.

## 3. Storing and reading secrets

### 3.1 Interactive (TTY)

```sh
chaperone vault-set --store ~/.config/chaperone/vault.bin --path prod/stripe/key
# prompts: Vault passphrase:            (hidden)
#          <paste the secret, then press Ctrl-D>
```

`vault-set` reads the **entire remaining stdin** as the secret value, so
multi-line values (SSH keys, certificates) work naturally: paste, then end
input with Ctrl-D. Trailing newlines are trimmed.

### 3.2 Scripted (piped)

With `--passphrase-stdin`, stdin is parsed as:

```
<line 1>      passphrase
<remainder>   the secret (may be multi-line)
```

```sh
printf 'my-passphrase\nmy-secret-token\n' | \
  chaperone vault-set --store v.bin --path prod/stripe/key --passphrase-stdin
```

Multi-line secret, piped:

```sh
printf '%s\n%s\n' "$PASSPHRASE" "$(cat deploy_key.pem)" | \
  chaperone vault-set --store v.bin --path prod/deploy/key --passphrase-stdin
```

> **⚠️ Passphrase hygiene with pipes.** Anything you type literally on a
> command line — including a passphrase — lands in your shell history
> (`~/.bash_history`, `~/.zsh_history`). The examples above use a
> `$PASSPHRASE` variable or a file *on purpose*. For real credentials:
> prefer the interactive prompt (no `--passphrase-stdin`), or read from a
> `0600` file/fd. Never inline production passphrases into commands.

### 3.3 Reading

```sh
# Redacted presence check — safe around screens and scrollback:
chaperone vault-get --store v.bin --path prod/stripe/key
# → [redacted] 48 bytes present

# Explicit plaintext reveal (goes to YOUR terminal):
chaperone vault-get --store v.bin --path prod/stripe/key --show
```

`--show` exists because operators occasionally need export/recovery; the
default redaction exists because unasked-for secrets scrolling by is how
they end up in screenshots. Listing names only:

```sh
chaperone vault-list --store v.bin
```

### 3.4 Deleting

```sh
chaperone vault-del --store v.bin --path prod/stripe/key
```

## 4. Rotating a secret

Overwrite in place — the path, and therefore every `cred_ref` and policy
rule referencing it, stays stable:

```sh
chaperone vault-set --store v.bin --path prod/stripe/key   # new value on stdin
```

Agents notice nothing until their next intent resolves the fresh value.
Every write re-randomizes the AES-GCM nonce and rewrites the file atomically.

## 5. How AGENTS use these entries

Entries are addressed as **`cred_ref` = `local://<path>`** inside signed
intents. Example policy rule granting one agent one credential against one
host:

```toml
[[rule]]
name       = "ci agent may charge via stripe"
effect     = "allow"
agent_id   = "agent:planner-7"
cred_ref   = "local://prod/stripe/key"
target_uri = "https://api.stripe.com/v1/*"

[rule.limits]
max_response_bytes = 262144
```

Start the gateway pointing at your store — the passphrase unlocks it once
at startup:

```sh
chaperone serve \
  --enrollment ~/.config/chaperone/enrollment.json \
  --policy     ~/.config/chaperone/policy.toml \
  --store      ~/.config/chaperone/vault.bin \
  --audit-journal ~/.config/chaperone/audit.jsonl \
  --audit-key     ~/.config/chaperone/audit.key \
  [--console-socket ~/.config/chaperone/console.sock]
```

From there the agent never sees the secret: it files intents naming
`local://prod/stripe/key`; the gateway resolves, injects, and audits.
Full flow: [CONNECTIVITY-MATRIX.md](CONNECTIVITY-MATRIX.md).

## 6. Backups and storage hygiene

- **Backup = copy the file.** It is ciphertext at rest; a copy is exactly as
  safe as the original *and* still requires your passphrase.
- Keep copies on trusted media only. Do not commit vaults to git, attach
  them to tickets, or park them next to a plaintext passphrase note.
- Store multiple vaults by using different paths — e.g. separate personal /
  work stores. Each has its own passphrase and its own DEK.
- The passphrase travels through memory like any secret (hidden prompt or
  first piped line); nothing about it is logged, echoed, or stored.

## 7. Troubleshooting

| Symptom | Meaning | What to do |
|---|---|---|
| `error: passphrase does not open this vault` | Wrong passphrase (or wrong file) | Nothing was opened; retry. Forgotten passphrases cannot be recovered — restore from a backup copy made with a known passphrase |
| `vault corrupt: body authentication failed` | File bytes were modified/corrupted | Fail-closed by design. Restore your backup copy; do NOT force-open |
| `a vault already exists at …` | `vault-init` refuses to clobber | Use the existing store, or move the old file aside deliberately |
| `<path> does not exist` | Entry never stored, or typo'd path | `vault-list` to compare |
| `no provider for scheme "…" (supported: local)` | Intent used another scheme without that backend configured | Either register the backend (e.g. `--vault-url`) or fix the cred_ref |

All operator errors exit non-zero and print human-legible reasons. Error
messages never contain secret material.

## 8. Under the hood (short version)

- Header: argon2id parameters + random salt + the data-encryption key
  wrapped with your passphrase-derived key (AES-256-GCM).
- Body: all entries encrypted as one AES-256-GCM payload with a fresh nonce
  per write; authenticated — tampering fails at open.
- Writes are atomic temp-file + rename; a crash mid-write cannot shred the
  store.
- Opening authenticates BOTH the wrapped key and the body before any handle
  exists — a wrong passphrase and a corrupted file are distinct, content-free
  errors.
- Optional stronger sealing: building with `--features keyring` stores the
  data key in the OS credential store (Keychain / Credential Manager /
  kernel keyring) instead of passphrase-wrapping it.

Details and rationale: [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) D5, D19.
