# Getting Started with Chaperone

**From zero to: an agent used a credential you can prove it never saw.**

Two ways through this guide — pick one:

- **The UI way** (recommended): start `chaperone serve`, open the setup
  wizard in your browser, fill forms.
- **The CLI way**: run the commands shown under *Terminal equivalent* at
  each step.

Both paths produce the same four files on disk. Neither is a toy: the
wizard writes through the exact same crates the CLI uses — there is one
validator in this project, not two.

---

## What you will create

| File | Purpose |
|---|---|
| `~/.config/chaperone/vault.bin` | Your encrypted secret store (argon2id + AES-256-GCM) |
| `~/.config/chaperone/audit.key` | Ed25519 seed that signs your audit chain — **back this up** |
| `~/.config/chaperone/policy.toml` | The ruleset: who may use what, where |
| `~/.config/chaperone/agents.json` | Enrolled agent public keys |

Everything below assumes `~/.config/chaperone`; any directory works if you
pass explicit paths.

## Step 0 — Install

See [INSTALL.md](../INSTALL.md). Verify:

```console
$ chaperone version
chaperone 0.1.0-alpha.3 (protocol 0.1, gateway spec v0.1)
```

## Step 1 — First run starts the wizard

```console
$ chaperone serve \
    --socket ~/.config/chaperone/agent.sock \
    --enrollment ~/.config/chaperone/agents.json \
    --policy ~/.config/chaperone/policy.toml \
    --store ~/.config/chaperone/vault.bin \
    --audit-journal ~/.config/chaperone/audit.jsonl \
    --audit-key ~/.config/chaperone/audit.key

CHAPERONE SETUP
  required artifacts are missing; starting the setup wizard only.
  open: http://127.0.0.1:8720
```

No artifacts yet means there is nothing to broker and no passphrase to ask
for — so serve runs **setup mode only**: just the wizard on your loopback.

> **Terminal equivalent:** keep reading; steps 2–4 each show the command
> the wizard button corresponds to.

## Step 2 — Create the vault

In the wizard: **Setup → Local secret vault**, pick a passphrase twice.

This creates `vault.bin`. The passphrase is the only way in — there is no
recovery. Losing it means re-entering every secret.

> **Terminal equivalent:** `chaperone vault-init --store ~/.config/chaperone/vault.bin`

## Step 3 — Generate the audit key

Wizard: **Setup → Audit chain signing key**, press generate.

Every decision the gateway ever makes is appended to a signed,
hash-chained journal (`audit.jsonl`). This key signs it. Anyone can verify
your chain later with the public key the wizard prints.

> **Terminal equivalent:** `chaperone audit-keygen --out ~/.config/chaperone/audit.key`

## Step 4 — Write the policy scaffold

Wizard: **Setup → Policy file**, press write. You get an empty document,
which is a valid pure default-deny ruleset: until you add rules, **every**
intent is refused.

> **Terminal equivalent:** `touch ~/.config/chaperone/policy.toml` (empty is valid)

## Step 5 — Restart into broker mode

Ctrl-C the process and run the same serve command again. Now it prompts for
the vault passphrase, prints three lines — event feed, gateway socket, UI —
and brokers intents. The dashboard at <http://127.0.0.1:8720> says
**brokering**.

## Step 6 — Add a secret

Wizard: **Secrets**, e.g. path `prod/github/token`, paste a GitHub
fine-grained PAT once. It is never displayed again — pages show only
`[redacted] N bytes present`.

> **Terminal equivalent:** `echo "$PAT" | chaperone vault-set --store ~/.config/chaperone/vault.bin --path prod/github/token --passphrase-stdin`

Rotating later = storing the same path again. Credential references never
change, so neither does anything downstream.

## Step 7 — Enroll an agent

An agent publishes its Ed25519 *public* key out-of-band (32 bytes,
base64url — not a JSON blob). Wizard: **Agents**, paste it.

Revocation is one click and effective immediately: revoked keys fail at
identity verification before anything else happens.

> **Terminal equivalent:** `chaperone enroll --store ~/.config/chaperone/agents.json --agent-id agent:github-1 --public-key <B64URL>`

## Step 8 — Add your first rule

Wizard: **Rules → Add a rule**. Pick the mechanism (badges come from the
[connectivity matrix](CONNECTIVITY-MATRIX.md) — read ⚠️ caveats *before*
building on them), pick a service template to prefill a tested
`target_uri` glob, then choose agent, credential, effect.

Saving validates the generated TOML through the same parser the gateway
loads at startup; an invalid rule cannot be saved.

> **Terminal equivalent:** edit `policy.toml` by hand:
>
> ```toml
> [[rule]]
> name       = "ci agent may read github"
> effect     = "allow"
> agent_id   = "agent:github-1"
> cred_ref   = "local://prod/github/token"
> target_uri = "https://api.github.com/*"
>
> [rule.limits]
> max_response_bytes = 262144
> ```

### How edits reach a running gateway

They don't — deliberately. There is no hot reload: **restart
`chaperone serve`** to load a changed policy. While running, a guard
watches the file; any change under a live daemon halts brokering loudly
(signed `policy_drift` audit record + event broadcast) until you restart.
An edited rule can never take effect silently.

## Step 9 — Watch it work

Tail decisions live from a second terminal:

```console
$ chaperone serve ... --events-socket ~/.config/chaperone/events.sock   # add this flag
$ curl --unix-socket ~/.config/chaperone/events.sock http://localhost/feed
{"audit_id":"aud_3","agent_id":"agent:github-1","effect":"allow","mechanism":"http-bearer","target_uri":"https://api.github.com/user","outcome":{"status":"proceeded"}}
```

And verify the chain any time:

```console
$ chaperone audit-verify --journal ~/.config/chaperone/audit.jsonl --public-key <B64URL>
```

---

## Where to go next

- [LOCAL-VAULT-GUIDE.md](LOCAL-VAULT-GUIDE.md) — rotation, keyring sealing
- [CONNECTIVITY-MATRIX.md](CONNECTIVITY-MATRIX.md) — everything agents can reach today
- [INSTALL.md](../INSTALL.md) — service install, upgrade semantics
- [docs/RELEASE.md](RELEASE.md) — verifying release artifacts
