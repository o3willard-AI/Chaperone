# B-1 spec: SSH certificate authority / dynamic minting

Author: ox-chap (Hermes, host 192.168.101.11)
Date: 2026-10-04
Status: **DRAFT — for review by Heph, then ruling by Stephen**
Branch: `docs/b1-ca-spec` (this document)

Source items: MVP-GAP-REVIEW **B-1** (deferred with reason), D29 (Vault PKI
"plugs into mint() post-v1"), D30 (post-v1 backlog), D31 (PinStore), D43 (pair
rows, "deleted when B-1 supersedes per-host secrets"), D47 (the
secret-free-by-construction standard B-4 set).

---

## 0. The problem in one paragraph

Chaperone's SSH story today is *per-host long-lived secrets*: one Ed25519
private key per host in the vault, one `[[rule]]` (or a pair row) binding it.
The gap review's own analysis:

- **Per-host keys do not scale.** 300 hosts = 300 secrets, 300 pair rows
  (or 300 rules), 300 rotation chores, and 300 blast radii.
- **A long-lived private key is the wrong granularity of authority.** Whoever
  holds it holds the host forever, with no expiry and no attribution trail.
- **`mint()` already exists and reports unsupported.** The hook is in
  `crates/vault/src/provider.rs`; PKI was deferred to post-v1 in D29.

B-1 replaces per-host secrets with **one CA credential and short-lived signed
certificates minted per action**: the vault holds exactly one CA key, the
gateway signs a short-lived user certificate binding the *agent's* key to the
*host*, and the host trusts the CA. No per-host secret ever exists.

## 1. The trust model — five decisions before any code

These are the decisions this document exists to get ruled. Each has a
recommendation and the alternative, with the reasoning.

### TD-1 — Who is the CA? A Chaperone-owned keypair, in the vault.

**Recommendation: the gateway mints from a Chaperone-held CA keypair stored in
the vault at `local://chaperone/ca/ssh`.**

- One key, one rotation story, stored exactly where every other secret lives.
- Reuses D5/D19 sealing — no new storage format, no new passphrase surface.
- The vault is already the "holds credentials" primitive; making the CA a
  *vault entry* means the operator's existing backup procedure (P2-3's warning)
  covers it.

*Alternative:* delegate to a HashiCorp Vault PKI engine via `vault://`. That is
the enterprise answer and D29 anticipated it, but it requires a Vault deployment
to use B-1 at all. **Plan: Chaperone-owned CA now, Vault PKI as a provider
behind the same `mint()` signature later.** The trait change is identical; only
the backend differs.

*Rejected:* OS trust stores / sshd `TrustedUserCAKeys` pointing at a
 remotely-provisioned CA — out of scope, and airgapped-first customers (the
 licensing stance) cannot fetch one.

### TD-2 — What does a minted cert attest? Agent key + principal + host.

**Recommendation: each mint signs the AGENT'S public key (enrolled at
enrollment time, RAE L0) into an SSH user certificate with:**

| Cert field | Value | Why |
|---|---|---|
| Key ID | `chaperone:<agent_id>:<msg_id>` | the audit chain can correlate a cert to its decision |
| Principals | the single host the rule binds (or the agent_id as principal, per TD-3) | least privilege |
| Validity | **default 300 s, ceiling 3600 s, operator-configurable down only** | short-lived is the point; the ceiling exists so an operator cannot configure themselves into a de-facto long-lived cert |
| Extensions | `permit-pty` iff the intent requested one; **never** `permit-agent-forwarding`, `permit-port-forwarding`, `permit-X11-forwarding` | forwarding tunnels are a credential-laundering channel; the threat model has no case for them |
| Critical options | none | keep the surface minimal |

The cert does **not** carry the secret — it carries the agent's *public* key
and an identity. The vault's CA key signs it and is never exposed outside the
mint call.

*Alternative:* sign a fresh throwaway keypair per action. That adds a keygen
per action, and the enrolled agent key already exists — reusing it is what ties
the cert to the RAE identity in the enrollment store.

**API verification (against the pinned `russh` 0.60.3 in Cargo.lock, checked
before drafting further):** everything this design needs exists.

- `russh::keys::ssh_key::certificate::Builder` — `new_with_random_nonce`,
  `key_id`, `valid_principal` (singular; the spec's one-principal rule maps
  directly), `extension` (opt-in map, **starts empty**, so the default cert
  carries no forwarding extensions unless code explicitly adds them — TD-2's
  "never" is enforced by omission plus a test, not by a denylist),
  `critical_option`, `sign(&PrivateKey) -> Certificate`, `to_openssh()`.
- `russh::client::Handle::authenticate_openssh_cert(user, Arc<PrivateKey>,
  cert)` — the client-side auth method for certs (verified signature in the
  pinned source), so the injector change is a method swap plus cert plumbing,
  not a protocol implementation. Note the agent's private key is still required
  per auth: the cert extends the key, it does not replace it — which is what
  makes "stolen cert alone is worthless" true by construction.
- `Certificate::validate(&ca_fingerprints)` — exists for the receiving side
  (tests, and any future host-side tooling).

Falsifiability note: acceptance test 1's revert experiment is real because
signing is a pure function over `(ca_key, agent_pubkey, fields)` — no network
required, so a test can break the signer and observe a parse failure.

### TD-3 — How does sshd authorize the cert? Principals = host.

**Recommendation: the certificate's principal list contains exactly one
principal, equal to the canonical host form the rule binds.** `sshd`
configures `TrustedUserCAKeys` plus `AuthorizedPrincipalsFile` (or
`AuthorizedPrincipalsCommand`) so a cert is only valid for the principal it
names.

- P1-2's rule *already* binds cred_ref→target_uri. The cert's principal is that
  binding, now enforced by sshd rather than only by Chaperone. **Two
  independent enforcement points for the same grant.**
- This is what makes the CA model *narrower* than the per-host key model: a
  stolen per-host key opens that host from anywhere; a stolen minted cert
  opens nothing (it needs the agent's private key too, and it expires).

*Alternative:* principal = agent_id, with sshd matching the agent's login user
to it. Simpler config, but it decouples the cert from the rule's target
binding, which throws away P1-2's guarantee. Rejected.

### TD-4 — What does the host trust? `TrustedUserCAKeys`, documented.

**Recommendation: B-1 ships the gateway side and the **documented** host-side
recipe (an sshd_config snippet + the CA public key export command), NOT an
agent that reconfigures sshd.**

- We are a credential broker, not a fleet-management product. Touching sshd on
  customer machines is a different product with a different threat model.
- The airgapped-first buyer can apply the snippet from a runbook; that is how
  they apply any sshd change today.

*Alternative:* a `chaperone host-enroll` that edits sshd_config. Deferred —
recorded here so it is a decision, not an accident. If fleets demand it, it
lands as its own slice with its own threat-model entry.

### TD-5 — What happens to the per-host keys? Nothing, for now.

**Recommendation: per-host keys keep working. B-1 is additive.** The gap
review's wording is "rows are deleted when B-1 supersedes per-host secrets" —
but that deletion is a *migration*, not a prerequisite. D43 pairs remain valid
config; D47's principle (a claim that is true by construction) applies to the
cert path independently.

Migration lands when operators have real fleets on B-1; forcing a cutover
before that would break every existing install for no security gain.

*Alternative:* remove pair-row support in the same slice. Rejected — a
config-compatibility trap for zero gain, and D43's ruling explicitly priced
rows as acceptable.

---

## 2. Where minting lives in the code

```
chaperone-vault
  provider.rs        mint(entry, ttl_secs) -> SecretString   [exists]
  ssh_ca.rs          NEW  — the CA: keypair load/create, sign_crt()
chaperone-gateway-core
  ssh.rs             host-key pinning (D31) — unchanged
  mint.rs            NEW  — MintRequest {agent_id, msg_id, host, want_pty}
                          -> verify rule binding -> sign cert -> return
chaperone-injectors
  ssh.rs             uses the CERT as the credential (russh accepts
                     PublicKey w/ cert); key text still zeroized
```

**The flow, per SSH intent:**

1. Policy allows (existing path, unchanged).
2. Instead of `resolve(cred_ref)`, the gateway calls `mint(...)` on the CA
   provider when `cred_ref` is `ca://<host>` — **a new scheme**, so no
   existing `local://` ref changes meaning.
3. The CA provider loads the CA keypair from the vault (fresh per resolve, D5's
   no-caching rule), signs the agent's enrolled public key, returns the cert
   text as the `SecretString` (it is credential material — short-lived, but
   still zeroize-on-drop).
4. The SSH injector authenticates with the cert; D31 pinning still runs on the
   host key (a CA does not vouch for the host — it vouches for the agent).
5. The audit record's `Outcome::Proceeded` gains a minted-cert correlation
   (key ID), so `cert → audit line` is traceable both ways.

**What this does NOT change:** the vault passphrase surface, the policy
engine, the P2 UI, `no_secret_leak` (cert text enters the vault-adjacent path
like any secret; the B-4 classified-error rule applies to the mint path as
well).

---

## 3. Threat model deltas (what the CA model changes)

| Threat | Per-host key (today) | CA model (B-1) |
|---|---|---|
| Vault compromise | every host's key leaks, none expire | only the CA key leaks; **revoke by rotating the CA**, hosts re-trust the new CA key |
| Agent compromise | the agent's per-host key leaks, no expiry | the agent's *enrolled* key leaks; certs minted with it expire ≤ 1 h; revoke the agent in the enrollment store and no new certs mint |
| Compromised sshd | agent key usable forever | cert invalid after expiry; CA unaffected |
| Stolen cert in transit | n/a | worthless without the agent's private key; expires ≤ 1 h |
| Compromised CA key | n/a | **worst case**: attacker can mint valid certs for any principal until the CA rotates. Mitigation: vault sealing + P2-3's backup warning + the operator keeps the CA offline when possible (TD-1 alt) |

**The worst case is worse than today** — that is the honest statement, and the
reason for the operator-configurable-down-only TTL ceiling and the audit
correlation. Record it in the threat model as a delta, not a footnote.

## 4. Acceptance criteria (falsifiable)

1. `mint()` on the CA provider produces a parseable SSH user certificate whose
   key ID embeds the agent_id and msg_id; **reverting the signer makes this
   test fail** with a parse error.
2. A cert minted for host A is refused by a validator implementing TD-3's
   principal rule for host B; **reverting the principal-binding makes the test
   fail** by accepting the wrong host.
3. A cert is refused after its expiry; **the TTL ceiling cannot be configured
   above 3600 s** (a test proves the ceiling, not just the default).
4. `permit-agent-forwarding` etc. never appear in a minted cert; **reverting
   the extension list makes the test fail**.
5. `no_secret_leak` still passes with the mint path exercised: the cert text
   never reaches agent-visible frames beyond the SSH auth itself, and the CA
   key material never leaves the mint call.
6. A cert minted for a revoked agent is refused; **revocation, not TTL, is
   what stops an actively-compromised agent** — both are tested.
7. The D31 pin store still rejects a changed host key under the CA model.
8. B-4's classified-error rule applies to the mint path: mint failures surface
   as `TransportError`-style classified causes, never free-form text.

## 5. Sizing and sequencing

| Slice | Est. |
|---|---|
| `ssh_ca.rs`: keypair load/create + `sign_crt` (pure, unit-testable offline) | 1.5–2 d |
| `ca://` scheme + gateway mint wiring + rule-binding check | 1 d |
| Injector switches to cert auth | 1 d |
| Tests 1–8 above (falsifiable, incl. the ceiling and revocation) | 1.5–2 d |
| Docs: sshd recipe + threat-model delta + migration note | 0.5–1 d |
| **Total** | **~5.5–7.5 d** |

Sequenced after Heph's review and Stephen's ruling on TD-1…TD-5. B-2 (bulk
import) is *not* blocked by this and can proceed in parallel if wanted; B-3 is
independent.

---

## 6. Open questions for the ruling (numbered for item-by-item)

1. **TD-1** — Chaperone-owned CA keypair in the vault? *Recommend yes; Vault
   PKI later behind the same `mint()`.*
2. **TD-2** — Sign the agent's enrolled public key; 300 s default / 3600 s
   hard ceiling; forwarding extensions never? *Recommend yes on all three.*
3. **TD-3** — Principal = the rule-bound host, enforced by sshd as well as
   Chaperone? *Recommend yes.*
4. **TD-4** — Ship the gateway + documented sshd recipe, NOT host
   auto-configuration? *Recommend yes; host-enroll is a separate product
   decision.*
5. **TD-5** — Per-host keys remain valid config; B-1 is additive; migration
   later? *Recommend yes.*
6. **CA-key storage** — `local://chaperone/ca/ssh` as a normal vault entry
   (same sealing, same P2-3 warning, operator-managed backup)? *Recommend
   yes.* The alternative — a separate, differently-sealed file — adds a second
   passphrase surface for no gain.
7. **TTL default** — 300 s (five minutes) covers an interactive session; the
   ceiling is what actually protects. *Recommend 300 s default / 3600 s
   ceiling, both operator-visible in the UI.*