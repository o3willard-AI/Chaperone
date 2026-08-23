# Chaperone — Design Decisions

The specs deliberately leave some choices to the implementation. Per Brief §6:
when the spec is silent, decide explicitly and write it down. Each entry states
the decision, the reasoning, and the spec section it fills. Decisions may be
superseded — superseded entries stay, marked as such, with a pointer.

| # | Topic | Decision | Status |
|---|---|---|---|
| D1 | Crate layout | Add `protocol` crate beyond the brief's suggested nine (see below) | Accepted |
| D2 | Wire/serialization details | serde + `serde_json`; JCS via maintained RFC 8785 crate; base64url no-pad for `sig` | Accepted |
| D3 | Policy rule language | Declarative TOML ruleset; exact/prefix matchers only in v0; boringly explicit | Accepted |
| D4 | Session handle format | Opaque random token, server-side state; handle carries zero authority alone | Accepted |
| D5 | Local vault sealing | Platform key store first (keyring/Keychain/DPAPI); passphrase+argon2id fallback | Accepted |
| D6 | Replay cache persistence | Persisted alongside audit chain; survives restarts | Accepted |
| D7 | Audit chain encoding | JSONL records, SHA-256 hash chaining, gateway Ed25519 signature per record | Accepted |
| D8 | Operator channel / confirmation UX | v0: controlling TTY prompt of the daemon; socket-based console later | Accepted |
| D9 | Unknown envelope fields | Ignore unknown request/response fields (MINOR forward-compat); reject unknown `mechanism` values | Accepted |
| D10 | Frame size limits | Hard max frame 8 MiB at transport; `max_response_bytes` separately enforced at injection | Accepted |
| D11 | Async runtime & I/O stack | tokio; one accept loop, task per connection; session streaming later rides the same runtime | Accepted |
| D12 | Transport-level error frames | `{"type":"error","scope":"transport","reason":…}` for framing/parsing violations; NO invented `E_*` codes | Accepted |
| D13 | Windows named-pipe ACLs | v1 uses tokio default DACL (process-token derived); explicit restrictive ACL deferred to hardening — tracked, not silent | Accepted |

---

## D1 — Crate layout: one extra `protocol` crate

Brief §5 suggests `gateway-core`, `transport`, `identity`, `policy`, `vault`,
`injectors`, `audit`, `privileged-helper`, `cli`. We add **`protocol`**: the
envelope/intent types, error codes (`E_*`), version constant, and JCS-canonical
form helpers.

Reasoning: PROTO-SPEC is the governing artifact and its schema is consumed by
nearly every other crate (transport frames it, identity signs it, policy reads
it, cli produces it). A dependency-free leaf crate keeps the contract in exactly
one place and mirrors ARCH-SPEC §1.1's inward-only layering: everything may
depend on `protocol`; nothing in `protocol` depends on anything.

Dependency direction (matches ARCH-SPEC §1.1):

```
cli ──► transport ──► protocol ◄── identity
gateway-core ──► {identity, policy, injectors, audit, vault}
injectors ──► vault(trait) ; privileged-helper ◄─ gateway-core (spawned)
```

## D2 — Serialization primitives

- `serde`/`serde_json` for all wire structures; unknown-field tolerance on parse (see D9).
- JCS canonicalization via a maintained RFC 8785 crate (e.g. `jcs`-family), not hand-rolled.
- Ed25519 via `ed25519-dalek` family; signatures base64url-unpadded in `sig`.
- No hand-rolled crypto anywhere (Brief §4).

## D3 — Policy rule language

The protocol carries decisions, not rules (PROTO-SPEC §9); ARCH-SPEC §2.3 leaves
the language open. v0 rules are a single ordered list in a TOML file:

```toml
[[rule]]
effect = "allow"                # allow | deny | needs_confirmation
agent_id = "agent:planner-7"    # exact match
cred_ref = "vault://prod/stripe/*"   # glob, path-scoped
target_uri = "https://api.stripe.com/v1/*"  # glob
operation = { mechanism = "http-bearer", method = "POST" }
```

Rules:

- Evaluation: first match wins; **no match → deny** (default-deny is structural,
  not a rule anyone can delete).
- Only explicit matchers in v0 (exact / glob). Time windows, rates, argument
  pinning arrive with the phases that need them.
- The engine is total and side-effect-free by construction: it receives data,
  returns a verdict, holds no handles.
- Glob semantics kept minimal and documented; no regex in v0 (auditability).

## D4 — Session handle format

`sess_` + base64url(32 bytes from the OS CSPRNG). Purely opaque: the gateway
holds the authoritative session table (handle → agent_id, channel, expiry).
Authority comes from the *signature over the frame* + owner binding check, never
from possession of the string. Handles are unguessable (256-bit) so the binding
check is defense-in-depth, not the only gate.

## D5 — Built-in local vault sealing

Order of preference, decided at store creation:

1. **Platform key store** seals the data-encryption key: kernel keyring (Linux),
   Keychain/Secure Enclave (macOS), DPAPI (Windows). Matches ARCH-SPEC §4.2 row
   "Vault: local store seal".
2. **Software fallback** (no keystore available): AES-256-GCM with a key derived
   from an operator passphrase via argon2id. Documented loudly as weaker; exists
   so the built-in vault honors its "usable with no external dependency" promise
   even on stripped platforms.

File layout: one encrypted file under user config/state dirs, perms `0600`,
no plaintext ever at rest. Secret material in memory only in zeroize-on-drop buffers.

## D6 — Replay cache persistence

PROTO-SPEC §4 requires nonce uniqueness within the freshness window. An
in-memory-only cache forgets nonces across daemon restarts — a restart inside
the window would re-accept a replayed intent. So the replay cache is persisted
(append-only nonce log with periodic compaction) next to the audit chain, covering
max(skew window, observed clock jitter) + margin.

## D7 — Audit chain encoding

JSONL, one record per line: `{prev_hash, this_hash, seq, timestamp, record…}`
with `this_hash = SHA-256(prev_hash || canonical_record_bytes)` and an Ed25519
signature by the gateway's audit key over `this_hash`. Genesis record anchors
the chain at first start. Verification walks the file recomputing hashes and
signatures (CLI subcommand, Phase 4). Append-only enforced by convention +
OS file permissions in v0; tamper-evidence (not tamper-resistance) is the goal,
per THREAT-MODEL §6 detection row.

## D8 — Operator channel and confirmation surface

PROTO-SPEC §9.2 says the gateway surfaces confirmation through "the operator
channel" but does not define it. v0: if the daemon has a controlling TTY, render
the full-context prompt there (target label, agent_id, mechanism, operation
summary) and block on stdin y/n with timeout → `E_CONFIRM_TIMEOUT`. A dedicated
operator console over a second local socket arrives later; when it does, TTY
prompting becomes a fallback. Never the agent socket — the agent cannot see or
answer the gate.

## D9 — Unknown fields

PROTO-SPEC §10.2: agents MUST ignore unknown response fields; MINOR versions add
optional fields only. Symmetrically, the gateway **ignores** unknown envelope
fields on receipt (they participate in JCS/signature since they were signed —
ignoring ≠ stripping). Unknown `mechanism` values are rejected (`E_MECHANISM`
stage-consistent error) because mechanisms define body schemas we must not guess.
Unknown `type` values rejected as malformed envelope.

## D10 — Frame size limits

Transport rejects any frame declaring `Content-Length` > 8 MiB (hard DoS guard,
THREAT-MODEL T3 spirit) before reading the body. This is independent of, and
additional to, the agent-declared/policy-declared `max_response_bytes` cap that
bounds what an injector will relay back. Both ceilings take minimums with any
policy-declared limit per PROTO-SPEC §5.1 constraints note.

## D11 — Async runtime and I/O stack

tokio, chosen at Phase 1 when the first real I/O landed. Reasons: the brokered
session lifecycle (PROTO-SPEC §6.2) needs concurrent command ingress and
output streaming per connection, which selects against a blocking-I/O thread
per direction; tokio's `UnixListener`, Windows named pipes, and TCP share one
API surface, keeping the platform matrix honest from the first commit; and it
is the most heavily scrutinized async runtime in the ecosystem, which matters
for supply-chain review. Concurrency shape: one accept loop, one task per
connection; nothing is shared between connections.

## D12 — Transport-level error frames

A connection can fail before any valid message exists (malformed header,
oversized frame, non-object payload). PROTO-SPEC §10.1's error taxonomy is
defined for *messages* — inventing codes there would risk colliding with
future spec revisions. So the transport answers once with:

```json
{ "type": "error", "scope": "transport", "reason": "<human-legible>" }
```

then disconnects. These frames never echo message content and are documented
as outside the §10.1 taxonomy.

## D13 — Windows named-pipe ACL posture

ARCH-SPEC requires owner-only access on every transport. On Windows, tokio's
named pipe creation applies the default DACL derived from the creating
process token (current user plus system), which matches that intent for the
single-user local deployment Chaperone targets. Building an explicit
restrictive ACL requires unsafe Win32 calls, which the workspace forbids
workspace-wide; the tightening work belongs to the hardening phase (PLAN M10)
and is tracked here rather than silently accepted.
