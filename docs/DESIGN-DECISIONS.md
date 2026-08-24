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

## D15 — Pre-schema failure mapping & verification-order details

PROTO-SPEC §4 defines the sequence for well-formed envelopes; real peers send
malformed ones. Choices made where the spec is silent:

- **Version gate is step 0**, before agent resolution: it is a static
  contract check, not trust evaluation, and rejecting early avoids spending
  work on intents no version of us may honor. Malformed or missing
  `chaperone` reports `E_VERSION`.
- Fields that fail extraction map to the step that owns them: missing/non-
  string `agent_id` → `E_UNKNOWN_AGENT` (nothing to attribute);
  missing/unparsable/out-of-window `issued_at` or missing `nonce` →
  `E_REPLAY` (freshness cannot be established); missing/undecodable/wrong-
  length `sig` or a failed verification → `E_BAD_SIGNATURE`. No new codes are
  invented.
- Nonces are reserved BEFORE signature examination (still step 2): reserving
  only after verify would let two racing identical intents both pass.
- RFC 3339 timestamps with non-zero offsets are accepted and normalized to
  their UTC instant — freshness compares instants; the skew bound does the
  limiting.
- Replay-cache retention = 3 × skew: an intent accepted at the future edge of
  the window stays valid up to insertion + 2·skew; the third skew is boundary
  epsilon against clock jitter.
- Signatures verify via ed25519 `verify_strict` (rejects malleable
  signatures) rather than bare `verify`.

## D16 — Enrollment store shape

Single JSON file (`version`, `agents[]`) holding id, base64url public key,
`enrolled_at`, optional `revoked_at` (kept as history; revoked ids resolve to
nothing per ARCH §2.2). Writes are temp-file + rename (atomic replacement,
`0600` preserved). Rotation requires revoking first, or an explicit force
flag — overwriting a live key silently would be exactly the kind of quiet
authority change Chaperone exists to prevent. The operator CLI takes an
explicit `--store` path in v0; defaulting locations is deferred until the
daemon owns its state directory layout. The CLI never generates private keys:
PROTO-SPEC §4.1 requires them to be born inside a platform key store.

## D17 — Policy engine v0 details

Choices filling ARCH-SPEC §2.3's deliberate silence on rule language:

- **Operation axis = `mechanism`** in v0. The protocol's fourth axis
  ("operation") is represented by the mechanism selector; structured
  operation-body matching (method, command/argument pinning) arrives with the
  phases that need it (M9 for local-privilege allowlists), keeping v0 rules
  boringly auditable.
- **Glob semantics**: `*` matches any run of ANY characters, separators
  included - there is no path-scoped wildcard class. Consequence stated in
  the matcher docs and tests: patterns like `https://*.example.com/*` do not
  enforce hostname boundaries; boundary-critical rules anchor with Exact or
  Prefix. Explicit tags `glob:` / `prefix:` exist for literals that contain
  `*`; bare strings containing `*` are globs.
- **Strict schema**: the TOML loader uses deny_unknown_fields and validates
  effect values, so a typo'd axis (`agents_id`) fails the load loudly instead
  of silently matching-any - a silent match-any would be a quiet authority
  grant, exactly what this engine exists to prevent.
- **Per-rule `limits`** are policy-side ceilings; evaluation returns the
  element-wise minimum of matched-rule limits and agent-declared constraints
  (PROTO-SPEC §5.1: constraints only narrow). Denials report no effective
  widening either way.
- **First match wins**; rule file order is precedence. Default-deny is not a
  rule: an empty or non-matching ruleset denies structurally.

## D18 — Audit chain encoding & the tail-truncation honesty note

Concrete shape of D7 in code:

- Line = JCS-canonical JSON of the full record (stable, diffable bytes).
- `this_hash = SHA-256(prev_hash_raw || canonical_body)` where body excludes
  exactly `{this_hash, sig}`; `sig` = Ed25519 over the raw 32-byte hash.
- Genesis anchors with a zero `prev_hash` and is itself signed - key
  substitution fails at line one.
- Appends flush + fsync before returning; a crash cannot leave a last line
  that later verifies.
- The writer re-verifies the whole journal on open and REFUSES to extend a
  chain that breaks anywhere: extending a broken chain would launder the
  break. Broken journals are quarantined for operator ruling.

**Honest limit:** deleting the LAST record(s) leaves a perfectly valid
shorter chain. That is inherent to hash chains, not an implementation gap -
and it stays that way by design. The mitigation is operational: the head
`(seq, hash)` from `AuditWriter::head()` / `chaperone audit-verify` is
published/monitored externally, and any divergence means truncation. A test
asserts this limit explicitly so no later optimization quietly claims more
than the cryptography provides.

Record schema is pinned by test (top-level key allow-list); adding a field
must consciously pass review - that list is the entire surface through which
content can enter the journal. The API accepts no credential material at all:
references only (ARCH-SPEC §2.8).

## D19 — Vault sealing posture & local-store format

Concrete shape of D5 as shipped in Phase 5:

- **Sealer trait** abstracts DEK protection; two implementations:
  - `PassphraseSealer` (default): argon2id (64 MiB / t=3 / p=1, params
    persisted per-store) derives a KEK from the operator passphrase; the
    random DEK is AES-256-GCM-wrapped. Chosen as v0 default because it works
    on headless servers with no OS credential service - a real deployment
    surface for this project. Documented-weaker: the KEK exists in process
    memory while the store is open.
  - `KeyringSealer` (feature `keyring`, off by default): DEK lives in the
    platform credential store via the maintained `keyring` crate with
    NATIVE backends only - kernel keyring (Linux, matching ARCH §4.2's
    "kernel keyring" row), Keychain (macOS), Credential Manager (Windows).
    Off by default because those services must exist at RUNTIME.
- **Store format**: `CHAPVAULT1` magic + JSON header (version, sealer name,
  KDF params, sealed DEK, body nonce) + AES-256-GCM body of `{path: value}`.
  Fresh nonce on every write; atomic temp+rename persistence at 0600;
  open() authenticates BOTH the sealed-DEK tag and the body tag before any
  handle exists.
- **In-memory posture** (the ephemerality contract made structural):
  the handle keeps only header material, ciphertext, and the zeroized DEK;
  entry plaintext exists solely inside `get()`/`set()` call frames and only
  ever inside a `SecretString`.
- **SecretString discipline**: non-Clone (no accidental copies),
  Debug/Display print "[secret redacted]" (pinned by test), no Serialize
  impl (nothing can serialize it by mistake), explicit `.expose()` naming
  every plaintext read, explicit `.wipe()` for early scrubbing on failure
  paths.
- **No caching at ANY layer**: router -> provider -> store each fetch fresh;
  a counting-provider test proves 25 resolves = 25 backend hits and that a
  restart starts from zero cache. This is what makes "a retry is a fresh
  fetch" true by construction rather than by review.
- **Minting**: `Provider::mint` is the short-lived/narrowest-credential hook
  (ARCH §2.4); static local:// reports unsupported instead of pretending to
  scope. Dynamic minting arrives with enterprise providers post-v1.
- **Operator CLI**: vault-init/set/get/list/del; passphrase via hidden
  prompt or piped stdin (`--passphrase-stdin`: FIRST line = passphrase,
  remaining stdin = secret value for set). `vault-get` prints a redacted
  presence confirmation unless `--show` is passed explicitly - the console
  is trusted context, but scrolling secrets into terminals unasked is how
  they end up in screen-shares and scrollback.

## D20 - Response ceilings abort, never truncate

`max_response_bytes` (effective = min of rule limit, agent constraint, or
gateway default) is enforced by STREAM-counting the body: a lying
Content-Length cannot buy an unbounded buffer, and exceeding the ceiling
fails the operation loudly (`E_MECHANISM`) instead of silently delivering a
truncated payload the agent might act on. A truncated charge response would
be worse than a failed one.

## D21 - Redirects are disabled at the HTTP client

The signed intent names exactly one target URI; following a 30x would hand
whatever answers next both the request AND its Authorization header -
a hostile-target laundering primitive (THREAT-MODEL T3). The injector's
client sets redirect policy to none. If a future mechanism needs redirects,
it must re-sign per hop with policy in the loop.

## D22 - Post-signature schema failures map to E_MECHANISM

PROTO-SPEC's error taxonomy has no code for "signature verified but the
signed body fails typed parsing" (only possible for agents that sign
garbage). Rather than inventing an envelope-level code, this maps to
E_MECHANISM with a descriptive reason; identity-stage failures keep their
§10 codes. Unknown message `type` values likewise answer E_MECHANISM until
session types land (M8). Recorded here so the mapping is a decision, not an
accident.

## D23 - SSH host-key policy

The ssh session backend REFUSES unknown host keys by default. A
TrustOnFirstUseAll mode exists for tests and explicitly configured single-
operator environments (--trust-host-keys on serve); it is documented-weaker,
never silent. Proper pin-store (TOFU journal + known_hosts import) is
tracked as post-v1 hardening; shipping an accept-all default would let any
on-path attacker harvest auth attempts against pinned infrastructure.

## D24 - Session relay batching over unary frames

PROTO-SPEC §8 describes streamed `session.output` frames. v1 transports are
strictly unary (one response frame per request frame), so the gateway
relays each `session.command`'s output as ONE batched `session.output`
frame containing seq-numbered chunks collected during a bounded quiet
window (~400 ms) or until channel close/exit. True push-streaming requires
transport extension and lands post-v1; batching preserves ordering,
attribution and the closed/exit semantics while keeping the wire contract
additive.

## D25 - local-privilege confirmation posture

Mechanism local-privilege ALWAYS routes through the human gate unless BOTH
(a) policy effect is allow AND (b) the daemon-side allowlist mirror pins
the exact command+argument prefix. The helper process re-checks the SAME
allowlist authoritatively at execution - the daemon copy only decides
whether prompting is needed, so a compromised daemon cannot skip the
helper's own gate, and an edited allowlist cannot bypass confirmation.
Elevation mechanics (sudoers/setuid/polkit wrapper invoking the helper)
are deployment configuration, deliberately outside both processes.

## D26 - Error reasons never amplify secret-shaped input

When an agent pastes secret-shaped text where a cred_ref belongs, the
vault's malformed-reference error must not echo that text back (it would
land in logs and audit evidence verbatim). Malformed cred_ref errors are
content-free and shape-teaching ("must look like scheme://entry-path").
Pinned by test alongside the skill's paste-token anti-pattern case.
