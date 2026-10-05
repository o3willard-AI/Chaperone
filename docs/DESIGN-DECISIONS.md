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
| D14 | http-basic username resolution | Non-secret `username` is a required field inside the signed operation body; absent → error; no vault-metadata fallback; Basic auth per RFC 7617 (no `:` in username). | Accepted |

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

## D14 — http-basic username resolution

PROTO-SPEC §7.1 specifies only `http-bearer`; the intent-catalog lists both
mechanisms against a shared operation body. Basic auth requires a *username* in
addition to the secret — the spec does not state where it comes from.

**Decision (matches `assemble_authorization` in `crates/injectors/src/http.rs`):**

- The `username` is a **required** field inside the signed operation body. The
  `http-basic` arm reads `operation.username`; if it is absent the injector
  returns a `BadOperation` error: `"http-basic requires a username field (D14)"`.
- There is **no vault-metadata fallback** for the username. SI-2's original
  assumption proposed deriving it from the vault backend; the implementation
  instead made it mandatory, matching the RFC 7617 model where the username is
  not secret and belongs in the signed intent alongside `method`/`headers`.
- The username **must not** contain `:` — a colon would corrupt the
  `user:password` pairing before base64 encoding. The injector checks
  `username.contains(':')` and rejects with `"username must not contain ':'
  (RFC 7617)"`.
- Authorization is built as `Basic <standard-base64-of("username:password")>`
  (RFC 7617, with padding) — the same base64 STANDARD engine used for
  `body_b64`. The `username:password` string is dropped immediately after
  encoding so no plaintext lingers beyond the call frame.

**Reasoning:** the username is non-secret and agent-supplied; the vault's job
is the *password* in the `cred_ref`, not identity metadata. Forcing the
username into the signed operation body makes the full credential identity
attributable (which user is being authenticated against) without expanding
the vault provider interface or trusting backend-specific metadata formats.

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

## D27 - db-scram endpoint & lifecycle mapping

PROTO-SPEC's db-scram operation body carries engine/database/statement/
params but no host - so the connection endpoint lives in `target.uri`
(`postgres://user@host:port/dbname`, hand-parsed tiny grammar, everything
else rejected). Guards:

- `operation.database` contradicting the URI path fails BEFORE connecting -
  a signed-intent ambiguity must not silently resolve to whichever database
  answered.
- Statement present => ONE-SHOT (connect/auth/run/serialize/drop);
  statement absent => SESSION opener. This mirrors the intent-catalog's
  "single query vs session" split without inventing a third message type.
- SCRAM-SHA-256 performed by tokio-postgres; the secret exists only as the
  password inside one connect frame (never verbatim on the wire - that is
  what SCRAM is).
- Params bound AS TEXT via prepared statements (injection-safe); explicit
  `$1::int` casts disambiguate types.
- TLS-to-DB is NOT negotiated in v0 (NoTls): documented gap, tracked
  post-v1 with the rustls connector work.

## D28 - Provider goes async

`Provider::resolve/mint` return boxed futures now: HTTP backends (Vault,
cloud SDKs later) are inherently async and forcing sync signatures would
push block_on into either providers or every call site. `VaultRouter::
resolve` is async too but validates scheme dispatch synchronously first, so
malformed refs fail without entering the future. LocalVault wraps its
sync get in the same boxed shape. No caching appeared anywhere in the
conversion (the counting tests still prove 25 calls = 25 hits).

## D29 - HashiCorp Vault KV-v2 provider scope

First remote backend (`vault://mount/data/path#key`):
- KV-v2 READS over token-authenticated HTTP(S) via reqwest/rustls;
  redirects disabled like injectors.
- Single-key secrets resolve directly; multi-key secrets REQUIRE a
  `#key` selector rather than guessing - ambiguity is refused loudly.
- 401/403 map to "vault rejected the token", 404 to EntryNotFound;
  neither echoes the requested path beyond what the caller already sent.
- Dynamic engines (database creds, PKI) plug into mint() post-v1; KV is
  static by nature so mint stays unsupported here.
- serve wiring: --vault-url [--vault-mount], token from VAULT_TOKEN env
  (operator-managed; interactive token entry lands with the console).

## D30 - Post-v1 backlog codified

The deferrals called out during M7-M11 are tracked in PLAN.md's new
"Post-v1 backlog" section so they are roadmap, not folklore: db-scram wire
implementation (SHIPPED this phase), enterprise providers (Vault SHIPPED),
host-key pin store, streaming transport extension, cargo-fuzz targets,
enclave runtime, plugin ABI + browser-session, operator console socket.

## D31 - SSH host-key pin store (supersedes D23's stopgap)

`PinStore` persists pins as JSON (`version`, `pins[]`: hostport,
openssh two-field key line, first_seen, source) via temp+rename at owner
perms. Semantics:

- Pinned match -> accept. **Changed key on a pinned host -> refuse** - that
  is the MITM signal the store exists to catch.
- Unknown host + TOFU enabled -> record then accept; persistence failure
  surfaces as a REFUSAL, never silent trust.
- Unknown host + TOFU off -> refuse (strict default preserved).
- OpenSSH known_hosts import accepts only plain host / host:port entries;
  wildcards, exclusions, comma lists and hashed entries are skipped AND
  reported (wildcards would widen exactly the authority being pinned).
  Pin replacement is an explicit operator verb with a reason string.

## D32 - Operator console socket (supersedes TTY prompting)

A second local socket carries the single confirmation surface: plain UTF-8
lines, prompt out, one-line answer in. Nothing secret-shaped crosses it -
only the human decision - so it uses line protocol rather than agent
framing. Fail-closed posture: NO connected operator => confirmations
refuse immediately (never hang, never approve); a mid-prompt disconnect is
a refusal; the latest connection wins (one console, last writer takes
over). Daemon binds it owner-only (0600) with live-peer detection mirroring
the agent socket.

## D33 - Fuzz targets are always-buildable artifacts

fuzz/ ships three libfuzzer targets (frame codec, envelope verification,
policy parse+eval) as a standalone workspace so nightly/libfuzzer tooling
never contaminates the root build. Each target documents its invariant
(Ok-or-typed-Err, never panic; policy evaluation additionally asserted
PURE inside the loop). They complement - not replace - the deterministic
20k-mutation harness that gates every CI run.

## D34 - Replay-journal capacity policy

The nonce reservation order in §4 (reserve BEFORE signature verification)
is load-bearing against duplicate-intent races — but it means unverified
input drives journal growth. Policy: the persisted replay journal has a
hard byte cap (16 MiB default, overridable per-instance). When exceeded:

1. Compaction runs once (purge expired, rewrite).
2. If still over: the in-flight reservation is rolled back entirely and the
   intent is refused `E_REPLAY` ("replay cache at capacity") — fail closed,
   nothing journaled for refused intents.

Self-healing: refusals persist only while flood-era entries remain within
retention (~3× skew); as they expire, compaction reclaims space and service
resumes without operator action.

**Rejected alternative (B):** deferring persistence until after signature
verification would keep garbage off disk but reintroduces a crash-window
replay: a daemon crash between acceptance and persistence forgets the nonce,
letting a captured intent be replayed once across restart — precisely what
D6's persistence exists to prevent. Option B remains available if a future
threat model prefers it; switching is a contained change.

## D35 - Event feed transport

The console socket is deliberately 1:1 answer-oriented; notifications want
fan-out. A second read-only Unix socket (`chaperone-events.sock`, owner-only,
identical discipline to agent/console sockets) broadcasts one JSON line per
terminal intent decision to unlimited simultaneous readers. Nothing is ever
written back; no new fact is invented - fields are exactly what
`audit-export` already produces, so the only novelty is timing. Denies are
broadcast deliberately: repeated quiet refusal is itself signal.

**Rejected:** extending the console protocol with a subscribe verb - it
would entangle 1:1 confirm-and-answer semantics with fan-out in one state
machine for no shared-code benefit.

## D36 - The UI is a thin client over existing crates

The config UI must never parse or write policy TOML, vault format, or
enrollment JSON. Every mutation goes through `chaperone-policy`,
`chaperone-vault`, or `chaperone-identity` - the same implementations, and
therefore the same tests and fuzz targets, as the CLI. Rule documents are
produced by `Policy::to_toml` (the one canonical writer, living beside the
one parser) and re-validated with `Policy::from_toml` before any byte hits
disk. This is D12/D33's single-source-of-truth reasoning applied to a new
surface: a second validator in UI code is how "the UI let me create a
state the CLI would have refused" bugs get made.

## D37 - Notify defaults to on

`[rule.notify] on_use` defaults to **true**; quiet is opt-out. Inverted on
purpose: the rules where notification matters most (brokered sessions after
one-time approval, `never-approve` deployments) are precisely those where
no prompt would otherwise ever surface use. Opt-in would ship the feature
silent by default, which is the bug it exists to fix.

## D38 - Ruleset hash anchoring

Every gateway start appends a signed `policy_load` record carrying SHA-256
of the governing policy document; every decision record carries the same
hash under `ruleset_hash`. Any post-hoc edit of `policy.toml` is therefore
detectable as a hash break across restarts. Detection-over-prevention:
in the per-user model an ownership check is a no-op against the very actor
it would target (the same-user agent), matching D7/D18's honesty posture.
Strengthened from restart-time detection to live detection by D39.

## D39 - Policy-file integrity guard: perm gate + drift watch + halt

Two layers over D38:

1. **Load gate:** refuse a policy file that is group/other-writable or not
   owned by the running account, with a remediation-shaped message. Cheap,
   portable hygiene (ssh `authorized_keys` discipline).
2. **Live watch:** while serving, re-hash the file periodically against the
   anchored baseline. Content change, deletion, or persistent unreadability
   appends one signed `policy_drift` record, broadcasts on the events feed,
   prints a loud banner, and **halts brokering** until operator restart.

Halt-on-drift is fail-closed by construction: rules edited out-of-band can
never take effect silently because the daemon stops consulting its in-memory
ruleset entirely. The cost is availability - an accidental editor touch
takes the broker down until a human restarts it - accepted deliberately at
decision time. The restart that follows re-runs the load gate and re-anchors
the chain, so only what an operator implicitly re-approved by starting up
survives.

**Rejected:** updating the watch baseline when the config UI saves policy.
It would spare operators a restart cycle but means any local process able
to reach the UI endpoint could rewrite policy AND suppress the alarm -
trading a loud halt for a silent widening path. Not worth it.

## D40 - Operator UI shape: axum, in-daemon, bare loopback, server-rendered

Ratified E-decisions, as built:

- **axum**, sharing the workspace tokio runtime (D11) rather than adding a
  sync HTTP crate and bridge layer.
- **Served from `chaperone serve`**, including a setup-only mode that runs
  just the wizard when required artifacts are missing (a gateway cannot run
  without an audit chain, so first-run cannot be full-broker).
- **~~Bare loopback trust~~ → D41 token gate**: D40's original "no login,
  no token" call was **superseded by D41** after live review: plain TCP on
  127.0.0.1 has no OS-level per-user ACL the way a `0600` UDS does, so any
  local OS account could reach the port. D41 adds a per-instance access
  token; D40's Host/Origin guard stays as defense against a different
  attack (remote browser CSRF/DNS-rebinding). D40's other calls — axum,
  in-daemon, server-rendered, zero JS — are unaffected.
- **Server-rendered HTML/CSS, zero JS build step**: forms POST and
  redirect; no node/npm anywhere near reproducible builds; one hand-rolled,
  tested HTML escaper instead of a template-engine dependency.

## D41 - Per-instance UI access token (supersedes D40's access-control half)

D40 shipped the config UI on bare loopback TCP with "no login, no token."
A live review confirmed the gap this opens: unlike every Unix domain
socket in the system (`0600`, uid-gated by the OS), a plain TCP listener on
127.0.0.1 has **no per-user ACL** — any local OS account can reach the port
and drive the full config surface. The Host/Origin guard stops remote
browser CSRF/DNS-rebinding; it does nothing against a second local account.

**Fix:** a per-instance access token, 32 random bytes (base64url),
persisted at `0600` in the config directory alongside `audit.key`. The
token inherits the directory's existing OS-level owner restriction on all
three platforms — no new platform-specific socket/pipe ACL code. The token
is required before the UI renders or accepts anything beyond the paste
page itself.

- **Generation:** `chaperone ui-token rotate --token <PATH>`; `show`
  prints it and the URL. `serve` **never auto-generates** — it refuses to
  start the UI until the token file exists. A stable URL an operator can
  bookmark matters more than rotation-by-default; `rotate` exists for the
  case that actually calls for it (suspected local compromise).
- **Enforcement:** first load needs `?token=…`; the UI sets a scoped
  `HttpOnly; SameSite=Strict` cookie and 303-redirects to the same path
  with the token stripped. Subsequent requests use the cookie. Any request
  without a valid token or cookie: GET → paste page; non-GET → 403.
  The Host/Origin guard (D40) stays layered underneath: a foreign Host is
  refused even with a valid cookie (the token answers "which local
  account," the guard answers "which origin").
- **Constant-time comparison** so a timing oracle cannot recover the
  token byte by byte.

**Rejected alternatives:** (a) auto-generating the token at serve startup
and printing it — convenient but puts a secret in process stdout/logs, and
means the browser-based wizard would create its own gate (chicken-and-egg).
(b) A transport-level fix (UDS-only UI) — browsers cannot connect to UDS,
so the UI would need a local forwarder, adding a moving part. (c) Per-user
encrypted config (§8.2 backlog) — explicitly not a substitute; an isolated
per-user vault does nothing to stop an unauthenticated local port.

**Backlog (§8.2):** per-user encrypted config for a future native-app UI.
Explicitly deferred; explicitly not a substitute for D41. Needs its own
design pass (one install per OS account vs. shared-daemon multi-tenancy).

---

## D42 — Windows reproducible builds require `/Brepro`

RELEASE.md and BUILDER-NOTES-WINDOWS.md §3 promise SLSA-style verification:
anyone can rebuild from source and get byte-identical bytes. `scripts/repro-check.sh`
enforces this by building twice from clean state and diffing. On the first
Windows hardware pass, two clean `cargo build --release --locked` runs of
identical source produced binaries that differed in 23 bytes: 2 bytes near
the PE header start (the COFF `TimeDateStamp` field), three more 2-byte
pairs 28 bytes apart around a debug directory, and a contiguous ~13-byte
block immediately after (a PDB GUID/hash derived from the timestamp). This
is MSVC's `link.exe` embedding wall-clock time by default — a Windows-only
gap; ELF (Linux) and Mach-O (macOS) outputs from the same source have no
such field and were already reproducible.

**Fix:** `/Brepro`, MSVC's deterministic-linking switch (available since
VS2015 Update 3), zeroes the timestamp and its derived fields instead of
stamping the build clock. Applied via `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/Brepro"]
```

Scoped to the target so it's a no-op on Linux/macOS. Cargo reads
`.cargo/config.toml` automatically — no `release.yml` change needed; CI
picks this up for free. Verified: two clean builds with this flag produce
identical SHA-256 for both `chaperone.exe` and `chaperone-helper.exe`.

**Consequence:** every previously-published Windows binary (v0.1.0-alpha.1,
v0.1.0-alpha.2 — the only two that actually built and shipped) was built
without this flag and is very likely *not* independently reproducible by a
verifier rebuilding from the same tag today, since a rebuild will embed a
different timestamp than whatever CI happened to embed at build time. This
does not affect the hash-manifest or hash-of-download check (§1's weaker
guarantee); it affects only the "rebuild and compare" strongest check. Not
retroactively fixable for already-tagged releases; first release built with
this flag is the first one for which the strongest verification path
actually holds on Windows.

## D43 — Policy correlation: explicit pairs, not capture substitution

Fleet-scale SSH (MVP-GAP-REVIEW P1-2) needs "this credential only against this
endpoint" without N hand-maintained rules. Two candidate mechanisms were
analyzed (`docs/research/p1-2-correlation-analysis.md`): capture substitution
(`cred_ref = "local://ssh/fleet/{host}"` bound to a `target_uri` capture) and
an explicit `[[rule.pair]]` table of (cred_ref, target_uri) rows on a rule.

**Decision (Stephen, 2026-09-30): pairs.** A rule may carry pair rows; the
rule matches when its shared axes match AND the request's (cred_ref,
target_uri) matches a row. Row fields parse with the standard `Matcher` tags
(`glob:`/`prefix:`/`exact:`); bare strings are Exact — rows are literals in
practice, and a deliberate `glob:` in a row is the operator's explicit choice.
Absent pairs, rules behave exactly as before: strictly additive, no migration,
no existing rule changes meaning. Empty `pair = []` is equivalent to absent;
the canonical writer never emits an empty table.

Rationale (full analysis in the decision paper):

1. **Keeps matching first-order.** Substitution composes an agent-controlled
   string (the captured `target_uri` span) into the pattern that selects
   credentials — second-order matching in the codebase whose thesis is the
   confused-deputy problem (THREAT-MODEL §3). The paper's verified example:
   `ssh://{host}.internal` matching `ssh://app-01.attacker.com/.internal`
   captures `app-01.attacker.com/`, slash included (the D17 glob looseness
   compounding with interpolation). Pairs adds correlation with zero new
   trust assumptions.
2. **The permission set is readable, not simulated.** P1-2's security
   complaint was over-permission invisible in rule text; a pairs rule cannot
   over-grant relative to what it says (D3/D17 auditability).
3. **Cheaper half of every pairing:** one slice in `chaperone-policy`; rows
   are B-2 bulk-import's natural output; rows are deleted when B-1 (CA
   minting) supersedes per-host secrets — no language feature to deprecate.
4. **Reversible in the safe direction:** substitution can be added later if
   real fleets demand convention-matching; removing it after shipping would
   be a config-compatibility trap.

Accepted cost: a perfectly regular 300-host fleet carries 300 rows where
substitution gives one line — acceptable because B-2 makes rows
machine-generated and the rows display what a one-liner would hide.

Details pinned by this decision: denials/decisions report the matched pair
index (`DecisionSource::Rule` carries it) for audit and `policy-check`
legibility; pairs are an AND-clause within a rule, not separate rules, so
first-match-wins ordering across rules is unchanged; `effect = "deny"` rules
may carry pairs (deny key A against host B specifically under a broader
allow); limits and notify stay rule-level; one pair list per rule — pairing
other axis combinations is a future decision, not a silent generalization.

Acceptance gate (P1-2's): one rule expresses "each fleet key may be used only
against its own host," and a test proves key A cannot reach host B under it —
plus TOML round-trip stability, default-deny untouched, and `policy-check`
showing the matched pair.

## D44 — Operator-channel Windows parity: one cross-platform facade, owner-only DACL

**Status:** Accepted (2026-10-01, P1-1 item 3). **Fills:** MVP-GAP-REVIEW P1-1
item 3 ("same owner-only discipline the UDS path uses"), supersedes the
S-2 "events feed SKIPPED-WITH-RECORD on Windows" posture and the issue #43
loud-failure stub.

**Decision.** The two operator-facing channels — the read-only events feed
(D35) and the 1:1 confirmation console (D8/D32) — run on ONE code path on
every platform, backed by a new facade in `chaperone-transport`
(`operator_pipe::OperatorListener` / `OperatorStream`, over the maintained
`interprocess` crate): Unix-domain sockets on unix, named pipes on Windows.
The Windows stubs are deleted; `chaperone tail`, `chaperone console`,
`--console-socket`, and `--events-socket` are real on Windows.

**Security posture — stronger than the D13 fallback, deliberately.** The gap
review asked for "the same owner-only discipline the UDS path uses."
`interprocess` exposes `ListenerOptionsExt::security_descriptor`, which wraps
the Win32 SD API safely, so the pipe is created with a protected DACL
(`D:P(A;;GA;;;CO)(A;;GA;;;SY)(A;;GA;;;BA)` — Creator-Owner, SYSTEM, local
Administrators full control; no inheritance, Everyone absent): the exact
named-pipe analogue of the unix `0600`. The workspace `unsafe_code =
"forbid"` is preserved. This *upgrades* the earlier plan of matching the
agent channel's D13 default-DACL posture (creator-token derived, explicit
ACLs deferred to hardening); operator channels now exceed it. Note D13's
agent-channel upgrade remains a separate open hardening item — this decision
does not silently change the agent channel.

**Placement.** All platform-specific pipe mechanics live in the facade, not
in `cfg(windows)` branches scattered through gateway-core/CLI/tests. This is
also a verification strategy: `chaperone-transport` has a tiny dependency
tree and cross-compiles from the Linux dev box (`cargo check/clippy --target
x86_64-pc-windows-msvc`, both green at acceptance), while gateway-core cannot
(aws-lc-rs needs MSVC `lib.exe`). The riskiest code is compiler-proven for
Windows before CI ever sees it; windows-latest CI provides native execution
proof of the whole tree.

**Windows naming.** Operators pass filesystem-style endpoint strings
uniformly. The pipe namespace is machine-wide and pipe names cannot contain
separators, so `operator_pipe::windows_pipe_name` maps an endpoint to a pipe
name by three rules: an explicit `\\.\pipe\<name>` resolves verbatim; a bare
name (no separators) maps to itself (operators wanting a specific namespace
name pass exactly that); and a filesystem path maps to
`<sanitized-basename>-<sha256-16hex-of-the-full-path>`. The hash suffix is
what makes two `...\events.sock` in different directories — e.g. parallel
tests each in their own tempdir — yield DIFFERENT pipe names, so they cannot
collide in the single namespace. (The first cut mapped to the basename alone,
which collided exactly this way and failed the first native Windows CI run of
the un-gated feed tests; the fix is `windows_pipe_name`, unit-tested on Linux
CI because it is deliberately platform-independent.) Live-endpoint probing
preserves the unix posture: bind refuses when a connect succeeds ("a live
feed already owns …"); a stale endpoint is reclaimed (`try_overwrite`), and
client connects retry briefly on `ERROR_PIPE_BUSY` (the agent channel's
existing pattern).

**Test consequences.** S-2's skip list is now empty: `no_secret_leak`
surface 4 (events feed) is mechanically asserted on all three platforms, and
the Windows stub-string test is deleted along with the stub. Feed-observation
tests (`notify_on_use`, `session_events`, `policy_guard` drift) and the
console acceptance tests run on Windows unmodified — console tests moved off
the unix-only `UnixStream::pair()` shortcut onto real `ConsoleHub::spawn`
endpoints, exercising the production bind path on every platform.

**Accepted costs.** `interprocess` + `widestring` dependency trees (flagged
in the PR like the earlier zbus/tree-size disclosure); the console's
timeout-read uses a short nonblocking poll loop (`read_byte_timeout`)
because Windows pipes lack `set_read_timeout` — acceptable for a
human-speed prompt channel, documented on the method.

**Windows I/O deadlock on first native CI run (CH-77, 2026-10-02).** PR #77
is NOT yet merged — release engineering is holding it until the Windows leg
is green. The first native windows-latest run of the un-gated feed/console
tests *hung* (the runner stalled rather than failing cleanly). Diagnosis,
from the vendored `interprocess` 2.4.4 source (not from a Windows box — this
project cannot execute Windows locally, aws-lc-rs needs `lib.exe`):
- Windows pipes reject I/O timeouts outright (`no_timeouts()` →
  "named pipes do not support I/O timeouts"), so `read_byte_timeout`'s
  poll loop is the only bounded-wait mechanism.
- The original loop keyed "no data yet" off `io::ErrorKind::WouldBlock`.
  But `interprocess`'s read path runs errors through `decode_eof`
  (`os/windows/misc.rs`), which remaps ONLY `ERROR_PIPE_NOT_CONNECTED` →
  `BrokenPipe`; it does NOT map `ERROR_NO_DATA` (232). Rust's own mapping
  surfaces a nonblocking empty pipe read as `ERROR_NO_DATA`→`BrokenPipe`,
  never `WouldBlock`. So on Windows the loop's `WouldBlock` arm never fired:
  an empty read fell through to `break Err(e)`, returning immediately.
- Fix: a platform-split `no_data_yet(e)` predicate — `WouldBlock` on unix,
  `WouldBlock` **or raw OS error 232** on Windows — so a no-data read polls
  to the deadline instead of fast-failing, while a genuine
  `ERROR_BROKEN_PIPE` (109) still maps to EOF. The unix branch is
  byte-identical to before (zero risk to the green legs).

**Honest limit of this fix.** The change corrects a *wrong fast-fail* into a
correct bounded wait. Whether it also clears the *hang* depends on whether
the deeper cause is `set_nonblocking(true)` not taking effect on a client
pipe handle (in which case `ReadFile` parks regardless of the predicate).
That branch cannot be distinguished from Linux source-reading alone, so the
PR ships an INSTRUMENT, not just a fix: `bind_connect_roundtrip` now runs its
body on a worker thread under a 20 s watchdog that panics naming the last
phase reached (bind / connect / client-read / client-write / join). A future
Windows deadlock then fails in ≤20 s and points at the exact call, instead of
stalling the runner blind. The watchdog itself is proven to fire by
`watchdog_fires_on_a_hanging_body` (`#[should_panic]`), so it cannot silently
become an inert instrument. `listener_and_client_derive_same_pipe_name` pins
Heph's invariant that bind and connect agree on the pipe name for one
endpoint (a disagreement would deadlock the round-trip).

**CH-77-2 — the ACTUAL Windows hang, and its fix (2026-10-02).** The
attempt-2 read fix above was correct but was not the hang. windows-latest job
111038618704 (run 37067424587) localized it precisely: in
`gateway-core/tests/session_events.rs`, `decision_events_carry_sponsor_id`
and `heartbeat_fires_once_per_window` PASSED (so connect + bounded read work
on Windows), while `client_close_emits_summary_with_stats` and
`ttl_expiry_reaps_with_summary` ran >60 s each and the job was cancelled at
the 6 h limit. The two hang tests are exactly the two where a session CLOSES
(client close, TTL reap) and the gateway broadcasts a `session.summary`.

Root cause — a WRITE-side circular wait on the broker thread, not a read:
`EventHub::broadcast` wrote each line to subscriber sockets INLINE, on the
calling (broker) thread, under the subscribers mutex. The two hang tests
produce TWO feed lines the subscriber has not yet drained (the opener's
`decision`, then the close's `session.summary`) before the client gets to
read. On Windows the pipe output buffer is 512 bytes (`interprocess`
`PipeListenerOptions::output_buffer_size_hint` default; two ~250-byte JSON
lines exceed it), so writing line #2 blocked until the client read line #1 —
but the client reads only AFTER `handle_message(closer)` /
`emit_session_heartbeats()` returns, which cannot return until the write
completes. Circular wait ⇒ hang. Unix hid it: UDS socket buffers (~200 KB)
absorbed both unread lines, so the write never blocked. That is why only
windows-latest hung, and why the operator_pipe read watchdog never fired —
`session_events` stalled the whole test run before that binary's tests ran.

Fix — move feed writes OFF the broker thread entirely:
- `EventHub` is now a queue + a dedicated writer thread. `broadcast` only
  enqueues the line (bounded: `MAX_QUEUED_LINES` = 4096, newest dropped on
  overflow — the feed is a loss-tolerant live tap per D35, the audit chain is
  the evidence of record) and returns WITHOUT touching a socket. No broker
  call can block on a subscriber, so the circular wait is structurally
  impossible, not merely timed-out.
- The writer thread delivers each queued line to every subscriber under a
  bounded deadline (`SUBSCRIBER_WRITE_TIMEOUT` = 2 s) via the new
  `OperatorStream::write_all_timeout` (nonblocking poll loop, mirroring
  `read_byte_timeout`; Windows `no_space_yet` maps ERROR_PIPE_BUSY 231 /
  ERROR_NO_DATA 232 to "retry"). A subscriber that stalls or dies is DROPPED,
  never allowed to wedge delivery to the others — the D35 tap semantics,
  enforced.
- The attempt-2 `no_data_yet` read fix and the operator_pipe round-trip
  watchdog are KEPT (both correct). The watchdog is RELOCATED/DUPLICATED into
  `session_events.rs` (`run_guarded`, all four tests, phase marks at
  build/subscribe/open/command/close/reap/read) so the file that actually
  hung now fails fast and located if it ever regresses;
  `watchdog_fires_on_a_hanging_body` proves that watchdog fires.

Verification (Linux; Windows native is CI's call):
- `events::tests::broadcast_never_blocks_on_a_stalled_subscriber` is the
  regression pin, and it is FALSIFIABLE — proven by temporarily reverting
  `broadcast` to the inline blocking write: the test then FAILED in ~5 s with
  the located message "REGRESSION: broadcast blocked on subscriber socket
  I/O" (it does NOT hang the runner; the flood runs on a worker behind a
  channel `recv_timeout`). The good version was restored and re-verified
  green.
- `events::tests::healthy_subscriber_receives_queued_lines_in_order` proves
  the async hub still delivers in order and completely (the queue did not
  break the one-object-per-line contract).
- `operator_pipe` gains `write_to_stalled_peer_times_out_not_hang` (bounded
  write to a connected non-draining peer — the exact Windows condition) and
  `write_to_draining_peer_succeeds` (positive control).
- `session_events` all four tests run under the watchdog; full workspace 43
  suites green, fmt/clippy(linux + windows facade)/deny all green.

**CH-77-2, second Windows finding — `Ok(0)` is ambiguous on pipes (2026-10-03).**
The first windows-latest run of the async hub (`9ca09d8`) completed in ~2 min
instead of hanging 6 h — the deadlock fix works, and
`broadcast_never_blocks_on_a_stalled_subscriber` passed on Windows. But
`healthy_subscriber_receives_queued_lines_in_order` failed with an instant
`UnexpectedEof`, and (lib-test failure ⇒ cargo aborts) `session_events` never
ran. Mechanism, from `interprocess` source (`os/windows/named_pipe/stream/
impl/recv_bytes.rs` + `os/windows/misc.rs`): EVERY Windows pipe read goes
through `downgrade_eof`, which converts `BrokenPipe`-kind errors into
`Ok(0)` — that covers both NOWAIT "no data yet" (`ERROR_NO_DATA` 232) and a
real disconnect (`ERROR_PIPE_NOT_CONNECTED` 233). So attempt 2's
`no_data_yet(232)` Err-arm never fires on Windows reads (the error never
surfaces as `Err` — it is downgraded first), and the old `Ok(0) ⇒ EOF`
reading made any client that raced the writer thread see an instant EOF.
Fix: platform-split `zero_read_is_eof()` — true on unix (`Ok(0)` IS the peer
closing; no-data is `Err(WouldBlock)`, distinct), false on Windows (`Ok(0)`
polls to the deadline, then `TimedOut`). Accepted cost on Windows: a
genuinely disconnected peer costs the read timeout instead of an instant EOF
— bounded and acceptable for tap readers; the console answer path uses the
BLOCKING `read_byte` (never nonblocking), so its fail-closed EOF semantics
are untouched. Why attempt 2 masked this: with inline broadcast the line was
always already in the pipe buffer before the client read, so the no-data
race never occurred; the async writer thread made the race observable —
which is exactly what a positive-control test is for. This failure was caught
by Windows CI in 2 minutes, not by a 6-hour hang: the fast-fail instrumentation
is doing its job.

**CH-77-2, third Windows finding — NOWAIT writes silently don't deliver;
final design is per-subscriber threads with BLOCKING writes (2026-10-03).**
With the `Ok(0)` read fix in place, windows-latest run 2 changed the failure
from instant `UnexpectedEof` to `TimedOut` after the full 5s deadline: the
read side now polls correctly, but the data NEVER ARRIVES. The single-writer
hub delivered via `OperatorStream::write_all_timeout`, which flips the pipe
to `PIPE_NOWAIT` and relies on `interprocess`'s NOWAIT write + flush
semantics. Empirical conclusion from run 2: that path reports success but
does not commit bytes to a healthy subscriber (the exact Win32 behavior of
NOWAIT writes + `FlushFileBuffers` through this abstraction is not something
to keep guessing at — this was the third Windows-pipe guess, and guessing
is what burned the previous two CI cycles).

Final design — remove the guess entirely:
- **Per-subscriber delivery threads.** Each accepted subscriber gets a
  `sync_channel(256)` and a dedicated thread doing conventional BLOCKING
  `write_all` — the one write path empirically proven on Windows (the
  pre-fix inline hub delivered single lines fine; `bind_connect_roundtrip`'s
  blocking writes pass on windows-latest). No `PIPE_NOWAIT` is ever set on
  a write-side handle anywhere. `write_all_timeout` and its `no_space_yet`
  helper are DELETED, along with their two transport tests (a pointer note
  remains in `operator_pipe.rs` tests so the coverage isn't silently lost).
- **`broadcast` does `try_send` only** — never touches a socket, never
  blocks, so the CH-77-2 circular-wait deadlock remains structurally
  impossible. A subscriber whose bounded queue is full (stalled observer) or
  whose thread died is pruned from the registry on the spot (D35 drop
  semantics). A parked blocking write on a wedged peer is isolated to that
  subscriber's own thread: it affects neither the broker nor other
  subscribers, and exits when the peer closes or the channel disconnects.
- **Read side unchanged from the run-2 fix**: `zero_read_is_eof()`
  platform split stands (`Ok(0)` = EOF on unix, ambiguous-and-poll on
  Windows).
- The regression pin (`broadcast_never_blocks_on_a_stalled_subscriber`,
  proven falsifiable by an actual revert experiment) and the positive
  control (`healthy_subscriber_receives_queued_lines_in_order` — the test
  that caught BOTH run-1 and run-2 failures) move unchanged onto the new
  hub shape; they pin hub-level properties, not the removed primitive.

Process note, recorded honestly: three Windows-pipe behaviors were guessed
from Linux source-reading across CH-77/CH-77-2 (`WouldBlock` mapping,
`ERROR_NO_DATA` surfacing, NOWAIT write delivery). Guesses 1–2 were wrong in
ways CI exposed in minutes; guess 3 is now deleted rather than fixed, in
favor of the one behavior with empirical Windows evidence. The lesson for
this codebase: on Windows pipe I/O, prefer the boring blocking path with
thread isolation over clever nonblocking modes through an abstraction
layer; require native-CI evidence before trusting any NOWAIT semantics.

**CH-77-2 run 3 (job 111187240294) — the design is PROVEN on Windows; the
last failure was a test artifact (2026-10-03).** The per-subscriber
blocking-write hub ran green on windows-latest where it matters: ALL
production-shaped tests passed — `session_events` 5/5 (including both
original hang tests `client_close_emits_summary_with_stats` and
`ttl_expiry_reaps_with_summary`), `console` 4/4, `no_secret_leak` surface 4
3/3, `notify_on_use` 3/3, both hub tests (stall-pin + positive control),
`policy_guard` drift. The CH-77-2 acceptance criterion (the originally
hanging tests complete on Windows) was MET. The single red was the synthetic
`bind_connect_roundtrip`, and the watchdog located it precisely:
- Real error (previously hidden): `write_all(b"ack\\n")` after a
  `read_byte_timeout` on the same handle → `Os { code: 232, kind:
  BrokenPipe, "The pipe is being closed." }` then an indefinite stall.
  Empirical finding: **on Windows, mixing a NOWAIT-toggled read with a
  subsequent write on the same pipe handle is broken** — the NOWAIT mode
  change and/or its restore leaves the handle in a state where the next
  blocking write fails with 232 or wedges. No production path does this:
  feed clients are read-only (D35), console clients use blocking
  `read_byte` in both directions (their tests pass on Windows).
  `read_byte_timeout` stays exactly where it is safe: read-only handles,
  all of them Windows-green.
- Test fixed to the production pattern: blocking reads on both sides (same
  shape as the passing console tests). The NOWAIT-read-then-write mix is
  removed from the suite — documented here and in the test so the hazard is
  recorded, not silently dropped.
- Second lesson, fixed in the harness: run 3 reported the failure as
  "HANG at phase client-write" after the full 20 s because the transport
  `with_watchdog` lacked the Done-Drop-guard — a worker PANIC never set the
  done flag, so the watchdog mislabeled it a hang and delayed the run.
  `with_watchdog` now matches `run_guarded` (Drop-guard +
  `resume_unwind`): panics propagate verbatim immediately; only a true
  stall gets the HANG label. The `watchdog_fires_on_a_hanging_body`
  self-test still proves the hang path.





---

## D45 — Operator decision preview: one engine, one vocabulary, one caveat rule

**Status:** decided (ox-chap, implementing P2-2; rulings 1-5 by Heph
2026-10-03). Closes MVP-GAP-REVIEW P2-2.

### The problem

Four independent glob matchers with no feedback on what the result permits is
an expert interface. The gap review's framing is the governing one: **a security
control wearing a UX costume.** The operator most likely to write an
over-permissive rule is the one least likely to read `matcher.rs`'s header note
that `*` spans `/` and `:`.

### Three decisions, each with its alternative recorded

**1. The preview describes the PARSED rule, never the raw form strings.**
`preview::candidate_rule` performs the same construction `rules_add` performs —
empty axis coerces to `Matcher::Any`, `glob:`/`prefix:`/`exact:` tags parse
through `Matcher::parse`. *Alternative considered:* render the form fields
verbatim (one line of code, guaranteed to drift). Rejected: the preview would
describe a rule the validator would not produce, which is worse than no preview
at all.

**2. `Matcher::Any` renders as "any value", never as the literal `*`.** The
pre-existing `axis_text` helper in `pages.rs` rendered `Any` as `"*"`, which is
indistinguishable on screen from a glob of `*` — while `Any` is strictly *wider*.
An operator who cannot tell them apart is being told their rule is narrower than
it is. `Matcher::describe` is display-only and its output is deliberately not
re-parseable, pinned by
`describe_is_display_only_and_never_round_trips_into_a_decision`.

**3. `DecisionSource::label` is shared, not copied.** The CLI's `policy-check`,
the gateway's deny reason, and the UI's test box all render provenance. There
were three hand-rolled formatters before this decision; two are gone. The
gateway keeps its own phrasing (`denied by rule[0] (name)`, `default-deny`)
because its text is operator- and log-visible — the exact strings are pinned by
`deny_reason_text_is_unchanged`. The shared piece is the provenance itself.
*Alternative considered:* copy the CLI's formatter into the UI (narrower public
API). Rejected per Heph's ruling: it makes the parity test-enforced rather than
structural, which is the divergence D36 exists to prevent.

### The caveat predicate (Heph's ruling, applied literally)

Fires only when a `target_uri` or `cred_ref` axis is a `Matcher::Glob` that
actually contains `*`, AND the pattern has `*` adjacent to `.` or `/` in a
dangerous position:

- `*.` — star before dot. The hostname-boundary bypass named in `matcher.rs`'s
  own SECURITY NOTE: `ssh://*.internal` also matches `ssh://evil.com/.internal`.
- `*/` — star spanning into a path.
- **Does NOT fire on a trailing `/*`.** `vault://prod/*` is a legitimate open
  tail; caveat-ing it puts the warning on every fleet rule and trains operators
  to dismiss it — the exact failure the caveat exists to prevent.

Mechanical, no regex, both directions pinned by
`caveat_fires_only_on_dangerous_star_positions`.

### Non-goals, recorded so they are not re-litigated

No JS (D40 holds). No reimplementation of evaluation: the test box calls
`Policy::evaluate`, the same function the gateway calls. No shell-out to the CLI.
No change to `evaluate`, to the axes, to the effect trichotomy, or to the TOML
schema. The preview is labelled "not saved yet" so it can never be mistaken for
current state — over-labelling was preferred to under-labelling.

---

## D46 — "Connect a service": one submit, four artifacts, rule last

**Status:** decided (ox-chap, implementing P2-1). Plan
`docs/plans/P2-1-P2-2-PLAN.md` §4; rulings 1-5 by Heph 2026-10-03. Closes
MVP-GAP-REVIEW P2-1.

### What it is

The artifact-shaped wizard walks artifacts (enrollment, policy, audit key,
vault); the operator's actual sentence is one line. "Connect a service" is
organised around that sentence and produces a rule, a vault entry, an enrolled
identity, and a runnable test command in one submit. **Composition, not new
capability** — every primitive already existed behind `/secrets/store`,
`/agents/enroll`, `/setup/audit-key`, and `/rules/add`.

### Decision 1: Option A — the vault must already exist

**Ruled by Stephen, 2026-10-03.** The flow refuses cleanly when no vault is
open and points at the wizard; it never creates one implicitly.

*Why:* it keeps the flow's secret surface to exactly ONE pasted value. Option B
(passphrase field in the same form) is a nicer one-submit experience but puts two
secrets in one form; option C (auto-create) opens a plaintext window and is not
an option at all. Acceptance is unaffected: the wizard is UI, not CLI, so
"daemon -> brokered audited action with no CLI command" still holds.

### Decision 2: rule last (Heph, ruling 3) — and a bug the test found

Validate all four artifacts in memory, write **vault -> enrollment -> audit key
-> rule**. The rule is the only artifact whose presence turns the grant *on*;
everything before it is inert scaffolding under default-deny and over-permits
nothing.

**Heph's correction to my original framing is recorded rather than dropped:** I
described the bad residue as "deny-all". It is not — it is *an allow rule with a
dangling `cred_ref`*: policy says allow, and it fails only at action time on a
vault miss. The conclusion was right; the description was wrong.

**The acceptance test found a real bug while being built.** The partial-failure
test (rule-last residue) was written twice:

1. *First attempt* induced the failure by making the config directory read-only
   and asserted no rule exists. It passed — **and passed even when the rule was
   deliberately reordered to be written FIRST.** The assertion was vacuous: the
   vault is held in memory and does not touch the directory at `set()` time, so
   the induced "failure" never happened and no mid-flow error ever occurred.
2. *Second attempt* induces a failure that is real: a **directory squatting on
   the audit-key path**, which sits between the vault entry and the rule.
   `atomic_write` cannot persist onto a directory, so the write fails with every
   earlier step already succeeded — precisely the window the ordering protects.

That second version **failed immediately against correct-looking code**, and the
cause was a genuine defect: the guard was `if !state.audit_key_path.exists()`.
`Path::exists()` is true for a directory, so a directory on that path made the
flow skip the audit key and write the rule anyway — producing exactly the
misleading residue ruling 3 exists to prevent. Fixed to `is_file()`.

Re-verified after the fix by re-running the reorder experiment: with the rule
written first, the test now **fails** with `rule-last ordering violated: 1
rule(s) exist`. The pin is falsifiable in the direction that matters.

### Non-goals, recorded so they are not re-litigated

No JS (D40). No "simple mode" writing rules the CLI would refuse (D36). The
policy is rebuilt and re-validated through `Policy::from_rules(...).to_toml()` and
re-parsed with `Policy::from_toml` **exactly as `rules_add` does**, so this flow
is not a fifth writer. The existing artifact-shaped wizard is never removed.
`CONNECTIVITY-MATRIX.md` untouched.

---

## D47 — B-4: the audit/error path is secret-free BY CONSTRUCTION

**Status:** decided (ox-chap, implementing B-4 = S-3 option 2). Closes the
MVP-GAP-REVIEW B-4 item, deferred by Stephen 2026-09-28 with the gating note
"likely required BEFORE SafeKeyPass ships."

### The distinction this draws

S-3 option 1 (shipped, holds the line) is: a **normative sentence** plus a
sentinel test against a hostile reflecting target. That proves the property
*holds today* for the strings the test exercises.

B-4 makes it a **type fact**. The claim becomes "the audit/error path cannot
carry free-form text" rather than "the audit/error path does not currently carry
free-form text." Same philosophy as the licensing design's structural
non-enforcement: *no `disable()` exists to call.*

### What changed

`InjectorError::Transport(String)` → `InjectorError::Transport(TransportError)`.

`TransportError` is a closed enum with **no payload**: `ConnectionRefused`,
`Timeout`, `TlsFailure`, `DnsFailure`, `BodyReadFailed`, `RequestBuildFailed`,
`AuditAppendFailed`. `detail()` is a `const fn` returning `&'static str`, so
there is no API for attaching caller text to it.

`TransportError::classify(&reqwest::Error)` maps a client error to a class by
reading only the error's **kind predicates** (`is_timeout`, `is_connect`,
`is_body`, ...) — never its message, because the message is where URLs and other
target-influenced text live.

### What was deleted, and why that matters

`redacted_error` — the runtime word filter that stripped anything URL-shaped
from transport error text — is **removed**, along with its unit test. It is
dead code now: there is no string left for it to filter. Leaving a
belt-and-braces filter in place after the belt became the whole belt would invite
the belief that the string path still exists.

### The compile-fail evidence

B-4's guarantee is not expressible as a runtime assertion, so it is verified by
attempting the violation:

```rust
InjectorError::Transport("reflected-secret-value-from-response-body")
// error[E0308]: expected `TransportError`, found `&str`
```

Run during implementation, output recorded in
`error_classes_are_closed_and_render_static_text` and in the PR. A future
contributor who tries to widen the variant back to a string is stopped by the
compiler, not by a failing test.

### Two judgement calls

**1. `AuditEvent` was left alone — deliberately.** Its structural property is
already intact: every field is a `&'a str`, a reference-shaped `String`, or the
signed `intent_envelope`. There is no field that can carry resolved credential
material or response bytes, and `append()` accepts nothing of the sort. B-4's
real gap was the *error* path, not the audit record. Changing `AuditEvent`
would have been refactoring for its own sake.

**2. A new variant was added after the first cut got it wrong.** The gateway's
startup audit-append failure was initially mapped to `BodyReadFailed` — it
compiled, it was locally plausible, and it was operator-misleading:
"response body unreadable" describes an outbound read, not a failed genesis
write. `AuditAppendFailed` was added so each class names what actually happened.
Recorded because a classified vocabulary is only worth having if every class is
*true*; a plausible-but-wrong class is worse than a free-form string, because it
looks authoritative.

### Non-goals

No change to `AuditEvent`, to `Outcome`, to the scrub in the relay path (P0-1
still does real work there), or to `no_secret_leak`'s observable assertions. No
new secret surface. `SafeKeyPass` remains the consumer this unblocks.
