# B-3 — `serve --transcript`: the enterprise evaluation artifact

**Author:** ox-chap (Hermes, host 192.168.101.11)
**Date:** 2026-10-07
**Status:** RULED by Stephen 2026-10-07 — fold rulings into the implementation
**Work order:** `~/workspace/tasks/wi-B-3.md`; backlog item B-3
(MVP-GAP-REVIEW.md §711) ← P0-2 layer 3 (§233)
**Registry note:** D45–D47 and CA-1 live in MVP-GAP-REVIEW.md, not
DESIGN-DECISIONS.md (Heph F3 discipline from B-2).

---

## 0. What B-3 is, in one paragraph

`serve --transcript <path>` writes **exactly what the agent saw** — the
plaintext JSON messages exchanged on the gateway channel, framed verbatim —
as a **signed artifact** alongside the audit chain. A prospect runs their own
workload and inspects the recording afterward, instead of trusting our demo.
It is the enterprise form of the two-pane demo (P0-2 layer 2) and adds **no
new capability**: the channel is already plaintext JSON with `Content-Length`
framing (01-PROTOCOL-SPEC §3, 01-protocol-spec.md:79), so the transcript is a
*recording*, not a feature.

---

## TD-1 — What "exactly what the agent saw" captures

**Recommendation: capture the wire-level frames, both directions, verbatim.**

The recording unit is the **framed byte block**: the `Content-Length: N\r\n\r\n`
header line plus the exact `N` bytes of UTF-8 JSON, for every request the
agent sent and every response the gateway returned. Rationale:

- The work order says "exactly what the agent saw." What the agent *saw* is
  the framed stream; re-serializing the JSON (pretty-printing, reordering
  keys) would produce a *different artifact* than what crossed the wire and
  would undermine the "byte-stable for a deterministic workload" acceptance
  (any `HashMap` iteration or timestamp field would wobble).
- Byte-verbatim capture makes the transcript **replayable** against a future
  gateway: a replay tool can feed the recorded request frames back through
  the framing parser with zero transformation.
- `Request::value()` (`transport/src/message.rs:39`) parses the frame; the
  capture point sits *beside* it (see TD-4), not inside it, so the transcript
  records bytes the gateway never parsed. No trust decision depends on the
  transcript, so recording unparsed bytes is safe.

**Deliberately omitted (mirror the B-2 rule: paths/stats, never secrets):**

| Omitted | Why |
|---|---|
| Vault secrets, minted certs, CA material | The gateway never puts them in channel messages (the `no_secret_leak` suite asserts this per surface); the transcript records the channel, so it inherits the property — but TD-3 adds an explicit sweep. |
| The audit key, the transcript signing key | Never agent-visible. |
| OS socket peer metadata | Not agent-visible data. |
| Anything the *response relay* fetched from the target beyond what the response frame itself carries | The response frame is what the agent saw; the injector's own wire traffic to the target is a different channel and is already covered by the audit chain's relay records. |

**What about timestamps the gateway stamps?** `Request::reply()`
(`message.rs:54`) stamps an echo. The transcript records the frame *as
returned*, stamp included — it is what the agent saw. Determinism is handled
in TD-4 (two-pass framing: recorded in order, but the acceptance test uses a
fixed-clock workload).

**Alternative considered:** capture only the *parsed* JSON messages (semantic
log). Rejected — it is a different artifact than what crossed the wire,
loses byte-stability, and duplicates what the audit chain already records
semantically. The transcript's value is *exactness*.

---

## TD-2 — The signed-artifact format

**Recommendation: reuse the audit chain's exact record format — hash-chained,
every record Ed25519-signed by the audit key — as a *separate journal file*
(`transcript.jsonl`), with a genesis record binding it to the run.**

The audit crate (`crates/audit/`) already implements precisely the machinery
B-3 needs and it is verified offline today (`verify.rs::verify_file(path, vk)`
→ `Report`): canonical JCS body, `this_hash = SHA-256(prev_hash_raw || body)`,
prev-hash chaining from a zero genesis, every record Ed25519-signed
(`writer.rs:7–13`). Rebuilding any of that for the transcript would be
duplicating a security-critical primitive; reusing it means the transcript is
verified by the **same offline tool path** the audit chain already has.

- **Key choice:** the **audit key** (D45-adjacent: the audit key already
  signs the chain; the transcript is a chain-shaped artifact of the same
  run). A separate transcript key would double the operator's key ceremony
  for no trust benefit — the prospect verifies against the audit public key
  they already publish. **Alternative:** hash-only (no signatures). Rejected:
  the work order says *signed artifact*; hash-only proves integrity
  post-hoc but not origin, and the chain machinery is already there.
- **Format:** `transcript.jsonl`, one audit-record-shaped line per *frame
  pair*? No — one record per **frame** (request and response are separate
  records), body carrying: `kind` (`"transcript_frame"`), `direction`
  (`request`/`response`), `content_length`, `frame_b64` (the verbatim bytes,
  base64-encoded so JSONL stays line-safe), `seq`. The frame bytes are the
  *payload*, the chain covers them exactly like any record body.
- **Genesis binding:** the transcript's genesis record carries, in its body:
  the audit journal's **current head hash** at serve start, the audit
  public key, the gateway's protocol version, the transcript start timestamp, and an
  `evidence_class` field set to `"self-produced"` with a one-line honesty
  clause ("signed by the operator's audit key; not third-party notarized;
  trust rests on operator key custody"). This is the cross-artifact link: a prospect can confirm the
  transcript they are holding was recorded by the same run that produced
  the audit chain they are also holding.
- **Offline re-verification:** the existing `chaperone audit-verify` (or its
  library path `verify_file`) gains a transcript mode — same verifier, plus
  one extra check that the genesis body's `audit_head_hash` exists in the
  companion audit journal. No new crypto code. A prospect with the two files
  and the published audit public key re-verifies both offline.

**Alternative considered:** a single-file bundle (transcript + audit tail +
signature manifest, e.g. a tar/zip). Rejected for v1: two plain JSONL files
that the existing verifier already handles beat a new container format with
its own parser and its own attack surface. (A bundle can be added later
without breaking anything — the chain format is stable.)

---

## TD-3 — The no-secret property

**Recommendation: three layers, with the `no_secret_leak` suite extended as
P0-2 layer 3 says it should be.**

1. **Inheritance by construction.** The transcript records the agent
   channel; the gateway never places secrets in channel messages — that is
   the property the existing `no_secret_leak` suite asserts per surface
   (response frames, audit journal, error paths). The transcript is a new
   *surface* over the same data, so the suite is the right place to assert
   it, exactly as P0-2 layer 3 (MVP-GAP-REVIEW.md:237–239) anticipated:
   *"(1) should assert it over the transcript too, once it exists."*
2. **The new test.** Extend `no_secret_leak.rs` with
   `transcript_carries_no_secret_text`: run the existing spine (which
   already exercises bearer/basic http-broker flows with sentinel secrets
   and a seeded vault) with `--transcript` enabled; after the workload,
   read `transcript.jsonl` and assert the sentinel secret text, the vault
   entry value, and any cert marker appear **nowhere** — including inside
   the base64 frame payloads (the assertion decodes each record's
   `frame_b64` before scanning, so base64 is not a hiding place). Also
   assert the positive control: the frames DO carry the agent-visible
   request/response (e.g. the intent's `msg_id`), so the test cannot pass
   vacuously on an empty transcript.
   **Revert that breaks it:** remove the sweep at the capture point (or
   place a secret into a response frame by reverting the P0-1 scrub) → the
   sentinel appears in a decoded frame → FAIL.
3. **The belt-and-braces sweep at capture time is deliberately NOT a
   filter.** Following the B-4 discipline (D47: prefer structure over
   filters, "no disable() exists to call"): the transcript does not scrub
   frames, because the frames are by construction secret-free — the
   *gateway* is the thing that must not put secrets on the channel, and
   that is enforced upstream (P0-1) and asserted by the suite. A scrubber
   on the transcript would imply the channel may carry secrets and the
   transcript cleans them — the exact inversion of the claim we make. The
   test exists to catch a regression of the upstream property, not to
   clean up after one.

**Alternative considered:** a redaction pass over recorded frames with a
"redacted" marker. Rejected: it breaks byte-verbatim capture (TD-1), breaks
replay, and — worse — the recorded artifact would no longer be *what the
agent saw*, which is the entire product claim of B-3.

---

## TD-4 — Command shape + storage

**Recommendation: a streaming sidecar, written live, finalized on shutdown.**

`serve --transcript <path>` opens the transcript journal at startup (after
the audit chain is open; the genesis records the audit head hash) and appends
one chain record per frame as frames cross the channel. On graceful shutdown
(SIGINT/SIGTERM or socket close-after-drain), the writer appends a
**`transcript_end` record** (body: end timestamp, frame count, final chain
hash) and closes. A crashed run leaves a transcript without the end record —
`audit-verify --transcript` reports `unterminated` as a *warning*, not a
failure (the chain itself is still verifiable up to the last record; the
end record is a convenience marker, not an integrity anchor).

- **Capture point:** in `serve`'s framing loop
  (`crates/cli/src/main.rs:1405–1409`), where the raw framed request bytes
  are available before `Request` parsing and the response value is
  available before `reply()` serializes it. The transcript writer hangs off
  this point; `handle_message` is untouched. The gateway core gains no
  transcript knowledge — the transcript is a serve-layer (operator-tool)
  concern, matching how the UI and audit-key loading are already
  serve-layer concerns.
- **One-shot vs stream vs replay-server:** a **stream** (live append), not a
  one-shot dump (a dump needs the whole session buffered in memory and is
  useless if the process dies) and not a replay-server (a different product;
  replay can be a later tool that reads the recording — nothing in the
  format blocks it).
- **Rotation:** the transcript journal is per-serve-run, one file per run —
  it does NOT rotate with the audit journal. Rationale: the transcript is
  the recording of *this* evaluation run; the audit chain is the long-lived
  evidence stream with its own rotation rules. The genesis binding (TD-2)
  ties the two artifacts together per-run; rotating the audit chain
  mid-run does not affect an already-open transcript (its records chain
  among themselves; only the genesis carries the audit-head link).
- **CLI surface:** `serve --transcript <path>`; absent flag = no transcript
  (zero behavior change for every existing user). If the transcript path
  exists at startup: **fail closed** (refuse to start, "transcript file
  exists; move it first") — appending to an old recording would forge a
  chain across two runs.

**Alternative considered:** `--transcript` writing into the audit journal
itself (frames as audit events). Rejected: it would double journal size for
every production run whether or not an evaluation is happening, and it
conflates the operator-evidence stream with the evaluation artifact.

---

## TD-5 — Threat model

**What the transcript proves:**

1. The gateway returned *these exact bytes* to the agent channel, in this
   order, under this policy load — signed by the audit key, hash-chained, so
   post-hoc tampering of the recording is detected.
2. The frames are consistent with the audit chain of the same run (genesis
   binding): the prospect can cross-check that decisions recorded in the
   audit chain correspond to the frames the agent saw.
3. The no-secret property held on this run's channel (asserted by the suite;
   the transcript is the artifact a prospect can scan themselves).

**What the transcript does NOT prove:**

1. **What the target did.** The transcript is a recording of what the agent
   *saw* — the response frame the gateway relayed, not what the target
   service actually processed or returned upstream of the injector. The
   injector's target-side traffic is evidenced (coarsely) by the audit
   chain's relay records, not by the transcript. An enterprise reader must
   not read "the transcript shows the API returned X" as "the API returned
   X" — it shows *the agent received X*.
2. **That the agent sent nothing else.** Off-channel activity (the agent
   talking to the target directly, bypassing the gateway) is invisible here.
3. **Policy correctness.** The transcript shows frames; whether the policy
   that permitted them was right is the audit chain + policy review's
   question.
4. **Absence of secrets by itself.** The transcript being clean *on this
   run* is a property asserted by the suite per-run, not a structural
   guarantee that no future channel change could carry one (the structural
   claim lives in the audit/error-path design, D47).

**Must never contain:** vault secrets, minted certificates or CA material,
the audit or transcript signing keys, or any payload the gateway did not
actually place on the agent channel. The suite (TD-3) enforces the first and
last of these per-run.

**Adversarial framing:** the transcript is operator-generated evidence about
the gateway, produced by the gateway's own operator. It is *not* notarized
by a third party, and it is signed by the same key whose public half the
operator publishes. Its honesty claim rests on the operator's audit-key
custody — the same basis as the audit chain itself, and the same basis every
Chaperone evidence artifact rests on. It strengthens the enterprise story
(demonstrable, verifiable, self-produced evidence of the no-secret claim)
without pretending to be independent attestation.

---

## Acceptance tests

1. **Offline re-verification (a).** Run the spine with `--transcript`; stop;
   verify `transcript.jsonl` with the audit verifier: chain checks pass,
   every record's signature verifies against the audit public key, and the
   genesis `audit_head_hash` resolves inside the companion audit journal.
   **Revert that breaks it:** sign records with a different key, or break
   the genesis binding → verifier FAIL.
2. **No-secret over the transcript (b).** `transcript_carries_no_secret_text`
   in `no_secret_leak.rs` (TD-3): sentinel secret / vault value / cert
   markers absent from the raw JSONL **and** from every decoded
   `frame_b64` payload, with the positive control (frames carry the intent
   `msg_id`) guarding against a vacuous pass.
   **Revert that breaks it:** reintroduce the P0-1 scrub regression (a
   secret into a response frame) → the sentinel appears in a decoded frame
   → FAIL.
3. **Byte-stability (c).** Two identical runs of a deterministic workload
   (fixed clock injected at the spine, same intents) produce transcript
   journals whose *frame payloads* (`frame_b64` sequence, direction, order)
   are identical. (Chain hashes/timestamps differ by construction — the
   assertion is on the frame sequence, which is the recording.)
   **Revert that breaks it:** re-serializing frames instead of recording
   bytes (key order/timestamp wobble) → frame payloads differ → FAIL.
4. **Fail-closed path collision.** `serve --transcript <existing-file>`
   refuses to start with exit 2 and a clear message; the existing file is
   untouched. **Revert:** append-across-runs → chain spans two runs →
   verifier FAIL.
5. **Absent flag = zero behavior change.** The existing `serve` test suite
   passes unchanged without the flag (regression guard).

---

## Sizing + sequencing

| Slice | Work | Estimate |
|---|---|---|
| 1 | Transcript writer over the audit crate (chain reuse, genesis binding, end record) + unit tests | 1–1.5d |
| 2 | Serve capture point + `--transcript` flag + fail-closed path check | 0.5–1d |
| 3 | `no_secret_leak` extension + E2E verify test + byte-stability test | 1–1.5d |
| 4 | `audit-verify --transcript` mode (genesis cross-check) + docs (threat-model delta, CONNECTIVITY-MATRIX line) | 0.5–1d |

**Total: ~3–5 days.**

**Sequencing (RULED 2026-10-07): revocation live-E2E fast-follow FIRST, then B-3.**
Independent artifacts, but the revocation E2E is smaller and closes an agreed
honesty gap rather than opening a new feature.

---

## Rulings — Stephen 2026-10-07

1. **TD-2 key choice:** audit key (as written).
2. **TD-4 unterminated semantics:** warning, not failure (as written).
3. **TD-5 self-produced-evidence caveat:** ADD the genesis body field —
   `evidence_class: "self-produced"` with a one-line clause ("signed by the
   operator's audit key; not third-party notarized; trust rests on operator
   key custody").
4. **Byte-stability scope:** frame payloads only (as written).

**Sequencing:** revocation live-E2E fast-follow FIRST, then B-3.
