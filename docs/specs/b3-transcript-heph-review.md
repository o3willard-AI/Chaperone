# B-3 `serve --transcript` — Heph review

Verified against the code, not the prose: the audit crate's Ed25519 signing
identity (`crates/audit/src/keys.rs`: `SigningKey`/`verifying_key`), the
hash-chained record format (`writer.rs` + `verify.rs::verify_file(path, vk)`),
the serve framing loop (`crates/cli/src/main.rs:1400` — the `Handler` closure
where `request.value()` and `request.reply()` bracket the raw framed bytes),
and `Request::value()`/`reply()` (`transport/src/message.rs:39/54`). Every code
claim checks out.

## Rulings

**1 — TD-2 key choice: audit key. AGREE as written.** A dedicated transcript
key doubles the operator's key ceremony for zero trust benefit — the operator
holds both keys, so there is no separation-of-duties gain. The genesis binding
(audit head hash + audit public key) already ties the transcript to the audited
run; the prospect verifies against the one key already published.

**2 — TD-4 unterminated semantics: warning, not failure. AGREE as written.**
The hash chain is the integrity anchor; the `transcript_end` record is a
convenience marker (frame count, end timestamp, final hash). A crashed run's
chain verifies up to the last record. Marking it a failure would falsely call a
genuinely-crashed run "tampered"; `unterminated` as a warning is the honest
signal.

**3 — TD-5 self-produced-evidence caveat: ADD the genesis field.** This
artifact exists for a prospect's evaluation, so its honesty limits must be
self-describing, not only documented in the threat model. Add a genesis body
field — `evidence_class: "self-produced"` plus a one-line clause ("signed by
the operator's audit key; not third-party notarized; trust rests on operator
key custody"). The artifact must say what it is, on the artifact.

**4 — TD-4 byte-stability scope: frame payloads only. AGREE as written.**
Whole-journal determinism would require fixing the signing key, genesis
timestamp, and audit head hash — heavy injection for a property the prospect
does not care about. The frame payload sequence (direction, order, `frame_b64`)
is the recording; the chain hashes are per-run integrity metadata that should
differ.

## Sequencing

**Revocation live-E2E fast-follow FIRST, then B-3.** Both are independent, but
the revocation E2E is smaller and closes an agreed honesty gap rather than
opening a new feature. Fold this into the spec's sequencing section as a
decision, not a parenthetical.
