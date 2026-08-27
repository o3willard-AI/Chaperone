# Chaperone — Spec Issues & Discrepancies

Found while reading the four artifacts per Brief §2 ("if you find a discrepancy,
note it as an issue rather than silently picking one"). The Protocol Spec governs;
these are questions for the spec authors, plus the assumptions we adopt until
ruled otherwise. Each item becomes a GitHub issue when tracking is available.

| ID | Severity | Where | Summary | Status |
|---|---|---|---|---|
| SI-1 | Editorial | 04-agent-skill.md, docs/README.md, IMPLEMENTATION_AGENT_BRIEF.md | Broken skill-path references (resolved to `skill/…` relative to `docs/`) | Resolved |
| SI-2 | Clarification | PROTO-SPEC §7 / intent-catalog | `http-basic` operation body never specified | Open |
| SI-3 | Assumption | PROTO-SPEC §8 | Verification order/replay rules not restated for session frames | Open |
| SI-4 | Editorial | THREAT-MODEL §2 | Adversary numbering skips T5 in §2.x (covered in §3) | Open |
| SI-5 | Editorial | SKILL.md vs PROTO-SPEC §5/§7.1 | Worked-example bodies differ between artifacts | Open |
| SI-6 | Clarification | PROTO-SPEC §5.1 | `cred_ref` "omitted only for mechanisms that carry it in the body" — no such v1 mechanism exists | Open |
| SI-7 | Clarification | PROTO-SPEC §10.2 | Gateway behavior on *higher* MINOR than implemented is unstated | Open |
| SI-8 | Clarification | ARCH-SPEC §2.6 | "Operator channel" referenced but never defined | Open |

---

## SI-1 — Broken skill-path references

`docs/04-agent-skill.md` linked `[skill/SKILL.md](skill/SKILL.md)` and
`[skill/references/intent-catalog.md](skill/references/intent-catalog.md)`;
`docs/README.md` said "Source under [`skill/`](skill/)"; the brief likewise
referenced `skill/chaperone.skill`. From `docs/`, `skill/` correctly resolves to
`docs/skill/` (`SKILL.md`, `references/intent-catalog.md`, `chaperone.skill`
zip). **Fixed:** all references updated to use `skill/…` relative to `docs/`.

**Impact on implementation:** none; documentation hygiene only.

## SI-2 — `http-basic` has no defined operation body

PROTO-SPEC §7.1 specifies only `http-bearer`; the intent-catalog lists both
mechanisms against one body (`method`/`headers`/`body_b64`). Basic auth needs a
*username* in addition to the secret — where does it come from?

**Assumption until ruled otherwise:** identical body to `http-bearer` plus an
optional, non-secret `username` field inside `operation` (signed like everything
else); when absent, the gateway derives the username from vault metadata if the
backend provides it, else errors `E_CRED_UNRESOLVED`. Recorded in
[DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) as D14 when first implemented (Phase 6).

## SI-3 — Session-frame verification underspecified

§8 says session frames are "independently signed" and owner-bound but does not
restate the §4 sequence. Do freshness + replay cache apply to
`session.command`/`session.close`?

**Assumption:** yes — the full §4 order (resolve → freshness/replay → signature
→ parse) applies to *every* signed inbound frame, including session frames, with
owner binding checked after signature. A weaker reading (signature-only) would
let captured frames be replayed within a live session's lifetime.

## SI-4 — Threat-model adversary numbering skips T5 in §2.x

§2.4 covers T4, §2.5 jumps to T6; T5 lives in §3 (the confused-deputy analysis —
arguably the point, given its weight). Purely editorial; suggest a pointer
sentence at §2.5. No implementation impact.

## SI-5 — Worked examples disagree on bytes

SKILL.md's http-bearer example uses
`body_b64 = eyJhbW91bnQiOjIwMDB9` (`{"amount":2000}`); PROTO-SPEC §5 and §7.1 use
`eyJhbW91bnQiOjIwMDAsImN1cnJlbmN5IjoidXNkIn0=` (`{"amount":2000,"currency":"usd"}`).
Examples are illustrative, not normative — but conformance tests (Phase 11)
should pin one canonical example set. Suggest the protocol's version wins.

## SI-6 — `cred_ref` optionality footnote is dead text in v1

Envelope table: cred_ref MUST\* "\*Omitted only for mechanisms that carry it in
the body (rare)". No v1 mechanism defines such a body. As written a client could
argue omission is legal somewhere. Suggest tightening to "mandatory for all v1
mechanisms". Implementation treats it as mandatory in v1.

## SI-7 — Version negotiation: gateway vs newer-MINOR agent

§10.2 defines rejection of unsupported MAJOR (`E_VERSION`) and that MINORs are
backward-compatible additions, and obligates *agents* to ignore unknown response
fields. It is silent on whether a gateway must accept intents stamped with a
*higher* MINOR than it implements.

**Assumption:** gateway accepts any MINOR within the same MAJOR (additive-only
evolution makes old gateways safe), rejects other MAJORs with `E_VERSION`.
Recorded here; revisit if the spec gains explicit negotiation.

## SI-8 — The operator channel is load-bearing but undefined

ARCH-SPEC §2.6 and PROTO-SPEC §9.2 route the single confirmation through "the
operator channel", which no artifact defines (installer/console UX declared out
of scope). Since Phase 7 cannot ship without *some* concrete surface, we define
v0 ourselves: controlling-TTY prompt with full context and timeout (see
DESIGN-DECISIONS D8), to be replaced by a proper operator console socket later.
Flagging because the confirmation gate is security-critical; its transport should
eventually be specified with the same care as the agent socket.
