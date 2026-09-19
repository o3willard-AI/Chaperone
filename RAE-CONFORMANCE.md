# RAE Conformance Statement — Chaperone

**Specification:** [Registered Accountable Entity (RAE)](https://github.com/o3willard-AI/RAE), v1.0.4
**Product:** Chaperone (this repository)
**Claim:** *displays an RAE at L0 (declared, unverified)* — **not** *implements RAE*
**Date:** 2026-09-19

Per RAE §4, L0 is a display-only claim: "An L0 display is not an implementation
and publishes no conformance statement." This file is therefore **not** a
conformance declaration in the §4 sense — Chaperone makes no claim to implement
the RAE practice, whose attribution machinery (N1, N3, N4, N6a/N6b, N7, N8)
begins at L1. This file is published voluntarily, at the conventional location
§4 names, to state exactly what Chaperone does and does not assert, so that no
reader has to infer the boundary.

## The claim, precisely

Chaperone displays an RAE at L0 (declared, unverified):

- **What exists:** enrollment binds each agent to a named human sponsor
  (`sponsor_id` + `sponsor_name`), and every audit record carries that sponsor,
  so every brokered action is *attributed to a declared human* rather than only
  to an agent key. The proof leg is strong at the agent layer: signed intents
  (non-repudiable origin) in an append-only, hash-chained audit (tamper
  detection).
- **What is missing for L1:** the sponsor's identity is self-declared at
  enrollment and is not verified by the deploying organization, and the
  sponsor binding is not itself a signing credential bound to authorization
  records. Chaperone will not claim L1 until an operator-verifiable identity
  binding exists.

## Clause status (informational — L0 declares no enforcement)

| Clause | Status in Chaperone | Note |
|---|---|---|
| N1 Pre-attribution | Partial, declared | Sponsor is bound at enrollment, before any intent can be submitted. Not registration-grade: the binding is an unverified declaration. |
| N2 Agents are never RAEs | Honored | Attribution terminates at the human sponsor; agents are subjects, never objects, of accountability. |
| N3 No-RAE invariant | Informational | Every audit record names a sponsor, so no brokered action is silent about accountability. Chaperone declares no enforcement tier at L0; blocking/flagging semantics belong to L1 conformance. |
| N4 Influenced actions | Not applicable | Chaperone brokers agent actions directly; it does not record human-acts-on-agent-output provenance. |
| N5 Natural-person resolution | Honored | The sponsor is a named natural person, never an organization. |
| N6a/N6b Sponsorship scope | Partial, declared | Enrollment + policy rules bound what an agent may do (mechanism/target/operation, default-deny), which functions as a scope expression; it is not yet a declared-scope construct assessed for breadth per N6b. |
| N7 Sponsorship lifecycle | Partial | Un-enrolling an agent severs its sponsor binding prospectively; expiry, transfer, and in-flight-revocation semantics are not implemented. |
| N8 Agent-to-agent delegation | Not applicable (architectural) | Chaperone brokers agent → external-system actions; agent-invokes-agent chains are out of scope in v0.1. If Chaperone later brokers on behalf of invoked sub-agents, this becomes applicable and must be re-declared. |

## Proof location

- **Signed intents:** each intent is signed by the agent's per-enrollment
  private key; the gateway verifies before acting and stores the full signed
  intent as evidence (Protocol Spec §5, §9.3).
- **Audit records:** append-only, signed, hash-chained (each record carries
  the prior record's hash), written on every terminal outcome and binding the
  signed intent, decision, `cred_ref`, mechanism, target, timing, outcome —
  and the human sponsor (Protocol Spec §9.3–9.4).
- **Verification:** `chaperone` CLI audit verification (see README, repository
  layout `audit/`).

## What would change the claim

Raising Chaperone to *implements RAE 1.0.x L1, \<tier\> tier* requires:
organization-verified sponsor identity; a signing credential bound to the
sponsor's authorization records; declared-scope expressions with N6a runtime
evaluation and N6b breadth review; N7 lifecycle semantics; and this file
converted into a true §4 conformance statement with the canonical claim form.
