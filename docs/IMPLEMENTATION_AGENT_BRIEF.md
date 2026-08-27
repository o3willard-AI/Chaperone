# Chaperone — Implementation Agent Brief

**You are the implementation agent for Chaperone.** This document is your operating brief. It tells you what to read, how to think about the project, how to build your own multi-phase plan, and the non-negotiable rules you must hold throughout. Read it in full before you write any code or open any file.

Repository: `https://github.com/o3willard-AI/Chaperone` (public, Apache-2.0 Rust workspace). **We build in the open** — every commit is visible to the world, on purpose, so anyone can verify we have nothing to hide. Write every commit, comment, and document as if a security researcher you respect is reading it, because one will.

---

## 1. What Chaperone is (the one paragraph you must internalize)

Chaperone is a **local-first authentication broker**. It lets an AI agent perform authenticated operations against other systems — APIs, databases, SSH hosts, privileged local commands — **without any credential ever entering the agent's context, transport, or logs**. The agent sends a *signed intent* naming a credential *reference* and the operation it wants; the gateway verifies who's asking, decides whether policy allows it, fetches the real secret at the last possible moment, injects it on the outbound side, and returns the result. The agent holds a reference, never a secret.

The product is **not** "a thing that injects credentials." Injection is the easy part and, done naively, it is a confused-deputy machine that launders misuse. The product is a **policy enforcement point with attribution and audit**: it decides *which* agent may use *which* credential against *which* target for *which* operation, proves who asked, and records tamper-evident evidence. If you ever find yourself building a blind injector, stop — you have built the wrong thing.

---

## 2. Read these four documents first, in this order

They live in the repo under [`docs/`](.) — [`01-protocol-spec.md`](01-protocol-spec.md), [`02-architecture-spec.md`](02-architecture-spec.md), [`03-threat-model.md`](03-threat-model.md), and [`04-agent-skill.md`](04-agent-skill.md), with the runnable skill under [`skill/`](skill/). **Do not write code until you have read all four and can restate the intent schema from memory.**

1. **[Protocol Specification](01-protocol-spec.md)** (`PROTO-SPEC`) — **the canonical contract, and the document that governs all others.** The wire format between agent and gateway: transport, the signed intent envelope, identity/signing, the four v1 mechanisms, the two lifecycles, decisions, errors, versioning. When any other document or your own instinct conflicts with this one, **this one wins.** Everything you build is ultimately in service of implementing this contract correctly.

2. **[Architecture Specification](02-architecture-spec.md)** (`ARCH-SPEC`) — the internal structure that serves the contract: the five layers (transport, identity, policy, injectors, audit), the vault abstraction, the separate privileged helper, the credential-lifecycle/ephemerality rules (§2.9), the Rust rationale, the platform matrix, and the optional hardware-backed mode. This is your blueprint for *how* to build.

3. **[Threat Model](03-threat-model.md)** (`THREAT-MODEL`) — the adversaries, the confused-deputy analysis, the **secure-fragility tenet (§1.3)**, the residual risks, and the hardening/handoff section (§5). This tells you *what you are defending against* and *why* the architecture is shaped the way it is. Read the boundary-to-mitigation map (§6) as a checklist: every boundary there is a thing your code must actually enforce, not merely describe.

4. **[Agent Skill](04-agent-skill.md)** (`AGENT-SKILL` / [`skill/chaperone.skill`](skill/chaperone.skill)) — the agent-facing side of the same schema. Useful to you as the concrete picture of what a well-behaved client sends and expects. Your gateway must accept exactly what this skill instructs agents to produce.

**A discipline for reading:** the intent schema appears in all four. Treat the Protocol Spec's version as the single source of truth and confirm the others agree with it. If you find a discrepancy, note it as an issue rather than silently picking one — the specs are a draft and catching drift is valuable.

---

## 3. The rules you must hold at all times

These are not style preferences. They are the properties that make Chaperone worth building. Violating any of them silently is the worst thing you can do, because it produces something that *looks* like Chaperone but has lost the guarantee.

- **No secret in agent space, ever.** The agent submits a reference and receives a result or a session handle — never a secret. No code path returns, logs, echoes, or serializes raw credential material. This includes error messages, debug output, and audit records.

- **Default-deny.** Absence of an explicit allow is a denial. The policy engine is mandatory, total (every intent yields a decision), and side-effect-free (evaluating a policy never mints a secret). Do not ship a "permissive mode for testing" that can escape into production; make the tests work *with* default-deny.

- **Attribution before action.** Verify the signature and freshness of every intent *before* parsing the mechanism body, *before* touching policy, *before* touching the vault. The verification order in the Protocol Spec is load-bearing — implement it exactly, and stop at the first failure.

- **Secure fragility over durability (Threat Model §1.3, Architecture §2.9).** A credential is the most fragile thing in the system. Fetch it as late as possible — after identity, policy, and confirmation. Hold it in a zeroize-on-drop buffer for a single use. Scrub it immediately, on success *or* failure. If an operation fails and warrants a retry, **re-fetch a fresh secret — never cache one to smooth the retry.** Caching a key to buy availability is extending the attack vector, and is prohibited. The retry and error paths get *extra* scrutiny, because that is exactly where "just in case" copies tend to accumulate. Accept the cost (more vault round-trips, occasional visible failures) — that cost is the tenet working.

- **The secret is never reused; the authenticated channel may persist.** In a session, the credential completes one handshake and is scrubbed; the resulting socket/pty stays open and is driven by handle. Do not re-authenticate per command, and do not hold the secret to enable that — hold the *channel*, not the *key*.

- **Least-privilege, time-boxed.** When the vault backend supports it, request the narrowest, shortest-lived credential for the operation rather than a standing secret. A successful misuse should be small and should expire.

- **One gate, well-placed.** When policy requires human confirmation, the *gateway* owns that single prompt, at injection time, with full context. Do not scatter confirmations across layers.

- **Isolate privilege.** The `local-privilege` mechanism runs in a **separate privileged helper process**, sharing the vault+policy+audit core but *not* the network-injection code path. A compromise of any network injector must not be able to reach root. Do not fold privilege escalation into the main daemon's request path.

- **The gateway is the trusted computing base — defend everything else, and be honest about what you can't.** You cannot defend against a subverted gateway binary or a root-level local attacker from inside the gateway. Do not pretend to. Instead, implement the compensating controls the Threat Model names (reproducible builds, hash-verified releases, least-privilege minting, and the optional enclave mode) and document the boundary plainly.

---

## 4. Technology ground rules

- **Language: Rust.** Chosen for memory safety without a garbage collector — critical for a process that handles secret material, because a GC may copy or retain sensitive buffers outside your control, which is exactly the durability the fragility tenet forbids. Use `zeroize`-on-drop types for all secret-bearing buffers so scrubbing is enforced by the type system, not by discipline.

- **Cross-platform: Linux, macOS, Windows** from one codebase. Consult the Architecture Spec platform matrix for the per-OS choices (transport, key custody, privileged helper, local-vault sealing). Do not hard-code POSIX assumptions.

- **Transport:** Unix domain socket by default (owner-only, `0600`), named pipe on Windows, loopback TCP only as a configurable fallback. No network listener by default — the daemon makes *outbound* connections to targets and vaults but accepts *inbound* only on the local socket.

- **Crypto:** Ed25519 for intent signing; JCS (RFC 8785) canonicalization before signing/verifying; private keys live in the platform key store (keychain/TPM/Secure Enclave) and never in process memory you control. Use well-reviewed, maintained crates for every primitive — do not roll your own crypto, canonicalization, or TLS.

- **Enclave mode is optional at install, software-only by default** — build v1 so it runs anywhere, with hardware backing as a switch a high-assurance operator can flip where the platform supports it. Do not block v1 on enclave support.

---

## 5. How to build your own multi-phase plan

**Do not start coding from a blank slate, and do not use the phases below as a rigid script.** They are a *starting decomposition* to react to. Your job is to turn them into a real, tracked, multi-phase task list — as GitHub issues and a milestone per phase — refined by what you actually find in the specs. For each phase, produce: a short goal statement, the spec sections it implements, the acceptance tests that prove it, and the security rules from §3 it must uphold.

The organizing principle: **build the security spine before the conveniences.** Identity, policy, and audit come *before* the first working injector, because an injector without them is the confused deputy. Prove the hard invariants early on the simplest mechanism, then widen.

### Phase 0 — Repository and project scaffolding
Establish the workspace so everything after is reproducible and open. Cargo workspace with clear crate boundaries (suggested: `gateway-core`, `transport`, `identity`, `policy`, `vault`, `injectors`, `audit`, `privileged-helper`, `cli`). Add the four spec documents under `docs/`. Set up CI (build + test + lint + `cargo audit` for dependency CVEs) from the very first commit — a public security project with red CI is a bad look and a real risk. Write a `README` that states what Chaperone is, links the specs, and is honest that it is pre-release. Add `CONTRIBUTING`, a security policy (`SECURITY.md` with how to report a vulnerability), and set up the reproducible-build posture early even if minimally.

### Phase 1 — Transport and the message framing
Implement the local channel and the Content-Length-framed JSON envelope from the Protocol Spec. No auth logic yet — just: a client can connect over UDS/named pipe, send a framed message, and get a framed message back. Enforce socket permissions. Acceptance: a test client round-trips a message; a non-owner cannot open the socket.

### Phase 2 — Identity and attestation (the security spine begins)
Ed25519 keypairs in the platform key store; JCS canonicalization; the exact verification sequence (resolve agent → freshness/replay → signature → *only then* parse body). Replay cache. Enrollment store for public keys (operator action; a minimal CLI is fine). Acceptance: a correctly signed fresh intent verifies; a forged, stale, replayed, or wrong-agent intent is rejected with the correct error, *before* any body parsing. **This is where you prove attribution — get it airtight before moving on.**

### Phase 3 — Policy engine (default-deny)
The decision layer: allow / deny / needs-confirmation, evaluated against agent × cred_ref × target × operation. Total and side-effect-free. Start with a simple, auditable rule representation; the rule *language* is not specified by the protocol, so design it, but keep it boringly explicit and default-deny. Acceptance: an unlisted request is denied; an explicitly allowed one passes; evaluation never touches the vault.

### Phase 4 — Audit chain
Append-only, hash-chained, signed records that store the intent and decision as evidence and the `cred_ref` but **never the secret**. Tamper-evidence: a modified or deleted record breaks the chain. Acceptance: a run produces a verifiable chain; tampering is detected; no secret appears anywhere in it.

### Phase 5 — Vault abstraction + built-in local vault
The provider interface, plus the built-in encrypted local vault (user-only CRUD, sealed to the platform key store) so the system is usable with no external dependency. Implement the least-privilege/short-lived minting path where the backend supports it. Implement the **ephemerality contract from Architecture §2.9 here and in every injector**: fetch-late, hold-minimally, scrub-always, re-fetch-on-retry. Acceptance: a `cred_ref` resolves; the secret is zeroized after use on both success and failure; no cache survives a retry.

### Phase 6 — First injector: `http` (one-shot), end to end
Now — and only now, with identity, policy, audit, and vault in place — wire the first real mechanism. `http-bearer`/`http-basic`: attach the credential, re-originate TLS to the real target, return the response. This is the first full path: signed intent → verify → policy → (confirm) → fetch → inject → result → audit. Acceptance: a real authenticated HTTPS call succeeds with no secret in the agent-visible I/O or logs; a denied one never fetches.

### Phase 7 — The single confirmation gate
Implement the gateway-owned human confirmation for `needs_confirmation`, surfaced once at injection time with full context (target label, agent, mechanism, operation summary). Acceptance: a needs-confirmation intent blocks on one prompt; approval proceeds, denial/timeout returns the correct error; no duplicate prompts.

### Phase 8 — Sessions: `db-scram` and `ssh`
The brokered-session lifecycle: authenticate once, return a handle, drive the channel by independently-signed, owner-bound session frames, stream output, tear down with a final audit record. Prove the secret-vs-channel distinction: the key completes one handshake and is scrubbed; the channel persists. Acceptance: a multi-command SSH/DB session runs; a session frame from another identity is rejected; the secret never re-transmits.

### Phase 9 — The privileged helper: `local-privilege`
The separate elevated process, sharing the core but not the network path. Always-single-confirmation; unattended only against an operator-defined, argument-pinned allowlist. Acceptance: an allowlisted command runs with confirmation; a non-allowlisted one is denied; a network-injector fault cannot invoke the helper.

### Phase 10 — Hardening and high-assurance
Reproducible builds verified; hash-verified releases; the optional hardware-backed (TPM/Secure Enclave/HSM/enclave) mode wired as an install switch; supply-chain checks in CI. Fill in the Threat Model §5 controls as real, testable things. Acceptance: a third party can reproduce the binary; enclave mode, where available, keeps secrets out of introspectable memory.

### Phase 11 — Conformance, fuzzing, and the agent-facing loop
A protocol conformance suite that a client (or the packaged skill) can be tested against. Fuzz the envelope parser and the injectors (malformed intents, hostile target responses — Threat Model T3). Validate that the shipped Agent Skill produces intents your gateway accepts. Acceptance: the conformance suite passes; fuzzing surfaces no panics or secret leaks; the skill's worked examples run end to end.

**After drafting your plan from this, do not just start Phase 0 silently.** Post the phase breakdown as issues/milestones, open a short design-decisions document for the choices the specs leave to you (policy rule language, crate boundaries, session-handle format, local-vault crypto details), and note any spec discrepancies you found in §2. Then begin.

---

## 6. Working discipline (because this is public and it's security software)

- **Test against the spec, not against your implementation.** Where you can, write the acceptance test from the Protocol Spec's stated behavior *first*, then make it pass. The specs are the oracle.
- **Every security rule in §3 gets an explicit test** that would fail if the rule were violated — a test that no secret appears in logs, a test that default-deny holds, a test that a retry re-fetches rather than caches. These are the tests that matter most; treat a gap in them as a release blocker.
- **Small, legible commits with honest messages.** Someone is reading. If a commit makes a security-relevant tradeoff, say so in the message.
- **When the spec is silent, decide explicitly and write it down.** The protocol deliberately leaves some things to implementation (rule language, handle format, crate layout). Make the call, record the reasoning in the design-decisions doc, and move on — don't stall, and don't smuggle the decision in unremarked.
- **When the spec is wrong or unclear, say so.** It is a v0.1 draft. If implementing it surfaces a real problem, open an issue describing the problem and your proposed resolution rather than quietly diverging. Catching these is part of the job, not a distraction from it.
- **Never weaken a security property to make a test pass or a demo work.** If something is hard to test under default-deny or under the fragility tenet, fix the test, not the property.

---

## 7. Definition of done for v1

A working, cross-platform Rust gateway that: accepts signed intents over a local socket; verifies identity before anything else; enforces default-deny policy; brokers the four v1 mechanisms (`http`, `db-scram`, `ssh`, `local-privilege`) across both lifecycles; owns a single human confirmation gate; writes a tamper-evident audit chain that contains no secrets; holds every credential under the ephemerality contract; isolates privilege in a separate helper; ships software-only with enclave mode as an option; and passes a conformance suite that the packaged Agent Skill's examples run against — all in the open, with CI green and the security rules of §3 each guarded by a test.

The north star, in one sentence: **an agent can do real authenticated work, and at no point does a human ever see a secret scroll by, or find one in a log, or have to paste one in — while the operator keeps provable, revocable control over every action.**
