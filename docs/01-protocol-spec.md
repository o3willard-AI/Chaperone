# Chaperone — Agent ↔ Gateway Protocol Specification

> **The credential-brokering contract between AI agents and the Virtual Interface Security Gateway.**

| | |
|---|---|
| **Document** | PROTO-SPEC — Artifact 1 of 4 |
| **Version** | 0.1 (Draft for review) |
| **Status** | Design-locked; open for implementation review |
| **Date** | 22 August 2026 |
| **Related** | Architecture Spec · Threat Model · Agent Skill |

---

## 1. Purpose and Scope

**Chaperone** is a local-first authentication broker that lets an AI agent perform authenticated, authorized operations against external and local systems **without any credential ever entering the agent's context, transport, or logs.** This document specifies the **wire contract** between an agent and the gateway: the transport, the identity and signing model, the structured `intent` objects an agent submits, the response and session contracts it receives back, and the decision and audit fields that make every brokered action attributable.

This is the canonical schema for the product. The Architecture Specification, the Threat Model, and the Agent Skill all derive from it. **Where any other artifact disagrees with this document, this document governs.**

### 1.1 What this document covers

- The local transport and how an agent reaches the gateway.
- **Identity:** per-agent keypairs, key custody, and how intents are signed and verified.
- **The intent envelope** shared by every request, and the per-mechanism intent bodies for v1.
- **Two session lifecycles:** one-shot invocation and brokered-handle sessions.
- **Decision, confirmation, and audit fields** that make the gateway a policy enforcement point rather than a credential dispenser.
- Error taxonomy and versioning rules.

### 1.2 What this document does not cover

- Vault-integration internals — see the **Architecture Specification**.
- Policy-rule authoring language and evaluation — the protocol carries the *decision*, not the ruleset.
- Adversary analysis and mitigations — see the **Threat Model**.
- Installer, key-provisioning UX, and operator console.

### 1.3 Design tenets

| Tenet | Consequence in this spec |
|---|---|
| No secret in agent space | The agent submits a credential reference, never a secret. It never receives a secret back — only results, or a session handle. |
| Attribution over trust | Every intent is signed by a per-agent private key held outside agent context. The gateway verifies before it acts, and stores the signed intent as evidence. |
| Default-deny | Absence of an explicit allow is a denial. The gateway is an authority that adjudicates, not a proxy that forwards. |
| Least-privilege, time-boxed | The gateway requests the narrowest, shortest-lived credential the vault can mint for the operation. A successful misuse is small and expires. |
| One gate, well-placed | The human confirmation, when required, happens once — at the gateway, at injection time, with full context — not scattered across agent and tool-runner layers. |

---

## 2. Terminology and Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are used as defined in RFC 2119 / RFC 8174.

| Term | Definition |
|---|---|
| Agent | An autonomous or semi-autonomous AI process that submits intents. Identified by a stable Agent ID and a keypair. |
| Gateway | The Chaperone daemon. Holds no agent trust of its own; verifies, adjudicates, injects, audits. |
| Intent | A signed, structured request from an agent describing a target, a mechanism, a credential reference, and an operation. |
| Credential reference (`cred_ref`) | An opaque handle naming a secret in a vault. Resolvable only by the gateway; meaningless in agent space. |
| Mechanism | The auth method the gateway must complete on the outbound side (e.g. `http-bearer`, `db-scram`, `ssh`, `local-privilege`). |
| Injector | The gateway module that completes a specific mechanism — attaches a header, answers a SCRAM challenge, signs an SSH challenge, brokers a privilege transaction. |
| One-shot | A lifecycle where the gateway authenticates, executes, returns a result, and closes. |
| Brokered session | A lifecycle where the gateway authenticates once, holds the live channel open, and returns a `session_handle` the agent drives across turns. |
| Decision | The gateway's allow / deny / needs-confirmation verdict on an intent, recorded in the audit log. |

---

## 3. Transport

### 3.1 Local channel

The gateway exposes a **Unix domain socket** as its default and RECOMMENDED transport on POSIX platforms, and a **named pipe** on Windows. On platforms or runtimes that cannot use a local IPC socket, the gateway MAY expose a **loopback TCP listener** bound strictly to `127.0.0.1` (or `::1`).

> **Rationale.** A filesystem socket makes OS permissions the first access-control layer: only principals with rights to the socket path can even attempt a request, and nothing is exposed on any network interface. Earlier drafts signalled routing through addresses in the `127.0.0.0/8` range; that indirection is removed. The agent addresses the gateway directly and states its intent explicitly.

Default socket path (override at install): `$XDG_RUNTIME_DIR/chaperone/gw.sock` (POSIX), `\\.\pipe\chaperone-gw` (Windows). The socket MUST be created with owner-only permissions (`0600`).

### 3.2 Framing

Requests and responses are **JSON objects** exchanged over the channel. Each message is framed as a `Content-Length`–prefixed block (LSP-style): an ASCII header line `Content-Length: N\r\n\r\n` followed by exactly `N` bytes of UTF-8 JSON. This avoids delimiter ambiguity in streamed session output.

### 3.3 Request/response model

- **Unary:** agent sends one intent, gateway returns one final response (one-shot mechanisms).
- **Streaming:** for brokered sessions, the gateway returns an initial response bearing a `session_handle`, then emits zero or more `session.output` frames, terminated by a `session.closed` frame.
- **Correlation:** every message carries a `msg_id` (agent-chosen, unique per connection); responses echo it.

---

## 4. Identity and Signing

**This is the load-bearing section of the protocol.** The gateway extends real credentials on an agent's behalf; it therefore MUST know, provably, which agent asked. Identity is established by a **per-agent keypair**, and every intent is **signed**. A signature is not secret-shaped and never enters agent context — so it neither trips the agent's own credential guards nor leaks anything if logged.

### 4.1 Key custody

- Each agent identity has an **Ed25519** keypair. The **private key MUST be generated in, and MUST NOT leave, a platform key store** — OS keychain, TPM, or Secure Enclave where available.
- The agent **never handles the private key material**. It requests a signature from the key store the way an SSH client uses `ssh-agent`: the bytes to sign go in, a signature comes out.
- The gateway stores only **public keys**, bound to Agent IDs at enrollment. Enrollment is an operator action, out of scope here.

> **Why this beats a static agent token.** A static bearer token is exactly the shape agent security guards are trained to block, and it makes the audit trail only as trustworthy as a copyable string. A signature over the request proves who issued *this specific* intent, is non-repudiable, and reads to any inspecting layer as the output of a security process — which is what it is. The same choice that gives the strongest audit trail also lowers the agent's proclivity to balk.

### 4.2 The signature

An agent signs the **canonical serialization** of the intent envelope with its private key. Canonicalization is `JCS` (RFC 8785, JSON Canonicalization Scheme) over every envelope field *except* `sig`. The resulting signature is base64url-encoded into the `sig` field.

**Verification order (the gateway MUST follow this sequence and stop at the first failure):**

1. **Resolve** the `agent_id` to an enrolled public key. Unknown → reject `E_UNKNOWN_AGENT`.
2. **Check freshness:** `issued_at` within the allowed skew and `nonce` unseen (replay cache). Stale or replayed → `E_REPLAY`.
3. **Verify** `sig` over the JCS canonical form. Bad signature → `E_BAD_SIGNATURE`.
4. **Only then** parse the mechanism body and proceed to policy evaluation.

> **Replay & binding.** `nonce` MUST be unique per agent within the freshness window; the gateway keeps a replay cache covering at least that window. `issued_at` is RFC 3339 UTC. Default allowed skew is ±30s. The signature covers `target`, `mechanism`, `cred_ref`, and `operation` together, so none can be swapped after signing without detection — this is what prevents an injected agent from being steered to reuse a signed intent against a different target.

---

## 5. The Intent Envelope

Every request an agent submits shares one envelope. The `mechanism` field selects which body schema (§7) applies. The envelope is what gets signed.

```json
{
  "chaperone": "0.1",
  "msg_id": "a3f1c9",
  "type": "intent",
  "agent_id": "agent:planner-7",
  "issued_at": "2026-08-22T17:04:03Z",
  "nonce": "9f2b7c1e5a",
  "target": {
    "uri": "https://api.stripe.com/v1/charges",
    "label": "stripe-prod"
  },
  "mechanism": "http-bearer",
  "cred_ref": "vault://prod/stripe/secret_key",
  "operation": { "...": "mechanism-specific body (§7)" },
  "constraints": {
    "max_response_bytes": 1048576,
    "session_ttl_s": 300
  },
  "sig": "base64url(ed25519 over JCS of all fields except sig)"
}
```

### 5.1 Envelope fields

| Field | Req. | Description |
|---|---|---|
| `chaperone` | MUST | Protocol version. See §10. |
| `msg_id` | MUST | Agent-chosen correlation id, unique per connection. |
| `type` | MUST | `intent` for a new request; `session.command` / `session.close` drive an open session (§8). |
| `agent_id` | MUST | Stable enrolled identity. Resolves to a public key. |
| `issued_at` | MUST | RFC 3339 UTC issue time. Freshness-checked. |
| `nonce` | MUST | Unique per agent within the freshness window. Anti-replay. |
| `target` | MUST | `uri` the operation acts on, plus a human-legible `label` for the confirmation surface. |
| `mechanism` | MUST | Selects the injector and the `operation` body schema. |
| `cred_ref` | MUST\* | Opaque vault handle. \*Omitted only for mechanisms that carry it in the body (rare). |
| `operation` | MUST | Mechanism-specific body (§7). |
| `constraints` | MAY | Agent-declared self-limits the gateway MUST honor as ceilings (never as grants). |
| `sig` | MUST | Signature over the JCS canonical form of every other field. |

> **On constraints.** `constraints` can only *narrow*. An agent may lower a ceiling (shorter TTL, smaller response) but can never use the field to request more than policy already allows. The gateway takes the minimum of the agent-declared and policy-declared limits.

---

## 6. Invocation Lifecycles

Two lifecycles share the envelope, the identity model, and the vault + policy + audit core. They differ only in the response contract.

### 6.1 One-shot

1. Agent submits a signed intent.
2. Gateway verifies signature and freshness (§4).
3. Gateway evaluates policy → a **decision** (allow / deny / needs-confirmation).
4. If needed, the gateway obtains a **single human confirmation** (§9).
5. Gateway resolves `cred_ref`, requests the **narrowest, shortest-lived** secret the vault can mint, and the injector completes the mechanism.
6. Gateway returns `result` and writes the audit record. Secret is discarded.

### 6.2 Brokered session

For mechanisms that hold a live authenticated channel (an SSH shell, a DB connection, a privileged local shell), the gateway authenticates **once** at establishment and returns a `session_handle`. The secret is used at setup and **never travels again**. The agent then drives the channel by handle:

1. `type:intent` with a session-capable mechanism → response carries `session_handle` + `session_ttl`.
2. `type:session.command` referencing the handle → gateway relays the command into the live channel; streams `session.output` frames back.
3. `type:session.close` (or TTL expiry, or connection drop) → gateway tears down the channel, emits `session.closed`, writes the audit record.

> **Why name both first-class.** The "secret used once, never re-transmitted" property is most valuable — and most subtle — in the session case. Treating everything as one-shot would either re-authenticate on every turn (leaking the secret repeatedly into injectors) or force the agent to hold the channel itself. Neither is acceptable; the handle model is the point.

---

## 7. v1 Mechanisms

Four mechanisms ship in v1. They were chosen to exercise **both lifecycles** and to avoid multiplying human-confirmation surfaces before the core is proven. **`browser-session` is deliberately deferred** to a later release: it multiplies consent surfaces and is the least conceptually settled.

| Mechanism | Lifecycle | Injector completes | Confirmation posture |
|---|---|---|---|
| `http-bearer` / `http-basic` | One-shot | Attaches `Authorization` header to the outbound HTTPS request; gateway re-originates TLS. | Gentle — routine egress. |
| `db-scram` | One-shot or session | Answers the SCRAM challenge/response in the DB wire protocol. Secret never sent verbatim. | Calm. |
| `ssh` | Session | Signs the SSH auth challenge with a vault-held key; holds the pty. Agent drives by handle. | Moderate — brokered as a session, routes around native `ssh` reflexes. |
| `local-privilege` | Session | Brokers a PAM/privilege transaction via a separate privileged helper; holds a privileged shell. | Loud — the one mechanism that MUST take a single, deliberate, high-friction confirmation. |

### 7.1 `http-bearer` operation body

```json
{
  "mechanism": "http-bearer",
  "cred_ref": "vault://prod/stripe/secret_key",
  "operation": {
    "method": "POST",
    "headers": { "Content-Type": "application/json" },
    "body_b64": "eyJhbW91bnQiOjIwMDAsImN1cnJlbmN5IjoidXNkIn0="
  }
}
```

The gateway injects `Authorization: Bearer <secret>`, performs the request to `target.uri` over freshly-originated TLS, and returns status, headers, and body. The agent supplies everything *except* the credential.

### 7.2 `local-privilege` — special handling

> **Distinct trust model.** Privilege escalation is not "inject a secret into a request" — it is "run this as root." It is brokered by a separate privileged helper (polkit / launchd-authorized daemon), sharing the vault + policy + audit core but **NOT** the network-injection code path. It ALWAYS takes a single deliberate human confirmation; policy MUST NOT allow it to run unattended unless an operator has explicitly configured an allowlisted, argument-pinned command.

---

## 8. Session Frames

### 8.1 `session.command` (agent → gateway)

```json
{
  "chaperone": "0.1",
  "msg_id": "a3f1cd",
  "type": "session.command",
  "agent_id": "agent:planner-7",
  "issued_at": "2026-08-22T17:05:10Z",
  "nonce": "1a4d...",
  "session_handle": "sess_7Kd9",
  "input_b64": "bHMgLWxhIC92YXIvbG9nCg==",
  "sig": "..."
}
```

Every session frame is **independently signed**. The `session_handle` is bound at issuance to the `agent_id` that opened it; a frame signed by any other identity is rejected `E_SESSION_OWNER`.

### 8.2 `session.output` / `session.closed` (gateway → agent)

```json
{ "type": "session.output", "session_handle": "sess_7Kd9",
  "stream": "stdout", "data_b64": "...", "seq": 4 }

{ "type": "session.closed", "session_handle": "sess_7Kd9",
  "reason": "client_close", "exit_code": 0, "audit_id": "aud_20260822_4471" }
```

---

## 9. Decision, Confirmation, and Audit

**This is what makes Chaperone a policy enforcement point rather than a confused-deputy machine.** The gateway evaluates every intent to a **decision** before any secret is touched. The protocol carries the decision and its audit id; it does *not* carry the policy ruleset.

### 9.1 Decision values

| Decision | Meaning | Protocol effect |
|---|---|---|
| `allow` | Policy permits; no human needed. | Gateway proceeds; response carries `decision:allow` and `audit_id`. |
| `needs_confirmation` | Permitted only with a live human approval. | Gateway blocks on a single confirmation (§9.2), then proceeds or denies. |
| `deny` | No explicit allow, or an explicit deny. | Gateway returns `E_DENIED` with a reason code; nothing is injected. Default-deny lands here. |

### 9.2 The single confirmation

When a decision is `needs_confirmation`, the gateway — **not the agent** — owns the human gate. It surfaces one prompt through the operator channel with full context: the `target.label`, the `agent_id`, the `mechanism`, and the resolved operation summary (e.g. *"agent:planner-7 wants to POST a charge via stripe-prod — approve?"*).

> **Collapsing the triple-prompt.** Because the agent is visibly *delegating* the credential-bearing step to Chaperone rather than performing it, the Agent Skill instructs agents that filing a Chaperone intent needs no separate credential-handling confirmation — Chaperone owns that gate. This is legitimate because the gate genuinely moved. Result: one deliberate prompt at the injection point, instead of the agent, the tool-runner, and the gateway each prompting.

### 9.3 Audit record

Every terminal outcome writes one **append-only, signed** audit record binding: the full signed intent (as evidence), the decision and who/what confirmed it, the `cred_ref` used (never the secret), the mechanism and target, timing, and outcome. Records are chained (each carries the hash of the prior) so tampering is detectable.

---

## 10. Errors and Versioning

### 10.1 Error codes

| Code | Stage | Meaning |
|---|---|---|
| `E_UNKNOWN_AGENT` | Identity | `agent_id` not enrolled. |
| `E_BAD_SIGNATURE` | Identity | Signature failed verification over the canonical form. |
| `E_REPLAY` | Identity | Stale `issued_at` or reused `nonce`. |
| `E_DENIED` | Policy | No explicit allow (default-deny) or an explicit deny. Carries a reason code. |
| `E_CONFIRM_TIMEOUT` | Confirmation | Human confirmation not granted within the window. |
| `E_CRED_UNRESOLVED` | Vault | `cred_ref` did not resolve, or vault declined to mint. |
| `E_MECHANISM` | Injection | Outbound mechanism failed (target refused auth, channel error). |
| `E_SESSION_OWNER` | Session | Session frame signed by an identity other than the opener. |
| `E_SESSION_EXPIRED` | Session | `session_handle` unknown or past TTL. |
| `E_VERSION` | Envelope | Unsupported `chaperone` version. |

Errors never carry secret material and never echo resolved credentials. An error response echoes `msg_id`, an error `code`, and a human-legible `reason`.

### 10.2 Versioning

- `chaperone` is `MAJOR.MINOR`. A gateway MUST reject a MAJOR it does not implement (`E_VERSION`).
- MINOR additions MUST be backward-compatible: new optional fields only. Agents MUST ignore unknown response fields.
- New mechanisms are additive and do not bump MAJOR. `browser-session` is expected to arrive as an additive mechanism in a future MINOR.

---

*Next artifacts (derive from this spec): [Architecture Specification](02-architecture-spec.md) → [Threat Model](03-threat-model.md) → [Agent Skill](04-agent-skill.md).*
