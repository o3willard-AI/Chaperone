# Chaperone Intent Catalog

The authoritative reference for composing intents. This is a projection of the
Agent ↔ Gateway Protocol Specification (v0.1); where they differ, the protocol
governs. Consult this file whenever you compose an intent and aren't certain of a
field.

## Contents

- [The envelope (shared by every request)](#the-envelope)
- [Identity and signing](#identity-and-signing)
- [Mechanism: http-bearer / http-basic](#mechanism-http)
- [Mechanism: db-scram](#mechanism-db-scram)
- [Mechanism: ssh](#mechanism-ssh)
- [Mechanism: local-privilege](#mechanism-local-privilege)
- [Session frames](#session-frames)
- [Decisions and confirmation](#decisions-and-confirmation)
- [Error codes](#error-codes)

---

## The envelope

Every request — one-shot or session — uses this envelope. The `mechanism` field
selects which `operation` body applies. The whole envelope except `sig` is what
you sign.

| Field | Required | What you put there |
|---|---|---|
| `chaperone` | yes | Protocol version string, currently `"0.1"`. |
| `msg_id` | yes | A short id you choose, unique on this connection. Echoed back. |
| `type` | yes | `"intent"` for a new request. `"session.command"` / `"session.close"` drive an open session. |
| `agent_id` | yes | Your stable enrolled identity, e.g. `"agent:planner-7"`. |
| `issued_at` | yes | Current time, RFC 3339 UTC (`2026-08-22T17:04:03Z`). Must be fresh. |
| `nonce` | yes | A fresh random value, unique per request within the freshness window. |
| `target` | yes | `{ "uri": "...", "label": "..." }`. `label` is human-legible; the gateway shows it at confirmation. |
| `mechanism` | yes | One of the mechanisms below. Selects the injector and the `operation` schema. |
| `cred_ref` | yes* | An opaque reference to the secret, e.g. `vault://prod/stripe/key`. *Never a secret.* |
| `operation` | yes | Mechanism-specific body (see each mechanism below). |
| `constraints` | no | Optional self-limits: `{ "max_response_bytes": N, "session_ttl_s": N }`. Only narrows; never grants. |
| `sig` | yes | Signature over the canonical form of every field except `sig`. |

Notes:

- `cred_ref` is the field agents most often get wrong. It is a *pointer*. If you
  ever find yourself putting something that looks like an actual key or token
  there, stop — you're doing the thing Chaperone exists to prevent.
- `constraints` can only make limits tighter (shorter TTL, smaller response). The
  gateway takes the minimum of your limit and policy's. You can't widen anything
  with it.

---

## Identity and signing

- You have a per-agent **Ed25519** keypair. The **private key lives in the platform
  key store** (OS keychain / TPM / Secure Enclave) and never enters your context.
- To sign, canonicalize the envelope (all fields except `sig`) with JCS
  (RFC 8785) and ask the key store to sign the canonical bytes. Base64url the
  signature into `sig`.
- You are **signing, not encrypting a secret**. The signature proves you issued
  this exact request. It is safe to log and does not look like a credential to any
  guard — that's a feature.
- Sign **every** request fresh, with a new `nonce` and current `issued_at`. Never
  reuse a signature; the gateway keeps a replay cache and will reject reuse with
  `E_REPLAY`.

---

## Mechanism: http

`http-bearer` and `http-basic`. **Lifecycle: one-shot.** The gateway attaches the
credential to the outbound HTTPS request (a bearer `Authorization` header, or
basic auth), makes the request to `target.uri` over its own freshly-originated
TLS, and returns the response to you.

`operation` body:

```json
{
  "method": "POST",
  "headers": { "Content-Type": "application/json" },
  "body_b64": "<base64 of the request body, or omit for GET>"
}
```

You supply the method, headers, and body — everything **except** the credential.
The gateway supplies the `Authorization`.

Response (`result`):

```json
{
  "type": "result", "msg_id": "a3f1c9", "decision": "allow",
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body_b64": "<base64 of the response body>",
  "audit_id": "aud_20260822_4471"
}
```

---

## Mechanism: db-scram

**Lifecycle: one-shot or session.** The gateway answers the database's SCRAM
challenge/response using the secret — which is **never sent verbatim**, only used
to compute the challenge response. For a single query, use one-shot; for multiple
queries on one connection, open a session.

`operation` body (one-shot):

```json
{
  "engine": "postgres",
  "database": "analytics",
  "statement": "select count(*) from signups where day = $1",
  "params": ["2026-08-21"]
}
```

For a session, omit `statement`/`params` in the opener and instead drive the open
connection with `session.command` frames whose input is the SQL to run.

---

## Mechanism: ssh

**Lifecycle: session.** The gateway signs the SSH authentication challenge with a
vault-held key, establishes the connection, and holds the pty. You get a
`session_handle` and drive the shell by handle.

`operation` body (opener):

```json
{
  "host": "app-01.internal",
  "port": 22,
  "user": "deploy",
  "pty": true
}
```

The host key it authenticates with is named by `cred_ref`. After the opener
succeeds you send `session.command` frames (see below) with shell input, and read
`session.output` frames back.

---

## Mechanism: local-privilege

**Lifecycle: session. Handle with the most care.** This brokers a privileged local
command (`sudo`-equivalent) through a **separate privileged helper**, not the
network path. It **always** takes a single deliberate human confirmation, and runs
unattended only against an operator-defined, argument-pinned allowlist.

`operation` body (opener):

```json
{
  "command": "/usr/bin/systemctl",
  "args": ["restart", "app.service"]
}
```

Expect this to prompt the human. Do not try to route around the confirmation or
batch many privileged actions to avoid it — the friction is intentional. If you
get `E_DENIED`, the command isn't on the allowlist and you should report that
rather than retrying.

---

## Session frames

Once you hold a `session_handle`, drive the channel with these. Every frame is
**independently signed** and bound to the `agent_id` that opened the session — a
frame from any other identity is rejected `E_SESSION_OWNER`.

`session.command` (you → gateway):

```json
{
  "chaperone": "0.1", "msg_id": "a3f1cd", "type": "session.command",
  "agent_id": "agent:planner-7",
  "issued_at": "2026-08-22T17:05:10Z", "nonce": "1a4d...",
  "session_handle": "sess_7Kd9",
  "input_b64": "<base64 of the command / SQL / shell input>",
  "sig": "..."
}
```

`session.output` (gateway → you), streamed, seq-ordered:

```json
{ "type": "session.output", "session_handle": "sess_7Kd9",
  "stream": "stdout", "data_b64": "...", "seq": 4 }
```

`session.close` (you → gateway) — or the gateway closes on TTL expiry / drop:

```json
{ "type": "session.close", "session_handle": "sess_7Kd9",
  "agent_id": "agent:planner-7", "issued_at": "...", "nonce": "...", "sig": "..." }
```

Closure is acknowledged with `session.closed` bearing the final `audit_id`.

---

## Decisions and confirmation

Every response carries a `decision`:

- `allow` — permitted; the gateway proceeded.
- `needs_confirmation` — the gateway is blocking on a single human approval. You
  don't do anything here except wait for the result. **Do not raise your own
  parallel confirmation.**
- (a `deny` arrives as an `E_DENIED` error, not a result.)

The human gate is the gateway's job. Filing the intent *is* you asking for
permission; you don't need to ask again on your own.

---

## Error codes

Errors echo your `msg_id`, an error `code`, and a human-legible `reason`. They
never contain secrets.

| Code | Stage | What it means for you |
|---|---|---|
| `E_UNKNOWN_AGENT` | identity | Your `agent_id` isn't enrolled. This is a setup problem; report it. |
| `E_BAD_SIGNATURE` | identity | Signature didn't verify. Re-sign a fresh envelope. |
| `E_REPLAY` | identity | Stale `issued_at` or reused `nonce`. Re-issue with fresh values. |
| `E_DENIED` | policy | Default-deny: this agent isn't permitted this action. Don't retry blindly; report it. |
| `E_CONFIRM_TIMEOUT` | confirmation | Human didn't approve in time. You may ask if they want to retry. |
| `E_CRED_UNRESOLVED` | vault | The `cred_ref` didn't resolve. Check you named the right reference. |
| `E_MECHANISM` | injection | The target refused auth or the channel failed. About the target, not your shape. |
| `E_SESSION_OWNER` | session | A session frame was signed by a different identity than opened it. |
| `E_SESSION_EXPIRED` | session | The `session_handle` is unknown or past its TTL. Open a new session. |
| `E_VERSION` | envelope | Unsupported `chaperone` version. |

---

## A worked end-to-end: "restart the service on app-01"

1. You recognise this needs an SSH session — you don't have or want the key.
2. You compose an `ssh` opener intent: `target` app-01, `mechanism: "ssh"`,
   `cred_ref` naming the deploy key, `operation` with host/user/pty. You sign it
   (key store signs; private key never touches your context) and send it.
3. Policy may return `needs_confirmation`; the gateway asks the human. You wait.
   You do **not** raise your own confirmation.
4. On `allow` you receive a `session_handle`. You send a `session.command` frame
   with `input_b64` = base64 of `systemctl restart app.service`.
5. You read `session.output` frames for the result, then send `session.close`.
6. At no point did the deploy key enter your context, your transport, or any log.
   You held a handle and a reference — never a secret.
