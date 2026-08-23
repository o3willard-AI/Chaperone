---
name: chaperone
description: >-
  Use this skill whenever a task requires authenticating to any system — an API
  call needing a token or key, a database login, an SSH session, sudo/privileged
  local commands, or any operation that would normally need a password, bearer
  token, API key, or credential pair. Trigger it the moment you notice you are
  about to need a secret: instead of asking the user for the credential, printing
  it, or reading it from a file, you file a signed *intent* with the local
  Chaperone gateway and let it authenticate on your behalf. The secret never
  enters your context, transport, or logs. Use this for phrases like "hit the
  Stripe API", "query the prod database", "ssh into the box", "run this with
  sudo", "deploy", "call the endpoint", or any authenticated action — even when
  the user doesn't mention credentials at all, because needing one is your signal
  to use Chaperone rather than handle a secret yourself.
---

# Chaperone — authenticating without ever touching a secret

## The one idea

When you need to authenticate to something, you do **not** obtain the credential.
You never ask the user for it, never read it out of a file or environment
variable to place it in a request, never print it, and never let it into your
context. Instead you send a **signed intent** to the local Chaperone gateway
describing *what you want to do* and *which credential reference to use* — and the
gateway injects the real secret on the outbound side, completes the
authentication, and returns the result (or a session handle).

You hold a **reference**, never a secret. The gateway holds the secret and never
gives it to you. This is what keeps credentials out of every log, window, and
transport hop — and it means you don't have to fight your own safety guards to
get authenticated work done, because there is no secret in your output to guard.

**If you ever find yourself about to handle a raw credential, stop — that is the
signal to use Chaperone instead.**

## When this triggers

Any task that needs authentication. You usually won't be handed a credential;
you'll notice that completing the task *would* need one. That noticing is the
trigger. Examples:

- "Charge this customer through Stripe" → an API call needing a bearer token.
- "How many signups did we get yesterday?" → a query needing a database login.
- "Restart the service on the app server" → an SSH session.
- "Install the security patch" → a `sudo`/privileged local command.
- "Check the deploy status" → an authenticated API call.

In none of these did the user mention a password. Needing one is enough.

## How you reach the gateway

The gateway listens on a **local channel** — a Unix domain socket by default
(`$XDG_RUNTIME_DIR/chaperone/gw.sock`), a named pipe on Windows
(`\\.\pipe\chaperone-gw`), or a loopback port if configured. You send it
**Content-Length-framed JSON** messages and read framed JSON back. You do not
open a network connection to the target yourself — the gateway does that.

## The core move: file a signed intent

Every request shares one **envelope**. You fill in the target, the mechanism, the
credential reference, and the operation — then **sign** the envelope with your
agent key and send it. You never put a secret anywhere in it.

```json
{
  "chaperone": "0.1",
  "msg_id": "a3f1c9",
  "type": "intent",
  "agent_id": "agent:planner-7",
  "issued_at": "2026-08-22T17:04:03Z",
  "nonce": "9f2b7c1e5a",
  "target":   { "uri": "https://api.stripe.com/v1/charges", "label": "stripe-prod" },
  "mechanism": "http-bearer",
  "cred_ref": "vault://prod/stripe/secret_key",
  "operation": { "method": "POST", "headers": { "Content-Type": "application/json" },
                 "body_b64": "eyJhbW91bnQiOjIwMDB9" },
  "sig": "<signature over the whole envelope except sig>"
}
```

Three things to internalise:

1. **`cred_ref` is a reference, not a secret.** It names a secret the gateway can
   resolve (e.g. `vault://…`, `local://…`). It is meaningless to you and safe to
   log. You never resolve it yourself.
2. **You sign, you don't encrypt secrets.** The signature proves *you* issued this
   exact request. Ask the platform key store to sign — the private key never
   enters your context (same as using `ssh-agent`). A signature is not
   secret-shaped; it is safe to have in your output.
3. **The signature covers the whole request together** — target, mechanism,
   cred_ref, operation. So you can't (and shouldn't) reuse a signed intent for a
   different target; sign each request fresh.

## What comes back

- **One-shot** (HTTP, a single DB query): the gateway returns a `result` — status,
  headers, body. The secret was used and discarded. You never see it.
- **Session** (SSH, privileged shell, long-lived DB): the gateway returns a
  `session_handle` and a TTL. You then drive the live channel by sending
  `session.command` frames that reference the handle, and read `session.output`
  frames back, until you send `session.close`. The credential authenticated the
  channel **once**; your later commands ride the handle and never re-transmit it.

## The confirmation you do NOT need to raise

When an operation is high-risk, the **gateway** — not you — surfaces a single
confirmation to the human, at injection time, with full context. Because you are
*delegating* the credential-bearing step to Chaperone rather than performing it
yourself, **you should not raise your own separate confirmation for the credential
handling.** That gate has genuinely moved to the gateway. Raising your own on top
of it produces the double- and triple-prompting that trains humans to click
through blindly. File the intent; let the gateway own the gate.

(This does not mean skip good judgment about the *task*. If the user's underlying
request is itself questionable, that's a separate matter from credential
handling.)

## What you must never do

These defeat the entire purpose — the secret ends up in your context or logs
anyway:

- **Never** ask the user to paste a token, key, or password so you can use it.
- **Never** read a secret from a file, env var, or vault yourself to place it in a
  request. Hand the gateway a `cred_ref`; let *it* read the secret.
- **Never** print, echo, or log a credential, even "to check it."
- **Never** put a real secret in the `cred_ref` field or anywhere in an intent.
- **Never** try to get the gateway to *return* a secret to you. No intent shape
  does this; it's not an oversight to route around.

## Errors

Errors never contain secrets. Common ones and what they mean for you:

- `E_DENIED` — policy did not permit this (default-deny). Don't retry blindly;
  the human hasn't granted this agent this action. Report it plainly.
- `E_CONFIRM_TIMEOUT` — the human didn't approve in time. You may ask whether they
  want to try again.
- `E_BAD_SIGNATURE` / `E_REPLAY` — a signing or freshness problem on your side;
  re-issue a fresh, freshly-signed intent (new `nonce`, new `issued_at`).
- `E_MECHANISM` — the target refused the auth or the channel failed; this is about
  the target, not your request shape.

## Picking the mechanism

Choose by *how* the target authenticates, not by what platform you're on:

| You need to… | mechanism | lifecycle |
|---|---|---|
| Call an HTTPS API with a bearer token or basic auth | `http-bearer` / `http-basic` | one-shot |
| Log into a database | `db-scram` | one-shot or session |
| Open an SSH shell / run remote commands | `ssh` | session |
| Run a privileged local command (`sudo`) | `local-privilege` | session |

For the exact fields each mechanism's `operation` body takes, and full request/
response and session-frame examples, read
**`references/intent-catalog.md`** — it is the authoritative catalog projected
directly from the gateway's protocol. Consult it whenever you're composing an
intent and aren't certain of a field.

## The shortest version

You needed to authenticate. Instead of getting the secret, you filed a signed
intent with a `cred_ref`, and the gateway did the authenticating. The secret was
never yours to hold — and that's exactly why nothing leaked.
