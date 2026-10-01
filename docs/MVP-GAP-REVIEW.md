# MVP Gap Review — Accountability, Proof, Fleet Scale, and Config UX

**Audience: implementation agents.** This document is the brief for the
next milestone. It picks up where
[END-USER-ONBOARDING.md](END-USER-ONBOARDING.md) leaves off: that pass asked
*"can a first-time user install this and get one brokered action?"* This pass
asks four different questions, all of which turned out to have answers in the
code rather than in the specs:

1. How do we handle a service class — SSH above all — with **hundreds of
   endpoints holding different secrets**?
2. The natural person is accountable. **How are they notified** when their
   authority is actually exercised through the proxy?
3. For POCs, demos, and general trust: **how do we *show* that the agent-facing
   stream contains no secret material?**
4. Have we taken the **intuitiveness of configuration** seriously?

Read [IMPLEMENTATION_AGENT_BRIEF.md](IMPLEMENTATION_AGENT_BRIEF.md) §3 first if
you haven't. Every recommendation below is constrained by those rules; none of
them asks you to weaken one.

## Citation key

**There is no `PROTO-SPEC.md`, and there never was one.** `PROTO-SPEC` is the
repo's shorthand *label* for the protocol specification, declared inside that
document's own header table, not a filename. The same holds for the other three
artifacts. Section numbers below (`PROTO-SPEC §9.3`) refer to the numbered
sections inside the linked file:

| Shorthand | File | Governs |
|---|---|---|
| `PROTO-SPEC` | [`docs/01-protocol-spec.md`](01-protocol-spec.md) | The wire contract. Canonical; wins over all others where they differ. |
| `ARCH-SPEC` | [`docs/02-architecture-spec.md`](02-architecture-spec.md) | Internal structure, vault abstraction, ephemerality rules. |
| `THREAT-MODEL` | [`docs/03-threat-model.md`](03-threat-model.md) | Adversaries, confused-deputy analysis, secure-fragility tenet. |
| `AGENT-SKILL` | [`docs/04-agent-skill.md`](04-agent-skill.md) | The agent-facing projection of the schema. |

`Dnn` references (`D37`, `D35`) are numbered decisions in
[DESIGN-DECISIONS.md](DESIGN-DECISIONS.md). `Pn-n` references to *previously
reported* items are in [END-USER-ONBOARDING.md](END-USER-ONBOARDING.md); `Pn-n`
IDs in the table below are this document's own and are independently numbered.

This shorthand is used unlinked throughout DESIGN-DECISIONS.md and in Rust
doc-comments across `crates/`, so it is worth learning once — and worth making
discoverable, which is P2-4 below.

---

## How these findings were produced — and their evidentiary status

**Read honestly, because this differs from the last pass.** END-USER-ONBOARDING
was written from a live install on real hardware; every claim in it was
reproduced. **This document was produced by reading source at commit `25d4085`
and by workspace-wide grep. Nothing here was verified by running the binary.**

**Reviewer re-baseline (hermes-ox-chap, 2026-09-26):** every "X is not wired to
Y" finding below was re-verified against main at `b9fd4f3` (43 commits after
`25d4085`, including #64 sponsor-binding and #65 RAE docs) and all still hold.
Two consequences of the re-baseline are folded in: the sponsor-binding gap in
P1-1 (added), and P0-0 — main's CI is currently red, which gates two items of
this document's own definition of done. Line-number citations may drift by a
line or two from `25d4085`; each finding names a one-command re-verification,
which is the durable form.

That distinction matters for how you work these items:

- Findings stated as **"X is not wired to Y"** are grep-complete over
  `crates/` and are high-confidence — absence of a call site is a fact you can
  re-verify in one command, and each such finding names the command.
- Findings stated as **behavioral** (P0-1 in particular) are inferred from the
  code path and **must be reproduced before they are fixed.** Each carries a
  reproduction recipe. If a reproduction fails, say so and close the item —
  that outcome is a good one, not a wasted pass.

Do not treat this document the way you would treat a reproduced QA report.
Reproduce first, then fix, then mark.

---

## Priority-ranked issues

| # | Issue | Tier | One-liner |
|---|---|---|---|
| P0-0 | Main's CI is red on all three platforms | Blocking | `cargo fmt --check` (6 diffs across 3 files), `cargo audit` (RUSTSEC-2026-0285, rustls 0.23.43 → upgrade to ≥0.23.45), `cargo deny`, and `clippy -D warnings` all fail on `b9fd4f3`. P0-2 and P1-1 acceptance require "green in CI on Linux, macOS, Windows" — unreachable until this is fixed first. Tests themselves pass on all three; the failures are hygiene, not the unix-only-events gap. |
| P0-1 | Response path relays a reflected credential back into agent space | Blocking | The README's central claim is written unconditionally; the HTTP injector returns target headers and body verbatim, so a reflecting target launders the secret straight into agent context |
| P0-2 | No test proves the no-leak property | Blocking | The guarantee is architectural, not demonstrated. There is no test that would fail if a secret leaked into agent-visible bytes |
| P0-3 | `notify_on_use` is a control that does nothing | Blocking | Parsed, round-tripped to TOML, rendered as a checkbox — and read by no consumer. The events feed broadcasts every decision regardless |
| P1-1 | ~~No notification consumer ships~~ MOSTLY SHIPPED (PRs #75/#76): `chaperone tail`, `sponsor_id` in feed, OS toast (`--toast`); Windows transport parity open | High | "The accountable person is notified" currently means "they happened to have a terminal attached to a Unix socket." On Windows even that is unavailable |
| P1-2 | ~~Policy expresses a cross-product, not a pairing~~ SHIPPED (PR #74, D43 pairs) | High | Independent axes mean one fleet rule permits *any* key against *any* host. Binding key→host costs one rule per host — and the over-permission is invisible in the rule text |
| P1-3 | ~~Session notification granularity is per-establishment, not per-use~~ SHIPPED (PR #75) | High | One SSH session = one event, then silence across every command relayed. This is the exact case D37 says notification exists for |
| P2-1 | The wizard is artifact-shaped; the user's task is intent-shaped | Medium | Setup walks vault → policy → audit key → enrollment. The user's mental model is one sentence, and it isn't that one |
| P2-2 | The rule editor has no decision preview | Medium | Four glob matchers with no "what would this allow?" feedback, against a matcher whose `*` spans `/` and `:`. `policy-check` already exists and is CLI-only |
| P2-3 | Vault-passphrase irreversibility is surfaced too late | Medium | No recovery path is a legitimate design choice; learning it at rotation time is how a user is lost permanently |
| P2-4 | Spec shorthand labels are undiscoverable | Medium | `PROTO-SPEC` and friends are cited unlinked across docs and dozens of source comments with no index mapping them to filenames; an implementation team reading this very document went looking for a file that does not exist |

Backlog items (explicitly deferred, recorded so they are roadmap and not
folklore) are in the final section.

---

## P0-0 — Main's CI is red on all three platforms

**What the state is.** At `b9fd4f3` (main, 2026-09-23), the `build-test-clippy`
matrix fails on ubuntu, macos, and windows; `fmt`, `audit`, and `deny` also
fail. The test suites themselves pass on all three platforms — the failures are
hygiene gates, not behavior:

- `cargo fmt --check`: 6 diffs across `crates/ui/src/setup.rs`,
  `crates/vault/src/local.rs`, `crates/vault/src/shared.rs`.
- `cargo clippy --all-targets -- -D warnings`: two unique warnings (an
  `expect()` on an `Option` and a redundant closure, both auto-fixable).
- `cargo audit`: RUSTSEC-2026-0285 — rustls 0.23.43, "TLS 1.3 handshake
  messages incorrectly accepted across encryption level boundaries"
  (medium, 5.3); fix is `rustls ≥ 0.23.45` — a `cargo update -p rustls` and
  re-lock.
- `cargo deny`: `advisories FAILED, bans ok, licenses ok, sources ok` — the
  same rustls advisory the audit job flags, surfaced through deny's
  advisories check. One `cargo update -p rustls` should clear both.

Re-verify in one command each: `cargo fmt --check`,
`cargo clippy --locked --all-targets -- -D warnings`,
`cargo audit --file Cargo.lock --ignore RUSTSEC-2023-0071`.

**Why it is P0 here.** This document's own definition of done demands
"green in CI on Linux, macOS, and Windows" for P0-2's `no_secret_leak` test
and P1-1's three-platform notification acceptance. A red baseline makes those
criteria unmeasurable — a new failing test hides inside existing noise. Fix
the baseline first; it is under an hour of mechanical work (`cargo fmt`,
`clippy --fix`, `cargo update -p rustls`, then re-run deny).

**One nuance worth stating:** the Windows CI failure is *not* the
unix-only events feed described in P1-1 — tests pass there. P1-1's Windows
gap is real but silent (the stub fails loudly at `listen()` and no test
exercises a notification end-to-end on Windows). P0-0 and P1-1 are independent
work items.

---

## P0-1 — Response path relays a reflected credential back into agent space

**What the code does.** `crates/injectors/src/http.rs` collects the target's
response headers (`resp_headers`, ~line 157) and body (`read_body_capped`,
~line 167) and returns both to the caller unmodified, subject only to the
`max_response_bytes` ceiling. There is no scrub of the resolved secret's bytes
on the return path. The module's own header comment is accurate about intent —
the response is relayed "as untrusted DATA (THREAT-MODEL §2.3)" — but untrusted
data that happens to contain our own credential is still our credential.

**Why it matters.** `README.md` states the guarantee with no qualifier:
*"without any credential ever entering the agent's context, transport, or
logs."* PROTO-SPEC §1.3 repeats it as a design tenet. A target that reflects
request headers falsifies that sentence in one call —
`https://httpbin.org/headers` does exactly this by design, and plenty of
internal debug and echo endpoints do too. This is not a flaw in the injection
model; it is a gap between an unconditional claim and a conditional property.
A hostile reviewer finds it in about five minutes, and finding it in *our*
headline claim costs more credibility than the bug itself is worth.

**Reproduce first.** Stand up a local endpoint that echoes its received
`Authorization` header into its response body. Store a distinctive sentinel as
the secret. File one `http-bearer` intent against it. Inspect the frames the
agent received. If the sentinel appears there, the finding holds.

**Recommended fix shape.** Two parts, both small:

1. **Scrub on relay.** Before returning, replace any occurrence of the
   resolved secret's bytes in response headers and body with a fixed redaction
   marker. Exact-match byte scan against the live `SecretString` buffer, inside
   the injector, before the secret is zeroized — so the comparison happens in
   the one frame that legitimately holds the material, and nothing new is
   retained. For session mechanisms, see backlog **S-1 (RESOLVED 2026-09-28)**:
   the primary defense is structural — non-echoing auth paths, so the secret
   never enters the relayed stream — with the whole-frame exact-match scrub
   kept as a cheap backstop where frame boundaries permit it.
2. **Make the claim honest in the same PR.** Either the claim is unconditional
   because the scrub makes it so, or it is stated with its boundary. After (1),
   the first option is available — take it, and note the mechanism in
   THREAT-MODEL §2.3 so a reader can see *why* it holds rather than being asked
   to trust it.

Doing (1) also makes P0-2's test pass against a hostile target, which is a
materially stronger demonstration than one that only passes against a
well-behaved one.

**Acceptance.** A test with a deliberately reflecting target: the secret is
present on the outbound wire, absent from every byte the agent receives.

---

## P0-2 — No test proves the no-leak property

**What exists.** The architecture delivers the property: `cred_ref` never
resolves in agent space, audit records carry the reference and not the secret
(PROTO-SPEC §9.3), error strings are scrubbed (`redacted_error`, D26), and the
fragility tenet governs the buffers. What does not exist is anything that
*fails* if that stopped being true. IMPLEMENTATION_AGENT_BRIEF §6 already
requires this — "every security rule in §3 gets an explicit test... a test that
no secret appears in logs" — and for this particular rule, the most important
one in the project, the test is absent.

**Why it matters.** Two reasons, and the second is the bigger one.

First, regression safety: every future injector, every new mechanism, every
error path is an opportunity to leak, and nothing currently catches it.

Second — and this is the answer to the POC/demo question — **an architectural
claim and a falsifiable claim are worth very different amounts to a skeptical
buyer.** Right now a prospect is asked to read specs and trust a design. A
named, runnable test that asserts the negative is a different kind of artifact:
it is the claim, mechanized, in a form they can execute against their own
build. That is the single highest-credibility thing this project can produce
for the effort involved, and it costs a day.

**Recommended fix shape — three layers, shippable independently.**

1. **The sentinel conformance test (do this one first).** Store a unique
   high-entropy sentinel as the secret. Run one intent per mechanism. Then
   assert the sentinel's bytes appear in **zero** of: the agent-facing frames,
   the audit chain records, gateway stdout/stderr, the events feed, the policy
   file, and every error response — and in **exactly one** place, the outbound
   wire (captured by a local target that reports what it received). Give it a
   name we can point at in a README and a sales conversation:
   `cargo test --test no_secret_leak`. Run it in CI on all three platforms.

2. **A two-pane demo recording.** Left pane: a `tee` of the agent socket,
   showing an intent that carries only `local://demo/token`. Right pane: the
   local target printing the `Authorization` header it actually received. Same
   timestamps, side by side. The agent channel is already plaintext JSON with
   `Content-Length` framing (PROTO-SPEC §3.2), so this requires no new
   capability — it is a recording, not a feature. A non-technical viewer
   understands it in about ten seconds, which is more than can be said for any
   paragraph we could write instead.

3. **`serve --transcript <path>`** — writes exactly what the agent saw, as a
   signed artifact alongside the audit chain, so a prospect can run their own
   workload and inspect it afterward rather than trusting our demo workload.
   This is the enterprise form of (2) and can follow later; note that the
   transcript is agent-visible data by construction, so it inherits the same
   no-secret property (1) asserts — and (1) should assert it over the
   transcript too, once it exists.

**Acceptance.** (1) exists, is named in the README, is green in CI on Linux,
macOS, and Windows, and fails if the scrub from P0-1 is reverted. "Green on
Windows" carries the precise meaning fixed by **S-2 (RESOLVED 2026-09-28)**:
every existing surface asserted clean, the unix-only events-feed surface
skipped *with its name recorded in the test output* (not silent), and the
Windows stub's loud-failure strings asserted secret-free.

---

## P0-3 — `notify_on_use` is a control that does nothing

**What the code does.** `Rule.notify_on_use` is a real field
(`crates/policy/src/lib.rs:95`), defaults to `true` per D37
(`crates/policy/src/lib.rs:288`), round-trips through the canonical TOML
writer, and is rendered as an operator checkbox with the label *"notify me when
this credential is used (on_use)"* (`crates/ui/src/pages.rs:653`). It is
covered by policy tests and a UI test.

Nothing reads it. The broadcast site
(`crates/gateway-core/src/lib.rs:1051`) fires on every terminal intent
decision unconditionally; `notify_on_use` is not consulted there or anywhere
else outside policy's own parse/write path and the UI form.

Re-verify in one command:

```sh
grep -rn "notify_on_use" --include="*.rs" crates/
```

Every hit will be in `crates/policy/`, `crates/ui/`, or their tests.

**Why it matters.** This is worse than a missing feature: it is a shipped
control that misrepresents system behavior to the operator, in the security
surface, in the direction of false comfort. An operator who unchecks the box
believes they have silenced a rule and has not. An operator who checks it
believes they have enabled something that was already on. Both are wrong, and
D37's whole argument — that quiet must be opt-out because silence is the bug —
depends on the flag having an effect.

It is also, specifically, the kind of thing that gets discovered live in a
demo by someone poking the UI.

**Recommended fix shape.** Consult `notify_on_use` from the matched rule at
the broadcast site and suppress the broadcast when false. Two constraints:

- **Denies broadcast regardless.** D35 is explicit that repeated quiet refusal
  is itself signal, and default-deny lands on the structural floor where there
  is no rule and therefore no flag. Suppression applies to `allow` and
  `needs_confirmation` outcomes under a rule that opted out.
- **The audit chain is never suppressed.** `notify_on_use` governs the live
  feed only. The record is written either way; that separation is what keeps
  a notification preference from becoming an evidence preference.

**Acceptance.** A rule with `on_use = false` produces an audit record and no
event-feed line; the same rule with `on_use = true` produces both; a deny
produces both regardless of the flag.

---

## P1-1 — No notification consumer ships, and Windows has no channel at all

**MOSTLY SHIPPED (PRs #75 + #76, 2026-09-30).** Items 1 and 2 and the sponsor
gap are done; only item 3 (Windows transport parity) remains open:

- **SHIPPED — `chaperone tail`** (item 1): subscribes to the feed and renders
  one human-legible line per event (`[decision] allow human@example.org via
  agent:x ssh/ssh://host`, `[session summary|heartbeat] … N cmd(s), NB in,
  NB out, Ns elapsed`, `[POLICY DRIFT] …`); unknown types pass through as
  compact JSON rather than being dropped. Serve's socket-binding message now
  names the command. Unix-only by construction until item 3 lands (Windows
  has no feed transport yet — same S-2 skip-with-record posture).
- **SHIPPED — feed names the accountable human:** `sponsor_id` is in the
  `decision` payload and in every session event; `tail` renders it as
  `sponsor via agent`. Consumer-side join was chosen over adding
  `sponsor_name` to the payload (D35 "no new facts" stays trivially true;
  the enrollment store remains the one source for display names). P0-2's
  sentinel already asserts the feed line secret-free and passes unchanged.
- **SHIPPED — OS-native toast** (item 2, PR #76): `chaperone tail --toast`
  pushes events to the desktop notification daemon via `notify-rust` (one
  maintained cross-platform crate, as prescribed: zbus/dbus on Linux,
  UserNotifications on macOS, WinRT on Windows). Consumer-side by design —
  the daemon is headless-deployed; the operator running `tail` has the
  session bus. A pure event→(title, body, urgency) mapper
  (`cli/src/toast.rs`, 7 unit tests, headless-safe): denials,
  confirmation gates, and policy drift are Critical; allows and session
  summaries Normal; heartbeats Low; unknown types don't interrupt.
  Delivery is best-effort: failure warns once on stderr and the terminal
  render continues — proven live on a daemonless box (real dbus
  `ServiceUnknown`, warn-once fired, tail kept working).
- **OPEN — Windows transport parity** (item 3: named-pipe feed + console
  parity). Item 3 also unshrinks the S-2 skip list without a test rewrite.

**What exists.** A read-only fan-out socket
(`crates/gateway-core/src/events.rs`, D35) broadcasting one JSON line per
terminal decision to unlimited subscribers. The design is right and the
transport reasoning in D35 is sound.

**What is missing, in two parts.**

*No consumer.* There is no `chaperone tail`. The CLI dispatch table
(`crates/cli/src/main.rs`, ~line 1152 onward) has no such subcommand; binding
the socket prints *"event feed listening on {path} (tail with any stream
reader)"* (`crates/cli/src/main.rs:950`). There is no desktop notification, no
menubar item, no webhook, no mail path. Operationally, "the accountable natural
person is notified" currently resolves to "the accountable natural person
happened to have a terminal attached to a Unix domain socket at the moment the
action occurred."

*No Windows channel.* `pub mod console` is `#[cfg(unix)]`
(`crates/gateway-core/src/lib.rs:36`), and the functional half of `events` is
too — the non-unix `EventHub` is a stand-in whose `broadcast` drops lines. So
on Windows the accountable person has **neither** a confirmation channel nor a
notification channel. P1-3 and P2-1 in END-USER-ONBOARDING made these fail
loudly rather than lie, which was the correct first move; the capability is
still absent. Windows is also where our one real end-user QA pass took place.

*The feed doesn't name the accountable person (added at re-baseline — this
post-dates the original pass).* #64 (RAE L0, `b1d2f17`) bound every enrolled
agent to a named human sponsor: `AuditEvent` now carries `sponsor_id`
(`crates/audit/src/event.rs:139`), and the broadcast site has the populated
value in scope — `event.sponsor_id` is set a dozen lines above the
`hub.broadcast(...)` call (`crates/gateway-core/src/lib.rs`, ~1044–1064) — but
the serialized JSON line omits it: the payload carries `audit_id`, `agent_id`,
`effect`, `mechanism`, `target_uri`, `outcome` and nothing else. So even once a
notifier ships, the notification can say "planner-7 used local://ssh/fleet/app-01"
but not "*whose* authority was exercised" — the one fact the accountability
story is about. Re-verify: `grep -n "sponsor" crates/gateway-core/src/lib.rs |
grep broadcast` (no hits) vs `grep -n sponsor_id crates/audit/src/event.rs`
(the field exists). Fix is nearly free at the broadcast site and preserves
D35's "no new facts — a live tap on data the audit chain already produces":
`sponsor_id` *is* audit-chain data, the tap just isn't tapping all of it.
Add it to the broadcast payload (and `sponsor_name` for human-legible toasts,
or let the consumer join it), and extend P0-2's sentinel test to assert the
feed's new field carries a reference, never credential material — D35's
property, unchanged.

**Why it matters.** This is the load-bearing gap for the accountability story.
Everything else in the system — signed intents, attribution, the audit chain —
establishes *who is responsible after the fact*. Notification is the only
mechanism that tells the responsible person *while it is happening*, and it is
the piece a non-technical stakeholder actually pictures when they hear
"accountable." Shipping attribution without notification means the person
learns of their own exercised authority by reading a hash chain.

**Recommended fix shape.** One notifier, working on all three platforms.
Resist the urge to build three.

1. **`chaperone tail`.** Subscribe to the feed, print one human-legible line
   per event. Trivial to write, immediately useful in every demo, and it makes
   the feed real rather than theoretical. Ship this first.
2. **OS-native toast** behind a config flag, via a maintained
   cross-platform notification crate. Title = the decision, body = agent ·
   mechanism · target label. No secret material is in the feed by construction
   (the fields are exactly what `audit-export` already produces, per D35), so
   the notification surface inherits that property — assert it in P0-2's test.
3. **Windows transport parity.** Put the events feed behind a named pipe with
   the same owner-only discipline the UDS path uses. The privileged-helper
   protocol is already described as platform-neutral; the same reasoning
   applies here. Do the console socket in the same pass — a confirmation gate
   no one can answer is a fail-closed timeout, which is safe and useless.

**Acceptance.** On each of Linux, macOS, and Windows: a brokered action
produces a visible notification to a person who is not watching a terminal, and
a `needs_confirmation` decision can be answered. The notification names the
responsible human — the events feed carries `sponsor_id` (and a
human-legible name, or enough for the consumer to resolve one) — not merely
the agent id.

---

## P1-2 — Policy expresses a cross-product, not a pairing

**This is the answer to the SSH-fleet question, and it is a policy-engine
problem rather than a vault problem.**

**What already works.** `cred_ref` is an opaque `scheme://path` routed by
scheme to a provider (`crates/vault/src/provider.rs`, dispatch at ~line 114).
Nothing caps cardinality: three hundred hosts is three hundred vault entries
(`local://ssh/fleet/app-01`, …) and that functions today. The host-key pin
store is already keyed per `hostport`
(`crates/gateway-core/src/known_hosts.rs`), so per-endpoint *server* identity
is handled and a changed key is a hard refusal.

**The problem.** `Rule` matches four **independent** axes — `agent_id`,
`cred_ref`, `target_uri`, `mechanism` — each its own `Matcher`, first match
wins (`crates/policy/src/lib.rs`). Independent axes express a cross-product.
This rule:

```toml
cred_ref   = "local://ssh/fleet/*"
target_uri = "ssh://*.internal"
```

permits **any** fleet key against **any** fleet host. Binding key to host
requires one rule per host: N hosts, N hand-maintained rules, and the
maintenance burden lands on exactly the operator least equipped to carry it.

Compounding it: `crates/policy/src/matcher.rs` documents in its own header
that `*` spans **all** characters including `/` and `:`, so the intuitive glob
an operator reaches for over-permits in a way that is not visible in the rule
text. The engine is behaving exactly as designed and documented; the gap is
that the design has no way to say the thing operators need to say.

**Why it matters.** Two distinct costs. The operational one is the scaling
wall: this design does not survive a real fleet. The security one is quieter
and worse — today's fleet rules silently grant more than their author believes,
and nothing in the UI or the CLI reveals the gap between intent and effect.
That makes this a correctness issue, not only an ergonomics issue, which is why
it sits at P1 rather than in the backlog.

**Recommended fix shape.**

1. **Add correlation to the rule language.** Either capture substitution —
   `target_uri = "ssh://*.internal"` with
   `cred_ref = "local://ssh/fleet/${target.host}"` — or an explicit `pairs`
   table. Substitution is the more expressive option and collapses N rules
   into one; a `pairs` table is more boring and more auditable, which given D3's
   stated preference for boring may be the better trade. **Make this call
   explicitly and record it in DESIGN-DECISIONS.md.** Either way the change is
   contained entirely within `chaperone-policy`, requires no protocol change,
   and is straightforwardly testable.
   > **CALLED (Stephen, 2026-09-30): `pairs` table — recorded as D43.** Full
   > analysis in `docs/research/p1-2-correlation-analysis.md`. Decisive: pairs
   > keeps matching first-order (substitution composes an agent-controlled
   > captured string into the pattern that selects credentials — the
   > confused-deputy posture argues against it, and the paper verifies a
   > concrete capture-injection case), and a pairs rule's permission set is
   > readable rather than simulated. Implementation slice may be tasked.
2. **Then bulk inventory import.** `chaperone vault import` fed by
   `~/.ssh/config`, `known_hosts`, or a CSV, creating entries **and** the
   paired rule in one action. Only worth building after (1) exists — without
   correlation it generates the N-rule sprawl rather than removing it.
3. **Fix the docs' implied shape now, cheaply.**
   [CONNECTIVITY-MATRIX.md](CONNECTIVITY-MATRIX.md) currently reads as though
   per-host keys are the intended model for SSH. State that the intended model
   at fleet scale is a certificate authority (see backlog B-1) and that
   per-host keys are the v1 shape. A reader with fleet operations experience
   will otherwise conclude we have not thought about scale, which is a worse
   impression than admitting the roadmap.

**Acceptance.** A single rule expresses "each fleet key may be used only
against its own host," and a test proves key A cannot reach host B under it.

---

## P1-3 — Session notification granularity is per-establishment, not per-use

**SHIPPED (PR #75, 2026-09-30).** The fix shape below is implemented as
specified: in-memory per-session counters (`record_relay` at the relay site,
never at the audit site), `session.summary` on both teardown paths (client
close *and* TTL reap — lazy expiry alone would never surface an abandoned
session), `session.heartbeat` from a liveness scan at
`--session-heartbeat-secs` (default 300; 0 disables beats but reaping
continues), idempotent per window. Per-command detail stays in the audit
chain; the audit chain itself is unchanged by this slice (feed-only events).
Acceptance is pinned by `tests/session_events.rs`: counters accurate
(commands/bytes_in/bytes_out), summary carries sponsor + mechanism + target
references and **no relayed content** (asserted against the command text and
the simulated key PEM), heartbeat fires once per window, TTL reap emits the
summary.

**What the code does.** The broadcast fires once per terminal intent decision.
For a brokered SSH or DB session, that is one event at establishment. The next
three hundred commands relayed into that pty produce no notification at all.
The session does write its audit record at teardown, so the evidence exists —
but the live signal does not.

**Why it matters.** D37 argues that notification defaults to on precisely
because *"brokered sessions after one-time approval"* are the case where no
prompt would otherwise ever surface use. The implementation surfaces exactly
one event for exactly that case. The accountability claim is therefore weakest
where its own design rationale says it matters most, which is the kind of
inconsistency a careful reviewer will find and a careless one will ship.

**Recommended fix shape.** Do not notify per command — that is noise, and it
would make long sessions unusable. Instead:

1. **A session-summary event at `session.closed`**: commands relayed, bytes in
   and out, duration, exit reason. One event, high information density.
2. **A heartbeat for long-lived sessions** — a periodic event while a session
   remains open past a configurable threshold, so an unattended session cannot
   run for hours in silence. The threshold belongs in config, not in code.
3. Keep per-command detail in the audit chain, where it already belongs.

**Acceptance.** A ten-minute SSH session produces an establishment event, at
least one heartbeat, and a summary at teardown; the audit chain is unchanged.

---

## P2-1 — The wizard is artifact-shaped; the user's task is intent-shaped

**Credit where it is due, because the baseline here is better than most
projects at this stage.** The setup wizard exists and each step names the real
file it writes (`crates/ui/src/setup.rs`). The rule editor offers service
templates prefilled from the connectivity matrix, carrying maturity badges so
an operator sees a mechanism's caveats *before* building a rule on it
(`crates/ui/src/matrix.rs`) — that is a genuinely thoughtful piece of design.
D36's rule that the UI is a thin client over the same validators as the CLI is
correct and worth defending. And doing a live install QA pass and writing down
what actually happened is an instinct most projects skip entirely.

**The remaining friction is the mental model, not the forms.** Before a single
action brokers, a first-time operator must hold five new concepts: agent
enrollment and identity, `cred_ref` and its scheme, the four policy axes, the
effect trichotomy, and the vault passphrase lifecycle. The wizard walks
*artifacts* — enrollment store, policy file, audit key, vault — which is the
implementer's decomposition of the problem. The user's decomposition is one
sentence:

> *Let this agent use this credential against this thing, and tell me when it
> does.*

Every noun in that sentence maps to something the system already has. Nothing
in the UI is organized around the sentence.

**Recommended fix shape.** A **"Connect a service"** flow that produces all
four artifacts in one submit: pick a template → paste the secret → name the
agent → receive a working rule, a vault entry, an enrolled identity, and a
copy-pasteable test command. Every primitive already exists behind it; this is
composition, not new capability, and it does not violate D36 because it calls
the same validators in the same order.

Keep the existing artifact-shaped wizard as the advanced path. Some operators
genuinely want it, and it is the one that maps to the CLI.

**Acceptance.** A first-time operator goes from a running daemon to a brokered,
audited action without reading PROTO-SPEC and without typing a CLI command.

---

## P2-2 — The rule editor has no decision preview

**What the code does.** The rule form collects four glob matchers
(`crates/ui/src/pages.rs`, rule editor ~line 520 onward). There is no feedback
about what the resulting rule would actually permit. Meanwhile
`cmd_policy_check` already exists (`crates/cli/src/main.rs:175`) and does
exactly the needed evaluation — it is simply CLI-only.

**Why it matters.** Four independent glob matchers is an expert interface, and
it sits on top of a matcher whose `*` spans `/` and `:` (P1-2). The operator
most likely to write an over-permissive rule is the one least likely to read
`matcher.rs`'s header comment. Surfacing the decision is therefore a security
control wearing a UX costume — and the engine to power it is already written
and already tested.

**Recommended fix shape.**

1. **A live plain-language preview** under the form: *"This rule would allow:
   agent `planner-7` · using any `local://ssh/fleet/*` credential · against any
   `ssh://*.internal` target."* Generate it from the parsed `Rule`, not from
   the raw form strings, so it reflects what the validator actually produced.
2. **A test box**: paste an agent id, a `cred_ref`, and a target URI; see the
   verdict, which rule matched, and its index. This is `policy-check` rendered
   in HTML — per D36, call the same code, do not reimplement the evaluation.
3. **Warn on the boundary case.** When a submitted glob contains `*` adjacent
   to a `.` or `/` in a hostname or path position, show the caveat inline. Not
   a block — a sentence, at the moment it is relevant.

**Acceptance.** An operator can see what a rule permits before saving it, and
can test a concrete request against the saved ruleset without leaving the UI.

---

## P2-3 — Vault-passphrase irreversibility is surfaced too late

The local vault has no recovery path. That is a defensible design choice and
D19 argues it adequately. The problem is *when* the user learns it: today,
realistically, at rotation or recovery time, which is the worst possible moment
and the one that converts a design choice into a betrayal.

**Fix shape:** one sentence at vault-creation time in the wizard, stating
plainly that a lost passphrase means lost secrets with no recovery, and naming
the backup procedure from [LOCAL-VAULT-GUIDE.md](LOCAL-VAULT-GUIDE.md) in the
same breath. Not a modal, not a scare screen — a sentence, at the moment it is
actionable.

**Acceptance.** The irreversibility statement and the backup pointer appear on
the vault-creation step, before the passphrase field.

---

## P2-4 — Spec shorthand labels are undiscoverable

**How this was found.** An implementation team reading the first draft of this
document reported that `PROTO-SPEC.md` "isn't checked in anywhere." They were
right about the filename and wrong about the conclusion — and the confusion was
this document's fault, not theirs.

**The actual state.** Each of the four artifacts declares a shorthand label in
its own header table at line 7 — `PROTO-SPEC`, `ARCH-SPEC`, `THREAT-MODEL`,
`AGENT-SKILL` — and every other document and source comment then cites the
shorthand. Verify:

```sh
grep -rn "PROTO-SPEC" --include="*.md" docs/ | grep -v 01-protocol-spec
grep -rln "PROTO-SPEC" --include="*.rs" crates/
```

DESIGN-DECISIONS.md cites it roughly twenty times, always unlinked. Ten-plus
Rust modules cite it in doc-comments. Nothing maps the label to a path:
`docs/README.md` lists all four documents by their *prose titles* ("Protocol
Specification") and never mentions the shorthand at all. Only
IMPLEMENTATION_AGENT_BRIEF.md §2 binds the two together, and only for a reader
who arrives there first.

**Why it matters.** Every agent or contributor who enters the docs at any point
other than the brief hits a dead reference on their first citation. That is a
tax on exactly the audience we most want to move quickly, and it costs one
table column to remove. It also erodes confidence in the surrounding document:
a reader who cannot resolve one citation reasonably discounts the rest.

**Fix shape.** Two lines of work:

1. **`docs/README.md`** — add a `Label` column to the four-document table so
   the shorthand is bound to the path in the place a reader lands first. Done
   in the same pass as this document.
2. **A `Dnn` decision** recording that the shorthand labels are the citation
   convention, so the next contributor adds a label rather than inventing a
   second scheme.

Do **not** rename the files to `PROTO-SPEC.md`. The numeric prefixes encode
reading order, which is load-bearing in the brief, and the labels are already
referenced from source comments that would all need touching.

**Acceptance.** A reader who opens `docs/README.md` cold can resolve
`PROTO-SPEC §9.3` to a file and a section without searching.

---

## What we deliberately will not do

Recorded so these do not get re-litigated in a review, and so no one
"helpfully" adds one:

- **No JS framework in the config UI.** D40's server-rendered posture holds.
  Every improvement in P2-1 and P2-2 is achievable with forms and a round trip.
- **No "simple mode" that writes rules the CLI would refuse.** D36 exists
  precisely to prevent the class of bug where one front end can create a state
  the other rejects. A friendlier flow must produce the same validated
  artifacts through the same code path.
- **No suppressing audit records via `notify_on_use`.** The flag governs the
  live feed only. Conflating a notification preference with an evidence
  preference would hand any operator a quiet switch for the one thing that
  must not have one.
- **No permissive or demo mode.** Already an anti-goal in
  CONNECTIVITY-MATRIX §2. The demo in P0-2 runs under default-deny with a real
  rule, or it is not a demo of this product.

---

## Backlog — deferred, with reasons

- **B-1 — SSH certificate authority / dynamic minting.** The real answer to
  fleet scale: one CA credential, short-lived signed certificates, no per-host
  secret in the vault at all. `mint()` is already named in the post-v1 backlog
  (D29/D30). P1-2 is the v1 shape that makes fleets survivable until this
  lands; it is not a substitute for it. Say so in the matrix.
- **B-2 — Bulk inventory import.** See P1-2 item 2. Sequenced after
  correlation, not before.
- **B-3 — `serve --transcript`.** See P0-2 layer 3. Wanted for enterprise
  evaluation; not needed for the first credible demo.
- **B-4 — Type-level secret-free audit/error paths (S-3 option 2, deferred by
  Stephen 2026-09-28).** Make the S-3 property structural rather than
  test-enforced: the audit/error constructors accept only a reference-shaped
  facts type (e.g. an `AuditFacts` struct), so response bytes are unreachable
  from the recording path — you cannot log what you cannot touch. Same
  philosophy as the licensing design's structural non-enforcement ("no
  `disable()` exists to call"). **Gating note: likely required BEFORE SafeKeyPass
  (Chaperone Enterprise) ships** — the enterprise tier sells defensible
  evidence to compliance buyers, and "the audit path is secret-free by
  construction" is a materially stronger claim than "a test asserts it."
  Moderate cost: an API refactor of the injector→audit boundary. Revisit at
  SafeKeyPass spec time at the latest; until then S-3 option 1 (normative
  sentence + reflecting-target sentinel coverage) holds the line.

**Decide-during-spec (raised in review of this document, 2026-09-26; each is a
design decision the fix-shape sections above deliberately leave open, recorded
here so they are decided explicitly rather than discovered mid-slice. All
three have since been ruled by Stephen, 2026-09-28):**

- **S-1 — Streaming scrub for session mechanisms (P0-1 fix, part 1). RESOLVED
  (Stephen, 2026-09-28): option 3 — no-relay-of-echo.** Session mechanisms do
  not scrub a byte stream; they are built so the resolved secret cannot appear
  in relayed output at all — credentials never traverse an echoing pty (SSH
  key auth from the vault, `SSH_ASKPASS`-style protocol-level handshakes, and
  equivalent non-echoing paths per mechanism). Consequences:
  - P0-1's "apply identically to the session mechanisms' relayed output" is
    replaced: the HTTP scrub (whole-response, exact-match, before zeroize)
    stands as written; for session mechanisms the requirement is the
    *non-echo property*, asserted per mechanism, not a stream scrub. No
    hold-back windowing machinery is built.
  - P0-2's `no_secret_leak` test gains a session-mechanism case asserting the
    sentinel never appears in relayed output — which under this decision is a
    test of the auth path's echo-freedom, including any mechanism-specific
    edge (e.g. a server that echoes its input banner).
  - Mechanisms whose protocols cannot guarantee non-echo are **not connected
    to** until they can. Coverage extends as gaps are found; each addition is
    release-notes material and strengthens the public story ("we keep adding
    services under the same unconditional no-leak guarantee") rather than
    diluting it. The connectivity matrix is the honest surface for what is and
    isn't supported.
  - One residual for the spec to state: non-echo covers *our* relay path; a
    target that independently logs or displays the credential it received
    (then echoes that display back) is the same reflected-secret class as
    P0-1's HTTP case. For session mechanisms the P0-1 exact-match scrub is
    therefore still applied where a whole-frame scan is possible (command
    output frames), as a cheap backstop — it is not the primary defense and
    its boundary-split limitation is acceptable *because* the primary defense
    is structural.
- **S-2 — Windows assertion surfaces for `no_secret_leak` (P0-2). RESOLVED
  (Stephen, 2026-09-28): option 1 — skip-with-record, plus stub error-string
  assertions.** The surface list splits into what exists per platform:
  - **Asserted everywhere (Linux, macOS, Windows):** agent-facing frames,
    audit chain records, gateway stdout/stderr, the policy file, every error
    response, and the outbound wire (exactly-one-place check). These surfaces
    are platform-independent and the test runs them in full on all three.
  - **Skipped-with-record on Windows (until P1-1 named-pipe parity):** the
    events feed — the only `#[cfg(unix)]` entry in P0-2's surface list. (The
    console/confirmation channel is unix-only too, but it is not a
    `no_secret_leak` surface: it carries confirmation prompts and answers,
    never the resolved secret. Its Windows parity is a P1-1 concern, tracked
    there.) The Windows test run **enumerates the skipped surface in its
    output** ("events feed: SKIPPED — no Windows transport until named-pipe
    parity, tracked in P1-1") rather than passing silently. CI green on
    Windows then means precisely "every existing surface is clean, and the
    gap is named" — not "all surfaces checked."
  - **Stub error-strings are still asserted (option 4 folded in):** the
    Windows `EventHub::listen()` fails loudly (`"events socket not implemented
    on this platform"`, issue #43) and `broadcast` is a documented no-op that
    drops lines. The test asserts these stub paths cannot carry secret
    material — i.e. the loud-failure strings contain no sentinel — so even the
    absent surface's *error text* is proven clean rather than assumed.
  - **Implementation shape:** the test enumerates surfaces from a small
    platform-capability map (not scattered `#[cfg]` branches), so when
    named-pipe parity lands the Windows skip list shrinks and coverage
    tightens with no test rewrite. This keeps P0-2's "green on all three
    platforms" honest without waiting on P1-1's larger transport slice.
- **S-3 — Audit-path assertion in the P0-1 scrub (P0-1/P0-2 boundary).
  RESOLVED (Stephen, 2026-09-28): option 1 now — normative sentence +
  sentinel coverage; option 2 (type-level enforcement) deferred to backlog
  B-4, likely required before SafeKeyPass ships.** Concretely:
  - The spec carries one normative sentence: *"No audit record, error string,
    log line, or event-feed payload may incorporate response bytes (headers or
    body) from which the resolved secret could be reconstructed; error and
    audit content is limited to request-side facts, references, and redacted
    transport diagnostics."* (Verified against current code when ruled: the
    property already holds — `http.rs` errors are built from transport errors
    via `redacted_error`, request-side facts, and limits; `AuditEvent` records
    references and envelope evidence, never response bytes. S-3 exists so the
    property survives the next contributor's "helpful" debug addition.)
  - P0-2's sentinel test asserts the audit-record and error-response surfaces
    against the **reflecting target** (P0-1's hostile endpoint), so any future
    response-echoing error or record path fails the test immediately.
  - Structural hardening (constructors that cannot receive response bytes) is
    B-4, with the SafeKeyPass gating note recorded there.

---

## Definition of done for this milestone

1. Main's CI is green on Linux, macOS, and Windows — fmt, clippy, audit, deny
   — before any other item is claimed done, because items 3 and 5 are
   unmeasurable against a red baseline (P0-0).
2. A reflected credential cannot reach agent space, and the README's
   unconditional claim is true as written (P0-1).
3. `cargo test --test no_secret_leak` exists, is named in the README, and is
   green in CI on Linux, macOS, and Windows (P0-2).
4. `notify_on_use` governs the event feed; denies always broadcast; audit
   records are never suppressed (P0-3).
5. A brokered action produces a visible notification — naming the responsible
   human, not only the agent — to a person who is not watching a terminal, on
   all three platforms, and a `needs_confirmation` decision can be answered on
   all three (P1-1).
6. One rule can bind each credential to its own endpoint, with a test proving
   key A cannot reach host B (P1-2).
7. A long-lived session produces establishment, heartbeat, and summary events
   (P1-3).
8. A first-time operator reaches a brokered, audited action through the UI
   without reading a spec or typing a CLI command (P2-1).
9. The rule editor shows what a rule permits before it is saved (P2-2).
10. A reader who opens `docs/README.md` cold can resolve `PROTO-SPEC §9.3` to a
    file and section without searching (P2-4).

Items S-1 through S-3 in the backlog are decisions the spec must record before
the corresponding slices are worked; they are done when decided and written
down, not when code lands. All three are decided (Stephen, 2026-09-28): S-1
(no-relay-of-echo), S-2 (skip-with-record per-platform surfaces plus stub
error-string assertions), S-3 (normative sentence plus reflecting-target
sentinel coverage; structural hardening deferred to B-4).

Treat P0 items as blocking any demo to anyone outside the current contributor
set — not because the system is unsafe without them, but because P0-1 and P0-2
together determine whether our central claim is *demonstrated* or merely
*asserted*, and P0-3 is a control that currently tells an operator something
untrue. Those are the three that a serious evaluator will test first.
