# P2-1 + P2-2 implementation plan — for review by Heph (release engineering)

Author: ox-chap (Hermes, host 192.168.101.11)
Date: 2026-10-03
Baseline: `main` @ `92ed67e` (PR #77 merged, 8/8 CI)
Source findings: `docs/MVP-GAP-REVIEW.md` §P2-1, §P2-2
Status: **proposal — nothing implemented, no branch pushed, awaiting review**

---

## 0. What I verified before planning (not transcribed from the gap review)

Every claim below was checked against the tree at `92ed67e`. File:line references
are the current truth, not the review's.

| Claim | Verified how |
|---|---|
| `policy-check` is CLI-only | `cmd_policy_check` at `crates/cli/src/main.rs:203`, dispatched at `:1345`. No UI route calls it. |
| The engine to power a preview already exists | `Policy::evaluate(&Request) -> Decision` at `crates/policy/src/lib.rs:479`, `#[must_use]`, total and side-effect-free |
| The UI crate already depends on the policy crate | `chaperone-policy = { path = "../policy" }` in `crates/ui/Cargo.toml` — **no new dependency needed for P2-2** |
| A rule preview can be generated from the parsed `Rule`, not raw form strings | `RuleForm` → real `Rule` construction happens in `rules_add` (`crates/ui/src/pages.rs:766`); the `axis` closure maps empty→`Matcher::Any`, else `Matcher::parse(raw)` |
| The verdict string the preview/test box needs is already formatted | `main.rs:242-254` formats `rule[{index}] ({name}) pair[{p}]` — reusable verbatim so UI and CLI cannot drift |
| Matcher has no describe/summary helper | `crates/policy/src/matcher.rs` exposes only `parse` (:42), `matches` (:60), `source` (:75). **P2-2 needs one new small helper — see §3.** |
| Every primitive P2-1 needs already exists in the UI | `/setup/*` (`lib.rs:48-54`), `POST /secrets/store` (`pages.rs:236`), `POST /agents/enroll` (`pages.rs:394`), `POST /rules/add` (`pages.rs:766`) |
| A UI test harness with 18 existing tests to extend | `crates/ui/tests/ui_http.rs`, incl. `rule_editor_round_trips_through_the_one_validator` (:324) and `rule_editor_parses_pair_bindings` (:416) |

**Net finding: both items are composition over existing, tested code.** The only
new *logic* in either slice is a `Matcher` describe helper (§3.1). This is the
single most important thing for you to sanity-check, because if it is wrong the
estimates in §5 are wrong too.

---

## 1. What P2-1 and P2-2 are, in one paragraph each

**P2-1 — the wizard is artifact-shaped; the operator's task is intent-shaped.**
Today a first-time operator must hold five concepts (enrollment, `cred_ref` +
scheme, four policy axes, effect trichotomy, vault passphrase lifecycle) and the
wizard walks *artifacts* in that order. The user's actual sentence is one line:
*"Let this agent use this credential against this thing, and tell me when it
does."* Every noun in that sentence already exists in the system; nothing in the
UI is organised around it. Fix: a **"Connect a service"** flow that produces all
four artifacts in one submit. Keep the existing artifact-shaped wizard as the
advanced path — some operators want it and it is the one that maps 1:1 to the CLI.

**P2-2 — the rule editor has no decision preview.** The editor collects four
independent glob matchers and gives no feedback on what the result permits, over a
matcher whose `*` spans `/` and `:`. The operator most likely to write an
over-permissive rule is the one least likely to read `matcher.rs`'s header. The
gap review's own framing is the right one: **this is a security control wearing a
UX costume.** The engine exists and is tested; it is just CLI-only.

---

## 2. Sequencing and why

**P2-2 first, in its own PR. Then P2-1.**

Reasoning:

1. **P2-2 is strictly smaller and lower-risk** — three additive read-only
   affordances, no new write path, no new artifact, nothing to migrate. It is
   reviewable in one sitting.
2. **P2-1 should not be built before P2-2 exists.** P2-1's flow ends by handing
   the operator a freshly-minted rule. If that rule's preview isn't there yet,
   the very first thing a new operator sees in the new flow is a rule they cannot
   inspect — reproducing the exact failure P2-2 exists to fix. Building P2-2
   first means P2-1 ships with the safety surface already in place.
3. P2-2 is also the **falsifiability donor** for P2-1: the test box introduced in
   P2-2 is exactly the harness P2-1's acceptance test needs.

If you disagree with this ordering, say so and I'll flip it — the dependency is
argumentative, not structural.

---

## 3. P2-2 — decision preview

### 3.1 The one new piece of logic: `Matcher` → plain language

Today the UI reconstructs an axis for display with a private `axis_text` helper
(`pages.rs:566`) that falls back to the literal `"*"`. That is display-by-hack and
it cannot express `Matcher::Any` vs `Matcher::Exact` correctly to an operator.

Add to `crates/policy/src/matcher.rs`:

```rust
impl Matcher {
    /// Operator-facing plain-language rendering, e.g.
    /// Any agent / agent `planner-7` / any cred of `local://ssh/fleet/*`.
    /// Display only — never parsed, never a security boundary.
    pub fn describe(&self) -> String;
}
```

Constraints I want you to hold me to:
- **Display-only.** It must not be reachable from any code path that changes a
  decision. If a caller could feed its output back into `parse`, that is a bug.
- **It must not over-promise.** `*` spanning `/` and `:` is a *sharp edge*, not a
  detail — the honest rendering of `ssh://*.internal` has to make the operator
  look at it (see 3.3), and `describe` is what makes that possible.
- Unit tests in `matcher.rs` for every variant, including `Matcher::Any`
  rendering as "any" and **not** as a literal `*`.

### 3.2 Live plain-language preview under the rule form

Generated from the **parsed `Rule`**, not from the raw form strings — so it
reflects what the validator actually produced, including the empty-axis→`Any`
coercion and the pair-row parse. This is the whole point of P2-2's first sub-item.

- Render server-side, in the `GET /rules/new` stage-2 response.
- Regenerate on each form POST round-trip (the form is a plain GET-then-POST
  already — `pages.rs:572`; no JS framework per D40, so this is "re-render on
  submit", not "live on keystroke").
- **Honest about what it is:** preview the *candidate* rule, labelled as such, and
  say explicitly whether it is currently unsaved.

### 3.3 The boundary caveat — a sentence, not a block

When a submitted glob has `*` adjacent to `.` or `/` in a hostname or path
position, surface a one-sentence inline caveat at the moment it is relevant.
Per the gap review: **not a block**. Blocking would put a class of legitimate rule
(every fleet rule) behind a dialog, which is how security controls become
annoyances operators route around.

I want your opinion on the exact trigger predicate. My instinct is to keep it
narrow and mechanical — `*` immediately preceded or followed by `.` or `/`, in a
`target_uri` or `cred_ref` axis — because a fuzzy heuristic produces false
positives that train operators to dismiss it.

### 3.4 The test box

Paste agent id / `cred_ref` / target URI (+ mechanism, since it is the fourth
axis) → get verdict, matching rule index, and pair index.

**Hard requirement: it calls `Policy::evaluate` — the same function the gateway
calls. It does not reimplement evaluation, and it does not shell out to the CLI.**
D36 says the UI is a thin client over the CLI's validators; duplicating the
evaluation in the UI would create exactly the divergence D36 exists to prevent.
Reuse the formatting at `main.rs:242-254` verbatim so the two surfaces cannot
drift. My preference is to extract that formatting into a shared function in
`chaperone-policy` rather than copy it — but that widens the PR into a public API
change, so: **your call.** Copy-with-a-comment is acceptable if you prefer a
smaller blast radius.

---

## 4. P2-1 — "Connect a service" flow

### 4.1 Shape

One submit produces: **rule + vault entry + enrolled identity + a copy-pasteable
test command.**

Pick a template (reuse `matrix::templates_for`, which already carries maturity
badges) → paste the secret → name the agent → receive all four artifacts.

Per-mechanism input fields come from the matrix entry, not from a hardcoded
per-mechanism form. This is what keeps it from becoming a second matrix.

### 4.2 The constraint that must not be broken

**D36 — one validator path.** The flow must call the same code, in the same order,
that the four existing endpoints call. Concretely, the risk is real and specific:
if the new endpoint hand-builds a `Rule` and a vault entry and then writes both
files itself, we get a fifth writer. If it writes the policy file and then calls
the vault separately, a partial failure leaves a rule referencing a missing
secret — a **deny-all rule that looks configured**. That second failure mode is
the dangerous one, and it is the reason this is a real slice rather than a UI
form.

My proposed answer: build all four artifacts **in memory**, validate all four,
and only then perform the writes — with the ordering chosen so that an
interruption leaves a *safe* residue rather than a misleading one. I want you to
push back on the ordering specifically, because "safe residue" has two defensible
directions (rule-last vs. secret-last) and they fail differently.

### 4.3 Secret handling

The pasted secret goes into the vault. It must never appear in:
- the HTML response (there is an existing escaper and an existing
  `no_secret_leak` sentinel discipline — reuse, don't reinvent)
- the returned test command (the test command references a `cred_ref`, never the value)
- any flash/query-param redirect (redirects carry `?msg=`/`?err=` — never a value)

`no_secret_leak` (P0-2) currently covers the gateway. **This adds a new path that
carries a secret into a process that renders HTML.** I believe it needs a sentinel
case, and I would rather add it than argue about it later. Flagging as scope.

### 4.4 Keep the existing wizard

The artifact-shaped wizard stays, reachable, as the advanced path. It is the one
that maps 1:1 to the CLI. The new flow is the default landing surface for a
first-time operator; the old one is never removed.

---

## 5. Sizing — my estimate, and how confident I am

| Slice | Est. | Confidence | Why |
|---|---|---|---|
| P2-2.1 `Matcher::describe` + tests | 0.5 day | **high** | ~40 lines, pure function, exhaustive variants |
| P2-2.2 preview render | 0.5 day | high | reuses `rules_new`'s existing shape |
| P2-2.3 caveat predicate | 0.25 day | medium | depends on getting the predicate right; may need iteration |
| P2-2.4 test box | 0.75 day | high | `evaluate` already exists; the work is form + render |
| P2-2.5 tests | 0.5 day | high | harness exists (`ui_http.rs`, 18 tests) |
| **P2-2 total** | **~2.5 days** | | |
| P2-1 flow | 2–3 days | **medium-low** | multi-artifact transaction + secret handling; the write-ordering question is unresolved |
| P2-1 `no_secret_leak` case | 0.5 day | high | additive |
| P2-1 tests | 1 day | medium | needs a real vault + enrollment in the test app |
| **P2-1 total** | **~3.5–4.5 days** | | |

My P2-1 number is the soft one. If §4.2's ordering discussion goes long, or if
the matrix templates need normalising into per-mechanism form fields, it moves.

---

## 6. Acceptance criteria — falsifiable, per item

These are written so each **fails when the fix is reverted.** That is the standard
we've held elsewhere; I'd like P2 to meet it too.

**P2-2**
1. `Matcher::describe` unit tests cover every variant and fail if the helper
   returns a raw `*` for `Matcher::Any`.
2. The preview under the rule form renders the *parsed* rule: a test submits a
   form with an empty `agent_id` axis and asserts the preview says "any agent",
   **not** "agent ``" — this pins the empty→`Any` coercion as displayed.
3. A pair-bound rule's preview names the binding; reverting the pair parse makes
   the test fail.
4. Test box: a request the saved ruleset allows returns that rule's index and
   effect; a request no rule matches returns default-deny. **Reverting to a
   reimplemented evaluation (or shelling out) breaks the parity assertion**, which
   is the D36 pin.
5. The boundary caveat appears for `ssh://*.internal` and does **not** appear for
   a fully-qualified exact target. Neither direction may pass vacuously.

**P2-1**
6. A first-time operator, from a running daemon, reaches a **brokered, audited**
   action having read no spec and typed no CLI command.
7. The flow is not a simulation: the returned test command, pasted into a real
   `chaperone` invocation, produces a real decision and a real audit record.
8. All four artifacts exist and are consistent after one submit.
9. **The partial-failure test:** force the vault write to fail *after* the rule is
   built, and assert the residue is the safe direction agreed in §4.2. Without this
   test, §4.2's ordering is an opinion; with it, it's a guarantee.
10. `no_secret_leak` sentinel: the pasted secret appears nowhere in the HTML
    response, the redirect, or the test command. Reverting the scrub fails it.
11. The existing artifact-shaped wizard remains reachable and still passes its
    existing tests.

---

## 7. Decisions I need from you

Numbered so you can rule item-by-item. I have a recommendation on each.

1. **Sequencing** — P2-2 before P2-1 (§2). *Recommend: yes.*
2. **§3.4 formatting** — extract the `rule[i] pair[p]` formatting into
   `chaperone-policy` as shared, or copy it into the UI? *Recommend: extract; it
   is a small, obviously-correct public addition and copying is how the two
   surfaces drift. Your call on blast radius.*
3. **§4.2 write ordering** — rule-last vs secret-last on partial failure (§4.2).
   *No strong preference; I want your reasoning. My tiebreak is "never leave
   something that reads as configured but isn't."*
4. **§4.3 scope** — add the `no_secret_leak` sentinel case in the P2-1 PR, or
   split it? *Recommend: in the same PR. Splitting means a PR that ships a secret
   into an HTML renderer without the sentinel guarding it.*
5. **§5 P2-1 sizing** — is ~3.5–4.5 days acceptable for review turnaround, or do
   you want P2-1 itself split into (a) the flow and (b) the tests?

---

## 8. What I am *not* proposing

- **No JS framework.** D40's server-rendered posture holds; everything above is
  forms and a round trip.
- **No "simple mode" that writes rules the CLI would refuse.** D36 exists to
  prevent exactly this, and P2-1 is the single most likely place to reintroduce it.
  The new flow is *friendlier*, not *different*.
- **No new policy semantics.** Both items are presentation over the existing
  engine. No new axes, no new effect, no change to `evaluate`, no change to the
  TOML schema.
- **Nothing touching the vault passphrase lifecycle.** P2-3 is a separate,
  one-sentence item and is not in scope here.
- **No change to `CONNECTIVITY-MATRIX.md`.** The templates are consumed as-is.

---

## 9. Open risks I want on the record before you approve

1. **P2-1 introduces a second multi-artifact write path.** Even if it honours D36,
   the existence of a flow that writes policy + vault + enrollment + audit in one
   go is a new failure surface. Mitigation is §4.2 ordering plus test 9. It does
   not eliminate the risk; it bounds it.
2. **The preview shows a rule that is not yet saved.** An operator could read it as
   the current state. §3.2's "unsaved" labelling is the mitigation and I would
   rather over-label than under-label.
3. **The caveat predicate will produce false positives.** §3.3's narrowness is a
   deliberate choice; if it proves too narrow in practice, operators get an
   under-warning. I would rather ship narrow and widen on evidence than ship
   noisy and have it dismissed.
4. **P2-1's estimate is soft** (§5) and I would rather say so now than discover it
   mid-implementation.