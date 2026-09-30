# P1-2 design analysis — policy correlation: capture-substitution vs pairs table

**Status:** **RULED — Option B (pairs), Stephen 2026-09-30.** Recorded as D43 in DESIGN-DECISIONS.md. This paper is the supporting analysis; §8's draft became the D43 entry (lightly expanded). Implementation slice may now be tasked.
**Author:** hermes-ox-chap, 2026-09-30
**Implements the call demanded by:** `docs/MVP-GAP-REVIEW.md` P1-2 ("Make this call explicitly and record it in DESIGN-DECISIONS.md")
**Scope:** contained entirely within `chaperone-policy`; no protocol change either way (per P1-2's own note).

---

## 1. The problem, concretely

`Rule` matches four **independent** axes (`agent_id`, `cred_ref`, `target_uri`, `mechanism`), first match wins. Independent axes express a cross-product, so this rule:

```toml
[[rule]]
effect = "allow"
agent_id = "agent:deployer"
mechanism = "ssh"
cred_ref   = "local://ssh/fleet/*"
target_uri = "ssh://*.internal"
```

permits **any** fleet key against **any** fleet host: `local://ssh/fleet/app-01` reaches `ssh://app-02.internal` and nothing objects. Binding key→host requires one rule per host — N hosts, N hand-maintained rules — and the over-permission is **invisible in the rule text**: every individual matcher looks disciplined. P1-2 rates this a correctness issue, not only ergonomics, and it is the v1 stopgap until B-1 (SSH CA / dynamic minting) removes per-host secrets entirely.

Two candidate fixes were named in the gap review. This paper specifies both against the actual code, compares them, and recommends.

---

## 2. Option A — capture substitution

### Mechanism

One axis's glob gains **named captures**; another axis's pattern may **reference** them:

```toml
[[rule]]
effect = "allow"
agent_id = "agent:deployer"
mechanism = "ssh"
target_uri = "ssh://{host}.internal"          # capture source
cred_ref   = "local://ssh/fleet/{host}"       # dependent pattern
```

Evaluation becomes order-dependent: match the capture source against the request first, bind `{host}`, substitute into the dependent pattern, then match the dependent axis. One rule covers the whole fleet.

### What it costs in this codebase

1. **`glob_match` grows a capture API.** Today it returns `bool` (matcher.rs:120) via a head/middles/tail scan. Captures need the matched span of each `*`, a new return type, and decisions about multiple captures and empty captures.
2. **Axis evaluation stops being independent.** `Policy::evaluate` (lib.rs:406-428) currently ANDs four `matches()` calls in any order. Substitution introduces a dependency DAG between axes: which axis captures, which consumes, what happens when the source doesn't match (rule skips — fine — but the error/preview story must say so), and what a capture *means* when the source pattern has several `*`s.
3. **Second-order matching with agent-influenced interpolation.** This is the deep cost. The capture source value (`target_uri`) **comes from the intent — the agent controls it.** Substitution embeds an agent-controlled string into the pattern used to match a *second* agent-controlled string (`cred_ref`). Matching stops being "request vs fixed rule text" (first-order) and becomes "request vs pattern-composed-from-request" (second-order). In a product whose entire thesis is the confused-deputy problem (THREAT-MODEL §3), every second-order construction deserves adversarial review before shipping.
4. **The known glob looseness compounds.** D17/matcher.rs document that `*` spans `/` and `:` with no boundary enforcement. A capture inherits that: `ssh://{host}.internal` matched against `ssh://app-01.attacker.com/.internal` **matches** (tail `.internal` is present at the end), capturing `host = "app-01.attacker.com/"` — slashes and all. *(Verified by running the actual `glob_match` algorithm from matcher.rs:120 against this input, 2026-09-30: match `true`, captured span `app-01.attacker.com/`.)* The dependent `cred_ref` then interpolates a captured string containing `/`, i.e. an agent-steerable vault path fragment (`local://ssh/fleet/app-01.attacker.com/`). Whether that resolves anywhere depends on the vault's path handling — but the *policy layer* just handed an agent-controlled substring into credential selection. Mitigations exist (character-class restrictions on captures, rejecting captures containing `/` or `..`, normalizing before substitution) — each is more spec surface, more tests, more ways to be subtly wrong.
5. **Everything downstream of `Rule` inherits it:** the canonical TOML writer round-trip (`parse(source()) == self` invariant, lib.rs:377ff), `policy-check` output (must show bindings), the UI rule editor + P2-2 preview (a preview of a substitution rule must *simulate* it — the preview engine now contains a template interpreter), the fuzz targets, and the D36 rule that UI and CLI share validators (both need the substitution semantics identically).

### What it buys

- One rule per naming *convention* instead of one row per host: a regular fleet (`app-NN`) is a single line, and hosts added later need no policy edit at all **if** the vault entry exists.
- Genuine expressiveness beyond the fleet case: any two axes with a derivable relationship (per-agent cred paths, per-env target/cred coupling).

---

## 3. Option B — explicit pairs table

### Mechanism

A rule may carry a list of **(cred_ref, target_uri) pair rows**; the rule matches when the shared axes match **and** the request's (cred_ref, target_uri) equals one row:

```toml
[[rule]]
name = "deployer fleet ssh"
effect = "allow"
agent_id = "agent:deployer"
mechanism = "ssh"

  [[rule.pair]]
  cred_ref   = "local://ssh/fleet/app-01"
  target_uri = "ssh://app-01.internal:22"

  [[rule.pair]]
  cred_ref   = "local://ssh/fleet/app-02"
  target_uri = "ssh://app-02.internal:22"
```

300 hosts = 300 rows **in one rule** — one audit unit, one notify setting, one limits block, one entry in `policy-check` output. The binding is the row: key `app-01` can only ever match the row whose `target_uri` is `app-01`.

### What it costs in this codebase

1. `RuleDef` gains `#[serde(default)] pair: Vec<PairDef>` (the strict `deny_unknown_fields` schema keeps typos loud — a misspelled `[[rule.pairs]]` fails the load, per D17's silent-match-any prevention).
2. `Rule` gains `pairs: Vec<(Matcher, Matcher)>`; `evaluate` gains one clause: when `pairs` is non-empty, require `(cred_ref, target_uri)` to match some row. **Absent pairs = today's behavior exactly** — fully backward compatible, no migration, no existing rule changes meaning.
3. `DecisionSource::Rule` optionally reports the matched pair index (audit legibility: "allowed by rule[3] pair[17]").
4. TOML writer emits rows; the `parse(source()) == self` invariant extends naturally (rows are strings, not logic).
5. UI/P2-2 preview: renders rows literally. **The over-permission gap disappears from the rule text** — which was P1-2's security complaint ("invisible in the rule text"). A pairs rule's permission set is exactly what it looks like.

### Row matcher semantics — one sub-decision

- **B1 (recommended): reuse `Matcher::parse` per row field.** Bare strings are `Exact` (rows are literals in practice); an operator *may* write `glob:`/`prefix:` in a row if they deliberately want a row that covers a sub-range. Zero new semantics — the tested tag system applies unchanged. The doc note: a `*` in a bare row string makes it a glob, same rule as everywhere (D17).
- B2: rows are Exact-only, full stop. Maximally boring, but inconsistent with the rest of the language and needs its own parse path/rejection message. Not worth the special case.

### What it buys — and what it doesn't

- **Buys:** first-order matching only (request vs fixed rule text — no composition, no captures, nothing agent-influenced inside a pattern); total auditability (the table *is* the permission set, greppable and diffable); trivial mechanical generation (B-2 bulk import writes rows from `~/.ssh/config`/inventory — P1-2 itself sequences B-2 *after* correlation precisely because import-generated N-rule sprawl is the failure mode, and rows are the natural import target); clean obsolescence (when B-1's CA lands, per-host secrets vanish, the fleet rule collapses to one cred_ref pattern, and the rows are deleted — no language feature to deprecate).
- **Doesn't buy:** convention coverage. A host added at 3am needs a row added (or pre-generated in bulk). For *irregular* fleets this is a feature (explicit grant per endpoint); for perfectly regular fleets it's mild friction that B-2's import removes.

---

## 4. Comparison

| Dimension | A: substitution | B: pairs |
|---|---|---|
| Rules for a 300-host fleet | 1 | 1 rule, 300 rows |
| New host, regular naming | no policy edit | row added (or bulk-imported) |
| Matching order | second-order (pattern composed from request data) | first-order (request vs fixed literals) |
| Agent-influenced data inside patterns | **yes** — capture interpolation; needs a hardening spec (char classes, `/`+`..` rejection) | none |
| Glob-looseness interaction (D17: `*` spans `/`) | compounds (captures inherit it) | bounded (rows are literals by default) |
| Auditability (D3's stated value: "no regex in v0 (auditability)"; D17: "boringly auditable") | logic must be *simulated* to know what's permitted | permission set is *readable* — the table is the truth |
| Implementation surface | matcher capture API + evaluation DAG + writer + preview interpreter + fuzz + shared-validator parity (D36) | one struct field + one evaluate clause + writer rows + literal preview |
| Protocol change | none | none |
| Backward compatibility | additive but changes match semantics of any rule using `{}` | strictly additive; absent = unchanged |
| UI preview (P2-2) | must interpret templates | lists rows |
| Interaction with B-1 (CA/minting) | syntax outlives its usefulness — config compatibility forever | rows deleted when CA lands — nothing to deprecate |
| Interaction with B-2 (bulk import) | import must *infer* the convention (fragile) | import *writes* rows (mechanical) |
| Estimated size | large (multi-slice; matcher semantics + hardening + docs) | small (one slice in `chaperone-policy` + writer + tests) |

## 5. Recommendation

**Pairs (Option B, with B1 row semantics).** The decisive arguments, in order:

1. **It keeps the policy engine first-order.** The confused-deputy thesis is the product; a matching language where agent-controlled strings compose into the patterns that select credentials is the one direction this codebase should be maximally reluctant to grow. Pairs adds correlation with *zero* new trust assumptions.
2. **It fixes the actual security complaint, not just the ergonomics.** P1-2's sharper cost was invisibility: fleet rules that grant more than their author believes. A pairs rule cannot over-grant relative to its text — the rows are the grant. Substitution rules still require simulation to know their reach (that's what the P2-2 preview interpreter would be for).
3. **D3/D17 already picked this taste.** "No regex in v0 (auditability)", "boringly auditable", "glob semantics kept minimal and documented" — pairs is the option consistent with the recorded values; substitution is a template language, i.e. exactly the expressiveness those decisions deferred.
4. **It's the cheaper half of every pairing:** smaller implementation, natural target for B-2 import, clean obsolescence under B-1, literal UI preview.
5. **Reversibility.** If a real fleet later proves row maintenance painful *after* B-2 exists, substitution can still be added then — informed by real inventories rather than anticipated ones. The reverse (shipping substitution, then removing it) is a config-compatibility trap.

**Honest cost of the recommendation:** a perfectly regular 300-host fleet gets 300 rows where substitution gives one line. We accept that because B-2 makes the rows machine-generated, and because "one line" hides the permission set that the rows display.

## 6. Edge cases to settle in the D43 entry / implementation slice

1. Row semantics: `Matcher::parse` per row field (B1) — recommended above.
2. `pairs` with `effect = "deny"`: allowed and meaningful (deny key A against host B specifically while a broader allow covers the rest) — first-match-wins ordering across rules is unchanged; within a rule, pairs are an AND-clause, not separate rules.
3. `DecisionSource` carries the matched pair index for audit/`policy-check` legibility.
4. One `pair` list per rule (not per-axis generalization). If a future need wants (agent, cred) pairs, that's a new decision, not a silent generalization.
5. Limits/notify stay rule-level in v1; per-row limits are future work if ever needed.
6. Empty `pair = []` means "no pairs clause" (absent = today's behavior) — the writer must not emit an empty table that changes semantics; strict schema rejects `[[rule.pairs]]` typos loudly (D17).
7. The acceptance test from P1-2 is the gate: *one rule expresses "each fleet key may be used only against its own host," and a test proves key A cannot reach host B under it* — plus round-trip stability, default-deny untouched, and `policy-check` showing the pair.

## 7. Companion doc fix (P1-2 item 3, independent of this decision)

CONNECTIVITY-MATRIX.md currently reads as though per-host keys are the intended model for SSH at scale. It should say: per-host keys are the **v1 shape**; the intended model at fleet scale is a **certificate authority with short-lived minted certificates (B-1)**; correlation (this decision) is what makes v1 survivable until B-1 lands. A reader with fleet-operations experience should see the roadmap, not infer we haven't thought about scale.

## 8. Recorded decision

**Ruled: Option B (pairs), Stephen 2026-09-30.** The canonical record is
**D43** in `docs/DESIGN-DECISIONS.md` (this paper's draft became that entry,
lightly expanded with the verified capture-injection example, the empty-`pair`
semantics, the pairs-with-deny case, and the acceptance gate). DESIGN-DECISIONS.md
is authoritative; this paper is the supporting analysis. Implementation slice
may now be tasked against D43.
