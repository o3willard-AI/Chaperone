//! The policy engine (ARCH-SPEC §2.3).
//!
//! The component that makes the gateway an authority rather than a proxy.
//! It receives a verified request and emits exactly one decision:
//! `allow`, `deny`, or `needs_confirmation`.
//!
//! Invariants, enforced by construction:
//!
//! - **Default-deny is structural.** Absent a matching explicit allow, the
//!   verdict is deny — there is no configuration that removes the floor,
//!   because it is not itself a rule anyone can delete.
//! - **Total.** Every input yields a verdict; evaluation cannot fail.
//! - **Side-effect-free.** Evaluation reads nothing but its own rules and
//!   the request; it holds no handles, mints nothing, touches no vault.
//! - **First match wins**, so rule order in the file IS precedence: specific
//!   allows go above broad denies, deliberate overrides above them.

use std::fmt;

use chaperone_protocol::Constraints;
use serde::Deserialize;

pub mod matcher;

pub use matcher::{Matcher, MatcherError, glob_match};

/// What policy permits (PROTO-SPEC §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Proceed without human involvement.
    Allow,
    /// Proceed only after the gateway's single confirmation gate.
    NeedsConfirmation,
    /// Refuse. Default-deny lands here.
    Deny,
}

impl Effect {
    /// Wire string -> effect. Public for operator tooling that builds rules
    /// programmatically (the config UI); the TOML schema remains the only
    /// path rules actually enter service through.
    pub fn parse(raw: &str) -> Option<Effect> {
        match raw {
            "allow" => Some(Effect::Allow),
            "deny" => Some(Effect::Deny),
            "needs_confirmation" => Some(Effect::NeedsConfirmation),
            _ => None,
        }
    }

    /// Wire string for this effect.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::NeedsConfirmation => "needs_confirmation",
        }
    }
}

/// Policy-declared ceilings a matched rule imposes. Combined with the
/// agent's own constraints by minimum (PROTO-SPEC §5.1: constraints only
/// narrow, never widen). `None` means "no ceiling from this side".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// Ceiling on relayed response bytes.
    pub max_response_bytes: Option<u64>,
    /// Ceiling on brokered-session lifetime, seconds.
    pub session_ttl_s: Option<u64>,
}

impl Limits {
    /// Element-wise minimum of two limit sets (`None` = no ceiling).
    #[must_use]
    pub fn min_with(self, other: Limits) -> Limits {
        let min_opt = |a: Option<u64>, b: Option<u64>| match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        };
        Limits {
            max_response_bytes: min_opt(self.max_response_bytes, other.max_response_bytes),
            session_ttl_s: min_opt(self.session_ttl_s, other.session_ttl_s),
        }
    }
}

/// One (credential, endpoint) binding row inside a [`Rule`] (D43).
///
/// A rule with pairs matches only when the request's (cred_ref, target_uri)
/// matches one row — the fleet-scale answer to "this key only against this
/// host" without N hand-maintained rules. Row fields parse with the standard
/// [`Matcher`] tags; bare strings are `Exact` (rows are literals in practice).
/// Empty/absent pairs = no pair clause = prior behavior exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    /// Which credential reference this row binds.
    pub cred_ref: Matcher,
    /// Which target URI this row binds it to.
    pub target_uri: Matcher,
}

/// One auditable rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Optional human label, echoed in decisions for audit legibility.
    pub name: Option<String>,
    /// Whether use under this rule should emit a notification event.
    pub notify_on_use: bool,
    /// Verdict when this rule matches.
    pub effect: Effect,
    /// Which agents.
    pub agent_id: Matcher,
    /// Which credential references.
    pub cred_ref: Matcher,
    /// Which targets.
    pub target_uri: Matcher,
    /// Which mechanisms (the operation axis in v0 — see D17).
    pub mechanism: Matcher,
    /// (cred_ref, target_uri) binding rows (D43). Non-empty means the
    /// request must match one row IN ADDITION to the shared axes above;
    /// pairs are an AND-clause within this rule, not separate rules.
    pub pairs: Vec<Pair>,
    /// Ceilings imposed when this rule matches.
    pub limits: Limits,
}

/// A request under adjudication: the four axes plus declared ceilings.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Verified agent identity (already attested upstream of policy).
    pub agent_id: &'a str,
    /// Credential reference named by the intent.
    pub cred_ref: &'a str,
    /// Target URI from the intent.
    pub target_uri: &'a str,
    /// Mechanism from the intent.
    pub mechanism: &'a str,
    /// Agent-declared constraints, if any. Ceilings only.
    pub declared: Option<Constraints>,
}

/// How a verdict was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionSource {
    /// No rule matched: the structural default-deny floor.
    DefaultDeny,
    /// The rule at this zero-based index (with its name, if any) matched.
    Rule {
        /// Position in rule order.
        index: usize,
        /// The rule's optional label.
        name: Option<String>,
        /// When the rule carries D43 pair rows, the zero-based row that
        /// bound this decision; `None` for rules without pairs. Audit and
        /// `policy-check` legibility ("allowed by rule[3] pair[17]").
        pair: Option<usize>,
    },
}

impl DecisionSource {
    /// The single rendering of "how was this verdict reached", shared by
    /// every surface that shows it: `policy-check` JSON, the gateway's deny
    /// reasons, and the operator UI's test box (P2-2, ruling 2).
    ///
    /// This lives here, on the type, rather than in either caller, so the CLI
    /// and the UI cannot drift into two different vocabularies for the same
    /// verdict — D36 exists to prevent exactly that, and a shared impl makes
    /// the parity structural instead of test-enforced. The CLI keeps its JSON
    /// envelope; only the source label is shared.
    ///
    /// Display/provenance only: never parsed, never a security boundary.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            DecisionSource::DefaultDeny => "default_deny".to_owned(),
            DecisionSource::Rule { index, name, pair } => format!(
                "rule[{index}]{}{}",
                name.as_deref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default(),
                pair.map_or(String::new(), |p| format!(" pair[{p}]")),
            ),
        }
    }
}

/// A complete verdict (PROTO-SPEC §9.1): effect, provenance, effective
/// ceilings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// What policy permits.
    pub effect: Effect,
    /// Whether the matched rule requests a notification on use (D38).
    pub notify_on_use: bool,
    /// Why: which rule, or the floor.
    pub source: DecisionSource,
    /// Effective limits: min(matched-rule limits, agent-declared). For
    /// denies these still compute but nothing will consume them.
    pub limits: Limits,
}

/// Failures loading a policy document. These are operator-facing and must be
/// loud: a typo that silently dropped a field could silently widen access.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// Document was not parseable TOML.
    Parse(String),
    /// Parsed but violated the schema: bad effect, unknown key, bad matcher.
    Schema(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Parse(e) => write!(f, "policy is not valid TOML: {e}"),
            PolicyError::Schema(e) => write!(f, "policy violates its schema: {e}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Appends `key = "escaped"` using the toml crate's own string quoting so
/// escapes are never hand-rolled here.
fn push_kv(out: &mut String, key: &str, value: &str) {
    let quoted = toml::Value::from(value).to_string();
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(&quoted);
    out.push('\n');
}

// Wire format: deliberately strict. deny_unknown_fields means a misspelled
// axis ("agents_id") fails the load instead of silently matching-any.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    /// An absent or empty rule list is a VALID pure default-deny policy.
    #[serde(default)]
    rule: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDef {
    effect: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    cred_ref: Option<String>,
    #[serde(default)]
    target_uri: Option<String>,
    #[serde(default)]
    mechanism: Option<String>,
    /// D43 pair rows: `[[rule.pair]]`. Strict like everything else — a
    /// typo'd row field fails the load loudly rather than silently
    /// widening a binding.
    #[serde(default)]
    pair: Vec<PairDef>,
    #[serde(default)]
    limits: Option<LimitsDef>,
    #[serde(default)]
    notify: Option<NotifyDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairDef {
    cred_ref: String,
    target_uri: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotifyDef {
    #[serde(default = "default_true")]
    on_use: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsDef {
    #[serde(default)]
    max_response_bytes: Option<u64>,
    #[serde(default)]
    session_ttl_s: Option<u64>,
}

/// The active ruleset, bound to the hash of the document it was parsed
/// from (DESIGN-DECISIONS D38): every decision can name the exact ruleset
/// that governed it, and any post-hoc edit shows up as a hash break in the
/// audit chain at next load.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    rules: Vec<Rule>,
    source_hash_hex: String,
}

impl Policy {
    /// An empty policy: everything denied, provably.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            source_hash_hex: String::new(),
        }
    }

    /// Parses the TOML ruleset (DESIGN-DECISIONS D3).
    ///
    /// ```toml
    /// [[rule]]
    /// name = "planner may charge via stripe"
    /// effect = "allow"
    /// agent_id = "agent:planner-7"
    /// cred_ref = "vault://prod/stripe/*"
    /// target_uri = "https://api.stripe.com/v1/*"
    /// mechanism = "http-bearer"
    ///
    /// [rule.limits]
    /// max_response_bytes = 1048576
    /// ```
    pub fn from_toml(doc: &str) -> Result<Policy, PolicyError> {
        let file: PolicyFile =
            toml::from_str(doc).map_err(|e| PolicyError::Schema(e.to_string()))?;
        let mut rules = Vec::with_capacity(file.rule.len());
        for (i, def) in file.rule.into_iter().enumerate() {
            let effect = Effect::parse(&def.effect).ok_or_else(|| {
                PolicyError::Schema(format!(
                    "rule {i}: unknown effect {:?} (want allow|deny|needs_confirmation)",
                    def.effect
                ))
            })?;
            let axis = |label: &str, raw: &Option<String>| -> Result<Matcher, PolicyError> {
                match raw.as_deref() {
                    None => Ok(Matcher::Any),
                    Some(s) => Matcher::parse(s)
                        .map_err(|e| PolicyError::Schema(format!("rule {i}: {label}: {e}"))),
                }
            };
            let notify_on_use = def.notify.as_ref().map(|n| n.on_use).unwrap_or(true);
            let limits = def
                .limits
                .map(|l| Limits {
                    max_response_bytes: l.max_response_bytes,
                    session_ttl_s: l.session_ttl_s,
                })
                .unwrap_or_default();
            // D43: parse pair rows. Row fields are mandatory strings (a row
            // names an exact binding); each parses through the standard
            // Matcher tags. A row that fails to parse fails the whole load.
            let mut pairs = Vec::with_capacity(def.pair.len());
            for (pi, p) in def.pair.into_iter().enumerate() {
                let cred_ref = Matcher::parse(&p.cred_ref).map_err(|e| {
                    PolicyError::Schema(format!("rule {i} pair {pi}: cred_ref: {e}"))
                })?;
                let target_uri = Matcher::parse(&p.target_uri).map_err(|e| {
                    PolicyError::Schema(format!("rule {i} pair {pi}: target_uri: {e}"))
                })?;
                pairs.push(Pair {
                    cred_ref,
                    target_uri,
                });
            }
            rules.push(Rule {
                name: def.name,
                notify_on_use,
                effect,
                agent_id: axis("agent_id", &def.agent_id)?,
                cred_ref: axis("cred_ref", &def.cred_ref)?,
                target_uri: axis("target_uri", &def.target_uri)?,
                mechanism: axis("mechanism", &def.mechanism)?,
                pairs,
                limits,
            });
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(doc.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let source_hash_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Policy {
            rules,
            source_hash_hex,
        })
    }

    /// Builds directly from rules (programmatic construction / tests).
    #[must_use]
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            source_hash_hex: String::new(),
        }
    }

    /// The loaded rules, in precedence order (first match wins).
    ///
    /// Read-only view for operator tooling (the config UI lists these);
    /// mutating goes through a document rebuild + [`Policy::from_toml`]
    /// validation, never by editing this slice.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Canonical TOML serialization of this ruleset (D40).
    ///
    /// ONE writer, living beside the one parser: the config UI saves
    /// through this method and then re-validates with [`Policy::from_toml`],
    /// so "what the UI wrote" is exactly "what the CLI would have parsed".
    /// Round-trip guarantee (tested): `from_toml(&to_toml())` yields a
    /// policy that evaluates identically, and every matcher survives via
    /// its `source()` form.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if index > 0 {
                out.push('\n');
            }
            out.push_str("[[rule]]\n");
            if let Some(name) = &rule.name {
                push_kv(&mut out, "name", name);
            }
            out.push_str(&format!("effect = \"{}\"\n", rule.effect.as_str()));
            for (key, matcher) in [
                ("agent_id", &rule.agent_id),
                ("cred_ref", &rule.cred_ref),
                ("target_uri", &rule.target_uri),
                ("mechanism", &rule.mechanism),
            ] {
                if let Some(source) = matcher.source() {
                    push_kv(&mut out, key, &source);
                }
            }
            // Sub-tables must follow every bare key of this rule. D43 pair
            // rows first (they are the binding), then limits, then notify —
            // and the writer never emits an empty pair table (D43: empty is
            // equivalent to absent).
            for pair in &rule.pairs {
                out.push_str("[[rule.pair]]\n");
                // Pair fields are mandatory Matchers; source() is None only
                // for Any, which cannot occur in a parsed pair (row fields
                // are required strings) — fall back to the wildcard glob so
                // an Any pair (only constructible programmatically) still
                // round-trips to equivalent semantics.
                push_kv(
                    &mut out,
                    "cred_ref",
                    &pair.cred_ref.source().unwrap_or_else(|| "*".to_owned()),
                );
                push_kv(
                    &mut out,
                    "target_uri",
                    &pair.target_uri.source().unwrap_or_else(|| "*".to_owned()),
                );
            }
            if rule.limits.max_response_bytes.is_some() || rule.limits.session_ttl_s.is_some() {
                out.push_str("[rule.limits]\n");
                if let Some(v) = rule.limits.max_response_bytes {
                    out.push_str(&format!("max_response_bytes = {v}\n"));
                }
                if let Some(v) = rule.limits.session_ttl_s {
                    out.push_str(&format!("session_ttl_s = {v}\n"));
                }
            }
            out.push_str("[rule.notify]\n");
            out.push_str(&format!("on_use = {}\n", rule.notify_on_use));
        }
        out
    }

    /// Number of rules loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Hex SHA-256 of the raw document bytes this ruleset was parsed from.
    #[must_use]
    pub fn source_hash(&self) -> &str {
        &self.source_hash_hex
    }

    /// True when there are no rules at all (then EVERYTHING is denied).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluates one request to exactly one verdict.
    ///
    /// Total and side-effect-free: same inputs, same verdict, forever, with
    /// nothing touched outside this function's arguments.
    #[must_use]
    pub fn evaluate(&self, request: &Request<'_>) -> Decision {
        let declared_limits = Limits {
            max_response_bytes: request.declared.and_then(|c| c.max_response_bytes),
            session_ttl_s: request.declared.and_then(|c| c.session_ttl_s),
        };

        for (index, rule) in self.rules.iter().enumerate() {
            if rule.agent_id.matches(request.agent_id)
                && rule.cred_ref.matches(request.cred_ref)
                && rule.target_uri.matches(request.target_uri)
                && rule.mechanism.matches(request.mechanism)
            {
                // D43: when the rule carries pair rows, the request's
                // (cred_ref, target_uri) must additionally match one row —
                // an AND-clause within the rule, not separate rules, so
                // first-match-wins across rules is unchanged. A rule with no
                // rows behaves exactly as before.
                let pair = if rule.pairs.is_empty() {
                    None
                } else {
                    match rule.pairs.iter().position(|p| {
                        p.cred_ref.matches(request.cred_ref)
                            && p.target_uri.matches(request.target_uri)
                    }) {
                        Some(pi) => Some(pi),
                        // Shared axes matched but no binding row does: this
                        // rule does not cover the request. Keep scanning —
                        // a later rule may match; otherwise default-deny.
                        None => continue,
                    }
                };
                return Decision {
                    effect: rule.effect,
                    notify_on_use: rule.notify_on_use,
                    source: DecisionSource::Rule {
                        index,
                        name: rule.name.clone(),
                        pair,
                    },
                    limits: rule.limits.min_with(declared_limits),
                };
            }
        }

        Decision {
            effect: Effect::Deny,
            notify_on_use: false,
            source: DecisionSource::DefaultDeny,
            // Nothing was granted; report bare declared limits unchanged so
            // callers cannot read a widening out of a denial.
            limits: declared_limits,
        }
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(agent: &'a str, cred: &'a str, target: &'a str, mech: &'a str) -> Request<'a> {
        Request {
            agent_id: agent,
            cred_ref: cred,
            target_uri: target,
            mechanism: mech,
            declared: None,
        }
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = Policy::empty();
        assert!(p.is_empty());
        for mech in ["http-bearer", "ssh", "db-scram", "local-privilege"] {
            let d = p.evaluate(&req("agent:a", "vault://x", "https://x", mech));
            assert_eq!(d.effect, Effect::Deny);
            assert_eq!(d.source, DecisionSource::DefaultDeny);
        }
    }

    const SAMPLE: &str = r#"
        [[rule]]
        name = "stripe charges"
        effect = "allow"
        agent_id = "agent:planner-7"
        cred_ref = "vault://prod/stripe/*"
        target_uri = "https://api.stripe.com/v1/*"
        mechanism = "http-bearer"

        [[rule]]
        name = "no prod ssh for interns"
        effect = "deny"
        agent_id = "agent:intern-*"
        cred_ref = "*"
        target_uri = "*prod*"

        [[rule]]
        effect = "needs_confirmation"
        agent_id = "agent:ops-1"
        cred_ref = "local://sudo"
    "#;

    #[test]
    fn parses_and_applies_first_match_in_order() {
        let p = Policy::from_toml(SAMPLE).unwrap();
        assert_eq!(p.len(), 3);

        let d = p.evaluate(&req(
            "agent:planner-7",
            "vault://prod/stripe/sk",
            "https://api.stripe.com/v1/charges",
            "http-bearer",
        ));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(
            d.source,
            DecisionSource::Rule {
                index: 0,
                name: Some("stripe charges".to_owned()),
                pair: None,
            }
        );

        // Intern + prod target: rule 1 fires before rule 2 ever could.
        let d = p.evaluate(&req(
            "agent:intern-9",
            "local://sudo",
            "https://prod.internal/x",
            "ssh",
        ));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(
            d.source,
            DecisionSource::Rule {
                index: 1,
                name: Some("no prod ssh for interns".to_owned()),
                pair: None,
            }
        );
    }

    #[test]
    fn unlisted_requests_hit_default_deny_floor() {
        let p = Policy::from_toml(SAMPLE).unwrap();
        // Right agent, wrong credential reference: no rule matches.
        let d = p.evaluate(&req(
            "agent:planner-7",
            "local://etc/shadow",
            "https://api.stripe.com/v1/charges",
            "http-bearer",
        ));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.source, DecisionSource::DefaultDeny);
    }

    #[test]
    fn needs_confirmation_returns_verdict_not_error() {
        let p = Policy::from_toml(SAMPLE).unwrap();
        let d = p.evaluate(&req(
            "agent:ops-1",
            "local://sudo",
            "local://host",
            "local-privilege",
        ));
        assert_eq!(d.effect, Effect::NeedsConfirmation);
    }

    #[test]
    fn partial_matches_grant_nothing() {
        // Every axis must match; three-out-of-four grants nothing.
        let p = Policy::from_toml(SAMPLE).unwrap();
        let cases = [
            req(
                "agent:planner-7",
                "vault://dev/stripe/sk",
                "https://api.stripe.com/v1/c",
                "http-bearer",
            ),
            req(
                "agent:other",
                "vault://prod/stripe/sk",
                "https://api.stripe.com/v1/c",
                "http-bearer",
            ),
            req(
                "agent:planner-7",
                "vault://prod/stripe/sk",
                "https://evil.example/v1/c",
                "http-bearer",
            ),
            req(
                "agent:planner-7",
                "vault://prod/stripe/sk",
                "https://api.stripe.com/v1/c",
                "ssh",
            ),
        ];
        for c in &cases {
            let d = p.evaluate(c);
            assert_eq!(d.effect, Effect::Deny, "{c:?}");
            assert_eq!(d.source, DecisionSource::DefaultDeny);
        }
    }

    #[test]
    fn evaluation_is_total_across_weird_inputs() {
        let p = Policy::from_toml(SAMPLE).unwrap();
        let long = "x".repeat(10_000);
        let values = ["", "*", "\u{1F600}", "a\nb", long.as_str()];
        for a in &values {
            for c in &values {
                for t in &values {
                    for m in &values {
                        let d = p.evaluate(&req(a, c, t, m));
                        assert!(matches!(
                            d.effect,
                            Effect::Allow | Effect::Deny | Effect::NeedsConfirmation
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn repeated_evaluation_is_pure() {
        let p = Policy::from_toml(SAMPLE).unwrap();
        let r = req(
            "agent:planner-7",
            "vault://prod/stripe/sk",
            "https://api.stripe.com/v1/c",
            "http-bearer",
        );
        let first = p.evaluate(&r);
        for _ in 0..100 {
            assert_eq!(p.evaluate(&r), first);
        }
    }

    #[test]
    fn constraints_narrow_but_never_widen() {
        let doc = r#"
            [[rule]]
            effect = "allow"
            cred_ref = "vault://x"
            [rule.limits]
            max_response_bytes = 1000
            session_ttl_s = 300
        "#;
        let p = Policy::from_toml(doc).unwrap();

        // Agent declares smaller: theirs wins.
        let narrow = Request {
            agent_id: "a",
            cred_ref: "vault://x",
            target_uri: "t",
            mechanism: "m",
            declared: Some(Constraints {
                max_response_bytes: Some(10),
                session_ttl_s: Some(600),
            }),
        };
        let d = p.evaluate(&narrow);
        assert_eq!(d.limits.max_response_bytes, Some(10));
        assert_eq!(d.limits.session_ttl_s, Some(300)); // min(300, 600)

        // Agent declares larger: policy ceiling stands.
        let wide = Request {
            agent_id: "a",
            cred_ref: "vault://x",
            target_uri: "t",
            mechanism: "m",
            declared: Some(Constraints {
                max_response_bytes: Some(u64::MAX),
                session_ttl_s: None,
            }),
        };
        let d = p.evaluate(&wide);
        assert_eq!(d.limits.max_response_bytes, Some(1000));
        assert_eq!(d.limits.session_ttl_s, Some(300));

        // No declaration: rule limits stand alone.
        let plain = req("a", "vault://x", "t", "m");
        let d = p.evaluate(&plain);
        assert_eq!(d.limits.max_response_bytes, Some(1000));
    }

    #[test]
    fn empty_document_is_valid_pure_default_deny() {
        let p = Policy::from_toml("").unwrap();
        assert!(p.is_empty());
        let d = p.evaluate(&req("agent:a", "vault://x", "https://t", "http-bearer"));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.source, DecisionSource::DefaultDeny);
    }

    // ---------- canonical writer (D40) ----------

    #[test]
    fn to_toml_parses_back_to_identical_ruleset() {
        let doc = r#"
            [[rule]]
            name = "stripe \"prod\" # not a comment"
            effect = "allow"
            agent_id = "agent:planner-7"
            cred_ref = "vault://prod/stripe/*"
            target_uri = "https://api.stripe.com/v1/*"
            mechanism = "http-bearer"
            [rule.limits]
            max_response_bytes = 262144
            [rule.notify]
            on_use = false

            [[rule]]
            effect = "deny"
            target_uri = "prefix:https://api.github.com/orgs/*/hooks*"

            [[rule]]
            effect = "needs_confirmation"
            cred_ref = "exact:local://weird*path"
        "#;
        let p = Policy::from_toml(doc).unwrap();
        let regenerated = Policy::from_toml(&p.to_toml()).unwrap();
        assert_eq!(p.rules(), regenerated.rules());
        assert_eq!(p.len(), 3);

        // And evaluation agrees everywhere.
        for (a, c, t, m) in [
            (
                "agent:planner-7",
                "vault://prod/stripe/k",
                "https://api.stripe.com/v1/x",
                "http-bearer",
            ),
            (
                "agent:other",
                "vault://prod/stripe/k",
                "https://api.stripe.com/v1/x",
                "http-bearer",
            ),
            (
                "a",
                "local://weird*path",
                "https://api.github.com/orgs/x/hooksY",
                "ssh",
            ),
        ] {
            assert_eq!(
                p.evaluate(&req(a, c, t, m)),
                regenerated.evaluate(&req(a, c, t, m)),
                "{a} {c} {t} {m}"
            );
        }
    }

    #[test]
    fn every_matcher_kind_round_trips_through_source() {
        use crate::matcher::Matcher;
        for m in [
            Matcher::Any,
            Matcher::Exact("plain".to_owned()),
            Matcher::Exact("has*star".to_owned()),
            Matcher::Prefix("pre*fix".to_owned()),
            Matcher::Glob("https://x/*".to_owned()),
            Matcher::Glob("no-star".to_owned()),
            Matcher::Glob(String::new()),
        ] {
            match (&m, m.source()) {
                (Matcher::Any, None) => {}
                (_, Some(src)) => {
                    assert_eq!(&Matcher::parse(&src).unwrap(), &m, "source {src:?}");
                }
                (_, None) => assert!(matches!(m, Matcher::Any), "only Any serializes as absent"),
            }
        }
    }

    #[test]
    fn empty_policy_serializes_to_empty_document() {
        assert_eq!(Policy::empty().to_toml(), "");
        assert!(Policy::empty().is_empty());
    }

    #[test]
    fn writer_output_is_stable_and_explicit_about_notify() {
        let p = Policy::from_toml(
            "[[rule]]\neffect = \"allow\"\n[[rule]]\neffect=\"deny\"\n[rule.notify]\non_use=false\n",
        )
        .unwrap();
        let out = p.to_toml();
        // Both rules carry an explicit notify block; default-true is written
        // out so the file reads the way it behaves.
        assert_eq!(out.matches("[rule.notify]").count(), 2);
        assert!(out.contains("on_use = true"));
        assert!(out.contains("on_use = false"));
    }

    #[test]
    fn malformed_policies_fail_loudly() {
        // Unknown key: would have silently matched-any without strictness.
        let typo = r#"
            [[rule]]
            effect = "allow"
            agents_id = "agent:x"
        "#;
        assert!(matches!(
            Policy::from_toml(typo),
            Err(PolicyError::Schema(_))
        ));

        // Unknown effect string.
        let bad_effect = r#"
            [[rule]]
            effect = "probably_fine"
        "#;
        assert!(matches!(
            Policy::from_toml(bad_effect),
            Err(PolicyError::Schema(_))
        ));

        // Not TOML at all.
        assert!(matches!(
            Policy::from_toml("{{{"),
            Err(PolicyError::Schema(_))
        ));
    }

    // ---- D43: pair correlation ----

    const FLEET: &str = r#"
        [[rule]]
        name = "deployer fleet ssh, each key to its own host"
        effect = "allow"
        agent_id = "agent:deployer"
        mechanism = "ssh"
        target_uri = "ssh://*.internal"

          [[rule.pair]]
          cred_ref = "local://ssh/fleet/app-01"
          target_uri = "ssh://app-01.internal"

          [[rule.pair]]
          cred_ref = "local://ssh/fleet/app-02"
          target_uri = "ssh://app-02.internal"
    "#;

    #[test]
    fn pairs_bind_each_credential_to_its_own_host() {
        let p = Policy::from_toml(FLEET).unwrap();

        // Key app-01 against host app-01: allowed, pair[0].
        let ok = p.evaluate(&req(
            "agent:deployer",
            "local://ssh/fleet/app-01",
            "ssh://app-01.internal",
            "ssh",
        ));
        assert_eq!(ok.effect, Effect::Allow);
        assert_eq!(
            ok.source,
            DecisionSource::Rule {
                index: 0,
                name: Some("deployer fleet ssh, each key to its own host".to_owned()),
                pair: Some(0),
            }
        );

        // THE acceptance gate: key A (app-01) CANNOT reach host B (app-02).
        // Shared axes match (agent, mechanism, target_uri glob ssh://*.internal),
        // but no pair row binds app-01's key to app-02's host -> keep scanning
        // -> default-deny.
        let crossed = p.evaluate(&req(
            "agent:deployer",
            "local://ssh/fleet/app-01",
            "ssh://app-02.internal",
            "ssh",
        ));
        assert_eq!(
            crossed.effect,
            Effect::Deny,
            "credential app-01 must not reach host app-02"
        );
        assert_eq!(crossed.source, DecisionSource::DefaultDeny);

        // Key app-02 against host app-02: allowed, pair[1] (index reported).
        let ok2 = p.evaluate(&req(
            "agent:deployer",
            "local://ssh/fleet/app-02",
            "ssh://app-02.internal",
            "ssh",
        ));
        assert_eq!(ok2.effect, Effect::Allow);
        assert!(
            matches!(ok2.source, DecisionSource::Rule { pair: Some(1), .. }),
            "{:?}",
            ok2.source
        );
    }

    #[test]
    fn pairs_absent_means_prior_behavior_exactly() {
        // The SAMPLE rules carry no pairs; they must behave as before and
        // report pair: None (already asserted in parses_and_applies...).
        let p = Policy::from_toml(SAMPLE).unwrap();
        for rule in p.rules() {
            assert!(rule.pairs.is_empty(), "SAMPLE rules have no pair rows");
        }
    }

    #[test]
    fn empty_pair_table_is_equivalent_to_absent() {
        // D43: empty pair = [] is the same as no pairs (no AND-clause).
        let with_empty = Policy::from_toml(
            "[[rule]]\neffect = \"allow\"\nagent_id = \"agent:x\"\n[[rule.pair]]\n",
        );
        // A rule.pair with no fields fails the strict schema (cred_ref/
        // target_uri are required) — so "empty" means zero pair tables, not
        // one blank row. Assert zero rows parses and behaves as absent.
        let zero_rows =
            Policy::from_toml("[[rule]]\neffect = \"allow\"\nagent_id = \"agent:x\"\n").unwrap();
        assert!(zero_rows.rules()[0].pairs.is_empty());
        let d = zero_rows.evaluate(&req("agent:x", "c", "t", "m"));
        assert_eq!(d.effect, Effect::Allow);
        // And the writer never emits an empty pair table.
        assert!(!zero_rows.to_toml().contains("rule.pair"));
        // A blank [[rule.pair]] (missing required fields) is rejected loudly.
        assert!(
            with_empty.is_err(),
            "a pair row missing fields must fail the load"
        );
    }

    #[test]
    fn pair_row_missing_a_field_fails_loudly() {
        // Strict schema: a row must name both sides; a typo'd field is loud.
        let bad = r#"
            [[rule]]
            effect = "allow"
            [[rule.pair]]
            cred_ref = "local://x"
        "#;
        assert!(matches!(
            Policy::from_toml(bad),
            Err(PolicyError::Schema(_))
        ));
        let typo_field = r#"
            [[rule]]
            effect = "allow"
            [[rule.pair]]
            cred_ref = "local://x"
            target_url = "ssh://x"
        "#;
        assert!(matches!(
            Policy::from_toml(typo_field),
            Err(PolicyError::Schema(_))
        ));
    }

    #[test]
    fn pair_rows_roundtrip_through_the_writer() {
        let p = Policy::from_toml(FLEET).unwrap();
        let out = p.to_toml();
        assert_eq!(out.matches("[[rule.pair]]").count(), 2);
        // Re-parse what the writer produced and evaluate identically.
        let p2 = Policy::from_toml(&out).unwrap();
        assert_eq!(p2.rules()[0].pairs.len(), 2);
        let crossed = p2.evaluate(&req(
            "agent:deployer",
            "local://ssh/fleet/app-01",
            "ssh://app-02.internal",
            "ssh",
        ));
        assert_eq!(
            crossed.effect,
            Effect::Deny,
            "binding survived the round-trip"
        );
        let ok = p2.evaluate(&req(
            "agent:deployer",
            "local://ssh/fleet/app-02",
            "ssh://app-02.internal",
            "ssh",
        ));
        assert_eq!(ok.effect, Effect::Allow);
    }

    #[test]
    fn pair_fields_honor_matcher_tags() {
        // A deliberate glob: row covers a sub-range; bare strings are Exact.
        let p = Policy::from_toml(
            r#"
            [[rule]]
            effect = "allow"
            [[rule.pair]]
            cred_ref = "glob:local://ssh/fleet/app-*"
            target_uri = "glob:ssh://app-*.internal"
            "#,
        )
        .unwrap();
        // Both glob-matched consistently.
        assert_eq!(
            p.evaluate(&req(
                "a",
                "local://ssh/fleet/app-07",
                "ssh://app-07.internal",
                "m"
            ))
            .effect,
            Effect::Allow
        );
        // NOTE: a glob row does NOT bind key-N to host-N — app-07's key against
        // app-09's host also matches this single glob row. That is the
        // operator's explicit choice in writing a glob row; exact rows are the
        // per-host binding. Pinned here so the distinction is intentional.
        assert_eq!(
            p.evaluate(&req(
                "a",
                "local://ssh/fleet/app-07",
                "ssh://app-09.internal",
                "m"
            ))
            .effect,
            Effect::Allow,
            "a glob row matches by pattern, not by per-host identity"
        );
    }

    #[test]
    fn deny_rule_may_carry_pairs() {
        // D43: pairs on a deny rule are meaningful — deny key A against host B
        // specifically, while a broader allow covers the rest.
        let p = Policy::from_toml(
            r#"
            [[rule]]
            name = "never app-01 key against the db host"
            effect = "deny"
            [[rule.pair]]
            cred_ref = "local://ssh/fleet/app-01"
            target_uri = "ssh://db.internal"

            [[rule]]
            name = "otherwise fleet ssh is fine"
            effect = "allow"
            target_uri = "ssh://*.internal"
            "#,
        )
        .unwrap();
        // The specific denied binding hits rule[0].
        let denied = p.evaluate(&req(
            "a",
            "local://ssh/fleet/app-01",
            "ssh://db.internal",
            "ssh",
        ));
        assert_eq!(denied.effect, Effect::Deny);
        assert!(
            matches!(
                denied.source,
                DecisionSource::Rule {
                    index: 0,
                    pair: Some(0),
                    ..
                }
            ),
            "{:?}",
            denied.source
        );
        // A different key against the db host falls through to the allow.
        let allowed = p.evaluate(&req(
            "a",
            "local://ssh/fleet/app-02",
            "ssh://db.internal",
            "ssh",
        ));
        assert_eq!(allowed.effect, Effect::Allow);
        assert!(
            matches!(allowed.source, DecisionSource::Rule { index: 1, .. }),
            "{:?}",
            allowed.source
        );
    }
}

#[cfg(test)]
mod decision_source_label_tests {
    use super::*;

    #[test]
    fn source_label_renders_the_same_text_the_cli_prints() {
        assert_eq!(DecisionSource::DefaultDeny.label(), "default_deny");
        assert_eq!(
            DecisionSource::Rule {
                index: 3,
                name: Some("ci reads github".to_owned()),
                pair: None
            }
            .label(),
            "rule[3] (ci reads github)"
        );
        assert_eq!(
            DecisionSource::Rule {
                index: 3,
                name: None,
                pair: Some(17)
            }
            .label(),
            "rule[3] pair[17]"
        );
        assert_eq!(
            DecisionSource::Rule {
                index: 0,
                name: Some("n".to_owned()),
                pair: Some(2)
            }
            .label(),
            "rule[0] (n) pair[2]"
        );
    }

    #[test]
    fn cli_json_envelope_consumes_the_shared_label() {
        // The D36 pin: the CLI must not hand-roll this string. If someone
        // re-introduces a second formatter, the envelope test below is the
        // thing that notices.
        let s = DecisionSource::Rule {
            index: 3,
            name: Some("ci reads github".to_owned()),
            pair: Some(17),
        };
        let json = format!(
            "{{\"effect\":\"allow\",\"source\":\"{}\",\"limits\":{{\"max_response_bytes\":null,\"session_ttl_s\":null}}}}",
            s.label()
        );
        assert_eq!(
            json,
            r#"{"effect":"allow","source":"rule[3] (ci reads github) pair[17]","limits":{"max_response_bytes":null,"session_ttl_s":null}}"#
        );
    }
}
