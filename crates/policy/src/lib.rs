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
    fn parse(raw: &str) -> Option<Effect> {
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

/// One auditable rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Optional human label, echoed in decisions for audit legibility.
    pub name: Option<String>,
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
    },
}

/// A complete verdict (PROTO-SPEC §9.1): effect, provenance, effective
/// ceilings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// What policy permits.
    pub effect: Effect,
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
    #[serde(default)]
    limits: Option<LimitsDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsDef {
    #[serde(default)]
    max_response_bytes: Option<u64>,
    #[serde(default)]
    session_ttl_s: Option<u64>,
}

/// The active ruleset.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    rules: Vec<Rule>,
}

impl Policy {
    /// An empty policy: everything denied, provably.
    #[must_use]
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
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
            rules.push(Rule {
                name: def.name,
                effect,
                agent_id: axis("agent_id", &def.agent_id)?,
                cred_ref: axis("cred_ref", &def.cred_ref)?,
                target_uri: axis("target_uri", &def.target_uri)?,
                mechanism: axis("mechanism", &def.mechanism)?,
                limits: def
                    .limits
                    .map(|l| Limits {
                        max_response_bytes: l.max_response_bytes,
                        session_ttl_s: l.session_ttl_s,
                    })
                    .unwrap_or_default(),
            });
        }
        Ok(Policy { rules })
    }

    /// Builds directly from rules (programmatic construction / tests).
    #[must_use]
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Number of rules loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
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
                return Decision {
                    effect: rule.effect,
                    source: DecisionSource::Rule {
                        index,
                        name: rule.name.clone(),
                    },
                    limits: rule.limits.min_with(declared_limits),
                };
            }
        }

        Decision {
            effect: Effect::Deny,
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
                name: Some("stripe charges".to_owned())
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
                name: Some("no prod ssh for interns".to_owned())
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
}
