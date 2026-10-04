//! P2-2: the rule editor's decision preview.
//!
//! Three affordances, all display-only, all built on the SAME code the
//! gateway uses (D36):
//!
//! 1. **A plain-language preview** of what a candidate rule permits,
//!    generated from the *parsed* `Rule` — never from the raw form strings,
//!    so it reflects what the validator actually produced (including the
//!    empty-axis-coerces-to-`Any` rule).
//! 2. **A boundary caveat** for globs whose `*` sits in a position that does
//!    not enforce a hostname or path boundary. A sentence, never a block.
//! 3. **A test box** that answers "what would this request do?" by calling
//!    `Policy::evaluate` and rendering `DecisionSource::label`.
//!
//! Nothing in here re-implements policy evaluation, and nothing parses a
//! preview string back into a matcher.

use chaperone_policy::{Matcher, Pair, Rule};

use crate::render::esc;

/// Builds a candidate rule the same way `rules_add` does, so the preview and
/// the saved artifact cannot disagree. Returns `None` when the form cannot
/// produce a rule at all (unknown mechanism, unknown effect).
#[must_use]
pub fn candidate_rule(
    mechanism: &str,
    target_uri: &str,
    agent_id: &str,
    cred_ref: &str,
    effect: &str,
    pairs_raw: &str,
) -> Option<Rule> {
    let effect = chaperone_policy::Effect::parse(effect)?;
    let axis = |raw: &str| -> Matcher {
        if raw.is_empty() {
            Matcher::Any
        } else {
            Matcher::parse(raw).unwrap_or(Matcher::Exact(raw.to_owned()))
        }
    };

    // Same rule as the editor: a malformed pair line fails the whole submit
    // rather than silently dropping a binding that would over-permit. For
    // the preview, a malformed line means "cannot preview yet" — the form
    // will reject the save, so we must not show a rosy preview of it.
    let mut pairs: Vec<Pair> = Vec::new();
    for line in pairs_raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (cred, target) = line.split_once('|')?;
        pairs.push(Pair {
            cred_ref: Matcher::parse(cred.trim()).unwrap_or(Matcher::Exact(cred.trim().to_owned())),
            target_uri: Matcher::parse(target.trim())
                .unwrap_or(Matcher::Exact(target.trim().to_owned())),
        });
    }

    Some(Rule {
        name: None,
        notify_on_use: true,
        effect,
        agent_id: axis(agent_id),
        cred_ref: axis(cred_ref),
        target_uri: axis(target_uri),
        mechanism: axis(mechanism),
        pairs,
        limits: chaperone_policy::Limits::default(),
    })
}

/// One sentence, in plain language, saying what the rule permits.
#[must_use]
pub fn rule_sentence(rule: &Rule) -> String {
    let verb = match rule.effect {
        chaperone_policy::Effect::Allow => "allow",
        chaperone_policy::Effect::NeedsConfirmation => "ask a human, then allow",
        chaperone_policy::Effect::Deny => "deny",
    };
    format!(
        "This rule would {verb}: agent {}, using credential {}, against target {}, over {}.",
        rule.agent_id.describe(),
        rule.cred_ref.describe(),
        rule.target_uri.describe(),
        rule.mechanism.describe(),
    )
}

/// The binding list as prose, one line per pair. Empty string when the rule
/// carries no bindings.
#[must_use]
pub fn pairs_sentence(rule: &Rule) -> String {
    if rule.pairs.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = rule
        .pairs
        .iter()
        .map(|p| {
            format!(
                "    {} \u{2192} {}",
                p.cred_ref.describe(),
                p.target_uri.describe()
            )
        })
        .collect();
    format!(
        "  It also binds {} credential(s) to their own endpoint (D43):\n{}",
        rule.pairs.len(),
        lines.join("\n")
    )
}

/// The boundary caveat, or `None` when the glob is not in a dangerous
/// position.
///
/// Heph's ruling (2026-10-03), applied literally and mechanically — no regex:
///
/// - Fires on `*.`  — a star immediately before a dot. `*` spans ALL
///   characters including `/` and `:`, so `ssh://*.internal` does NOT enforce
///   a hostname boundary: `ssh://evil.com/.internal` matches it. This is the
///   bypass called out in `matcher.rs`'s own SECURITY NOTE.
/// - Fires on `*/` — a star spanning into a path, same class of hazard.
/// - Does **NOT** fire on a trailing `/*`. That is a legitimate open tail
///   (`vault://prod/*`); caveat-ing it would put the warning on every fleet
///   rule and train operators to dismiss it, which is the exact failure the
///   caveat exists to prevent.
#[must_use]
pub fn boundary_caveat(rule: &Rule) -> Option<String> {
    let risky = [&rule.target_uri, &rule.cred_ref]
        .into_iter()
        .any(|axis| match axis {
            Matcher::Glob(g) => g.contains('*') && (g.contains("*.") || g.contains("*/")),
            _ => false,
        });
    if !risky {
        return None;
    }
    Some(
        "Caveat: in a glob, `*` spans every character \u{2014} including `/` and \
         `:`. A star before a dot does not enforce a hostname boundary, so \
         `ssh://*.internal` also matches `ssh://evil.com/.internal`. Where a \
         boundary matters, anchor with `exact:` or `prefix:` on the trusted \
         portion and leave `*` only on an open-ended tail."
            .to_owned(),
    )
}

/// The whole preview block: the sentence, the bindings, the caveat, and an
/// explicit "not saved yet" label so an operator cannot mistake a candidate
/// for the current state of their ruleset.
#[must_use]
pub fn preview_block(rule: &Rule) -> String {
    let mut out = String::from("<div class=\"card\"><strong>This rule would allow</strong></div>");
    // The sentence already begins "This rule would …", so render it as the
    // body rather than repeating the heading.
    out.clear();
    out.push_str("<div class=\"card\"><strong>Preview (not saved yet)</strong><br>");
    out.push_str(&esc(&rule_sentence(rule)));
    let pairs = pairs_sentence(rule);
    if !pairs.is_empty() {
        out.push_str("<br>");
        out.push_str(&esc(&pairs));
    }
    if let Some(caveat) = boundary_caveat(rule) {
        out.push_str("<p class=\"err\">");
        out.push_str(&esc(&caveat));
        out.push_str("</p>");
    }
    out.push_str("</div>");
    out
}

/// The test box's rendered verdict. `label` comes from
/// `DecisionSource::label` — the same string `policy-check` prints, so the
/// two surfaces cannot drift (P2-2 ruling 2).
#[must_use]
pub fn verdict_block(effect: &str, label: &str) -> String {
    let plain = match effect {
        "allow" => "allow \u{2014} permitted without prompting",
        "needs_confirmation" => "needs_confirmation \u{2014} a human must approve each use",
        _ => "deny \u{2014} refused",
    };
    format!(
        "<div class=\"card\"><strong>Verdict: {plain}</strong><br>\
         <span class=\"muted\">reached by</span> <code>{label}</code></div>"
    )
}
