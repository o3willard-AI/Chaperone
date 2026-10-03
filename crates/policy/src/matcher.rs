//! Rule matchers: deliberately boring, fully auditable string predicates.
//!
//! Syntax (DESIGN-DECISIONS D3, D17):
//!
//! | Written as            | Means                                            |
//! |-----------------------|--------------------------------------------------|
//! | field absent          | `Any` — matches everything                       |
//! | `glob:<pattern>`      | `Glob` — `*` matches any run of characters       |
//! | `prefix:<literal>`    | `Prefix` — literal byte-prefix                   |
//! | `exact:<literal>`     | `Exact` — full-string equality, even with `*`    |
//! | anything containing `*` (no tag) | same as `glob:`                       |
//! | otherwise             | `Exact` — full-string equality, case-sensitive   |
//!
//! No regex. The `exact:` tag exists so every matcher kind round-trips
//! through [`Matcher::parse`] losslessly (the canonical TOML writer relies
//! on it); before it was added, a literal value containing `*` could not be
//! written as an exact match at all.
//!
//! SECURITY NOTE: `*` spans ALL characters including `/` and `:`. A pattern
//! like `https://*.example.com/x` does NOT enforce hostname boundaries
//! (`https://evil.com/.example.com/x` matches). Where a boundary matters,
//! anchor with `Exact`/`Prefix` on the trusted portion and keep `Glob` for
//! open-ended tails.

use std::fmt;

/// One axis predicate in a [`crate::Rule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// Matches any value.
    Any,
    /// Full-string equality.
    Exact(String),
    /// Literal prefix.
    Prefix(String),
    /// Glob with `*` wildcards only; see [`glob_match`].
    Glob(String),
}

impl Matcher {
    /// Parses a rule-file string into a matcher per the table above.
    pub fn parse(raw: &str) -> Result<Matcher, MatcherError> {
        if let Some(pat) = raw.strip_prefix("glob:") {
            return Ok(Matcher::Glob(pat.to_owned()));
        }
        if let Some(lit) = raw.strip_prefix("prefix:") {
            return Ok(Matcher::Prefix(lit.to_owned()));
        }
        if let Some(lit) = raw.strip_prefix("exact:") {
            return Ok(Matcher::Exact(lit.to_owned()));
        }
        if raw.contains('*') {
            return Ok(Matcher::Glob(raw.to_owned()));
        }
        Ok(Matcher::Exact(raw.to_owned()))
    }

    /// Evaluates the matcher against a candidate string.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        match self {
            Matcher::Any => true,
            Matcher::Exact(v) => v == candidate,
            Matcher::Prefix(p) => candidate.starts_with(p.as_str()),
            Matcher::Glob(g) => glob_match(g, candidate),
        }
    }

    /// Operator-facing plain-language rendering of this axis, e.g. `any
    /// value`, `exactly \`planner-7\``, `starting with \`local://prod/\``.
    ///
    /// **DISPLAY ONLY.** This never participates in a decision, and its
    /// output is deliberately NOT re-parseable into an equivalent matcher —
    /// the decoration (`exactly`, backticks) is what guarantees that, and
    /// `describe_is_display_only_and_never_round_trips_into_a_decision`
    /// pins it. If a caller ever feeds this string back into
    /// [`Matcher::parse`], that is a bug: a display helper must never become
    /// a security boundary by accident.
    ///
    /// The wording is also the UI's axis vocabulary, so the rule preview
    /// (P2-2) can join phrases without knowing anything about matcher
    /// internals. `Matcher::Any` reads as "any", never as the literal `*`:
    /// an empty axis is *wider* than a glob of `*`, and an operator who
    /// cannot tell them apart is being told their rule is narrower than it
    /// is.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Matcher::Any => "any value".to_owned(),
            Matcher::Exact(v) => format!("exactly `{v}`"),
            Matcher::Prefix(p) => format!("starting with `{p}`"),
            Matcher::Glob(g) => format!("matching `{g}`"),
        }
    }

    /// The rule-file string that parses back to exactly this matcher
    /// (`None` for [`Matcher::Any`], which is written by omitting the axis).
    ///
    /// This is the canonical serialization used by the TOML writer; the
    /// invariant `parse(source()) == *self` (for non-Any) is tested.
    #[must_use]
    pub fn source(&self) -> Option<String> {
        match self {
            Matcher::Any => None,
            Matcher::Exact(v) => {
                if v.contains('*') {
                    Some(format!("exact:{v}"))
                } else {
                    Some(v.clone())
                }
            }
            Matcher::Prefix(p) => Some(format!("prefix:{p}")),
            Matcher::Glob(g) => {
                if g.contains('*') {
                    // A bare pattern containing `*` re-parses as Glob.
                    Some(g.clone())
                } else {
                    // Wildcard-less globs (incl. the empty glob) need the
                    // tag to keep their kind across a save/load cycle.
                    Some(format!("glob:{g}"))
                }
            }
        }
    }
}

/// Why a matcher string could not be parsed (reserved for future syntax
/// errors; current grammar accepts every string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherError(pub String);

impl fmt::Display for MatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid matcher: {}", self.0)
    }
}

impl std::error::Error for MatcherError {}

/// Glob matching where `*` stands for any run of characters (including none,
/// including separators). Greedy left-to-right; no other metacharacters.
///
/// Operates on bytes but never slices mid-character: all indices come from
/// successful ASCII-boundary-safe operations (`starts_with`, `find`,
/// `ends_with`, lengths).
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }

    let head = parts[0];
    if !text.starts_with(head) {
        return false;
    }
    let mut pos = head.len();

    for middle in &parts[1..parts.len() - 1] {
        if middle.is_empty() {
            continue;
        }
        match text[pos..].find(middle) {
            Some(found) => pos += found + middle.len(),
            None => return false,
        }
    }

    let tail = parts[parts.len() - 1];
    if tail.is_empty() {
        return true;
    }
    // The tail must fit after `pos`: enough bytes remaining AND actually at
    // the end.
    text.len().saturating_sub(pos) >= tail.len() && text.ends_with(tail)
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_is_case_sensitive_equality() {
        let m = Matcher::parse("agent:planner-7").unwrap();
        assert_eq!(m, Matcher::Exact("agent:planner-7".to_owned()));
        assert!(m.matches("agent:planner-7"));
        assert!(!m.matches("Agent:planner-7"));
        assert!(!m.matches("agent:planner-70"));
    }

    #[test]
    fn absent_means_any() {
        assert!(Matcher::Any.matches("anything"));
        assert!(Matcher::Any.matches(""));
    }

    #[test]
    fn tagged_glob_and_prefix() {
        let g = Matcher::parse("glob:vault://prod/*").unwrap();
        assert_eq!(g, Matcher::Glob("vault://prod/*".to_owned()));
        assert!(g.matches("vault://prod/stripe/key"));
        assert!(!g.matches("vault://dev/stripe/key"));

        let p = Matcher::parse("prefix:vault://prod/").unwrap();
        assert!(p.matches("vault://prod/anything/at/all"));
        assert!(!p.matches("vault://production/x"));
    }

    #[test]
    fn bare_star_becomes_glob() {
        assert_eq!(
            Matcher::parse("https://api.example.com/v1/*").unwrap(),
            Matcher::Glob("https://api.example.com/v1/*".to_owned())
        );
    }

    #[test]
    fn glob_semantics_documented_cases() {
        assert!(glob_match("*", "anything at all"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(glob_match("a*b*c", "abc")); // zero-width middles
        assert!(!glob_match("a*b*c", "aXXbYY")); // missing tail
        assert!(!glob_match("ab*ba", "aba")); // tail would overlap head
        assert!(glob_match("*x*y*", "zxqywz"));
        // `*` spans separators too - including '/'. This is the documented
        // deal: "*.example.com" matches "evil.com/.example.com", so rules
        // needing host/path boundaries MUST anchor with exact or prefix.
        assert!(glob_match("*.example.com", "evil.com/.example.com"));
        assert!(glob_match("*.example.com", "api.sub.example.com"));
    }

    #[test]
    fn utf8_candidates_do_not_panic() {
        let g = Matcher::parse("cred-é*").unwrap();
        assert!(g.matches("cred-é-key-日本語"));
        assert!(!g.matches("cred-x"));
        let p = Matcher::Prefix("日".to_owned());
        assert!(p.matches("日本語"));
    }

    // ---- P2-2: operator-facing rendering (display only) ----

    #[test]
    fn describe_any_says_any_never_a_literal_star() {
        // The pin that matters: an empty axis coerces to `Any`, and the UI
        // used to render that as the literal "*" via its own display hack.
        // "any <thing>" and a glob "*" must never read the same, or the
        // preview tells an operator their rule is narrower than it is.
        let d = Matcher::Any.describe();
        assert!(
            d.starts_with("any "),
            "Any should read as 'any ...', got {d}"
        );
        assert!(
            !d.contains("\"*\""),
            "Any must not render as a literal *, got {d}"
        );
        // A glob of "*" is a *different* thing and must not read as "any".
        assert_ne!(d, Matcher::Glob("*".to_owned()).describe());
    }

    #[test]
    fn describe_renders_each_variant_distinctly() {
        let variants = [
            Matcher::Any,
            Matcher::Exact("agent:planner-7".to_owned()),
            Matcher::Prefix("local://prod/".to_owned()),
            Matcher::Glob("vault://prod/*".to_owned()),
        ];
        let rendered: Vec<String> = variants.iter().map(Matcher::describe).collect();
        for (i, a) in rendered.iter().enumerate() {
            for (j, b) in rendered.iter().enumerate() {
                assert!(
                    i == j || a != b,
                    "variants {i} and {j} render identically: {a}"
                );
            }
        }
    }

    #[test]
    fn describe_is_display_only_and_never_round_trips_into_a_decision() {
        // "Display only" means exactly this: feeding describe() output back
        // into parse() must not silently reconstruct a matcher. If some future
        // caller does that, describe() has become a security boundary by
        // accident. Every rendering that contains a `*`-bearing value is
        // checked to be un-parseable back to an equivalent matcher.
        for m in [
            Matcher::Any,
            Matcher::Exact("agent:planner-7".to_owned()),
            Matcher::Prefix("local://prod/".to_owned()),
            Matcher::Glob("vault://prod/*".to_owned()),
            Matcher::Glob("ssh://*.internal".to_owned()),
        ] {
            let d = m.describe();
            if let Ok(back) = Matcher::parse(&d) {
                assert_ne!(
                    back, m,
                    "describe output re-parsed into the same matcher ({d:?}); \
                     it must stay display-only"
                );
            }
        }
    }
}
