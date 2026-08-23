//! Rule matchers: deliberately boring, fully auditable string predicates.
//!
//! Syntax (DESIGN-DECISIONS D3, D17):
//!
//! | Written as            | Means                                            |
//! |-----------------------|--------------------------------------------------|
//! | field absent          | `Any` — matches everything                       |
//! | `glob:<pattern>`      | `Glob` — `*` matches any run of characters       |
//! | `prefix:<literal>`    | `Prefix` — literal byte-prefix                   |
//! | anything containing `*` (no tag) | same as `glob:`                       |
//! | otherwise             | `Exact` — full-string equality, case-sensitive   |
//!
//! No regex. A literal value that must contain `*` uses the explicit
//! `prefix:` or `exact:`-style tags; there is no escaping to misread.
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
}
