//! Mechanism + service-template catalog for the rule editor.
//!
//! A static snapshot of `docs/CONNECTIVITY-MATRIX.md` §1/§2, embedded so the
//! UI shows maturity badges and caveats BEFORE a rule is built around a
//! partial mechanism (the exact `target_uri` failure this crate exists to
//! fix). The matrix remains the living document; update both together.

/// Maturity badge, verbatim semantics from CONNECTIVITY-MATRIX.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    /// Implemented, tested, documented.
    Stable,
    /// Works with documented limitations.
    Caveated,
    /// On the roadmap, not built.
    Planned,
}

impl Maturity {
    /// Badge glyph + word.
    #[must_use]
    pub fn badge(self) -> &'static str {
        match self {
            Maturity::Stable => "\u{2705} supported",
            Maturity::Caveated => "\u{26A0}\u{FE0F} partial",
            Maturity::Planned => "\u{1F5FA}\u{FE0F} planned",
        }
    }
}

/// One row of CONNECTIVITY-MATRIX §1 (mechanisms).
#[derive(Debug, Clone, Copy)]
pub struct Mechanism {
    /// Wire mechanism id (`mechanism = "..."`).
    pub id: &'static str,
    /// Display label.
    pub label: &'static str,
    /// Lifecycle shape.
    pub lifecycle: &'static str,
    /// Credential form the vault must hold.
    pub credential_form: &'static str,
    /// Maturity badge.
    pub maturity: Maturity,
    /// Confirmation behavior summary.
    pub confirmation: &'static str,
}

/// All v1 mechanisms, matrix order.
pub const MECHANISMS: &[Mechanism] = &[
    Mechanism {
        id: "http-bearer",
        label: "HTTP bearer token",
        lifecycle: "one-shot",
        credential_form: "bearer token",
        maturity: Maturity::Stable,
        confirmation: "per policy",
    },
    Mechanism {
        id: "http-basic",
        label: "HTTP basic auth",
        lifecycle: "one-shot",
        credential_form: "password (username rides the intent)",
        maturity: Maturity::Stable,
        confirmation: "per policy",
    },
    Mechanism {
        id: "db-scram",
        label: "PostgreSQL SCRAM-SHA-256",
        lifecycle: "one-shot or session",
        credential_form: "database password",
        maturity: Maturity::Stable,
        confirmation: "per policy",
    },
    Mechanism {
        id: "ssh",
        label: "SSH session",
        lifecycle: "session",
        credential_form: "Ed25519 private key",
        maturity: Maturity::Stable,
        confirmation: "per policy",
    },
    Mechanism {
        id: "local-privilege",
        label: "Local privileged command",
        lifecycle: "session (one pinned exec)",
        credential_form: "none (sudoers / pin allowlist)",
        maturity: Maturity::Stable,
        confirmation: "ALWAYS unless command+args exactly pinned",
    },
];

/// One row of CONNECTIVITY-MATRIX §2: a pre-validated target shape.
#[derive(Debug, Clone, Copy)]
pub struct ServiceTemplate {
    /// Which mechanism this template applies to.
    pub mechanism: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Pre-filled `target_uri` glob.
    pub target_uri: &'static str,
    /// Caveat lifted from the matrix Notes column (shown inline).
    pub note: Option<&'static str>,
}

/// Service templates per mechanism (matrix §2 selection; `custom` is always
/// available as free text - templating is an aid, not a wall).
pub const TEMPLATES: &[ServiceTemplate] = &[
    ServiceTemplate {
        mechanism: "http-bearer",
        name: "Any HTTPS API (general case)",
        target_uri: "https://*",
        note: None,
    },
    ServiceTemplate {
        mechanism: "http-bearer",
        name: "GitHub REST API v3",
        target_uri: "https://api.github.com/*",
        note: Some("Use a fine-grained PAT scoped to needed repos only. Tested shape."),
    },
    ServiceTemplate {
        mechanism: "http-bearer",
        name: "GraphQL API (GitHub v4, Hasura, ...)",
        target_uri: "https://*/graphql",
        note: Some("POST-with-JSON rides the same injector."),
    },
    ServiceTemplate {
        mechanism: "http-bearer",
        name: "Kubernetes API",
        target_uri: "https://kubernetes.default.svc/*",
        note: Some(
            "\u{26A0}\u{FE0F} custom/private CA roots are not configurable yet \
             (backlog C1): works against clusters with publicly-trusted certs.",
        ),
    },
    ServiceTemplate {
        mechanism: "http-bearer",
        name: "OAuth2 client-credentials endpoint (manual)",
        target_uri: "https://*",
        note: Some(
            "Token fetched once into the vault by the operator; automatic \
             refresh is post-v1.",
        ),
    },
    ServiceTemplate {
        mechanism: "http-basic",
        name: "Any HTTPS API (basic auth)",
        target_uri: "https://*",
        note: Some("Username travels in the intent, password stays in the vault."),
    },
    ServiceTemplate {
        mechanism: "db-scram",
        name: "PostgreSQL (incl. Supabase/RDS/Cloud SQL)",
        target_uri: "postgres://USER@HOST:5432/DBNAME",
        note: Some(
            "\u{26A0}\u{FE0F} TLS-to-DB is NOT negotiated yet (D27): restrict \
             to networks you trust.",
        ),
    },
    ServiceTemplate {
        mechanism: "ssh",
        name: "SSH host (shell or remote commands)",
        target_uri: "ssh://USER@HOST",
        note: Some(
            "Host keys are pinned (TOFU or known_hosts import); a changed key is a hard refusal.",
        ),
    },
    ServiceTemplate {
        mechanism: "local-privilege",
        name: "Local privileged commands (systemctl, apt, ...)",
        target_uri: "local://HOST",
        note: Some(
            "Every use is confirmed unless the operator pinned the exact \
             command+args; the helper re-checks authoritatively.",
        ),
    },
];

/// Templates scoped to one mechanism.
#[must_use]
pub fn templates_for(mechanism: &str) -> Vec<&'static ServiceTemplate> {
    TEMPLATES
        .iter()
        .filter(|t| t.mechanism == mechanism)
        .collect()
}

/// Matrix row for a mechanism id.
#[must_use]
pub fn mechanism(id: &str) -> Option<&'static Mechanism> {
    MECHANISMS.iter().find(|m| m.id == id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    #[test]
    fn every_mechanism_has_at_least_one_template() {
        for m in super::MECHANISMS {
            assert!(
                !super::templates_for(m.id).is_empty(),
                "{} has no service template",
                m.id
            );
            assert!(super::mechanism(m.id).is_some());
        }
    }

    #[test]
    fn template_target_uris_are_parseable_matchers() {
        for t in super::TEMPLATES {
            // Must survive the real matcher parser unchanged.
            let m = chaperone_policy::Matcher::parse(t.target_uri).unwrap();
            // And match its own literal form (self-consistent glob).
            assert!(
                m.matches(t.target_uri),
                "{} does not match itself",
                t.target_uri
            );
        }
    }
}
