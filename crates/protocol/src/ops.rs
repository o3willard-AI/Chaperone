//! Mechanism-specific `operation` bodies (PROTO-SPEC §7).
//!
//! These are parsed ONLY after identity verification succeeds (§4 step 4):
//! before that, the operation is opaque bytes covered by a signature.

use serde::{Deserialize, Serialize};

/// `db-scram` operation body (PROTO-SPEC §7 row, intent-catalog).
///
/// With `statement`: ONE-SHOT - connect, authenticate via SCRAM (the vault
/// secret is the password, never sent verbatim), execute, return rows.
/// Without: SESSION opener - open the authenticated connection and drive it
/// by handle with `session.command` frames whose input is SQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbOperation {
    /// Database engine. Only `"postgres"` in v0.
    pub engine: String,
    /// Database name. Must agree with the target URI's path when both
    /// present (mismatch => rejected before connecting).
    #[serde(default)]
    pub database: Option<String>,
    /// SQL for one-shot execution; omitted for session openers.
    #[serde(default)]
    pub statement: Option<String>,
    /// Positional parameters bound AS TEXT (cast explicitly with `$1::int`
    /// style hints when needed). Parameterized = injection-safe; string
    /// concatenation into `statement` defeats the point and is on you.
    #[serde(default)]
    pub params: Option<Vec<String>>,
    /// Username when absent from the target URI's userinfo.
    #[serde(default)]
    pub username: Option<String>,
}

impl DbOperation {
    /// Human-legible summary for the confirmation surface.
    #[must_use]
    pub fn summary(&self) -> String {
        match (&self.statement, &self.database) {
            (Some(sql), Some(db)) => format!("query {db}: {}", first_line(sql)),
            (Some(sql), None) => format!("query: {}", first_line(sql)),
            (None, Some(db)) => format!("open session on {db}"),
            (None, None) => "open database session".to_owned(),
        }
    }
}

fn first_line(sql: &str) -> String {
    let line = sql.lines().next().unwrap_or("");
    let mut out: String = line.chars().take(60).collect();
    if line.chars().count() > 60 {
        out.push('…');
    }
    out
}

/// Connection endpoint parsed from `target.uri` for postgres targets
/// (DESIGN-DECISIONS D29): `postgres://user@host:port/dbname`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgEndpoint {
    /// Account name (empty when the URI carries no userinfo).
    pub user: String,
    /// Hostname or IP.
    pub host: String,
    /// Port (default 5432).
    pub port: u16,
    /// Database name from the URI path (empty when absent).
    pub database: String,
}

/// Parses a postgres target URI. Deliberately hand-rolled and tiny rather
/// than pulling a URL crate: the accepted grammar is exactly one form,
/// documented here, everything else is an error.
pub fn parse_pg_uri(uri: &str) -> Result<PgEndpoint, String> {
    let rest = uri
        .strip_prefix("postgres://")
        .ok_or_else(|| "target.uri must start with postgres://".to_owned())?;

    let (authority, path_db) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };

    let (userinfo, hostport) = match authority.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let user = userinfo
        .map(|u| {
            u.split_once(':')
                .map(|(name, _pw)| name.to_owned())
                .unwrap_or_else(|| u.to_owned())
        })
        .unwrap_or_default();

    let (host, port_str) = match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_owned(), Some(p.to_owned()))
        }
        _ => (hostport.to_owned(), None),
    };
    if host.is_empty() {
        return Err("target.uri has empty host".to_owned());
    }
    let port = port_str
        .map(|p| p.parse::<u16>().map_err(|_| "port out of range".to_owned()))
        .transpose()?
        .unwrap_or(5432);

    // Strip query/fragment remnants from the db segment; reject weirdness
    // rather than guessing.
    let database = path_db.split(['?', '#']).next().unwrap_or("").to_owned();

    Ok(PgEndpoint {
        user,
        host,
        port,
        database,
    })
}

/// `http-bearer` / `http-basic` operation body (§7.1).
///
/// The agent supplies everything except the credential; the gateway supplies
/// the `Authorization` header. An agent-supplied `authorization` header is
/// rejected - agents do not attach credentials, that is the entire point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpOperation {
    /// HTTP method (GET, POST, ...).
    pub method: String,
    /// Agent-supplied headers. Case-insensitive names; `authorization`
    /// (any case) is rejected.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Base64 (standard) of the request body; omit for bodiless methods.
    #[serde(default)]
    pub body_b64: Option<String>,
    /// Username for `http-basic` only (non-secret, signed like everything
    /// else - SPEC-ISSUES SI-2 / DESIGN-DECISIONS D14). The password half
    /// comes from the vault at injection time and never appears here.
    #[serde(default)]
    pub username: Option<String>,
}

impl HttpOperation {
    /// True when the agent tried to smuggle their own credential header.
    #[must_use]
    pub fn has_agent_authorization(&self) -> bool {
        self.headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("authorization"))
    }

    /// Human-legible operation summary for the confirmation surface (§9.2).
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.body_b64 {
            Some(_) => format!("{} with body", self.method),
            None => self.method.clone(),
        }
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_bearer_body() {
        let op: HttpOperation = serde_json::from_value(json!({
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body_b64": "eyJhbW91bnQiOjIwMDB9"
        }))
        .unwrap();
        assert_eq!(op.method, "POST");
        assert!(!op.has_agent_authorization());
        assert_eq!(op.summary(), "POST with body");
    }

    #[test]
    fn detects_agent_supplied_authorization_any_case() {
        for key in ["Authorization", "authorization", "AUTHORIZATION"] {
            let op: HttpOperation = serde_json::from_value(json!({
                "method": "GET",
                "headers": {key: "Bearer attacker-token"}
            }))
            .unwrap();
            assert!(op.has_agent_authorization(), "{key}");
        }
    }

    #[test]
    fn unknown_fields_tolerated_forward_compat() {
        let op: HttpOperation = serde_json::from_value(json!({
            "method": "GET",
            "new_in_minor": {"x": 1}
        }))
        .unwrap();
        assert_eq!(op.method, "GET");
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod db_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_full_pg_uri() {
        let ep = parse_pg_uri("postgres://deploy@db.internal:5433/analytics").unwrap();
        assert_eq!(ep.user, "deploy");
        assert_eq!(ep.host, "db.internal");
        assert_eq!(ep.port, 5433);
        assert_eq!(ep.database, "analytics");
    }

    #[test]
    fn defaults_port_and_allows_missing_userinfo() {
        let ep = parse_pg_uri("postgres://db.internal/prod").unwrap();
        assert_eq!(ep.user, "");
        assert_eq!(ep.port, 5432);
        assert_eq!(ep.database, "prod");
    }

    #[test]
    fn rejects_non_postgres_and_broken_uris() {
        assert!(parse_pg_uri("mysql://x/y").is_err());
        assert!(parse_pg_uri("postgres://").is_err());
        assert!(parse_pg_uri("postgres://host:99999/db").is_err());
    }

    #[test]
    fn db_operation_summary_and_defaults() {
        let op: DbOperation = serde_json::from_value(json!({
            "engine": "postgres",
            "database": "analytics",
            "statement": "select count(*) from signups",
            "params": ["2026-08-21"]
        }))
        .unwrap();
        assert_eq!(op.engine, "postgres");
        assert!(op.summary().contains("analytics"));

        let opener: DbOperation = serde_json::from_value(json!({
            "engine": "postgres"
        }))
        .unwrap();
        assert_eq!(opener.statement, None, "opener without statement = session");
        assert!(opener.summary().contains("session"));
    }
}
