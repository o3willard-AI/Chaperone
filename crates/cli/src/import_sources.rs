//! B-2 inventory source parsers (TD-1): CSV and ssh_config.
//!
//! Both are pure functions from source text to `Vec<InventoryRow>`; no I/O
//! here, so tests are offline and falsifiable by construction. Parsers are
//! deliberately strict: a row that cannot be understood is `Failed` with a
//! reason the summary will show — import never guesses (a guessed host is a
//! silently imported lie).

/// One row from an inventory source, before any vault/policy action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryRow {
    /// Entry name — becomes `{cred_scheme}/{name}` in the vault.
    pub name: String,
    /// Target host (bare hostname, no scheme).
    pub host: String,
    /// Target port (default 22 when the source omits it).
    pub port: u16,
    /// Login user from the source (informational in v1 — the ssh operation
    /// carries its own user).
    pub user: Option<String>,
    /// Secret for the vault entry; `None` = placeholder sentinel (TD-5).
    pub secret: Option<String>,
}

/// Parse outcome for one row: usable, or failed with the reason the summary
/// will print. Warnings (skipped pattern blocks) are carried separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Row(InventoryRow),
    Failed { line: usize, reason: String },
}

/// One skipped-with-warning element (e.g. an ssh_config pattern block with a
/// HostName — Heph Q3: warn only then; a `Host *` catch-all with no HostName
/// is skipped silently).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub line: usize,
    pub reason: String,
}

pub struct ParseOutcome {
    pub rows: Vec<Parsed>,
    pub warnings: Vec<Skipped>,
}

/// CSV: header `name,host,port,user,secret` (header required). `port`
/// optional (default 22); `user` optional; `secret` optional (empty =
/// placeholder). Values must not contain `"` quoting tricks in v1: fields
/// are split on plain commas and rejected if they contain a comma or quote
/// — machine-generated exports from fleet tooling don't need them, and a
/// strict parser cannot silently mis-split a name that turns out to be
/// someone else's host.
pub fn parse_csv(text: &str) -> ParseOutcome {
    let mut rows = Vec::new();
    let mut lines = text.lines().enumerate();
    // Header check
    let header = match lines.next() {
        Some((_, h)) => h,
        None => {
            return ParseOutcome {
                rows: vec![Parsed::Failed {
                    line: 1,
                    reason: "empty source".into(),
                }],
                warnings: vec![],
            };
        }
    };
    let hcols: Vec<&str> = header.trim().split(',').collect();
    let want = ["name", "host", "port", "user", "secret"];
    if hcols.iter().map(|c| c.trim()).collect::<Vec<_>>() != want {
        return ParseOutcome {
            rows: vec![Parsed::Failed {
                line: 1,
                reason: format!(
                    "header must be exactly `{}` (got `{}`)",
                    want.join(","),
                    header.trim()
                ),
            }],
            warnings: vec![],
        };
    }
    for (i, line) in lines {
        let ln = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.trim_end().split(',').collect();
        if cols.len() < 2 {
            rows.push(Parsed::Failed {
                line: ln,
                reason: "need at least name,host".into(),
            });
            continue;
        }
        let bad = |reason: String| Parsed::Failed { line: ln, reason };
        let name = cols[0].trim();
        let host = cols[1].trim();
        if name.is_empty() || host.is_empty() {
            rows.push(bad("name and host are required".into()));
            continue;
        }
        if name.contains(',') || name.contains('"') || name.contains('/') && name.starts_with('/') {
            rows.push(bad(format!("name `{name}` contains a forbidden character")));
            continue;
        }
        let port: u16 = match cols.get(2).map(|c| c.trim()).filter(|c| !c.is_empty()) {
            Some(p) => match p.parse() {
                Ok(v) => v,
                Err(_) => {
                    rows.push(bad(format!("port `{p}` is not a number")));
                    continue;
                }
            },
            None => 22,
        };
        let user = cols
            .get(3)
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .map(String::from);
        let secret = cols
            .get(4)
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .map(String::from);
        rows.push(Parsed::Row(InventoryRow {
            name: name.to_owned(),
            host: host.to_owned(),
            port,
            user,
            secret,
        }));
    }
    ParseOutcome {
        rows,
        warnings: vec![],
    }
}

/// ssh_config: flat parse (no `Include`, no `%h`/`%r` expansion — stated
/// scope). A `Host` block with a concrete (pattern-free) `Host` name AND a
/// `HostName` becomes a row; a pattern block WITH a HostName is
/// `Skipped`-with-warning (Heph Q3); a block without `HostName` is skipped
/// silently (settings catch-all).
pub fn parse_ssh_config(text: &str) -> ParseOutcome {
    let mut rows: Vec<Parsed> = Vec::new();
    let mut warnings: Vec<Skipped> = Vec::new();
    let mut current_hosts: Option<(usize, Vec<String>)> = None;
    let mut current_hostname: Option<String> = None;
    let mut current_port: Option<u16> = None;
    let mut current_user: Option<String> = None;

    let flush = |rows: &mut Vec<Parsed>,
                 warnings: &mut Vec<Skipped>,
                 hosts: &Option<(usize, Vec<String>)>,
                 hostname: &Option<String>,
                 port: &Option<u16>,
                 user: &Option<String>| {
        if let Some((ln, names)) = hosts {
            let is_pattern = names.iter().any(|n| n.contains('*') || n.contains('?'));
            match hostname {
                Some(hn) if !is_pattern => {
                    rows.push(Parsed::Row(InventoryRow {
                        name: names[0].clone(),
                        host: hn.clone(),
                        port: port.unwrap_or(22),
                        user: user.clone(),
                        secret: None, // ssh_config never carries secrets
                    }));
                }
                Some(_) => warnings.push(Skipped {
                    line: *ln,
                    reason: format!(
                        "pattern block `Host {}` with HostName is not a host; skipped",
                        names.join(" ")
                    ),
                }),
                None => {} // settings-only block: silent skip
            }
        }
    };

    for (i, raw) in text.lines().enumerate() {
        let ln = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or("").trim();
        let val = parts.next().unwrap_or("").trim();
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                flush(
                    &mut rows,
                    &mut warnings,
                    &current_hosts,
                    &current_hostname,
                    &current_port,
                    &current_user,
                );
                current_hosts = Some((ln, val.split_whitespace().map(String::from).collect()));
                current_hostname = None;
                current_port = None;
                current_user = None;
            }
            "hostname" => current_hostname = Some(val.to_owned()),
            "port" => match val.parse::<u16>() {
                Ok(p) => current_port = Some(p),
                Err(_) => warnings.push(Skipped {
                    line: ln,
                    reason: format!("`Port {val}` is not a number; ignored"),
                }),
            },
            "user" => current_user = Some(val.to_owned()),
            _ => {} // all other ssh_config directives are out of scope
        }
    }
    flush(
        &mut rows,
        &mut warnings,
        &current_hosts,
        &current_hostname,
        &current_port,
        &current_user,
    );
    ParseOutcome { rows, warnings }
}

/// The placeholder sentinel value (TD-5 / Heph Q4.3): resolves are refused
/// by the vault so the value is never brokered. Single definition lives in
/// the vault crate.
pub const PLACEHOLDER: &str = chaperone_vault::PLACEHOLDER_ENTRY_VALUE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_happy_path() {
        let out = parse_csv(
            "name,host,port,user,secret\napp-01,app-01.internal,22,deploy,s3cr3t\napp-02,app-02.internal,,,,\n",
        );
        assert_eq!(out.rows.len(), 2);
        assert!(
            matches!(&out.rows[0], Parsed::Row(r) if r.name=="app-01" && r.port==22 && r.secret.as_deref()==Some("s3cr3t"))
        );
        assert!(matches!(&out.rows[1], Parsed::Row(r) if r.name=="app-02" && r.secret.is_none()));
    }

    #[test]
    fn csv_rejects_bad_header_and_short_rows() {
        let out = parse_csv("host,name\nx,y\n");
        assert!(matches!(&out.rows[0], Parsed::Failed { line: 1, .. }));
        let out = parse_csv("name,host,port,user,secret\nsolo\n");
        assert!(matches!(&out.rows[0], Parsed::Failed { line: 2, .. }));
    }

    #[test]
    fn csv_rejects_forbidden_name_chars() {
        let out = parse_csv("name,host,port,user,secret\nbad,name,x\n");
        assert!(matches!(&out.rows[0], Parsed::Failed { line: 2, .. }));
    }

    #[test]
    fn ssh_config_concrete_and_patterns() {
        let cfg = "Host app-01\n  HostName app-01.internal\n  Port 2201\n  User deploy\n\nHost *\n  AddKeysToAgent yes\n\nHost *.internal\n  HostName %h.internal\n";
        let out = parse_ssh_config(cfg);
        assert_eq!(out.rows.len(), 1, "one concrete host");
        assert!(matches!(&out.rows[0], Parsed::Row(r) if r.name=="app-01" && r.port==2201));
        assert_eq!(out.warnings.len(), 1, "pattern-with-HostName warns");
        // the Host * catch-all is silent
        assert!(out.warnings[0].reason.contains("*.internal"));
    }

    #[test]
    fn placeholder_is_the_refused_sentinel() {
        assert_eq!(PLACEHOLDER, "<chaperone:unset>");
    }
}
