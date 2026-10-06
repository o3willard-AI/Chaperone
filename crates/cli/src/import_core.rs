//! B-2: the `vault import` command core (TD-2/TD-3). Pure orchestration over
//! parsed rows — the CLI layer wires I/O around this. Separated from main.rs
//! so the ordering/atomicity/guard logic is unit-testable offline.

use crate::import_sources::{InventoryRow, PLACEHOLDER};
use chaperone_policy::{Matcher, Pair, Policy};
use chaperone_vault::LocalVault;

/// Outcome for one inventory row, exactly the summary line the operator sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowOutcome {
    /// Entry written, pair row added.
    Imported { entry_path: String },
    /// Entry already existed (kept, value untouched) — pair row added.
    SkippedExists { entry_path: String },
    /// Nothing written; reason is the printed summary text.
    Failed { reason: String },
}

impl RowOutcome {
    /// The summary line (TD-4: paths, never values).
    pub fn line(&self) -> String {
        match self {
            RowOutcome::Imported { entry_path } => {
                format!("imported {entry_path}")
            }
            RowOutcome::SkippedExists { entry_path } => {
                format!("skipped {entry_path} (exists, pre-existing secret kept) -> row added")
            }
            RowOutcome::Failed { reason } => format!("failed: {reason}"),
        }
    }
}

/// Everything the run needs. The vault is passed as `&mut LocalVault` (CLI
/// direct handle); the policy arrives parsed and leaves canonical.
pub struct ImportPlan<'a> {
    pub vault: &'a mut LocalVault,
    pub policy_doc: &'a str,
    /// Exact rule name to attach rows to (fail closed if absent).
    pub rule_name: &'a str,
    /// Entry namespace prefix, e.g. `local://ssh/fleet`.
    pub cred_scheme: &'a str,
    /// Whether to write anything (false = TD-2 dry-run).
    pub dry_run: bool,
}

/// The CA-namespace refusal applies to the FULLY RESOLVED entry path
/// (Heph F4), not the name: `--cred-scheme local://chaperone/ca` must not
/// slip through a name-only check.
fn resolved_entry_path(cred_scheme: &str, name: &str) -> String {
    // cred_scheme is stored WITHOUT the `scheme://` prefix in the vault
    // namespace sense? No: vault entries are plain paths (`fleet/app-01`);
    // cred_scheme is the cred_ref prefix (`local://ssh/fleet`). The entry
    // path inside the vault is everything after `scheme://`.
    let path = cred_scheme
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(cred_scheme);
    format!("{path}/{name}")
}

/// One axis row (cred_ref or target_uri as a string) can never match the
/// rule's own same-axis Matcher? (Heph Q2 — the substantive correction:
/// pair rows are subordinate to shared axes; a row that can never match
/// must fail, not silently add.)
fn axis_compatible(rule_matcher_text: &str, row_value: &str) -> bool {
    // The rule axis and the row value must at least agree on scheme. We do
    // NOT simulate globs (D43 keeps matching first-order); we check the
    // cheap structural fact: the row's scheme prefix appears in the rule
    // axis text. `ssh://app-01` vs rule `https://*` -> incompatible.
    let row_scheme = row_value.split("://").next().unwrap_or("");
    if row_scheme.is_empty() {
        return true; // no scheme to disagree about
    }
    rule_matcher_text.contains(row_scheme)
        || rule_matcher_text == "*"
        || rule_matcher_text.starts_with("glob:*")
}

/// Run the import. Returns per-row outcomes plus the (possibly) rewritten
/// policy document. On `Err`, NOTHING was written (fail closed).
pub fn run_import(
    plan: &mut ImportPlan<'_>,
    rows: &[InventoryRow],
) -> Result<(Vec<RowOutcome>, String), String> {
    // Fail-closed rule lookup FIRST (TD-2: unknown rule name = nothing written).
    let policy =
        Policy::from_toml(plan.policy_doc).map_err(|e| format!("policy does not parse: {e}"))?;
    let rule_idx = policy
        .rules()
        .iter()
        .position(|r| r.name.as_deref() == Some(plan.rule_name))
        .ok_or_else(|| format!("no rule named {:?} in the policy", plan.rule_name))?;
    let rule = &policy.rules()[rule_idx];

    // Pre-check EVERY resolved path against the CA namespace before any write
    // (whole run fails closed if any row would land there — TD-2).
    for row in rows {
        let full = resolved_entry_path(plan.cred_scheme, &row.name);
        if full.starts_with(chaperone_vault::CA_NAMESPACE) {
            return Err(format!(
                "row `{}` would write into the non-exportable CA namespace ({full}); \
                 the entire import is refused",
                row.name
            ));
        }
    }

    // Axis compatibility (Q2): a row that can never match the rule's own
    // axes fails as `axis-incompatible` rather than silently adding.
    let rule_cred_text = format!("{:?}", rule.cred_ref);
    let rule_target_text = format!("{:?}", rule.target_uri);

    let mut outcomes = Vec::with_capacity(rows.len());
    let mut existing_paths: std::collections::HashSet<String> = plan
        .vault
        .list()
        .map_err(|e| format!("vault list: {e}"))?
        .into_iter()
        .collect();

    let mut new_pairs: Vec<Pair> = Vec::new();
    let existing_pairs: Vec<(String, String)> = rule
        .pairs
        .iter()
        .map(|p| (format!("{:?}", p.cred_ref), format!("{:?}", p.target_uri)))
        .collect();

    for row in rows {
        let entry_path = resolved_entry_path(plan.cred_scheme, &row.name);
        // cred_scheme already carries `scheme://prefix`; cred_ref is
        // cred_scheme verbatim + `/name`.
        let cred_ref = format!("{}/{}", plan.cred_scheme, row.name);
        let target_uri = format!("ssh://{}:{}", row.host, row.port);

        // Axis compatibility against the rule's own shared axes.
        if !axis_compatible(&rule_cred_text, &cred_ref)
            || !axis_compatible(&rule_target_text, &target_uri)
        {
            outcomes.push(RowOutcome::Failed {
                reason: format!(
                    "{cred_ref} -> {target_uri}: axis-incompatible with rule {:?} (a row that can never match is not added)",
                    plan.rule_name
                ),
            });
            continue;
        }

        // Vault phase (TD-3: entries first).
        if existing_paths.contains(&entry_path) {
            // Keep the pre-existing value (F1); the row still gets added (Q1).
            if !plan.dry_run {
                // nothing to write
            }
            outcomes.push(RowOutcome::SkippedExists {
                entry_path: entry_path.clone(),
            });
        } else {
            let value = row.secret.clone().unwrap_or_else(|| PLACEHOLDER.to_owned());
            if !plan.dry_run {
                plan.vault
                    .set(&entry_path, chaperone_vault::SecretString::new(value))
                    .map_err(|e| format!("vault set {entry_path}: {e}"))?;
            }
            existing_paths.insert(entry_path.clone());
            outcomes.push(RowOutcome::Imported {
                entry_path: entry_path.clone(),
            });
        }

        // Pair row (Q1: also for skipped-exists). Dedup against the rule's
        // original pairs AND rows added earlier in this same run (B2-FIX
        // Fix 2: two identical rows in one CSV must yield one pair row).
        let dup = existing_pairs
            .iter()
            .any(|(c, t)| c.contains(&cred_ref) && t.contains(&target_uri))
            || new_pairs.iter().any(|p| {
                format!("{:?}", p.cred_ref).contains(&cred_ref)
                    && format!("{:?}", p.target_uri).contains(&target_uri)
            });
        if !dup {
            let cred_matcher =
                Matcher::parse(&cred_ref).map_err(|e| format!("cred_ref `{cred_ref}`: {e}"))?;
            let target_matcher = Matcher::parse(&target_uri)
                .map_err(|e| format!("target_uri `{target_uri}`: {e}"))?;
            new_pairs.push(Pair {
                cred_ref: cred_matcher,
                target_uri: target_matcher,
            });
        }
    }

    if plan.dry_run {
        return Ok((outcomes, plan.policy_doc.to_owned()));
    }

    // Policy phase (TD-3: rows second). Canonical rewrite (F2: named
    // comment-loss; atomic write is the caller's I/O concern).
    let mut rules = policy.rules().to_vec();
    if !new_pairs.is_empty() {
        let mut updated = rules[rule_idx].clone();
        updated.pairs.extend(new_pairs);
        rules[rule_idx] = updated;
    }
    let new_doc = Policy::from_rules(rules).to_toml();
    // Validate exactly what will hit the disk (UI-save discipline).
    Policy::from_toml(&new_doc).map_err(|e| format!("generated policy failed validation: {e}"))?;

    Ok((outcomes, new_doc))
}

/// F2: atomic policy write — write-temp-then-rename. A torn write would
/// corrupt the ENTIRE ruleset; the sealed vault has its own integrity, the
/// policy file does not.
pub fn atomic_write(path: &std::path::Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, contents).map_err(|e| format!("temp write: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn vault_with(entries: &[(&str, &str)]) -> LocalVault {
        let dir = tempfile::tempdir().unwrap();
        let mut v = LocalVault::create(
            &dir.path().join("v.bin"),
            "passphrase",
            zeroize::Zeroizing::new("pass".to_owned()),
        )
        .unwrap();
        for (p, s) in entries {
            v.set(p, chaperone_vault::SecretString::new(s.to_string()))
                .unwrap();
        }
        // NOTE: vault keeps no dir ref after create? It does — but for tests
        // we leak the tempdir by returning vault only; entries are in memory.
        v
    }

    const TARGET_RULE: &str = r#"
    [[rule]]
    name = "fleet"
    effect = "allow"
    agent_id = "agent:deployer"
    cred_ref = "local://ssh/fleet/*"
    target_uri = "ssh://*.internal:*"
    mechanism = "ssh"
"#;

    #[test]
    fn imports_rows_and_pairs() {
        let mut v = vault_with(&[]);
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: TARGET_RULE,
            rule_name: "fleet",
            cred_scheme: "local://ssh/fleet",
            dry_run: false,
        };
        let rows = vec![
            InventoryRow {
                name: "app-01".into(),
                host: "app-01.internal".into(),
                port: 22,
                user: None,
                secret: Some("s3cr3t".into()),
            },
            InventoryRow {
                name: "app-02".into(),
                host: "app-02.internal".into(),
                port: 2202,
                user: None,
                secret: None,
            },
        ];
        let (outcomes, doc) = run_import(&mut plan, &rows).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(
            matches!(&outcomes[0], RowOutcome::Imported { entry_path } if entry_path == "ssh/fleet/app-01")
        );
        // The policy doc gained both pair rows and revalidates (run_import did it).
        let p = Policy::from_toml(&doc).unwrap();
        let rule = p
            .rules()
            .iter()
            .find(|r| r.name.as_deref() == Some("fleet"))
            .unwrap();
        assert_eq!(rule.pairs.len(), 2);
        // The placeholder went into the vault for app-02.
        assert!(doc.contains("local://ssh/fleet/app-02"));
    }

    #[test]
    fn skipped_exists_keeps_value_and_adds_row() {
        // F1/Q1: pre-existing value survives; the row is still added.
        let mut v = vault_with(&[("ssh/fleet/app-01", "OLD-VALUE")]);
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: TARGET_RULE,
            rule_name: "fleet",
            cred_scheme: "local://ssh/fleet",
            dry_run: false,
        };
        let rows = vec![InventoryRow {
            name: "app-01".into(),
            host: "app-01.internal".into(),
            port: 22,
            user: None,
            secret: Some("NEW-VALUE".into()),
        }];
        let (outcomes, doc) = run_import(&mut plan, &rows).unwrap();
        assert!(matches!(&outcomes[0], RowOutcome::SkippedExists { .. }));
        let p = Policy::from_toml(&doc).unwrap();
        let rule = p
            .rules()
            .iter()
            .find(|r| r.name.as_deref() == Some("fleet"))
            .unwrap();
        assert_eq!(rule.pairs.len(), 1, "skipped-exists still adds the row");
        let _ = v; // value assertion is end-to-end (CLI test reads it back)
    }

    #[test]
    fn unknown_rule_fails_closed() {
        let mut v = vault_with(&[]);
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: TARGET_RULE,
            rule_name: "nope",
            cred_scheme: "local://ssh/fleet",
            dry_run: false,
        };
        let rows = vec![InventoryRow {
            name: "app-01".into(),
            host: "app-01.internal".into(),
            port: 22,
            user: None,
            secret: Some("x".into()),
        }];
        let err = run_import(&mut plan, &rows).unwrap_err();
        assert!(err.contains("no rule named"), "{err}");
    }

    #[test]
    fn ca_namespace_path_fails_whole_run() {
        // F4: the check is on the resolved path via the SCHEME.
        let mut v = vault_with(&[]);
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: TARGET_RULE,
            rule_name: "fleet",
            cred_scheme: "local://chaperone/ca",
            dry_run: false,
        };
        let rows = vec![InventoryRow {
            name: "ssh".into(),
            host: "h.internal".into(),
            port: 22,
            user: None,
            secret: Some("x".into()),
        }];
        let err = run_import(&mut plan, &rows).unwrap_err();
        assert!(err.contains("non-exportable CA namespace"), "{err}");
    }

    #[test]
    fn axis_incompatible_rows_fail_not_add() {
        // Q2: rule targets ssh://*.internal:*; feed https rows? The row's
        // target_uri is always ssh:// — so instead make the RULE http-only.
        let policy = r#"
    [[rule]]
    name = "web"
    effect = "allow"
    agent_id = "agent:deployer"
    cred_ref = "local://ssh/fleet/*"
    target_uri = "https://*.internal"
    mechanism = "ssh"
"#;
        let mut v = vault_with(&[]);
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: policy,
            rule_name: "web",
            cred_scheme: "local://ssh/fleet",
            dry_run: false,
        };
        let rows = vec![InventoryRow {
            name: "app-01".into(),
            host: "app-01.internal".into(),
            port: 22,
            user: None,
            secret: Some("x".into()),
        }];
        let (outcomes, doc) = run_import(&mut plan, &rows).unwrap();
        assert!(
            matches!(&outcomes[0], RowOutcome::Failed { reason } if reason.contains("axis-incompatible"))
        );
        let p = Policy::from_toml(&doc).unwrap();
        let rule = p
            .rules()
            .iter()
            .find(|r| r.name.as_deref() == Some("web"))
            .unwrap();
        assert_eq!(rule.pairs.len(), 0, "a never-matching row is not added");
    }

    #[test]
    fn dry_run_writes_nothing() {
        let mut v = vault_with(&[]);
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: TARGET_RULE,
            rule_name: "fleet",
            cred_scheme: "local://ssh/fleet",
            dry_run: true,
        };
        let rows = vec![InventoryRow {
            name: "app-01".into(),
            host: "app-01.internal".into(),
            port: 22,
            user: None,
            secret: Some("x".into()),
        }];
        let (outcomes, doc) = run_import(&mut plan, &rows).unwrap();
        assert!(matches!(&outcomes[0], RowOutcome::Imported { .. }));
        assert_eq!(doc, TARGET_RULE, "dry-run leaves the policy doc untouched");
        let list = v.list().unwrap();
        assert!(list.iter().all(|p| !p.contains("ssh/fleet")), "{list:?}");
    }

    #[test]
    fn re_run_is_idempotent() {
        let mut v = vault_with(&[]);
        let rows = vec![InventoryRow {
            name: "app-01".into(),
            host: "app-01.internal".into(),
            port: 22,
            user: None,
            secret: Some("s".into()),
        }];
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: TARGET_RULE,
            rule_name: "fleet",
            cred_scheme: "local://ssh/fleet",
            dry_run: false,
        };
        let (_, doc1) = run_import(&mut plan, &rows).unwrap();
        // Second run against the REWRITTEN doc.
        let mut plan2 = ImportPlan {
            vault: &mut v,
            policy_doc: &doc1,
            rule_name: "fleet",
            cred_scheme: "local://ssh/fleet",
            dry_run: false,
        };
        let (outcomes2, doc2) = run_import(&mut plan2, &rows).unwrap();
        assert!(matches!(&outcomes2[0], RowOutcome::SkippedExists { .. }));
        assert_eq!(doc1, doc2, "re-run must not duplicate rows");
    }
    /// B2-FIX Fix 2: two identical rows in ONE CSV yield ONE pair row (the
    /// within-run dedup consults new_pairs, not just the rule's originals).
    #[test]
    fn duplicate_rows_in_one_run_yield_one_pair() {
        let mut v = vault_with(&[]);
        let mut plan = ImportPlan {
            vault: &mut v,
            policy_doc: TARGET_RULE,
            rule_name: "fleet",
            cred_scheme: "local://ssh/fleet",
            dry_run: false,
        };
        let row = || InventoryRow {
            name: "app-01".into(),
            host: "app-01.internal".into(),
            port: 22,
            user: None,
            secret: Some("x".into()),
        };
        let rows = vec![row(), row()];
        let (outcomes, doc) = run_import(&mut plan, &rows).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(
            matches!(&outcomes[0], RowOutcome::Imported { .. }),
            "first row imports"
        );
        assert!(
            matches!(&outcomes[1], RowOutcome::SkippedExists { .. }),
            "second row skips (entry exists): {:?}",
            outcomes[1]
        );
        let p = Policy::from_toml(&doc).unwrap();
        let rule = p
            .rules()
            .iter()
            .find(|r| r.name.as_deref() == Some("fleet"))
            .unwrap();
        assert_eq!(rule.pairs.len(), 1, "one pair row, not two");
    }
}
