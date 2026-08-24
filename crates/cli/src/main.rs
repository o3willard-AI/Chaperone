//! Chaperone operator CLI.
//!
//! Operator actions live here, out of the request path (ARCH-SPEC §2.2).
//! Phase 2 ships the enrollment commands; policy authoring, local-vault CRUD,
//! and audit verification grow with their phases ([PLAN](../../docs/PLAN.md)).
//!
//! Enrollment is deliberately explicit: the operator names the store file and
//! pastes the agent's public key (base64url), which the agent's platform key
//! store published out-of-band. The CLI never generates private keys — those
//! MUST be born inside a key store per PROTO-SPEC §4.1.

use std::process::ExitCode;

use chaperone_audit::AuditKey;
use chaperone_identity::{EnrollmentError, EnrollmentStore};
use chaperone_policy::Policy;
use chaperone_vault::SecretString;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

const USAGE: &str = "\
chaperone - Chaperone operator CLI

USAGE:
    chaperone enroll --store <PATH> --agent-id <ID> --public-key <B64URL> [--force]
    chaperone revoke --store <PATH> --agent-id <ID>
    chaperone list-agents --store <PATH>

LOCAL VAULT (operator CRUD):
    chaperone vault-init  --store <FILE> [--sealer passphrase] [--passphrase-stdin]
    chaperone vault-set   --store <FILE> --path <P> [--passphrase-stdin]   (secret on stdin)
    chaperone vault-get   --store <FILE> --path <P> [--passphrase-stdin] [--show]
    chaperone vault-list  --store <FILE> [--passphrase-stdin]
    chaperone vault-del   --store <FILE> --path <P> [--passphrase-stdin]

AUDIT CHAIN:
    chaperone audit-keygen --out <SEEDFILE>
    chaperone audit-verify --journal <FILE> --public-key <B64URL>
    chaperone audit-export --journal <FILE>
    chaperone policy-check --policy <TOML> --agent-id <ID> --cred-ref <REF>
                           --target-uri <URI> --mechanism <M>
                           [--max-response-bytes N] [--session-ttl-s S]

Enrollment binds an agent_id to an Ed25519 public key (base64url of 32
bytes) that the agent's key store publishes out-of-band. Revocation is
effective immediately. Rotation requires revoking first (or --force).
";

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "<time-error>".to_owned())
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("error: {msg}");
    ExitCode::from(2)
}

/// Minimal flag parsing: expects pairs `--name value`; booleans via `--flag`.
struct Flags {
    values: std::collections::HashMap<String, String>,
    switches: Vec<String>,
}

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut values = std::collections::HashMap::new();
    let mut switches = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with("--") {
            return Err(format!("unexpected argument {arg:?}"));
        }
        match args.get(i + 1) {
            Some(next) if !next.starts_with("--") => {
                values.insert(arg.trim_start_matches('-').to_owned(), next.clone());
                i += 2;
            }
            _ => {
                switches.push(arg.trim_start_matches('-').to_owned());
                i += 1;
            }
        }
    }
    Ok(Flags { values, switches })
}

impl Flags {
    fn require(&self, name: &str) -> Result<String, String> {
        self.values
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing required flag --{name}"))
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }
}

fn open_store(path: &str) -> Result<EnrollmentStore, EnrollmentError> {
    EnrollmentStore::load(std::path::Path::new(path))
}

fn cmd_enroll(flags: &Flags) -> Result<(), String> {
    let store_path = flags.require("store")?;
    let agent_id = flags.require("agent-id")?;
    let public_key = flags.require("public-key")?;
    let force = flags.has("force");

    let store = open_store(&store_path).map_err(|e| e.to_string())?;
    store
        .enroll(&agent_id, &public_key, &now_rfc3339(), force)
        .map_err(|e| e.to_string())?;
    println!("enrolled {agent_id} in {store_path}");
    Ok(())
}

fn cmd_revoke(flags: &Flags) -> Result<(), String> {
    let store_path = flags.require("store")?;
    let agent_id = flags.require("agent-id")?;

    let store = open_store(&store_path).map_err(|e| e.to_string())?;
    match store.revoke(&agent_id, &now_rfc3339()) {
        Ok(true) => println!("revoked {agent_id}; effective immediately"),
        Ok(false) => println!("{agent_id} was not enrolled"),
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

fn cmd_list_agents(flags: &Flags) -> Result<(), String> {
    let store_path = flags.require("store")?;
    let store = open_store(&store_path).map_err(|e| e.to_string())?;

    for rec in store.list() {
        let status = if rec.revoked_at.is_some() {
            "REVOKED"
        } else {
            "live"
        };
        println!(
            "{:<28} {:<6} enrolled={} key={}",
            rec.agent_id,
            status,
            rec.enrolled_at,
            &rec.public_key[..rec.public_key.len().min(12)],
        );
    }
    Ok(())
}

fn cmd_policy_check(flags: &Flags) -> Result<(), String> {
    let doc = flags.require("policy")?;
    let agent_id = flags.require("agent-id")?;
    let cred_ref = flags.require("cred-ref")?;
    let target_uri = flags.require("target-uri")?;
    let mechanism = flags.require("mechanism")?;
    let max_bytes = flags
        .values
        .get("max-response-bytes")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| "--max-response-bytes must be a number".to_owned())
        })
        .transpose()?;
    let ttl = flags
        .values
        .get("session-ttl-s")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| "--session-ttl-s must be a number".to_owned())
        })
        .transpose()?;

    let policy = Policy::from_toml(
        &std::fs::read_to_string(&doc).map_err(|e| format!("cannot read {doc}: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let request = chaperone_policy::Request {
        agent_id: &agent_id,
        cred_ref: &cred_ref,
        target_uri: &target_uri,
        mechanism: &mechanism,
        declared: Some(chaperone_protocol::Constraints {
            max_response_bytes: max_bytes,
            session_ttl_s: ttl,
        }),
    };
    let decision = policy.evaluate(&request);
    println!(
        "{{\"effect\":\"{}\",\"source\":\"{}\",\"limits\":{{\"max_response_bytes\":{},\"session_ttl_s\":{}}}}}",
        decision.effect.as_str(),
        match &decision.source {
            chaperone_policy::DecisionSource::DefaultDeny => "default_deny".to_owned(),
            chaperone_policy::DecisionSource::Rule { index, name } => format!(
                "rule[{index}]{}",
                name.as_deref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default()
            ),
        },
        decision
            .limits
            .max_response_bytes
            .map_or("null".to_owned(), |v| v.to_string()),
        decision
            .limits
            .session_ttl_s
            .map_or("null".to_owned(), |v| v.to_string()),
    );
    Ok(())
}

fn cmd_audit_keygen(flags: &Flags) -> Result<(), String> {
    let out = flags.require("out")?;
    if std::path::Path::new(&out).exists() {
        return Err(format!(
            "{out} already exists; refusing to overwrite an audit key"
        ));
    }
    let key = AuditKey::generate();

    // Atomic temp+rename at owner-only permissions (tempfile creates 0600 on
    // unix; rename preserves them).
    let path = std::path::Path::new(&out);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    use std::io::Write;
    tmp.write_all(chaperone_protocol::encode_signature(&key.to_seed()).as_bytes())
        .and_then(|_| tmp.flush())
        .map_err(|e| e.to_string())?;
    tmp.persist(path).map_err(|pe| pe.error.to_string())?;

    println!("audit key written to {out} (0600)");
    println!("public key: {}", key.public_key_b64url());
    Ok(())
}

fn cmd_audit_verify(flags: &Flags) -> Result<(), String> {
    let journal = flags.require("journal")?;
    let pubkey = flags.require("public-key")?;
    let vk = chaperone_audit::verifying_key_from_b64url(&pubkey)?;

    match chaperone_audit::verify_file(std::path::Path::new(&journal), &vk) {
        Ok(report) => match (&report.tail, &report.error) {
            (Some(tail), None) => println!(
                "OK: {} records verified; head seq={} hash={}",
                report.records_ok, tail.seq, tail.hash_hex
            ),
            (_, Some(brk)) => println!(
                "TAMPERED: {} records ok before failure - line {}: {}",
                report.records_ok,
                brk.line + 1,
                brk.reason
            ),
            (None, None) => println!("EMPTY: journal has no records"),
        },
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

fn cmd_audit_export(flags: &Flags) -> Result<(), String> {
    let journal = flags.require("journal")?;
    let content =
        std::fs::read_to_string(&journal).map_err(|e| format!("cannot read {journal}: {e}"))?;
    print!("{content}");
    if !content.is_empty() && !content.ends_with('\n') {
        println!();
    }
    eprintln!(
        "# export complete; verify before trusting: chaperone audit-verify --journal {journal} --public-key <B64URL>"
    );
    Ok(())
}

// ---------- local vault ----------

/// Passphrase from stdin (first line, piped scripts) or a hidden prompt.
fn read_passphrase(flags: &Flags, confirm: bool) -> Result<Zeroizing<String>, String> {
    if flags.has("passphrase-stdin") {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("read passphrase: {e}"))?;
        while line.ends_with(['\n', '\r']) {
            line.pop();
        }
        return Ok(Zeroizing::new(line));
    }
    let first = rpassword::prompt_password("Vault passphrase: ").map_err(|e| e.to_string())?;
    if confirm {
        let second =
            rpassword::prompt_password("Confirm passphrase: ").map_err(|e| e.to_string())?;
        if first != second {
            std::mem::forget(second);
            return Err("passphrases do not match".to_owned());
        }
    }
    Ok(Zeroizing::new(first))
}

fn open_vault(flags: &Flags) -> Result<chaperone_vault::LocalVault, String> {
    let store = flags.require("store")?;
    let pass = read_passphrase(flags, false)?;
    chaperone_vault::LocalVault::open(std::path::Path::new(&store), pass).map_err(|e| e.to_string())
}

fn cmd_vault_init(flags: &Flags) -> Result<(), String> {
    let store = flags.require("store")?;
    let sealer = flags
        .values
        .get("sealer")
        .cloned()
        .unwrap_or_else(|| "passphrase".to_owned());
    match sealer.as_str() {
        "passphrase" => {}
        other => {
            return Err(format!(
                "unknown --sealer {other:?}; this build supports 'passphrase'"
            ));
        }
    }
    let pass = read_passphrase(flags, true)?;
    chaperone_vault::LocalVault::create(std::path::Path::new(&store), pass)
        .map_err(|e| e.to_string())?;
    println!("created vault at {store} (sealed with: {sealer})");
    Ok(())
}

fn cmd_vault_set(flags: &Flags) -> Result<(), String> {
    let entry = flags.require("path")?;
    let mut vault = open_vault(flags)?;
    let mut value = String::new();
    use std::io::Read as _;
    std::io::stdin()
        .read_to_string(&mut value)
        .map_err(|e| format!("read secret from stdin: {e}"))?;
    while value.ends_with(['\n', '\r']) {
        value.pop();
    }
    vault
        .set(&entry, SecretString::new(value))
        .map_err(|e| e.to_string())?;
    println!("stored {entry}");
    Ok(())
}

fn cmd_vault_get(flags: &Flags) -> Result<(), String> {
    let entry = flags.require("path")?;
    let vault = open_vault(flags)?;
    match vault.get(&entry).map_err(|e| e.to_string())? {
        Some(secret) => {
            if flags.has("show") {
                println!("{}", secret.expose());
            } else {
                println!("[redacted] {} bytes present", secret.len());
            }
            Ok(())
        }
        None => Err(format!("{entry} does not exist")),
    }
}

fn cmd_vault_list(flags: &Flags) -> Result<(), String> {
    let vault = open_vault(flags)?;
    for path in vault.list().map_err(|e| e.to_string())? {
        println!("{path}");
    }
    Ok(())
}

fn cmd_vault_del(flags: &Flags) -> Result<(), String> {
    let entry = flags.require("path")?;
    let mut vault = open_vault(flags)?;
    match vault.delete(&entry).map_err(|e| e.to_string())? {
        true => println!("removed {entry}"),
        false => println!("{entry} was not present"),
    }
    Ok(())
}

fn run(args: Vec<String>) -> Result<(), String> {
    let Some(command) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };
    let flags = parse_flags(&args[1..])?;
    match command.as_str() {
        "enroll" => cmd_enroll(&flags),
        "revoke" => cmd_revoke(&flags),
        "list-agents" => cmd_list_agents(&flags),
        "policy-check" => cmd_policy_check(&flags),
        "audit-keygen" => cmd_audit_keygen(&flags),
        "audit-verify" => cmd_audit_verify(&flags),
        "audit-export" => cmd_audit_export(&flags),
        "vault-init" => cmd_vault_init(&flags),
        "vault-set" => cmd_vault_set(&flags),
        "vault-get" => cmd_vault_get(&flags),
        "vault-list" => cmd_vault_list(&flags),
        "vault-del" => cmd_vault_del(&flags),
        "--help" | "-h" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}; see `chaperone help`")),
    }
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => fail(&msg),
    }
}
