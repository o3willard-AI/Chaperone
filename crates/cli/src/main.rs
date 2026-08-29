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
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

const USAGE: &str = "\
chaperone - Chaperone operator CLI

USAGE:
    chaperone enroll --store <PATH> --agent-id <ID> --public-key <B64URL> [--force]
    chaperone revoke --store <PATH> --agent-id <ID>
    chaperone list-agents --store <PATH>

GATEWAY DAEMON:
    chaperone serve --socket <PATH> --enrollment <FILE> --policy <TOML>
                    --store <VAULT> --audit-journal <FILE> --audit-key <SEED>
                    [--tcp-port N] [--max-response-bytes N] [--timeout-secs N]
                    [--passphrase-file PATH]
                    [--confirm-timeout-secs N|--confirm never-approve]
                    [--console-socket PATH] [--events-socket PATH] [--trust-host-keys]
                    [--ssh-known-hosts PATH] [--ssh-tofu]
                    [--ui-port N] [--no-ui] [--ui-token PATH]

LOCAL VAULT (operator CRUD):
    chaperone vault-init  --store <FILE> [--sealer passphrase|keyring] [--passphrase-stdin]
    chaperone vault-set   --store <FILE> --path <P> [--passphrase-stdin]   (secret on stdin)
    chaperone vault-get   --store <FILE> --path <P> [--passphrase-stdin] [--show]
    chaperone vault-list  --store <FILE> [--passphrase-stdin]
    chaperone vault-del   --store <FILE> --path <P> [--passphrase-stdin]

UI ACCESS TOKEN (required before the config UI serves; D41):
    chaperone ui-token show   --token <PATH>
    chaperone ui-token rotate --token <PATH>

AUDIT CHAIN:
    chaperone audit-keygen --out <SEEDFILE>
    chaperone audit-verify --journal <FILE> --public-key <B64URL>
    chaperone audit-export --journal <FILE>
    chaperone policy-check --policy <TOML> --agent-id <ID> --cred-ref <REF>
                           --target-uri <URI> --mechanism <M>
                           [--max-response-bytes N] [--session-ttl-s S]

HEALTH CHECK (diagnostic only; exit 1 if anything fails):
    chaperone doctor --policy <TOML> --enrollment <FILE> --store <VAULT>
                     --audit-key <SEEDFILE> --audit-journal <FILE>
                     [--socket <PATH>] [--passphrase-file P|--passphrase-stdin]

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

#[cfg(unix)]
fn cmd_console(flags: &Flags) -> Result<(), String> {
    use std::io::{BufRead as _, Read as _, Write as _};

    let path = flags.require("socket")?;
    let mut sock = std::os::unix::net::UnixStream::connect(std::path::Path::new(&path))
        .map_err(|e| format!("cannot reach console at {path}: {e}"))?;
    let mut server_out = sock.try_clone().map_err(|e| e.to_string())?;

    // Socket -> stdout on a thread; stdin lines -> socket on this one.
    let reader_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match server_out.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        print!("{}", String::from_utf8_lossy(&buf));
                        let _ = std::io::stdout().flush();
                        buf.clear();
                    }
                }
            }
        }
    });

    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| format!("stdin: {e}"))?;
        sock.write_all(line.as_bytes())
            .and_then(|_| sock.write_all(b"\n"))
            .map_err(|e| format!("console write: {e}"))?;
    }
    drop(sock);
    let _ = reader_thread.join();
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

/// Passphrase from a 0600 file (service-friendly), stdin first line
/// (piped scripts), or a hidden prompt.
fn read_passphrase(flags: &Flags, confirm: bool) -> Result<Zeroizing<String>, String> {
    if let Some(path) = flags.values.get("passphrase-file") {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read passphrase file {path}: {e}"))?;
        let line = text.lines().next().unwrap_or_default().to_owned();
        if line.is_empty() {
            return Err(format!("passphrase file {path} is empty"));
        }
        return Ok(Zeroizing::new(line));
    }
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
    // A keyring-sealed vault opens without any passphrase (the DEK lives in
    // the platform credential store); don't prompt for one. Peek the header
    // sealer so this works for every vault subcommand.
    let is_keyring = chaperone_vault::LocalVault::sealer_of(std::path::Path::new(&store))
        .map(|s| s == "keyring")
        .unwrap_or(false);
    if is_keyring
        && (flags.values.contains_key("passphrase-file") || flags.has("passphrase-stdin"))
    {
        eprintln!(
            "note: {store} is keyring-sealed; the provided passphrase source is NOT used (the vault key lives in the platform credential store)"
        );
    }
    let pass = if is_keyring {
        zeroize::Zeroizing::new(String::new())
    } else {
        read_passphrase(flags, false)?
    };
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
        // Issue #50: the keyring sealer is wired through when the CLI is
        // built with the vault's `keyring` feature. The error below fires
        // in builds without it, so the operator gets a build-level hint
        // rather than a generic "unknown sealer".
        #[cfg(feature = "keyring")]
        "keyring" => {}
        #[cfg(not(feature = "keyring"))]
        "keyring" => {
            return Err(
                "this build has no keyring support; rebuild the CLI with `cargo build --release --locked --features keyring -p chaperone-cli` (or use --sealer passphrase)".to_owned(),
            );
        }
        other => {
            return Err(format!(
                "unknown --sealer {other:?}; this build supports 'passphrase'{}",
                if cfg!(feature = "keyring") { ", 'keyring'" } else { "" }
            ));
        }
    }
    // A keyring-sealed vault has no passphrase at all: reject a provided
    // one so the operator never believes it is being used.
    if sealer == "keyring"
        && (flags.values.contains_key("passphrase-file") || flags.has("passphrase-stdin"))
    {
        return Err(
            "--sealer keyring stores the vault key in the platform credential store; \
             no --passphrase-file/--passphrase-stdin is used — remove it"
                .to_owned(),
        );
    }
    // The keyring arm of create() ignores the passphrase; never prompt for
    // one (a headless run has no tty, and prompting would imply it matters).
    let pass = if sealer == "keyring" {
        zeroize::Zeroizing::new(String::new())
    } else {
        read_passphrase(flags, true)?
    };
    chaperone_vault::LocalVault::create(std::path::Path::new(&store), &sealer, pass)
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

fn cmd_doctor(flags: &Flags) -> Result<(), String> {
    // Doctor answers "is my install healthy?" with per-check, actionable
    // output. STRICTLY diagnostic: it never mutates state, never resolves a
    // credential, never signs anything, and holds no passphrase longer than
    // one unlock check (zeroized by LocalVault's own buffers).
    let mut failures: Vec<String> = Vec::new();
    let check = |name: &str, result: Result<String, String>, failures: &mut Vec<String>| {
        match result {
            Ok(detail) => println!("  ok    {name}: {detail}"),
            Err(actionable) => {
                println!("  FAIL  {name}: {actionable}");
                failures.push(name.to_owned());
            }
        }
    };

    // 1. Binary/version (always passes if you got this far; proves the
    //    binary runs and reports its protocol).
    check(
        "binary version",
        Ok(format!(
            "chaperone {} (protocol {})",
            env!("CARGO_PKG_VERSION"),
            chaperone_protocol::PROTOCOL_VERSION
        )),
        &mut failures,
    );

    // 2. Policy file parses (same parser the gateway loads at startup).
    let policy_path = flags.values.get("policy").cloned().unwrap_or_default();
    let policy_result: Result<String, String> = if policy_path.is_empty() {
        Err("pass --policy <TOML> (the same file serve uses)".to_owned())
    } else {
        (|| -> Result<String, String> {
            let doc = std::fs::read_to_string(&policy_path).map_err(|e| {
                format!(
                    "cannot read {policy_path}: {e}; run `chaperone serve` once to create it via the setup wizard"
                )
            })?;
            let rules =
                chaperone_policy::Policy::from_toml(&doc).map_err(|e| e.to_string())?;
            Ok(format!(
                "{policy_path} ({} rule(s); default-deny when 0)",
                rules.len()
            ))
        })()
    };
    check("policy parses", policy_result, &mut failures);

    // 3. Enrollment store readable (same loader serve uses).
    let enrollment_path = flags
        .values
        .get("enrollment")
        .cloned()
        .unwrap_or_default();
    check(
        "enrollment store",
        if enrollment_path.is_empty() {
            Err("pass --enrollment <FILE> (agents.json)".to_owned())
            as Result<String, String>
        } else if !std::path::Path::new(&enrollment_path).exists() {
            // EnrollmentStore::load treats a missing file as an empty store
            // (first-run convenience); for a health check that is a misspelled
            // path, not a healthy empty store.
            Err(format!(
                "{enrollment_path} does not exist; enroll with `chaperone enroll --store {enrollment_path} --agent-id <ID> --public-key <B64URL>`"
            ))
        } else {
            match chaperone_identity::EnrollmentStore::load(std::path::Path::new(
                &enrollment_path,
            )) {
                Err(e) => Err(format!(
                    "cannot load {enrollment_path}: {e}; create it with `chaperone enroll --store {enrollment_path} --agent-id <ID> --public-key <B64URL>`"
                )),
                Ok(store) => {
                    let total = store.list().len();
                    let live = store.list().iter().filter(|r| r.revoked_at.is_none()).count();
                    Ok(format!(
                        "{enrollment_path} ({live} live / {total} enrolled)"
                    ))
                }
            }
        },
        &mut failures,
    );

    // 4. Vault unlocks with the configured passphrase source (open only;
    //    nothing is read, written, or resolved).
    let store_path = flags.values.get("store").cloned().unwrap_or_default();
    let vault_result: Result<String, String> = if store_path.is_empty() {
        Err("pass --store <VAULT> (vault.bin)".to_owned())
    } else if !std::path::Path::new(&store_path).exists() {
        Err(format!(
            "{store_path} does not exist; run `chaperone serve` once (setup wizard) or `chaperone vault-init --store {store_path}`"
        ))
    } else {
        (|| -> Result<String, String> {
            let pass = read_passphrase(flags, false).map_err(|e| {
                format!("no passphrase available: {e}; pass --passphrase-file or pipe --passphrase-stdin")
            })?;
            match chaperone_vault::LocalVault::open(std::path::Path::new(&store_path), pass) {
                Err(e) => Err(format!(
                    "unlock failed: {e} (wrong passphrase or corrupt store; the passphrase has no recovery)"
                )),
                Ok(vault) => {
                    let entries = vault.list().map_err(|e| e.to_string())?.len();
                    Ok(format!("{store_path} ({entries} entr(y|ies))"))
                }
            }
        })()
    };
    check("vault unlocks", vault_result, &mut failures);

    // 5. Audit key loads and the chain tail verifies (exact serve +
    //    audit-verify machinery; empty journals pass as "no records yet").
    let key_path = flags.values.get("audit-key").cloned().unwrap_or_default();
    let journal_path = flags
        .values
        .get("audit-journal")
        .cloned()
        .unwrap_or_default();
    let audit_result: Result<String, String> = if key_path.is_empty() || journal_path.is_empty()
    {
        Err("pass --audit-key <SEEDFILE> and --audit-journal <FILE>".to_owned())
    } else if !std::path::Path::new(&key_path).exists() {
        Err(format!(
            "{key_path} does not exist; generate with `chaperone audit-keygen --out {key_path}`"
        ))
    } else {
        (|| -> Result<String, String> {
            let seed_text = std::fs::read_to_string(&key_path)
                .map_err(|e| format!("cannot read {key_path}: {e}"))?;
            let key = load_audit_seed_text(&seed_text)?;
            let vk = key.verifying_key();
            if !std::path::Path::new(&journal_path).exists() {
                // Fresh install: serve creates the journal on first start.
                return Ok("no journal yet (created on first `serve`)".to_owned());
            }
            match chaperone_audit::verify_file(std::path::Path::new(&journal_path), &vk) {
                Err(e) => Err(format!("journal unreadable: {e}")),
                Ok(report) => match (&report.tail, &report.error) {
                    (Some(tail), None) => Ok(format!(
                        "{} records verified; head seq={} hash={}",
                        report.records_ok, tail.seq, tail.hash_hex
                    )),
                    (_, Some(brk)) => Err(format!(
                        "TAMPERED at line {}: {} — investigate before trusting this journal",
                        brk.line + 1,
                        brk.reason
                    )),
                    (None, None) => {
                        Ok("no records yet (chain will start on first decision)".to_owned())
                    }
                },
            }
        })()
    };
    check("audit chain tail", audit_result, &mut failures);

    // 6. Transport endpoint reachable (connect/disconnect only — NO intent
    //    is sent, so this cannot touch the signing or policy trust path).
    //    Skipped when no --socket is given so doctor also works against a
    //    not-yet-running gateway for the other checks.
    if let Some(path) = flags.values.get("socket") {
        #[cfg(unix)]
        {
            let result: Result<String, String> = if !std::path::Path::new(path).exists() {
                Err(format!(
                    "{path} does not exist; is `chaperone serve --socket {path}` running?"
                ))
            } else {
                use std::os::unix::net::UnixStream;
                UnixStream::connect(std::path::Path::new(path))
                    .map(|s| drop(s))
                    .map(|_| format!("{path} accepting connections"))
                    .map_err(|e| {
                        format!("connect failed: {e}; is serve running with --socket {path}?")
                    })
            };
            check("transport endpoint", result, &mut failures);
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
    }

    println!();
    if failures.is_empty() {
        println!("doctor: all checks passed");
        Ok(())
    } else {
        Err(format!(
            "doctor: {} check(s) failed — fix the FAIL lines above and re-run",
            failures.len()
        ))
    }
}

fn cmd_ui_token(args: &[String]) -> Result<(), String> {
    // `ui-token show --token X` / `ui-token rotate --token X`. The action
    // is a bare positional, which the generic flag parser rejects, so this
    // command peels it off before delegating to the flag parser for the
    // rest.
    let (action, rest) = match args.split_first().map(|(a, r)| (a.as_str(), r)) {
        Some(("show", r)) => ("show", r),
        Some(("rotate", r)) => ("rotate", r),
        _ => return Err("usage: chaperone ui-token show|rotate --token <PATH>".to_owned()),
    };
    let flags = parse_flags(rest)?;
    let token_path = flags.require("token")?;
    let port = flags
        .values
        .get("ui-port")
        .map_or(8720, |v| v.parse().unwrap_or(8720));
    let token_path = std::path::Path::new(&token_path);
    match action {
        "show" => {
            let token = chaperone_ui::load(token_path).map_err(|e| e.to_string())?;
            println!("UI token:  {}", token.as_str());
            println!(
                "open:      http://127.0.0.1:{port}/?token={}",
                token.as_str()
            );
        }
        "rotate" => {
            let token = chaperone_ui::rotate(token_path).map_err(|e| e.to_string())?;
            println!("rotated UI token at {} (0600)", token_path.display());
            println!("UI token:  {token}");
            println!("open:      http://127.0.0.1:{port}/?token={token}");
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn cmd_serve(flags: &Flags) -> Result<(), String> {
    use std::sync::Arc;

    let enrollment_path = flags.require("enrollment")?;
    let policy_path = flags.require("policy")?;
    let store_path = flags.require("store")?;
    let journal_path = flags.require("audit-journal")?;
    let key_path = flags.require("audit-key")?;
    let ui_port = flags
        .values
        .get("ui-port")
        .map_or(8720, |v| v.parse().unwrap_or(8720));
    let ui_enabled = !flags.has("no-ui");

    // D41: the UI token path defaults to beside the audit key (same config
    // directory, same 0600 discipline). The operator creates it with
    // `chaperone ui-token rotate` before first serve; we never auto-generate.
    let ui_token_path = flags.values.get("ui-token").cloned().unwrap_or_else(|| {
        std::path::Path::new(&key_path)
            .with_file_name("ui.token")
            .to_string_lossy()
            .to_string()
    });

    // First-run detection: without the three broker-required artifacts
    // there is nothing to serve and no vault passphrase to prompt for -
    // run the setup wizard instead (OPERATOR-UI-SPEC §3.3).
    let provisioned = std::path::Path::new(&policy_path).exists()
        && std::path::Path::new(&store_path).exists()
        && std::path::Path::new(&key_path).exists();
    if !provisioned {
        return cmd_serve_setup(flags, ui_port, &ui_token_path);
    }

    // D39: the integrity gate runs before anything else touches the file.
    chaperone_gateway_core::verify_permissions(std::path::Path::new(&policy_path))?;

    let now = chaperone_gateway_core::chaperone_time_now();

    let enrollment = Arc::new(
        chaperone_identity::EnrollmentStore::load(std::path::Path::new(&enrollment_path))
            .map_err(|e| e.to_string())?,
    );
    let replay = Arc::new(
        chaperone_identity::ReplayCache::open(
            &std::path::Path::new(&journal_path).with_file_name("replay.jsonl"),
            now.unix_timestamp(),
        )
        .map_err(|e| e.to_string())?,
    );
    let attestor = chaperone_identity::Attestor::new(
        Arc::clone(&enrollment),
        replay,
        chaperone_identity::IdentityConfig { max_skew_secs: 30 },
    );

    let doc = std::fs::read_to_string(&policy_path)
        .map_err(|e| format!("cannot read {policy_path}: {e}"))?;
    let policy = chaperone_policy::Policy::from_toml(&doc).map_err(|e| e.to_string())?;

    // Vault passphrase: prompted (or piped first stdin line) at startup.
    let pass = read_passphrase(flags, false)?;
    let shared_vault = chaperone_vault::SharedVault::new(
        chaperone_vault::LocalVault::open(std::path::Path::new(&store_path), pass)
            .map_err(|e| e.to_string())?,
    );
    let schemes = {
        let mut r = chaperone_vault::VaultRouter::new();
        r.register("local", Arc::new(shared_vault.clone()));
        r.schemes()
    };
    let router = {
        let mut r = chaperone_vault::VaultRouter::new();
        r.register("local", Arc::new(shared_vault.clone()));
        r
    };

    let seed_text =
        std::fs::read_to_string(&key_path).map_err(|e| format!("cannot read {key_path}: {e}"))?;
    let audit_key = load_audit_seed_text(&seed_text)?;
    let audit = Arc::new(
        chaperone_audit::AuditWriter::open(std::path::Path::new(&journal_path), audit_key)
            .map_err(|e| e.to_string())?,
    );

    let config = chaperone_gateway_core::GatewayConfig {
        default_session_ttl_secs: flags
            .values
            .get("session-ttl-secs")
            .map_or(300, |v| v.parse().unwrap_or(300)),
        default_max_response_bytes: flags
            .values
            .get("max-response-bytes")
            .map_or(1_048_576, |v| v.parse().unwrap_or(1_048_576)),
        default_timeout_secs: flags
            .values
            .get("timeout-secs")
            .map_or(30, |v| v.parse().unwrap_or(30)),
    };

    let confirm_timeout = Duration::from_secs(
        flags
            .values
            .get("confirm-timeout-secs")
            .map_or(120, |v| v.parse().unwrap_or(120)),
    );
    let never_approve = matches!(
        flags.values.get("confirm-timeout-secs").map(String::as_str),
        Some("never-approve")
    );

    fn stdio_gate(timeout: Duration) -> Arc<dyn chaperone_gateway_core::ConfirmationGate> {
        struct StdioOperator;
        impl chaperone_gateway_core::OperatorIo for StdioOperator {
            fn write_prompt(&self, block: &str) -> std::io::Result<()> {
                use std::io::Write as _;
                let mut out = std::io::stdout().lock();
                out.write_all(block.as_bytes())?;
                out.flush()
            }
            fn read_answer(&self) -> std::io::Result<Option<String>> {
                use std::io::BufRead as _;
                let mut line = String::new();
                match std::io::stdin().lock().read_line(&mut line) {
                    Ok(0) => Ok(None),
                    Ok(_) => Ok(Some(line.trim_end_matches(['\n', '\r']).to_owned())),
                    Err(e) => Err(e),
                }
            }
        }
        Arc::new(chaperone_gateway_core::OperatorGate::new(
            Box::new(StdioOperator),
            timeout,
        ))
    }

    #[cfg(unix)]
    fn socket_gate(
        path: &str,
        timeout: Duration,
    ) -> Result<Arc<dyn chaperone_gateway_core::ConfirmationGate>, String> {
        use chaperone_gateway_core::{ConsoleHub, OperatorGate};
        let listener =
            chaperone_gateway_core::console::UnixListener2::bind(std::path::Path::new(path))
                .map_err(|e| e.to_string())?;
        let hub = ConsoleHub::new(path.into());
        ConsoleHub::spawn_acceptor(listener, Arc::clone(&hub));
        println!(
            "operator console listening on {path} (attach with: chaperone console --socket {path})"
        );
        Ok(Arc::new(OperatorGate::new(Box::new(hub), timeout)))
    }

    let gate: Arc<dyn chaperone_gateway_core::ConfirmationGate> = if never_approve {
        Arc::new(chaperone_gateway_core::AlwaysTimeoutGate)
    } else {
        match flags.values.get("console-socket") {
            #[cfg(unix)]
            Some(path) => socket_gate(path, confirm_timeout)?,
            // Issue #44: the flag was silently ignored on non-unix builds.
            // Don't fail — just make sure the operator doesn't believe it
            // took effect.
            #[cfg(not(unix))]
            Some(path) => {
                eprintln!(
                    "note: --console-socket {path} is ignored on this platform (no Unix-domain sockets); using stdin/stdout for confirmations"
                );
                stdio_gate(confirm_timeout)
            }
            None => stdio_gate(confirm_timeout),
        }
    };

    let mut gateway_core = chaperone_gateway_core::Gateway::new(
        attestor,
        policy,
        router,
        Arc::clone(&audit),
        Arc::clone(&gate),
        config,
    )
    .map_err(|e| e.to_string())?;

    // SSH host-key policy: pin store (preferred), explicit trust-all, or
    // strict refusal.
    let host_key_policy = if let Some(kh_path) = flags.values.get("ssh-known-hosts").cloned() {
        let store = chaperone_gateway_core::PinStore::load(std::path::Path::new(&kh_path))
            .map_err(|e| e.to_string())?;
        let tofu = flags.has("ssh-tofu");
        chaperone_gateway_core::HostKeyPolicy::PinStore {
            store: Arc::new(store),
            tofu,
        }
    } else if flags.has("trust-host-keys") {
        chaperone_gateway_core::HostKeyPolicy::TrustOnFirstUseAll
    } else {
        chaperone_gateway_core::HostKeyPolicy::RefuseUnknown
    };
    gateway_core.with_session_backend(
        "ssh",
        Arc::new(chaperone_gateway_core::SshBackend::new(host_key_policy)),
    );
    gateway_core.with_session_backend("db-scram", Arc::new(chaperone_gateway_core::DbBackend));

    // Event feed: always constructed (the policy-integrity guard and the
    // config UI broadcast through it); bound to a socket when requested.
    let event_hub = chaperone_gateway_core::EventHub::new();
    if let Some(path) = flags.values.get("events-socket") {
        event_hub.listen(std::path::Path::new(path))?;
        println!("event feed listening on {path} (tail with any stream reader)");
    }
    gateway_core.with_event_hub(Arc::clone(&event_hub));

    let policy_watch = chaperone_gateway_core::PolicyWatch::new(
        std::path::PathBuf::from(&policy_path),
        gateway_core.ruleset_hash().to_owned(),
    );
    let watch_audit = Arc::clone(&audit);

    let gateway = Arc::new(gateway_core);

    let ui_state = if ui_enabled {
        // D41: refuse to serve the UI without a token file. The operator
        // creates it with `chaperone ui-token rotate` before first serve.
        let token = chaperone_ui::load(std::path::Path::new(&ui_token_path)).map_err(|e| {
            format!(
                "{e}\n\nThe config UI requires an access token (D41). Create one with:\n  \
                     chaperone ui-token rotate --token {ui_token_path}\n\
                     Then restart `chaperone serve`."
            )
        })?;
        Some(std::sync::Arc::new(chaperone_ui::UiState {
            policy_path: std::path::PathBuf::from(&policy_path),
            vault_path: std::path::PathBuf::from(&store_path),
            enrollment_path: std::path::PathBuf::from(&enrollment_path),
            audit_key_path: std::path::PathBuf::from(&key_path),
            journal_path: std::path::PathBuf::from(&journal_path),
            vault: std::sync::RwLock::new(Some(shared_vault)),
            enrollment: Arc::clone(&enrollment),
            gateway: Some(Arc::clone(&gateway)),
            event_hub: Some(Arc::clone(&event_hub)),
            events_socket_path: flags
                .values
                .get("events-socket")
                .map(std::path::PathBuf::from),
            schemes,
            token,
            port: ui_port,
        }))
    } else {
        None
    };

    let spec = if let Some(path) = flags.values.get("socket") {
        chaperone_transport::ListenSpec::UnixSocket { path: path.into() }
    } else if let Some(port) = flags.values.get("tcp-port") {
        chaperone_transport::ListenSpec::TcpV4 {
            port: port
                .parse()
                .map_err(|_| "--tcp-port must be a number".to_owned())?,
        }
    } else {
        chaperone_transport::default_listen_spec()
    };

    let handler: chaperone_transport::Handler = {
        let gw = Arc::clone(&gateway);
        Arc::new(move |request| {
            let gw = Arc::clone(&gw);
            Box::pin(async move {
                let response = gw.handle_message(request.value()).await;
                request.reply(response)
            })
        })
    };

    let endpoint_desc = match &spec {
        chaperone_transport::ListenSpec::UnixSocket { path } => path.display().to_string(),
        chaperone_transport::ListenSpec::NamedPipe { name } => name.clone(),
        chaperone_transport::ListenSpec::TcpV4 { port } => format!("127.0.0.1:{port}"),
        chaperone_transport::ListenSpec::TcpV6 { port } => format!("[::1]:{port}"),
    };
    println!(
        "chaperone gateway listening on {endpoint_desc} (protocol {})",
        chaperone_protocol::PROTOCOL_VERSION
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    // Bind + accept inside the runtime: async listeners need a reactor.
    rt.block_on(async move {
        // Operator config UI on the loopback (D40).
        if let Some(state) = ui_state {
            match chaperone_ui::bind(ui_port).await {
                Ok(listener) => {
                    println!(
                        "config UI on http://127.0.0.1:{ui_port} (token required; run 'chaperone ui-token show --token {ui_token_path}')"
                    );
                    tokio::spawn(chaperone_ui::serve_on(listener, state));
                }
                Err(e) => eprintln!("config UI disabled: {e}"),
            }
        }

        // D39: live policy drift watch - any change to the governing file
        // under a running gateway halts brokering, loudly.
        tokio::spawn(policy_watch.run(Arc::clone(&gateway), watch_audit, Some(event_hub)));

        let server = chaperone_transport::serve(&spec, handler).map_err(|e| e.to_string())?;
        println!("press Ctrl-C to stop");
        server.joined().await;
        Ok::<(), String>(())
    })?;
    Ok(())
}

/// Setup-only daemon: no gateway, no vault prompt - just the wizard.
fn cmd_serve_setup(flags: &Flags, ui_port: u16, ui_token_path: &str) -> Result<(), String> {
    use std::sync::Arc;
    if flags.has("no-ui") {
        return Err(
            "required artifacts are missing and --no-ui was given; cannot start. \
             Create policy.toml, the vault store, and an audit key first."
                .to_owned(),
        );
    }
    let enrollment_path = flags.require("enrollment")?;
    let policy_path = flags.require("policy")?;
    let store_path = flags.require("store")?;
    let journal_path = flags.require("audit-journal")?;
    let key_path = flags.require("audit-key")?;

    // D41: setup mode serves the UI too, so the token gate is required
    // here as well. The operator creates it with `chaperone ui-token
    // rotate` before first serve.
    let token = chaperone_ui::load(std::path::Path::new(ui_token_path)).map_err(|e| {
        format!(
            "{e}\n\nThe setup wizard is also token-gated (D41). Create one with:\n  \
             chaperone ui-token rotate --token {ui_token_path}\n\
             Then restart `chaperone serve`."
        )
    })?;

    let enrollment = Arc::new(
        chaperone_identity::EnrollmentStore::load(std::path::Path::new(&enrollment_path))
            .map_err(|e| e.to_string())?,
    );
    let state = Arc::new(chaperone_ui::UiState {
        policy_path: std::path::PathBuf::from(&policy_path),
        vault_path: std::path::PathBuf::from(&store_path),
        enrollment_path: std::path::PathBuf::from(&enrollment_path),
        audit_key_path: std::path::PathBuf::from(&key_path),
        journal_path: std::path::PathBuf::from(&journal_path),
        vault: std::sync::RwLock::new(None),
        enrollment,
        gateway: None,
        event_hub: None,
        events_socket_path: None,
        schemes: Vec::new(),
        token,
        port: ui_port,
    });

    println!("CHAPERONE SETUP");
    println!("  required artifacts are missing; starting the setup wizard only.");
    println!("  open: http://127.0.0.1:{ui_port}/?token=<TOKEN>");
    println!("  token: chaperone ui-token show --token {ui_token_path}");
    println!("  after setup, restart this command to broker intents.");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(chaperone_ui::serve(state))
}

fn load_audit_seed_text(text: &str) -> Result<chaperone_audit::AuditKey, String> {
    let seed = chaperone_protocol::decode_signature(text.trim())
        .map_err(|e| format!("seed file is not base64url: {e}"))?;
    let seed: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "seed file must hold 32 bytes".to_owned())?;
    Ok(chaperone_audit::AuditKey::from_seed(seed))
}

fn run(args: Vec<String>) -> Result<(), String> {
    let Some(command) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };
    match command.as_str() {
        "version" | "--version" | "-V" => {
            println!(
                "chaperone {} (protocol {}, gateway spec v0.1)",
                env!("CARGO_PKG_VERSION"),
                chaperone_protocol::PROTOCOL_VERSION
            );
            return Ok(());
        }
        _ => {}
    }
    // `ui-token show|rotate` carries a bare positional sub-action that the
    // generic flag parser rejects; handle it before parse_flags.
    if command.as_str() == "ui-token" {
        return cmd_ui_token(&args[1..]);
    }
    let flags = parse_flags(&args[1..])?;
    match command.as_str() {
        "enroll" => cmd_enroll(&flags),
        "revoke" => cmd_revoke(&flags),
        "list-agents" => cmd_list_agents(&flags),
        "policy-check" => cmd_policy_check(&flags),
        "audit-keygen" => cmd_audit_keygen(&flags),
        #[cfg(unix)]
        "console" => cmd_console(&flags),
        "audit-verify" => cmd_audit_verify(&flags),
        "audit-export" => cmd_audit_export(&flags),
        "doctor" => cmd_doctor(&flags),
        "vault-init" => cmd_vault_init(&flags),
        "vault-set" => cmd_vault_set(&flags),
        "vault-get" => cmd_vault_get(&flags),
        "vault-list" => cmd_vault_list(&flags),
        "vault-del" => cmd_vault_del(&flags),
        "serve" => cmd_serve(&flags),
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
