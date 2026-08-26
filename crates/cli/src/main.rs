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
                    [--ui-port N] [--no-ui]

LOCAL VAULT (operator CRUD):
    chaperone vault-init  --store <FILE> [--sealer passphrase] [--passphrase-stdin]
    chaperone vault-set   --store <FILE> --path <P> [--passphrase-stdin]   (secret on stdin)
    chaperone vault-get   --store <FILE> --path <P> [--passphrase-stdin] [--show]
    chaperone vault-list  --store <FILE> [--passphrase-stdin]
    chaperone vault-del   --store <FILE> --path <P> [--passphrase-stdin]

RELEASE SIGNING (PLAN Phase 10):
    chaperone release-sign  --key <SEEDFILE> --file <ARTIFACT>   # writes ARTIFACT.sig
    chaperone release-verify --file <ARTIFACT> --sig <SIGFILE> --public-key <B64URL>

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

fn cmd_release_sign(flags: &Flags) -> Result<(), String> {
    let key_path = flags.require("key")?;
    let file = flags.require("file")?;
    let seed_text =
        std::fs::read_to_string(&key_path).map_err(|e| format!("cannot read {key_path}: {e}"))?;
    let key = load_audit_seed_text(&seed_text)?;
    let artifact = std::fs::read(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let signature = key.sign_message(&artifact);
    let sig_path = format!("{file}.sig");
    std::fs::write(&sig_path, &signature).map_err(|e| e.to_string())?;
    println!("signed {file} -> {sig_path}");
    println!("public key: {}", key.public_key_b64url());
    Ok(())
}

fn cmd_release_verify(flags: &Flags) -> Result<(), String> {
    let file = flags.require("file")?;
    let sig = flags.require("sig")?;
    let pubkey = flags.require("public-key")?;
    let artifact = std::fs::read(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let signature = std::fs::read_to_string(&sig).map_err(|e| format!("cannot read {sig}: {e}"))?;
    let vk = chaperone_audit::verifying_key_from_b64url(&pubkey)?;
    if chaperone_audit::AuditKey::verify_message(&vk, &artifact, signature.trim()) {
        println!("VERIFIED: {file} matches {sig}");
        Ok(())
    } else {
        Err(format!("signature does NOT match {file}"))
    }
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

    // First-run detection: without the three broker-required artifacts
    // there is nothing to serve and no vault passphrase to prompt for -
    // run the setup wizard instead (OPERATOR-UI-SPEC §3.3).
    let provisioned = std::path::Path::new(&policy_path).exists()
        && std::path::Path::new(&store_path).exists()
        && std::path::Path::new(&key_path).exists();
    if !provisioned {
        return cmd_serve_setup(flags, ui_port);
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
            #[cfg(not(unix))]
            Some(_) => stdio_gate(confirm_timeout),
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

    let ui_state = ui_enabled.then(|| {
        std::sync::Arc::new(chaperone_ui::UiState {
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
            port: ui_port,
        })
    });

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
                        "config UI on http://127.0.0.1:{ui_port} (loopback only; no auth by design - same trust tier as the console client)"
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
fn cmd_serve_setup(flags: &Flags, ui_port: u16) -> Result<(), String> {
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
        port: ui_port,
    });

    println!("CHAPERONE SETUP");
    println!("  required artifacts are missing; starting the setup wizard only.");
    println!("  open: http://127.0.0.1:{ui_port}");
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
    let flags = parse_flags(&args[1..])?;
    match command.as_str() {
        "enroll" => cmd_enroll(&flags),
        "revoke" => cmd_revoke(&flags),
        "list-agents" => cmd_list_agents(&flags),
        "policy-check" => cmd_policy_check(&flags),
        "audit-keygen" => cmd_audit_keygen(&flags),
        "release-sign" => cmd_release_sign(&flags),
        "release-verify" => cmd_release_verify(&flags),
        #[cfg(unix)]
        "console" => cmd_console(&flags),
        "audit-verify" => cmd_audit_verify(&flags),
        "audit-export" => cmd_audit_export(&flags),
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
