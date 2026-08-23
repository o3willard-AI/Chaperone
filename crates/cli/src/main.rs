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

use chaperone_identity::{EnrollmentError, EnrollmentStore};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const USAGE: &str = "\
chaperone - Chaperone operator CLI

USAGE:
    chaperone enroll --store <PATH> --agent-id <ID> --public-key <B64URL> [--force]
    chaperone revoke --store <PATH> --agent-id <ID>
    chaperone list-agents --store <PATH>

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
