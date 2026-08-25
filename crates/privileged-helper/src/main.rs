//! The Chaperone privileged helper binary (ARCH-SPEC §2.7).
//!
//! A deliberately SEPARATE process: privilege escalation is "run this as
//! root", not "attach a secret to a request". It shares no code path with
//! network injection, so a compromise of any injector cannot reach here.
//!
//! This binary is thin glue over [`chaperone_helper_core::process_request`]
//! - every security decision lives in the library where it is tested.

use chaperone_helper_core::{Allowlist, read_frame, write_frame};
use serde_json::Value;

fn main_inner() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // --elevated is placed INSIDE the sudoers command line, so any genuinely
    // elevated invocation necessarily carries it. It switches the allowlist
    // check to strict root-ownership validation. It can only make things
    // STRICTER - never weaker - so a non-elevated caller passing it just
    // fails their own (user-owned) file.
    let elevated = args.iter().position(|a| a == "--elevated").is_some();
    if elevated && let Some(pos) = args.iter().position(|a| a == "--elevated") {
        args.remove(pos);
    }

    let mut allowlist_path = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--allowlist"
            && let Some(v) = args.get(i + 1)
        {
            allowlist_path = Some(v.clone());
            break;
        }
        i += 1;
    }
    let Some(allowlist_path) = allowlist_path else {
        return Err("usage: chaperone-helper [--elevated] --allowlist <TOML>".to_owned());
    };

    let expected_token = std::env::var("CHAPERONE_HELPER_TOKEN")
        .map_err(|_| "CHAPERONE_HELPER_TOKEN not set; refusing to run".to_owned())?;
    if expected_token.is_empty() {
        return Err("empty helper token; refusing to run".to_owned());
    }

    let path = std::path::Path::new(&allowlist_path);
    #[cfg(unix)]
    if elevated {
        chaperone_helper_core::check_allowlist_for_elevated(path)
            .map_err(|e| format!("elevated allowlist check failed: {e}"))?;
    }
    #[cfg(not(unix))]
    let _ = elevated;

    let allowlist = Allowlist::load(path)?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    while let Some(body) = read_frame(&mut reader)? {
        let msg: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        for response in
            chaperone_helper_core::process_request(&msg, &expected_token, &allowlist, true)
        {
            write_frame(&mut writer, &response.to_string().into_bytes())?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = main_inner() {
        eprintln!("chaperone-helper: {e}");
        std::process::exit(1);
    }
}
