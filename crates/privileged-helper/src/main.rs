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
    let mut args = std::env::args().skip(1);
    let allowlist_path = loop {
        match (args.next(), args.next()) {
            (Some(a), Some(v)) if a == "--allowlist" => break v,
            (None, _) => return Err("usage: chaperone-helper --allowlist <TOML>".to_owned()),
            _ => continue,
        }
    };
    let expected_token = std::env::var("CHAPERONE_HELPER_TOKEN")
        .map_err(|_| "CHAPERONE_HELPER_TOKEN not set; refusing to run".to_owned())?;
    if expected_token.is_empty() {
        return Err("empty helper token; refusing to run".to_owned());
    }
    let allowlist = Allowlist::load(std::path::Path::new(&allowlist_path))?;

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
