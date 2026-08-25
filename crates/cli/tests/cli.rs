//! CLI surface smoke tests: version reporting must work for release QA and
//! installer assertions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_chaperone"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "exit: {:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn version_reports_crate_and_protocol() {
    let out = run(&["version"]);
    assert!(out.contains(env!("CARGO_PKG_VERSION")), "{out}");
    assert!(out.contains("protocol 0.1"), "{out}");
}

#[test]
fn vault_round_trip_with_passphrase_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("v.bin");
    let pass_file = dir.path().join("vault.pass");
    std::fs::write(&pass_file, "service-passphrase\n").unwrap();

    let run_raw = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_chaperone"))
            .args(args)
            .output()
            .unwrap()
    };

    // init + set + get --show, all reading the passphrase from the file.
    let out = run_raw(&[
        "vault-init",
        "--store",
        store.to_str().unwrap(),
        "--passphrase-file",
        pass_file.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let passphrase = std::fs::read_to_string(&pass_file).unwrap();
    let trimmed = passphrase.trim_end();
    let value = "stored-via-passphrase-file";
    let stdin_data = format!("{trimmed}\n{value}\n");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_chaperone"));
    cmd.args([
        "vault-set",
        "--store",
        store.to_str().unwrap(),
        "--path",
        "prod/k",
        "--passphrase-file",
        pass_file.to_str().unwrap(),
    ])
    .stdin(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_data.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run(&[
        "vault-get",
        "--store",
        store.to_str().unwrap(),
        "--path",
        "prod/k",
        "--show",
        "--passphrase-file",
        pass_file.to_str().unwrap(),
    ]);
    assert!(out.contains(value), "{out}");
}

#[test]
fn dash_dash_version_flag_equivalent() {
    let out = run(&["--version"]);
    assert!(out.contains("chaperone"), "{out}");
    assert!(out.contains(env!("CARGO_PKG_VERSION")), "{out}");
}
