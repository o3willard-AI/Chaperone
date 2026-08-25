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
fn dash_dash_version_flag_equivalent() {
    let out = run(&["--version"]);
    assert!(out.contains("chaperone"), "{out}");
    assert!(out.contains(env!("CARGO_PKG_VERSION")), "{out}");
}
