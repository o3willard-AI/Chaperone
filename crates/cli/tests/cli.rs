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

#[test]
fn enroll_requires_a_named_sponsor() {
    // RAE L0: the enroll command must refuse to record an agent with no
    // named human sponsor. Mutation check: drop the --sponsor-id/--sponsor-name
    // requirement in cmd_enroll and this test goes red.
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("agents.json");
    // base64url (unpadded) of 32 zero bytes: a structurally valid public
    // key, all the enroll gate needs.
    let pub_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let run_raw = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_chaperone"))
            .args(args)
            .output()
            .unwrap()
    };

    // No sponsor flags -> exit 2 with the missing-flag error.
    let out = run_raw(&[
        "enroll",
        "--store",
        store.to_str().unwrap(),
        "--agent-id",
        "agent:cli-test",
        "--public-key",
        pub_b64,
    ]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("sponsor-id"), "{stderr}");

    // Only one of the two -> still refused.
    let out = run_raw(&[
        "enroll",
        "--store",
        store.to_str().unwrap(),
        "--agent-id",
        "agent:cli-test",
        "--public-key",
        pub_b64,
        "--sponsor-id",
        "sponsor@example.org",
    ]);
    assert_eq!(out.status.code(), Some(2));

    // Both -> succeeds, and list-agents shows the human.
    let out = run_raw(&[
        "enroll",
        "--store",
        store.to_str().unwrap(),
        "--agent-id",
        "agent:cli-test",
        "--public-key",
        pub_b64,
        "--sponsor-id",
        "sponsor@example.org",
        "--sponsor-name",
        "Test Sponsor",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listed = run(&["list-agents", "--store", store.to_str().unwrap()]);
    assert!(listed.contains("sponsor@example.org"), "{listed}");
}

/// GO CA-1 (Stephen, 2026-10-06): the operator CLI must refuse get/set/del on
/// the CA namespace — the direct-handle path that bypasses the SharedVault
/// Provider::resolve guard. Falsifiable: the same commands on a normal entry
/// must SUCCEED, so the guard is provably namespace-scoped, not vault-wide.
#[test]
fn ca_namespace_is_refused_by_operator_cli() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("v.bin");
    let pf = dir.path().join("p");
    std::fs::write(&pf, "service-passphrase\n").unwrap();

    let run = |args: &[&str], input: &str| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_chaperone"));
        c.args(args);
        if !input.is_empty() {
            c.stdin(std::process::Stdio::piped());
        }
        c.stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let mut ch = c.spawn().unwrap();
        if !input.is_empty() {
            use std::io::Write as _;
            ch.stdin
                .as_mut()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let o = ch.wait_with_output().unwrap();
        eprintln!(
            "DBGC args={:?} code={:?} out={:?} err={:?}",
            args.first(),
            o.status.code(),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        o
    };

    let passphrase = std::fs::read_to_string(&pf).unwrap();
    let trimmed = passphrase.trim_end();

    let o = run(
        &[
            "vault-init",
            "--store",
            store.to_str().unwrap(),
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    assert!(o.status.success(), "init failed");

    // GET refused
    let o = run(
        &[
            "vault-get",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "chaperone/ca/ssh",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "GET: {stderr}");
    assert!(
        stderr.contains("non-exportable SSH CA namespace"),
        "GET: {stderr}"
    );

    // SET refused
    let o = run(
        &[
            "vault-set",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "chaperone/ca/ssh",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        &format!("{trimmed}\nFAKE-CA-KEY\n"),
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "SET: {stderr}");
    assert!(
        stderr.contains("non-exportable SSH CA namespace"),
        "SET: {stderr}"
    );

    // DEL refused
    let o = run(
        &[
            "vault-del",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "chaperone/ca/ssh",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "DEL: {stderr}");
    assert!(
        stderr.contains("non-exportable SSH CA namespace"),
        "DEL: {stderr}"
    );

    // Positive control: a normal entry round-trips through the same vault.
    let value = "guard-does-not-eat-normal-entries";
    let o = run(
        &[
            "vault-set",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "normal/entry",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        &format!("{trimmed}\n{value}\n"),
    );
    assert!(
        o.status.success(),
        "normal set failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = run(
        &[
            "vault-get",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "normal/entry",
            "--show",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains(value), "normal get: {out}");
}
// B-2 acceptance (ruled spec, tests 1/2/4/5/7 end-to-end): real binary,
// real vault + policy files. P1-2's acceptance now machine-generated.
#[test]
fn vault_import_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("v.bin");
    let pf = dir.path().join("pf");
    std::fs::write(&pf, "service-passphrase\n").unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        r#"
[[rule]]
name = "fleet"
effect = "allow"
agent_id = "agent:deployer"
cred_ref = "local://ssh/fleet/*"
target_uri = "ssh://*.internal:*"
mechanism = "ssh"
"#,
    )
    .unwrap();
    let csv = dir.path().join("fleet.csv");
    std::fs::write(
        &csv,
        "name,host,port,user,secret\napp-01,app-01.internal,22,deploy,real-secret-1\napp-02,app-02.internal,2202,deploy,\n",
    )
    .unwrap();

    let source_arg = format!("csv:{}", csv.to_str().unwrap());
    let run_raw = |args: &[&str], stdin_data: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_chaperone"));
        cmd.args(args);
        if !stdin_data.is_empty() {
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if !stdin_data.is_empty() {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(stdin_data.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    };

    // init
    let o = run_raw(
        &[
            "vault-init",
            "--store",
            store.to_str().unwrap(),
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    // import
    let o = run_raw(
        &[
            "vault-import",
            "--store",
            store.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--rule-name",
            "fleet",
            "--source",
            source_arg.as_str(),
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("imported ssh/fleet/app-01"), "{out}");
    assert!(out.contains("1 placeholder"), "{out}");
    // F5 warning present
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("plaintext secrets"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // no-leak (test 7): the secret never reaches stdout
    assert!(!out.contains("real-secret-1"), "secret leaked: {out}");

    // policy file gained BOTH pair rows (canonical writer)
    let doc = std::fs::read_to_string(&policy).unwrap();
    assert!(
        doc.contains("cred_ref = \"local://ssh/fleet/app-01\""),
        "{doc}"
    );
    assert!(
        doc.contains("cred_ref = \"local://ssh/fleet/app-02\""),
        "{doc}"
    );

    // value preservation + placeholder honesty (F1/TD-5)
    let o = run_raw(
        &[
            "vault-get",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "ssh/fleet/app-01",
            "--show",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "real-secret-1");

    // idempotent re-run (test 2): skipped, no duplicate rows
    let before = std::fs::read_to_string(&policy).unwrap();
    let o = run_raw(
        &[
            "vault-import",
            "--store",
            store.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--rule-name",
            "fleet",
            "--source",
            source_arg.as_str(),
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("skipped ssh/fleet/app-01"), "{out}");
    assert_eq!(
        std::fs::read_to_string(&policy).unwrap(),
        before,
        "re-run must not change the policy"
    );

    // fail-closed rule name (test 5)
    let o = run_raw(
        &[
            "vault-import",
            "--store",
            store.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--rule-name",
            "nope",
            "--source",
            source_arg.as_str(),
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        std::fs::read_to_string(&policy).unwrap(),
        before,
        "failed import must not touch the policy"
    );
}

/// B2-FIX Fix 3: pin the F1 value-survival END-TO-END — pre-seed V1, import
/// V2, the run reports `skipped (exists)` and the stored value is still V1.
/// (The spec's acceptance #2; no prior test actually did this.)
#[test]
fn import_never_overwrites_existing_value() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("v.bin");
    let pf = dir.path().join("pf");
    std::fs::write(&pf, "service-passphrase\n").unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        r#"
[[rule]]
name = "fleet"
effect = "allow"
agent_id = "agent:deployer"
cred_ref = "local://ssh/fleet/*"
target_uri = "ssh://*.internal:*"
mechanism = "ssh"
"#,
    )
    .unwrap();
    // Import CSV carries NEW-VALUE for an entry that will already exist.
    let csv = dir.path().join("fleet.csv");
    std::fs::write(
        &csv,
        "name,host,port,user,secret\napp-01,app-01.internal,22,deploy,NEW-VALUE\n",
    )
    .unwrap();

    let run_raw = |args: &[&str], stdin_data: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_chaperone"));
        cmd.args(args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        if !stdin_data.is_empty() {
            cmd.stdin(std::process::Stdio::piped());
        }
        let mut child = cmd.spawn().unwrap();
        if !stdin_data.is_empty() {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(stdin_data.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    };

    // init + pre-seed V1 via the operator CLI
    let o = run_raw(
        &[
            "vault-init",
            "--store",
            store.to_str().unwrap(),
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = run_raw(
        &[
            "vault-set",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "ssh/fleet/app-01",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "OLD-VALUE\n",
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    // import with V2
    let o = run_raw(
        &[
            "vault-import",
            "--store",
            store.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--rule-name",
            "fleet",
            "--source",
            &format!("csv:{}", csv.to_str().unwrap()),
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        out.contains("skipped ssh/fleet/app-01"),
        "expected skipped (exists): {out}"
    );
    // no-leak: NEW-VALUE must not reach stdout either (the value was refused)
    assert!(!out.contains("NEW-VALUE"), "{out}");

    // THE pin: the stored value is still V1.
    let o = run_raw(
        &[
            "vault-get",
            "--store",
            store.to_str().unwrap(),
            "--path",
            "ssh/fleet/app-01",
            "--show",
            "--passphrase-file",
            pf.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "OLD-VALUE",
        "import must not overwrite a pre-existing secret"
    );
}
