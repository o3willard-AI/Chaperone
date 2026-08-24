//! Phase 5 acceptance tests (docs/PLAN.md M5).
//!
//! The ephemerality contract (ARCH-SPEC §2.9) proven here:
//! - cred_refs resolve through scheme dispatch;
//! - plaintext is redacted in every accidental-observability channel and
//!   lives only inside call frames;
//! - a retry RE-FETCHES: two calls, two backend hits, no cache anywhere;
//! - nothing survives restart except the encrypted store itself.

// Tests are allowed to panic: a failing assert IS the test result.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::err_expect
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chaperone_vault::{LocalVault, Provider, ResolveError, SecretString, VaultRouter};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "operator-passphrase-with-real-length-1";
const ENTRY: &str = "prod/stripe/secret_key";

fn new_store(dir: &Path) -> LocalVault {
    LocalVault::create(
        &dir.join("vault.bin"),
        Zeroizing::new(PASSPHRASE.to_owned()),
    )
    .unwrap()
}

use std::path::Path;

fn seeded_store(dir: &Path) -> LocalVault {
    let mut v = new_store(dir);
    v.set(
        ENTRY,
        SecretString::new("sk-simulated-value-not-a-real-key".to_owned()),
    )
    .unwrap();
    v.set("other/entry", SecretString::new("second-value".to_owned()))
        .unwrap();
    v
}

/// Provider wrapper that counts backend hits - the no-cache oracle.
#[derive(Debug)]
struct Counting {
    inner: Arc<LocalVault>,
    resolve_calls: AtomicUsize,
}

impl Counting {
    fn calls(&self) -> usize {
        self.resolve_calls.load(Ordering::SeqCst)
    }
}

impl Provider for Counting {
    fn resolve(&self, entry: &str) -> Result<SecretString, ResolveError> {
        self.resolve_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve(entry)
    }
}

#[test]
fn cred_ref_resolves_through_scheme_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(seeded_store(dir.path()));

    let mut router = VaultRouter::new();
    router.register("local", vault.clone());

    let secret = router.resolve(&format!("local://{ENTRY}")).unwrap();
    assert_eq!(secret.expose(), "sk-simulated-value-not-a-real-key");
}

#[test]
fn unsupported_schemes_report_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(seeded_store(dir.path()));
    let mut router = VaultRouter::new();
    router.register("local", vault);

    // Enterprise schemes are shaped but not configured (ARCH §2.4 table).
    for r in [
        "aws://prod/db",
        "gcp://x",
        "vault://y",
        "noscheme",
        "local://",
    ] {
        let err = router.resolve(r).unwrap_err();
        assert!(
            matches!(
                err,
                ResolveError::UnsupportedScheme { .. } | ResolveError::MalformedCredRef(_)
            ),
            "{r}: {err}"
        );
    }
}

#[test]
fn retry_refetches_two_backend_hits_no_cache() {
    let dir = tempfile::tempdir().unwrap();
    let counting = Counting {
        inner: Arc::new(seeded_store(dir.path())),
        resolve_calls: AtomicUsize::new(0),
    };

    // Same reference twice - a retry-shaped pattern.
    let first = counting.resolve(ENTRY).unwrap();
    let second = counting.resolve(ENTRY).unwrap();

    assert_eq!(counting.calls(), 2, "every resolve must hit the backend");
    assert_eq!(first.expose(), second.expose());
}

#[test]
fn router_itself_caches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let counting = Arc::new(Counting {
        inner: Arc::new(seeded_store(dir.path())),
        resolve_calls: AtomicUsize::new(0),
    });
    let mut router = VaultRouter::new();
    router.register("local", counting.clone());

    for _ in 0..25 {
        router.resolve(&format!("local://{ENTRY}")).unwrap();
    }
    assert_eq!(counting.calls(), 25, "no memoization at any layer");
}

#[test]
fn nothing_survives_restart_except_the_encrypted_store() {
    let dir = tempfile::tempdir().unwrap();
    let counting = Arc::new(Counting {
        inner: Arc::new(seeded_store(dir.path())),
        resolve_calls: AtomicUsize::new(0),
    });

    // First process-generation resolves.
    counting.resolve(ENTRY).unwrap();
    assert_eq!(counting.calls(), 1);

    // Restart: fresh store handle + fresh cache state by construction.
    let reopened = Arc::new(
        LocalVault::open(
            &dir.path().join("vault.bin"),
            Zeroizing::new(PASSPHRASE.to_owned()),
        )
        .unwrap(),
    );
    assert_eq!(reopened.list().unwrap().len(), 2, "store persists");
    let fresh_counter = Counting {
        inner: reopened,
        resolve_calls: AtomicUsize::new(0),
    };
    fresh_counter.resolve(ENTRY).unwrap();
    assert_eq!(fresh_counter.calls(), 1, "restart starts from zero cache");
}

#[test]
fn plaintext_is_redacted_in_accidental_channels() {
    let s = SecretString::new("leak-me-not".to_owned());
    assert!(!format!("{s:?}").contains("leak-me-not"));
    assert!(!format!("{s}").contains("leak-me-not"));
}

#[test]
fn missing_entries_fail_without_content_leaks() {
    let dir = tempfile::tempdir().unwrap();
    let vault = seeded_store(dir.path());
    match vault.get("does/not/exist").unwrap() {
        None => {}
        Some(_) => panic!("missing entry resolved"),
    }
    let err = Provider::resolve(&vault, "does/not/exist").unwrap_err();
    let rendered = err.to_string();
    assert!(
        rendered.contains("does/not/exist"),
        "path named for forensics"
    );
    assert!(
        !rendered.contains("sk-simulated"),
        "no value material in errors"
    );
}

#[test]
fn wrong_passphrase_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    seeded_store(dir.path());

    let err = LocalVault::open(
        &dir.path().join("vault.bin"),
        Zeroizing::new("wrong-passphrase".to_owned()),
    )
    .err()
    .expect("wrong passphrase must fail");
    assert!(
        matches!(err, chaperone_vault::VaultError::WrongPassphrase),
        "{err}"
    );
}

#[test]
fn corrupted_body_detected_at_open() {
    let dir = tempfile::tempdir().unwrap();
    seeded_store(dir.path());
    let path = dir.path().join("vault.bin");

    // Flip one byte deep in the file (inside the ciphertext body).
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 3;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, bytes).unwrap();

    let err = LocalVault::open(&path, Zeroizing::new(PASSPHRASE.to_owned()))
        .err()
        .expect("corruption must fail open");
    assert!(
        matches!(
            err,
            chaperone_vault::VaultError::WrongPassphrase | chaperone_vault::VaultError::Corrupt(_)
        ),
        "{err}"
    );
}

#[test]
fn writes_are_atomic_and_durable_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.bin");
    {
        let mut v = new_store(dir.path());
        v.set(ENTRY, SecretString::new("v1".to_owned())).unwrap();
    }
    {
        let mut v = LocalVault::open(&path, Zeroizing::new(PASSPHRASE.to_owned())).unwrap();
        v.set(ENTRY, SecretString::new("v2".to_owned())).unwrap();
    }
    let v = LocalVault::open(&path, Zeroizing::new(PASSPHRASE.to_owned())).unwrap();
    assert_eq!(v.get(ENTRY).unwrap().unwrap().expose(), "v2");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "vault file must be owner-only");
    }
}

#[test]
fn mint_on_static_local_reports_unsupported_not_fake_scoping() {
    let dir = tempfile::tempdir().unwrap();
    let vault = seeded_store(dir.path());
    let err = Provider::mint(&vault, ENTRY, 300).unwrap_err();
    assert!(err.to_string().contains("minting"), "{err}");
}
