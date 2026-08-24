//! Fuzz target: identity verification over arbitrary envelope bytes.
//!
//! Invariant: the §4 verification sequence (version -> resolve -> freshness/
//! replay -> signature) returns Ok or a typed IdentityError for ANY input;
//! it must never panic, never parse mechanism bodies before attribution,
//! and never allocate unboundedly.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");

    rt.block_on(async {
        let now = chaperone_gateway_core::chaperone_time_now();

        let dir = match tempfile_in_cwd() {
            Some(d) => d,
            None => return,
        };
        let enrollment =
            std::sync::Arc::new(chaperone_identity::EnrollmentStore::load(&dir.path().join("e.json")).expect("store"));
        let cache = std::sync::Arc::new(
            chaperone_identity::ReplayCache::open(&dir.path().join("r.jsonl"), now.unix_timestamp())
                .expect("cache"),
        );
        let attestor = chaperone_identity::Attestor::new(
            enrollment,
            cache,
            chaperone_identity::IdentityConfig { max_skew_secs: 30 },
        );

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
            return; // not JSON: nothing to verify
        };

        // Ok or typed Err - both acceptable. A panic is the finding.
        let _ = attestor.verify(&value, now);
    });
    });

fn tempfile_in_cwd() -> Option<tempfile_shim::TempDir> {
    tempfile_shim::tempdir()
}

// Minimal shim so the fuzz target needs no extra dependency beyond what the
// workspace already trusts.
mod tempfile_shim {
    use std::path::PathBuf;

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    pub fn tempdir() -> Option<TempDir> {
        let mut raw = [0u8; 12];
        getrandom_fill(&mut raw);
        let name = format!(
            "chaperone-fuzz-{}",
            data_encoding_lite(&raw)
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).ok()?;
        Some(TempDir(path))
    }

    fn getrandom_fill(buf: &mut [u8]) {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(buf);
    }

    fn data_encoding_lite(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
