//! Fuzz target: policy document parsing + evaluation.
//!
//! Invariants under arbitrary TOML text: parse either succeeds with a
//! usable ruleset or fails with PolicyError; evaluation of the fixed probe
//! request is TOTAL (always yields a verdict) and PURE (same input, same
//! verdict across repeated calls).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(policy) = chaperone_policy::Policy::from_toml(text) else { return };

    let request = chaperone_policy::Request {
        agent_id: "agent:fuzz",
        cred_ref: "vault://fuzz/entry",
        target_uri: "https://fuzz.example/v1",
        mechanism: "http-bearer",
        declared: None,
    };

    let first = policy.evaluate(&request);
    for _ in 0..3 {
        assert_eq!(policy.evaluate(&request), first, "evaluation must be pure");
    }
});
