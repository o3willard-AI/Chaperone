//! Fuzz target: the Content-Length frame codec (PROTO-SPEC §3.2).
//!
//! Invariant under arbitrary wire bytes: read_frame returns Ok(text) or a
//! typed FrameError - never panics, never allocates against an attacker-
//! controlled length beyond the D10 hard cap.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let mut reader: &[u8] = data;
        // Ok or Err are both fine outcomes; only a panic is a finding.
        let _ = chaperone_transport::read_frame(&mut reader).await;
    });
});
