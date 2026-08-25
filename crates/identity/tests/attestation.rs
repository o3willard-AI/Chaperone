//! Phase 2 acceptance tests (docs/PLAN.md M2).
//!
//! The core property proven here: **attribution before action**. Forged,
//! stale, replayed, wrong-key, and revoked intents are rejected with the
//! correct error BEFORE any body parsing — demonstrated by intents whose
//! bodies are deliberately unparseable garbage: if the pipeline ever touched
//! the body, these tests would fail differently.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chaperone_identity::{Attestor, EnrollmentStore, IdentityConfig, IdentityError};
use chaperone_protocol::{canonical_form, encode_signature};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const AGENT: &str = "agent:planner-7";
const SKEW: i64 = 30;

fn key_from_seed(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap()
}

fn secs(n: i64) -> std::time::Duration {
    std::time::Duration::from_secs(u64::try_from(n).unwrap())
}

/// Signs `envelope` with `key` exactly as a well-behaved agent would.
fn sign(key: &SigningKey, envelope: &mut Value) {
    let canonical = canonical_form(envelope).unwrap();
    let sig = key.sign(&canonical);
    envelope["sig"] = json!(encode_signature(&sig.to_bytes()));
}

fn make_attestor(now: OffsetDateTime) -> (Attestor, Arc<EnrollmentStore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(EnrollmentStore::load(&dir.path().join("enrollment.json")).unwrap());
    let cache = Arc::new(
        chaperone_identity::ReplayCache::open(
            &dir.path().join("replay.jsonl"),
            now.unix_timestamp(),
        )
        .unwrap(),
    );
    (
        Attestor::new(
            store.clone(),
            cache,
            IdentityConfig {
                max_skew_secs: SKEW,
            },
        ),
        store,
        dir,
    )
}

/// Builds a signed http-bearer intent naming `key`'s agent.
fn signed_intent(key: &SigningKey, now: OffsetDateTime, nonce: &str) -> Value {
    let mut env = json!({
        "chaperone": "0.1",
        "msg_id": "a3f1c9",
        "type": "intent",
        "agent_id": AGENT,
        "issued_at": rfc3339(now),
        "nonce": nonce,
        "target": {"uri": "https://api.stripe.com/v1/charges", "label": "stripe-prod"},
        "mechanism": "http-bearer",
        "cred_ref": "vault://prod/stripe/secret_key",
        "operation": {"method": "POST", "headers": {}, "body_b64": "not-really-base64-on-purpose"},
    });
    sign(key, &mut env);
    env
}

#[test]
fn correctly_signed_fresh_intent_verifies() {
    let key = key_from_seed(1);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let intent = signed_intent(&key, now, "nonce-001");
    let verified = attestor.verify(&intent, now).unwrap();
    assert_eq!(verified.agent_id, AGENT);
    assert_eq!(verified.nonce, "nonce-001");
    assert_eq!(
        verified.envelope["cred_ref"],
        "vault://prod/stripe/secret_key"
    );
}

#[test]
fn precedence_unknown_agent_beats_everything() {
    // Unparseable body + stale timestamp + garbage signature + UNKNOWN agent:
    // step 1 must win with E_UNKNOWN_AGENT before anything else is examined.
    let now = OffsetDateTime::now_utc();
    let (attestor, _store, _dir) = make_attestor(now);

    let mut env = json!({
        "chaperone": "0.1", "type": "intent", "agent_id": "agent:nobody",
        "issued_at": "1999-01-01T00:00:00Z", "nonce": "n", "sig": "!!!",
        "operation": {"this is": "garbage"},
    });
    env["msg_id"] = json!("m");

    assert_eq!(
        attestor.verify(&env, now).unwrap_err(),
        IdentityError::UnknownAgent("agent:nobody".to_owned())
    );
}

#[test]
fn precedence_replay_beats_bad_signature() {
    // Known agent + stale timestamp + broken signature: freshness/replay
    // (step 2) must win over signature (step 3).
    let key = key_from_seed(2);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let env = json!({
        "chaperone": "0.1", "msg_id": "m", "type": "intent", "agent_id": AGENT,
        "issued_at": rfc3339(now - secs(SKEW * 10)),
        "nonce": "n1", "sig": "not-a-real-signature",
    });
    let err = attestor.verify(&env, now).unwrap_err();
    assert!(matches!(err, IdentityError::Replay(_)), "got {err:?}");
    drop(env);

    // And within skew but with a reused nonce: still Replay, not BadSignature.
    let good = signed_intent(&key, now, "dup-nonce");
    attestor.verify(&good, now).unwrap();

    let mut tampered_sig = good.clone();
    tampered_sig["sig"] = json!("AAAA"); // undecodable-length garbage
    tampered_sig["nonce"] = json!("dup-nonce"); // reused
    let err = attestor.verify(&tampered_sig, now).unwrap_err();
    assert!(matches!(err, IdentityError::Replay(_)), "got {err:?}");
}

#[test]
fn bad_signature_is_the_last_identity_gate() {
    let key = key_from_seed(3);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let env = json!({
        "chaperone": "0.1", "msg_id": "m", "type": "intent", "agent_id": AGENT,
        "issued_at": rfc3339(now), "nonce": "fresh-1",
        "target": {"uri": "https://x", "label": "x"},
        "mechanism": "http-bearer", "cred_ref": "vault://x",
        "operation": {"method": "GET"},
        "sig": encode_signature(&[7u8; 64]), // well-formed bytes, wrong signature
    });
    assert_eq!(
        attestor.verify(&env, now).unwrap_err(),
        IdentityError::BadSignature
    );
}

#[test]
fn tampering_any_signed_field_invalidates() {
    let key = key_from_seed(4);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    // Sign against stripe; swap target to an attacker host post-signing.
    let mut intent = signed_intent(&key, now, "swap-1");
    intent["target"]["uri"] = json!("https://attacker.example/v1/charges");
    assert_eq!(
        attestor.verify(&intent, now).unwrap_err(),
        IdentityError::BadSignature
    );

    // Same attack against cred_ref.
    let mut intent = signed_intent(&key, now, "swap-2");
    intent["cred_ref"] = json!("local://etc/shadow");
    assert_eq!(
        attestor.verify(&intent, now).unwrap_err(),
        IdentityError::BadSignature
    );
}

#[test]
fn signature_must_match_claimed_agent_not_merely_some_agent() {
    // Attacker IS enrolled as their own agent but signs while CLAIMING ours.
    let victim_key = key_from_seed(5);
    let attacker_key = key_from_seed(6);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&victim_key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();
    store
        .enroll(
            "agent:attacker",
            &encode_signature(&attacker_key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let mut env = json!({
        "chaperone": "0.1", "msg_id": "m", "type": "intent",
        "agent_id": AGENT, // claims planner-7...
        "issued_at": rfc3339(now), "nonce": "steal-1",
        "target": {"uri": "https://x", "label": "x"}, "mechanism": "http-bearer",
        "cred_ref": "vault://x", "operation": {},
    });
    sign(&attacker_key, &mut env); // ...but attacker signs
    assert_eq!(
        attestor.verify(&env, now).unwrap_err(),
        IdentityError::BadSignature
    );
}

#[test]
fn replays_are_rejected_and_never_reserved_twice() {
    let key = key_from_seed(7);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let intent = signed_intent(&key, now, "same-nonce");
    attestor.verify(&intent, now).unwrap();
    let second = signed_intent(&key, now, "same-nonce");
    let err = attestor.verify(&second, now).unwrap_err();
    assert!(matches!(err, IdentityError::Replay(_)));
}

#[test]
fn staleness_beyond_skew_is_replay_boundary_exact_passes() {
    let key = key_from_seed(8);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    // Exactly at the boundary: acceptable per ±30s.
    let edge = signed_intent_with_time(&key, now - secs(SKEW), "edge-1");
    attestor.verify(&edge, now).unwrap();

    // One second beyond: rejected.
    let late = signed_intent_with_time(&key, now - secs(SKEW + 1), "edge-2");
    assert!(matches!(
        attestor.verify(&late, now).unwrap_err(),
        IdentityError::Replay(_)
    ));

    // Future-dated just past the window: rejected.
    let future = signed_intent_with_time(&key, now + secs(SKEW + 1), "edge-3");
    assert!(matches!(
        attestor.verify(&future, now).unwrap_err(),
        IdentityError::Replay(_)
    ));

    // Non-RFC3339 timestamp: Replay (step 2 owns this check).
    let mut junk = signed_intent(&key, now, "edge-4");
    junk["issued_at"] = json!("yesterday-ish");
    assert!(matches!(
        attestor.verify(&junk, now).unwrap_err(),
        IdentityError::Replay(_)
    ));
}

fn signed_intent_with_time(key: &SigningKey, issued_at: OffsetDateTime, nonce: &str) -> Value {
    let mut env = json!({
        "chaperone": "0.1", "msg_id": "m", "type": "intent", "agent_id": AGENT,
        "issued_at": rfc3339(issued_at), "nonce": nonce,
        "target": {"uri": "https://x", "label": "x"}, "mechanism": "http-bearer",
        "cred_ref": "vault://x", "operation": {},
    });
    sign(key, &mut env);
    env
}

#[test]
fn revocation_is_immediate_and_fails_at_step_one() {
    let key = key_from_seed(9);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    // Perfectly valid intent from a perfectly valid key...
    let intent = signed_intent(&key, now, "pre-revoke");
    attestor.verify(&intent, now).unwrap();

    // ...then revocation turns it into an UNKNOWN agent, even though the
    // signature itself would verify fine. That ordering is the point.
    assert!(store.revoke(AGENT, &rfc3339(now)).unwrap());
    let post = signed_intent(&key, now, "post-revoke");
    assert_eq!(
        attestor.verify(&post, now).unwrap_err(),
        IdentityError::UnknownAgent(AGENT.to_owned())
    );
}

#[test]
fn unknown_signed_fields_stay_covered_by_the_signature() {
    // A future MINOR adds fields. Old gateways must still verify intents
    // carrying them (D9): canonical form includes unknowns.
    let key = key_from_seed(10);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let mut env = signed_intent(&key, now, "fwd-1");
    env["new_in_minor"] = json!({"added": true});
    sign(&key, &mut env); // re-sign including the new field
    attestor.verify(&env, now).unwrap();

    // But an unknown field added AFTER signing breaks it, like any other
    // tamper. Fresh nonce: the previous attempt reserved "fwd-1".
    let mut sneaky = signed_intent(&key, now, "fwd-2");
    sneaky["sneaky_after_signing"] = json!(true);
    assert_eq!(
        attestor.verify(&sneaky, now).unwrap_err(),
        IdentityError::BadSignature
    );
}

#[test]
fn version_gate_precedes_resolution_si7() {
    let key = key_from_seed(14);
    let now = OffsetDateTime::now_utc();
    let (attestor, store, _dir) = make_attestor(now);
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let mut env = json!({
        "chaperone": "1.0", "type": "intent", "agent_id": "agent:anyone",
        "issued_at": rfc3339(now), "nonce": "v1"
    });

    use chaperone_protocol::ErrorCode;
    let err = attestor.verify(&env, now).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::Version);
    drop(env);

    // Same MAJOR, newer MINOR: accepted shape-wise (SI-7 stance).
    env = json!({
        "chaperone": "0.9", "msg_id": "m", "type": "intent", "agent_id": AGENT,
        "issued_at": rfc3339(now), "nonce": "v2",
        "target": {"uri": "https://x", "label": "x"}, "mechanism": "http-bearer",
        "cred_ref": "vault://x", "operation": {}, "sig": ""
    });
    // Fails later at signature, NOT at version — proving the minor passed.
    assert_eq!(
        attestor.verify(&env, now).unwrap_err(),
        IdentityError::BadSignature
    );
}

#[test]
fn replay_cache_survives_restart() {
    let key = key_from_seed(11);
    let now = OffsetDateTime::now_utc();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(EnrollmentStore::load(&dir.path().join("e.json")).unwrap());
    store
        .enroll(
            AGENT,
            &encode_signature(&key.verifying_key().to_bytes()),
            &rfc3339(now),
            false,
        )
        .unwrap();

    let path = dir.path().join("replay.jsonl");
    {
        let cache =
            Arc::new(chaperone_identity::ReplayCache::open(&path, now.unix_timestamp()).unwrap());
        let attestor = Attestor::new(
            store.clone(),
            cache,
            IdentityConfig {
                max_skew_secs: SKEW,
            },
        );
        attestor
            .verify(&signed_intent(&key, now, "across-restart"), now)
            .unwrap();
    }
    // "Restart": fresh cache over the same journal.
    {
        let cache =
            Arc::new(chaperone_identity::ReplayCache::open(&path, now.unix_timestamp()).unwrap());
        let attestor = Attestor::new(
            store.clone(),
            cache,
            IdentityConfig {
                max_skew_secs: SKEW,
            },
        );
        let err = attestor
            .verify(&signed_intent(&key, now, "across-restart"), now)
            .unwrap_err();
        assert!(
            matches!(err, IdentityError::Replay(_)),
            "replay must survive restart (D6)"
        );
    }

    // Expired entries do not survive: same nonce after retention passes.
    let later = now + secs(SKEW * 4);
    let cache =
        Arc::new(chaperone_identity::ReplayCache::open(&path, later.unix_timestamp()).unwrap());
    let _attestor = Attestor::new(
        store.clone(),
        Arc::clone(&cache),
        IdentityConfig {
            max_skew_secs: SKEW,
        },
    );
    // Freshness fails first (old issued_at), which is fine — drive the cache
    // directly to prove expiry purges state.
    assert_eq!(
        cache.check_and_reserve(AGENT, "across-restart", later.unix_timestamp(), SKEW * 3),
        chaperone_identity::replay::Reservation::Fresh
    );
}

#[test]
fn enrollment_rotation_requires_revocation_or_force() {
    let k1 = key_from_seed(12);
    let k2 = key_from_seed(13);
    let now = OffsetDateTime::now_utc();
    let (_attestor, store, _dir) = make_attestor(now);
    let pk1 = encode_signature(&k1.verifying_key().to_bytes());
    let pk2 = encode_signature(&k2.verifying_key().to_bytes());

    store.enroll(AGENT, &pk1, &rfc3339(now), false).unwrap();
    assert!(matches!(
        store.enroll(AGENT, &pk2, &rfc3339(now), false),
        Err(chaperone_identity::EnrollmentError::Duplicate(_))
    ));

    store.revoke(AGENT, &rfc3339(now)).unwrap();
    store.enroll(AGENT, &pk2, &rfc3339(now), false).unwrap(); // rotation ok now

    // Only the new key resolves.
    let vk = store.lookup(AGENT).unwrap();
    assert_eq!(vk.as_bytes(), k2.verifying_key().as_bytes());

    // Force-rotate over a live entry also works when explicitly asked.
    store.enroll(AGENT, &pk1, &rfc3339(now), true).unwrap();
    let vk = store.lookup(AGENT).unwrap();
    assert_eq!(vk.as_bytes(), k1.verifying_key().as_bytes());
}
