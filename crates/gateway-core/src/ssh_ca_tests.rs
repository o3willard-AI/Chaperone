#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use chaperone_vault::SecretString;

/// A random Ed25519 CA key built from the fork's own from_bytes constructors
/// (no rand_core version clash: our OsRng is 0.6, the fork's CryptoRng is 0.10).
fn test_ca() -> russh::keys::PrivateKey {
    // The private half is the seed; the public half MUST be derived from it,
    // not generated independently (a mismatched pair fails the signature
    // check inside the builder with a bare "Crypto" error — learned by probe).
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let kp = russh::keys::ssh_key::private::Ed25519Keypair {
        public: russh::keys::ssh_key::public::Ed25519PublicKey(signing.verifying_key().to_bytes()),
        private: russh::keys::ssh_key::private::Ed25519PrivateKey::from_bytes(&seed),
    };
    russh::keys::PrivateKey::from(kp)
}

fn ca_key() -> russh::keys::PrivateKey {
    test_ca()
}

fn other_ca_key() -> (russh::keys::PrivateKey, String) {
    // Distinct random CA for the falsifiability experiment.
    test_ca();
    let k = test_ca();
    (k, String::new())
}

/// A REAL Ed25519 public key: base64url of the RFC 8032 test-vector public
/// key. The enrollment store holds exactly this shape.
fn agent_pubkey_b64() -> String {
    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned()
}

fn req() -> MintRequest<'static> {
    MintRequest {
        agent_id: "agent:ci",
        msg_id: "m-1",
        username: "deploy",
        host: "app-01.internal",
        want_pty: false,
        ttl_secs: 300,
    }
}

fn parse(cert: &MintedCert) -> russh::keys::Certificate {
    russh::keys::Certificate::from_openssh(cert.cert_openssh.expose()).unwrap()
}

// ---- Test 1 + field pins ----

#[test]
fn mint_produces_a_parseable_cert_with_the_ruled_fields() {
    let cert = sign_crt(&ca_key(), &agent_pubkey_b64(), &req()).unwrap();
    let parsed = parse(&cert);
    assert_eq!(parsed.key_id(), "chaperone:agent:ci:m-1");
    assert_eq!(
        parsed.cert_type(),
        russh::keys::ssh_key::certificate::CertType::User
    );
    // TD-3: principal = the username, exactly one.
    let principals = parsed.valid_principals();
    assert_eq!(principals.len(), 1, "exactly one principal: {principals:?}");
    assert_eq!(principals[0], "deploy");
    // TD-3: the host binding lives in the extension.
    let host = parsed
        .extensions()
        .iter()
        .find(|(k, _)| k.as_str() == HOST_EXTENSION)
        .map(|(_, v)| v.clone());
    assert_eq!(host.as_deref(), Some("app-01.internal"));
}

// ---- TD-2: extensions ----

#[test]
fn forwarding_extensions_are_never_minted() {
    // want_pty=true is the MOST permissive allowed mint; even so, no
    // forwarding extension may appear.
    let mut r2 = req();
    r2.want_pty = true;
    let parsed = parse(&sign_crt(&ca_key(), &agent_pubkey_b64(), &r2).unwrap());
    for forbidden in [
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-X11-forwarding",
    ] {
        assert!(
            !parsed.extensions().iter().any(|(k, _)| k == forbidden),
            "{forbidden} must never be minted"
        );
    }
}

#[test]
fn pty_is_minted_only_when_requested() {
    let plain = parse(&sign_crt(&ca_key(), &agent_pubkey_b64(), &req()).unwrap());
    assert!(!plain.extensions().iter().any(|(k, _)| k == "permit-pty"));

    let mut r2 = req();
    r2.want_pty = true;
    let with_pty = parse(&sign_crt(&ca_key(), &agent_pubkey_b64(), &r2).unwrap());
    assert!(with_pty.extensions().iter().any(|(k, _)| k == "permit-pty"));
}

// ---- Test 3 + 4: TTL ceiling and validity window ----

#[test]
fn ttl_ceiling_cannot_be_configured_above_3600() {
    // Above the ceiling is an ERROR, not a clamp: an operator cannot drift
    // into a long-lived cert by misconfiguration.
    let mut r2 = req();
    r2.ttl_secs = 3601;
    assert_eq!(
        sign_crt(&ca_key(), &agent_pubkey_b64(), &r2).err(),
        Some(MintError::TtlAboveCeiling)
    );
    // Zero is refused too (a zero-second cert is meaningless).
    r2.ttl_secs = 0;
    assert_eq!(
        sign_crt(&ca_key(), &agent_pubkey_b64(), &r2).err(),
        Some(MintError::TtlAboveCeiling)
    );
    // Exactly at the ceiling is fine.
    r2.ttl_secs = 3600;
    assert!(sign_crt(&ca_key(), &agent_pubkey_b64(), &r2).is_ok());
}

#[test]
fn cert_validity_window_matches_the_requested_ttl() {
    // Deterministic: fixed anchor, no wall-clock, no sleeping.
    let anchor: u64 = 1_800_000_000;
    let cert = sign_crt_at(&ca_key(), &agent_pubkey_b64(), &req(), anchor).unwrap();
    let parsed = parse(&cert);
    // sign_crt_at applies a 60 s clock-skew grace to valid_after.
    assert_eq!(parsed.valid_after(), anchor - 60);
    assert_eq!(parsed.valid_before(), anchor + 300);
}

// ---- Falsifiability: the pins fail when the fix is reverted ----

#[test]
fn falsifiable_a_different_ca_produces_a_different_untrusted_cert() {
    // Acceptance test 1's revert experiment, run for real: signing is pure
    // over (ca_key, agent_pubkey, fields), so a different CA key MUST yield a
    // different cert. If this ever fails, the "signed by our CA" property is
    // not actually in the output.
    let (other_ca, _) = other_ca_key();
    let good = sign_crt(&ca_key(), &agent_pubkey_b64(), &req()).unwrap();
    let bad = sign_crt(&other_ca, &agent_pubkey_b64(), &req()).unwrap();
    assert_ne!(
        good.cert_openssh.expose(),
        bad.cert_openssh.expose(),
        "a different CA must produce a different (untrusted) cert"
    );
}

#[test]
fn falsifiable_the_host_binding_is_in_the_output_not_just_the_request() {
    // If the extension were dropped, two requests differing ONLY in host
    // would produce identical certs. The test would then be asserting on the
    // request rather than the minted artifact.
    let mut r2 = req();
    r2.host = "other.internal";
    let a = sign_crt(&ca_key(), &agent_pubkey_b64(), &req()).unwrap();
    let b = sign_crt(&ca_key(), &agent_pubkey_b64(), &r2).unwrap();
    assert_ne!(a.cert_openssh.expose(), b.cert_openssh.expose());
    assert_ne!(
        parse(&a)
            .extensions()
            .iter()
            .find(|(k, _)| k.as_str() == HOST_EXTENSION)
            .map(|(_, v)| v.clone()),
        parse(&b)
            .extensions()
            .iter()
            .find(|(k, _)| k.as_str() == HOST_EXTENSION)
            .map(|(_, v)| v.clone())
    );
}

// ---- Test 9 + refusals ----

#[test]
fn all_principals_valid_is_never_the_mint_path() {
    // The golden-ticket escape hatch produces an empty principal list. The
    // mint path calls valid_principal() exactly once; pin that a minted cert
    // never carries the empty list.
    let parsed = parse(&sign_crt(&ca_key(), &agent_pubkey_b64(), &req()).unwrap());
    assert!(!parsed.valid_principals().is_empty());
}

#[test]
fn agent_key_must_decode_to_exactly_32_bytes() {
    // The mint-time gate is decodability and length, not curve membership:
    // SSH Ed25519 public keys are raw 32-byte encodings, and possession is
    // proven by the signature at auth time. (The original "real curve point"
    // premise was wrong for SSH - dalek's from_bytes accepts any 32 bytes.)
    // A 31-byte value is refused, not minted.
    let short = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // decodes to 29 bytes
    assert_eq!(
        sign_crt(&ca_key(), short, &req()).err(),
        Some(MintError::BadAgentKey)
    );
    // Non-base64 is refused.
    assert_eq!(
        sign_crt(&ca_key(), "!!!not-base64!!!", &req()).err(),
        Some(MintError::BadAgentKey)
    );
}

#[test]
fn empty_fields_are_refused_loudly() {
    let cases = [
        (
            "agent_id",
            MintRequest {
                agent_id: "",
                ..req()
            },
        ),
        (
            "username",
            MintRequest {
                username: "",
                ..req()
            },
        ),
        ("host", MintRequest { host: "", ..req() }),
        (
            "msg_id",
            MintRequest {
                msg_id: "",
                ..req()
            },
        ),
    ];
    for (name, bad) in cases {
        assert_eq!(
            sign_crt(&ca_key(), &agent_pubkey_b64(), &bad).err(),
            Some(MintError::EmptyField),
            "empty {name} must be refused"
        );
    }
}

// ---- B-4 discipline carries into the mint path ----

#[test]
fn mint_errors_render_as_fixed_classified_text() {
    // The mint path's failures are classified, never free-form: no field of
    // MintRequest (or any secret) can appear in the rendered error.
    let cases = [
        MintError::TtlAboveCeiling,
        MintError::BadAgentKey,
        MintError::EmptyField,
        MintError::BadCaKey,
    ];
    for (i, e) in cases.iter().enumerate() {
        let a = e.to_string();
        for (j, other) in cases.iter().enumerate() {
            let b = other.to_string();
            assert!(i == j || a != b, "mint error classes {i}/{j} collide: {a}");
        }
        assert!(!a.contains("agent:ci") && !a.contains("deploy"));
    }
}

#[test]
fn cert_text_is_zeroizing_backed() {
    // The cert IS credential material: it must be held in a SecretString
    // (zeroize-on-drop), not a bare String. This is a type fact, checked by
    // construction here.
    let cert = sign_crt(&ca_key(), &agent_pubkey_b64(), &req()).unwrap();
    // SecretString::expose is the explicit read; the field type asserts the
    // zeroizing. Compile-fact: this line only compiles if cert_openssh is a
    // SecretString.
    let _: &SecretString = &cert.cert_openssh;
    assert!(cert.cert_openssh.expose().starts_with("ssh-"));
}
