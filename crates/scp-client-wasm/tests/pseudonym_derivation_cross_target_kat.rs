//! Cross-target byte-parity known-answer tests for the §9.10.4.A per-context
//! pseudonym DERIVATION (ADR-057 Option A, planning-session-10).
//!
//! The software-custody pseudonym derivation — `derive_pseudonym_secret`
//! (HKDF-SHA-256 over the private seed) and `derive_pseudonym_keypair`
//! (HMAC-SHA-256 keying + Ed25519 keygen) — was factored into the wasm-safe
//! `scp-crypto::pseudonym` module so the in-browser client can derive its own
//! per-context pseudonym in Rust over the wasm-held signing key WITHOUT forking
//! the native `scp-platform` copy. This file is the guard that the shared
//! derivation produces **byte-identical** output on both native and `wasm32`,
//! so the future browser call site inherits one non-forked implementation.
//!
//! Every assertion lives in a helper called from BOTH a native `#[test]` and a
//! `#[wasm_bindgen_test]`, against the SAME committed §25.19 golden vectors
//! (Vectors 30/31). Agreement is transitive: `native == golden` AND
//! `wasm == golden` implies `native == wasm`. The `scp-crypto` module's own
//! `derive_pseudonym_keypair_known_answer_vectors` unit test pins these same
//! bytes natively; this test extends that guarantee across the wasm32 boundary.

// KATs assert on fixed vectors; `expect`/`unwrap`/`panic` keep failures legible.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use scp_crypto::pseudonym::{derive_pseudonym_keypair, derive_pseudonym_secret};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

// ---------------------------------------------------------------------------
// Fixed inputs + golden outputs — §25.19 Vectors 30 & 31 (identical on every
// target and every run).
// ---------------------------------------------------------------------------

/// `context_id` used by both §25.19 derivation vectors.
const KAT_CONTEXT_ID: &[u8] = b"context-alpha";

/// One §25.19 derivation vector: identity seed → (`pseudonym_secret`, v1 pubkey,
/// v2 pubkey at epoch 1).
struct DerivationVector {
    seed: [u8; 32],
    secret: [u8; 32],
    v1_pub: [u8; 32],
    v2_pub: [u8; 32],
}

/// §25.19 Vector 30 — identity seed `0x01 × 32`.
const VECTOR_30: DerivationVector = DerivationVector {
    seed: [0x01u8; 32],
    secret: [
        0x27, 0x45, 0x6a, 0x3d, 0xd2, 0x4e, 0xd5, 0x81, 0x3b, 0x26, 0x45, 0xf0, 0xee, 0x00, 0x1f,
        0x57, 0x76, 0x0c, 0x49, 0xb9, 0x11, 0x7b, 0x93, 0xc8, 0xfa, 0x98, 0xe4, 0x12, 0x9d, 0x36,
        0xa6, 0x43,
    ],
    v1_pub: [
        0xfd, 0xdc, 0x04, 0x88, 0x2a, 0x48, 0xaa, 0x39, 0x88, 0x8f, 0x6d, 0xbe, 0xc6, 0x22, 0xf9,
        0xc5, 0xaa, 0x6f, 0x06, 0xb2, 0xe4, 0x08, 0x20, 0xa6, 0x9a, 0x2e, 0x0e, 0x89, 0xb5, 0xf0,
        0x9a, 0xc2,
    ],
    v2_pub: [
        0x43, 0xe5, 0x0a, 0x94, 0x7c, 0x4b, 0x2b, 0xe4, 0x4f, 0x87, 0x1e, 0x30, 0x9c, 0x7e, 0xdc,
        0x64, 0xaf, 0xaf, 0x42, 0x07, 0xb9, 0xa5, 0x89, 0xc9, 0xb0, 0x1f, 0x61, 0xc0, 0x11, 0x58,
        0x09, 0x0f,
    ],
};

/// §25.19 Vector 31 — identity seed `0x9d, 0x01..0x1f`.
const VECTOR_31: DerivationVector = DerivationVector {
    seed: [
        0x9d, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ],
    secret: [
        0xa5, 0x86, 0x19, 0x1a, 0x1a, 0xb6, 0xcd, 0x3e, 0xfe, 0x45, 0x69, 0x7b, 0x35, 0x10, 0xee,
        0x1e, 0xda, 0xc8, 0xc5, 0x4a, 0x7f, 0x27, 0x86, 0x35, 0x46, 0xb6, 0xe0, 0x33, 0x3e, 0x20,
        0xd6, 0x90,
    ],
    v1_pub: [
        0xff, 0x6e, 0x2e, 0x90, 0x9a, 0x00, 0x83, 0x18, 0xf9, 0x7b, 0xb2, 0xc2, 0x6c, 0x1d, 0x78,
        0x7c, 0xeb, 0x9a, 0xa2, 0x99, 0x6f, 0x74, 0x67, 0x66, 0x33, 0x5e, 0x10, 0xba, 0x7e, 0x22,
        0x13, 0xcc,
    ],
    v2_pub: [
        0xed, 0xd4, 0x73, 0x19, 0x71, 0x9e, 0x23, 0x50, 0xd1, 0xdb, 0x94, 0x88, 0xe0, 0x18, 0x9f,
        0x24, 0x05, 0x26, 0x7d, 0x7d, 0xc2, 0x43, 0x48, 0x9c, 0xfd, 0x9a, 0xa6, 0xf3, 0xac, 0x3f,
        0xc6, 0x39,
    ],
};

// ---------------------------------------------------------------------------
// The golden-vector assertion body (called from BOTH targets)
// ---------------------------------------------------------------------------

fn assert_pseudonym_derivation_cross_target_vectors() {
    for vector in [&VECTOR_30, &VECTOR_31] {
        let sk = SigningKey::from_bytes(&vector.seed);

        // (1) pseudonym_secret = HKDF-SHA256(private_seed) matches the golden.
        let secret = derive_pseudonym_secret(&sk);
        assert_eq!(
            secret.as_slice(),
            &vector.secret,
            "derive_pseudonym_secret diverged from the §25.19 golden vector \
             (cross-target HKDF divergence or a derivation change)"
        );

        // (2) v1 (static) pseudonym public key matches the golden.
        let v1 = derive_pseudonym_keypair(&sk, KAT_CONTEXT_ID, None);
        assert_eq!(
            v1.verifying_key().to_bytes(),
            vector.v1_pub,
            "v1 pseudonym public key diverged from the §25.19 golden vector"
        );

        // (3) v2 (rotatable, epoch = 1) pseudonym public key matches the golden.
        let v2 = derive_pseudonym_keypair(&sk, KAT_CONTEXT_ID, Some(1));
        assert_eq!(
            v2.verifying_key().to_bytes(),
            vector.v2_pub,
            "v2 (epoch=1) pseudonym public key diverged from the §25.19 golden vector"
        );

        // (4) Domain separation: v1 and v2 must differ.
        assert_ne!(
            v1.verifying_key().to_bytes(),
            v2.verifying_key().to_bytes(),
            "v1 and v2 derivations must differ (domain separation)"
        );
    }
}

// ---------------------------------------------------------------------------
// Native + wasm entry point
// ---------------------------------------------------------------------------

/// Pseudonym-derivation cross-target byte-parity KAT. Runs natively (proving
/// determinism vs. the committed §25.19 vectors) and under
/// `wasm-pack test --node` (proving byte-equality across targets — ADR-057
/// Option A: the browser derives its pseudonym in Rust over the wasm-held key).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pseudonym_derivation_matches_golden_vectors() {
    assert_pseudonym_derivation_cross_target_vectors();
}

// ---------------------------------------------------------------------------
// C2 — the FULL `ScpMlsGroup::derive_pseudonym` serde-extraction path, driven on
// BOTH native and wasm32. The KAT above pins the raw `derive_pseudonym_keypair`
// recipe; this exercises the driver's actual reach into the openmls
// `SignatureKeyPair` (recovering the 32-byte Ed25519 seed through the type's serde
// form — the step whose wasm32 32-bit-`usize` behavior the byte-parity claim
// depends on). The MLS key is random, so this is not a fixed-byte golden; instead
// it pins determinism + context-separation + restore-stability of the serde path
// on each target (a `usize`/serde divergence would break one of these).
// ---------------------------------------------------------------------------

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn mls_group_derive_pseudonym_serde_path_is_stable_cross_target() {
    use scp_clock::TestClock;
    use scp_did::SigningKeyId;
    use scp_mls::ScpCredential;
    use scp_mls::group::create_group;

    let clock = TestClock::new(1_900_000_000);
    let cred = ScpCredential::new(
        "did:key:z6MkPseudonymDeriveSerdePathKAT".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .expect("credential");
    let group = create_group(&cred, &clock).expect("create group");
    let ctx = b"scp-mls-derive-serde-path-kat";

    // Determinism: the serde seed-extraction recovers the same seed each call.
    let p1 = group.derive_pseudonym(ctx).expect("derive p1");
    let p2 = group.derive_pseudonym(ctx).expect("derive p2");
    assert_eq!(
        p1, p2,
        "derive_pseudonym is deterministic (serde seed-extraction stable) on this target"
    );
    assert_ne!(p1, [0u8; 32], "a real pseudonym is non-zero");

    // Context separation.
    let other = group
        .derive_pseudonym(b"a-different-context")
        .expect("derive other");
    assert_ne!(other, p1, "distinct contexts derive distinct pseudonyms");

    // The serde-extraction path survives a state serialize/restore round-trip —
    // the reopened-tab property, exercised on THIS target.
    let blob = group.serialize_state().expect("serialize");
    let restored = scp_mls::ScpMlsGroup::deserialize_state(&blob).expect("restore");
    assert_eq!(
        restored
            .derive_pseudonym(ctx)
            .expect("derive after restore"),
        p1,
        "serde seed-extraction is stable across a state restore on this target"
    );
}
