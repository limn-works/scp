//! Cross-target byte-parity known-answer tests for the §9.10.4 per-context
//! pseudonym DERIVATION (ADR-057 Option A, planning-session-10).
//!
//! The software-custody pseudonym derivation — `derive_pseudonym_secret`
//! (HKDF-SHA-256 over the 32-byte private key material) and
//! `derive_pseudonym` (HMAC-SHA-256 context seed, then the FIPS 186-5 A.2.1
//! seed-to-scalar step onto P-256, then the point) — lives in the wasm-safe
//! `scp-crypto::pseudonym` module so the in-browser client derives its own
//! per-context pseudonym in Rust over the wasm-held key WITHOUT forking the
//! native `scp-platform` copy. This file is the guard that the shared
//! derivation produces **byte-identical** output on both native and `wasm32`.
//!
//! Every assertion lives in a helper called from BOTH a native `#[test]` and a
//! `#[wasm_bindgen_test]`, against the SAME §25.19 golden vectors (Vectors
//! 30/31), copied from `.docs/specs/25-test-vectors.md`. Agreement is
//! transitive: `native == golden` AND `wasm == golden` implies `native == wasm`.

// KATs assert on fixed vectors; `expect`/`unwrap`/`panic` keep failures legible.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use scp_crypto::p256::{P256SecretKey, SeedLabel};
use scp_crypto::pseudonym::{
    PseudonymVersion, derive_pseudonym, derive_pseudonym_secret, pseudonym_routing_id,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

// ---------------------------------------------------------------------------
// Fixed inputs + golden outputs — §25.19 Vectors 30 & 31 (identical on every
// target and every run).
// ---------------------------------------------------------------------------

/// `context_id` used by both §25.19 derivation vectors.
const KAT_CONTEXT_ID: &[u8] = b"context-alpha";

/// One §25.19 derivation vector, as hex: identity seed → identity scalar →
/// `pseudonym_secret` → v1 pubkey and v2 pubkey at epoch 1 (33-byte
/// compressed points).
struct DerivationVector {
    seed: &'static str,
    scalar: &'static str,
    secret: &'static str,
    v1_pub: &'static str,
    v2_pub: &'static str,
    v1_routing: &'static str,
    v2_routing: &'static str,
}

/// §25.19 Vector 30 — identity seed `0x01 × 32`.
const VECTOR_30: DerivationVector = DerivationVector {
    seed: "0101010101010101010101010101010101010101010101010101010101010101",
    scalar: "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
    secret: "b88e781bb954a6681abc9016f8f69939f0e624311aeaa7e8f1b145857f58de82",
    v1_pub: "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
    v2_pub: "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
    v1_routing: "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
    v2_routing: "b19754a5e88c993683f99e48646ba518cba80dec0693f920c5671263650b6ae9",
};

/// §25.19 Vector 31 — identity seed `0x9d, 0x01..0x1f`.
const VECTOR_31: DerivationVector = DerivationVector {
    seed: "9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    scalar: "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
    secret: "17ef25ad3e5be8adad38c4c5a1c68d3daca80015e81bdcae2ae8940645774739",
    v1_pub: "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
    v2_pub: "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
    v1_routing: "cab5ff45d21b6d0425fa7657e89fc68514965cbb4ca2b9549f4ccf430d581e7c",
    v2_routing: "3c0ac4dec86c0dafe38195a7b66cdfec6b0ae0d44834c6e8b6b6129e097b5e27",
};

fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn seed32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

// ---------------------------------------------------------------------------
// The golden-vector assertion body (called from BOTH targets)
// ---------------------------------------------------------------------------

fn assert_pseudonym_derivation_cross_target_vectors() {
    for vector in [&VECTOR_30, &VECTOR_31] {
        // (1) identity seed → identity scalar (FIPS 186-5 A.2.1, §25.2 label).
        let identity = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &seed32(vector.seed));
        let ikm = identity.to_scalar_bytes();
        assert_eq!(
            to_hex(ikm.as_ref()),
            vector.scalar,
            "identity scalar diverged"
        );

        // (2) pseudonym_secret = HKDF-SHA256(ikm) matches the golden.
        let secret = derive_pseudonym_secret(&ikm);
        assert_eq!(
            to_hex(secret.as_ref()),
            vector.secret,
            "derive_pseudonym_secret diverged from the §25.19 golden vector \
             (cross-target HKDF divergence or a derivation change)"
        );

        // (3) v1 (static) pseudonym public key matches the golden.
        let v1 = derive_pseudonym(&ikm, KAT_CONTEXT_ID, PseudonymVersion::Static);
        assert_eq!(
            to_hex(&v1.to_compressed()),
            vector.v1_pub,
            "v1 pseudonym public key diverged from the §25.19 golden vector"
        );
        assert_eq!(
            to_hex(&pseudonym_routing_id(&v1)),
            vector.v1_routing,
            "v1 pseudonym_routing_id diverged from the §25.19 golden vector"
        );

        // (4) v2 (rotatable, epoch = 1) pseudonym public key matches the golden.
        let v2 = derive_pseudonym(
            &ikm,
            KAT_CONTEXT_ID,
            PseudonymVersion::Rotatable { epoch: 1 },
        );
        assert_eq!(
            to_hex(&v2.to_compressed()),
            vector.v2_pub,
            "v2 (epoch=1) pseudonym public key diverged from the §25.19 golden vector"
        );
        assert_eq!(
            to_hex(&pseudonym_routing_id(&v2)),
            vector.v2_routing,
            "v2 (epoch=1) pseudonym_routing_id diverged from the §25.19 golden vector"
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
// BOTH native and wasm32. The KAT above pins the raw `derive_pseudonym`
// recipe; this exercises the driver's actual reach into the openmls
// `SignatureKeyPair` (recovering the 32-byte Ed25519 seed, the interim ikm, through the type's serde
// form — the step whose wasm32 32-bit-`usize` behavior the byte-parity claim
// depends on). The MLS key is random, so this is not a fixed-byte golden; instead
// it pins determinism + context-separation + restore-stability of the serde path
// on each target (a `usize`/serde divergence would break one of these).
// Byte-truth is TRANSITIVE, not direct: C2 never compares native vs wasm bytes (the
// key is random), but both targets run the ONE shared `derive_pseudonym` over the
// golden-pinned raw recipe (the KAT above) — so each target reproducing that recipe
// faithfully through its own serde path implies the two targets agree byte-for-byte.
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
    assert_ne!(p1, [0u8; 32], "a real pseudonym routing id is non-zero");

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
