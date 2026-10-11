//! Cross-validation of `scp_protocol::crypto::hpke::p256` against the
//! `hpke-rs` RFC 9180 reference implementation.
//!
//! These tests are the independent backstop for the hand-implemented HPKE
//! core: any transcription or composition error that the Appendix A.3 KATs
//! somehow miss would surface here as an interop failure against a separate
//! codebase. `hpke-rs` is a dev-dependency only — it never ships in
//! production or wasm32 builds — and this whole file is gated off wasm32.
//! The crate-private X25519 suite runs the same oracle in its own test
//! module (`hpke::legacy_x25519::hpke_rs_oracle`).
#![cfg(not(target_arch = "wasm32"))]

use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rand::rngs::OsRng;
use scp_protocol::crypto::hpke;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The §9.5 suite under the `hpke-rs` reference implementation, Base mode.
fn ref_hpke_p256() -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKemP256,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    )
}

/// A fresh recipient: a uniformly random scalar in [1, n − 1]. The
/// `DeriveKeyPair` comparison against the reference lives in the
/// `hpke::p256` test module, since `derive_key_pair` is crate-private.
fn fresh_p256_recipient() -> Result<([u8; 32], [u8; 65]), Box<dyn std::error::Error>> {
    loop {
        let mut candidate = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut candidate);
        // A candidate of zero or at least n is rejected; the chance is
        // below 2^-32, so the loop almost always ends on its first pass.
        if let Ok(sk) = scp_crypto::p256::P256SecretKey::from_scalar_bytes(&candidate) {
            return Ok((*sk.to_scalar_bytes(), sk.public_key().to_uncompressed()));
        }
    }
}

/// Our P-256 `seal` opens under the reference, and the reference's P-256
/// `seal` opens under our software and custody open paths. Empty plaintext is
/// only sealed by the reference: `hpke-rs`'s `open` rejects an empty recovered
/// plaintext as `InvalidInput`, a quirk of the reference receiver.
#[test]
fn p256_round_trips_against_reference() -> TestResult {
    let cases: &[(&[u8], &[u8], &[u8])] = &[
        (b"", b"", b"x"),
        (
            b"scp-sender-key-v1",
            b"aad",
            b"32-byte-payload-padded-to-len!!!",
        ),
        (b"info", b"", &[0xAB; 257]),
        (b"\x00\x01\x02", b"\xff\xfe", b"yz"),
    ];

    for (idx, (info, aad, pt)) in cases.iter().enumerate() {
        let (sk, pk) = fresh_p256_recipient()?;

        // Ours → reference.
        let (enc, ct) = hpke::p256::seal(&hpke::p256::P256Point::try_from(pk)?, info, aad, pt)?;
        let enc = *enc.as_bytes();
        assert_eq!(enc.len(), hpke::p256::ENC_LEN, "case {idx}: enc length");
        assert_eq!(enc[0], 0x04, "case {idx}: enc is uncompressed SEC1");
        let recovered = ref_hpke_p256()
            .open(
                &enc,
                &HpkePrivateKey::new(sk.to_vec()),
                info,
                aad,
                &ct,
                None,
                None,
                None,
            )
            .map_err(|e| format!("case {idx}: reference open: {e:?}"))?;
        assert_eq!(recovered.as_slice(), *pt, "case {idx}: ours → reference");

        // Reference → ours (software and custody paths), empty plaintext included.
        for ref_pt in [*pt, b"".as_slice()] {
            let (ref_enc, ref_ct) = ref_hpke_p256()
                .seal(
                    &HpkePublicKey::new(pk.to_vec()),
                    info,
                    aad,
                    ref_pt,
                    None,
                    None,
                    None,
                )
                .map_err(|e| format!("case {idx}: reference seal: {e:?}"))?;
            let got: zeroize::Zeroizing<Vec<u8>> =
                hpke::p256::open(&sk, &ref_enc, info, aad, &ref_ct)?;
            assert_eq!(got.as_slice(), ref_pt, "case {idx}: reference → ours");

            let sk_key = scp_crypto::p256::P256SecretKey::from_scalar_bytes(&sk)?;
            let enc = hpke::p256::validate_enc(&ref_enc)?;
            let dh = scp_crypto::p256::ecdh_p256(&sk_key, enc.point());
            let got: zeroize::Zeroizing<Vec<u8>> =
                hpke::p256::custody::open_with_external_dh(&dh, &pk, &enc, info, aad, &ref_ct)?;
            assert_eq!(got.as_slice(), ref_pt, "case {idx}: reference → custody");
        }
    }
    Ok(())
}
