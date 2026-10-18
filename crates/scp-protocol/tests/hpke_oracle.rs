//! Cross-validation of `scp_protocol::crypto::hpke::p256` against the
//! `hpke-rs` RFC 9180 reference implementation.
//!
//! These tests are the independent backstop for the hand-implemented HPKE
//! core: any transcription or composition error that the Appendix A.3 KATs
//! somehow miss would surface here as an interop failure against a separate
//! codebase. `hpke-rs` is a dev-dependency only — it never ships in
//! production or wasm32 builds — and this whole file is gated off wasm32.
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

/// The §5.12.3.1 invitation `info` or `aad`, rebuilt here from the spec's
/// layout (`label || u32_be(len(context_id)) || context_id ||
/// u32_be(len(creator_did)) || creator_did`) rather than from the crate's
/// private builders, so a builder that drifts from the spec fails these tests.
fn invitation_binding(label: &[u8], context_id: &str, creator_did: &str) -> Vec<u8> {
    let mut out = label.to_vec();
    for field in [context_id.as_bytes(), creator_did.as_bytes()] {
        out.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

const INVITE_CONTEXT_ID: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";
const INVITE_CREATOR_DID: &str = "did:dht:z6MkInvitationOracleCreator";

/// An invitation sealed by `hpke_seal_invitation` to a P-256 recipient opens
/// under the `hpke-rs` reference with the spec's invitation `info` and `aad`,
/// and its enc is the 65-byte uncompressed point the reference expects.
#[test]
fn invitation_info_p256_seal_opens_with_hpke_rs() -> TestResult {
    use scp_protocol::crypto::envelope_seal::hpke_seal_invitation;
    let info = invitation_binding(b"scp-invitation-v1", INVITE_CONTEXT_ID, INVITE_CREATOR_DID);
    let aad = invitation_binding(
        b"scp-invitation-aad-v1",
        INVITE_CONTEXT_ID,
        INVITE_CREATOR_DID,
    );
    for pt in [b"x".as_slice(), &[0x5A; 4096]] {
        let (sk, pk) = fresh_p256_recipient()?;
        let (ct, enc) = hpke_seal_invitation(
            pt,
            &hpke::p256::P256Point::try_from(pk)?,
            INVITE_CONTEXT_ID,
            INVITE_CREATOR_DID,
        )?;
        assert_eq!(enc.as_bytes().len(), hpke::p256::ENC_LEN);
        let recovered = ref_hpke_p256()
            .open(
                enc.as_bytes(),
                &HpkePrivateKey::new(sk.to_vec()),
                &info,
                &aad,
                &ct,
                None,
                None,
                None,
            )
            .map_err(|e| format!("reference open of an invitation: {e:?}"))?;
        assert_eq!(recovered.as_slice(), pt);
    }
    Ok(())
}

/// An invitation the `hpke-rs` reference seals with the spec's invitation
/// `info` and `aad` opens through `hpke_open_invitation_with_external_dh`
/// fed the ECDH a custody computes (`scp_crypto::p256::ecdh_p256` on the
/// recipient scalar and the enc), and the plaintext equals the reference's
/// own open of the same ciphertext.
#[test]
fn invitation_external_dh_open_equals_hpke_rs_open() -> TestResult {
    use scp_protocol::crypto::envelope_seal::hpke_open_invitation_with_external_dh;
    let info = invitation_binding(b"scp-invitation-v1", INVITE_CONTEXT_ID, INVITE_CREATOR_DID);
    let aad = invitation_binding(
        b"scp-invitation-aad-v1",
        INVITE_CONTEXT_ID,
        INVITE_CREATOR_DID,
    );
    for pt in [b"y".as_slice(), &[0xC3; 1500]] {
        let (sk, pk) = fresh_p256_recipient()?;
        let (ref_enc, ref_ct) = ref_hpke_p256()
            .seal(
                &HpkePublicKey::new(pk.to_vec()),
                &info,
                &aad,
                pt,
                None,
                None,
                None,
            )
            .map_err(|e| format!("reference seal of an invitation: {e:?}"))?;
        let reference = ref_hpke_p256()
            .open(
                &ref_enc,
                &HpkePrivateKey::new(sk.to_vec()),
                &info,
                &aad,
                &ref_ct,
                None,
                None,
                None,
            )
            .map_err(|e| format!("reference open of an invitation: {e:?}"))?;

        let enc = hpke::p256::validate_enc(&ref_enc)?;
        let dh = scp_crypto::p256::ecdh_p256(
            &scp_crypto::p256::P256SecretKey::from_scalar_bytes(&sk)?,
            &scp_crypto::p256::P256PublicKey::from_uncompressed(enc.as_bytes())?,
        );
        let ours = hpke_open_invitation_with_external_dh(
            &ref_ct,
            &dh,
            &hpke::p256::P256Point::try_from(&pk[..])?,
            &enc,
            INVITE_CONTEXT_ID,
            INVITE_CREATOR_DID,
        )?;
        assert_eq!(ours.as_slice(), reference.as_slice());
        assert_eq!(ours.as_slice(), pt);
    }
    Ok(())
}
