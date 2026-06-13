//! Cross-validation of `scp_protocol::crypto::hpke` against the `hpke-rs`
//! RFC 9180 reference implementation.
//!
//! These tests are the independent backstop for the hand-implemented HPKE
//! core: any transcription or composition error that the Appendix A.1 KATs
//! somehow miss would surface here as an interop failure against a separate
//! codebase. `hpke-rs` is a dev-dependency only — it never ships in
//! production or wasm32 builds — and this whole file is gated off wasm32.
#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used, clippy::panic)]

use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rand::rngs::OsRng;
use scp_protocol::crypto::hpke;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

/// Construct the SCP suite under the `hpke-rs` reference implementation:
/// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, Base mode.
fn ref_hpke() -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    )
}

fn fresh_keypair() -> (StaticSecret, [u8; 32]) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = X25519Pub::from(&sk).to_bytes();
    (sk, pk)
}

/// Our `seal` → reference `open`. Run across several input shapes.
///
/// NOTE: empty-plaintext is intentionally NOT exercised in this direction —
/// `hpke-rs`'s `open` rejects an empty recovered plaintext as `InvalidInput`
/// (its `bytes_to_option` maps an empty result to `None`; see hpke-rs lib.rs
/// §1101). That is a quirk of the reference receiver, not of our seal: the
/// empty case is covered by our in-crate roundtrip KAT and by the
/// reference→ours direction below.
#[test]
fn our_seal_opens_under_reference() {
    let cases: &[(&[u8], &[u8], &[u8])] = &[
        (b"", b"", b"x"),
        (
            b"scp-sender-key-v1",
            b"aad",
            b"32-byte-payload-padded-to-len!!!",
        ),
        (b"info", b"", &[0xAB; 100]),
        (b"\x00\x01\x02", b"\xff\xfe", b"x"),
    ];

    for (idx, (info, aad, pt)) in cases.iter().enumerate() {
        let (sk, pk) = fresh_keypair();
        let (enc, ct) = hpke::seal(&pk, info, aad, pt).unwrap();

        let reference = ref_hpke();
        let recovered = reference
            .open(
                &enc,
                &HpkePrivateKey::new(sk.to_bytes().to_vec()),
                info,
                aad,
                &ct,
                None,
                None,
                None,
            )
            .unwrap_or_else(|e| panic!("case {idx}: reference open failed: {e:?}"));
        assert_eq!(recovered.as_slice(), *pt, "case {idx}: plaintext mismatch");
    }
}

/// Reference `seal` → our `open`. Run across several input shapes.
#[test]
fn reference_seal_opens_under_ours() {
    let cases: &[(&[u8], &[u8], &[u8])] = &[
        (b"", b"", b""),
        (b"scp-access-key-v1", b"aad-bytes", b"the quick brown fox"),
        (b"info", b"", &[0x5A; 257]),
        (b"\x10\x20", b"\x30", b"yz"),
    ];

    for (idx, (info, aad, pt)) in cases.iter().enumerate() {
        let (sk, pk) = fresh_keypair();

        let mut reference = ref_hpke();
        let (enc, ct) = reference
            .seal(
                &HpkePublicKey::new(pk.to_vec()),
                info,
                aad,
                pt,
                None,
                None,
                None,
            )
            .unwrap_or_else(|e| panic!("case {idx}: reference seal failed: {e:?}"));

        let enc_arr: [u8; 32] = enc.as_slice().try_into().unwrap();
        let recovered = hpke::open(&sk.to_bytes(), &enc_arr, info, aad, &ct).unwrap();
        assert_eq!(recovered.as_slice(), *pt, "case {idx}: plaintext mismatch");
    }
}

/// Reference `seal` → our custody-path `open` (external DH). Confirms the
/// custody Decap variant interops with the reference too.
#[test]
fn reference_seal_opens_under_custody() {
    let (sk, pk) = fresh_keypair();
    let info = b"scp-broadcast-key-v1";
    let aad = b"ctx||author||epoch";
    let pt = b"broadcast key material 32 bytes!";

    let mut reference = ref_hpke();
    let (enc, ct) = reference
        .seal(
            &HpkePublicKey::new(pk.to_vec()),
            info,
            aad,
            pt,
            None,
            None,
            None,
        )
        .unwrap();
    let enc_arr: [u8; 32] = enc.as_slice().try_into().unwrap();

    // Simulate KeyCustody::dh_agree(handle, enc) = DH(skR, enc) and
    // KeyCustody::public_key(handle) = pkR.
    let enc_pub = X25519Pub::from(enc_arr);
    let dh = sk.diffie_hellman(&enc_pub);

    let recovered =
        hpke::custody::open_with_external_dh(dh.as_bytes(), &pk, &enc_arr, info, aad, &ct).unwrap();
    assert_eq!(recovered.as_slice(), pt);
}
