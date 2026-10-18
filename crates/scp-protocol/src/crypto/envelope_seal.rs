//! RFC 9180 HPKE envelope seal/open for arbitrary-length payloads.
//!
//! Used for invitation bundle encryption (spec §5.12.3.1), over the
//! DHKEM(P-256) suite of the shared [`crate::crypto::hpke`] core (RFC 9180
//! Base mode). The recipient key is the invitee `KeyPackage`'s `0xFF01`
//! `scp_wrapping_key` (§9.16.1), held in the invitee's `KeyCustody`.
//! The invitation-specific `info`/`aad` domain separators distinguish these
//! ciphertexts from sender-key, access-key, broadcast-key, and private-state
//! HPKE.

use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use crate::crypto::hpke::p256::{self, P256Point, ValidatedEnc};

/// Errors from envelope seal/open operations.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeSealError {
    /// HPKE encryption failed.
    #[error("HPKE encryption failed: {0}")]
    SealFailed(String),
    /// HPKE decryption failed.
    #[error("HPKE decryption failed: {0}")]
    OpenFailed(String),
}

/// Appends `data` to `buf` with a 4-byte big-endian length prefix.
///
/// Used by `build_invitation_info`, `build_invitation_aad`, and
/// `derive_routing_id` to enforce unambiguous field boundaries and prevent
/// boundary-shift attacks.
#[allow(clippy::cast_possible_truncation)]
fn append_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Derives a routing ID by hashing a DID with a domain separator.
/// Format: `SHA-256(len(did) || did || domain)` where `len` is a 4-byte
/// big-endian length prefix, preventing boundary-shift attacks where a DID
/// suffix could be confused with the domain prefix.
fn derive_routing_id(did: &str, domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let did_bytes = did.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let did_len = did_bytes.len() as u32;
    hasher.update(did_len.to_be_bytes());
    hasher.update(did_bytes);
    hasher.update(domain);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Derives a personal invitation routing ID for a DID.
/// `SHA-256(len(did) || did || b"scp-invitations")` per spec §5.12.3.
#[must_use]
pub fn derive_invitation_routing_id(did: &str) -> [u8; 32] {
    derive_routing_id(did, b"scp-invitations")
}

/// Derives a key package routing ID for a DID.
/// `SHA-256(len(did) || did || b"scp-key-packages")`.
#[must_use]
pub fn derive_key_package_routing_id(did: &str) -> [u8; 32] {
    derive_routing_id(did, b"scp-key-packages")
}

/// Builds the HPKE `info` string for invitation HPKE (§5.12.3.1).
/// Format: `"scp-invitation-v1" || len(context_id) || context_id || len(creator_did) || creator_did`
fn build_invitation_info(context_id: &str, creator_did: &str) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"scp-invitation-v1");
    append_length_prefixed(&mut info, context_id.as_bytes());
    append_length_prefixed(&mut info, creator_did.as_bytes());
    info
}

/// Builds the AEAD AAD for invitation HPKE (distinct from the HPKE `info`).
/// Format: `"scp-invitation-aad-v1" || len(context_id) || context_id || len(creator_did) || creator_did`
///
/// The ephemeral public key (`enc`) is NOT carried in the AAD: RFC 9180 binds
/// `enc` into the key schedule via `kem_context = enc || pkRm` (§4.1), so an
/// ephemeral-key substitution already produces a different derived key and
/// fails AEAD verification. Including `enc` in the AAD would be redundant (and
/// caused a build-AAD-before-enc-exists ordering wart). See spec §5.12.3.1.
fn build_invitation_aad(context_id: &str, creator_did: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"scp-invitation-aad-v1");
    append_length_prefixed(&mut aad, context_id.as_bytes());
    append_length_prefixed(&mut aad, creator_did.as_bytes());
    aad
}

/// HPKE-seals an arbitrary-length payload to a recipient's DHKEM(P-256)
/// public key (RFC 9180 Base mode, §5.12.3.1).
///
/// `recipient` is the invitee `KeyPackage`'s `0xFF01` `scp_wrapping_key`, taken
/// only after the `KeyPackage`'s §9.7.1 attestation verifies. Returns
/// `(sealed, enc)`: `sealed` is the HPKE ciphertext (`ciphertext || tag`) and
/// `enc` is the 65-byte uncompressed SEC1 encapsulated key. There is no
/// external nonce; RFC 9180 derives the AEAD nonce.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::SealFailed`] if HPKE sealing fails.
pub fn hpke_seal_invitation(
    plaintext: &[u8],
    recipient: &P256Point,
    context_id: &str,
    creator_did: &str,
) -> Result<(Vec<u8>, P256Point), EnvelopeSealError> {
    let info = build_invitation_info(context_id, creator_did);
    let aad = build_invitation_aad(context_id, creator_did);

    let (enc, ct) = p256::seal(recipient, &info, &aad, plaintext)
        .map_err(|e| EnvelopeSealError::SealFailed(e.to_string()))?;

    Ok((ct, enc))
}

/// HPKE-opens a sealed invitation whose KEM Diffie-Hellman output was computed
/// inside a `KeyCustody` boundary (spec §5.12.3.1, §9.16.2 Open step 2).
///
/// This is the only invitation open. The recipient key is the joiner's
/// DHKEM(P-256) wrapping key (§9.16.1), held in custody; the runtime holds no
/// wrapping private scalar. The one step that touches the private key,
/// `dh = DH(skR, enc)`, runs in custody as `KeyCustody::dh_agree`, and this
/// function completes the RFC 9180 Decap and AEAD open in software. The
/// `info` and `aad` come from the same builders as the seal side.
///
/// # Caller contract (load-bearing)
///
/// In this order, for one and the same custody wrapping handle `h`:
///
/// 1. `enc` = `p256::validate_enc(wire_enc)?`. §9.5 requires this before any
///    key agreement, and the [`ValidatedEnc`] parameter makes it the only way
///    to call this function.
/// 2. `dh` = `KeyCustody::dh_agree(h, enc.as_bytes())`.
/// 3. `recipient_pk` (`pkRm`) = the 65-byte public key of `h`.
///
/// A mismatched `dh`, `recipient_pk`, `enc`, `info` or `aad` fails closed as an
/// AEAD tag mismatch, indistinguishable from a wrong-key error. Binding
/// `enc || pkRm` into the shared secret closes the unknown-key-share gap.
///
/// `context_id` and `creator_did` are the binding hints that build `info` and
/// `aad`; a successful open proves the sealer used the same values. The caller
/// still cross-checks them against the decrypted, signature-verified bundle
/// before deriving any authority.
///
/// The plaintext is returned in [`Zeroizing`], so it is wiped when dropped.
///
/// # Errors
///
/// Returns [`EnvelopeSealError::OpenFailed`] if HPKE open fails (wrong
/// `dh`/`recipient_pk`/`enc`, wrong context or DID binding, or tampered
/// `sealed`).
pub fn hpke_open_invitation_with_external_dh(
    sealed: &[u8],
    dh: &[u8; 32],
    recipient_pk: &[u8; p256::PUBLIC_KEY_LEN],
    enc: &ValidatedEnc,
    context_id: &str,
    creator_did: &str,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeSealError> {
    let info = build_invitation_info(context_id, creator_did);
    let aad = build_invitation_aad(context_id, creator_did);

    p256::custody::open_with_external_dh(dh, recipient_pk, enc, &info, &aad, sealed)
        .map_err(|e| EnvelopeSealError::OpenFailed(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use rand::RngCore as _;
    use rand::rngs::OsRng;
    use scp_crypto::p256::{P256SecretKey, ecdh_p256};

    use super::*;

    /// A fresh P-256 recipient: its secret (standing in for the custody
    /// handle) and its 65-byte public key.
    fn fresh_recipient() -> (P256SecretKey, [u8; 65]) {
        loop {
            let mut candidate = [0u8; 32];
            OsRng.fill_bytes(&mut candidate);
            if let Ok(sk) = P256SecretKey::from_scalar_bytes(&candidate) {
                let pk = sk.public_key().to_uncompressed();
                return (sk, pk);
            }
        }
    }

    /// The joiner's open as custody runs it: validate the wire `enc`, agree on
    /// it with the recipient key, open with the recipient's public key.
    fn open_as_custody(
        sk: &P256SecretKey,
        pk: &[u8; 65],
        sealed: &[u8],
        wire_enc: &[u8],
        context_id: &str,
        creator_did: &str,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeSealError> {
        let enc = p256::validate_enc(wire_enc).unwrap();
        let dh = ecdh_p256(sk, enc.point());
        hpke_open_invitation_with_external_dh(sealed, &dh, pk, &enc, context_id, creator_did)
    }

    #[test]
    fn seal_open_roundtrip_through_external_dh() {
        let (sk, pk) = fresh_recipient();
        let plaintext = b"hello world, this is an invitation bundle";
        let (sealed, enc) = hpke_seal_invitation(
            plaintext,
            &P256Point::try_from(pk).unwrap(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();

        let recovered = open_as_custody(
            &sk,
            &pk,
            &sealed,
            enc.as_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn seal_emits_a_65_byte_uncompressed_enc() {
        let (_, pk) = fresh_recipient();
        let (sealed, enc) = hpke_seal_invitation(
            b"payload",
            &P256Point::try_from(pk).unwrap(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        assert_eq!(enc.as_bytes().len(), 65);
        assert_eq!(enc.as_bytes()[0], 0x04);
        assert_eq!(sealed.len(), b"payload".len() + 16);
    }

    #[test]
    fn open_with_the_wrong_context_fails() {
        let (sk, pk) = fresh_recipient();
        let (sealed, enc) = hpke_seal_invitation(
            b"payload",
            &P256Point::try_from(pk).unwrap(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        let result = open_as_custody(
            &sk,
            &pk,
            &sealed,
            enc.as_bytes(),
            "ctx-WRONG",
            "did:dht:z6MkAlice",
        );
        assert!(matches!(result, Err(EnvelopeSealError::OpenFailed(_))));
    }

    #[test]
    fn open_with_the_wrong_creator_fails() {
        let (sk, pk) = fresh_recipient();
        let (sealed, enc) = hpke_seal_invitation(
            b"payload",
            &P256Point::try_from(pk).unwrap(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        let result = open_as_custody(
            &sk,
            &pk,
            &sealed,
            enc.as_bytes(),
            "ctx-123",
            "did:dht:z6MkMallory",
        );
        assert!(matches!(result, Err(EnvelopeSealError::OpenFailed(_))));
    }

    #[test]
    fn open_with_another_recipients_key_fails() {
        let (_, pk) = fresh_recipient();
        let (wrong_scalar, wrong_point) = fresh_recipient();
        let (sealed, enc) = hpke_seal_invitation(
            b"payload",
            &P256Point::try_from(pk).unwrap(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        // The other key's dh with its own pkRm, and its dh with the real pkRm.
        for recipient_pk in [wrong_point, pk] {
            let result = open_as_custody(
                &wrong_scalar,
                &recipient_pk,
                &sealed,
                enc.as_bytes(),
                "ctx-123",
                "did:dht:z6MkAlice",
            );
            assert!(matches!(result, Err(EnvelopeSealError::OpenFailed(_))));
        }
    }

    #[test]
    fn open_with_the_right_dh_and_the_wrong_pkrm_fails() {
        let (sk, pk) = fresh_recipient();
        let (_, wrong_pk) = fresh_recipient();
        let (sealed, enc) = hpke_seal_invitation(
            b"payload",
            &P256Point::try_from(pk).unwrap(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        let result = open_as_custody(
            &sk,
            &wrong_pk,
            &sealed,
            enc.as_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        );
        assert!(matches!(result, Err(EnvelopeSealError::OpenFailed(_))));
    }

    #[test]
    fn open_of_a_tampered_ciphertext_fails() {
        let (sk, pk) = fresh_recipient();
        let (mut sealed, enc) = hpke_seal_invitation(
            b"payload",
            &P256Point::try_from(pk).unwrap(),
            "ctx-123",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        sealed[0] ^= 0x01;
        let result = open_as_custody(
            &sk,
            &pk,
            &sealed,
            enc.as_bytes(),
            "ctx-123",
            "did:dht:z6MkAlice",
        );
        assert!(matches!(result, Err(EnvelopeSealError::OpenFailed(_))));
    }

    /// §9.5: every malformed wire `enc` fails `validate_enc`, the open's only
    /// way in, so none reaches a key agreement.
    #[test]
    fn malformed_enc_forms_fail_validation() {
        let (_, pk) = fresh_recipient();
        // p, the P-256 field prime.
        let p: [u8; 32] =
            hex::decode("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
                .unwrap()
                .try_into()
                .unwrap();
        let mut x_is_p = pk;
        x_is_p[1..33].copy_from_slice(&p);
        let mut y_is_p = pk;
        y_is_p[33..65].copy_from_slice(&p);
        let mut off_curve = pk;
        off_curve[64] ^= 0x01;
        let mut zero_led = pk;
        zero_led[0] = 0x00;
        let mut compressed_02 = vec![0x02];
        compressed_02.extend_from_slice(&pk[1..33]);
        let mut compressed_03 = vec![0x03];
        compressed_03.extend_from_slice(&pk[1..33]);

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("32 bytes", pk[..32].to_vec()),
            ("64 bytes", pk[1..].to_vec()),
            ("66 bytes", [pk.as_slice(), &[0]].concat()),
            ("a single 0x00", vec![0x00]),
            ("65 bytes led by 0x00", zero_led.to_vec()),
            ("33-byte 0x02 compressed", compressed_02),
            ("33-byte 0x03 compressed", compressed_03),
            ("x = p", x_is_p.to_vec()),
            ("y = p", y_is_p.to_vec()),
            ("off the curve", off_curve.to_vec()),
        ];
        for (name, enc) in cases {
            assert!(p256::validate_enc(&enc).is_err(), "{name} must be rejected");
        }
        assert!(
            p256::validate_enc(&pk).is_ok(),
            "the control point must pass"
        );
    }

    #[test]
    fn routing_id_derivation() {
        let id1 = derive_invitation_routing_id("did:dht:z6MkAlice");
        let id2 = derive_invitation_routing_id("did:dht:z6MkAlice");
        let id3 = derive_invitation_routing_id("did:dht:z6MkBob");

        assert_eq!(id1, id2); // Deterministic
        assert_ne!(id1, id3); // Different for different DIDs
    }

    #[test]
    fn large_payload_round_trips() {
        let (sk, pk) = fresh_recipient();
        // 10 KB, larger than a typical Welcome.
        let plaintext = vec![0x42u8; 10_000];
        let (sealed, enc) = hpke_seal_invitation(
            &plaintext,
            &P256Point::try_from(pk).unwrap(),
            "ctx-large",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        let recovered = open_as_custody(
            &sk,
            &pk,
            &sealed,
            enc.as_bytes(),
            "ctx-large",
            "did:dht:z6MkAlice",
        )
        .unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }
}
