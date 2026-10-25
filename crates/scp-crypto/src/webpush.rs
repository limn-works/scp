//! `WebPush` message encryption (RFC 8291) as one RFC 8188 `aes128gcm` record.
//!
//! The relay's `WebPush` sender (PUSH-022) encrypts every wake body with
//! [`seal`], which draws a fresh P-256 ephemeral key and a fresh 16-byte salt
//! for each call (`10-infrastructure-and-self-hosting.md` §10.7.1 **`WebPush`
//! body**). The P-256 arithmetic stays in this crate, because `deny.toml`
//! confines the curve crates to `scp-crypto`.
//!
//! The derivation follows RFC 8291 §3.4 and RFC 8188 §2, the steps
//! `25-test-vectors.md` §25.30 Vector 60 prints:
//!
//! ```text
//! ecdh    = ECDH(as_private, ua_public)
//! prk_key = HMAC-SHA256(auth, ecdh)
//! ikm     = HMAC-SHA256(prk_key, "WebPush: info" || 0x00 || ua_public || as_public || 0x01)
//! prk     = HMAC-SHA256(salt, ikm)
//! cek     = HMAC-SHA256(prk, "Content-Encoding: aes128gcm" || 0x00 || 0x01)[..16]
//! nonce   = HMAC-SHA256(prk, "Content-Encoding: nonce" || 0x00 || 0x01)[..12]
//! body    = salt || BE32(4096) || 0x41 || as_public || AES-128-GCM(cek, nonce, plaintext || 0x02)
//! ```
//!
//! Each step is one HMAC block, because every HKDF-Expand here asks for at
//! most 32 bytes. Every secret intermediate this module owns sits in a
//! `Zeroizing` buffer. The HMAC and AES states inside `hmac`, `sha2` and
//! `aes` are wiped only where those crates wipe them, so wiping is best
//! effort, as for the other derivations in this crate.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::p256::{P256PublicKey, P256SecretKey, UNCOMPRESSED_POINT_LEN, ecdh_p256};

/// The record size every `WebPush` wake declares in its header, 4,096 bytes
/// (`09-security-model.md` §9.18.13).
pub const RECORD_SIZE: usize = 4096;

/// [`RECORD_SIZE`] as the header's 4-byte big-endian `rs` field.
const RECORD_SIZE_FIELD: [u8; 4] = 4096u32.to_be_bytes();

/// The header's `idlen` byte: the 65-byte uncompressed key id.
const KEY_ID_LEN_FIELD: u8 = 65;

/// The salt length RFC 8188 §2.1 fixes.
pub const SALT_LEN: usize = 16;

/// The length of a subscription's `auth` secret (RFC 8291 §3.2).
pub const AUTH_SECRET_LEN: usize = 16;

/// The AES-128-GCM tag length.
pub const TAG_LEN: usize = 16;

/// The header length: `salt (16) || rs (4) || idlen (1) || keyid (65)`.
pub const HEADER_LEN: usize = SALT_LEN + 4 + 1 + UNCOMPRESSED_POINT_LEN;

/// The padding delimiter of the last (and only) record (RFC 8188 §2).
const LAST_RECORD_DELIMITER: u8 = 0x02;

const WEBPUSH_INFO: &[u8] = b"WebPush: info\0";
const CEK_INFO: &[u8] = b"Content-Encoding: aes128gcm\0";
const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\0";

/// The largest plaintext one body holds, 3,993 bytes.
///
/// RFC 8291 §4 limits the whole body, header included, to the 4,096-byte
/// record size, and the body carries the header, the plaintext, the
/// delimiter and the tag.
pub const MAX_PLAINTEXT_LEN: usize = RECORD_SIZE - HEADER_LEN - 1 - TAG_LEN;

/// A `WebPush` encryption failure. Each variant names one rejected input or one
/// failed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WebPushError {
    /// The header, the plaintext, the delimiter and the tag exceed one
    /// 4,096-byte record (RFC 8291 §4).
    #[error("plaintext of {len} bytes exceeds one record (at most {MAX_PLAINTEXT_LEN} bytes)")]
    RecordTooLarge {
        /// The rejected plaintext length.
        len: usize,
    },
    /// AES-128-GCM refused the record.
    #[error("AES-128-GCM refused the record")]
    Aead,
    /// A body handed to the test opener is shorter than a header, declares
    /// another record size, or carries a key id that is not a P-256 point.
    #[error("aes128gcm body is malformed: {0}")]
    Malformed(&'static str),
}

/// The content-encryption key and nonce of one record.
struct RecordKeys {
    cek: Zeroizing<[u8; 16]>,
    nonce: [u8; 12],
}

/// Encrypts `plaintext` to a subscription's `p256dh` key `ua_public` and its
/// `auth` secret, as one `aes128gcm` record with `rs` 4,096.
///
/// Draws a fresh ephemeral P-256 key pair and a fresh 16-byte salt from the
/// operating system's RNG on every call, so no two bodies share either
/// (RFC 8291 §3.4, RFC 8188 §2.1). No caller supplies the randomness, so no
/// caller can pass a weak or repeating source.
///
/// # Errors
///
/// - [`WebPushError::RecordTooLarge`] when `plaintext` exceeds
///   [`MAX_PLAINTEXT_LEN`].
/// - [`WebPushError::Aead`] when AES-128-GCM refuses the record.
pub fn seal(
    ua_public: &P256PublicKey,
    auth: &[u8; AUTH_SECRET_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, WebPushError> {
    check_len(plaintext)?;
    let mut rng = rand_core::OsRng;
    let ephemeral = P256SecretKey::random(&mut rng);
    let mut salt = [0u8; SALT_LEN];
    rand_core::RngCore::fill_bytes(&mut rng, &mut salt);
    seal_with(&ephemeral, &salt, ua_public, auth, plaintext)
}

const fn check_len(plaintext: &[u8]) -> Result<(), WebPushError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(WebPushError::RecordTooLarge {
            len: plaintext.len(),
        });
    }
    Ok(())
}

/// [`seal`] with the ephemeral key and salt fixed, so the RFC 8291 Appendix A
/// example and Vector 60 reproduce.
fn seal_with(
    ephemeral: &P256SecretKey,
    salt: &[u8; SALT_LEN],
    ua_public: &P256PublicKey,
    auth: &[u8; AUTH_SECRET_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, WebPushError> {
    check_len(plaintext)?;
    let as_public = ephemeral.public_key().to_uncompressed();
    let keys = derive(ephemeral, ua_public, &as_public, auth, salt);

    let mut body = Vec::with_capacity(HEADER_LEN + plaintext.len() + 1 + TAG_LEN);
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE_FIELD);
    body.push(KEY_ID_LEN_FIELD);
    body.extend_from_slice(&as_public);

    let mut record = Zeroizing::new(Vec::with_capacity(plaintext.len() + 1 + TAG_LEN));
    record.extend_from_slice(plaintext);
    record.push(LAST_RECORD_DELIMITER);
    let cipher = Aes128Gcm::new(keys.cek.as_ref().into());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&keys.nonce), b"", record.as_mut())
        .map_err(|_| WebPushError::Aead)?;
    body.extend_from_slice(&record);
    body.extend_from_slice(&tag);
    Ok(body)
}

/// The RFC 8291 §3.4 key schedule for one record. `local` is the private half
/// of the side that derives: the sender's ephemeral key when sealing, the
/// subscription's key when opening. `ua_public` and `as_public` are always
/// the subscription's and the sender's public keys, in that order.
fn derive_keys(
    local: &P256SecretKey,
    peer: &P256PublicKey,
    ua_public: &[u8; UNCOMPRESSED_POINT_LEN],
    as_public: &[u8; UNCOMPRESSED_POINT_LEN],
    auth: &[u8; AUTH_SECRET_LEN],
    salt: &[u8; SALT_LEN],
) -> RecordKeys {
    let ecdh = ecdh_p256(local, peer);
    let prk_key = prk_key(auth, &ecdh);
    let ikm = ikm(&prk_key, ua_public, as_public);
    let prk = prk(salt, &ikm);
    RecordKeys {
        cek: cek(&prk),
        nonce: nonce(&prk),
    }
}

/// RFC 8291 §3.4 `PRK_key = HKDF-Extract(auth, ecdh_secret)`.
fn prk_key(auth: &[u8; AUTH_SECRET_LEN], ecdh: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hmac_sha256(auth, &[ecdh])
}

/// RFC 8291 §3.4 `IKM = HKDF-Expand(PRK_key, "WebPush: info" || 0x00 ||
/// ua_public || as_public, 32)`: one HMAC block, ending in the counter `0x01`.
fn ikm(
    prk_key: &[u8; 32],
    ua_public: &[u8; UNCOMPRESSED_POINT_LEN],
    as_public: &[u8; UNCOMPRESSED_POINT_LEN],
) -> Zeroizing<[u8; 32]> {
    hmac_sha256(prk_key, &[WEBPUSH_INFO, ua_public, as_public, &[0x01]])
}

/// RFC 8188 §2.2 `PRK = HKDF-Extract(salt, IKM)`.
fn prk(salt: &[u8; SALT_LEN], ikm: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hmac_sha256(salt, &[ikm])
}

/// RFC 8188 §2.2 `CEK = HKDF-Expand(PRK, "Content-Encoding: aes128gcm" ||
/// 0x00, 16)`.
fn cek(prk: &[u8; 32]) -> Zeroizing<[u8; 16]> {
    let block = hmac_sha256(prk, &[CEK_INFO, &[0x01]]);
    let mut cek = Zeroizing::new([0u8; 16]);
    cek.copy_from_slice(&block[..16]);
    cek
}

/// RFC 8188 §2.3 `NONCE = HKDF-Expand(PRK, "Content-Encoding: nonce" || 0x00,
/// 12)`; with one record the sequence number is zero, so the XOR is a no-op.
fn nonce(prk: &[u8; 32]) -> [u8; 12] {
    let block = hmac_sha256(prk, &[NONCE_INFO, &[0x01]]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&block[..12]);
    nonce
}

fn derive(
    ephemeral: &P256SecretKey,
    ua_public: &P256PublicKey,
    as_public: &[u8; UNCOMPRESSED_POINT_LEN],
    auth: &[u8; AUTH_SECRET_LEN],
    salt: &[u8; SALT_LEN],
) -> RecordKeys {
    derive_keys(
        ephemeral,
        ua_public,
        &ua_public.to_uncompressed(),
        as_public,
        auth,
        salt,
    )
}

/// `HMAC-SHA256(key, parts[0] || parts[1] || …)` into a wiping buffer.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
        unreachable!("HMAC-SHA256 accepts keys of any length")
    };
    for part in parts {
        mac.update(part);
    }
    let mut bytes: [u8; 32] = mac.finalize().into_bytes().into();
    let out = Zeroizing::new(bytes);
    bytes.zeroize();
    out
}

/// Decrypts one `aes128gcm` `WebPush` body as the subscription would: the
/// inverse of [`seal`], for tests that check what a relay sent.
///
/// Compiled only under `cfg(test)` or the `testing` feature, which only
/// dev-dependencies enable, so no shipped build carries it.
///
/// # Errors
///
/// [`WebPushError::Malformed`] for a body that is not one record with `rs`
/// 4,096 and a 65-byte key id, and [`WebPushError::Aead`] when the tag fails
/// or the delimiter is not `0x02`.
#[cfg(any(test, feature = "testing"))]
pub fn open(
    ua_private: &P256SecretKey,
    auth: &[u8; AUTH_SECRET_LEN],
    body: &[u8],
) -> Result<Vec<u8>, WebPushError> {
    use aes_gcm::Tag;

    if body.len() < HEADER_LEN + 1 + TAG_LEN {
        return Err(WebPushError::Malformed("shorter than a header and a tag"));
    }
    let (header, payload) = body.split_at(HEADER_LEN);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&header[..SALT_LEN]);
    if header[SALT_LEN..SALT_LEN + 4] != RECORD_SIZE_FIELD {
        return Err(WebPushError::Malformed("record size is not 4096"));
    }
    if header[SALT_LEN + 4] != KEY_ID_LEN_FIELD {
        return Err(WebPushError::Malformed("key id is not 65 bytes"));
    }
    let mut as_public = [0u8; UNCOMPRESSED_POINT_LEN];
    as_public.copy_from_slice(&header[SALT_LEN + 5..]);
    let sender = P256PublicKey::from_uncompressed(&as_public)
        .map_err(|_| WebPushError::Malformed("key id is not a P-256 point"))?;
    let ua_public = ua_private.public_key().to_uncompressed();
    let keys = derive_keys(ua_private, &sender, &ua_public, &as_public, auth, &salt);

    let (ciphertext, tag) = payload.split_at(payload.len() - TAG_LEN);
    let mut record = ciphertext.to_vec();
    Aes128Gcm::new(keys.cek.as_ref().into())
        .decrypt_in_place_detached(
            Nonce::from_slice(&keys.nonce),
            b"",
            &mut record,
            Tag::from_slice(tag),
        )
        .map_err(|_| WebPushError::Aead)?;
    match record.pop() {
        Some(LAST_RECORD_DELIMITER) => Ok(record),
        _ => Err(WebPushError::Aead),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use proptest::prelude::*;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s)
    }

    fn arr<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Box<dyn std::error::Error>> {
        Ok(<[u8; N]>::try_from(bytes)?)
    }

    fn secret(bytes: &[u8]) -> Result<P256SecretKey, Box<dyn std::error::Error>> {
        Ok(P256SecretKey::from_scalar_bytes(&arr::<32>(bytes)?)?)
    }

    /// RFC 8291 Appendix A, in the RFC's base64url.
    struct AppendixA {
        plaintext: &'static [u8],
        as_private: P256SecretKey,
        ua_private: P256SecretKey,
        ua_public: P256PublicKey,
        salt: [u8; SALT_LEN],
        auth: [u8; AUTH_SECRET_LEN],
    }

    fn appendix_a() -> Result<AppendixA, Box<dyn std::error::Error>> {
        Ok(AppendixA {
            plaintext: b"When I grow up, I want to be a watermelon",
            as_private: secret(&b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")?)?,
            ua_private: secret(&b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")?)?,
            ua_public: P256PublicKey::from_uncompressed(&b64(
                "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
            )?)?,
            salt: arr(&b64("DGv6ra1nlYgDCS1FRnbzlw")?)?,
            auth: arr(&b64("BTBZMqHH6r4Tts7J_aSIgg")?)?,
        })
    }

    #[test]
    fn seal_with_reproduces_rfc8291_appendix_a() -> TestResult {
        let a = appendix_a()?;
        let body = seal_with(&a.as_private, &a.salt, &a.ua_public, &a.auth, a.plaintext)?;
        let expected = b64(
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
        )?;
        assert_eq!(body, expected);
        assert_eq!(
            body[HEADER_LEN..],
            b64("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ")?
                [..]
        );
        assert_eq!(open(&a.ua_private, &a.auth, &body)?, a.plaintext);
        Ok(())
    }

    /// `25-test-vectors.md` §25.30 Vector 60: the wake body and every
    /// intermediate, with Appendix A's ephemeral key and salt.
    #[test]
    fn seal_with_reproduces_vector_60_intermediates_and_body() -> TestResult {
        let a = appendix_a()?;
        let as_public = a.as_private.public_key().to_uncompressed();
        assert_eq!(
            hex::encode(as_public),
            "04fe33f4ab0dea71914db55823f73b54948f41306d920732dbb9a59a53286482\
             200e597a7b7bc260ba1c227998580992e93973002f3012a28ae8f06bbb78e5ec0f"
        );
        // Each step of the production chain, fed the previous step's output.
        let ecdh = ecdh_p256(&a.as_private, &a.ua_public);
        let prk_key = prk_key(&a.auth, &ecdh);
        let ikm = ikm(&prk_key, &a.ua_public.to_uncompressed(), &as_public);
        let prk = prk(&a.salt, &ikm);
        let cek = cek(&prk);
        let nonce = nonce(&prk);
        let cases: [(&str, &[u8], &str); 6] = [
            (
                "ecdh",
                ecdh.as_ref(),
                "932acbd63208387133837b0cd995911c3441eb66000998614a592727aef6912b",
            ),
            (
                "prk_key",
                prk_key.as_ref(),
                "4a7af724cc5a1d50d71d6267e70742e765a3a42b5dd84204181ca40dc656df69",
            ),
            (
                "ikm",
                ikm.as_ref(),
                "4b895831bfcbd05c427aad16843c7cd772a0498a94dba90ecb359476c5d8cab8",
            ),
            (
                "prk",
                prk.as_ref(),
                "d3dfde5191abb2fc428430864427642e20d7ad178638455e48274270f0522527",
            ),
            ("cek", cek.as_ref(), "a088555b4e0c45dcb65cdf4288a2f14e"),
            ("nonce", &nonce, "e21ffde6495727913faa7a0d"),
        ];
        for (name, got, want) in cases {
            assert_eq!(hex::encode(got), want, "{name}");
        }
        let keys = derive(&a.as_private, &a.ua_public, &as_public, &a.auth, &a.salt);
        assert_eq!(*keys.cek, *cek);
        assert_eq!(keys.nonce, nonce);

        let body = seal_with(
            &a.as_private,
            &a.salt,
            &a.ua_public,
            &a.auth,
            br#"{"scp":"1"}"#,
        )?;
        assert_eq!(body.len(), 114);
        assert_eq!(
            hex::encode(&body[..HEADER_LEN]),
            "0c6bfaadad67958803092d454676f397000010004104fe33f4ab0dea71914db5\
             5823f73b54948f41306d920732dbb9a59a53286482200e597a7b7bc260ba1c22\
             7998580992e93973002f3012a28ae8f06bbb78e5ec0f"
        );
        assert_eq!(
            hex::encode(&body[HEADER_LEN..]),
            "deddc85612f0a034109eae8c1bde9c4f0cc78cfeb46af48de50400fd"
        );
        assert_eq!(open(&a.ua_private, &a.auth, &body)?, br#"{"scp":"1"}"#);
        Ok(())
    }

    #[test]
    fn header_fields_match_their_lengths() {
        assert_eq!(u32::from_be_bytes(RECORD_SIZE_FIELD), 4096);
        assert_eq!(usize::from(KEY_ID_LEN_FIELD), UNCOMPRESSED_POINT_LEN);
        assert_eq!(HEADER_LEN, 86);
    }

    #[test]
    fn seal_draws_a_fresh_ephemeral_key_and_salt_per_call() -> TestResult {
        let a = appendix_a()?;
        let one = seal(&a.ua_public, &a.auth, b"x")?;
        let two = seal(&a.ua_public, &a.auth, b"x")?;
        assert_ne!(one[..SALT_LEN], two[..SALT_LEN], "salt");
        assert_ne!(
            one[SALT_LEN + 5..HEADER_LEN],
            two[SALT_LEN + 5..HEADER_LEN],
            "key id"
        );
        assert_eq!(open(&a.ua_private, &a.auth, &one)?, b"x");
        assert_eq!(open(&a.ua_private, &a.auth, &two)?, b"x");
        Ok(())
    }

    #[test]
    fn seal_accepts_3993_bytes_and_rejects_3994() -> TestResult {
        let a = appendix_a()?;
        let ephemeral = P256SecretKey::random(&mut rand::rngs::OsRng);
        let salt = [7u8; SALT_LEN];
        let largest = vec![0x61; 3993];
        let body = seal_with(&ephemeral, &salt, &a.ua_public, &a.auth, &largest)?;
        assert_eq!(body.len(), RECORD_SIZE, "the whole body fills one record");
        assert_eq!(open(&a.ua_private, &a.auth, &body)?, largest);
        let over = vec![0x61; 3994];
        assert_eq!(
            seal_with(&ephemeral, &salt, &a.ua_public, &a.auth, &over),
            Err(WebPushError::RecordTooLarge { len: 3994 })
        );
        assert_eq!(
            seal(&a.ua_public, &a.auth, &over),
            Err(WebPushError::RecordTooLarge { len: 3994 })
        );
        Ok(())
    }

    #[test]
    fn open_rejects_a_tampered_body_and_a_wrong_auth() -> TestResult {
        let a = appendix_a()?;
        let body = seal_with(&a.as_private, &a.salt, &a.ua_public, &a.auth, b"wake")?;
        let mut tampered = body.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert_eq!(
            open(&a.ua_private, &a.auth, &tampered),
            Err(WebPushError::Aead)
        );
        assert_eq!(
            open(&a.ua_private, &[0; 16], &body),
            Err(WebPushError::Aead)
        );
        assert!(matches!(
            open(&a.ua_private, &a.auth, &body[..HEADER_LEN]),
            Err(WebPushError::Malformed(_))
        ));
        Ok(())
    }

    proptest! {
        #[test]
        fn seal_then_open_round_trips(
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            auth in any::<[u8; 16]>(),
            seed in any::<[u8; 32]>(),
        ) {
            let ua_private = P256SecretKey::from_seed(crate::p256::SeedLabel::TestVectorKey, &seed);
            let body = seal(&ua_private.public_key(), &auth, &plaintext)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(body.len(), HEADER_LEN + plaintext.len() + 1 + TAG_LEN);
            let opened = open(&ua_private, &auth, &body)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(opened, plaintext);
        }
    }
}
