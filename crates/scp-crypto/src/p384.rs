//! P-384 verification for SCP (`09-security-model.md` §9.3.1).
//!
//! This module is the single home of SCP's P-384 arithmetic. SCP signs nothing
//! with P-384; the one use is reading Apple's App Attest certificate chain,
//! whose two issuers, the App Attestation Root CA and its intermediate, hold
//! P-384 keys (§9.3.1 App Attest check 3). It is pure: no custody, no I/O, no
//! async. Every function returns its result or a typed [`P384Error`].
//!
//! - [`P384PublicKey::from_sec1`] is the only parser of a P-384 point. It
//!   accepts a 49-byte compressed or 97-byte uncompressed SEC1 point on the
//!   curve, and rejects the point at infinity.
//! - [`verify_prehash_der_lenient`] verifies a strict-DER `ECDSA-Sig-Value`
//!   over a 32-byte (SHA-256) or 48-byte (SHA-384) digest and accepts either
//!   value of `s`: Apple's certificate signatures follow no low-`s` rule, and
//!   §9.3.1 check 3 accepts both.
//!
//! Test support, compiled only under `cfg(test)` or the `testing` feature that
//! only dev-dependencies enable: [`P384SecretKey::from_seed`] and
//! [`sign_prehash_der`], which a test certificate authority uses to issue a
//! chain shaped like Apple's.

use ::p384::PublicKey;
use ::p384::ecdsa::signature::hazmat::PrehashVerifier;
use ::p384::ecdsa::{Signature, VerifyingKey};
use ::p384::elliptic_curve::sec1::ToSec1Point;

/// Length of a SEC1 compressed P-384 point.
pub const COMPRESSED_POINT_LEN: usize = 49;

/// Length of a SEC1 uncompressed P-384 point, the form X.509 certificates
/// carry in `subjectPublicKey`.
pub const UNCOMPRESSED_POINT_LEN: usize = 97;

/// Length of one P-384 scalar, `r` or `s`, as a big-endian field element.
pub const SCALAR_LEN: usize = 48;

/// Errors from the P-384 primitives. Each variant names one rejected input or
/// one failed check, so a caller can map it without parsing text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum P384Error {
    /// A SEC1 point encoding was neither 49 nor 97 bytes long.
    #[error("P-384 point encoding must be 49 or 97 bytes, got {0}")]
    InvalidPointLength(usize),
    /// A SEC1 point encoding carried a leading byte its length does not allow
    /// (49 bytes need `0x02`/`0x03`, 97 bytes need `0x04`).
    #[error("P-384 point encoding of {len} bytes has invalid leading byte {prefix:#04x}")]
    InvalidPointPrefix {
        /// Length of the rejected encoding.
        len: usize,
        /// The rejected leading byte.
        prefix: u8,
    },
    /// The decoded point is not on the P-384 curve, or is the point at
    /// infinity.
    #[error("P-384 point is not on the curve or is the point at infinity")]
    PointNotOnCurve,
    /// The digest was neither 32 bytes (SHA-256) nor 48 bytes (SHA-384).
    #[error("P-384 prehash must be 32 or 48 bytes, got {0}")]
    InvalidDigestLength(usize),
    /// A DER `ECDSA-Sig-Value` was not strict DER.
    #[error("ECDSA DER signature is malformed: {0}")]
    MalformedDer(&'static str),
    /// A signature's `r` or `s` was zero or not below the group order.
    #[error("P-384 signature r or s is zero or not below the group order")]
    SignatureScalarOutOfRange,
    /// The signature does not verify under the key and digest.
    #[error("P-384 signature does not verify")]
    VerificationFailed,
    /// A test seed did not reduce to a valid private scalar.
    #[error("P-384 private scalar is zero or not below the group order")]
    InvalidScalar,
    /// ECDSA signing failed (the RFC 6979 nonce yielded `r = 0` or `s = 0`).
    #[error("P-384 signing failed")]
    SigningFailed,
}

/// A validated P-384 public key: on the curve and not the point at infinity.
///
/// [`P384PublicKey::from_sec1`] is the only constructor outside test support,
/// so every key reaching [`verify_prehash_der_lenient`] has passed point
/// validation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P384PublicKey(PublicKey);

impl core::fmt::Debug for P384PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("P384PublicKey(")?;
        self.to_uncompressed()
            .iter()
            .try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

impl P384PublicKey {
    /// Parses and validates a SEC1 point.
    ///
    /// Accepts exactly a 49-byte compressed point led by `0x02` or `0x03`, or a
    /// 97-byte uncompressed point led by `0x04`.
    ///
    /// # Errors
    ///
    /// - [`P384Error::InvalidPointLength`] for any other length (including the
    ///   1-byte SEC1 encoding of the point at infinity).
    /// - [`P384Error::InvalidPointPrefix`] for a wrong leading byte.
    /// - [`P384Error::PointNotOnCurve`] when the coordinates fail the curve
    ///   equation or no `y` exists for a compressed `x`.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, P384Error> {
        match (bytes.len(), bytes.first().copied()) {
            (COMPRESSED_POINT_LEN, Some(0x02 | 0x03)) | (UNCOMPRESSED_POINT_LEN, Some(0x04)) => {}
            (len @ (COMPRESSED_POINT_LEN | UNCOMPRESSED_POINT_LEN), Some(prefix)) => {
                return Err(P384Error::InvalidPointPrefix { len, prefix });
            }
            (len, _) => return Err(P384Error::InvalidPointLength(len)),
        }
        // `from_sec1_bytes` checks the curve equation for the uncompressed form
        // (decompression yields only on-curve points) and rejects the identity.
        PublicKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| P384Error::PointNotOnCurve)
    }

    /// The 97-byte SEC1 uncompressed form.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; UNCOMPRESSED_POINT_LEN] {
        let encoded = self.0.to_sec1_point(false);
        let mut out = [0u8; UNCOMPRESSED_POINT_LEN];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.0)
    }
}

/// Verifies a strict-DER `ECDSA-Sig-Value` over a 32-byte or 48-byte digest
/// under a P-384 key, accepting either value of `s`.
///
/// The digest is the SHA-256 or SHA-384 of the signed bytes; the caller hashes
/// with the algorithm the signature names. A 32-byte digest is the whole of
/// the ECDSA integer `e`, as FIPS 186-5 §6.4.2 takes a hash shorter than the
/// group order.
///
/// # Errors
///
/// [`P384Error::InvalidDigestLength`], [`P384Error::MalformedDer`],
/// [`P384Error::SignatureScalarOutOfRange`], or
/// [`P384Error::VerificationFailed`].
pub fn verify_prehash_der_lenient(
    key: &P384PublicKey,
    digest: &[u8],
    der_signature: &[u8],
) -> Result<(), P384Error> {
    if digest.len() != 32 && digest.len() != 48 {
        return Err(P384Error::InvalidDigestLength(digest.len()));
    }
    let signature = der_to_signature(der_signature)?;
    key.verifying_key()
        .verify_prehash(digest, &signature)
        .map_err(|_| P384Error::VerificationFailed)
}

/// Parses a strict-DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3): a SEQUENCE with a
/// short-form length that covers the input exactly, holding exactly two
/// INTEGERs, each minimally encoded, non-negative, and at most 48 bytes of
/// magnitude. A P-384 `ECDSA-Sig-Value` is at most 2 + 2·(2 + 49) = 104 bytes,
/// so a long-form length is non-minimal and rejected.
fn der_to_signature(der: &[u8]) -> Result<Signature, P384Error> {
    let [tag, len, body @ ..] = der else {
        return Err(P384Error::MalformedDer("truncated SEQUENCE header"));
    };
    if *tag != 0x30 {
        return Err(P384Error::MalformedDer("expected SEQUENCE tag"));
    }
    if *len & 0x80 != 0 {
        return Err(P384Error::MalformedDer("SEQUENCE length is not short form"));
    }
    if usize::from(*len) != body.len() {
        return Err(P384Error::MalformedDer(
            "SEQUENCE length does not match the input",
        ));
    }
    let (r, rest) = parse_der_integer(body)?;
    let (s, rest) = parse_der_integer(rest)?;
    if !rest.is_empty() {
        return Err(P384Error::MalformedDer("trailing bytes inside SEQUENCE"));
    }
    let mut r_bytes = [0u8; SCALAR_LEN];
    r_bytes[SCALAR_LEN - r.len()..].copy_from_slice(r);
    let mut s_bytes = [0u8; SCALAR_LEN];
    s_bytes[SCALAR_LEN - s.len()..].copy_from_slice(s);
    Signature::from_scalars(r_bytes, s_bytes).map_err(|_| P384Error::SignatureScalarOutOfRange)
}

/// Reads one strict-DER INTEGER and returns its magnitude without the sign
/// pad, plus the bytes after it.
fn parse_der_integer(input: &[u8]) -> Result<(&[u8], &[u8]), P384Error> {
    let [tag, len, rest @ ..] = input else {
        return Err(P384Error::MalformedDer("truncated INTEGER header"));
    };
    if *tag != 0x02 {
        return Err(P384Error::MalformedDer("expected INTEGER tag"));
    }
    if *len & 0x80 != 0 {
        return Err(P384Error::MalformedDer("INTEGER length is not short form"));
    }
    let len = usize::from(*len);
    let (value, rest) = rest
        .split_at_checked(len)
        .ok_or(P384Error::MalformedDer("INTEGER runs past the SEQUENCE"))?;
    let magnitude = match value {
        [] => return Err(P384Error::MalformedDer("empty INTEGER")),
        [first, ..] if first & 0x80 != 0 => {
            return Err(P384Error::MalformedDer("negative INTEGER"));
        }
        [0x00, second, ..] if second & 0x80 == 0 => {
            return Err(P384Error::MalformedDer(
                "INTEGER has a redundant leading zero",
            ));
        }
        [0x00, tail @ ..] if !tail.is_empty() => tail,
        other => other,
    };
    if magnitude.len() > SCALAR_LEN {
        return Err(P384Error::SignatureScalarOutOfRange);
    }
    Ok((magnitude, rest))
}

/// A P-384 private key, for tests that issue a certificate chain shaped like
/// Apple's. `Debug` never prints the scalar.
#[cfg(any(test, feature = "testing"))]
pub struct P384SecretKey(::p384::ecdsa::SigningKey);

#[cfg(any(test, feature = "testing"))]
impl core::fmt::Debug for P384SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("P384SecretKey(..)")
    }
}

#[cfg(any(test, feature = "testing"))]
impl P384SecretKey {
    /// Derives a key from a 32-byte test seed: the scalar is
    /// `SHA-384("SCP-TEST-P384-KEY-V1:" ‖ seed)` read big-endian.
    ///
    /// # Errors
    ///
    /// [`P384Error::InvalidScalar`] when that digest is zero or not below the
    /// group order (probability about 2^-190).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, P384Error> {
        use sha2::Digest as _;

        let mut hasher = sha2::Sha384::new();
        hasher.update(b"SCP-TEST-P384-KEY-V1:");
        hasher.update(seed);
        let mut scalar = zeroize::Zeroizing::new([0u8; SCALAR_LEN]);
        scalar.copy_from_slice(&hasher.finalize());
        ::p384::ecdsa::SigningKey::from_slice(scalar.as_ref())
            .map(Self)
            .map_err(|_| P384Error::InvalidScalar)
    }

    /// The key's public point.
    ///
    /// # Errors
    ///
    /// [`P384Error::PointNotOnCurve`] if the signing key's point fails
    /// validation, which a valid scalar never produces.
    pub fn public_key(&self) -> Result<P384PublicKey, P384Error> {
        PublicKey::from_affine(*self.0.verifying_key().as_affine())
            .map(P384PublicKey)
            .map_err(|_| P384Error::PointNotOnCurve)
    }
}

/// Signs a 32-byte or 48-byte digest and returns the strict-DER
/// `ECDSA-Sig-Value`.
///
/// The nonce is RFC 6979 deterministic. With `high_s` false the signature
/// carries the low `s`; with `high_s` true it carries `n − s`, the other value
/// a verifier that accepts either must take.
///
/// # Errors
///
/// [`P384Error::InvalidDigestLength`] or [`P384Error::SigningFailed`].
#[cfg(any(test, feature = "testing"))]
pub fn sign_prehash_der(
    key: &P384SecretKey,
    digest: &[u8],
    high_s: bool,
) -> Result<Vec<u8>, P384Error> {
    use ::p384::ecdsa::signature::hazmat::PrehashSigner;

    if digest.len() != 32 && digest.len() != 48 {
        return Err(P384Error::InvalidDigestLength(digest.len()));
    }
    let signature: Signature = key
        .0
        .sign_prehash(digest)
        .map_err(|_| P384Error::SigningFailed)?;
    let low = signature.normalize_s();
    let chosen = if high_s {
        let (r, s) = low.split_scalars();
        let negated = -*s;
        Signature::from_scalars(r.to_bytes(), negated.to_bytes())
            .map_err(|_| P384Error::SigningFailed)?
    } else {
        low
    };
    let (r, s) = chosen.split_bytes();
    encode_signature_der(r.as_slice(), s.as_slice())
}

/// The strict-DER `ECDSA-Sig-Value` of two big-endian scalars of at most
/// [`SCALAR_LEN`] bytes each.
#[cfg(any(test, feature = "testing"))]
fn encode_signature_der(r: &[u8], s: &[u8]) -> Result<Vec<u8>, P384Error> {
    fn short_len(len: usize) -> Result<u8, P384Error> {
        u8::try_from(len)
            .ok()
            .filter(|len| *len < 0x80)
            .ok_or(P384Error::SigningFailed)
    }
    fn integer(out: &mut Vec<u8>, value: &[u8]) -> Result<(), P384Error> {
        let start = value.iter().position(|b| *b != 0).unwrap_or(value.len());
        let magnitude = value.get(start..).ok_or(P384Error::SigningFailed)?;
        // Zero encodes as one 0x00 byte; a set high bit needs a sign pad.
        let pad = magnitude.first().is_none_or(|b| b & 0x80 != 0);
        out.push(0x02);
        out.push(short_len(magnitude.len() + usize::from(pad))?);
        if pad {
            out.push(0x00);
        }
        out.extend_from_slice(magnitude);
        Ok(())
    }
    let mut body = Vec::with_capacity(2 * (2 + SCALAR_LEN + 1));
    integer(&mut body, r)?;
    integer(&mut body, s)?;
    let mut der = Vec::with_capacity(body.len() + 2);
    der.push(0x30);
    der.push(short_len(body.len())?);
    der.extend_from_slice(&body);
    Ok(der)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use ::p384::elliptic_curve::scalar::IsHigh;
    use sha2::{Digest, Sha256, Sha384};

    use super::*;

    fn key(seed: u8) -> P384SecretKey {
        P384SecretKey::from_seed(&[seed; 32]).unwrap()
    }

    fn s_is_high(der: &[u8]) -> bool {
        bool::from(der_to_signature(der).unwrap().s().is_high())
    }

    #[test]
    fn sha384_digest_low_and_high_s_both_verify() {
        let key = key(1);
        let public = key.public_key().unwrap();
        let digest = Sha384::digest(b"tbs");
        let low = sign_prehash_der(&key, &digest, false).unwrap();
        let high = sign_prehash_der(&key, &digest, true).unwrap();
        assert!(!s_is_high(&low));
        assert!(s_is_high(&high));
        assert_ne!(low, high);
        assert_eq!(verify_prehash_der_lenient(&public, &digest, &low), Ok(()));
        assert_eq!(verify_prehash_der_lenient(&public, &digest, &high), Ok(()));
    }

    #[test]
    fn sha256_digest_verifies_under_p384_key() {
        let key = key(2);
        let public = key.public_key().unwrap();
        let digest = Sha256::digest(b"tbs");
        let sig = sign_prehash_der(&key, &digest, false).unwrap();
        assert_eq!(verify_prehash_der_lenient(&public, &digest, &sig), Ok(()));
    }

    #[test]
    fn wrong_digest_key_or_bit_fails() {
        let key1 = key(3);
        let public = key1.public_key().unwrap();
        let other = key(4).public_key().unwrap();
        let digest = Sha384::digest(b"tbs");
        let sig = sign_prehash_der(&key1, &digest, false).unwrap();
        assert_eq!(verify_prehash_der_lenient(&public, &digest, &sig), Ok(()));
        let other_digest = Sha384::digest(b"other");
        assert_eq!(
            verify_prehash_der_lenient(&public, &other_digest, &sig),
            Err(P384Error::VerificationFailed)
        );
        assert_eq!(
            verify_prehash_der_lenient(&other, &digest, &sig),
            Err(P384Error::VerificationFailed)
        );
        let mut flipped = sig;
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            verify_prehash_der_lenient(&public, &digest, &flipped),
            Err(P384Error::VerificationFailed)
        );
    }

    #[test]
    fn digest_length_other_than_32_or_48_rejected() {
        let key = key(5);
        let public = key.public_key().unwrap();
        let digest = Sha384::digest(b"tbs");
        let sig = sign_prehash_der(&key, &digest, false).unwrap();
        assert_eq!(verify_prehash_der_lenient(&public, &digest, &sig), Ok(()));
        for len in [0, 31, 33, 47, 49, 64] {
            assert_eq!(
                verify_prehash_der_lenient(&public, &vec![0u8; len], &sig),
                Err(P384Error::InvalidDigestLength(len))
            );
        }
    }

    #[test]
    fn non_strict_der_rejected() {
        let key = key(6);
        let public = key.public_key().unwrap();
        let digest = Sha384::digest(b"tbs");
        let sig = sign_prehash_der(&key, &digest, false).unwrap();
        assert_eq!(verify_prehash_der_lenient(&public, &digest, &sig), Ok(()));

        // Long-form SEQUENCE length.
        let mut long_form = vec![0x30, 0x81];
        long_form.extend_from_slice(&sig[1..]);
        assert!(matches!(
            verify_prehash_der_lenient(&public, &digest, &long_form),
            Err(P384Error::MalformedDer(_))
        ));
        // Trailing byte after the SEQUENCE.
        let mut trailing = sig.clone();
        trailing.push(0);
        assert!(matches!(
            verify_prehash_der_lenient(&public, &digest, &trailing),
            Err(P384Error::MalformedDer(_))
        ));
        // A redundant leading zero on r.
        let r_len = usize::from(sig[3]);
        let mut padded = vec![0x30, sig[1] + 1, 0x02, sig[3] + 1, 0x00];
        padded.extend_from_slice(&sig[4..4 + r_len]);
        padded.extend_from_slice(&sig[4 + r_len..]);
        if sig[4] & 0x80 == 0 {
            assert!(matches!(
                verify_prehash_der_lenient(&public, &digest, &padded),
                Err(P384Error::MalformedDer(_))
            ));
        }
        assert!(matches!(
            verify_prehash_der_lenient(&public, &digest, &[]),
            Err(P384Error::MalformedDer(_))
        ));
    }

    #[test]
    fn point_validation() {
        let public = key(7).public_key().unwrap();
        let point = public.to_uncompressed();
        assert_eq!(P384PublicKey::from_sec1(&point), Ok(public));
        let mut off_curve = point;
        off_curve[96] ^= 1;
        assert_eq!(
            P384PublicKey::from_sec1(&off_curve),
            Err(P384Error::PointNotOnCurve)
        );
        let mut bad_prefix = point;
        bad_prefix[0] = 0x06;
        assert_eq!(
            P384PublicKey::from_sec1(&bad_prefix),
            Err(P384Error::InvalidPointPrefix {
                len: 97,
                prefix: 0x06
            })
        );
        assert_eq!(
            P384PublicKey::from_sec1(&point[..65]),
            Err(P384Error::InvalidPointLength(65))
        );
        assert_eq!(
            P384PublicKey::from_sec1(&[0x00]),
            Err(P384Error::InvalidPointLength(1))
        );
    }
}
