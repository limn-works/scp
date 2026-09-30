//! P-256 primitives for SCP (spec §9.5, §9.5.1, §9.10.4).
//!
//! This module is the single home of SCP's ECDSA P-256 / SHA-256 and P-256 ECDH
//! arithmetic. It is pure: no custody, no I/O, no async. Every function either
//! returns its result or a typed [`P256Error`]; nothing falls back.
//!
//! Signature rules (§9.5):
//! - An SCP signature is the 64-byte raw form `r ‖ s`, each a 32-byte
//!   big-endian integer, never DER.
//! - A signer emits the low-`s` form, and a software signer derives its nonce
//!   under RFC 6979 with SHA-256. SCP signs a 32-byte canonical hash (§9.5.1), so
//!   the ECDSA message digest **is** that hash and RFC 6979 runs with
//!   `h1 = digest` (§25.1). [`sign_prehash_rfc6979`] does exactly that.
//! - A verifier of a §9.5.1 signature rejects high `s`
//!   ([`verify_prehash_strict`]). MLS-layer signatures and ES256 signatures on a
//!   UCAN an outside party issued are exempt ([`verify_prehash_lenient`]).
//!
//! Point validation (§9.5): [`P256PublicKey::from_sec1`] accepts only a 33-byte
//! point led by `0x02`/`0x03` or a 65-byte point led by `0x04`, checks the curve
//! equation, and rejects the point at infinity. It is the only constructor of
//! [`P256PublicKey`], so every point reaching [`verify_prehash_strict`],
//! [`verify_prehash_lenient`], or [`ecdh_p256`] has passed it.
//!
//! Seed to scalar (§9.10.4, §25.2): [`seed_to_scalar`] is the FIPS 186-5
//! Appendix A.2.1 extra-random-bits method: HKDF-Expand-SHA256 the 32-byte seed
//! to 48 bytes under a label, reduce modulo `n − 1`, add one.

use ::p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ::p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ::p256::elliptic_curve::bigint::{NonZero, U256, U384};
use ::p256::elliptic_curve::sec1::ToEncodedPoint;
use ::p256::{NonZeroScalar, PublicKey};
use zeroize::{Zeroize, Zeroizing};

/// Length of a SEC1 compressed P-256 point (the signature-verification key
/// form, §9.5).
pub const COMPRESSED_POINT_LEN: usize = 33;

/// Length of a SEC1 uncompressed P-256 point (the HPKE and MLS key form,
/// RFC 9180 §7.1, RFC 9420 §5.1.2).
pub const UNCOMPRESSED_POINT_LEN: usize = 65;

/// Length of a raw `r ‖ s` P-256 signature (§9.5).
pub const SIGNATURE_LEN: usize = 64;

/// The P-256 group order minus one, `n − 1`, as a 384-bit integer: the modulus
/// of the FIPS 186-5 A.2.1 reduction in [`seed_to_scalar`].
///
/// `n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`
/// (RFC 6979 A.2.5 prints the same `q`).
const N_MINUS_ONE: NonZero<U384> = NonZero::<U384>::const_new(U384::from_be_hex(
    "00000000000000000000000000000000\
     FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550",
))
.0;

/// Errors from the P-256 primitives. Each variant names one rejected input or
/// one failed check, so a caller can map it without parsing text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum P256Error {
    /// A SEC1 point encoding was neither 33 nor 65 bytes long.
    #[error("P-256 point encoding must be 33 or 65 bytes, got {0}")]
    InvalidPointLength(usize),
    /// A SEC1 point encoding carried a leading byte its length does not allow
    /// (33 bytes need `0x02`/`0x03`, 65 bytes need `0x04`).
    #[error("P-256 point encoding of {len} bytes has invalid leading byte {prefix:#04x}")]
    InvalidPointPrefix {
        /// Length of the rejected encoding.
        len: usize,
        /// The rejected leading byte.
        prefix: u8,
    },
    /// The decoded point is not on the P-256 curve, or is the point at
    /// infinity.
    #[error("P-256 point is not on the curve or is the point at infinity")]
    PointNotOnCurve,
    /// A private scalar was zero or not below the group order.
    #[error("P-256 private scalar is zero or not below the group order")]
    InvalidScalar,
    /// A raw signature was not exactly 64 bytes.
    #[error("P-256 signature must be 64 bytes, got {0}")]
    InvalidSignatureLength(usize),
    /// A signature's `r` or `s` was zero or not below the group order.
    #[error("P-256 signature r or s is zero or not below the group order")]
    SignatureScalarOutOfRange,
    /// A signature's `s` exceeds `n/2`; §9.5 requires the low form.
    #[error("P-256 signature s exceeds n/2 (high-s form is rejected under §9.5)")]
    HighS,
    /// The signature does not verify under the key and digest.
    #[error("P-256 signature does not verify")]
    VerificationFailed,
    /// A DER `ECDSA-Sig-Value` was not strict DER.
    #[error("ECDSA DER signature is malformed: {0}")]
    MalformedDer(&'static str),
    /// ECDSA signing failed (RFC 6979 produced a nonce yielding `r = 0` or
    /// `s = 0`, probability about 2^-256).
    #[error("P-256 signing failed")]
    SigningFailed,
}

/// The HKDF-Expand `info` label of a [`seed_to_scalar`] derivation. Each label
/// is a separate domain, so the same seed yields unrelated scalars under two
/// labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeedLabel {
    /// `"SCP-PSEUDONYM-P256-V1"`: the per-context pseudonym scalar (§9.10.4).
    Pseudonym,
    /// `"SCP-TEST-VECTOR-KEY-V1"`: the §25.2 reference key material.
    TestVectorKey,
}

impl SeedLabel {
    /// The label's bytes, as §9.10.4 and §25.2 print them.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Pseudonym => b"SCP-PSEUDONYM-P256-V1",
            Self::TestVectorKey => b"SCP-TEST-VECTOR-KEY-V1",
        }
    }
}

/// A validated P-256 public key: on the curve and not the point at infinity.
///
/// The only constructors are [`P256PublicKey::from_sec1`] and
/// [`P256SecretKey::public_key`], so holding one proves §9.5 point validation
/// has run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P256PublicKey(PublicKey);

impl core::fmt::Debug for P256PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("P256PublicKey")
            .field(&Hex(&self.to_compressed()))
            .finish()
    }
}

impl P256PublicKey {
    /// Parses and validates a SEC1 point (§9.5 point validation).
    ///
    /// Accepts exactly a 33-byte compressed point led by `0x02` or `0x03`, or a
    /// 65-byte uncompressed point led by `0x04`.
    ///
    /// # Errors
    ///
    /// - [`P256Error::InvalidPointLength`] for any other length (including the
    ///   1-byte SEC1 encoding of the point at infinity).
    /// - [`P256Error::InvalidPointPrefix`] for a wrong leading byte (hybrid
    ///   `0x06`/`0x07` encodings included).
    /// - [`P256Error::PointNotOnCurve`] when the coordinates fail the curve
    ///   equation or no `y` exists for a compressed `x`.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, P256Error> {
        match (bytes.len(), bytes.first().copied()) {
            (COMPRESSED_POINT_LEN, Some(0x02 | 0x03)) | (UNCOMPRESSED_POINT_LEN, Some(0x04)) => {}
            (len @ (COMPRESSED_POINT_LEN | UNCOMPRESSED_POINT_LEN), Some(prefix)) => {
                return Err(P256Error::InvalidPointPrefix { len, prefix });
            }
            (len, _) => return Err(P256Error::InvalidPointLength(len)),
        }
        // `from_sec1_bytes` decodes the point, checks y² = x³ − 3x + b for the
        // uncompressed form (decompression can only yield an on-curve point for
        // the compressed form, or fails), and rejects the identity.
        PublicKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| P256Error::PointNotOnCurve)
    }

    /// The 33-byte SEC1 compressed form: the §9.5 signature-verification key
    /// encoding.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; COMPRESSED_POINT_LEN] {
        let encoded = self.0.to_encoded_point(true);
        let mut out = [0u8; COMPRESSED_POINT_LEN];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    /// The 65-byte SEC1 uncompressed form: the HPKE (RFC 9180 §7.1) and MLS
    /// (RFC 9420 §5.1.2) key encoding.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; UNCOMPRESSED_POINT_LEN] {
        let encoded = self.0.to_encoded_point(false);
        let mut out = [0u8; UNCOMPRESSED_POINT_LEN];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.0)
    }
}

/// A P-256 private key. It signs (ECDSA) and agrees (ECDH); §25.2 uses one key
/// in both roles, as does DHKEM(P-256).
///
/// The inner scalar is zeroized on drop by `p256`. `Debug` never prints it.
#[derive(Clone)]
pub struct P256SecretKey(SigningKey);

impl core::fmt::Debug for P256SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("P256SecretKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl P256SecretKey {
    /// Builds a key from a 32-byte big-endian scalar.
    ///
    /// # Errors
    ///
    /// [`P256Error::InvalidScalar`] when the scalar is zero or not below `n`.
    pub fn from_scalar_bytes(scalar: &[u8; 32]) -> Result<Self, P256Error> {
        SigningKey::from_slice(scalar)
            .map(Self)
            .map_err(|_| P256Error::InvalidScalar)
    }

    /// Builds a key from a scalar already known to lie in `[1, n − 1]`.
    #[must_use]
    pub fn from_nonzero_scalar(scalar: NonZeroScalar) -> Self {
        Self(SigningKey::from(scalar))
    }

    /// Derives a key from a 32-byte seed by [`seed_to_scalar`] under `label`.
    #[must_use]
    pub fn from_seed(label: SeedLabel, seed: &[u8; 32]) -> Self {
        Self::from_nonzero_scalar(seed_to_scalar(label, seed))
    }

    /// The public key `d·G`.
    #[must_use]
    pub fn public_key(&self) -> P256PublicKey {
        P256PublicKey(PublicKey::from(self.0.verifying_key()))
    }

    /// The 32-byte big-endian private scalar, zeroized on drop.
    #[must_use]
    pub fn to_scalar_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        let mut bytes = self.0.to_bytes();
        out.copy_from_slice(&bytes);
        bytes.as_mut_slice().zeroize();
        out
    }
}

/// FIPS 186-5 Appendix A.2.1 (extra random bits) seed-to-scalar, as §9.10.4
/// and §25.2 state it:
///
/// ```text
/// scalar_input = HKDF-Expand-SHA256(prk = seed, info = label, L = 48)
/// d            = (int(scalar_input) mod (n − 1)) + 1
/// ```
///
/// The 48-byte input carries 128 bits more than `n`, so the bias from uniform
/// is below 2^-128. There is no reject-and-retry and no direct reduction of the
/// 32-byte seed, both of which §9.10.4 forbids.
#[must_use]
pub fn seed_to_scalar(label: SeedLabel, seed: &[u8; 32]) -> NonZeroScalar {
    let okm = crate::kdf::hkdf_expand::<48>(seed, label.as_bytes());

    let mut wide = U384::from_be_slice(okm.as_ref());
    let mut reduced = wide.rem(&N_MINUS_ONE);
    wide.zeroize();
    // `reduced < n − 1 < 2^256`, so truncating to 256 bits is exact.
    let mut narrow: U256 = reduced.resize();
    reduced.zeroize();
    let mut d = narrow.wrapping_add(&U256::ONE);
    narrow.zeroize();
    let scalar = Option::<NonZeroScalar>::from(NonZeroScalar::from_uint(d));
    d.zeroize();
    // `d = (x mod (n − 1)) + 1` lies in `[1, n − 1]` for every `x`, so
    // `from_uint` accepts it for every seed.
    let Some(scalar) = scalar else {
        unreachable!("(x mod (n - 1)) + 1 is always in [1, n - 1]")
    };
    scalar
}

/// Signs a 32-byte digest with RFC 6979 deterministic nonces (`h1 = digest`,
/// §25.1) and returns the low-`s` raw signature (§9.5).
///
/// # Errors
///
/// [`P256Error::SigningFailed`] if the nonce yields `r = 0` or `s = 0`.
pub fn sign_prehash_rfc6979(
    key: &P256SecretKey,
    digest: &[u8; 32],
) -> Result<[u8; SIGNATURE_LEN], P256Error> {
    let signature: Signature = key
        .0
        .sign_prehash(digest)
        .map_err(|_| P256Error::SigningFailed)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(signature_to_raw(&signature))
}

/// Verifies a §9.5.1 signature: exactly 64 bytes, `r` and `s` in `[1, n − 1]`,
/// `s ≤ n/2`, and a valid ECDSA equation over `digest` with no second hash.
///
/// # Errors
///
/// [`P256Error::InvalidSignatureLength`], [`P256Error::SignatureScalarOutOfRange`],
/// [`P256Error::HighS`], or [`P256Error::VerificationFailed`].
pub fn verify_prehash_strict(
    key: &P256PublicKey,
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), P256Error> {
    let signature = parse_raw_signature(signature)?;
    if signature.normalize_s().is_some() {
        return Err(P256Error::HighS);
    }
    key.verifying_key()
        .verify_prehash(digest, &signature)
        .map_err(|_| P256Error::VerificationFailed)
}

/// Verifies a raw signature that may carry a high `s`.
///
/// Only for the §9.5 carve-out on JOSE ES256 signatures an outside party
/// issued (RFC 7518 imposes no low-`s` rule), reached through
/// [`jose::es256_verify_lenient`]. MLS-layer signatures are verified inside
/// openmls, not here. Every signature built under §9.5.1 goes through
/// [`verify_prehash_strict`] instead.
///
/// # Errors
///
/// [`P256Error::InvalidSignatureLength`], [`P256Error::SignatureScalarOutOfRange`],
/// or [`P256Error::VerificationFailed`].
pub fn verify_prehash_lenient(
    key: &P256PublicKey,
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), P256Error> {
    let signature = parse_raw_signature(signature)?;
    key.verifying_key()
        .verify_prehash(digest, &signature)
        .map_err(|_| P256Error::VerificationFailed)
}

/// Replaces `s` with `n − s` when `s > n/2`; a low-`s` signature is returned
/// unchanged.
///
/// # Errors
///
/// [`P256Error::SignatureScalarOutOfRange`] when `r` or `s` is zero or not
/// below `n`.
pub fn normalize_low_s(signature: &[u8; SIGNATURE_LEN]) -> Result<[u8; SIGNATURE_LEN], P256Error> {
    let parsed = parse_raw_signature(signature)?;
    Ok(signature_to_raw(&parsed.normalize_s().unwrap_or(parsed)))
}

/// Converts a strict-DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3) into the raw
/// 64-byte form, left-padding `r` and `s` to 32 bytes.
///
/// Strict means: a SEQUENCE with a short-form length that covers the input
/// exactly, holding exactly two INTEGERs, each minimally encoded, non-negative,
/// and at most 32 bytes of magnitude. BER forms (long-form lengths, redundant
/// leading zeros, indefinite lengths, trailing bytes) are rejected. The high-`s`
/// form is preserved, not normalized; call [`normalize_low_s`] for that.
///
/// # Errors
///
/// [`P256Error::MalformedDer`] for an encoding that is not strict DER, and
/// [`P256Error::SignatureScalarOutOfRange`] when `r` or `s` is zero or not
/// below `n`.
pub fn der_to_raw(der: &[u8]) -> Result<[u8; SIGNATURE_LEN], P256Error> {
    let [tag, len, body @ ..] = der else {
        return Err(P256Error::MalformedDer("truncated SEQUENCE header"));
    };
    if *tag != 0x30 {
        return Err(P256Error::MalformedDer("expected SEQUENCE tag"));
    }
    // A P-256 ECDSA-Sig-Value is at most 2 + 2·(2 + 33) = 72 bytes, so every
    // DER length here fits the short form; a long form is non-minimal.
    if *len & 0x80 != 0 {
        return Err(P256Error::MalformedDer("SEQUENCE length is not short form"));
    }
    if usize::from(*len) != body.len() {
        return Err(P256Error::MalformedDer(
            "SEQUENCE length does not match the input",
        ));
    }
    let (r, rest) = parse_der_integer(body)?;
    let (s, rest) = parse_der_integer(rest)?;
    if !rest.is_empty() {
        return Err(P256Error::MalformedDer("trailing bytes inside SEQUENCE"));
    }
    let mut raw = [0u8; SIGNATURE_LEN];
    raw[32 - r.len()..32].copy_from_slice(r);
    raw[SIGNATURE_LEN - s.len()..].copy_from_slice(s);
    parse_raw_signature(&raw)?;
    Ok(raw)
}

/// P-256 ECDH: returns the 32-byte x-coordinate of `d·Q` (SEC1 §3.3.1, the
/// DHKEM(P-256) `DH` output of RFC 9180 §7.1.1).
///
/// `peer` has already passed §9.5 point validation by construction, which is
/// what closes the invalid-curve attack §9.5 names.
#[must_use]
pub fn ecdh_p256(key: &P256SecretKey, peer: &P256PublicKey) -> Zeroizing<[u8; 32]> {
    let shared = ::p256::ecdh::diffie_hellman(key.0.as_nonzero_scalar(), peer.0.as_affine());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.raw_secret_bytes());
    out
}

/// JOSE ES256 codec (RFC 7518 §3.4): ECDSA P-256 over SHA-256 of the JWS
/// signing input, with the signature as the fixed 64-byte `r ‖ s`.
///
/// This is only the signature codec and the `alg` value. It is not wired into
/// UCAN or any JWT in S0: UCAN issuers resolve through did:dht, which carries
/// only Ed25519 until S12.
pub mod jose {
    use sha2::{Digest, Sha256};

    use super::{
        P256Error, P256PublicKey, P256SecretKey, SIGNATURE_LEN, sign_prehash_rfc6979,
        verify_prehash_lenient, verify_prehash_strict,
    };

    /// The JOSE `alg` header value for ECDSA P-256 / SHA-256.
    pub const ES256_ALG: &str = "ES256";

    /// Signs a JWS signing input and returns the 64-byte ES256 signature.
    ///
    /// The input is `BASE64URL(header) '.' BASE64URL(payload)`. The output is
    /// low-`s`, so it passes both [`es256_verify_strict`] and
    /// [`es256_verify_lenient`].
    ///
    /// # Errors
    ///
    /// [`P256Error::SigningFailed`], as for [`sign_prehash_rfc6979`].
    pub fn es256_sign(
        key: &P256SecretKey,
        signing_input: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], P256Error> {
        sign_prehash_rfc6979(key, &Sha256::digest(signing_input).into())
    }

    /// Verifies an ES256 signature an SCP party issued: 64 bytes, low `s`.
    ///
    /// # Errors
    ///
    /// As for [`verify_prehash_strict`]. A DER-encoded signature (a common
    /// ES256 interop bug) fails with [`P256Error::InvalidSignatureLength`].
    pub fn es256_verify_strict(
        key: &P256PublicKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), P256Error> {
        verify_prehash_strict(key, &Sha256::digest(signing_input).into(), signature)
    }

    /// Verifies an ES256 signature an outside party issued, accepting high `s`
    /// (§9.5 carve-out: RFC 7518 imposes no low-`s` rule).
    ///
    /// # Errors
    ///
    /// As for [`verify_prehash_lenient`].
    pub fn es256_verify_lenient(
        key: &P256PublicKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), P256Error> {
        verify_prehash_lenient(key, &Sha256::digest(signing_input).into(), signature)
    }
}

fn parse_raw_signature(signature: &[u8]) -> Result<Signature, P256Error> {
    if signature.len() != SIGNATURE_LEN {
        return Err(P256Error::InvalidSignatureLength(signature.len()));
    }
    // `from_slice` splits into r and s and rejects zero or ≥ n for either.
    Signature::from_slice(signature).map_err(|_| P256Error::SignatureScalarOutOfRange)
}

fn signature_to_raw(signature: &Signature) -> [u8; SIGNATURE_LEN] {
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&signature.to_bytes());
    out
}

/// Parses one strict-DER INTEGER and returns its magnitude (at most 32 bytes,
/// leading sign-padding zero removed) and the remaining input.
fn parse_der_integer(input: &[u8]) -> Result<(&[u8], &[u8]), P256Error> {
    let [tag, len, rest @ ..] = input else {
        return Err(P256Error::MalformedDer("truncated INTEGER header"));
    };
    if *tag != 0x02 {
        return Err(P256Error::MalformedDer("expected INTEGER tag"));
    }
    if *len & 0x80 != 0 {
        return Err(P256Error::MalformedDer("INTEGER length is not short form"));
    }
    let len = usize::from(*len);
    if len == 0 {
        return Err(P256Error::MalformedDer("empty INTEGER"));
    }
    if rest.len() < len {
        return Err(P256Error::MalformedDer("truncated INTEGER"));
    }
    let (value, rest) = rest.split_at(len);
    let (first, tail) = (value[0], &value[1..]);
    if first & 0x80 != 0 {
        return Err(P256Error::MalformedDer("negative INTEGER"));
    }
    if first == 0 && tail.first().is_some_and(|b| b & 0x80 == 0) {
        return Err(P256Error::MalformedDer("non-minimal INTEGER encoding"));
    }
    let magnitude = if first == 0 { tail } else { value };
    if magnitude.len() > 32 {
        return Err(P256Error::MalformedDer("INTEGER wider than 32 bytes"));
    }
    Ok((magnitude, rest))
}

struct Hex<'a>(&'a [u8]);

impl core::fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// `n` from RFC 6979 A.2.5 (`q`), for test-side arithmetic independent of
    /// the code under test.
    const N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// `n − s` on 32-byte big-endian integers, by schoolbook subtraction.
    fn n_minus(s: &[u8; 32]) -> [u8; 32] {
        let n: [u8; 32] = h(N_HEX);
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = i16::from(n[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(d < 0);
            if d < 0 {
                d += 256;
            }
            out[i] = u8::try_from(d).unwrap();
        }
        assert_eq!(borrow, 0);
        out
    }

    /// `(n − 1)/2`, the largest `s` §9.5 admits.
    const HALF_N_HEX: &str = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";
    /// `(n + 1)/2`, the smallest high `s`.
    const HALF_N_PLUS_ONE_HEX: &str =
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9";

    /// Builds a key and a VALID signature over `digest` whose `s` is exactly
    /// `s_hex`: with nonce `k = 1`, `R = G` and `r = G.x mod n`, so choosing
    /// `d = (s − z) / r` makes `s = k⁻¹(z + r·d)` hold.
    fn key_with_signature_s(digest: &[u8; 32], s_hex: &str) -> (P256PublicKey, [u8; 64]) {
        use p256::elliptic_curve::PrimeField;
        use p256::elliptic_curve::ops::Reduce;
        use p256::elliptic_curve::point::AffineCoordinates;
        use p256::{AffinePoint, FieldBytes, Scalar, U256};

        let s_bytes: [u8; 32] = h(s_hex);
        let s = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(s_bytes))).unwrap();
        let z = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(*digest));
        let r = <Scalar as Reduce<U256>>::reduce_bytes(&AffinePoint::GENERATOR.x());
        let d = (s - z) * Option::<Scalar>::from(r.invert()).unwrap();
        let key = P256SecretKey::from_scalar_bytes(&d.to_repr().into()).unwrap();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r.to_repr());
        sig[32..].copy_from_slice(&s_bytes);
        (key.public_key(), sig)
    }

    /// The §9.5 boundary: `s = (n − 1)/2` is low and passes strict
    /// verification; `s = (n + 1)/2` is high, so strict returns `HighS` while
    /// lenient accepts the same valid signature.
    #[test]
    fn strict_low_s_boundary_is_exact() {
        let digest: [u8; 32] = Sha256::digest(b"low-s boundary").into();

        let (pk, sig) = key_with_signature_s(&digest, HALF_N_HEX);
        verify_prehash_lenient(&pk, &digest, &sig).unwrap();
        assert_eq!(verify_prehash_strict(&pk, &digest, &sig), Ok(()));
        assert_eq!(normalize_low_s(&sig).unwrap(), sig);

        let (pk, sig) = key_with_signature_s(&digest, HALF_N_PLUS_ONE_HEX);
        verify_prehash_lenient(&pk, &digest, &sig).unwrap();
        assert_eq!(
            verify_prehash_strict(&pk, &digest, &sig),
            Err(P256Error::HighS)
        );
        // n − (n+1)/2 = (n−1)/2.
        let normalized = normalize_low_s(&sig).unwrap();
        assert_eq!(normalized[32..], h::<32>(HALF_N_HEX));
        assert_eq!(verify_prehash_strict(&pk, &digest, &normalized), Ok(()));
    }

    /// RFC 6979 Appendix A.2.5, P-256 with SHA-256. SCP signs a 32-byte digest
    /// with `h1 = digest` (§25.1); with `digest = SHA-256(message)` that is
    /// exactly the RFC's computation, so the RFC's `r` must reproduce, and `s`
    /// must reproduce up to the §9.5 low-`s` normalisation.
    #[test]
    fn rfc6979_a25_p256_sha256() {
        let x: [u8; 32] = h("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let ux = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
        let uy = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
        let key = P256SecretKey::from_scalar_bytes(&x).unwrap();
        let pk = key.public_key();
        assert_eq!(hex::encode(pk.to_uncompressed()), format!("04{ux}{uy}"));

        for (msg, r_hex, s_hex) in [
            (
                &b"sample"[..],
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            ),
            (
                &b"test"[..],
                "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
                "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            ),
        ] {
            let digest: [u8; 32] = Sha256::digest(msg).into();
            let r: [u8; 32] = h(r_hex);
            let s: [u8; 32] = h(s_hex);
            let mut rfc_sig = [0u8; 64];
            rfc_sig[..32].copy_from_slice(&r);
            rfc_sig[32..].copy_from_slice(&s);

            // The RFC's own signature verifies under the lenient verifier.
            verify_prehash_lenient(&pk, &digest, &rfc_sig).unwrap();

            let ours = sign_prehash_rfc6979(&key, &digest).unwrap();
            assert_eq!(&ours[..32], &r, "RFC 6979 r mismatch for {msg:?}");
            let s_high = s[0] >= 0x80; // n/2 = 7fffffff80000000…, so s ≥ 0x80… is high
            let expected_s = if s_high { n_minus(&s) } else { s };
            assert_eq!(
                &ours[32..],
                &expected_s,
                "RFC 6979 s (low-s) mismatch for {msg:?}"
            );
            verify_prehash_strict(&pk, &digest, &ours).unwrap();

            if s_high {
                assert_eq!(
                    verify_prehash_strict(&pk, &digest, &rfc_sig),
                    Err(P256Error::HighS)
                );
                assert_eq!(normalize_low_s(&rfc_sig).unwrap(), ours);
            } else {
                assert_eq!(normalize_low_s(&rfc_sig).unwrap(), rfc_sig);
            }
        }
    }

    /// §25.2 reference key material: seed → scalar under
    /// `"SCP-TEST-VECTOR-KEY-V1"`, then compressed and uncompressed points.
    #[test]
    fn spec_25_2_fixture_keys() {
        for (seed, scalar, compressed, uncompressed) in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "6f0712104c3f61ba04526a822836d3f4a13be12e09a8c3c7586b2da0c795998b",
                "033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027",
                "043b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30\
                 27471695574e78728df503a0c21dd1da9f7b77252d8398527a1b2177c78224f051",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "0fed5549df222a5cf0b537e423fbd60875c6fb2b334b381a0c0a6c89eae9ac6a",
                "0223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aea",
                "0423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20a\
                 ead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da6",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "55118deda48fbb900efe9692e644dc5971211c8d3dfcc50f117d842c6056be4f",
                "026fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a670",
                "046fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a6\
                 700192d543b6d5d6b3d7990f4463d2f0692bcb7bdbaf3b1ee8f4465dd888323df0",
            ),
        ] {
            let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &h(seed));
            assert_eq!(
                hex::encode(*key.to_scalar_bytes()),
                scalar,
                "scalar for seed {seed}"
            );
            let pk = key.public_key();
            assert_eq!(hex::encode(pk.to_compressed()), compressed);
            assert_eq!(hex::encode(pk.to_uncompressed()), uncompressed);
            // Both encodings parse back to the same key.
            assert_eq!(P256PublicKey::from_sec1(&pk.to_compressed()).unwrap(), pk);
            assert_eq!(P256PublicKey::from_sec1(&pk.to_uncompressed()).unwrap(), pk);
        }
    }

    /// §25.26 Vectors 41 and 42 intermediates, rebuilt in test code from the
    /// vector's own bytes. Vector 42's challenge is `"SCP-KEY-EVENT-V1:" || D`,
    /// carried unpadded base64url inside `clientDataJSON`, and its
    /// `authenticatorData` is `SHA-256("ctx.network") || 0x05 || BE32(0)`.
    struct Spec2526 {
        preimage_41: Vec<u8>,
        digest_41: [u8; 32],
        digest_42: [u8; 32],
        challenge_b64url: String,
        client_data_json: String,
        client_data_hash: [u8; 32],
        digest_assertion: [u8; 32],
    }

    fn spec_25_26() -> Spec2526 {
        const PREIMAGE_41: &str = "5343502d4b454c2d4556454e542d56313a010000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000100\
             00000001010000000000000001033b1cac23f45cf1cdfdf0b32f8f777b99166c\
             1b69649c2295b1517883d47f3027000000010000000100000002033b1cac23f4\
             5cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30270101000000\
             000000000001010223702a648232f2d00713de9289753c2fbd4c4efa7e1e3390\
             5e3723a412b20aea020100000000000000000101000000019d94df95bc0a13f1\
             963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e1002000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a51\
             5de80a3e43eb010100000001";
        fn unhex(s: &str) -> Vec<u8> {
            let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            hex::decode(compact).unwrap()
        }
        fn sha256(parts: &[&[u8]]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize().into()
        }
        fn b64url(bytes: &[u8]) -> String {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = chunk
                    .iter()
                    .enumerate()
                    .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
                for i in 0..=chunk.len() {
                    out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
                }
            }
            out
        }

        let preimage_41 = unhex(PREIMAGE_41);
        let digest_41 = sha256(&[&preimage_41]);
        // Vector 42's preimage differs from Vector 41's only in the
        // signature-form list's entry, byte 100.
        let mut preimage_42 = preimage_41.clone();
        preimage_42[100] = 0x02;
        let digest_42 = sha256(&[&preimage_42]);
        let challenge = [b"SCP-KEY-EVENT-V1:".as_slice(), &digest_42].concat();
        let challenge_b64url = b64url(&challenge);
        let client_data_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge_b64url}\",\
             \"origin\":\"https://ctx.network\",\"crossOrigin\":false}}"
        );
        let client_data_hash = sha256(&[client_data_json.as_bytes()]);
        let authenticator_data =
            [sha256(&[b"ctx.network"]).as_slice(), &[0x05, 0, 0, 0, 0]].concat();
        let digest_assertion = sha256(&[&authenticator_data, &client_data_hash]);
        Spec2526 {
            preimage_41,
            digest_41,
            digest_42,
            challenge_b64url,
            client_data_json,
            client_data_hash,
            digest_assertion,
        }
    }

    /// §25.26 Vectors 41 and 42: the RFC 6979 signer, keyed with §25.2's
    /// reference scalar (the root-set member 0 of the vector identity),
    /// reproduces each vector's 64-byte signature exactly, and each verifies
    /// strictly. Vector 41 (raw form) signs the preimage digest `D`; Vector 42
    /// (`WebAuthn` assertion form) signs
    /// `SHA-256(authenticatorData || SHA-256(clientDataJSON))`, both from
    /// `spec_25_26`. Each failure message prints the rebuilt intermediates
    /// beside the values §25.26 prints, so a failure names the step that
    /// diverged.
    #[test]
    fn spec_25_26_vectors_41_42_signatures() {
        let v = spec_25_26();
        let key = P256SecretKey::from_seed(
            SeedLabel::TestVectorKey,
            &h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        );
        let public_key = key.public_key();

        let signature_41 = sign_prehash_rfc6979(&key, &v.digest_41).unwrap();
        assert_eq!(
            hex::encode(signature_41),
            "274e7cf73b6807ec53619491a1cc094a5fa2a649b4a04a043965597c7faa5e96\
             7e7b499be2e9750521b4bfec6fa65bfdd14c8e5c940bb60884d040da9d1e70a0"
                .replace(char::is_whitespace, ""),
            "Vector 41: preimage length {} (spec 364), byte 100 {:#04x} (spec 0x01), \
             D {} (spec d8ba4ebad52657208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7)",
            v.preimage_41.len(),
            v.preimage_41[100],
            hex::encode(v.digest_41),
        );
        verify_prehash_strict(&public_key, &v.digest_41, &signature_41).unwrap();

        let signature_42 = sign_prehash_rfc6979(&key, &v.digest_assertion).unwrap();
        assert_eq!(
            hex::encode(signature_42),
            "6aee5c6f9b367f8a886fb996c2f08d77fefcddee6399f1b928cf1110cef786d0\
             315de3e854e0669d355b4968b5c2bc8075a5630e3c980844049ebcbf9716c424"
                .replace(char::is_whitespace, ""),
            "Vector 42: D {} (spec 9a41b0fdb978014730ab7d8d56b9a77745b4ff4824affc096bbd923d14a569a6), \
             challenge {} (spec U0NQLUtFWS1FVkVOVC1WMTqaQbD9uXgBRzCrfY1Wuad3RbT_SCSv_AlrvZI9FKVppg), \
             clientDataJSON length {} (spec 155), \
             SHA-256(clientDataJSON) {} (spec 0b33b76a4ecb79e15753a17147ac39f6964ae20523e7e001c258e67d2562c236), \
             signed digest {} (spec 1f63ea5226c20ce261b3243ad941ef8834b0678cf4681b2f914963b0bffe4d6b)",
            hex::encode(v.digest_42),
            v.challenge_b64url,
            v.client_data_json.len(),
            hex::encode(v.client_data_hash),
            hex::encode(v.digest_assertion),
        );
        verify_prehash_strict(&public_key, &v.digest_assertion, &signature_42).unwrap();
    }

    #[test]
    fn from_sec1_rejects_identity_and_off_curve() {
        // The 1-byte SEC1 identity encoding.
        assert_eq!(
            P256PublicKey::from_sec1(&[0x00]),
            Err(P256Error::InvalidPointLength(1))
        );
        // (0, 0) uncompressed is not on the curve (b ≠ 0).
        let mut zero = [0u8; 65];
        zero[0] = 0x04;
        assert_eq!(
            P256PublicKey::from_sec1(&zero),
            Err(P256Error::PointNotOnCurve)
        );
        // Flip one bit of a valid y.
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[7u8; 32]);
        let mut bad = key.public_key().to_uncompressed();
        bad[64] ^= 1;
        assert_eq!(
            P256PublicKey::from_sec1(&bad),
            Err(P256Error::PointNotOnCurve)
        );
        assert_eq!(
            P256PublicKey::from_sec1(&[]),
            Err(P256Error::InvalidPointLength(0))
        );
    }

    #[test]
    fn scalar_bounds_are_enforced() {
        assert_eq!(
            P256SecretKey::from_scalar_bytes(&[0u8; 32]).unwrap_err(),
            P256Error::InvalidScalar
        );
        assert_eq!(
            P256SecretKey::from_scalar_bytes(&h(N_HEX)).unwrap_err(),
            P256Error::InvalidScalar
        );
        assert_eq!(
            P256SecretKey::from_scalar_bytes(&[0xff; 32]).unwrap_err(),
            P256Error::InvalidScalar
        );
    }

    #[test]
    fn strict_verify_rejects_malformed_signatures() {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[9u8; 32]);
        let pk = key.public_key();
        let digest = [0x42u8; 32];
        let sig = sign_prehash_rfc6979(&key, &digest).unwrap();
        verify_prehash_strict(&pk, &digest, &sig).unwrap();

        assert_eq!(
            verify_prehash_strict(&pk, &digest, &sig[..63]),
            Err(P256Error::InvalidSignatureLength(63))
        );
        let mut long = sig.to_vec();
        long.push(0);
        assert_eq!(
            verify_prehash_strict(&pk, &digest, &long),
            Err(P256Error::InvalidSignatureLength(65))
        );
        let mut r_zero = sig;
        r_zero[..32].fill(0);
        assert_eq!(
            verify_prehash_strict(&pk, &digest, &r_zero),
            Err(P256Error::SignatureScalarOutOfRange)
        );
        let mut s_n = sig;
        s_n[32..].copy_from_slice(&h::<32>(N_HEX));
        assert_eq!(
            verify_prehash_strict(&pk, &digest, &s_n),
            Err(P256Error::SignatureScalarOutOfRange)
        );
        let mut high = sig;
        let s: [u8; 32] = sig[32..].try_into().unwrap();
        high[32..].copy_from_slice(&n_minus(&s));
        assert_eq!(
            verify_prehash_strict(&pk, &digest, &high),
            Err(P256Error::HighS)
        );
        verify_prehash_lenient(&pk, &digest, &high).unwrap();
        assert_eq!(
            verify_prehash_strict(&pk, &[0x43u8; 32], &sig),
            Err(P256Error::VerificationFailed)
        );
    }

    #[test]
    fn der_to_raw_round_trip() {
        // r = 1, s = 0x80 (needs a sign-padding zero).
        let der = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80];
        let raw = der_to_raw(&der).unwrap();
        assert_eq!(raw[31], 1);
        assert_eq!(raw[63], 0x80);
        assert!(raw[..31].iter().all(|b| *b == 0));
        assert!(raw[32..63].iter().all(|b| *b == 0));
    }

    fn assert_der_rejected(der: &[u8], expected: P256Error) {
        assert_eq!(der_to_raw(der), Err(expected), "{der:02x?}");
    }

    #[test]
    fn der_rejects_truncated_sequence_header() {
        assert_der_rejected(
            &[0x30],
            P256Error::MalformedDer("truncated SEQUENCE header"),
        );
    }

    #[test]
    fn der_rejects_set_tag() {
        assert_der_rejected(
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            P256Error::MalformedDer("expected SEQUENCE tag"),
        );
    }

    #[test]
    fn der_rejects_sequence_length_mismatch() {
        assert_der_rejected(
            &[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            P256Error::MalformedDer("SEQUENCE length does not match the input"),
        );
    }

    /// The SEQUENCE length covers the whole input, and a byte follows the
    /// second INTEGER inside it.
    #[test]
    fn der_rejects_trailing_byte_inside_sequence() {
        assert_der_rejected(
            &[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
            P256Error::MalformedDer("trailing bytes inside SEQUENCE"),
        );
    }

    #[test]
    fn der_rejects_truncated_integer_header() {
        assert_der_rejected(
            &[0x30, 0x04, 0x02, 0x01, 0x01, 0x02],
            P256Error::MalformedDer("truncated INTEGER header"),
        );
    }

    #[test]
    fn der_rejects_wrong_integer_tag() {
        assert_der_rejected(
            &[0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01],
            P256Error::MalformedDer("expected INTEGER tag"),
        );
    }

    #[test]
    fn der_rejects_empty_integer() {
        assert_der_rejected(
            &[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01],
            P256Error::MalformedDer("empty INTEGER"),
        );
    }

    #[test]
    fn der_rejects_truncated_integer() {
        assert_der_rejected(
            &[0x30, 0x04, 0x02, 0x05, 0x01, 0x01],
            P256Error::MalformedDer("truncated INTEGER"),
        );
    }

    #[test]
    fn der_rejects_negative_integer() {
        assert_der_rejected(
            &[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01],
            P256Error::MalformedDer("negative INTEGER"),
        );
    }

    #[test]
    fn der_rejects_non_minimal_integer() {
        assert_der_rejected(
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
            P256Error::MalformedDer("non-minimal INTEGER encoding"),
        );
    }

    /// A 33-byte INTEGER whose first byte is not a sign-padding zero carries
    /// 33 bytes of magnitude.
    #[test]
    fn der_rejects_integer_wider_than_32_bytes() {
        let mut der = vec![0x30, 0x26, 0x02, 0x21];
        der.extend_from_slice(&[0x01; 33]);
        der.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert_der_rejected(&der, P256Error::MalformedDer("INTEGER wider than 32 bytes"));
    }

    #[test]
    fn der_rejects_zero_r() {
        assert_der_rejected(
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
            P256Error::SignatureScalarOutOfRange,
        );
    }

    /// `Debug` on a private key prints the public key and never the scalar
    /// (§9.5 secret handling).
    #[test]
    fn secret_key_debug_hides_the_scalar() {
        let key = P256SecretKey::from_seed(
            SeedLabel::TestVectorKey,
            &h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        );
        let printed = format!("{key:?}");
        assert!(
            !printed.contains("6f0712104c3f61ba04526a822836d3f4a13be12e09a8c3c7586b2da0c795998b")
        );
        assert!(
            printed.contains("033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027")
        );
    }

    /// RFC 7515 Appendix A.3: the JWS ES256 example. Its `s` begins `0xc5`,
    /// above `n/2`, so the strict verifier returns `HighS` and the lenient
    /// verifier accepts it (§9.5 carve-out for outside ES256 tokens).
    #[test]
    fn rfc7515_a3_es256_high_s_is_lenient_only() {
        let signing_input = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let pk = P256PublicKey::from_sec1(&h::<65>(
            "047fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445\
             c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad",
        ))
        .unwrap();
        let sig: [u8; 64] = h(
            "0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665\
             c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5",
        );
        assert_eq!(
            jose::es256_verify_strict(&pk, signing_input, &sig),
            Err(P256Error::HighS)
        );
        assert_eq!(jose::es256_verify_lenient(&pk, signing_input, &sig), Ok(()));
        let low = normalize_low_s(&sig).unwrap();
        assert_eq!(jose::es256_verify_strict(&pk, signing_input, &low), Ok(()));
    }

    /// `p` is the field prime. `02‖p` and `03‖p` carry an `x` outside the
    /// field; `02‖(p + 1)` likewise. None may decode (§9.5 point validation).
    #[test]
    fn from_sec1_rejects_x_at_or_above_field_prime() {
        const P_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        const P_PLUS_ONE_HEX: &str =
            "ffffffff00000001000000000000000000000001000000000000000000000000";
        for encoded in [
            format!("02{P_HEX}"),
            format!("03{P_HEX}"),
            format!("02{P_PLUS_ONE_HEX}"),
        ] {
            assert_eq!(
                P256PublicKey::from_sec1(&h::<33>(&encoded)),
                Err(P256Error::PointNotOnCurve),
                "{encoded}"
            );
        }
    }

    /// A valid leading byte at a length that byte does not allow is a length
    /// error for lengths other than 33 and 65, and a prefix error at the other
    /// of the two.
    #[test]
    fn from_sec1_rejects_valid_prefix_at_wrong_length() {
        for (prefix, len) in [
            (0x02u8, 32usize),
            (0x03, 34),
            (0x02, 65),
            (0x04, 33),
            (0x04, 64),
            (0x04, 66),
        ] {
            let mut encoded = vec![0x11u8; len];
            encoded[0] = prefix;
            let expected = if len == 33 || len == 65 {
                P256Error::InvalidPointPrefix { len, prefix }
            } else {
                P256Error::InvalidPointLength(len)
            };
            assert_eq!(
                P256PublicKey::from_sec1(&encoded),
                Err(expected),
                "{prefix:#04x} at {len}"
            );
        }
    }

    #[test]
    fn jose_es256_round_trip() {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[3u8; 32]);
        let input = b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0";
        let sig = jose::es256_sign(&key, input).unwrap();
        jose::es256_verify_strict(&key.public_key(), input, &sig).unwrap();
        jose::es256_verify_lenient(&key.public_key(), input, &sig).unwrap();
        assert_eq!(
            jose::es256_verify_strict(&key.public_key(), b"other", &sig),
            Err(P256Error::VerificationFailed)
        );
    }

    proptest! {
        /// §9.5: every signature this module emits is low-`s` and verifies
        /// strictly.
        #[test]
        fn every_signature_is_low_s(seed in any::<[u8; 32]>(), digest in any::<[u8; 32]>()) {
            let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &seed);
            let sig = sign_prehash_rfc6979(&key, &digest).unwrap();
            // Equal-length big-endian byte strings compare as integers.
            let half_n: [u8; 32] = h("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
            prop_assert!(sig[32..] <= half_n[..]);
            prop_assert_eq!(normalize_low_s(&sig).unwrap(), sig);
            prop_assert!(verify_prehash_strict(&key.public_key(), &digest, &sig).is_ok());
        }

        /// `from_sec1` rejects every leading byte outside {02, 03} at 33 bytes
        /// and outside {04} at 65 bytes, and every length other than 33 or 65.
        #[test]
        fn from_sec1_rejects_bad_prefixes_and_lengths(
            body in proptest::collection::vec(any::<u8>(), 65),
            prefix in prop::sample::select(vec![0x00u8, 0x05, 0x06, 0x07]),
            len in prop::sample::select(vec![0usize, 1, 32, 64, 66, 97]),
        ) {
            let mut c = body[..33].to_vec();
            c[0] = prefix;
            prop_assert_eq!(
                P256PublicKey::from_sec1(&c),
                Err(P256Error::InvalidPointPrefix { len: 33, prefix })
            );
            let mut u = body;
            u[0] = prefix;
            prop_assert_eq!(
                P256PublicKey::from_sec1(&u),
                Err(P256Error::InvalidPointPrefix { len: 65, prefix })
            );
            let wrong = vec![0x04u8; len];
            prop_assert_eq!(P256PublicKey::from_sec1(&wrong), Err(P256Error::InvalidPointLength(len)));
        }

        /// A 33-byte `02`/`03` point parses only to a key whose compressed
        /// encoding is the input (no second encoding of one key).
        #[test]
        fn compressed_parse_is_canonical(body in any::<[u8; 32]>(), odd in any::<bool>()) {
            let mut c = [0u8; 33];
            c[0] = if odd { 0x03 } else { 0x02 };
            c[1..].copy_from_slice(&body);
            if let Ok(pk) = P256PublicKey::from_sec1(&c) {
                prop_assert_eq!(pk.to_compressed(), c);
            }
        }
    }
}
