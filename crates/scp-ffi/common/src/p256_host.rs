//! P-256 primitives every custody host calls so that no host re-implements
//! the §9.10.4 scalar reduction or the §9.5 nonce.
//!
//! A host pseudonym key is a 32-byte P-256 scalar the host stores in its own
//! custody. The host computes the §9.10.4 `context_seed` (HMAC-SHA-256 under
//! its `pseudonym_secret`, which on hardware custody never leaves the secure
//! boundary, §9.10.4.A), then:
//!
//! 1. [`p256_pseudonym_scalar`] maps the seed to the scalar under the fixed
//!    `SCP-PSEUDONYM-P256-V1` label (FIPS 186-5 A.2.1, constant-time
//!    `crypto-bigint` reduction in `scp-crypto`), so no host passes the label;
//! 2. [`p256_public_key`] gives the 33-byte compressed point it returns from
//!    `derive_pseudonym` and `get_public_key`;
//! 3. [`p256_sign_prehash_rfc6979`] signs a 32-byte digest with RFC 6979
//!    deterministic nonces and returns the low-`s` `r || s` (§9.5), which the
//!    bridge then verifies strictly.
//!
//! The `PyO3`, napi-rs and `UniFFI` exports of the same names are thin
//! wrappers over these functions, so the three bridges share one argument
//! order, one set of checks and one pair of error codes:
//! `SCP-VALID-7005` for an input of the wrong length and `SCP-CRYPTO-4001`
//! for a scalar out of range or a failed reduction or signature.
//!
//! Every scalar copy made here is wiped on drop (`Zeroizing`); the caller
//! wipes the buffers it owns.

use scp_crypto::p256::{P256SigningKey, seed_to_scalar, sign_prehash_rfc6979};
use scp_crypto::pseudonym::PSEUDONYM_SCALAR_LABEL;
use zeroize::Zeroizing;

use crate::error_codes as codes;

/// A rejected [`p256_pseudonym_scalar`], [`p256_public_key`] or
/// [`p256_sign_prehash_rfc6979`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P256HostError {
    /// An input had the wrong length (`SCP-VALID-7005`).
    Validation(String),
    /// A scalar was zero or not below `n`, or the reduction or signature
    /// failed (`SCP-CRYPTO-4001`).
    Crypto(String),
}

impl P256HostError {
    /// The error code a bridge reports for this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => codes::VALID_7005,
            Self::Crypto(_) => codes::CRYPTO_4001,
        }
    }

    /// The error text, which never carries key material.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Validation(m) | Self::Crypto(m) => m,
        }
    }
}

impl std::fmt::Display for P256HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for P256HostError {}

fn exact_32(what: &str, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, P256HostError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        P256HostError::Validation(format!("{what} must be 32 bytes, got {}", bytes.len()))
    })?;
    Ok(Zeroizing::new(array))
}

fn signing_key(scalar: &[u8]) -> Result<P256SigningKey, P256HostError> {
    let scalar = exact_32("P-256 scalar", scalar)?;
    P256SigningKey::from_scalar_bytes(&scalar)
        .map_err(|e| P256HostError::Crypto(format!("invalid P-256 scalar: {e}")))
}

/// Maps a 32-byte §9.10.4 `context_seed` (v1 or v2) to its P-256 pseudonym
/// scalar in `[1, n − 1]`.
///
/// FIPS 186-5 A.2.1, §9.10.4:
/// `HKDF-Expand(context_seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n − 1) + 1`.
/// The label is fixed here ([`PSEUDONYM_SCALAR_LABEL`]), so a host cannot
/// derive a pseudonym under a mistyped one. Returns the 32-byte big-endian
/// scalar.
///
/// # Errors
///
/// [`P256HostError::Validation`] when `context_seed` is not 32 bytes;
/// [`P256HostError::Crypto`] if the reduction fails (unreachable for a
/// 32-byte seed).
pub fn p256_pseudonym_scalar(context_seed: &[u8]) -> Result<Zeroizing<[u8; 32]>, P256HostError> {
    let seed = exact_32("context_seed", context_seed)?;
    let scalar = seed_to_scalar(PSEUDONYM_SCALAR_LABEL, &seed)
        .map_err(|e| P256HostError::Crypto(format!("seed_to_scalar failed: {e}")))?;
    Ok(P256SigningKey::from_nonzero_scalar(scalar).to_scalar_bytes())
}

/// The 33-byte SEC1 compressed public key `d·G` of a 32-byte scalar.
///
/// # Errors
///
/// [`P256HostError::Validation`] when `scalar` is not 32 bytes;
/// [`P256HostError::Crypto`] when it is zero or not below `n`.
pub fn p256_public_key(scalar: &[u8]) -> Result<[u8; 33], P256HostError> {
    Ok(signing_key(scalar)?.public_key().to_compressed())
}

/// Signs a 32-byte digest with the scalar: RFC 6979 deterministic nonce
/// (`h1 = digest`), low-`s` normalized, returned as the 64-byte `r || s`
/// (§9.5).
///
/// # Errors
///
/// [`P256HostError::Validation`] when `scalar` or `digest` is not 32 bytes;
/// [`P256HostError::Crypto`] when the scalar is out of range or signing
/// fails.
pub fn p256_sign_prehash_rfc6979(scalar: &[u8], digest: &[u8]) -> Result<[u8; 64], P256HostError> {
    let key = signing_key(scalar)?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| {
        P256HostError::Validation(format!("digest must be 32 bytes, got {}", digest.len()))
    })?;
    sign_prehash_rfc6979(&key, &digest)
        .map_err(|e| P256HostError::Crypto(format!("P-256 signing failed: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// P-256 group order `n` (SEC 2 / FIPS 186-5).
    const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// Big-endian `a + b mod 2^256`.
    fn add_be(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
            out[i] = u8::try_from(sum & 0xff).unwrap();
            carry = sum >> 8;
        }
        out
    }

    /// RFC 6979 A.2.5 (P-256, SHA-256, message "sample"): the RFC's
    /// deterministic nonce (its `r` reproduces), the low-`s` form of the
    /// RFC's high `s` (the two sum to `n`), strict verification, and the same
    /// bytes on every call.
    #[test]
    fn sign_reproduces_rfc6979_a25_low_s() {
        use sha2::Digest;
        let x = h("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let digest: [u8; 32] = sha2::Sha256::digest(b"sample").into();
        let sig = p256_sign_prehash_rfc6979(&x, &digest).expect("sign");
        assert_eq!(
            hex::encode(&sig[..32]),
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        );
        let rfc_s = h("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
        assert_eq!(hex::encode(add_be(&sig[32..], &rfc_s)), N);
        let point =
            scp_crypto::p256::P256PublicKey::from_sec1(&p256_public_key(&x).unwrap()).unwrap();
        scp_crypto::p256::verify_prehash_strict(&point, &digest, &sig).expect("strict, low-s");
        assert_eq!(p256_sign_prehash_rfc6979(&x, &digest).expect("sign"), sig);
    }

    /// §25.19 Vectors 30 and 31: each spec `context_seed_v1` maps through the
    /// fixed-label reduction to the spec's v1 point.
    #[test]
    fn pseudonym_scalar_reproduces_vectors_30_and_31_v1_points() {
        for (seed, point) in [
            (
                "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
                "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
            ),
            (
                "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
                "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
            ),
        ] {
            let scalar = p256_pseudonym_scalar(&h(seed)).expect("scalar");
            assert_eq!(
                hex::encode(p256_public_key(scalar.as_slice()).expect("point")),
                point
            );
        }
    }

    #[test]
    fn malformed_input_is_rejected_with_its_code() {
        let err = p256_pseudonym_scalar(&[0; 31]).expect_err("31-byte seed");
        assert!(matches!(err, P256HostError::Validation(_)), "{err:?}");
        assert_eq!(err.code(), "SCP-VALID-7005");
        let err = p256_public_key(&[0; 32]).expect_err("zero scalar");
        assert!(matches!(err, P256HostError::Crypto(_)), "{err:?}");
        assert_eq!(err.code(), "SCP-CRYPTO-4001");
        let err = p256_public_key(&[0xff; 32]).expect_err("scalar ≥ n");
        assert_eq!(err.code(), "SCP-CRYPTO-4001");
        let err = p256_public_key(&[1; 33]).expect_err("33-byte scalar");
        assert_eq!(err.code(), "SCP-VALID-7005");
        let err = p256_sign_prehash_rfc6979(&[1; 32], &[0; 12]).expect_err("12-byte digest");
        assert_eq!(err.code(), "SCP-VALID-7005");
        let err = p256_sign_prehash_rfc6979(&[0; 32], &[0; 32]).expect_err("zero scalar");
        assert_eq!(err.code(), "SCP-CRYPTO-4001");
    }
}
