//! P-256 primitives the Swift and Kotlin custody adapters call so that no host
//! re-implements the §9.10.4 scalar reduction or the §9.5 nonce.
//!
//! A host pseudonym key is a 32-byte P-256 scalar the host stores in its own
//! custody. The host computes the §9.10.4 `context_seed` (HMAC-SHA-256 under
//! its `pseudonym_secret`, which on hardware custody never leaves the secure
//! boundary, §9.10.4.A), then:
//!
//! 1. [`p256_seed_to_scalar`] maps the seed to the scalar (FIPS 186-5 A.2.1,
//!    constant-time `crypto-bigint` reduction in `scp-crypto`);
//! 2. [`p256_public_key`] gives the 33-byte compressed point it returns from
//!    `derive_pseudonym` and `get_public_key`;
//! 3. [`p256_sign_prehash_rfc6979`] signs a 32-byte digest with RFC 6979
//!    deterministic nonces and returns the low-`s` `r || s` (§9.5), which the
//!    bridge then verifies strictly.
//!
//! Each export wraps the function of the same name in
//! `scp_ffi_common::p256_host`, which the `PyO3` and napi-rs exports wrap too.
//!
//! The scalar crosses the FFI boundary because the host is its custodian.
//! Wiping is best-effort: the Rust side wipes the seed and scalar `Vec`s it is
//! handed and its own copies (`Zeroizing`), but uniffi's lift and
//! `rustbuffer_free` do not wipe the transfer buffers that carry the seed and
//! the scalar across the boundary, in either direction, and the returned
//! scalar `Vec` is freed by uniffi unwiped. The host wipes its own arrays.

use scp_ffi_common::p256_host::{self as shared, P256HostError};
use zeroize::Zeroizing;

use crate::bridge::ScpError;

fn scp_error(e: P256HostError) -> ScpError {
    let code = e.code().to_owned();
    match e {
        P256HostError::Validation(msg) => ScpError::Validation { msg, code },
        P256HostError::Crypto(msg) => ScpError::Crypto { msg, code },
    }
}

/// Maps a 32-byte seed to a P-256 private scalar in `[1, n − 1]` under `label`.
///
/// FIPS 186-5 A.2.1, §9.10.4: `HKDF-Expand(seed, label, 48) mod (n − 1) + 1`.
/// Returns the 32-byte big-endian scalar. For a pseudonym the label is
/// `"SCP-PSEUDONYM-P256-V1"` and the seed the §9.10.4 `context_seed`.
///
/// # Errors
///
/// `SCP-VALID-7005` when `seed` is not 32 bytes; `SCP-CRYPTO-4001` if the
/// reduction fails (unreachable for a 32-byte seed).
#[uniffi::export]
pub fn p256_seed_to_scalar(label: Vec<u8>, seed: Vec<u8>) -> Result<Vec<u8>, ScpError> {
    let seed = Zeroizing::new(seed);
    let scalar = shared::p256_seed_to_scalar(&label, &seed).map_err(scp_error)?;
    Ok(scalar.to_vec())
}

/// The 33-byte SEC1 compressed public key `d·G` of a 32-byte scalar.
///
/// # Errors
///
/// `SCP-VALID-7005` when `scalar` is not 32 bytes; `SCP-CRYPTO-4001` when it
/// is zero or not below `n`.
#[uniffi::export]
pub fn p256_public_key(scalar: Vec<u8>) -> Result<Vec<u8>, ScpError> {
    let scalar = Zeroizing::new(scalar);
    Ok(shared::p256_public_key(&scalar)
        .map_err(scp_error)?
        .to_vec())
}

/// Signs a 32-byte digest with the scalar: RFC 6979 deterministic nonce
/// (`h1 = digest`), low-`s` normalized, returned as the 64-byte `r || s`
/// (§9.5).
///
/// # Errors
///
/// `SCP-VALID-7005` when `scalar` or `digest` is not 32 bytes;
/// `SCP-CRYPTO-4001` when the scalar is out of range or signing fails.
#[uniffi::export]
pub fn p256_sign_prehash_rfc6979(scalar: Vec<u8>, digest: Vec<u8>) -> Result<Vec<u8>, ScpError> {
    let scalar = Zeroizing::new(scalar);
    Ok(shared::p256_sign_prehash_rfc6979(&scalar, &digest)
        .map_err(scp_error)?
        .to_vec())
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

    /// RFC 6979 A.2.5 (P-256, SHA-256, message "sample"): the export uses the
    /// RFC's deterministic nonce (its `r` reproduces), returns the low-`s`
    /// form of the RFC's high `s` (the two sum to `n`), and signs the same
    /// digest to the same bytes every time.
    #[test]
    fn sign_export_reproduces_rfc6979_a25_low_s() {
        let x = h("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let digest = {
            use sha2::Digest;
            sha2::Sha256::digest(b"sample").to_vec()
        };
        let sig = p256_sign_prehash_rfc6979(x.clone(), digest.clone()).expect("sign");
        assert_eq!(
            hex::encode(&sig[..32]),
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        );
        let rfc_s = h("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
        assert_eq!(hex::encode(add_be(&sig[32..], &rfc_s)), N);
        let point =
            scp_crypto::p256::P256PublicKey::from_sec1(&p256_public_key(x.clone()).unwrap())
                .unwrap();
        let digest32: [u8; 32] = digest.as_slice().try_into().unwrap();
        scp_crypto::p256::verify_prehash_strict(&point, &digest32, &sig).expect("strict, low-s");
        assert_eq!(p256_sign_prehash_rfc6979(x, digest).expect("sign"), sig);
    }

    /// §25.19 Vector 30: the spec's `context_seed_v1` maps through the
    /// exported reduction to the spec's v1 point.
    #[test]
    fn seed_export_reproduces_vector_30_v1_point() {
        let seed = h("47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b");
        let scalar = p256_seed_to_scalar(b"SCP-PSEUDONYM-P256-V1".to_vec(), seed).expect("scalar");
        assert_eq!(
            hex::encode(p256_public_key(scalar).expect("point")),
            "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72"
        );
    }

    #[test]
    fn exports_reject_malformed_input() {
        let err = p256_seed_to_scalar(b"L".to_vec(), vec![0; 31]).expect_err("31-byte seed");
        assert!(matches!(err, ScpError::Validation { .. }), "{err:?}");
        let err = p256_public_key(vec![0; 32]).expect_err("zero scalar");
        assert!(matches!(err, ScpError::Crypto { .. }), "{err:?}");
        let err = p256_public_key(vec![0xff; 32]).expect_err("scalar ≥ n");
        assert!(matches!(err, ScpError::Crypto { .. }), "{err:?}");
        let err = p256_sign_prehash_rfc6979(vec![1; 32], vec![0; 12]).expect_err("12-byte digest");
        assert!(matches!(err, ScpError::Validation { .. }), "{err:?}");
    }
}
