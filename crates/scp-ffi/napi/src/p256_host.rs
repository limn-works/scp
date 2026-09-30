//! P-256 primitives a TypeScript custody host calls so that it does not
//! re-implement the §9.10.4 scalar reduction or the §9.5 nonce.
//!
//! Each export wraps the function of the same name in
//! `scp_ffi_common::p256_host`, as the `PyO3` and `UniFFI` exports do, so the
//! argument order, the checks and the error codes (`SCP-VALID-7005` for a
//! wrong length, `SCP-CRYPTO-4001` for an out-of-range scalar or a failed
//! reduction or signature) are the same in every binding.
//!
//! Wiping is best-effort: the Rust side wipes the seed and scalar `Vec`s it
//! is handed and its own copies (`Zeroizing`), but napi-rs copies each
//! JavaScript array into a `Vec` and each returned `Vec` into a JavaScript
//! array without wiping either, and the returned scalar `Vec` is freed
//! unwiped. The host wipes its own arrays.

use napi::bindgen_prelude::BigInt;
use napi_derive::napi;
use scp_ffi_common::p256_host::{self as shared, P256HostError};
use zeroize::Zeroizing;

use crate::error::ScpNapiError;

fn napi_error(e: P256HostError) -> napi::Error {
    let code = e.code().to_owned();
    napi::Error::from(match e {
        P256HostError::Validation(message) => ScpNapiError::Validation { message, code },
        P256HostError::Crypto(message) => ScpNapiError::Crypto { message, code },
    })
}

/// Maps a 32-byte §9.10.4 `context_seed` (v1 or v2) to its P-256 pseudonym
/// scalar in `[1, n − 1]`.
///
/// FIPS 186-5 A.2.1, §9.10.4:
/// `HKDF-Expand(context_seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n − 1) + 1`,
/// with the label fixed inside the helper. Returns the 32-byte big-endian
/// scalar.
///
/// # Errors
///
/// `SCP-VALID-7005` when `context_seed` is not 32 bytes; `SCP-CRYPTO-4001` if
/// the reduction fails (unreachable for a 32-byte seed).
#[napi(js_name = "p256PseudonymScalar")]
pub fn p256_pseudonym_scalar(context_seed: Vec<u8>) -> napi::Result<Vec<u8>> {
    let context_seed = Zeroizing::new(context_seed);
    let scalar = shared::p256_pseudonym_scalar(&context_seed).map_err(napi_error)?;
    Ok(scalar.to_vec())
}

/// The 33-byte SEC1 compressed public key `d·G` of a 32-byte scalar.
///
/// # Errors
///
/// `SCP-VALID-7005` when `scalar` is not 32 bytes; `SCP-CRYPTO-4001` when it
/// is zero or not below `n`.
#[napi(js_name = "p256PublicKey")]
pub fn p256_public_key(scalar: Vec<u8>) -> napi::Result<Vec<u8>> {
    let scalar = Zeroizing::new(scalar);
    Ok(shared::p256_public_key(&scalar)
        .map_err(napi_error)?
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
#[napi(js_name = "p256SignPrehashRfc6979")]
pub fn p256_sign_prehash_rfc6979(scalar: Vec<u8>, digest: Vec<u8>) -> napi::Result<Vec<u8>> {
    let scalar = Zeroizing::new(scalar);
    Ok(shared::p256_sign_prehash_rfc6979(&scalar, &digest)
        .map_err(napi_error)?
        .to_vec())
}

/// The compressed pseudonym point of a §9.10.4 `context_seed`.
///
/// The 33-byte SEC1 point of a 32-byte `context_seed` (v1 or v2), for a
/// host that computes the seed itself. No
/// scalar reaches the host.
///
/// # Errors
///
/// `SCP-VALID-7005` when `context_seed` is not 32 bytes.
#[napi(js_name = "p256PseudonymPoint")]
pub fn p256_pseudonym_point(context_seed: Vec<u8>) -> napi::Result<Vec<u8>> {
    let context_seed = Zeroizing::new(context_seed);
    Ok(shared::p256_pseudonym_point(&context_seed)
        .map_err(napi_error)?
        .to_vec())
}

/// The compressed pseudonym point a software custody derives (§9.10.4.A).
///
/// From the 32-byte identity key material `ikm`: the v1 point for
/// `context_id` when `epoch` is omitted, the v2 point at `epoch` otherwise.
/// `epoch` is a `bigint` so the full unsigned 64-bit range crosses exactly.
/// No scalar reaches the host.
///
/// # Errors
///
/// `SCP-VALID-7005` when `ikm` is not 32 bytes, or `epoch` is negative or
/// wider than 64 bits.
#[napi(js_name = "p256SoftwarePseudonymPoint")]
pub fn p256_software_pseudonym_point(
    ikm: Vec<u8>,
    context_id: Vec<u8>,
    epoch: Option<BigInt>,
) -> napi::Result<Vec<u8>> {
    let ikm = Zeroizing::new(ikm);
    let epoch = epoch.as_ref().map(epoch_u64).transpose()?;
    Ok(
        shared::p256_software_pseudonym_point(&ikm, &context_id, epoch)
            .map_err(napi_error)?
            .to_vec(),
    )
}

fn epoch_u64(epoch: &BigInt) -> napi::Result<u64> {
    let (signed, value, lossless) = epoch.get_u64();
    if signed || !lossless {
        return Err(napi_error(P256HostError::Validation(
            "epoch must be a non-negative integer that fits in an unsigned 64-bit integer"
                .to_owned(),
        )));
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// §25.19 Vector 30: the spec's `context_seed_v1` maps to the spec's v1
    /// point through the napi exports.
    #[test]
    fn exports_reproduce_vector_30_v1_point() {
        let seed = hex::decode("47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b")
            .unwrap();
        let scalar = p256_pseudonym_scalar(seed).expect("scalar");
        assert_eq!(
            hex::encode(p256_public_key(scalar).expect("point")),
            "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72"
        );
    }

    /// An epoch of 2^64, wider than 64 bits, is `SCP-VALID-7005` rather than
    /// the truncated epoch 0. (The TypeScript suite covers a negative epoch.)
    #[test]
    fn software_point_rejects_an_epoch_wider_than_64_bits() {
        let wide = BigInt {
            sign_bit: false,
            words: vec![0, 1],
        };
        let err = p256_software_pseudonym_point(vec![1; 32], b"ctx".to_vec(), Some(wide))
            .expect_err("epoch 2^64");
        assert!(err.reason.contains("SCP-VALID-7005"), "{}", err.reason);
    }

    #[test]
    fn exports_carry_the_shared_error_codes() {
        let err = p256_pseudonym_scalar(vec![0; 31]).expect_err("31-byte seed");
        assert!(err.reason.contains("SCP-VALID-7005"), "{}", err.reason);
        let err = p256_public_key(vec![0; 32]).expect_err("zero scalar");
        assert!(err.reason.contains("SCP-CRYPTO-4001"), "{}", err.reason);
        let err = p256_sign_prehash_rfc6979(vec![1; 32], vec![0; 12]).expect_err("12-byte digest");
        assert!(err.reason.contains("SCP-VALID-7005"), "{}", err.reason);
    }
}
