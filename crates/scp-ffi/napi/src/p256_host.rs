//! P-256 pseudonym point helpers a TypeScript custody host calls so that it
//! does not re-implement the §9.10.4 derivation (§9.10.4.A).
//!
//! Each export wraps the function of the same name in
//! `scp_ffi_common::p256_host`, as the `PyO3` and `UniFFI` exports do, so the
//! argument order, the checks and the error code (`SCP-VALID-7005` for a
//! wrong length) are the same in every binding. Each returns the 33-byte
//! compressed point: no scalar reaches the host.
//!
//! Wiping is best-effort: the Rust side wipes the seed and `ikm` `Vec`s it
//! is handed (`Zeroizing`), but napi-rs copies each JavaScript array into a
//! `Vec` without wiping the source. The host wipes its own arrays.

use napi::bindgen_prelude::BigInt;
use napi_derive::napi;
use scp_ffi_common::p256_host::{self as shared, P256HostError};
use zeroize::Zeroizing;

use crate::error::ScpNapiError;

fn napi_error(e: P256HostError) -> napi::Error {
    let code = e.code().to_owned();
    napi::Error::from(match e {
        P256HostError::Validation(message) => ScpNapiError::Validation { message, code },
    })
}

/// The compressed pseudonym point of a §9.10.4 `context_seed`.
///
/// The 33-byte SEC1 point of a 32-byte `context_seed` (v1 or v2), for a
/// host that computes the seed itself. No scalar reaches the host.
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

    /// §25.19 Vector 30 through the exports: the `identity_scalar` over
    /// "context-alpha" gives the spec's v1 point, and at epoch 1 its v2
    /// point (passed as a `bigint`); `context_seed_v1` gives the v1 point.
    #[test]
    fn point_exports_reproduce_spec_25_19_vector_30() {
        let ikm = hex::decode("32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64")
            .unwrap();
        let seed_v1 =
            hex::decode("47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b")
                .unwrap();
        let v1 = "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72";
        let v2 = "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479";
        let ctx = b"context-alpha".to_vec();
        let point = p256_software_pseudonym_point(ikm.clone(), ctx.clone(), None).unwrap();
        assert_eq!(hex::encode(point), v1);
        let one = BigInt::from(1u64);
        let point = p256_software_pseudonym_point(ikm, ctx, Some(one)).unwrap();
        assert_eq!(hex::encode(point), v2);
        assert_eq!(hex::encode(p256_pseudonym_point(seed_v1).unwrap()), v1);
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
    fn point_exports_carry_valid_7005_for_a_wrong_length_input() {
        let err = p256_pseudonym_point(vec![0; 31]).expect_err("31-byte seed");
        assert!(err.reason.contains("SCP-VALID-7005"), "{}", err.reason);
        let err = p256_software_pseudonym_point(vec![0; 33], b"ctx".to_vec(), None)
            .expect_err("33-byte ikm");
        assert!(err.reason.contains("SCP-VALID-7005"), "{}", err.reason);
    }
}
