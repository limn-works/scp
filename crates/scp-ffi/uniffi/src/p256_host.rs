//! P-256 pseudonym point helpers the Swift and Kotlin custody adapters call
//! so that no host re-implements the §9.10.4 derivation (§9.10.4.A).
//!
//! Each export wraps the function of the same name in
//! `scp_ffi_common::p256_host`, which the `PyO3` and napi-rs exports wrap too,
//! and returns the 33-byte compressed point: no scalar reaches the host.
//!
//! Wiping is best-effort: the Rust side wipes the seed and `ikm` `Vec`s it is
//! handed (`Zeroizing`), but uniffi's lift and `rustbuffer_free` do not wipe
//! the transfer buffer that carries them across the boundary. The host wipes
//! its own arrays.

use scp_ffi_common::p256_host::{self as shared, P256HostError};
use zeroize::Zeroizing;

use crate::bridge::ScpError;

fn scp_error(e: P256HostError) -> ScpError {
    let code = e.code().to_owned();
    match e {
        P256HostError::Validation(msg) => ScpError::Validation { msg, code },
    }
}

/// The compressed pseudonym point of a §9.10.4 `context_seed`.
///
/// The 33-byte SEC1 point of a 32-byte `context_seed` (v1 or v2), for a
/// host that computes the seed inside its keystore. No scalar reaches the
/// host.
///
/// # Errors
///
/// `SCP-VALID-7005` when `context_seed` is not 32 bytes.
#[uniffi::export]
pub fn p256_pseudonym_point(context_seed: Vec<u8>) -> Result<Vec<u8>, ScpError> {
    let context_seed = Zeroizing::new(context_seed);
    Ok(shared::p256_pseudonym_point(&context_seed)
        .map_err(scp_error)?
        .to_vec())
}

/// The compressed pseudonym point a software custody derives (§9.10.4.A).
///
/// From the 32-byte identity key material `ikm`: the v1 point for
/// `context_id` when `epoch` is `None`, the v2 point at `epoch` otherwise. No
/// scalar reaches the host.
///
/// # Errors
///
/// `SCP-VALID-7005` when `ikm` is not 32 bytes.
#[uniffi::export]
pub fn p256_software_pseudonym_point(
    ikm: Vec<u8>,
    context_id: Vec<u8>,
    epoch: Option<u64>,
) -> Result<Vec<u8>, ScpError> {
    let ikm = Zeroizing::new(ikm);
    Ok(
        shared::p256_software_pseudonym_point(&ikm, &context_id, epoch)
            .map_err(scp_error)?
            .to_vec(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// §25.19 Vectors 30 and 31 through the exports: each `identity_scalar`
    /// (the software `ikm`) over "context-alpha" gives the spec's v1 point,
    /// and at epoch 1 its v2 point; each `context_seed_v1` gives the v1
    /// point.
    #[test]
    fn point_exports_reproduce_spec_25_19_vectors_30_and_31() {
        for (ikm, seed_v1, v1, v2) in [
            (
                "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
                "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
                "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
                "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
            ),
            (
                "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
                "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
                "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
                "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
            ),
        ] {
            let ctx = b"context-alpha".to_vec();
            let point = p256_software_pseudonym_point(h(ikm), ctx.clone(), None).unwrap();
            assert_eq!(hex::encode(point), v1);
            let point = p256_software_pseudonym_point(h(ikm), ctx, Some(1)).unwrap();
            assert_eq!(hex::encode(point), v2);
            assert_eq!(hex::encode(p256_pseudonym_point(h(seed_v1)).unwrap()), v1);
        }
    }

    /// A wrong-length seed or `ikm` is `ScpError::Validation` carrying
    /// `SCP-VALID-7005`.
    #[test]
    fn point_exports_report_a_wrong_length_input_as_valid_7005() {
        use scp_ffi_common::error_codes as codes;
        let err = p256_pseudonym_point(vec![0; 31]).expect_err("31-byte seed");
        assert!(
            matches!(&err, ScpError::Validation { code, .. } if code == codes::VALID_7005),
            "{err:?}"
        );
        let err = p256_software_pseudonym_point(vec![0; 33], b"ctx".to_vec(), None)
            .expect_err("33-byte ikm");
        assert!(
            matches!(&err, ScpError::Validation { code, .. } if code == codes::VALID_7005),
            "{err:?}"
        );
    }
}
