//! P-256 pseudonym point helpers every custody host calls so that no host
//! re-implements the §9.10.4 derivation (§9.10.4.A).
//!
//! Each helper returns the 33-byte SEC1 compressed pseudonym point and
//! nothing else: the private scalar exists only inside the derivation and is
//! wiped on drop, so no scalar reaches a host.
//!
//! - [`p256_pseudonym_point`] maps a `context_seed` the host computed (inside
//!   a keystore, say) to the point;
//! - [`p256_software_pseudonym_point`] runs the whole software recipe from the
//!   32-byte identity key material, so no host hand-writes the HKDF and HMAC
//!   steps.
//!
//! The `PyO3`, napi-rs and `UniFFI` exports of the same names are thin
//! wrappers over these functions, so the three bridges share one argument
//! order, one set of checks and one error code: `SCP-VALID-7005` for an input
//! of the wrong length.

use scp_crypto::pseudonym::{PseudonymVersion, derive_pseudonym, pseudonym_from_context_seed};
use zeroize::Zeroizing;

use crate::error_codes as codes;

/// A rejected P-256 host helper call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P256HostError {
    /// An input had the wrong length (`SCP-VALID-7005`).
    Validation(String),
}

impl P256HostError {
    /// The error code a bridge reports for this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => codes::VALID_7005,
        }
    }

    /// The error text, which never carries key material.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Validation(m) => m,
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

/// The compressed pseudonym point of a §9.10.4 `context_seed`.
///
/// The 33-byte SEC1 point of a 32-byte `context_seed` (v1 or v2): the scalar
/// `HKDF-Expand(context_seed, "SCP-PSEUDONYM-P256-V1", 48) mod (n − 1) + 1`
/// (FIPS 186-5 A.2.1, with the label fixed inside `scp-crypto`), then `d·G`.
/// The scalar never leaves this function and is wiped on drop.
///
/// # Errors
///
/// [`P256HostError::Validation`] when `context_seed` is not 32 bytes.
pub fn p256_pseudonym_point(context_seed: &[u8]) -> Result<[u8; 33], P256HostError> {
    let seed = exact_32("context_seed", context_seed)?;
    Ok(pseudonym_from_context_seed(&seed).to_compressed())
}

/// The compressed pseudonym point a software custody derives (§9.10.4.A).
///
/// From the 32-byte identity key material `ikm`:
/// `pseudonym_secret = HKDF-SHA256(ikm, "scp-pseudonym-secret-v1")`, the v1
/// `context_seed` for `context_id` when `epoch` is `None` and the v2 seed at
/// `epoch` otherwise (§9.10.4.1), then the point. This function's copy of
/// `ikm` and every intermediate buffer `scp-crypto` owns are wiped on drop;
/// the hash crates' internal state is not, so wiping is best effort.
///
/// # Errors
///
/// [`P256HostError::Validation`] when `ikm` is not 32 bytes.
pub fn p256_software_pseudonym_point(
    ikm: &[u8],
    context_id: &[u8],
    epoch: Option<u64>,
) -> Result<[u8; 33], P256HostError> {
    let ikm = exact_32("ikm", ikm)?;
    let version = epoch.map_or(PseudonymVersion::Static, |epoch| {
        PseudonymVersion::Rotatable { epoch }
    });
    Ok(derive_pseudonym(&ikm, context_id, version).to_compressed())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// §25.19 Vectors 30 and 31: the identity scalar (the software `ikm`)
    /// with `context_id` "context-alpha" gives the spec's v1 point, and at
    /// epoch 1 the spec's v2 point; the spec's `context_seed_v1` gives the v1
    /// point through [`p256_pseudonym_point`].
    #[test]
    fn point_helpers_reproduce_spec_25_19_vectors_30_and_31() {
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
            let ctx = b"context-alpha";
            assert_eq!(
                hex::encode(p256_software_pseudonym_point(&h(ikm), ctx, None).unwrap()),
                v1
            );
            assert_eq!(
                hex::encode(p256_software_pseudonym_point(&h(ikm), ctx, Some(1)).unwrap()),
                v2
            );
            assert_eq!(hex::encode(p256_pseudonym_point(&h(seed_v1)).unwrap()), v1);
        }
    }

    /// A seed or `ikm` of any length but 32 is `SCP-VALID-7005`.
    #[test]
    fn point_helpers_reject_a_wrong_length_input() {
        for len in [0, 31, 33] {
            let err = p256_pseudonym_point(&vec![1; len]).expect_err("wrong-length seed");
            assert!(matches!(err, P256HostError::Validation(_)), "{err:?}");
            assert_eq!(err.code(), "SCP-VALID-7005");
            let err = p256_software_pseudonym_point(&vec![1; len], b"ctx", None)
                .expect_err("wrong-length ikm");
            assert!(matches!(err, P256HostError::Validation(_)), "{err:?}");
            assert_eq!(err.code(), "SCP-VALID-7005");
        }
    }
}
