//! Shared pseudonym secret derivation and per-context P-256 keypair derivation
//! (§9.10.4, §9.10.4.A, §9.10.4.1).
//!
//! This is the single wasm-safe source of the software-custody pseudonym
//! derivation. Every native `KeyCustody` backend in `scp-platform` and the
//! in-browser client (ADR-057 Option A) call it, so software pseudonyms agree
//! byte-for-byte across platforms (§25.19 vectors 30/31).
//!
//! ```text
//! pseudonym_secret = HKDF-SHA256(ikm, salt = "scp-pseudonym-secret-v1", info = "", L = 32)
//! context_seed     = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")              // v1
//!                  = HMAC-SHA256(pseudonym_secret, context_id || BE64(epoch) || "scp-pseudonym-v2") // v2
//! d                = seed_to_scalar("SCP-PSEUDONYM-P256-V1", context_seed)   // FIPS 186-5 A.2.1
//! context_pseudonym    = compressed(d·G)                                     // 33 bytes
//! pseudonym_routing_id = SHA-256("scp-pseudonym-routing-v1:" || context_pseudonym)
//! ```
//!
//! `ikm` is the 32-byte identity private key material. The spec's target is the
//! P-256 private scalar; until the identity key moves to P-256 (S12), native
//! software custody passes the Ed25519 seed and the browser passes its per-context
//! MLS key's private bytes (§9.10.4.A interim). The algorithm is the same either
//! way; only the key material differs.
//!
//! CRITICAL PRIVACY REQUIREMENT (§9.10.4.A): the HMAC key is derived from
//! private key bytes, never from a public key. A public-key-keyed derivation
//! would be a membership enumeration oracle.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::p256::{COMPRESSED_POINT_LEN, P256Error, P256SigningKey};

/// Salt for HKDF-SHA-256 pseudonym secret derivation (§9.10.4.A).
const PSEUDONYM_SECRET_SALT: &[u8] = b"scp-pseudonym-secret-v1";

/// Domain separator for v1 (static) pseudonym derivation (§9.10.4).
const PSEUDONYM_V1_DOMAIN: &[u8] = b"scp-pseudonym";

/// Domain separator for v2 (rotatable) pseudonym derivation (§9.10.4.1).
const PSEUDONYM_V2_DOMAIN: &[u8] = b"scp-pseudonym-v2";

/// HKDF-Expand label of the seed-to-scalar step (§9.10.4).
pub const PSEUDONYM_SCALAR_LABEL: &[u8] = b"SCP-PSEUDONYM-P256-V1";

/// Prefix of the pseudonym routing-id hash (§9.10.4, registered in §9.18.2).
pub const PSEUDONYM_ROUTING_PREFIX: &[u8] = b"scp-pseudonym-routing-v1:";

/// Derives the `pseudonym_secret` from 32 bytes of private key material via
/// HKDF-SHA-256 (§9.10.4.A).
///
/// # Panics
///
/// Never in practice. The single `assert!` guards an infallible invariant:
/// HKDF-Expand with a 32-byte output length cannot fail (32 ≤ 255 · `HashLen`).
#[must_use]
pub fn derive_pseudonym_secret(ikm: &Zeroizing<[u8; 32]>) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PSEUDONYM_SECRET_SALT), ikm.as_ref());
    let mut secret = Zeroizing::new([0u8; 32]);
    assert!(
        hk.expand(b"", secret.as_mut()).is_ok(),
        "HKDF-Expand with 32-byte output is infallible"
    );
    secret
}

/// Computes the per-context `context_seed` (§9.10.4 v1, §9.10.4.1 v2).
///
/// # Panics
///
/// Never in practice: HMAC-SHA-256 accepts a key of any length.
fn context_seed(
    pseudonym_secret: &Zeroizing<[u8; 32]>,
    context_id: &[u8],
    epoch: Option<u64>,
) -> Zeroizing<[u8; 32]> {
    let mac_result = <Hmac<Sha256> as Mac>::new_from_slice(pseudonym_secret.as_slice());
    assert!(mac_result.is_ok(), "HMAC-SHA256 accepts keys of any length");
    let mut seed = Zeroizing::new([0u8; 32]);
    if let Ok(mut mac) = mac_result {
        mac.update(context_id);
        match epoch {
            None => mac.update(PSEUDONYM_V1_DOMAIN),
            Some(e) => {
                mac.update(&e.to_be_bytes());
                mac.update(PSEUDONYM_V2_DOMAIN);
            }
        }
        // Copy out and wipe via `[u8]: Zeroize`, which holds whether or not
        // `generic-array`'s `zeroize` feature is unified in.
        let mut hmac_bytes = mac.finalize().into_bytes();
        seed.copy_from_slice(&hmac_bytes[..32]);
        hmac_bytes.as_mut_slice().zeroize();
    }
    seed
}

/// Derives the per-context P-256 pseudonym key from identity private key
/// material (`ikm`), for `epoch = None` (v1, static) or `Some(e)` (v2,
/// rotatable).
///
/// # Errors
///
/// [`P256Error::ScalarDerivationFailed`], unreachable for a 32-byte seed; it
/// is propagated rather than papered over.
pub fn derive_pseudonym_keypair(
    ikm: &Zeroizing<[u8; 32]>,
    context_id: &[u8],
    epoch: Option<u64>,
) -> Result<P256SigningKey, P256Error> {
    let secret = derive_pseudonym_secret(ikm);
    let seed = context_seed(&secret, context_id, epoch);
    P256SigningKey::from_seed(PSEUDONYM_SCALAR_LABEL, &seed)
}

/// The 32-byte routing id every routing field carries for a pseudonym
/// (§9.10.4): `SHA-256("scp-pseudonym-routing-v1:" || context_pseudonym)`.
#[must_use]
pub fn pseudonym_routing_id(context_pseudonym: &[u8; COMPRESSED_POINT_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PSEUDONYM_ROUTING_PREFIX);
    hasher.update(context_pseudonym);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// §25.19 Vectors 30 and 31. The identity seed maps to the identity P-256
    /// scalar under the §25.2 label, and that scalar is the `ikm`.
    /// `context_id` = `"context-alpha"`, v2 `epoch` = 1. Every value is copied
    /// from `.docs/specs/25-test-vectors.md` §25.19.
    #[test]
    fn spec_25_19_vectors_30_31() {
        struct V {
            seed: &'static str,
            scalar: &'static str,
            secret: &'static str,
            seed_v1: &'static str,
            pub_v1: &'static str,
            seed_v2: &'static str,
            pub_v2: &'static str,
        }
        let vectors = [
            V {
                seed: "0101010101010101010101010101010101010101010101010101010101010101",
                scalar: "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
                secret: "b88e781bb954a6681abc9016f8f69939f0e624311aeaa7e8f1b145857f58de82",
                seed_v1: "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
                pub_v1: "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
                seed_v2: "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
                pub_v2: "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
            },
            V {
                seed: "9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                scalar: "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
                secret: "17ef25ad3e5be8adad38c4c5a1c68d3daca80015e81bdcae2ae8940645774739",
                seed_v1: "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
                pub_v1: "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
                seed_v2: "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
                pub_v2: "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
            },
        ];
        let ctx = b"context-alpha";
        for v in vectors {
            let identity =
                P256SigningKey::from_seed(b"SCP-TEST-VECTOR-KEY-V1", &h(v.seed)).unwrap();
            let ikm = identity.to_scalar_bytes();
            assert_eq!(hex::encode(*ikm), v.scalar, "identity scalar");

            let secret = derive_pseudonym_secret(&ikm);
            assert_eq!(hex::encode(*secret), v.secret, "pseudonym_secret");

            assert_eq!(hex::encode(*context_seed(&secret, ctx, None)), v.seed_v1);
            assert_eq!(hex::encode(*context_seed(&secret, ctx, Some(1))), v.seed_v2);

            let k1 = derive_pseudonym_keypair(&ikm, ctx, None).unwrap();
            assert_eq!(hex::encode(k1.public_key().to_compressed()), v.pub_v1);
            let k2 = derive_pseudonym_keypair(&ikm, ctx, Some(1)).unwrap();
            assert_eq!(hex::encode(k2.public_key().to_compressed()), v.pub_v2);
        }
    }

    #[test]
    fn routing_id_is_prefixed_sha256_of_point() {
        let point: [u8; 33] =
            h("0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72");
        let mut pre = PSEUDONYM_ROUTING_PREFIX.to_vec();
        pre.extend_from_slice(&point);
        let expected: [u8; 32] = Sha256::digest(&pre).into();
        assert_eq!(pseudonym_routing_id(&point), expected);
        assert_eq!(PSEUDONYM_ROUTING_PREFIX, b"scp-pseudonym-routing-v1:");
    }

    #[test]
    fn distinct_contexts_and_epochs() {
        let ikm = Zeroizing::new([0x07u8; 32]);
        let pk = |c: &[u8], e| {
            derive_pseudonym_keypair(&ikm, c, e)
                .unwrap()
                .public_key()
                .to_compressed()
        };
        assert_eq!(pk(b"ctx", None), pk(b"ctx", None));
        assert_ne!(pk(b"ctx-1", None), pk(b"ctx-2", None));
        assert_ne!(pk(b"ctx-1", Some(1)), pk(b"ctx-1", Some(2)));
        assert_ne!(pk(b"ctx-1", None), pk(b"ctx-1", Some(0)));
    }
}
