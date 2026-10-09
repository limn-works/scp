//! Shared pseudonym secret derivation and per-context P-256 pseudonym
//! derivation (§9.10.4, §9.10.4.A, §9.10.4.1).
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
//! context_pseudonym    = compressed(d·G)                                     // 33 bytes; d is discarded
//! pseudonym_routing_id = SHA-256("scp-pseudonym-routing-v1:" || context_pseudonym)
//! ```
//!
//! A pseudonym has no private key (§9.10.4): no protocol message is signed
//! under one, so every function here returns the point and wipes `d`.
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

use crate::p256::{P256PublicKey, P256SecretKey, SeedLabel};

/// Salt for HKDF-SHA-256 pseudonym secret derivation (§9.10.4.A).
const PSEUDONYM_SECRET_SALT: &[u8] = b"scp-pseudonym-secret-v1";

/// Domain separator for v1 (static) pseudonym derivation (§9.10.4).
const PSEUDONYM_V1_DOMAIN: &[u8] = b"scp-pseudonym";

/// Domain separator for v2 (rotatable) pseudonym derivation (§9.10.4.1).
const PSEUDONYM_V2_DOMAIN: &[u8] = b"scp-pseudonym-v2";

/// Prefix of the pseudonym routing-id hash (§9.10.4, registered in §9.18.2).
const PSEUDONYM_ROUTING_PREFIX: &[u8] = b"scp-pseudonym-routing-v1:";

/// Which pseudonym derivation to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PseudonymVersion {
    /// v1, the static pseudonym (§9.10.4).
    Static,
    /// v2, the rotatable pseudonym of rotation epoch `epoch` (§9.10.4.1).
    Rotatable {
        /// The pseudonym rotation epoch, distinct from MLS epochs.
        epoch: u64,
    },
}

/// Derives the `pseudonym_secret` from 32 bytes of private key material via
/// HKDF-SHA-256 (§9.10.4.A). The returned secret wipes on drop; the `hkdf`
/// crate's PRK does not, so wiping is best effort.
#[must_use]
pub fn derive_pseudonym_secret(ikm: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0u8; 32]);
    // 32 bytes is within 255 · HashLen, so the expansion cannot fail.
    let Ok(()) = Hkdf::<Sha256>::new(Some(PSEUDONYM_SECRET_SALT), ikm).expand(b"", secret.as_mut())
    else {
        unreachable!("32 bytes is within 255 * HashLen")
    };
    secret
}

/// `HMAC-SHA256(key, parts[0] || parts[1] || …)` into a wiping buffer. The
/// keyed HMAC state is not wiped, so wiping is best effort.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    // HMAC accepts a key of any length.
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

/// Computes the per-context `context_seed` (§9.10.4 v1, §9.10.4.1 v2).
fn context_seed(
    pseudonym_secret: &[u8; 32],
    context_id: &[u8],
    version: PseudonymVersion,
) -> Zeroizing<[u8; 32]> {
    match version {
        PseudonymVersion::Static => {
            hmac_sha256(pseudonym_secret, &[context_id, PSEUDONYM_V1_DOMAIN])
        }
        PseudonymVersion::Rotatable { epoch } => hmac_sha256(
            pseudonym_secret,
            &[context_id, &epoch.to_be_bytes(), PSEUDONYM_V2_DOMAIN],
        ),
    }
}

/// Turns a 32-byte `context_seed` into the pseudonym point: the §9.10.4
/// seed-to-scalar step, then `d·G`. `d` wipes on drop.
///
/// This is the step a custody whose `pseudonym_secret` stays inside a keystore
/// runs on the seed the keystore computed (§9.10.4.A).
#[must_use]
pub fn pseudonym_from_context_seed(context_seed: &[u8; 32]) -> P256PublicKey {
    P256SecretKey::from_seed(SeedLabel::Pseudonym, context_seed).public_key()
}

/// Derives the per-context pseudonym point from identity private key material
/// (`ikm`) for the static (v1) or rotatable (v2) `version` (§9.10.4,
/// §9.10.4.1).
///
/// Every intermediate buffer this crate owns wipes on drop (best effort; see
/// [`derive_pseudonym_secret`]).
#[must_use]
pub fn derive_pseudonym(
    ikm: &[u8; 32],
    context_id: &[u8],
    version: PseudonymVersion,
) -> P256PublicKey {
    let secret = derive_pseudonym_secret(ikm);
    pseudonym_from_context_seed(&context_seed(&secret, context_id, version))
}

/// The 32-byte routing id every routing field carries for a pseudonym
/// (§9.10.4): `SHA-256("scp-pseudonym-routing-v1:" || context_pseudonym)`,
/// over the 33-byte compressed point.
#[must_use]
pub fn pseudonym_routing_id(context_pseudonym: &P256PublicKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PSEUDONYM_ROUTING_PREFIX);
    hasher.update(context_pseudonym.to_compressed());
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
            rid_v1: &'static str,
            seed_v2: &'static str,
            pub_v2: &'static str,
            rid_v2: &'static str,
        }
        let vectors = [
            V {
                seed: "0101010101010101010101010101010101010101010101010101010101010101",
                scalar: "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
                secret: "b88e781bb954a6681abc9016f8f69939f0e624311aeaa7e8f1b145857f58de82",
                seed_v1: "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
                pub_v1: "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
                rid_v1: "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
                seed_v2: "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
                pub_v2: "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
                rid_v2: "b19754a5e88c993683f99e48646ba518cba80dec0693f920c5671263650b6ae9",
            },
            V {
                seed: "9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                scalar: "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
                secret: "17ef25ad3e5be8adad38c4c5a1c68d3daca80015e81bdcae2ae8940645774739",
                seed_v1: "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
                pub_v1: "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
                rid_v1: "cab5ff45d21b6d0425fa7657e89fc68514965cbb4ca2b9549f4ccf430d581e7c",
                seed_v2: "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
                pub_v2: "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
                rid_v2: "3c0ac4dec86c0dafe38195a7b66cdfec6b0ae0d44834c6e8b6b6129e097b5e27",
            },
        ];
        let ctx = b"context-alpha";
        for v in vectors {
            let identity = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &h(v.seed));
            let ikm = identity.to_scalar_bytes();
            assert_eq!(hex::encode(*ikm), v.scalar, "identity scalar");

            let secret = derive_pseudonym_secret(&ikm);
            assert_eq!(hex::encode(*secret), v.secret, "pseudonym_secret");

            let v1 = PseudonymVersion::Static;
            let v2 = PseudonymVersion::Rotatable { epoch: 1 };
            let seed_v1 = context_seed(&secret, ctx, v1);
            let seed_v2 = context_seed(&secret, ctx, v2);
            assert_eq!(hex::encode(*seed_v1), v.seed_v1);
            assert_eq!(hex::encode(*seed_v2), v.seed_v2);
            assert_eq!(
                hex::encode(pseudonym_from_context_seed(&seed_v1).to_compressed()),
                v.pub_v1
            );

            let p1 = derive_pseudonym(&ikm, ctx, v1);
            assert_eq!(hex::encode(p1.to_compressed()), v.pub_v1);
            assert_eq!(hex::encode(pseudonym_routing_id(&p1)), v.rid_v1);
            let p2 = derive_pseudonym(&ikm, ctx, v2);
            assert_eq!(hex::encode(p2.to_compressed()), v.pub_v2);
            assert_eq!(hex::encode(pseudonym_routing_id(&p2)), v.rid_v2);
        }
    }

    #[test]
    fn distinct_contexts_and_epochs() {
        let ikm = [0x07u8; 32];
        let pk = |c: &[u8], version| derive_pseudonym(&ikm, c, version).to_compressed();
        let rotatable = |epoch| PseudonymVersion::Rotatable { epoch };
        assert_eq!(
            pk(b"ctx", PseudonymVersion::Static),
            pk(b"ctx", PseudonymVersion::Static)
        );
        assert_ne!(
            pk(b"ctx-1", PseudonymVersion::Static),
            pk(b"ctx-2", PseudonymVersion::Static)
        );
        assert_ne!(pk(b"ctx-1", rotatable(1)), pk(b"ctx-1", rotatable(2)));
        assert_ne!(
            pk(b"ctx-1", PseudonymVersion::Static),
            pk(b"ctx-1", rotatable(0))
        );
    }
}
