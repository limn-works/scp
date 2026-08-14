//! Shared pseudonym secret derivation and per-context keypair derivation.
//!
//! This is the single wasm-safe source of the §9.10.4.A software-custody
//! pseudonym derivation. It is consumed by every native `KeyCustody` backend
//! in `scp-platform` and — per ADR-057 Option A (planning-session-10) — by the
//! in-browser client, which derives its own per-context pseudonym in Rust over
//! the wasm-held signing key. Because the algorithm lives here, unforked, and
//! is exercised by a cross-target byte-parity KAT, software pseudonyms agree
//! byte-for-byte across platforms (§25.19 vectors 30/31).
//!
//! CRITICAL PRIVACY REQUIREMENT (§9.10.4.A): Using public key bytes as the
//! HMAC key for pseudonym derivation would be a membership enumeration oracle —
//! anyone who knows a member's public key could compute their pseudonym for any
//! `context_id` and check relay subscriptions. The `pseudonym_secret` is derived
//! from private key bytes via HKDF-SHA-256, making it unknowable without the
//! private key.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Salt for HKDF-SHA-256 pseudonym secret derivation (§9.10.4.A).
const PSEUDONYM_SECRET_SALT: &[u8] = b"scp-pseudonym-secret-v1";

/// Domain separator for v1 (static) pseudonym derivation (§9.10.4).
const PSEUDONYM_V1_DOMAIN: &[u8] = b"scp-pseudonym";

/// Domain separator for v2 (rotatable) pseudonym derivation (§9.10.4.1).
const PSEUDONYM_V2_DOMAIN: &[u8] = b"scp-pseudonym-v2";

/// Derives a `pseudonym_secret` from an Ed25519 private key via HKDF-SHA-256.
///
/// ```text
/// pseudonym_secret = HKDF-SHA256(
///     ikm: ed25519_private_key_bytes,
///     salt: "scp-pseudonym-secret-v1",
///     info: "",
///     len: 32
/// )
/// ```
///
/// All three Rust custody backends (`InMemory`, `File`, `SQLite`) use this function
/// to ensure consistent pseudonym derivation. The derived secret is then used
/// as the HMAC key in `derive_pseudonym` and `derive_rotatable_pseudonym`.
///
/// # Panics
///
/// Never in practice. The single `assert!` guards an infallible invariant:
/// HKDF-Expand with a 32-byte output length cannot fail (32 ≤ 255 · `HashLen`).
/// The assertion documents that invariant rather than propagating an
/// unreachable error.
#[must_use]
pub fn derive_pseudonym_secret(signing_key: &SigningKey) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PSEUDONYM_SECRET_SALT), signing_key.as_bytes());
    let mut secret = Zeroizing::new([0u8; 32]);
    // HKDF-Expand with 32-byte output cannot fail (32 <= 255 * HashLen).
    assert!(
        hk.expand(b"", secret.as_mut()).is_ok(),
        "HKDF-Expand with 32-byte output is infallible"
    );
    secret
}

/// Derives a per-context pseudonym Ed25519 keypair from an identity signing key.
///
/// This performs the HMAC keying + Ed25519 keygen step shared by every software
/// custody backend (`InMemory`, `File`, `SQLite`), eliminating the previously
/// duplicated inline blocks. It first derives the `pseudonym_secret` via
/// [`derive_pseudonym_secret`] (HKDF over the private seed), then computes:
///
/// ```text
/// // epoch = None  (v1, static)
/// context_seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")
///
/// // epoch = Some(e)  (v2, rotatable)
/// context_seed = HMAC-SHA256(pseudonym_secret, context_id || BE64(e) || "scp-pseudonym-v2")
///
/// pseudonym_keypair = Ed25519_keygen(context_seed[0..32])
/// ```
///
/// The 32-byte `context_seed` is interpreted as an RFC-8032 Ed25519 **seed** (fed
/// to `SigningKey::from_bytes`, which applies the standard SHA-512 expansion and
/// scalar clamping internally), NOT as a pre-clamped scalar. Every SDK MUST treat
/// it the same way so software pseudonyms agree byte-for-byte across platforms.
///
/// Intermediate secret material (the HMAC output) is wrapped in [`Zeroizing`] so
/// it is cleared after the keypair is constructed.
///
/// The output is byte-identical to the prior inline derivation blocks: same domain
/// separators, same `mac.update` ordering, same `from_bytes(&hmac[..32])`.
///
/// # Panics
///
/// Never in practice. The single `assert!` guards an infallible invariant:
/// HMAC-SHA-256 accepts a key of any length, so keyed initialization from the
/// derived `pseudonym_secret` cannot fail. The assertion documents that
/// invariant rather than propagating an unreachable error.
#[must_use]
pub fn derive_pseudonym_keypair(
    signing_key: &SigningKey,
    context_id: &[u8],
    epoch: Option<u64>,
) -> SigningKey {
    let pseudonym_secret = derive_pseudonym_secret(signing_key);
    // HMAC accepts a key of any length, so keyed initialization is infallible.
    // Construct via the `Mac::new_from_slice` result, asserting the (unreachable)
    // error case rather than propagating — this mirrors `derive_pseudonym_secret`'s
    // handling of its own infallible HKDF expand and avoids the workspace-denied
    // `unwrap`/`expect`/`panic` lints.
    let mac_result = <Hmac<Sha256> as Mac>::new_from_slice(pseudonym_secret.as_slice());
    assert!(mac_result.is_ok(), "HMAC-SHA256 accepts keys of any length");
    let mut context_seed = Zeroizing::new([0u8; 32]);
    if let Ok(mut mac) = mac_result {
        mac.update(context_id);
        match epoch {
            None => mac.update(PSEUDONYM_V1_DOMAIN),
            Some(e) => {
                mac.update(&e.to_be_bytes());
                mac.update(PSEUDONYM_V2_DOMAIN);
            }
        }
        // HMAC-SHA256 output is a `GenericArray<u8, U32>`. Copy it into the
        // already-`Zeroizing` `context_seed`, then wipe the intermediate via the
        // always-available `[u8]: Zeroize` impl. Wrapping the `GenericArray`
        // itself in `Zeroizing` would require `GenericArray: Zeroize`, which is
        // only present when `generic-array`'s `zeroize` feature is unified in by
        // another crate — so this path is robust to that feature not being on.
        let mut hmac_bytes = mac.finalize().into_bytes();
        context_seed.copy_from_slice(&hmac_bytes[..32]);
        hmac_bytes.as_mut_slice().zeroize();
    }
    SigningKey::from_bytes(&context_seed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Known-answer test (KAT) for software-custody pseudonym derivation.
    ///
    /// These vectors are the mechanical enforcement that the documented values in
    /// `.docs/specs/25-test-vectors.md` §25.19 stay true. Any change to the
    /// derivation recipe (domain separators, HMAC ordering, seed interpretation,
    /// or HKDF salt) breaks this test. The vectors apply to SOFTWARE custody only,
    /// which is cross-platform deterministic; hardware custody is device-local.
    ///
    /// `context_id` = ASCII `"context-alpha"`, v2 `epoch` = 1.
    #[test]
    fn derive_pseudonym_keypair_known_answer_vectors() {
        // Vector A: all-0x01 identity seed.
        let seed_a = [0x01u8; 32];
        let secret_a: [u8; 32] = [
            0x27, 0x45, 0x6a, 0x3d, 0xd2, 0x4e, 0xd5, 0x81, 0x3b, 0x26, 0x45, 0xf0, 0xee, 0x00,
            0x1f, 0x57, 0x76, 0x0c, 0x49, 0xb9, 0x11, 0x7b, 0x93, 0xc8, 0xfa, 0x98, 0xe4, 0x12,
            0x9d, 0x36, 0xa6, 0x43,
        ];
        let v1_pub_a: [u8; 32] = [
            0xfd, 0xdc, 0x04, 0x88, 0x2a, 0x48, 0xaa, 0x39, 0x88, 0x8f, 0x6d, 0xbe, 0xc6, 0x22,
            0xf9, 0xc5, 0xaa, 0x6f, 0x06, 0xb2, 0xe4, 0x08, 0x20, 0xa6, 0x9a, 0x2e, 0x0e, 0x89,
            0xb5, 0xf0, 0x9a, 0xc2,
        ];
        let v2_pub_a: [u8; 32] = [
            0x43, 0xe5, 0x0a, 0x94, 0x7c, 0x4b, 0x2b, 0xe4, 0x4f, 0x87, 0x1e, 0x30, 0x9c, 0x7e,
            0xdc, 0x64, 0xaf, 0xaf, 0x42, 0x07, 0xb9, 0xa5, 0x89, 0xc9, 0xb0, 0x1f, 0x61, 0xc0,
            0x11, 0x58, 0x09, 0x0f,
        ];

        // Vector B: non-trivial identity seed (0x9d, then 0x01..0x1f).
        let seed_b: [u8; 32] = [
            0x9d, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let secret_b: [u8; 32] = [
            0xa5, 0x86, 0x19, 0x1a, 0x1a, 0xb6, 0xcd, 0x3e, 0xfe, 0x45, 0x69, 0x7b, 0x35, 0x10,
            0xee, 0x1e, 0xda, 0xc8, 0xc5, 0x4a, 0x7f, 0x27, 0x86, 0x35, 0x46, 0xb6, 0xe0, 0x33,
            0x3e, 0x20, 0xd6, 0x90,
        ];
        let v1_pub_b: [u8; 32] = [
            0xff, 0x6e, 0x2e, 0x90, 0x9a, 0x00, 0x83, 0x18, 0xf9, 0x7b, 0xb2, 0xc2, 0x6c, 0x1d,
            0x78, 0x7c, 0xeb, 0x9a, 0xa2, 0x99, 0x6f, 0x74, 0x67, 0x66, 0x33, 0x5e, 0x10, 0xba,
            0x7e, 0x22, 0x13, 0xcc,
        ];
        let v2_pub_b: [u8; 32] = [
            0xed, 0xd4, 0x73, 0x19, 0x71, 0x9e, 0x23, 0x50, 0xd1, 0xdb, 0x94, 0x88, 0xe0, 0x18,
            0x9f, 0x24, 0x05, 0x26, 0x7d, 0x7d, 0xc2, 0x43, 0x48, 0x9c, 0xfd, 0x9a, 0xa6, 0xf3,
            0xac, 0x3f, 0xc6, 0x39,
        ];

        let context_id = b"context-alpha";

        for (seed, secret, v1_pub, v2_pub) in [
            (seed_a, secret_a, v1_pub_a, v2_pub_a),
            (seed_b, secret_b, v1_pub_b, v2_pub_b),
        ] {
            let sk = SigningKey::from_bytes(&seed);

            let derived_secret = derive_pseudonym_secret(&sk);
            assert_eq!(
                derived_secret.as_slice(),
                &secret,
                "pseudonym_secret must match the documented KAT vector"
            );

            let v1 = derive_pseudonym_keypair(&sk, context_id, None);
            assert_eq!(
                v1.verifying_key().to_bytes(),
                v1_pub,
                "v1 pseudonym public key must match the documented KAT vector"
            );

            let v2 = derive_pseudonym_keypair(&sk, context_id, Some(1));
            assert_eq!(
                v2.verifying_key().to_bytes(),
                v2_pub,
                "v2 (epoch=1) pseudonym public key must match the documented KAT vector"
            );

            assert_ne!(
                v1.verifying_key().to_bytes(),
                v2.verifying_key().to_bytes(),
                "v1 and v2 derivations must differ (domain separation)"
            );
        }
    }

    #[test]
    fn derive_pseudonym_keypair_is_deterministic() {
        let sk = SigningKey::from_bytes(&[0x07u8; 32]);
        let a = derive_pseudonym_keypair(&sk, b"ctx", None);
        let b = derive_pseudonym_keypair(&sk, b"ctx", None);
        assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    fn derive_pseudonym_keypair_distinct_contexts_and_epochs() {
        let sk = SigningKey::from_bytes(&[0x07u8; 32]);
        let c1 = derive_pseudonym_keypair(&sk, b"ctx-1", None);
        let c2 = derive_pseudonym_keypair(&sk, b"ctx-2", None);
        assert_ne!(c1.verifying_key().to_bytes(), c2.verifying_key().to_bytes());

        let e1 = derive_pseudonym_keypair(&sk, b"ctx-1", Some(1));
        let e2 = derive_pseudonym_keypair(&sk, b"ctx-1", Some(2));
        assert_ne!(e1.verifying_key().to_bytes(), e2.verifying_key().to_bytes());
    }
}
