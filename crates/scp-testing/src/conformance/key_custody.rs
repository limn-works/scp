//! Key custody conformance test macro.
//!
//! The `key_custody_conformance` macro generates 13 test cases that validate
//! any `KeyCustody` implementation against the
//! protocol specification (ADR-006):
//!
//! 1. `generate_sign_verify_roundtrip` — generate Ed25519 keypair, sign data, verify signature
//! 2. `destroy_prevents_sign` — generate, destroy, attempt sign -> `KeyNotFound`
//! 3. `distinct_handles` — generate two keypairs, handles are different
//! 4. `sign_with_invalid_handle_errors` — sign with non-existent handle -> `KeyNotFound`
//! 5. `p256_generate_sign_verify` — P-256 signing key: 33-byte public key;
//!    signatures over 64 distinct 32-byte digests all verify strictly
//!    (low-`s`); data that is not 32 bytes is refused with `CustodyError`
//! 6. `hpke_p256_dh_agree_matches_ecdh` — HPKE P-256 key: 65-byte public key,
//!    `dh_agree` equals `ecdh_p256` from the peer side
//! 7. `hpke_p256_dh_agree_rejects_off_curve_peer` — a 65-byte point off the
//!    curve is refused with `CustodyError`
//! 8. `p256_wrong_key_type` — signing with an HPKE key, or key agreement with
//!    a signing key, yields `WrongKeyType`
//! 9. `hpke_p256_dh_agree_rejects_non_uncompressed_peer` — valid coordinates
//!    under a `0x05` or `0x02` prefix, and the 33-byte compressed point, are
//!    refused with `CustodyError` (RFC 9180 §7.1.1)
//! 10. `p256_destroy_prevents_use` — destroyed P-256 keys of both types can
//!     no longer sign, agree, or report a public key: each is `KeyNotFound`
//! 11. `identity_keys_derive` — an identity key, generated or imported,
//!     derives the same v1 and v2 pseudonyms on every call
//! 12. `derive_from_operational_key_is_not_identity_key` — an operational
//!     key of every type is refused as a derivation source with
//!     `NotIdentityKey`, and the operational Ed25519 key still signs
//! 13. `destroyed_identity_derives_key_not_found` — after an identity is
//!     destroyed, its v1 and v2 derivations fail with `KeyNotFound`, and a
//!     bystander identity still derives the same points (§9.10.4.A)
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the platform adapter design.

/// Generates 13 conformance tests for a `KeyCustody` implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance of a type
/// implementing `KeyCustody`. This expression is called once per test to
/// create a fresh custody provider with no pre-existing keys.
///
/// # Example
///
/// ```ignore
/// use scp_testing::key_custody_conformance;
///
/// key_custody_conformance!(InMemoryKeyCustody::new());
/// ```
///
/// See ADR-006 and spec section 17.11.
#[macro_export]
macro_rules! key_custody_conformance {
    ($factory:expr) => {
        #[allow(
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            unused_imports
        )]
        mod key_custody_conformance {
            use super::*;

            use scp_platform::{KeyCustody, KeyHandle, KeyType, PlatformError};
            use $crate::conformance::key_custody::test_helpers::assert_key_not_found;

            #[tokio::test]
            async fn generate_sign_verify_roundtrip() {
                let custody = $factory;
                let handle = custody
                    .generate_keypair(KeyType::Ed25519)
                    .await
                    .expect("generate_keypair should succeed");

                let data = b"conformance test data";
                let signature = custody
                    .sign(&handle, data)
                    .await
                    .expect("sign should succeed");

                let public_key = custody
                    .public_key(&handle)
                    .await
                    .expect("public_key should succeed");

                // Verify the Ed25519 signature using the public key.
                $crate::conformance::key_custody::test_helpers::verify_ed25519_signature(
                    public_key.as_bytes(),
                    data,
                    signature.as_bytes(),
                );
            }

            #[tokio::test]
            async fn destroy_prevents_sign() {
                let custody = $factory;
                let handle = custody
                    .generate_keypair(KeyType::Ed25519)
                    .await
                    .expect("generate_keypair should succeed");

                // Destroy the key.
                custody
                    .destroy_key(&handle)
                    .await
                    .expect("destroy_key should succeed");

                assert_key_not_found(
                    custody.sign(&handle, b"data").await.map(|_| ()),
                    "sign with a destroyed key",
                );
            }

            #[tokio::test]
            async fn distinct_handles() {
                let custody = $factory;
                let handle_a = custody
                    .generate_keypair(KeyType::Ed25519)
                    .await
                    .expect("first generate_keypair should succeed");

                let handle_b = custody
                    .generate_keypair(KeyType::Ed25519)
                    .await
                    .expect("second generate_keypair should succeed");

                assert_ne!(
                    handle_a, handle_b,
                    "two generated keypairs should have distinct handles"
                );

                // Also verify they produce different public keys.
                let pk_a = custody
                    .public_key(&handle_a)
                    .await
                    .expect("public_key a should succeed");
                let pk_b = custody
                    .public_key(&handle_b)
                    .await
                    .expect("public_key b should succeed");
                assert_ne!(
                    pk_a, pk_b,
                    "two generated keypairs should have distinct public keys"
                );
            }

            #[tokio::test]
            async fn sign_with_invalid_handle_errors() {
                let custody = $factory;
                // Use an extremely high handle ID that was never generated.
                let invalid_handle = KeyHandle::new(u64::MAX);

                assert_key_not_found(
                    custody.sign(&invalid_handle, b"data").await.map(|_| ()),
                    "sign with a handle never generated",
                );
            }

            #[tokio::test]
            async fn p256_generate_sign_verify() {
                let custody = $factory;
                let handle = custody
                    .generate_keypair(KeyType::P256Signing)
                    .await
                    .expect("generate_keypair(P256Signing) should succeed");
                let public_key = custody
                    .public_key(&handle)
                    .await
                    .expect("public_key should succeed");
                assert_eq!(
                    public_key.as_bytes().len(),
                    33,
                    "a P-256 signing key's public key is the compressed point"
                );

                // 64 distinct digests: RFC 6979 gives a high raw `s` for
                // about half of them, so all of them verifying strictly shows
                // the low-`s` normalisation (a lone digest passes by luck
                // half the time).
                for i in 0..64u8 {
                    let digest = [i; 32];
                    let signature = custody
                        .sign(&handle, &digest)
                        .await
                        .expect("sign should succeed");
                    $crate::conformance::key_custody::test_helpers::verify_p256_prehash_strict(
                        public_key.as_bytes(),
                        &digest,
                        signature.as_bytes(),
                    )
                    .expect("the P-256 signature must verify strictly");
                }

                for data in [&[0u8; 31][..], &[0u8; 33][..], &[][..], b"not a digest"] {
                    let result = custody.sign(&handle, data).await;
                    assert!(
                        matches!(result, Err(scp_platform::PlatformError::CustodyError(_))),
                        "P-256 signing of {} bytes must be CustodyError, got {:?}",
                        data.len(),
                        result.map(|_| ())
                    );
                }
            }

            #[tokio::test]
            async fn hpke_p256_dh_agree_matches_ecdh() {
                let custody = $factory;
                let handle = custody
                    .generate_keypair(KeyType::HpkeP256)
                    .await
                    .expect("generate_keypair(HpkeP256) should succeed");
                let public_key = custody
                    .public_key(&handle)
                    .await
                    .expect("public_key should succeed");
                assert_eq!(
                    public_key.as_bytes().len(),
                    65,
                    "an HPKE P-256 key's public key is the uncompressed point"
                );

                let (peer, expected) =
                    $crate::conformance::key_custody::test_helpers::p256_peer_and_shared_secret(
                        public_key.as_bytes(),
                    )
                    .expect("the HPKE public key is a valid P-256 point");
                let shared = custody
                    .dh_agree(&handle, &peer)
                    .await
                    .expect("dh_agree should succeed");
                assert_eq!(
                    shared.as_bytes(),
                    &expected,
                    "dh_agree must equal ecdh_p256 computed from the peer side"
                );
            }

            #[tokio::test]
            async fn hpke_p256_dh_agree_rejects_off_curve_peer() {
                let custody = $factory;
                let handle = custody
                    .generate_keypair(KeyType::HpkeP256)
                    .await
                    .expect("generate_keypair(HpkeP256) should succeed");
                let off_curve =
                    $crate::conformance::key_custody::test_helpers::off_curve_p256_point()
                        .expect("the generator is a valid point");
                let result = custody.dh_agree(&handle, &off_curve).await;
                assert!(
                    matches!(result, Err(scp_platform::PlatformError::CustodyError(_))),
                    "dh_agree must refuse a 65-byte point that is not on P-256 with \
                     CustodyError, got {:?}",
                    result.map(|_| ())
                );
            }

            #[tokio::test]
            async fn hpke_p256_dh_agree_rejects_non_uncompressed_peer() {
                let custody = $factory;
                let handle = custody
                    .generate_keypair(KeyType::HpkeP256)
                    .await
                    .expect("generate_keypair(HpkeP256) should succeed");
                let public_key = custody
                    .public_key(&handle)
                    .await
                    .expect("public_key should succeed");
                let (peer, _) =
                    $crate::conformance::key_custody::test_helpers::p256_peer_and_shared_secret(
                        public_key.as_bytes(),
                    )
                    .expect("the HPKE public key is a valid P-256 point");
                let mut prefix_05 = peer.clone();
                prefix_05[0] = 0x05;
                let mut prefix_02 = peer.clone();
                prefix_02[0] = 0x02;
                let compressed =
                    $crate::conformance::key_custody::test_helpers::compress_p256_point(&peer)
                        .expect("the peer is a valid P-256 point");
                for (label, bad) in [
                    ("0x05 prefix", prefix_05),
                    ("0x02 prefix on 65 bytes", prefix_02),
                    ("33-byte compressed", compressed),
                ] {
                    let result = custody.dh_agree(&handle, &bad).await;
                    assert!(
                        matches!(result, Err(scp_platform::PlatformError::CustodyError(_))),
                        "dh_agree must refuse a {label} peer with CustodyError, got {:?}",
                        result.map(|_| ())
                    );
                }
            }

            #[tokio::test]
            async fn p256_destroy_prevents_use() {
                let custody = $factory;
                let signing = custody
                    .generate_keypair(KeyType::P256Signing)
                    .await
                    .expect("generate_keypair(P256Signing) should succeed");
                let hpke = custody
                    .generate_keypair(KeyType::HpkeP256)
                    .await
                    .expect("generate_keypair(HpkeP256) should succeed");
                let hpke_public = custody
                    .public_key(&hpke)
                    .await
                    .expect("public_key should succeed");
                let (peer, _) =
                    $crate::conformance::key_custody::test_helpers::p256_peer_and_shared_secret(
                        hpke_public.as_bytes(),
                    )
                    .expect("the HPKE public key is a valid P-256 point");
                custody
                    .destroy_key(&signing)
                    .await
                    .expect("destroy_key(P256Signing) should succeed");
                custody
                    .destroy_key(&hpke)
                    .await
                    .expect("destroy_key(HpkeP256) should succeed");

                assert_key_not_found(
                    custody.sign(&signing, &[0u8; 32]).await.map(|_| ()),
                    "sign with a destroyed P-256 signing key",
                );
                assert_key_not_found(
                    custody.public_key(&signing).await.map(|_| ()),
                    "public_key of a destroyed P-256 signing key",
                );
                assert_key_not_found(
                    custody.dh_agree(&hpke, &peer).await.map(|_| ()),
                    "dh_agree with a destroyed HPKE P-256 key",
                );
                assert_key_not_found(
                    custody.public_key(&hpke).await.map(|_| ()),
                    "public_key of a destroyed HPKE P-256 key",
                );
            }

            #[tokio::test]
            async fn identity_keys_derive() {
                let custody = $factory;
                let generated = custody
                    .generate_identity_keypair()
                    .await
                    .expect("generate_identity_keypair should succeed");
                let imported = custody
                    .import_ed25519_signing_key(
                        &$crate::conformance::key_custody::test_helpers::import_seed(),
                    )
                    .await
                    .expect("import_ed25519_signing_key should succeed");
                for identity in [generated, imported] {
                    let v1 = custody
                        .derive_pseudonym(&identity, b"ctx")
                        .await
                        .expect("an identity key derives a v1 pseudonym");
                    assert_eq!(
                        custody
                            .derive_pseudonym(&identity, b"ctx")
                            .await
                            .expect("an identity key derives a v1 pseudonym"),
                        v1
                    );
                    let v2 = custody
                        .derive_rotatable_pseudonym(&identity, b"ctx", 3)
                        .await
                        .expect("an identity key derives a v2 pseudonym");
                    assert_eq!(
                        custody
                            .derive_rotatable_pseudonym(&identity, b"ctx", 3)
                            .await
                            .expect("an identity key derives a v2 pseudonym"),
                        v2
                    );
                    assert_ne!(v1, v2, "v1 and v2 use different domain separators");
                }
            }

            #[tokio::test]
            async fn derive_from_operational_key_is_not_identity_key() {
                let custody = $factory;
                for key_type in [
                    KeyType::Ed25519,
                    KeyType::X25519,
                    KeyType::P256Signing,
                    KeyType::HpkeP256,
                ] {
                    let operational = custody
                        .generate_keypair(key_type)
                        .await
                        .expect("generate_keypair should succeed");
                    let v1 = custody.derive_pseudonym(&operational, b"ctx").await;
                    assert!(
                        matches!(v1, Err(PlatformError::NotIdentityKey)),
                        "v1 derivation from an operational {key_type:?} key must be \
                         NotIdentityKey, got {v1:?}"
                    );
                    let v2 = custody
                        .derive_rotatable_pseudonym(&operational, b"ctx", 1)
                        .await;
                    assert!(
                        matches!(v2, Err(PlatformError::NotIdentityKey)),
                        "v2 derivation from an operational {key_type:?} key must be \
                         NotIdentityKey, got {v2:?}"
                    );
                }
                // The refusal is the role: the same operational Ed25519 key
                // still signs.
                let operational = custody
                    .generate_keypair(KeyType::Ed25519)
                    .await
                    .expect("generate_keypair should succeed");
                custody
                    .sign(&operational, b"data")
                    .await
                    .expect("an operational Ed25519 key signs");
            }

            #[tokio::test]
            async fn destroyed_identity_derives_key_not_found() {
                let custody = $factory;
                let u = custody
                    .generate_identity_keypair()
                    .await
                    .expect("generate_identity_keypair should succeed");
                let v = custody
                    .generate_identity_keypair()
                    .await
                    .expect("generate_identity_keypair should succeed");
                let v_static = custody
                    .derive_pseudonym(&v, b"ctx")
                    .await
                    .expect("v derives");
                let v_rotatable = custody
                    .derive_rotatable_pseudonym(&v, b"ctx", 7)
                    .await
                    .expect("v derives");
                custody
                    .derive_pseudonym(&u, b"ctx")
                    .await
                    .expect("u derives before the destroy");

                custody
                    .destroy_key(&u)
                    .await
                    .expect("destroy_key should succeed");

                assert_key_not_found(
                    custody.derive_pseudonym(&u, b"ctx").await.map(|_| ()),
                    "v1 derivation from a destroyed identity",
                );
                assert_key_not_found(
                    custody
                        .derive_rotatable_pseudonym(&u, b"ctx", 7)
                        .await
                        .map(|_| ()),
                    "v2 derivation from a destroyed identity",
                );
                assert_eq!(
                    custody
                        .derive_pseudonym(&v, b"ctx")
                        .await
                        .expect("the bystander still derives"),
                    v_static
                );
                assert_eq!(
                    custody
                        .derive_rotatable_pseudonym(&v, b"ctx", 7)
                        .await
                        .expect("the bystander still derives"),
                    v_rotatable
                );
            }

            #[tokio::test]
            async fn p256_wrong_key_type() {
                let custody = $factory;
                let signing = custody
                    .generate_keypair(KeyType::P256Signing)
                    .await
                    .expect("generate_keypair(P256Signing) should succeed");
                let hpke = custody
                    .generate_keypair(KeyType::HpkeP256)
                    .await
                    .expect("generate_keypair(HpkeP256) should succeed");

                let result = custody.sign(&hpke, &[0u8; 32]).await;
                assert!(
                    matches!(
                        result,
                        Err(scp_platform::PlatformError::WrongKeyType {
                            actual: KeyType::HpkeP256,
                            ..
                        })
                    ),
                    "sign with an HPKE key must be WrongKeyType, got {result:?}"
                );

                let hpke_public = custody
                    .public_key(&hpke)
                    .await
                    .expect("public_key should succeed");
                let result = custody.dh_agree(&signing, hpke_public.as_bytes()).await;
                assert!(
                    matches!(
                        result,
                        Err(scp_platform::PlatformError::WrongKeyType {
                            actual: KeyType::P256Signing,
                            ..
                        })
                    ),
                    "dh_agree with a signing key must be WrongKeyType, got {:?}",
                    result.map(|_| ())
                );
            }
        }
    };
}

/// Helper functions used by the conformance test macro.
///
/// These are public so the macro-generated tests can reference them, but
/// they are implementation details of the conformance suite.
pub mod test_helpers {
    /// Asserts that `result` is exactly [`PlatformError::KeyNotFound`], the
    /// failure a bridge reports as `SCP-CRYPTO-4006`.
    ///
    /// # Panics
    ///
    /// Panics naming `what` when `result` is `Ok` or any other error.
    ///
    /// [`PlatformError::KeyNotFound`]: scp_platform::PlatformError::KeyNotFound
    #[allow(clippy::panic)]
    pub fn assert_key_not_found(result: Result<(), scp_platform::PlatformError>, what: &str) {
        match result {
            Err(scp_platform::PlatformError::KeyNotFound) => {}
            Err(other) => panic!("{what}: expected KeyNotFound, got {other:?}"),
            Ok(()) => panic!("{what}: expected KeyNotFound, got Ok"),
        }
    }

    /// A fixed Ed25519 seed for the identity-import case.
    #[must_use]
    pub fn import_seed() -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new([0x5Au8; 32])
    }

    /// Verifies an Ed25519 signature against a public key and message.
    ///
    /// # Panics
    ///
    /// Panics if the public key is not 32 bytes, the signature is not 64 bytes,
    /// or the signature does not verify.
    #[allow(clippy::expect_used, clippy::panic)]
    pub fn verify_ed25519_signature(public_key: &[u8], message: &[u8], signature: &[u8]) {
        use ed25519_dalek::VerifyingKey;

        assert_eq!(
            public_key.len(),
            32,
            "Ed25519 public key should be 32 bytes"
        );
        assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");

        let vk_bytes: [u8; 32] = public_key
            .try_into()
            .expect("public key should be 32 bytes");
        let verifying_key = VerifyingKey::from_bytes(&vk_bytes).expect("valid Ed25519 public key");

        let sig_bytes: [u8; 64] = signature.try_into().expect("signature should be 64 bytes");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify_strict(message, &sig)
            .expect("signature verification should succeed");
    }

    /// Verifies a raw 64-byte P-256 signature over a 32-byte digest under
    /// the strict (low-`s`) rule, against a 33-byte compressed public key.
    ///
    /// # Errors
    ///
    /// The public key is not a valid P-256 point, or the signature does not
    /// verify strictly.
    ///
    /// # Panics
    ///
    /// Panics if the public key is not 33 bytes (the compressed point).
    pub fn verify_p256_prehash_strict(
        public_key: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), scp_crypto::p256::P256Error> {
        assert_eq!(
            public_key.len(),
            scp_crypto::p256::COMPRESSED_POINT_LEN,
            "a P-256 signing public key is the 33-byte compressed point"
        );
        let pk = scp_crypto::p256::P256PublicKey::from_sec1(public_key)?;
        scp_crypto::p256::verify_prehash_strict(&pk, digest, signature)
    }

    /// Returns a fixed peer's uncompressed public key and the shared secret
    /// that peer computes with `own_public` (`ecdh_p256` from the peer side).
    ///
    /// # Errors
    ///
    /// `own_public` is not a valid P-256 point.
    pub fn p256_peer_and_shared_secret(
        own_public: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32]), scp_crypto::p256::P256Error> {
        let own = scp_crypto::p256::P256PublicKey::from_sec1(own_public)?;
        let peer = scp_crypto::p256::P256SecretKey::from_scalar_bytes(&[0x2Au8; 32])?;
        let shared = scp_crypto::p256::ecdh_p256(&peer, &own);
        Ok((peer.public_key().to_uncompressed().to_vec(), *shared))
    }

    /// The 33-byte compressed encoding of a 65-byte uncompressed point.
    ///
    /// # Errors
    ///
    /// `uncompressed` is not a valid P-256 point.
    pub fn compress_p256_point(
        uncompressed: &[u8],
    ) -> Result<Vec<u8>, scp_crypto::p256::P256Error> {
        Ok(scp_crypto::p256::P256PublicKey::from_sec1(uncompressed)?
            .to_compressed()
            .to_vec())
    }

    /// A 65-byte uncompressed SEC1 encoding (`0x04 ‖ x ‖ y`) of a point that
    /// is not on P-256: the generator with the last bit of `y` flipped.
    ///
    /// # Errors
    ///
    /// Never in practice; the generator scalar is a constant.
    ///
    /// # Panics
    ///
    /// Panics if the tweaked point is still on the curve.
    pub fn off_curve_p256_point() -> Result<[u8; 65], scp_crypto::p256::P256Error> {
        let mut one = [0u8; 32];
        one[31] = 1;
        let generator = scp_crypto::p256::P256SecretKey::from_scalar_bytes(&one)?;
        let mut point = generator.public_key().to_uncompressed();
        point[64] ^= 1;
        assert!(
            scp_crypto::p256::P256PublicKey::from_sec1(&point).is_err(),
            "the tweaked generator must be off the curve"
        );
        Ok(point)
    }
}
