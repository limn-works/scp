//! Key custody conformance test macro.
//!
//! The [`key_custody_conformance`] macro generates 4 test cases that validate
//! any [`KeyCustody`](scp_platform::KeyCustody) implementation against the
//! protocol specification (ADR-006):
//!
//! 1. `generate_sign_verify_roundtrip` — generate Ed25519 keypair, sign data, verify signature
//! 2. `destroy_prevents_sign` — generate, destroy, attempt sign -> error
//! 3. `distinct_handles` — generate two keypairs, handles are different
//! 4. `sign_with_invalid_handle_errors` — sign with non-existent handle -> error
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the platform adapter design.

/// Generates 4 conformance tests for a [`KeyCustody`] implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance of a type
/// implementing [`KeyCustody`]. This expression is called once per test to
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

            use scp_platform::{KeyCustody, KeyHandle, KeyType};

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

                // Attempt to sign with the destroyed key should fail.
                let result = custody.sign(&handle, b"data").await;
                assert!(
                    result.is_err(),
                    "sign with destroyed key should return an error"
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

                let result = custody.sign(&invalid_handle, b"data").await;
                assert!(
                    result.is_err(),
                    "sign with non-existent handle should return an error"
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
    /// Verifies an Ed25519 signature against a public key and message.
    ///
    /// # Panics
    ///
    /// Panics if the public key is not 32 bytes, the signature is not 64 bytes,
    /// or the signature does not verify.
    #[allow(clippy::expect_used, clippy::panic)]
    pub fn verify_ed25519_signature(public_key: &[u8], message: &[u8], signature: &[u8]) {
        use ed25519_dalek::{Verifier, VerifyingKey};

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
            .verify(message, &sig)
            .expect("signature verification should succeed");
    }
}
