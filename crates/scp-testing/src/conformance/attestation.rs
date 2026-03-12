//! Device attestation conformance test macro.
//!
//! The `attestation_conformance` macro generates 2 test cases that validate
//! any `DeviceAttestation` implementation
//! against the protocol specification (ADR-006):
//!
//! 1. `attest_verify_roundtrip` — `attest()`, then `verify(token)` -> success
//! 2. `invalid_token_rejected` — `verify(garbage_bytes)` -> false
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the platform adapter design.

/// Generates 2 conformance tests for a `DeviceAttestation` implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance of a type
/// implementing `DeviceAttestation`. This expression is called once per test
/// to create a fresh attestation provider.
///
/// # Example
///
/// ```ignore
/// use scp_testing::attestation_conformance;
///
/// attestation_conformance!(InMemoryDeviceAttestation::new());
/// ```
///
/// See ADR-006 and spec section 17.11.
#[macro_export]
macro_rules! attestation_conformance {
    ($factory:expr) => {
        #[allow(
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            unused_imports
        )]
        mod attestation_conformance {
            use super::*;

            use scp_platform::{DeviceAttestation, DeviceAttestationToken};

            #[tokio::test]
            async fn attest_verify_roundtrip() {
                let attestation = $factory;

                let token = attestation.attest().await.expect("attest should succeed");

                let verified = attestation
                    .verify(&token)
                    .await
                    .expect("verify should succeed");

                assert!(
                    verified,
                    "a freshly generated attestation token should verify as valid"
                );
            }

            #[tokio::test]
            async fn invalid_token_rejected() {
                let attestation = $factory;

                // Construct a garbage token that should not verify.
                let garbage = DeviceAttestationToken::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);

                let result = attestation.verify(&garbage).await;

                match result {
                    Ok(valid) => {
                        assert!(
                            !valid,
                            "garbage attestation token should not verify as valid"
                        );
                    }
                    Err(_) => {
                        // An error is also acceptable — the implementation may
                        // reject malformed tokens with an error rather than
                        // returning false.
                    }
                }
            }
        }
    };
}
