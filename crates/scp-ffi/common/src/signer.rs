//! The bridges' one way to build the signer a runtime command carries
//! (ADR-049 Decision 7a).
//!
//! A bridge resolves an identity to its custody and key handle, then builds a
//! [`CommandSigner`] here. The private key never leaves the custody. A failure
//! comes back as the custody's own [`PlatformError`], which each bridge maps
//! through its custody translator, so a destroyed key reports
//! `SCP-CRYPTO-4006`.

use std::sync::Arc;

use scp_core::context::actor::signer::CommandSigner;
use scp_crypto::SigAlg;
use scp_platform::PlatformError;
use scp_platform::signer::CustodySigner;
use scp_platform::traits::{KeyCustody, KeyHandle};

/// Builds the [`CommandSigner`] for the identity key `handle` in `custody`.
///
/// Identity keys sign with Ed25519 until the curve slice moves them to the
/// algorithm of `09-security-model.md` §9.5.
///
/// # Errors
///
/// The custody's [`PlatformError`] when it cannot read the key's public key
/// (`KeyNotFound` for a destroyed key), or `WrongKeyType` when the key is not
/// an Ed25519 key.
pub async fn identity_command_signer<C: KeyCustody + 'static>(
    custody: Arc<C>,
    handle: KeyHandle,
) -> Result<CommandSigner, PlatformError> {
    let signer = CustodySigner::new(custody, handle, SigAlg::Ed25519).await?;
    Ok(CommandSigner::from_custody(signer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_codes::{self, custody_failure_code};
    use scp_core::context::ContextError;
    use scp_core::context::actor::signer::{SIGN_TIMEOUT, sign_bounded};
    use scp_crypto::{CustodyFailure, CustodyFailureKind, DynScpSigner, SignFuture};
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct NeverReadySigner;

    impl DynScpSigner for NeverReadySigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            vec![0; 32]
        }

        fn sign_boxed<'a>(&'a self, _digest: &'a [u8; 32]) -> SignFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    /// The signer signs with the identity key, and its signature verifies
    /// against the key custody reports.
    #[tokio::test]
    async fn identity_command_signer_signs_with_the_identity_key() -> TestResult {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let handle = custody.generate_keypair(KeyType::Ed25519).await?;
        let public_key = custody.public_key(&handle).await?;
        let signer = identity_command_signer(Arc::clone(&custody), handle).await?;
        assert_eq!(signer.public_key(), public_key.as_bytes());
        let digest = [4u8; 32];
        let signature = sign_bounded(&signer, &digest).await?;
        signer
            .verifying_key()?
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))?;
        Ok(())
    }

    /// A destroyed key fails construction with the custody's own
    /// `KeyNotFound`, which every bridge reports as `SCP-CRYPTO-4006`.
    #[tokio::test]
    async fn identity_command_signer_destroyed_key_is_key_not_found() -> TestResult {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let handle = custody.generate_keypair(KeyType::Ed25519).await?;
        custody.destroy_key(&handle).await?;
        let result = identity_command_signer(custody, handle).await;
        assert!(
            matches!(result, Err(PlatformError::KeyNotFound)),
            "{result:?}"
        );
        let failure = CustodyFailure::from(&PlatformError::KeyNotFound);
        assert_eq!(custody_failure_code(&failure), error_codes::CRYPTO_4006);
        Ok(())
    }

    /// A sign past the budget reaches the bridges as `SCP-CRYPTO-4061`.
    #[tokio::test(start_paused = true)]
    async fn sign_bounded_timeout_is_crypto_4061() {
        let signer = CommandSigner::new(Arc::new(NeverReadySigner));
        let started = tokio::time::Instant::now();
        let result = sign_bounded(&signer, &[5; 32]).await;
        assert!(started.elapsed() >= SIGN_TIMEOUT);
        assert!(
            matches!(
                &result,
                Err(ContextError::Custody(failure))
                    if failure.kind == CustodyFailureKind::TimedOut
                        && custody_failure_code(failure) == "SCP-CRYPTO-4061"
            ),
            "{result:?}"
        );
    }
}
