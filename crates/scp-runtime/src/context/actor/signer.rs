//! The erased signer a runtime command carries (ADR-049 Decision 7a).
//!
//! The actor holds no key material. A command that needs a signature carries
//! a [`CommandSigner`], an `Arc<dyn DynScpSigner>`; in production it wraps a
//! [`CustodySigner`] over the identity's `KeyCustody`. A handler runs its sync
//! prechecks, awaits [`CommandSigner::sign_bounded_ed25519`] once, and applies
//! the signed result in the same actor turn. A sign that does not answer
//! within [`SIGN_TIMEOUT`] is a custody failure of kind
//! [`CustodyFailureKind::TimedOut`] (`SCP-CRYPTO-4062`), never a transport
//! timeout.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use scp_crypto::{CustodyFailure, CustodyFailureKind, DynScpSigner, SigAlg, SignError};
use scp_platform::signer::CustodySigner;
use scp_platform::traits::KeyCustody;
use scp_protocol::context::ContextError;

/// The signing budget of ADR-049 Decision 7a: the longest a handler waits on
/// custody for one signature before the turn fails with
/// [`CustodyFailureKind::TimedOut`].
pub const SIGN_TIMEOUT: Duration = Duration::from_secs(30);

/// The turn budget of an actor handler that signs through
/// [`CommandSigner::sign_bounded_ed25519`]:
/// the 30-second handler work budget plus [`SIGN_TIMEOUT`].
///
/// A plain 30-second handler budget would expire with the signing budget, so a
/// stalled custody would surface as the handler's `TransportTimeout` instead of
/// [`CustodyFailureKind::TimedOut`]. With this budget a single stalled sign
/// always fails first, as `SCP-CRYPTO-4062`. A turn whose several signs each
/// answer within [`SIGN_TIMEOUT`] but together outlast this budget still
/// reports the handler timeout. The budget stays below the caller's
/// [`REPLY_TIMEOUT`](crate::context::actor::REPLY_TIMEOUT), so the handler's
/// typed error reaches the caller before the caller stops waiting.
pub const SIGNING_HANDLER_TIMEOUT: Duration = Duration::from_secs(30 + SIGN_TIMEOUT.as_secs());

const _: () = assert!(SIGNING_HANDLER_TIMEOUT.as_secs() > SIGN_TIMEOUT.as_secs());
const _: () =
    assert!(SIGNING_HANDLER_TIMEOUT.as_secs() < crate::context::actor::REPLY_TIMEOUT.as_secs());

/// The signer a runtime command carries into the actor turn.
///
/// Cloning shares the underlying signer. `Debug` prints only the algorithm
/// and public key, never key material.
#[derive(Clone)]
pub struct CommandSigner(Arc<dyn DynScpSigner>);

impl CommandSigner {
    /// Wraps an erased signer.
    #[must_use]
    pub fn new(signer: Arc<dyn DynScpSigner>) -> Self {
        Self(signer)
    }

    /// Wraps a custody-backed signer, the production signer.
    #[must_use]
    pub fn from_custody<C: KeyCustody + 'static>(signer: CustodySigner<C>) -> Self {
        Self(Arc::new(signer))
    }

    /// A signer over a local Ed25519 key, for tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn local_ed25519(key: ed25519_dalek::SigningKey) -> Self {
        Self(Arc::new(scp_crypto::LocalEd25519Signer::new(key)))
    }

    /// The signature algorithm the signer produces.
    #[must_use]
    pub fn algorithm(&self) -> SigAlg {
        self.0.algorithm()
    }

    /// The signer's public key bytes.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }

    /// The signer's public key as an Ed25519 verifying key.
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] when the signer is not Ed25519 or its
    /// public key is not a valid Ed25519 point.
    pub fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, ContextError> {
        self.require_ed25519()?;
        let public_key = self.0.public_key();
        let bytes: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
            ContextError::CryptoFailed(format!(
                "Ed25519 signer public key is {} bytes, not 32",
                public_key.len()
            ))
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("invalid Ed25519 public key: {e}")))
    }
}

impl CommandSigner {
    /// Signs the 32-byte `digest` of an Ed25519-format artifact, waiting at
    /// most [`SIGN_TIMEOUT`].
    ///
    /// The key-type check and the bounded wait are one call, so no site can
    /// ask custody for a signature that the artifact's format cannot carry:
    /// every SCP artifact a [`CommandSigner`] signs (a vote, a checkpoint, a
    /// broadcast or inner envelope, a saga receipt, a divergence marker, a
    /// challenge record) fixes Ed25519.
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] naming the algorithm when the signer
    ///   is not Ed25519; custody is not called.
    /// - [`ContextError::Custody`] with the custody's own kind when custody
    ///   refuses the sign.
    /// - [`ContextError::Custody`] with kind [`CustodyFailureKind::TimedOut`]
    ///   when custody does not answer within [`SIGN_TIMEOUT`].
    /// - [`ContextError::CryptoFailed`] for any other signer failure.
    pub async fn sign_bounded_ed25519(&self, digest: &[u8; 32]) -> Result<[u8; 64], ContextError> {
        self.require_ed25519()?;
        sign_bounded(self, digest).await
    }

    /// Fails unless this signer makes Ed25519 signatures.
    /// [`Self::sign_bounded_ed25519`] runs it before every sign; a site calls
    /// it directly only to reject a signer before work that precedes the sign.
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] naming the signer's algorithm.
    pub fn require_ed25519(&self) -> Result<(), ContextError> {
        if self.0.algorithm() == SigAlg::Ed25519 {
            Ok(())
        } else {
            Err(ContextError::CryptoFailed(format!(
                "signer algorithm is {:?}, not Ed25519",
                self.0.algorithm()
            )))
        }
    }
}

impl fmt::Debug for CommandSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandSigner")
            .field("algorithm", &self.0.algorithm())
            .field("public_key", &hex::encode(self.0.public_key()))
            .finish_non_exhaustive()
    }
}

/// Signs `digest` through `signer`, waiting at most [`SIGN_TIMEOUT`]. Private:
/// every caller goes through [`CommandSigner::sign_bounded_ed25519`], which
/// checks the key type first.
///
/// # Errors
///
/// - [`ContextError::Custody`] with the custody's own kind when custody
///   refuses the sign.
/// - [`ContextError::Custody`] with kind [`CustodyFailureKind::TimedOut`]
///   when custody does not answer within [`SIGN_TIMEOUT`].
/// - [`ContextError::CryptoFailed`] for any other signer failure.
async fn sign_bounded(signer: &CommandSigner, digest: &[u8; 32]) -> Result<[u8; 64], ContextError> {
    match tokio::time::timeout(SIGN_TIMEOUT, signer.0.sign_boxed(digest)).await {
        Ok(Ok(signature)) => Ok(signature),
        Ok(Err(SignError::Custody(failure))) => Err(ContextError::Custody(failure)),
        Ok(Err(e)) => Err(ContextError::CryptoFailed(e.to_string())),
        Err(_) => Err(ContextError::Custody(CustodyFailure {
            kind: CustodyFailureKind::TimedOut,
            detail: format!("custody did not sign within {SIGN_TIMEOUT:?}"),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use scp_crypto::{ScpSigner, SignFuture};
    use std::future::Future;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A signer whose sign never completes.
    struct NeverReadySigner;

    impl ScpSigner for NeverReadySigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            vec![0; 32]
        }

        fn sign(
            &self,
            _digest: &[u8; 32],
        ) -> impl Future<Output = Result<[u8; 64], SignError>> + Send {
            std::future::pending()
        }
    }

    /// A signer that refuses with a fixed custody kind, or with a backend
    /// error when the kind is `None`.
    struct RefusingSigner(Option<CustodyFailureKind>);

    impl DynScpSigner for RefusingSigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            vec![0; 32]
        }

        fn sign_boxed<'a>(&'a self, _digest: &'a [u8; 32]) -> SignFuture<'a> {
            let error = self.0.map_or_else(
                || SignError::Backend("backend down".to_owned()),
                |kind| {
                    SignError::Custody(CustodyFailure {
                        kind,
                        detail: "refused".to_owned(),
                    })
                },
            );
            Box::pin(async move { Err(error) })
        }
    }

    /// A signer whose public key is not 32 bytes.
    struct ShortKeySigner;

    impl DynScpSigner for ShortKeySigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }

        fn public_key(&self) -> Vec<u8> {
            vec![1; 31]
        }

        fn sign_boxed<'a>(&'a self, _digest: &'a [u8; 32]) -> SignFuture<'a> {
            Box::pin(async { Err(SignError::Backend("unused".to_owned())) })
        }
    }

    /// A sign past the budget is a custody failure of kind `TimedOut`, not a
    /// transport timeout.
    #[tokio::test(start_paused = true)]
    async fn sign_bounded_times_out() {
        let signer = CommandSigner::new(Arc::new(NeverReadySigner));
        let started = tokio::time::Instant::now();
        let result = signer.sign_bounded_ed25519(&[1; 32]).await;
        assert!(started.elapsed() >= SIGN_TIMEOUT);
        assert!(
            matches!(
                &result,
                Err(ContextError::Custody(CustodyFailure { kind: CustodyFailureKind::TimedOut, detail }))
                    if detail == "custody did not sign within 30s"
            ),
            "{result:?}"
        );
    }

    /// A custody refusal keeps its kind and detail; any other signer failure
    /// is `CryptoFailed`.
    #[tokio::test]
    async fn sign_bounded_keeps_custody_kind() {
        for kind in [
            CustodyFailureKind::KeyNotFound,
            CustodyFailureKind::PseudonymRejected,
            CustodyFailureKind::StorageClosed,
            CustodyFailureKind::StorageLockHeld,
            CustodyFailureKind::Failed,
        ] {
            let signer = CommandSigner::new(Arc::new(RefusingSigner(Some(kind))));
            let result = signer.sign_bounded_ed25519(&[2; 32]).await;
            assert!(
                matches!(
                    &result,
                    Err(ContextError::Custody(failure))
                        if failure.kind == kind && failure.detail == "refused"
                ),
                "{result:?}"
            );
        }
        let signer = CommandSigner::new(Arc::new(RefusingSigner(None)));
        let result = signer.sign_bounded_ed25519(&[2; 32]).await;
        assert!(
            matches!(
                &result,
                Err(ContextError::CryptoFailed(detail))
                    if detail == "signing backend failed: backend down"
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn sign_bounded_signs_through_local_signer() -> TestResult {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signer = CommandSigner::local_ed25519(key.clone());
        let digest = [3u8; 32];
        let signature = signer.sign_bounded_ed25519(&digest).await?;
        assert_eq!(signature, key.sign(&digest).to_bytes());
        let verifying_key = signer.verifying_key()?;
        assert_eq!(verifying_key, key.verifying_key());
        verifying_key.verify(&digest, &ed25519_dalek::Signature::from_bytes(&signature))?;
        Ok(())
    }

    #[test]
    fn command_signer_debug_redacts() {
        let key = SigningKey::from_bytes(&[0x5A; 32]);
        let signer = CommandSigner::local_ed25519(key.clone());
        let rendered = format!("{signer:?}");
        assert!(rendered.contains(&hex::encode(key.verifying_key().to_bytes())));
        assert!(!rendered.contains(&hex::encode(key.to_bytes())));
        assert!(!rendered.contains(&format!("{:?}", key.to_bytes())));
    }

    #[test]
    fn verifying_key_rejects_wrong_length() {
        let result = CommandSigner::new(Arc::new(ShortKeySigner)).verifying_key();
        assert!(
            matches!(result, Err(ContextError::CryptoFailed(ref detail)) if detail == "Ed25519 signer public key is 31 bytes, not 32"),
            "{result:?}"
        );
    }
}
