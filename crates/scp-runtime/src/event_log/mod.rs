//! Event log adapter for SCP contexts.
//!
//! Re-exports removed — import directly from [`scp_event_log`].
//! SCP has not shipped, so no backward compatibility is needed.
//!
//! The `KeyCustodySigner` adapter bridges `scp-platform`'s `KeyCustody`/`KeyHandle`
//! to the [`EventLogSigner`] trait defined in `scp-event-log`.
//!
//! See ADR-011 in `.docs/adrs/phase-2.md` for the full design.

// ---------------------------------------------------------------------------
// KeyCustodySigner adapter
// ---------------------------------------------------------------------------

use scp_event_log::EventLogSigner;
use scp_platform::traits::{KeyCustody, KeyHandle};

/// Adapter bridging `scp-platform`'s [`KeyCustody`]/[`KeyHandle`] to the
/// [`EventLogSigner`] trait defined in `scp-event-log`.
///
/// This allows checkpoint generation and other signing operations in `scp-core`
/// to use the platform's key custody implementation transparently.
pub struct KeyCustodySigner<'a, C: KeyCustody> {
    /// The key custody implementation.
    pub custody: &'a C,
    /// The signing key handle.
    pub key: &'a KeyHandle,
}

#[async_trait::async_trait]
impl<C: KeyCustody> EventLogSigner for KeyCustodySigner<'_, C> {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, scp_crypto::CustodyFailure> {
        let sig = self.custody.sign(self.key, message).await?;
        Ok(sig.into_bytes())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};

    use super::KeyCustodySigner;

    /// A checkpoint signed through a destroyed key fails with a typed
    /// key-not-found custody failure, which every bridge reports as
    /// `SCP-CRYPTO-4006`.
    #[tokio::test]
    async fn checkpoint_with_a_destroyed_key_is_custody_key_not_found() {
        let custody = InMemoryKeyCustody::new();
        let key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        custody.destroy_key(&key).await.unwrap();
        let log = scp_event_log::EventLog::new("ctx-checkpoint-custody".to_owned());
        let signer = KeyCustodySigner {
            custody: &custody,
            key: &key,
        };
        let err = scp_event_log::checkpoint::generate_checkpoint(
            &log,
            &scp_did::DID::from("did:dht:alice"),
            1,
            &signer,
        )
        .await
        .expect_err("a checkpoint under a destroyed key must fail");
        assert!(
            matches!(&err, scp_event_log::EventLogError::Custody(failure) if failure.is_key_not_found()),
            "expected EventLogError::Custody key-not-found, got {err:?}"
        );
    }
}
