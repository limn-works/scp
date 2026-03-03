//! In-memory [`DeviceAttestation`] implementation for testing.
//!
//! Returns synthetic attestation tokens that always verify. No actual device
//! verification is performed. See ADR-006 in `.docs/adrs/phase-1.md`.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::PlatformError;
use crate::traits::{DeviceAttestation, DeviceAttestationToken};

/// A synthetic attestation magic prefix used to identify tokens produced by
/// this adapter.
const SYNTHETIC_ATTESTATION_PREFIX: &[u8] = b"scp-test-attestation-v1:";

/// In-memory implementation of [`DeviceAttestation`] for testing and development.
///
/// Produces synthetic attestation tokens that always verify. This adapter
/// exists to satisfy the trait requirements for Phase 1 testing where no
/// actual device attestation hardware is available.
///
/// Tokens produced by this adapter carry a known prefix
/// (`scp-test-attestation-v1:`) followed by a monotonically increasing
/// sequence number. The [`verify`](DeviceAttestation::verify) method checks
/// for this prefix and returns `true` for any token that has it.
///
/// See ADR-006 in `.docs/adrs/phase-1.md`.
pub struct InMemoryDeviceAttestation {
    counter: AtomicU64,
}

impl InMemoryDeviceAttestation {
    /// Creates a new in-memory device attestation adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
        }
    }
}

impl Default for InMemoryDeviceAttestation {
    fn default() -> Self {
        Self::new()
    }
}

// The trait uses RPITIT (`-> impl Future<...> + Send`), so each impl method
// must return a future rather than use `async fn` directly.
// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl DeviceAttestation for InMemoryDeviceAttestation {
    fn attest(&self) -> impl Future<Output = Result<DeviceAttestationToken, PlatformError>> + Send {
        async move {
            let seq = self.counter.fetch_add(1, Ordering::Relaxed);
            let mut token_bytes = Vec::from(SYNTHETIC_ATTESTATION_PREFIX);
            token_bytes.extend_from_slice(&seq.to_le_bytes());
            Ok(DeviceAttestationToken::new(token_bytes))
        }
    }

    fn verify(
        &self,
        token: &DeviceAttestationToken,
    ) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let has_prefix = token.as_bytes().starts_with(SYNTHETIC_ATTESTATION_PREFIX);
        async move { Ok(has_prefix) }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn attest_returns_token_with_prefix() {
        let attestation = InMemoryDeviceAttestation::new();
        let token = attestation.attest().await.unwrap();
        assert!(token.as_bytes().starts_with(SYNTHETIC_ATTESTATION_PREFIX));
    }

    #[tokio::test]
    async fn verify_own_attestation_returns_true() {
        let attestation = InMemoryDeviceAttestation::new();
        let token = attestation.attest().await.unwrap();
        assert!(attestation.verify(&token).await.unwrap());
    }

    #[tokio::test]
    async fn verify_foreign_token_returns_false() {
        let attestation = InMemoryDeviceAttestation::new();
        let foreign = DeviceAttestationToken::new(b"not-our-token".to_vec());
        assert!(!attestation.verify(&foreign).await.unwrap());
    }

    #[tokio::test]
    async fn verify_empty_token_returns_false() {
        let attestation = InMemoryDeviceAttestation::new();
        let empty = DeviceAttestationToken::new(vec![]);
        assert!(!attestation.verify(&empty).await.unwrap());
    }

    #[tokio::test]
    async fn sequential_attestations_produce_unique_tokens() {
        let attestation = InMemoryDeviceAttestation::new();
        let first = attestation.attest().await.unwrap();
        let second = attestation.attest().await.unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[tokio::test]
    async fn multiple_attestation_instances_both_verify_own_tokens() {
        let first_att = InMemoryDeviceAttestation::new();
        let second_att = InMemoryDeviceAttestation::new();

        let first_token = first_att.attest().await.unwrap();
        let second_token = second_att.attest().await.unwrap();

        // Both instances verify tokens with the synthetic prefix.
        assert!(first_att.verify(&first_token).await.unwrap());
        assert!(second_att.verify(&second_token).await.unwrap());
        assert!(first_att.verify(&second_token).await.unwrap());
        assert!(second_att.verify(&first_token).await.unwrap());
    }
}
