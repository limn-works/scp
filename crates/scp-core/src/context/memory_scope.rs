//! Memory scope enforcement and key destruction orchestration.
//!
//! Implements ADR-018 (`.docs/adrs/phase-4.md`), sections 5-9:
//!
//! - [`KeyDestructionLevel`] -- Attestation level for key destruction
//!   verification (hardware-attested, software-only, no attestation).
//! - [`RelayDeletionRequest`] -- Request to delete encrypted event data from a
//!   relay.
//! - [`KeyDestructionOrchestrator`] -- Orchestrates MLS group state destruction,
//!   sender key destruction, and relay deletion requests for ephemeral close.
//! - [`RelayDeletionTracker`] -- Tracks relay compliance with deletion requests
//!   and deprioritizes non-compliant relays.
//! - [`validate_memory_scope_for_broadcast`] -- Rejects `Ephemeral` or
//!   `Summary` memory scopes for broadcast contexts.
//!
//! # Key Destruction
//!
//! Key destruction makes content physically unreadable, enforced by
//! cryptography rather than policy. Destroying MLS tree secrets, epoch key
//! schedules, and application key material makes all historical content
//! physically unreadable. Relay deletion tracking deprioritizes non-compliant
//! relays but does not gate protocol operation.
//!
//! # Broadcast Restriction
//!
//! Broadcast contexts (spec section 5.14) use per-author keys without MLS
//! group management. Forward secrecy depends on MLS epoch ratcheting, which
//! broadcast mode lacks. Ephemeral/Summary scopes promise key destruction
//! semantics that broadcast mode cannot deliver. Only `MemoryScope::Full` is
//! permitted for broadcast contexts.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::builder::ContextCryptoProvider;
use super::{ContextError, ContextMode, MemoryScope};

// ---------------------------------------------------------------------------
// Type aliases (per-module pattern used throughout scp-core)
// ---------------------------------------------------------------------------

/// A context identifier string.
///
/// Represented as a plain `String`. This matches the type alias pattern used
/// across `scp-core` modules (`event_log`, `discovery`, `context`).
pub type ContextId = String;

/// An opaque blob identifier (SHA-256 hash of the blob content).
///
/// Represented as `[u8; 32]` per ADR-005 in `.docs/adrs/phase-1.md`.
pub type BlobId = [u8; 32];

// ---------------------------------------------------------------------------
// KeyDestructionLevel
// ---------------------------------------------------------------------------

/// Attestation level for key destruction verification.
///
/// The protocol records what level of assurance was achieved during key
/// destruction. This is metadata recorded in the close event -- not a gate.
/// The protocol works regardless of attestation level, but higher assurance
/// levels are visible to other participants.
///
/// See ADR-018 acceptance criterion 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyDestructionLevel {
    /// Key destruction is attested by hardware security module (Secure
    /// Enclave, Android Keystore). Provides the highest assurance that
    /// key material has been physically erased.
    HardwareAttested,
    /// Key destruction is attested by software-only mechanisms. The key
    /// material was zeroed in memory and removed from persistent storage,
    /// but without hardware-level guarantees.
    SoftwareOnly,
    /// No attestation is available. Key destruction was requested but
    /// cannot be verified. This is the lowest assurance level.
    NoAttestation,
}

impl std::fmt::Display for KeyDestructionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HardwareAttested => write!(f, "HardwareAttested"),
            Self::SoftwareOnly => write!(f, "SoftwareOnly"),
            Self::NoAttestation => write!(f, "NoAttestation"),
        }
    }
}

// ---------------------------------------------------------------------------
// RelayDeletionRequest
// ---------------------------------------------------------------------------

/// A request to delete encrypted event data from a relay.
///
/// Issued during ephemeral or summary context close. The relay is expected
/// to delete the specified blobs. Relay compliance is tracked by
/// [`RelayDeletionTracker`] -- non-compliant relays are deprioritized for
/// future context creation.
///
/// See ADR-018 acceptance criterion 5 and 8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeletionRequest {
    /// URL of the relay to send the deletion request to.
    pub relay_url: String,
    /// Blob identifiers to delete from the relay.
    pub blob_ids: Vec<BlobId>,
    /// Context identifier for which the blobs were stored.
    pub context_id: ContextId,
    /// Unix timestamp (seconds) when the deletion was requested.
    pub requested_at: u64,
}

// ---------------------------------------------------------------------------
// RelayDeletionResponse
// ---------------------------------------------------------------------------

/// Relay response status for a deletion request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeletionResponseStatus {
    /// The relay confirmed that all requested blobs were deleted.
    Confirmed,
    /// The relay partially deleted the requested blobs (some remain).
    Partial,
    /// The relay rejected or failed to process the deletion request.
    Failed,
    /// No response was received from the relay within the expected window.
    NoResponse,
}

// ---------------------------------------------------------------------------
// KeyDestructionAttestation
// ---------------------------------------------------------------------------

/// Attestation of key destruction, recorded in the close event.
///
/// See ADR-018 acceptance criterion 7: verification level is metadata
/// recorded in the close event -- not a gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDestructionAttestation {
    /// Context for which keys were destroyed.
    pub context_id: ContextId,
    /// Level of attestation achieved.
    pub level: KeyDestructionLevel,
    /// Unix timestamp (seconds) when destruction was attested.
    pub attested_at: u64,
    /// Whether MLS group state (tree secrets, epoch key schedules,
    /// application key material) was destroyed.
    pub mls_group_destroyed: bool,
    /// Whether all sender keys for this context were destroyed.
    pub sender_keys_destroyed: bool,
}

// ---------------------------------------------------------------------------
// KeyDestructionOrchestrator
// ---------------------------------------------------------------------------

/// Orchestrates key destruction for ephemeral (and summary, post-window)
/// context close.
///
/// Coordinates the destruction of MLS group state (tree secrets, all epoch
/// key schedules, application key material) and sender keys, then issues
/// relay deletion requests for all encrypted event data.
///
/// See ADR-018 acceptance criteria 5 and 6.
pub struct KeyDestructionOrchestrator<'a> {
    /// Crypto provider for MLS group and sender key destruction.
    crypto: &'a dyn ContextCryptoProvider,
}

/// Result of a key destruction orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDestructionResult {
    /// Attestation of the key destruction.
    pub attestation: KeyDestructionAttestation,
    /// Relay deletion requests issued for encrypted event data.
    pub deletion_requests: Vec<RelayDeletionRequest>,
}

/// Converts a `context_id` string to a 32-byte array (truncated/zero-padded).
///
/// Mirrors the helper in `ttl.rs` and `manager.rs`.
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    let bytes = context_id.as_bytes();
    let mut result = [0u8; 32];
    let len = bytes.len().min(32);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

impl<'a> KeyDestructionOrchestrator<'a> {
    /// Creates a new orchestrator with the given crypto provider.
    #[must_use]
    pub const fn new(crypto: &'a dyn ContextCryptoProvider) -> Self {
        Self { crypto }
    }

    /// Destroys all key material for an ephemeral context close.
    ///
    /// Performs the following steps in order:
    /// 1. Destroys MLS group state (tree secrets, all epoch key schedules,
    ///    application key material) via the crypto provider.
    /// 2. Destroys all sender keys for this context via the crypto provider.
    /// 3. Issues [`RelayDeletionRequest`]s for all encrypted event data.
    ///
    /// The `attestation_level` parameter records the platform's attestation
    /// level for key destruction. This is metadata -- not a gate.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context whose keys are being destroyed.
    /// * `relay_urls` -- Relay URLs where encrypted event data is stored.
    /// * `blob_ids` -- Blob identifiers of encrypted event data to request
    ///   deletion for.
    /// * `attestation_level` -- Platform-provided attestation level.
    /// * `now` -- Current Unix timestamp (seconds).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if MLS group or sender key
    /// destruction fails.
    pub fn destroy_ephemeral_keys(
        &self,
        context_id: &str,
        relay_urls: &[String],
        blob_ids: &[BlobId],
        attestation_level: KeyDestructionLevel,
        now: u64,
    ) -> Result<KeyDestructionResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Step 1: Destroy MLS group state (tree secrets, epoch key schedules,
        // application key material).
        self.crypto
            .destroy_mls_group(&context_id_bytes)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Step 2: Destroy all sender keys for this context.
        self.crypto
            .destroy_sender_key(&context_id_bytes)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Step 3: Issue relay deletion requests for all encrypted event data.
        let deletion_requests: Vec<RelayDeletionRequest> = relay_urls
            .iter()
            .map(|url| RelayDeletionRequest {
                relay_url: url.clone(),
                blob_ids: blob_ids.to_vec(),
                context_id: context_id.to_owned(),
                requested_at: now,
            })
            .collect();

        let attestation = KeyDestructionAttestation {
            context_id: context_id.to_owned(),
            level: attestation_level,
            attested_at: now,
            mls_group_destroyed: true,
            sender_keys_destroyed: true,
        };

        Ok(KeyDestructionResult {
            attestation,
            deletion_requests,
        })
    }
}

// ---------------------------------------------------------------------------
// RelayDeletionTracker
// ---------------------------------------------------------------------------

/// Tracks relay compliance with deletion requests and deprioritizes
/// non-compliant relays for future context creation.
///
/// Maintains per-relay statistics: total requests, confirmed deletions,
/// partial deletions, failures, and no-responses. Relays with low compliance
/// rates are deprioritized.
///
/// See ADR-018 acceptance criterion 8.
pub struct RelayDeletionTracker {
    /// Per-relay deletion compliance statistics.
    relay_stats: HashMap<String, RelayDeletionStats>,
}

/// Per-relay deletion compliance statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeletionStats {
    /// Total number of deletion requests sent to this relay.
    pub total_requests: u64,
    /// Number of requests the relay confirmed as fully deleted.
    pub confirmed: u64,
    /// Number of requests the relay partially processed.
    pub partial: u64,
    /// Number of requests the relay failed or rejected.
    pub failed: u64,
    /// Number of requests that received no response.
    pub no_response: u64,
}

impl RelayDeletionStats {
    /// Returns the deletion compliance rate as a value between 0.0 and 1.0.
    ///
    /// A relay with zero total requests returns 1.0 (no evidence of
    /// non-compliance).
    #[must_use]
    pub fn compliance_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let rate = self.confirmed as f64 / self.total_requests as f64;
        rate
    }
}

impl RelayDeletionTracker {
    /// Creates a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            relay_stats: HashMap::new(),
        }
    }

    /// Records a relay's response to a deletion request.
    ///
    /// Increments the appropriate counter for the relay URL based on the
    /// response status.
    pub fn record_response(&mut self, relay_url: &str, response: DeletionResponseStatus) {
        let entry = self
            .relay_stats
            .entry(relay_url.to_owned())
            .or_default();

        entry.total_requests += 1;
        match response {
            DeletionResponseStatus::Confirmed => entry.confirmed += 1,
            DeletionResponseStatus::Partial => entry.partial += 1,
            DeletionResponseStatus::Failed => entry.failed += 1,
            DeletionResponseStatus::NoResponse => entry.no_response += 1,
        }
    }

    /// Returns the compliance statistics for a specific relay.
    ///
    /// Returns `None` if no deletion requests have been tracked for this
    /// relay.
    #[must_use]
    pub fn stats_for_relay(&self, relay_url: &str) -> Option<&RelayDeletionStats> {
        self.relay_stats.get(relay_url)
    }

    /// Returns the compliance rate for a specific relay.
    ///
    /// Returns 1.0 if no deletion requests have been tracked (no evidence
    /// of non-compliance). Returns a value between 0.0 and 1.0 otherwise.
    #[must_use]
    pub fn compliance_rate(&self, relay_url: &str) -> f64 {
        self.relay_stats
            .get(relay_url)
            .map_or(1.0, RelayDeletionStats::compliance_rate)
    }

    /// Returns `true` if the relay should be deprioritized for future
    /// context creation based on its deletion compliance record.
    ///
    /// A relay is deprioritized if its compliance rate is below the given
    /// threshold. The default threshold from ADR-012 is 0.5 (50%).
    #[must_use]
    pub fn is_deprioritized(&self, relay_url: &str, threshold: f64) -> bool {
        self.compliance_rate(relay_url) < threshold
    }

    /// Returns all tracked relay URLs and their compliance stats.
    #[must_use]
    pub const fn all_stats(&self) -> &HashMap<String, RelayDeletionStats> {
        &self.relay_stats
    }

    /// Returns relay URLs sorted by compliance rate (ascending -- worst
    /// compliance first). Useful for selecting relays to deprioritize.
    #[must_use]
    pub fn relays_by_compliance(&self) -> Vec<(&str, f64)> {
        let mut relays: Vec<(&str, f64)> = self
            .relay_stats
            .iter()
            .map(|(url, stats)| (url.as_str(), stats.compliance_rate()))
            .collect();
        relays.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        relays
    }
}

impl Default for RelayDeletionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Broadcast scope validation
// ---------------------------------------------------------------------------

/// Validates that the memory scope is permitted for the given context mode.
///
/// Broadcast contexts (spec section 5.14) are restricted to
/// `MemoryScope::Full` only. Ephemeral and Summary scopes promise key
/// destruction semantics that broadcast mode cannot deliver, because
/// broadcast mode uses per-author keys without MLS group management and
/// lacks forward secrecy via epoch ratcheting.
///
/// This function should be called at context creation time.
///
/// # Errors
///
/// Returns [`ContextError::InvalidMemoryScopeForBroadcast`] if the context
/// mode is `Broadcast` and the memory scope is `Ephemeral` or `Summary`.
pub fn validate_memory_scope_for_broadcast(
    mode: ContextMode,
    scope: MemoryScope,
) -> Result<(), ContextError> {
    if mode == ContextMode::Broadcast && scope != MemoryScope::Full {
        return Err(ContextError::InvalidMemoryScopeForBroadcast);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::builder::{ContextCreationError, ContextCryptoProvider};
    use crate::context::{ContextError, ContextMode, MemoryScope};

    // -----------------------------------------------------------------------
    // Mock crypto provider for testing key destruction
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockCryptoProvider {
        mls_destroyed: AtomicBool,
        sender_key_destroyed: AtomicBool,
        fail_mls: bool,
        fail_sender: bool,
    }

    impl MockCryptoProvider {
        fn new() -> Self {
            Self {
                mls_destroyed: AtomicBool::new(false),
                sender_key_destroyed: AtomicBool::new(false),
                fail_mls: false,
                fail_sender: false,
            }
        }

        fn failing_mls() -> Self {
            Self {
                mls_destroyed: AtomicBool::new(false),
                sender_key_destroyed: AtomicBool::new(false),
                fail_mls: true,
                fail_sender: false,
            }
        }

        fn failing_sender() -> Self {
            Self {
                mls_destroyed: AtomicBool::new(false),
                sender_key_destroyed: AtomicBool::new(false),
                fail_mls: false,
                fail_sender: true,
            }
        }
    }

    impl ContextCryptoProvider for MockCryptoProvider {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn create_mls_group(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn generate_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn init_broadcast_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn destroy_mls_group(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_mls {
                return Err(ContextCreationError::CryptoFailed(
                    "MLS destruction failed".to_owned(),
                ));
            }
            self.mls_destroyed.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn destroy_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_sender {
                return Err(ContextCreationError::CryptoFailed(
                    "sender key destruction failed".to_owned(),
                ));
            }
            self.sender_key_destroyed.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn validate_key_package(&self, _owner_did: &str) -> Result<(), ContextError> {
            Ok(())
        }

        fn add_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            _payload: &[u8],
        ) -> Result<Vec<u8>, ContextError> {
            Ok(vec![])
        }
    }

    // -----------------------------------------------------------------------
    // KeyDestructionLevel tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_destruction_level_display() {
        assert_eq!(
            format!("{}", KeyDestructionLevel::HardwareAttested),
            "HardwareAttested"
        );
        assert_eq!(
            format!("{}", KeyDestructionLevel::SoftwareOnly),
            "SoftwareOnly"
        );
        assert_eq!(
            format!("{}", KeyDestructionLevel::NoAttestation),
            "NoAttestation"
        );
    }

    #[test]
    fn key_destruction_level_variants_are_distinct() {
        assert_ne!(
            KeyDestructionLevel::HardwareAttested,
            KeyDestructionLevel::SoftwareOnly
        );
        assert_ne!(
            KeyDestructionLevel::SoftwareOnly,
            KeyDestructionLevel::NoAttestation
        );
        assert_ne!(
            KeyDestructionLevel::HardwareAttested,
            KeyDestructionLevel::NoAttestation
        );
    }

    #[test]
    fn key_destruction_level_serialization_roundtrip() {
        let levels = [
            KeyDestructionLevel::HardwareAttested,
            KeyDestructionLevel::SoftwareOnly,
            KeyDestructionLevel::NoAttestation,
        ];
        for level in &levels {
            let json = serde_json::to_string(level).unwrap();
            let deserialized: KeyDestructionLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, level);
        }
    }

    // -----------------------------------------------------------------------
    // RelayDeletionRequest tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_deletion_request_construction() {
        let blob_id: BlobId = [0xAB; 32];
        let req = RelayDeletionRequest {
            relay_url: "wss://relay.example.com".to_owned(),
            blob_ids: vec![blob_id],
            context_id: "ctx-42".to_owned(),
            requested_at: 1_700_000_000,
        };
        assert_eq!(req.relay_url, "wss://relay.example.com");
        assert_eq!(req.blob_ids.len(), 1);
        assert_eq!(req.blob_ids[0], [0xAB; 32]);
        assert_eq!(req.context_id, "ctx-42");
        assert_eq!(req.requested_at, 1_700_000_000);
    }

    #[test]
    fn relay_deletion_request_serialization_roundtrip() {
        let req = RelayDeletionRequest {
            relay_url: "wss://relay.example.com".to_owned(),
            blob_ids: vec![[0x01; 32], [0x02; 32]],
            context_id: "ctx-99".to_owned(),
            requested_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: RelayDeletionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, req);
    }

    // -----------------------------------------------------------------------
    // KeyDestructionOrchestrator tests
    // -----------------------------------------------------------------------

    #[test]
    fn destroy_ephemeral_keys_destroys_mls_and_sender_keys() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = KeyDestructionOrchestrator::new(&crypto);

        let result = orchestrator.destroy_ephemeral_keys(
            "ctx-1",
            &["wss://relay1.example.com".to_owned()],
            &[[0x01; 32]],
            KeyDestructionLevel::SoftwareOnly,
            1_700_000_000,
        );

        assert!(result.is_ok());
        assert!(crypto.mls_destroyed.load(Ordering::SeqCst));
        assert!(crypto.sender_key_destroyed.load(Ordering::SeqCst));
    }

    #[test]
    fn destroy_ephemeral_keys_issues_relay_deletion_requests() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = KeyDestructionOrchestrator::new(&crypto);

        let relay_urls = vec![
            "wss://relay1.example.com".to_owned(),
            "wss://relay2.example.com".to_owned(),
        ];
        let blob_ids = vec![[0x01; 32], [0x02; 32]];

        let result = orchestrator
            .destroy_ephemeral_keys(
                "ctx-1",
                &relay_urls,
                &blob_ids,
                KeyDestructionLevel::HardwareAttested,
                1_700_000_000,
            )
            .unwrap();

        assert_eq!(result.deletion_requests.len(), 2);
        assert_eq!(
            result.deletion_requests[0].relay_url,
            "wss://relay1.example.com"
        );
        assert_eq!(
            result.deletion_requests[1].relay_url,
            "wss://relay2.example.com"
        );
        // Each relay request should include all blob_ids.
        for req in &result.deletion_requests {
            assert_eq!(req.blob_ids.len(), 2);
            assert_eq!(req.context_id, "ctx-1");
            assert_eq!(req.requested_at, 1_700_000_000);
        }
    }

    #[test]
    fn destroy_ephemeral_keys_returns_attestation() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = KeyDestructionOrchestrator::new(&crypto);

        let result = orchestrator
            .destroy_ephemeral_keys(
                "ctx-1",
                &[],
                &[],
                KeyDestructionLevel::HardwareAttested,
                1_700_000_000,
            )
            .unwrap();

        assert_eq!(result.attestation.context_id, "ctx-1");
        assert_eq!(
            result.attestation.level,
            KeyDestructionLevel::HardwareAttested
        );
        assert_eq!(result.attestation.attested_at, 1_700_000_000);
        assert!(result.attestation.mls_group_destroyed);
        assert!(result.attestation.sender_keys_destroyed);
    }

    #[test]
    fn destroy_ephemeral_keys_records_attestation_level_not_gates() {
        // NoAttestation level is recorded as metadata but does not prevent
        // key destruction from succeeding.
        let crypto = MockCryptoProvider::new();
        let orchestrator = KeyDestructionOrchestrator::new(&crypto);

        let result = orchestrator.destroy_ephemeral_keys(
            "ctx-1",
            &[],
            &[],
            KeyDestructionLevel::NoAttestation,
            1_700_000_000,
        );

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.attestation.level, KeyDestructionLevel::NoAttestation);
    }

    #[test]
    fn destroy_ephemeral_keys_fails_on_mls_destruction_error() {
        let crypto = MockCryptoProvider::failing_mls();
        let orchestrator = KeyDestructionOrchestrator::new(&crypto);

        let result = orchestrator.destroy_ephemeral_keys(
            "ctx-1",
            &[],
            &[],
            KeyDestructionLevel::SoftwareOnly,
            1_700_000_000,
        );

        assert!(result.is_err());
        match result {
            Err(ContextError::CryptoFailed(msg)) => {
                assert!(msg.contains("MLS destruction failed"));
            }
            _ => panic!("expected CryptoFailed error"),
        }
    }

    #[test]
    fn destroy_ephemeral_keys_fails_on_sender_key_destruction_error() {
        let crypto = MockCryptoProvider::failing_sender();
        let orchestrator = KeyDestructionOrchestrator::new(&crypto);

        let result = orchestrator.destroy_ephemeral_keys(
            "ctx-1",
            &[],
            &[],
            KeyDestructionLevel::SoftwareOnly,
            1_700_000_000,
        );

        assert!(result.is_err());
        match result {
            Err(ContextError::CryptoFailed(msg)) => {
                assert!(msg.contains("sender key destruction failed"));
            }
            _ => panic!("expected CryptoFailed error"),
        }
    }

    #[test]
    fn destroy_ephemeral_keys_with_no_relays_returns_empty_requests() {
        let crypto = MockCryptoProvider::new();
        let orchestrator = KeyDestructionOrchestrator::new(&crypto);

        let result = orchestrator
            .destroy_ephemeral_keys(
                "ctx-1",
                &[],
                &[],
                KeyDestructionLevel::SoftwareOnly,
                1_700_000_000,
            )
            .unwrap();

        assert!(result.deletion_requests.is_empty());
    }

    // -----------------------------------------------------------------------
    // RelayDeletionTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_deletion_tracker_new_is_empty() {
        let tracker = RelayDeletionTracker::new();
        assert!(tracker.all_stats().is_empty());
    }

    #[test]
    fn relay_deletion_tracker_default_is_empty() {
        let tracker = RelayDeletionTracker::default();
        assert!(tracker.all_stats().is_empty());
    }

    #[test]
    fn relay_deletion_tracker_records_confirmed_response() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);

        let stats = tracker.stats_for_relay("wss://relay.example.com").unwrap();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.confirmed, 1);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn relay_deletion_tracker_records_multiple_responses() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        let stats = tracker.stats_for_relay("wss://relay.example.com").unwrap();
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.confirmed, 2);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn relay_deletion_tracker_tracks_all_response_types() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Partial);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::NoResponse);

        let stats = tracker.stats_for_relay("wss://relay.example.com").unwrap();
        assert_eq!(stats.total_requests, 4);
        assert_eq!(stats.confirmed, 1);
        assert_eq!(stats.partial, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.no_response, 1);
    }

    #[test]
    fn relay_deletion_tracker_unknown_relay_returns_none() {
        let tracker = RelayDeletionTracker::new();
        assert!(tracker.stats_for_relay("wss://unknown.example.com").is_none());
    }

    #[test]
    fn relay_deletion_tracker_compliance_rate_full_compliance() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);

        let rate = tracker.compliance_rate("wss://relay.example.com");
        assert!((rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_compliance_rate_zero_compliance() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        let rate = tracker.compliance_rate("wss://relay.example.com");
        assert!(rate.abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_compliance_rate_partial() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        let rate = tracker.compliance_rate("wss://relay.example.com");
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_unknown_relay_compliance_is_1() {
        let tracker = RelayDeletionTracker::new();
        let rate = tracker.compliance_rate("wss://unknown.example.com");
        assert!((rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_deprioritized_below_threshold() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);

        // compliance_rate = 1/3 ~= 0.333, which is below 0.5
        assert!(tracker.is_deprioritized("wss://relay.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_not_deprioritized_above_threshold() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        // compliance_rate = 2/3 ~= 0.667, which is above 0.5
        assert!(!tracker.is_deprioritized("wss://relay.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_unknown_relay_not_deprioritized() {
        let tracker = RelayDeletionTracker::new();
        assert!(!tracker.is_deprioritized("wss://unknown.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_multiple_relays() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://good.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://good.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://bad.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://bad.example.com", DeletionResponseStatus::Failed);

        assert!((tracker.compliance_rate("wss://good.example.com") - 1.0).abs() < f64::EPSILON);
        assert!(tracker.compliance_rate("wss://bad.example.com").abs() < f64::EPSILON);

        assert!(!tracker.is_deprioritized("wss://good.example.com", 0.5));
        assert!(tracker.is_deprioritized("wss://bad.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_relays_by_compliance_sorted() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://good.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://bad.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://mid.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://mid.example.com", DeletionResponseStatus::Failed);

        let sorted = tracker.relays_by_compliance();
        assert_eq!(sorted.len(), 3);
        // Worst compliance first.
        assert_eq!(sorted[0].0, "wss://bad.example.com");
        assert!(sorted[0].1.abs() < f64::EPSILON);
        assert_eq!(sorted[1].0, "wss://mid.example.com");
        assert!((sorted[1].1 - 0.5).abs() < f64::EPSILON);
        assert_eq!(sorted[2].0, "wss://good.example.com");
        assert!((sorted[2].1 - 1.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Broadcast scope validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_broadcast_full_scope_succeeds() {
        let result =
            validate_memory_scope_for_broadcast(ContextMode::Broadcast, MemoryScope::Full);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_broadcast_ephemeral_scope_rejected() {
        let result =
            validate_memory_scope_for_broadcast(ContextMode::Broadcast, MemoryScope::Ephemeral);
        assert!(result.is_err());
        match result {
            Err(ContextError::InvalidMemoryScopeForBroadcast) => {}
            _ => panic!("expected InvalidMemoryScopeForBroadcast error"),
        }
    }

    #[test]
    fn validate_broadcast_summary_scope_rejected() {
        let result =
            validate_memory_scope_for_broadcast(ContextMode::Broadcast, MemoryScope::Summary);
        assert!(result.is_err());
        match result {
            Err(ContextError::InvalidMemoryScopeForBroadcast) => {}
            _ => panic!("expected InvalidMemoryScopeForBroadcast error"),
        }
    }

    #[test]
    fn validate_encrypted_all_scopes_accepted() {
        assert!(validate_memory_scope_for_broadcast(
            ContextMode::Encrypted,
            MemoryScope::Ephemeral
        )
        .is_ok());
        assert!(validate_memory_scope_for_broadcast(
            ContextMode::Encrypted,
            MemoryScope::Summary
        )
        .is_ok());
        assert!(
            validate_memory_scope_for_broadcast(ContextMode::Encrypted, MemoryScope::Full).is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // KeyDestructionAttestation tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_destruction_attestation_serialization_roundtrip() {
        let attestation = KeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            level: KeyDestructionLevel::HardwareAttested,
            attested_at: 1_700_000_000,
            mls_group_destroyed: true,
            sender_keys_destroyed: true,
        };
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: KeyDestructionAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, attestation);
    }

    // -----------------------------------------------------------------------
    // RelayDeletionStats tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_deletion_stats_default_values() {
        let stats = RelayDeletionStats::default();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.confirmed, 0);
        assert_eq!(stats.partial, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.no_response, 0);
    }

    #[test]
    fn relay_deletion_stats_compliance_rate_no_requests() {
        let stats = RelayDeletionStats::default();
        assert!((stats.compliance_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_stats_serialization_roundtrip() {
        let stats = RelayDeletionStats {
            total_requests: 10,
            confirmed: 7,
            partial: 1,
            failed: 1,
            no_response: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: RelayDeletionStats = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, stats);
    }

    // -----------------------------------------------------------------------
    // DeletionResponseStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn deletion_response_status_serialization_roundtrip() {
        let statuses = [
            DeletionResponseStatus::Confirmed,
            DeletionResponseStatus::Partial,
            DeletionResponseStatus::Failed,
            DeletionResponseStatus::NoResponse,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: DeletionResponseStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, status);
        }
    }
}
