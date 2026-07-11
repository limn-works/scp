//! Memory scope enforcement and key destruction data types.
//!
//! Implements ADR-018 (`.docs/adrs/phase-4.md`), sections 5-9:
//!
//! - [`KeyDestructionLevel`] -- Attestation level for key destruction
//!   verification (hardware-attested, software-only, no attestation).
//! - [`RelayDeletionRequest`] -- Request to delete encrypted event data from a
//!   relay.
//! - [`RelayDeletionTracker`] -- Tracks relay compliance with deletion requests
//!   and deprioritizes non-compliant relays.
//! - [`validate_memory_scope_for_broadcast`] -- Rejects `Ephemeral` or
//!   `Summary` memory scopes for broadcast contexts.
//!
//! The `KeyDestructionOrchestrator` (which actually invokes the crypto
//! provider to destroy keys) lives in
//! `scp_runtime::context::key_destruction` after ADR-049 commit 12c.9e —
//! it operates on the concrete `MlsCryptoProvider` and so cannot live in
//! `scp-protocol` (forward dep).
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
// KeyDestructionAttestation (internal tracking)
// ---------------------------------------------------------------------------

/// Internal attestation of key destruction, recorded in the close event.
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
// DestructionMethod (§9.15)
// ---------------------------------------------------------------------------

/// Method used for key destruction, determining the trust level of the
/// destruction claim.
///
/// See spec §9.15: hardware-backed provides high confidence; software-only
/// provides moderate confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestructionMethod {
    /// Key destruction is backed by a hardware security module (Secure
    /// Enclave, Android Keystore). The hardware claims the key is gone.
    HardwareBacked,
    /// Key destruction is software-only (`memset(0)` on key material in
    /// memory). Memory dumps, swap files, or crash logs may have retained
    /// the key.
    SoftwareOnly,
}

impl std::fmt::Display for DestructionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HardwareBacked => write!(f, "HardwareBacked"),
            Self::SoftwareOnly => write!(f, "SoftwareOnly"),
        }
    }
}

// ---------------------------------------------------------------------------
// PlatformAttestation (§9.15)
// ---------------------------------------------------------------------------

/// Platform-provided attestation for key destruction, if available.
///
/// Contains opaque attestation data from the platform's hardware security
/// module (e.g., Secure Enclave attestation blob, Android Keystore
/// attestation certificate chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformAttestation {
    /// Opaque platform attestation data (format is platform-specific).
    pub attestation_data: Vec<u8>,
    /// Human-readable platform identifier (e.g., "apple-secure-enclave",
    /// "android-keystore").
    pub platform: String,
}

// ---------------------------------------------------------------------------
// PublishableKeyDestructionAttestation (§9.15)
// ---------------------------------------------------------------------------

/// Publishable key destruction attestation per spec §9.15.
///
/// Published to relays after context key destruction. Signed by the
/// member's Identity Key (`#0`) or Active Signing Key (`#active`) — NOT
/// the Agent Signing Key (`#agent`, ADR-039). The signature remains
/// verifiable after context keys are destroyed because it is bound to the
/// identity key, not the context key material.
///
/// Trust levels:
/// - **Hardware-attested:** High confidence (hardware claims key is gone).
/// - **Software-only:** Moderate confidence (memory zeroed, no hardware
///   guarantee).
/// - **No attestation:** Member went offline before close (not represented
///   here — the absence of an attestation IS the "no attestation" case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishableKeyDestructionAttestation {
    /// The context for which keys were destroyed.
    pub context_id: ContextId,
    /// The DID of the member who destroyed their keys.
    pub member_did: String,
    /// Unix timestamp (seconds) when keys were destroyed.
    pub destroyed_at: u64,
    /// Platform-provided attestation, if hardware-backed destruction was
    /// used. `None` for software-only destruction.
    pub platform_attestation: Option<PlatformAttestation>,
    /// The destruction method used.
    pub method: DestructionMethod,
    /// Ed25519 signature over the attestation payload, signed by `#0`
    /// (Identity Key) or `#active` (Active Signing Key). NOT `#agent`
    /// per ADR-039 — agents cannot sign destruction attestations.
    ///
    /// Stored as `Vec<u8>` (always 64 bytes) because `[u8; 64]` does not
    /// implement `Serialize`/`Deserialize` in serde without additional
    /// configuration.
    pub signature: Vec<u8>,
}

impl PublishableKeyDestructionAttestation {
    /// Validates that the signature field is the correct length (64 bytes).
    #[must_use]
    pub const fn has_valid_signature_length(&self) -> bool {
        self.signature.len() == 64
    }

    /// Returns the signing payload for this attestation.
    ///
    /// The payload is length-prefixed to prevent field-boundary ambiguity:
    /// ```text
    /// "SCP-KEY-DESTRUCTION-V1:"
    ///   || len(context_id) (4 bytes BE) || context_id
    ///   || len(member_did) (4 bytes BE) || member_did
    ///   || destroyed_at (8 bytes BE)
    ///   || len(method) (4 bytes BE) || method
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SCP-KEY-DESTRUCTION-V1:");

        let ctx_bytes = self.context_id.as_bytes();
        payload.extend_from_slice(&(ctx_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(ctx_bytes);

        let did_bytes = self.member_did.as_bytes();
        payload.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(did_bytes);

        payload.extend_from_slice(&self.destroyed_at.to_be_bytes());

        let method_str = self.method.to_string();
        let method_bytes = method_str.as_bytes();
        payload.extend_from_slice(&(method_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(method_bytes);
        payload
    }
}

// ---------------------------------------------------------------------------
// EphemeralContextMetadata (§5.11 durable metadata)
// ---------------------------------------------------------------------------

/// Durable metadata that persists after ephemeral context close.
///
/// Per spec §5.11: "Durable metadata persists: who participated, when, the
/// declared purpose, participation contributions (participation counts,
/// outlet invocations), and discovery provenance."
///
/// Content and messages are NOT included — they are destroyed with the keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralContextMetadata {
    /// The context identifier.
    pub context_id: ContextId,
    /// DIDs of all participants who were members during the context's
    /// lifetime.
    pub participants: Vec<String>,
    /// Unix timestamp (seconds) when the context was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the context was closed/expired.
    pub closed_at: u64,
    /// The declared purpose/description from context params.
    pub purpose: Option<String>,
    /// Per-participant message counts.
    pub participation_counts: HashMap<String, u64>,
    /// Memory scope at close time (always `Ephemeral` for this struct).
    pub memory_scope: super::MemoryScope,
}

// ---------------------------------------------------------------------------
// KeyDestructionResult
// ---------------------------------------------------------------------------

/// Result of a key destruction orchestration.
///
/// Produced by the runtime-side `KeyDestructionOrchestrator`
/// (`scp_runtime::context::key_destruction`). Lives in `scp-protocol` as a
/// pure-data payload because it crosses the protocol → runtime boundary
/// and has no crypto-provider dependency of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDestructionResult {
    /// Attestation of the key destruction.
    pub attestation: KeyDestructionAttestation,
    /// Relay deletion requests issued for encrypted event data.
    pub deletion_requests: Vec<RelayDeletionRequest>,
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
        // Ratio of small counts; precision loss is negligible.
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
        let entry = self.relay_stats.entry(relay_url.to_owned()).or_default();

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
    use crate::context::{ContextError, ContextMode, MemoryScope};

    // Note: `KeyDestructionOrchestrator` tests moved to
    // `scp_runtime::context::key_destruction` in ADR-049 commit 12c.9e —
    // the orchestrator now operates on the concrete `MlsCryptoProvider`
    // which lives in scp-runtime (forward dep of scp-protocol).

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
        tracker.record_response(
            "wss://relay.example.com",
            DeletionResponseStatus::NoResponse,
        );

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
        assert!(
            tracker
                .stats_for_relay("wss://unknown.example.com")
                .is_none()
        );
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
        let result = validate_memory_scope_for_broadcast(ContextMode::Broadcast, MemoryScope::Full);
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
        assert!(
            validate_memory_scope_for_broadcast(ContextMode::Encrypted, MemoryScope::Ephemeral)
                .is_ok()
        );
        assert!(
            validate_memory_scope_for_broadcast(ContextMode::Encrypted, MemoryScope::Summary)
                .is_ok()
        );
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

    // -----------------------------------------------------------------------
    // DestructionMethod tests (§9.15)
    // -----------------------------------------------------------------------

    #[test]
    fn destruction_method_display() {
        assert_eq!(
            format!("{}", DestructionMethod::HardwareBacked),
            "HardwareBacked"
        );
        assert_eq!(
            format!("{}", DestructionMethod::SoftwareOnly),
            "SoftwareOnly"
        );
    }

    #[test]
    fn destruction_method_variants_are_distinct() {
        assert_ne!(
            DestructionMethod::HardwareBacked,
            DestructionMethod::SoftwareOnly
        );
    }

    #[test]
    fn destruction_method_serialization_roundtrip() {
        let methods = [
            DestructionMethod::HardwareBacked,
            DestructionMethod::SoftwareOnly,
        ];
        for method in &methods {
            let json = serde_json::to_string(method).unwrap();
            let deserialized: DestructionMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, method);
        }
    }

    // -----------------------------------------------------------------------
    // PlatformAttestation tests (§9.15)
    // -----------------------------------------------------------------------

    #[test]
    fn platform_attestation_serialization_roundtrip() {
        let attestation = PlatformAttestation {
            attestation_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            platform: "apple-secure-enclave".to_owned(),
        };
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: PlatformAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, attestation);
    }

    // -----------------------------------------------------------------------
    // PublishableKeyDestructionAttestation tests (§9.15)
    // -----------------------------------------------------------------------

    #[test]
    fn publishable_attestation_serialization_roundtrip() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-42".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: Some(PlatformAttestation {
                attestation_data: vec![0x01, 0x02],
                platform: "android-keystore".to_owned(),
            }),
            method: DestructionMethod::HardwareBacked,
            signature: vec![0xAA; 64],
        };
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: PublishableKeyDestructionAttestation =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, attestation);
    }

    #[test]
    fn publishable_attestation_valid_signature_length() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:bob".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signature: vec![0x00; 64],
        };
        assert!(attestation.has_valid_signature_length());
    }

    #[test]
    fn publishable_attestation_invalid_signature_length() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:bob".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signature: vec![0x00; 32], // Wrong length
        };
        assert!(!attestation.has_valid_signature_length());
    }

    #[test]
    fn publishable_attestation_signing_payload_deterministic() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signature: vec![0x00; 64],
        };
        let payload1 = attestation.signing_payload();
        let payload2 = attestation.signing_payload();
        assert_eq!(payload1, payload2);
        assert!(!payload1.is_empty());
    }

    #[test]
    fn publishable_attestation_no_platform_attestation_for_software_only() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:carol".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signature: vec![0xFF; 64],
        };
        assert!(attestation.platform_attestation.is_none());
        assert_eq!(attestation.method, DestructionMethod::SoftwareOnly);
    }

    // -----------------------------------------------------------------------
    // EphemeralContextMetadata tests (§5.11)
    // -----------------------------------------------------------------------

    #[test]
    fn ephemeral_metadata_serialization_roundtrip() {
        let mut counts = HashMap::new();
        counts.insert("did:dht:alice".to_owned(), 15);
        counts.insert("did:dht:bob".to_owned(), 8);
        let metadata = EphemeralContextMetadata {
            context_id: "ctx-ephemeral".to_owned(),
            participants: vec!["did:dht:alice".to_owned(), "did:dht:bob".to_owned()],
            created_at: 1_700_000_000,
            closed_at: 1_700_001_000,
            purpose: Some("Quick brainstorm".to_owned()),
            participation_counts: counts,
            memory_scope: crate::context::MemoryScope::Ephemeral,
        };
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: EphemeralContextMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, metadata);
    }

    #[test]
    fn ephemeral_metadata_preserves_participants_after_creation() {
        let metadata = EphemeralContextMetadata {
            context_id: "ctx-1".to_owned(),
            participants: vec![
                "did:dht:alice".to_owned(),
                "did:dht:bob".to_owned(),
                "did:dht:carol".to_owned(),
            ],
            created_at: 1_700_000_000,
            closed_at: 1_700_000_300,
            purpose: None,
            participation_counts: HashMap::new(),
            memory_scope: crate::context::MemoryScope::Ephemeral,
        };
        // Verify all participants are preserved.
        assert_eq!(metadata.participants.len(), 3);
        assert!(metadata.participants.contains(&"did:dht:alice".to_owned()));
        assert!(metadata.participants.contains(&"did:dht:bob".to_owned()));
        assert!(metadata.participants.contains(&"did:dht:carol".to_owned()));
        // Creation time is preserved.
        assert_eq!(metadata.created_at, 1_700_000_000);
    }
}
