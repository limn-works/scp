//! Tiered event log storage with cold proof fetching.
//!
//! Separates event storage into two tiers:
//!
//! - **Hot tier:** Recent events stored on-device for fast access. Backed by
//!   an in-memory [`EventLog`] with full Merkle tree structure.
//! - **Cold tier:** Older events offloaded to relay storage. Only leaf hashes
//!   and metadata are retained locally. Full events and inclusion proofs are
//!   fetched on-demand from the relay via [`ColdTierProvider`].
//!
//! Relays are untrusted -- all proofs fetched from cold storage are
//! cryptographically verified client-side using [`proof::verify_inclusion`].
//!
//! # Types
//!
//! - [`TierConfig`] -- Configurable thresholds for tier migration.
//! - [`TieredEventLog`] -- Wraps an [`EventLog`] with hot/cold tier separation.
//! - [`ColdTierProvider`] -- Async trait for fetching cold events from a relay.
//! - [`ColdTierEntry`] -- Local metadata retained for a cold-tier event.
//! - [`TierMigrationResult`] -- Statistics from a migration operation.
//! - [`TieredStorageError`] -- Error type for tiered storage operations.
//!
//! # Operations
//!
//! - [`TieredEventLog::migrate_to_cold`] -- Move eligible hot events to cold.
//! - [`TieredEventLog::fetch_cold_proof`] -- Fetch and verify a cold proof.
//! - [`TieredEventLog::hot_event_count`] -- Number of events in hot tier.
//! - [`TieredEventLog::cold_event_count`] -- Number of events in cold tier.
//! - [`TieredEventLog::total_event_count`] -- Total events across both tiers.
//!
//! See ADR-030 in `.docs/adrs/phase-6.md`.

use super::proof::{self, InclusionProof};
use super::{EventLog, EventLogError};
use crate::tree;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default age threshold for tier migration: 7 days in seconds.
///
/// Events older than this are eligible for migration to cold storage.
const DEFAULT_AGE_THRESHOLD_SECS: u64 = 604_800;

/// Default maximum number of events to retain in hot storage.
const DEFAULT_MAX_HOT_EVENTS: u64 = 10_000;

/// Default maximum hot tier storage size in bytes (50 MB).
const DEFAULT_MAX_HOT_BYTES: u64 = 50 * 1024 * 1024;

// ---------------------------------------------------------------------------
// TierConfig
// ---------------------------------------------------------------------------

/// Configurable thresholds for tier migration.
///
/// Controls when events are moved from the hot tier (on-device) to the cold
/// tier (relay-hosted). Both age-based and size-based thresholds are
/// supported; migration is triggered when any threshold is exceeded.
///
/// See ADR-030 section 2.
#[derive(Debug, Clone)]
pub struct TierConfig {
    /// Age threshold in seconds. Events older than `now - age_threshold_secs`
    /// are eligible for migration to cold storage.
    ///
    /// `None` disables age-based migration.
    pub age_threshold_secs: Option<u64>,

    /// Maximum number of events to retain in hot storage. When the hot tier
    /// exceeds this count, the oldest events are migrated to cold.
    ///
    /// `None` disables count-based migration.
    pub max_hot_events: Option<u64>,

    /// Maximum storage bytes for the hot tier. When exceeded, oldest events
    /// are migrated to cold.
    ///
    /// `None` disables size-based migration.
    pub max_hot_bytes: Option<u64>,
}

impl Default for TierConfig {
    fn default() -> Self {
        Self {
            age_threshold_secs: Some(DEFAULT_AGE_THRESHOLD_SECS),
            max_hot_events: Some(DEFAULT_MAX_HOT_EVENTS),
            max_hot_bytes: Some(DEFAULT_MAX_HOT_BYTES),
        }
    }
}

// ---------------------------------------------------------------------------
// ColdTierEntry
// ---------------------------------------------------------------------------

/// Local metadata retained for a cold-tier event.
///
/// When an event is migrated to cold storage, the full event payload is
/// removed from the device. Only the leaf hash, sequence number, and
/// timestamp are retained locally. This is sufficient to request and verify
/// inclusion proofs from the relay.
#[derive(Debug, Clone)]
pub struct ColdTierEntry {
    /// The leaf hash of the event (SHA-256 with RFC 6962 domain separation).
    pub leaf_hash: [u8; 32],
    /// The global sequence number of the event in the original log.
    pub sequence: u64,
    /// The timestamp of the event (Unix seconds).
    pub timestamp: u64,
    /// Estimated size of the original event payload in bytes.
    pub payload_bytes: u64,
}

// ---------------------------------------------------------------------------
// ColdTierProvider
// ---------------------------------------------------------------------------

/// Async trait for fetching cold-tier events and proofs from a relay.
///
/// Relays are untrusted -- implementations fetch data from any relay, but
/// all returned proofs must be verified client-side before use.
///
/// The trait is object-safe and uses `async_trait`-style boxing to avoid
/// requiring `async fn` in traits (compatible with stable Rust).
pub trait ColdTierProvider: Send + Sync {
    /// Fetches an inclusion proof for a cold-tier event from the relay.
    ///
    /// The relay returns a Merkle inclusion proof for the event at
    /// `leaf_index` with the given `leaf_hash`. The proof is verified
    /// against `expected_root` by the caller -- the provider itself
    /// does NOT verify.
    ///
    /// # Errors
    ///
    /// Returns [`TieredStorageError::ColdFetchFailed`] if the relay is
    /// unreachable or returns an invalid response.
    fn fetch_inclusion_proof(
        &self,
        context_id: &str,
        leaf_index: u64,
        leaf_hash: [u8; 32],
    ) -> Result<InclusionProof, TieredStorageError>;
}

// ---------------------------------------------------------------------------
// TieredStorageError
// ---------------------------------------------------------------------------

/// Errors produced by tiered storage operations.
#[derive(Debug, thiserror::Error)]
pub enum TieredStorageError {
    /// The event log operation failed.
    #[error("event log error: {0}")]
    EventLogError(#[from] EventLogError),

    /// Cold tier fetch failed (relay unreachable or invalid response).
    #[error("cold tier fetch failed: {0}")]
    ColdFetchFailed(String),

    /// The inclusion proof fetched from the relay failed verification.
    ///
    /// This indicates the relay returned a forged or corrupted proof.
    /// The relay is untrusted -- verification failure is expected when
    /// the relay is malicious.
    #[error("cold proof verification failed for leaf index {leaf_index}")]
    ColdProofVerificationFailed {
        /// The leaf index of the event whose proof failed.
        leaf_index: u64,
    },

    /// The requested event is not in the cold tier.
    #[error("event at sequence {sequence} is not in the cold tier")]
    NotInColdTier {
        /// The sequence number that was requested.
        sequence: u64,
    },

    /// No events are eligible for migration.
    #[error("no events eligible for migration to cold tier")]
    NothingToMigrate,

    /// The tier configuration has no thresholds enabled.
    #[error("tier configuration has no migration thresholds enabled")]
    NoThresholdsConfigured,
}

// ---------------------------------------------------------------------------
// TierMigrationResult
// ---------------------------------------------------------------------------

/// Statistics from a tier migration operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierMigrationResult {
    /// Number of events migrated from hot to cold.
    pub events_migrated: u64,
    /// Estimated bytes freed from hot storage.
    pub bytes_freed: u64,
    /// Number of events remaining in hot storage.
    pub hot_events_remaining: u64,
    /// Number of events now in cold storage (total).
    pub cold_events_total: u64,
}

// ---------------------------------------------------------------------------
// TieredEventLog
// ---------------------------------------------------------------------------

/// An event log with hot/cold tier separation.
///
/// The hot tier is a standard [`EventLog`] holding recent events with full
/// Merkle tree structure for fast proof generation. The cold tier is a
/// local index of [`ColdTierEntry`] metadata for events that have been
/// offloaded to relay storage.
///
/// Device storage is bounded: the hot tier size is controlled by
/// [`TierConfig`], and cold entries are lightweight (leaf hash + metadata).
///
/// A ghost collection of all leaf hashes (cold + hot) is maintained so that
/// the checkpoint root always spans the full log. This ensures cold proofs
/// remain verifiable across multiple migration cycles.
///
/// See ADR-030 in `.docs/adrs/phase-6.md`.
pub struct TieredEventLog {
    /// The hot-tier event log (recent events, full Merkle tree).
    hot: EventLog,
    /// Cold-tier entries (metadata only, ordered by sequence).
    cold_entries: Vec<ColdTierEntry>,
    /// Tier migration configuration.
    config: TierConfig,
    /// The Merkle root of the complete log (all events ever appended,
    /// spanning both cold and hot tiers). Computed from `all_leaf_hashes`
    /// at each migration.
    ///
    /// This root is authoritative for cold proof verification. It is set
    /// once at the first migration and recomputed from the full ghost tree
    /// on each subsequent migration, ensuring it always spans ALL cold
    /// entries -- not just the most recently migrated batch.
    ///
    /// When no migration has occurred, this is `[0u8; 32]` (the hot tier
    /// root is authoritative).
    checkpoint_root: [u8; 32],
    /// Ghost collection of ALL leaf hashes in global append order (cold +
    /// hot). Maintained across migrations so the checkpoint root can always
    /// be recomputed from the full log state.
    all_leaf_hashes: Vec<[u8; 32]>,
    /// The number of events that have been migrated to cold storage. This
    /// serves as the global index offset for the hot log: hot leaf 0
    /// corresponds to global index `global_index_offset`.
    global_index_offset: u64,
    /// Timestamps of events in the hot tier, parallel to `hot.leaves()`.
    /// Used for age-based migration decisions.
    hot_timestamps: Vec<u64>,
    /// Estimated byte sizes of events in the hot tier, parallel to
    /// `hot.leaves()`. Used for size-based migration decisions.
    hot_byte_sizes: Vec<u64>,
}

impl TieredEventLog {
    /// Creates a new tiered event log with the given configuration.
    #[must_use]
    pub const fn new(context_id: String, config: TierConfig) -> Self {
        Self {
            hot: EventLog::new(context_id),
            cold_entries: Vec::new(),
            config,
            checkpoint_root: [0u8; 32],
            all_leaf_hashes: Vec::new(),
            global_index_offset: 0,
            hot_timestamps: Vec::new(),
            hot_byte_sizes: Vec::new(),
        }
    }

    /// Returns the context ID.
    #[must_use]
    pub fn context_id(&self) -> &str {
        self.hot.context_id()
    }

    /// Returns a reference to the hot-tier event log.
    #[must_use]
    pub const fn hot_log(&self) -> &EventLog {
        &self.hot
    }

    /// Returns a mutable reference to the hot-tier event log.
    ///
    /// Used for appending new events to the log.
    pub const fn hot_log_mut(&mut self) -> &mut EventLog {
        &mut self.hot
    }

    /// Returns the number of events in the hot tier.
    #[must_use]
    pub const fn hot_event_count(&self) -> u64 {
        tree::event_count(&self.hot)
    }

    /// Returns the number of events in the cold tier.
    #[must_use]
    pub const fn cold_event_count(&self) -> u64 {
        self.cold_entries.len() as u64
    }

    /// Returns the total number of events across both tiers.
    #[must_use]
    pub const fn total_event_count(&self) -> u64 {
        self.cold_event_count() + self.hot_event_count()
    }

    /// Returns the cold tier entries.
    #[must_use]
    pub fn cold_entries(&self) -> &[ColdTierEntry] {
        &self.cold_entries
    }

    /// Returns the tier configuration.
    #[must_use]
    pub const fn config(&self) -> &TierConfig {
        &self.config
    }

    /// Returns the checkpoint root used for cold proof verification.
    ///
    /// This is the Merkle root of the full log (all events across both
    /// tiers) computed at the time of the most recent migration. If no
    /// migration has occurred, returns `[0u8; 32]`.
    #[must_use]
    pub const fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }

    /// Returns the global index offset for the hot log.
    ///
    /// Hot leaf `i` corresponds to global index `global_index_offset + i`.
    #[must_use]
    pub const fn global_index_offset(&self) -> u64 {
        self.global_index_offset
    }

    /// Records metadata for a newly appended hot-tier event.
    ///
    /// Call this after successfully appending an event to the hot log
    /// via [`tree::append`]. The timestamp and byte size are used for
    /// tier migration decisions. The leaf hash is also recorded in the
    /// ghost collection for checkpoint root computation.
    pub fn record_hot_event(&mut self, timestamp: u64, byte_size: u64) {
        self.hot_timestamps.push(timestamp);
        self.hot_byte_sizes.push(byte_size);

        // Keep the ghost collection in sync with the hot log.
        // The most recently appended leaf is the last one in hot.leaves().
        let hot_leaves = self.hot.leaves();
        if let Some(&leaf_hash) = hot_leaves.last() {
            self.all_leaf_hashes.push(leaf_hash);
        }

        // Invariant: parallel metadata vectors must stay in sync with hot leaves.
        debug_assert_eq!(self.hot.leaves().len(), self.hot_timestamps.len());
        debug_assert_eq!(self.hot.leaves().len(), self.hot_byte_sizes.len());
    }

    /// Returns the estimated total bytes in the hot tier.
    #[must_use]
    pub fn hot_storage_bytes(&self) -> u64 {
        self.hot_byte_sizes.iter().sum()
    }

    /// Computes how many events should be migrated based on the current
    /// configuration and state.
    ///
    /// Returns the number of events to migrate (from the oldest in hot),
    /// or `0` if no migration is needed.
    #[must_use]
    pub fn events_to_migrate(&self, now: u64) -> u64 {
        let hot_count = self.hot_event_count();
        if hot_count == 0 {
            return 0;
        }

        let mut migrate_count: u64 = 0;

        // Age-based: count events older than the threshold.
        if let Some(age_threshold) = self.config.age_threshold_secs {
            let cutoff = now.saturating_sub(age_threshold);
            let age_eligible = self
                .hot_timestamps
                .iter()
                .take_while(|&&ts| ts < cutoff)
                .count() as u64;
            migrate_count = migrate_count.max(age_eligible);
        }

        // Count-based: if hot exceeds max, migrate the excess.
        if let Some(max_hot) = self.config.max_hot_events
            && hot_count > max_hot
        {
            let count_excess = hot_count - max_hot;
            migrate_count = migrate_count.max(count_excess);
        }

        // Size-based: migrate oldest events until under the byte limit.
        if let Some(max_bytes) = self.config.max_hot_bytes {
            let total_bytes = self.hot_storage_bytes();
            if total_bytes > max_bytes {
                let mut freed: u64 = 0;
                let mut size_migrate: u64 = 0;
                for &size in &self.hot_byte_sizes {
                    if total_bytes.saturating_sub(freed) <= max_bytes {
                        break;
                    }
                    freed += size;
                    size_migrate += 1;
                }
                migrate_count = migrate_count.max(size_migrate);
            }
        }

        migrate_count
    }

    /// Migrates eligible events from the hot tier to the cold tier.
    ///
    /// The checkpoint root is computed from the full ghost tree (all leaf
    /// hashes across both tiers) to ensure it spans ALL cold entries, not
    /// just the most recently migrated batch. Hot leaf indices are offset
    /// by `global_index_offset` to maintain correct global addressing.
    ///
    /// # Errors
    ///
    /// Returns [`TieredStorageError::NothingToMigrate`] if no events are
    /// eligible for migration.
    pub fn migrate_to_cold(&mut self, now: u64) -> Result<TierMigrationResult, TieredStorageError> {
        let count = self.events_to_migrate(now);
        if count == 0 {
            return Err(TieredStorageError::NothingToMigrate);
        }

        // Invariant: parallel metadata vectors must stay in sync with hot leaves.
        debug_assert_eq!(self.hot.leaves().len(), self.hot_timestamps.len());
        debug_assert_eq!(self.hot.leaves().len(), self.hot_byte_sizes.len());
        // NOTE: This holds only while cold entries are never pruned.
        debug_assert_eq!(self.global_index_offset, self.cold_entries.len() as u64);

        // Compute the checkpoint root from the FULL ghost tree (all leaves
        // ever appended, both cold and hot). This ensures the root is valid
        // for ALL cold entries across every migration cycle.
        self.checkpoint_root = compute_root_from_leaves(&self.all_leaf_hashes);

        let hot_leaves = self.hot.leaves();

        // count comes from event log size; fits in usize.
        #[allow(clippy::cast_possible_truncation)]
        let count_usize = count as usize;

        let mut bytes_freed: u64 = 0;

        // Move leaf hashes and metadata to cold entries.
        // Sequence numbers use global indices (offset + local position).
        for (i, &leaf_hash) in hot_leaves.iter().enumerate().take(count_usize) {
            let global_sequence = self.global_index_offset + i as u64;
            let timestamp = self.hot_timestamps[i];
            let payload_bytes = self.hot_byte_sizes[i];
            bytes_freed += payload_bytes;

            self.cold_entries.push(ColdTierEntry {
                leaf_hash,
                sequence: global_sequence,
                timestamp,
                payload_bytes,
            });
        }

        // Update the global index offset to reflect migrated events.
        self.global_index_offset += count;

        // Rebuild the hot log from remaining leaves.
        let remaining_leaves: Vec<[u8; 32]> = hot_leaves[count_usize..].to_vec();
        let remaining_timestamps: Vec<u64> = self.hot_timestamps[count_usize..].to_vec();
        let remaining_byte_sizes: Vec<u64> = self.hot_byte_sizes[count_usize..].to_vec();

        let context_id = self.hot.context_id().to_owned();
        self.hot = EventLog::new(context_id);
        for leaf in &remaining_leaves {
            self.hot.push_leaf_raw(*leaf);
        }
        self.hot_timestamps = remaining_timestamps;
        self.hot_byte_sizes = remaining_byte_sizes;

        Ok(TierMigrationResult {
            events_migrated: count,
            bytes_freed,
            hot_events_remaining: self.hot_event_count(),
            cold_events_total: self.cold_event_count(),
        })
    }

    /// Fetches and verifies an inclusion proof for a cold-tier event.
    ///
    /// The proof is fetched from the given [`ColdTierProvider`] and
    /// verified client-side against the checkpoint root using
    /// [`proof::verify_inclusion`]. Relays are untrusted -- if the
    /// proof fails verification, [`TieredStorageError::ColdProofVerificationFailed`]
    /// is returned.
    ///
    /// # Errors
    ///
    /// Returns [`TieredStorageError::NotInColdTier`] if the sequence is
    /// not in the cold tier.
    /// Returns [`TieredStorageError::ColdFetchFailed`] if the provider
    /// cannot reach the relay.
    /// Returns [`TieredStorageError::ColdProofVerificationFailed`] if the
    /// fetched proof does not verify against the checkpoint root.
    pub fn fetch_cold_proof(
        &self,
        sequence: u64,
        provider: &dyn ColdTierProvider,
    ) -> Result<InclusionProof, TieredStorageError> {
        // Look up the cold entry.
        let entry = self
            .cold_entries
            .iter()
            .find(|e| e.sequence == sequence)
            .ok_or(TieredStorageError::NotInColdTier { sequence })?;

        // Fetch the proof from the relay using the global sequence as the
        // leaf index (this is the position in the full log).
        let mut proof = provider.fetch_inclusion_proof(
            self.hot.context_id(),
            entry.sequence,
            entry.leaf_hash,
        )?;

        // The proof must verify against our locally stored checkpoint root.
        // Override the proof's stated root with our checkpoint root for
        // verification -- we trust our local root, not the relay's claim.
        proof.root = self.checkpoint_root;

        if !proof::verify_inclusion(&proof) {
            return Err(TieredStorageError::ColdProofVerificationFailed {
                leaf_index: entry.sequence,
            });
        }

        Ok(proof)
    }

    /// Returns `true` if the given sequence number is in the cold tier.
    #[must_use]
    pub fn is_cold(&self, sequence: u64) -> bool {
        self.cold_entries.iter().any(|e| e.sequence == sequence)
    }

    /// Returns `true` if the given sequence number is in the hot tier.
    #[must_use]
    pub const fn is_hot(&self, sequence: u64) -> bool {
        sequence >= self.global_index_offset
            && sequence < self.global_index_offset + self.hot_event_count()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes the Merkle root from a set of leaf hashes.
///
/// Used to compute the checkpoint root from the full ghost tree.
fn compute_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current: Vec<[u8; 32]> = leaves.to_vec();

    while current.len() > 1 {
        let parent_count = current.len().div_ceil(2);
        let mut parents = Vec::with_capacity(parent_count);

        let mut i = 0;
        while i < current.len() {
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(current[i]);
            if i + 1 < current.len() {
                hasher.update(current[i + 1]);
            } else {
                hasher.update(current[i]);
            }
            parents.push(hasher.finalize().into());
            i += 2;
        }

        current = parents;
    }

    current[0]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::branches_sharing_code,
    clippy::cast_possible_truncation
)]
mod tests {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::proof::{Direction, InclusionProof, ProofStep};
    use crate::tree::{self, GENESIS_PREV_HASH};
    use crate::{Event, EventPayload, EventType};

    // -------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------

    fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
        let hex: String = verifying_key
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
        format!("did:key:{hex}")
    }

    /// Must match the production `compute_event_canonical_hash` in `tree.rs`.
    fn compute_event_canonical_hash(event: &Event) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-EVENT-V1:");
        #[allow(clippy::cast_possible_truncation)]
        let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
            hasher.update((bytes.len() as u32).to_be_bytes());
            hasher.update(bytes);
        };
        hasher.update(event_type_tag(&event.event_type).to_be_bytes());
        length_prefix(&mut hasher, event.actor_did.as_bytes());
        hasher.update(event.timestamp.to_be_bytes());
        hasher.update(event.sequence.to_be_bytes());
        length_prefix(&mut hasher, &event.payload.data);
        hasher.update(event.prev_hash);
        hasher.finalize().to_vec()
    }

    const fn event_type_tag(event_type: &EventType) -> u16 {
        match event_type {
            EventType::ContextCreated => 0,
            EventType::ContextClosing => 1,
            EventType::ContextClosed => 2,
            EventType::ContextExpired => 3,
            EventType::MemberJoined => 4,
            EventType::MemberLeft => 5,
            EventType::RoleAssigned => 6,
            EventType::TokenRevoked => 7,
            EventType::MessageSent => 8,
            EventType::ToolRegistered => 9,
            EventType::ToolUpdated => 10,
            EventType::ToolInvoked => 11,
            EventType::ToolVerified => 12,
            EventType::ToolInterfaceEstablished => 13,
            EventType::GovernanceAction => 14,
            EventType::ConsistencyCheckpoint => 15,
            EventType::AbsenceProofRequested => 16,
            EventType::MemberBlocked => 17,
            EventType::KeyEpochAdvance => 18,
            EventType::MediaSessionStarted => 19,
            EventType::MediaSessionEnded => 20,
            EventType::PaymentReceived => 21,
            EventType::EconomicPolicyChanged => 22,
            EventType::SpendingUcanGranted => 23,
            EventType::SpendingUcanRevoked => 24,
            // Governance event types (ADR-031 §8)
            EventType::GovernanceProposalCreated => 25,
            EventType::GovernanceVoteCast => 26,
            EventType::GovernanceVoteWithdrawn => 27,
            EventType::GovernanceProposalResolved => 28,
            EventType::GovernanceConflictDetected => 29,
            EventType::GovernanceConflictResolved => 30,
            EventType::GovernanceDeadlockRecovery => 31,
            EventType::GovernanceActionExecuted => 32,
        }
    }

    fn sign_event(
        event_type: EventType,
        actor_did: &str,
        timestamp: u64,
        sequence: u64,
        payload: Vec<u8>,
        prev_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Event {
        let mut event = Event {
            event_type,
            actor_did: actor_did.into(),
            timestamp,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash,
            signature: Vec::new(),
        };

        let canonical_hash = compute_event_canonical_hash(&event);
        let signature = signing_key.sign(&canonical_hash);
        event.signature = signature.to_bytes().to_vec();

        event
    }

    /// Compute a leaf hash with the 0x00 domain separation prefix (RFC 6962).
    fn leaf_hash_from_event(event: &Event) -> [u8; 32] {
        let serialized = rmp_serde::to_vec(event).unwrap();
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&serialized);
        hasher.finalize().into()
    }

    /// Build a tiered event log with `n` events and return it along with
    /// the leaf hashes and serialized event sizes.
    fn build_tiered_log(
        n: u64,
        config: TierConfig,
        base_timestamp: u64,
        timestamp_step: u64,
    ) -> (TieredEventLog, Vec<[u8; 32]>) {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut tiered = TieredEventLog::new("ctx-tiered-test".to_owned(), config);
        let mut prev_hash = GENESIS_PREV_HASH;
        let mut leaf_hashes = Vec::new();

        for i in 0..n {
            let timestamp = base_timestamp + i * timestamp_step;
            let event = sign_event(
                EventType::MessageSent,
                &did,
                timestamp,
                i,
                format!("message {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );

            let serialized = rmp_serde::to_vec(&event).unwrap();
            let byte_size = serialized.len() as u64;

            tree::append(tiered.hot_log_mut(), &event).unwrap();
            tiered.record_hot_event(timestamp, byte_size);

            let leaf_hash = leaf_hash_from_event(&event);
            leaf_hashes.push(leaf_hash);
            prev_hash = leaf_hash;
        }

        (tiered, leaf_hashes)
    }

    // -------------------------------------------------------------------
    // Mock ColdTierProvider
    // -------------------------------------------------------------------

    /// In-memory mock cold tier provider for testing.
    ///
    /// Stores pre-computed inclusion proofs keyed by leaf index.
    struct MockColdProvider {
        proofs: std::collections::HashMap<u64, InclusionProof>,
    }

    impl MockColdProvider {
        fn new() -> Self {
            Self {
                proofs: std::collections::HashMap::new(),
            }
        }
    }

    impl ColdTierProvider for MockColdProvider {
        fn fetch_inclusion_proof(
            &self,
            _context_id: &str,
            leaf_index: u64,
            _leaf_hash: [u8; 32],
        ) -> Result<InclusionProof, TieredStorageError> {
            self.proofs.get(&leaf_index).cloned().ok_or_else(|| {
                TieredStorageError::ColdFetchFailed(format!(
                    "no proof available for leaf index {leaf_index}"
                ))
            })
        }
    }

    /// A mock provider that always returns a forged (invalid) proof.
    struct MaliciousProvider;

    impl ColdTierProvider for MaliciousProvider {
        fn fetch_inclusion_proof(
            &self,
            _context_id: &str,
            leaf_index: u64,
            leaf_hash: [u8; 32],
        ) -> Result<InclusionProof, TieredStorageError> {
            // Return a proof with a tampered sibling hash.
            Ok(InclusionProof {
                leaf_index,
                leaf_hash,
                path: vec![ProofStep {
                    sibling_hash: [0xFF; 32],
                    direction: Direction::Right,
                }],
                root: [0xAA; 32], // Wrong root -- will be overridden anyway
            })
        }
    }

    /// A mock provider that generates valid proofs against the full ghost
    /// tree. Used to test cold proof verification across multiple migrations.
    struct GhostTreeProvider {
        /// All leaf hashes in global order (the ghost tree).
        all_leaves: Vec<[u8; 32]>,
    }

    impl GhostTreeProvider {
        fn new(all_leaves: Vec<[u8; 32]>) -> Self {
            Self { all_leaves }
        }
    }

    impl ColdTierProvider for GhostTreeProvider {
        fn fetch_inclusion_proof(
            &self,
            _context_id: &str,
            leaf_index: u64,
            leaf_hash: [u8; 32],
        ) -> Result<InclusionProof, TieredStorageError> {
            let idx = leaf_index as usize;
            if idx >= self.all_leaves.len() {
                return Err(TieredStorageError::ColdFetchFailed(
                    "leaf index out of range".into(),
                ));
            }

            // Build a proof from the ghost tree.
            let root = compute_root_from_leaves(&self.all_leaves);
            let path = build_ghost_proof_path(idx, &self.all_leaves);

            Ok(InclusionProof {
                leaf_index,
                leaf_hash,
                path,
                root,
            })
        }
    }

    /// Build a Merkle proof path from a leaf to the root using the full
    /// leaf set (ghost tree).
    fn build_ghost_proof_path(leaf_idx: usize, leaves: &[[u8; 32]]) -> Vec<ProofStep> {
        if leaves.len() <= 1 {
            return Vec::new();
        }

        let mut path = Vec::new();
        let mut idx = leaf_idx;
        let mut current_layer: Vec<[u8; 32]> = leaves.to_vec();

        loop {
            if current_layer.len() <= 1 {
                break;
            }

            let sibling_idx = idx ^ 1;
            if sibling_idx < current_layer.len() {
                let direction = if idx.is_multiple_of(2) {
                    Direction::Right
                } else {
                    Direction::Left
                };
                path.push(ProofStep {
                    sibling_hash: current_layer[sibling_idx],
                    direction,
                });
            } else {
                // Odd node: sibling is itself (promoted).
                path.push(ProofStep {
                    sibling_hash: current_layer[idx],
                    direction: Direction::Right,
                });
            }

            // Compute the next layer.
            let parent_count = current_layer.len().div_ceil(2);
            let mut parents = Vec::with_capacity(parent_count);
            let mut i = 0;
            while i < current_layer.len() {
                if i + 1 < current_layer.len() {
                    let mut hasher = Sha256::new();
                    hasher.update([0x01]);
                    hasher.update(current_layer[i]);
                    hasher.update(current_layer[i + 1]);
                    parents.push(hasher.finalize().into());
                } else {
                    let mut hasher = Sha256::new();
                    hasher.update([0x01]);
                    hasher.update(current_layer[i]);
                    hasher.update(current_layer[i]);
                    parents.push(hasher.finalize().into());
                }
                i += 2;
            }

            idx /= 2;
            current_layer = parents;
        }

        path
    }

    // -------------------------------------------------------------------
    // TierConfig defaults
    // -------------------------------------------------------------------

    #[test]
    fn tier_config_defaults_are_sensible() {
        let config = TierConfig::default();
        assert_eq!(config.age_threshold_secs, Some(DEFAULT_AGE_THRESHOLD_SECS));
        assert_eq!(config.max_hot_events, Some(DEFAULT_MAX_HOT_EVENTS));
        assert_eq!(config.max_hot_bytes, Some(DEFAULT_MAX_HOT_BYTES));
    }

    // -------------------------------------------------------------------
    // TieredEventLog::new creates empty tiers
    // -------------------------------------------------------------------

    #[test]
    fn new_creates_empty_tiers() {
        let tiered = TieredEventLog::new("ctx-1".to_owned(), TierConfig::default());
        assert_eq!(tiered.hot_event_count(), 0);
        assert_eq!(tiered.cold_event_count(), 0);
        assert_eq!(tiered.total_event_count(), 0);
        assert_eq!(tiered.context_id(), "ctx-1");
        assert_eq!(tiered.checkpoint_root(), [0u8; 32]);
        assert_eq!(tiered.global_index_offset(), 0);
    }

    // -------------------------------------------------------------------
    // Events start in hot tier
    // -------------------------------------------------------------------

    #[test]
    fn events_start_in_hot_tier() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: None,
            max_hot_bytes: None,
        };
        let (tiered, _) = build_tiered_log(10, config, 1_000_000, 60);

        assert_eq!(tiered.hot_event_count(), 10);
        assert_eq!(tiered.cold_event_count(), 0);
        assert_eq!(tiered.total_event_count(), 10);

        for i in 0..10u64 {
            assert!(tiered.is_hot(i));
            assert!(!tiered.is_cold(i));
        }
    }

    // -------------------------------------------------------------------
    // Age-based migration
    // -------------------------------------------------------------------

    #[test]
    fn migrate_to_cold_age_based() {
        let config = TierConfig {
            age_threshold_secs: Some(3600), // 1 hour threshold
            max_hot_events: None,
            max_hot_bytes: None,
        };

        // 10 events, each 1 minute apart, starting at t=1_000_000.
        let (mut tiered, _) = build_tiered_log(10, config, 1_000_000, 60);

        // At t=1_000_000 + 3600 + 600 = 1_004_200, events at t < 1_000_600
        // are older than 1 hour. That's events 0..10 (all at t <= 1_000_540).
        // Actually, event 0 at t=1_000_000, event 9 at t=1_000_540.
        // Cutoff = 1_004_200 - 3600 = 1_000_600. Events with t < 1_000_600:
        // all 10 events (0..9 have timestamps 1_000_000..1_000_540).
        let now = 1_004_200;
        let to_migrate = tiered.events_to_migrate(now);
        assert_eq!(to_migrate, 10);

        // Only first 5 events older than threshold at t=1_003_300.
        // Cutoff = 1_003_300 - 3600 = 999_700. All events are after that.
        // Actually cutoff = 999_700, all events at t >= 1_000_000 so 0 eligible.
        let to_migrate_none = tiered.events_to_migrate(999_700);
        assert_eq!(to_migrate_none, 0);

        // At t=1_003_800: cutoff = 1_000_200. Events with t < 1_000_200:
        // event 0 (t=1_000_000), event 1 (t=1_000_060), event 2 (t=1_000_120),
        // event 3 (t=1_000_180). That's 4 events.
        let result = tiered.migrate_to_cold(1_003_800).unwrap();
        assert_eq!(result.events_migrated, 4);
        assert_eq!(result.hot_events_remaining, 6);
        assert_eq!(result.cold_events_total, 4);
        assert_eq!(tiered.hot_event_count(), 6);
        assert_eq!(tiered.cold_event_count(), 4);
        assert_eq!(tiered.total_event_count(), 10);
    }

    // -------------------------------------------------------------------
    // Count-based migration
    // -------------------------------------------------------------------

    #[test]
    fn migrate_to_cold_count_based() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(5), // Keep at most 5 in hot
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(10, config, 1_000_000, 60);

        assert_eq!(tiered.events_to_migrate(1_000_000), 5); // 10 - 5 = 5 excess

        let result = tiered.migrate_to_cold(1_000_000).unwrap();
        assert_eq!(result.events_migrated, 5);
        assert_eq!(result.hot_events_remaining, 5);
        assert_eq!(result.cold_events_total, 5);
    }

    // -------------------------------------------------------------------
    // Size-based migration
    // -------------------------------------------------------------------

    #[test]
    fn migrate_to_cold_size_based() {
        // Set a very low byte limit to force migration.
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: None,
            max_hot_bytes: Some(100), // Very small -- most events are larger
        };

        let (mut tiered, _) = build_tiered_log(5, config, 1_000_000, 60);

        let total_bytes = tiered.hot_storage_bytes();
        assert!(total_bytes > 100, "events should exceed 100 bytes total");

        let to_migrate = tiered.events_to_migrate(1_000_000);
        assert!(to_migrate > 0, "should need to migrate some events");

        let result = tiered.migrate_to_cold(1_000_000).unwrap();
        assert!(result.events_migrated > 0);
        assert!(result.bytes_freed > 0);
    }

    // -------------------------------------------------------------------
    // Nothing to migrate returns error
    // -------------------------------------------------------------------

    #[test]
    fn migrate_returns_error_when_nothing_to_migrate() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: None,
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(5, config, 1_000_000, 60);

        let result = tiered.migrate_to_cold(1_000_000);
        assert!(result.is_err());
        match result {
            Err(TieredStorageError::NothingToMigrate) => {}
            other => panic!("expected NothingToMigrate, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Cold proof fetch and verification
    // -------------------------------------------------------------------

    #[test]
    fn fetch_cold_proof_succeeds_with_valid_proof() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(5),
            max_hot_bytes: None,
        };

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut tiered = TieredEventLog::new("ctx-cold-test".to_owned(), config);
        let mut prev_hash = GENESIS_PREV_HASH;

        // Build 10 events.
        for i in 0..10u64 {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i * 60,
                i,
                format!("message {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );
            let serialized = rmp_serde::to_vec(&event).unwrap();
            tree::append(tiered.hot_log_mut(), &event).unwrap();
            tiered.record_hot_event(1_000_000 + i * 60, serialized.len() as u64);
            prev_hash = leaf_hash_from_event(&event);
        }

        // Create a ghost tree provider with all leaf hashes for valid proofs.
        let all_leaves = tiered.all_leaf_hashes.clone();
        let ghost_provider = GhostTreeProvider::new(all_leaves);

        // Migrate first 5 events to cold.
        let result = tiered.migrate_to_cold(1_000_000).unwrap();
        assert_eq!(result.events_migrated, 5);

        // Fetch and verify cold proof for sequence 0.
        let proof = tiered.fetch_cold_proof(0, &ghost_provider).unwrap();
        assert_eq!(proof.leaf_index, 0);
    }

    // -------------------------------------------------------------------
    // Cold proof verification rejects forged proofs
    // -------------------------------------------------------------------

    #[test]
    fn fetch_cold_proof_rejects_forged_proof() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(3),
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(6, config, 1_000_000, 60);

        // Migrate first 3 events.
        tiered.migrate_to_cold(1_000_000).unwrap();

        // Use the malicious provider that returns forged proofs.
        let malicious = MaliciousProvider;
        let result = tiered.fetch_cold_proof(0, &malicious);

        assert!(result.is_err());
        match result {
            Err(TieredStorageError::ColdProofVerificationFailed { leaf_index }) => {
                assert_eq!(leaf_index, 0);
            }
            other => panic!("expected ColdProofVerificationFailed, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Fetch for non-cold event returns error
    // -------------------------------------------------------------------

    #[test]
    fn fetch_cold_proof_rejects_hot_sequence() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(5),
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(10, config, 1_000_000, 60);
        tiered.migrate_to_cold(1_000_000).unwrap();

        // Sequence 7 is in hot tier, not cold.
        let mock = MockColdProvider::new();
        let result = tiered.fetch_cold_proof(7, &mock);
        assert!(result.is_err());
        match result {
            Err(TieredStorageError::NotInColdTier { sequence }) => {
                assert_eq!(sequence, 7);
            }
            other => panic!("expected NotInColdTier, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Cold fetch failure propagates
    // -------------------------------------------------------------------

    #[test]
    fn fetch_cold_proof_propagates_provider_error() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(3),
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(6, config, 1_000_000, 60);
        tiered.migrate_to_cold(1_000_000).unwrap();

        // Provider has no proofs for this index -- will return ColdFetchFailed.
        let empty_provider = MockColdProvider::new();
        let result = tiered.fetch_cold_proof(0, &empty_provider);
        assert!(result.is_err());
        match result {
            Err(TieredStorageError::ColdFetchFailed(_)) => {}
            other => panic!("expected ColdFetchFailed, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // is_hot and is_cold are consistent after migration
    // -------------------------------------------------------------------

    #[test]
    fn is_hot_and_is_cold_consistent_after_migration() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(5),
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(10, config, 1_000_000, 60);
        tiered.migrate_to_cold(1_000_000).unwrap();

        // Sequences 0..5 are cold, 5..10 are hot.
        for i in 0..5u64 {
            assert!(tiered.is_cold(i), "seq {i} should be cold");
            assert!(!tiered.is_hot(i), "seq {i} should not be hot");
        }
        for i in 5..10u64 {
            assert!(tiered.is_hot(i), "seq {i} should be hot");
            assert!(!tiered.is_cold(i), "seq {i} should not be cold");
        }
    }

    // -------------------------------------------------------------------
    // Storage is bounded after migration
    // -------------------------------------------------------------------

    #[test]
    fn device_storage_bounded_after_migration() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(3),
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(20, config, 1_000_000, 60);

        let result = tiered.migrate_to_cold(1_000_000).unwrap();
        assert_eq!(result.hot_events_remaining, 3);
        assert_eq!(result.cold_events_total, 17);
        assert!(result.bytes_freed > 0);

        // Hot tier is bounded to max_hot_events.
        assert_eq!(tiered.hot_event_count(), 3);
        // Total is preserved.
        assert_eq!(tiered.total_event_count(), 20);

        // Cold entries are lightweight -- just metadata.
        let cold_overhead = std::mem::size_of_val(tiered.cold_entries());
        // Each ColdTierEntry is ~56 bytes (32 hash + 8 seq + 8 ts + 8 bytes).
        // For 17 entries, that's ~952 bytes -- much less than the original payloads.
        assert!(
            cold_overhead < 2000,
            "cold tier metadata should be lightweight, got {cold_overhead} bytes"
        );
    }

    // -------------------------------------------------------------------
    // Multiple migrations accumulate cold entries
    // -------------------------------------------------------------------

    #[test]
    fn multiple_migrations_accumulate_cold_entries() {
        let config = TierConfig {
            age_threshold_secs: Some(300), // 5 minutes
            max_hot_events: None,
            max_hot_bytes: None,
        };

        // 10 events, 2 minutes apart. At different `now` values, different
        // events become eligible.
        let (mut tiered, _) = build_tiered_log(10, config, 1_000_000, 120);

        // At t = 1_000_000 + 300 + 120 = 1_000_420: cutoff = 1_000_120.
        // Events with t < 1_000_120: event 0 (t=1_000_000). That's 1 event.
        let r1 = tiered.migrate_to_cold(1_000_420).unwrap();
        assert_eq!(r1.events_migrated, 1);
        assert_eq!(tiered.cold_event_count(), 1);
        assert_eq!(tiered.hot_event_count(), 9);

        // At t = 1_000_000 + 300 + 480 = 1_000_780: cutoff = 1_000_480.
        // Hot events now start at sequence 1 (t=1_000_120). Events with
        // t < 1_000_480: event 1 (t=1_000_120), event 2 (t=1_000_240),
        // event 3 (t=1_000_360). That's 3 more.
        let r2 = tiered.migrate_to_cold(1_000_780).unwrap();
        assert_eq!(r2.events_migrated, 3);
        assert_eq!(tiered.cold_event_count(), 4);
        assert_eq!(tiered.hot_event_count(), 6);
    }

    // -------------------------------------------------------------------
    // Checkpoint root spans all tiers after multiple migrations
    // -------------------------------------------------------------------

    #[test]
    fn checkpoint_root_captured_at_migration() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(5),
            max_hot_bytes: None,
        };

        let (mut tiered, leaf_hashes) = build_tiered_log(10, config, 1_000_000, 60);

        // Before migration, checkpoint root is zero.
        assert_eq!(tiered.checkpoint_root(), [0u8; 32]);

        // The full-log root is the root of all 10 leaf hashes.
        let full_root = compute_root_from_leaves(&leaf_hashes);

        tiered.migrate_to_cold(1_000_000).unwrap();

        // After migration, checkpoint root should be the full-log root.
        assert_eq!(tiered.checkpoint_root(), full_root);
        assert_ne!(tiered.checkpoint_root(), [0u8; 32]);
    }

    // -------------------------------------------------------------------
    // Checkpoint root valid across two migration cycles (regression test
    // for the "second migration invalidates checkpoint root" bug)
    // -------------------------------------------------------------------

    #[test]
    fn checkpoint_root_valid_after_two_migrations() {
        let config = TierConfig {
            age_threshold_secs: Some(300), // 5 minutes
            max_hot_events: None,
            max_hot_bytes: None,
        };

        // 10 events, 2 minutes apart.
        let (mut tiered, all_leaf_hashes) = build_tiered_log(10, config, 1_000_000, 120);

        // First migration: migrate event 0.
        tiered.migrate_to_cold(1_000_420).unwrap();
        let root_after_first = tiered.checkpoint_root();

        // The root should be the root of ALL 10 leaves.
        let expected_full_root = compute_root_from_leaves(&all_leaf_hashes);
        assert_eq!(root_after_first, expected_full_root);

        // Second migration: migrate events 1, 2, 3.
        tiered.migrate_to_cold(1_000_780).unwrap();
        let root_after_second = tiered.checkpoint_root();

        // The root should STILL be the root of ALL 10 leaves (unchanged
        // because no new events were added between migrations).
        assert_eq!(root_after_second, expected_full_root);

        // Cold proofs from the first migration batch should still verify.
        let ghost_provider = GhostTreeProvider::new(all_leaf_hashes);
        let proof = tiered.fetch_cold_proof(0, &ghost_provider).unwrap();
        assert_eq!(proof.leaf_index, 0);

        // Cold proofs from the second migration batch should also verify.
        let proof = tiered.fetch_cold_proof(1, &ghost_provider).unwrap();
        assert_eq!(proof.leaf_index, 1);
    }

    // -------------------------------------------------------------------
    // Global index offset maintained after migration
    // -------------------------------------------------------------------

    #[test]
    fn global_index_offset_maintained_after_migration() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: Some(5),
            max_hot_bytes: None,
        };

        let (mut tiered, _) = build_tiered_log(10, config, 1_000_000, 60);

        assert_eq!(tiered.global_index_offset(), 0);

        tiered.migrate_to_cold(1_000_000).unwrap();

        // After migrating 5, offset should be 5.
        assert_eq!(tiered.global_index_offset(), 5);

        // Cold entries should have global sequences 0..5.
        for (i, entry) in tiered.cold_entries().iter().enumerate() {
            assert_eq!(entry.sequence, i as u64);
        }

        // is_hot should use global addressing.
        for i in 5..10u64 {
            assert!(tiered.is_hot(i), "global seq {i} should be hot");
        }
        for i in 0..5u64 {
            assert!(!tiered.is_hot(i), "global seq {i} should not be hot");
        }
    }

    // -------------------------------------------------------------------
    // Global index offset correct after two migrations
    // -------------------------------------------------------------------

    #[test]
    fn global_index_offset_correct_after_two_migrations() {
        let config = TierConfig {
            age_threshold_secs: Some(300),
            max_hot_events: None,
            max_hot_bytes: None,
        };

        // 10 events, 2 minutes apart.
        let (mut tiered, _) = build_tiered_log(10, config, 1_000_000, 120);

        // First migration: migrate 1 event.
        tiered.migrate_to_cold(1_000_420).unwrap();
        assert_eq!(tiered.global_index_offset(), 1);
        assert_eq!(tiered.cold_entries()[0].sequence, 0);

        // Second migration: migrate 3 more events.
        tiered.migrate_to_cold(1_000_780).unwrap();
        assert_eq!(tiered.global_index_offset(), 4);

        // Cold entries should have correct global sequences.
        let cold_seqs: Vec<u64> = tiered.cold_entries().iter().map(|e| e.sequence).collect();
        assert_eq!(cold_seqs, vec![0, 1, 2, 3]);

        // Hot events should be at global indices 4..10.
        for i in 4..10u64 {
            assert!(tiered.is_hot(i), "global seq {i} should be hot");
        }
        for i in 0..4u64 {
            assert!(!tiered.is_hot(i), "global seq {i} should not be hot");
            assert!(tiered.is_cold(i), "global seq {i} should be cold");
        }
    }

    // -------------------------------------------------------------------
    // Empty log migration returns error
    // -------------------------------------------------------------------

    #[test]
    fn empty_log_migration_returns_error() {
        let config = TierConfig {
            age_threshold_secs: Some(3600),
            max_hot_events: Some(5),
            max_hot_bytes: None,
        };

        let mut tiered = TieredEventLog::new("ctx-empty".to_owned(), config);
        let result = tiered.migrate_to_cold(1_000_000);
        assert!(result.is_err());
        match result {
            Err(TieredStorageError::NothingToMigrate) => {}
            other => panic!("expected NothingToMigrate, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // hot_storage_bytes tracks sizes correctly
    // -------------------------------------------------------------------

    #[test]
    fn hot_storage_bytes_tracks_sizes() {
        let config = TierConfig {
            age_threshold_secs: None,
            max_hot_events: None,
            max_hot_bytes: None,
        };

        let (tiered, _) = build_tiered_log(5, config, 1_000_000, 60);

        let total = tiered.hot_storage_bytes();
        assert!(total > 0);
        // Each event is at least ~100 bytes serialized.
        assert!(total > 500);
    }
}
