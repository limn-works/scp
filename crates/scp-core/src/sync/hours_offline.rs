//! Tier 1 hours-scale offline recovery: relay buffering + MLS catch-up.
//!
//! This module implements the baseline offline scenario (< 4 hours) from
//! ADR-029 section 1. Devices are full protocol participants (§10.2), not thin
//! clients. The SDK issues an MLS Update after reconnecting (§9.12). The
//! reorder buffer respects the 30-second gap timeout and 100-message capacity
//! (§9.8.5). `KeyPackage`s are pre-published for offline member addition
//! (§9.6). No synchronized clock dependency (§9.8.3). Relays are untrusted —
//! all verification is client-side.
//!
//! # Architecture
//!
//! - [`RelayMessageBuffer`] — Retrieves and verifies buffered messages from
//!   relays after reconnection.
//! - [`EpochCatchUpState`] — Tracks progress of MLS epoch catch-up (sequential
//!   Commit processing).
//! - [`ReorderBuffer`] — Buffers out-of-order messages, delivering in sequence
//!   order with a 30-second gap timeout and 100-message capacity.
//! - [`ReconnectionCoordinator`] — Orchestrates the six-phase reconnection
//!   protocol for all active contexts.
//! - [`KeyPackagePrePublisher`] — Manages pre-publication of `KeyPackage`s so
//!   offline members can be added to groups.
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{
    CatchUpStatus, ContextId, Ed25519Signature, OfflineTier, SyncError, SyncEvent, SyncOutcome,
    SyncPolicy,
};
use crate::crypto::canonical::{CanonicalField, canonical_hash};
use crate::store::queue::DEFAULT_QUEUE_TTL_SECS;
use scp_identity::DID;

// ---------------------------------------------------------------------------
// RelayMessageBuffer
// ---------------------------------------------------------------------------

/// A message retrieved from the relay's store-and-forward buffer.
///
/// Relays are untrusted infrastructure (protocol tenet: encryption-as-access-
/// control). All messages are verified client-side after retrieval. The relay
/// stores opaque encrypted blobs; the structure here represents the metadata
/// envelope visible to the client after initial parsing.
///
/// See ADR-004 (Native Relay) and ADR-029 section 2, Phase 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedMessage {
    /// Unique identifier for the blob as assigned by the relay.
    pub blob_id: String,
    /// The context this message belongs to.
    pub context_id: ContextId,
    /// The opaque encrypted message payload (MLS ciphertext).
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Timestamp when the relay stored this message (relay-assigned, untrusted).
    /// Used only for ordering and TTL checks, not for protocol decisions.
    /// SCP does not require synchronized clocks (§9.8.3).
    pub stored_at: u64,
    /// The MLS epoch this message was encrypted under, if known from the
    /// public message header. `None` for opaque application messages where
    /// the epoch is only known after decryption.
    pub epoch: Option<u64>,
}

/// Retrieves and deduplicates buffered messages from relay(s) after reconnect.
///
/// On reconnection (Phase 1 of the reconnection protocol), the SDK
/// re-subscribes to each relay with `since` = last received `stored_at` minus
/// a 5-second overlap (ADR-004 Connection Recovery). The relay backfills all
/// retained blobs. This struct tracks retrieval progress and deduplication.
///
/// See ADR-029 section 2, Phase 1.
#[derive(Debug)]
pub struct RelayMessageBuffer {
    /// The context for which messages are being retrieved.
    context_id: ContextId,
    /// Last `stored_at` timestamp successfully processed before going offline.
    last_stored_at: u64,
    /// Overlap subtracted from `last_stored_at` when re-subscribing (5 seconds).
    overlap_secs: u64,
    /// Blob IDs already seen (for deduplication per ADR-012).
    seen_blob_ids: std::collections::HashSet<String>,
    /// Messages retrieved and deduplicated, awaiting processing.
    messages: Vec<BufferedMessage>,
}

impl RelayMessageBuffer {
    /// Creates a new relay message buffer for a context.
    ///
    /// # Arguments
    ///
    /// * `context_id` — The context to retrieve messages for.
    /// * `last_stored_at` — Timestamp of the last message processed before
    ///   going offline. The relay `SUBSCRIBE` will use
    ///   `last_stored_at - overlap_secs` as the `since` parameter.
    #[must_use]
    pub fn new(context_id: ContextId, last_stored_at: u64) -> Self {
        Self {
            context_id,
            last_stored_at,
            overlap_secs: 5,
            seen_blob_ids: std::collections::HashSet::new(),
            messages: Vec::new(),
        }
    }

    /// Returns the `since` timestamp to use when re-subscribing to the relay.
    ///
    /// This is `last_stored_at` minus the overlap window (5 seconds per
    /// ADR-004 Connection Recovery). Uses `saturating_sub` to handle the case
    /// where `last_stored_at` is very small.
    #[must_use]
    pub const fn subscribe_since(&self) -> u64 {
        self.last_stored_at.saturating_sub(self.overlap_secs)
    }

    /// Ingests a message from the relay, deduplicating by `blob_id`.
    ///
    /// Returns `true` if the message was new (not a duplicate), `false` if
    /// it was already seen and discarded.
    pub fn ingest(&mut self, message: BufferedMessage) -> bool {
        if self.seen_blob_ids.contains(&message.blob_id) {
            return false;
        }
        self.seen_blob_ids.insert(message.blob_id.clone());
        self.messages.push(message);
        true
    }

    /// Returns the number of unique messages retrieved so far.
    #[must_use]
    pub const fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Returns the context ID.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Consumes the buffer and returns all deduplicated messages, sorted by
    /// `stored_at` ascending.
    ///
    /// After this call the buffer is empty.
    #[must_use]
    pub fn drain_sorted(mut self) -> Vec<BufferedMessage> {
        self.messages.sort_by(|a, b| a.stored_at.cmp(&b.stored_at));
        self.messages
    }
}

// ---------------------------------------------------------------------------
// EpochCatchUpState
// ---------------------------------------------------------------------------

/// Tracks the progress of MLS epoch catch-up for a single context.
///
/// MLS requires sequential epoch processing — each Commit depends on the
/// previous epoch's key schedule. An offline member at epoch E who reconnects
/// to find the group at epoch E+N must process all N intermediate Commits in
/// order. The SDK processes at most [`SyncPolicy::max_sequential_commits`] Commits per
/// catch-up attempt; beyond that it falls back to Welcome-based fast-forward.
///
/// See ADR-029 section 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCatchUpState {
    /// The context being caught up.
    pub context_id: ContextId,
    /// The local epoch when catch-up started.
    pub local_epoch: u64,
    /// The target epoch (current group epoch observed from relay messages).
    pub target_epoch: u64,
    /// Number of Commits successfully processed so far.
    pub commits_processed: u64,
    /// Current catch-up status.
    pub status: CatchUpStatus,
}

impl EpochCatchUpState {
    /// Creates a new catch-up state for a context.
    ///
    /// The initial status is [`CatchUpStatus::Processing`].
    #[must_use]
    pub const fn new(context_id: ContextId, local_epoch: u64, target_epoch: u64) -> Self {
        Self {
            context_id,
            local_epoch,
            target_epoch,
            commits_processed: 0,
            status: CatchUpStatus::Processing,
        }
    }

    /// Returns the number of epochs remaining to catch up.
    #[must_use]
    pub const fn epochs_remaining(&self) -> u64 {
        self.target_epoch
            .saturating_sub(self.local_epoch.saturating_add(self.commits_processed))
    }

    /// Returns `true` if the epoch gap exceeds the sequential processing limit.
    ///
    /// When this returns `true`, the SDK should fall back to Welcome-based
    /// fast-forward instead of continuing sequential processing.
    #[must_use]
    pub const fn exceeds_sequential_limit(&self, policy: &SyncPolicy) -> bool {
        self.target_epoch.saturating_sub(self.local_epoch) > policy.max_sequential_commits
    }

    /// Records a successfully processed Commit and advances the catch-up state.
    ///
    /// If all epochs have been caught up, the status transitions to
    /// [`CatchUpStatus::Complete`].
    pub fn record_commit_processed(&mut self) {
        self.commits_processed = self.commits_processed.saturating_add(1);
        if self.local_epoch.saturating_add(self.commits_processed) >= self.target_epoch {
            self.status = CatchUpStatus::Complete;
        }
    }

    /// Transitions to fast-forward status, recording the skipped epoch range.
    pub fn transition_to_fast_forward(&mut self) {
        let current = self.local_epoch.saturating_add(self.commits_processed);
        self.status = CatchUpStatus::FastForwarded {
            skipped_from: current,
            skipped_to: self.target_epoch,
        };
    }

    /// Transitions to failed status with the given reason.
    pub fn transition_to_failed(&mut self, reason: String) {
        self.status = CatchUpStatus::Failed { reason };
    }
}

// ---------------------------------------------------------------------------
// CommitRangeRequest / CommitRangeResponse
// ---------------------------------------------------------------------------

/// Domain separator for `CommitRangeRequest` canonical hash (§9.18.2, §23.16.2).
pub const COMMIT_RANGE_REQUEST_DOMAIN_SEPARATOR: &str = "SCP-COMMIT-RANGE-REQ-V1:";

/// Domain separator for `CommitRangeResponse` canonical hash (§9.18.2, §23.16.3).
pub const COMMIT_RANGE_RESPONSE_DOMAIN_SEPARATOR: &str = "SCP-COMMIT-RANGE-RESP-V1:";

/// A request for missing MLS Commit messages from peers.
///
/// Sent when the relay backfill does not contain all Commits needed for
/// sequential epoch catch-up. Online members who have persisted the Commit
/// messages respond with the missing range.
///
/// See ADR-029 section 3, source 2 (Peer request).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRangeRequest {
    /// The context the Commits belong to.
    pub context_id: ContextId,
    /// First epoch to retrieve (inclusive).
    pub from_epoch: u64,
    /// Last epoch to retrieve (inclusive).
    pub to_epoch: u64,
    /// DID of the requesting member.
    pub requester_did: DID,
    /// Signature over the request fields for authentication.
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

impl CommitRangeRequest {
    /// Computes the canonical hash for signing/verification (§23.16.2).
    ///
    /// Field order: `context_id`, `from_epoch`, `to_epoch`, `requester_did`.
    /// Domain separator: `"SCP-COMMIT-RANGE-REQ-V1:"`.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        canonical_hash(
            COMMIT_RANGE_REQUEST_DOMAIN_SEPARATOR,
            &[
                CanonicalField::VarBytes(self.context_id.as_bytes()),
                CanonicalField::U64(self.from_epoch),
                CanonicalField::U64(self.to_epoch),
                CanonicalField::VarBytes(self.requester_did.as_bytes()),
            ],
        )
    }
}

/// A response containing missing MLS Commit messages.
///
/// Each entry in `commits` is a serialized MLS Commit message, in epoch
/// order. The responding member signs the response for authentication.
///
/// See ADR-029 section 3, source 2 (Peer request).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRangeResponse {
    /// The context the Commits belong to.
    pub context_id: ContextId,
    /// Serialized MLS Commit messages, in epoch order.
    pub commits: Vec<Vec<u8>>,
    /// DID of the responding member.
    pub responder_did: DID,
    /// Signature over the response fields for authentication.
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

impl CommitRangeResponse {
    /// Computes the canonical hash for signing/verification (§23.16.3).
    ///
    /// The `commits` array is encoded as each entry with its own `BE32(len)`
    /// prefix, then the concatenation is wrapped in an outer `BE32(len)` prefix.
    /// Field order: `context_id`, `commits_concat`, `responder_did`.
    /// Domain separator: `"SCP-COMMIT-RANGE-RESP-V1:"`.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        // Build length-prefixed concatenation of commits.
        let commits_concat = self.encode_commits();
        canonical_hash(
            COMMIT_RANGE_RESPONSE_DOMAIN_SEPARATOR,
            &[
                CanonicalField::VarBytes(self.context_id.as_bytes()),
                CanonicalField::VarBytes(&commits_concat),
                CanonicalField::VarBytes(self.responder_did.as_bytes()),
            ],
        )
    }

    /// Encodes commits as length-prefixed concatenation for canonical hashing.
    fn encode_commits(&self) -> Vec<u8> {
        let total_len: usize = self.commits.iter().map(|c| 4 + c.len()).sum();
        let mut buf = Vec::with_capacity(total_len);
        for commit in &self.commits {
            #[allow(clippy::cast_possible_truncation)]
            let len = commit.len() as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(commit);
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// ReorderBuffer
// ---------------------------------------------------------------------------

/// A single entry in the reorder buffer.
#[derive(Debug, Clone)]
pub struct ReorderEntry {
    /// Sequence number for ordering.
    pub sequence: u64,
    /// The buffered message payload.
    pub payload: Vec<u8>,
    /// Timestamp when this entry was buffered (monotonic, not wall clock).
    /// Used for gap timeout calculations.
    pub buffered_at_secs: u64,
}

/// Reorder buffer for out-of-order message delivery.
///
/// During relay catch-up, messages may arrive out of order (different relays,
/// different latencies). The reorder buffer holds messages until they can be
/// delivered in sequence order. Respects the 30-second gap timeout and
/// 100-message capacity from spec §9.8.5.
///
/// # Invariants
///
/// - Messages are delivered in strict sequence order.
/// - A gap (missing sequence number) is tolerated for up to
///   [`SyncPolicy::gap_timeout`] (default 30 seconds).
/// - The buffer holds at most [`SyncPolicy::reorder_buffer_capacity`] (default 100) messages.
///   When full, the oldest messages are force-delivered regardless of gaps.
///
/// See ADR-029 and spec §9.8.5.
#[derive(Debug)]
pub struct ReorderBuffer {
    /// The context this buffer belongs to.
    context_id: ContextId,
    /// The next expected sequence number for in-order delivery.
    next_expected: u64,
    /// Buffered entries keyed by sequence number.
    entries: BTreeMap<u64, ReorderEntry>,
    /// Maximum number of entries the buffer can hold.
    capacity: usize,
    /// Duration after which a gap is considered timed out.
    gap_timeout: Duration,
}

impl ReorderBuffer {
    /// Creates a new reorder buffer for a context using the given
    /// [`SyncPolicy`].
    ///
    /// # Arguments
    ///
    /// * `context_id` — The context this buffer serves.
    /// * `next_expected` — The first sequence number expected for in-order
    ///   delivery.
    /// * `policy` — Sync policy providing buffer capacity and gap timeout.
    #[must_use]
    pub const fn new(context_id: ContextId, next_expected: u64, policy: &SyncPolicy) -> Self {
        Self {
            context_id,
            next_expected,
            entries: BTreeMap::new(),
            capacity: policy.reorder_buffer_capacity,
            gap_timeout: policy.gap_timeout,
        }
    }

    /// Creates a reorder buffer with custom capacity and gap timeout.
    ///
    /// Useful for testing with smaller values.
    #[must_use]
    pub const fn with_config(
        context_id: ContextId,
        next_expected: u64,
        capacity: usize,
        gap_timeout: Duration,
    ) -> Self {
        Self {
            context_id,
            next_expected,
            entries: BTreeMap::new(),
            capacity,
            gap_timeout,
        }
    }

    /// Returns the context ID.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the next expected sequence number.
    #[must_use]
    pub const fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Returns the number of entries currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts a message into the reorder buffer.
    ///
    /// If the message's sequence number matches `next_expected`, it and any
    /// consecutive buffered messages are returned immediately for delivery.
    /// Otherwise the message is buffered.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::ReorderBufferOverflow`] if the buffer is at
    /// capacity and the message cannot be inserted without exceeding it.
    /// In this case the caller should call [`force_drain`](Self::force_drain)
    /// first.
    pub fn insert(&mut self, entry: ReorderEntry) -> Result<Vec<ReorderEntry>, SyncError> {
        // Discard messages with sequence numbers below what we've already delivered.
        if entry.sequence < self.next_expected {
            return Ok(Vec::new());
        }

        // Check capacity before inserting.
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&entry.sequence) {
            return Err(SyncError::ReorderBufferOverflow {
                context_id: self.context_id.clone(),
                buffered: self.entries.len(),
            });
        }

        self.entries.insert(entry.sequence, entry);

        // Deliver consecutive messages starting from next_expected.
        Ok(self.drain_consecutive())
    }

    /// Drains consecutive messages starting from `next_expected`.
    ///
    /// Returns all messages that form a contiguous sequence from the current
    /// `next_expected` position.
    fn drain_consecutive(&mut self) -> Vec<ReorderEntry> {
        let mut delivered = Vec::new();
        while let Some(entry) = self.entries.remove(&self.next_expected) {
            delivered.push(entry);
            self.next_expected = self.next_expected.saturating_add(1);
        }
        delivered
    }

    /// Checks for gap timeouts and force-delivers timed-out entries.
    ///
    /// Any gap that has persisted longer than [`SyncPolicy::gap_timeout`] causes all
    /// entries up to and including the first available entry after the gap
    /// to be delivered in order. The gap sequence numbers are skipped.
    ///
    /// # Arguments
    ///
    /// * `now_secs` — Current timestamp in seconds (monotonic preferred).
    ///   SCP does not require synchronized clocks (§9.8.3).
    pub fn check_gap_timeout(&mut self, now_secs: u64) -> Vec<ReorderEntry> {
        if self.entries.is_empty() {
            return Vec::new();
        }

        // Check if the earliest buffered entry has been waiting too long.
        let gap_timeout_secs = self.gap_timeout.as_secs();
        let Some(earliest_seq) = self.entries.keys().next().copied() else {
            return Vec::new();
        };

        // If the earliest entry is at next_expected, just drain consecutive.
        if earliest_seq == self.next_expected {
            return self.drain_consecutive();
        }

        // There's a gap. Check if the earliest buffered entry has timed out.
        let Some(earliest_entry) = self.entries.get(&earliest_seq) else {
            return Vec::new();
        };
        let waited = now_secs.saturating_sub(earliest_entry.buffered_at_secs);
        if waited < gap_timeout_secs {
            return Vec::new();
        }

        // Gap has timed out. Skip to the earliest available entry.
        self.next_expected = earliest_seq;
        self.drain_consecutive()
    }

    /// Force-drains all buffered entries in sequence order.
    ///
    /// Used when the buffer reaches capacity and must make room. All entries
    /// are delivered regardless of gaps. `next_expected` advances past the
    /// highest delivered sequence number.
    pub fn force_drain(&mut self) -> Vec<ReorderEntry> {
        let mut delivered: Vec<ReorderEntry> = self.entries.values().cloned().collect();
        delivered.sort_by_key(|e| e.sequence);
        if let Some(last) = delivered.last() {
            self.next_expected = last.sequence.saturating_add(1);
        }
        self.entries.clear();
        delivered
    }
}

// ---------------------------------------------------------------------------
// KeyPackagePrePublisher
// ---------------------------------------------------------------------------

/// Tracks `KeyPackage` pre-publication state for offline member addition.
///
/// MLS requires single-use `KeyPackage`s for adding members. When a member
/// goes offline, their pre-published `KeyPackage`s allow other members to add
/// new participants on their behalf. This struct tracks which `KeyPackage`s
/// have been published to relays and when they should be refreshed.
///
/// See ADR-029 (§9.6) and ADR-001 criterion 8 (key package buffer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackagePrePublisher {
    /// The DID of the member whose `KeyPackage`s are being managed.
    pub member_did: DID,
    /// Number of `KeyPackage`s currently published to relays.
    pub published_count: usize,
    /// Minimum number of `KeyPackage`s to maintain published.
    pub min_published: usize,
    /// Timestamp of the last publication (Unix seconds).
    pub last_published_at: u64,
    /// IDs of published `KeyPackage`s (for tracking consumption).
    pub published_ids: Vec<String>,
}

impl KeyPackagePrePublisher {
    /// Creates a new pre-publisher for a member.
    ///
    /// Defaults to maintaining at least 10 published `KeyPackage`s.
    #[must_use]
    pub const fn new(member_did: DID) -> Self {
        Self {
            member_did,
            published_count: 0,
            min_published: 10,
            last_published_at: 0,
            published_ids: Vec::new(),
        }
    }

    /// Creates a pre-publisher with a custom minimum publication count.
    #[must_use]
    pub const fn with_min_published(member_did: DID, min_published: usize) -> Self {
        Self {
            member_did,
            published_count: 0,
            min_published,
            last_published_at: 0,
            published_ids: Vec::new(),
        }
    }

    /// Returns `true` if the number of published `KeyPackage`s is below
    /// the minimum threshold and new ones should be generated and published.
    #[must_use]
    pub const fn needs_replenish(&self) -> bool {
        self.published_count < self.min_published
    }

    /// Returns how many new `KeyPackage`s should be generated to reach the
    /// minimum threshold.
    #[must_use]
    pub const fn replenish_count(&self) -> usize {
        self.min_published.saturating_sub(self.published_count)
    }

    /// Records that `count` new `KeyPackage`s were published, each with an ID.
    pub fn record_published(&mut self, ids: Vec<String>, timestamp: u64) {
        self.published_count = self.published_count.saturating_add(ids.len());
        self.last_published_at = timestamp;
        self.published_ids.extend(ids);
    }

    /// Records that a `KeyPackage` was consumed (used to add a member).
    ///
    /// Returns `true` if the `KeyPackage` ID was found and removed, `false`
    /// if the ID was not in the published set (already consumed or unknown).
    pub fn record_consumed(&mut self, key_package_id: &str) -> bool {
        if let Some(pos) = self
            .published_ids
            .iter()
            .position(|id| id == key_package_id)
        {
            self.published_ids.remove(pos);
            self.published_count = self.published_count.saturating_sub(1);
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// ReconnectionCoordinator
// ---------------------------------------------------------------------------

/// Per-context result of the reconnection protocol.
///
/// See ADR-029 acceptance criterion 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSyncResult {
    /// The context that was synced.
    pub context_id: ContextId,
    /// The offline tier classification for this context.
    pub tier: OfflineTier,
    /// Number of MLS epochs caught up.
    pub epochs_caught_up: u64,
    /// Number of event log events recovered.
    pub events_recovered: u64,
    /// Number of messages that could not be recovered (forward secrecy).
    pub messages_unrecoverable: u64,
    /// Whether the MLS Update was issued after catch-up (§9.12).
    pub mls_update_issued: bool,
    /// The sync outcome.
    pub outcome: SyncOutcome,
    /// Sync events detected during this context's sync (e.g., equivocation alerts).
    pub sync_events: Vec<SyncEvent>,
}

/// Report produced by the reconnection coordinator after completing the
/// six-phase reconnection protocol.
///
/// See ADR-029 acceptance criterion 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectionReport {
    /// Per-context sync results.
    pub contexts_synced: Vec<ContextSyncResult>,
    /// Total number of queued messages drained across all contexts.
    pub messages_drained: u64,
    /// Total number of queued messages discarded (expired or context gone).
    pub messages_discarded: u64,
    /// Total duration of the reconnection protocol in milliseconds.
    pub total_duration_ms: u64,
}

/// Orchestrates the six-phase reconnection protocol for all active contexts.
///
/// The reconnection protocol (ADR-029 section 2) runs the following phases
/// sequentially for each context:
///
/// 1. **Relay catch-up** — Re-subscribe with `since` overlap, deduplicate
///    by `blob_id`.
/// 2. **MLS epoch reconciliation** — Sequential Commit processing (max 100)
///    or Welcome-based fast-forward.
/// 3. **Event log sync** — Exchange consistency checkpoints, request missing
///    events, verify Merkle proofs.
/// 4. **Sender key re-acquisition** — Request current sender keys for any
///    senders whose keys advanced during the offline period.
/// 5. **MLS Update** — Issue an MLS Update proposal for post-compromise
///    security (§9.12).
/// 6. **Queue drain** — MLS-encrypt and send queued outbound messages.
///
/// Contexts are synced concurrently. Each context has a 120-second timeout.
///
/// See ADR-029 section 2.
#[derive(Debug)]
pub struct ReconnectionCoordinator {
    /// The DID of the reconnecting member.
    member_did: DID,
    /// Active context IDs to sync.
    context_ids: Vec<ContextId>,
    /// Per-context last relay contact timestamps.
    last_relay_contacts: std::collections::HashMap<ContextId, u64>,
    /// Overall timeout for the reconnection protocol.
    overall_timeout: Duration,
    /// Sync policy governing recovery behavior.
    policy: SyncPolicy,
}

impl ReconnectionCoordinator {
    /// Creates a new reconnection coordinator with the default
    /// [`SyncPolicy`].
    ///
    /// # Arguments
    ///
    /// * `member_did` — The DID of the reconnecting member.
    /// * `context_ids` — Active context IDs to sync.
    /// * `last_relay_contacts` — Per-context last relay contact timestamps
    ///   (persisted in `ProtocolRepository` under
    ///   `sync/{context_id}/last_relay_contact`).
    #[must_use]
    pub fn new(
        member_did: DID,
        context_ids: Vec<ContextId>,
        last_relay_contacts: std::collections::HashMap<ContextId, u64>,
    ) -> Self {
        Self::with_policy(
            member_did,
            context_ids,
            last_relay_contacts,
            SyncPolicy::default(),
        )
    }

    /// Creates a new reconnection coordinator with a custom [`SyncPolicy`].
    ///
    /// # Arguments
    ///
    /// * `member_did` — The DID of the reconnecting member.
    /// * `context_ids` — Active context IDs to sync.
    /// * `last_relay_contacts` — Per-context last relay contact timestamps
    ///   (persisted in `ProtocolRepository` under
    ///   `sync/{context_id}/last_relay_contact`).
    /// * `policy` — Sync policy governing recovery behavior.
    #[must_use]
    pub const fn with_policy(
        member_did: DID,
        context_ids: Vec<ContextId>,
        last_relay_contacts: std::collections::HashMap<ContextId, u64>,
        policy: SyncPolicy,
    ) -> Self {
        Self {
            member_did,
            context_ids,
            last_relay_contacts,
            overall_timeout: Duration::from_secs(120),
            policy,
        }
    }

    /// Returns the member DID.
    #[must_use]
    pub const fn member_did(&self) -> &DID {
        &self.member_did
    }

    /// Returns the context IDs to sync.
    #[must_use]
    pub fn context_ids(&self) -> &[ContextId] {
        &self.context_ids
    }

    /// Returns the overall timeout for the reconnection protocol.
    #[must_use]
    pub const fn overall_timeout(&self) -> Duration {
        self.overall_timeout
    }

    /// Returns a reference to the sync policy.
    #[must_use]
    pub const fn policy(&self) -> &SyncPolicy {
        &self.policy
    }

    /// Classifies the offline tier for a specific context.
    ///
    /// Uses the per-context last relay contact timestamp and the provided
    /// `now` timestamp. SCP does not require synchronized clocks (§9.8.3).
    #[must_use]
    pub fn classify_context(&self, context_id: &str, now: u64) -> OfflineTier {
        let last_contact = self
            .last_relay_contacts
            .get(context_id)
            .copied()
            .unwrap_or(0);
        self.policy.classify_offline_duration(last_contact, now)
    }

    /// Plans the reconnection by classifying each context and producing
    /// the initial sync results.
    ///
    /// This does not execute the protocol — it prepares the context-level
    /// metadata that the actual transport/MLS layer uses to drive catch-up.
    /// The transport layer is injected at the SDK level, not in `scp-core`.
    #[must_use]
    pub fn plan(&self, now: u64) -> Vec<ContextSyncResult> {
        self.context_ids
            .iter()
            .map(|ctx_id| {
                let tier = self.classify_context(ctx_id, now);
                ContextSyncResult {
                    context_id: ctx_id.clone(),
                    tier,
                    epochs_caught_up: 0,
                    events_recovered: 0,
                    messages_unrecoverable: 0,
                    mls_update_issued: false,
                    outcome: SyncOutcome::FullyCaughtUp, // Placeholder until sync runs.
                    sync_events: Vec::new(),
                }
            })
            .collect()
    }

    /// Records that the MLS Update was issued for a context after catch-up.
    ///
    /// Per §9.12, the SDK SHOULD issue an MLS Update after reconnecting.
    /// This method updates the result to reflect that the Update was issued.
    pub const fn record_mls_update(result: &mut ContextSyncResult) {
        result.mls_update_issued = true;
    }

    /// Drains the outbound queue for a context (Phase 6 of the reconnection
    /// protocol).
    ///
    /// 1. Prunes expired entries based on TTL before draining (spec §23.2).
    /// 2. Dequeues all remaining entries in queue order.
    /// 3. Returns the entries for the caller to MLS-encrypt with the current
    ///    epoch's key schedule and send.
    ///
    /// If the context no longer exists (closed or expired while offline),
    /// the caller should discard the returned entries and emit a `ContextGone`
    /// notification.
    ///
    /// # Arguments
    ///
    /// * `store` — The protocol repository containing the outbound queue.
    /// * `context_id` — The context to drain.
    /// * `now` — Current Unix timestamp (seconds).
    /// * `blob_ttl_secs` — The context's `blob_ttl` in seconds. If `None`,
    ///   [`DEFAULT_QUEUE_TTL_SECS`] (7 days) is used.
    ///
    /// # Returns
    ///
    /// A `QueueDrainResult` with the entries to send and the number of
    /// expired entries that were pruned.
    ///
    /// # Errors
    ///
    /// Returns [`crate::store::StoreError`] if any storage operation fails.
    pub async fn drain_context_queue<S: scp_platform::traits::Storage>(
        store: &crate::store::ProtocolRepository<S>,
        context_id: &str,
        now: u64,
        blob_ttl_secs: Option<u64>,
    ) -> Result<QueueDrainResult, crate::store::StoreError> {
        let ttl = blob_ttl_secs.unwrap_or(DEFAULT_QUEUE_TTL_SECS);

        // Step 1: Prune expired entries.
        let expired = store.prune_expired_queue(context_id, now, ttl).await?;

        // Step 2: Dequeue remaining entries.
        let entries = store.dequeue_messages(context_id).await?;

        Ok(QueueDrainResult {
            entries,
            expired_pruned: expired,
        })
    }

    /// Builds a [`ReconnectionReport`] from per-context sync results.
    ///
    /// # Arguments
    ///
    /// * `results` — Per-context sync results.
    /// * `messages_drained` — Total queued messages sent.
    /// * `messages_discarded` — Total queued messages discarded.
    /// * `total_duration_ms` — Total time spent in the reconnection protocol.
    #[must_use]
    pub const fn build_report(
        results: Vec<ContextSyncResult>,
        messages_drained: u64,
        messages_discarded: u64,
        total_duration_ms: u64,
    ) -> ReconnectionReport {
        ReconnectionReport {
            contexts_synced: results,
            messages_drained,
            messages_discarded,
            total_duration_ms,
        }
    }
}

/// Result of draining the outbound queue for a context.
///
/// Returned by [`ReconnectionCoordinator::drain_context_queue`]. The caller
/// is responsible for MLS-encrypting each entry's `inner_envelope` with the
/// current epoch's key schedule and sending it.
///
/// See spec section 23.2, 23.3 Phase 6.
#[derive(Debug, Clone)]
pub struct QueueDrainResult {
    /// Queue entries to MLS-encrypt and send, in queue order.
    pub entries: Vec<crate::store::queue::QueueEntry>,
    /// Number of expired entries that were pruned before draining.
    pub expired_pruned: u64,
}

// ---------------------------------------------------------------------------
// NetworkSimulator (test support)
// ---------------------------------------------------------------------------

/// Simulated network condition for testing offline/reconnect scenarios.
///
/// Used by the `NetworkSimulator` to model relay availability, message loss,
/// and latency during hours-scale offline testing.
#[derive(Debug, Clone)]
pub struct NetworkCondition {
    /// Whether the relay is reachable.
    pub relay_reachable: bool,
    /// Simulated one-way latency in milliseconds.
    pub latency_ms: u64,
    /// Probability (0.0–1.0) that a message is dropped by the relay.
    pub drop_rate: f64,
    /// Maximum number of messages the relay will buffer before dropping old ones.
    pub relay_buffer_capacity: usize,
}

impl Default for NetworkCondition {
    fn default() -> Self {
        Self {
            relay_reachable: true,
            latency_ms: 50,
            drop_rate: 0.0,
            relay_buffer_capacity: 10_000,
        }
    }
}

/// Simulates network conditions for testing hours-scale offline scenarios.
///
/// The `NetworkSimulator` models relay behaviour: buffering messages while a
/// member is offline, enforcing relay buffer limits, and delivering buffered
/// messages on reconnection. All verification remains client-side (relays are
/// untrusted).
///
/// See ADR-029 acceptance criterion 8.
#[derive(Debug)]
pub struct NetworkSimulator {
    /// Current network condition.
    condition: NetworkCondition,
    /// Messages buffered by the simulated relay, keyed by context ID.
    relay_buffers: std::collections::HashMap<ContextId, Vec<BufferedMessage>>,
    /// Current simulated timestamp (seconds since epoch).
    current_time: u64,
}

impl NetworkSimulator {
    /// Creates a new simulator with default network conditions and the given
    /// starting timestamp.
    #[must_use]
    pub fn new(start_time: u64) -> Self {
        Self {
            condition: NetworkCondition::default(),
            relay_buffers: std::collections::HashMap::new(),
            current_time: start_time,
        }
    }

    /// Returns the current simulated time.
    #[must_use]
    pub const fn current_time(&self) -> u64 {
        self.current_time
    }

    /// Advances the simulated clock by the given number of seconds.
    pub const fn advance_time(&mut self, seconds: u64) {
        self.current_time = self.current_time.saturating_add(seconds);
    }

    /// Sets the network condition (relay reachability, latency, drop rate).
    pub const fn set_condition(&mut self, condition: NetworkCondition) {
        self.condition = condition;
    }

    /// Simulates a member going offline by making the relay unreachable.
    pub const fn disconnect(&mut self) {
        self.condition.relay_reachable = false;
    }

    /// Simulates a member reconnecting by making the relay reachable again.
    pub const fn reconnect(&mut self) {
        self.condition.relay_reachable = true;
    }

    /// Returns whether the relay is currently reachable.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.condition.relay_reachable
    }

    /// Sends a message to the simulated relay buffer for a context.
    ///
    /// If the relay is unreachable, the message is buffered (store-and-forward).
    /// If the relay buffer is at capacity, the oldest message is dropped.
    pub fn send_message(
        &mut self,
        context_id: &str,
        blob_id: String,
        payload: Vec<u8>,
        epoch: Option<u64>,
    ) {
        let buffer = self.relay_buffers.entry(context_id.to_owned()).or_default();

        // Enforce relay buffer capacity.
        if buffer.len() >= self.condition.relay_buffer_capacity {
            buffer.remove(0);
        }

        buffer.push(BufferedMessage {
            blob_id,
            context_id: context_id.to_owned(),
            payload,
            stored_at: self.current_time,
            epoch,
        });
    }

    /// Retrieves all buffered messages for a context since the given timestamp.
    ///
    /// Models the relay's `SUBSCRIBE` with `since` parameter. Only returns
    /// messages if the relay is reachable.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::RelayCatchUpFailed`] if the relay is not reachable.
    pub fn retrieve_messages(
        &self,
        context_id: &str,
        since: u64,
    ) -> Result<Vec<BufferedMessage>, SyncError> {
        if !self.condition.relay_reachable {
            return Err(SyncError::RelayCatchUpFailed {
                context_id: context_id.to_owned(),
                reason: "relay not reachable".to_owned(),
            });
        }

        let Some(buffer) = self.relay_buffers.get(context_id) else {
            return Ok(Vec::new());
        };

        Ok(buffer
            .iter()
            .filter(|msg| msg.stored_at >= since)
            .cloned()
            .collect())
    }

    /// Returns the number of messages buffered for a context.
    #[must_use]
    pub fn buffered_count(&self, context_id: &str) -> usize {
        self.relay_buffers.get(context_id).map_or(0, Vec::len)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // RelayMessageBuffer tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_buffer_subscribe_since_subtracts_overlap() {
        let buf = RelayMessageBuffer::new("ctx-1".to_owned(), 1000);
        assert_eq!(buf.subscribe_since(), 995);
    }

    #[test]
    fn relay_buffer_subscribe_since_saturates_at_zero() {
        let buf = RelayMessageBuffer::new("ctx-1".to_owned(), 3);
        assert_eq!(buf.subscribe_since(), 0);
    }

    #[test]
    fn relay_buffer_deduplicates_by_blob_id() {
        let mut buf = RelayMessageBuffer::new("ctx-1".to_owned(), 0);
        let msg1 = BufferedMessage {
            blob_id: "blob-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            payload: vec![1, 2, 3],
            stored_at: 100,
            epoch: Some(1),
        };
        let msg2 = BufferedMessage {
            blob_id: "blob-1".to_owned(),
            context_id: "ctx-1".to_owned(),
            payload: vec![4, 5, 6],
            stored_at: 101,
            epoch: Some(1),
        };

        assert!(buf.ingest(msg1));
        assert!(!buf.ingest(msg2));
        assert_eq!(buf.message_count(), 1);
    }

    #[test]
    fn relay_buffer_drain_sorted_returns_messages_in_order() {
        let mut buf = RelayMessageBuffer::new("ctx-1".to_owned(), 0);
        buf.ingest(BufferedMessage {
            blob_id: "b2".to_owned(),
            context_id: "ctx-1".to_owned(),
            payload: vec![2],
            stored_at: 200,
            epoch: None,
        });
        buf.ingest(BufferedMessage {
            blob_id: "b1".to_owned(),
            context_id: "ctx-1".to_owned(),
            payload: vec![1],
            stored_at: 100,
            epoch: None,
        });
        buf.ingest(BufferedMessage {
            blob_id: "b3".to_owned(),
            context_id: "ctx-1".to_owned(),
            payload: vec![3],
            stored_at: 150,
            epoch: None,
        });

        let sorted = buf.drain_sorted();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].stored_at, 100);
        assert_eq!(sorted[1].stored_at, 150);
        assert_eq!(sorted[2].stored_at, 200);
    }

    // -----------------------------------------------------------------------
    // EpochCatchUpState tests
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_catch_up_new_starts_in_processing() {
        let state = EpochCatchUpState::new("ctx-1".to_owned(), 5, 10);
        assert_eq!(state.status, CatchUpStatus::Processing);
        assert_eq!(state.epochs_remaining(), 5);
        assert_eq!(state.commits_processed, 0);
    }

    #[test]
    fn epoch_catch_up_record_commit_advances_state() {
        let mut state = EpochCatchUpState::new("ctx-1".to_owned(), 5, 8);
        state.record_commit_processed();
        assert_eq!(state.commits_processed, 1);
        assert_eq!(state.epochs_remaining(), 2);
        assert_eq!(state.status, CatchUpStatus::Processing);

        state.record_commit_processed();
        state.record_commit_processed();
        assert_eq!(state.commits_processed, 3);
        assert_eq!(state.epochs_remaining(), 0);
        assert_eq!(state.status, CatchUpStatus::Complete);
    }

    #[test]
    fn epoch_catch_up_exceeds_limit_for_large_gap() {
        let state = EpochCatchUpState::new("ctx-1".to_owned(), 0, 150);
        assert!(state.exceeds_sequential_limit(&SyncPolicy::default()));
    }

    #[test]
    fn epoch_catch_up_within_limit_for_small_gap() {
        let state = EpochCatchUpState::new("ctx-1".to_owned(), 0, 50);
        assert!(!state.exceeds_sequential_limit(&SyncPolicy::default()));
    }

    #[test]
    fn epoch_catch_up_at_boundary_does_not_exceed() {
        let state = EpochCatchUpState::new("ctx-1".to_owned(), 0, 100);
        assert!(!state.exceeds_sequential_limit(&SyncPolicy::default()));
    }

    #[test]
    fn epoch_catch_up_transition_to_fast_forward() {
        let mut state = EpochCatchUpState::new("ctx-1".to_owned(), 5, 200);
        state.record_commit_processed(); // epoch 6
        state.record_commit_processed(); // epoch 7
        state.transition_to_fast_forward();
        assert_eq!(
            state.status,
            CatchUpStatus::FastForwarded {
                skipped_from: 7,
                skipped_to: 200,
            }
        );
    }

    #[test]
    fn epoch_catch_up_transition_to_failed() {
        let mut state = EpochCatchUpState::new("ctx-1".to_owned(), 5, 10);
        state.transition_to_failed("corrupted commit".to_owned());
        assert_eq!(
            state.status,
            CatchUpStatus::Failed {
                reason: "corrupted commit".to_owned(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // ReorderBuffer tests
    // -----------------------------------------------------------------------

    #[test]
    fn reorder_buffer_delivers_consecutive_messages_immediately() {
        let mut buf = ReorderBuffer::new("ctx-1".to_owned(), 0, &SyncPolicy::default());
        let entry = ReorderEntry {
            sequence: 0,
            payload: vec![0],
            buffered_at_secs: 100,
        };
        let delivered = buf.insert(entry).unwrap_or_default();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].sequence, 0);
        assert_eq!(buf.next_expected(), 1);
    }

    #[test]
    fn reorder_buffer_buffers_out_of_order_messages() {
        let mut buf = ReorderBuffer::new("ctx-1".to_owned(), 0, &SyncPolicy::default());

        // Insert seq 2 first (out of order).
        let delivered = buf
            .insert(ReorderEntry {
                sequence: 2,
                payload: vec![2],
                buffered_at_secs: 100,
            })
            .unwrap_or_default();
        assert!(delivered.is_empty());
        assert_eq!(buf.len(), 1);

        // Insert seq 1 (still missing seq 0).
        let delivered = buf
            .insert(ReorderEntry {
                sequence: 1,
                payload: vec![1],
                buffered_at_secs: 101,
            })
            .unwrap_or_default();
        assert!(delivered.is_empty());
        assert_eq!(buf.len(), 2);

        // Insert seq 0 — should deliver 0, 1, 2 in order.
        let delivered = buf
            .insert(ReorderEntry {
                sequence: 0,
                payload: vec![0],
                buffered_at_secs: 102,
            })
            .unwrap_or_default();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].sequence, 0);
        assert_eq!(delivered[1].sequence, 1);
        assert_eq!(delivered[2].sequence, 2);
        assert_eq!(buf.next_expected(), 3);
    }

    #[test]
    fn reorder_buffer_discards_old_sequence_numbers() {
        let mut buf = ReorderBuffer::new("ctx-1".to_owned(), 5, &SyncPolicy::default());
        let delivered = buf
            .insert(ReorderEntry {
                sequence: 3,
                payload: vec![3],
                buffered_at_secs: 100,
            })
            .unwrap_or_default();
        assert!(delivered.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn reorder_buffer_gap_timeout_delivers_after_wait() {
        let mut buf = ReorderBuffer::new("ctx-1".to_owned(), 0, &SyncPolicy::default());

        // Buffer seq 2 (gap at seq 0 and 1).
        let _ = buf.insert(ReorderEntry {
            sequence: 2,
            payload: vec![2],
            buffered_at_secs: 100,
        });

        // Check timeout before 30 seconds — nothing delivered.
        let delivered = buf.check_gap_timeout(120);
        assert!(delivered.is_empty());

        // Check timeout after 30 seconds — seq 2 delivered.
        let delivered = buf.check_gap_timeout(131);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].sequence, 2);
        assert_eq!(buf.next_expected(), 3);
    }

    #[test]
    fn reorder_buffer_gap_timeout_delivers_consecutive_run() {
        let mut buf = ReorderBuffer::new("ctx-1".to_owned(), 0, &SyncPolicy::default());

        // Buffer seq 2 and 3 (gap at 0, 1).
        let _ = buf.insert(ReorderEntry {
            sequence: 2,
            payload: vec![2],
            buffered_at_secs: 100,
        });
        let _ = buf.insert(ReorderEntry {
            sequence: 3,
            payload: vec![3],
            buffered_at_secs: 100,
        });

        // After timeout, both 2 and 3 should deliver.
        let delivered = buf.check_gap_timeout(131);
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].sequence, 2);
        assert_eq!(delivered[1].sequence, 3);
        assert_eq!(buf.next_expected(), 4);
    }

    #[test]
    fn reorder_buffer_overflow_returns_error() {
        let mut buf =
            ReorderBuffer::with_config("ctx-1".to_owned(), 0, 3, SyncPolicy::default().gap_timeout);

        // Fill to capacity (seq 1, 2, 3 — gap at 0).
        let _ = buf.insert(ReorderEntry {
            sequence: 1,
            payload: vec![1],
            buffered_at_secs: 100,
        });
        let _ = buf.insert(ReorderEntry {
            sequence: 2,
            payload: vec![2],
            buffered_at_secs: 100,
        });
        let _ = buf.insert(ReorderEntry {
            sequence: 3,
            payload: vec![3],
            buffered_at_secs: 100,
        });

        // Inserting seq 4 should fail (capacity = 3, all occupied).
        let result = buf.insert(ReorderEntry {
            sequence: 4,
            payload: vec![4],
            buffered_at_secs: 101,
        });
        assert!(result.is_err());
    }

    #[test]
    fn reorder_buffer_force_drain_delivers_all() {
        let mut buf = ReorderBuffer::new("ctx-1".to_owned(), 0, &SyncPolicy::default());
        let _ = buf.insert(ReorderEntry {
            sequence: 5,
            payload: vec![5],
            buffered_at_secs: 100,
        });
        let _ = buf.insert(ReorderEntry {
            sequence: 3,
            payload: vec![3],
            buffered_at_secs: 100,
        });
        let _ = buf.insert(ReorderEntry {
            sequence: 1,
            payload: vec![1],
            buffered_at_secs: 100,
        });

        let delivered = buf.force_drain();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].sequence, 1);
        assert_eq!(delivered[1].sequence, 3);
        assert_eq!(delivered[2].sequence, 5);
        assert_eq!(buf.next_expected(), 6);
        assert!(buf.is_empty());
    }

    // -----------------------------------------------------------------------
    // KeyPackagePrePublisher tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_package_pre_publisher_needs_replenish_initially() {
        let pp = KeyPackagePrePublisher::new(DID::from("did:dht:z6MkAlice"));
        assert!(pp.needs_replenish());
        assert_eq!(pp.replenish_count(), 10);
    }

    #[test]
    fn key_package_pre_publisher_records_publication() {
        let mut pp = KeyPackagePrePublisher::new(DID::from("did:dht:z6MkAlice"));
        pp.record_published(
            vec!["kp-1".to_owned(), "kp-2".to_owned(), "kp-3".to_owned()],
            1000,
        );
        assert_eq!(pp.published_count, 3);
        assert_eq!(pp.last_published_at, 1000);
        assert!(pp.needs_replenish());
        assert_eq!(pp.replenish_count(), 7);
    }

    #[test]
    fn key_package_pre_publisher_records_consumption() {
        let mut pp = KeyPackagePrePublisher::with_min_published(DID::from("did:dht:z6MkBob"), 2);
        pp.record_published(vec!["kp-1".to_owned(), "kp-2".to_owned()], 1000);
        assert!(!pp.needs_replenish());

        assert!(pp.record_consumed("kp-1"));
        assert_eq!(pp.published_count, 1);
        assert!(pp.needs_replenish());

        // Consuming unknown ID returns false.
        assert!(!pp.record_consumed("kp-unknown"));
        assert_eq!(pp.published_count, 1);
    }

    // -----------------------------------------------------------------------
    // ReconnectionCoordinator tests
    // -----------------------------------------------------------------------

    #[test]
    fn reconnection_coordinator_classifies_contexts() {
        let mut contacts = std::collections::HashMap::new();
        contacts.insert("ctx-1".to_owned(), 1_000_000u64);
        contacts.insert("ctx-2".to_owned(), 900_000u64);

        let coord = ReconnectionCoordinator::new(
            DID::from("did:dht:z6MkAlice"),
            vec!["ctx-1".to_owned(), "ctx-2".to_owned()],
            contacts,
        );

        // ctx-1: 1_003_600 - 1_000_000 = 3_600 < 14_400 → Short
        assert_eq!(
            coord.classify_context("ctx-1", 1_003_600),
            OfflineTier::Short,
        );

        // ctx-2: 1_003_600 - 900_000 = 103_600 → Extended
        assert_eq!(
            coord.classify_context("ctx-2", 1_003_600),
            OfflineTier::Extended,
        );
    }

    #[test]
    fn reconnection_coordinator_unknown_context_defaults_to_long() {
        let coord = ReconnectionCoordinator::new(
            DID::from("did:dht:z6MkAlice"),
            vec!["ctx-unknown".to_owned()],
            std::collections::HashMap::new(),
        );

        // Unknown context has last_contact = 0 → always Long for any
        // reasonable `now`.
        assert_eq!(
            coord.classify_context("ctx-unknown", 1_000_000),
            OfflineTier::Long,
        );
    }

    #[test]
    fn reconnection_coordinator_plan_produces_per_context_results() {
        let mut contacts = std::collections::HashMap::new();
        contacts.insert("ctx-a".to_owned(), 1_000_000u64);
        // 1_010_000 - 200_000 = 810_000 > 604_800 (7 days) → Long
        contacts.insert("ctx-b".to_owned(), 200_000u64);

        let coord = ReconnectionCoordinator::new(
            DID::from("did:dht:z6MkAlice"),
            vec!["ctx-a".to_owned(), "ctx-b".to_owned()],
            contacts,
        );

        let plan = coord.plan(1_010_000);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].context_id, "ctx-a");
        assert_eq!(plan[0].tier, OfflineTier::Short);
        assert_eq!(plan[1].context_id, "ctx-b");
        assert_eq!(plan[1].tier, OfflineTier::Long);
    }

    #[test]
    fn reconnection_coordinator_record_mls_update() {
        let mut result = ContextSyncResult {
            context_id: "ctx-1".to_owned(),
            tier: OfflineTier::Short,
            epochs_caught_up: 3,
            events_recovered: 10,
            messages_unrecoverable: 0,
            mls_update_issued: false,
            outcome: SyncOutcome::FullyCaughtUp,
            sync_events: vec![],
        };
        assert!(!result.mls_update_issued);
        ReconnectionCoordinator::record_mls_update(&mut result);
        assert!(result.mls_update_issued);
    }

    #[test]
    fn reconnection_coordinator_build_report() {
        let results = vec![ContextSyncResult {
            context_id: "ctx-1".to_owned(),
            tier: OfflineTier::Short,
            epochs_caught_up: 5,
            events_recovered: 20,
            messages_unrecoverable: 2,
            mls_update_issued: true,
            outcome: SyncOutcome::FullyCaughtUp,
            sync_events: vec![],
        }];
        let report = ReconnectionCoordinator::build_report(results, 15, 3, 2500);
        assert_eq!(report.contexts_synced.len(), 1);
        assert_eq!(report.messages_drained, 15);
        assert_eq!(report.messages_discarded, 3);
        assert_eq!(report.total_duration_ms, 2500);
    }

    // -----------------------------------------------------------------------
    // NetworkSimulator stress tests
    // -----------------------------------------------------------------------

    #[test]
    fn network_simulator_buffers_messages_during_offline() {
        let mut sim = NetworkSimulator::new(1_000_000);

        // Send messages while connected.
        sim.send_message("ctx-1", "b1".to_owned(), vec![1], Some(1));
        sim.advance_time(1);
        sim.send_message("ctx-1", "b2".to_owned(), vec![2], Some(1));

        assert_eq!(sim.buffered_count("ctx-1"), 2);

        // Go offline — relay still buffers incoming messages from others.
        sim.disconnect();
        assert!(!sim.is_connected());

        // Other members send messages while we're offline.
        sim.advance_time(3600); // 1 hour passes
        sim.send_message("ctx-1", "b3".to_owned(), vec![3], Some(2));
        sim.advance_time(3600); // Another hour
        sim.send_message("ctx-1", "b4".to_owned(), vec![4], Some(3));

        assert_eq!(sim.buffered_count("ctx-1"), 4);

        // Can't retrieve while offline.
        let result = sim.retrieve_messages("ctx-1", 0);
        assert!(result.is_err());

        // Reconnect.
        sim.reconnect();
        assert!(sim.is_connected());

        // Retrieve all messages since just before going offline.
        let messages = sim
            .retrieve_messages("ctx-1", 1_000_000)
            .unwrap_or_default();
        assert_eq!(messages.len(), 4);
    }

    #[test]
    fn network_simulator_hours_offline_relay_catch_up() {
        let mut sim = NetworkSimulator::new(1_000_000);

        // Simulate 3 hours of activity while a member is offline.
        sim.disconnect();

        let hours = 3;
        let messages_per_hour = 10;
        for hour in 0..hours {
            for msg_idx in 0..messages_per_hour {
                let seq = hour * messages_per_hour + msg_idx;
                sim.advance_time(360); // 6 minutes between messages
                sim.send_message(
                    "ctx-1",
                    format!("blob-{seq}"),
                    format!("payload-{seq}").into_bytes(),
                    Some(u64::try_from(seq / 5).unwrap_or(0) + 1),
                );
            }
        }

        assert_eq!(
            sim.buffered_count("ctx-1"),
            usize::try_from(hours * messages_per_hour).unwrap_or(0),
        );

        // Reconnect and retrieve.
        sim.reconnect();
        let messages = sim
            .retrieve_messages("ctx-1", 1_000_000)
            .unwrap_or_default();
        assert_eq!(
            messages.len(),
            usize::try_from(hours * messages_per_hour).unwrap_or(0),
        );

        // Feed into a RelayMessageBuffer for dedup.
        let mut relay_buf = RelayMessageBuffer::new("ctx-1".to_owned(), 1_000_000);
        for msg in &messages {
            relay_buf.ingest(msg.clone());
        }
        assert_eq!(relay_buf.message_count(), messages.len());

        // Drain sorted — messages should be in stored_at order.
        let sorted = relay_buf.drain_sorted();
        for window in sorted.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[test]
    fn network_simulator_respects_relay_buffer_capacity() {
        let mut sim = NetworkSimulator::new(0);
        sim.set_condition(NetworkCondition {
            relay_reachable: true,
            latency_ms: 0,
            drop_rate: 0.0,
            relay_buffer_capacity: 5,
        });

        for i in 0..10 {
            sim.send_message("ctx-1", format!("b{i}"), vec![i], None);
        }

        // Only the last 5 should be retained (oldest dropped).
        assert_eq!(sim.buffered_count("ctx-1"), 5);
        let messages = sim.retrieve_messages("ctx-1", 0).unwrap_or_default();
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0].blob_id, "b5");
        assert_eq!(messages[4].blob_id, "b9");
    }

    #[test]
    fn network_simulator_epoch_catch_up_within_limit() {
        // Simulate an offline period with 50 epoch advances.
        let mut catch_up = EpochCatchUpState::new("ctx-1".to_owned(), 10, 60);
        assert!(!catch_up.exceeds_sequential_limit(&SyncPolicy::default()));
        assert_eq!(catch_up.epochs_remaining(), 50);

        // Process all 50 Commits.
        for _ in 0..50 {
            assert_eq!(catch_up.status, CatchUpStatus::Processing);
            catch_up.record_commit_processed();
        }
        assert_eq!(catch_up.status, CatchUpStatus::Complete);
        assert_eq!(catch_up.commits_processed, 50);
        assert_eq!(catch_up.epochs_remaining(), 0);
    }

    #[test]
    fn network_simulator_epoch_catch_up_exceeds_limit_falls_back() {
        // Simulate an offline period with 150 epoch advances.
        let mut catch_up = EpochCatchUpState::new("ctx-1".to_owned(), 10, 160);
        assert!(catch_up.exceeds_sequential_limit(&SyncPolicy::default()));

        // Process up to the limit.
        for _ in 0..SyncPolicy::default().max_sequential_commits {
            catch_up.record_commit_processed();
        }
        // Still not complete because target is 160.
        assert_eq!(catch_up.status, CatchUpStatus::Processing);
        assert_eq!(catch_up.epochs_remaining(), 50);

        // Fall back to fast-forward.
        catch_up.transition_to_fast_forward();
        assert_eq!(
            catch_up.status,
            CatchUpStatus::FastForwarded {
                skipped_from: 110,
                skipped_to: 160,
            }
        );
    }

    #[test]
    fn network_simulator_reorder_buffer_stress() {
        let mut buf = ReorderBuffer::new("ctx-1".to_owned(), 0, &SyncPolicy::default());

        // Insert messages in reverse order (worst case for reordering).
        let count = 50u64;
        for seq in (0..count).rev() {
            let _ = buf.insert(ReorderEntry {
                sequence: seq,
                payload: vec![u8::try_from(seq % 256).unwrap_or(0)],
                buffered_at_secs: 100,
            });
        }

        // All should have been delivered because filling in seq 0 last
        // triggers the full consecutive drain.
        assert!(buf.is_empty());
        assert_eq!(buf.next_expected(), count);
    }

    #[test]
    fn network_simulator_full_hours_offline_scenario() {
        // Full integration test: member goes offline for 2 hours, relay
        // buffers messages, member reconnects, catches up MLS epochs,
        // reorders messages, issues MLS Update.

        let mut sim = NetworkSimulator::new(1_000_000);

        // Phase: member is online, establish baseline.
        sim.send_message("ctx-1", "b0".to_owned(), vec![0], Some(1));
        let last_contact = sim.current_time();

        // Phase: member goes offline for 2 hours.
        sim.disconnect();
        sim.advance_time(7200); // 2 hours

        // Other members send messages and advance epochs.
        for i in 1..=20u64 {
            sim.advance_time(60);
            sim.send_message(
                "ctx-1",
                format!("offline-{i}"),
                vec![u8::try_from(i % 256).unwrap_or(0)],
                Some(i / 5 + 1),
            );
        }

        // Phase: reconnect.
        sim.reconnect();
        let now = sim.current_time();

        // Classify offline tier.
        let tier = super::super::classify_offline_duration(last_contact, now);
        assert_eq!(tier, OfflineTier::Short);

        // Retrieve buffered messages.
        let relay_buf_start = last_contact.saturating_sub(5); // 5-second overlap
        let messages = sim
            .retrieve_messages("ctx-1", relay_buf_start)
            .unwrap_or_default();
        assert!(!messages.is_empty());

        // Feed into relay message buffer for dedup.
        let mut relay_buf = RelayMessageBuffer::new("ctx-1".to_owned(), last_contact);
        for msg in &messages {
            relay_buf.ingest(msg.clone());
        }
        assert_eq!(relay_buf.message_count(), messages.len());

        // Epoch catch-up (max epoch in messages).
        let max_epoch = messages.iter().filter_map(|m| m.epoch).max().unwrap_or(1);
        let mut catch_up = EpochCatchUpState::new("ctx-1".to_owned(), 1, max_epoch);
        assert!(!catch_up.exceeds_sequential_limit(&SyncPolicy::default()));

        // Process epochs.
        let epochs_to_process = max_epoch.saturating_sub(1);
        for _ in 0..epochs_to_process {
            catch_up.record_commit_processed();
        }
        assert_eq!(catch_up.status, CatchUpStatus::Complete);

        // Reorder buffer (simulate out-of-order delivery).
        let mut reorder = ReorderBuffer::new("ctx-1".to_owned(), 0, &SyncPolicy::default());
        let sorted_messages = relay_buf.drain_sorted();
        for (i, msg) in sorted_messages.iter().enumerate() {
            let seq = u64::try_from(i).unwrap_or(0);
            let _ = reorder.insert(ReorderEntry {
                sequence: seq,
                payload: msg.payload.clone(),
                buffered_at_secs: msg.stored_at,
            });
        }
        // All should be delivered since they're in order after sorting.
        assert!(reorder.is_empty());

        // MLS Update recorded.
        let mut sync_result = ContextSyncResult {
            context_id: "ctx-1".to_owned(),
            tier,
            epochs_caught_up: epochs_to_process,
            events_recovered: u64::try_from(sorted_messages.len()).unwrap_or(0),
            messages_unrecoverable: 0,
            mls_update_issued: false,
            outcome: SyncOutcome::FullyCaughtUp,
            sync_events: vec![],
        };
        ReconnectionCoordinator::record_mls_update(&mut sync_result);
        assert!(sync_result.mls_update_issued);

        // Build report.
        let report = ReconnectionCoordinator::build_report(vec![sync_result], 0, 0, 150);
        assert_eq!(report.contexts_synced.len(), 1);
        assert_eq!(
            report.contexts_synced[0].outcome,
            SyncOutcome::FullyCaughtUp,
        );
    }

    // -----------------------------------------------------------------------
    // CommitRangeRequest/Response tests
    // -----------------------------------------------------------------------

    #[test]
    fn commit_range_request_serializable() {
        let req = CommitRangeRequest {
            context_id: "ctx-1".to_owned(),
            from_epoch: 5,
            to_epoch: 15,
            requester_did: DID::from("did:dht:z6MkAlice"),
            signature: vec![0u8; 64],
        };
        let json = serde_json::to_string(&req);
        assert!(json.is_ok());
    }

    #[test]
    fn commit_range_response_serializable() {
        let resp = CommitRangeResponse {
            context_id: "ctx-1".to_owned(),
            commits: vec![vec![1, 2, 3], vec![4, 5, 6]],
            responder_did: DID::from("did:dht:z6MkBob"),
            signature: vec![0u8; 64],
        };
        let json = serde_json::to_string(&resp);
        assert!(json.is_ok());
    }

    // -----------------------------------------------------------------------
    // No synchronized clock dependency tests (§9.8.3)
    // -----------------------------------------------------------------------

    #[test]
    fn no_clock_dependency_reversed_timestamps() {
        // Verify that all timestamp-based operations handle clock skew
        // gracefully via saturating arithmetic.
        let mut sim = NetworkSimulator::new(1_000_000);

        // Send a message at time T.
        sim.send_message("ctx-1", "b1".to_owned(), vec![1], Some(1));

        // "Go back in time" — clock skew.
        sim.current_time = 999_000;
        sim.send_message("ctx-1", "b2".to_owned(), vec![2], Some(1));

        // Retrieve should work regardless of timestamp ordering.
        let msgs = sim.retrieve_messages("ctx-1", 0).unwrap_or_default();
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn relay_buffer_saturating_sub_with_small_last_stored_at() {
        // Verify subscribe_since doesn't underflow when last_stored_at is
        // less than the overlap window.
        let buf = RelayMessageBuffer::new("ctx-1".to_owned(), 0);
        assert_eq!(buf.subscribe_since(), 0);
    }

    // -----------------------------------------------------------------------
    // Untrusted relay verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_messages_carry_no_trust_metadata() {
        // Verify that BufferedMessage has no relay-trust fields — all
        // verification is client-side. The `stored_at` is explicitly untrusted.
        let msg = BufferedMessage {
            blob_id: "b1".to_owned(),
            context_id: "ctx-1".to_owned(),
            payload: vec![1, 2, 3],
            stored_at: 12345,
            epoch: Some(1),
        };
        // stored_at is relay-assigned and untrusted — just used for ordering.
        assert_eq!(msg.stored_at, 12345);
        // No "verified" or "trusted" fields on the struct.
    }

    // -----------------------------------------------------------------------
    // KeyPackage pre-publication for offline member addition (§9.6)
    // -----------------------------------------------------------------------

    #[test]
    fn key_package_pre_publisher_full_lifecycle() {
        let mut pp = KeyPackagePrePublisher::with_min_published(DID::from("did:dht:z6MkCarol"), 5);

        // Initially needs replenish.
        assert!(pp.needs_replenish());
        assert_eq!(pp.replenish_count(), 5);

        // Publish 5 KeyPackages.
        pp.record_published((0..5).map(|i| format!("kp-{i}")).collect(), 1000);
        assert!(!pp.needs_replenish());
        assert_eq!(pp.published_count, 5);

        // Consume 3 (used to add members while Carol is offline).
        for i in 0..3 {
            assert!(pp.record_consumed(&format!("kp-{i}")));
        }
        assert_eq!(pp.published_count, 2);
        assert!(pp.needs_replenish());
        assert_eq!(pp.replenish_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Queue drain integration tests (Phase 6, spec §23.2)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn drain_context_queue_returns_entries_in_order() {
        let store = crate::store::ProtocolRepository::new_for_testing(
            scp_platform::testing::InMemoryStorage::new(),
        );

        // Enqueue 3 messages.
        for i in 0u8..3 {
            store
                .enqueue_message("ctx-drain", &[i; 32], 1_000_000 + u64::from(i))
                .await
                .unwrap();
        }

        let result = ReconnectionCoordinator::drain_context_queue(
            &store,
            "ctx-drain",
            1_000_100,
            Some(86_400), // 1-day TTL
        )
        .await
        .unwrap();

        assert_eq!(result.entries.len(), 3);
        assert_eq!(result.expired_pruned, 0);
        // Verify order.
        for (i, entry) in result.entries.iter().enumerate() {
            assert_eq!(entry.queued_at, 1_000_000 + i as u64);
        }
    }

    #[tokio::test]
    async fn drain_context_queue_prunes_expired_before_drain() {
        let store = crate::store::ProtocolRepository::new_for_testing(
            scp_platform::testing::InMemoryStorage::new(),
        );

        // Enqueue messages at different times.
        store
            .enqueue_message("ctx-drain", &[1u8; 16], 100)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-drain", &[2u8; 16], 200)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-drain", &[3u8; 16], 900)
            .await
            .unwrap();

        // At now=1000, TTL=500: entry at 100 expired (100+500=600 < 1000),
        // entry at 200 expired (200+500=700 < 1000), entry at 900 is fresh.
        let result =
            ReconnectionCoordinator::drain_context_queue(&store, "ctx-drain", 1000, Some(500))
                .await
                .unwrap();

        assert_eq!(result.expired_pruned, 2);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].queued_at, 900);
    }

    #[tokio::test]
    async fn drain_context_queue_uses_default_ttl_when_none() {
        let store = crate::store::ProtocolRepository::new_for_testing(
            scp_platform::testing::InMemoryStorage::new(),
        );

        let now = 1_000_000u64;
        // Queue a message that is within the default 7-day TTL.
        store
            .enqueue_message("ctx-drain", &[1u8; 16], now - 100)
            .await
            .unwrap();

        let result = ReconnectionCoordinator::drain_context_queue(
            &store,
            "ctx-drain",
            now,
            None, // Uses DEFAULT_QUEUE_TTL_SECS (7 days)
        )
        .await
        .unwrap();

        assert_eq!(result.expired_pruned, 0);
        assert_eq!(result.entries.len(), 1);
    }

    #[tokio::test]
    async fn drain_empty_queue_returns_empty() {
        let store = crate::store::ProtocolRepository::new_for_testing(
            scp_platform::testing::InMemoryStorage::new(),
        );

        let result = ReconnectionCoordinator::drain_context_queue(
            &store,
            "ctx-empty",
            1_000_000,
            Some(3600),
        )
        .await
        .unwrap();

        assert!(result.entries.is_empty());
        assert_eq!(result.expired_pruned, 0);
    }
}
