//! DID-record single-slot / slot-exclusivity bookkeeping for a validating
//! SCP-native relay (§3.10.2 "Slot-exclusivity", §9.10.12, ADR-004
//! "DID-Record Slot-Exclusivity").
//!
//! [`classify_did_record_frame`](crate::relay::did_record_validation::classify_did_record_frame)
//! decides, cheaply and statelessly, whether a PUBLISH blob is a valid DID-record
//! frame for its `routing_id`. This module holds the **stateful** other half:
//! which DID-domain `routing_id`s have a claimed slot, at what BEP44 `seq`, and
//! the atomic single-slot write rule + eviction that make such a `routing_id`
//! **slot-exclusive**:
//!
//! - **(single highest-seq slot)** a valid frame replaces the slot only on a
//!   strictly-higher `seq`; an equal-`seq` byte-identical republish is an
//!   idempotent TTL refresh; a lower or equal-but-different frame is rejected.
//! - **(a)** once a slot exists, any non-superseding PUBLISH at that
//!   `routing_id` — a non-frame blob, a wrong-binding frame, an invalid
//!   signature, or a stale `seq` — is rejected;
//! - **(b)** establishing the first slot **evicts** every pre-existing opaque
//!   blob at that `routing_id` (closing the pre-seed gap);
//! - **(c)** QUERY at a claimed `routing_id` returns **only** the slot.
//!
//! # Backend-agnostic
//!
//! The slot index is kept here, over the relay's shared blob store, and is
//! enforced purely through the existing [`BlobStorage`](super::storage::BlobStorage)
//! primitives (`store` / `query` / `get` / `delete`). It therefore applies
//! uniformly to **every** configured backend (in-memory, `SQLite`, redb, `S3`,
//! `Postgres`) with no per-backend code and no dev/test-only stand-in.
//!
//! # Reversion (spec §3.10.2)
//!
//! The index is in-memory. If a slot's blob TTL expires (owner offline past the
//! 6-day republish cycle) or the relay restarts, the `routing_id` reverts to an
//! unclaimed opaque-blob address and the pre-seed window reopens. This is not a
//! suppression bypass: the genuine record is already absent, any attacker blob
//! still fails the resolver's DID-derived-key BEP44 verification, resolution
//! falls through to the DHT, and the owner's next republish re-establishes the
//! slot and re-fires eviction. Expiry is reconciled lazily: a slot whose blob is
//! gone is dropped from the index the next time it is consulted.
//!
//! # Not a trust dependency
//!
//! Slot-exclusivity is an **availability / anti-suppression** measure. The
//! client re-verifies every record independently (RELAYRES-002), so a relay that
//! does not run this bookkeeping degrades availability only, never integrity.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::storage::{BlobStorage, BlobStorageBackend, StorageError, StoredBlob};

/// A claimed DID-record slot: the single blob currently occupying a DID-domain
/// `routing_id`, and its BEP44 sequence number (for supersession).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DidSlot {
    /// `SHA-256` of the slot blob (its `blob_id`). Doubles as the byte-identity
    /// discriminant: an equal-`seq` republish is byte-identical iff it hashes to
    /// this same `blob_id`.
    blob_id: [u8; 32],
    /// The slot's BEP44 sequence number (§3.10.7).
    seq: u64,
}

/// What a successful validated-frame PUBLISH did to the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotPublishOutcome {
    /// First binding-valid frame at a previously-unclaimed (or reverted)
    /// `routing_id`: slot established, pre-existing opaque blobs evicted (rule
    /// (b)).
    Established,
    /// A strictly-higher-`seq` valid frame replaced the slot.
    Superseded,
    /// An equal-`seq`, byte-identical republish: idempotent TTL refresh (no
    /// supersession, no error) — the slot's storage lifetime is renewed.
    IdempotentRefresh,
}

/// Why a validated-frame PUBLISH was rejected by the single-slot rule, or an
/// underlying storage failure.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SlotPublishError {
    /// The frame's `seq` did not supersede the stored slot's `seq` and was not a
    /// byte-identical equal-`seq` refresh (§3.10.2 step 4): either `seq <
    /// stored_seq`, or `seq == stored_seq` with different bytes (a same-`seq`
    /// conflict, which §3.10.4 forbids). Rejected — the slot is unchanged.
    #[error(
        "DID-record frame does not supersede the stored slot (stored seq {stored_seq}, got {got_seq})"
    )]
    NonSuperseding {
        /// The BEP44 `seq` of the record currently in the slot.
        stored_seq: u64,
        /// The BEP44 `seq` of the rejected frame.
        got_seq: u64,
    },

    /// An underlying blob-store operation failed.
    #[error("slot storage error: {0}")]
    Storage(#[from] StorageError),
}

/// The validating relay's DID-record slot index over its shared blob store.
///
/// Cheap to [`Clone`] (shares one `Arc<RwLock<..>>`), so it is threaded through
/// the relay like the subscription registry and rate limiters. All mutation is
/// serialized through the inner lock; the common read paths ([`is_claimed`],
/// [`slot_blob`]) take only a read lock and release it before touching storage.
///
/// [`is_claimed`]: DidSlotRegistry::is_claimed
/// [`slot_blob`]: DidSlotRegistry::slot_blob
#[derive(Clone, Default)]
pub struct DidSlotRegistry {
    slots: Arc<RwLock<HashMap<[u8; 32], DidSlot>>>,
}

impl std::fmt::Debug for DidSlotRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidSlotRegistry").finish_non_exhaustive()
    }
}

impl DidSlotRegistry {
    /// Creates an empty slot index (no `routing_id` claimed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a **validated** DID-record frame to its `routing_id`'s slot.
    ///
    /// The caller MUST have already established (via
    /// [`classify_did_record_frame`](crate::relay::did_record_validation::classify_did_record_frame))
    /// that `blob` decodes as a `DidRecordV1` frame whose `DID→routing_id` binding
    /// holds and whose BEP44 signature verifies, yielding `seq`. This method
    /// enforces the single-slot rule and slot-exclusivity eviction atomically:
    ///
    /// - no live slot (or a slot whose blob has expired) → **establish**,
    ///   evicting any pre-existing opaque blobs (rule (b));
    /// - `seq >` stored → **supersede** (replace the slot, evict strays);
    /// - `seq ==` stored and byte-identical (same `blob_id`) → **idempotent TTL
    ///   refresh**;
    /// - otherwise → [`SlotPublishError::NonSuperseding`].
    ///
    /// On success the slot is left as the sole blob at `routing_id`.
    ///
    /// # Errors
    ///
    /// [`SlotPublishError::NonSuperseding`] if the frame does not supersede the
    /// stored slot; [`SlotPublishError::Storage`] on a blob-store failure.
    // The `slots` write guard is deliberately held across the storage ops below:
    // the read-modify-(evict+store)-write of a slot MUST be atomic w.r.t. other
    // frame publishes to the same routing_id, so it cannot be tightened.
    #[allow(clippy::too_many_arguments, clippy::significant_drop_tightening)]
    pub async fn publish_frame(
        &self,
        storage: &BlobStorageBackend,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
        seq: u64,
    ) -> Result<(StoredBlob, SlotPublishOutcome), SlotPublishError> {
        // Held across the storage ops below so concurrent frame publishes to the
        // same routing_id serialize (DID publishes are rare + rate-limited, so a
        // single index lock is ample; opaque publishes never take this lock).
        let mut slots = self.slots.write().await;

        // Lazily reconcile a slot whose blob has TTL-expired: treat as unclaimed
        // so a fresh frame re-establishes (and re-fires eviction).
        let live_slot = match slots.get(&routing_id).copied() {
            Some(slot) => {
                if storage.get(&slot.blob_id).await?.is_some() {
                    Some(slot)
                } else {
                    slots.remove(&routing_id);
                    None
                }
            }
            None => None,
        };

        match live_slot {
            None => {
                let stored = Self::store_as_sole_slot(
                    storage,
                    routing_id,
                    blob_id,
                    recipient_hint,
                    blob_ttl,
                    blob,
                )
                .await?;
                slots.insert(routing_id, DidSlot { blob_id, seq });
                Ok((stored, SlotPublishOutcome::Established))
            }
            Some(slot) if seq > slot.seq => {
                let stored = Self::store_as_sole_slot(
                    storage,
                    routing_id,
                    blob_id,
                    recipient_hint,
                    blob_ttl,
                    blob,
                )
                .await?;
                slots.insert(routing_id, DidSlot { blob_id, seq });
                Ok((stored, SlotPublishOutcome::Superseded))
            }
            Some(slot) if seq == slot.seq && blob_id == slot.blob_id => {
                // Byte-identical equal-seq republish: refresh storage lifetime
                // (re-store overwrites stored_at + blob_ttl) and re-assert
                // sole-slot. The slot entry (blob_id, seq) is unchanged.
                let stored = Self::store_as_sole_slot(
                    storage,
                    routing_id,
                    blob_id,
                    recipient_hint,
                    blob_ttl,
                    blob,
                )
                .await?;
                Ok((stored, SlotPublishOutcome::IdempotentRefresh))
            }
            Some(slot) => Err(SlotPublishError::NonSuperseding {
                stored_seq: slot.seq,
                got_seq: seq,
            }),
        }
    }

    /// Returns whether `routing_id` currently has a claimed, live DID slot.
    ///
    /// Used to enforce slot-exclusivity rule (a): a non-frame / wrong-binding /
    /// invalid-signature / non-superseding PUBLISH at a claimed `routing_id` is
    /// rejected. Reconciles a TTL-expired slot lazily (returns `false` and drops
    /// the stale index entry). The fast path (unclaimed `routing_id`) takes only
    /// a read lock and touches no storage, so it does not serialize ordinary
    /// traffic.
    pub async fn is_claimed(&self, storage: &BlobStorageBackend, routing_id: &[u8; 32]) -> bool {
        let slot = { self.slots.read().await.get(routing_id).copied() };
        let Some(slot) = slot else {
            return false;
        };
        if let Ok(Some(_)) = storage.get(&slot.blob_id).await {
            true
        } else {
            self.revert_if_stale(routing_id, slot.blob_id).await;
            false
        }
    }

    /// Returns the single slot blob at `routing_id`, or `None` if the
    /// `routing_id` is unclaimed or its slot has expired.
    ///
    /// Used to enforce slot-exclusivity rule (c): QUERY at a claimed
    /// `routing_id` returns only this blob, regardless of `limit`, and never any
    /// co-located opaque junk. Reconciles a TTL-expired slot lazily. The fast
    /// path (unclaimed `routing_id`) takes only a read lock and touches no
    /// storage.
    pub async fn slot_blob(
        &self,
        storage: &BlobStorageBackend,
        routing_id: &[u8; 32],
    ) -> Option<StoredBlob> {
        let slot = { self.slots.read().await.get(routing_id).copied() };
        let slot = slot?;
        if let Ok(Some(stored)) = storage.get(&slot.blob_id).await {
            Some(stored)
        } else {
            self.revert_if_stale(routing_id, slot.blob_id).await;
            None
        }
    }

    /// Drops a `routing_id` from the index iff it still points at `blob_id`
    /// (i.e. no concurrent establish replaced it since the caller observed it).
    async fn revert_if_stale(&self, routing_id: &[u8; 32], blob_id: [u8; 32]) {
        let mut slots = self.slots.write().await;
        if slots.get(routing_id).map(|s| s.blob_id) == Some(blob_id) {
            slots.remove(routing_id);
        }
    }

    /// Stores `blob` as the **sole** blob at `routing_id`: writes it, then evicts
    /// every other blob co-located there. Used for establish (rule (b) eviction),
    /// supersede, and idempotent refresh, so a claimed `routing_id` physically
    /// holds exactly one blob after any DID write.
    ///
    /// (A benign, QUERY-invisible race exists: an opaque PUBLISH that read
    /// "unclaimed" and stores *after* this eviction snapshot lingers in storage
    /// until TTL or the next DID write — but QUERY is registry-gated (rule (c)),
    /// so it is never returned.)
    async fn store_as_sole_slot(
        storage: &BlobStorageBackend,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored = storage
            .store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
            .await?;
        // Evict every other blob at this routing_id. `u32::MAX` enumerates all
        // co-located blobs; DID routing_ids hold at most a handful (only
        // pre-seed junk), so the full scan is cheap.
        let existing = storage.query(&routing_id, None, u32::MAX).await?;
        for other in existing {
            if other.blob_id != blob_id {
                storage.delete(&other.blob_id).await?;
            }
        }
        Ok(stored)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn blob_id_of(blob: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(blob));
        out
    }

    async fn store_opaque(storage: &BlobStorageBackend, routing_id: [u8; 32], blob: &[u8]) {
        storage
            .store(routing_id, blob_id_of(blob), None, 3600, blob.to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn establish_evicts_preexisting_opaque_blobs() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let rid = [0x11; 32];

        // Pre-seed opaque junk BEFORE any slot exists.
        store_opaque(&storage, rid, b"junk-1").await;
        store_opaque(&storage, rid, b"junk-2").await;
        assert_eq!(storage.query(&rid, None, 100).await.unwrap().len(), 2);

        let frame = b"the-real-did-record".to_vec();
        let bid = blob_id_of(&frame);
        let (_stored, outcome) = reg
            .publish_frame(&storage, rid, bid, None, 3600, frame.clone(), 5)
            .await
            .unwrap();
        assert_eq!(outcome, SlotPublishOutcome::Established);

        // Only the slot remains in storage; the pre-seed junk is evicted (b).
        let remaining = storage.query(&rid, None, 100).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].blob_id, bid);

        // slot_blob returns exactly the slot (c).
        assert_eq!(reg.slot_blob(&storage, &rid).await.unwrap().blob_id, bid);
        assert!(reg.is_claimed(&storage, &rid).await);
    }

    #[tokio::test]
    async fn higher_seq_supersedes_lower_seq_rejected() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let rid = [0x22; 32];

        let v5 = b"seq5".to_vec();
        reg.publish_frame(&storage, rid, blob_id_of(&v5), None, 3600, v5, 5)
            .await
            .unwrap();

        // seq 4 <= 5 → rejected, slot unchanged.
        let v4 = b"seq4".to_vec();
        let err = reg
            .publish_frame(&storage, rid, blob_id_of(&v4), None, 3600, v4, 4)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SlotPublishError::NonSuperseding {
                stored_seq: 5,
                got_seq: 4
            }
        ));

        // seq 9 > 5 → supersede.
        let v9 = b"seq9".to_vec();
        let bid9 = blob_id_of(&v9);
        let (_s, outcome) = reg
            .publish_frame(&storage, rid, bid9, None, 3600, v9, 9)
            .await
            .unwrap();
        assert_eq!(outcome, SlotPublishOutcome::Superseded);
        assert_eq!(reg.slot_blob(&storage, &rid).await.unwrap().blob_id, bid9);
    }

    #[tokio::test]
    async fn equal_seq_byte_identical_is_idempotent_refresh() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let rid = [0x33; 32];

        let v = b"seq7-record".to_vec();
        let bid = blob_id_of(&v);
        reg.publish_frame(&storage, rid, bid, None, 3600, v.clone(), 7)
            .await
            .unwrap();

        // Same seq, same bytes → idempotent refresh (no error).
        let (_s, outcome) = reg
            .publish_frame(&storage, rid, bid, None, 3600, v, 7)
            .await
            .unwrap();
        assert_eq!(outcome, SlotPublishOutcome::IdempotentRefresh);
    }

    #[tokio::test]
    async fn equal_seq_different_bytes_is_rejected() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let rid = [0x44; 32];

        let v = b"seq7-a".to_vec();
        reg.publish_frame(&storage, rid, blob_id_of(&v), None, 3600, v, 7)
            .await
            .unwrap();

        // Same seq, DIFFERENT bytes → §3.10.4 conflict → rejected.
        let v2 = b"seq7-b-different".to_vec();
        let err = reg
            .publish_frame(&storage, rid, blob_id_of(&v2), None, 3600, v2, 7)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SlotPublishError::NonSuperseding {
                stored_seq: 7,
                got_seq: 7
            }
        ));
    }

    #[tokio::test]
    async fn unclaimed_routing_id_is_not_claimed() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        assert!(!reg.is_claimed(&storage, &[0x55; 32]).await);
        assert!(reg.slot_blob(&storage, &[0x55; 32]).await.is_none());
    }

    #[tokio::test]
    async fn slot_reverts_when_underlying_blob_expires() {
        use super::super::storage::{ClockFn, InMemoryBlobStorage};
        use std::sync::atomic::{AtomicU64, Ordering};

        let clock_value = Arc::new(AtomicU64::new(1_000_000));
        let cv = clock_value.clone();
        let clock: ClockFn = Arc::new(move || cv.load(Ordering::Relaxed));
        let storage = BlobStorageBackend::from(InMemoryBlobStorage::with_clock(clock));
        let reg = DidSlotRegistry::new();
        let rid = [0x66; 32];

        let v = b"short-lived".to_vec();
        reg.publish_frame(&storage, rid, blob_id_of(&v), None, 10, v, 1)
            .await
            .unwrap();
        assert!(reg.is_claimed(&storage, &rid).await);

        // Advance past the slot blob's TTL: get() now returns None, so the slot
        // reverts to unclaimed (pre-seed window reopens, §3.10.2).
        clock_value.store(1_000_011, Ordering::Relaxed);
        assert!(!reg.is_claimed(&storage, &rid).await);
        assert!(reg.slot_blob(&storage, &rid).await.is_none());

        // A fresh publish re-establishes the slot (and would re-fire eviction).
        let v2 = b"republished".to_vec();
        let (_s, outcome) = reg
            .publish_frame(&storage, rid, blob_id_of(&v2), None, 3600, v2, 1)
            .await
            .unwrap();
        assert_eq!(outcome, SlotPublishOutcome::Established);
    }
}
