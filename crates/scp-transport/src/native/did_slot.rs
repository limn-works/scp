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
//! suppression bypass: the genuine record is already absent (owner offline, not
//! attacker action). The rollback defense here is **not** signature verification
//! — a replayed *old genuine* record is owner-signed and passes the resolver's
//! DID-derived-key BEP44 verify — it is the resolver's **client-side
//! seq-monotonicity** freshness check: a record is accepted only when its BEP44
//! `seq >= last_known_seq`, and the highest valid `seq` wins across both the
//! relay and the DHT (§3.10.7; spec §9.6.1 "the BEP44 sequence number is the
//! sole authority for document freshness"). So during a reversion window a
//! stale attacker-replayed record cannot roll a resolver back; resolution also
//! falls through to the DHT, and the owner's next republish re-establishes the
//! slot and re-fires eviction.
//!
//! Reversion is reconciled two ways. **Lazily** — a slot whose blob is gone is
//! dropped from the index the next time it is consulted
//! ([`is_claimed`](DidSlotRegistry::is_claimed) /
//! [`slot_blob`](DidSlotRegistry::slot_blob)). **Actively** — a periodic
//! [`sweep_expired`](DidSlotRegistry::sweep_expired) drops entries whose blob
//! has TTL-expired even if the `routing_id` is never consulted again, so a
//! slot claimed once and then abandoned cannot pin its index entry forever.
//!
//! # Cold-index reconciliation (never roll a genuine record back)
//!
//! The index can be **cold** while storage still holds a genuine record — after
//! a durable-backend restart (index empty, the genuine blob persisted), or when
//! a store-sharing transport deposited a frame. Establishing a slot at a cold
//! `routing_id` therefore reconciles against storage *before* evicting: it
//! adopts the highest-`seq` binding-valid frame already present, so a replayed
//! lower-`seq` frame can never delete a higher-`seq` genuine record. This
//! preserves the invariant that slot-exclusivity affects **availability only,
//! never integrity**.
//!
//! # Not a trust dependency
//!
//! Slot-exclusivity is an **availability / anti-suppression** measure. The
//! client re-verifies every record independently (RELAYRES-002), so a relay that
//! does not run this bookkeeping degrades availability only, never integrity.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::storage::{BlobStorage, StorageError, StoredBlob};
use crate::relay::did_record_validation::{DidRecordClass, classify_did_record_frame};

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
    /// [`classify_did_record_frame`]) that `blob` decodes as a `DidRecordV1`
    /// frame whose `DID→routing_id` binding holds and whose BEP44 signature
    /// verifies, yielding `seq`. This method enforces the single-slot rule and
    /// slot-exclusivity eviction atomically:
    ///
    /// - no live slot (or a slot whose blob has expired) → **establish**, but
    ///   first *reconcile against storage*: if the (possibly cold) store already
    ///   holds a binding-valid frame with a higher `seq` — or an equal `seq`
    ///   with different bytes — that genuine frame is **adopted** as the slot and
    ///   the lower/conflicting newcomer is rejected, so a replay can never delete
    ///   a fresher genuine record (integrity is never sacrificed). Otherwise the
    ///   newcomer establishes the slot, evicting pre-existing opaque blobs (rule
    ///   (b));
    /// - `seq >` stored → **supersede** (replace the slot, evict strays);
    /// - `seq ==` stored and byte-identical (same `blob_id`) → **idempotent TTL
    ///   refresh**;
    /// - otherwise → [`SlotPublishError::NonSuperseding`].
    ///
    /// On success the slot is left as the sole blob at `routing_id`. The slot is
    /// claimed in the index **before** the (best-effort) eviction of co-located
    /// strays, so a durable-backend delete failure can never leave the frame
    /// committed to storage with the `routing_id` still unclaimed.
    ///
    /// Works over any [`BlobStorage`] backend, so the WebSocket relay (over its
    /// `BlobStorageBackend`) and a co-deployed QUIC/UDP listener (over the same
    /// shared store) drive the *same* slot logic — never a fork.
    ///
    /// # Errors
    ///
    /// [`SlotPublishError::NonSuperseding`] if the frame does not supersede the
    /// stored slot (or a higher/equal genuine frame is adopted from storage
    /// instead); [`SlotPublishError::Storage`] on a blob-store failure.
    // The `slots` write guard is deliberately held across the storage ops below:
    // the read-modify-(evict+store)-write of a slot MUST be atomic w.r.t. other
    // frame publishes to the same routing_id, so it cannot be tightened.
    #[allow(clippy::too_many_arguments, clippy::significant_drop_tightening)]
    pub async fn publish_frame<S: BlobStorage + ?Sized>(
        &self,
        storage: &S,
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
                // Cold index (fresh routing_id, TTL revert, relay/durable-backend
                // restart, or a store-sharing transport). Reconcile against
                // storage BEFORE evicting so a replayed lower-seq frame cannot
                // destroy a genuine higher-seq record that is present in storage
                // but absent from the cold index (rollback defense — "availability
                // only, never integrity"). This is the one-time O(N) scan a first
                // establish after a pre-seed flood incurs; N is bounded (a DID
                // routing_id holds only pre-seed junk) and the whole path sits
                // behind the per-IP PUBLISH rate limit.
                let existing = storage.query(&routing_id, None, u32::MAX).await?;
                if let Some((best_id, best_seq)) = Self::highest_valid_frame(&routing_id, &existing)
                    && (best_seq > seq || (best_seq == seq && best_id != blob_id))
                {
                    // A genuine stored frame strictly supersedes the newcomer, or
                    // ties on seq with different bytes (a §3.10.4 conflict): adopt
                    // it as the slot, evict every other co-located blob, and REJECT
                    // the newcomer. Never let a lower-or-equal-seq frame delete a
                    // higher/equal genuine record.
                    slots.insert(
                        routing_id,
                        DidSlot {
                            blob_id: best_id,
                            seq: best_seq,
                        },
                    );
                    Self::evict_others(storage, &routing_id, best_id).await;
                    return Err(SlotPublishError::NonSuperseding {
                        stored_seq: best_seq,
                        got_seq: seq,
                    });
                }

                // The newcomer is the highest-seq valid frame here (or ties
                // byte-identically, or only opaque junk is present): establish it.
                // Index-first — claim the slot BEFORE the best-effort eviction.
                let stored = storage
                    .store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
                    .await?;
                slots.insert(routing_id, DidSlot { blob_id, seq });
                Self::evict_others(storage, &routing_id, blob_id).await;
                Ok((stored, SlotPublishOutcome::Established))
            }
            Some(slot) if seq > slot.seq => {
                let stored = storage
                    .store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
                    .await?;
                slots.insert(routing_id, DidSlot { blob_id, seq });
                Self::evict_others(storage, &routing_id, blob_id).await;
                Ok((stored, SlotPublishOutcome::Superseded))
            }
            Some(slot) if seq == slot.seq && blob_id == slot.blob_id => {
                // Byte-identical equal-seq republish: refresh storage lifetime
                // (re-store overwrites stored_at + blob_ttl) and re-assert
                // sole-slot. The slot entry (blob_id, seq) is unchanged.
                let stored = storage
                    .store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
                    .await?;
                Self::evict_others(storage, &routing_id, blob_id).await;
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
    pub async fn is_claimed<S: BlobStorage + ?Sized>(
        &self,
        storage: &S,
        routing_id: &[u8; 32],
    ) -> bool {
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
    pub async fn slot_blob<S: BlobStorage + ?Sized>(
        &self,
        storage: &S,
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

    /// Sweeps the whole slot index against `storage`, dropping every entry whose
    /// slot blob is no longer present (TTL-expired and purged). This is the
    /// **active** backstop to the lazy on-consult reversion
    /// ([`revert_if_stale`](Self::revert_if_stale)): a `routing_id` claimed once
    /// and then never re-queried would otherwise keep its ~72-byte index entry
    /// forever after its blob expires, letting an attacker who mints unlimited
    /// keypairs pin unbounded permanent slots. The relay's TTL background task
    /// calls this periodically; the lazy path stays the fast path for live
    /// traffic.
    ///
    /// Snapshots the `(routing_id, blob_id)` pairs under a read lock, probes
    /// storage without holding the lock, then drops only the entries confirmed
    /// absent — and only if the index still points at the same (now-gone) blob,
    /// so a concurrent re-establish is never clobbered.
    pub async fn sweep_expired<S: BlobStorage + ?Sized>(&self, storage: &S) {
        let entries: Vec<([u8; 32], [u8; 32])> = {
            let slots = self.slots.read().await;
            slots
                .iter()
                .map(|(rid, slot)| (*rid, slot.blob_id))
                .collect()
        };
        if entries.is_empty() {
            return;
        }

        let mut stale: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for (rid, blob_id) in entries {
            match storage.get(&blob_id).await {
                Ok(Some(_)) => {}
                Ok(None) => stale.push((rid, blob_id)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        routing_id = hex::encode(rid),
                        "DID slot sweep: storage probe failed; leaving entry for a later sweep",
                    );
                }
            }
        }
        if stale.is_empty() {
            return;
        }

        let mut slots = self.slots.write().await;
        for (rid, blob_id) in stale {
            if slots.get(&rid).map(|s| s.blob_id) == Some(blob_id) {
                slots.remove(&rid);
            }
        }
    }

    /// Returns the `(blob_id, seq)` of the highest-`seq` binding-and-signature
    /// valid DID-record frame among `blobs` (all co-located at `routing_id`), or
    /// `None` if none is a valid frame. Used to reconcile a cold index against
    /// storage before establishing a slot, so an adopted genuine record is
    /// always the freshest one present.
    fn highest_valid_frame(routing_id: &[u8; 32], blobs: &[StoredBlob]) -> Option<([u8; 32], u64)> {
        let mut best: Option<([u8; 32], u64)> = None;
        for b in blobs {
            if let DidRecordClass::Valid { seq } = classify_did_record_frame(routing_id, &b.blob)
                && best.is_none_or(|(_, best_seq)| seq > best_seq)
            {
                best = Some((b.blob_id, seq));
            }
        }
        best
    }

    /// Best-effort eviction of every co-located blob at `routing_id` except
    /// `keep`, leaving `keep` as the sole blob there. Called only *after* the
    /// slot is authoritative in the index, so co-located strays are already
    /// QUERY-invisible (rule (c)); a durable-backend `query`/`delete` failure is
    /// therefore logged and **not** propagated — it must never fail an
    /// already-committed slot write, and the next DID write (or the sweep)
    /// re-attempts eviction. `u32::MAX` enumerates all co-located blobs; a DID
    /// `routing_id` holds at most a handful (only pre-seed junk), so the scan is
    /// cheap.
    ///
    /// (A benign, QUERY-invisible race exists: an opaque PUBLISH that read
    /// "unclaimed" and stores *after* this eviction snapshot lingers in storage
    /// until TTL or the next DID write — but QUERY is registry-gated (rule (c)),
    /// so it is never returned.)
    async fn evict_others<S: BlobStorage + ?Sized>(
        storage: &S,
        routing_id: &[u8; 32],
        keep: [u8; 32],
    ) {
        let existing = match storage.query(routing_id, None, u32::MAX).await {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    routing_id = hex::encode(routing_id),
                    "DID slot eviction scan failed; co-located strays stay QUERY-invisible",
                );
                return;
            }
        };
        for other in existing {
            if other.blob_id != keep
                && let Err(e) = storage.delete(&other.blob_id).await
            {
                tracing::warn!(
                    error = %e,
                    routing_id = hex::encode(routing_id),
                    "DID slot best-effort eviction of a co-located blob failed",
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::storage::BlobStorageBackend;
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use scp_dht::bep44_signable;
    use scp_identity::{did_from_ed25519_public_key, did_routing_id};
    use scp_protocol::envelope::did_record::DidRecordV1;
    use sha2::{Digest, Sha256};

    fn blob_id_of(blob: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(blob));
        out
    }

    /// Builds a genuine, self-consistent DID-record frame at the signing key's
    /// own DID-domain `routing_id` (the frame's embedded key signs the BEP44
    /// payload), returning `(routing_id, blob_id, frame_bytes)`. Used by the
    /// cold-index reconciliation tests to plant *binding-valid* frames in
    /// storage that `classify_did_record_frame` accepts.
    fn genuine_frame(seed: u8, seq: u64, value: &[u8]) -> ([u8; 32], [u8; 32], Vec<u8>) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk: VerifyingKey = sk.verifying_key();
        let did = did_from_ed25519_public_key(&vk.to_bytes());
        let rid = did_routing_id(&did);
        let signature: ed25519_dalek::Signature = sk.sign(&bep44_signable(value, seq));
        let bytes = DidRecordV1::try_new(vk.to_bytes(), seq, signature.to_bytes(), value.to_vec())
            .unwrap()
            .encode();
        let bid = blob_id_of(&bytes);
        (rid, bid, bytes)
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

    /// Fix 2 (rollback defense): a cold index over a durable store that already
    /// holds a genuine higher-seq frame must NOT let a replayed lower-seq frame
    /// evict it. The genuine seq-9 record survives, is adopted as the slot, and
    /// is what QUERY returns; the replayed seq-3 frame is rejected and never
    /// stored.
    #[tokio::test]
    async fn cold_index_establish_adopts_higher_seq_genuine_frame() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();

        // Genuine seq-9 record pre-placed in storage; the registry index is COLD
        // (nothing published through it yet — models a durable-backend restart or
        // a store-sharing transport that deposited the frame).
        let (rid, bid9, frame9) = genuine_frame(9, 9, b"did-doc-v9");
        let (rid3, bid3, frame3) = genuine_frame(9, 3, b"did-doc-v3");
        assert_eq!(rid, rid3, "same key ⇒ same DID-domain routing_id");
        assert_ne!(bid9, bid3);
        storage.store(rid, bid9, None, 3600, frame9).await.unwrap();

        // Attacker replays the owner's OLD, validly-signed seq-3 frame (DID
        // records are public). classify() returns Valid { seq: 3 }, so without
        // reconciliation the establish branch would DELETE the genuine seq-9 blob.
        let err = reg
            .publish_frame(&storage, rid, bid3, None, 3600, frame3, 3)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SlotPublishError::NonSuperseding {
                stored_seq: 9,
                got_seq: 3
            }
        ));

        // The genuine seq-9 record survived, is adopted as the slot, and is the
        // sole blob QUERY returns.
        assert!(reg.is_claimed(&storage, &rid).await);
        assert_eq!(reg.slot_blob(&storage, &rid).await.unwrap().blob_id, bid9);
        let remaining = storage.query(&rid, None, 100).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].blob_id, bid9);
    }

    /// The complement of the rollback test: a cold index over a store holding a
    /// genuine LOWER-seq frame lets the owner's fresh HIGHER-seq publish win —
    /// it establishes and evicts the stale record (adoption only fires against a
    /// strictly-higher / conflicting stored frame, never to freeze a stale one).
    #[tokio::test]
    async fn cold_index_establish_supersedes_lower_seq_stored_frame() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();

        let (rid, bid3, frame3) = genuine_frame(11, 3, b"old");
        let (_rid, bid9, frame9) = genuine_frame(11, 9, b"new");
        storage.store(rid, bid3, None, 3600, frame3).await.unwrap();

        let (_s, outcome) = reg
            .publish_frame(&storage, rid, bid9, None, 3600, frame9, 9)
            .await
            .unwrap();
        assert_eq!(outcome, SlotPublishOutcome::Established);
        assert_eq!(reg.slot_blob(&storage, &rid).await.unwrap().blob_id, bid9);
        let remaining = storage.query(&rid, None, 100).await.unwrap();
        assert_eq!(remaining.len(), 1, "stale lower-seq frame evicted");
        assert_eq!(remaining[0].blob_id, bid9);
    }

    /// Fix 3 (unbounded index growth): a slot claimed once and then abandoned
    /// (never re-consulted) leaves a dangling index entry after its blob expires;
    /// the periodic sweep is the active backstop that reclaims it. Inspects the
    /// private index directly to prove the SWEEP — not a lazy on-consult revert —
    /// removed the entry.
    #[tokio::test]
    async fn sweep_reclaims_abandoned_expired_slot() {
        use super::super::storage::{ClockFn, InMemoryBlobStorage};
        use std::sync::atomic::{AtomicU64, Ordering};

        let clock_value = Arc::new(AtomicU64::new(1_000_000));
        let cv = clock_value.clone();
        let clock: ClockFn = Arc::new(move || cv.load(Ordering::Relaxed));
        let storage = BlobStorageBackend::from(InMemoryBlobStorage::with_clock(clock));
        let reg = DidSlotRegistry::new();
        let rid = [0x77; 32];

        let v = b"short-lived".to_vec();
        reg.publish_frame(&storage, rid, blob_id_of(&v), None, 10, v, 1)
            .await
            .unwrap();
        assert!(reg.slots.read().await.contains_key(&rid));

        // Expire the blob and purge storage, but NEVER consult the routing_id —
        // so the lazy revert path never fires and the index entry lingers.
        clock_value.store(1_000_011, Ordering::Relaxed);
        storage.purge_expired().await.unwrap();
        assert!(
            reg.slots.read().await.contains_key(&rid),
            "index entry lingers until it is actively reclaimed",
        );

        // The sweep reclaims the dangling entry.
        reg.sweep_expired(&storage).await;
        assert!(
            !reg.slots.read().await.contains_key(&rid),
            "sweep reclaimed the abandoned expired slot",
        );
    }

    /// The sweep must not clobber a still-live slot.
    #[tokio::test]
    async fn sweep_keeps_live_slots() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let rid = [0x88; 32];
        let v = b"live".to_vec();
        reg.publish_frame(&storage, rid, blob_id_of(&v), None, 3600, v, 1)
            .await
            .unwrap();

        reg.sweep_expired(&storage).await;
        assert!(reg.slots.read().await.contains_key(&rid));
        assert!(reg.is_claimed(&storage, &rid).await);
    }
}
