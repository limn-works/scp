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
//! # Reversion (spec §3.10.2) — two *different* causes
//!
//! The index is in-memory, so a slot can "revert" for two causes with **very
//! different** consequences; conflating them (as an earlier revision did) is
//! wrong:
//!
//! 1. **TTL-expiry** — the slot record's own blob TTL lapsed (owner offline past
//!    the 6-day republish cycle). Here the genuine record really *is* absent from
//!    storage; the `routing_id` reverts to an unclaimed opaque address. Not a
//!    suppression bypass — the record is gone because the owner stopped
//!    republishing, not because of attacker action.
//! 2. **Relay-restart / store-sharing cold index** — the in-memory index is
//!    empty but a **durable backend still holds the genuine blob**. The record is
//!    *present*; only the relay's cache forgot it. This DOES open a real, bounded,
//!    availability-only suppression/rollback window **on that one relay** until a
//!    binding-valid observation re-warms the index — and the storage-authoritative
//!    gates below are what keep it availability-only rather than integrity-losing.
//!
//! In **both** cases integrity holds by client re-verification, never by relay
//! signature checks: a replayed *old-but-genuine* record is owner-signed and
//! passes the resolver's DID-derived-key BEP44 verify, so the rollback defense is
//! the resolver's **client-side `seq`-monotonicity** freshness check (accept only
//! `seq >= last_known_seq`; the highest valid `seq` wins across relay *and* DHT —
//! §3.10.7, spec §9.6.1 "the BEP44 sequence number is the sole authority for
//! document freshness"), backed by multi-relay publishing and the DHT.
//!
//! For the restart case specifically, the storage-authoritative QUERY gate
//! ([`gate_query`](DidSlotRegistry::gate_query)) re-derives the slot from the
//! durable blob on a cold-index read, so a QUERY returns only the genuine record
//! even before the index re-warms — **largely closing the suppression window on
//! the read path**, not merely relying on the client to sort out a flood. The
//! DELETE gate ([`gate_delete`](DidSlotRegistry::gate_delete)) and cold-index
//! establish are likewise storage-authoritative, so a cold index cannot be used
//! to *purge* or *roll back* the durable record either.
//!
//! Reversion of an expired slot is reclaimed **lazily** (on the next consult) and
//! **actively** ([`sweep_expired`](DidSlotRegistry::sweep_expired)), so an
//! abandoned slot cannot pin its index entry forever.
//!
//! # Closed-by-construction matrix — every slot-touching operation
//!
//! The invariant is that the **index is a pure cache**; every decision that
//! could otherwise leak/purge/rollback a genuine record is authoritative against
//! *storage* (the immutable, content-addressed, self-certifying blob), so a cold
//! or empty index (restart / store-sharing peer) can never break integrity. Each
//! operation, the rule it enforces, and its cold-index behavior:
//!
//! | Operation | Rule | Authority | Cold-index behavior |
//! |---|---|---|---|
//! | **establish** (`publish_frame`, `None` arm) | single-slot | **storage** — reconciles co-located blobs, adopts highest-`seq` valid before evicting | a replayed lower-`seq` frame is rejected; the durable higher-`seq` record is adopted, never purged |
//! | **supersede / refresh** (`publish_frame`) | single highest-`seq` slot | index + storage `get` liveness | a stale index entry is reverted via `generation`-gated checks; a higher valid `seq` always wins |
//! | **opaque-PUBLISH rule (a)** (`gate_publish` `NotAFrame`) | reject junk at a claimed slot | **index cache** (fast path) | cold-miss may *accept junk into storage*, but it can never *suppress* — QUERY (below) is storage-authoritative and the next establish/sweep evicts. Made storage-authoritative here would put an unbounded scan on the hot path of every encrypted-context PUBLISH (a worse denial-of-service); the read-path authority is the sound closure |
//! | **QUERY / SUBSCRIBE-backfill rule (c)** (`gate_query`) | return only the slot | **storage** — re-applies over the `storage.query` result, returns only the highest-`seq` valid frame in the returned set; warms the index **only from a complete scan** (`since=None` and untruncated) | a cold index returns ONLY the genuine record (no leaked junk); no extra hot-path scan for non-DID `routing_id`s (the query already ran; only its results are classified). A partial/windowed scan never warms — so a small-`limit` query can't pin an *older* co-located genuine frame |
//! | **DELETE rule (d)** (`gate_delete`) | only a superseding PUBLISH may replace a slot | **storage** — decodes+verifies the immutable blob; fails *closed* on storage error; rate-limited | a cold index still refuses to delete a genuine record; content-addressing makes the check-then-delete window benign (availability-only) |
//! | **live delivery** (`deliver_to_subscribers` on opaque fall-through) | — | n/a (delivery, not a slot decision) | any junk delivered live is filtered by the subscriber's own re-verification (RELAYRES-002) |
//!
//! # Not a trust dependency
//!
//! Slot-exclusivity is an **availability / anti-suppression** measure. The
//! client re-verifies every record independently (RELAYRES-002), so a relay that
//! does not run this bookkeeping degrades availability only, never integrity.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use scp_identity::{did_from_ed25519_public_key, did_routing_id};
use scp_protocol::envelope::did_record::DidRecordV1;
use scp_relay_client::code;

use super::server::DidRecordValidation;
use super::storage::{BlobStorage, StorageError, StoredBlob};
use crate::relay::did_record_validation::{
    DidRecordClass, DidRecordRejection, classify_did_record_frame, slot_publish_error_response,
};
use crate::relay::rate_limit::PublishRateLimiter;

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
    /// A monotonically-increasing token bumped on **every** (re-)insert of this
    /// slot (establish, supersede, adopt, refresh). Unlike `blob_id` — which is
    /// *stable* across an expiry→same-record-refresh (the 6-day BEP44 republish
    /// re-stores the identical `value`+`seq`, hence the same `blob_id`) — the
    /// generation changes on each write. The reversion paths
    /// ([`revert_if_stale`](DidSlotRegistry::revert_if_stale),
    /// [`sweep_expired`](DidSlotRegistry::sweep_expired)) gate removal on the
    /// generation, not just `blob_id`, so a slot that a concurrent refresh
    /// re-established between the caller's probe and the write lock is never
    /// clobbered (Fix A).
    generation: u64,
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

/// Outcome of the shared PUBLISH slot-gate ([`DidSlotRegistry::gate_publish`]).
///
/// Each transport matches these arms and emits its own wire response, so the
/// ~90-line DID-record PUBLISH decision tree (classify → single-slot rule → error
/// mapping → rule (a)) lives in exactly one place across WebSocket, QUIC,
/// UDP/DTLS, and WebTransport — a chokepoint, not four copies.
#[derive(Debug)]
pub enum DidPublishGate {
    /// A binding-valid DID-record frame was applied to its slot. The transport
    /// delivers `stored` to subscribers (where the transport supports live
    /// delivery) and emits an `Ok { blob_id }`.
    Accepted(StoredBlob),
    /// The PUBLISH is rejected — the transport emits `Err { code, msg }`.
    Rejected {
        /// The relay wire error code (e.g. `DID_RECORD_REJECTED`).
        code: u16,
        /// A human-readable rejection reason.
        msg: String,
    },
    /// Not a DID-record frame at an unclaimed `routing_id` (or validation is
    /// disabled): the transport takes its ordinary opaque-store path (store +
    /// deliver + `Ok`).
    FallThrough,
}

/// Outcome of the shared DELETE slot-gate
/// ([`DidSlotRegistry::gate_delete`]).
#[derive(Debug)]
pub enum DidDeleteGate {
    /// The DELETE is allowed — the transport performs its best-effort delete and
    /// emits `Ok`.
    Proceed,
    /// The DELETE is refused — the transport emits `Err { code, msg }` and does
    /// **not** delete.
    Rejected {
        /// The relay wire error code.
        code: u16,
        /// A human-readable rejection reason.
        msg: String,
    },
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
    /// Source of the monotonic [`DidSlot::generation`] token. Shared across every
    /// clone of the registry (all clones enforce one store's slots), so the
    /// counter is globally monotonic. An `AtomicU64` — independent of the `slots`
    /// lock — so bumping it never widens the critical section.
    next_generation: Arc<AtomicU64>,
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

    /// Builds a [`DidSlot`] carrying a fresh, globally-unique generation token.
    /// Every insert into the index MUST go through this so the reversion paths
    /// can distinguish a re-established slot from the one they observed (Fix A).
    fn fresh_slot(&self, blob_id: [u8; 32], seq: u64) -> DidSlot {
        DidSlot {
            blob_id,
            seq,
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
        }
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
                    slots.insert(routing_id, self.fresh_slot(best_id, best_seq));
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
                slots.insert(routing_id, self.fresh_slot(blob_id, seq));
                Self::evict_others(storage, &routing_id, blob_id).await;
                Ok((stored, SlotPublishOutcome::Established))
            }
            Some(slot) if seq > slot.seq => {
                let stored = storage
                    .store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
                    .await?;
                slots.insert(routing_id, self.fresh_slot(blob_id, seq));
                Self::evict_others(storage, &routing_id, blob_id).await;
                Ok((stored, SlotPublishOutcome::Superseded))
            }
            Some(slot) if seq == slot.seq && blob_id == slot.blob_id => {
                // Byte-identical equal-seq republish: refresh storage lifetime
                // (re-store overwrites stored_at + blob_ttl) and re-assert
                // sole-slot. The (blob_id, seq) is unchanged, but re-insert with a
                // fresh generation so a concurrent sweep/revert that snapshotted
                // the pre-refresh generation cannot drop this now-refreshed slot
                // (Fix A).
                let stored = storage
                    .store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
                    .await?;
                slots.insert(routing_id, self.fresh_slot(blob_id, seq));
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
            self.revert_if_stale(routing_id, slot.blob_id, slot.generation)
                .await;
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
            self.revert_if_stale(routing_id, slot.blob_id, slot.generation)
                .await;
            None
        }
    }

    /// Warms the index from an **authoritative storage observation**: records
    /// that `routing_id` is claimed by the valid frame `(blob_id, seq)` that a
    /// storage-backed decision just found. This turns a cold-index cold-miss into
    /// a subsequent fast-path hit (QUERY/opaque-PUBLISH), so the storage-backed
    /// scan is paid at most once per `routing_id` per cold window.
    ///
    /// Best-effort and race-safe: it does **not** overwrite an index entry that
    /// already claims an equal-or-higher `seq` (a concurrent establish/supersede
    /// must win); any staleness it does introduce is reconciled by the ordinary
    /// lazy revert + sweep. Never establishes a *lower*-seq claim over a higher one.
    async fn warm_slot(&self, routing_id: [u8; 32], blob_id: [u8; 32], seq: u64) {
        let mut slots = self.slots.write().await;
        match slots.get(&routing_id) {
            Some(existing) if existing.seq >= seq => {}
            _ => {
                let slot = self.fresh_slot(blob_id, seq);
                slots.insert(routing_id, slot);
            }
        }
    }

    /// The storage-authoritative predicate shared by every slot decision: does
    /// `blob` (the immutable, content-addressed bytes at some `blob_id`) decode as
    /// a binding-and-signature-**Valid** DID-record frame? Returns its
    /// `(derived_routing_id, seq)` if so.
    ///
    /// A DID-record frame is content-addressed (`blob_id = SHA-256(blob)`, so its
    /// bytes are immutable) and self-certifying (embedded `public_key` + BEP44
    /// signature), so its protected status is reconstructible from the bytes
    /// alone — independent of any index. The `routing_id` a frame binds to is
    /// derived from its **own** `public_key`; a self-consistent frame binds to
    /// exactly that derived `routing_id`, which is what makes it a protected DID
    /// record. This is the single source of truth behind the DELETE gate and the
    /// cold-index reconciliation of QUERY / establish.
    #[must_use]
    fn classify_stored_frame(blob: &[u8]) -> Option<([u8; 32], u64)> {
        let frame = DidRecordV1::decode(blob).ok()?;
        let routing_id = did_routing_id(&did_from_ed25519_public_key(frame.public_key()));
        match classify_did_record_frame(&routing_id, blob) {
            DidRecordClass::Valid { seq } => Some((routing_id, seq)),
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Shared slot gates — the single chokepoint every transport routes through
    // (§3.10.2). Extracting them here means a change to slot policy (or a new
    // transport) is made in ONE place, not copy-pasted four times.
    // -----------------------------------------------------------------------

    /// Shared PUBLISH slot-gate (§3.10.2 rules 1–4 + rule (a)). Given a candidate
    /// blob at `routing_id`, decides establish/supersede/refresh/reject/opaque and
    /// returns a transport-agnostic [`DidPublishGate`]; the caller emits the wire
    /// response (and, on [`Accepted`](DidPublishGate::Accepted), delivers to
    /// subscribers).
    ///
    /// When `validation` is
    /// [`Disabled`](crate::native::server::DidRecordValidation::Disabled) the gate
    /// is a no-op ([`FallThrough`](DidPublishGate::FallThrough)) — the frame is
    /// stored opaquely like a foreign transport.
    ///
    /// Cold-index note: a `Valid` frame goes through
    /// [`publish_frame`](Self::publish_frame), which is already storage-authoritative
    /// (it reconciles a cold index against storage before evicting). The
    /// `NotAFrame` rule-(a) check uses the index fast-path
    /// ([`is_claimed`](Self::is_claimed)): on a cold index a junk opaque PUBLISH at
    /// a DID `routing_id` may be *accepted into storage*, but it can never *suppress*
    /// the genuine record — QUERY ([`gate_query`](Self::gate_query)) is
    /// storage-authoritative and returns only the genuine frame, and the next
    /// establish/sweep evicts the stray. Making rule (a) itself storage-authoritative
    /// would put an unbounded `storage.query` scan on the hot path of *every*
    /// encrypted-context PUBLISH (which is `NotAFrame` at an unclaimed `routing_id`),
    /// a far worse denial-of-service than it prevents; the read-path authority is the
    /// sound closure.
    #[allow(clippy::too_many_arguments)]
    pub async fn gate_publish<S: BlobStorage + ?Sized>(
        &self,
        validation: DidRecordValidation,
        storage: &S,
        routing_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: &[u8],
        blob_id: [u8; 32],
    ) -> DidPublishGate {
        if validation != DidRecordValidation::Enabled {
            return DidPublishGate::FallThrough;
        }
        match classify_did_record_frame(&routing_id, blob) {
            DidRecordClass::Valid { seq } => {
                match self
                    .publish_frame(
                        storage,
                        routing_id,
                        blob_id,
                        recipient_hint,
                        blob_ttl,
                        blob.to_vec(),
                        seq,
                    )
                    .await
                {
                    Ok((stored, _outcome)) => DidPublishGate::Accepted(stored),
                    Err(e) => {
                        let (code, msg) = slot_publish_error_response(&e);
                        DidPublishGate::Rejected { code, msg }
                    }
                }
            }
            DidRecordClass::Invalid(reason) => {
                let detail = match reason {
                    DidRecordRejection::BindingMismatch => {
                        "DID→routing_id binding mismatch (frame published at the wrong routing_id)"
                    }
                    DidRecordRejection::SignatureInvalid => "BEP44 signature verification failed",
                };
                DidPublishGate::Rejected {
                    code: code::DID_RECORD_REJECTED,
                    msg: format!("DID-record frame rejected: {detail}"),
                }
            }
            DidRecordClass::NotAFrame => {
                if self.is_claimed(storage, &routing_id).await {
                    DidPublishGate::Rejected {
                        code: code::DID_RECORD_REJECTED,
                        msg: "routing_id has a claimed DID-record slot; \
                              non-superseding blobs are rejected (slot-exclusive)"
                            .to_string(),
                    }
                } else {
                    DidPublishGate::FallThrough
                }
            }
        }
    }

    /// Shared QUERY / SUBSCRIBE-backfill slot-gate (§3.10.2 rule (c)). Returns the
    /// exact blob set to return for a QUERY at `routing_id`, applying
    /// slot-exclusivity **storage-authoritatively**:
    ///
    /// 1. index fast-path — a live claimed slot returns only that blob;
    /// 2. otherwise the ordinary `storage.query(since, limit)` runs, and if any
    ///    returned blob is a binding-valid DID frame, only the highest-`seq` valid
    ///    one **in the returned set** is returned — so a **cold index cannot leak
    ///    co-located junk** alongside a genuine record after a restart.
    ///
    /// The index is **warmed only from a COMPLETE view** of the `routing_id` — an
    /// untruncated (`blobs.len() < limit`) *and* un-narrowed (`since.is_none()`)
    /// scan. A partial/windowed scan can pick the highest-valid *within the
    /// window*, which — if two genuine frames coexist (only possible after a
    /// best-effort `evict_others` delete failed) — may be the *older* frame;
    /// warming from that would pin the older frame and hide the newer on this
    /// relay (an attacker could trigger it with a small `limit`). So a partial
    /// query still returns the correct highest-valid-in-window blob but never
    /// warms/pins the index. (Returning the in-window best is correct: the client
    /// re-verifies and takes the highest `seq` across relays and the DHT.)
    ///
    /// Step 2 adds no extra storage round-trip on the hot path: the
    /// `storage.query` is the one a fall-through QUERY does anyway, and the
    /// frame-scan (`highest_valid_frame`) only classifies the returned blobs —
    /// for an ordinary encrypted-context `routing_id` they are all `NotAFrame`
    /// (a one-byte decode reject), so no signature work and no slot-only filtering.
    ///
    /// When `validation` is `Disabled`, this is a plain `storage.query`.
    ///
    /// # Errors
    /// Propagates a [`StorageError`] from the underlying `storage.query`.
    pub async fn gate_query<S: BlobStorage + ?Sized>(
        &self,
        validation: DidRecordValidation,
        storage: &S,
        routing_id: [u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        if validation == DidRecordValidation::Enabled
            && let Some(slot) = self.slot_blob(storage, &routing_id).await
        {
            return Ok(vec![slot]);
        }

        let blobs = storage.query(&routing_id, since, limit).await?;

        if validation == DidRecordValidation::Enabled
            && let Some((best_id, best_seq)) = Self::highest_valid_frame(&routing_id, &blobs)
        {
            // A cold index missed a genuine frame that storage holds. Return ONLY
            // the highest-seq valid frame *in the returned set* (rule (c)) — this
            // is correct for THIS query regardless of windowing; the client
            // re-verifies and takes the highest `seq` across relays/DHT.
            //
            // Warm the index ONLY from a COMPLETE view of the routing_id: an
            // untruncated (`blobs.len() < limit`) AND un-narrowed (`since.is_none()`)
            // scan. A partial/windowed scan can pick the highest-valid *within the
            // window*, which — if two genuine frames coexist in storage (only
            // possible after a best-effort `evict_others` delete failed) — may be
            // the OLDER frame. Warming from that would PIN the older frame and
            // hide the newer on this relay (attacker-triggerable via a small
            // `limit`). Never warm from a partial view; leave the index cold so
            // the next complete scan (or a re-establish) sets it correctly.
            let complete_scan = since.is_none() && (blobs.len() as u64) < u64::from(limit);
            if complete_scan {
                self.warm_slot(routing_id, best_id, best_seq).await;
            }
            if let Some(slot) = blobs.into_iter().find(|b| b.blob_id == best_id) {
                return Ok(vec![slot]);
            }
            // Unreachable: best_id came from `blobs`. Fall through defensively.
            return Ok(Vec::new());
        }

        Ok(blobs)
    }

    /// Shared DELETE slot-gate (§3.10.2 rule (d)): decides whether a DELETE of
    /// `blob_id` is allowed or must be refused because it would purge a protected
    /// DID-record slot.
    ///
    /// The gate is **storage-backed** (not index-based) and therefore immune to a
    /// cold/empty index: it reads the immutable, content-addressed blob and
    /// reconstructs its protected status via [`classify_stored_frame`](Self::classify_stored_frame)
    /// — a DID frame is self-certifying, so protection is derivable from the bytes
    /// alone. Order of operations (defends the CPU-amplifiable classify):
    ///
    /// 1. **rate-limit first** (per-IP, shared with PUBLISH) — the storage read +
    ///    Ed25519 verify below is refused for a client over budget, so an
    ///    unauthenticated DELETE cannot be used for CPU amplification;
    /// 2. `storage.get`: `Ok(Some)` → classify; `Ok(None)` → not protected
    ///    (proceed); **`Err` → fail *closed*** (treat as protected, refuse) — an
    ///    integrity gate must never let a transient storage error open the delete.
    ///
    /// Content-addressing makes the check-then-delete window benign: the bytes at
    /// a `blob_id` are immutable, so a valid frame present at check time cannot
    /// become unprotected before the delete; the only residual is an unforceable
    /// "published just after a not-present check" race, which is availability-only.
    pub async fn gate_delete<S: BlobStorage + ?Sized>(
        &self,
        storage: &S,
        blob_id: &[u8; 32],
        rate_limiter: &PublishRateLimiter,
        ip: IpAddr,
    ) -> DidDeleteGate {
        // (1) Rate-limit BEFORE the CPU-amplifiable storage-backed classify,
        // consistent with PUBLISH (DELETE has no dedicated budget; it draws on the
        // same shared per-IP publish budget).
        if !rate_limiter.check(ip).await {
            return DidDeleteGate::Rejected {
                code: code::RATE_LIMITED,
                msg: "delete rate limit exceeded".to_string(),
            };
        }

        // (2) Storage-authoritative protection check, fail-closed on error.
        match storage.get(blob_id).await {
            Ok(Some(stored)) => {
                if Self::classify_stored_frame(&stored.blob).is_some() {
                    DidDeleteGate::Rejected {
                        code: code::DID_RECORD_REJECTED,
                        msg: "blob_id is a claimed DID-record slot; only a superseding \
                              PUBLISH may replace it (slot-exclusive)"
                            .to_string(),
                    }
                } else {
                    DidDeleteGate::Proceed
                }
            }
            Ok(None) => DidDeleteGate::Proceed,
            Err(e) => {
                // Fail CLOSED: an integrity gate must not let a transient storage
                // error open the delete of a possibly-protected record. DELETE is
                // best-effort + client-retryable, so refusing on error is cheap.
                tracing::warn!(
                    error = %e,
                    "DID slot DELETE gate: storage probe failed; refusing delete (fail-closed)",
                );
                DidDeleteGate::Rejected {
                    code: code::INTERNAL_ERROR,
                    msg: "storage error while verifying delete target; delete refused".to_string(),
                }
            }
        }
    }

    /// Drops a `routing_id` from the index iff it still points at the exact slot
    /// the caller observed — same `blob_id` **and** same `generation`. Gating on
    /// generation (not just `blob_id`) is load-bearing: an expiry→same-record
    /// refresh re-establishes the identical `blob_id`, so a `blob_id`-only guard
    /// would drop a slot that a concurrent refresh made live again (Fix A).
    async fn revert_if_stale(&self, routing_id: &[u8; 32], blob_id: [u8; 32], generation: u64) {
        let mut slots = self.slots.write().await;
        if slots.get(routing_id).map(|s| (s.blob_id, s.generation)) == Some((blob_id, generation)) {
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
    /// Snapshots the `(routing_id, blob_id, generation)` triples under a read
    /// lock, probes storage without holding the lock, then drops only the entries
    /// confirmed absent — and only if the index still points at the exact same
    /// slot (same `blob_id` **and** `generation`). Gating on generation is
    /// load-bearing: a slot whose blob TTL-expires and is then re-established by a
    /// concurrent same-record refresh keeps the identical `blob_id`, so a
    /// `blob_id`-only guard would clobber a now-live slot (Fix A).
    pub async fn sweep_expired<S: BlobStorage + ?Sized>(&self, storage: &S) {
        let entries: Vec<([u8; 32], [u8; 32], u64)> = {
            let slots = self.slots.read().await;
            slots
                .iter()
                .map(|(rid, slot)| (*rid, slot.blob_id, slot.generation))
                .collect()
        };
        if entries.is_empty() {
            return;
        }

        let mut stale: Vec<([u8; 32], [u8; 32], u64)> = Vec::new();
        for (rid, blob_id, generation) in entries {
            match storage.get(&blob_id).await {
                Ok(Some(_)) => {}
                Ok(None) => stale.push((rid, blob_id, generation)),
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
        for (rid, blob_id, generation) in stale {
            if slots.get(&rid).map(|s| (s.blob_id, s.generation)) == Some((blob_id, generation)) {
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

    /// A [`BlobStorage`] whose `get` always errors — used to prove the DELETE gate
    /// fails CLOSED on a storage fault (Fix 4).
    struct FailingGetStorage;

    #[async_trait::async_trait]
    impl BlobStorage for FailingGetStorage {
        async fn store(
            &self,
            routing_id: [u8; 32],
            blob_id: [u8; 32],
            recipient_hint: Option<[u8; 32]>,
            blob_ttl: u32,
            blob: Vec<u8>,
        ) -> Result<StoredBlob, StorageError> {
            Ok(StoredBlob {
                routing_id,
                blob_id,
                recipient_hint,
                blob_ttl,
                stored_at: 0,
                blob,
            })
        }

        async fn get(&self, _blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
            Err(StorageError::Internal(
                "simulated storage fault".to_string(),
            ))
        }

        async fn query(
            &self,
            _routing_id: &[u8; 32],
            _since: Option<u64>,
            _limit: u32,
        ) -> Result<Vec<StoredBlob>, StorageError> {
            Ok(Vec::new())
        }

        async fn delete(&self, _blob_id: &[u8; 32]) -> Result<bool, StorageError> {
            Ok(false)
        }

        async fn purge_expired(&self) -> Result<usize, StorageError> {
            Ok(0)
        }

        async fn count(&self) -> Result<usize, StorageError> {
            Ok(0)
        }
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

    /// Fix A (same-`blob_id` refresh race): the 6-day BEP44 refresh republishes
    /// the identical record (same `value`+`seq` → same `blob_id`), so a reversion
    /// guard that compares only `blob_id` would drop a slot that a concurrent
    /// refresh re-established between the reverter's probe and its write lock.
    /// The `generation` gate must reject a removal keyed to the pre-refresh slot.
    #[tokio::test]
    async fn refresh_bumps_generation_so_stale_generation_revert_is_ignored() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let rid = [0x99; 32];
        let v = b"genuine-record".to_vec();
        let bid = blob_id_of(&v);

        // Establish, then capture the slot's generation.
        reg.publish_frame(&storage, rid, bid, None, 3600, v.clone(), 5)
            .await
            .unwrap();
        let gen1 = reg.slots.read().await.get(&rid).unwrap().generation;

        // Byte-identical equal-seq republish (the TTL refresh): same blob_id, but
        // the generation must advance.
        let (_s, outcome) = reg
            .publish_frame(&storage, rid, bid, None, 3600, v, 5)
            .await
            .unwrap();
        assert_eq!(outcome, SlotPublishOutcome::IdempotentRefresh);
        let gen2 = reg.slots.read().await.get(&rid).unwrap().generation;
        assert!(gen2 > gen1, "a refresh must bump the generation");

        // A reverter that snapshotted the PRE-refresh slot (same blob_id, old
        // generation) — the exact interleave `sweep_expired`/`revert_if_stale`
        // guard against — must NOT drop the now-refreshed live slot.
        reg.revert_if_stale(&rid, bid, gen1).await;
        assert!(
            reg.slots.read().await.contains_key(&rid),
            "stale-generation revert must be a no-op on a refreshed slot",
        );
        assert!(reg.is_claimed(&storage, &rid).await);

        // The gate still removes a truly-current stale entry (matching generation
        // when the blob is genuinely gone).
        storage.delete(&bid).await.unwrap();
        reg.revert_if_stale(&rid, bid, gen2).await;
        assert!(
            !reg.slots.read().await.contains_key(&rid),
            "matching-generation revert of an absent blob must remove the entry",
        );
    }

    /// Fix B (cold-index storage-backed DELETE gate): a genuine binding-valid DID
    /// frame is present in the durable store but the slot index is COLD (fresh
    /// registry — models a relay restart / store-sharing peer). The gate is
    /// storage-backed, so it reconstructs protection from the self-describing,
    /// content-addressed blob and REFUSES the delete despite the cold index.
    /// Non-frame and absent blobs remain deletable.
    #[tokio::test]
    async fn cold_index_delete_gate_is_storage_backed() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new(); // COLD: nothing ever published through it.
        let limiter = PublishRateLimiter::new(1000);
        let ip = IpAddr::from([127, 0, 0, 1]);

        // A genuine seq-5 DID record deposited straight into storage (no publish),
        // so the in-memory index never learns about it.
        let (rid, bid, frame) = genuine_frame(71, 5, b"did-doc");
        storage.store(rid, bid, None, 3600, frame).await.unwrap();

        // The storage-backed gate REFUSES the delete despite the cold index.
        assert!(
            matches!(
                reg.gate_delete(&storage, &bid, &limiter, ip).await,
                DidDeleteGate::Rejected { code: c, .. } if c == code::DID_RECORD_REJECTED
            ),
            "storage-backed gate must protect the genuine record despite a cold index",
        );

        // A co-located opaque (non-frame) blob is not protected — DELETE proceeds.
        let opaque = b"\x80 not-a-did-frame".to_vec();
        let obid = blob_id_of(&opaque);
        storage.store(rid, obid, None, 3600, opaque).await.unwrap();
        assert!(matches!(
            reg.gate_delete(&storage, &obid, &limiter, ip).await,
            DidDeleteGate::Proceed
        ));

        // An absent blob is not protected.
        assert!(matches!(
            reg.gate_delete(&storage, &[0xAB; 32], &limiter, ip).await,
            DidDeleteGate::Proceed
        ));
    }

    /// Fix 3: the DELETE gate is rate-limited (per-IP, shared with PUBLISH) BEFORE
    /// the CPU-amplifiable storage-backed classify, so an unauthenticated DELETE
    /// flood cannot be used for CPU amplification.
    ///
    /// The target is a **genuine, binding-valid, signed** DID-record frame that IS
    /// present in storage — so the gate's expensive path (`storage.get` →
    /// `classify_stored_frame`, an Ed25519 verify) is fully reachable and, when the
    /// limiter permits, actually runs (each within-budget DELETE returns
    /// `DID_RECORD_REJECTED`, proving the classify fired). The over-budget DELETE of
    /// the SAME protected blob must return `RATE_LIMITED`, NOT `DID_RECORD_REJECTED`:
    /// the only way the code emits `RATE_LIMITED` is the limiter short-circuiting
    /// **before** the classify. Getting `DID_RECORD_REJECTED` on the over-budget call
    /// would prove the classify ran first — exactly the CPU-amplification bug this
    /// ordering defends against. Same blob, two different codes selected purely by
    /// remaining budget: that is the short-circuit, proven.
    #[tokio::test]
    async fn delete_gate_is_rate_limited() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let limiter = PublishRateLimiter::new(2); // budget of 2
        let ip = IpAddr::from([127, 0, 0, 2]);

        // A genuine seq-5 DID record deposited straight into storage: `storage.get`
        // returns `Some` and the blob classifies as a protected slot, so the gate
        // WOULD reach + run the Ed25519-verifying classify absent the rate limit.
        let (rid, bid, frame) = genuine_frame(74, 5, b"did-doc");
        storage.store(rid, bid, None, 3600, frame).await.unwrap();

        // Within budget, the classify runs and refuses the protected blob — proving
        // the expensive path is live (not short-circuited) while budget remains.
        for _ in 0..2 {
            assert!(
                matches!(
                    reg.gate_delete(&storage, &bid, &limiter, ip).await,
                    DidDeleteGate::Rejected { code: c, .. } if c == code::DID_RECORD_REJECTED
                ),
                "within-budget DELETE of a protected slot must run the classify and \
                 reject it as DID_RECORD_REJECTED",
            );
        }

        // Over budget, the SAME protected blob yields RATE_LIMITED — the limiter
        // short-circuited BEFORE the classify. DID_RECORD_REJECTED here would mean
        // the classify ran first (the CPU-amplification bug).
        assert!(
            matches!(
                reg.gate_delete(&storage, &bid, &limiter, ip).await,
                DidDeleteGate::Rejected { code: c, .. } if c == code::RATE_LIMITED
            ),
            "over-budget DELETE must short-circuit to RATE_LIMITED before the \
             CPU-amplifiable classify, not fall through to DID_RECORD_REJECTED",
        );
    }

    /// Fix 4: the DELETE gate fails CLOSED on a storage error — a transient
    /// `storage.get` failure must never open the delete of a possibly-protected
    /// record (an integrity gate).
    #[tokio::test]
    async fn delete_gate_fails_closed_on_storage_error() {
        let reg = DidSlotRegistry::new();
        let limiter = PublishRateLimiter::new(1000);
        let ip = IpAddr::from([127, 0, 0, 3]);
        let storage = FailingGetStorage;

        assert!(
            matches!(
                reg.gate_delete(&storage, &[0x07; 32], &limiter, ip).await,
                DidDeleteGate::Rejected { code: c, .. } if c == code::INTERNAL_ERROR
            ),
            "a storage error must refuse the delete, not allow it",
        );
    }

    /// Fix 1 (storage-authoritative QUERY): a COLD index over a durable store that
    /// holds a genuine frame co-located with junk must return ONLY the genuine
    /// frame. The index-only `slot_blob` would cold-miss and leak the junk; the
    /// storage-authoritative `gate_query` re-applies rule (c) over the storage
    /// result and warms the index.
    #[tokio::test]
    async fn cold_index_query_returns_only_genuine_frame() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new(); // COLD: nothing published through it.

        // Genuine frame + co-located junk, all deposited straight into storage.
        let (rid, bid, frame) = genuine_frame(72, 5, b"did-doc");
        storage.store(rid, bid, None, 3600, frame).await.unwrap();
        store_opaque(&storage, rid, b"junk-1").await;
        store_opaque(&storage, rid, b"junk-2").await;
        assert_eq!(storage.query(&rid, None, 100).await.unwrap().len(), 3);

        // The storage-authoritative QUERY gate returns ONLY the genuine frame.
        let out = reg
            .gate_query(DidRecordValidation::Enabled, &storage, rid, None, 100)
            .await
            .unwrap();
        assert_eq!(out.len(), 1, "cold-index QUERY must filter co-located junk");
        assert_eq!(out[0].blob_id, bid);

        // It warmed the index — the fast path now recognizes the claimed slot.
        assert!(reg.slots.read().await.contains_key(&rid));
        assert!(reg.is_claimed(&storage, &rid).await);
    }

    /// A QUERY at an ordinary (non-DID) `routing_id` returns all blobs unchanged —
    /// the storage-authoritative re-application only engages when storage actually
    /// holds a binding-valid frame, so it never filters encrypted-context blobs.
    #[tokio::test]
    async fn query_at_non_did_routing_id_is_pass_through() {
        let storage = BlobStorageBackend::in_memory();
        let reg = DidSlotRegistry::new();
        let rid = [0xCC; 32];
        store_opaque(&storage, rid, b"ctx-1").await;
        store_opaque(&storage, rid, b"ctx-2").await;

        let out = reg
            .gate_query(DidRecordValidation::Enabled, &storage, rid, None, 100)
            .await
            .unwrap();
        assert_eq!(out.len(), 2, "no frame present → all blobs returned");
        assert!(
            !reg.slots.read().await.contains_key(&rid),
            "index not warmed"
        );
    }

    /// Warm-only-on-complete-scan guard: a TRUNCATED cold-index QUERY (a `limit`
    /// smaller than the co-located blob count) must NOT warm/pin the index to the
    /// highest-valid frame *in that window* — which, when two genuine frames
    /// coexist (only possible after a best-effort eviction failed) and the older
    /// one sorts first, would pin the OLDER frame and hide the newer on this
    /// relay. The truncated query still returns the in-window best (correct for
    /// that query); a later COMPLETE scan returns the true newest and warms to it.
    #[tokio::test]
    async fn partial_cold_index_query_does_not_warm_to_older_frame() {
        use super::super::storage::{ClockFn, InMemoryBlobStorage};

        let clock_value = Arc::new(AtomicU64::new(1000));
        let cv = clock_value.clone();
        let clock: ClockFn = Arc::new(move || cv.load(Ordering::Relaxed));
        let storage = BlobStorageBackend::from(InMemoryBlobStorage::with_clock(clock));
        let reg = DidSlotRegistry::new(); // COLD.

        // Two genuine frames from the SAME DID key coexist in storage (only
        // reachable after a best-effort `evict_others` delete failed). Store the
        // OLDER (seq 3) first so it sorts before the newer (seq 9) in an
        // ascending-`stored_at` query window.
        let (rid, bid3, frame3) = genuine_frame(80, 3, b"old");
        let (rid9, bid9, frame9) = genuine_frame(80, 9, b"new");
        assert_eq!(rid, rid9, "same key ⇒ same routing_id");
        storage.store(rid, bid3, None, 3600, frame3).await.unwrap();
        clock_value.store(2000, Ordering::Relaxed);
        storage.store(rid, bid9, None, 3600, frame9).await.unwrap();

        // Truncating query (limit 1 < 2 co-located): returns the in-window best
        // (older seq-3), but MUST NOT warm the index.
        //
        // Assumption pinned: this asserts the WINDOW contains only the older frame,
        // which relies on the `BlobStorage::query` contract (storage.rs, trait doc:
        // "Results are ordered oldest-first (ascending stored_at timestamp)") plus
        // `limit`-truncation keeping the earliest — so with stored_at(bid3)=1000 <
        // stored_at(bid9)=2000, `limit=1` yields exactly [bid3]. If a backend's
        // query returned newest-first (or truncated differently), the window would
        // hold bid9 and this exact-blob assertion would need revisiting; the
        // no-warm invariant below (index stays cold on ANY partial scan) would still
        // hold regardless of which in-window frame is returned.
        let out = reg
            .gate_query(DidRecordValidation::Enabled, &storage, rid, None, 1)
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].blob_id, bid3,
            "in-window highest-valid is the older frame"
        );
        assert!(
            !reg.slots.read().await.contains_key(&rid),
            "a partial/truncated scan must NOT warm or pin the index",
        );

        // A `since`-narrowed query likewise must not warm, even if untruncated.
        let out = reg
            .gate_query(DidRecordValidation::Enabled, &storage, rid, Some(0), 100)
            .await
            .unwrap();
        assert_eq!(
            out[0].blob_id, bid9,
            "since-narrowed still returns in-window best (newest here)"
        );
        assert!(
            !reg.slots.read().await.contains_key(&rid),
            "a since-narrowed scan must NOT warm the index",
        );

        // A COMPLETE scan (untruncated, since=None) returns the true newest AND
        // warms to it — never to the older frame.
        let out = reg
            .gate_query(DidRecordValidation::Enabled, &storage, rid, None, 100)
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].blob_id, bid9,
            "complete scan returns the true highest-seq frame"
        );
        assert_eq!(
            reg.slots.read().await.get(&rid).unwrap().blob_id,
            bid9,
            "complete scan warms to the NEWER frame",
        );
    }

    /// The `generation` also protects `sweep_expired` end-to-end: after an
    /// expiry→same-record refresh re-establishes the slot (new generation, blob
    /// live again), a subsequent sweep must keep it.
    #[tokio::test]
    async fn sweep_keeps_slot_after_expiry_then_refresh() {
        use super::super::storage::{ClockFn, InMemoryBlobStorage};
        use std::sync::atomic::AtomicU64 as ClockU64;

        let clock_value = Arc::new(ClockU64::new(1_000_000));
        let cv = clock_value.clone();
        let clock: ClockFn = Arc::new(move || cv.load(Ordering::Relaxed));
        let storage = BlobStorageBackend::from(InMemoryBlobStorage::with_clock(clock));
        let reg = DidSlotRegistry::new();
        let rid = [0xAA; 32];
        let v = b"refreshable".to_vec();
        let bid = blob_id_of(&v);

        reg.publish_frame(&storage, rid, bid, None, 10, v.clone(), 1)
            .await
            .unwrap();
        let gen1 = reg.slots.read().await.get(&rid).unwrap().generation;

        // Blob TTL-expires.
        clock_value.store(1_000_011, Ordering::Relaxed);

        // Owner republishes the identical record (same blob_id) with a fresh TTL:
        // the live-slot probe finds the blob gone and re-establishes → new
        // generation, blob live again.
        reg.publish_frame(&storage, rid, bid, None, 3600, v, 1)
            .await
            .unwrap();
        let gen2 = reg.slots.read().await.get(&rid).unwrap().generation;
        assert!(gen2 > gen1);

        // The sweep must keep the refreshed live slot.
        reg.sweep_expired(&storage).await;
        assert!(reg.slots.read().await.contains_key(&rid));
        assert!(reg.is_claimed(&storage, &rid).await);
    }
}
