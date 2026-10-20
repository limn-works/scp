//! `KeyPackageStoreActor` — one actor per local identity, owns the
//! KeyPackage pool per spec §9.16.1 and ADR-049 §9.
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! # Lifecycle contract
//!
//! - Maintain a pool of [`MIN_BUFFER`] usable KeyPackages for this identity.
//! - Replenish when `pool.len() + reserved.len()` falls below
//!   [`REPLENISH_THRESHOLD`].
//! - Two-phase reservation against Welcome processing
//!   ([`crate::context::actor::state::WelcomeProcessing`]):
//!   [`KeyPackageCommand::Reserve`] moves a KP from `pool` to `reserved` and
//!   returns ONLY a fresh `ReservationId` plus the KP's PUBLIC bytes — the
//!   private signer-state never leaves the actor. [`KeyPackageCommand::ConfirmConsume`]
//!   carries the Welcome, runs the join INTERNALLY against the held
//!   signer-state, and durably records the consume on success;
//!   [`KeyPackageCommand::CancelReservation`] discards the reservation (KP
//!   single-use semantics preclude returning to the pool).
//!
//! # Fused single-use model (ADR-049 §9 — two durable anchors)
//!
//! The single-use guarantee for a `KeyPackage` rests on TWO independent
//! durable anchors and a FUSED join, so a held-bytes replay or a pre-confirm
//! crash cannot join a group twice:
//!
//! 1. **Fused join — private bytes never cross the channel.** `Reserve`
//!    returns only the `ReservationId` and the KP's PUBLIC bytes. The private
//!    signer-state stays inside the actor (`reserved` map). `ConfirmConsume`
//!    carries the `welcome_bytes`, looks up the reserved signer-state
//!    internally, and calls
//!    [`MlsBackend::join_from_welcome`]
//!    itself, returning the JOIN RESULT (the joined group bytes) — never the
//!    raw signer-state. There is therefore no held-bytes copy a caller could
//!    replay, and no zeroization-across-channel gap.
//!
//! 2. **Reservation journal (reservation_id keying).** A reservation record +
//!    consumed tombstone, keyed by `ReservationId`, persisted under namespaced
//!    `mls_storage` keys. `Reserve` writes the reservation-id set BEFORE
//!    acking (the enumerable Class-S anchor reconcile reads); `ConfirmConsume`
//!    deletes the KP private record and writes the consumed tombstone (keyed by
//!    the consumed `kp_ref`) BEFORE acking; both fail-closed. Reconcile
//!    excludes consumed `kp_ref`s from the pool branch so a consumed KP can
//!    never be re-pooled.
//!
//! 3. **Crypto-layer consumed-init-key set (init-key keying).** Inside
//!    [`MlsBackend::join_from_welcome`] the backend consults a durable
//!    consumed-init-key set keyed by the KP's HPKE init key (the
//!    cryptographically-unique single-use element) BEFORE completing the join
//!    and records it on success. This is independent of the actor's
//!    reservation bookkeeping in KEYING and ENFORCEMENT LOCATION: even if the
//!    reservation journal has a LOGIC bug, a second join with the same init key
//!    is rejected durably at the crypto layer. `ConfirmConsume` thus exercises
//!    two independent keyings — the reservation-id tombstone here and the
//!    init-key marker in the backend.
//!    This backstop covers every join because `MlsBackend::join_from_welcome`
//!    (the fused-confirm path) is the only join primitive: the ADR-049 §9(b)
//!    2F-residual slice deleted the legacy single-slot
//!    `NodeMlsFactory::join_from_welcome` path, which called
//!    `group::join_group_from_bytes` directly, and
//!    `scripts/check-deleted-primitives.sh` rejects its reintroduction.
//!
//! The KP private signer-state lives ENTIRELY inside the opaque
//! [`SignerState`] blob returned by
//! [`MlsBackend::finish_key_package`] (a fresh isolated OpenMLS provider per
//! KP, serialized) — it is NOT written to any shared OpenMLS keystore. The
//! actor (in memory) and the durable KP record (at rest) are the only homes
//! for that material; deleting the KP record on consume/cancel makes a
//! replayed join from the journal impossible (the signer-state is gone), and
//! the consumed-init-key set makes a replay of any surviving bytes through
//! `MlsBackend::join_from_welcome` impossible at the crypto layer (the only
//! join primitive — see anchor 3 above).
//!
//! ## Anchor independence vs. shared durable substrate
//!
//! Anchors 2 (the reservation journal) and 3 (the consumed-init-key set) are
//! independent in KEYING (reservation-id / consumed-`kp_ref` vs. HPKE init key)
//! and in ENFORCEMENT LOCATION (this actor vs. the crypto backend): a LOGIC bug
//! in one cannot defeat the other. They are NOT, however, independent in their
//! durable substrate — both persist to the SAME injected `mls_storage` `Arc`.
//! Single-use DURABILITY is therefore contingent on that backend's
//! crash-and-rollback consistency: an operator or faulty/adversarial `Storage`
//! backend that can roll `mls_storage` back to a pre-consume state — a partial
//! restore, a rollback, or a correlated loss spanning BOTH key prefixes — can
//! un-consume a KeyPackage at both layers at once and replay it (re-pool +
//! re-join). This is consistent with the protocol treating durable storage as
//! the trust anchor; it is not a logic gap the actor can close in code. Giving
//! anchor 3 (the crypto-layer init-key set) a SEPARATE failure domain from the
//! reservation journal is a possible FUTURE hardening — out of scope here (the
//! consume path is not production-wired until the spawn-from-Welcome entrypoint
//! lands) and deliberately NOT implemented now.
//!
//! # Crash-safety (ADR-049 §9 — Class S, journal-backed)
//!
//! "KeyPackage consumption (Welcome idempotency)" is **Class S**: the
//! reserve / consume transitions are sync-persisted, fail-closed, BEFORE the
//! reply is acked. Unlike per-context Class-S state (which lives in the dead
//! actor's `PerContextState`), this Class-S state lives in the
//! supervisor-owned `mls_storage` journal, which survives the actor task
//! unwind — so its durability is contingent on the injected `Storage`
//! backend's write semantics (a durable backend is required for the guarantee
//! to hold; an in-memory backend gives the guarantee only within the process).
//!
//! On respawn the actor rebuilds `pool` / `reserved` from the DURABLE source
//! (the persisted records), never from a coalesced snapshot.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::crypto::hpke::p256::P256Point;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::context::builder::ContextTransportProvider;
use crate::crypto::mls::attestation_signer::{
    KeyPackageAttestationSigner, mint_attested_key_package,
};
use crate::crypto::mls::backend::{GeneratedKeyPackage, MlsBackend, SignerState};
use crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter;
use crate::crypto::wrapping::IdentityWrappingKey;
use scp_mls::error::MlsError;
use scp_mls::group::ScpMlsGroup;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Mailbox capacity for a `KeyPackageStoreActor`. Deliberately smaller
/// than the per-context actor capacity (256) — KP operations are rare
/// per identity (a Reserve per Welcome, a Replenish every 5 consumed),
/// so 32 is plenty and keeps memory bounded when many identities are
/// registered.
pub const KP_MAILBOX_CAPACITY: usize = 32;

/// Per-caller mailbox-send timeout. Matches
/// [`crate::context::actor::handle::SEND_TIMEOUT`] for consistency.
pub const KP_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-caller reply-await timeout bounding how long
/// [`KeyPackageStoreHandle::send`] waits on the actor's oneshot reply AFTER the
/// command was enqueued. Distinct budget from [`KP_SEND_TIMEOUT`], which bounds
/// only mailbox ADMISSION (waiting for a free slot on a full mailbox): once the
/// command is enqueued, this bounds actor-side PROCESSING — the actor runs a
/// single serial mailbox loop, so a `Reserve` / `ConfirmConsume` / `Replenish`
/// reply can legitimately trail every command already queued ahead of it
/// (up to [`KP_MAILBOX_CAPACITY`] of them), each doing MLS crypto plus durable
/// storage I/O. Conflating the two budgets would risk turning a merely
/// deep-queued (but healthy) actor into an error on the very bootstrap path
/// this bound protects, so the reply budget is deliberately larger. Bounding it
/// at all is the point: a WEDGED actor (stuck inside a hung storage/transport
/// call) must never pin a bootstrap caller forever — on elapse the handle
/// fail-closes with a typed [`ContextError::ActorBusy`] (retryable) rather than
/// awaiting the reply unbounded (internal follow-up #129).
pub const KP_REPLY_TIMEOUT: Duration = Duration::from_mins(1);

/// Target pool size: 10 usable KeyPackages per identity (ADR-001 criterion 8,
/// mirrored by ADR-049 §9.16.1). Replenish refills `pool` (+ outstanding
/// `reserved`) back up to this high-water mark.
pub const MIN_BUFFER: usize = 10;

/// Low-water mark: replenish when `pool.len() + reserved.len()` drops below
/// this (ADR-001 criterion 8). Auto-replenish fires after every `Reserve` and
/// `CancelReservation`.
pub const REPLENISH_THRESHOLD: usize = 5;

/// Time-to-live for an unconfirmed reservation, in milliseconds (10 minutes).
/// A Welcome flow reserves a KP, joins, then confirms/cancels within seconds;
/// a reservation older than this has been abandoned (the caller crashed
/// between Reserve and Confirm/Cancel) and is swept on the next replenish tick
/// — treated as a cancel (the KP is burned, durable records cleaned up) so a
/// reserve-without-confirm/cancel never leaks a private record forever.
pub const RESERVATION_TTL_MS: u64 = 10 * 60 * 1000;

/// Hard ceiling on the number of concurrent outstanding reservations per
/// identity. A flood of `Reserve` calls without matching confirm/cancel is
/// rejected past this bound with a typed error, capping the private-record
/// footprint a misbehaving (or adversarial) caller can pin in memory and at
/// rest. Generously above the realistic concurrent-Welcome count.
pub const MAX_OUTSTANDING_RESERVATIONS: usize = 128;

/// Ceiling on the replies a store holds: `ReserveAny` commands waiting for
/// their signer check, `ReserveAny` commands that found the pool empty, and
/// `Replenish` commands waiting for the refill to end. Each queue holds at
/// most this many; a command past it is
/// refused with [`ContextError::ActorBusy`]. Equal to the mailbox capacity, so
/// parking never holds more callers than the mailbox already admits.
pub const MAX_PARKED_REPLIES: usize = KP_MAILBOX_CAPACITY;

// ---------------------------------------------------------------------------
// Durable journal key namespaces (ADR-049 §9 — Class S anchors)
// ---------------------------------------------------------------------------

/// Namespace prefix for a KP private-record key: `scp-kp/{identity}/{kp_ref}`.
/// Value = MessagePack-serialized [`PersistedKeyPackage`]. Deleting this key
/// destroys the only at-rest copy of the KP's private signer-state, making a
/// replayed journal join impossible (one of the single-use anchors).
const KP_RECORD_PREFIX: &str = "scp-kp";

/// Namespace prefix for a reservation record:
/// `scp-kp-reservation/{identity}/{reservation_id}`. Value = MessagePack
/// [`PersistedReservation`]. The reservation-id set (see
/// [`KP_RESERVATION_IDS_PREFIX`]) is written fail-closed BEFORE `Reserve`
/// acks; the per-reservation record rides the same single store.
const KP_RESERVATION_PREFIX: &str = "scp-kp-reservation";

/// Namespace prefix for the per-identity enumerable reservation-id set:
/// `scp-kp-reservation-ids/{identity}`. Value = MessagePack `Vec<String>` of
/// every live `reservation_id`. Reconcile enumerates reservations through this
/// set (the KV adapter has no list API). This is the single Class-S anchor
/// `Reserve` persists fail-closed before acking.
const KP_RESERVATION_IDS_PREFIX: &str = "scp-kp-reservation-ids";

/// Namespace prefix for a consumed tombstone:
/// `scp-kp-consumed/{identity}/{reservation_id}`. Value = the consumed
/// `kp_ref` bytes. Written fail-closed during `ConfirmConsume`; its presence
/// proves the reservation was permanently consumed even if a crash races the
/// in-memory removal, AND its value (the `kp_ref`) lets reconcile exclude the
/// consumed KP from the pool branch.
const KP_CONSUMED_PREFIX: &str = "scp-kp-consumed";

/// Namespace prefix for the per-identity index of live KP refs:
/// `scp-kp-index/{identity}`. Value = MessagePack `Vec<String>` of every
/// `kp_ref` whose KP record currently exists. Lets respawn enumerate the
/// durable pool without a list API on the KV adapter (which only offers
/// get/put/delete).
const KP_INDEX_PREFIX: &str = "scp-kp-index";

// ---------------------------------------------------------------------------
// Newtype ids (stable public surface)
// ---------------------------------------------------------------------------

/// Opaque reservation identifier (a UUID v4 string). Supervisor-scoped;
/// opaque to callers.
///
/// A newtype (not a bare `String` alias) so it cannot be transposed with a
/// [`KpRef`] at a call boundary — the two are distinct domains (a reservation
/// handle vs. a KeyPackage content hash) and the type system rejects passing
/// one where the other is expected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReservationId(String);

impl ReservationId {
    /// Mint a fresh random reservation id (UUIDv4). This is the only *minting*
    /// constructor, but not the only way to obtain a `ReservationId`: the type
    /// is reconstructible from a string via its `#[serde(transparent)]`
    /// `Deserialize` — the sanctioned path the FFI bridges use to round-trip the
    /// id back across the boundary. That reconstruction grants nothing: a
    /// `ReservationId` is a LOOKUP KEY scoped to the caller's own per-identity
    /// KeyPackage actor, so a forged or foreign id simply matches no reservation
    /// and is rejected.
    #[must_use]
    pub fn new_random() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Borrow the inner string (for key formatting / logging).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only raw constructor from an arbitrary string, so a test can name a
    /// known/bogus reservation id (e.g. for unknown-reservation error paths or
    /// the transparent-serde round-trip pin). NOT available in production — a
    /// real `ReservationId` is always [`Self::new_random`]-minted.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }
}

impl std::fmt::Display for ReservationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque `KpRef` — the KeyPackage's stable identifier, `hex(SHA-256(kp))`.
///
/// A newtype (not a bare `String` alias) for the same transposition-safety
/// reason as [`ReservationId`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KpRef(String);

impl KpRef {
    /// Derive the stable `KpRef` for a KeyPackage's PUBLIC bytes:
    /// `hex(SHA-256(public_bytes))`. This is the ONLY public constructor — a
    /// `KpRef` therefore always names a real KeyPackage content hash and can
    /// never be arbitrarily minted from a caller-chosen string.
    ///
    /// NOTE: this is the actor's `kp_ref`, NOT the MLS `KeyPackageRef` an
    /// incoming Welcome carries. A 2E integrator matching a Welcome's
    /// `KeyPackageRef` to a pooled `KpRef` computes the MLS ref itself from the
    /// `public_bytes` returned by [`KeyPackageCommand::ListPooled`]; the two are
    /// distinct derivations over the same bytes.
    #[must_use]
    pub fn from_public_bytes(public_bytes: &[u8]) -> Self {
        let digest = Sha256::digest(public_bytes);
        Self(hex::encode(digest))
    }

    /// Borrow the inner string (for key formatting / logging).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reconstruct a `KpRef` from a hex string already stored in the durable
    /// journal (a consumed tombstone value, or a reservation record's recovered
    /// ref). Module-private: only reconcile, which reads refs the actor ITSELF
    /// wrote via [`Self::from_public_bytes`], may rebuild a `KpRef` this way.
    const fn from_durable(hex_ref: String) -> Self {
        Self(hex_ref)
    }

    /// Test-only raw constructor from an arbitrary string, so a test can name a
    /// known/bogus ref (e.g. for no-such-ref error paths or the
    /// transparent-serde round-trip pin) without computing a real hash. NOT
    /// available in production — a real `KpRef` is always
    /// [`Self::from_public_bytes`]-derived.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }
}

impl std::fmt::Display for KpRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Durable record shapes
// ---------------------------------------------------------------------------

/// Durable KP record: the publishable public bytes + the private signer-state.
/// Persisted under `scp-kp/{identity}/{kp_ref}`.
///
/// The `signer_state` field holds private signing/HPKE join material, so it
/// is `Zeroizing`: a transient `PersistedKeyPackage` (built to serialize a
/// record, or parsed back out during reconcile) wipes it on every drop.
/// zeroize's `serde` impls delegate to the inner `Vec<u8>`, so the record
/// encodes as it did with a plain `Vec<u8>` field. `public_bytes` is
/// publishable and not zeroed.
#[derive(Serialize, Deserialize)]
struct PersistedKeyPackage {
    /// TLS-serialized public KeyPackage bytes (publishable).
    public_bytes: Vec<u8>,
    /// Opaque private signer-state (the join material). At rest it lives in
    /// `mls_storage` and is deleted on consume/cancel.
    signer_state: Zeroizing<Vec<u8>>,
    /// The Ed25519 key the `KeyPackage`'s `0xFF03` attestation verifies under
    /// (§9.7.1): the owner's `#active` key when it was minted. Reconcile reads
    /// it back so a respawned store knows which entries a later `#active` key
    /// supersedes (§9.12).
    attested_by: [u8; 32],
}

/// Durable reservation record. Persisted under
/// `scp-kp-reservation/{identity}/{reservation_id}`. Maps a reservation back
/// to the KP it reserved plus the mint time (for TTL expiry).
#[derive(Serialize, Deserialize)]
struct PersistedReservation {
    /// The `kp_ref` this reservation holds.
    kp_ref: KpRef,
    /// Wall-clock millis the reservation was minted.
    reserved_at_ms: u64,
}

/// The two reconcile maps built from the durable reservation-id set:
/// - `reserved_by_ref`: `kp_ref -> (reservation_id, reserved_at_ms)` for LIVE
///   (non-tombstoned) reservations, used to restore the `reserved` map.
/// - `consumed_rid_by_ref`: consumed `kp_ref -> consuming reservation_id` for
///   tombstoned reservations, used to exclude consumed refs from the pool.
type ReconcileReservationMaps = (
    HashMap<KpRef, (ReservationId, u64)>,
    HashMap<KpRef, ReservationId>,
);

/// The pooled-KeyPackage listing returned by [`KeyPackageCommand::ListPooled`]:
/// each entry is a pooled `(KpRef, public bytes)` pair. The private
/// signer-state never appears here.
pub type PooledKeyPackages = Vec<(KpRef, Vec<u8>)>;

// ---------------------------------------------------------------------------
// In-memory pool/reservation entries
// ---------------------------------------------------------------------------

/// A pooled (unreserved) KeyPackage. `attested_by` is the key its `0xFF03`
/// attestation verifies under.
struct PooledKeyPackage {
    kp_ref: KpRef,
    public_bytes: Vec<u8>,
    signer_state: Zeroizing<Vec<u8>>,
    attested_by: [u8; 32],
}

/// A reserved KeyPackage awaiting confirm/cancel. Holds the private
/// signer-state (it NEVER leaves the actor) plus the public bytes the fused
/// join needs to derive the crypto-layer init-key marker.
struct ReservedKeyPackage {
    kp_ref: KpRef,
    public_bytes: Vec<u8>,
    signer_state: Zeroizing<Vec<u8>>,
    attested_by: [u8; 32],
    reserved_at_ms: u64,
}

/// A reply a `ReserveAny` sends: the reservation and the public bytes.
type ReserveReply = oneshot::Sender<Result<(ReservationId, Vec<u8>), ContextError>>;

/// What one off-turn mint returns: the key its attestation verifies under,
/// and the minted `KeyPackage` or the mint's error.
struct MintOutcome {
    attested_by: [u8; 32],
    result: Result<GeneratedKeyPackage, ContextError>,
}

/// A subtask's handle that aborts the subtask when dropped, so a stopped
/// actor leaves none of its subtasks running.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The one mint in flight, a task of its own. The actor polls its handle
/// alongside its mailbox, so a slow custody sign never holds a command turn.
/// Dropping it (the actor stopped) aborts the mint.
struct MintTask {
    attested_by: [u8; 32],
    task: AbortOnDrop<Result<GeneratedKeyPackage, ContextError>>,
}

/// The one signer check in flight: a `ReserveAny`'s signer whose key is not
/// the installed signer's, and the task re-resolving the owner's `#active`
/// key for it ([`KeyPackageAttestationSigner::confirm_still_active`]). The
/// actor polls it alongside its mailbox, so a slow resolver never holds a
/// command turn.
struct SignerCheck {
    signer: Arc<KeyPackageAttestationSigner>,
    reply: ReserveReply,
    task: AbortOnDrop<Result<(), ContextError>>,
}

/// A refill in progress: how many `KeyPackages` it has pooled, and the
/// `Replenish` replies waiting for it to end, each with the count pooled when
/// it parked.
#[derive(Default)]
struct Refill {
    generated: usize,
    waiters: Vec<(oneshot::Sender<Result<usize, ContextError>>, usize)>,
}

/// Polls the mint in flight, or never resolves when there is none, so the
/// run loop's `select!` waits on the mailbox alone.
async fn next_mint(minting: &mut Option<MintTask>) -> MintOutcome {
    let Some(mint) = minting else {
        return std::future::pending().await;
    };
    let result = match (&mut mint.task.0).await {
        Ok(result) => result,
        Err(e) => Err(ContextError::CryptoFailed(format!(
            "key package mint task failed: {e}"
        ))),
    };
    MintOutcome {
        attested_by: mint.attested_by,
        result,
    }
}

/// Polls the signer check in flight, or never resolves when there is none.
async fn next_signer_check(checking: &mut Option<SignerCheck>) -> Result<(), ContextError> {
    let Some(check) = checking else {
        return std::future::pending().await;
    };
    match (&mut check.task.0).await {
        Ok(result) => result,
        Err(e) => Err(ContextError::CryptoFailed(format!(
            "attestation signer check task failed: {e}"
        ))),
    }
}

/// A copy of a refill's error for each reply waiting on the refill.
/// [`ContextError`] is not `Clone`; a mint or pool insert fails only with the
/// variants matched here, and any other is carried as
/// [`ContextError::CryptoFailed`] with its message.
fn refill_error_copy(e: &ContextError) -> ContextError {
    match e {
        ContextError::Custody(failure) => ContextError::Custody(failure.clone()),
        ContextError::AttestationSignerNotActiveKey => ContextError::AttestationSignerNotActiveKey,
        ContextError::AttestationSignerActiveKeyUnresolved => {
            ContextError::AttestationSignerActiveKeyUnresolved
        }
        ContextError::CryptoFailed(m) => ContextError::CryptoFailed(m.clone()),
        ContextError::PersistenceFailed(m) => ContextError::PersistenceFailed(m.clone()),
        other => ContextError::CryptoFailed(format!("key package refill failed: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Command enum
// ---------------------------------------------------------------------------

/// Commands the `KeyPackageStoreActor` accepts. Each variant carries a
/// `oneshot::Sender` for the reply; cancellation is via receiver drop.
pub enum KeyPackageCommand {
    /// Reserve one KP from the pool. Moves the entry into the `reserved`
    /// map and returns a fresh `ReservationId` plus the KP's PUBLIC bytes
    /// (for routing only — the private signer-state never leaves the actor).
    /// The caller is the Welcome-processing `ContextActor`; on join it sends
    /// `ConfirmConsume` (carrying the Welcome), on abandonment
    /// `CancelReservation`.
    Reserve {
        /// The `KpRef` identifying which KP to reserve.
        kp_ref: KpRef,
        /// Oneshot reply: `(ReservationId, public KP bytes)` on success.
        reply: oneshot::Sender<Result<(ReservationId, Vec<u8>), ContextError>>,
    },
    /// Atomically reserve the FIRST pooled KP: pick the first pooled ref and
    /// reserve it inside one command handler, or wait for the refill when the
    /// pool is empty.
    ///
    /// This is the reserve entrypoint the supervisor's `reserve_key_package`
    /// uses. Folding replenish + list-first-pooled + reserve into a single
    /// command closes the concurrency gap of composing them as three separate
    /// round-trips: because the actor owns `pool`/`reserved` and handlers run
    /// serialized on the mailbox loop, no interleaved command can observe the
    /// same pooled KP between the pick and the reserve, so two concurrent
    /// same-identity reserves get DISTINCT KeyPackages instead of the second
    /// spuriously failing `InvalidState("already reserved")` on a ref the first
    /// just took. Returns a fresh `ReservationId` plus the KP's PUBLIC bytes,
    /// exactly like [`Self::Reserve`]; the private signer-state never leaves the
    /// actor.
    ///
    /// The command carries the owner's attestation signer (§9.7.1), which
    /// the supervisor built only after resolving the owner's `#active` key and
    /// finding the signer holds it. It is the only way a signer reaches the
    /// store. A signer for another identity is refused with
    /// [`ContextError::InvalidState`] and nothing changes. A signer over the
    /// installed signer's key replaces it and the reserve proceeds. A signer
    /// over any other key waits its turn in a queue of signer checks, run one
    /// at a time off the command turn: the store resolves the owner's
    /// `#active` key again, and a signer whose key is no longer it (resolved
    /// before a rotation, delivered after a newer signer) is refused with
    /// [`ContextError::AttestationSignerNotActiveKey`], leaving the installed
    /// signer and the pool as they were. A signer that passes is installed:
    /// every pooled `KeyPackage` another key attested is burned (record
    /// deleted, unpublished, index rewritten, §9.12), and every `KeyPackage`
    /// minted from then on carries an attestation the signer made. More than
    /// [`MAX_PARKED_REPLIES`] queued checks is [`ContextError::ActorBusy`].
    ///
    /// On an empty pool the reply is parked until the refill pools a
    /// `KeyPackage`, which happens off the command turn; the store's pool fills
    /// on the first `ReserveAny`. A refill that pools nothing replies with its
    /// error. More than [`MAX_PARKED_REPLIES`] parked replies is
    /// [`ContextError::ActorBusy`].
    ReserveAny {
        /// The owner's attestation signer.
        signer: Arc<KeyPackageAttestationSigner>,
        /// Oneshot reply: `(ReservationId, public KP bytes)` on success.
        reply: oneshot::Sender<Result<(ReservationId, Vec<u8>), ContextError>>,
    },
    // NOTE: `kp_ref: KpRef` / `reservation_id: ReservationId` are distinct
    // newtypes — a caller cannot transpose one for the other.
    /// Confirm-consume a reservation by FUSING the join into the actor. The
    /// handler looks up the reserved KP's private signer-state (held
    /// internally), runs `join_from_welcome(welcome, signer_state, public)`
    /// internally, and — only on a successful join — durably records the
    /// consume (consumed-init-key marker via the backend + KP-record delete +
    /// reservation-id tombstone) BEFORE acking. The private signer-state never
    /// crosses the reply channel; the reply is the unit success of the fused
    /// join + durable consume. A failed join leaves the reservation intact for
    /// retry / cancel.
    ///
    /// The joined `ScpMlsGroup` is produced and validated INTERNALLY and, on a
    /// fresh successful confirm, MOVED out over the reply channel to the
    /// spawn-from-Welcome entrypoint (ADR-049 Phase 2J), which installs it into
    /// the live crypto provider so the joiner becomes a real send-capable
    /// participant. The private signer-state is embedded inside the group value
    /// (it owns its own OpenMLS provider + signer); it is never surfaced as raw
    /// bytes on the reserve path, so the "fused join" property is preserved —
    /// only the fully-formed group crosses the channel, not loose key material.
    ///
    /// # Retry idempotency (RE-CONFIRM AFTER A PARTIAL FAILURE IS SAFE)
    ///
    /// If a confirm partially fails AFTER the internal join completed but BEFORE
    /// the durable consume finished (e.g. the consumed-tombstone write failed),
    /// the reservation is deliberately RETAINED and the call replies `Err`. The
    /// integrator SHOULD simply retry `ConfirmConsume` with the SAME
    /// `reservation_id`. The retry is idempotent for the DURABLE CONSUME: the
    /// re-run inner join hits the already-written consumed-init-key marker
    /// (`MlsError::KeyPackageReplay`, which `join_from_welcome` returns before
    /// any lifetime check, so also once the KeyPackage has expired under
    /// either clock), which the handler recognizes as its OWN
    /// prior completion and finishes the durable consume (delete + tombstone +
    /// cleanup). Single-use still holds across the retry, and the retry can
    /// NEVER be coerced into a second or DIFFERENT join: an alternate welcome's
    /// init key is never consumed because the inner join short-circuits on the
    /// existing marker before processing the new welcome.
    ///
    /// **The joined group is NOT retained across confirms.** The group value is
    /// produced by the inner join and dropped if the first confirm returns `Err`
    /// (the durable-consume `?` propagates before the group is returned), and a
    /// replay-driven own-prior-completion retry has NO group to re-produce (the
    /// join short-circuited on the marker). So an own-prior-completion retry
    /// COMPLETES the durable consume but replies `Err(InvalidState)` — a
    /// tombstone-write failure loses the join, and the joiner must re-initiate
    /// with a FRESH key package. This is fail-closed: a lost group never leaves
    /// a half-consumed reservation reusable, and never silently succeeds without
    /// a group to install. A retry of a fully completed (already-consumed)
    /// reservation replies `InvalidState` — the reservation is gone.
    ///
    /// The own-prior-completion recognition does NOT rest on "the reservation is
    /// still live" alone. It additionally requires that THIS reservation's KP
    /// PRIVATE RECORD is ALREADY ABSENT — durable evidence that a prior join of
    /// THIS reservation ran (a real prior join deletes the KP record FIRST,
    /// fail-safe, before tombstoning). If a `KeyPackageReplay` fires while the KP
    /// record STILL EXISTS, the marker was NOT written by a completed prior join
    /// of this reservation, so it is surfaced as `KeyPackageReplay` — never a
    /// spurious `Ok` — closing the false-success chain a re-pool could otherwise
    /// ride.
    ///
    /// # Errors
    ///
    /// A failed inner join maps through `map_join_error`, and the reservation
    /// is kept:
    /// - [`ContextError::KeyPackageReplay`]: the reserved KeyPackage's init
    ///   key is already consumed and this reservation's KP record still exists,
    ///   so the marker is not this reservation's own prior completion.
    /// - [`ContextError::InvalidKeyPackage`]: the joiner's own reserved
    ///   KeyPackage is not current, under the injected clock or openmls's
    ///   clock, or its `Lifetime` range is empty, inverted or over the maximum
    ///   (`MlsError::KeyPackageLifetimeInvalid`). Cancel the reservation, or
    ///   retry after correcting the clock.
    /// - [`ContextError::CryptoFailed`]: every other join failure, chiefly a
    ///   Welcome or ratchet tree from the sender that the join rejects,
    ///   including another member's out-of-range tree leaf
    ///   (`MlsError::TreeLeafLifetimeRangeInvalid`). A retry with the same
    ///   Welcome reaches the same rejection; wait for another Welcome. A
    ///   failure to read or write the consumed-init-key store also maps here.
    ///
    /// Outside the join, an unknown or already-completed reservation, and an
    /// own-prior-completion retry, are [`ContextError::InvalidState`]; a failed
    /// KP-record or tombstone write is [`ContextError::PersistenceFailed`].
    ConfirmConsume {
        /// The reservation ID returned by [`Self::Reserve`].
        reservation_id: ReservationId,
        /// TLS-serialized MLS Welcome message addressed to the reserved KP.
        welcome_bytes: Vec<u8>,
        /// Oneshot reply: the joined [`ScpMlsGroup`] on a fresh successful
        /// fused join + durable consume (ADR-049 Phase 2J). The joined group
        /// is a self-contained value (it owns its OpenMLS provider + signer),
        /// so it is MOVED across the reply channel for the spawn-from-Welcome
        /// entrypoint to install into the live crypto provider — the private
        /// signer-state is embedded in the group, never surfaced as raw bytes.
        /// An idempotent retry of an already-consumed reservation replies
        /// `Err(InvalidState)` because the joined group is not retained across
        /// confirms (see the retry-idempotency note below).
        reply: oneshot::Sender<Result<ScpMlsGroup, ContextError>>,
    },
    // NOTE: `reservation_id` is a `ReservationId` newtype — distinct from
    // `KpRef`, so a kp_ref cannot be passed where a reservation_id is wanted.
    /// Cancel a reservation. OpenMLS KPs are single-use by spec, so the
    /// KP is discarded, not returned to the pool; this triggers a
    /// `Replenish` after the reply if the pool size dropped below the
    /// low-water mark.
    CancelReservation {
        /// The reservation ID returned by [`Self::Reserve`].
        reservation_id: ReservationId,
        /// Oneshot reply.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Explicitly replenish the pool up to [`MIN_BUFFER`]. The reply waits for
    /// the refill, which mints off the command turn, and carries the count of
    /// KPs it pooled after this command arrived: `Ok(0)` when the pool is
    /// already full, `Ok(n)` when it pooled `n` before it ended or failed, and
    /// the failure when it pooled none. Without an installed attestation
    /// signer it replies [`ContextError::NotInitialized`] at once.
    Replenish {
        /// Oneshot reply: count of KPs added to the pool.
        reply: oneshot::Sender<Result<usize, ContextError>>,
    },
    /// Publish every not-yet-published pooled public KP through the transport
    /// under the owning identity's canonical KeyPackage routing id. Idempotent.
    /// Routing is per-`owner_did`: the transport routes each KP to its own
    /// adapter connection, so each KP is published exactly ONCE — there is no
    /// per-relay-URL fan-out, and therefore no caller-supplied relay list (a
    /// relay-URL vector would falsely imply a fan-out that never happens).
    Publish {
        /// Oneshot reply.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// List the currently POOLED (unreserved) KeyPackages as `(KpRef, public
    /// bytes)` pairs, so a (future 2E) integrator can DISCOVER which KPs are
    /// available to reserve through the handle alone — without a private
    /// `derive_kp_ref` or a hand-minted [`KpRef`]. Read-only: it does not move
    /// any KP out of the pool. The returned `KpRef` is the actor's content hash
    /// (`hex(SHA-256(public_bytes))`); reserve flows by passing one back in a
    /// [`Self::Reserve`].
    ///
    /// MLS-ref matching is a 2E concern: an incoming Welcome carries an MLS
    /// `KeyPackageRef`, which is NOT this `KpRef`. The caller maps a Welcome to
    /// a pooled KP by computing the MLS ref ITSELF from the returned
    /// `public_bytes` (the two are distinct derivations over the same bytes);
    /// this command deliberately exposes the public bytes so that mapping is
    /// possible without leaking any private signer-state.
    ListPooled {
        /// Oneshot reply: the pooled `(KpRef, public KP bytes)` pairs. Empty
        /// when the pool is empty.
        reply: oneshot::Sender<Result<PooledKeyPackages, ContextError>>,
    },
    /// Read the `0xFF01` `scp_wrapping_key` of a reserved KeyPackage
    /// (§9.16.1), from the KeyPackage bundle in the reservation's own signer
    /// state. Read-only: the reservation stays live. The joiner checks it
    /// against its custody wrapping key before it opens an invitation or
    /// consumes the reservation (spec 05 §5.12.3.1, §9.16.2 Open step 2).
    ReservedWrappingKey {
        /// The reservation to read.
        reservation_id: ReservationId,
        /// Oneshot reply: the reserved KeyPackage's `0xFF01`. An unknown or
        /// consumed reservation is [`ContextError::InvalidState`]; a
        /// KeyPackage without `0xFF01`, or an unreadable signer state, is
        /// [`ContextError::InvalidKeyPackage`].
        reply: oneshot::Sender<Result<P256Point, ContextError>>,
    },
    /// Test-only fault-injection seam: panic the actor task so the watchdog's
    /// crash/poison/respawn path can be exercised deterministically. Gated
    /// behind the `testing` feature so it cannot exist in a production build.
    /// The `panic!` lives in the dispatch loop (not a handler) and is
    /// `testing`-gated, so the per-context panic-ban gate stays green.
    #[cfg(feature = "testing")]
    TestInducePanic {
        /// Sentinel string the panic carries (verified absent from logs).
        sentinel: String,
    },
    /// Terminal command — the actor's `run()` loop exits after this is
    /// observed. No reply channel: callers dropping the handle is the
    /// observable effect.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Caller-side handle for a `KeyPackageStoreActor`. Cheap to clone
/// (wraps `mpsc::Sender<KeyPackageCommand>`).
#[derive(Clone)]
pub struct KeyPackageStoreHandle {
    inbox: mpsc::Sender<KeyPackageCommand>,
}

impl KeyPackageStoreHandle {
    /// Wraps a raw sender. `pub(in crate::context)` matches
    /// `ContextActorHandle::from_sender` — only the supervisor
    /// constructs handles.
    #[must_use]
    pub(in crate::context) const fn from_sender(inbox: mpsc::Sender<KeyPackageCommand>) -> Self {
        Self { inbox }
    }

    /// Submit a command and await its reply. See
    /// [`ContextActorHandle::send`](crate::context::actor::handle::ContextActorHandle::send)
    /// for full semantics — this method follows the same shape.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] — mailbox full for
    ///   [`KP_SEND_TIMEOUT`], or the actor did not reply within
    ///   [`KP_REPLY_TIMEOUT`] after enqueue (wedged/backed-up actor), or inbox
    ///   closed, or the actor dropped the reply channel.
    /// - The handler's typed error.
    pub async fn send<T, F>(&self, cmd_factory: F) -> Result<T, ContextError>
    where
        F: FnOnce(oneshot::Sender<Result<T, ContextError>>) -> KeyPackageCommand,
    {
        let (tx, rx) = oneshot::channel::<Result<T, ContextError>>();
        let cmd = cmd_factory(tx);

        match tokio::time::timeout(KP_SEND_TIMEOUT, self.inbox.send(cmd)).await {
            // Enqueued: bound the reply-await too. A stuck/slow actor (e.g. hung
            // inside a storage/transport call) must never pin the caller — a
            // bootstrap path — forever (#129). On elapse, fail-closed with a
            // retryable `ActorBusy`, matching the enqueue-timeout taxonomy;
            // never a silent default.
            Ok(Ok(())) => match tokio::time::timeout(KP_REPLY_TIMEOUT, rx).await {
                Ok(Ok(reply)) => reply,
                Ok(Err(_dropped)) => Err(ContextError::ActorBusy(
                    "key-package actor dropped reply channel".to_owned(),
                )),
                Err(_elapsed) => Err(ContextError::ActorBusy(format!(
                    "key-package actor did not reply within {} seconds",
                    KP_REPLY_TIMEOUT.as_secs()
                ))),
            },
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "key-package actor inbox is closed".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(format!(
                "key-package actor mailbox full for {} seconds",
                KP_SEND_TIMEOUT.as_secs()
            ))),
        }
    }

    /// Test-only: send the fault-injection panic command.
    ///
    /// # Errors
    ///
    /// Returns `ContextError::ActorBusy` if the mailbox is full or closed.
    #[cfg(feature = "testing")]
    pub async fn send_induce_panic(&self, sentinel: impl Into<String>) -> Result<(), ContextError> {
        let cmd = KeyPackageCommand::TestInducePanic {
            sentinel: sentinel.into(),
        };
        match tokio::time::timeout(KP_SEND_TIMEOUT, self.inbox.send(cmd)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "key-package actor inbox is closed".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(
                "key-package actor mailbox full on induce-panic".to_owned(),
            )),
        }
    }

    /// Fire-and-forget shutdown. Drops the supervisor's reference to the
    /// handle; the actor observes the refcount reaching zero (when all
    /// clones drop) or the terminal `Shutdown` command.
    ///
    /// # Errors
    ///
    /// Returns `ContextError::ActorBusy` if the mailbox is full for
    /// `KP_SEND_TIMEOUT` or the inbox is closed.
    pub async fn send_shutdown(&self) -> Result<(), ContextError> {
        match tokio::time::timeout(
            KP_SEND_TIMEOUT,
            self.inbox.send(KeyPackageCommand::Shutdown),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "key-package actor inbox is closed".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(
                "key-package actor mailbox full on shutdown".to_owned(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Actor dependencies
// ---------------------------------------------------------------------------

/// The owned collaborators a [`KeyPackageStoreActor`] needs. Assembled by the
/// supervisor's `key_package_store_for` from its own provider slots and moved
/// into the actor task at spawn time.
pub(in crate::context) struct KeyPackageStoreDeps {
    /// MLS primitives backend — the replenish source AND the fused-join
    /// executor (its `join_from_welcome` enforces the crypto-layer
    /// consumed-init-key backstop).
    pub mls: Arc<dyn MlsBackend>,
    /// Durable KV for the Class-S reservation journal + KP records.
    pub mls_storage: Arc<dyn OpenMlsStorageAdapter>,
    /// Transport for the publish fan-out.
    pub transport: Arc<dyn ContextTransportProvider>,
    /// Wall-clock source for reservation timestamps.
    pub clock: Arc<dyn Clock>,
    /// The owning identity's wrapping key (spec 09 §9.16.1), shared with
    /// the supervisor. Every KeyPackage publishes its public point in
    /// `0xFF01`.
    pub wrapping_key: Arc<IdentityWrappingKey>,
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// One per local identity. Owns the KeyPackage pool and the reservation map.
///
/// Handlers run on the single mailbox loop, so all `&mut self` mutations are
/// serialized — there are no internal locks. Private signer-state bytes are
/// wrapped in [`Zeroizing`] so they zero on drop, and they NEVER cross the
/// reply channel (the join is fused into `Self::handle_confirm`).
pub struct KeyPackageStoreActor {
    /// The identity this actor owns the pool for.
    identity: DID,
    /// The owner's `KeyPackage` attestation signer (§9.7.1), installed by the
    /// first [`KeyPackageCommand::ReserveAny`]. Without one the actor mints,
    /// reserves, lists and publishes nothing, so it never serves a
    /// `KeyPackage` whose attesting key it cannot vouch for.
    attestation_signer: Option<Arc<KeyPackageAttestationSigner>>,
    /// The mint in flight, polled alongside the mailbox.
    minting: Option<MintTask>,
    /// The signer check in flight, polled alongside the mailbox.
    checking: Option<SignerCheck>,
    /// `ReserveAny` commands waiting for their signer check.
    signer_checks: VecDeque<(Arc<KeyPackageAttestationSigner>, ReserveReply)>,
    /// Spawns the mint and signer-check subtasks onto the Supervisor's task
    /// tracker (ADR-049 Decision 16).
    subtasks: super::supervisor::SubtaskSpawner,
    /// The refill in progress, if any.
    refill: Option<Refill>,
    /// `ReserveAny` replies waiting for the refill to pool a `KeyPackage`.
    parked_reserves: VecDeque<ReserveReply>,
    /// Refs of superseded `KeyPackages` whose record delete failed. The index
    /// keeps naming them so a respawn still reaches the record, and each
    /// signer install retries the delete.
    stale_refs: HashSet<KpRef>,
    /// The owning identity's wrapping key (§9.16.1), whose public point every
    /// KeyPackage publishes.
    wrapping_key: Arc<IdentityWrappingKey>,
    /// MLS primitives backend — the replenish source + fused-join executor.
    mls: Arc<dyn MlsBackend>,
    /// Durable KV for the Class-S reservation journal + KP records.
    mls_storage: Arc<dyn OpenMlsStorageAdapter>,
    /// Transport for the publish fan-out.
    transport: Arc<dyn ContextTransportProvider>,
    /// Wall-clock source.
    clock: Arc<dyn Clock>,
    /// Unreserved usable KeyPackages.
    pool: Vec<PooledKeyPackage>,
    /// Reservations awaiting confirm/cancel, keyed by `ReservationId`.
    reserved: HashMap<ReservationId, ReservedKeyPackage>,
    /// Refs already published through the transport (Class-C liveness;
    /// re-published on respawn, which is harmless). Keyed by `kp_ref` alone:
    /// the transport publishes each `KeyPackage` exactly once through its own
    /// adapter connection (routing is per-`owner_did`, not per relay URL), so
    /// there is no per-relay fan-out to track.
    published_refs: HashSet<KpRef>,
    /// Inbox receiver paired with `KeyPackageStoreHandle::inbox`.
    inbox: mpsc::Receiver<KeyPackageCommand>,
}

impl KeyPackageStoreActor {
    /// Spawns a new actor task onto a task tracker of its own and returns
    /// its handle and `JoinHandle`. Test-only: production spawns through
    /// [`Self::spawn_through`] and the Supervisor's task tracker (ADR-049
    /// Decision 16).
    #[cfg(test)]
    pub(in crate::context) fn spawn(
        identity: DID,
        deps: KeyPackageStoreDeps,
    ) -> (KeyPackageStoreHandle, tokio::task::JoinHandle<()>) {
        let subtasks = super::supervisor::SubtaskSpawner::standalone();
        let (handle, actor) = Self::new(identity, deps, subtasks.clone());
        (handle, subtasks.spawn(actor.run()))
    }

    /// Like [`Self::spawn`], with `signer` installed through
    /// [`Self::install_attestation_signer`] (the path `ReserveAny` takes)
    /// before the actor serves its first command, so a test can drive
    /// `Replenish` without reserving first.
    #[cfg(test)]
    pub(in crate::context) fn spawn_with_signer(
        identity: DID,
        deps: KeyPackageStoreDeps,
        signer: Arc<KeyPackageAttestationSigner>,
    ) -> (KeyPackageStoreHandle, tokio::task::JoinHandle<()>) {
        let subtasks = super::supervisor::SubtaskSpawner::standalone();
        let (handle, mut actor) = Self::new(identity, deps, subtasks.clone());
        (
            handle,
            subtasks.spawn(async move {
                if let Err(e) = actor.reconcile_from_storage().await {
                    tracing::error!(error = %e, "test spawn: reconcile failed");
                }
                if let Err(e) = actor.install_attestation_signer(signer).await {
                    tracing::error!(error = %e, "test spawn: signer install refused");
                }
                actor.serve().await;
            }),
        )
    }

    /// Builds a new actor and spawns it through `permit` onto the
    /// Supervisor's task tracker (ADR-049 Decision 16), returning its handle
    /// and `JoinHandle`. The Supervisor attaches a watchdog to the
    /// `JoinHandle` (mirroring the per-context actor watchdog, ADR-049 §10).
    /// On spawn the actor runs the §9 respawn reconciliation from
    /// `mls_storage` before serving commands. It mints nothing until the
    /// first [`KeyPackageCommand::ReserveAny`] installs the owner's
    /// attestation signer; the pool fills on that first reserve.
    ///
    /// The returned handle is the only way to reach the actor — the
    /// `mpsc::Receiver<KeyPackageCommand>` moves into the actor and never
    /// escapes.
    pub(in crate::context) fn spawn_through(
        permit: &super::supervisor::SpawnPermit<'_>,
        identity: DID,
        deps: KeyPackageStoreDeps,
    ) -> (KeyPackageStoreHandle, tokio::task::JoinHandle<()>) {
        let (handle, actor) = Self::new(identity, deps, permit.subtask_spawner());
        (handle, permit.spawn(actor.run()))
    }

    /// Builds a new actor and its handle without spawning it. Private, with
    /// [`Self::run`], so no caller can spawn the actor off the tracker.
    /// `subtasks` spawns the actor's mints and signer checks.
    fn new(
        identity: DID,
        deps: KeyPackageStoreDeps,
        subtasks: super::supervisor::SubtaskSpawner,
    ) -> (KeyPackageStoreHandle, Self) {
        let (tx, rx) = mpsc::channel::<KeyPackageCommand>(KP_MAILBOX_CAPACITY);

        let actor = Self {
            identity,
            attestation_signer: None,
            minting: None,
            checking: None,
            signer_checks: VecDeque::new(),
            subtasks,
            refill: None,
            parked_reserves: VecDeque::new(),
            stale_refs: HashSet::new(),
            wrapping_key: deps.wrapping_key,
            mls: deps.mls,
            mls_storage: deps.mls_storage,
            transport: deps.transport,
            clock: deps.clock,
            pool: Vec::new(),
            reserved: HashMap::new(),
            published_refs: HashSet::new(),
            inbox: rx,
        };
        (KeyPackageStoreHandle::from_sender(tx), actor)
    }

    // -----------------------------------------------------------------
    // Durable journal key helpers
    // -----------------------------------------------------------------

    fn kp_record_key(&self, kp_ref: &KpRef) -> String {
        format!("{KP_RECORD_PREFIX}/{}/{kp_ref}", self.identity.0)
    }

    fn reservation_key(&self, reservation_id: &ReservationId) -> String {
        format!(
            "{KP_RESERVATION_PREFIX}/{}/{reservation_id}",
            self.identity.0
        )
    }

    fn consumed_key(&self, reservation_id: &ReservationId) -> String {
        format!("{KP_CONSUMED_PREFIX}/{}/{reservation_id}", self.identity.0)
    }

    fn index_key(&self) -> String {
        format!("{KP_INDEX_PREFIX}/{}", self.identity.0)
    }

    fn reservation_ids_key(&self) -> String {
        format!("{KP_RESERVATION_IDS_PREFIX}/{}", self.identity.0)
    }

    /// Derive the stable `kp_ref` for a KeyPackage's public bytes:
    /// `hex(SHA-256(key_package_bytes))`. Stable across processes and serves as
    /// the durable record key; nothing else (no shared OpenMLS keystore) keys
    /// this KP, so the record IS the journal single-use anchor. Delegates to
    /// the public [`KpRef::from_public_bytes`] constructor so the derivation
    /// lives in exactly one place.
    fn derive_kp_ref(public_bytes: &[u8]) -> KpRef {
        KpRef::from_public_bytes(public_bytes)
    }

    /// Map an [`MlsError`] from the fused join to a typed [`ContextError`].
    /// Each lifetime variant names one party's leaf (ADR-057 §Prereq-1):
    ///
    /// - A replay rejection (the crypto-layer consumed-init-key backstop) maps
    ///   to the dedicated [`ContextError::KeyPackageReplay`], distinct from
    ///   [`ContextError::InvalidState`] (which also means "unknown
    ///   reservation"), so a caller can detect a security-relevant single-use
    ///   replay.
    /// - [`MlsError::KeyPackageLifetimeInvalid`] names the caller's OWN reserved
    ///   KeyPackage: its `Lifetime` is expired or not yet valid under the
    ///   injected clock (or under openmls's internal clock in the native
    ///   backend), or its range is empty, inverted or over the maximum. It
    ///   maps to [`ContextError::InvalidKeyPackage`]. The native backend
    ///   checks the injected clock before openmls's, so an expired own
    ///   KeyPackage is `InvalidKeyPackage` whichever clock reads it, never
    ///   `CryptoFailed`.
    /// - [`MlsError::TreeLeafLifetimeRangeInvalid`] names ANOTHER member's leaf
    ///   in the sender's tree whose range is empty, inverted or over the
    ///   maximum. It is not the caller's KeyPackage, so it maps, with every
    ///   other error, to [`ContextError::CryptoFailed`]. No dedicated error
    ///   variant for a rejected Welcome exists yet.
    fn map_join_error(e: &MlsError) -> ContextError {
        match e {
            MlsError::KeyPackageReplay => ContextError::KeyPackageReplay(
                "key package already consumed (init-key replay rejected)".to_owned(),
            ),
            own @ MlsError::KeyPackageLifetimeInvalid { .. } => {
                ContextError::InvalidKeyPackage(format!("join from welcome: {own}"))
            }
            other => ContextError::CryptoFailed(format!("join from welcome: {other}")),
        }
    }

    // -----------------------------------------------------------------
    // Durable journal read/write
    // -----------------------------------------------------------------

    /// Load the live KP-ref index. Missing key → empty.
    async fn load_index(&self) -> Result<Vec<KpRef>, ContextError> {
        match self.mls_storage.retrieve(&self.index_key()).await {
            Ok(Some(bytes)) => rmp_serde::from_slice::<Vec<KpRef>>(&bytes)
                .map_err(|e| ContextError::PersistenceFailed(format!("kp index decode: {e}"))),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(ContextError::PersistenceFailed(format!(
                "kp index retrieve: {e}"
            ))),
        }
    }

    /// Persist the live KP-ref index derived from the current `pool` +
    /// `reserved` sets (both reference live KP records). The MessagePack
    /// scratch buffer is plain `Vec<String>` (public refs, no secrets), so it
    /// is not zeroized.
    async fn persist_index(&self) -> Result<(), ContextError> {
        let mut refs: Vec<KpRef> = self.pool.iter().map(|p| p.kp_ref.clone()).collect();
        refs.extend(self.reserved.values().map(|r| r.kp_ref.clone()));
        refs.extend(self.stale_refs.iter().cloned());
        let bytes = rmp_serde::to_vec_named(&refs)
            .map_err(|e| ContextError::PersistenceFailed(format!("kp index encode: {e}")))?;
        self.mls_storage
            .store(&self.index_key(), &bytes)
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("kp index store: {e}")))
    }

    /// Persist the live index, logging (not failing) on error. The index is a
    /// Class-C liveness aid — the KP records it points at are the durable
    /// truth, so a failed index write degrades reconciliation completeness but
    /// never the single-use / no-double-consume invariant. `phase` tags the
    /// log line with the calling handler.
    async fn persist_index_best_effort(&self, phase: &str) {
        if let Err(e) = self.persist_index().await {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                phase,
                error = %e,
                "index persist failed (KP records still durable)"
            );
        }
    }

    /// Persist the live reservation-id set, logging (not failing) on error.
    /// Best-effort variant for the confirm/cancel cleanup paths where the
    /// consume/cancel is already durable.
    async fn persist_reservation_ids_best_effort(&self, phase: &str) {
        if let Err(e) = self.persist_reservation_ids(None).await {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                phase,
                error = %e,
                "reservation-ids persist failed (consume already durable)"
            );
        }
    }

    /// Persist the live reservation-id set PLUS one extra `retain` rid that is
    /// no longer in `self.reserved`, logging (not failing) on error.
    ///
    /// Used by the confirm cleanup tail when a best-effort reservation-record or
    /// tombstone delete failed: the consumed rid is no longer a live reservation
    /// (so `persist_reservation_ids` would prune it), but its surviving durable
    /// record(s) must stay reachable via the id-set so a later reconcile/GC pass
    /// can reclaim them. Keeping the rid enumerable is safe: reconcile reads the
    /// tombstone (retained alongside) FIRST and resolves the rid as CONSUMED, so
    /// it is never restored as a live `reserved` entry.
    async fn persist_reservation_ids_retaining_best_effort(
        &self,
        retain: &ReservationId,
        phase: &str,
    ) {
        if let Err(e) = self.persist_reservation_ids(Some(retain)).await {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                phase,
                error = %e,
                "reservation-ids persist (retaining consumed rid for GC) failed \
                 (consume already durable)"
            );
        }
    }

    /// Persist the live reservation-id set PLUS a (possibly empty) SET of `retain`
    /// rids, logging (not failing) on error.
    ///
    /// Used by the reconcile self-heal tail: the GC pass returns the consumed
    /// rids it could not fully reclaim this pass (record still present, or a
    /// best-effort delete failed). Those rids must stay enumerable in the durable
    /// id-set so a later reconcile/GC pass can reach and finish reclaiming their
    /// surviving record(s); the unconditional tail rewrite (built from
    /// `self.reserved` alone) would otherwise prune them and sever reachability.
    /// An empty `retain` reduces to the plain live-keys rewrite.
    async fn persist_reservation_ids_retaining_many_best_effort(
        &self,
        retain: &[ReservationId],
        phase: &str,
    ) {
        if let Err(e) = self.persist_reservation_ids_retaining_slice(retain).await {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                phase,
                error = %e,
                "reservation-ids persist (retaining GC-incomplete rids) failed \
                 (single-use truth unaffected)"
            );
        }
    }

    /// Persist one KP record (public + private signer-state). The `MessagePack`
    /// buffer carries the private signer-state, so it is held in a buffer
    /// wiped on drop (security model spec §9.15 step 2; mirrors
    /// `serialize_signer_state`).
    async fn persist_kp_record(
        &self,
        kp_ref: &KpRef,
        public_bytes: &[u8],
        signer_state: &[u8],
        attested_by: [u8; 32],
    ) -> Result<(), ContextError> {
        let record = PersistedKeyPackage {
            public_bytes: public_bytes.to_vec(),
            signer_state: Zeroizing::new(signer_state.to_vec()),
            attested_by,
        };
        let bytes = rmp_serde::to_vec_named(&record)
            .map(Zeroizing::new)
            .map_err(|e| ContextError::PersistenceFailed(format!("kp record encode: {e}")))?;
        self.mls_storage
            .store(&self.kp_record_key(kp_ref), &bytes)
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("kp record store: {e}")))
    }

    /// Whether one KP private record currently exists in durable storage.
    /// Used by the confirm retry-idempotency guard: a real prior join of a
    /// reservation deletes the KP record (fail-safe B1 ordering) BEFORE writing
    /// the consumed tombstone, so record-absence is durable evidence that a
    /// prior join of THIS reservation already ran.
    async fn kp_record_exists(&self, kp_ref: &KpRef) -> Result<bool, ContextError> {
        self.mls_storage
            .retrieve(&self.kp_record_key(kp_ref))
            .await
            .map(|opt| opt.is_some())
            .map_err(|e| ContextError::PersistenceFailed(format!("kp record retrieve: {e}")))
    }

    /// Durably delete one KP record (the journal single-use anchor delete).
    async fn delete_kp_record(&self, kp_ref: &KpRef) -> Result<(), ContextError> {
        self.mls_storage
            .delete(&self.kp_record_key(kp_ref))
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("kp record delete: {e}")))
    }

    // -----------------------------------------------------------------
    // Run loop
    // -----------------------------------------------------------------

    /// Dispatch loop. On startup runs the §9 reconciliation, then serves
    /// commands until the inbox closes or a `Shutdown` command arrives. It
    /// mints nothing until a `ReserveAny` installs the owner's attestation
    /// signer.
    async fn run(mut self) {
        if let Err(e) = self.reconcile_from_storage().await {
            tracing::error!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                error = %e,
                "key-package actor reconciliation failed on spawn; serving from empty pool"
            );
        }
        self.serve().await;
    }

    /// Serves the mailbox, the mint in flight and the signer check in flight
    /// together. A mint (resolver and custody sign) and a signer check
    /// (resolver) each run as a subtask this loop polls, never inside a
    /// command turn, so a `ConfirmConsume` is handled while a custody sign or
    /// a resolution is still pending.
    async fn serve(mut self) {
        loop {
            tokio::select! {
                cmd = self.inbox.recv() => match cmd {
                    None | Some(KeyPackageCommand::Shutdown) => break,
                    #[cfg(feature = "testing")]
                    Some(KeyPackageCommand::TestInducePanic { sentinel }) => {
                        #[allow(clippy::panic)]
                        {
                            panic!("{sentinel}");
                        }
                    }
                    Some(other) => self.dispatch(other).await,
                },
                outcome = next_mint(&mut self.minting) => self.handle_minted(outcome).await,
                checked = next_signer_check(&mut self.checking) => {
                    self.handle_signer_checked(checked).await;
                }
            }
        }
    }

    /// Dispatch one (non-Shutdown, non-test) command to its handler.
    async fn dispatch(&mut self, cmd: KeyPackageCommand) {
        match cmd {
            KeyPackageCommand::Reserve { kp_ref, reply } => {
                let result = self.handle_reserve(kp_ref).await;
                let _ = reply.send(result);
                // Auto-replenish (and sweep expired reservations) after a
                // successful reserve drops the pool.
                self.maybe_replenish().await;
            }
            KeyPackageCommand::ReserveAny { signer, reply } => {
                self.admit_reserve_any(signer, reply).await;
            }
            KeyPackageCommand::ConfirmConsume {
                reservation_id,
                welcome_bytes,
                reply,
            } => {
                let result = self.handle_confirm(reservation_id, &welcome_bytes).await;
                let _ = reply.send(result);
            }
            KeyPackageCommand::CancelReservation {
                reservation_id,
                reply,
            } => {
                let result = self.handle_cancel(reservation_id).await;
                let _ = reply.send(result);
                self.maybe_replenish().await;
            }
            KeyPackageCommand::Replenish { reply } => self.handle_replenish(reply),
            KeyPackageCommand::Publish { reply } => {
                let result = self.handle_publish().await;
                let _ = reply.send(result);
            }
            KeyPackageCommand::ListPooled { reply } => {
                let _ = reply.send(self.handle_list_pooled());
            }
            KeyPackageCommand::ReservedWrappingKey {
                reservation_id,
                reply,
            } => {
                let result = self.handle_reserved_wrapping_key(reservation_id).await;
                let _ = reply.send(result);
            }
            // Shutdown + TestInducePanic are handled in `serve()`; included
            // for exhaustiveness.
            KeyPackageCommand::Shutdown => {}
            #[cfg(feature = "testing")]
            KeyPackageCommand::TestInducePanic { .. } => {}
        }
    }

    // -----------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------

    /// Reserve a KP by ref. Class-S: the reservation-id SET (the single
    /// enumerable anchor reconcile reads) is persisted fail-closed BEFORE the
    /// ack, folded with the per-reservation record into one consistent write
    /// pair with no orphan window: the per-reservation record is written
    /// first, then the id-set; on EITHER failure the KP is returned to the
    /// pool and the call replies `Err` (fail-closed — no ack of a reservation
    /// we did not durably anchor). Returns only `(ReservationId, public
    /// bytes)` — the private signer-state stays in `reserved`.
    async fn handle_reserve(
        &mut self,
        kp_ref: KpRef,
    ) -> Result<(ReservationId, Vec<u8>), ContextError> {
        // Ceiling on outstanding reservations (anti-leak / anti-flood).
        if self.reserved.len() >= MAX_OUTSTANDING_RESERVATIONS {
            return Err(ContextError::LimitExceeded(format!(
                "key package reservation ceiling reached ({MAX_OUTSTANDING_RESERVATIONS})"
            )));
        }

        // Reject a ref already reserved (double-reserve of the same KP).
        if self.reserved.values().any(|r| r.kp_ref == kp_ref) {
            return Err(ContextError::InvalidState(format!(
                "key package '{kp_ref}' already reserved"
            )));
        }

        // Only a KeyPackage the installed signer's `#active` key attested is
        // available (§9.7.1, §9.12).
        let active = self.active_attesting_key()?;
        let Some(pos) = self
            .pool
            .iter()
            .position(|p| p.kp_ref == kp_ref && p.attested_by == active)
        else {
            return Err(ContextError::InvalidKeyPackage(format!(
                "no pooled key package with ref '{kp_ref}' attested by the current #active key"
            )));
        };
        let entry = self.pool.remove(pos);
        let public_bytes = entry.public_bytes;
        let signer_state = entry.signer_state;
        let attested_by = entry.attested_by;

        let reservation_id = ReservationId::new_random();
        let reserved_at_ms = self.clock.now_millis();

        // Move the reservation into memory FIRST so the id-set persist (below)
        // enumerates it. On any persist failure we fully roll back.
        self.reserved.insert(
            reservation_id.clone(),
            ReservedKeyPackage {
                kp_ref: kp_ref.clone(),
                public_bytes: public_bytes.clone(),
                signer_state,
                attested_by,
                reserved_at_ms,
            },
        );

        // Class-S write pair (no orphan window):
        // 1. the per-reservation record (kp_ref + mint time), then
        // 2. the enumerable reservation-id set — the anchor reconcile reads.
        // The record is written before the id-set so that any id the set
        // enumerates always resolves to a record; a crash after (1) but before
        // (2) leaves an unreferenced record that reconcile never reaches (it
        // is not in the id-set), which is harmless. A crash after (2) restores
        // the reservation as `reserved` (non-poolable). On either persist
        // failure: roll back (remove the reservation, return the KP to the
        // pool, best-effort delete the record) and ack nothing.
        let record = PersistedReservation {
            kp_ref: kp_ref.clone(),
            reserved_at_ms,
        };
        let record_persist = match rmp_serde::to_vec_named(&record) {
            Ok(bytes) => self
                .mls_storage
                .store(&self.reservation_key(&reservation_id), &bytes)
                .await
                .map_err(|e| ContextError::PersistenceFailed(format!("reservation store: {e}"))),
            Err(e) => Err(ContextError::PersistenceFailed(format!(
                "reservation encode: {e}"
            ))),
        };
        if let Err(e) = record_persist {
            self.rollback_reserve(&reservation_id, kp_ref, public_bytes);
            return Err(e);
        }

        if let Err(e) = self.persist_reservation_ids(None).await {
            // Roll back the in-memory reservation + KP, and best-effort delete
            // the record we just wrote so it does not linger.
            self.rollback_reserve(&reservation_id, kp_ref, public_bytes);
            if let Err(del) = self
                .mls_storage
                .delete(&self.reservation_key(&reservation_id))
                .await
            {
                tracing::error!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %del,
                    "reserve rollback: reservation record delete failed (best-effort)"
                );
            }
            return Err(e);
        }

        Ok((reservation_id, public_bytes))
    }

    /// The `#active` key of the installed attestation signer: the only key
    /// whose `KeyPackages` the store reserves, publishes or lists.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotInitialized`] before a `ReserveAny` installs a
    /// signer.
    fn active_attesting_key(&self) -> Result<[u8; 32], ContextError> {
        self.attestation_signer
            .as_ref()
            .map(|s| s.active_key().to_bytes())
            .ok_or_else(|| {
                ContextError::NotInitialized(
                    "key-package store has no attestation signer; a reserve installs the \
                     owner's #active signer"
                        .to_owned(),
                )
            })
    }

    /// `KeyPackages` the store holds or has promised: pooled plus reserved.
    fn stock(&self) -> usize {
        self.pool.len() + self.reserved.len()
    }

    /// The installed attestation signer's key, if one is installed.
    fn installed_key(&self) -> Option<[u8; 32]> {
        self.attestation_signer
            .as_ref()
            .map(|s| s.active_key().to_bytes())
    }

    /// Admits a `ReserveAny`. A signer for another identity is refused. A
    /// signer over the installed signer's key, with no check queued ahead of
    /// it, replaces the installed signer (nothing is burned, the key is the
    /// same) and the reserve is served. Any other signer joins the queue of
    /// signer checks.
    async fn admit_reserve_any(
        &mut self,
        signer: Arc<KeyPackageAttestationSigner>,
        reply: ReserveReply,
    ) {
        if signer.owner() != &self.identity {
            let _ = reply.send(Err(ContextError::InvalidState(
                "attestation signer owner mismatch".to_owned(),
            )));
            return;
        }
        if self.checking.is_none()
            && self.signer_checks.is_empty()
            && self.installed_key() == Some(signer.active_key().to_bytes())
        {
            self.attestation_signer = Some(signer);
            self.serve_reserve_any(reply).await;
            return;
        }
        if self.signer_checks.len() >= MAX_PARKED_REPLIES {
            let _ = reply.send(Err(ContextError::ActorBusy(format!(
                "key package store has {MAX_PARKED_REPLIES} reserves waiting for a signer check"
            ))));
            return;
        }
        self.signer_checks.push_back((signer, reply));
        self.start_next_signer_check().await;
    }

    /// Starts the next queued signer check when none runs. A queued signer
    /// over the installed signer's key needs no check and is served at once;
    /// a queued reply whose caller has gone is dropped.
    async fn start_next_signer_check(&mut self) {
        while self.checking.is_none() {
            let Some((signer, reply)) = self.signer_checks.pop_front() else {
                return;
            };
            if reply.is_closed() {
                continue;
            }
            if self.installed_key() == Some(signer.active_key().to_bytes()) {
                self.attestation_signer = Some(signer);
                self.serve_reserve_any(reply).await;
                continue;
            }
            let checked = Arc::clone(&signer);
            let task = self
                .subtasks
                .spawn(async move { checked.confirm_still_active().await });
            self.checking = Some(SignerCheck {
                signer,
                reply,
                task: AbortOnDrop(task),
            });
        }
    }

    /// Takes the finished signer check. A signer whose key is still the
    /// owner's `#active` key is installed and its reserve served; any other
    /// outcome refuses the reserve and leaves the installed signer and the
    /// pool as they were. Then the next queued check starts.
    async fn handle_signer_checked(&mut self, checked: Result<(), ContextError>) {
        let Some(SignerCheck { signer, reply, .. }) = self.checking.take() else {
            return;
        };
        match checked {
            Ok(()) => match self.install_attestation_signer(signer).await {
                Ok(()) => self.serve_reserve_any(reply).await,
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            },
            Err(e) => {
                tracing::warn!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %e,
                    "reserve refused: its attestation signer's key is not the owner's \
                     #active key; the installed signer and the pool are unchanged"
                );
                let _ = reply.send(Err(e));
            }
        }
        self.start_next_signer_check().await;
    }

    /// Serves a `ReserveAny` whose signer is installed, then replenishes.
    async fn serve_reserve_any(&mut self, reply: ReserveReply) {
        self.handle_reserve_any(reply).await;
        self.maybe_replenish().await;
    }

    /// Installs `signer` as the owner's attestation signer, then burns every
    /// pooled `KeyPackage` another key attested (§9.12, rotation is
    /// revocation). A `ReserveAny` reaches this only after its signer check
    /// found the signer's key is still the owner's `#active` key.
    ///
    /// # Errors
    ///
    /// [`ContextError::InvalidState`] when `signer` attests another identity;
    /// the previous signer stays and nothing is burned.
    async fn install_attestation_signer(
        &mut self,
        signer: Arc<KeyPackageAttestationSigner>,
    ) -> Result<(), ContextError> {
        if signer.owner() != &self.identity {
            return Err(ContextError::InvalidState(
                "attestation signer owner mismatch".to_owned(),
            ));
        }
        let active = signer.active_key().to_bytes();
        self.attestation_signer = Some(signer);
        self.burn_superseded(active).await;
        Ok(())
    }

    /// Removes every pooled `KeyPackage` whose attestation verifies under a
    /// key other than `active`: drops it from the pool and from
    /// `published_refs`, deletes its record, and rewrites the index. A record
    /// whose delete fails stays named by the index (through `stale_refs`), so
    /// a respawn still reaches it, and the next install retries the delete.
    /// Reserved `KeyPackages` are left to their confirm, cancel or expiry.
    async fn burn_superseded(&mut self, active: [u8; 32]) {
        let (current, superseded): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pool)
            .into_iter()
            .partition(|p| p.attested_by == active);
        self.pool = current;
        if superseded.is_empty() && self.stale_refs.is_empty() {
            return;
        }
        let burned = superseded.len();
        for entry in superseded {
            self.published_refs.remove(&entry.kp_ref);
            self.stale_refs.insert(entry.kp_ref);
            // `entry.signer_state` is `Zeroizing`; it is wiped here.
        }
        let stale: Vec<KpRef> = self.stale_refs.iter().cloned().collect();
        for kp_ref in stale {
            match self.delete_kp_record(&kp_ref).await {
                Ok(()) => {
                    self.stale_refs.remove(&kp_ref);
                }
                Err(e) => tracing::warn!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    kp_ref = %kp_ref,
                    error = %e,
                    "superseded KP record delete failed; the index keeps it for a retry"
                ),
            }
        }
        tracing::info!(
            actor_kind = "key_package_store",
            identity = %self.identity.0,
            burned,
            "burned pooled key packages attested by a superseded #active key"
        );
        self.persist_index_best_effort("burn superseded").await;
    }

    /// Serves a `ReserveAny` after its signer is installed: reserves the
    /// first pooled `KeyPackage` the signer's key attested, or parks the reply
    /// until the refill pools one.
    ///
    /// Reserving inside one handler keeps two concurrent reserves from
    /// observing the same pooled `KeyPackage`: handlers run serialized on the
    /// actor's mailbox, and [`Self::handle_reserve`] moves the entry out of
    /// `pool` before the next handler runs.
    async fn handle_reserve_any(&mut self, reply: ReserveReply) {
        if !self.pool.is_empty() {
            let result = self.reserve_first_pooled().await;
            let _ = reply.send(result);
            return;
        }
        if self.parked_reserves.len() >= MAX_PARKED_REPLIES {
            let _ = reply.send(Err(ContextError::ActorBusy(format!(
                "key package store has {MAX_PARKED_REPLIES} reserves waiting for a refill"
            ))));
            return;
        }
        self.parked_reserves.push_back(reply);
        if !self.ensure_refill() {
            // The signer is installed, so no refill runs only because pooled
            // plus reserved reach the reservation ceiling.
            self.fail_parked_reserves(&ContextError::CreationFailed(format!(
                "the KeyPackage pool is empty and {} reservations are outstanding, the \
                 ceiling of {MAX_OUTSTANDING_RESERVATIONS}; no refill runs until one is \
                 confirmed or cancelled",
                self.reserved.len()
            )));
        }
    }

    /// Reserves the first pooled `KeyPackage` the installed signer's key
    /// attested.
    async fn reserve_first_pooled(&mut self) -> Result<(ReservationId, Vec<u8>), ContextError> {
        let active = self.active_attesting_key()?;
        let Some(first) = self.pool.iter().find(|p| p.attested_by == active) else {
            return Err(ContextError::CreationFailed(
                "the KeyPackage pool holds no KeyPackage the current #active key attested"
                    .to_owned(),
            ));
        };
        let kp_ref = first.kp_ref.clone();
        self.handle_reserve(kp_ref).await
    }

    /// Replies to every parked `ReserveAny` with a copy of `e`.
    fn fail_parked_reserves(&mut self, e: &ContextError) {
        for reply in self.parked_reserves.drain(..) {
            let _ = reply.send(Err(refill_error_copy(e)));
        }
    }

    /// Reserves for parked `ReserveAny` replies while the pool has
    /// `KeyPackages`. A reply whose caller has gone is dropped without
    /// reserving.
    async fn serve_parked_reserves(&mut self) {
        while !self.pool.is_empty() {
            let Some(reply) = self.parked_reserves.pop_front() else {
                return;
            };
            if reply.is_closed() {
                continue;
            }
            let result = self.reserve_first_pooled().await;
            let _ = reply.send(result);
        }
    }

    /// Roll back an in-memory reservation on a Class-S persist failure:
    /// remove it from `reserved` and return the KP to the pool (the private
    /// signer-state moves back, never lost).
    fn rollback_reserve(
        &mut self,
        reservation_id: &ReservationId,
        kp_ref: KpRef,
        public_bytes: Vec<u8>,
    ) {
        if let Some(reserved) = self.reserved.remove(reservation_id) {
            self.pool.push(PooledKeyPackage {
                kp_ref,
                public_bytes,
                signer_state: reserved.signer_state,
                attested_by: reserved.attested_by,
            });
        }
    }

    /// Reads the `0xFF01` of the reserved KeyPackage from the reservation's
    /// signer state, leaving the reservation in place.
    async fn handle_reserved_wrapping_key(
        &self,
        reservation_id: ReservationId,
    ) -> Result<P256Point, ContextError> {
        let Some(reserved) = self.reserved.get(&reservation_id) else {
            return Err(ContextError::InvalidState(
                "unknown or already-consumed reservation".to_owned(),
            ));
        };
        let signer_state = SignerState {
            bytes: Zeroizing::new(reserved.signer_state.to_vec()),
        };
        self.mls
            .reserved_wrapping_key(&signer_state)
            .await
            .map_err(|e| {
                ContextError::InvalidKeyPackage(format!(
                    "reserved KeyPackage wrapping key unreadable: {e}"
                ))
            })?
            .ok_or_else(|| {
                ContextError::InvalidKeyPackage(
                    "reserved KeyPackage carries no scp_wrapping_key (0xFF01)".to_owned(),
                )
            })
    }

    /// Confirm-consume a reservation by FUSING the join into the actor.
    ///
    /// Steps:
    /// 1. Look up the reserved KP (private signer-state held internally).
    /// 2. Run `join_from_welcome(welcome, signer_state, public_bytes)` — this
    ///    ALSO consults/writes the backend's durable consumed-init-key set
    ///    (the crypto-layer single-use anchor). On Err (bad/duplicate welcome,
    ///    or init-key replay) DO NOT burn the KP: keep the reservation intact
    ///    and reply Err so the caller can retry or cancel.
    /// 3. On a successful join, durably record the consume BEFORE the ack,
    ///    in the fail-safe order (B1): delete the KP private record FIRST
    ///    (so a crash leaves the record GONE — can't be re-pooled), then write
    ///    the reservation-id-keyed consumed tombstone (carrying the `kp_ref`
    ///    so reconcile excludes it from the pool branch). Return the joined
    ///    [`ScpMlsGroup`] (a self-contained value that owns its OpenMLS
    ///    provider + signer) — never the raw signer-state.
    ///
    /// A replay-driven own-prior-completion retry (see the `ConfirmConsume`
    /// doc) has no group to re-produce, so it completes the durable consume and
    /// returns `Err(InvalidState)` rather than a groupless `Ok`.
    async fn handle_confirm(
        &mut self,
        reservation_id: ReservationId,
        welcome_bytes: &[u8],
    ) -> Result<ScpMlsGroup, ContextError> {
        // Borrow the reserved entry WITHOUT removing it: a failed join must
        // leave the reservation intact for retry/cancel.
        let Some(reserved) = self.reserved.get(&reservation_id) else {
            return Err(ContextError::InvalidState(
                "unknown or already-consumed reservation".to_owned(),
            ));
        };
        let kp_ref = reserved.kp_ref.clone();
        let public_bytes = reserved.public_bytes.clone();
        // `reserved.signer_state` is `Zeroizing`; `.to_vec()` alone would yield
        // a plain un-zeroized `Vec<u8>` of private signing/HPKE material. The
        // `SignerState.bytes` field is itself `Zeroizing`, so this transient
        // copy zeroes on drop (when the backend finishes with it).
        let signer_state = SignerState {
            bytes: Zeroizing::new(reserved.signer_state.to_vec()),
        };

        // Fused join INTERNALLY. The signer-state never leaves the actor as raw
        // bytes; the fully-formed joined group (which embeds its own OpenMLS
        // provider + signer) is what crosses back to the spawn-from-Welcome
        // entrypoint. `Some(group)` on a fresh successful join; `None` on the
        // replay-driven own-prior-completion path (the group was already
        // produced + dropped by a prior confirm and cannot be re-produced).
        let joined_group: Option<ScpMlsGroup> = match self
            .mls
            .join_from_welcome(welcome_bytes, signer_state, &public_bytes)
            .await
        {
            Ok(group) => Some(group),
            Err(e) => {
                // A crypto-layer init-key replay rejection (A2 backstop) needs
                // careful interpretation. The init-key marker is written by THIS
                // actor's own prior `join_from_welcome` for THIS reservation. So a
                // replay rejection while the reservation is STILL LIVE in `reserved`
                // means our own earlier confirm attempt already completed the join
                // but failed to finish the durable-consume completion (e.g. the
                // tombstone store failed and we kept the reservation for retry).
                // A naive retry would re-run the join, hit the marker, and fail
                // PERMANENTLY here — never reaching the tombstone write — leaving
                // the reservation stuck until the TTL sweep. Instead, recognize our
                // own already-completed join and fall through to the idempotent
                // durable-consume completion (delete KP record + write tombstone +
                // cleanup), making the retry an idempotent SUCCESS.
                //
                // We detect the variant BEFORE `map_join_error` so the replay is
                // matched against the `MlsError` rather than the (now distinct)
                // typed `ContextError`.
                //
                // The guard requires TWO independent facts before treating a replay
                // as this reservation's OWN prior completion, NOT "the reservation is
                // still live" alone:
                //   (1) the reservation is still live in `reserved` (an
                //       unknown/foreign reservation never reaches here — the early
                //       lookup returned `InvalidState`); AND
                //   (2) THIS reservation's KP private record is ALREADY ABSENT from
                //       durable storage. A real prior join of THIS reservation
                //       deletes the KP record FIRST (fail-safe B1 ordering) before
                //       writing the tombstone, so record-absence is durable EVIDENCE
                //       that a prior join of THIS reservation already ran and reached
                //       at least the delete step. If the KP record still EXISTS, a
                //       `KeyPackageReplay` is NOT a legitimate own-prior-completion —
                //       our own prior join would have deleted it — so the marker must
                //       have been written by something OTHER than a completed prior
                //       join of this reservation (e.g. journal corruption, or a
                //       distinct init-key collision). Surfacing it as
                //       `KeyPackageReplay` rather than a spurious `Ok` breaks any
                //       false-success chain regardless of how a re-pool could occur.
                if matches!(e, MlsError::KeyPackageReplay) {
                    let record_absent = !self.kp_record_exists(&kp_ref).await?;
                    if self.reserved.contains_key(&reservation_id) && record_absent {
                        tracing::info!(
                            actor_kind = "key_package_store",
                            identity = %self.identity.0,
                            kp_ref = %kp_ref,
                            "confirm retry: prior join already consumed this reservation's \
                             init key AND deleted its KP record; completing the durable \
                             consume idempotently"
                        );
                        // Fall through to the durable-consume completion below.
                    } else {
                        // Either no live reservation (defensive — the early lookup
                        // returns first), or the KP record still EXISTS so this is
                        // NOT our own prior completion. Surface the replay as a
                        // security-relevant single-use rejection, never a false Ok.
                        tracing::warn!(
                            actor_kind = "key_package_store",
                            identity = %self.identity.0,
                            kp_ref = %kp_ref,
                            kp_record_present = !record_absent,
                            "confirm: init-key replay rejected; not this reservation's own prior \
                             completion (KP record still present or reservation absent)"
                        );
                        return Err(Self::map_join_error(&e));
                    }
                } else {
                    // Ordinary join failure (a bad or duplicate Welcome, or the own
                    // KeyPackage's `Lifetime` rejected). Join failed — KP NOT
                    // burned; reservation stays for retry/cancel.
                    return Err(Self::map_join_error(&e));
                }
                // Own-prior-completion (replay + KP record already absent): there is
                // NO group to return — it was produced and dropped by a prior
                // confirm. Fall through with `None`; the durable-consume completion
                // below still runs (idempotent cleanup), and the final reply is
                // `Err(InvalidState)` (the join is lost; re-initiate with a fresh KP).
                None
            }
        };

        // Class-S, fail-SAFE ordering (B1): delete the KP private record FIRST
        // so a crash before the tombstone leaves the record GONE (reconcile
        // cannot re-pool it). On delete failure the KP record may survive, so
        // we MUST NOT have already removed the reservation; reply Err (via `?`)
        // and keep the reservation for an idempotent retry. A2 makes a naive
        // re-confirm's INNER JOIN fail with `KeyPackageReplay`, which the block
        // above recognizes as our own prior completion and converts back into
        // this completion path — so the retry is idempotent-successful, not a
        // permanent failure. The KP record delete is itself idempotent.
        self.delete_kp_record(&kp_ref).await?;

        // Write the reservation-id-keyed consumed tombstone carrying the
        // consumed `kp_ref`. Reconcile reads the value to exclude this ref from
        // the pool branch even if a later cleanup step is lost. On failure the
        // KP record is already gone (fail-safe — cannot be re-pooled), but the
        // tombstone is not anchored, so reply Err and keep the reservation for a
        // retry (which re-runs the idempotent delete + tombstone write); the
        // consumed-init-key set already rejects a replayed join.
        self.mls_storage
            .store(
                &self.consumed_key(&reservation_id),
                kp_ref.as_str().as_bytes(),
            )
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("consume tombstone: {e}")))?;

        // Consume is now durable. Hand off to the best-effort cleanup tail, which
        // removes the in-memory reservation and reclaims the reservation record +
        // tombstone WITHOUT ever undoing the consume.
        self.finalize_confirm_consume(&reservation_id, &kp_ref)
            .await;

        // Return the freshly-joined group to the spawn-from-Welcome caller. On
        // the own-prior-completion retry path `joined_group` is `None` (the
        // group was produced and dropped by a prior confirm and cannot be
        // re-produced); the durable consume above still ran, but there is no
        // group to install — reply `Err` so the joiner re-initiates the join
        // with a fresh key package rather than silently succeeding groupless.
        joined_group.ok_or_else(|| {
            ContextError::InvalidState(
                "reservation consumed on a prior confirm; the joined group was not retained \
                 — re-initiate the join with a fresh key package"
                    .to_owned(),
            )
        })
    }

    /// Best-effort cleanup tail of a durable confirm-consume. The consume is
    /// ALREADY durable (KP record deleted + tombstone written via `?`) before
    /// this runs, so every step here is best-effort: a failure is logged but
    /// NEVER undoes the consume (rolling a record back would re-expose a consumed
    /// KP). It removes the in-memory reservation (zeroing the signer-state on
    /// drop) and reclaims the durable reservation record + consumed tombstone,
    /// while preserving the invariant "any surviving durable reservation/tombstone
    /// record is always reachable via the id-set until fully reclaimed."
    async fn finalize_confirm_consume(&mut self, reservation_id: &ReservationId, kp_ref: &KpRef) {
        let removed = self.reserved.remove(reservation_id);

        // Delete the reservation record first. On success it is gone; on failure
        // it is orphaned UNLESS it remains reachable via the id-set (the gated
        // prune below). A surviving reservation record is the sole at-rest
        // fallback for the malformed-tombstone consumed-ref recovery, so it must
        // never be stranded unreachable.
        let reservation_record_deleted = match self
            .mls_storage
            .delete(&self.reservation_key(reservation_id))
            .await
        {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %e,
                    "confirm: reservation record delete failed after durable consume; \
                     retained in the id-set for reconcile GC reclaim"
                );
                false
            }
        };

        // Delete the consumed tombstone ONLY once the reservation record is
        // confirmed gone. If the reservation-record delete failed, KEEP the
        // tombstone: it is the reachability anchor that makes reconcile resolve
        // this rid as CONSUMED (never restored as `reserved`) and lets the GC
        // reclaim BOTH records together on a later pass. Deleting the tombstone
        // while the reservation record survives — then pruning the rid — would
        // strand the reservation record permanently (the rid is gone from the
        // id-set, the tombstone is gone, so `gc_consumed_journal`, which walks
        // the id-set + tombstones, can never reach it). The tombstone's
        // re-pool-exclusion duty is already discharged by the `?`-propagated
        // KP-record delete; deleting it here merely bounds durable growth.
        // Crash-safety: if the process dies after the tombstone write but before
        // this delete, the rid is still in the id-set (the gated prune below has
        // not run), so reconcile still excludes the consumed ref and the GC
        // reclaims the tombstone once the KP record is confirmed gone.
        let tombstone_deleted = if reservation_record_deleted {
            match self
                .mls_storage
                .delete(&self.consumed_key(reservation_id))
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        actor_kind = "key_package_store",
                        identity = %self.identity.0,
                        error = %e,
                        "confirm: consumed tombstone delete failed after durable consume; \
                         retained in the id-set for reconcile GC reclaim"
                    );
                    false
                }
            }
        } else {
            false
        };

        self.persist_index_best_effort("confirm").await;

        // Prune the rid from the durable id-set ONLY when BOTH best-effort
        // deletes succeeded. Otherwise KEEP the rid enumerable so a later
        // reconcile/GC pass can reach and reclaim the surviving reservation
        // record and/or tombstone — preserving the reachability invariant.
        // `persist_reservation_ids` rebuilds the set from the live `self.reserved`
        // keys (the rid is already removed), so retaining the rid means persisting
        // the live keys PLUS this rid.
        if reservation_record_deleted && tombstone_deleted {
            self.persist_reservation_ids_best_effort("confirm").await;
        } else {
            self.persist_reservation_ids_retaining_best_effort(reservation_id, "confirm")
                .await;
        }

        // Observability (ADR-049 §9): a successful single-use consume is a
        // security-critical transition — record it (no secret material) so an
        // anomalous consume rate is detectable.
        tracing::info!(
            actor_kind = "key_package_store",
            identity = %self.identity.0,
            kp_ref = %kp_ref,
            "key package consumed (single-use confirm)"
        );

        // `removed` (Zeroizing signer-state) drops here, zeroing it.
        drop(removed);
    }

    /// Cancel a reservation. KP single-use: the KP is discarded, NOT returned
    /// to the pool. Fail-SAFE ordering (B3): delete the KP record FIRST and
    /// only remove the reservation record AFTER the KP record is confirmed
    /// gone. On a KP-record-delete failure, RE-INSERT the in-memory
    /// reservation (and leave the reservation record in place) so reconcile
    /// restores it as `reserved` (non-poolable) rather than orphaning a live
    /// KP record that reconcile would re-pool.
    ///
    /// This asymmetry vs `ConfirmConsume` is deliberate: a cancel never
    /// consumes, so the only invariant to protect is "never re-pool an
    /// abandoned KP" — which the delete-first + re-insert-on-failure ordering
    /// guarantees.
    async fn handle_cancel(&mut self, reservation_id: ReservationId) -> Result<(), ContextError> {
        let Some(reserved) = self.reserved.remove(&reservation_id) else {
            return Err(ContextError::InvalidState("unknown reservation".to_owned()));
        };

        // Delete the KP record FIRST. On failure, re-insert the reservation so
        // reconcile restores it as `reserved` (not pooled), and reply Err.
        if let Err(e) = self.delete_kp_record(&reserved.kp_ref).await {
            self.reserved.insert(reservation_id, reserved);
            return Err(e);
        }

        // KP record confirmed gone — now it is safe to remove the reservation
        // record. A failure here only orphans a reservation record whose KP
        // record is already gone, so reconcile pools nothing from it; log and
        // continue (the KP is burned regardless).
        if let Err(e) = self
            .mls_storage
            .delete(&self.reservation_key(&reservation_id))
            .await
        {
            tracing::error!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                error = %e,
                "cancel: reservation record delete failed after KP record gone (best-effort)"
            );
        }
        self.persist_index_best_effort("cancel").await;
        self.persist_reservation_ids_best_effort("cancel").await;

        drop(reserved);
        Ok(())
    }

    /// Publish each pooled KP's public bytes (not yet published) ONCE through
    /// the transport, under the owning identity's canonical KeyPackage routing
    /// id (threaded as `owner_did` into the transport). Routing is per-DID and
    /// the bytes land on the transport adapter's own connection, so a KP is
    /// published exactly once — NOT fanned out per relay URL; the actor takes no
    /// caller-supplied relay list (it would falsely imply a fan-out that never
    /// happens). Idempotent: a `kp_ref` already published is skipped, and it is
    /// marked published only after the transport accepts it. An empty pool is a
    /// no-op success.
    ///
    /// Only `KeyPackages` the installed signer's `#active` key attested are
    /// published; without a signer the call is
    /// [`ContextError::NotInitialized`].
    async fn handle_publish(&mut self) -> Result<(), ContextError> {
        let active = self.active_attesting_key()?;
        // Snapshot the refs+bytes to publish so we don't borrow `self.pool`
        // while mutating `published_refs`. The transport publish is sync.
        let to_publish: Vec<(KpRef, Vec<u8>)> = self
            .pool
            .iter()
            .filter(|p| p.attested_by == active)
            .map(|p| (p.kp_ref.clone(), p.public_bytes.clone()))
            .collect();
        let owner_did = self.identity.0.clone();

        for (kp_ref, public_bytes) in to_publish {
            if self.published_refs.contains(&kp_ref) {
                continue;
            }
            self.transport
                .publish_key_package(&owner_did, &public_bytes)
                .await
                .map_err(|e| {
                    ContextError::TransportFailed(format!("publishing key package: {e}"))
                })?;
            // The transport accepted this ref — mark it published.
            self.published_refs.insert(kp_ref);
        }
        Ok(())
    }

    /// List the pooled (unreserved) KeyPackages as `(KpRef, public bytes)`
    /// pairs. Read-only — does not move any KP out of the pool. Reserved KPs are
    /// deliberately EXCLUDED: they are not available to reserve, and their
    /// public bytes are already held by whoever reserved them. The private
    /// signer-state never appears here (only `kp_ref` + public bytes). Only
    /// `KeyPackages` the installed signer's `#active` key attested are listed;
    /// without a signer the call is [`ContextError::NotInitialized`].
    fn handle_list_pooled(&self) -> Result<PooledKeyPackages, ContextError> {
        let active = self.active_attesting_key()?;
        Ok(self
            .pool
            .iter()
            .filter(|p| p.attested_by == active)
            .map(|p| (p.kp_ref.clone(), p.public_bytes.clone()))
            .collect())
    }

    // -----------------------------------------------------------------
    // Replenishment + orphan-reservation TTL sweep
    // -----------------------------------------------------------------

    /// Sweep expired reservations, then replenish to [`MIN_BUFFER`] if
    /// `pool.len() + reserved.len()` is below [`REPLENISH_THRESHOLD`].
    ///
    /// The refill mints off the command turn; see [`Self::ensure_refill`].
    async fn maybe_replenish(&mut self) {
        self.sweep_expired_reservations().await;
        if self.stock() < REPLENISH_THRESHOLD {
            self.ensure_refill();
        }
    }

    /// Expire `reserved` entries older than [`RESERVATION_TTL_MS`], treating
    /// expiry as a cancel (the KP is burned, durable records cleaned up). A
    /// reserve-without-confirm/cancel (caller crashed mid-flow) therefore
    /// cannot leak a private record forever.
    ///
    /// # Activity-gated (no timer)
    ///
    /// This sweep runs ONLY from [`Self::maybe_replenish`] — i.e. after a
    /// `Reserve` or `CancelReservation`. There is no periodic timer, so an
    /// IDLE actor (no commands arriving) does not sweep abandoned reservations
    /// until its next command. This is intentional and bounded: the
    /// [`MAX_OUTSTANDING_RESERVATIONS`] ceiling caps the live `reserved` map
    /// (and therefore the abandoned-reservation footprint) regardless of how
    /// long the actor sits idle, and the natural replenish cap of
    /// [`MIN_BUFFER`] keeps the steady-state count far below that ceiling. An
    /// abandoned reservation on a then-idle actor is swept the moment ANY
    /// reserve/cancel arrives; until then it occupies at most one bounded slot.
    /// Adding a free-running timer would introduce a mailbox-independent wakeup
    /// the actor model deliberately avoids; the ceiling is the footprint bound.
    async fn sweep_expired_reservations(&mut self) {
        let now = self.clock.now_millis();
        let expired: Vec<ReservationId> = self
            .reserved
            .iter()
            .filter(|(_, r)| now.saturating_sub(r.reserved_at_ms) > RESERVATION_TTL_MS)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                "expiring abandoned key-package reservation past TTL (burning the KP)"
            );
            // Reuse the cancel path (delete-first, fail-safe). An error leaves
            // the reservation in place for the next sweep; log via cancel.
            if let Err(e) = self.handle_cancel(id).await {
                tracing::warn!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %e,
                    "TTL sweep: cancel of expired reservation failed; will retry next sweep"
                );
            }
        }
    }

    /// Whether the refill mints another `KeyPackage`: a signer is installed,
    /// and either pooled plus reserved is below [`MIN_BUFFER`], or parked
    /// reserves outnumber the pool while pooled plus reserved is below
    /// [`MAX_OUTSTANDING_RESERVATIONS`], the most reservations the store
    /// holds.
    fn wants_mint(&self) -> bool {
        self.attestation_signer.is_some()
            && (self.stock() < MIN_BUFFER
                || (self.parked_reserves.len() > self.pool.len()
                    && self.stock() < MAX_OUTSTANDING_RESERVATIONS))
    }

    /// Starts a refill when none runs and [`Self::wants_mint`]. Returns
    /// whether a refill is running.
    ///
    /// A refill mints one `KeyPackage` at a time as the actor's in-flight mint
    /// subtask (see [`Self::serve`]) while [`Self::wants_mint`]: it serves
    /// every parked reserve, then tops pooled plus reserved back up to
    /// [`MIN_BUFFER`], or ends when a mint fails. Every `KeyPackage` carries a
    /// `0xFF03` attestation the installed signer made with the owner's
    /// `#active` key (§9.7.1).
    fn ensure_refill(&mut self) -> bool {
        if self.refill.is_some() {
            return true;
        }
        if !self.wants_mint() {
            return false;
        }
        self.refill = Some(Refill::default());
        self.start_mint();
        true
    }

    /// Starts one mint with the installed signer as a subtask on the
    /// Supervisor's task tracker. The task owns clones of the backend and
    /// signer, so it borrows nothing from the actor.
    fn start_mint(&mut self) {
        let Some(signer) = self.attestation_signer.clone() else {
            return;
        };
        let mls = Arc::clone(&self.mls);
        // The identity's wrapping public key, published as the `0xFF01` leaf
        // extension. The supervisor's entry never changes once inserted, so
        // every KeyPackage this store generates carries the same key.
        let wrapping_public_key = *self.wrapping_key.public();
        let attested_by = signer.active_key().to_bytes();
        self.minting = Some(MintTask {
            attested_by,
            task: AbortOnDrop(self.subtasks.spawn(async move {
                mint_attested_key_package(&*mls, &signer, &wrapping_public_key).await
            })),
        });
    }

    /// Takes one finished mint. A `KeyPackage` attested by the installed
    /// signer's key is pooled and serves parked reserves; one attested by a
    /// key a later `ReserveAny` superseded is dropped unpersisted. The refill
    /// then mints again, or ends.
    async fn handle_minted(&mut self, outcome: MintOutcome) {
        self.minting = None;
        let current = self
            .attestation_signer
            .as_ref()
            .map(|s| s.active_key().to_bytes());
        match outcome.result {
            Ok(minted) if current == Some(outcome.attested_by) => {
                if let Err(e) = self.pool_minted(minted, outcome.attested_by).await {
                    self.end_refill(Some(e));
                    return;
                }
                if let Some(refill) = self.refill.as_mut() {
                    refill.generated += 1;
                }
                self.serve_parked_reserves().await;
            }
            // Attested by a superseded key: its `Zeroizing` signer-state is
            // wiped here and the refill mints again with the current signer.
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %e,
                    "key package mint failed; refill ends"
                );
                self.end_refill(Some(e));
                return;
            }
        }
        if self.wants_mint() {
            self.start_mint();
        } else {
            self.end_refill(None);
        }
    }

    /// Ends the refill: each waiting `Replenish` gets the count pooled since it
    /// parked, or the refill's error when that count is zero (`Ok(0)` when the
    /// refill ended without one). Parked reserves the pool cannot serve get the
    /// error, or [`ContextError::CreationFailed`] when there is none.
    fn end_refill(&mut self, error: Option<ContextError>) {
        let Some(refill) = self.refill.take() else {
            return;
        };
        for (reply, base) in refill.waiters {
            let pooled = refill.generated.saturating_sub(base);
            let result = match (&error, pooled) {
                (Some(e), 0) => Err(refill_error_copy(e)),
                _ => Ok(pooled),
            };
            let _ = reply.send(result);
        }
        if !self.parked_reserves.is_empty() {
            let e = error.unwrap_or_else(|| {
                ContextError::CreationFailed(format!(
                    "the KeyPackage refill ended with {MAX_OUTSTANDING_RESERVATIONS} \
                     KeyPackages reserved, the reservation ceiling"
                ))
            });
            self.fail_parked_reserves(&e);
        }
    }

    /// Persists one minted `KeyPackage` and pools it.
    ///
    /// The KP record is persisted, the entry pushed into the pool, then the
    /// index persisted — the index derives its ref list from the live `pool`
    /// and `reserved`, so a pooled KP always has a matching index entry. If the
    /// index persist fails the KP is rolled back out of the pool and its
    /// orphaned record best-effort deleted (a pooled KP whose index entry was
    /// lost could never be re-pooled or re-published on respawn, leaking its
    /// record). The union-enumeration in [`Self::reconcile_from_storage`] is
    /// the backstop for residual drift. Class-C: a lost unreserved KP is just
    /// minted again.
    async fn pool_minted(
        &mut self,
        minted: GeneratedKeyPackage,
        attested_by: [u8; 32],
    ) -> Result<(), ContextError> {
        let kp_ref = Self::derive_kp_ref(&minted.key_package_bytes);
        self.persist_kp_record(
            &kp_ref,
            &minted.key_package_bytes,
            &minted.signer_state.bytes,
            attested_by,
        )
        .await?;
        self.pool.push(PooledKeyPackage {
            kp_ref: kp_ref.clone(),
            public_bytes: minted.key_package_bytes,
            // `signer_state.bytes` is already `Zeroizing<Vec<u8>>`.
            signer_state: minted.signer_state.bytes,
            attested_by,
        });
        if let Err(e) = self.persist_index().await {
            self.pool.pop();
            if let Err(del) = self.delete_kp_record(&kp_ref).await {
                tracing::warn!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %del,
                    "replenish: orphaned KP record delete failed after \
                     index persist failure (excluded from pool)"
                );
            }
            return Err(e);
        }
        Ok(())
    }

    /// Serves `Replenish`: replies [`ContextError::NotInitialized`] without a
    /// signer and `Ok(0)` when pooled plus reserved already reach
    /// [`MIN_BUFFER`]; otherwise parks the reply on the refill (starting one if
    /// none runs), and [`Self::end_refill`] answers it.
    fn handle_replenish(&mut self, reply: oneshot::Sender<Result<usize, ContextError>>) {
        if let Err(e) = self.active_attesting_key() {
            let _ = reply.send(Err(e));
            return;
        }
        if !self.ensure_refill() {
            let _ = reply.send(Ok(0));
            return;
        }
        let Some(refill) = self.refill.as_mut() else {
            let _ = reply.send(Ok(0));
            return;
        };
        if refill.waiters.len() >= MAX_PARKED_REPLIES {
            let _ = reply.send(Err(ContextError::ActorBusy(format!(
                "key package store has {MAX_PARKED_REPLIES} replenishes waiting for a refill"
            ))));
            return;
        }
        let base = refill.generated;
        refill.waiters.push((reply, base));
    }

    // -----------------------------------------------------------------
    // Respawn reconciliation (ADR-049 §9 — rebuild from the durable source)
    // -----------------------------------------------------------------

    /// Build the reconcile reservation maps from the durable reservation-id set:
    /// `reserved_by_ref` (kp_ref -> (reservation_id, reserved_at_ms)) for LIVE
    /// (non-tombstoned) reservations, and `consumed_rid_by_ref` (consumed kp_ref
    /// -> consuming rid) for tombstoned ones. A tombstone marks a reservation
    /// confirmed; its value is the consumed `kp_ref`, collected so the pool
    /// branch can exclude it even if the KP-record delete was lost.
    ///
    /// A malformed (non-UTF-8) tombstone value is Anchor-1 corruption: its OWN
    /// recorded `kp_ref` is unrecoverable. But the consumed `kp_ref` ALSO lives
    /// in the SURVIVING reservation record (`PersistedReservation.kp_ref` under
    /// `reservation_key(rid)`), written at Reserve time and independent of the
    /// corrupt tombstone. We RECOVER it from there and STILL treat the
    /// reservation as consumed — inserting it into `consumed_rid_by_ref` (so it
    /// lands in `consumed_refs` and the reconcile EXCLUSION + stale-record-delete
    /// branch runs) while keeping the `continue` (it is NOT restored to
    /// `reserved`). This closes the compound failure {corrupt tombstone + KP
    /// record + index entry all survive a lost delete}: without the recovery,
    /// reconcile would walk the surviving ref, find it neither reserved nor in
    /// `consumed_refs`, and RE-POOL a consumed KP (re-reservable + signer-state
    /// retained at rest).
    ///
    /// If the reservation record is ALSO gone (the genuine shared-substrate
    /// total-loss limit — both the tombstone value AND the reservation record
    /// lost together), the `kp_ref` is truly unrecoverable here; we log loudly
    /// and leave it as the documented contingency. Anchor-2 (the crypto-layer
    /// init-key set) still blocks the actual double-join in that residual case.
    /// The loud `tracing::error!` fires regardless.
    async fn load_reservation_maps(&self) -> Result<ReconcileReservationMaps, ContextError> {
        let reservation_ids = self.load_reservation_ids().await?;
        let mut reserved_by_ref: HashMap<KpRef, (ReservationId, u64)> = HashMap::new();
        let mut consumed_rid_by_ref: HashMap<KpRef, ReservationId> = HashMap::new();
        for rid in reservation_ids {
            let tomb = self
                .mls_storage
                .retrieve(&self.consumed_key(&rid))
                .await
                .map_err(|e| ContextError::PersistenceFailed(format!("consumed retrieve: {e}")))?;
            if let Some(consumed_ref_bytes) = tomb {
                if let Ok(consumed_ref) = String::from_utf8(consumed_ref_bytes) {
                    consumed_rid_by_ref.insert(KpRef::from_durable(consumed_ref), rid);
                } else {
                    // The tombstone value is corrupt, but the consumed `kp_ref`
                    // ALSO lives in the surviving reservation record. Recover it
                    // from there so the ref is still EXCLUDED from the pool (and
                    // its stale record deleted), never re-pooled.
                    if let Some(kp_ref) = self.recover_consumed_ref_from_reservation(&rid).await? {
                        tracing::error!(
                            actor_kind = "key_package_store",
                            identity = %self.identity.0,
                            reservation_id = %rid,
                            "reconcile: consumed tombstone value is not valid UTF-8 \
                             (Anchor-1 corruption); recovered consumed kp_ref from the \
                             surviving reservation record — treating as consumed (excluded)"
                        );
                        consumed_rid_by_ref.insert(kp_ref, rid);
                    } else {
                        tracing::error!(
                            actor_kind = "key_package_store",
                            identity = %self.identity.0,
                            reservation_id = %rid,
                            "reconcile: consumed tombstone value is not valid UTF-8 AND \
                             the reservation record is gone (shared-substrate total loss); \
                             kp_ref unrecoverable — Anchor-2 init-key set still blocks re-join"
                        );
                    }
                }
                continue;
            }
            let rec = self
                .mls_storage
                .retrieve(&self.reservation_key(&rid))
                .await
                .map_err(|e| {
                    ContextError::PersistenceFailed(format!("reservation retrieve: {e}"))
                })?;
            let Some(bytes) = rec else { continue };
            if let Ok(parsed) = rmp_serde::from_slice::<PersistedReservation>(&bytes) {
                reserved_by_ref.insert(parsed.kp_ref, (rid, parsed.reserved_at_ms));
            }
        }
        Ok((reserved_by_ref, consumed_rid_by_ref))
    }

    /// Recover the consumed `kp_ref` for `rid` from its SURVIVING reservation
    /// record (`PersistedReservation.kp_ref` under `reservation_key(rid)`) —
    /// the malformed-tombstone recovery path. Returns `None` if the reservation
    /// record is gone (total loss) or fails to decode.
    async fn recover_consumed_ref_from_reservation(
        &self,
        rid: &ReservationId,
    ) -> Result<Option<KpRef>, ContextError> {
        let rec = self
            .mls_storage
            .retrieve(&self.reservation_key(rid))
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("reservation retrieve: {e}")))?;
        let Some(bytes) = rec else {
            return Ok(None);
        };
        match rmp_serde::from_slice::<PersistedReservation>(&bytes) {
            Ok(parsed) => Ok(Some(parsed.kp_ref)),
            Err(e) => {
                tracing::error!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    reservation_id = %rid,
                    error = %e,
                    "reconcile: reservation record decode failed during malformed-tombstone \
                     kp_ref recovery; treating as unrecoverable"
                );
                Ok(None)
            }
        }
    }

    /// Drops every consumed ref from `reserved_by_ref`, so a ref a corrupted
    /// journal names as both reserved and consumed is never restored as a live
    /// reservation: consumed wins (single use).
    fn drop_consumed_from_reserved<V>(
        &self,
        consumed_refs: &HashSet<KpRef>,
        reserved_by_ref: &mut HashMap<KpRef, V>,
    ) {
        for consumed_ref in consumed_refs {
            if reserved_by_ref.remove(consumed_ref).is_some() {
                tracing::error!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    kp_ref = %consumed_ref,
                    "reconcile: kp_ref named by BOTH a live reservation AND a consumed \
                     tombstone (journal corruption); CONSUMED wins — not restored as reserved"
                );
            }
        }
    }

    /// Rebuild `pool` / `reserved` from the DURABLE journal in `mls_storage`.
    ///
    /// For every `kp_ref` in the UNION of ALL THREE durable enumeration sources
    /// — the live index (POOLED), the fail-closed reserved spine
    /// (`reserved_by_ref.keys()`, RESERVED), and the consumed tombstones
    /// (`consumed_refs`, CONSUMED) — whose KP record still exists:
    /// - If a live reservation claims it → restore into `reserved` (NOT
    ///   re-poolable).
    /// - Else if it is a CONSUMED `kp_ref` (named by any consumed tombstone)
    ///   → skip it (never re-pool a consumed KP) and best-effort delete the
    ///   stale record so its private `signer_state` does not leak at rest.
    /// - Otherwise pool it.
    ///
    /// A KP whose record is gone (consumed/cancelled) is never restored. This
    /// is the crash-safety crux: a reservation persisted before a crash
    /// restores `reserved`; a reservation NOT persisted means the caller's
    /// Reserve returned Err (no ack), and the KP is restored to the pool — no
    /// double-consume either way. The consumed-`kp_ref` exclusion closes the
    /// window where a consume's KP-record delete or index write was lost: even
    /// if the record survives, the tombstone's recorded `kp_ref` keeps it out
    /// of the pool, AND — because `consumed_refs` is part of the enumeration
    /// union — its surviving record is visited and best-effort deleted even
    /// when its index entry was also lost, so no private material leaks at rest.
    async fn reconcile_from_storage(&mut self) -> Result<(), ContextError> {
        self.pool.clear();
        self.reserved.clear();
        self.published_refs.clear();
        self.stale_refs.clear();

        let index = self.load_index().await?;

        // The KV adapter has no list API, so the durable truth we enumerate is
        // (a) the kp_ref index and (b) the live reservation-id set, both
        // persisted explicitly. Build the live-reservation and consumed maps
        // from the reservation-id set (extracted into a helper to keep this
        // method's body bounded).
        let (mut reserved_by_ref, consumed_rid_by_ref) = self.load_reservation_maps().await?;
        let consumed_refs: HashSet<KpRef> = consumed_rid_by_ref.keys().cloned().collect();

        // CONSUMED precedence over RESERVED (defense-in-depth). Through the
        // protocol's OWN writes a single `kp_ref` can never be named by both a
        // live reservation record AND a consumed tombstone — a confirm deletes
        // the KP record and tombstones the rid; a fresh reserve mints a NEW rid
        // for a NEW ref. But storage corruption (a hand-written / rolled-back
        // journal) could fabricate that overlap. If it did, the per-ref branch
        // below would hit `reserved_by_ref.remove(&kp_ref)` FIRST and restore a
        // CONSUMED KP as a live, re-confirmable reservation — defeating
        // single-use. Make consumed strictly win: drop any consumed ref from
        // `reserved_by_ref` up front, so a consumed ref is NEVER restored as
        // reserved (it falls through to the consumed exclusion/stale-delete
        // branch instead). A consumed ref must never be restored as reserved OR
        // pooled.
        self.drop_consumed_from_reserved(&consumed_refs, &mut reserved_by_ref);

        // Enumerate the UNION of ALL THREE durable enumeration sources, not just
        // the index. The KV adapter has no list API, so every persisted ref that
        // can name private KP material at rest must be walked here or its record
        // can leak. There are exactly three such sources and no fourth:
        //   1. the kp_ref index           (Class-C, best-effort) — POOLED refs;
        //   2. the live reservation spine  (Class-S, fail-closed) — RESERVED refs
        //      (`reserved_by_ref.keys()`);
        //   3. the consumed tombstones     (Class-S, fail-closed) — CONSUMED refs
        //      (`consumed_refs`).
        //
        // A RESERVED KP whose `kp_ref` is absent from the index — because a prior
        // replenish-time index write was lost — would otherwise never be
        // visited: its `reserved_by_ref` entry would be silently dropped, the
        // tail self-heal would rewrite the reservation-id set from `self.reserved`
        // (now missing that rid), and the reservation-id, reservation record, and
        // KP private record would be PERMANENTLY orphaned (the caller's
        // outstanding `ConfirmConsume` then fails `InvalidState` forever and the
        // signer-state leaks).
        //
        // Symmetrically, a CONSUMED KP whose private record survived a lost
        // delete AND whose index entry was also lost would never be visited
        // either — the `consumed_refs` exclusion/stale-record-delete branch below
        // only runs for refs that ARE walked. Its surviving `signer_state` (the
        // private HPKE/signing material) would leak permanently at rest, and the
        // tail id-set/index rewrite (built from live state only) would sever
        // future enumeration of that rid. Adding `consumed_refs` to the union
        // guarantees the consumed ref is visited → its stale record is best-effort
        // deleted; the next respawn then finds the record gone so
        // `gc_consumed_journal` reclaims the tombstone + reservation record.
        //
        // Walking the full union and restoring/excluding each ref makes the tail
        // self-heal rewrite the index to a faithful liveness view, so reconcile
        // self-corrects instead of self-amputating (and never leaks at rest).
        let all_refs = enumeration_union(index, reserved_by_ref.keys().chain(&consumed_refs));

        for kp_ref in all_refs {
            let rec = self
                .mls_storage
                .retrieve(&self.kp_record_key(&kp_ref))
                .await
                .map_err(|e| ContextError::PersistenceFailed(format!("kp record retrieve: {e}")))?;
            let Some(bytes) = rec else {
                continue; // record gone (consumed/cancelled) — not restorable.
            };
            let PersistedKeyPackage {
                public_bytes,
                signer_state,
                attested_by,
            } = match rmp_serde::from_slice(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    // A record that does not decode cannot be served and may
                    // hold private material, so it is deleted.
                    tracing::error!(
                        actor_kind = "key_package_store",
                        identity = %self.identity.0,
                        error = %e,
                        "reconcile: kp record decode failed; deleting it"
                    );
                    if let Err(del) = self.delete_kp_record(&kp_ref).await {
                        tracing::warn!(
                            actor_kind = "key_package_store",
                            identity = %self.identity.0,
                            error = %del,
                            "reconcile: undecodable kp record delete failed"
                        );
                    }
                    continue;
                }
            };
            // Both fields move into the actor's records without a copy; an
            // excluded consumed record drops its `Zeroizing` signer-state.
            if let Some((rid, reserved_at_ms)) = reserved_by_ref.remove(&kp_ref) {
                self.reserved.insert(
                    rid,
                    ReservedKeyPackage {
                        kp_ref: kp_ref.clone(),
                        public_bytes,
                        signer_state,
                        attested_by,
                        reserved_at_ms,
                    },
                );
            } else if consumed_refs.contains(&kp_ref) {
                // Consumed KP whose record survived a lost delete/index write:
                // NEVER re-pool. Best-effort delete the stale record so it does
                // not linger. The tombstone is retained until the record is
                // confirmed gone (the GC pass below handles that).
                //
                // Observability (ADR-049 §9): excluding + deleting a stale
                // consumed record is a security-critical reconcile transition
                // (it closes the lost-delete crash window) — record it (no
                // secret material) so an anomalous rate is detectable.
                tracing::info!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    kp_ref = %kp_ref,
                    "reconcile: excluding consumed KP whose record survived; deleting stale record"
                );
                if let Err(e) = self.delete_kp_record(&kp_ref).await {
                    tracing::warn!(
                        actor_kind = "key_package_store",
                        identity = %self.identity.0,
                        error = %e,
                        "reconcile: stale consumed KP record delete failed (excluded from pool)"
                    );
                }
            } else {
                self.pool.push(PooledKeyPackage {
                    kp_ref,
                    public_bytes,
                    signer_state,
                    attested_by,
                });
            }
        }

        // E3 — bounded durable growth: GC consumed tombstones whose KP record
        // is now confirmed gone (see [`Self::gc_consumed_journal`]). Any rid the
        // GC could NOT fully reclaim this pass (record still present, or a
        // best-effort delete failed) is returned so the tail id-set rewrite
        // RETAINS it — otherwise the unconditional rewrite below (built from
        // `self.reserved` alone) would prune it and sever the only enumeration
        // path back to its surviving record(s).
        let gc_retained = self.gc_consumed_journal(&consumed_rid_by_ref).await?;

        // Orphan self-heal (L1/L2/L3): unconditionally rewrite BOTH durable
        // enumeration anchors from the reconstructed LIVE state, so each respawn
        // drops any rid/ref that resolves to neither a live reservation nor a
        // live KP record:
        //   - The reservation-id set is rewritten from `self.reserved` keys PLUS
        //     any `gc_retained` rid the GC could not fully reclaim this pass, so a
        //     rid lingering with no tombstone and no restorable record (a
        //     best-effort-persist casualty) is no longer enumerated on the next
        //     respawn — it can never resurrect a phantom reservation — while a
        //     consumed rid whose record(s) survived a partial GC stays reachable
        //     for a later pass instead of being stranded.
        //   - The index is rewritten from the live `pool` + `reserved` refs, so a
        //     ref pointing at a now-absent KP record (a lost delete/index write)
        //     is dropped, keeping the index a faithful liveness view and bounding
        //     its growth.
        // Both are Class-C liveness aids (the KP records + tombstones are the
        // durable single-use truth), so a write failure here is logged, not
        // fatal — the next respawn retries.
        self.persist_index_best_effort("reconcile").await;
        self.persist_reservation_ids_retaining_many_best_effort(&gc_retained, "reconcile")
            .await;

        Ok(())
    }

    /// E3 — bounded durable growth: GC the journal for consumed reservations
    /// whose KP record is now confirmed ABSENT.
    ///
    /// Once the KP record is gone, a consumed tombstone (and its reservation
    /// record) can never re-pool anything, so retaining them only grows storage
    /// without bound (UUIDv4 reservation ids are never reused, so there is no
    /// reuse window to protect). For each such consumed rid we delete the
    /// reservation record FIRST and the consumed tombstone ONLY once that
    /// succeeded — symmetric with [`Self::finalize_confirm_consume`] so a partial
    /// delete failure keeps the tombstone as the reachability anchor rather than
    /// stranding the surviving reservation record. A tombstone whose KP record
    /// still SURVIVES (a lost delete) is KEPT so it keeps excluding the ref on
    /// the next reconcile.
    ///
    /// Returns the consumed rids that were NOT fully reclaimed this pass (record
    /// still present, or a best-effort delete failed). The caller
    /// [`Self::reconcile_from_storage`] rewrites the reservation-id set from the
    /// live `self.reserved` keys PLUS these retained rids — so a fully-reclaimed
    /// rid is dropped (bounded growth) while a partially-reclaimed rid stays
    /// enumerable for a later pass (reachability invariant). This method does the
    /// durable record deletes and reports retention; the authoritative
    /// enumeration rewrite is the caller's.
    async fn gc_consumed_journal(
        &self,
        consumed_rid_by_ref: &HashMap<KpRef, ReservationId>,
    ) -> Result<Vec<ReservationId>, ContextError> {
        // rids whose GC delete pair did NOT fully succeed this pass. The caller's
        // tail id-set rewrite (built from `self.reserved` alone) would otherwise
        // PRUNE these rids, severing the only enumeration path to their surviving
        // record(s) (reconcile walks the id-set, not the tombstone keyspace —
        // the KV adapter has no list API). Retaining them keeps a later pass able
        // to reach and finish the reclaim, preserving the reachability invariant.
        let mut retain: Vec<ReservationId> = Vec::new();
        for (consumed_ref, rid) in consumed_rid_by_ref {
            let record_present = self
                .mls_storage
                .retrieve(&self.kp_record_key(consumed_ref))
                .await
                .map_err(|e| ContextError::PersistenceFailed(format!("kp record retrieve: {e}")))?
                .is_some();
            if record_present {
                // Keep the tombstone until the record is gone; the rid must stay
                // enumerable so a later pass revisits it (mirrors the confirm
                // path's reachability anchor).
                retain.push(rid.clone());
                continue;
            }
            // Symmetric with `finalize_confirm_consume`: delete the reservation
            // record FIRST and delete the consumed tombstone ONLY once that
            // succeeded. If the reservation-record delete fails, KEEP the
            // tombstone as the reachability anchor (so reconcile resolves this rid
            // as CONSUMED, never `reserved`) and RETAIN the rid in the id-set so a
            // later pass reclaims BOTH together. Deleting the tombstone first
            // while the reservation record survives — then letting the tail prune
            // the rid — would strand the reservation record permanently (rid gone
            // from the id-set, tombstone gone → no future pass can reach it). The
            // tombstone's re-pool-exclusion duty is already discharged here: the
            // KP private record is confirmed ABSENT in this branch, so single-use
            // cannot regress regardless of delete ordering.
            if let Err(e) = self.mls_storage.delete(&self.reservation_key(rid)).await {
                tracing::warn!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %e,
                    "reconcile GC: consumed reservation record delete failed; \
                     tombstone retained as anchor, rid retained for next-pass reclaim"
                );
                retain.push(rid.clone());
                continue;
            }
            if let Err(e) = self.mls_storage.delete(&self.consumed_key(rid)).await {
                tracing::warn!(
                    actor_kind = "key_package_store",
                    identity = %self.identity.0,
                    error = %e,
                    "reconcile GC: consumed tombstone delete failed (reservation record \
                     already gone); rid retained for next-pass reclaim"
                );
                retain.push(rid.clone());
            }
        }
        Ok(retain)
    }

    /// Load the set of live reservation_ids. Persisted alongside the index so a
    /// respawn can enumerate reservations (the KV has no list API).
    async fn load_reservation_ids(&self) -> Result<Vec<ReservationId>, ContextError> {
        match self.mls_storage.retrieve(&self.reservation_ids_key()).await {
            Ok(Some(bytes)) => rmp_serde::from_slice::<Vec<ReservationId>>(&bytes).map_err(|e| {
                ContextError::PersistenceFailed(format!("reservation-ids decode: {e}"))
            }),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(ContextError::PersistenceFailed(format!(
                "reservation-ids retrieve: {e}"
            ))),
        }
    }

    /// Persist the set of live reservation_ids (the in-memory `reserved` keys),
    /// optionally PLUS one `retain` rid that is no longer a live `reserved`
    /// entry. Class-S when called as part of a reserve: the durable reservation
    /// enumeration must include the new id BEFORE the reserve acks, or a crash
    /// would lose the ability to restore the reservation on respawn.
    ///
    /// `retain`:
    /// - `None` — persist exactly the live `reserved` keys (the default: a fresh
    ///   reserve, or a clean cleanup tail where every consumed rid was fully
    ///   reclaimed).
    /// - `Some(rid)` — persist the live keys PLUS `rid` (deduped via `contains`).
    ///   Used by the confirm cleanup tail when a best-effort reservation-record
    ///   or tombstone delete failed: the consumed rid is no longer a live
    ///   reservation (so it would otherwise be pruned), but its surviving durable
    ///   record(s) must stay reachable via the id-set so a later reconcile/GC
    ///   pass can reclaim them. Keeping the rid enumerable is safe: reconcile
    ///   reads the retained tombstone FIRST and resolves the rid as CONSUMED, so
    ///   it is never restored as a live `reserved` entry.
    async fn persist_reservation_ids(
        &self,
        retain: Option<&ReservationId>,
    ) -> Result<(), ContextError> {
        // `Option::as_slice` is stable but recent; build the slice explicitly to
        // keep the MSRV unconstrained.
        match retain {
            Some(rid) => {
                self.persist_reservation_ids_retaining_slice(std::slice::from_ref(rid))
                    .await
            }
            None => self.persist_reservation_ids_retaining_slice(&[]).await,
        }
    }

    /// Slice-retaining core for [`Self::persist_reservation_ids`]. Persists the
    /// live `reserved` keys PLUS every rid in `retain` (each deduped via
    /// `contains`). `retain` is the (possibly empty) set of consumed rids that
    /// must stay enumerable in the durable id-set so a later reconcile/GC pass
    /// can reach their surviving record(s) — see the confirm cleanup tail (one
    /// rid) and the reconcile GC tail (the rids the GC could not fully reclaim).
    async fn persist_reservation_ids_retaining_slice(
        &self,
        retain: &[ReservationId],
    ) -> Result<(), ContextError> {
        let mut ids: Vec<ReservationId> = self.reserved.keys().cloned().collect();
        for rid in retain {
            if !ids.contains(rid) {
                ids.push(rid.clone());
            }
        }
        let bytes = rmp_serde::to_vec_named(&ids)
            .map_err(|e| ContextError::PersistenceFailed(format!("reservation-ids encode: {e}")))?;
        self.mls_storage
            .store(&self.reservation_ids_key(), &bytes)
            .await
            .map_err(|e| ContextError::PersistenceFailed(format!("reservation-ids store: {e}")))
    }
}

/// `index` followed by every ref in `extra` it does not already hold: the
/// union of the durable sources reconcile walks.
fn enumeration_union<'a>(
    mut index: Vec<KpRef>,
    extra: impl Iterator<Item = &'a KpRef>,
) -> Vec<KpRef> {
    for kp_ref in extra {
        if !index.contains(kp_ref) {
            index.push(kp_ref.clone());
        }
    }
    index
}

#[cfg(test)]
#[path = "key_package_actor_tests.rs"]
mod tests;
