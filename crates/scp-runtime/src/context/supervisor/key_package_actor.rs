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
//!    [`MlsBackend::join_from_welcome`](crate::crypto::mls::backend::MlsBackend::join_from_welcome)
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
//!    This backstop covers every join that flows through
//!    `MlsBackend::join_from_welcome` (the fused-confirm path); the legacy
//!    `MlsCryptoProvider::join_from_welcome` calls `group::join_group_from_bytes`
//!    directly and is production-unreachable (it is `#[cfg(any(test, feature =
//!    "testing"))]`-gated), slated for deletion when the spawn-from-Welcome
//!    entrypoint lands — so there is no LIVE production gap, only a test/feature-
//!    gated path that will be removed.
//!
//! The KP private signer-state lives ENTIRELY inside the opaque
//! [`SignerState`](crate::crypto::mls::backend::SignerState) blob returned by
//! [`MlsBackend::generate_key_package`] (a fresh isolated OpenMLS provider per
//! KP, serialized) — it is NOT written to any shared OpenMLS keystore. The
//! actor (in memory) and the durable KP record (at rest) are the only homes
//! for that material; deleting the KP record on consume/cancel makes a
//! replayed join from the journal impossible (the signer-state is gone), and
//! the consumed-init-key set makes a replay of any surviving bytes through
//! `MlsBackend::join_from_welcome` impossible at the crypto layer (the legacy
//! provider join path is production-unreachable — test/feature-gated, slated for
//! deletion — see anchor 3 above).
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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::ContextError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::context::builder::ContextTransportProvider;
use crate::crypto::mls::backend::{MlsBackend, SignerState};
use crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter;
use scp_did::SigningKeyId;
use scp_mls::credential::ScpCredential;
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
/// one where the other is expected. Mirrors the sibling
/// [`BroadcastReservationId`](crate::context::actor::state::BroadcastReservationId).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReservationId(String);

impl ReservationId {
    /// Mint a fresh random reservation id (UUIDv4). The ONLY non-test
    /// constructor — a `ReservationId` is always supervisor-minted, never
    /// caller-supplied, so there is no public string constructor to forge one.
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
/// The `signer_state` field holds private signing/HPKE join material. A
/// transient `PersistedKeyPackage` (built to serialize a record, or parsed back
/// out during reconcile) would otherwise drop its `signer_state` un-zeroed. The
/// hand-written [`Drop`] zeroes that private field on every drop while leaving
/// the on-disk serde format (plain `Vec<u8>` fields) unchanged. `public_bytes`
/// is publishable and not zeroed.
#[derive(Serialize, Deserialize)]
struct PersistedKeyPackage {
    /// TLS-serialized public KeyPackage bytes (publishable).
    public_bytes: Vec<u8>,
    /// Opaque private signer-state (the join material). Held in `Zeroizing`
    /// in memory; at rest it lives in `mls_storage` and is deleted on
    /// consume/cancel. Zeroed on drop via the `Drop` impl below.
    signer_state: Vec<u8>,
}

impl Drop for PersistedKeyPackage {
    fn drop(&mut self) {
        // Zero the private join material; `public_bytes` is publishable.
        zeroize::Zeroize::zeroize(&mut self.signer_state);
    }
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

/// A pooled (unreserved) KeyPackage.
struct PooledKeyPackage {
    kp_ref: KpRef,
    public_bytes: Vec<u8>,
    signer_state: Zeroizing<Vec<u8>>,
}

/// A reserved KeyPackage awaiting confirm/cancel. Holds the private
/// signer-state (it NEVER leaves the actor) plus the public bytes the fused
/// join needs to derive the crypto-layer init-key marker.
struct ReservedKeyPackage {
    kp_ref: KpRef,
    public_bytes: Vec<u8>,
    signer_state: Zeroizing<Vec<u8>>,
    reserved_at_ms: u64,
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
    /// (`MlsError::KeyPackageReplay`), which the handler recognizes as its OWN
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
    /// Explicitly replenish the pool up to [`MIN_BUFFER`]. Returns the count
    /// of KPs newly generated.
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
    ///   [`KP_SEND_TIMEOUT`], or inbox closed, or the actor dropped the
    ///   reply channel.
    /// - The handler's typed error.
    pub async fn send<T, F>(&self, cmd_factory: F) -> Result<T, ContextError>
    where
        F: FnOnce(oneshot::Sender<Result<T, ContextError>>) -> KeyPackageCommand,
    {
        let (tx, rx) = oneshot::channel::<Result<T, ContextError>>();
        let cmd = cmd_factory(tx);

        match tokio::time::timeout(KP_SEND_TIMEOUT, self.inbox.send(cmd)).await {
            Ok(Ok(())) => rx.await.unwrap_or_else(|_| {
                Err(ContextError::ActorBusy(
                    "key-package actor dropped reply channel".to_owned(),
                ))
            }),
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
    /// Optional wrapping pubkey published in each generated KP's leaf node.
    pub wrapping_pubkey: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// One per local identity. Owns the KeyPackage pool and the reservation map.
///
/// Handlers run on the single mailbox loop, so all `&mut self` mutations are
/// serialized — there are no internal locks. Private signer-state bytes are
/// wrapped in [`Zeroizing`] so they zero on drop, and they NEVER cross the
/// reply channel (the join is fused into [`Self::handle_confirm`]).
pub struct KeyPackageStoreActor {
    /// The identity this actor owns the pool for.
    identity: DID,
    /// Credential used to generate KeyPackages (built once at spawn).
    /// `None` only on a malformed-DID wiring bug, in which case replenish
    /// fail-closes rather than pooling inert KPs.
    credential: Option<ScpCredential>,
    /// Optional wrapping pubkey published in each KP leaf node (§9.16.1).
    wrapping_pubkey: Option<[u8; 32]>,
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
    /// Spawns a new actor task and returns its handle + `JoinHandle`.
    ///
    /// The supervisor keeps the `JoinHandle` and attaches a watchdog (mirroring
    /// the per-context actor watchdog, ADR-049 §10). On spawn the actor runs
    /// the §9 respawn reconciliation from `mls_storage` and replenishes to
    /// [`MIN_BUFFER`] before serving commands.
    ///
    /// The returned handle is the only way to reach the actor — the
    /// `mpsc::Receiver<KeyPackageCommand>` is moved into the actor task and
    /// never escapes.
    pub(in crate::context) fn spawn(
        identity: DID,
        deps: KeyPackageStoreDeps,
    ) -> (KeyPackageStoreHandle, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<KeyPackageCommand>(KP_MAILBOX_CAPACITY);

        // Build the credential once. The DID is a genuine local participant
        // (the supervisor resolves it from `local_dids`); credential
        // construction only fails on a malformed DID, which would be a
        // supervisor wiring bug — surface it as a degraded actor whose
        // replenish FAIL-CLOSES (typed errors), never pooling inert KPs.
        let credential = ScpCredential::new(identity.0.clone(), None, SigningKeyId::Active).ok();

        let actor = Self {
            identity,
            credential,
            wrapping_pubkey: deps.wrapping_pubkey,
            mls: deps.mls,
            mls_storage: deps.mls_storage,
            transport: deps.transport,
            clock: deps.clock,
            pool: Vec::new(),
            reserved: HashMap::new(),
            published_refs: HashSet::new(),
            inbox: rx,
        };
        let join = tokio::spawn(actor.run());
        (KeyPackageStoreHandle::from_sender(tx), join)
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
    /// A replay rejection (the crypto-layer consumed-init-key backstop) maps to
    /// the dedicated [`ContextError::KeyPackageReplay`] — distinct from
    /// [`ContextError::InvalidState`] (which also means "unknown reservation")
    /// so a caller can detect a security-relevant single-use replay. Everything
    /// else is a crypto failure.
    fn map_join_error(e: &MlsError) -> ContextError {
        match e {
            MlsError::KeyPackageReplay => ContextError::KeyPackageReplay(
                "key package already consumed (init-key replay rejected)".to_owned(),
            ),
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

    /// Persist one KP record (public + private signer-state). The MessagePack
    /// scratch buffer carries the private signer-state, so it is wrapped in
    /// [`Zeroizing`] (mirrors `serialize_signer_state`).
    async fn persist_kp_record(
        &self,
        kp_ref: &KpRef,
        public_bytes: &[u8],
        signer_state: &[u8],
    ) -> Result<(), ContextError> {
        let record = PersistedKeyPackage {
            public_bytes: public_bytes.to_vec(),
            signer_state: signer_state.to_vec(),
        };
        let bytes = Zeroizing::new(
            rmp_serde::to_vec_named(&record)
                .map_err(|e| ContextError::PersistenceFailed(format!("kp record encode: {e}")))?,
        );
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

    /// Dispatch loop. On startup runs the §9 reconciliation + an initial
    /// replenish, then serves commands until the inbox closes or a `Shutdown`
    /// command arrives.
    async fn run(mut self) {
        if let Err(e) = self.reconcile_from_storage().await {
            tracing::error!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                error = %e,
                "key-package actor reconciliation failed on spawn; serving from empty pool"
            );
        }
        // Best-effort initial replenish to the high-water mark. A failure here
        // is non-fatal: subsequent Reserve/Replenish commands retry.
        if let Err(e) = self.replenish_to_min().await {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                error = %e,
                "key-package actor initial replenish failed; pool may be below target"
            );
        }

        while let Some(cmd) = self.inbox.recv().await {
            match cmd {
                KeyPackageCommand::Shutdown => break,
                #[cfg(feature = "testing")]
                KeyPackageCommand::TestInducePanic { sentinel } => {
                    #[allow(clippy::panic)]
                    {
                        panic!("{sentinel}");
                    }
                }
                other => self.dispatch(other).await,
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
            KeyPackageCommand::Replenish { reply } => {
                let result = self.replenish_to_min().await;
                let _ = reply.send(result);
            }
            KeyPackageCommand::Publish { reply } => {
                let result = self.handle_publish();
                let _ = reply.send(result);
            }
            KeyPackageCommand::ListPooled { reply } => {
                let _ = reply.send(Ok(self.handle_list_pooled()));
            }
            // Shutdown + TestInducePanic are handled in `run()`; included for
            // exhaustiveness.
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

        // Find-and-remove from the pool.
        let Some(pos) = self.pool.iter().position(|p| p.kp_ref == kp_ref) else {
            return Err(ContextError::InvalidKeyPackage(format!(
                "no pooled key package with ref '{kp_ref}'"
            )));
        };
        let entry = self.pool.remove(pos);
        let public_bytes = entry.public_bytes;
        let signer_state = entry.signer_state;

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
            });
        }
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
                    // Ordinary crypto failure (bad/duplicate welcome). Join failed —
                    // KP NOT burned; reservation stays for retry/cancel.
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
    fn handle_publish(&mut self) -> Result<(), ContextError> {
        // Snapshot the refs+bytes to publish so we don't borrow `self.pool`
        // while mutating `published_refs`. The transport publish is sync.
        let to_publish: Vec<(KpRef, Vec<u8>)> = self
            .pool
            .iter()
            .map(|p| (p.kp_ref.clone(), p.public_bytes.clone()))
            .collect();
        let owner_did = self.identity.0.clone();

        for (kp_ref, public_bytes) in to_publish {
            if self.published_refs.contains(&kp_ref) {
                continue;
            }
            self.transport
                .publish_key_package(&owner_did, &public_bytes)
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
    /// signer-state never appears here (only `kp_ref` + public bytes).
    fn handle_list_pooled(&self) -> PooledKeyPackages {
        self.pool
            .iter()
            .map(|p| (p.kp_ref.clone(), p.public_bytes.clone()))
            .collect()
    }

    // -----------------------------------------------------------------
    // Replenishment + orphan-reservation TTL sweep
    // -----------------------------------------------------------------

    /// Sweep expired reservations, then replenish to [`MIN_BUFFER`] if
    /// `pool.len() + reserved.len()` is below [`REPLENISH_THRESHOLD`].
    async fn maybe_replenish(&mut self) {
        self.sweep_expired_reservations().await;
        if self.pool.len() + self.reserved.len() >= REPLENISH_THRESHOLD {
            return;
        }
        if let Err(e) = self.replenish_to_min().await {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %self.identity.0,
                error = %e,
                "auto-replenish failed; pool below target"
            );
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

    /// Generate KeyPackages until `pool.len() + reserved.len()` reaches
    /// [`MIN_BUFFER`]. Returns the count newly generated.
    ///
    /// On the first generate error: stop, persist what we have, and reply
    /// `Ok(count)` if any were generated (partial-retain, mirroring
    /// `KeyPackageBuffer::replenish`) else `Err(CryptoFailed)`. New pool
    /// entries are persisted as KP records (Class-C-acceptable: a lost
    /// unreserved KP is just regenerated; only reserved/consumed transitions
    /// are Class S). Fail-closes if the credential is absent (malformed-DID
    /// wiring bug) rather than pooling inert KPs.
    ///
    /// # Index/pool consistency (per-KP index persist)
    ///
    /// For each generated KP we persist the KP record, push it into the
    /// in-memory pool, then persist the index — which derives its ref list from
    /// the live `pool` + `reserved` — so a pooled KP ALWAYS has a matching index
    /// entry. If that per-KP index persist fails we roll the KP back OUT of the
    /// pool (and best-effort delete its now-orphaned record) and stop, keeping
    /// the durable index and the in-memory pool consistent: a pooled KP whose
    /// index entry was lost can otherwise never be re-pooled or re-published on
    /// respawn, leaking its record forever. The union-enumeration in
    /// [`Self::reconcile_from_storage`] is the robust backstop for any residual
    /// drift, but the source-side per-KP persist closes the leak at the write.
    async fn replenish_to_min(&mut self) -> Result<usize, ContextError> {
        let Some(credential) = self.credential.clone() else {
            return Err(ContextError::CryptoFailed(
                "key-package actor has no valid credential (malformed owning DID); \
                 refusing to generate inert key packages"
                    .to_owned(),
            ));
        };

        let current = self.pool.len() + self.reserved.len();
        if current >= MIN_BUFFER {
            return Ok(0);
        }
        let deficit = MIN_BUFFER - current;

        let mut generated = 0usize;
        let mut first_err: Option<ContextError> = None;
        for _ in 0..deficit {
            match self
                .mls
                .generate_key_package(&credential, self.wrapping_pubkey.as_ref())
                .await
            {
                Ok(generated_kp) => {
                    let kp_ref = Self::derive_kp_ref(&generated_kp.key_package_bytes);
                    // Persist the KP record (public + private signer-state).
                    if let Err(e) = self
                        .persist_kp_record(
                            &kp_ref,
                            &generated_kp.key_package_bytes,
                            &generated_kp.signer_state.bytes,
                        )
                        .await
                    {
                        first_err = Some(e);
                        break;
                    }
                    // Push into the pool FIRST so the index persist below
                    // enumerates this ref, then persist the index reliably. If
                    // the index persist fails, roll the KP back out of the pool
                    // and best-effort delete its now-orphaned record so a pooled
                    // KP can never exist without a matching index entry (the
                    // leak this guards against). Stop on failure.
                    self.pool.push(PooledKeyPackage {
                        kp_ref: kp_ref.clone(),
                        public_bytes: generated_kp.key_package_bytes,
                        // `signer_state.bytes` is already `Zeroizing<Vec<u8>>`.
                        signer_state: generated_kp.signer_state.bytes,
                    });
                    if let Err(e) = self.persist_index().await {
                        // Drop the just-pushed entry (last in the pool) and
                        // delete its orphaned record. Keep durable + in-memory
                        // consistent: no pooled KP without an index entry.
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
                        first_err = Some(e);
                        break;
                    }
                    generated += 1;
                }
                Err(e) => {
                    first_err = Some(ContextError::CryptoFailed(format!(
                        "generating key package: {e}"
                    )));
                    break;
                }
            }
        }

        if generated == 0 {
            if let Some(e) = first_err {
                return Err(e);
            }
            // deficit was >0 but we generated nothing without an error — only
            // possible if deficit underflowed, which the guard above prevents.
            return Ok(0);
        }
        Ok(generated)
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
        for consumed_ref in &consumed_refs {
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
        debug_assert!(
            consumed_refs
                .iter()
                .all(|r| !reserved_by_ref.contains_key(r)),
            "consumed precedence: no consumed ref may remain in reserved_by_ref"
        );

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
        let mut all_refs = index;
        for kp_ref in reserved_by_ref.keys() {
            if !all_refs.contains(kp_ref) {
                all_refs.push(kp_ref.clone());
            }
        }
        for kp_ref in &consumed_refs {
            if !all_refs.contains(kp_ref) {
                all_refs.push(kp_ref.clone());
            }
        }

        for kp_ref in all_refs {
            let rec = self
                .mls_storage
                .retrieve(&self.kp_record_key(&kp_ref))
                .await
                .map_err(|e| ContextError::PersistenceFailed(format!("kp record retrieve: {e}")))?;
            let Some(bytes) = rec else {
                continue; // record gone (consumed/cancelled) — not restorable.
            };
            let mut parsed: PersistedKeyPackage = match rmp_serde::from_slice(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        actor_kind = "key_package_store",
                        identity = %self.identity.0,
                        error = %e,
                        "reconcile: kp record decode failed; skipping"
                    );
                    continue;
                }
            };
            // `PersistedKeyPackage` has a `Drop` that zeroes its private
            // `signer_state`, so its fields cannot be moved out by value. Take
            // each field out via `mem::take` (leaving an empty Vec the Drop
            // harmlessly zeroes) so the private bytes move into the actor's
            // `Zeroizing` home without an un-zeroed copy.
            if let Some((rid, reserved_at_ms)) = reserved_by_ref.remove(&kp_ref) {
                self.reserved.insert(
                    rid,
                    ReservedKeyPackage {
                        kp_ref: kp_ref.clone(),
                        public_bytes: std::mem::take(&mut parsed.public_bytes),
                        signer_state: Zeroizing::new(std::mem::take(&mut parsed.signer_state)),
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
                    public_bytes: std::mem::take(&mut parsed.public_bytes),
                    signer_state: Zeroizing::new(std::mem::take(&mut parsed.signer_state)),
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

#[cfg(test)]
#[path = "key_package_actor_tests.rs"]
mod tests;
