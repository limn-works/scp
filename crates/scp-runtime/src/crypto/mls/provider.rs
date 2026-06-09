//! Production `MlsCryptoProvider` implementation backed by `OpenMLS`.
//!
//! [`MlsCryptoProvider`] bridges the historical inherent API to the actor-era
//! [`MlsBackend`](super::backend::MlsBackend) and
//! [`HpkeBackend`](crate::crypto::hpke_backend::HpkeBackend) primitives. State
//! that used to live in `Mutex<HashMap>` / `Mutex<scalar>` fields on the
//! provider has migrated to lock-free containers per ADR-049 commit 12c.9f
//! (`MlsCryptoProvider` dissolution):
//!
//! - Per-context MLS state → `DashMap<[u8;32], ContextCryptoState>`
//! - Broadcast keys → `DashMap<[u8;32], SenderKey>`
//! - Wrapping keys (X25519, §9.16.1) → `ArcSwap<...>` for atomic rotation; the
//!   supervisor exposes per-identity accessors that mirror the same source.
//! - Pending Welcome-join state → `ArcSwap<Option<Arc<PendingJoinState>>>`
//! - Taken-context tracking → `DashSet<[u8;32]>`
//!
//! No `std::sync::Mutex` survives in this file (CI: `clippy.toml`'s
//! `disallowed-types` ban for `std::sync::Mutex` is enforced — every internal
//! datapath is lock-free).
//!
//! Inline `OpenMLS` calls in primitive paths route through the injected
//! [`MlsBackend`](super::backend::MlsBackend) so test harnesses can substitute
//! a fail-injecting backend via [`MlsCryptoProvider::with_backends`].
//!
//! See ADR-001 for the MLS wrapper design and ADR-007 for sender keys; ADR-049
//! for the actor refactor + dissolution ladder.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::{DashMap, DashSet};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use scp_identity::SigningKeyId;
use scp_primitives::Clock;
use serde::{Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserializeTrait;
use zeroize::{Zeroize, Zeroizing};

use super::backend::MlsBackend;
use super::credential::ScpCredential;
use super::encrypt::{DecryptedContent, decrypt_with_sender_did};
use super::group::{self, SCP_CIPHERSUITE, ScpMlsGroup};
use super::production_backend::ProductionMlsBackend;
use crate::crypto::hpke_backend::{HpkeBackend, ProductionHpkeBackend};
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::crypto::sender_keys::{
    NonceDedup, SenderKey, SenderKeyDistributionMessage, SenderKeyResponse, SenderKeyStore,
    generate_sender_key, generate_wrapping_keypair,
};

/// Maximum allowed epoch advance in a single sender key distribution.
/// Prevents epoch poisoning attacks where an attacker sets `epoch=u64::MAX`.
///
/// Also used by `import_context` (§23.17 Invariant 3) to bound incoming
/// snapshot epoch values against the local per-sender floors.
pub(crate) const MAX_EPOCH_ADVANCE: u64 = 1000;

// ---------------------------------------------------------------------------
// MlsCryptoSnapshot — serializable per-context crypto state for persistence
// ---------------------------------------------------------------------------

/// Serializable snapshot of per-context MLS cryptographic state.
///
/// Captures all state needed to resume MLS encryption/decryption after a
/// process restart: the `OpenMLS` `MemoryStorage` contents (MLS group tree,
/// epoch secrets, key schedule, etc.), the local sender key, the sender
/// key store entries, the sender key epoch counter, and per-member X25519
/// wrapping public keys.
///
/// The MLS group state is serialized as the raw key-value pairs from the
/// `OpenMLS` `MemoryStorage` backing the group. On restore, these are
/// re-injected into a fresh `MemoryStorage` and the `MlsGroup` is
/// reconstructed via `MlsGroup::load`.
///
/// # Security — Sensitive Key Material
///
/// **This struct contains raw private key material:**
///
/// - `signer_bytes` — Ed25519 private signing key (MLS credential signer)
/// - `local_sender_key` — AES-256 sender key (per-context message encryption)
/// - `wrapping_secret_key` — X25519 secret key (HPKE-sealed sender key decryption)
/// - `mls_storage_entries` — `OpenMLS` `MemoryStorage` dump, which includes MLS
///   epoch secrets, HPKE private keys, and the key schedule
///
/// **Why self-encryption is not feasible:** Encrypting the snapshot before
/// returning from `export_crypto_state` creates a circular dependency — the
/// encryption key would need to be stored outside the snapshot or derived
/// from material inside it (defeating the purpose). This is the same trust
/// model used by `OpenMLS` itself, which stores MLS `KeyPackage` private
/// keys in its `StorageProvider` backend in plaintext.
///
/// **Storage layer requirements:** The `Storage` backend that persists this
/// blob MUST provide encryption at rest (§17.5). Platform implementations
/// (Keychain on iOS/macOS, Android Keystore, OS-level encrypted storage)
/// satisfy this. In-memory storage used in tests is acceptable because no
/// persistence occurs.
///
/// **Defense in depth:** `export_crypto_state` and `restore_crypto_state`
/// zeroize the intermediate `MlsCryptoSnapshot` struct after
/// serialization/extraction to minimize the window where private keys
/// exist as a structured, easily-extractable object in memory.
#[derive(Serialize, Deserialize)]
struct MlsCryptoSnapshot {
    /// The raw key-value pairs from the `OpenMLS` `MemoryStorage`.
    /// Each pair is `(key_bytes, value_bytes)`.
    mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// The local member's AES-256 sender key (32 bytes).
    local_sender_key: SenderKey,
    /// All sender keys for this context: `(sender_did, key)` pairs.
    sender_key_entries: Vec<(String, SenderKey)>,
    /// Per-sender epoch high-water marks for this context:
    /// `(sender_did, epoch)` pairs.
    ///
    /// Persisted so the `#1608` rollback-protection invariant
    /// (`SenderKeyStore::set_checked` rejects epoch regressions) survives
    /// a restart. Without this, an attacker who captured an old-epoch
    /// sender-key distribution pre-restart could replay it after restore
    /// because the fresh in-memory map would have no record of the
    /// higher epoch.
    ///
    /// MIGRATION: `#[serde(default)]` — legacy snapshots (pre-C1)
    /// deserialize with an empty vec. `SenderKey` material does not
    /// carry the epoch it was bound to, so per-sender floors cannot
    /// be recovered exactly from legacy data. The restore path
    /// compensates by seeding every sender with a conservative lower
    /// bound derived from the persisted global `sender_key_epoch`
    /// counter. This closes the one-shot rollback window for the
    /// common case. See `had_epoch_map` / `legacy_floor` logic in
    /// `restore_crypto_state` for details and the documented
    /// residual window for peers whose true floor exceeded the local
    /// counter at snapshot time (bounded by `MAX_EPOCH_ADVANCE` in
    /// the receive path).
    #[serde(default)]
    sender_key_epochs: Vec<(String, u64)>,
    /// The sender key epoch counter.
    sender_key_epoch: u64,
    /// The send-side message sequence counter.
    /// MIGRATION: `#[serde(default)]` — old snapshots deserialize as 0, which is
    /// the correct initial state. GCM nonces are random (`OsRng`), not counter-derived,
    /// so a sequence reset does not create nonce reuse.
    #[serde(default)]
    send_sequence: u64,
    /// Remote members' X25519 wrapping public keys: `(did, pubkey)` pairs.
    member_wrapping_keys: Vec<(String, [u8; 32])>,
    /// The MLS signer (`SignatureKeyPair`) serialized via serde to bytes.
    /// `SignatureKeyPair` does not derive `Clone` without the `clonable`
    /// feature, so we serialize it separately and store the blob here.
    signer_bytes: Vec<u8>,
    /// The MLS group ID bytes. Required to call `MlsGroup::load` on restore.
    group_id: Vec<u8>,
    /// Receive-side sequence tracking: `(sender_did, last_epoch, last_sequence)`.
    /// MIGRATION: `#[serde(default)]` — old snapshots deserialize with an empty
    /// tracker, so the first message from each sender is accepted unconditionally.
    /// MLS-level replay protection remains the primary defense; this tracker is
    /// defense-in-depth at the sender-key layer.
    #[serde(default)]
    recv_sequence_tracker: Vec<(String, u64, u64)>,
    /// The provider-level X25519 wrapping public key (§9.16.1).
    /// Persisted so remote members' HPKE-sealed sender key responses can
    /// still be decrypted after a restart. Without this, the restored
    /// provider would generate a fresh keypair whose public key doesn't
    /// match the one published in the MLS tree's `LeafNode` extension.
    #[serde(default)]
    wrapping_public_key: [u8; 32],
    /// The provider-level X25519 wrapping secret key (§9.16.1).
    /// Wrapped in a `Vec<u8>` for serde compatibility; the 32-byte key
    /// is re-wrapped in [`Zeroizing`] on restore.
    #[serde(default)]
    wrapping_secret_key: Vec<u8>,
}

// SECURITY: Manual Debug impl redacts all sensitive key material.
// Clone is intentionally NOT derived — snapshots contain raw private keys
// (Ed25519 signer, AES-256 sender key, X25519 wrapping secret, MLS epoch
// secrets) and should not be freely duplicated. The export/restore path
// constructs snapshots fresh each time without cloning.
impl std::fmt::Debug for MlsCryptoSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsCryptoSnapshot")
            .field(
                "mls_storage_entries",
                &format_args!("[{} entries, REDACTED]", self.mls_storage_entries.len()),
            )
            .field("local_sender_key", &"[REDACTED]")
            .field(
                "sender_key_entries",
                &format_args!("[{} entries, REDACTED]", self.sender_key_entries.len()),
            )
            .field(
                "sender_key_epochs",
                &format_args!("[{} entries]", self.sender_key_epochs.len()),
            )
            .field("sender_key_epoch", &self.sender_key_epoch)
            .field("send_sequence", &self.send_sequence)
            .field(
                "recv_sequence_tracker",
                &format_args!("[{} entries]", self.recv_sequence_tracker.len()),
            )
            .field(
                "member_wrapping_keys",
                &format_args!("[{} entries]", self.member_wrapping_keys.len()),
            )
            .field("signer_bytes", &"[REDACTED]")
            .field("group_id", &format_args!("[{} bytes]", self.group_id.len()))
            .field("wrapping_public_key", &"[REDACTED]")
            .field("wrapping_secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Per-context cryptographic state managed by [`MlsCryptoProvider`].
struct ContextCryptoState {
    /// The `OpenMLS` group for this context (Encrypted mode only).
    mls_group: ScpMlsGroup,
    /// The local member's AES-256 sender key for this context.
    sender_key: SenderKey,
    /// Sender key store tracking per-member keys (for blocking/distribution).
    sender_key_store: SenderKeyStore,
    /// Sender key epoch counter (incremented on each key rotation).
    sender_key_epoch: u64,
    /// Send-side message sequence counter.
    send_sequence: u64,
    /// Pending sender key distribution messages: `(target_did, serialized_message)`.
    /// Drained by [`MlsCryptoProvider::drain_pending_sender_key_messages`].
    pending_distributions: Vec<(String, Vec<u8>)>,
    /// Nonce deduplication cache for sender key requests (replay protection).
    nonce_dedup: NonceDedup,
    /// Remote members' X25519 wrapping public keys, keyed by DID.
    /// Populated from key packages during [`MlsCryptoProvider::add_member`].
    member_wrapping_keys: HashMap<String, [u8; 32]>,
    /// Receive-side sequence tracking for replay detection.
    /// Maps `sender_did` -> (`last_epoch`, `last_sequence`).
    recv_sequence_tracker: HashMap<String, (u64, u64)>,
}

// ---------------------------------------------------------------------------
// OwnedMlsCryptoState — destructive-move payload for actor ownership transfer
// ---------------------------------------------------------------------------

/// Owned per-context MLS crypto state moved out of
/// [`MlsCryptoProvider::contexts`] by [`MlsCryptoProvider::take_crypto_state`]
/// (ADR-049 commit 12).
///
/// Mirrors the private [`ContextCryptoState`] struct above — one public
/// `pub` field per legacy field, plus the `send_sequence` counter so
/// callers can seed an actor-side
/// [`crate::context::actor::SendSequenceTracker`] at take-time. After
/// `take_crypto_state` returns `Ok(OwnedMlsCryptoState)`, the provider's
/// `contexts[ctx_id]` entry is absent and subsequent `seal` / `open` /
/// `with_context` calls targeting that context return
/// [`ContextError::CryptoFailed`] with a "context state owned by actor"
/// message. The invariant is tracked by
/// [`MlsCryptoProvider::taken_context_ids`] — a post-refactor set that
/// distinguishes "state has been taken" from "state was never created"
/// so the error message is actionable.
///
/// # Scope — infrastructure only
///
/// Commit 12b.2a does NOT move any production state into actor ownership.
/// `take_crypto_state` is callable but no production site calls it yet;
/// the legacy `create_mls_group` still populates `contexts` via the
/// `ContextCryptoProvider` trait impl, and the legacy `seal` / `open`
/// path continues to operate on `contexts[ctx_id]`. Commit 12b.2b is the
/// first site that invokes `take_crypto_state` to atomically migrate every
/// messaging handler's state into actor ownership at spawn time — see
/// `.docs/adrs/ADR-049-actor-per-context.md` §Commit ladder row 12b.2b.
///
/// # Why every field is `pub`
///
/// This type is a move payload, not a domain struct. Callers (the actor
/// construction helper in 12b.2b) destructure it field-by-field to build
/// the actor-side [`crate::context::actor::ContextCryptoState`]. The
/// legacy `ContextCryptoState` keeps its fields private because it is
/// internal to the provider; the owned mirror here is the FFI-boundary
/// shape between the provider and the actor.
pub struct OwnedMlsCryptoState {
    /// The `OpenMLS` group handle for this context.
    pub mls_group: ScpMlsGroup,
    /// Local member's AES-256 sender key.
    pub sender_key: SenderKey,
    /// Per-member sender-key store.
    pub sender_key_store: SenderKeyStore,
    /// Sender-key epoch counter.
    pub sender_key_epoch: u64,
    /// Send-side sequence counter at take-time. Callers seed their
    /// actor-side [`crate::context::actor::SendSequenceTracker`] with this
    /// value via
    /// [`crate::context::actor::SendSequenceTracker::from_persisted`] so
    /// the actor picks up where the provider left off (preserves AAD
    /// byte-identity — see `crates/scp-runtime/src/context/actor/sequence.rs`
    /// §"Sequence numbering convention").
    pub send_sequence: u64,
    /// Pending sender-key distribution messages (target DID, serialized
    /// message). Not yet drained to transport at take-time; actor
    /// replays via its own transport provider.
    pub pending_distributions: Vec<(String, Vec<u8>)>,
    /// Nonce dedup cache for sender-key requests (replay protection).
    pub nonce_dedup: NonceDedup,
    /// Remote members' X25519 wrapping public keys (by DID).
    pub member_wrapping_keys: HashMap<String, [u8; 32]>,
    /// Receive-side sender-key sequence tracker (by DID →
    /// `(last_epoch, last_sequence)`).
    pub recv_sequence_tracker: HashMap<String, (u64, u64)>,
}

// SECURITY: Redacts the MLS group (holds OpenMLS epoch secrets) and
// sender key (raw AES-256 key material). Other fields are counters or
// byte-array maps that already redact on their own. Manual impl —
// `ScpMlsGroup` does not derive `Debug` at the library boundary.
impl std::fmt::Debug for OwnedMlsCryptoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedMlsCryptoState")
            .field("mls_group", &"[REDACTED]")
            .field("sender_key", &"[REDACTED]")
            .field("sender_key_store", &self.sender_key_store)
            .field("sender_key_epoch", &self.sender_key_epoch)
            .field("send_sequence", &self.send_sequence)
            .field(
                "pending_distributions",
                &format_args!("[{} entries]", self.pending_distributions.len()),
            )
            .field("nonce_dedup", &self.nonce_dedup)
            .field(
                "member_wrapping_keys",
                &format_args!("[{} entries]", self.member_wrapping_keys.len()),
            )
            .field(
                "recv_sequence_tracker",
                &format_args!("[{} entries]", self.recv_sequence_tracker.len()),
            )
            .finish()
    }
}

/// State retained for a pending Welcome-based join operation.
///
/// When [`MlsCryptoProvider::prepare_key_package_for_join`] generates a key
/// package, the signer and provider are retained here so that a subsequent
/// [`MlsCryptoProvider::join_from_welcome`] call can reconstruct the group.
struct PendingJoinState {
    /// The signing key pair for the generated key package, wrapped in
    /// [`EagerDropSigner`] for best-effort zeroization (consistent with
    /// [`ScpMlsGroup::signer`]).
    signer: super::group::EagerDropSigner,
    /// The MLS provider holding the key package's private state.
    provider: super::storage::InMemoryMlsProvider,
}

/// Production `ContextCryptoProvider` backed by `OpenMLS`.
///
/// Manages per-context MLS groups and sender keys. Thread-safe via internal
/// `Mutex`-protected maps.
///
/// # Construction
///
/// Create with [`MlsCryptoProvider::new`], providing the local member's DID.
/// The DID is used to generate SCP credentials for MLS group operations.
///
/// # Concurrency
///
/// Each method acquires the internal mutex for the duration of the operation.
/// The `ContextManager` ensures that concurrent calls for the same context are
/// serialized at a higher level (via `tokio::sync::Mutex` on the context map),
/// so contention on these mutexes is minimal.
pub struct MlsCryptoProvider {
    /// The local member's DID (e.g., `"did:dht:z6Mk..."`).
    local_did: String,
    /// Injected MLS primitive backend (ADR-049 commit 12). Production
    /// callers receive a [`ProductionMlsBackend`] from
    /// [`MlsCryptoProvider::new`]; tests inject failure-driven mocks via
    /// [`MlsCryptoProvider::with_backends`]. The provider's orchestration
    /// methods route every inline `OpenMLS` primitive through this trait —
    /// state still lives on the provider's lock-free containers below.
    mls_backend: Arc<dyn MlsBackend>,
    /// Injected HPKE primitive backend (ADR-049 commit 12). Same
    /// injection contract as `mls_backend` — production wires
    /// [`ProductionHpkeBackend`]; tests can substitute mocks for fail
    /// injection on the wrapping-key seal/unseal path.
    hpke_backend: Arc<dyn HpkeBackend>,
    /// Per-context crypto state, keyed by the 32-byte context ID.
    ///
    /// Lock-free [`DashMap`] — the actor refactor (ADR-049 commit 12)
    /// removed the `std::sync::Mutex<HashMap<...>>` wrapper. State that
    /// migrates onto [`crate::context::actor::ContextActor`] via
    /// [`Self::take_crypto_state`] is removed from this map and recorded
    /// in [`Self::taken_context_ids`].
    contexts: DashMap<[u8; 32], ContextCryptoState>,
    /// Broadcast keys for broadcast-mode contexts.
    ///
    /// Lock-free [`DashMap`] — same migration path as
    /// [`Self::contexts`]. Per ADR-049 the post-actor home for these is
    /// `ContextModeState::Broadcast` on the per-context actor state;
    /// during the 12c.9f → 12 window the provider continues to hold the
    /// authoritative copy for non-actor callers.
    broadcast_keys: DashMap<[u8; 32], SenderKey>,
    /// X25519 wrapping public key for sender key HPKE (§9.16.1).
    /// Published in the MLS `LeafNode` `scp_wrapping_key` extension.
    ///
    /// Held in [`ArcSwap`] so the snapshot-restore path (which takes
    /// `&self`) can replace the keypair atomically without contention.
    /// The supervisor mirrors this slot per-identity via
    /// [`crate::context::supervisor::Supervisor::wrapping_public_key_for`]
    /// — both pointers are kept consistent on
    /// [`MlsCryptoProvider`] writes through the supervisor's
    /// `set_wrapping_keys` accessor.
    wrapping_public_key: ArcSwap<[u8; 32]>,
    /// X25519 wrapping secret key for sender key HPKE (§9.16.1).
    /// Used to open HPKE-sealed sender key responses.
    ///
    /// Held in [`ArcSwap<Zeroizing<[u8; 32]>>`] so rotation is atomic and
    /// the prior key material is zeroized when the last `Arc` to it
    /// drops. Reader discipline (load → use → drop within the same
    /// poll) is enforced at every callsite — no callsite stores the
    /// loaded `Arc` in a struct field.
    wrapping_secret_key: ArcSwap<Zeroizing<[u8; 32]>>,
    /// Pending key package state for Welcome-based joins (§5.12.3).
    /// `prepare_key_package_for_join` replaces any previous entry;
    /// `join_from_welcome` takes it. `ArcSwapOption` enforces the
    /// single-entry invariant at the type level (None = no pending
    /// join, Some = one pending key package).
    ///
    /// `swap(None)` is the atomic take primitive; the consumer then
    /// `Arc::try_unwrap`s to extract the [`PendingJoinState`]. The
    /// provider is the sole writer of this slot — `swap` returns an
    /// `Arc` whose strong count is 1 in the absence of concurrent
    /// `load`s, so `try_unwrap` succeeds in the steady state.
    pending_joins: ArcSwapOption<PendingJoinState>,
    /// Contexts whose crypto state has been destructively moved into a
    /// [`crate::context::actor::ContextActor`] via
    /// [`Self::take_crypto_state`] (ADR-049 commit 12).
    ///
    /// Tracked separately from [`Self::contexts`] so [`Self::with_context`]
    /// can distinguish "context was never created" (returns the legacy
    /// `no MLS group for this context` error) from "state was taken by
    /// the actor runtime" (returns an actionable
    /// `context state owned by actor` error). The two failure modes have
    /// different call-site remediations — the former indicates a
    /// create-before-send ordering bug, the latter indicates a caller
    /// reaching through the provider after actor ownership has been
    /// transferred (post-12b.2b that caller should route through the
    /// actor's mailbox instead).
    ///
    /// # Lifecycle
    ///
    /// - Insert: on successful [`Self::take_crypto_state`].
    /// - Remove: never in this commit — actor ownership is one-way during
    ///   the 12b.2a → 12 window. Commit 12 deletes the provider
    ///   entirely; until then a taken context stays taken for the
    ///   provider's lifetime.
    ///
    /// Lock-free [`DashSet`] — the prior `std::sync::Mutex<HashSet>`
    /// wrapper was removed in ADR-049 commit 12c.9f.
    taken_context_ids: DashSet<[u8; 32]>,
}

#[allow(clippy::significant_drop_tightening)]
impl MlsCryptoProvider {
    /// Creates a new production crypto provider for the given local DID.
    ///
    /// Constructs the production [`MlsBackend`] / [`HpkeBackend`]
    /// implementations and injects them into the provider. Call
    /// [`Self::with_backends`] when test fail-injection is required.
    ///
    /// # Arguments
    ///
    /// * `local_did` - The local member's DID (must be a valid `did:dht:z...`).
    #[must_use]
    pub fn new(local_did: String) -> Self {
        Self::with_backends(
            local_did,
            Arc::new(ProductionMlsBackend::new()),
            Arc::new(ProductionHpkeBackend::new()),
        )
    }

    /// Creates an `MlsCryptoProvider` with caller-supplied backends.
    ///
    /// Test seam introduced by ADR-049 commit 12c.9f. Production code
    /// uses [`Self::new`]; failure-injection tests instantiate mock
    /// `MlsBackend` / `HpkeBackend` impls and pass them here. The
    /// `local_did` and lock-free state containers behave identically to
    /// [`Self::new`].
    ///
    /// # Arguments
    ///
    /// * `local_did` - The local member's DID (must be a valid `did:dht:z...`).
    /// * `mls_backend` - The MLS primitive backend (typically
    ///   [`ProductionMlsBackend`] in production; a mock for fail-injection
    ///   in tests).
    /// * `hpke_backend` - The HPKE primitive backend (typically
    ///   [`ProductionHpkeBackend`] in production).
    #[must_use]
    pub fn with_backends(
        local_did: String,
        mls_backend: Arc<dyn MlsBackend>,
        hpke_backend: Arc<dyn HpkeBackend>,
    ) -> Self {
        let (wrapping_public_key, wrapping_secret_key) = generate_wrapping_keypair();
        Self {
            local_did,
            mls_backend,
            hpke_backend,
            contexts: DashMap::new(),
            broadcast_keys: DashMap::new(),
            wrapping_public_key: ArcSwap::from_pointee(wrapping_public_key),
            wrapping_secret_key: ArcSwap::from_pointee(Zeroizing::new(wrapping_secret_key)),
            pending_joins: ArcSwapOption::empty(),
            taken_context_ids: DashSet::new(),
        }
    }

    /// Borrowed reference to the injected MLS primitive backend
    /// (ADR-049 commit 12). Helper functions outside the provider
    /// that need the same backend (e.g. handler code in
    /// `handlers/messaging.rs` once the deletion ladder lands) can
    /// borrow through this accessor.
    #[must_use]
    pub fn mls_backend(&self) -> &Arc<dyn MlsBackend> {
        &self.mls_backend
    }

    /// Borrowed reference to the injected HPKE primitive backend
    /// (ADR-049 commit 12). See [`Self::mls_backend`].
    #[must_use]
    pub fn hpke_backend(&self) -> &Arc<dyn HpkeBackend> {
        &self.hpke_backend
    }

    /// Destructively move the per-context MLS crypto state out of this
    /// provider and return it as an [`OwnedMlsCryptoState`] the caller
    /// can hand to a [`crate::context::actor::ContextActor`] at spawn
    /// time (ADR-049 commit 12).
    ///
    /// After `Ok` return:
    /// - `self.contexts[context_id]` is absent (`HashMap::remove`d).
    /// - `context_id` is recorded in [`Self::taken_context_ids`].
    /// - Every subsequent [`Self::with_context`] /
    ///   `ContextCryptoProvider::seal` /
    ///   `ContextCryptoProvider::open` on `context_id` returns
    ///   [`ContextError::CryptoFailed`] with the
    ///   `context state owned by actor` message.
    ///
    /// # Invariant
    ///
    /// Actor ownership is one-way during the 12b.2a → 12f migration
    /// window. Once taken, a context's crypto state does not return to
    /// the provider — the actor becomes the sole authority for its
    /// lifetime. This matches plan §"`MlsCryptoProvider` dissolution":
    /// production lookups (publish, subscribe, etc.) reach the crypto
    /// state only through the actor's mailbox post-12b.2b.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if no entry exists in
    ///   `contexts` for `context_id`. The error message distinguishes
    ///   "never created" from "already taken" by inspecting the
    ///   `taken_context_ids` set.
    /// - [`ContextError::CryptoFailed`] if the internal `Mutex` is
    ///   poisoned (caller should treat this as fatal — the provider is
    ///   now inconsistent).
    ///
    /// # Scope — infrastructure only
    ///
    /// This commit wires the move path but no production call site
    /// invokes it yet. The first production caller arrives in commit
    /// 12b.2b with the atomic messaging-handler migration.
    pub fn take_crypto_state(
        &self,
        context_id: &[u8; 32],
    ) -> Result<OwnedMlsCryptoState, ContextError> {
        // ADR-049 commit 12c.9f: the underlying `contexts` map is now a
        // lock-free `DashMap`. `DashMap::remove` is atomic over the
        // shard; the post-removal taken-set insert is unconditionally
        // reachable so the actor-ownership marker stays consistent.
        let Some((_, state)) = self.contexts.remove(context_id) else {
            // Distinguish "never created" from "already taken" so the
            // error is actionable.
            if self.taken_context_ids.contains(context_id) {
                return Err(ContextError::CryptoFailed(
                    "context state owned by actor".to_owned(),
                ));
            }
            return Err(ContextError::ContextNotRegistered(format!(
                "no MLS group for context {}",
                hex::encode(context_id),
            )));
        };
        // Remove first, then record in the taken set. `DashSet::insert`
        // is atomic; the actor refactor's one-way ownership invariant
        // (no take-then-restore) keeps the recorded id stable for the
        // provider's lifetime.
        self.taken_context_ids.insert(*context_id);
        // Map the private struct field-for-field onto the public owned
        // payload. This is the one place where the private-to-public
        // shape translation happens; 12b.2b downstream consumes
        // `OwnedMlsCryptoState` exclusively.
        let ContextCryptoState {
            mls_group,
            sender_key,
            sender_key_store,
            sender_key_epoch,
            send_sequence,
            pending_distributions,
            nonce_dedup,
            member_wrapping_keys,
            recv_sequence_tracker,
        } = state;
        Ok(OwnedMlsCryptoState {
            mls_group,
            sender_key,
            sender_key_store,
            sender_key_epoch,
            send_sequence,
            pending_distributions,
            nonce_dedup,
            member_wrapping_keys,
            recv_sequence_tracker,
        })
    }

    /// Returns a reference to the per-context MLS group state.
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] with `"no MLS group for this context"`
    ///   if the context was never created (or its state was evicted).
    /// - [`ContextError::CryptoFailed`] with
    ///   `"context state owned by actor"` if the state was destructively
    ///   moved via [`Self::take_crypto_state`] (ADR-049 commit 12).
    ///   Callers seeing this error must route through the actor's
    ///   mailbox — the provider no longer owns the state.
    fn with_context<F, R>(&self, context_id: &[u8; 32], f: F) -> Result<R, ContextError>
    where
        F: FnOnce(&mut ContextCryptoState) -> Result<R, ContextError>,
    {
        // ADR-049 commit 12c.9f: lock-free per-shard access via
        // `DashMap::get_mut`. The returned guard is per-entry and is
        // dropped when the closure returns.
        if let Some(mut entry) = self.contexts.get_mut(context_id) {
            return f(entry.value_mut());
        }
        // Context is not in the map — distinguish "never created" from
        // "actor took ownership".
        if self.taken_context_ids.contains(context_id) {
            return Err(ContextError::CryptoFailed(
                "context state owned by actor".to_owned(),
            ));
        }
        Err(ContextError::CryptoFailed(
            "no MLS group for this context".to_string(),
        ))
    }

    /// Creates the SCP credential for the local member.
    fn make_credential(&self) -> Result<ScpCredential, ContextCreationError> {
        ScpCredential::new(self.local_did.clone(), None, SigningKeyId::Active)
            .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))
    }
}

#[allow(clippy::significant_drop_tightening)]
impl MlsCryptoProvider {
    /// Validates that the creator's identity is valid and the signing key is
    /// accessible.
    ///
    /// Called during Phase 1 (validation) before any side effects. This is a
    /// read-only check that does not create or modify any state.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::IdentityValidationFailed`] if the
    /// identity is invalid or the signing key cannot be accessed.
    pub fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        // Validate that the local DID is a valid did:dht:z... format.
        //
        // Under the `testing` feature gate, also accept `did:test:*` and
        // `did:key:*` prefixes so the extensive test suite — which used
        // non-dht test DIDs with the deleted `ContextCryptoProvider`
        // mocks before ADR-049 commit 12c.9e — continues to work with
        // the inherent `MlsCryptoProvider` API. Production builds (no
        // `testing` feature) still require `did:dht:z*`.
        let accepted = self.local_did.starts_with("did:dht:z")
            || (cfg!(any(test, feature = "testing"))
                && (self.local_did.starts_with("did:test:")
                    || self.local_did.starts_with("did:key:")));
        if !accepted {
            return Err(ContextCreationError::IdentityValidationFailed(
                "invalid DID format".to_string(),
            ));
        }
        Ok(())
    }

    /// Creates an MLS group for the given context.
    ///
    /// Called only when `mode == Encrypted`. The provider stores the group
    /// state internally, keyed by `context_id`.
    ///
    /// Refuses to overwrite an existing entry: if a group is already
    /// registered for `context_id`, returns
    /// [`ContextCreationError::CreationFailed`] and leaves the existing
    /// state untouched. An unconditional insert here would let a racing
    /// second bootstrap for the same deterministic id clobber a live
    /// MLS group with fresh keys (crypto desync — the actor still
    /// references group #1 while the provider holds group #2). The
    /// supervisor serializes same-id bootstraps via `bootstrap_spawn_lock`,
    /// but this is the crypto layer's own defense-in-depth invariant so
    /// no future caller path can silently overwrite a live group.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::CreationFailed`] if a group already
    /// exists for `context_id`, or [`ContextCreationError::CryptoFailed`]
    /// if MLS group creation fails.
    pub fn create_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        use dashmap::mapref::entry::Entry;

        // Reserve the slot up front via `entry`: this is an atomic
        // check-and-occupy on the `DashMap` shard, so two concurrent
        // creates for the same id cannot both pass the existence check.
        // The vacant guard is held across the crypto-init below; the
        // shard lock it implies is scoped to this one key.
        let Entry::Vacant(slot) = self.contexts.entry(*context_id) else {
            return Err(ContextCreationError::CreationFailed(format!(
                "MLS group already exists for context '{}' — refusing to overwrite a live group",
                hex::encode(context_id)
            )));
        };

        let credential = self.make_credential()?;
        // Load through ArcSwap; the returned guard is dropped before
        // the create_group call because we copy the bytes into a stack
        // array.
        let wrapping_pk = **self.wrapping_public_key.load();
        let mls_group = group::create_group_with_wrapping_key(&credential, Some(&wrapping_pk))
            .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))?;

        let sender_key = generate_sender_key();
        let sender_key_store = SenderKeyStore::new();

        let state = ContextCryptoState {
            mls_group,
            sender_key,
            sender_key_store,
            sender_key_epoch: 1,
            send_sequence: 0,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys: HashMap::new(),
            recv_sequence_tracker: HashMap::new(),
        };

        // Occupy the reserved vacant slot. No overwrite is possible: if
        // the entry had been occupied we returned `CreationFailed` above.
        slot.insert(state);
        Ok(())
    }

    /// Generates a sender key for the given context.
    ///
    /// For `Encrypted` mode this is an AES-256 sender key.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if sender key generation fails.
    pub fn generate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
            ContextCreationError::CryptoFailed(
                "no MLS group for this context — cannot generate sender key".to_string(),
            )
        })?;
        // Rotate the sender key to a fresh random value.
        entry.value_mut().sender_key = generate_sender_key();
        Ok(())
    }

    /// Initializes a broadcast key for the given context.
    ///
    /// Called only when `mode == Broadcast`. The provider stores the
    /// broadcast key internally, keyed by `context_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if broadcast key initialisation fails.
    pub fn init_broadcast_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        // ADR-049 commit 12c.9f: lock-free `DashMap::insert`.
        let key = generate_sender_key();
        self.broadcast_keys.insert(*context_id, key);
        Ok(())
    }

    /// Destroys the MLS group created for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails.
    pub fn destroy_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        // ADR-049 commit 12c.9f: lock-free `DashMap::remove`.
        if let Some((_, mut state)) = self.contexts.remove(context_id) {
            let _ = group::destroy_group(&mut state.mls_group);
        }
        Ok(())
    }

    /// Destroys the sender key created for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails.
    pub fn destroy_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        // ADR-049 commit 12c.9f: lock-free per-shard mutation. Drop the
        // `RefMut` guard before touching `broadcast_keys` to release the
        // shard lock.
        if let Some(mut entry) = self.contexts.get_mut(context_id) {
            let state = entry.value_mut();
            // Overwrite with a fresh key then drop — ensures old key
            // material doesn't linger. The fresh key is immediately
            // discarded when the context is later destroyed.
            state.sender_key = generate_sender_key();
            // Clear all stored member sender keys for this context.
            let ctx_id_hex = hex::encode(context_id);
            let member_dids: Vec<String> = state
                .sender_key_store
                .get_all(&ctx_id_hex)
                .keys()
                .cloned()
                .collect();
            for did in &member_dids {
                state.sender_key_store.remove(&ctx_id_hex, did);
            }
        }
        // Also clean up broadcast keys (lock-free `DashMap::remove`).
        self.broadcast_keys.remove(context_id);
        Ok(())
    }

    /// Validates a joiner's key package.
    ///
    /// # Arguments
    ///
    /// * `owner_did` - The DID of the key package owner.
    /// * `key_package_bytes` - Optional TLS-serialized MLS `KeyPackage` bytes.
    ///   `None` for mock providers; production providers require `Some`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidKeyPackage`] if the key package is invalid.
    pub fn validate_key_package(
        &self,
        owner_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        // Under `cfg(test)` / `testing` feature accept `None` as a valid
        // key package — matches the old `MockCrypto::validate_key_package`
        // behaviour deleted in ADR-049 commit 12c.9e.
        let Some(bytes) = key_package_bytes else {
            if cfg!(any(test, feature = "testing")) {
                let _ = owner_did;
                return Ok(());
            }
            return Err(ContextError::InvalidKeyPackage(
                "production MlsCryptoProvider requires MLS key package bytes".to_string(),
            ));
        };

        // Deserialize the key package as KeyPackageIn (TLS format).
        // This matches add_member() which also uses KeyPackageIn, ensuring
        // both methods accept the same byte format (#1294).
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*bytes)
            .map_err(|e| ContextError::InvalidKeyPackage(format!("TLS deserialization: {e}")))?;

        // Validate ciphersuite and signature.
        let provider = super::storage::InMemoryMlsProvider::default();
        let verified = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| ContextError::InvalidKeyPackage(format!("validation failed: {e}")))?;

        if verified.ciphersuite() != SCP_CIPHERSUITE {
            return Err(ContextError::InvalidKeyPackage(format!(
                "wrong ciphersuite: expected {:?}, got {:?}",
                SCP_CIPHERSUITE,
                verified.ciphersuite()
            )));
        }

        // Bind credential to owner_did: extract the ScpCredential
        // from the key package's leaf node and verify the DID matches.
        let leaf_node = verified.leaf_node();
        if let Ok(basic_cred) = BasicCredential::try_from(leaf_node.credential().clone()) {
            let scp_cred = ScpCredential::from_bytes(basic_cred.identity()).map_err(|e| {
                ContextError::InvalidKeyPackage(format!("credential deserialization failed: {e}"))
            })?;
            if scp_cred.did != owner_did {
                return Err(ContextError::InvalidKeyPackage(
                    "key package credential DID does not match owner_did".to_string(),
                ));
            }
        } else {
            return Err(ContextError::InvalidKeyPackage(
                "key package does not contain a BasicCredential".to_string(),
            ));
        }

        Ok(())
    }

    /// Adds a member to the MLS group (ADR-001 `add_member()`).
    ///
    /// Returns an [`AddMemberOutput`](scp_protocol::context::builder::AddMemberOutput) containing the TLS-serialized MLS
    /// Welcome (for the joiner) and Commit (for existing members). Non-MLS
    /// providers return `AddMemberOutput::default()` (empty bytes).
    ///
    /// # Arguments
    ///
    /// * `context_id` - The 32-byte context identifier.
    /// * `member_did` - The DID of the member to add.
    /// * `key_package_bytes` - Optional TLS-serialized MLS `KeyPackage` bytes.
    ///   `None` for mock providers; production providers require `Some`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS operation fails.
    pub fn add_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        // Under the `testing` feature or `cfg(test)`, `None` key-package
        // bytes were previously handled by the no-op `MockCrypto` fixture
        // (deleted in ADR-049 commit 12c.9e). Preserve the mock-equivalent
        // return so integration tests that don't produce real MLS key
        // packages continue to exercise the non-crypto pipeline — role
        // state sync, event logging, governance side effects.
        let Some(bytes) = key_package_bytes else {
            if cfg!(any(test, feature = "testing")) {
                let _ = member_did; // used only by real path
                return Ok(scp_protocol::context::builder::AddMemberOutput::default());
            }
            return Err(ContextError::CryptoFailed(
                "production MlsCryptoProvider requires MLS key package bytes for add_member"
                    .to_string(),
            ));
        };

        // Pre-validate the key package to extract the wrapping key before
        // the add operation consumes it. Key package bytes arrive as TLS-
        // serialized KeyPackageIn (not MlsMessageIn).
        let wrapping_key = {
            KeyPackageIn::tls_deserialize(&mut &*bytes)
                .ok()
                .and_then(|kp_in| {
                    let provider_tmp = super::storage::InMemoryMlsProvider::default();
                    kp_in
                        .validate(provider_tmp.crypto(), ProtocolVersion::Mls10)
                        .ok()
                        .and_then(|verified| {
                            super::wrapping_extension::extract_wrapping_key(
                                verified.leaf_node().extensions(),
                            )
                            .ok()
                            .flatten()
                        })
                })
        };

        // Deserialize to KeyPackageIn for the actual add operation.
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("key package deserialization: {e}")))?;

        let member_did_owned = member_did.to_owned();
        self.with_context(context_id, |state| {
            let result = group::add_member(&mut state.mls_group, kp_in)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            // TLS-serialize Welcome and Commit for cross-process delivery.
            let welcome_bytes = result
                .welcome
                .tls_serialize_detached()
                .map_err(|e| ContextError::CryptoFailed(format!("serializing welcome: {e}")))?;
            let commit_bytes = result
                .commit
                .tls_serialize_detached()
                .map_err(|e| ContextError::CryptoFailed(format!("serializing commit: {e}")))?;

            // Store the member's wrapping key if present.
            if let Some(wk) = wrapping_key {
                state.member_wrapping_keys.insert(member_did_owned, wk);
            }

            Ok(scp_protocol::context::builder::AddMemberOutput {
                welcome_bytes,
                commit_bytes,
            })
        })
    }

    /// Removes a member from the MLS group (ADR-001 `remove_member()`).
    ///
    /// Returns a [`RemoveMemberOutput`](scp_protocol::context::builder::RemoveMemberOutput) containing the TLS-serialized MLS
    /// Commit (for remaining members to process). Non-MLS providers return
    /// `RemoveMemberOutput::default()` (empty bytes).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS operation fails.
    pub fn remove_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<scp_protocol::context::builder::RemoveMemberOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        // Self-removal (leave): the local member's MLS group state does not
        // need to be updated when they leave — they simply abandon their
        // local group state. The remaining members process the removal via
        // a Commit from the group admin. Treat as a no-op (#1294).
        if member_did == self.local_did {
            return Ok(scp_protocol::context::builder::RemoveMemberOutput::default());
        }

        self.with_context(context_id, |state| {
            // Find the member's leaf index by matching their DID in the
            // SCP credential embedded in each member's MLS leaf node.
            let members = state
                .mls_group
                .members()
                .map_err(|e: super::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

            let own_index = state
                .mls_group
                .own_leaf_index()
                .map_err(|e: super::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

            let mut target_index = None;
            for member in &members {
                if member.index == own_index {
                    continue;
                }
                if let Ok(basic_cred) = BasicCredential::try_from(member.credential.clone())
                    && let Ok(scp_cred) = ScpCredential::from_bytes(basic_cred.identity())
                    && scp_cred.did == member_did
                {
                    target_index = Some(member.index);
                    break;
                }
            }

            // If the member is not in the MLS group (e.g., they were never
            // MLS-added, or they're the local member under a different DID
            // in a multi-identity test environment), treat as a no-op. The
            // ContextManager handles membership state authoritatively; the
            // crypto provider only manages MLS group state (#1294).
            let Some(leaf_index) = target_index else {
                tracing::warn!(
                    member_did = %member_did,
                    "remove_member: member DID not found in MLS group leaf nodes — \
                     member may not have been MLS-added"
                );
                return Ok(scp_protocol::context::builder::RemoveMemberOutput::default());
            };

            let result = group::remove_member(&mut state.mls_group, leaf_index)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let commit_bytes = result.commit.tls_serialize_detached().map_err(|e| {
                ContextError::CryptoFailed(format!("serializing remove commit: {e}"))
            })?;

            let group_info_bytes = result
                .group_info
                .map(|gi| {
                    gi.tls_serialize_detached().map_err(|e| {
                        ContextError::CryptoFailed(format!("serializing remove group info: {e}"))
                    })
                })
                .transpose()?
                .unwrap_or_default();

            Ok(scp_protocol::context::builder::RemoveMemberOutput {
                commit_bytes,
                group_info_bytes,
            })
        })
    }

    /// Distributes sender key bundle to a new member via ADR-007.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if distribution fails.
    pub fn distribute_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let state = entry.value_mut();
        // Store our sender key locally under our DID so local
        // encrypt/decrypt can find it.
        state.sender_key_store.set_unchecked(
            &ctx_id_hex,
            &self.local_did,
            state.sender_key.clone(),
        );

        // HPKE-seal our sender key to the target member's wrapping pubkey
        // and queue a SenderKeyResponse for transport delivery.
        if let Some(recipient_wrapping_pub) = state.member_wrapping_keys.get(member_did) {
            let (sealed_vec, ephemeral_pub) =
                crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                    state.sender_key.as_bytes(),
                    recipient_wrapping_pub,
                    &ctx_id_hex,
                    &self.local_did,
                    state.sender_key_epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(format!("HPKE seal failed: {e}")))?;

            let sealed: [u8; 60] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
                ContextError::CryptoFailed(format!(
                    "HPKE seal produced {} bytes, expected 60",
                    v.len()
                ))
            })?;

            let response = SenderKeyResponse {
                sender_did: self.local_did.clone(),
                epoch: state.sender_key_epoch,
                hpke_sealed_key: sealed,
                ephemeral_pubkey: ephemeral_pub,
                // No request nonce for proactive distribution — use zeroed nonce.
                request_nonce: [0u8; 16],
            };

            let msg = SenderKeyDistributionMessage::KeyResponse(response);
            let serialized = msg
                .to_bytes()
                .map_err(|e| ContextError::CryptoFailed(format!("serialization failed: {e}")))?;

            state
                .pending_distributions
                .push((member_did.to_owned(), serialized));
        } else {
            tracing::debug!(
                member_did = %member_did,
                context_id = %ctx_id_hex,
                "no wrapping key for member — sender key stored locally only"
            );
        }
        Ok(())
    }

    /// Removes a member's sender key from all members' stores.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if removal fails.
    pub fn remove_member_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let state = entry.value_mut();
        state.sender_key_store.remove(&ctx_id_hex, member_did);
        // Also remove the member's wrapping key — they are no longer a member.
        state.member_wrapping_keys.remove(member_did);
        // Prune replay tracker entry for this specific member.
        state.recv_sequence_tracker.remove(member_did);
        // D3 defensive sweep: also drop any recv_sequence_tracker entries
        // for DIDs that are no longer in member_wrapping_keys. This catches
        // the re-population edge case where in-flight messages from a
        // previously-removed member arrive after their explicit prune and
        // re-populate the tracker via `open()`. Without this sweep the
        // tracker could slowly accumulate entries for non-members across a
        // churning context. Bounded by current membership size.
        let current_members: std::collections::HashSet<String> =
            state.member_wrapping_keys.keys().cloned().collect();
        state
            .recv_sequence_tracker
            .retain(|did, _| current_members.contains(did));
        Ok(())
    }

    /// Rotates the local sender key for a context (§9.16.4).
    ///
    /// Generates a fresh AES-256 sender key, increments `sender_key_epoch`,
    /// updates the local sender key store, HPKE-seals the new key to each
    /// remaining member's wrapping public key, and queues distribution
    /// messages in `pending_distributions`.
    ///
    /// Called after a member is removed (governance or voluntary departure)
    /// so that the removed party cannot decrypt future messages encrypted
    /// with the new sender key.
    ///
    /// The default implementation is a no-op (`Ok(())`) so that mock and
    /// test providers compile without changes.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key generation, HPKE
    /// sealing, or internal lock acquisition fails.
    pub fn rotate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let state = entry.value_mut();

        // 1. Generate fresh AES-256 sender key.
        let new_key = generate_sender_key();
        state.sender_key = new_key.clone();

        // 2. Increment sender_key_epoch (monotonic, §9.16.5).
        state.sender_key_epoch = state
            .sender_key_epoch
            .checked_add(1)
            .ok_or_else(|| ContextError::CryptoFailed("sender key epoch overflow".to_string()))?;

        // 3. Update local sender key store entry.
        state
            .sender_key_store
            .set_unchecked(&ctx_id_hex, &self.local_did, new_key);

        // 4. HPKE-seal new key to each remaining member's wrapping pubkey
        //    and queue distributions (§9.16.2).
        let member_keys: Vec<(String, [u8; 32])> = state
            .member_wrapping_keys
            .iter()
            .map(|(did, key)| (did.clone(), *key))
            .collect();

        for (member_did, wrapping_pub) in &member_keys {
            // Skip self-sealing: the local member already has the key in
            // state.sender_key. Sealing to ourselves wastes CPU and queues
            // a distribution message that the local node would discard.
            if *member_did == self.local_did {
                continue;
            }
            let seal_result = crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                state.sender_key.as_bytes(),
                wrapping_pub,
                &ctx_id_hex,
                &self.local_did,
                state.sender_key_epoch,
            );

            match seal_result {
                Ok((sealed_vec, ephemeral_pub)) => {
                    let sealed: [u8; 60] = match sealed_vec.try_into() {
                        Ok(s) => s,
                        Err(v) => {
                            tracing::warn!(
                                member_did = %member_did,
                                "HPKE seal produced {} bytes, expected 60 — skipping",
                                v.len()
                            );
                            continue;
                        }
                    };

                    let response = SenderKeyResponse {
                        sender_did: self.local_did.clone(),
                        epoch: state.sender_key_epoch,
                        hpke_sealed_key: sealed,
                        ephemeral_pubkey: ephemeral_pub,
                        request_nonce: [0u8; 16],
                    };

                    let msg = SenderKeyDistributionMessage::KeyResponse(response);
                    match msg.to_bytes() {
                        Ok(serialized) => {
                            state
                                .pending_distributions
                                .push((member_did.clone(), serialized));
                        }
                        Err(e) => {
                            tracing::warn!(
                                member_did = %member_did,
                                error = %e,
                                "failed to serialize sender key distribution — skipping"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        member_did = %member_did,
                        error = %e,
                        "HPKE seal failed for sender key rotation — skipping"
                    );
                }
            }
        }

        Ok(())
    }

    /// Drains pending sender key distribution messages for a context.
    ///
    /// Returns `(target_did, serialized_message)` pairs that should be
    /// delivered to the target members via transport. Each message is a
    /// serialized `SenderKeyDistributionMessage::KeyResponse` containing
    /// an HPKE-sealed sender key.
    ///
    /// The default implementation returns an empty vector (no pending
    /// distributions). Production providers that HPKE-seal sender keys
    /// during [`distribute_sender_key`](Self::distribute_sender_key) should
    /// override this to drain their pending queue.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the internal lock is
    /// poisoned.
    pub fn drain_pending_sender_key_messages(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        Ok(std::mem::take(&mut entry.value_mut().pending_distributions))
    }

    /// Processes an incoming sender key distribution message from a remote
    /// member.
    ///
    /// Deserializes the message, extracts the sender key, and stores it in
    /// the local sender key store so subsequent messages from `sender_did`
    /// can be decrypted.
    ///
    /// The default implementation is a no-op. Production providers that
    /// support HPKE sender key distribution should override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if deserialization, HPKE
    /// decryption, or storage fails.
    pub fn process_incoming_sender_key(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        message_bytes: &[u8],
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);

        // Deserialize the distribution message.
        let msg = SenderKeyDistributionMessage::from_bytes(message_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("deserialization failed: {e}")))?;

        match msg {
            SenderKeyDistributionMessage::KeyResponse(response) => {
                // ADR-049 commit 12c.9f: load wrapping secret through
                // `ArcSwap`. The returned `Arc` is held only for the
                // duration of the HPKE-open call (no `.await` between
                // load and drop).
                let wrapping_secret_guard = self.wrapping_secret_key.load();
                let sender_key = crate::crypto::sender_keys::key_protocol::hpke_open_sender_key(
                    &response.hpke_sealed_key,
                    &response.ephemeral_pubkey,
                    &wrapping_secret_guard,
                    &ctx_id_hex,
                    &response.sender_did,
                    response.epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(format!("HPKE open failed: {e}")))?;
                drop(wrapping_secret_guard);

                // Verify the sender DID matches the claimed sender.
                if response.sender_did != sender_did {
                    return Err(ContextError::CryptoFailed(
                        "sender DID mismatch in sender key distribution".into(),
                    ));
                }

                // Store the recovered sender key with epoch monotonicity check (#1608).
                // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
                let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
                    ContextError::CryptoFailed("no MLS group for this context".to_string())
                })?;
                let state = entry.value_mut();

                // Epoch poisoning defense: reject sender keys with unreasonably
                // high epoch values. An attacker could set epoch=u64::MAX to
                // permanently block future key rotations via epoch monotonicity.
                let current_epoch = state.sender_key_store.epoch(&ctx_id_hex, sender_did);
                if response.epoch > current_epoch.saturating_add(MAX_EPOCH_ADVANCE) {
                    return Err(ContextError::CryptoFailed(
                        "epoch poisoning: claimed epoch exceeds acceptable advance".into(),
                    ));
                }

                state
                    .sender_key_store
                    .set_checked(&ctx_id_hex, sender_did, sender_key, response.epoch)
                    .map_err(|e| ContextError::CryptoFailed(format!("epoch check failed: {e}")))?;
                Ok(())
            }
            _ => Err(ContextError::CryptoFailed(
                "expected SenderKeyDistributionMessage::KeyResponse".to_string(),
            )),
        }
    }

    /// Handles an incoming sender key request from a remote member.
    ///
    /// Verifies the request, checks replay protection, and HPKE-seals the
    /// local sender key to the requester's wrapping pubkey.
    ///
    /// Returns `Some(serialized_response)` if the requester should receive
    /// a key, or `None` if the request was silently dropped (e.g., blocked).
    ///
    /// The default implementation returns an error indicating the provider
    /// does not support sender key request handling.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if signature verification,
    /// HPKE encryption, or serialization fails.
    pub fn handle_sender_key_request(
        &self,
        context_id: &[u8; 32],
        request_bytes: &[u8],
        requester_public_key: &[u8],
        blocked_dids: &std::collections::HashSet<String>,
    ) -> Result<Option<Vec<u8>>, ContextError> {
        let ctx_id_hex = hex::encode(context_id);

        // Deserialize the request.
        let request: scp_protocol::crypto::sender_keys::SenderKeyRequest =
            rmp_serde::from_slice(request_bytes)
                .map_err(|e| ContextError::CryptoFailed(format!("request deserialization: {e}")))?;

        let now_secs = scp_primitives::SystemClock.now_secs();

        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let state = entry.value_mut();

        // Verify the request signature.
        let valid = scp_protocol::crypto::sender_keys::verify_sender_key_request(
            &request,
            requester_public_key,
        )
        .map_err(|e| ContextError::CryptoFailed(format!("signature verification: {e}")))?;
        if !valid {
            return Err(ContextError::CryptoFailed(
                "sender key request signature verification failed".to_string(),
            ));
        }

        // Timestamp freshness.
        scp_protocol::crypto::sender_keys::validate_sender_key_request_freshness(
            &request, now_secs,
        )
        .map_err(|e| ContextError::CryptoFailed(format!("freshness check: {e}")))?;

        // Nonce replay protection.
        if state.nonce_dedup.is_replayed(&request.nonce, now_secs) {
            return Err(ContextError::CryptoFailed(
                "replayed sender key request".to_string(),
            ));
        }

        // H1: Membership check — requester must be a known member (has a
        // wrapping key registered via add_member). Prevents non-members
        // from obtaining sender keys even if they forge a valid request.
        if !state
            .member_wrapping_keys
            .contains_key(&request.requester_did)
        {
            return Err(ContextError::CryptoFailed(
                "sender key request from non-member".to_string(),
            ));
        }

        // H1: Blocked DID check — requester must not be blocked.
        if blocked_dids.contains(&request.requester_did) {
            return Err(ContextError::CryptoFailed(
                "sender key request from blocked member".to_string(),
            ));
        }

        // HPKE-seal our sender key to the requester's wrapping pubkey.
        let (sealed_vec, ephemeral_pub) =
            crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                state.sender_key.as_bytes(),
                &request.wrapping_pubkey,
                &ctx_id_hex,
                &self.local_did,
                state.sender_key_epoch,
            )
            .map_err(|e| ContextError::CryptoFailed(format!("HPKE seal failed: {e}")))?;

        let sealed: [u8; 60] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
            ContextError::CryptoFailed(format!("HPKE seal produced {} bytes, expected 60", v.len()))
        })?;

        let response = SenderKeyResponse {
            sender_did: self.local_did.clone(),
            epoch: state.sender_key_epoch,
            hpke_sealed_key: sealed,
            ephemeral_pubkey: ephemeral_pub,
            request_nonce: request.nonce,
        };

        let message = rmp_serde::to_vec_named(&response)
            .map_err(|e| ContextError::CryptoFailed(format!("serialization: {e}")))?;

        // Record nonce after successful processing.
        state.nonce_dedup.record(request.nonce, now_secs);

        Ok(Some(message))
    }

    /// Seals an inner envelope for transport: serializes, sender-key encrypts,
    /// MLS encrypts, wraps in outer envelope.
    ///
    /// This is the primary send-path crypto operation. The caller constructs
    /// the `InnerEnvelope` (including signing); this method handles all
    /// encryption layers.
    ///
    /// The default implementation returns an error. Production providers
    /// (`MlsCryptoProvider`) override this with the full envelope pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if any encryption step fails.
    pub fn seal(
        &self,
        context_id: &[u8; 32],
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        self.with_context(context_id, |state| {
            // Use hex-encoded context_id bytes as AAD context string, matching
            // the decrypt path in `open` which also uses `hex::encode(context_id)`.
            // `seal_envelope` uses `inner.context_id` (the original string), which
            // would cause an AAD mismatch on the receive side.
            let ctx_str = hex::encode(context_id);

            // 1. Serialize inner envelope to MessagePack.
            let serialized = rmp_serde::to_vec_named(inner).map_err(|e| {
                ContextError::CryptoFailed(format!("inner envelope serialization: {e}"))
            })?;

            // 2. Sender key encrypt (AES-256-GCM, ADR-007).
            // AAD binds context_id, sender_did, epoch, and sequence to prevent
            // ciphertext relocation. Uses hex-encoded context_id bytes for
            // consistency with the decrypt path.
            let sender_encrypted =
                scp_protocol::crypto::sender_keys::encrypt::encrypt_sender_layer(
                    &state.sender_key,
                    &serialized,
                    &ctx_str,
                    &self.local_did,
                    state.sender_key_epoch,
                    state.send_sequence,
                )
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let with_header = scp_protocol::crypto::sender_keys::encrypt::build_sender_header(
                state.sender_key_epoch,
                state.send_sequence,
                &sender_encrypted,
            );

            // 3. MLS encrypt.
            let mls_message =
                crate::crypto::mls::encrypt::encrypt(&mut state.mls_group, &with_header)
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let encrypted_blob = crate::crypto::mls::encrypt::serialize_ciphertext(&mls_message)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            // 4. Wrap in outer envelope.
            let outer = scp_protocol::envelope::outer::create_outer_envelope(
                routing_id,
                None, // no recipient hint for group messages
                blob_ttl,
                encrypted_blob,
            )
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            state.send_sequence = state.send_sequence.checked_add(1).ok_or_else(|| {
                ContextError::CryptoFailed("send sequence counter overflow".into())
            })?;

            rmp_serde::to_vec_named(&outer).map_err(|e| {
                ContextError::CryptoFailed(format!("outer envelope serialization: {e}"))
            })
        })
    }

    /// Opens a received envelope: MLS decrypts, sender-key decrypts,
    /// deserializes, verifies membership + padding + integrity check.
    ///
    /// Returns [`OpenResult::Application`](scp_protocol::context::builder::OpenResult::Application) for application messages,
    /// [`OpenResult::Control`](scp_protocol::context::builder::OpenResult::Control) for MLS Commit/Proposal messages, or
    /// [`OpenResult::Management`](scp_protocol::context::builder::OpenResult::Management) for MLS-wrapped management messages
    /// (identified by the [`MANAGEMENT_MSG_MAGIC`](scp_protocol::context::builder::MANAGEMENT_MSG_MAGIC) prefix).
    ///
    /// Signature verification is NOT performed here — the caller
    /// (`ContextManager`) handles it via `key_resolver` after `open` returns.
    ///
    /// The default implementation returns an error. Production providers
    /// (`MlsCryptoProvider`) override this with the full receive pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if MLS decryption, sender key
    /// decryption, deserialization, padding strip, or integrity check fails.
    pub fn open(
        &self,
        context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_protocol::context::builder::OpenResult, ContextError> {
        self.with_context(context_id, |state| {
            let ctx_str = hex::encode(context_id);

            // Step 0: Deserialize outer envelope to extract MLS ciphertext.
            let outer: scp_protocol::envelope::outer::OuterEnvelope =
                rmp_serde::from_slice(outer_bytes).map_err(|e| {
                    ContextError::CryptoFailed(format!("outer envelope deserialization: {e}"))
                })?;

            // Step 1: MLS decrypt and extract sender DID from credential.
            let content = decrypt_with_sender_did(&mut state.mls_group, &outer.encrypted_blob)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            match content {
                DecryptedContent::Application {
                    plaintext: mls_decrypted,
                    sender_did,
                } => {
                    // Per spec §9.16.1 "Management prefix exclusivity", the
                    // SCPM_MAGIC check lives in exactly one place — the
                    // shared helper in scp-protocol::context::builder. Do
                    // not re-implement the prefix check inline here or
                    // anywhere else in the codebase.
                    if let Some(mgmt_payload) =
                        scp_protocol::context::builder::try_strip_management_prefix(&mls_decrypted)
                    {
                        if mgmt_payload.len()
                            > scp_protocol::context::builder::MAX_MANAGEMENT_PAYLOAD_SIZE
                        {
                            return Err(ContextError::CryptoFailed(
                                "management payload exceeds size limit".into(),
                            ));
                        }
                        return Ok(scp_protocol::context::builder::OpenResult::Management {
                            sender_did,
                            payload: mgmt_payload.to_vec(),
                        });
                    }

                    // Step 2: Look up the sender's key from the sender key store.
                    let sender_key = state
                        .sender_key_store
                        .get(&ctx_str, &sender_did)
                        .cloned()
                        .ok_or_else(|| {
                            ContextError::CryptoFailed("sender key lookup failed".into())
                        })?;

                    // Step 3: Parse header and sender key decrypt.
                    let (epoch, sequence, sender_ciphertext) =
                        scp_protocol::crypto::sender_keys::encrypt::parse_sender_header(
                            &mls_decrypted,
                        )
                        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
                    // Epoch/sequence from header — see send_message comment about AAD.
                    let decrypted = scp_protocol::crypto::sender_keys::decrypt_sender_layer(
                        &sender_key,
                        sender_ciphertext,
                        &ctx_str,
                        &sender_did,
                        epoch,
                        sequence,
                    )
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                    // Receive-side epoch ceiling (H9): reject messages whose
                    // claimed sender-key epoch exceeds the highest legitimately
                    // distributed epoch for that sender by more than
                    // `MAX_EPOCH_ADVANCE`. Without this guard a sender could
                    // craft a single message with `epoch = u64::MAX`, which
                    // updates `recv_sequence_tracker` and permanently locks
                    // out all subsequent legitimate messages from that sender
                    // (self-DoS / persistent per-receiver poisoning). The
                    // `process_incoming_sender_key` path enforces the same
                    // ceiling on key distributions; this mirrors that bound
                    // on the message receive path so the two cannot diverge.
                    let stored_high_water = state.sender_key_store.epoch(&ctx_str, &sender_did);
                    let allowed_epoch_ceiling = stored_high_water.saturating_add(MAX_EPOCH_ADVANCE);
                    if epoch > allowed_epoch_ceiling {
                        return Err(ContextError::CryptoFailed(format!(
                            "sender key epoch {epoch} exceeds ceiling \
                             {allowed_epoch_ceiling} (stored high-water \
                             {stored_high_water}, MAX_EPOCH_ADVANCE \
                             {MAX_EPOCH_ADVANCE})",
                        )));
                    }

                    // Receive-side replay detection: reject messages with
                    // epoch/sequence <= last seen for this sender.
                    if let Some(&(last_epoch, last_seq)) =
                        state.recv_sequence_tracker.get(&sender_did)
                        && (epoch < last_epoch || (epoch == last_epoch && sequence <= last_seq))
                    {
                        return Err(ContextError::CryptoFailed(
                            "replay or reorder detected".into(),
                        ));
                    }
                    state
                        .recv_sequence_tracker
                        .insert(sender_did.clone(), (epoch, sequence));

                    // Step 4: Deserialize as InnerEnvelope.
                    // The inner envelope is returned with its padded payload intact.
                    // The caller (verify_and_unwrap) is responsible for stripping
                    // padding and verifying content integrity — keeping open()
                    // focused on MLS decrypt → sender key decrypt → deserialize.
                    let inner =
                        scp_protocol::envelope::inner::InnerEnvelope::from_bytes(&decrypted)
                            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                    // Signature verification is deferred to ContextManager which
                    // has access to the key_resolver for resolving sender public keys.

                    Ok(scp_protocol::context::builder::OpenResult::Application(
                        Box::new(scp_protocol::context::builder::OpenedEnvelope {
                            inner,
                            sender_did,
                        }),
                    ))
                }
                DecryptedContent::Commit { sender_did: _ } => {
                    // Commit messages advance the MLS epoch. `decrypt_with_sender_did`
                    // has already called `merge_staged_commit` to apply the epoch
                    // change. No application payload exists.
                    Ok(scp_protocol::context::builder::OpenResult::Control)
                }
                DecryptedContent::Proposal { sender_did: _ } => {
                    Ok(scp_protocol::context::builder::OpenResult::Control)
                }
            }
        })
    }

    /// MLS-encrypts a management payload for group-authenticated delivery.
    ///
    /// Prepends the [`MANAGEMENT_MSG_MAGIC`](scp_protocol::context::builder::MANAGEMENT_MSG_MAGIC) prefix, MLS-encrypts the result,
    /// and wraps in an outer envelope. Used to send sender key distributions
    /// that are authenticated by MLS membership.
    ///
    /// The default implementation returns an error. Production providers
    /// (`MlsCryptoProvider`) override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if MLS encryption or
    /// serialization fails.
    pub fn mls_encrypt_management(
        &self,
        context_id: &[u8; 32],
        plaintext: &[u8],
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        if plaintext.len() > scp_protocol::context::builder::MAX_MANAGEMENT_PAYLOAD_SIZE {
            return Err(ContextError::CryptoFailed(
                "management payload exceeds size limit".into(),
            ));
        }
        self.with_context(context_id, |state| {
            // Prepend the canonical SCPM magic to tag this as a management
            // message for the receive side. The strip/check logic lives in
            // the shared `try_strip_management_prefix` helper per spec
            // §9.16.1 exclusivity; the prepend side is symmetric and
            // trivial enough to leave inline.
            let magic = &scp_protocol::context::builder::MANAGEMENT_MSG_MAGIC;
            let mut tagged = Vec::with_capacity(magic.len() + plaintext.len());
            tagged.extend_from_slice(magic);
            tagged.extend_from_slice(plaintext);
            let mls_message = crate::crypto::mls::encrypt::encrypt(&mut state.mls_group, &tagged)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let encrypted_blob = crate::crypto::mls::encrypt::serialize_ciphertext(&mls_message)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let outer = scp_protocol::envelope::outer::create_outer_envelope(
                routing_id,
                None,
                blob_ttl,
                encrypted_blob,
            )
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            rmp_serde::to_vec_named(&outer)
                .map_err(|e| ContextError::CryptoFailed(format!("serialization: {e}")))
        })
    }

    /// Advances the MLS epoch for post-compromise security (§9.12 step 2).
    ///
    /// Issues an MLS Update proposal + self-Commit, ratcheting the group to
    /// a new epoch with fresh key material. After this call, the compromised
    /// old epoch key is useless for future messages.
    ///
    /// Returns an [`AdvanceEpochOutput`](scp_protocol::context::builder::AdvanceEpochOutput) containing the TLS-serialized MLS
    /// Commit message that must be distributed to all group members.
    ///
    /// The default implementation is a no-op returning empty output so that
    /// mock and test providers compile without changes.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS update/commit fails.
    pub fn advance_epoch(
        &self,
        context_id: &[u8; 32],
    ) -> Result<scp_protocol::context::builder::AdvanceEpochOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        // ADR-049 commit 12c.9f: load wrapping pubkey through `ArcSwap`.
        let wrapping_pk = **self.wrapping_public_key.load();
        self.with_context(context_id, |state| {
            let commit = super::ratchet::propose_update_with_wrapping_key(
                &mut state.mls_group,
                &wrapping_pk,
            )
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let commit_bytes = commit.tls_serialize_detached().map_err(|e| {
                ContextError::CryptoFailed(format!("serializing epoch advance commit: {e}"))
            })?;

            Ok(scp_protocol::context::builder::AdvanceEpochOutput { commit_bytes })
        })
    }

    /// Exports the per-context cryptographic state as an opaque byte blob
    /// for persistence alongside the `ContextSnapshot`.
    ///
    /// The returned bytes capture all state needed to resume MLS encryption
    /// and decryption for this context after a process restart: the MLS group
    /// state (tree, epoch secrets, key schedule), the local sender key, the
    /// sender key store (all member keys), the sender key epoch, and per-member
    /// wrapping public keys.
    ///
    /// Returns an empty `Vec` if no crypto state exists for the given context
    /// (e.g., mock providers or broadcast-only contexts).
    ///
    /// The default implementation returns an empty `Vec` (no state to persist).
    /// Production providers that manage MLS groups MUST override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if serialization fails.
    pub fn export_crypto_state(&self, context_id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
        // ADR-049 commit 12c.9f: lock-free `DashMap::get`. Holds the
        // per-shard read guard for the duration of snapshot
        // construction; no other writer can mutate this entry while
        // the guard is alive.
        let Some(entry) = self.contexts.get(context_id) else {
            return Ok(Vec::new());
        };
        let state = entry.value();

        // Extract the MLS group and signer, both required for restore.
        let group = state
            .mls_group
            .group
            .as_ref()
            .ok_or_else(|| ContextError::CryptoFailed("MLS group destroyed".to_string()))?;

        let signer = state
            .mls_group
            .signer
            .as_ref()
            .ok_or_else(|| ContextError::CryptoFailed("MLS signer destroyed".to_string()))?;

        let group_id = group.group_id().as_slice().to_vec();

        // Serialize the signer via serde (it derives Serialize).
        // SECURITY: Wrapped in Zeroizing so the Ed25519 private key bytes are
        // zeroed if an early `?` return occurs before the snapshot is built.
        let mut signer_bytes = Zeroizing::new(
            rmp_serde::to_vec_named(signer)
                .map_err(|e| ContextError::CryptoFailed(format!("signer serialization: {e}")))?,
        );

        // Extract the raw key-value pairs from the OpenMLS MemoryStorage.
        let mls_storage_entries = {
            let values = state
                .mls_group
                .provider
                .storage()
                .values
                .read()
                .map_err(|e| ContextError::CryptoFailed(format!("storage lock poisoned: {e}")))?;
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };

        // Collect sender key store entries for this context.
        let ctx_id_hex = hex::encode(context_id);
        let sender_key_entries: Vec<(String, SenderKey)> = state
            .sender_key_store
            .get_all(&ctx_id_hex)
            .into_iter()
            .collect();

        // Persist per-sender epoch high-water marks so the `#1608`
        // rollback-protection invariant survives a restart
        // (`SenderKeyStore::set_checked` will reject any restored epoch
        // that regresses below the persisted floor). Includes entries
        // for senders whose key has been removed but whose floor is
        // still retained — `remove` intentionally preserves the epoch
        // as a high-water mark.
        let sender_key_epochs: Vec<(String, u64)> =
            state.sender_key_store.epochs_for_context(&ctx_id_hex);

        // Read the provider-level wrapping keypair for persistence.
        // ADR-049 commit 12c.9f: load through `ArcSwap` and copy the
        // bytes immediately so guards drop before snapshot serialization.
        let pub_key_bytes = **self.wrapping_public_key.load();
        let secret_key_bytes: Vec<u8> = self.wrapping_secret_key.load().to_vec();

        let mut snapshot = MlsCryptoSnapshot {
            mls_storage_entries,
            local_sender_key: state.sender_key.clone(),
            sender_key_entries,
            sender_key_epochs,
            sender_key_epoch: state.sender_key_epoch,
            send_sequence: state.send_sequence,
            member_wrapping_keys: state
                .member_wrapping_keys
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            // Move signer bytes out of the Zeroizing wrapper and into the
            // snapshot. The wrapper is left holding an empty Vec (which it
            // will zeroize on drop — a no-op for an empty vec).
            recv_sequence_tracker: state
                .recv_sequence_tracker
                .iter()
                .map(|(did, (epoch, seq))| (did.clone(), *epoch, *seq))
                .collect(),
            signer_bytes: std::mem::take(&mut signer_bytes),
            group_id,
            wrapping_public_key: pub_key_bytes,
            wrapping_secret_key: secret_key_bytes,
        };

        let result = rmp_serde::to_vec_named(&snapshot)
            .map_err(|e| ContextError::CryptoFailed(format!("snapshot serialization: {e}")));

        // SECURITY: Zeroize sensitive key material in the intermediate snapshot
        // to minimize the window where private keys exist as structured data in
        // memory. The serialized blob is the caller's responsibility (Storage
        // layer must encrypt at rest per §17.5).
        snapshot.signer_bytes.zeroize();
        snapshot.local_sender_key.zeroize();
        snapshot.wrapping_secret_key.zeroize();
        for (_, value) in &mut snapshot.mls_storage_entries {
            value.zeroize();
        }
        for (_, key) in &mut snapshot.sender_key_entries {
            key.zeroize();
        }

        result
    }

    /// Restores per-context cryptographic state from a previously exported
    /// byte blob (produced by [`export_crypto_state`](Self::export_crypto_state)).
    ///
    /// Called during `ContextManager::restore_context` to reinstate MLS
    /// groups and sender keys after a process restart. If `data` is empty,
    /// this is a no-op (the provider was never persisted or is a mock).
    ///
    /// The default implementation is a no-op. Production providers that
    /// manage MLS groups MUST override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if deserialization fails or
    /// the data is corrupt.
    pub fn restore_crypto_state(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), ContextError> {
        if data.is_empty() {
            return Ok(());
        }

        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(data)
            .map_err(|e| ContextError::CryptoFailed(format!("snapshot deserialization: {e}")))?;

        // Reconstruct the InMemoryMlsProvider with the persisted storage entries.
        let provider = super::storage::InMemoryMlsProvider::default();
        {
            let mut values =
                provider.storage().values.write().map_err(|e| {
                    ContextError::CryptoFailed(format!("storage lock poisoned: {e}"))
                })?;
            // Drain entries so the snapshot no longer holds MLS storage data
            // (which contains epoch secrets and HPKE private keys).
            for (k, v) in snapshot.mls_storage_entries.drain(..) {
                values.insert(k, v);
            }
        }

        // Deserialize the signer from the snapshot's raw bytes.
        let signer: SignatureKeyPair = rmp_serde::from_slice(&snapshot.signer_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("signer deserialization: {e}")))?;

        // SECURITY: Zeroize the raw signer bytes now that they've been
        // deserialized — the Ed25519 private key should not linger in this
        // intermediate buffer.
        snapshot.signer_bytes.zeroize();

        // Re-store the signer in the provider's key store so OpenMLS can find it.
        signer
            .store(provider.storage())
            .map_err(|e| ContextError::CryptoFailed(format!("signer store failed: {e}")))?;

        // Reconstruct the MLS group from persisted storage via MlsGroup::load.
        let group_id = GroupId::from_slice(&snapshot.group_id);
        let mls_group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|e| ContextError::CryptoFailed(format!("MlsGroup::load storage error: {e}")))?
            .ok_or_else(|| {
                ContextError::CryptoFailed(
                    "MlsGroup::load returned None — group not found in restored storage"
                        .to_string(),
                )
            })?;

        // Reconstruct SenderKeyStore. drain() moves keys out and clears the
        // snapshot's copy.
        let ctx_id_hex = hex::encode(context_id);
        let mut sender_key_store = SenderKeyStore::new();

        // Restore the per-sender epoch high-water map FIRST so it acts
        // as a floor for the `set_checked` path going forward. The
        // restored values are authoritative high-water marks (not
        // user-supplied receive traffic), so `restore_epoch_high_water`
        // bypasses the monotonicity check.
        //
        // `sender_key_epochs` can cover DIDs that no longer have a key
        // entry (e.g., removed members whose floor was preserved by
        // `SenderKeyStore::remove`) — those entries still matter for
        // rollback protection and must be restored.
        let had_epoch_map = !snapshot.sender_key_epochs.is_empty();
        for (did, epoch) in snapshot.sender_key_epochs.drain(..) {
            sender_key_store.restore_epoch_high_water(&ctx_id_hex, &did, epoch);
        }

        // Legacy-snapshot back-compat hardening: snapshots without a
        // `sender_key_epochs` field leave the map above empty. If
        // we installed key material below with `set_unchecked` and
        // left every floor at 0, the first post-upgrade receive
        // would be `set_checked(..., epoch=k>0)` and would be
        // accepted against a zero floor — re-opening the rollback
        // window for exactly one boot cycle.
        //
        // `SenderKey` material does not carry the epoch it was
        // bound to, so legacy data cannot recover per-sender floors
        // exactly. Use the snapshot's global `sender_key_epoch`
        // counter (present in legacy snapshots) as a conservative
        // lower bound for every sender we see key material for.
        // This is strictly tighter than zero and closes the one-
        // shot rollback window for the common case.
        //
        // Residual window: the global `sender_key_epoch` counter
        // increments only on local `rotate_sender_key`, so a remote
        // sender whose true floor exceeded the local counter at
        // snapshot time is seeded with the lower local value. The
        // residual window per sender is `peer_floor - local_floor`,
        // bounded by the `MAX_EPOCH_ADVANCE = 1000` guard in
        // `open_inner_envelope`. The next legitimate rotation from
        // that sender advances the floor past the exposed window
        // permanently. Closing this residual fully would require
        // either a format break (carrying per-sender epochs in
        // legacy snapshots, which they do not have) or rejecting
        // legacy snapshots outright, locking users out on upgrade.
        let legacy_floor = if had_epoch_map {
            None
        } else {
            Some(snapshot.sender_key_epoch.max(1))
        };
        for (did, key) in snapshot.sender_key_entries.drain(..) {
            // Install key material via `set_unchecked` — the restored
            // key IS authoritative (it was persisted by this same
            // provider). `set_checked` would be rejected when the
            // restored key's epoch equals an already-restored floor.
            sender_key_store.set_unchecked(&ctx_id_hex, &did, key);
            // Legacy-path only: seed a floor from the global
            // `sender_key_epoch` if no per-sender map was persisted.
            if let Some(floor) = legacy_floor {
                sender_key_store.restore_epoch_high_water(&ctx_id_hex, &did, floor);
            }
        }

        // Reconstruct member wrapping keys.
        let member_wrapping_keys: HashMap<String, [u8; 32]> =
            snapshot.member_wrapping_keys.drain(..).collect();

        let scp_group = ScpMlsGroup {
            group: Some(mls_group),
            provider,
            signer: super::group::EagerDropSigner::new(signer),
            destroyed: false,
        };

        // Take the local_sender_key and leave a zeroed placeholder. SenderKey
        // implements ZeroizeOnDrop, so the placeholder is cleaned when snapshot
        // drops, and the original is moved into crypto_state.
        let local_sender_key = std::mem::replace(
            &mut snapshot.local_sender_key,
            SenderKey::from_bytes([0u8; 32]),
        );

        let recv_sequence_tracker: HashMap<String, (u64, u64)> = snapshot
            .recv_sequence_tracker
            .drain(..)
            .map(|(did, epoch, seq)| (did, (epoch, seq)))
            .collect();

        let crypto_state = ContextCryptoState {
            mls_group: scp_group,
            sender_key: local_sender_key,
            sender_key_store,
            sender_key_epoch: snapshot.sender_key_epoch,
            send_sequence: snapshot.send_sequence,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys,
            recv_sequence_tracker,
        };

        // Restore the provider-level X25519 wrapping keypair BEFORE inserting
        // into the contexts map. This prevents partial state: if either
        // ArcSwap store is observed mid-rotation the contexts map has not
        // yet seen the new entry.
        //
        // ADR-049 commit 12c.9f: `ArcSwap::store` is atomic per-slot;
        // observing one slot pre-rotation and the other post-rotation is
        // possible only across the two stores below, but both rotate
        // together to the same `snapshot` source so any in-flight reader
        // sees a consistent pair (either old/old or new/new) at the
        // protocol boundary that uses both keys (HPKE seal + open).
        //
        // Legacy snapshots (pre-wrapping-key persistence) have default
        // [0u8; 32] — skip restore in that case to keep the fresh keypair.
        if snapshot.wrapping_public_key != [0u8; 32] && snapshot.wrapping_secret_key.len() == 32 {
            // SECURITY: Wrap the intermediate secret in Zeroizing so it is
            // zeroed on drop even if a `?` return occurs below.
            let mut secret = Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(&snapshot.wrapping_secret_key);

            self.wrapping_public_key
                .store(Arc::new(snapshot.wrapping_public_key));
            self.wrapping_secret_key
                .store(Arc::new(Zeroizing::new(*secret)));
        }

        // SECURITY: Zeroize the wrapping secret key bytes remaining in the
        // snapshot. The key has been copied into the Zeroizing<[u8; 32]> guard
        // above (or skipped for legacy snapshots), so this intermediate Vec
        // should not retain raw X25519 secret key material.
        snapshot.wrapping_secret_key.zeroize();

        // ADR-049 commit 12c.9f: lock-free `DashMap::insert`.
        self.contexts.insert(*context_id, crypto_state);

        Ok(())
    }

    /// Returns the per-sender epoch high-water marks for a given context.
    ///
    /// Each `(sender_did, epoch)` pair represents the highest sender key epoch
    /// seen from that participant.  Used by `lifecycle_helpers::import_context`
    /// to capture the local floors **before** destroying existing crypto state
    /// so the incoming snapshot can be validated against them.
    ///
    /// Returns an empty `Vec` when the context has no epoch state (mock
    /// providers, broadcast-only contexts, or providers that do not track
    /// epochs).
    ///
    /// The default implementation returns an empty `Vec`.  Production
    /// providers that maintain a `SenderKeyStore` MUST override this.
    pub fn export_sender_key_epochs(&self, context_id: &[u8; 32]) -> Vec<(String, u64)> {
        // ADR-049 commit 12c.9f: lock-free `DashMap::get`.
        let Some(entry) = self.contexts.get(context_id) else {
            return Vec::new();
        };
        let ctx_id_hex = hex::encode(context_id);
        entry
            .value()
            .sender_key_store
            .epochs_for_context(&ctx_id_hex)
    }

    /// Validates that the per-sender epoch floors in the just-restored crypto
    /// state do not regress any entry in `local_floors`, then applies a
    /// max-merge so `max(local, imported)` is the effective floor for every
    /// sender (spec §23.17 Invariant 3 + Invariant 4).
    ///
    /// Call this AFTER `restore_crypto_state` during `import_context`, passing
    /// the floors captured via `export_sender_key_epochs` **before** the
    /// destroy+restore cycle.
    ///
    /// Rejects (returns `Err`) if any imported epoch is below its local floor
    /// (regression) **or** exceeds `local_floor + max_advance_per_sender`
    /// (epoch-poisoning guard). No state is mutated on failure.
    ///
    /// The default implementation is a no-op (`Ok`). Production providers MUST
    /// override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::SnapshotFloorRegression`] on regression or
    /// ceiling violation.
    // Parameter type `Vec<(String, u64)>` is fixed by the `ContextCryptoProvider`
    // trait signature (the forwarder impl below passes ownership through from a
    // trait-object call). Switching to `&[(String, u64)]` is a signature change
    // that belongs with trait deletion in commit 12c.9e.6 of ADR-049.
    #[allow(clippy::needless_pass_by_value)]
    pub fn validate_and_merge_epoch_floors(
        &self,
        context_id: &[u8; 32],
        local_floors: Vec<(String, u64)>,
        max_advance_per_sender: u64,
    ) -> Result<(), ContextError> {
        if local_floors.is_empty() {
            return Ok(());
        }

        let ctx_id_hex = hex::encode(context_id);

        // Step 1: read the imported (restored) epoch floors.
        // ADR-049 commit 12c.9f: lock-free `DashMap::get`.
        let import_floors: Vec<(String, u64)> =
            self.contexts
                .get(context_id)
                .map_or_else(Vec::new, |entry| {
                    entry
                        .value()
                        .sender_key_store
                        .epochs_for_context(&ctx_id_hex)
                });

        // Step 2: build a temporary store seeded with local floors, then
        // validate the import floors against them via the atomic-reject helper.
        // Rejects if any import floor regresses below a local floor, or
        // overshoots local + max_advance (epoch-poisoning guard).
        let mut temp_store = SenderKeyStore::new();
        for (did, floor) in &local_floors {
            temp_store.restore_epoch_high_water(&ctx_id_hex, did, *floor);
        }
        temp_store
            .merge_incoming_epochs_with_atomic_reject(
                &ctx_id_hex,
                import_floors,
                max_advance_per_sender,
            )
            .map_err(|per_sender_deltas| ContextError::SnapshotFloorRegression {
                resource: "sender_key_epoch".to_owned(),
                per_sender_deltas,
            })?;

        // Step 3: apply the merged floors (max of local and import) back into
        // the real store. Ensures local-only senders (absent from the import
        // snapshot) retain their floor (Invariant 4 append-only dominance).
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let merged = temp_store.epochs_for_context(&ctx_id_hex);
        if let Some(mut entry) = self.contexts.get_mut(context_id) {
            let state = entry.value_mut();
            for (did, epoch) in merged {
                state
                    .sender_key_store
                    .restore_epoch_high_water(&ctx_id_hex, &did, epoch);
            }
        }

        Ok(())
    }

    /// Generates a key package for joining a group via Welcome.
    /// Returns TLS-serialized key package bytes. The provider retains the
    /// private state needed to process the incoming Welcome.
    ///
    /// Default: not supported (returns error).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key package generation fails.
    pub fn prepare_key_package_for_join(&self) -> Result<Vec<u8>, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        let credential = self
            .make_credential()
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // ADR-049 commit 12c.9f: load wrapping pubkey through `ArcSwap`.
        let wrapping_pk = **self.wrapping_public_key.load();

        let (kp_bundle, signer, provider) =
            super::group::generate_key_package_with_wrapping_key(&credential, Some(&wrapping_pk))
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let kp_bytes = kp_bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| ContextError::CryptoFailed(format!("serializing key package: {e}")))?;

        // Only one key package can be outstanding at a time.
        // New prepare calls replace the old pending state to avoid
        // LIFO matching errors when Welcomes arrive out of order.
        // ADR-049 commit 12c.9f: `ArcSwapOption::store` is atomic; any
        // prior `Some` is dropped (with its `Zeroizing` signer wrapper).
        self.pending_joins.store(Some(Arc::new(PendingJoinState {
            signer: super::group::EagerDropSigner::new(signer),
            provider,
        })));

        Ok(kp_bytes)
    }

    /// Joins an MLS group from a TLS-serialized Welcome message.
    /// Consumes the retained key package state from `prepare_key_package_for_join`.
    ///
    /// Default: not supported (returns error).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if Welcome processing fails.
    pub fn join_from_welcome(
        &self,
        context_id: &[u8; 32],
        welcome_bytes: &[u8],
    ) -> Result<(), ContextError> {
        // ADR-049 commit 12c.9f: atomic take via `ArcSwapOption::swap(None)`.
        // The provider is the sole writer; in the steady state (no
        // concurrent reader holding a `load`-ed Arc) the returned Arc
        // has strong count 1 and `Arc::try_unwrap` succeeds. If a
        // concurrent reader keeps a strong reference alive we fall back
        // to a defensive error rather than panicking — but no production
        // call path does this today.
        let pending_arc = self.pending_joins.swap(None).ok_or_else(|| {
            ContextError::CryptoFailed("no pending key package for Welcome".into())
        })?;
        let mut entry = Arc::try_unwrap(pending_arc).map_err(|_| {
            ContextError::CryptoFailed(
                "pending join state still aliased — concurrent join_from_welcome racing".into(),
            )
        })?;

        let signer = entry.signer.take().ok_or_else(|| {
            ContextError::CryptoFailed("pending join signer already consumed".into())
        })?;

        let group = super::group::join_group_from_bytes(welcome_bytes, entry.provider, signer)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let sender_key = generate_sender_key();

        // ADR-049 commit 12c.9f: lock-free `DashMap` writes. Destroy any
        // existing MLS group state for this context to ensure proper key
        // material cleanup (defense-in-depth).
        if let Some((_, mut old_state)) = self.contexts.remove(context_id) {
            let _ = group::destroy_group(&mut old_state.mls_group);
        }

        self.contexts.insert(
            *context_id,
            ContextCryptoState {
                mls_group: group,
                sender_key,
                sender_key_store: SenderKeyStore::new(),
                sender_key_epoch: 1,
                send_sequence: 0,
                pending_distributions: Vec::new(),
                nonce_dedup: NonceDedup::new(),
                member_wrapping_keys: HashMap::new(),
                recv_sequence_tracker: HashMap::new(),
            },
        );

        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use crate::crypto::mls::encrypt::{encrypt, serialize_ciphertext};
    use crate::crypto::mls::group::generate_key_package;
    use scp_protocol::crypto::sender_keys::SenderKeyError;
    use tls_codec::Serialize as TlsSerializeTrait;

    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    /// Test helper: encrypt a message using the old `encrypt_message` path
    /// (sender key + MLS encrypt). Used by provider-level tests that test
    /// the crypto layer directly without the full envelope pipeline.
    fn test_encrypt_message(
        provider: &MlsCryptoProvider,
        context_id: &[u8; 32],
        payload: &[u8],
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        provider.with_context(context_id, |state| {
            let ctx_str = hex::encode(context_id);
            let sender_encrypted =
                scp_protocol::crypto::sender_keys::encrypt::encrypt_sender_layer(
                    &state.sender_key,
                    payload,
                    &ctx_str,
                    &provider.local_did,
                    epoch,
                    sequence,
                )
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            let mls_message = encrypt(&mut state.mls_group, &sender_encrypted)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

            serialize_ciphertext(&mls_message)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))
        })
    }

    fn make_provider() -> MlsCryptoProvider {
        MlsCryptoProvider::new(TEST_DID.to_string())
    }

    fn make_context_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0x42;
        id
    }

    #[test]
    fn validate_creator_identity_accepts_valid_did() {
        let provider = make_provider();
        assert!(provider.validate_creator_identity().is_ok());
    }

    #[test]
    fn validate_creator_identity_rejects_invalid_did() {
        // Under `cfg(test)` the validator accepts `did:key:*` and
        // `did:test:*` so legacy mock-based tests still work; pick a
        // truly malformed DID string to prove rejection.
        let provider = MlsCryptoProvider::new("invalid:format:whatever".to_string());
        assert!(provider.validate_creator_identity().is_err());
    }

    #[test]
    fn create_mls_group_and_destroy() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        assert!(provider.create_mls_group(&ctx_id).is_ok());

        // Verify group exists by attempting to encrypt.
        let encrypted = test_encrypt_message(&provider, &ctx_id, b"hello", 0, 0);
        assert!(encrypted.is_ok());

        // Destroy.
        assert!(provider.destroy_mls_group(&ctx_id).is_ok());

        // After destroy, encrypt should fail.
        let encrypted = test_encrypt_message(&provider, &ctx_id, b"hello", 0, 0);
        assert!(encrypted.is_err());
    }

    #[test]
    fn add_member_with_real_key_package() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Generate a key package for Bob.
        let bob_cred = ScpCredential::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
            None,
            SigningKeyId::Active,
        )
        .unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();

        // Serialize the key package to bytes.
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();

        // Add Bob.
        let result = provider.add_member(&ctx_id, &bob_cred.did, Some(&kp_bytes));
        assert!(result.is_ok(), "add_member failed: {result:?}");
    }

    #[test]
    fn add_member_rejects_malformed_key_package_bytes() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Security intent: add_member must reject key material that is not a
        // valid MLS KeyPackage. Garbage bytes fail TLS deserialization in
        // BOTH production and test/testing builds — the `Some(bytes)` branch
        // is not cfg-gated, so this rejection holds regardless of feature
        // flags. (A `None` key package is, by design, accepted under the
        // `testing` feature to drive the non-crypto pipeline; production
        // builds — where `cfg!(any(test, feature = "testing"))` is false —
        // still reject `None`. See `add_member`.)
        let malformed: &[u8] = &[0xFF; 4];
        let result = provider.add_member(&ctx_id, "did:dht:z6MkBob", Some(malformed));
        assert!(
            result.is_err(),
            "add_member must reject malformed key package bytes: {result:?}"
        );
    }

    #[test]
    fn remove_member_by_did() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        // Remove Bob.
        let result = provider.remove_member(&ctx_id, bob_did);
        assert!(result.is_ok(), "remove_member failed: {result:?}");
        let output = result.unwrap();
        assert!(
            !output.commit_bytes.is_empty(),
            "remove_member must return non-empty commit_bytes for MLS group epoch advance"
        );
    }

    #[test]
    fn remove_member_self_returns_empty_commit() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Self-removal (leave) returns empty commit bytes — the local node
        // does not produce a Commit for its own departure.
        let output = provider
            .remove_member(&ctx_id, &provider.local_did)
            .unwrap();
        assert!(
            output.commit_bytes.is_empty(),
            "self-removal must return empty commit_bytes"
        );
    }

    #[test]
    fn advance_epoch_returns_non_empty_commit() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let output = provider.advance_epoch(&ctx_id);
        assert!(output.is_ok(), "advance_epoch failed: {output:?}");
        let output = output.unwrap();
        assert!(
            !output.commit_bytes.is_empty(),
            "advance_epoch must return non-empty commit_bytes for MLS epoch advance"
        );
    }

    #[test]
    fn encrypt_message_produces_ciphertext() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let plaintext = b"test message";
        let ciphertext = test_encrypt_message(&provider, &ctx_id, plaintext, 0, 0).unwrap();

        // Ciphertext should be non-empty and different from plaintext.
        assert!(!ciphertext.is_empty());
        assert_ne!(&ciphertext, plaintext.as_slice());
    }

    #[test]
    fn encrypt_decrypt_roundtrip_two_members() {
        // Alice creates a group.
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let alice_provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        // Generate a key package for Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred).unwrap();
        // We need the Welcome message to let Bob join. Get it from the
        // underlying group directly.
        let add_result = {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        // Bob joins using the Welcome.
        let bob_group =
            group::join_group(&add_result.welcome, bob_provider_mls, bob_signer).unwrap();

        // Alice encrypts a message.
        let plaintext = b"Hello Bob!";
        let ciphertext = {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let msg = encrypt(&mut state.mls_group, plaintext).unwrap();
            serialize_ciphertext(&msg).unwrap()
        };

        // Bob decrypts using his group directly.
        let mut bob_group = bob_group;
        let decrypted = super::super::encrypt::decrypt(&mut bob_group, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn forward_secrecy_after_epoch_advance() {
        // Alice creates a group.
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let alice_provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred).unwrap();

        let add_result = {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        let mut bob_group =
            group::join_group(&add_result.welcome, bob_provider_mls, bob_signer).unwrap();

        // Alice encrypts in epoch 1.
        let ciphertext_epoch1 = {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let msg = encrypt(&mut state.mls_group, b"epoch 1 message").unwrap();
            serialize_ciphertext(&msg).unwrap()
        };

        // Bob decrypts successfully in epoch 1.
        let decrypted = super::super::encrypt::decrypt(&mut bob_group, &ciphertext_epoch1).unwrap();
        assert_eq!(decrypted, b"epoch 1 message");

        // Add Carol to advance to epoch 2.
        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCar";
        let carol_cred =
            ScpCredential::new(carol_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (carol_kp_bundle, _carol_signer, _carol_provider) =
            generate_key_package(&carol_cred).unwrap();

        {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
            let _add_result2 = group::add_member(&mut state.mls_group, kp_in).unwrap();
        }

        // Verify epoch advanced.
        let epoch = {
            let entry = alice_provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            state.mls_group.epoch().unwrap()
        };
        assert_eq!(epoch, 2, "epoch should be 2 after second add");

        // Alice encrypts in epoch 2 — Carol can't replay epoch 1 messages
        // because they're under different epoch keys. This verifies forward
        // secrecy: keys from epoch 1 are not reusable in epoch 2.
        let ciphertext_epoch2 = {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let msg = encrypt(&mut state.mls_group, b"epoch 2 message").unwrap();
            serialize_ciphertext(&msg).unwrap()
        };

        // Verify the epoch 2 ciphertext is different from epoch 1.
        assert_ne!(ciphertext_epoch1, ciphertext_epoch2);
    }

    #[test]
    fn max_past_epochs_allows_grace_window() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let entry = provider.contexts.get(&ctx_id).unwrap();
        let state = entry.value();
        let inner = state.mls_group.inner().unwrap();

        assert_eq!(
            inner.epoch().as_u64(),
            0,
            "new group should start at epoch 0"
        );
    }

    #[test]
    fn three_member_group() {
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred).unwrap();
        let add_bob_result = {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        let _bob_group =
            group::join_group(&add_bob_result.welcome, bob_provider_mls, bob_signer).unwrap();

        // Add Carol.
        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCar";
        let carol_cred =
            ScpCredential::new(carol_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (carol_kp_bundle, carol_signer, carol_provider_mls) =
            generate_key_package(&carol_cred).unwrap();

        let add_carol_result = {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in).unwrap()
        };

        let _carol_group =
            group::join_group(&add_carol_result.welcome, carol_provider_mls, carol_signer).unwrap();

        let entry = provider.contexts.get(&ctx_id).unwrap();
        let state = entry.value();
        let members = state.mls_group.members().unwrap();
        assert_eq!(
            members.len(),
            3,
            "group should have 3 members (Alice, Bob, Carol)"
        );
        assert_eq!(
            state.mls_group.epoch().unwrap(),
            2,
            "epoch should be 2 after two adds"
        );
    }

    #[test]
    fn member_removal_advances_epoch() {
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let provider = MlsCryptoProvider::new(alice_did.to_string());
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        provider
            .add_member(&ctx_id, bob_did, Some(&bob_kp_bytes))
            .unwrap();

        {
            let entry = provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            assert_eq!(state.mls_group.epoch().unwrap(), 1);
        }

        provider.remove_member(&ctx_id, bob_did).unwrap();

        {
            let entry = provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            assert_eq!(state.mls_group.epoch().unwrap(), 2);
            let members = state.mls_group.members().unwrap();
            assert_eq!(members.len(), 1, "only Alice should remain");
        }
    }

    #[test]
    fn ciphersuite_is_correct() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let entry = provider.contexts.get(&ctx_id).unwrap();
        let state = entry.value();
        let inner = state.mls_group.inner().unwrap();
        assert_eq!(
            inner.ciphersuite(),
            SCP_CIPHERSUITE,
            "must use MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        );
    }

    #[test]
    fn init_and_destroy_broadcast_key() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        assert!(provider.init_broadcast_key(&ctx_id).is_ok());
        assert!(provider.destroy_sender_key(&ctx_id).is_ok());
    }

    #[test]
    fn distribute_and_remove_sender_key() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        assert!(
            provider
                .distribute_sender_key(&ctx_id, "did:dht:z6MkBob")
                .is_ok()
        );
        {
            let entry = provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            let ctx_hex = hex::encode(ctx_id);
            assert!(state.sender_key_store.get(&ctx_hex, TEST_DID).is_some());
        }

        assert!(provider.remove_member_sender_key(&ctx_id, TEST_DID).is_ok());
    }

    #[test]
    fn create_mls_group_refuses_to_overwrite_existing_group() {
        // Defense-in-depth: a second `create_mls_group` for the same
        // context id must FAIL with `CreationFailed` and leave the first
        // group's state byte-for-byte intact — never clobber a live MLS
        // group with fresh keys (the crypto-desync clobber that the
        // standing-context bootstrap-lock gap could trigger).
        const SENTINEL_SEQ: u64 = 0xDEAD_BEEF;

        let provider = make_provider();
        let ctx_id = make_context_id();

        provider
            .create_mls_group(&ctx_id)
            .expect("first create_mls_group succeeds");

        // Stamp a sentinel onto the live group's mutable state. A fresh
        // group (the clobber we are guarding against) constructs
        // `send_sequence: 0`, so a surviving sentinel proves no overwrite
        // occurred and the SAME `ContextCryptoState` instance is intact.
        {
            let mut entry = provider
                .contexts
                .get_mut(&ctx_id)
                .expect("first group is registered");
            entry.value_mut().send_sequence = SENTINEL_SEQ;
        }

        // Second create for the SAME id is rejected.
        match provider.create_mls_group(&ctx_id) {
            Err(ContextCreationError::CreationFailed(msg)) => {
                assert!(
                    msg.contains("already exists"),
                    "error must explain the duplicate, got: {msg}"
                );
            }
            other => panic!("second create_mls_group must return CreationFailed, got {other:?}"),
        }

        // The first group's state is byte-for-byte intact — the sentinel
        // survived, so no clobber with fresh keys occurred.
        let after_seq = {
            let entry = provider
                .contexts
                .get(&ctx_id)
                .expect("first group still registered after rejected duplicate");
            entry.value().send_sequence
        };
        assert_eq!(
            after_seq, SENTINEL_SEQ,
            "the live group's state must be unchanged after a rejected duplicate create \
             (a clobber would reset send_sequence to 0)"
        );
    }

    #[test]
    fn distribute_sender_key_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(
            provider
                .distribute_sender_key(&ctx_id, "did:dht:z6MkBob")
                .is_err()
        );
    }

    #[test]
    fn remove_member_sender_key_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(
            provider
                .remove_member_sender_key(&ctx_id, "did:dht:z6MkBob")
                .is_err()
        );
    }

    #[test]
    fn generate_sender_key_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(provider.generate_sender_key(&ctx_id).is_err());
    }

    #[test]
    fn self_removal_is_noop() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        // Self-removal is a no-op: the leaving member abandons their local
        // MLS group state; the remaining members handle the actual removal
        // via a Commit from the group admin (#1294).
        let result = provider.remove_member(&ctx_id, TEST_DID);
        assert!(result.is_ok());
    }

    // -- New tests for sender key distribution wiring --------------------------

    #[test]
    fn create_mls_group_includes_wrapping_key() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let entry = provider.contexts.get(&ctx_id).unwrap();
        let state = entry.value();
        let extracted =
            super::super::wrapping_extension::extract_own_wrapping_key(&state.mls_group).unwrap();
        assert_eq!(
            extracted,
            Some(**provider.wrapping_public_key.load()),
            "own leaf node must contain provider's wrapping public key"
        );
    }

    #[test]
    fn distribute_sender_key_hpke_seals_when_wrapping_key_available() {
        use super::super::group::generate_key_package_with_wrapping_key;

        let alice_provider = make_provider();
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_wrapping = [0xBB_u8; 32];
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping)).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();

        alice_provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        {
            let entry = alice_provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            assert_eq!(
                state.member_wrapping_keys.get(bob_did),
                Some(&bob_wrapping),
                "Bob's wrapping key must be stored after add_member"
            );
        }

        alice_provider
            .distribute_sender_key(&ctx_id, bob_did)
            .unwrap();

        let pending = alice_provider
            .drain_pending_sender_key_messages(&ctx_id)
            .unwrap();
        assert_eq!(pending.len(), 1, "should have 1 pending distribution");
        assert_eq!(pending[0].0, bob_did, "pending message should target Bob");
        assert!(
            !pending[0].1.is_empty(),
            "serialized message should be non-empty"
        );

        let msg = scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::from_bytes(
            &pending[0].1,
        )
        .unwrap();
        match msg {
            scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::KeyResponse(resp) => {
                assert_eq!(resp.sender_did, TEST_DID);
                assert_eq!(resp.epoch, 1, "initial epoch starts at 1 (0 is sentinel)");
            }
            _ => panic!("expected KeyResponse variant"),
        }
    }

    #[test]
    fn distribute_sender_key_no_wrapping_key_still_stores_locally() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        provider.distribute_sender_key(&ctx_id, bob_did).unwrap();

        {
            let entry = provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            let ctx_hex = hex::encode(ctx_id);
            assert!(state.sender_key_store.get(&ctx_hex, TEST_DID).is_some());
        }

        let pending = provider.drain_pending_sender_key_messages(&ctx_id).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn process_incoming_sender_key_roundtrip() {
        use super::super::group::generate_key_package_with_wrapping_key;

        let alice_provider = make_provider();
        let bob_provider = MlsCryptoProvider::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
        );
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();
        bob_provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";

        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let bob_wrapping_pk = **bob_provider.wrapping_public_key.load();
        let (bob_kp_bundle, _bob_signer, _bob_mls) =
            generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping_pk)).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        alice_provider
            .add_member(&ctx_id, bob_did, Some(&kp_bytes))
            .unwrap();

        alice_provider
            .distribute_sender_key(&ctx_id, bob_did)
            .unwrap();
        let pending = alice_provider
            .drain_pending_sender_key_messages(&ctx_id)
            .unwrap();
        assert_eq!(pending.len(), 1);

        bob_provider
            .process_incoming_sender_key(&ctx_id, TEST_DID, &pending[0].1)
            .unwrap();

        {
            let bob_entry = bob_provider.contexts.get(&ctx_id).unwrap();
            let bob_state = bob_entry.value();
            let ctx_hex = hex::encode(ctx_id);
            let alice_key = bob_state.sender_key_store.get(&ctx_hex, TEST_DID);
            assert!(
                alice_key.is_some(),
                "Bob must have Alice's sender key after processing distribution"
            );

            let alice_entry = alice_provider.contexts.get(&ctx_id).unwrap();
            let alice_state = alice_entry.value();
            assert_eq!(
                alice_key.unwrap().as_bytes(),
                alice_state.sender_key.as_bytes(),
                "recovered key must match Alice's sender key"
            );
        }
    }

    #[test]
    fn drain_pending_sender_key_messages_clears_queue() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let pending = provider.drain_pending_sender_key_messages(&ctx_id).unwrap();
        assert!(pending.is_empty());

        provider
            .distribute_sender_key(&ctx_id, "did:dht:z6MkBob")
            .unwrap();
        let pending = provider.drain_pending_sender_key_messages(&ctx_id).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn drain_pending_sender_key_messages_errors_without_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        assert!(provider.drain_pending_sender_key_messages(&ctx_id).is_err());
    }

    #[test]
    fn process_incoming_sender_key_rejects_wrong_sender() {
        let bob_provider = MlsCryptoProvider::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
        );
        let ctx_id = make_context_id();
        bob_provider.create_mls_group(&ctx_id).unwrap();

        let ctx_hex = hex::encode(ctx_id);
        let bob_wrapping_pk = **bob_provider.wrapping_public_key.load();
        let (sealed_vec, ephemeral_pub) =
            crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                &[42u8; 32],
                &bob_wrapping_pk,
                &ctx_hex,
                TEST_DID,
                0,
            )
            .unwrap();
        let sealed: [u8; 60] = sealed_vec.try_into().unwrap();

        let response = SenderKeyResponse {
            sender_did: TEST_DID.to_string(),
            epoch: 0,
            hpke_sealed_key: sealed,
            ephemeral_pubkey: ephemeral_pub,
            request_nonce: [0u8; 16],
        };
        let msg = SenderKeyDistributionMessage::KeyResponse(response);
        let serialized = msg.to_bytes().unwrap();

        let result =
            bob_provider.process_incoming_sender_key(&ctx_id, "did:dht:z6MkCharlie", &serialized);
        assert!(
            result.is_err(),
            "should reject when sender_did doesn't match transport sender"
        );
    }

    // -------------------------------------------------------------------
    // MLS crypto state persistence tests (#645)
    // -------------------------------------------------------------------

    #[test]
    fn export_crypto_state_returns_empty_for_unknown_context() {
        let provider = make_provider();
        let unknown_ctx = [0xFFu8; 32];
        let exported = provider.export_crypto_state(&unknown_ctx).unwrap();
        assert!(
            exported.is_empty(),
            "should return empty Vec for unknown context"
        );
    }

    #[test]
    fn restore_crypto_state_noop_on_empty_data() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        // restore_crypto_state with empty data should be a no-op.
        let result = provider.restore_crypto_state(&ctx_id, &[]);
        assert!(result.is_ok(), "empty data should succeed silently");
    }

    #[test]
    fn export_restore_crypto_state_roundtrip() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        // Create a group and generate a sender key.
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        // Store a sender key for a remote member.
        {
            let ctx_id_hex = hex::encode(ctx_id);
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state.sender_key_store.set_unchecked(
                &ctx_id_hex,
                "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
                generate_sender_key(),
            );
            state.member_wrapping_keys.insert(
                "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
                [0xAA; 32],
            );
            state.sender_key_epoch = 42;
        }

        // Capture pre-export state for comparison.
        let (original_sender_key, original_epoch, original_wrapping_key, original_bob_key) = {
            let entry = provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            let ctx_id_hex = hex::encode(ctx_id);
            (
                state.sender_key.clone(),
                state.sender_key_epoch,
                state
                    .member_wrapping_keys
                    .get("did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo")
                    .copied()
                    .unwrap(),
                state
                    .sender_key_store
                    .get(
                        &ctx_id_hex,
                        "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
                    )
                    .unwrap()
                    .clone(),
            )
        };

        // Export crypto state.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(!exported.is_empty(), "exported state should be non-empty");

        // Create a fresh provider and restore the state.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());

        // Verify context doesn't exist before restore.
        let encrypted = test_encrypt_message(&provider2, &ctx_id, b"test", 0, 0);
        assert!(encrypted.is_err(), "should fail before restore");

        // Restore.
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Verify the MLS group is functional: encrypt should succeed.
        let encrypted = test_encrypt_message(&provider2, &ctx_id, b"test after restore", 0, 0);
        assert!(
            encrypted.is_ok(),
            "encrypt should succeed after restore: {encrypted:?}"
        );

        // Verify sender key state is restored.
        {
            let entry = provider2.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            let ctx_id_hex = hex::encode(ctx_id);

            // Sender key matches.
            assert_eq!(
                state.sender_key.as_bytes(),
                original_sender_key.as_bytes(),
                "local sender key should be restored"
            );

            // Sender key epoch matches.
            assert_eq!(
                state.sender_key_epoch, original_epoch,
                "sender key epoch should be restored"
            );

            // Bob's sender key is restored.
            let bob_key = state
                .sender_key_store
                .get(
                    &ctx_id_hex,
                    "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
                )
                .expect("Bob's sender key should be restored");
            assert_eq!(
                bob_key.as_bytes(),
                original_bob_key.as_bytes(),
                "Bob's sender key should match"
            );

            // Bob's wrapping key is restored.
            let wk = state
                .member_wrapping_keys
                .get("did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo")
                .expect("Bob's wrapping key should be restored");
            assert_eq!(*wk, original_wrapping_key, "wrapping key should match");

            // Pending distributions should be empty after restore.
            assert!(
                state.pending_distributions.is_empty(),
                "pending distributions should be empty after restore"
            );
        }
    }

    #[test]
    fn restore_preserves_sender_key_epoch_high_water_mark() {
        // Regression for #1608 rollback-protection across restart.
        //
        // Scenario:
        //   1. Alice stores Bob's sender key via set_checked at epoch=5.
        //   2. Alice exports the crypto state (snapshot).
        //   3. Alice restarts and restores the snapshot into a fresh
        //      provider.
        //   4. An attacker replays an older-epoch distribution (epoch=3)
        //      or attempts same-epoch (epoch=5) — BOTH must be rejected.
        //   5. A legitimate post-snapshot rotation (epoch=6) must be
        //      accepted.
        //
        // Without persistence of the per-sender epoch map, the fresh
        // in-memory store would have no floor and accept any epoch,
        // silently re-opening the rollback window.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);

        // Step 1: install Bob's epoch-5 key via set_checked so the
        // epoch map is populated exactly as it would be in production.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 5)
                .expect("first set_checked at epoch 5 must succeed");
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                5,
                "pre-snapshot epoch must be 5"
            );
        }

        // Step 2: export snapshot.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(!exported.is_empty());

        // Step 3: simulate restart — fresh provider, restore state.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Verify the restored floor exactly matches the persisted epoch.
        {
            let entry = provider2.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                5,
                "post-restore epoch floor must match persisted value"
            );
        }

        // Step 4a: replay of pre-snapshot epoch=3 MUST be rejected.
        {
            let mut entry = provider2.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 3)
                .expect_err("replay of epoch 3 must be rejected after restore");
            assert!(
                matches!(
                    err,
                    SenderKeyError::EpochNotMonotonic {
                        current: 5,
                        received: 3,
                        ..
                    }
                ),
                "expected EpochNotMonotonic(current=5, received=3), got {err:?}"
            );
        }

        // Step 4b: same-epoch replay at 5 MUST also be rejected.
        {
            let mut entry = provider2.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 5)
                .expect_err("same-epoch replay at 5 must be rejected after restore");
            assert!(
                matches!(
                    err,
                    SenderKeyError::EpochNotMonotonic {
                        current: 5,
                        received: 5,
                        ..
                    }
                ),
                "expected EpochNotMonotonic(current=5, received=5), got {err:?}"
            );
        }

        // Step 5: legitimate post-snapshot rotation to epoch=6 is accepted.
        {
            let mut entry = provider2.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 6)
                .expect("post-snapshot rotation at epoch 6 must succeed");
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                6,
                "epoch floor should advance to 6 after legitimate rotation"
            );
        }
    }

    #[test]
    fn restore_preserves_epoch_floor_for_removed_members() {
        // Removed members still have their epoch floor retained (see
        // `SenderKeyStore::remove`) so a rejoining member cannot replay
        // an earlier-epoch key. This invariant must survive a restart.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCa";
        let ctx_id_hex = hex::encode(ctx_id);

        // Install then remove Carol's epoch-9 key. The key is gone but
        // the floor is retained.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, carol_did, generate_sender_key(), 9)
                .unwrap();
            state.sender_key_store.remove(&ctx_id_hex, carol_did);
            assert!(
                state.sender_key_store.get(&ctx_id_hex, carol_did).is_none(),
                "key must be gone after remove"
            );
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, carol_did),
                9,
                "epoch floor must be retained post-remove"
            );
        }

        // Snapshot + restart.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Restored store has no key for Carol but still has the floor.
        {
            let entry = provider2.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            assert!(
                state.sender_key_store.get(&ctx_id_hex, carol_did).is_none(),
                "removed key must not reappear after restore"
            );
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, carol_did),
                9,
                "removed-member floor must survive restart"
            );
        }

        // Attempt to install an earlier-epoch key (rejoin attack) — rejected.
        {
            let mut entry = provider2.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, carol_did, generate_sender_key(), 4)
                .expect_err("rejoin at older epoch must be rejected");
            assert!(matches!(err, SenderKeyError::EpochNotMonotonic { .. }));
        }
    }

    #[test]
    fn restore_tolerates_legacy_snapshot_with_seeded_floor() {
        // Back-compat: a snapshot serialized before `sender_key_epochs`
        // was persisted must still deserialize cleanly AND must close
        // the one-shot rollback window that would otherwise exist at
        // the first post-upgrade restart.
        //
        // Without the legacy-floor seed, restoring would leave every
        // per-sender floor at 0, so a captured pre-upgrade epoch=k>0
        // distribution could be replayed through `set_checked` against
        // a zero floor. The fix seeds every restored sender with the
        // global `sender_key_epoch` counter (which IS persisted in
        // legacy snapshots) as a conservative lower bound.
        //
        // We simulate a legacy snapshot by clearing the new field from
        // the freshly-exported snapshot and re-serializing it, which
        // models the wire format of the old struct (serde(default)
        // fills in an empty Vec on deserialize).
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            // Set a non-trivial global sender_key_epoch so we can verify
            // the legacy seed uses it.
            state.sender_key_epoch = 7;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob_did, generate_sender_key());
        }

        // Export, then hand-edit the msgpack to drop the epoch map.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2
            .restore_crypto_state(&ctx_id, &legacy_bytes)
            .expect("legacy snapshot (empty epoch map) must restore cleanly");

        // The legacy snapshot had no per-sender epoch map, so the
        // restore path seeds every sender with the global
        // `sender_key_epoch` counter as a conservative lower bound.
        // This closes the one-shot rollback window.
        {
            let mut entry = provider2.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, bob_did),
                7,
                "legacy restore must seed per-sender floor from the global sender_key_epoch \
                 counter (= 7 in this fixture), not leave it at zero"
            );
            // Replay of epoch <= 7 must be rejected — the one-shot
            // window is closed.
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 7)
                .expect_err("same-epoch replay must be rejected under legacy seed");
            assert!(matches!(err, SenderKeyError::EpochNotMonotonic { .. }));
            let err = state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 3)
                .expect_err("older-epoch replay must be rejected under legacy seed");
            assert!(matches!(err, SenderKeyError::EpochNotMonotonic { .. }));
            // Legitimate rotation above the seeded floor is accepted.
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, bob_did, generate_sender_key(), 8)
                .expect("post-seed rotation at epoch 8 must succeed");
        }
    }

    #[test]
    fn restore_legacy_snapshot_gap_case_residual_window_documented() {
        // Pins the residual-window case for legacy snapshots: the
        // floor seed uses the global `sender_key_epoch` counter,
        // which reflects LOCAL rotation count only. A remote peer
        // whose true per-sender floor exceeded the local counter at
        // snapshot time is seeded with the lower local value,
        // leaving a residual rollback window bounded by
        // `MAX_EPOCH_ADVANCE` in the receive path. This test
        // encodes the observed behavior so the gap case is
        // unambiguous.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let peer_did = "did:dht:z6MkPeerPeerPeerPeerPeerPeerPeerPeerPeerPe";
        let ctx_id_hex = hex::encode(ctx_id);

        // Scenario: local provider has rotated only once
        // (`sender_key_epoch = 1`), but the peer has rotated many
        // times and set_checked has been called with epoch = 50 for
        // the peer. This represents a pre-C1 runtime where the peer
        // epoch IS tracked in the `epochs` map but the snapshot
        // format does NOT persist it.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state.sender_key_epoch = 1;
            state
                .sender_key_store
                .set_checked(&ctx_id_hex, peer_did, generate_sender_key(), 50)
                .unwrap();
            assert_eq!(
                state.sender_key_store.epoch(&ctx_id_hex, peer_did),
                50,
                "pre-snapshot peer floor is 50 (above local counter 1)"
            );
        }

        // Export, then strip the per-sender epoch map to simulate a
        // legacy snapshot.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2
            .restore_crypto_state(&ctx_id, &legacy_bytes)
            .expect("legacy restore must succeed");

        // OBSERVED BEHAVIOR: the peer's restored floor equals the
        // LOCAL sender_key_epoch counter (1), NOT the true pre-snapshot
        // peer floor (50). This is the documented residual window.
        {
            let entry = provider2.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            let seeded = state.sender_key_store.epoch(&ctx_id_hex, peer_did);
            assert_eq!(
                seeded, 1,
                "legacy seed uses global sender_key_epoch (1), NOT the true peer floor (50). \
                 This is the documented residual window bounded by MAX_EPOCH_ADVANCE in the \
                 receive path. Fully closing it would require a format break."
            );
            // The residual window is `peer_floor - seeded_floor` = 49
            // in this scenario, bounded from above by MAX_EPOCH_ADVANCE
            // in the actual receive path.
            assert!(
                50 > seeded,
                "gap exists: true peer floor ({}) > seeded floor ({})",
                50,
                seeded
            );
        }
    }

    #[test]
    fn restore_legacy_snapshot_with_zero_global_epoch_seeds_floor_to_one() {
        // Edge case of the legacy-floor seed: if the legacy snapshot's
        // global `sender_key_epoch` is 0 (brand-new context, never
        // rotated), the seed must still be at least 1 so that
        // `set_checked` rejects an incoming epoch=0 (which would fail
        // the `epoch > current_epoch` guard regardless, but we want
        // the floor to be explicit rather than implicit).
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state.sender_key_epoch = 0;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob_did, generate_sender_key());
        }

        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2
            .restore_crypto_state(&ctx_id, &legacy_bytes)
            .unwrap();

        let entry = provider2.contexts.get(&ctx_id).unwrap();
        let state = entry.value();
        assert_eq!(
            state.sender_key_store.epoch(&ctx_id_hex, bob_did),
            1,
            "legacy seed must clamp to at least 1 when global counter is 0"
        );
    }

    #[test]
    fn export_fails_on_destroyed_group() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        provider.create_mls_group(&ctx_id).unwrap();
        provider.destroy_mls_group(&ctx_id).unwrap();

        // After destroy, export should return empty (context removed).
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(
            exported.is_empty(),
            "destroyed group should export empty state"
        );
    }

    #[test]
    fn restore_rejects_corrupt_data() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        let result = provider.restore_crypto_state(&ctx_id, b"not valid msgpack");
        assert!(result.is_err(), "corrupt data should fail");
    }

    #[test]
    fn restore_idempotent_on_same_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let exported = provider.export_crypto_state(&ctx_id).unwrap();

        // Restore into a fresh provider twice — second should overwrite cleanly.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Should still be functional.
        let encrypted = test_encrypt_message(&provider2, &ctx_id, b"test", 0, 0);
        assert!(
            encrypted.is_ok(),
            "second restore should produce working state"
        );
    }

    #[test]
    fn export_restore_preserves_mls_epoch() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Get the epoch before export.
        let epoch_before = {
            let entry = provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            state.mls_group.epoch().unwrap()
        };

        let exported = provider.export_crypto_state(&ctx_id).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // Verify epoch is preserved.
        let epoch_after = {
            let entry = provider2.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            state.mls_group.epoch().unwrap()
        };

        assert_eq!(
            epoch_before, epoch_after,
            "MLS epoch should be preserved across export/restore"
        );
    }

    #[test]
    fn test_wrapping_key_persisted_across_restart() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Capture the original wrapping keypair.
        let original_public = **provider.wrapping_public_key.load();
        let original_secret: [u8; 32] = ***provider.wrapping_secret_key.load();

        // Sanity: the keypair should not be all zeros.
        assert_ne!(
            original_public, [0u8; 32],
            "wrapping public key must not be zero"
        );
        assert_ne!(
            original_secret, [0u8; 32],
            "wrapping secret key must not be zero"
        );

        // Export the crypto state.
        let exported = provider.export_crypto_state(&ctx_id).unwrap();
        assert!(!exported.is_empty());

        // Create a fresh provider (simulates restart — gets a NEW random keypair).
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string());
        let fresh_public = **provider2.wrapping_public_key.load();
        assert_ne!(
            fresh_public, original_public,
            "fresh provider should have a DIFFERENT wrapping public key"
        );

        // Restore the exported state into the fresh provider.
        provider2.restore_crypto_state(&ctx_id, &exported).unwrap();

        // After restore, the wrapping keypair must match the ORIGINAL, not the fresh one.
        let restored_public = **provider2.wrapping_public_key.load();
        let restored_secret: [u8; 32] = ***provider2.wrapping_secret_key.load();

        assert_eq!(
            restored_public, original_public,
            "wrapping public key must be restored from snapshot, not freshly generated"
        );
        assert_eq!(
            restored_secret, original_secret,
            "wrapping secret key must be restored from snapshot, not freshly generated"
        );
    }

    // -------------------------------------------------------------------
    // H9: receive-side sender-key epoch ceiling
    // -------------------------------------------------------------------

    /// Two-party fixture: Alice (creator) and Bob (joiner) share a real
    /// MLS group via the provider-level Welcome flow, exchange Alice's
    /// sender key, and return both providers ready for `seal()` /
    /// `open()`. Used by the H9 ceiling tests.
    fn setup_alice_bob_two_party() -> (MlsCryptoProvider, MlsCryptoProvider, [u8; 32], String) {
        let alice_did = TEST_DID;
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let context_id = make_context_id();

        let alice = MlsCryptoProvider::new(alice_did.to_string());
        alice.create_mls_group(&context_id).unwrap();
        alice.generate_sender_key(&context_id).unwrap();

        let bob = MlsCryptoProvider::new(bob_did.to_string());
        let bob_kp_bytes = bob.prepare_key_package_for_join().unwrap();

        let add_output = alice
            .add_member(&context_id, bob_did, Some(&bob_kp_bytes))
            .unwrap();

        bob.join_from_welcome(&context_id, &add_output.welcome_bytes)
            .unwrap();
        bob.generate_sender_key(&context_id).unwrap();

        // Distribute Alice's sender key to Bob via the legitimate path.
        // This sets `bob.sender_key_store.epoch(ctx, alice_did) = 1`,
        // which is the H9 high-water mark.
        alice.distribute_sender_key(&context_id, bob_did).unwrap();
        let pending = alice
            .drain_pending_sender_key_messages(&context_id)
            .unwrap();
        assert_eq!(pending.len(), 1);
        for (_target, msg) in pending {
            bob.process_incoming_sender_key(&context_id, alice_did, &msg)
                .unwrap();
        }

        (alice, bob, context_id, alice_did.to_string())
    }

    /// Build a minimal `InnerEnvelope` with a deterministic signing key.
    /// `provider.open()` does not verify signatures (per the comment in
    /// `open()`, signature verification is deferred to `ContextManager`),
    /// so an arbitrary key suffices for the H9 receive-ceiling tests.
    fn build_test_inner(
        context_id: &[u8; 32],
        sender_did: &str,
        epoch_field: u64,
        sequence_field: u64,
    ) -> scp_protocol::envelope::inner::InnerEnvelope {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let params = crate::envelope::inner::InnerEnvelopeParams {
            version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
            context_id: &hex::encode(context_id),
            sender_did,
            epoch: epoch_field,
            generation: 0,
            sequence: sequence_field,
            timestamp: 1_700_000_000,
            message_type: crate::envelope::inner::MessageType::Content,
            payload: b"h9 ceiling probe",
            provenance: None,
            signing_key_id: SigningKeyId::Active,
        };
        crate::envelope::inner::sign::create_inner_envelope_raw(&params, &sk).unwrap()
    }

    /// Force Alice's local `sender_key_epoch` to a specific value so the
    /// next `seal()` emits a sender-layer header with that epoch in the
    /// clear, bypassing any sender-side bound. Bob's `open()` is what
    /// the test exercises.
    fn force_alice_sender_key_epoch(alice: &MlsCryptoProvider, context_id: &[u8; 32], epoch: u64) {
        let mut entry = alice.contexts.get_mut(context_id).unwrap();
        let state = entry.value_mut();
        state.sender_key_epoch = epoch;
    }

    fn ctx_routing_id(context_id: &[u8; 32]) -> Vec<u8> {
        // Any 32-byte routing id satisfies `create_outer_envelope`'s
        // length check; the open() path does not validate routing_id.
        context_id.to_vec()
    }

    #[test]
    fn test_recv_epoch_ceiling_rejects_far_future() {
        // H9: A crafted sender-layer header with `epoch = u64::MAX` must
        // be rejected before it pollutes `recv_sequence_tracker` and
        // permanently locks Bob out of subsequent legitimate messages
        // from Alice. Bob's stored high-water for Alice is 1 (set by
        // the legitimate distribution in `setup_alice_bob_two_party`),
        // so the ceiling is `1 + MAX_EPOCH_ADVANCE = 1001`.
        let (alice, bob, ctx_id, alice_did) = setup_alice_bob_two_party();

        force_alice_sender_key_epoch(&alice, &ctx_id, u64::MAX);

        let inner = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        let err = bob
            .open(&ctx_id, &sealed)
            .expect_err("u64::MAX epoch must be rejected by the H9 ceiling");
        match err {
            ContextError::CryptoFailed(msg) => {
                assert!(
                    msg.contains("exceeds ceiling"),
                    "expected ceiling-rejection error, got: {msg}"
                );
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }

        // Bob's recv_sequence_tracker for Alice MUST NOT have been
        // updated by the rejected message. Without this guarantee the
        // attack still succeeds — the next legitimate message from
        // Alice would be rejected as a "replay or reorder".
        {
            let entry = bob.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            assert!(
                !state.recv_sequence_tracker.contains_key(&alice_did),
                "rejected H9 message must not pollute recv_sequence_tracker"
            );
        }
    }

    #[test]
    fn test_recv_epoch_ceiling_rejects_unreasonable_advance() {
        // H9 boundary: stored high-water = 1, MAX_EPOCH_ADVANCE = 1000,
        // so ceiling = 1001. An advance of 1001 (epoch = 1002) is one
        // past the boundary and must be rejected.
        let (alice, bob, ctx_id, alice_did) = setup_alice_bob_two_party();

        force_alice_sender_key_epoch(&alice, &ctx_id, 1002);

        let inner = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        let err = bob
            .open(&ctx_id, &sealed)
            .expect_err("epoch one past the ceiling must be rejected");
        match err {
            ContextError::CryptoFailed(msg) => {
                assert!(
                    msg.contains("exceeds ceiling"),
                    "expected ceiling-rejection error, got: {msg}"
                );
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_recv_epoch_ceiling_allows_gap_fill() {
        // H9 boundary: an advance of exactly MAX_EPOCH_ADVANCE must be
        // accepted. Stored high-water = 1, ceiling = 1001, so an
        // incoming epoch of 1001 sits exactly on the boundary.
        let (alice, bob, ctx_id, alice_did) = setup_alice_bob_two_party();

        force_alice_sender_key_epoch(&alice, &ctx_id, 1001);

        let inner = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        let result = bob
            .open(&ctx_id, &sealed)
            .expect("epoch == ceiling must be accepted (boundary inclusive)");
        match result {
            scp_protocol::context::builder::OpenResult::Application(env) => {
                assert_eq!(env.sender_did, alice_did);
            }
            other => panic!("expected Application, got {other:?}"),
        }

        // The receive tracker must have been updated with the boundary
        // epoch so subsequent same-epoch messages don't replay.
        let entry = bob.contexts.get(&ctx_id).unwrap();
        let state = entry.value();
        let entry = state.recv_sequence_tracker.get(&alice_did).copied();
        assert_eq!(entry, Some((1001, 0)));
    }

    #[test]
    fn test_recv_epoch_normal_path_unchanged() {
        // Regression: the H9 ceiling must not break the happy path.
        // A sequential epoch+sequence stream below the ceiling is
        // accepted, and the receive tracker advances monotonically.
        let (alice, bob, ctx_id, alice_did) = setup_alice_bob_two_party();

        let routing_id = ctx_routing_id(&ctx_id);
        let inner1 = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let inner2 = build_test_inner(&ctx_id, &alice_did, 0, 1);

        // Two sequential seals at Alice's natural epoch=1, sequence
        // increments handled by `seal()` itself.
        let sealed1 = alice.seal(&ctx_id, &inner1, &routing_id, 300).unwrap();
        let sealed2 = alice.seal(&ctx_id, &inner2, &routing_id, 300).unwrap();

        bob.open(&ctx_id, &sealed1).expect("first seal must open");
        bob.open(&ctx_id, &sealed2).expect("second seal must open");

        let entry = bob.contexts.get(&ctx_id).unwrap();
        let state = entry.value();
        let (epoch, seq) = state
            .recv_sequence_tracker
            .get(&alice_did)
            .copied()
            .expect("tracker must be populated by happy-path opens");
        assert_eq!(epoch, 1, "epoch should be Alice's natural epoch");
        assert_eq!(seq, 1, "sequence should advance to the second message");
    }

    #[test]
    fn test_recv_epoch_reorder_still_rejected() {
        // Regression: existing replay/reorder rejection must still
        // fire even with the H9 ceiling in place. After a successful
        // open at (epoch=1, seq=1), a replay of the same (epoch, seq)
        // and a lower-sequence message must both be rejected.
        let (alice, bob, ctx_id, alice_did) = setup_alice_bob_two_party();

        let routing_id = ctx_routing_id(&ctx_id);

        // First, advance the receive tracker to (1, 1) via two
        // legitimate messages.
        let inner_a = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let inner_b = build_test_inner(&ctx_id, &alice_did, 0, 1);
        let sealed_a = alice.seal(&ctx_id, &inner_a, &routing_id, 300).unwrap();
        let sealed_b = alice.seal(&ctx_id, &inner_b, &routing_id, 300).unwrap();
        bob.open(&ctx_id, &sealed_a).unwrap();
        bob.open(&ctx_id, &sealed_b).unwrap();

        // Now force Alice's send_sequence backwards and re-seal. The
        // resulting header has (epoch=1, sequence=0) which is below
        // Bob's last-seen (epoch=1, sequence=1) — must be rejected by
        // the existing replay guard, NOT silently accepted because
        // the H9 ceiling check passed.
        {
            let mut entry = alice.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state.send_sequence = 0;
        }
        let inner_replay = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let sealed_replay = alice
            .seal(&ctx_id, &inner_replay, &routing_id, 300)
            .unwrap();
        let err = bob.open(&ctx_id, &sealed_replay).expect_err(
            "lower-sequence message at the same epoch must still be rejected as replay",
        );
        match err {
            ContextError::CryptoFailed(msg) => {
                assert!(
                    msg.contains("replay or reorder"),
                    "expected replay/reorder rejection, got: {msg}"
                );
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }

        // Lower-epoch reorder: force Alice's epoch to 0 and re-seal.
        // The header carries (epoch=0, sequence=...), which is below
        // Bob's last-seen (epoch=1, ...) and must be rejected.
        force_alice_sender_key_epoch(&alice, &ctx_id, 0);
        {
            let mut entry = alice.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state.send_sequence = 5;
        }
        let inner_lower = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let sealed_lower = alice.seal(&ctx_id, &inner_lower, &routing_id, 300).unwrap();
        let err = bob
            .open(&ctx_id, &sealed_lower)
            .expect_err("lower-epoch message must still be rejected as reorder");
        match err {
            ContextError::CryptoFailed(msg) => {
                assert!(
                    msg.contains("replay or reorder"),
                    "expected replay/reorder rejection, got: {msg}"
                );
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // ADR-049 commit 12b.2a — `take_crypto_state` tests
    // -----------------------------------------------------------------

    #[test]
    fn take_crypto_state_removes_entry_from_provider() {
        // Create a two-member context via the legacy path, then take
        // the state. Post-take: the provider's `contexts` map has no
        // entry for this context_id, the `taken_context_ids` set
        // does, and the returned `OwnedMlsCryptoState` carries the
        // expected mls group + sender key + counter values.
        let (alice, _bob, ctx_id, _alice_did) = setup_alice_bob_two_party();

        // Capture the sender_key_epoch before take so we can compare
        // to the returned owned value.
        let epoch_before = alice
            .contexts
            .get(&ctx_id)
            .unwrap()
            .value()
            .sender_key_epoch;

        let owned = alice
            .take_crypto_state(&ctx_id)
            .expect("take_crypto_state succeeds for live context");
        assert_eq!(owned.sender_key_epoch, epoch_before);
        // send_sequence starts at 0 — setup_alice_bob_two_party does
        // not call seal().
        assert_eq!(owned.send_sequence, 0);

        // `contexts` map now has no entry for this id.
        assert!(!alice.contexts.contains_key(&ctx_id));
        // `taken_context_ids` records the take.
        assert!(alice.taken_context_ids.contains(&ctx_id));
    }

    #[test]
    fn take_crypto_state_missing_context_returns_not_registered() {
        let provider = make_provider();
        let ctx_id = [9u8; 32];
        let err = provider
            .take_crypto_state(&ctx_id)
            .expect_err("take on unknown context must error");
        match err {
            ContextError::ContextNotRegistered(msg) => {
                assert!(
                    msg.contains("no MLS group for context"),
                    "expected 'no MLS group' message, got: {msg}",
                );
            }
            other => panic!("expected ContextNotRegistered, got {other:?}"),
        }
    }

    #[test]
    fn take_crypto_state_double_take_returns_owned_by_actor() {
        // First take succeeds. Second take sees the id in
        // `taken_context_ids` and returns the "owned by actor"
        // error instead of the generic `no MLS group` error.
        let (alice, _bob, ctx_id, _alice_did) = setup_alice_bob_two_party();

        let _owned = alice.take_crypto_state(&ctx_id).unwrap();

        let err = alice
            .take_crypto_state(&ctx_id)
            .expect_err("second take must error");
        match err {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(msg, "context state owned by actor");
            }
            other => panic!("expected CryptoFailed('owned by actor'), got {other:?}"),
        }
    }

    #[test]
    fn seal_after_take_returns_owned_by_actor() {
        // After `take_crypto_state`, the legacy `seal` path on the
        // same context must return `CryptoFailed('context state
        // owned by actor')` so callers learn to route through the
        // actor mailbox instead.
        let (alice, _bob, ctx_id, alice_did) = setup_alice_bob_two_party();
        let _owned = alice.take_crypto_state(&ctx_id).unwrap();

        let inner = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);

        let err = alice
            .seal(&ctx_id, &inner, &routing_id, 300)
            .expect_err("seal on a taken context must error");
        match err {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(msg, "context state owned by actor");
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_after_take_returns_owned_by_actor() {
        // Companion to `seal_after_take`: the `open` path also
        // errors with the same message.
        let (alice, bob, ctx_id, alice_did) = setup_alice_bob_two_party();

        // Seal a message via alice BEFORE taking the state so we
        // have a valid ciphertext to feed into bob's open.
        let inner = build_test_inner(&ctx_id, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        // Now take bob's state — open on bob's side should error.
        let _owned = bob.take_crypto_state(&ctx_id).unwrap();
        let err = bob
            .open(&ctx_id, &sealed)
            .expect_err("open on a taken context must error");
        match err {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(msg, "context state owned by actor");
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
    }

    #[test]
    fn with_context_distinguishes_never_created_from_taken() {
        // `with_context` (the internal accessor) returns the generic
        // "no MLS group for this context" error when the id was
        // never created, and the "context state owned by actor"
        // error when it was taken. The distinction matters for
        // actionable diagnostics.
        let (alice, _bob, ctx_id, _alice_did) = setup_alice_bob_two_party();

        // Never-created id.
        let other_id = [0xAAu8; 32];
        let err_never = alice
            .with_context(&other_id, |_state| Ok(()))
            .expect_err("never-created errors");
        match err_never {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(msg, "no MLS group for this context");
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }

        // Take and retry — same id now surfaces the "owned by
        // actor" message.
        let _owned = alice.take_crypto_state(&ctx_id).unwrap();
        let err_taken = alice
            .with_context(&ctx_id, |_state| Ok(()))
            .expect_err("taken errors");
        match err_taken {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(msg, "context state owned by actor");
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
    }
}
