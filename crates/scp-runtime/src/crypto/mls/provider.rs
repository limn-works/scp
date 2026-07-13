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

use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use scp_clock::Clock;
use scp_did::SigningKeyId;
use serde::{Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserializeTrait;
use zeroize::{Zeroize, Zeroizing};

use super::backend::MlsBackend;
use super::production_backend::ProductionMlsBackend;
use crate::crypto::hpke_backend::{HpkeBackend, ProductionHpkeBackend};
use scp_mls::credential::ScpCredential;
use scp_mls::encrypt::{DecryptedContent, decrypt_with_sender_did};
use scp_mls::group::{self, SCP_CIPHERSUITE, ScpMlsGroup};
use scp_mls::validate_key_package_lifetime;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::crypto::sender_keys::{
    MAX_EPOCH_ADVANCE, NonceDedup, SenderKey, SenderKeyDistributionMessage, SenderKeyResponse,
    SenderKeyStore, generate_sender_key, generate_wrapping_keypair,
};

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

impl MlsCryptoSnapshot {
    /// Zeroizes every field that holds private key material.
    ///
    /// [`export_crypto_state`](Self::export_crypto_state) calls this once at its
    /// end (belt-and-suspenders) after serializing the snapshot.
    /// [`restore_crypto_state`](Self::restore_crypto_state) does NOT call it:
    /// restore consumes each secret field incrementally as it moves the material
    /// into the live crypto state (`drain`/`mem::replace`/per-field `zeroize` at
    /// the point of use), so there is no single end-of-function sweep to make. On
    /// both paths the [`Drop`] impl below is the backstop that also fires on an
    /// early `?` return, so raw signer / sender-key / wrapping-secret / MLS-secret
    /// bytes never linger un-zeroized in freed memory on ANY path (matches the
    /// parity guarantee the `scp-mls` and `scp-client` snapshots make via their
    /// own `Drop`s).
    fn zeroize_secrets(&mut self) {
        self.signer_bytes.zeroize();
        self.local_sender_key.zeroize();
        self.wrapping_secret_key.zeroize();
        for (_, value) in &mut self.mls_storage_entries {
            value.zeroize();
        }
        for (_, key) in &mut self.sender_key_entries {
            key.zeroize();
        }
    }
}

// SECURITY: zeroize key material on every drop path — including an early `?`
// return between deserialization and the explicit trailing `zeroize` calls — so
// private material never lingers in freed memory. No field is ever moved out of a
// `MlsCryptoSnapshot` (the export/restore paths drain/replace/borrow in place), so
// this `Drop` does not conflict with a partial move.
impl Drop for MlsCryptoSnapshot {
    fn drop(&mut self) {
        self.zeroize_secrets();
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
/// Concurrent calls for the same context are serialized at a higher level by
/// the per-context actor's single-threaded command loop (ADR-049), so
/// contention on these mutexes is minimal.
pub struct MlsCryptoProvider {
    /// The local member's DID (e.g., `"did:dht:z6Mk..."`).
    local_did: String,
    /// Injected hardened [`Clock`] (ADR-057 §Prereq-1). Used for the provider's
    /// direct `scp-mls` calls that mint or validate `KeyPackage` / group-leaf
    /// `Lifetime`s (create-group, generate-key-package, add-member, decrypt) and
    /// for the committer-assigned timestamp at [`Self::add_member`]. In
    /// production this is the SAME `Arc` the actor-deps clock and the injected
    /// [`ProductionMlsBackend`] share — one hardened clock per node, never
    /// openmls's internal one.
    clock: Arc<dyn Clock>,
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
    /// One-shot test seam: when set, the NEXT [`Self::export_crypto_state`]
    /// call returns [`ContextError::CryptoFailed`] and resets the flag.
    ///
    /// This exists solely to drive the spawn-from-Welcome entrypoint's
    /// crypto-durability fail-closed branch end-to-end: the real provider always
    /// exports a NON-EMPTY blob for a just-installed group, so that branch is
    /// otherwise structurally unreachable through the full entrypoint. Gated
    /// behind `#[cfg(any(test, feature = "testing"))]` so the production build
    /// carries neither the field nor the branch. One-shot (fires once, then
    /// clears itself) so a post-rollback export read still behaves normally.
    #[cfg(any(test, feature = "testing"))]
    force_export_failure: std::sync::atomic::AtomicBool,
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
    /// * `clock` - The injected hardened [`Clock`] (ADR-057 §Prereq-1). Shared
    ///   with the constructed [`ProductionMlsBackend`] so a node has exactly one
    ///   hardened clock governing every `KeyPackage` / group-leaf `Lifetime`.
    #[must_use]
    pub fn new(local_did: String, clock: Arc<dyn Clock>) -> Self {
        Self::with_backends(
            local_did,
            Arc::new(ProductionMlsBackend::new(Arc::clone(&clock))),
            Arc::new(ProductionHpkeBackend::new()),
            clock,
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
    /// * `clock` - The injected hardened [`Clock`] (ADR-057 §Prereq-1) used for
    ///   the provider's direct `scp-mls` `Lifetime` mint/validate calls. Tests
    ///   pass `Arc::new(SystemClock)`; production passes the node's shared clock.
    #[must_use]
    pub fn with_backends(
        local_did: String,
        mls_backend: Arc<dyn MlsBackend>,
        hpke_backend: Arc<dyn HpkeBackend>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let (wrapping_public_key, wrapping_secret_key) = generate_wrapping_keypair();
        Self {
            local_did,
            clock,
            mls_backend,
            hpke_backend,
            contexts: DashMap::new(),
            broadcast_keys: DashMap::new(),
            wrapping_public_key: ArcSwap::from_pointee(wrapping_public_key),
            wrapping_secret_key: ArcSwap::from_pointee(Zeroizing::new(wrapping_secret_key)),
            taken_context_ids: DashSet::new(),
            #[cfg(any(test, feature = "testing"))]
            force_export_failure: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Arms the one-shot [`Self::force_export_failure`] seam: the NEXT
    /// [`Self::export_crypto_state`] call returns
    /// [`ContextError::CryptoFailed`] and clears the flag.
    ///
    /// Test-only (see the field docs) — used to induce the spawn-from-Welcome
    /// crypto-durability fail-closed branch, which the real provider cannot
    /// otherwise reach (an installed group always exports a non-empty blob).
    #[cfg(any(test, feature = "testing"))]
    pub fn arm_export_failure_once(&self) {
        self.force_export_failure
            .store(true, std::sync::atomic::Ordering::SeqCst);
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

    /// A clone of the injected hardened [`Clock`] (ADR-057 §Prereq-1) `Arc`.
    ///
    /// Lets the node/FFI construction sites wire the SAME clock `Arc` into the
    /// `Supervisor` that this provider holds, so the "one hardened clock per
    /// node" invariant documented on the [`Self::clock`] field holds by
    /// construction — the supervisor does not fabricate a second `SystemClock`.
    /// The returned `Arc` points at the exact same [`Clock`] this provider (and
    /// its [`ProductionMlsBackend`]) already share.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
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
        // Wrapping-key-only group (no `scp_context_params` `0xFF02`
        // `group_context` extension). The production creator path uses
        // [`Self::create_mls_group_with_context`], which binds the context
        // parameters into `group_context`; this variant is retained for callers
        // that create a bare group without params.
        self.create_group_into_slot(context_id, |credential, wrapping_pk| {
            group::create_group_with_wrapping_key(
                credential,
                Some(wrapping_pk),
                self.clock.as_ref(),
            )
        })
    }

    /// Creates an MLS **context** group whose `group_context` binds the SCP
    /// context parameters via the `scp_context_params` (`0xFF02`) extension
    /// (spec §5.13.3, finding FFI-02).
    ///
    /// This is the production creator write path: the committed
    /// [`ScpContextExtension`] is folded into the MLS key schedule and read back
    /// byte-identically by every joiner. Because the group carries `0xFF02`,
    /// `OpenMLS` (`valn0502`) rejects any Add whose leaf does not declare `0xFF02`
    /// support — pooled key packages therefore MUST be generated via the
    /// context-params path (see
    /// [`MlsBackend::generate_key_package`](super::backend::MlsBackend::generate_key_package)).
    ///
    /// Shares the same slot-reservation and overwrite-refusal invariant as
    /// [`Self::create_mls_group`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::CreationFailed`] if a group already
    /// exists for `context_id`, or [`ContextCreationError::CryptoFailed`]
    /// if MLS group creation fails.
    pub fn create_mls_group_with_context(
        &self,
        context_id: &[u8; 32],
        context_extension: &scp_protocol::context::ScpContextExtension,
    ) -> Result<(), ContextCreationError> {
        self.create_group_into_slot(context_id, |credential, wrapping_pk| {
            group::create_group_with_context(
                credential,
                wrapping_pk,
                context_extension,
                self.clock.as_ref(),
            )
        })
    }

    /// Shared core for [`Self::create_mls_group`] and
    /// [`Self::create_mls_group_with_context`].
    ///
    /// Atomically reserves the `contexts` slot for `context_id`, then builds the
    /// [`ScpMlsGroup`] via `build_group` *while holding the vacant guard* and
    /// installs a fresh [`ContextCryptoState`]. Holding the guard across the
    /// crypto-init preserves the overwrite-refusal invariant: two concurrent
    /// creates for the same id cannot both pass the existence check.
    fn create_group_into_slot<F>(
        &self,
        context_id: &[u8; 32],
        build_group: F,
    ) -> Result<(), ContextCreationError>
    where
        F: FnOnce(&ScpCredential, &[u8; 32]) -> Result<ScpMlsGroup, scp_mls::MlsError>,
    {
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
        let mls_group = build_group(&credential, &wrapping_pk)
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

    /// Installs an already-joined `OpenMLS` group into the provider's live
    /// context store, keyed by `context_id` (ADR-049 Phase 2J,
    /// spawn-from-Welcome).
    ///
    /// This is the join-side counterpart of [`Self::create_mls_group`]: the
    /// creator BUILDS a fresh group in the provider, whereas a joiner has
    /// already produced its `ScpMlsGroup` by processing a received Welcome
    /// (through the fused `KeyPackageStoreActor::ConfirmConsume` → the
    /// `MlsBackend`'s consumed-init-key-backstopped `join_from_welcome`).
    /// The joined group is a self-contained value (it owns its own `OpenMLS`
    /// provider + signer), so installing it is a move into the `contexts`
    /// map plus a locally-generated sender key — exactly the shape the
    /// (test/feature-gated, now-dead — pending deletion in the FFI follow-on
    /// slice) single-slot join path produced.
    ///
    /// The joiner's OWN sender key is generated LOCALLY here (spec §9.16.1);
    /// it is NOT carried in the Welcome. Other members' sender keys arrive
    /// later on demand via the PULL protocol (§9.16.2): the joiner sends a
    /// `SenderKeyRequest` — carrying a fresh EPHEMERAL wrapping key — to each
    /// incumbent, whose `handle_sender_key_request` seals its sender key to
    /// that ephemeral key. So `sender_key_store` and `recv_sequence_tracker`
    /// start empty — the same initial shape a fresh join produces.
    ///
    /// `member_wrapping_keys` also starts empty and, for a joiner, STAYS empty:
    /// it caches other members' STABLE wrapping keys, which are used ONLY by the
    /// proactive/offline PUSH path (`distribute_sender_key` / `rotate_sender_key`,
    /// §9.16.1) and are populated on the incumbent/adder side from the added
    /// `KeyPackage`'s leaf (`add_member_from_bytes`). openmls 0.8.1 exposes no
    /// public way to read a remote member's `scp_wrapping_key` `LeafNode` extension
    /// from a joined group (ADR-057; see `scp_mls::wrapping_extension`), so a
    /// joiner cannot learn incumbents' stable keys — but it does not need them:
    /// it reaches every incumbent through the pull protocol above, and answers
    /// incumbents' pulls via the ephemeral key in their requests.
    ///
    /// # Refuses to overwrite a live group
    ///
    /// Like [`Self::create_mls_group`], this reserves the `DashMap` slot with
    /// a `Vacant` guard and returns [`ContextError::CreationFailed`] rather
    /// than clobbering an existing entry — a second spawn-from-Welcome for the
    /// same context id must not silently replace a live group with divergent
    /// keys. The supervisor serializes same-id bootstraps, but this is the
    /// crypto layer's own defense-in-depth invariant.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CreationFailed`] if a group is already
    /// registered for `context_id`.
    pub fn install_joined_group(
        &self,
        context_id: &[u8; 32],
        group: ScpMlsGroup,
    ) -> Result<(), ContextError> {
        use dashmap::mapref::entry::Entry;

        // Atomic check-and-occupy on the shard: two concurrent installs for
        // the same id cannot both pass the existence check.
        let Entry::Vacant(slot) = self.contexts.entry(*context_id) else {
            return Err(ContextError::CreationFailed(format!(
                "MLS group already exists for context '{}' — refusing to overwrite a live \
                 group on spawn-from-Welcome",
                hex::encode(context_id)
            )));
        };

        let state = ContextCryptoState {
            mls_group: group,
            // The joiner's own AES-256 sender key (spec §9.16.1), minted
            // locally — the Welcome carries no sender key. Epoch starts at 1,
            // matching a fresh create / join.
            sender_key: generate_sender_key(),
            sender_key_store: SenderKeyStore::new(),
            sender_key_epoch: 1,
            send_sequence: 0,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys: HashMap::new(),
            recv_sequence_tracker: HashMap::new(),
        };

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
        let provider = scp_mls::InMemoryMlsProvider::default();
        let verified = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| ContextError::InvalidKeyPackage(format!("validation failed: {e}")))?;

        // SECURITY (ADR-057 §Prereq-1): openmls's `validate` above runs its own
        // internal `Lifetime::is_valid` against openmls's (wasm: unhardened)
        // clock. This eager join gate is the accept-family sibling of
        // `ProductionMlsBackend::validate_key_package` — re-validate the accepted
        // `Lifetime` against the injected hardened clock and enforce the RFC 9420
        // max-range bound openmls's `validate` never applies. Additive hardening;
        // never replaces openmls.
        validate_key_package_lifetime(verified.life_time(), self.clock.as_ref()).map_err(|e| {
            ContextError::InvalidKeyPackage(format!("key package lifetime invalid: {e}"))
        })?;

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
    /// Returns an [`AddMemberOutput`](scp_protocol::context::builder::AddMemberOutput)
    /// containing the TLS-serialized MLS Welcome (for the joiner) and Commit
    /// (for existing members). Non-MLS providers return
    /// `AddMemberOutput::default()` (empty bytes).
    ///
    /// # Arguments
    ///
    /// * `context_id` - The 32-byte context identifier.
    /// * `member_did` - The DID of the member to add.
    /// * `key_package_bytes` - Optional TLS-serialized MLS `KeyPackage` bytes.
    ///   The governance `AddMember` path carries the invitee's reserved
    ///   `KeyPackage` on the actor command envelope and passes it here as
    ///   `Some(..)`. With `None` (no `KeyPackage`), mock providers
    ///   (`cfg(test)`/`testing`) return an empty output and production returns
    ///   an error.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS operation fails or no
    /// `KeyPackage` is available in production.
    pub fn add_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        // The invitee's KeyPackage is supplied explicitly (the governance
        // `AddMember` path carries it on the actor command envelope).
        if let Some(bytes) = key_package_bytes {
            return self.add_member_from_bytes(context_id, member_did, bytes);
        }

        // No KeyPackage. Under the `testing` feature or `cfg(test)`, `None`
        // key-package bytes were previously handled by the no-op `MockCrypto`
        // fixture (deleted in ADR-049 commit 12c.9e). Preserve the
        // mock-equivalent return so integration tests that don't produce real
        // MLS key packages continue to exercise the non-crypto pipeline — role
        // state sync, event logging, governance side effects.
        if cfg!(any(test, feature = "testing")) {
            let _ = member_did; // used only by the real path
            return Ok(scp_protocol::context::builder::AddMemberOutput::default());
        }
        Err(ContextError::CryptoFailed(
            "production MlsCryptoProvider requires MLS key package bytes for add_member \
             (none supplied for this member)"
                .to_string(),
        ))
    }

    /// Real MLS add-member from explicit `KeyPackage` bytes. Shared by the
    /// explicit-KP and staged-KP resolution paths of [`Self::add_member`].
    fn add_member_from_bytes(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
        bytes: &[u8],
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        use tls_codec::Serialize as TlsSerializeTrait;

        // Pre-validate the key package to extract the wrapping key before
        // the add operation consumes it. Key package bytes arrive as TLS-
        // serialized KeyPackageIn (not MlsMessageIn).
        let wrapping_key = {
            KeyPackageIn::tls_deserialize(&mut &*bytes)
                .ok()
                .and_then(|kp_in| {
                    let provider_tmp = scp_mls::InMemoryMlsProvider::default();
                    kp_in
                        .validate(provider_tmp.crypto(), ProtocolVersion::Mls10)
                        .ok()
                        .and_then(|verified| {
                            scp_mls::wrapping_extension::extract_wrapping_key(
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
        // ADR-057 §Prereq-1: bound before the closure so the hardened clock ref
        // is captured by the closure without re-borrowing `self` inside it.
        let clock = self.clock.as_ref();
        self.with_context(context_id, |state| {
            let result = group::add_member(&mut state.mls_group, kp_in, clock)
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
                .map_err(|e: scp_mls::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

            let own_index = state
                .mls_group
                .own_leaf_index()
                .map_err(|e: scp_mls::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

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

            let sealed: [u8; 48] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
                ContextError::CryptoFailed(format!(
                    "HPKE seal produced {} bytes, expected 48",
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
                    let sealed: [u8; 48] = match sealed_vec.try_into() {
                        Ok(s) => s,
                        Err(v) => {
                            tracing::warn!(
                                member_did = %member_did,
                                "HPKE seal produced {} bytes, expected 48 — skipping",
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

    /// Stores a member's sender key recovered from a PULL response (§9.16.2).
    ///
    /// This is the store half of pull-response ingest — the requester-side
    /// counterpart to the push path's [`Self::process_incoming_sender_key`].
    /// After this node issues a `SenderKeyRequest` and the sender answers via
    /// [`Self::handle_sender_key_request`], the requester opens the HPKE-sealed
    /// response with the EPHEMERAL wrapping secret it generated for the request
    /// (via `key_protocol::open_sender_key_response`, which verifies the RFC 9180
    /// AEAD tag and the context/sender/epoch binding) and lands the authenticated
    /// key here. The key is therefore never injected blind: it is only reachable
    /// by presenting a response that opens under the requester's own ephemeral
    /// secret.
    ///
    /// Applies the SAME epoch monotonicity (`set_checked`) and epoch-poisoning
    /// (`MAX_EPOCH_ADVANCE`) defenses as the push path (§9.16.1, §9.16.5), so a
    /// stale or artificially-inflated epoch cannot rewind or wedge the store.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if no group is registered for
    /// `context_id`, if `epoch` exceeds `current_epoch + MAX_EPOCH_ADVANCE`
    /// (epoch poisoning), or if the monotonicity check rejects a rewind.
    pub fn store_member_sender_key(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        sender_key: SenderKey,
        epoch: u64,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        let mut entry = self.contexts.get_mut(context_id).ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let state = entry.value_mut();

        // Epoch poisoning defense (mirrors `process_incoming_sender_key`):
        // reject a claimed epoch unreasonably far above the current one so an
        // attacker cannot set epoch=u64::MAX to permanently block future
        // rotations via the monotonicity check.
        let current_epoch = state.sender_key_store.epoch(&ctx_id_hex, sender_did);
        if epoch > current_epoch.saturating_add(MAX_EPOCH_ADVANCE) {
            return Err(ContextError::CryptoFailed(
                "epoch poisoning: claimed epoch exceeds acceptable advance".into(),
            ));
        }
        state
            .sender_key_store
            .set_checked(&ctx_id_hex, sender_did, sender_key, epoch)
            .map_err(|e| ContextError::CryptoFailed(format!("epoch check failed: {e}")))?;
        Ok(())
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

        // ADR-057 §Prereq-1: committer-assigned timestamp from the injected
        // hardened clock, not a fresh un-injected `SystemClock`.
        let now_secs = self.clock.now_secs();

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

        // H1: Membership check — requester must be a CURRENT MLS group member,
        // per spec §9.16.6 Mitigation 1 ("handle_sender_key_request MUST verify
        // that the requester's DID is a current member of the context").
        //
        // Membership is read authoritatively from the MLS group tree — the same
        // DID-match over `members()` that `remove_member` uses — NOT from
        // `member_wrapping_keys`. That map only records members whose STABLE
        // wrapping key this node happens to have cached (populated on the
        // incumbent/adder side in `add_member_from_bytes`, from the added
        // `KeyPackage`'s own leaf). A Welcome-joiner's map starts empty
        // (`install_joined_group`), so gating on it would make the joiner reject
        // every incumbent's key request and be permanently RECEIVE-ONLY. The
        // pull protocol (§9.16.2) seals the response to the fresh EPHEMERAL
        // `request.wrapping_pubkey` carried in the request, so the responder
        // never needs the requester's stable key to answer — only proof that the
        // requester is a member, which the group tree provides directly.
        let members = state
            .mls_group
            .members()
            .map_err(|e: scp_mls::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;
        let mut requester_is_member = false;
        for member in &members {
            if let Ok(basic_cred) = BasicCredential::try_from(member.credential.clone())
                && let Ok(scp_cred) = ScpCredential::from_bytes(basic_cred.identity())
                && scp_cred.did == request.requester_did
            {
                requester_is_member = true;
                break;
            }
        }
        if !requester_is_member {
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

        let sealed: [u8; 48] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
            ContextError::CryptoFailed(format!("HPKE seal produced {} bytes, expected 48", v.len()))
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
            // The sender-layer AEAD AAD MUST bind the RAW `context_id` string
            // (UTF-8, 4-byte BE length prefix) per spec §9.16.1 + §9.5.1 — not
            // the hex encoding of its 32-byte hash. Binding anything else here
            // breaks cross-implementation interop and the
            // spec contract. The raw string is carried on the inner envelope.
            let ctx_str = inner.context_id.as_str();

            // Defense in depth: the supplied 32-byte `context_id` MUST be the
            // canonical digest of the inner envelope's `context_id` string —
            // i.e. `context_id_to_bytes(ctx_str)` (ADR-056): the raw
            // hex-decoded digest for a real 64-hex id, or `SHA-256(ctx_str)`
            // for a synthetic / non-context string. If they diverge, the AAD
            // would bind a string unrelated to the routing / store keying, so
            // fail closed rather than emit an unverifiable ciphertext. (No
            // panic/unwrap — clippy denies them on this path.)
            if crate::context::state::context_id_to_bytes(ctx_str) != *context_id {
                return Err(ContextError::CryptoFailed(
                    "inner envelope context_id does not resolve to the supplied context_id".into(),
                ));
            }

            // 1. Serialize inner envelope to MessagePack.
            let serialized = rmp_serde::to_vec_named(inner).map_err(|e| {
                ContextError::CryptoFailed(format!("inner envelope serialization: {e}"))
            })?;

            // 2. Sender key encrypt (AES-256-GCM, ADR-007).
            // AAD binds context_id, sender_did, epoch, and sequence to prevent
            // ciphertext relocation. Binds the RAW context_id string per
            // §9.16.1 so the receive side can reconstruct it.
            let sender_encrypted =
                scp_protocol::crypto::sender_keys::encrypt::encrypt_sender_layer(
                    &state.sender_key,
                    &serialized,
                    ctx_str,
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
            let mls_message = scp_mls::encrypt::encrypt(&mut state.mls_group, &with_header)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let encrypted_blob = scp_mls::encrypt::serialize_ciphertext(&mls_message)
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
        context_id_str: &str,
        outer_bytes: &[u8],
    ) -> Result<scp_protocol::context::builder::OpenResult, ContextError> {
        // ADR-057 §Prereq-1: bound before the closure so the hardened clock ref
        // (used to re-validate an add-Commit's KeyPackage `Lifetime`) is captured
        // without re-borrowing `self` inside it.
        let clock = self.clock.as_ref();
        self.with_context(context_id, |state| {
            // Defense in depth (symmetry with `seal`): the supplied 32-byte
            // `context_id` MUST be the canonical digest of `context_id_str` —
            // `context_id_to_bytes(context_id_str)` (ADR-056): the raw
            // hex-decoded digest for a real 64-hex id, or `SHA-256` for a
            // synthetic / non-context string. If they diverge, the AAD
            // reconstructed below from `context_id_str` would bind a string
            // unrelated to the routing / store keying, so fail fast here rather
            // than relying on the AEAD layer to reject it. Unreachable from
            // current callers (both are derived from one string) but cheap
            // fail-closed insurance. (No panic/unwrap — clippy denies them on
            // this path.)
            if crate::context::state::context_id_to_bytes(context_id_str) != *context_id {
                return Err(ContextError::CryptoFailed(
                    "context_id_str does not resolve to the supplied context_id".into(),
                ));
            }

            // Hex of the 32-byte id — the LOCAL sender-key store key (matches
            // every other store call site). NOT the AAD value.
            let ctx_id_hex = hex::encode(context_id);

            // The sender-layer AEAD AAD binds the RAW `context_id_str`
            // (§9.16.1), not this hex. The two are reconciled on the Application
            // path below: a `context_id_str` that does not hash to
            // `context_id` would bind an AAD no legitimate sealer produced, so
            // AEAD verification fails closed. Control/Management messages never
            // reach the sender-layer AEAD, so they are unaffected by the value
            // of `context_id_str`.

            // Step 0: Deserialize outer envelope to extract MLS ciphertext.
            let outer: scp_protocol::envelope::outer::OuterEnvelope =
                rmp_serde::from_slice(outer_bytes).map_err(|e| {
                    ContextError::CryptoFailed(format!("outer envelope deserialization: {e}"))
                })?;

            // Step 1: MLS decrypt and extract sender DID from credential.
            let content =
                decrypt_with_sender_did(&mut state.mls_group, &outer.encrypted_blob, clock)
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
                        .get(&ctx_id_hex, &sender_did)
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
                    // The AAD binds the RAW context_id string per §9.16.1 (NOT
                    // the hex store key), matching the `seal` encode path.
                    let decrypted = scp_protocol::crypto::sender_keys::decrypt_sender_layer(
                        &sender_key,
                        sender_ciphertext,
                        context_id_str,
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
                    let stored_high_water = state.sender_key_store.epoch(&ctx_id_hex, &sender_did);
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
                            // ADR-049 PR-4: surface the just-advanced receive
                            // floor (recorded into `recv_sequence_tracker`
                            // above) for the supervisor-registry follower
                            // mirror-forward. Read-only export of a value
                            // already computed + stored; does not alter
                            // enforcement.
                            receive_floor: scp_protocol::context::builder::ReceiveFloor {
                                epoch,
                                sequence,
                            },
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
            let mls_message = scp_mls::encrypt::encrypt(&mut state.mls_group, &tagged)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
            let encrypted_blob = scp_mls::encrypt::serialize_ciphertext(&mls_message)
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
            let commit = scp_mls::ratchet::propose_update_with_wrapping_key(
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
        // One-shot test seam (see `force_export_failure`): induce an export
        // failure so the spawn-from-Welcome crypto-durability fail-closed branch
        // can be driven end-to-end. `swap(false)` fires exactly once, then the
        // flag is cleared so subsequent (post-rollback) reads behave normally.
        #[cfg(any(test, feature = "testing"))]
        if self
            .force_export_failure
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ContextError::CryptoFailed(
                "forced export failure (one-shot test seam)".to_owned(),
            ));
        }

        // ADR-049 commit 12c.9f: lock-free `DashMap::get`. Holds the
        // per-shard read guard for the duration of snapshot
        // construction; no other writer can mutate this entry while
        // the guard is alive.
        let Some(entry) = self.contexts.get(context_id) else {
            return Ok(Vec::new());
        };
        let state = entry.value();

        // Extract the MLS group and signer, both required for restore.
        // Reads go through `scp_mls::ScpMlsGroup`'s public snapshot accessors
        // (ADR-057): the group's internal fields live in another crate now.
        let group = state
            .mls_group
            .inner()
            .map_err(|_| ContextError::CryptoFailed("MLS group destroyed".to_string()))?;

        let signer = state
            .mls_group
            .signer_key_pair()
            .map_err(|_| ContextError::CryptoFailed("MLS signer destroyed".to_string()))?;

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
                .provider()
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
        // memory. Delegates to the shared `zeroize_secrets` helper (single source
        // of truth for which fields are secret; the `Drop` impl is the backstop).
        // The serialized blob is the caller's responsibility (Storage layer must
        // encrypt at rest per §17.5).
        snapshot.zeroize_secrets();

        result
    }

    /// Test-only snapshot of the provider's identity-level X25519 wrapping
    /// keypair (§9.16.1): `(public, secret)`. Lets the full-stack harness
    /// publish the provider's OWN self-consistent keypair into the joiner's
    /// `Supervisor::set_wrapping_keys` slot so the pooled `KeyPackage`'s `0xFF01`
    /// wrapping-leaf pubkey and the secret this provider opens sender keys with
    /// stay the SAME keypair across the reserve → `spawn_actor_from_welcome` join
    /// migration. The wrapping SECRET never leaves the provider in a prod build.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn wrapping_keypair_snapshot(&self) -> ([u8; 32], zeroize::Zeroizing<[u8; 32]>) {
        let public = **self.wrapping_public_key.load();
        let secret = zeroize::Zeroizing::new(***self.wrapping_secret_key.load());
        (public, secret)
    }

    /// Restores per-context cryptographic state from a previously exported
    /// byte blob (produced by [`export_crypto_state`](Self::export_crypto_state)).
    ///
    /// Called during `Supervisor::restore_context` to reinstate MLS
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
        let provider = scp_mls::InMemoryMlsProvider::default();
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

        // Rebuild the live group via `scp_mls::ScpMlsGroup`'s public restore
        // constructor (the struct's fields are in another crate now; ADR-057).
        let scp_group = ScpMlsGroup::from_parts(mls_group, provider, signer);

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

    /// Reads the `scp_context_params` (`0xFF02`) group-context extension
    /// committed into the resident MLS group for `context_id`, if the group
    /// carries one (spec §5.13.3, finding FFI-02).
    ///
    /// This is the load-time read path that lets the `scp-runtime` lifecycle
    /// layer verify a *rehydrated* group (import / restore / respawn) against
    /// the snapshot's declared context parameters via
    /// [`ScpContextExtension::verify_against`](scp_protocol::context::ScpContextExtension::verify_against),
    /// exactly as the Welcome-join path verifies the freshly-joined group
    /// before installing it. Read-only: it inspects the replicated
    /// `group_context` extensions (the same bytes every member's key schedule
    /// is bound to) and never mutates crypto state.
    ///
    /// Returns `Ok(None)` for a group with no `0xFF02` extension (e.g. a
    /// wrapping-key-only group — not an SCP context).
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] `"no MLS group for this context"` if no
    ///   group is resident for `context_id` (never created / evicted), or
    ///   `"context state owned by actor"` if the state was destructively moved.
    /// - [`ContextError::CryptoFailed`] if the `0xFF02` extension is present but
    ///   its payload fails canonical decoding.
    pub fn group_context_extension(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<scp_protocol::context::ScpContextExtension>, ContextError> {
        self.with_context(context_id, |state| {
            state
                .mls_group
                .group_context_extension()
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))
        })
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

    /// Returns the stored epoch high-water for a SINGLE `(context, sender_did)`
    /// pair — `0` when absent, matching `SenderKeyStore::epoch`.
    ///
    /// ADR-049 PR-4: the remote-sender-epoch follower mirror-forward reads this
    /// (O(1)) AFTER `process_incoming_sender_key` / `store_member_sender_key`
    /// have advanced the authoritative floor via `set_checked`, to forward the
    /// just-recorded value into the supervisor floor registry. It surfaces the
    /// value already computed inside those paths without an O(senders)
    /// `export_sender_key_epochs` clone (Decision-14 budget). `pub(crate)` — an
    /// internal follower read with no FFI surface.
    #[must_use]
    pub(crate) fn sender_key_epoch(&self, context_id: &[u8; 32], sender_did: &str) -> u64 {
        // ADR-049 commit 12c.9f: lock-free `DashMap::get`.
        let Some(entry) = self.contexts.get(context_id) else {
            return 0;
        };
        let ctx_id_hex = hex::encode(context_id);
        entry
            .value()
            .sender_key_store
            .epoch(&ctx_id_hex, sender_did)
    }

    /// Returns the LOCAL sender-key epoch scalar (`state.sender_key_epoch`) for
    /// `context_id` — `0` when the context has no crypto state.
    ///
    /// ADR-049 PR-4: the local-sender-epoch follower mirror-forward reads this
    /// (O(1)) AFTER `rotate_sender_key` increments the local epoch, and forwards
    /// it (keyed by [`Self::local_did`]) into the supervisor floor registry.
    /// `rotate_sender_key` stores the local key via `set_unchecked`, which does
    /// NOT populate the store's per-sender epoch map — so the authoritative
    /// local floor is this scalar, not `export_sender_key_epochs`. `pub(crate)`.
    #[must_use]
    pub(crate) fn local_sender_key_epoch(&self, context_id: &[u8; 32]) -> u64 {
        // ADR-049 commit 12c.9f: lock-free `DashMap::get`.
        self.contexts
            .get(context_id)
            .map_or(0, |entry| entry.value().sender_key_epoch)
    }

    /// Returns this provider's local member DID — the key under which the local
    /// sender's epoch is recorded in the floor registry. `pub(crate)` — internal
    /// follower read with no FFI surface.
    #[must_use]
    pub(crate) fn local_did(&self) -> &str {
        &self.local_did
    }

    /// Test-only: seed a per-sender epoch high-water floor directly into the
    /// live sender-key store, simulating a floor that advanced AFTER the last
    /// coalesced snapshot was persisted (the exact §23.17.2 Invariant 2
    /// scenario the respawn floor-guard must tolerate). Gated on the `testing`
    /// feature (and `test`) so it never compiles into any non-test build, and so
    /// a plain `cargo test` (without `--features testing`) — which excludes its
    /// sole caller, a fault-injection respawn test — does not see it as dead.
    #[cfg(all(test, feature = "testing"))]
    pub(crate) fn seed_sender_key_epoch_for_test(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        epoch: u64,
    ) {
        let ctx_id_hex = hex::encode(context_id);
        if let Some(mut entry) = self.contexts.get_mut(context_id) {
            entry.value_mut().sender_key_store.restore_epoch_high_water(
                &ctx_id_hex,
                sender_did,
                epoch,
            );
        }
    }

    /// Merges the per-sender epoch floors of the just-restored crypto state
    /// against the captured live `local_floors`, applying a max-merge so
    /// `max(local, restored)` is the effective floor for every sender (spec
    /// §23.17 Invariant 4, append-only dominance).
    ///
    /// Call this AFTER `restore_crypto_state`, passing the floors captured via
    /// `export_sender_key_epochs` **before** the destroy+restore cycle.
    ///
    /// `trusted_local` selects the spec §23.17.2 lower-bound policy:
    /// - `true` (Invariant 2 — restoring the node's OWN snapshot: crash
    ///   recovery / actor respawn / process restart): a restored floor BELOW
    ///   the live floor is the expected coalesce-lag case; max-merge and
    ///   PROCEED, never reject. Only an overshoot beyond `max_advance_per_sender`
    ///   is rejected.
    /// - `false` (Invariant 3 — importing an UNTRUSTED peer snapshot): reject
    ///   the entire merge if ANY restored floor regresses below its live floor
    ///   (snapshot-mediated replay guard), or overshoots
    ///   `local_floor + max_advance_per_sender` (epoch-poisoning guard).
    ///
    /// No state is mutated on failure (atomic, both paths).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::SnapshotFloorRegression`] on a regression
    /// (import path only) or a ceiling overshoot (both paths).
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
        trusted_local: bool,
    ) -> Result<(), ContextError> {
        // Cold-restart no-op (ADR-049 §9 / spec §23.17.2). This merge + its
        // overshoot ceiling are a WARM-PATH protection: they bound the snapshot
        // floors against the LIVE pre-crash floors. On a COLD process restart
        // (`restore_all_contexts` into a fresh provider) there are no live
        // floors — `local_floors` is empty — so there is nothing to merge
        // against and nothing to ceiling against; the snapshot's floors load
        // verbatim. This is NOT a security regression: a cold restart trusts the
        // at-rest snapshot exactly as much as it already must (same
        // at-rest-storage trust boundary; an attacker who can rewrite epoch
        // floors in the snapshot can rewrite anything else in it too). Class M
        // monotonicity (Invariant 2 max-merge, Invariant 4 append-only) still
        // holds on every WARM respawn, where this function runs with non-empty
        // live floors. The ceiling protects against a peer-influenced epoch
        // advance racing a warm respawn; it does not police the at-rest snapshot
        // a cold restart loads, and is not claimed to.
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

        // Step 2: build a temporary store seeded with the captured LIVE floors,
        // then merge the restored/imported floors against them. The merge
        // semantics depend on the trust origin of the snapshot (spec §23.17.2):
        //
        // - `trusted_local = true` (Invariant 2 — restoring the node's OWN
        //   snapshot: crash recovery / actor respawn / process restart): a
        //   lower restored floor is the expected coalesce-lag case (an epoch
        //   advanced in the ≤50ms window before the crash, ADR-049 §9). MAX-
        //   merge and PROCEED — never reject a regression (rejecting would fail
        //   the respawn and poison a healthy context). Only the overshoot
        //   (epoch-poisoning) ceiling is enforced.
        // - `trusted_local = false` (Invariant 3 — importing an UNTRUSTED peer
        //   snapshot): reject the entire merge if ANY restored floor regresses
        //   below the live floor (snapshot-mediated replay guard), or overshoots
        //   local + max_advance.
        //
        // Either way the merged floor is `max(live, restored)` per sender and is
        // NEVER below the live floor (Invariant 4 append-only dominance).
        let mut temp_store = SenderKeyStore::new();
        for (did, floor) in &local_floors {
            temp_store.restore_epoch_high_water(&ctx_id_hex, did, *floor);
        }
        let policy = if trusted_local {
            scp_protocol::crypto::sender_keys::MergePolicy::MaxMergeTrustedLocal
        } else {
            scp_protocol::crypto::sender_keys::MergePolicy::RejectRegression
        };
        let merge_result = temp_store.merge_incoming_epochs(
            &ctx_id_hex,
            import_floors,
            max_advance_per_sender,
            policy,
        );
        merge_result.map_err(|per_sender_deltas| ContextError::SnapshotFloorRegression {
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

    /// Returns the per-sender receive-side sequence floors for a given context.
    ///
    /// Each `(sender_did, (last_epoch, last_sequence))` pair is the highest
    /// `(epoch, sequence)` accepted from that participant — the intra-epoch
    /// anti-replay floor (spec §23.17.3). The floor order is LEXICOGRAPHIC on
    /// `(epoch, sequence)`: a higher epoch dominates; at an equal epoch a higher
    /// sequence dominates (`(u64, u64)` derives this ordering).
    ///
    /// This is the receive-side twin of [`Self::export_sender_key_epochs`]. It
    /// is called by `restore_crypto_state_with_floor_guard` to capture the LIVE
    /// floors **before** destroying existing crypto state so the incoming
    /// snapshot can be validated/merged against them. A mailbox/handle despawn
    /// does NOT tear down the supervisor-owned crypto provider, so these live
    /// pre-crash floors are still authoritative on a warm respawn.
    ///
    /// Returns an empty `Vec` when the context has no crypto state (never
    /// created / evicted / owned by an actor) — the cold-restart case, where
    /// there is nothing to merge against.
    pub fn export_recv_sequence_floors(&self, context_id: &[u8; 32]) -> Vec<(String, (u64, u64))> {
        // ADR-049 commit 12c.9f: lock-free `DashMap::get`.
        let Some(entry) = self.contexts.get(context_id) else {
            return Vec::new();
        };
        entry
            .value()
            .recv_sequence_tracker
            .iter()
            .map(|(did, floor)| (did.clone(), *floor))
            .collect()
    }

    /// Merges the per-sender receive-side sequence floors of the just-restored
    /// crypto state against the captured live `local_floors`, applying a
    /// max-merge so `max(local, restored)` is the effective floor for every
    /// sender (spec §23.17.3; Invariant 2 `max(snapshot, retained)` / Invariant
    /// 4 append-only dominance — "Gaps are bugs"). This is the receive-side twin
    /// of [`Self::validate_and_merge_epoch_floors`]: the sender-key EPOCH
    /// high-water is already max-merged there; the `recv_sequence_tracker` is
    /// the missing twin that a warm respawn would otherwise reload VERBATIM from
    /// the ≤50ms-stale coalesced snapshot, rolling an intra-epoch replay floor
    /// BACKWARD (ADR-049 §9 Class M).
    ///
    /// Call this AFTER `restore_crypto_state`, passing the floors captured via
    /// [`Self::export_recv_sequence_floors`] **before** the destroy+restore
    /// cycle.
    ///
    /// The per-sender floor order is LEXICOGRAPHIC on `(epoch, sequence)`: a
    /// higher epoch wins; at an equal epoch a higher sequence wins.
    ///
    /// `trusted_local` selects the spec §23.17.2 lower-bound policy:
    /// - `true` (Invariant 2 — restoring the node's OWN snapshot: crash
    ///   recovery / actor respawn / process restart): a restored floor BELOW the
    ///   live floor is the expected coalesce-lag case; max-merge and PROCEED,
    ///   never reject (rejecting would fail the respawn and poison a healthy
    ///   context).
    /// - `false` (Invariant 3 — importing an UNTRUSTED peer snapshot): reject
    ///   the entire merge if ANY restored floor regresses below its live floor
    ///   (snapshot-mediated replay guard), OR if any imported recv floor's epoch
    ///   overshoots the sender's already-merged sender-key epoch floor by more
    ///   than `MAX_EPOCH_ADVANCE` (epoch-poisoning guard — mirrors the epoch
    ///   twin, so a malicious exporter cannot set a third party's recv floor to
    ///   `epoch = u64::MAX` and permanently lock that sender out).
    ///
    /// Either way the applied floor is `max(live, restored)` per sender and is
    /// NEVER below the live floor (Invariant 4). Local-only senders absent from
    /// the snapshot retain their live floor; senders present only in the
    /// snapshot keep their imported floor.
    ///
    /// A cold-restart no-op when `local_floors` is empty (same rationale as
    /// [`Self::validate_and_merge_epoch_floors`]: no live floors to merge or
    /// regress against; the snapshot loads verbatim under the same
    /// at-rest-storage trust boundary).
    ///
    /// No state is mutated on failure (atomic, both paths).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::SnapshotFloorRegression`] with
    /// `resource: "recv_sequence"` on the import path only. Each
    /// `per_sender_deltas` entry reports either the counter that rolled back
    /// (`(local_epoch, incoming_epoch)` when the epoch regressed, else
    /// `(local_sequence, incoming_sequence)` at an equal epoch) or, for an
    /// overshoot, `(ceiling, incoming_epoch)` where `ceiling` is the enforced
    /// `sender_key_epoch + MAX_EPOCH_ADVANCE` bound.
    // Parameter type `Vec<(String, (u64, u64))>` mirrors the by-value ownership
    // convention of `validate_and_merge_epoch_floors` (captured live floors are
    // consumed into the merge).
    #[allow(clippy::needless_pass_by_value)]
    pub fn validate_and_merge_recv_sequence_floors(
        &self,
        context_id: &[u8; 32],
        local_floors: Vec<(String, (u64, u64))>,
        trusted_local: bool,
    ) -> Result<(), ContextError> {
        // Cold-restart no-op (spec §23.17.2 / ADR-049 §9): with no captured live
        // floors there is nothing to merge or regress against, so the snapshot's
        // floors load verbatim. Class M monotonicity still holds on every WARM
        // respawn, where this runs with non-empty live floors.
        if local_floors.is_empty() {
            return Ok(());
        }

        // Step 1: read the imported (restored) recv-sequence floors. In the real
        // flow `restore_crypto_state` has already written these from the snapshot
        // bytes into the live `recv_sequence_tracker`.
        // ADR-049 commit 12c.9f: lock-free `DashMap::get`.
        let import_floors: HashMap<String, (u64, u64)> = self
            .contexts
            .get(context_id)
            .map_or_else(HashMap::new, |entry| {
                entry.value().recv_sequence_tracker.clone()
            });

        // Step 2: validate the UNTRUSTED import path (two guards, mirroring the
        // sender-key epoch twin `validate_and_merge_epoch_floors` /
        // `SenderKeyStore::merge_incoming_epochs`). The TRUSTED-LOCAL respawn
        // path gets NEITHER — a lower restored floor is the expected coalesce-lag
        // case (Invariant 2) and a healthy respawn must never be rejected.
        //
        // 2a. Regression guard (Invariant 3, replay): a restored floor
        //     lexicographically below the captured live floor for a sender
        //     present in BOTH is a snapshot-mediated replay vector. `(u64, u64)`
        //     compares lexicographically, so `<` is exactly the
        //     `(epoch, sequence)` floor order.
        //
        // 2b. Epoch-poisoning overshoot ceiling (mirrors the epoch twin's
        //     `MAX_EPOCH_ADVANCE` bound): an imported recv floor whose epoch
        //     exceeds the sender's ALREADY-MERGED sender-key epoch floor by more
        //     than `MAX_EPOCH_ADVANCE` is rejected, so a signature-valid but
        //     malicious/compromised exporter cannot set a third party's recv
        //     floor to `epoch = u64::MAX` and permanently lock that sender out.
        //     The bound is keyed off `sender_key_store.epoch(ctx, did)` — the
        //     epoch floor `validate_and_merge_epoch_floors` (which runs BEFORE
        //     this merge in `restore_crypto_state_with_floor_guard`) has already
        //     max-merged and validated. Keying off THAT (a) covers senders
        //     present only in the import (no live recv floor to bound against),
        //     and (b) avoids false-positives on legitimate imports (a real recv
        //     floor tracks the real sender-key epoch). `saturating_add` clamps
        //     the bound at `u64::MAX`.
        if !trusted_local {
            let ctx_id_hex = hex::encode(context_id);
            let mut per_sender_deltas: Vec<(String, u64, u64)> = Vec::new();

            // 2a. Regression: senders present in both live and import.
            for (did, live_floor) in &local_floors {
                if let Some(import_floor) = import_floors.get(did)
                    && import_floor < live_floor
                {
                    // Report whichever counter rolled back: the epoch if the
                    // epoch regressed, else the sequence (equal-epoch case).
                    let (local_scalar, incoming_scalar) = if import_floor.0 < live_floor.0 {
                        (live_floor.0, import_floor.0)
                    } else {
                        (live_floor.1, import_floor.1)
                    };
                    per_sender_deltas.push((did.clone(), local_scalar, incoming_scalar));
                }
            }

            // 2b. Overshoot ceiling: every imported recv floor (including
            // import-only senders) bounded against the merged sender-key epoch
            // floor + MAX_EPOCH_ADVANCE. One read-lock across the loop.
            //
            // NOTE: only the EPOCH axis is bounded here; the sequence axis is a
            // deliberate, documented residual (#2076). No sound
            // `MAX_SEQUENCE_ADVANCE` exists — there is no per-`(sender, epoch)`
            // sequence high-water oracle (unlike `sender_key_store.epoch` for the
            // epoch axis), so any constant would either false-positive legitimate
            // high-volume catch-up imports or stop nothing; and spec §23.17.2
            // Invariant 3 mandates accepting a floor `>= local` via max-merge. The
            // residual — an untrusted import (creator-signed; `exporter_did ==
            // creator_did`) setting `(valid_epoch, u64::MAX)` to silence a sender
            // for the CURRENT epoch — is LOW: creator-gated, append-only-safe (a
            // DoS, not a replay hole), and self-heals on the next sender-key
            // rotation. See #2076.
            if let Some(entry) = self.contexts.get(context_id) {
                let store = &entry.value().sender_key_store;
                for (did, (imp_epoch, _imp_seq)) in &import_floors {
                    let ceiling = store
                        .epoch(&ctx_id_hex, did)
                        .saturating_add(MAX_EPOCH_ADVANCE);
                    if *imp_epoch > ceiling {
                        // local = the ceiling (bound), incoming = the overshoot.
                        per_sender_deltas.push((did.clone(), ceiling, *imp_epoch));
                    }
                }
            }

            if !per_sender_deltas.is_empty() {
                return Err(ContextError::SnapshotFloorRegression {
                    resource: "recv_sequence".to_owned(),
                    per_sender_deltas,
                });
            }
        }

        // Step 3: apply `max(live, restored)` per sender back into the real
        // tracker. A sender in `local_floors` but absent from the import snapshot
        // retains its live floor (Invariant 4 append-only dominance); a sender
        // present only in the import snapshot keeps its imported floor (untouched
        // here). Lexicographic `max` on `(u64, u64)`.
        // ADR-049 commit 12c.9f: lock-free `DashMap::get_mut`.
        if let Some(mut entry) = self.contexts.get_mut(context_id) {
            let tracker = &mut entry.value_mut().recv_sequence_tracker;
            for (did, live_floor) in local_floors {
                let merged = tracker
                    .get(&did)
                    .map_or(live_floor, |restored| (*restored).max(live_floor));
                tracker.insert(did, merged);
            }
        }

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
    use scp_clock::SystemClock;
    use scp_mls::encrypt::{encrypt, serialize_ciphertext};
    use scp_mls::group::generate_key_package;
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
        MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock))
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
        let provider =
            MlsCryptoProvider::new("invalid:format:whatever".to_string(), Arc::new(SystemClock));
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
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();

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
    fn validate_key_package_rejects_expired_lifetime_at_gate() {
        use scp_clock::TestClock;
        use scp_mls::KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS;

        // Security intent (ADR-057 §Prereq-1): the eager join gate
        // `validate_key_package` must re-check the accepted KeyPackage
        // `Lifetime` against the provider's injected hardened clock — mirroring
        // its accept-family sibling `ProductionMlsBackend::validate_key_package`
        // — so a KeyPackage that is temporally invalid under the SCP clock is
        // rejected even though openmls's own internal `is_valid` (against the
        // real system clock) accepts it.

        // Bob's KeyPackage is minted at the REAL present via `SystemClock`, so
        // openmls's un-injectable internal validation (which reads the real
        // wall clock inside `kp_in.validate`) accepts it.
        let bob_cred = ScpCredential::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
            None,
            SigningKeyId::Active,
        )
        .unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();

        // Provider clock is pinned far past the KeyPackage's `not_after`
        // (`real_now + KEY_PACKAGE_LIFETIME_SECS`). One full max-range beyond the
        // present clears the ~3-month window with margin, so the SCP bracket's
        // `now < not_after` check fails.
        let future_now = SystemClock.now_secs() + KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS * 2;
        let provider =
            MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(TestClock::new(future_now)));

        let result = provider.validate_key_package(&bob_cred.did, Some(&kp_bytes));
        let err = result.expect_err(
            "validate_key_package must reject a KeyPackage whose lifetime is expired \
             under the injected clock",
        );
        assert!(
            matches!(err, ContextError::InvalidKeyPackage(ref m) if m.contains("lifetime")),
            "rejection must be at the lifetime gate, got: {err:?}"
        );

        // Positive control: with the provider clock at the real present, the
        // same KeyPackage passes the lifetime gate (and every other check),
        // proving the rejection above is caused by the injected clock offset —
        // not by an unrelated defect in the KeyPackage bytes.
        let live_provider = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        assert!(
            live_provider
                .validate_key_package(&bob_cred.did, Some(&kp_bytes))
                .is_ok(),
            "a freshly-minted KeyPackage must pass under a real-present clock"
        );
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
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
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
        let alice_provider = MlsCryptoProvider::new(alice_did.to_string(), Arc::new(SystemClock));
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        // Generate a key package for Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        // We need the Welcome message to let Bob join. Get it from the
        // underlying group directly.
        let add_result = {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in, &SystemClock).unwrap()
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
        let decrypted = scp_mls::encrypt::decrypt(&mut bob_group, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn forward_secrecy_after_epoch_advance() {
        // Alice creates a group.
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
        let alice_provider = MlsCryptoProvider::new(alice_did.to_string(), Arc::new(SystemClock));
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();

        let add_result = {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in, &SystemClock).unwrap()
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
        let decrypted = scp_mls::encrypt::decrypt(&mut bob_group, &ciphertext_epoch1).unwrap();
        assert_eq!(decrypted, b"epoch 1 message");

        // Add Carol to advance to epoch 2.
        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCar";
        let carol_cred =
            ScpCredential::new(carol_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (carol_kp_bundle, _carol_signer, _carol_provider) =
            generate_key_package(&carol_cred, &SystemClock).unwrap();

        {
            let mut entry = alice_provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
            let _add_result2 =
                group::add_member(&mut state.mls_group, kp_in, &SystemClock).unwrap();
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
        let provider = MlsCryptoProvider::new(alice_did.to_string(), Arc::new(SystemClock));
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // Add Bob.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, bob_signer, bob_provider_mls) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let add_bob_result = {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in, &SystemClock).unwrap()
        };

        let _bob_group =
            group::join_group(&add_bob_result.welcome, bob_provider_mls, bob_signer).unwrap();

        // Add Carol.
        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCar";
        let carol_cred =
            ScpCredential::new(carol_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (carol_kp_bundle, carol_signer, carol_provider_mls) =
            generate_key_package(&carol_cred, &SystemClock).unwrap();

        let add_carol_result = {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            let kp_in: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
            group::add_member(&mut state.mls_group, kp_in, &SystemClock).unwrap()
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
        let provider = MlsCryptoProvider::new(alice_did.to_string(), Arc::new(SystemClock));
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
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
            scp_mls::wrapping_extension::extract_own_wrapping_key(&state.mls_group).unwrap();
        assert_eq!(
            extracted,
            Some(**provider.wrapping_public_key.load()),
            "own leaf node must contain provider's wrapping public key"
        );
    }

    #[test]
    fn distribute_sender_key_hpke_seals_when_wrapping_key_available() {
        use scp_mls::group::generate_key_package_with_wrapping_key;

        let alice_provider = make_provider();
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_wrapping = [0xBB_u8; 32];
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping), &SystemClock)
                .unwrap();
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
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
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
        use scp_mls::group::generate_key_package_with_wrapping_key;

        let alice_provider = make_provider();
        let bob_provider = MlsCryptoProvider::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
            Arc::new(SystemClock),
        );
        let ctx_id = make_context_id();
        alice_provider.create_mls_group(&ctx_id).unwrap();
        bob_provider.create_mls_group(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";

        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let bob_wrapping_pk = **bob_provider.wrapping_public_key.load();
        let (bob_kp_bundle, _bob_signer, _bob_mls) =
            generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping_pk), &SystemClock)
                .unwrap();
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
            Arc::new(SystemClock),
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
        let sealed: [u8; 48] = sealed_vec.try_into().unwrap();

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
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));

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
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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
    fn validate_and_merge_epoch_floors_rejects_regression_on_import() {
        // §23.17 Invariant 3 (replay guard) — the UNTRUSTED IMPORT path
        // (`trusted_local = false`): an imported peer snapshot whose per-sender
        // epoch floor is BELOW the live floor must be rejected entirely, because
        // a peer-supplied stale floor is a snapshot-mediated replay vector. This
        // is the policy `import_context` / `PrepareForReplace` apply. NOTE: the
        // RESPAWN/restore path (`trusted_local = true`, Invariant 2) does NOT
        // reject here — see `validate_and_merge_epoch_floors_max_merges_on_restore`.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";
        let ctx_id_hex = hex::encode(ctx_id);

        // Live floor for Dave is epoch 12.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .sender_key_store
                .restore_epoch_high_water(&ctx_id_hex, dave_did, 12);
        }
        let live_floors = provider.export_sender_key_epochs(&ctx_id);
        assert!(
            live_floors.iter().any(|(d, e)| d == dave_did && *e == 12),
            "live floor for Dave must be epoch 12 before the regression check"
        );

        // The "restored" crypto now carries a LOWER floor (epoch 5) for Dave —
        // simulate a stale snapshot by lowering the store directly. (In the
        // real flow `restore_crypto_state` writes these from snapshot bytes;
        // here we exercise the validate/merge guard in isolation, passing the
        // captured live floors exactly as `restore_crypto_state_with_floor_guard`
        // does.)
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .sender_key_store
                .restore_epoch_high_water(&ctx_id_hex, dave_did, 5);
        }

        // IMPORT path (`trusted_local = false`): a regression is rejected.
        let err = provider
            .validate_and_merge_epoch_floors(&ctx_id, live_floors, MAX_EPOCH_ADVANCE, false)
            .expect_err("an import floor regression (5 < live 12) must be rejected");
        assert!(
            matches!(err, ContextError::SnapshotFloorRegression { .. }),
            "expected SnapshotFloorRegression, got {err:?}"
        );
    }

    #[test]
    fn validate_and_merge_epoch_floors_max_merges_on_restore() {
        // §23.17 Invariant 2 (own-snapshot restore) — the TRUSTED-LOCAL RESPAWN
        // path (`trusted_local = true`): a restored floor BELOW the live floor
        // is the EXPECTED coalesce-lag case (an epoch advanced in the ≤50ms
        // window before the crash, ADR-049 §9). It MUST max-merge and PROCEED —
        // NOT reject (rejecting would fail the respawn and poison a healthy
        // context: the round-2 HIGH bug this corrects). The merged floor is the
        // higher LIVE value (12), and no error is returned.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";
        let ctx_id_hex = hex::encode(ctx_id);

        // Live floor for Dave is epoch 12 (advanced just before the crash).
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .sender_key_store
                .restore_epoch_high_water(&ctx_id_hex, dave_did, 12);
        }
        let live_floors = provider.export_sender_key_epochs(&ctx_id);

        // The restored (coalesced) snapshot carries a LOWER floor (epoch 5) for
        // Dave — it predates the live epoch-12 advance.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .sender_key_store
                .restore_epoch_high_water(&ctx_id_hex, dave_did, 5);
        }

        // RESPAWN path (`trusted_local = true`): max-merge and proceed.
        provider
            .validate_and_merge_epoch_floors(&ctx_id, live_floors, MAX_EPOCH_ADVANCE, true)
            .expect(
                "a respawn from a coalesce-lagged snapshot must max-merge and proceed, not fail",
            );

        let merged = provider.export_sender_key_epochs(&ctx_id);
        assert!(
            merged.iter().any(|(d, e)| d == dave_did && *e == 12),
            "Dave's floor must be the higher LIVE value (12), never lowered to the stale snapshot's 5"
        );
    }

    #[test]
    fn validate_and_merge_epoch_floors_restore_rejects_overshoot() {
        // §23.17 Invariant 2 still enforces the epoch-poisoning overshoot
        // ceiling on the trusted-local path: a corrupt snapshot floor that
        // exceeds the live floor by more than `MAX_EPOCH_ADVANCE` is rejected
        // even on respawn, so a garbage snapshot cannot wedge a sender's
        // monotonicity guard at `epoch = u64::MAX`.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let gina_did = "did:dht:z6MkGinaGinaGinaGinaGinaGinaGinaGinaGinaGi";
        let ctx_id_hex = hex::encode(ctx_id);

        // Live floor for Gina is epoch 1.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .sender_key_store
                .restore_epoch_high_water(&ctx_id_hex, gina_did, 1);
        }
        let live_floors = provider.export_sender_key_epochs(&ctx_id);

        // Corrupt snapshot floor overshoots live (1) + MAX_EPOCH_ADVANCE.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry.value_mut().sender_key_store.restore_epoch_high_water(
                &ctx_id_hex,
                gina_did,
                1 + MAX_EPOCH_ADVANCE + 1,
            );
        }

        let err = provider
            .validate_and_merge_epoch_floors(&ctx_id, live_floors, MAX_EPOCH_ADVANCE, true)
            .expect_err("an overshoot beyond MAX_EPOCH_ADVANCE must be rejected even on restore");
        assert!(
            matches!(err, ContextError::SnapshotFloorRegression { .. }),
            "expected SnapshotFloorRegression on overshoot, got {err:?}"
        );
    }

    #[test]
    fn validate_and_merge_epoch_floors_empty_live_floors_is_noop_both_paths() {
        // Cryptographer Residual 1 (empty-floors bypass): when the captured
        // LIVE floors are empty — e.g. the crypto was destroyed on close /
        // migrate before the snapshot loaded — there is nothing to regress
        // against, so the guard is a no-op `Ok(())` on BOTH paths. This is NOT
        // a resurrection hazard: a closed/migrated context's snapshot.state is
        // terminal (close sync-persists the transition, ADR-049 §9), so the
        // respawn Active-only gate rejects it BEFORE the crypto restore runs
        // (`respawn_skips_terminal_snapshot`). The floor guard never has to be
        // the thing that stops a stale-Active resurrection; the lifecycle gate
        // does. This test pins the benign no-op so a future change that makes
        // empty-live-floors reject (and thus break legitimate first-restore of
        // a context with no prior live state) is caught.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        // Empty captured live floors → early Ok, regardless of trust origin.
        provider
            .validate_and_merge_epoch_floors(&ctx_id, Vec::new(), MAX_EPOCH_ADVANCE, true)
            .expect("empty live floors must be a no-op on the trusted-local restore path");
        provider
            .validate_and_merge_epoch_floors(&ctx_id, Vec::new(), MAX_EPOCH_ADVANCE, false)
            .expect("empty live floors must be a no-op on the untrusted import path");
    }

    #[test]
    fn validate_and_merge_epoch_floors_max_merges_non_regressing() {
        // The guard is not over-eager: when the restored floor is at or above
        // the live floor, it accepts and max-merges. A local-only sender
        // (absent from the restored set) retains its floor (Invariant 4).
        // Holds on BOTH paths; exercised here on the import path.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let erin_did = "did:dht:z6MkErinErinErinErinErinErinErinErinErinEr";
        let frank_did = "did:dht:z6MkFrankFrankFrankFrankFrankFrankFrankFr";
        let ctx_id_hex = hex::encode(ctx_id);

        // Live floors: Erin=4, Frank=7.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let store = &mut entry.value_mut().sender_key_store;
            store.restore_epoch_high_water(&ctx_id_hex, erin_did, 4);
            store.restore_epoch_high_water(&ctx_id_hex, frank_did, 7);
        }
        let live_floors = provider.export_sender_key_epochs(&ctx_id);

        // Restored set advances Erin to 9 and omits Frank entirely.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let store = &mut entry.value_mut().sender_key_store;
            store.restore_epoch_high_water(&ctx_id_hex, erin_did, 9);
            // Frank dropped from the restored snapshot.
        }

        provider
            .validate_and_merge_epoch_floors(&ctx_id, live_floors, MAX_EPOCH_ADVANCE, false)
            .expect("a non-regressing restore must be accepted and max-merged");

        let merged = provider.export_sender_key_epochs(&ctx_id);
        assert!(
            merged.iter().any(|(d, e)| d == erin_did && *e == 9),
            "Erin's floor must advance to the higher restored value (9)"
        );
        assert!(
            merged.iter().any(|(d, e)| d == frank_did && *e == 7),
            "Frank's local-only floor (7) must be retained (Invariant 4)"
        );
    }

    // ---- §23.17.3 receive-side sequence-floor twin -----------------------

    #[test]
    fn validate_and_merge_recv_sequence_floors_max_merges_on_restore() {
        // §23.17.3 Invariant 2 (own-snapshot restore) — the TRUSTED-LOCAL
        // RESPAWN path (`trusted_local = true`): when the captured LIVE recv
        // floor is AHEAD of the ≤50ms-stale coalesced snapshot, the merge MUST
        // keep the higher LIVE `(epoch, sequence)` and never lower it — a
        // rolled-back intra-epoch replay floor is the bug this corrects
        // (ADR-049 §9 Class M). The floor order is lexicographic on
        // `(epoch, sequence)`: a higher epoch dominates even a higher stale
        // sequence.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";

        // Live floor for Dave is (epoch 5, seq 20) — advanced just before crash.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (5, 20));
        }
        let live_floors = provider.export_recv_sequence_floors(&ctx_id);

        // The restored (coalesced) snapshot carries a LOWER epoch (3) for Dave,
        // even though its sequence (999) is higher — lexicographically stale.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (3, 999));
        }

        provider
            .validate_and_merge_recv_sequence_floors(&ctx_id, live_floors, true)
            .expect(
                "a respawn from a coalesce-lagged snapshot must max-merge and proceed, not fail",
            );

        let merged = provider.export_recv_sequence_floors(&ctx_id);
        assert!(
            merged.iter().any(|(d, f)| d == dave_did && *f == (5, 20)),
            "Dave's recv floor must stay the higher LIVE value (5, 20), never the stale (3, 999)"
        );
    }

    #[test]
    fn validate_and_merge_recv_sequence_floors_equal_epoch_keeps_higher_live_sequence() {
        // §23.17.3: at an EQUAL epoch the higher LIVE sequence must win. This is
        // the core intra-epoch anti-replay case: a stale snapshot at the same
        // epoch but a lower sequence must not roll the sequence floor back on a
        // trusted-local respawn.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";

        // Live floor: (epoch 7, seq 200).
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (7, 200));
        }
        let live_floors = provider.export_recv_sequence_floors(&ctx_id);

        // Stale snapshot: same epoch, lower sequence.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (7, 50));
        }

        provider
            .validate_and_merge_recv_sequence_floors(&ctx_id, live_floors, true)
            .expect("equal-epoch lower-sequence snapshot must max-merge and proceed");

        let merged = provider.export_recv_sequence_floors(&ctx_id);
        assert!(
            merged.iter().any(|(d, f)| d == dave_did && *f == (7, 200)),
            "Dave's recv floor must keep the higher LIVE sequence (7, 200), never (7, 50)"
        );
    }

    #[test]
    fn validate_and_merge_recv_sequence_floors_rejects_regression_on_import() {
        // §23.17.3 Invariant 3 (replay guard) — the UNTRUSTED IMPORT path
        // (`trusted_local = false`): an imported peer snapshot whose per-sender
        // recv floor is lexicographically BELOW the live floor must be rejected
        // entirely (snapshot-mediated replay vector). Mirrors the epoch-floor
        // import guard.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";

        // Live floor: (epoch 12, seq 100).
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (12, 100));
        }
        let live_floors = provider.export_recv_sequence_floors(&ctx_id);

        // Restored crypto carries a LOWER sequence (40) at the same epoch.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (12, 40));
        }

        let err = provider
            .validate_and_merge_recv_sequence_floors(&ctx_id, live_floors, false)
            .expect_err(
                "an import recv-floor regression ((12,40) < live (12,100)) must be rejected",
            );
        match err {
            ContextError::SnapshotFloorRegression {
                resource,
                per_sender_deltas,
            } => {
                assert_eq!(resource, "recv_sequence");
                assert!(
                    per_sender_deltas
                        .iter()
                        .any(|(d, local, incoming)| d == dave_did
                            && *local == 100
                            && *incoming == 40),
                    "delta must report the rolled-back sequence (local 100, incoming 40), got {per_sender_deltas:?}"
                );
            }
            other => panic!("expected SnapshotFloorRegression, got {other:?}"),
        }

        // The live floor must be untouched after a rejected import.
        let after = provider.export_recv_sequence_floors(&ctx_id);
        assert!(
            after.iter().any(|(d, f)| d == dave_did && *f == (12, 40)),
            "rejected import must not have merged; the tracker keeps whatever restore wrote"
        );
    }

    #[test]
    fn validate_and_merge_recv_sequence_floors_retains_local_only_sender() {
        // §23.17.3 Invariant 4 (append-only dominance): a sender present in the
        // captured LIVE floors but ABSENT from the restored snapshot must retain
        // its live floor, while a sender the snapshot advances is max-merged
        // upward. Exercised on the untrusted-import path (a non-regressing
        // advance is accepted).
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";
        let erin_did = "did:dht:z6MkErinErinErinErinErinErinErinErinErinEr";

        // Live floors: Dave=(4, 30), Erin=(7, 90).
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let tracker = &mut entry.value_mut().recv_sequence_tracker;
            tracker.insert(dave_did.to_owned(), (4, 30));
            tracker.insert(erin_did.to_owned(), (7, 90));
        }
        let live_floors = provider.export_recv_sequence_floors(&ctx_id);

        // Restored snapshot advances Dave to (9, 5) and omits Erin entirely.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let tracker = &mut entry.value_mut().recv_sequence_tracker;
            tracker.insert(dave_did.to_owned(), (9, 5));
            tracker.remove(erin_did);
        }

        provider
            .validate_and_merge_recv_sequence_floors(&ctx_id, live_floors, false)
            .expect("a non-regressing recv-floor restore must be accepted and max-merged");

        let merged = provider.export_recv_sequence_floors(&ctx_id);
        assert!(
            merged.iter().any(|(d, f)| d == dave_did && *f == (9, 5)),
            "Dave's floor must advance to the higher restored value (9, 5)"
        );
        assert!(
            merged.iter().any(|(d, f)| d == erin_did && *f == (7, 90)),
            "Erin's local-only floor (7, 90) must be retained (Invariant 4)"
        );
    }

    #[test]
    fn validate_and_merge_recv_sequence_floors_rejects_overshoot_on_import() {
        // §23.17.3 Invariant 3 (epoch-poisoning guard) — the UNTRUSTED IMPORT
        // path: an imported recv floor whose EPOCH overshoots the sender's
        // already-merged sender-key epoch floor by more than MAX_EPOCH_ADVANCE
        // must be rejected, so a signature-valid but malicious/compromised
        // exporter cannot pin a third party's recv floor at epoch = u64::MAX and
        // permanently lock that sender out. Mirrors the epoch twin's
        // `validate_and_merge_epoch_floors_restore_rejects_overshoot`. The bound
        // is keyed off `sender_key_store.epoch(ctx, did)` — the epoch floor the
        // epoch merge has already validated (it runs BEFORE this merge in
        // `restore_crypto_state_with_floor_guard`), which also covers senders
        // present only in the import.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";
        let ctx_id_hex = hex::encode(ctx_id);

        // Sender-key epoch floor for Dave is 1 (already max-merged by the epoch
        // twin). Live recv floor (1, 10) keeps `local_floors` non-empty (not the
        // cold-restart no-op).
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state
                .sender_key_store
                .restore_epoch_high_water(&ctx_id_hex, dave_did, 1);
            state
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (1, 10));
        }
        let live_floors = provider.export_recv_sequence_floors(&ctx_id);

        // Restore writes a recv floor whose epoch overshoots the ceiling
        // (sender_key_epoch 1 + MAX_EPOCH_ADVANCE).
        let overshoot_epoch = 1 + MAX_EPOCH_ADVANCE + 1;
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (overshoot_epoch, 5));
        }

        let err = provider
            .validate_and_merge_recv_sequence_floors(&ctx_id, live_floors, false)
            .expect_err("an imported recv epoch overshooting the ceiling must be rejected");
        match err {
            ContextError::SnapshotFloorRegression {
                resource,
                per_sender_deltas,
            } => {
                assert_eq!(resource, "recv_sequence");
                assert!(
                    per_sender_deltas
                        .iter()
                        .any(|(d, ceiling, incoming)| d == dave_did
                            && *ceiling == 1 + MAX_EPOCH_ADVANCE
                            && *incoming == overshoot_epoch),
                    "overshoot delta must report (ceiling, incoming_epoch), got {per_sender_deltas:?}"
                );
            }
            other => panic!("expected SnapshotFloorRegression, got {other:?}"),
        }

        // Atomic reject: no merge applied — the tracker still holds exactly what
        // restore wrote (the overshoot), unmodified.
        let after = provider.export_recv_sequence_floors(&ctx_id);
        assert!(
            after
                .iter()
                .any(|(d, f)| d == dave_did && *f == (overshoot_epoch, 5)),
            "a rejected overshoot must not merge; the tracker is unchanged"
        );
    }

    #[test]
    fn validate_and_merge_recv_sequence_floors_accepts_within_ceiling_import() {
        // No false-positive: an imported recv floor whose epoch is within
        // `sender_key_epoch + MAX_EPOCH_ADVANCE` is ACCEPTED on the untrusted
        // path. The boundary is inclusive (only `> ceiling` rejects).
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let dave_did = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveDa";
        let ctx_id_hex = hex::encode(ctx_id);

        // Sender-key epoch floor 5; live recv floor (5, 20).
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state
                .sender_key_store
                .restore_epoch_high_water(&ctx_id_hex, dave_did, 5);
            state
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (5, 20));
        }
        let live_floors = provider.export_recv_sequence_floors(&ctx_id);

        // Restore advances the recv floor to EXACTLY the ceiling epoch
        // (5 + MAX_EPOCH_ADVANCE) — allowed.
        let ceiling_epoch = 5 + MAX_EPOCH_ADVANCE;
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry
                .value_mut()
                .recv_sequence_tracker
                .insert(dave_did.to_owned(), (ceiling_epoch, 0));
        }

        provider
            .validate_and_merge_recv_sequence_floors(&ctx_id, live_floors, false)
            .expect(
                "a recv floor at exactly the ceiling epoch must be accepted (no false-positive)",
            );

        let merged = provider.export_recv_sequence_floors(&ctx_id);
        assert!(
            merged
                .iter()
                .any(|(d, f)| d == dave_did && *f == (ceiling_epoch, 0)),
            "the within-ceiling import must merge to the higher (ceiling_epoch, 0)"
        );
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

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
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
    /// String whose SHA-256 is the `context_id` returned by
    /// [`setup_alice_bob_two_party`]. The sender-layer AEAD AAD binds the raw
    /// context-id string (§9.16.1), and both `seal` and `open` assert the
    /// supplied 32-byte id is `context_id_bytes(ctx_str)`, so the fixture must
    /// derive its id from a real string rather than an arbitrary 32-byte value.
    const TEST_CTX_STR: &str = "h9-ceiling-ctx";

    fn setup_alice_bob_two_party() -> (
        Arc<MlsCryptoProvider>,
        Arc<MlsCryptoProvider>,
        [u8; 32],
        String,
    ) {
        let alice_did = TEST_DID;
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        // Stand up the joined pair over the REAL reserve → creator-add → sign →
        // HPKE-seal → spawn-from-Welcome path (the legacy provider-level
        // prepare/join shortcut is retired). The helper also distributes Alice's
        // sender key to Bob, so `bob.sender_key_store.epoch(ctx, alice_did) = 1` —
        // the H9 high-water mark these tests anchor on.
        let (alice, bob, context_id) =
            crate::crypto::mls::two_party_test_support::stand_up_two_party(
                TEST_CTX_STR,
                alice_did,
                bob_did,
            );

        (alice, bob, context_id, alice_did.to_string())
    }

    /// Build a minimal `InnerEnvelope` with a deterministic signing key.
    /// `provider.open()` does not verify signatures (per the comment in
    /// `open()`, signature verification is deferred to `ContextManager`),
    /// so an arbitrary key suffices for the H9 receive-ceiling tests.
    fn build_test_inner(
        context_id_str: &str,
        sender_did: &str,
        epoch_field: u64,
        sequence_field: u64,
    ) -> scp_protocol::envelope::inner::InnerEnvelope {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let params = crate::envelope::inner::InnerEnvelopeParams {
            version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
            context_id: context_id_str,
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

        let inner = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        let err = bob
            .open(&ctx_id, TEST_CTX_STR, &sealed)
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

        let inner = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        let err = bob
            .open(&ctx_id, TEST_CTX_STR, &sealed)
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

        let inner = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        let result = bob
            .open(&ctx_id, TEST_CTX_STR, &sealed)
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
        let inner1 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let inner2 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 1);

        // Two sequential seals at Alice's natural epoch=1, sequence
        // increments handled by `seal()` itself.
        let sealed1 = alice.seal(&ctx_id, &inner1, &routing_id, 300).unwrap();
        let sealed2 = alice.seal(&ctx_id, &inner2, &routing_id, 300).unwrap();

        bob.open(&ctx_id, TEST_CTX_STR, &sealed1)
            .expect("first seal must open");
        bob.open(&ctx_id, TEST_CTX_STR, &sealed2)
            .expect("second seal must open");

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
    fn seal_open_binds_raw_context_id_string_not_hex() {
        // §9.16.1: the sender-layer AEAD AAD MUST bind the RAW context_id
        // string (UTF-8, BE32 length-prefixed), NOT the hex encoding of its
        // 32-byte hash. This is the #1909 fix and the cross-implementation interop
        // contract. Proof: a `seal`ed message opens with the raw string but
        // FAILS to open when the hex-of-bytes string is supplied as the AAD
        // source — the exact value native used to (incorrectly) bind.
        let (alice, bob, ctx_id, alice_did) = setup_alice_bob_two_party();
        let routing_id = ctx_routing_id(&ctx_id);

        // Two independently-sealed messages. MLS forward secrecy deletes the
        // per-message decryption secret on the FIRST `open` of a given
        // ciphertext, so the negative and positive cases must each consume
        // their own freshly-sealed blob — re-opening one blob twice would fail
        // at the MLS layer for an unrelated (forward-secrecy) reason.
        let inner1 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let inner2 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 1);
        let sealed_neg = alice.seal(&ctx_id, &inner1, &routing_id, 300).unwrap();
        let sealed_pos = alice.seal(&ctx_id, &inner2, &routing_id, 300).unwrap();

        // Negative: opening with the hex-of-bytes string supplies a
        // `context_id_str` of `hex(ctx_id)` instead of the raw `TEST_CTX_STR`
        // the message was sealed under. The OLD (spec-violating) native code
        // bound `hex(ctx_id)` as the AAD; the §9.16.1 fix binds the RAW string,
        // so reconstructing the AAD from `hex(ctx_id)` yields a DIFFERENT AAD
        // and the sender-layer AEAD authentication fails — proving the bound
        // value is the raw string, not the hex.
        //
        // ADR-056 note: `hex(ctx_id)` is a canonical 64-hex string, so the
        // top-of-`open` resolve-consistency guard (`context_id_to_bytes`)
        // now resolves it back to `ctx_id` and PASSES — `hex(digest)` IS the
        // canonical id-string form of `digest`. The rejection therefore comes
        // from the AEAD layer (the AAD mismatch), one layer deeper than the
        // pre-ADR-056 hash-consistency guard, but it still proves the same
        // §9.16.1 contract: the AAD binds the raw string, not its hex. The
        // dedicated guard-rejection path is covered by
        // `open_rejects_context_id_str_that_does_not_resolve_to_context_id`.
        let hex_ctx = hex::encode(ctx_id);
        bob.open(&ctx_id, &hex_ctx, &sealed_neg).expect_err(
            "opening with hex(ctx_id) as the AAD source must fail — the message was sealed \
             under the RAW context_id string, so the rebuilt AAD does not authenticate",
        );

        // Positive: opening the second blob with the RAW context_id string
        // (the spec value) succeeds, proving the AAD binds the raw string.
        let opened = bob
            .open(&ctx_id, TEST_CTX_STR, &sealed_pos)
            .expect("opening with the raw context_id string (spec AAD) must succeed");
        match opened {
            scp_protocol::context::builder::OpenResult::Application(env) => {
                assert_eq!(env.sender_did, alice_did);
            }
            other => panic!("expected Application, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_context_id_str_that_does_not_resolve_to_context_id() {
        // Defense-in-depth symmetry with `seal`: `open` asserts the supplied
        // 32-byte `context_id` is `context_id_to_bytes(context_id_str)`
        // (ADR-056) and fails CLOSED if they diverge. This guard fires at the
        // very top of `open`, BEFORE any outer-envelope deserialization, MLS
        // decrypt, or sender-layer AEAD work — so the rejection is the fast-path
        // resolve-consistency error, distinct from an AEAD authentication
        // failure.
        let (_alice, bob, ctx_id, _alice_did) = setup_alice_bob_two_party();

        // A `context_id_str` whose canonical resolution is NOT `ctx_id`. It is a
        // non-64-hex string, so it resolves via the SHA-256 fallback; `ctx_id`
        // is the resolution of TEST_CTX_STR, so any other string resolves
        // elsewhere.
        let mismatched_ctx_str = "definitely-not-the-real-context-string";
        assert_ne!(
            crate::context::state::context_id_to_bytes(mismatched_ctx_str),
            ctx_id,
            "test precondition: the mismatched string must not resolve to ctx_id"
        );

        // The outer bytes are deliberately garbage: the guard must reject the
        // mismatched id/string pair BEFORE it ever attempts to deserialize or
        // decrypt them. If the guard did not fire first, this call would
        // instead surface an "outer envelope deserialization" error — proving
        // by its absence that the fail-fast assert ran ahead of the AEAD layer.
        let bogus_outer = [0xABu8; 64];
        let err = bob
            .open(&ctx_id, mismatched_ctx_str, &bogus_outer)
            .expect_err("open must reject a context_id_str that does not resolve to context_id");

        match err {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(
                    msg, "context_id_str does not resolve to the supplied context_id",
                    "expected the fail-fast resolve-consistency rejection, not an AEAD or \
                     deserialization failure, got: {msg}"
                );
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
    }

    #[test]
    fn seal_rejects_context_id_str_that_does_not_resolve_to_context_id() {
        // Defense-in-depth symmetry with `open` (mirror of
        // `open_rejects_context_id_str_that_does_not_resolve_to_context_id`):
        // `seal` asserts the AAD-bound inner-envelope `context_id` STRING
        // resolves via `context_id_to_bytes` (ADR-056) to the supplied 32-byte
        // `context_id` keying argument, and fails CLOSED if they diverge. This
        // guard fires at the very top of `seal`'s `with_context` closure,
        // BEFORE any inner-envelope serialization, sender-layer AEAD, or MLS
        // encrypt work — so the rejection is the fast-path resolve-consistency
        // error, not a downstream crypto failure.
        let (alice, _bob, ctx_id, alice_did) = setup_alice_bob_two_party();
        let routing_id = ctx_routing_id(&ctx_id);

        // The keying argument is the REAL `ctx_id` (so `with_context` finds the
        // live MLS group + sender key from setup), but the inner envelope binds
        // a DIFFERENT context-id string. The string is non-64-hex, so it
        // resolves via the SHA-256 fallback; `ctx_id` is the resolution of
        // TEST_CTX_STR, so any other string resolves elsewhere. The mismatch is
        // load-bearing: without it the guard would not fire.
        let mismatched_ctx_str = "definitely-not-the-real-context-string";
        assert_ne!(
            crate::context::state::context_id_to_bytes(mismatched_ctx_str),
            ctx_id,
            "test precondition: the mismatched string must not resolve to ctx_id"
        );

        let inner = build_test_inner(mismatched_ctx_str, &alice_did, 0, 0);
        let err = alice
            .seal(&ctx_id, &inner, &routing_id, 300)
            .expect_err("seal must reject an inner context_id that does not resolve to context_id");

        match err {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(
                    msg, "inner envelope context_id does not resolve to the supplied context_id",
                    "expected the fail-fast resolve-consistency rejection, not a serialization, \
                     AEAD, or MLS-encrypt failure, got: {msg}"
                );
            }
            other => panic!("expected CryptoFailed, got {other:?}"),
        }
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
        let inner_a = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let inner_b = build_test_inner(TEST_CTX_STR, &alice_did, 0, 1);
        let sealed_a = alice.seal(&ctx_id, &inner_a, &routing_id, 300).unwrap();
        let sealed_b = alice.seal(&ctx_id, &inner_b, &routing_id, 300).unwrap();
        bob.open(&ctx_id, TEST_CTX_STR, &sealed_a).unwrap();
        bob.open(&ctx_id, TEST_CTX_STR, &sealed_b).unwrap();

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
        let inner_replay = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let sealed_replay = alice
            .seal(&ctx_id, &inner_replay, &routing_id, 300)
            .unwrap();
        let err = bob.open(&ctx_id, TEST_CTX_STR, &sealed_replay).expect_err(
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
        let inner_lower = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let sealed_lower = alice.seal(&ctx_id, &inner_lower, &routing_id, 300).unwrap();
        let err = bob
            .open(&ctx_id, TEST_CTX_STR, &sealed_lower)
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

        let inner = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
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
        let inner = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let routing_id = ctx_routing_id(&ctx_id);
        let sealed = alice.seal(&ctx_id, &inner, &routing_id, 300).unwrap();

        // Now take bob's state — open on bob's side should error.
        let _owned = bob.take_crypto_state(&ctx_id).unwrap();
        let err = bob
            .open(&ctx_id, TEST_CTX_STR, &sealed)
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

    // -----------------------------------------------------------------------
    // §9.10.4 privacy: app-data outer-envelope routing_id is zeroed.
    //
    // App-data sends seal ONE blob and fan it out to N per-member pseudonym
    // transport addresses. If the cleartext outer-envelope `routing_id` field
    // embedded the relay-derivable `context_routing_id`, a curious relay could
    // read it off every pseudonym-addressed app-data blob and re-correlate all
    // senders — defeating the pseudonym scheme. The production helper
    // `build_encrypted_envelope` therefore zeroes that field for app-data.
    // Control messages (recovery / sender-key dist) legitimately keep
    // `context_routing_id` because their inner field == their transport address
    // (the shared bootstrap channel every member subscribes to), so there is no
    // leak — those sites are guarded below.
    // -----------------------------------------------------------------------

    fn app_data_recipients(
        ctx_str: &str,
        sender_did: &str,
    ) -> std::collections::HashMap<String, scp_protocol::crypto::access_keys::AccessKey> {
        let mut map = std::collections::HashMap::new();
        map.insert(
            sender_did.to_owned(),
            scp_protocol::crypto::access_keys::generate_access_key(ctx_str, sender_did),
        );
        map
    }

    /// Two-party MLS setup whose group is keyed by `context_id_bytes(ctx_str)`,
    /// matching how `build_encrypted_envelope` derives the group key from the
    /// context-id STRING it is passed. (`setup_alice_bob_two_party` keys the
    /// group by an arbitrary `[u8; 32]` that is not the SHA-256 of any string,
    /// which the string-driven helper cannot address.)
    fn setup_two_party_for_ctx_string(
        ctx_str: &str,
    ) -> (
        Arc<MlsCryptoProvider>,
        Arc<MlsCryptoProvider>,
        [u8; 32],
        String,
    ) {
        let alice_did = TEST_DID;
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        // Stand up the joined pair over the REAL join path, keyed by
        // `context_id_bytes(ctx_str)`. The helper distributes Alice's sender key
        // to Bob so Bob can decrypt Alice's app-data sends.
        let (alice, bob, context_id) =
            crate::crypto::mls::two_party_test_support::stand_up_two_party(
                ctx_str, alice_did, bob_did,
            );

        (alice, bob, context_id, alice_did.to_string())
    }

    /// The cleartext outer-envelope `routing_id` produced by
    /// `build_encrypted_envelope` for application data is the 32-byte zero
    /// sentinel — NOT the relay-derivable `context_routing_id`. A relay
    /// deserializing the single envelope layer therefore reads no shared
    /// correlator off a pseudonym-addressed app-data blob.
    #[test]
    fn app_data_envelope_routing_id_is_zeroed_not_context_rid() {
        let ctx_str = "ctx-app-data-zeroed-rid";
        let (alice, _bob, _ctx_id, alice_did) = setup_two_party_for_ctx_string(ctx_str);
        let alice = std::sync::Arc::new(alice);
        let clock: std::sync::Arc<dyn scp_clock::Clock> =
            std::sync::Arc::new(scp_clock::SystemClock);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sender = scp_did::DID(alice_did.clone());
        let recipients = app_data_recipients(ctx_str, &alice_did);

        let wire = crate::context::messaging_helpers::build_encrypted_envelope(
            &clock,
            &alice,
            ctx_str,
            &sender,
            b"hello app data",
            crate::context::supervisor::MessageSigner::Active(&signing_key),
            &recipients,
            0,
            None,
            scp_protocol::envelope::inner::MessageType::Content,
        )
        .unwrap();

        let decoded = scp_protocol::envelope::outer::OuterEnvelope::from_bytes(&wire).unwrap();
        let context_rid = scp_protocol::context::context_routing_id(ctx_str).to_vec();

        assert_eq!(
            decoded.routing_id,
            vec![0u8; 32],
            "app-data outer envelope routing_id must be the 32-byte zero sentinel"
        );
        assert_ne!(
            decoded.routing_id, context_rid,
            "app-data outer envelope routing_id must NOT be the relay-derivable context_routing_id"
        );
    }

    /// Receive is unaffected by zeroing the field: a full app-data
    /// send -> `open()` roundtrip still decrypts correctly, because the
    /// receiver routes on the transport key and MLS-decrypts the blob; it
    /// never reads the outer `routing_id` for app-data.
    #[test]
    fn app_data_roundtrip_decrypts_with_zeroed_routing_id() {
        let ctx_str = "ctx-app-data-roundtrip";
        let (alice, bob, ctx_id, alice_did) = setup_two_party_for_ctx_string(ctx_str);
        let alice_arc = std::sync::Arc::new(alice);
        let clock: std::sync::Arc<dyn scp_clock::Clock> =
            std::sync::Arc::new(scp_clock::SystemClock);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sender = scp_did::DID(alice_did.clone());
        let recipients = app_data_recipients(ctx_str, &alice_did);

        let wire = crate::context::messaging_helpers::build_encrypted_envelope(
            &clock,
            &alice_arc,
            ctx_str,
            &sender,
            b"roundtrip payload",
            crate::context::supervisor::MessageSigner::Active(&signing_key),
            &recipients,
            0,
            None,
            scp_protocol::envelope::inner::MessageType::Content,
        )
        .unwrap();

        // Sanity: the field really is zeroed on the wire.
        let decoded = scp_protocol::envelope::outer::OuterEnvelope::from_bytes(&wire).unwrap();
        assert_eq!(decoded.routing_id, vec![0u8; 32]);

        // Bob opens the same blob and recovers the application plaintext,
        // proving the zeroed routing_id does not break delivery.
        let opened = bob.open(&ctx_id, ctx_str, &wire).unwrap();
        match opened {
            scp_protocol::context::builder::OpenResult::Application(env) => {
                assert_eq!(
                    env.sender_did, alice_did,
                    "sender DID recovered from MLS credential despite zeroed routing_id"
                );
            }
            other => panic!("expected an Application message, got {other:?}"),
        }
    }

    /// Control-path guard: a control message (Recovery type) sealed with
    /// `context_routing_id` — exactly as the recovery / sender-key dist sites
    /// do — STILL embeds `context_routing_id` in its inner envelope. This is
    /// correct: for control traffic the inner field equals the transport
    /// address (the shared bootstrap channel every member subscribes to), so
    /// there is no relay correlator leak. The guard proves `seal` faithfully
    /// preserves whatever `routing_id` it is given, so the app-data fix is scoped
    /// purely to the argument passed in `build_encrypted_envelope` and did NOT
    /// over-broadly zero the control seal sites.
    #[test]
    fn control_message_seal_still_embeds_context_routing_id() {
        // The context id must be derived from a real string: `seal` binds the
        // raw `inner.context_id` into the AEAD AAD (§9.16.1) and asserts the
        // supplied 32-byte id is its SHA-256, so a hex-of-bytes inner id (which
        // is not the preimage of `ctx_id`) would be rejected.
        let ctx_str = "ctx-control-routing-id";
        let (alice, _bob, ctx_id, alice_did) = setup_two_party_for_ctx_string(ctx_str);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

        // Mirror the control-path inner envelope (Recovery message type).
        let params = crate::envelope::inner::InnerEnvelopeParams {
            version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
            context_id: ctx_str,
            sender_did: &alice_did,
            epoch: 0,
            generation: 0,
            sequence: 0,
            timestamp: 1_700_000_000,
            message_type: crate::envelope::inner::MessageType::Recovery,
            payload: b"recovery notification",
            provenance: None,
            signing_key_id: SigningKeyId::Active,
        };
        let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, &sk).unwrap();

        // Control path passes `context_routing_id` to `seal` (as in
        // trust_recovery_helpers / supervisor / lifecycle_helpers).
        let control_rid = scp_protocol::context::context_routing_id(ctx_str);
        let wire = alice.seal(&ctx_id, &inner, &control_rid, 300).unwrap();

        let decoded = scp_protocol::envelope::outer::OuterEnvelope::from_bytes(&wire).unwrap();
        assert_eq!(
            decoded.routing_id,
            control_rid.to_vec(),
            "control messages must still embed context_routing_id (shared bootstrap channel)"
        );
        assert_ne!(
            decoded.routing_id,
            vec![0u8; 32],
            "control routing_id must NOT be zeroed — that would break the shared channel"
        );
    }

    /// Root `scp_context_params` extension fixture for the provider create path.
    fn provider_context_extension(context_id: &str) -> scp_protocol::context::ScpContextExtension {
        use scp_did::DID;
        use scp_protocol::context::GovernanceModel;
        use scp_protocol::context::params::{CeilingPolicy, ContextMode};
        use scp_protocol::context::roles::{Capability, CapabilityCeiling};

        let governance = GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![
                DID::from("did:dht:z6MkAlice".to_owned()),
                DID::from("did:dht:z6MkBob".to_owned()),
            ],
        };
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        scp_protocol::context::ScpContextExtension::for_root(
            context_id.to_owned(),
            DID::from("did:dht:z6MkAlice".to_owned()),
            ContextMode::Encrypted,
            &governance,
            CeilingPolicy::Immutable,
            &ceiling,
        )
        .unwrap()
    }

    /// The production creator write path
    /// ([`MlsCryptoProvider::create_mls_group_with_context`]) commits the
    /// `scp_context_params` (`0xFF02`) extension into the group's
    /// `group_context`, byte-identical to the parameters supplied (§5.13.3,
    /// FFI-02).
    #[test]
    fn create_mls_group_with_context_commits_extension() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        let ctx_ext = provider_context_extension("ctx:provider-write");

        provider
            .create_mls_group_with_context(&ctx_id, &ctx_ext)
            .unwrap();

        let read_back = provider
            .with_context(&ctx_id, |state| {
                state
                    .mls_group
                    .group_context_extension()
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))
            })
            .unwrap();
        assert_eq!(
            read_back,
            Some(ctx_ext),
            "created context group must carry the committed ScpContextExtension"
        );
    }

    /// The wrapping-key-only [`MlsCryptoProvider::create_mls_group`] path leaves
    /// no `0xFF02` extension on the group (contrast to the context path above).
    #[test]
    fn create_mls_group_has_no_context_extension() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        provider.create_mls_group(&ctx_id).unwrap();

        let read_back = provider
            .with_context(&ctx_id, |state| {
                state
                    .mls_group
                    .group_context_extension()
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))
            })
            .unwrap();
        assert_eq!(
            read_back, None,
            "a wrapping-key-only group must not report a context extension"
        );
    }

    /// The context create path shares the overwrite-refusal invariant with
    /// [`MlsCryptoProvider::create_mls_group`]: a second create for a live id
    /// fails rather than clobbering the group.
    #[test]
    fn create_mls_group_with_context_refuses_overwrite() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        let ctx_ext = provider_context_extension("ctx:provider-overwrite");

        provider
            .create_mls_group_with_context(&ctx_id, &ctx_ext)
            .unwrap();
        let second = provider.create_mls_group_with_context(&ctx_id, &ctx_ext);
        assert!(
            matches!(second, Err(ContextCreationError::CreationFailed(_))),
            "a second create for a live id must be refused, got {second:?}"
        );
    }
}
