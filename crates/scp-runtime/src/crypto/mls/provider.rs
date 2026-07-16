//! Production `MlsCryptoProvider` implementation backed by `OpenMLS`.
//!
//! [`MlsCryptoProvider`] bridges the historical inherent API to the actor-era
//! [`MlsBackend`](super::backend::MlsBackend) and
//! [`HpkeBackend`](crate::crypto::hpke_backend::HpkeBackend) primitives. State
//! that used to live in `Mutex<HashMap>` / `Mutex<scalar>` fields on the
//! provider has migrated to lock-free containers per ADR-049 §15
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
use scp_mls::group::{self, SCP_CIPHERSUITE, ScpMlsGroup};
use scp_mls::validate_key_package_lifetime;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::builder::ReceiveFloor;
use scp_protocol::crypto::sender_keys::{
    NonceDedup, SenderKey, SenderKeyDistributionMessage, SenderKeyStore, generate_sender_key,
    generate_wrapping_keypair,
};
// `SenderKeyResponse` is only constructed by the sender-key PUSH/answer paths
// that PR-7 moved onto the actor; the retained provider copies
// (`distribute_sender_key`, `handle_sender_key_request`) are test/fixture-only
// (`#[cfg(any(test, feature = "testing"))]`), so the import is gated to match.
#[cfg(any(test, feature = "testing"))]
use scp_protocol::crypto::sender_keys::SenderKeyResponse;

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
// ADR-049 PR-7 (crypto-state move, prep A): visibility elevated from private to
// `pub(crate)` (fields included) so the additive
// [`crate::context::actor::PerContextState::export_crypto_state`] inherent method
// can build the BYTE-IDENTICAL snapshot by moving this provider method's body
// verbatim (Decision 6 / Decision 15(a)). This mirrors the earlier
// `EpochState` / `TtlState` / `AccessControlState` / `GovernanceState` elevations
// ("elevated from private to pub(crate) so the actor can carry it"). The struct
// stays defined here; the provider retains its own `export_crypto_state` until
// the atomic core (SCP-CRYPTOMOVE-001) deletes it.
#[derive(Serialize, Deserialize)]
pub(crate) struct MlsCryptoSnapshot {
    /// The raw key-value pairs from the `OpenMLS` `MemoryStorage`.
    /// Each pair is `(key_bytes, value_bytes)`.
    pub(crate) mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// The local member's AES-256 sender key (32 bytes).
    pub(crate) local_sender_key: SenderKey,
    /// All sender keys for this context: `(sender_did, key)` pairs.
    pub(crate) sender_key_entries: Vec<(String, SenderKey)>,
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
    pub(crate) sender_key_epochs: Vec<(String, u64)>,
    /// The sender key epoch counter.
    pub(crate) sender_key_epoch: u64,
    /// The send-side message sequence counter.
    /// MIGRATION: `#[serde(default)]` — old snapshots deserialize as 0, which is
    /// the correct initial state. GCM nonces are random (`OsRng`), not counter-derived,
    /// so a sequence reset does not create nonce reuse.
    #[serde(default)]
    pub(crate) send_sequence: u64,
    /// Remote members' X25519 wrapping public keys: `(did, pubkey)` pairs.
    pub(crate) member_wrapping_keys: Vec<(String, [u8; 32])>,
    /// The MLS signer (`SignatureKeyPair`) serialized via serde to bytes.
    /// `SignatureKeyPair` does not derive `Clone` without the `clonable`
    /// feature, so we serialize it separately and store the blob here.
    pub(crate) signer_bytes: Vec<u8>,
    /// The MLS group ID bytes. Required to call `MlsGroup::load` on restore.
    pub(crate) group_id: Vec<u8>,
    /// Receive-side sequence tracking: `(sender_did, last_epoch, last_sequence)`.
    /// MIGRATION: `#[serde(default)]` — old snapshots deserialize with an empty
    /// tracker, so the first message from each sender is accepted unconditionally.
    /// MLS-level replay protection remains the primary defense; this tracker is
    /// defense-in-depth at the sender-key layer.
    #[serde(default)]
    pub(crate) recv_sequence_tracker: Vec<(String, u64, u64)>,
    /// The provider-level X25519 wrapping public key (§9.16.1).
    /// Persisted so remote members' HPKE-sealed sender key responses can
    /// still be decrypted after a restart. Without this, the restored
    /// provider would generate a fresh keypair whose public key doesn't
    /// match the one published in the MLS tree's `LeafNode` extension.
    #[serde(default)]
    pub(crate) wrapping_public_key: [u8; 32],
    /// The provider-level X25519 wrapping secret key (§9.16.1).
    /// Wrapped in a `Vec<u8>` for serde compatibility; the 32-byte key
    /// is re-wrapped in [`Zeroizing`] on restore.
    #[serde(default)]
    pub(crate) wrapping_secret_key: Vec<u8>,
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
    /// [`export_crypto_state`](crate::context::actor::state::PerContextState::export_crypto_state) calls this once at its
    /// end (belt-and-suspenders) after serializing the snapshot.
    /// [`build_restored_owned`](crate::crypto::mls::provider::MlsCryptoProvider::build_restored_owned) does NOT call it:
    /// restore consumes each secret field incrementally as it moves the material
    /// into the live crypto state (`drain`/`mem::replace`/per-field `zeroize` at
    /// the point of use), so there is no single end-of-function sweep to make. On
    /// both paths the [`Drop`] impl below is the backstop that also fires on an
    /// early `?` return, so raw signer / sender-key / wrapping-secret / MLS-secret
    /// bytes never linger un-zeroized in freed memory on ANY path (matches the
    /// parity guarantee the `scp-mls` and `scp-client` snapshots make via their
    /// own `Drop`s).
    ///
    /// ADR-049 PR-7 (prep A): `pub(crate)` so the additive
    /// [`crate::context::actor::PerContextState::export_crypto_state`] verbatim
    /// move can perform the identical end-of-function secret sweep.
    pub(crate) fn zeroize_secrets(&mut self) {
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
    /// Drained by [`PerContextState::drain_pending_sender_key_messages`](crate::context::actor::state::PerContextState::drain_pending_sender_key_messages).
    pending_distributions: Vec<(String, Vec<u8>)>,
    /// Nonce deduplication cache for sender key requests (replay protection).
    nonce_dedup: NonceDedup,
    /// Remote members' X25519 wrapping public keys, keyed by DID.
    /// Populated from key packages during [`MlsCryptoProvider::add_member`].
    member_wrapping_keys: HashMap<String, [u8; 32]>,
    // ADR-049 PR-6 (read-authority switch): the node-only receive-side
    // `(epoch, sequence)` anti-replay mirror has been DELETED. The
    // authoritative Class-M home is now the Supervisor-owned floor registry
    // (`context/supervisor/floors.rs`), gated fail-closed at the messaging
    // seam. The durable blob field [`MlsCryptoSnapshot::recv_sequence_tracker`]
    // is retained and threaded through `export_crypto_state` /
    // `restore_crypto_state` as a parameter, not read from a live provider map.
}

// ---------------------------------------------------------------------------
// OwnedMlsCryptoState — destructive-move payload for actor ownership transfer
// ---------------------------------------------------------------------------

/// Owned per-context MLS crypto state moved out of
/// [`MlsCryptoProvider::contexts`] by [`MlsCryptoProvider::take_crypto_state`]
/// (ADR-049 PR-7, SCP-CRYPTOMOVE-001).
///
/// This is the one-way move payload that transfers a context's crypto state
/// from the provider to its per-context actor. It mirrors the private
/// [`ContextCryptoState`] struct above — one public `pub` field per legacy
/// field, plus the `send_sequence` counter so callers can seed an actor-side
/// [`crate::context::actor::SendSequenceTracker`] at take-time. After
/// `take_crypto_state` returns `Ok(OwnedMlsCryptoState)`, the provider's
/// `contexts[ctx_id]` entry is absent and any subsequent
/// [`MlsCryptoProvider::with_context`](crate::crypto::mls::provider::MlsCryptoProvider::with_context) access (or provider birth-seam) targeting that
/// context returns [`ContextError::CryptoFailed`] with a "context state owned
/// by actor" message. The invariant is tracked by
/// [`MlsCryptoProvider::taken_context_ids`] — a set that distinguishes
/// "state has been taken" from "state was never created" so the error
/// message is actionable.
///
/// # Ownership — the actor owns crypto by move
///
/// This is the shipped steady state, not an interim scaffold.
/// `take_crypto_state` IS called from the production spawn paths — the
/// join/WELCOME birth seam
/// ([`crate::context::supervisor::Supervisor::spawn_actor_from_welcome`]) and
/// the CREATE seam in `context/lifecycle_helpers.rs` — to hand each context's
/// freshly-born group + sender key onto its actor's `PerContextState` at spawn
/// time. The provider's steady-state `seal` / `open` methods are DELETED: once
/// seeded, the actor is the sole crypto authority. The transfer is one-way —
/// crypto is never handed back to the provider, so there is no dual-home
/// window. The remaining provider entry points (`create_mls_group`,
/// `install_joined_group`, sender-key generation, `with_context`) are birth
/// seams or fail-closed "owned by actor" guards, never a live steady-state
/// crypto path.
///
/// # Why every field is `pub`
///
/// This type is a move payload, not a domain struct. Callers (the actor spawn
/// seams above) destructure it field-by-field to build the actor-side
/// [`crate::context::actor::ContextCryptoState`]. The legacy
/// `ContextCryptoState` keeps its fields private because it is internal to the
/// provider; the owned mirror here is the boundary shape between the provider
/// and the actor.
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
            .finish()
    }
}

/// Per-context Class-M floors reconstructed from a persisted snapshot.
///
/// Returned by [`MlsCryptoProvider::build_restored_owned`](crate::crypto::mls::provider::MlsCryptoProvider::build_restored_owned) for the caller to
/// merge into the authoritative Supervisor-owned floor registry (ADR-049 PR-6).
///
/// `restore_crypto_state` installs the MLS group + sender-key MATERIAL into the
/// live provider but NO LONGER seeds any epoch / recv-sequence floor there (the
/// provider mirrors are deleted). Instead it returns the floors the snapshot
/// carried — including the legacy back-compat lower bound derived from a
/// pre-`sender_key_epochs` snapshot's global `sender_key_epoch` counter — so
/// `restore_crypto_state_with_floor_guard` can run them through the registry's
/// fail-closed `validate_and_merge_*` sink.
#[derive(Debug, Default)]
pub struct RestoredFloors {
    /// `(sender_did, epoch)` high-water floors to merge into the registry's
    /// `sender_epochs` map. Preserves the legacy back-compat computation: a
    /// snapshot with no per-sender epoch map contributes
    /// `snapshot.sender_key_epoch.max(1)` for every sender that has key material.
    pub sender_epochs: Vec<(String, u64)>,
    /// `(sender_did, ReceiveFloor)` intra-epoch anti-replay floors to merge into
    /// the registry's `recv_sequence` map.
    pub recv_sequence: Vec<(String, ReceiveFloor)>,
}

/// Production `ContextCryptoProvider` backed by `OpenMLS`.
///
/// Node-resident X25519 wrapping keypair (§9.16.1), held as one unit so the
/// public and secret halves rotate and are read atomically (ADR-049 PR-7
/// hardening H3). Stored behind a single [`ArcSwap`] on [`MlsCryptoProvider`].
struct WrappingKeypair {
    /// X25519 wrapping public key for sender key HPKE (§9.16.1). Published in
    /// the MLS `LeafNode` `scp_wrapping_key` extension.
    public: [u8; 32],
    /// X25519 wrapping secret key for sender key HPKE (§9.16.1). Used to open
    /// HPKE-sealed sender key responses. Wrapped in [`Zeroizing`] so the prior
    /// key material is zeroized when the last `Arc` to this pair drops (i.e. on
    /// rotation, when the `ArcSwap` slot is replaced).
    secret: Zeroizing<[u8; 32]>,
}

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
///
/// # Wrapping-keypair atomicity (ADR-049 PR-7 hardening H3)
///
/// The node-resident X25519 wrapping keypair is stored as a SINGLE
/// [`WrappingKeypair`] behind ONE [`ArcSwap`], so the public and secret halves
/// rotate and are read as one unit. A prior design held the two halves in two
/// separate `ArcSwap` slots; a reader that loaded the public half and then the
/// secret half across two `.load()` calls could observe a torn pair (public of
/// generation N with secret of N+1) if a rotation interleaved. That is closed by
/// construction here: every read goes through a single `.load()` of the combined
/// slot (see [`MlsCryptoProvider::wrapping_keypair`]).
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
    /// Injected MLS primitive backend (ADR-049 §15). Production
    /// callers receive a [`ProductionMlsBackend`] from
    /// [`MlsCryptoProvider::new`]; tests inject failure-driven mocks via
    /// [`MlsCryptoProvider::with_backends`]. The provider's orchestration
    /// methods route every inline `OpenMLS` primitive through this trait —
    /// state still lives on the provider's lock-free containers below.
    mls_backend: Arc<dyn MlsBackend>,
    /// Injected HPKE primitive backend (ADR-049 §15). Same
    /// injection contract as `mls_backend` — production wires
    /// [`ProductionHpkeBackend`]; tests can substitute mocks for fail
    /// injection on the wrapping-key seal/unseal path.
    hpke_backend: Arc<dyn HpkeBackend>,
    /// Per-context crypto state, keyed by the 32-byte context ID.
    ///
    /// Lock-free [`DashMap`] — the actor refactor (ADR-049 §15)
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
    /// the provider currently retains the authoritative copy for
    /// non-actor callers.
    broadcast_keys: DashMap<[u8; 32], SenderKey>,
    /// Node-resident X25519 wrapping keypair for sender key HPKE (§9.16.1) —
    /// public half published in the MLS `LeafNode` `scp_wrapping_key` extension,
    /// secret half used to open HPKE-sealed sender key responses.
    ///
    /// Held as a SINGLE [`WrappingKeypair`] behind ONE [`ArcSwap`] (ADR-049 PR-7
    /// hardening H3) so the pair rotates and is read atomically — the
    /// snapshot-restore path (which takes `&self`) replaces both halves in one
    /// `.store()`, and every reader loads both halves from one `.load()`,
    /// closing the two-slot torn-read window. Rotation is atomic and the prior
    /// key material is zeroized when the last `Arc` to the pair drops. Reader
    /// discipline (load → use → drop within the same poll) is enforced at every
    /// callsite — no callsite stores the loaded `Arc` in a struct field.
    wrapping_keypair: ArcSwap<WrappingKeypair>,
    /// Contexts whose crypto state has been destructively moved into a
    /// [`crate::context::actor::ContextActor`] via
    /// [`Self::take_crypto_state`] (ADR-049 PR-7).
    ///
    /// Tracked separately from [`Self::contexts`] so [`Self::with_context`]
    /// can distinguish "context was never created" (returns the legacy
    /// `no MLS group for this context` error) from "state was taken by
    /// the actor runtime" (returns an actionable
    /// `context state owned by actor` error). The two failure modes have
    /// different call-site remediations — the former indicates a
    /// create-before-send ordering bug, the latter indicates a caller
    /// reaching through the provider after actor ownership has been
    /// transferred — that caller should route through the actor's mailbox
    /// instead.
    ///
    /// # Lifecycle
    ///
    /// - Insert: on successful [`Self::take_crypto_state`].
    /// - Remove: never — actor ownership is permanently one-way. A taken
    ///   context stays taken for the provider's lifetime; the crypto never
    ///   returns to the provider. Full provider dissolution is deferred
    ///   (ADR-049 §6).
    ///
    /// Lock-free [`DashSet`] — the prior `std::sync::Mutex<HashSet>`
    /// wrapper was removed in ADR-049 §15.
    taken_context_ids: DashSet<[u8; 32]>,
    /// One-shot test seam: when set, the NEXT `rotate_sender_key`
    /// call returns [`ContextError::CryptoFailed`] and resets the flag.
    ///
    /// This exists solely to induce a rotation-call failure that drives the
    /// caller's ADR-049 §9 Class-S sync-persist fail-closed branch end-to-end
    /// (§15(c)): the "injected failure ⇒ rotation returns `Err` with the
    /// epoch/key NOT committed" criterion. Note the Class-S persist itself
    /// happens in the ACTOR after this call returns, not in this function —
    /// `rotate_sender_key` only mutates the provider's in-memory state and
    /// queues distributions; this seam makes that call fail so the actor
    /// observes its fail-closed signal. The real provider's in-process rotation
    /// always generates a fresh key and increments successfully, so that
    /// fail-closed branch is otherwise structurally unreachable. Gated behind
    /// `#[cfg(any(test, feature = "testing"))]` so the production build carries
    /// neither the field nor the branch. One-shot (fires once, then clears
    /// itself) so a subsequent rotation succeeds normally.
    #[cfg(any(test, feature = "testing"))]
    force_rotation_failure: std::sync::atomic::AtomicBool,
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
    /// Test seam introduced by ADR-049 §15. Production code
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
            wrapping_keypair: ArcSwap::from_pointee(WrappingKeypair {
                public: wrapping_public_key,
                secret: Zeroizing::new(wrapping_secret_key),
            }),
            taken_context_ids: DashSet::new(),
            #[cfg(any(test, feature = "testing"))]
            force_rotation_failure: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Arms the one-shot [`Self::force_rotation_failure`] seam: the NEXT
    /// `rotate_sender_key` call returns
    /// [`ContextError::CryptoFailed`] and clears the flag.
    ///
    /// Test-only (see the field docs) — used to induce a rotation-call failure
    /// that drives the caller's ADR-049 §9 Class-S sync-persist fail-closed
    /// branch (§15(c)); the persist itself happens in the actor after
    /// `rotate_sender_key` returns, not in this function. The real provider
    /// cannot otherwise reach that branch (an in-process rotation always
    /// generates a fresh key and increments the epoch successfully).
    #[cfg(any(test, feature = "testing"))]
    pub fn arm_rotation_failure_once(&self) {
        self.force_rotation_failure
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Borrowed reference to the injected MLS primitive backend
    /// (ADR-049 §15). Helper functions outside the provider
    /// that need the same backend (e.g. handler code in
    /// `handlers/messaging.rs` once the deletion ladder lands) can
    /// borrow through this accessor.
    #[must_use]
    pub fn mls_backend(&self) -> &Arc<dyn MlsBackend> {
        &self.mls_backend
    }

    /// Borrowed reference to the injected HPKE primitive backend
    /// (ADR-049 §15). See [`Self::mls_backend`].
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
    /// time (ADR-049 PR-7).
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
    /// Actor ownership is permanent and one-way. Once taken, a context's
    /// crypto state never returns to the provider — the actor becomes the
    /// sole authority for that context's crypto for the rest of its
    /// lifetime. Production lookups (publish, subscribe, etc.) reach the
    /// crypto state only through the actor's mailbox.
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
    /// # Production call sites
    ///
    /// Invoked at the two owned-state spawn seams: the CREATE seam
    /// ([`crate::context::lifecycle_helpers`] finalize, after the provider
    /// births the group) and the WELCOME seam
    /// ([`crate::context::supervisor`] welcome processing). Each takes the
    /// freshly-born crypto out of the provider and seeds it into the
    /// spawning actor's `PerContextState` via
    /// [`seed_encrypted_crypto_from_owned`](crate::context::actor::state::PerContextState::seed_encrypted_crypto_from_owned).
    pub fn take_crypto_state(
        &self,
        context_id: &[u8; 32],
    ) -> Result<OwnedMlsCryptoState, ContextError> {
        // ADR-049 §15: the underlying `contexts` map is now a
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
        // shape translation happens; per ADR-049 PR-7 downstream consumes
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
    ///   moved via [`Self::take_crypto_state`] (ADR-049 PR-7).
    ///   Callers seeing this error must route through the actor's
    ///   mailbox — the provider no longer owns the state.
    fn with_context<F, R>(&self, context_id: &[u8; 32], f: F) -> Result<R, ContextError>
    where
        F: FnOnce(&mut ContextCryptoState) -> Result<R, ContextError>,
    {
        // ADR-049 §15: lock-free per-shard access via
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
    /// Residency probe: returns `true` iff live (non-taken) per-context MLS
    /// crypto state is currently resident on THIS provider under `context_id`.
    ///
    /// The birth/destroy paths that stay provider-resident (creation rollback,
    /// ephemeral / TTL close key destruction) previously proved residency by
    /// calling `export_crypto_state` and checking the blob was non-empty (it
    /// short-circuited to EMPTY when the `contexts` entry was absent). ADR-049
    /// PR-7 (SCP-CRYPTOMOVE-001) moved `export_crypto_state` onto the actor and
    /// deleted the provider twin; this is its retained, non-serializing
    /// equivalent for the provider-resident destroy assertions. A context taken
    /// by an actor is NOT resident here (its entry was removed by
    /// `take_crypto_state` and recorded in `taken_context_ids`).
    #[must_use]
    pub fn context_crypto_present(&self, context_id: &[u8; 32]) -> bool {
        !self.taken_context_ids.contains(context_id) && self.contexts.contains_key(context_id)
    }

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
        // mocks before ADR-049 §15 — continues to work with
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
    /// [`ScpContextExtension`](scp_protocol::context::ScpContextExtension) is folded into the MLS key schedule and read back
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

        // H2 (ADR-049 PR-7): fail closed if this context's crypto state has
        // already been moved into the actor. `take_crypto_state` removes the
        // entry from `contexts` AND records the id in `taken_context_ids`, so a
        // taken context is absent from `contexts` — the `Entry::Vacant` guard
        // below would otherwise pass and resurrect a DIVERGENT second MLS group
        // (double-owner: provider and actor both sealing). This closes the
        // write side of the one-way take invariant that `with_context` already
        // enforces on the read side.
        if self.taken_context_ids.contains(context_id) {
            return Err(ContextCreationError::CreationFailed(format!(
                "context state owned by actor — refusing to create a second MLS group for \
                 context '{}'",
                hex::encode(context_id)
            )));
        }

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
        let wrapping_pk = self.wrapping_keypair.load().public;
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

        // H2 (ADR-049 PR-7): fail closed if this context's crypto state has
        // already been moved into the actor (see `create_group_into_slot`) —
        // a taken context is absent from `contexts`, so the `Entry::Vacant`
        // guard below would otherwise install a divergent second group.
        if self.taken_context_ids.contains(context_id) {
            return Err(ContextError::CreationFailed(format!(
                "context state owned by actor — refusing to install a joined MLS group for \
                 context '{}'",
                hex::encode(context_id)
            )));
        }

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
        // H2 (ADR-049 PR-7): fail closed with the actionable "owned by actor"
        // error if this context's crypto state has been moved into the actor.
        // Without this, a taken context is absent from `contexts` and the
        // `get_mut` below returns the generic "no MLS group" error, masking the
        // real cause (a caller reaching the provider after actor ownership).
        if self.taken_context_ids.contains(context_id) {
            return Err(ContextCreationError::CreationFailed(format!(
                "context state owned by actor — refusing to generate a sender key for \
                 context '{}'",
                hex::encode(context_id)
            )));
        }
        // ADR-049 §15: lock-free `DashMap::get_mut`.
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
        // ADR-049 §15: lock-free `DashMap::insert`.
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
        // ADR-049 §15: lock-free `DashMap::remove`.
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
        // ADR-049 §15: lock-free per-shard mutation. Drop the
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
        // behaviour deleted in ADR-049 §15.
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
        // fixture (deleted in ADR-049 §15). Preserve the
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

    /// Distributes sender key bundle to a new member via ADR-007.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if distribution fails.
    ///
    /// # ADR-049 PR-7 — test/fixture-only
    ///
    /// The steady-state join-time sender-key PUSH moved onto the actor
    /// ([`PerContextState::distribute_sender_key`](crate::context::actor::state::PerContextState::distribute_sender_key));
    /// production is zero-grep clean of this provider copy (a taken, actor-owned
    /// context pushes on the actor). Retained under
    /// `#[cfg(any(test, feature = "testing"))]` solely for provider-level
    /// two-party test fixtures.
    #[cfg(any(test, feature = "testing"))]
    pub fn distribute_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(context_id);
        // ADR-049 §15: lock-free `DashMap::get_mut`.
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

    /// Processes an incoming sender key distribution message from a remote
    /// member, returning the AUTHENTICATED `(sender_key, epoch)`.
    ///
    /// Deserializes the message and HPKE-opens + DID-verifies the recovered
    /// sender key. ADR-049 PR-6: it does NOT install the key or enforce any
    /// epoch floor — the caller (the `decrypt_and_dispatch` messaging seam)
    /// gates the returned `epoch` against the authoritative Class-M floor
    /// registry and then installs the key via
    /// `set_sender_key_unchecked` (gate-before-install = fail-safe).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if deserialization, HPKE
    /// decryption, or the sender-DID authentication check fails.
    pub fn process_incoming_sender_key(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        message_bytes: &[u8],
    ) -> Result<(SenderKey, u64), ContextError> {
        let ctx_id_hex = hex::encode(context_id);

        // Deserialize the distribution message.
        let msg = SenderKeyDistributionMessage::from_bytes(message_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("deserialization failed: {e}")))?;

        match msg {
            SenderKeyDistributionMessage::KeyResponse(response) => {
                // ADR-049 §15: load wrapping secret through
                // `ArcSwap`. The returned `Arc` is held only for the
                // duration of the HPKE-open call (no `.await` between
                // load and drop).
                let wrapping_keypair_guard = self.wrapping_keypair.load();
                let sender_key = crate::crypto::sender_keys::key_protocol::hpke_open_sender_key(
                    &response.hpke_sealed_key,
                    &response.ephemeral_pubkey,
                    &wrapping_keypair_guard.secret,
                    &ctx_id_hex,
                    &response.sender_did,
                    response.epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(format!("HPKE open failed: {e}")))?;
                drop(wrapping_keypair_guard);

                // Verify the sender DID matches the claimed sender. This is
                // AUTHENTICATION (the HPKE tag + DID binding), NOT floor gating,
                // so it stays here.
                if response.sender_did != sender_did {
                    return Err(ContextError::CryptoFailed(
                        "sender DID mismatch in sender key distribution".into(),
                    ));
                }

                // ADR-049 PR-6 (read-authority switch): epoch monotonicity
                // (#1608) + the epoch-poisoning ceiling are NO LONGER enforced
                // here. They are now the sole responsibility of the authoritative
                // Class-M floor registry, gated fail-closed at the messaging seam
                // (`decrypt_and_dispatch`) BEFORE the caller installs this key via
                // [`Self::set_sender_key_unchecked`] (gate-before-install =
                // fail-safe). Return the AUTHENTICATED key and its claimed epoch
                // for the caller to gate + install; this method no longer touches
                // the sender-key store.
                Ok((sender_key, response.epoch))
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
    /// ADR-049 PR-6 (read-authority switch): the pull-response ingest half —
    /// verifies the destination context is registered and returns the ALREADY-
    /// AUTHENTICATED `(sender_key, epoch)` for the caller to gate + install,
    /// mirroring the push path [`Self::process_incoming_sender_key`] EXACTLY. It
    /// does NOT install (no silent write): the caller gates the `epoch` against
    /// the authoritative Class-M registry and then installs via
    /// [`Self::set_sender_key_unchecked`] — the SAME shape as seam 2, so no
    /// pull-vs-push asymmetry and no method that installs without a conscious,
    /// separate call.
    ///
    /// The `sender_key` was opened (and its AEAD tag + context/sender/epoch
    /// binding verified) by the caller with the requester's EPHEMERAL wrapping
    /// secret (`key_protocol::open_sender_key_response`) BEFORE this call, so the
    /// authentication lives at that open, not here — the provider does not hold
    /// the ephemeral secret and cannot re-open it.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if no group is registered for
    /// `context_id`.
    ///
    /// # ADR-049 PR-7 — test/fixture-only
    ///
    /// The steady-state pull-answer store moved onto the actor; production is
    /// zero-grep clean of this provider copy. Retained under
    /// `#[cfg(any(test, feature = "testing"))]` solely for provider-level
    /// two-party test fixtures.
    #[cfg(any(test, feature = "testing"))]
    pub fn store_member_sender_key(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        sender_key: SenderKey,
        epoch: u64,
    ) -> Result<(SenderKey, u64), ContextError> {
        // Verify the destination context is registered (fail-closed) — the same
        // precondition the install path checked — WITHOUT installing.
        if !self.contexts.contains_key(context_id) {
            return Err(ContextError::CryptoFailed(
                "no MLS group for this context".to_string(),
            ));
        }
        let _ = sender_did; // named for API symmetry with process_incoming.
        Ok((sender_key, epoch))
    }

    /// ADR-049 PR-6 (read-authority switch): install an AUTHENTICATED sender
    /// key WITHOUT epoch gating.
    ///
    /// The epoch monotonicity + poisoning ceiling are enforced by the
    /// authoritative Class-M floor registry at the messaging seam BEFORE the key
    /// is installed here (gate-before-install = fail-safe). This is the install
    /// half of the decomposed [`Self::process_incoming_sender_key`] push path: a
    /// thin wrapper over [`SenderKeyStore::set_unchecked`].
    ///
    /// A no-op when no crypto state is resident for `context_id`. In the
    /// production seam the context is guaranteed present (the enclosing
    /// `decrypt_and_dispatch` already MLS-opened against it), so the no-op branch
    /// is unreachable there; the registry gate has already advanced the floor,
    /// so even a (hypothetical) missing-context skip is fail-safe (the floor
    /// advanced, no key below it can ever be admitted).
    ///
    /// # ADR-049 PR-7 — test/fixture-only
    ///
    /// The steady-state install moved onto the actor; production is zero-grep
    /// clean of this provider copy. Retained under
    /// `#[cfg(any(test, feature = "testing"))]` solely for provider-level
    /// two-party test fixtures.
    #[cfg(any(test, feature = "testing"))]
    pub fn set_sender_key_unchecked(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        sender_key: SenderKey,
    ) {
        let ctx_id_hex = hex::encode(context_id);
        // ADR-049 §15: lock-free `DashMap::get_mut`.
        if let Some(mut entry) = self.contexts.get_mut(context_id) {
            entry
                .value_mut()
                .sender_key_store
                .set_unchecked(&ctx_id_hex, sender_did, sender_key);
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
    /// # ADR-049 PR-7 — test/fixture-only
    ///
    /// The steady-state ANSWER half of §9.16.2 was MOVED onto the actor
    /// ([`ContextCryptoState::handle_sender_key_request`](crate::context::actor::state::ContextCryptoState::handle_sender_key_request));
    /// this provider copy is RETAINED under `#[cfg(any(test, feature =
    /// "testing"))]` as a **test FIXTURE builder** — it stands up the
    /// provider-side answer for the two-party join fixtures
    /// (`two_party_test_support`,
    /// `spawn_from_welcome_tests`) that must return providers still OWNING their
    /// per-context crypto. Production is zero-grep clean of this method — a taken
    /// (actor-owned) context answers on the actor, not here. It is NOT a wire
    /// authority: there is **no byte-for-byte-sync obligation** with the actor
    /// method (the retired oracle-vs-actor comparison proved nothing the actor
    /// round-trip's ground-truth assert does not), so its serialization is not
    /// required to track the actor's `SenderKeyDistributionMessage` framing.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if signature verification,
    /// HPKE encryption, or serialization fails.
    #[cfg(any(test, feature = "testing"))]
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

        // ADR-049 §15: lock-free `DashMap::get_mut`.
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

        // H1: Blocked DID check — a blocked requester is silently dropped
        // (§9.16.2: no response). `Ok(None)` mirrors the actor method (and the
        // §9.16 free function) so the byte-identity oracle stays in step.
        if blocked_dids.contains(&request.requester_did) {
            return Ok(None);
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
        self.wrapping_keypair()
    }

    /// Returns a copy of this provider's node-resident X25519 wrapping keypair
    /// `(public, secret)` from a SINGLE atomic `ArcSwap` load (ADR-049 PR-7
    /// hardening H3). The public half is the HPKE recipient key advertised in
    /// the `0xFF01` wrapping leaf; the secret half opens sender keys sealed to
    /// this member and is returned in [`zeroize::Zeroizing`] so it zeroes on
    /// drop (no bare `[u8; 32]` secret escapes the provider).
    ///
    /// ADR-049 PR-7 prep B (SCP-CRYPTOMOVE-000b) / hardening H3: the Prep A
    /// per-context crypto methods on `PerContextState` take the node-resident
    /// wrapping keypair as a METHOD PARAMETER (never stored on
    /// `ContextCryptoState`). The atomic core actor-seeding path
    /// (SCP-CRYPTOMOVE-001) reads the keypair off the provider to hand it in.
    /// This SINGLE combined accessor supersedes the earlier two separate
    /// `wrapping_public_key()` / `wrapping_secret()` accessors: reading both
    /// halves through one `.load()` makes the pair atomic by construction, so a
    /// rotation can never pair a public of generation N with a secret of N+1.
    #[must_use]
    pub(crate) fn wrapping_keypair(&self) -> ([u8; 32], zeroize::Zeroizing<[u8; 32]>) {
        let guard = self.wrapping_keypair.load();
        (guard.public, zeroize::Zeroizing::new(*guard.secret))
    }

    /// Reconstructs the per-context MLS crypto MATERIAL from a persisted
    /// snapshot and RETURNS it as an owned [`OwnedMlsCryptoState`] plus the
    /// Class-M [`RestoredFloors`], WITHOUT inserting into the provider's
    /// `contexts` map and WITHOUT calling
    /// [`take_crypto_state`](Self::take_crypto_state).
    ///
    /// ADR-049 §15(b) / story SCP-CRYPTOMOVE-000d. This is the owned-return
    /// restore seam: the atomic core (SCP-CRYPTOMOVE-001) seeds the per-context
    /// actor directly from the returned material rather than reaching into a
    /// provider-resident `contexts[ctx]` entry. The legacy insert-based
    /// `restore_crypto_state` delegates here and
    /// re-wraps the result into the provider-internal `ContextCryptoState`; it
    /// is retained until the atomic core flips the call site.
    ///
    /// The returned [`OwnedMlsCryptoState`] is the PROVIDER-side owned mirror
    /// (§15 keeps it distinct from the actor-side `ContextCryptoState`); this
    /// method imports nothing from `context::actor`.
    ///
    /// # Side effect — node-level wrapping keypair
    ///
    /// The X25519 wrapping keypair (§9.16.1) is node-level, NOT per-context and
    /// NOT part of [`OwnedMlsCryptoState`]; the atomic-core actor reads it via
    /// the Prep B `pub(crate)` accessors
    /// ([`wrapping_keypair`](Self::wrapping_keypair)). This method restores it into
    /// the provider's `ArcSwap` slots here, in the same order the legacy insert
    /// path did (before the caller installs the per-context material), so both
    /// restore paths keep byte-parity.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if `data` is empty (the owned path
    /// must always yield material — unlike the legacy no-op-on-empty
    /// `restore_crypto_state`), if deserialization
    /// fails, or if the data is corrupt.
    pub(crate) fn build_restored_owned(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(OwnedMlsCryptoState, RestoredFloors), ContextError> {
        if data.is_empty() {
            return Err(ContextError::CryptoFailed(
                "cannot build owned crypto state from empty snapshot".into(),
            ));
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

        // ADR-049 PR-6: collect the per-sender epoch high-water marks for the
        // caller to merge into the authoritative Class-M registry, instead of
        // seeding a provider-side floor. The restored values are authoritative
        // high-water marks (not user-supplied receive traffic).
        //
        // `sender_key_epochs` can cover DIDs that no longer have a key entry
        // (e.g., removed members whose floor was preserved by
        // `SenderKeyStore::remove`) — those entries still matter for rollback
        // protection and are returned so the registry retains them.
        let had_epoch_map = !snapshot.sender_key_epochs.is_empty();
        let mut restored_sender_epochs: Vec<(String, u64)> =
            snapshot.sender_key_epochs.drain(..).collect();

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
            // provider), and the floor is enforced by the registry.
            sender_key_store.set_unchecked(&ctx_id_hex, &did, key);
            // Legacy-path only: contribute a floor from the global
            // `sender_key_epoch` if no per-sender map was persisted, so the
            // registry merge seeds a non-zero lower bound (closing the one-shot
            // post-upgrade rollback window).
            if let Some(floor) = legacy_floor {
                restored_sender_epochs.push((did, floor));
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

        // ADR-049 PR-6: return the durable-blob receive floors for the registry
        // sink instead of reconstructing a provider mirror. Explicit named-field
        // bind (never a tuple `.into()`, which would reintroduce the
        // epoch/sequence transposition hazard).
        let restored_recv_sequence: Vec<(String, ReceiveFloor)> = snapshot
            .recv_sequence_tracker
            .drain(..)
            .map(|(did, epoch, sequence)| (did, ReceiveFloor { epoch, sequence }))
            .collect();

        let owned = OwnedMlsCryptoState {
            mls_group: scp_group,
            sender_key: local_sender_key,
            sender_key_store,
            sender_key_epoch: snapshot.sender_key_epoch,
            send_sequence: snapshot.send_sequence,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys,
        };

        // Restore the provider-level (node-level) X25519 wrapping keypair
        // before returning the owned material to the caller (the legacy
        // `restore_crypto_state` path installs that material into the contexts
        // map immediately after; the atomic core seeds the actor from it). This
        // preserves the original ordering — the keypair rotates before any
        // per-context entry becomes observable — so a reader never sees a
        // partial pairing of new wrapping key with stale context state.
        //
        // ADR-049 PR-7 hardening H3: the wrapping keypair is a SINGLE
        // `ArcSwap<WrappingKeypair>` slot, so the public and secret halves
        // rotate in ONE atomic `.store()` — an in-flight reader always sees a
        // consistent pair (either old/old or new/new). This closes the
        // prior two-store window where one slot could be observed rotated
        // while the other lagged.
        //
        // Legacy snapshots (pre-wrapping-key persistence) have default
        // [0u8; 32] — skip restore in that case to keep the fresh keypair.
        if snapshot.wrapping_public_key != [0u8; 32] && snapshot.wrapping_secret_key.len() == 32 {
            // SECURITY: Wrap the intermediate secret in Zeroizing so it is
            // zeroed on drop even if a `?` return occurs below.
            let mut secret = Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(&snapshot.wrapping_secret_key);

            self.wrapping_keypair.store(Arc::new(WrappingKeypair {
                public: snapshot.wrapping_public_key,
                secret: Zeroizing::new(*secret),
            }));
        }

        // SECURITY: Zeroize the wrapping secret key bytes remaining in the
        // snapshot. The key has been copied into the Zeroizing<[u8; 32]> guard
        // above (or skipped for legacy snapshots), so this intermediate Vec
        // should not retain raw X25519 secret key material.
        snapshot.wrapping_secret_key.zeroize();

        // H2 / CM-006 (ADR-049 PR-7): this method hands the per-context crypto
        // material OUT to seed an actor's `PerContextState` (welcome / restore /
        // respawn / cold-restart), WITHOUT ever installing it into
        // `self.contexts`. Record the context in `taken_context_ids` so the
        // one-way take invariant holds on the seed path too: a subsequent
        // provider `create_group_into_slot` / `install_joined_group` /
        // `generate_sender_key` for this id now fails closed ("owned by actor")
        // instead of finding a Vacant-and-unmarked slot and resurrecting a
        // divergent second group (the double-owner vector). Idempotent on a warm
        // respawn where `take_crypto_state` already marked the id.
        self.taken_context_ids.insert(*context_id);

        Ok((
            owned,
            RestoredFloors {
                sender_epochs: restored_sender_epochs,
                recv_sequence: restored_recv_sequence,
            },
        ))
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

    // ADR-049 PR-6 (read-authority switch): the provider `export_sender_key_epochs`
    // and single-sender `sender_key_epoch` follower-read twins are DELETED. The
    // authoritative per-sender epoch floors now live in — and are read from — the
    // Supervisor-owned Class-M registry (`Supervisor::export_sender_key_epochs`).

    /// Returns this provider's local member DID — the key under which the local
    /// sender's epoch is recorded in the authoritative floor registry, and the
    /// value the recv seam's F-3 `debug_assert_ne!` checks against. `pub(crate)` —
    /// internal read with no FFI surface.
    #[must_use]
    pub(crate) fn local_did(&self) -> &str {
        &self.local_did
    }

    // ADR-049 PR-6 (read-authority switch): the provider `validate_and_merge_epoch_floors`,
    // `export_recv_sequence_floors`, and `validate_and_merge_recv_sequence_floors` twins are
    // DELETED. The authoritative floors now live in the Supervisor-owned Class-M registry,
    // whose `validate_and_merge_*` sinks (`context/supervisor/floors.rs`) enforce the same
    // §23.17.2 Inv-2/Inv-3/Inv-4 + epoch-poisoning-overshoot merge; the restore/import guard
    // routes the snapshot floors there via the returned `RestoredFloors`.
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

    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the 11 provider steady-state crypto
    // methods (seal/open/advance_epoch/rotate_sender_key/remove_member/
    // remove_member_sender_key/mls_encrypt_management/local_sender_key_epoch/
    // export_crypto_state/restore_crypto_state/drain_pending_sender_key_messages)
    // were RELOCATED onto the actor's `PerContextState`. The provider retains
    // only the birth/restore machinery (`create_mls_group[_with_context]`,
    // `add_member`, `take_crypto_state`, `build_restored_owned`, `with_context`,
    // `wrapping_keypair`, `destroy_*`, `validate_key_package`) plus the
    // receive-side primitives (`distribute_sender_key`,
    // `process_incoming_sender_key`, `set_sender_key_unchecked`,
    // `store_member_sender_key`). The helpers below drive the relocated actor
    // seam so this module's coverage of the snapshot format, the one-way take,
    // and the retained per-context restore reader survives the move. Byte-parity
    // between the provider receiver and the actor seal/open path is pinned by the
    // `golden_*` cross-roundtrip tests in `context::actor::state`'s test module.
    use crate::context::actor::PerContextState;
    use scp_did::DID;

    /// Destructively move a provider-resident context onto a throwaway actor
    /// [`PerContextState`] (Encrypted mode) holding byte-identical crypto
    /// material, via the retained `take_crypto_state` + the production
    /// `seed_encrypted_crypto_from_owned` seed primitive. The provider loses the
    /// context (one-way take, ADR-049 PR-7 CM-001), so a caller that still needs
    /// to read the source provider must capture what it needs first.
    fn take_into_actor(provider: &MlsCryptoProvider, ctx: &[u8; 32]) -> PerContextState {
        let owned = provider
            .take_crypto_state(ctx)
            .expect("take owned crypto material");
        let mut state =
            PerContextState::new_for_test_encrypted(*ctx, 0, DID::from(provider.local_did.clone()));
        state.seed_encrypted_crypto_from_owned(owned);
        state
    }

    /// Export a provider-resident context through the relocated
    /// [`PerContextState::export_crypto_state`] seam, sourcing the node-resident
    /// wrapping keypair (public + secret) from the provider exactly as the
    /// production actor-export caller does. Destructive (see [`take_into_actor`]).
    fn actor_export(
        provider: &MlsCryptoProvider,
        ctx: &[u8; 32],
        sender_key_epochs: Vec<(String, u64)>,
        recv_sequence_floors: Vec<(String, ReceiveFloor)>,
    ) -> Result<Vec<u8>, ContextError> {
        let (wpub, wsec) = provider.wrapping_keypair();
        let state = take_into_actor(provider, ctx);
        state.export_crypto_state(sender_key_epochs, recv_sequence_floors, wpub, &*wsec)
    }

    /// Borrow the Encrypted-mode crypto sub-state of an actor `PerContextState`
    /// (panics on Broadcast) — the actor-seam analogue of the provider's
    /// `with_context` closure, for tests that inspect the live MLS group / stores.
    fn actor_crypto(state: &PerContextState) -> &crate::context::actor::ContextCryptoState {
        match &state.mode {
            crate::context::actor::ContextModeState::Encrypted(crypto) => crypto,
            crate::context::actor::ContextModeState::Broadcast(_) => {
                panic!("expected encrypted mode")
            }
        }
    }

    /// Mutable sibling of [`actor_crypto`] — hands out the `&mut ContextCryptoState`
    /// that the field-granular Class-C send/receive seams (e.g.
    /// `ContextCryptoState::seal` / `build_encrypted_envelope_actor`) operate on.
    fn actor_crypto_mut(
        state: &mut PerContextState,
    ) -> &mut crate::context::actor::ContextCryptoState {
        match &mut state.mode {
            crate::context::actor::ContextModeState::Encrypted(crypto) => crypto,
            crate::context::actor::ContextModeState::Broadcast(_) => {
                panic!("expected encrypted mode")
            }
        }
    }

    /// ADR-049 PR-7 prep B (SCP-CRYPTOMOVE-000b) / hardening H3: the single
    /// `pub(crate)` `wrapping_keypair()` accessor that the atomic core
    /// actor-seeding path (SCP-CRYPTOMOVE-001) reads must return a
    /// self-consistent `(public, secret)` pair from ONE atomic `ArcSwap` load,
    /// stable across repeated calls, and must observe the SAME node-resident
    /// keypair as the test-gated
    /// [`MlsCryptoProvider::wrapping_keypair_snapshot`] ground truth. Also pins
    /// the contract that the secret half returns `Zeroizing` (no bare
    /// `[u8; 32]` secret escapes the provider) via a load-bearing type witness.
    #[test]
    fn wrapping_keypair_single_load_matches_snapshot_and_secret_is_zeroizing() {
        let provider = make_provider();

        // Ground truth: the identity-level wrapping keypair as the test-gated
        // snapshot reports it (which now delegates to `wrapping_keypair`).
        let (snap_pub, snap_sec) = provider.wrapping_keypair_snapshot();

        // The single combined accessor returns the SAME pair, and is stable
        // across repeated calls (no torn read between the two halves).
        let (pub1, sec1) = provider.wrapping_keypair();
        let (pub2, sec2) = provider.wrapping_keypair();
        assert_eq!(pub1, pub2, "wrapping_keypair() public half must be stable");
        assert_eq!(
            *sec1, *sec2,
            "wrapping_keypair() secret half must be stable"
        );
        assert_eq!(
            pub1, snap_pub,
            "wrapping_keypair() public must match the snapshot"
        );
        assert_eq!(
            *sec1, *snap_sec,
            "wrapping_keypair() secret must match the snapshot"
        );

        // Type witness: the secret half is `Zeroizing<[u8; 32]>`, not a bare
        // secret. This binding is load-bearing — it fails to compile if the
        // signature ever regresses to a plain `[u8; 32]`.
        let _sec_witness: zeroize::Zeroizing<[u8; 32]> = sec1;
    }

    /// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): a normal sender-key rotation on the
    /// actor's `PerContextState` advances the local sender-key epoch by exactly
    /// one (§9.16.4/§9.16.5, relocated verbatim from the deleted provider
    /// `rotate_sender_key`).
    ///
    /// COVERAGE FLAG (orchestrator / atomic-core): the §15(c) fault-INJECTION
    /// half of the former `arm_rotation_failure_once_forces_fail_closed_then_normal`
    /// is NOT relocated here. `arm_rotation_failure_once` / `force_rotation_failure`
    /// are provider-resident, and the deleted provider `rotate_sender_key` was
    /// their ONLY consumer — the actor `rotate_sender_key` (state.rs) does not read
    /// the flag. Restoring the Class-S fail-closed injection coverage requires
    /// re-homing that one-shot fault seam onto the actor rotate (a `state.rs`
    /// change, per the Prep-E carry-forward) and asserting it as an atomic-core
    /// test (map C8 "Class-S rotation fail-closed via Prep-E `arm_rotation_failure_once`").
    #[test]
    fn rotate_sender_key_advances_epoch_on_actor() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let mut actor = take_into_actor(&provider, &ctx_id);
        let epoch_before = actor.local_sender_key_epoch();

        // A normal rotation persists a fresh key and advances the epoch by one.
        actor.rotate_sender_key(TEST_DID).unwrap();
        assert_eq!(
            actor.local_sender_key_epoch(),
            epoch_before + 1,
            "rotation must advance the epoch by exactly one"
        );
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

        // Remove Bob through the relocated actor seam (member removal moved onto
        // `PerContextState::remove_member`).
        let mut actor = take_into_actor(&provider, &ctx_id);
        let result = actor.remove_member(TEST_DID, bob_did);
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
        // does not produce a Commit for its own departure. Relocated onto the
        // actor `remove_member` seam.
        let mut actor = take_into_actor(&provider, &ctx_id);
        let output = actor.remove_member(TEST_DID, TEST_DID).unwrap();
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

        // Epoch advance moved onto `PerContextState::advance_epoch`, which sources
        // the node-resident wrapping public key as a parameter.
        let (wpub, _wsec) = provider.wrapping_keypair();
        let mut actor = take_into_actor(&provider, &ctx_id);
        let output = actor.advance_epoch(wpub);
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

        // Removal moved onto the actor seam; drive it there and inspect the
        // resulting live MLS group on the actor state.
        let mut actor = take_into_actor(&provider, &ctx_id);
        actor.remove_member(alice_did, bob_did).unwrap();

        {
            let group = actor_crypto(&actor)
                .mls_group
                .as_ref()
                .expect("group present");
            assert_eq!(group.epoch().unwrap(), 2);
            let members = group.members().unwrap();
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

        // Per-member sender-key removal moved onto the actor seam.
        let mut actor = take_into_actor(&provider, &ctx_id);
        assert!(actor.remove_member_sender_key(TEST_DID).is_ok());
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
        // Relocated onto the actor seam: the provider's "no context registered"
        // error becomes the actor's mode guard — a context with no MLS group
        // (Broadcast mode, `encrypted_crypto_mut` → CryptoFailed) rejects a
        // per-member sender-key removal.
        let mut actor = PerContextState::new_for_test_broadcast(
            make_context_id(),
            0,
            DID::from(TEST_DID.to_owned()),
        );
        assert!(actor.remove_member_sender_key("did:dht:z6MkBob").is_err());
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
        // via a Commit from the group admin (#1294). Relocated onto the actor
        // `remove_member` seam.
        let mut actor = take_into_actor(&provider, &ctx_id);
        let result = actor.remove_member(TEST_DID, TEST_DID);
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
            Some(provider.wrapping_keypair.load().public),
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

        // Draining the queued distribution moved onto the actor seam.
        let mut alice_actor = take_into_actor(&alice_provider, &ctx_id);
        let pending = alice_actor.drain_pending_sender_key_messages().unwrap();
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

        // Bob had no wrapping key, so nothing was queued — draining (on the actor
        // seam) yields an empty queue.
        let mut actor = take_into_actor(&provider, &ctx_id);
        let pending = actor.drain_pending_sender_key_messages().unwrap();
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
        let bob_wrapping_pk = bob_provider.wrapping_keypair.load().public;
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

        // Capture Alice's local sender key before moving her context onto an
        // actor to drain the queued distribution (the drain seam moved to the
        // actor). The provider loses the context on take, so read it first.
        let alice_sender_key_bytes = {
            let entry = alice_provider.contexts.get(&ctx_id).unwrap();
            *entry.value().sender_key.as_bytes()
        };
        let mut alice_actor = take_into_actor(&alice_provider, &ctx_id);
        let pending = alice_actor.drain_pending_sender_key_messages().unwrap();
        assert_eq!(pending.len(), 1);

        // ADR-049 PR-6: process returns the authenticated (key, epoch) WITHOUT
        // installing; install it via set_sender_key_unchecked (the floor gate is
        // the registry's job at the messaging seam).
        let (recovered_key, _epoch) = bob_provider
            .process_incoming_sender_key(&ctx_id, TEST_DID, &pending[0].1)
            .unwrap();
        bob_provider.set_sender_key_unchecked(&ctx_id, TEST_DID, recovered_key);

        {
            let bob_entry = bob_provider.contexts.get(&ctx_id).unwrap();
            let bob_state = bob_entry.value();
            let ctx_hex = hex::encode(ctx_id);
            let alice_key = bob_state.sender_key_store.get(&ctx_hex, TEST_DID);
            assert!(
                alice_key.is_some(),
                "Bob must have Alice's sender key after processing distribution"
            );

            assert_eq!(
                alice_key.unwrap().as_bytes(),
                &alice_sender_key_bytes,
                "recovered key must match Alice's sender key"
            );
        }
    }

    #[test]
    fn drain_pending_sender_key_messages_clears_queue() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();

        // The target has no wrapping key, so distribution queues nothing.
        provider
            .distribute_sender_key(&ctx_id, "did:dht:z6MkBob")
            .unwrap();

        // Drain moved onto the actor seam; draining yields an empty queue and a
        // second drain leaves it empty (the take clears it).
        let mut actor = take_into_actor(&provider, &ctx_id);
        let pending = actor.drain_pending_sender_key_messages().unwrap();
        assert!(pending.is_empty());
        let pending = actor.drain_pending_sender_key_messages().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn drain_pending_sender_key_messages_errors_without_context() {
        // Relocated onto the actor seam: a context with no MLS group (Broadcast
        // mode) rejects the drain via the `encrypted_crypto_mut` mode guard.
        let mut actor = PerContextState::new_for_test_broadcast(
            make_context_id(),
            0,
            DID::from(TEST_DID.to_owned()),
        );
        assert!(actor.drain_pending_sender_key_messages().is_err());
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
        let bob_wrapping_pk = bob_provider.wrapping_keypair.load().public;
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
        // Relocated onto the actor seam (ADR-049 PR-7): an Encrypted
        // `PerContextState` with no seeded MLS group is the actor-side analogue
        // of a context the provider never created — its
        // `export_crypto_state` returns an empty blob (Ok, not an error).
        let unknown_ctx = [0xFFu8; 32];
        let state =
            PerContextState::new_for_test_encrypted(unknown_ctx, 0, DID::from(TEST_DID.to_owned()));
        let (wpub, wsec) = make_provider().wrapping_keypair();
        let exported = state
            .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
            .unwrap();
        assert!(
            exported.is_empty(),
            "should return empty Vec for a context with no MLS group"
        );
    }

    // NOTE (ADR-049 PR-7): the former `restore_crypto_state_noop_on_empty_data`
    // pinned the DELETED provider insert-path `restore_crypto_state`'s
    // empty-data-is-a-silent-`Ok(default)` behavior. The relocated restore
    // reader is the owned-return `build_restored_owned`, whose empty-snapshot
    // contract is the OPPOSITE (a hard `CryptoFailed` error — the actor seed
    // path must always yield material) and is pinned by
    // `build_restored_owned_rejects_empty_snapshot`. There is no surviving
    // insert-path no-op to test, so this test is intentionally not relocated.

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

        // Export crypto state through the relocated actor seam (destructive
        // take of the provider-resident material).
        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();
        assert!(!exported.is_empty(), "exported state should be non-empty");

        // Rebuild the owned material on a fresh provider via the RETAINED restore
        // reader (`build_restored_owned`), then seed an actor and verify the
        // round-trip is FUNCTIONAL (the seeded encrypted actor holds a live MLS
        // group + sender key) and byte-faithful. The full seal→open functional
        // round-trip across the restored group is pinned by
        // `context::actor::state`'s `golden_seal_open_cross_roundtrip` (which
        // seals from a restored, seeded actor state).
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (owned, _floors) = provider2.build_restored_owned(&ctx_id, &exported).unwrap();

        // Verify sender key state is restored (on the owned material).
        {
            let state = &owned;
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

        // Functional coherence: seed a live actor from the restored material and
        // confirm it exposes a readable local sender-key epoch (Encrypted mode
        // with a live group + sender key). This is the actor-seam analogue of the
        // former "encrypt succeeds after restore" MLS-functional check.
        {
            let mut actor =
                PerContextState::new_for_test_encrypted(ctx_id, 0, DID::from(TEST_DID.to_owned()));
            actor.seed_encrypted_crypto_from_owned(owned);
            assert_eq!(
                actor.local_sender_key_epoch(),
                original_epoch,
                "seeded actor must expose the restored sender-key epoch"
            );
        }
    }

    /// ADR-049 PR-7 Prep D (SCP-CRYPTOMOVE-000d), AC4: `build_restored_owned`
    /// reconstructs the full per-context MATERIAL and returns it OWNED, with
    /// both floor axes, and WITHOUT inserting into `contexts` or recording a
    /// take. Anti-transposition: epoch and sequence land in the right
    /// `RestoredFloors` positions.
    #[test]
    fn build_restored_owned_returns_owned_material_without_insert() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);

        // Populate a rich snapshot: remote sender key, member wrapping key,
        // sender_key_epoch = 42.
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state.sender_key_epoch = 42;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob, generate_sender_key());
            state
                .member_wrapping_keys
                .insert(bob.to_owned(), [0xAA; 32]);
        }

        // Capture originals for comparison (bytes, so no Clone dependence).
        let (orig_local_key, orig_bob_key, orig_group_id) = {
            let entry = provider.contexts.get(&ctx_id).unwrap();
            let state = entry.value();
            (
                state.sender_key.as_bytes().to_vec(),
                state
                    .sender_key_store
                    .get(&ctx_id_hex, bob)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                state.mls_group.group_id().unwrap().to_vec(),
            )
        };

        // Export with BOTH floor axes populated: per-sender epoch (bob, 5) and
        // intra-epoch recv floor ReceiveFloor { epoch: 5, sequence: 3 }. Snapshot
        // is produced through the relocated actor export seam (destructive take;
        // the originals above were captured first).
        let exported = actor_export(
            &provider,
            &ctx_id,
            vec![(bob.to_owned(), 5)],
            vec![(
                bob.to_owned(),
                ReceiveFloor {
                    epoch: 5,
                    sequence: 3,
                },
            )],
        )
        .unwrap();
        assert!(!exported.is_empty());

        // Fresh provider: build the owned material (no insert, no take).
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (owned, floors) = provider2.build_restored_owned(&ctx_id, &exported).unwrap();

        // (a) Owned 8 fields match the snapshot. mls_group functional-equiv is
        // the group-id parity + a readable epoch.
        assert_eq!(owned.sender_key.as_bytes(), orig_local_key.as_slice());
        assert_eq!(owned.sender_key_epoch, 42);
        let owned_bob = owned
            .sender_key_store
            .get(&ctx_id_hex, bob)
            .map(|k| k.as_bytes().to_vec());
        assert_eq!(owned_bob, Some(orig_bob_key));
        assert_eq!(
            owned.member_wrapping_keys.get(bob).copied(),
            Some([0xAA; 32])
        );
        assert!(owned.pending_distributions.is_empty());
        assert_eq!(
            owned.mls_group.group_id().unwrap(),
            orig_group_id.as_slice()
        );
        assert!(owned.mls_group.epoch().is_ok());

        // (b) No `contexts` insert — the material is handed OUT, never installed.
        assert!(!provider2.contexts.contains_key(&ctx_id), "must NOT insert");
        // H2 / CM-006: the seed path DOES record the take, so a later provider
        // create/install/generate for this id fails closed instead of
        // resurrecting a divergent second group (double-owner).
        assert!(
            provider2.taken_context_ids.contains(&ctx_id),
            "build_restored_owned must mark the context taken (CM-006)"
        );

        // (c) Floors match on BOTH axes, epoch/sequence in the right positions.
        assert!(
            floors
                .sender_epochs
                .iter()
                .any(|(d, e)| d == bob && *e == 5),
            "per-sender epoch floor (bob, 5) must come back, got {:?}",
            floors.sender_epochs
        );
        let bob_recv = floors
            .recv_sequence
            .iter()
            .find(|(d, _)| d == bob)
            .map(|(_, f)| (f.epoch, f.sequence))
            .expect("bob's recv floor must come back");
        assert_eq!(
            bob_recv,
            (5, 3),
            "recv floor (epoch=5, seq=3), no transposition"
        );
    }

    // NOTE (ADR-049 PR-7): the former `build_restored_owned_matches_insert_path_parity`
    // asserted that the DELETED insert path (`restore_crypto_state`) and the
    // owned-return path (`build_restored_owned`) reconstruct byte-identical
    // material + set-equal floors from one snapshot. With the insert path gone
    // there is no second path to compare against — `build_restored_owned` is now
    // the sole restore reader. Its full 8-field + both-floor-axes reconstruction
    // (with the anti-transposition checks the parity test carried) is pinned
    // directly by `build_restored_owned_returns_owned_material_without_insert`.

    /// ADR-049 PR-7 Prep D (SCP-CRYPTOMOVE-000d), D2 cold-restart replay:
    /// a legacy snapshot with NO per-sender epoch map must yield the legacy
    /// back-compat floor (`sender_key_epoch.max(1)` per installed sender) on the
    /// owned restore reader — pinning that the owned seam does not weaken the D2
    /// rollback floor. (The former insert-path counterpart, `restore_crypto_state`,
    /// is deleted; `build_restored_owned` is now the sole restore reader.)
    #[test]
    fn build_restored_owned_yields_legacy_floor_parity() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            let state = entry.value_mut();
            state.sender_key_epoch = 7;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob, generate_sender_key());
        }
        // Simulate a legacy snapshot: export through the relocated actor seam,
        // then strip the per-sender map.
        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider_b = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (_owned_b, floors_b) = provider_b
            .build_restored_owned(&ctx_id, &legacy_bytes)
            .unwrap();

        // The owned path seeds bob's legacy floor from the global counter (7).
        assert!(
            floors_b
                .sender_epochs
                .iter()
                .any(|(did, epoch)| did == bob && *epoch == 7),
            "owned path must seed the legacy floor (7) for the installed sender, got {:?}",
            floors_b.sender_epochs
        );
    }

    /// ADR-049 PR-7 Prep D (SCP-CRYPTOMOVE-000d): the owned path must always
    /// yield material, so an empty snapshot is an ERROR (unlike the legacy
    /// `restore_crypto_state`, whose empty-data no-op still returns
    /// `Ok(default)` — see `restore_crypto_state_noop_on_empty_data`).
    #[test]
    fn build_restored_owned_rejects_empty_snapshot() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        let err = provider
            .build_restored_owned(&ctx_id, &[])
            .expect_err("empty snapshot must be rejected on the owned path");
        assert!(
            matches!(err, ContextError::CryptoFailed(_)),
            "empty owned-restore must fail with CryptoFailed, got {err:?}"
        );
    }

    /// Prep-D pass-through pin (ADR-049 PR-6): the floors that
    /// `export_crypto_state` now takes as parameters must land in the exported
    /// snapshot exactly as the provider's own `export_sender_key_epochs` /
    /// `export_recv_sequence_floors` twins report them — the byte-preserving
    /// no-op that freezes the signature ahead of the atomic read-authority swap.
    ///
    /// Whole-blob byte equality across an export → restore → export cycle is NOT
    /// a sound assertion: `mls_storage_entries` and `member_wrapping_keys`
    /// serialize from `HashMap` iteration, whose order is nondeterministic, so
    /// the blob's byte layout legitimately varies run to run (the existing
    /// `export_restore_crypto_state_roundtrip` test asserts field/functional
    /// equality, not bytes, for the same reason). This test instead pins the one
    /// property Prep D actually changes — that the per-sender epoch floors and
    /// the intra-epoch `(epoch, sequence)` floors are threaded from the twins
    /// into the snapshot with no loss and no epoch/sequence transposition — by
    /// deserializing the blob and comparing those fields, as order-insensitive
    /// sets, against the twin outputs.
    #[test]
    fn export_crypto_state_floor_params_land_in_snapshot_verbatim() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let carol = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCa";

        // ADR-049 PR-6: floors are AUTHORITATIVE in the registry and threaded
        // into `export_crypto_state` as PARAMETERS (the provider no longer holds
        // an epoch/recv mirror). Pass explicit floor params and assert they land
        // in the durable snapshot blob verbatim, with epoch/sequence in the right
        // positions (no transposition).
        let sender_key_epochs = vec![(bob.to_owned(), 7u64), (carol.to_owned(), 2u64)];
        let recv_sequence_floors = vec![
            (
                bob.to_owned(),
                ReceiveFloor {
                    epoch: 7,
                    sequence: 3,
                },
            ),
            (
                carol.to_owned(),
                ReceiveFloor {
                    epoch: 2,
                    sequence: 9,
                },
            ),
        ];

        let exported =
            actor_export(&provider, &ctx_id, sender_key_epochs, recv_sequence_floors).unwrap();
        assert!(!exported.is_empty(), "keyed context must export non-empty");

        let snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();

        // Sender-key epoch floors: blob field == params (as a set).
        let snap_epochs: std::collections::BTreeSet<(String, u64)> =
            snapshot.sender_key_epochs.iter().cloned().collect();
        assert_eq!(
            snap_epochs,
            std::collections::BTreeSet::from([(bob.to_owned(), 7), (carol.to_owned(), 2)]),
            "sender-key epoch floor params must land in the blob verbatim"
        );

        // Recv (epoch, sequence) floors: blob field == params (as a set), with
        // epoch and sequence in the right positions (no transposition).
        let snap_recv: std::collections::BTreeSet<(String, u64, u64)> =
            snapshot.recv_sequence_tracker.iter().cloned().collect();
        assert_eq!(
            snap_recv,
            std::collections::BTreeSet::from([(bob.to_owned(), 7, 3), (carol.to_owned(), 2, 9)]),
            "recv (epoch, sequence) floor params must land in the blob verbatim \
             with no epoch/sequence transposition"
        );
    }

    #[test]
    fn restore_preserves_sender_key_epoch_high_water_mark() {
        // Regression for #1608 rollback-protection across restart. ADR-049 PR-6:
        // the per-sender epoch floor survives the snapshot round-trip by being
        // RETURNED from `restore_crypto_state` in `RestoredFloors` (for the
        // authoritative Class-M registry to re-enforce), not by being re-seeded
        // into the provider store (the provider floor mirror is deleted). This
        // test pins the round-trip: a floor exported as the registry-sourced
        // param lands in the snapshot and comes back out of restore verbatim, and
        // the key MATERIAL is reinstalled so decryption still works.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);

        // Install Bob's key MATERIAL (the floor is carried by the registry and
        // passed as the export param, exactly as `build_snapshot_for_persist`
        // threads it).
        {
            let mut entry = provider.contexts.get_mut(&ctx_id).unwrap();
            entry.value_mut().sender_key_store.set_unchecked(
                &ctx_id_hex,
                bob_did,
                generate_sender_key(),
            );
        }

        // Export with the authoritative floor (epoch 5) as the param, through the
        // relocated actor export seam.
        let exported = actor_export(
            &provider,
            &ctx_id,
            vec![(bob_did.to_owned(), 5)],
            Vec::new(),
        )
        .unwrap();
        assert!(!exported.is_empty());

        // Restart: fresh provider, rebuild the owned material via the retained
        // restore reader. The floor comes back in RestoredFloors.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (owned, restored) = provider2.build_restored_owned(&ctx_id, &exported).unwrap();
        assert!(
            restored
                .sender_epochs
                .iter()
                .any(|(did, epoch)| did == bob_did && *epoch == 5),
            "the epoch-5 floor must survive the snapshot round-trip in RestoredFloors, \
             got {:?}",
            restored.sender_epochs
        );

        // The key MATERIAL is reinstalled (so decryption still works); the floor
        // itself is re-enforced by the registry once the caller merges
        // RestoredFloors (tested in the registry unit + cold-restart integration
        // tests).
        assert!(
            owned.sender_key_store.get(&ctx_id_hex, bob_did).is_some(),
            "restored material must reinstall Bob's key material"
        );
    }

    #[test]
    fn restore_preserves_epoch_floor_for_removed_members() {
        // A removed member's retained epoch floor must survive a restart so a
        // rejoining member cannot replay an earlier-epoch key. ADR-049 PR-6: the
        // floor is carried by the registry (no key material remains) and comes
        // back out of restore in `RestoredFloors` for the registry to re-enforce.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let carol_did = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCa";
        let ctx_id_hex = hex::encode(ctx_id);

        // Carol has NO key material (removed), but her floor (9) is retained in
        // the registry and exported as a param.
        let exported = actor_export(
            &provider,
            &ctx_id,
            vec![(carol_did.to_owned(), 9)],
            Vec::new(),
        )
        .unwrap();
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (owned, restored) = provider2.build_restored_owned(&ctx_id, &exported).unwrap();

        // The removed-member floor survives in RestoredFloors …
        assert!(
            restored
                .sender_epochs
                .iter()
                .any(|(did, epoch)| did == carol_did && *epoch == 9),
            "removed-member floor (9) must survive restart in RestoredFloors, got {:?}",
            restored.sender_epochs
        );
        // … and no key material reappears for the removed member.
        assert!(
            owned.sender_key_store.get(&ctx_id_hex, carol_did).is_none(),
            "removed key must not reappear after restore"
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

        // Export through the actor seam, then hand-edit the msgpack to drop the
        // epoch map.
        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (owned, restored) = provider2
            .build_restored_owned(&ctx_id, &legacy_bytes)
            .expect("legacy snapshot (empty epoch map) must restore cleanly");

        // The legacy snapshot had no per-sender epoch map, so restore seeds every
        // sender WITH KEY MATERIAL from the global `sender_key_epoch` counter (7)
        // as a conservative lower bound — RETURNED in RestoredFloors for the
        // registry, closing the one-shot rollback window.
        assert!(
            restored
                .sender_epochs
                .iter()
                .any(|(did, epoch)| did == bob_did && *epoch == 7),
            "legacy restore must seed the floor from the global counter (7) in \
             RestoredFloors, got {:?}",
            restored.sender_epochs
        );
        // Sanity: `ctx_id_hex` is still the store key for the reinstalled material.
        assert!(
            owned.sender_key_store.get(&ctx_id_hex, bob_did).is_some(),
            "legacy restore must reinstall Bob's key material"
        );
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

        // Export through the actor seam, then strip the per-sender epoch map to
        // simulate a legacy snapshot.
        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (_owned, restored) = provider2
            .build_restored_owned(&ctx_id, &legacy_bytes)
            .expect("legacy restore must succeed");

        // OBSERVED BEHAVIOR (ADR-049 PR-6): the peer's restored floor in
        // RestoredFloors equals the LOCAL sender_key_epoch counter (1), NOT the
        // true pre-snapshot peer floor (50). This is the documented residual
        // window bounded by MAX_EPOCH_ADVANCE in the receive path; fully closing
        // it would require a format break.
        let seeded = restored
            .sender_epochs
            .iter()
            .find(|(did, _)| did == peer_did)
            .map(|(_, epoch)| *epoch)
            .expect("peer with key material must be seeded a legacy floor");
        assert_eq!(
            seeded, 1,
            "legacy seed uses global sender_key_epoch (1), NOT the true peer floor (50)"
        );
        assert!(
            50 > seeded,
            "gap exists: true peer floor (50) > seeded floor ({seeded})"
        );
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

        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (owned, restored) = provider2
            .build_restored_owned(&ctx_id, &legacy_bytes)
            .unwrap();

        // ADR-049 PR-6: the legacy seed (max(global, 1)) is returned in
        // RestoredFloors, clamped to at least 1 when the global counter is 0.
        assert!(
            restored
                .sender_epochs
                .iter()
                .any(|(did, epoch)| did == bob_did && *epoch == 1),
            "legacy seed must clamp to at least 1 when global counter is 0, got {:?}",
            restored.sender_epochs
        );
        // `ctx_id_hex` keys the reinstalled material.
        assert!(owned.sender_key_store.get(&ctx_id_hex, bob_did).is_some());
    }

    #[test]
    fn export_fails_on_destroyed_group() {
        // Relocated onto the actor seam (ADR-049 PR-7): seed a live actor, confirm
        // it exports non-empty, then `destroy_mls_group` on the actor and confirm
        // the export goes empty — destroying the group clears exportability.
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let (wpub, wsec) = provider.wrapping_keypair();
        let mut actor = take_into_actor(&provider, &ctx_id);
        assert!(
            !actor
                .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
                .unwrap()
                .is_empty(),
            "live group must export non-empty state"
        );

        actor.destroy_mls_group().unwrap();

        // After destroy, export should return empty (no MLS group).
        let exported = actor
            .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
            .unwrap();
        assert!(
            exported.is_empty(),
            "destroyed group should export empty state"
        );
    }

    #[test]
    fn restore_rejects_corrupt_data() {
        let provider = make_provider();
        let ctx_id = make_context_id();

        // The relocated restore reader is `build_restored_owned`; corrupt bytes
        // must fail to deserialize.
        let result = provider.build_restored_owned(&ctx_id, b"not valid msgpack");
        assert!(result.is_err(), "corrupt data should fail");
    }

    #[test]
    fn restore_idempotent_on_same_context() {
        let provider = make_provider();
        let ctx_id = make_context_id();
        provider.create_mls_group(&ctx_id).unwrap();
        provider.generate_sender_key(&ctx_id).unwrap();

        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();

        // Rebuild the owned material on a fresh provider twice — the second call
        // must also yield working material (owned-return path, no insert to
        // clobber). Seed an actor from the second result and confirm it is a
        // coherent live encrypted state.
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (_owned1, _f1) = provider2.build_restored_owned(&ctx_id, &exported).unwrap();
        let (owned2, _f2) = provider2.build_restored_owned(&ctx_id, &exported).unwrap();

        let mut actor =
            PerContextState::new_for_test_encrypted(ctx_id, 0, DID::from(TEST_DID.to_owned()));
        actor.seed_encrypted_crypto_from_owned(owned2);
        // A coherent restored state exposes a readable local sender-key epoch.
        let _ = actor.local_sender_key_epoch();
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

        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();

        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let (owned, _floors) = provider2.build_restored_owned(&ctx_id, &exported).unwrap();

        // Verify epoch is preserved on the restored owned material.
        let epoch_after = owned.mls_group.epoch().unwrap();

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
        let original_public = provider.wrapping_keypair.load().public;
        let original_secret: [u8; 32] = *provider.wrapping_keypair.load().secret;

        // Sanity: the keypair should not be all zeros.
        assert_ne!(
            original_public, [0u8; 32],
            "wrapping public key must not be zero"
        );
        assert_ne!(
            original_secret, [0u8; 32],
            "wrapping secret key must not be zero"
        );

        // Export the crypto state through the relocated actor seam.
        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();
        assert!(!exported.is_empty());

        // Create a fresh provider (simulates restart — gets a NEW random keypair).
        let provider2 = MlsCryptoProvider::new(TEST_DID.to_string(), Arc::new(SystemClock));
        let fresh_public = provider2.wrapping_keypair.load().public;
        assert_ne!(
            fresh_public, original_public,
            "fresh provider should have a DIFFERENT wrapping public key"
        );

        // Rebuild the owned material on the fresh provider. `build_restored_owned`
        // restores the node-resident wrapping keypair into the provider's
        // ArcSwap slots as a documented side effect (ADR-049 PR-7 OBS-2), which
        // is exactly the persistence property this test pins.
        let _ = provider2.build_restored_owned(&ctx_id, &exported).unwrap();

        // After restore, the wrapping keypair must match the ORIGINAL, not the fresh one.
        let restored_public = provider2.wrapping_keypair.load().public;
        let restored_secret: [u8; 32] = *provider2.wrapping_keypair.load().secret;

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
    /// The actor seal/open seam (`PerContextState::open`) does not verify inner
    /// signatures — signature verification is deferred to the receive/dispatch
    /// path — so an arbitrary key suffices for the H9 receive-ceiling tests.
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

    fn ctx_routing_id(context_id: &[u8; 32]) -> Vec<u8> {
        // Any 32-byte routing id satisfies `create_outer_envelope`'s
        // length check; the open() path does not validate routing_id.
        context_id.to_vec()
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

        // Seal/open moved onto the actor seam: move each party's provider-resident
        // crypto onto an actor and drive the relocated
        // `PerContextState::seal` / `PerContextState::open`.
        let mut alice_actor = take_into_actor(&alice, &ctx_id);
        let mut bob_actor = take_into_actor(&bob, &ctx_id);

        // Two independently-sealed messages. MLS forward secrecy deletes the
        // per-message decryption secret on the FIRST `open` of a given
        // ciphertext, so the negative and positive cases must each consume
        // their own freshly-sealed blob — re-opening one blob twice would fail
        // at the MLS layer for an unrelated (forward-secrecy) reason.
        let inner1 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
        let inner2 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 1);
        let sealed_neg = alice_actor
            .seal(&alice_did, &inner1, &routing_id, 300)
            .unwrap();
        let sealed_pos = alice_actor
            .seal(&alice_did, &inner2, &routing_id, 300)
            .unwrap();

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
        bob_actor
            .open(&SystemClock, &hex_ctx, &sealed_neg)
            .expect_err(
                "opening with hex(ctx_id) as the AAD source must fail — the message was sealed \
             under the RAW context_id string, so the rebuilt AAD does not authenticate",
            );

        // Positive: opening the second blob with the RAW context_id string
        // (the spec value) succeeds, proving the AAD binds the raw string.
        let opened = bob_actor
            .open(&SystemClock, TEST_CTX_STR, &sealed_pos)
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
        // Seal/open moved onto the actor seam; drive the relocated open.
        let mut bob_actor = take_into_actor(&bob, &ctx_id);

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
        let err = bob_actor
            .open(&SystemClock, mismatched_ctx_str, &bogus_outer)
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
        // Seal moved onto the actor seam; drive the relocated seal on the
        // actor whose `context_id` is the real `ctx_id` (so the live MLS group +
        // sender key from setup are present).
        let mut alice_actor = take_into_actor(&alice, &ctx_id);

        // The keying context is the REAL `ctx_id`, but the inner envelope binds
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
        let err = alice_actor
            .seal(&alice_did, &inner, &routing_id, 300)
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

    // -----------------------------------------------------------------
    // ADR-049 PR-7 — `take_crypto_state` tests
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

    // NOTE (ADR-049 PR-7): the former `seal_after_take_returns_owned_by_actor`
    // and `open_after_take_returns_owned_by_actor` asserted that the provider
    // `seal` / `open` paths return `CryptoFailed("context state owned by actor")`
    // once a context's crypto has been moved into the actor. The provider `seal`
    // and `open` methods are now DELETED, so "no provider seal/open on a taken
    // context" is enforced by the TYPE SYSTEM (the calls no longer compile) — the
    // strongest possible form of the invariant. The surviving fail-closed
    // guarantee on the RETAINED provider write/read paths after a take is pinned
    // by `with_context_distinguishes_never_created_from_taken` (the read path →
    // "owned by actor") and `taken_context_write_paths_fail_closed`
    // (create_mls_group / install_joined_group / generate_sender_key → "owned by
    // actor"). No provider seal/open path survives to relocate these two onto.

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

    /// H2 (ADR-049 PR-7 hardening): once a context's crypto state has been
    /// moved into the actor via `take_crypto_state`, the three provider
    /// `contexts` write paths — `create_mls_group` (→ `create_group_into_slot`),
    /// `install_joined_group`, and `generate_sender_key` — MUST fail closed
    /// with the actionable "owned by actor" error. `take_crypto_state` removes
    /// the entry from `contexts`, so WITHOUT the `taken_context_ids` guard the
    /// `Entry::Vacant` reservation (or the `get_mut` in `generate_sender_key`)
    /// would resurrect a divergent second group / silently mask the cause —
    /// the double-owner vector where provider and actor both seal.
    #[test]
    fn taken_context_write_paths_fail_closed() {
        let (alice, bob, ctx_id, _alice_did) = setup_alice_bob_two_party();

        // Borrow a well-formed MLS group from bob BEFORE taking alice's state
        // (used only to exercise `install_joined_group`; the H2 guard fires
        // before the group value is inspected).
        let bob_owned = bob.take_crypto_state(&ctx_id).unwrap();
        let borrowed_group = bob_owned.mls_group;

        // Move alice's crypto state into the actor — the context is now taken.
        let _owned = alice.take_crypto_state(&ctx_id).unwrap();

        // create_mls_group → create_group_into_slot: fail closed.
        match alice
            .create_mls_group(&ctx_id)
            .expect_err("create must fail closed on a taken context")
        {
            ContextCreationError::CreationFailed(msg) => {
                assert!(msg.contains("owned by actor"), "create msg: {msg}");
            }
            other => panic!("expected CreationFailed, got {other:?}"),
        }

        // install_joined_group: fail closed.
        match alice
            .install_joined_group(&ctx_id, borrowed_group)
            .expect_err("install must fail closed on a taken context")
        {
            ContextError::CreationFailed(msg) => {
                assert!(msg.contains("owned by actor"), "install msg: {msg}");
            }
            other => panic!("expected CreationFailed, got {other:?}"),
        }

        // generate_sender_key: fail closed with the actionable message (not the
        // generic "no MLS group" one).
        match alice
            .generate_sender_key(&ctx_id)
            .expect_err("generate_sender_key must fail closed on a taken context")
        {
            ContextCreationError::CreationFailed(msg) => {
                assert!(msg.contains("owned by actor"), "gen msg: {msg}");
            }
            other => panic!("expected CreationFailed, got {other:?}"),
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
        let (alice, _bob, ctx_id, alice_did) = setup_two_party_for_ctx_string(ctx_str);
        let clock: std::sync::Arc<dyn scp_clock::Clock> =
            std::sync::Arc::new(scp_clock::SystemClock);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sender = scp_did::DID(alice_did.clone());
        let recipients = app_data_recipients(ctx_str, &alice_did);

        // Send-path seal moved onto the actor: `build_encrypted_envelope_actor` is
        // the production app-data seal that zeroes the outer routing_id (§9.10.4).
        let mut alice_actor = take_into_actor(&alice, &ctx_id);
        let wire = crate::context::messaging_helpers::build_encrypted_envelope_actor(
            &clock,
            actor_crypto_mut(&mut alice_actor),
            &alice_did,
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
        let clock: std::sync::Arc<dyn scp_clock::Clock> =
            std::sync::Arc::new(scp_clock::SystemClock);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sender = scp_did::DID(alice_did.clone());
        let recipients = app_data_recipients(ctx_str, &alice_did);

        // Both seal (Alice) and open (Bob) move onto the actor seam.
        let mut alice_actor = take_into_actor(&alice, &ctx_id);
        let mut bob_actor = take_into_actor(&bob, &ctx_id);
        let wire = crate::context::messaging_helpers::build_encrypted_envelope_actor(
            &clock,
            actor_crypto_mut(&mut alice_actor),
            &alice_did,
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
        let opened = bob_actor.open(&SystemClock, ctx_str, &wire).unwrap();
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
        // trust_recovery_helpers / supervisor / lifecycle_helpers). Seal moved
        // onto the actor seam, which preserves whatever `routing_id` it is given.
        let control_rid = scp_protocol::context::context_routing_id(ctx_str);
        let mut alice_actor = take_into_actor(&alice, &ctx_id);
        let wire = alice_actor
            .seal(&alice_did, &inner, &control_rid, 300)
            .unwrap();

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
