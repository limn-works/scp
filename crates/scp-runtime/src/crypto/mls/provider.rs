//! Production `NodeMlsFactory` implementation backed by `OpenMLS`.
//!
//! [`NodeMlsFactory`] bridges the historical inherent API to the actor-era
//! [`MlsBackend`](super::backend::MlsBackend) and
//! [`HpkeBackend`](crate::crypto::hpke_backend::HpkeBackend) primitives.
//!
//! #2148 (ADR-049 birth-into-actor) — provider per-context-state DISSOLUTION.
//! The provider holds NO per-context state: the `contexts` / `broadcast_keys`
//! `DashMap`s and the `taken_context_ids` `DashSet` are DELETED. The provider is
//! now a node-level MLS-birth / HPKE helper — local DID, injected clock,
//! MLS/HPKE backends, and the node-resident X25519 wrapping keypair
//! (`ArcSwap<...>` for atomic rotation; §9.16.1). The birth constructors
//! ([`NodeMlsFactory::create_mls_group_with_context`],
//! [`NodeMlsFactory::install_joined_group`]) and the restore seam
//! ([`NodeMlsFactory::build_restored_owned`]) return
//! [`OwnedMlsCryptoState`] the CREATE / WELCOME / restore caller seeds onto the
//! spawning actor's `PerContextState` — the actor is the sole per-context crypto
//! authority. Removing the shared maps closes the #2167 cross-map TOCTOU by
//! construction; the supervisor registry's atomic first-writer-wins insert is
//! the sole double-birth guard.
//!
//! No `std::sync::Mutex` survives in this file (CI: `clippy.toml`'s
//! `disallowed-types` ban for `std::sync::Mutex` is enforced — every internal
//! datapath is lock-free).
//!
//! Inline `OpenMLS` calls in primitive paths route through the injected
//! [`MlsBackend`](super::backend::MlsBackend) so test harnesses can substitute
//! a fail-injecting backend via [`NodeMlsFactory::with_backends`].
//!
//! See ADR-001 for the MLS wrapper design and ADR-007 for sender keys; ADR-049
//! for the actor refactor + dissolution ladder.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

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
    /// [`build_restored_owned`](crate::crypto::mls::provider::NodeMlsFactory::build_restored_owned) does NOT call it:
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

// #2148 (ADR-049 birth-into-actor): the provider's private per-context
// `ContextCryptoState` struct was DELETED. The provider holds NO per-context
// state — the actor's `ContextCryptoState` (`context/actor/state.rs`) is the
// sole per-context crypto home. The provider's birth constructors
// (`create_mls_group_with_context`, `install_joined_group`) now assemble the
// `OwnedMlsCryptoState` payload below DIRECTLY and hand it back to the CREATE /
// WELCOME caller, which seeds it onto the spawning actor.

// ---------------------------------------------------------------------------
// OwnedMlsCryptoState — owned payload the birth/restore seams hand to the actor
// ---------------------------------------------------------------------------

/// Owned per-context MLS crypto state the provider's birth/restore seams hand
/// to a context's actor (#2148 ADR-049 birth-into-actor).
///
/// This is the boundary payload between the provider and the actor. The
/// provider births it DIRECTLY — [`NodeMlsFactory::create_mls_group_with_context`]
/// (CREATE), [`NodeMlsFactory::install_joined_group`] (WELCOME), and
/// [`NodeMlsFactory::build_restored_owned`] (restore / respawn / import) each
/// assemble one and return it — and the CREATE / WELCOME / restore caller seeds
/// it onto the spawning actor's `PerContextState` via
/// [`seed_encrypted_crypto_from_owned`](crate::context::actor::state::PerContextState::seed_encrypted_crypto_from_owned).
/// The provider holds NO per-context state: there is no `contexts` map, no
/// insert-then-take round-trip, and no cross-map check-then-insert to race
/// (#2167 TOCTOU is impossible by construction — the supervisor registry's
/// atomic first-writer-wins insert is the sole double-birth guard).
///
/// # Ownership — the actor owns crypto by move
///
/// This is the shipped steady state. Once seeded, the actor is the sole crypto
/// authority for the context; crypto is never handed back to the provider, so
/// there is no dual-home window and no provider-resident residency to guard.
///
/// # Why every field is `pub`
///
/// This type is a move payload, not a domain struct. The birth/restore seams
/// assemble it and the actor spawn seams destructure it field-by-field to build
/// the actor-side [`crate::context::actor::ContextCryptoState`].
///
/// `#[must_use]`: a birth path that binds-and-drops this payload without seeding
/// it (spawning an actor with `mls_group = None`) is a defect the compiler flags
/// here (#2148 F7).
#[must_use]
pub struct OwnedMlsCryptoState {
    /// The `OpenMLS` group handle for this context.
    pub mls_group: ScpMlsGroup,
    /// Local member's AES-256 sender key.
    pub sender_key: SenderKey,
    /// Per-member sender-key store.
    pub sender_key_store: SenderKeyStore,
    /// Sender-key epoch counter.
    pub sender_key_epoch: u64,
    /// Send-side sequence counter for this birth/restore payload. A fresh
    /// birth mints it at `0` (via [`OwnedMlsCryptoState::fresh_birth`],
    /// used by `create_mls_group_with_context` / `install_joined_group`);
    /// the restore seam (`build_restored_owned`) carries the persisted
    /// high-water value. There is NO provider `take` — the CREATE / WELCOME /
    /// restore caller seeds its actor-side
    /// [`crate::context::actor::SendSequenceTracker`] from this value via
    /// [`crate::context::actor::SendSequenceTracker::from_persisted`]
    /// (preserving AAD byte-identity — see
    /// `crates/scp-runtime/src/context/actor/sequence.rs`
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

impl OwnedMlsCryptoState {
    /// Assembles a freshly-born owned crypto payload from a just-created /
    /// just-joined [`ScpMlsGroup`] (#2148 F11). Mints the local AES-256 sender
    /// key ([`generate_sender_key`], spec §9.16.1) and defaults the seven
    /// identical fields every birth seam shares (`sender_key_epoch = 1`,
    /// `send_sequence = 0`, empty stores/maps). The distinct restore shape is
    /// built by [`NodeMlsFactory::build_restored_owned`], which is left
    /// unchanged.
    pub(crate) fn fresh_birth(mls_group: ScpMlsGroup) -> Self {
        Self {
            mls_group,
            sender_key: generate_sender_key(),
            sender_key_store: SenderKeyStore::new(),
            sender_key_epoch: 1,
            send_sequence: 0,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys: HashMap::new(),
        }
    }

    /// Best-effort teardown of a born-but-never-seeded payload's secrets on a
    /// creation-rollback path (#2148 F6). A bare drop FREES the group's
    /// in-memory `OpenMLS` storage but does NOT zeroize its epoch-secret bytes or
    /// the Ed25519 signer (`OpenMLS` `SignatureKeyPair` implements no `Zeroize` —
    /// `scp-mls` `EagerDropSigner` / issue #82); [`scp_mls::group::destroy_group`]
    /// eagerly FREES the signer's `Vec<u8>` via `EagerDropSigner::take` (freed,
    /// not overwritten — signer zeroization stays open upstream, #82). The
    /// [`SenderKey`] zeroizes on its own `ZeroizeOnDrop` when the payload drops.
    pub(crate) fn dispose_secrets(&mut self) {
        let _ = scp_mls::group::destroy_group(&mut self.mls_group);
    }
}

/// Per-context Class-M floors reconstructed from a persisted snapshot.
///
/// Returned by [`NodeMlsFactory::build_restored_owned`](crate::crypto::mls::provider::NodeMlsFactory::build_restored_owned) for the caller to
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
/// hardening H3). Stored behind a single [`ArcSwap`] on [`NodeMlsFactory`].
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
/// Create with [`NodeMlsFactory::new`], providing the local member's DID.
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
/// slot (see [`NodeMlsFactory::wrapping_keypair`]).
///
/// Renamed from `MlsCryptoProvider` in #2185: after #2148 (birth-into-actor)
/// this type holds NO per-context state - it is a node-level MLS-birth + HPKE
/// helper (node DID, injected clock, MLS/HPKE backends, node wrapping keypair);
/// per-context crypto lives on the actor's `PerContextState` by move.
pub struct NodeMlsFactory {
    /// The local member's DID (e.g., `"did:dht:z6Mk..."`).
    local_did: String,
    /// Injected hardened [`Clock`] (ADR-057 §Prereq-1). Used for the provider's
    /// direct `scp-mls` calls that mint or validate `KeyPackage` / group-leaf
    /// `Lifetime`s (create-group, generate-key-package, decrypt). In
    /// production this is the SAME `Arc` the actor-deps clock and the injected
    /// [`ProductionMlsBackend`] share — one hardened clock per node, never
    /// openmls's internal one.
    clock: Arc<dyn Clock>,
    /// Injected MLS primitive backend (ADR-049 §15). Production
    /// callers receive a [`ProductionMlsBackend`] from
    /// [`NodeMlsFactory::new`]; tests inject failure-driven mocks via
    /// [`NodeMlsFactory::with_backends`]. The provider's orchestration
    /// methods route every inline `OpenMLS` primitive through this trait —
    /// the factory itself holds no per-context state (post-#2148).
    mls_backend: Arc<dyn MlsBackend>,
    /// Injected HPKE primitive backend (ADR-049 §15). Same
    /// injection contract as `mls_backend` — production wires
    /// [`ProductionHpkeBackend`]; tests can substitute mocks for fail
    /// injection on the wrapping-key seal/unseal path.
    hpke_backend: Arc<dyn HpkeBackend>,
    // #2148 (ADR-049 birth-into-actor): the per-context `contexts` /
    // `broadcast_keys` maps and the `taken_context_ids` guard set were DELETED.
    // The provider holds NO per-context state — the actor's `PerContextState`
    // (`context/actor/state.rs`) is the sole per-context crypto home. Removing
    // the shared `contexts` / `taken_context_ids` maps also closes the #2167
    // cross-map TOCTOU by construction: there is no check-then-insert to race;
    // the supervisor registry's atomic first-writer-wins insert is the sole
    // double-birth guard. The provider is now a node-level MLS-birth / HPKE
    // helper (local DID, clock, MLS/HPKE backends, node wrapping keypair).
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
}

#[allow(clippy::significant_drop_tightening)]
impl NodeMlsFactory {
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

    /// Creates a `NodeMlsFactory` with caller-supplied backends.
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
            wrapping_keypair: ArcSwap::from_pointee(WrappingKeypair {
                public: wrapping_public_key,
                secret: Zeroizing::new(wrapping_secret_key),
            }),
        }
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

    // #2148 (ADR-049 birth-into-actor): `take_crypto_state` and `with_context`
    // were DELETED along with the `contexts` / `taken_context_ids` maps. The
    // provider no longer owns per-context state: the birth constructors return
    // `OwnedMlsCryptoState` directly and the actor is the sole per-context crypto
    // authority. There is no insert-then-take round-trip and no residency guard.

    /// Creates the SCP credential for the local member.
    fn make_credential(&self) -> Result<ScpCredential, ContextCreationError> {
        ScpCredential::new(self.local_did.clone(), None, SigningKeyId::Active)
            .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))
    }
}

#[allow(clippy::significant_drop_tightening)]
impl NodeMlsFactory {
    // #2148 (ADR-049 birth-into-actor): the `context_crypto_present` residency
    // probe was DELETED — the provider holds no per-context state, so there is no
    // residency to probe. Actor-owned crypto presence is asserted on the actor's
    // `PerContextState` (`context/actor/state.rs`).

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
        // the inherent `NodeMlsFactory` API. Production builds (no
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

    /// Births an MLS **context** group whose `group_context` binds the SCP
    /// context parameters via the `scp_context_params` (`0xFF02`) extension
    /// (spec §5.13.3, finding FFI-02), and returns it as OWNED material.
    ///
    /// #2148 (ADR-049 birth-into-actor): this is the production CREATE birth
    /// seam. It builds the context group through the `scp-mls` primitive
    /// ([`group::create_group_with_context`]) — the committed
    /// [`ScpContextExtension`](scp_protocol::context::ScpContextExtension) is
    /// folded into the MLS key schedule and read back byte-identically by every
    /// joiner (because the group carries `0xFF02`, `OpenMLS` (`valn0502`) rejects
    /// any Add whose leaf does not declare `0xFF02` support — pooled key packages
    /// MUST be generated via the context-params path, see
    /// [`MlsBackend::generate_key_package`](super::backend::MlsBackend::generate_key_package)) —
    /// mints the local sender key via [`generate_sender_key`], and assembles the
    /// [`OwnedMlsCryptoState`] payload DIRECTLY. It touches NO shared provider
    /// map (there is none): `builder::create_context` hands the returned payload
    /// to the caller, which seeds it onto the spawning actor's `PerContextState`.
    /// There is no overwrite-refusal / "owned by actor" residency guard here —
    /// the supervisor registry's atomic first-writer-wins insert is the sole
    /// double-birth guard (#2167 TOCTOU is impossible by construction).
    ///
    /// Takes NO `context_id`: the owned birth reserves no shared-map slot, so it
    /// needs no context key — the caller already holds the `context_id` it uses
    /// to key the spawning actor.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::CryptoFailed`] if credential creation or
    /// MLS group creation fails.
    pub fn create_mls_group_with_context(
        &self,
        context_extension: &scp_protocol::context::ScpContextExtension,
    ) -> Result<OwnedMlsCryptoState, ContextCreationError> {
        let credential = self.make_credential()?;
        // Load through ArcSwap; the guard is dropped as `.public` is `Copy`ed
        // into the stack array (load → copy → drop within the poll).
        let wrapping_pk = self.wrapping_keypair.load().public;
        let mls_group = group::create_group_with_context(
            &credential,
            &wrapping_pk,
            context_extension,
            self.clock.as_ref(),
        )
        .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))?;

        // Assemble the owned payload directly — the fresh MLS group + a
        // locally-minted sender key (no shared-map install).
        Ok(OwnedMlsCryptoState::fresh_birth(mls_group))
    }

    /// Births the joiner's crypto from an already-joined `OpenMLS` group and
    /// returns it as OWNED material (#2148 ADR-049 birth-into-actor,
    /// spawn-from-Welcome).
    ///
    /// This is the join-side counterpart of
    /// [`Self::create_mls_group_with_context`]: the creator BUILDS a fresh group,
    /// whereas a joiner has already produced its self-contained [`ScpMlsGroup`]
    /// by processing a received Welcome (through the fused
    /// `KeyPackageStoreActor::ConfirmConsume` → the `MlsBackend`'s
    /// consumed-init-key-backstopped `join_from_welcome`; it owns its own
    /// `OpenMLS` provider + signer). This constructor mints the joiner's OWN
    /// AES-256 sender key LOCALLY via [`generate_sender_key`] (spec §9.16.1 — the
    /// Welcome carries no sender key), assembles the [`OwnedMlsCryptoState`]
    /// payload DIRECTLY (moving the joined `group` in verbatim), and returns it
    /// for the WELCOME seam (`Supervisor::spawn_actor_from_welcome`) to seed onto
    /// the spawning actor. It touches NO shared provider map (there is none):
    /// no residency guard, no double-owner window — the supervisor registry's
    /// atomic first-writer-wins insert is the sole double-birth guard.
    ///
    /// Cannot fail: it reserves no slot and does no fallible I/O, so it returns
    /// the payload by value (no `Result`).
    ///
    /// Other members' sender keys arrive later on demand via the PULL protocol
    /// (§9.16.2): the joiner sends a `SenderKeyRequest` carrying a fresh EPHEMERAL
    /// wrapping key to each incumbent. So `sender_key_store`, `nonce_dedup`,
    /// `pending_distributions`, and `member_wrapping_keys` start empty — the same
    /// initial shape a fresh join produces. `member_wrapping_keys` STAYS empty
    /// for a joiner: it caches other members' STABLE wrapping keys, used ONLY by
    /// the proactive/offline PUSH path and populated on the incumbent/adder side;
    /// openmls 0.8.1 exposes no way to read a remote member's `scp_wrapping_key`
    /// `LeafNode` extension from a joined group (ADR-057), and a joiner does not
    /// need them — it reaches every incumbent through the pull protocol and
    /// answers incumbents' pulls via the ephemeral key in their requests.
    pub fn install_joined_group(&self, group: ScpMlsGroup) -> OwnedMlsCryptoState {
        // Direct assembly — the joined group moves in verbatim; `fresh_birth`
        // mints the joiner's own local sender key (epoch 1), matching a fresh
        // create.
        OwnedMlsCryptoState::fresh_birth(group)
    }

    /// #2148 (ADR-049 birth-into-actor) test seam: births a wrapping-key-only
    /// group (NO `scp_context_params` `0xFF02` extension) as OWNED material.
    ///
    /// The production creator path always commits `0xFF02` (via
    /// [`Self::create_mls_group_with_context`]); this bare owned constructor
    /// exists ONLY so tests can stand up a NON-SCP group — e.g. to prove the join
    /// path REJECTS a group with no `0xFF02` extension. It touches no per-context
    /// state and mints the local sender key inline, exactly like the context
    /// birth seam. Gated `#[cfg(any(test, feature = "testing"))]` — never on a
    /// production path.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::CryptoFailed`] if credential creation or
    /// MLS group creation fails.
    #[cfg(any(test, feature = "testing"))]
    pub fn create_bare_group_owned(&self) -> Result<OwnedMlsCryptoState, ContextCreationError> {
        let credential = self.make_credential()?;
        let wrapping_pk = self.wrapping_keypair.load().public;
        let mls_group = group::create_group_with_wrapping_key(
            &credential,
            Some(&wrapping_pk),
            self.clock.as_ref(),
        )
        .map_err(|e| ContextCreationError::CryptoFailed(e.to_string()))?;
        // Bare (non-`0xFF02`) group as owned material; `fresh_birth` mints the
        // local sender key inline, exactly like the context birth seam.
        Ok(OwnedMlsCryptoState::fresh_birth(mls_group))
    }

    // #2148 (ADR-049 birth-into-actor): `generate_sender_key`, `init_broadcast_key`,
    // `destroy_mls_group`, and `destroy_sender_key` were DELETED along with the
    // `contexts` / `broadcast_keys` maps. The local sender key is minted INSIDE
    // the owned birth constructors; the broadcast key lives on the actor's
    // `BroadcastState`; and per-context teardown is the actor's job — it disposes
    // its OWNED crypto via `ContextCryptoState::dispose_secrets` (which runs
    // OpenMLS `destroy_group` and zeroizes the sender key material) at its close /
    // TTL-expiry / shutdown seams.

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
                "production NodeMlsFactory requires MLS key package bytes".to_string(),
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

    // #2148 (ADR-049 birth-into-actor): the provider `add_member` /
    // `add_member_from_bytes` were DELETED. Member addition mutates the
    // ACTOR-owned MLS group — the governance `AddMember` handler calls the
    // actor-side `ContextCryptoState::add_member` on its owned
    // `PerContextState` (`context/actor/state.rs`), which routes the invitee's
    // `KeyPackage` through the same `scp_mls::group::add_member` primitive. The
    // provider held a `contexts`-map copy only during the pre-birth-into-actor
    // window; that map is gone.

    // #2148 (ADR-049 birth-into-actor): the provider-fixture `distribute_sender_key`
    // (a `#[cfg(test)]` two-party-fixture copy of the join-time sender-key PUSH)
    // was DELETED with the `contexts` map. The steady-state PUSH lives on the
    // actor (`PerContextState::distribute_sender_key`); tests drive it there.

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

    // #2148 (ADR-049 birth-into-actor): the provider-fixture pull/answer copies
    // `store_member_sender_key`, `set_sender_key_unchecked`, and
    // `handle_sender_key_request` (all `#[cfg(test)]` two-party-fixture copies)
    // were DELETED with the `contexts` map. The steady-state pull-answer / install
    // seams live on the actor-owned `ContextCryptoState` (`context/actor/state.rs`);
    // tests drive them there.

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
    /// Class-M [`RestoredFloors`].
    ///
    /// #2148 (ADR-049 birth-into-actor): this is the owned-return restore seam.
    /// The restore / respawn / cold-restart / import caller
    /// (`lifecycle_helpers`) seeds the per-context actor directly from the
    /// returned material — the provider holds no per-context state to install
    /// into. This method restores the node-level X25519 wrapping keypair as a
    /// `&self` side effect but touches no per-context map (there is none) and
    /// imports nothing from `context::actor` (the owned payload is the boundary
    /// shape between the provider and the actor).
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
            std::mem::take(&mut snapshot.sender_key_epochs);

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

        // #2148 (ADR-049 birth-into-actor): this method hands the per-context
        // crypto material OUT to seed an actor's `PerContextState` (welcome /
        // restore / respawn / cold-restart) and touches no provider map (there
        // is none). There is no `taken_context_ids` marker to record: the actor
        // is the sole crypto authority by construction and the supervisor
        // registry's atomic first-writer-wins insert is the double-birth guard.

        Ok((
            owned,
            RestoredFloors {
                sender_epochs: restored_sender_epochs,
                recv_sequence: restored_recv_sequence,
            },
        ))
    }

    // #2148 (ADR-049 birth-into-actor): the provider `group_context_extension`
    // reader was DELETED — it read the resident MLS group out of the `contexts`
    // map (now gone) via the deleted `with_context`. Every caller reads the
    // extension off the OWNED group directly instead: the WELCOME seam reads
    // `joined_group.group_context_extension()` before seeding, and the
    // restore/import paths read `owned.mls_group.group_context_extension()` off
    // the material `build_restored_owned` returns. The actor's
    // `ContextCryptoState::group_context_extension` covers the live-actor read.

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
    use scp_mls::group::generate_key_package;
    use tls_codec::Serialize as TlsSerializeTrait;

    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    /// Test helper: encrypt a message using the old `encrypt_message` path
    /// (sender key + MLS encrypt). Used by provider-level tests that test
    /// the crypto layer directly without the full envelope pipeline.
    fn make_provider() -> NodeMlsFactory {
        NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock))
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

    /// #2148 (ADR-049 birth-into-actor): BIRTH a fresh owned group + local sender
    /// key on `provider` (via the owned-return
    /// [`NodeMlsFactory::create_bare_group_owned`]) and seed it onto a
    /// throwaway actor [`PerContextState`] (Encrypted mode). This is the
    /// actor-native replacement for the deleted `create_mls_group` +
    /// `generate_sender_key` + `take_crypto_state` triad: crypto is never
    /// provider-resident.
    ///
    /// The group is BARE (no `0xFF02` `scp_context_params` extension) so tests
    /// that add a plain (non-`0xFF02`) `KeyPackage` succeed — an `0xFF02` group
    /// requires every added leaf to declare `0xFF02` support. The seal/open path
    /// binds its OWN `ctx_str` in the AEAD AAD, independent of the group's
    /// committed extension, so a bare group exercises those seams identically.
    fn take_into_actor(provider: &NodeMlsFactory, ctx: &[u8; 32]) -> PerContextState {
        let owned = provider
            .create_bare_group_owned()
            .expect("birth owned crypto material");
        let mut state =
            PerContextState::new_for_test_encrypted(*ctx, 0, DID::from(provider.local_did.clone()));
        state.seed_encrypted_crypto_from_owned(owned);
        state
    }

    /// Birth a fresh owned context on `provider`, seed it onto a throwaway actor
    /// state, and export the crypto through the actor
    /// [`PerContextState::export_crypto_state`] seam — sourcing the node-resident
    /// wrapping keypair (public + secret) from the provider exactly as the
    /// production actor-export caller does.
    fn actor_export(
        provider: &NodeMlsFactory,
        ctx: &[u8; 32],
        sender_key_epochs: Vec<(String, u64)>,
        recv_sequence_floors: Vec<(String, ReceiveFloor)>,
    ) -> Result<Vec<u8>, ContextError> {
        let (wpub, wsec) = provider.wrapping_keypair();
        let state = take_into_actor(provider, ctx);
        state.export_crypto_state(sender_key_epochs, recv_sequence_floors, wpub, &*wsec)
    }

    /// #2148 (ADR-049 birth-into-actor): birth an owned context onto a throwaway
    /// actor, let `mutate` enrich its actor-owned crypto (remote sender keys,
    /// wrapping keys, epoch counter), then export the durable snapshot with the
    /// given Class-M floor params — the actor-native replacement for the deleted
    /// "create+generate on the provider, mutate `contexts[ctx]`, then export"
    /// setup the restore-format tests used.
    fn birth_mutate_export(
        provider: &NodeMlsFactory,
        ctx: &[u8; 32],
        sender_key_epochs: Vec<(String, u64)>,
        recv_sequence_floors: Vec<(String, ReceiveFloor)>,
        mutate: impl FnOnce(&mut crate::context::actor::ContextCryptoState),
    ) -> Vec<u8> {
        let (wpub, wsec) = provider.wrapping_keypair();
        let mut state = take_into_actor(provider, ctx);
        mutate(actor_crypto_mut(&mut state));
        state
            .export_crypto_state(sender_key_epochs, recv_sequence_floors, wpub, &*wsec)
            .expect("export seeded actor crypto")
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
    /// [`NodeMlsFactory::wrapping_keypair_snapshot`] ground truth. Also pins
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
    /// COVERAGE (§15(c) fail-closed injection): RESTORED on the actor. #2148
    /// re-homed the one-shot rotation fault seam onto the actor's
    /// `PerContextState` (`arm_rotation_failure_once` plus the `#[cfg(any(test,
    /// feature = "testing"))]` early-return in
    /// `PerContextState::rotate_sender_key`) and DELETED the now-orphaned
    /// provider `force_rotation_failure` field / `arm_rotation_failure_once`
    /// method (their only consumer, the provider `rotate_sender_key`, was
    /// already gone). The Class-S fail-closed branch is now exercised
    /// end-to-end by `state.rs`'s
    /// `arm_rotation_failure_once_forces_fail_closed_then_normal` (arm → next
    /// actor rotation fails closed with the epoch/key uncommitted → a
    /// subsequent rotation advances normally). This test covers only the
    /// NORMAL epoch-advance.
    #[test]
    fn rotate_sender_key_advances_epoch_on_actor() {
        let provider = make_provider();
        let ctx_id = make_context_id();
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
            NodeMlsFactory::new("invalid:format:whatever".to_string(), Arc::new(SystemClock));
        assert!(provider.validate_creator_identity().is_err());
    }

    // #2148 (ADR-049 birth-into-actor): `create_mls_group_and_destroy` was
    // DELETED — the provider `create_mls_group` / `destroy_mls_group` /
    // `with_context`-based encrypt path no longer exist; the actor owns the group
    // and disposes it via `ContextCryptoState::dispose_secrets` (covered by the
    // `golden_destroy_*` tests in `context::actor::state`).

    #[test]
    fn add_member_with_real_key_package() {
        // #2148: member addition mutates the ACTOR-owned group. Birth an owned
        // group into a throwaway actor state, then add Bob through the
        // actor-native `add_member` seam.
        let provider = make_provider();
        let ctx_id = make_context_id();
        let mut actor = take_into_actor(&provider, &ctx_id);

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

        // Add Bob on the actor-owned group.
        let result = actor.add_member(&bob_cred.did, Some(&kp_bytes), &SystemClock);
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
            NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(TestClock::new(future_now)));

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
        let live_provider = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
        assert!(
            live_provider
                .validate_key_package(&bob_cred.did, Some(&kp_bytes))
                .is_ok(),
            "a freshly-minted KeyPackage must pass under a real-present clock"
        );
    }

    #[test]
    fn add_member_rejects_malformed_key_package_bytes() {
        // #2148: member addition runs on the actor-owned group. Security intent:
        // `add_member` must reject key material that is not a valid MLS
        // KeyPackage — garbage bytes fail TLS deserialization.
        let provider = make_provider();
        let ctx_id = make_context_id();
        let mut actor = take_into_actor(&provider, &ctx_id);

        let malformed: &[u8] = &[0xFF; 4];
        let result = actor.add_member("did:dht:z6MkBob", Some(malformed), &SystemClock);
        assert!(
            result.is_err(),
            "add_member must reject malformed key package bytes: {result:?}"
        );
    }

    #[test]
    fn remove_member_by_did() {
        // #2148: add + remove both run on the ACTOR-owned group.
        let provider = make_provider();
        let ctx_id = make_context_id();
        let mut actor = take_into_actor(&provider, &ctx_id);

        // Add Bob on the actor-owned group.
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let bob_cred = ScpCredential::new(bob_did.to_string(), None, SigningKeyId::Active).unwrap();
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let kp_bytes = bob_kp_bundle
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        actor
            .add_member(bob_did, Some(&kp_bytes), &SystemClock)
            .unwrap();

        // Remove Bob through the actor seam.
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

        // Self-removal (leave) returns empty commit bytes — the local node
        // does not produce a Commit for its own departure.
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

    // #2148 (ADR-049 birth-into-actor): the provider-internal crypto-op tests
    // (encrypt/decrypt roundtrip, forward secrecy, three-member group, member
    // removal, `init_and_destroy_broadcast_key`, `distribute_and_remove_sender_key`,
    // the `create_mls_group_refuses_to_overwrite` / `*_errors_without_context`
    // guards) were DELETED. They poked the provider's now-deleted `contexts` map or
    // exercised deleted provider mechanics. The crypto operations themselves are
    // covered on the ACTOR-owned `ContextCryptoState` by the comprehensive
    // `golden_*` byte-identity suite in `context::actor::state`, and by the
    // two-party seam in `crypto::mls::two_party_test_support`.

    #[test]
    fn ciphersuite_is_correct() {
        // The actor-owned group born by the provider uses the SCP ciphersuite.
        let provider = make_provider();
        let ctx_id = make_context_id();
        let actor = take_into_actor(&provider, &ctx_id);
        let group = actor_crypto(&actor)
            .mls_group
            .as_ref()
            .expect("group present");
        let inner = group.inner().unwrap();
        assert_eq!(
            inner.ciphersuite(),
            SCP_CIPHERSUITE,
            "must use MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
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

    // #2148 (ADR-049 birth-into-actor): `generate_sender_key_errors_without_context`
    // was DELETED — the provider `generate_sender_key` method no longer exists
    // (the local sender key is minted inside the owned birth constructor).

    #[test]
    fn self_removal_is_noop() {
        let provider = make_provider();
        let ctx_id = make_context_id();
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
        // #2148: the owned group the provider births carries the provider's
        // node-resident wrapping public key in its own leaf node.
        let provider = make_provider();
        let ctx_id = make_context_id();
        let actor = take_into_actor(&provider, &ctx_id);

        let group = actor_crypto(&actor)
            .mls_group
            .as_ref()
            .expect("group present");
        let extracted = scp_mls::wrapping_extension::extract_own_wrapping_key(group).unwrap();
        assert_eq!(
            extracted,
            Some(provider.wrapping_keypair.load().public),
            "own leaf node must contain provider's wrapping public key"
        );
    }

    // #2148 (ADR-049 birth-into-actor): the provider distribute/roundtrip/drain
    // tests (`distribute_sender_key_hpke_seals_when_wrapping_key_available`,
    // `distribute_sender_key_no_wrapping_key_still_stores_locally`,
    // `process_incoming_sender_key_roundtrip`,
    // `drain_pending_sender_key_messages_clears_queue`) were DELETED — they drove
    // the deleted provider `distribute_sender_key` / `add_member` / `contexts`.
    // The join-time sender-key PUSH round-trip is covered on the actor-owned state
    // by `golden_distribute_and_process_recover_identical_key` in
    // `context::actor::state` and end-to-end by `two_party_test_support`.

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
        use scp_protocol::crypto::sender_keys::SenderKeyResponse;

        // #2148: `process_incoming_sender_key` is a node-level HPKE-open +
        // authentication check that reads only the provider's node-resident
        // wrapping keypair — it needs no per-context group resident.
        let bob_provider = NodeMlsFactory::new(
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string(),
            Arc::new(SystemClock),
        );
        let ctx_id = make_context_id();

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
        let bob = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);

        // #2148: birth an owned group onto a throwaway actor and enrich its
        // crypto (remote sender key, member wrapping key, epoch=42) through the
        // actor-owned `ContextCryptoState`.
        let mut actor = take_into_actor(&provider, &ctx_id);
        {
            let state = actor_crypto_mut(&mut actor);
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob, generate_sender_key());
            state
                .member_wrapping_keys
                .insert(bob.to_owned(), [0xAA; 32]);
            state.sender_key_epoch = 42;
        }

        // Capture pre-export state for comparison (from the actor).
        let (original_sender_key, original_epoch, original_wrapping_key, original_bob_key) = {
            let state = actor_crypto(&actor);
            (
                state.sender_key.clone().expect("local sender key present"),
                state.sender_key_epoch,
                state.member_wrapping_keys.get(bob).copied().unwrap(),
                state
                    .sender_key_store
                    .get(&ctx_id_hex, bob)
                    .unwrap()
                    .clone(),
            )
        };

        // Export crypto state through the actor seam.
        let (wpub, wsec) = provider.wrapping_keypair();
        let exported = actor
            .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
            .unwrap();
        assert!(!exported.is_empty(), "exported state should be non-empty");

        // Rebuild the owned material on a fresh provider via the RETAINED restore
        // reader (`build_restored_owned`), then seed an actor and verify the
        // round-trip is FUNCTIONAL (the seeded encrypted actor holds a live MLS
        // group + sender key) and byte-faithful. The full seal→open functional
        // round-trip across the restored group is pinned by
        // `context::actor::state`'s `golden_seal_open_cross_roundtrip` (which
        // seals from a restored, seeded actor state).
        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let bob = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);

        // #2148: birth an owned group onto a throwaway actor and populate a rich
        // snapshot (remote sender key, member wrapping key, sender_key_epoch=42)
        // on the actor-owned crypto.
        let mut actor = take_into_actor(&provider, &ctx_id);
        {
            let state = actor_crypto_mut(&mut actor);
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
            let state = actor_crypto(&actor);
            (
                state
                    .sender_key
                    .as_ref()
                    .expect("local sender key present")
                    .as_bytes()
                    .to_vec(),
                state
                    .sender_key_store
                    .get(&ctx_id_hex, bob)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                state
                    .mls_group
                    .as_ref()
                    .expect("group present")
                    .group_id()
                    .unwrap()
                    .to_vec(),
            )
        };

        // Export with BOTH floor axes populated: per-sender epoch (bob, 5) and
        // intra-epoch recv floor ReceiveFloor { epoch: 5, sequence: 3 }.
        let (wpub, wsec) = provider.wrapping_keypair();
        let exported = actor
            .export_crypto_state(
                vec![(bob.to_owned(), 5)],
                vec![(
                    bob.to_owned(),
                    ReceiveFloor {
                        epoch: 5,
                        sequence: 3,
                    },
                )],
                wpub,
                &*wsec,
            )
            .unwrap();
        assert!(!exported.is_empty());

        // Fresh provider: build the owned material (no insert, no take).
        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        // (b) #2148: the material is handed OUT, never installed — the provider
        // holds no per-context state (the `contexts` / `taken_context_ids` maps
        // are deleted), so there is nothing to assert residency on.

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

        let bob = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        // Simulate a legacy snapshot: birth+enrich+export through the actor seam,
        // then strip the per-sender map.
        let exported = birth_mutate_export(&provider, &ctx_id, Vec::new(), Vec::new(), |state| {
            state.sender_key_epoch = 7;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob, generate_sender_key());
        });
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider_b = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);

        // Install Bob's key MATERIAL on the actor-owned crypto (the floor is
        // carried by the registry and passed as the export param, exactly as
        // `build_snapshot_for_persist` threads it), then export with the
        // authoritative floor (epoch 5) as the param.
        let exported = birth_mutate_export(
            &provider,
            &ctx_id,
            vec![(bob_did.to_owned(), 5)],
            Vec::new(),
            |state| {
                state
                    .sender_key_store
                    .set_unchecked(&ctx_id_hex, bob_did, generate_sender_key());
            },
        );
        assert!(!exported.is_empty());

        // Restart: fresh provider, rebuild the owned material via the retained
        // restore reader. The floor comes back in RestoredFloors.
        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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
        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        // Export through the actor seam (non-trivial global sender_key_epoch=7 so
        // we can verify the legacy seed uses it), then hand-edit the msgpack to
        // drop the epoch map.
        let exported = birth_mutate_export(&provider, &ctx_id, Vec::new(), Vec::new(), |state| {
            state.sender_key_epoch = 7;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob_did, generate_sender_key());
        });
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let peer_did = "did:dht:z6MkPeerPeerPeerPeerPeerPeerPeerPeerPeerPe";
        let ctx_id_hex = hex::encode(ctx_id);

        // Scenario: local provider has rotated only once
        // (`sender_key_epoch = 1`), but the peer has rotated many
        // times and set_checked has been called with epoch = 50 for
        // the peer. This represents a pre-C1 runtime where the peer
        // epoch IS tracked in the `epochs` map but the snapshot
        // format does NOT persist it. Export through the actor seam, then
        // strip the per-sender epoch map to simulate a legacy snapshot.
        let exported = birth_mutate_export(&provider, &ctx_id, Vec::new(), Vec::new(), |state| {
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
        });
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        let ctx_id_hex = hex::encode(ctx_id);
        let exported = birth_mutate_export(&provider, &ctx_id, Vec::new(), Vec::new(), |state| {
            state.sender_key_epoch = 0;
            state
                .sender_key_store
                .set_unchecked(&ctx_id_hex, bob_did, generate_sender_key());
        });
        let mut snapshot: MlsCryptoSnapshot = rmp_serde::from_slice(&exported).unwrap();
        snapshot.sender_key_epochs.clear();
        let legacy_bytes = rmp_serde::to_vec_named(&snapshot).unwrap();

        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        let exported = actor_export(&provider, &ctx_id, Vec::new(), Vec::new()).unwrap();

        // Rebuild the owned material on a fresh provider twice — the second call
        // must also yield working material (owned-return path, no insert to
        // clobber). Seed an actor from the second result and confirm it is a
        // coherent live encrypted state.
        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

        // Birth an owned group onto an actor and read its epoch before export.
        let actor = take_into_actor(&provider, &ctx_id);
        let epoch_before = actor_crypto(&actor)
            .mls_group
            .as_ref()
            .expect("group present")
            .epoch()
            .unwrap();
        let (wpub, wsec) = provider.wrapping_keypair();
        let exported = actor
            .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
            .unwrap();

        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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
        let provider2 = NodeMlsFactory::new(TEST_DID.to_string(), Arc::new(SystemClock));
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

    fn setup_alice_bob_two_party() -> (PerContextState, PerContextState, [u8; 32], String) {
        let alice_did = TEST_DID;
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        // Stand up the joined pair over the REAL reserve → creator-add → sign →
        // HPKE-seal → join path, born DIRECTLY onto actor-owned state via the
        // #2148 owned-return constructors (no provider `take_crypto_state`
        // round-trip). The helper also pulls Alice's sender key to Bob, so Bob's
        // installed sender-key epoch for Alice is 1 — the H9 high-water mark these
        // tests anchor on. The returned providers are unused here, so they are
        // discarded.
        let crate::crypto::mls::two_party_test_support::TwoPartyPair {
            alice_state,
            bob_state,
            ctx_bytes: context_id,
            ..
        } = crate::crypto::mls::two_party_test_support::stand_up_two_party(
            TEST_CTX_STR,
            alice_did,
            bob_did,
        );

        (alice_state, bob_state, context_id, alice_did.to_string())
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
        let (mut alice_actor, mut bob_actor, ctx_id, alice_did) = setup_alice_bob_two_party();
        let routing_id = ctx_routing_id(&ctx_id);

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
        let (_alice_actor, mut bob_actor, ctx_id, _alice_did) = setup_alice_bob_two_party();

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
        let (mut alice_actor, _bob_actor, ctx_id, alice_did) = setup_alice_bob_two_party();
        let routing_id = ctx_routing_id(&ctx_id);

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
    // #2148 (ADR-049 birth-into-actor): the provider take/with_context bookkeeping
    // tests (`take_crypto_state_removes_entry_from_provider`,
    // `take_crypto_state_missing_context_returns_not_registered`,
    // `take_crypto_state_double_take_returns_owned_by_actor`,
    // `with_context_distinguishes_never_created_from_taken`,
    // `taken_context_write_paths_fail_closed`) were DELETED. They tested the
    // provider's `contexts` / `taken_context_ids` / `take_crypto_state` /
    // `with_context` mechanics, all of which are deleted — the provider holds no
    // per-context state, so there is no residency, take, or overwrite guard to
    // assert. The sole double-birth authority is now the supervisor registry's
    // atomic first-writer-wins insert.

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
    ) -> (PerContextState, PerContextState, [u8; 32], String) {
        let alice_did = TEST_DID;
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        // Stand up the joined pair over the REAL join path, born DIRECTLY onto
        // actor-owned state via the #2148 owned-return constructors, keyed by
        // `context_id_bytes(ctx_str)`. The helper pulls Alice's sender key to Bob
        // so Bob can decrypt Alice's app-data sends. The returned providers are
        // unused here, so they are discarded.
        let crate::crypto::mls::two_party_test_support::TwoPartyPair {
            alice_state,
            bob_state,
            ctx_bytes: context_id,
            ..
        } = crate::crypto::mls::two_party_test_support::stand_up_two_party(
            ctx_str, alice_did, bob_did,
        );

        (alice_state, bob_state, context_id, alice_did.to_string())
    }

    /// The cleartext outer-envelope `routing_id` produced by
    /// `build_encrypted_envelope` for application data is the 32-byte zero
    /// sentinel — NOT the relay-derivable `context_routing_id`. A relay
    /// deserializing the single envelope layer therefore reads no shared
    /// correlator off a pseudonym-addressed app-data blob.
    #[test]
    fn app_data_envelope_routing_id_is_zeroed_not_context_rid() {
        let ctx_str = "ctx-app-data-zeroed-rid";
        let (mut alice_actor, _bob_actor, _ctx_id, alice_did) =
            setup_two_party_for_ctx_string(ctx_str);
        let clock: std::sync::Arc<dyn scp_clock::Clock> =
            std::sync::Arc::new(scp_clock::SystemClock);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sender = scp_did::DID(alice_did.clone());
        let recipients = app_data_recipients(ctx_str, &alice_did);

        // `build_encrypted_envelope_actor` is the production app-data seal that
        // zeroes the outer routing_id (§9.10.4), driven on Alice's owned actor
        // state.
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
        let (mut alice_actor, mut bob_actor, _ctx_id, alice_did) =
            setup_two_party_for_ctx_string(ctx_str);
        let clock: std::sync::Arc<dyn scp_clock::Clock> =
            std::sync::Arc::new(scp_clock::SystemClock);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sender = scp_did::DID(alice_did.clone());
        let recipients = app_data_recipients(ctx_str, &alice_did);

        // Both seal (Alice) and open (Bob) drive their owned actor states.
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
        let (mut alice_actor, _bob_actor, _ctx_id, alice_did) =
            setup_two_party_for_ctx_string(ctx_str);
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
        // trust_recovery_helpers / supervisor / lifecycle_helpers). The actor
        // seal preserves whatever `routing_id` it is given.
        let control_rid = scp_protocol::context::context_routing_id(ctx_str);
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
    /// ([`NodeMlsFactory::create_mls_group_with_context`]) commits the
    /// `scp_context_params` (`0xFF02`) extension into the group's
    /// `group_context`, byte-identical to the parameters supplied (§5.13.3,
    /// FFI-02).
    #[test]
    fn create_mls_group_with_context_commits_extension() {
        // #2148: the owned birth constructor returns the group; read its
        // committed `0xFF02` extension off the owned material.
        let provider = make_provider();
        let ctx_ext = provider_context_extension("ctx:provider-write");

        let owned = provider
            .create_mls_group_with_context(&ctx_ext)
            .expect("birth owned context group");

        let read_back = owned
            .mls_group
            .group_context_extension()
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))
            .unwrap();
        assert_eq!(
            read_back,
            Some(ctx_ext),
            "created context group must carry the committed ScpContextExtension"
        );
    }
    // #2148 (ADR-049 birth-into-actor): DELETED provider-mechanic tests —
    // `create_mls_group_has_no_context_extension` (bare `create_mls_group` gone),
    // `create_mls_group_with_context_refuses_overwrite` (owned birth reserves no
    // slot, so there is no overwrite guard — the supervisor registry is the sole
    // double-birth authority), and the additive owned-vs-insert byte-parity
    // suite (`create_mls_group_with_context_owned_matches_insert_path`,
    // `install_joined_group_owned_matches_insert_path`,
    // `build_restored_owned_is_side_effect_free_on_contexts_map`) — the insert
    // path they compared against is deleted, so there is no second path to
    // compare. The surviving owned constructors' determinism is exercised by the
    // migrated birth/restore tests above and the actor `golden_*` suite.
}
