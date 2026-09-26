//! Narrow MLS primitive backend trait.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §6).
//!
//! # Trait split
//!
//! `MlsBackend` is the narrow MLS-primitive surface that replaces the
//! ~26-method `ContextCryptoProvider` trait. State lives on the caller's
//! `ScpMlsGroup`; methods take `&mut ScpMlsGroup` and never own state.
//!
//! The split strictly preserves RFC 9420 conformance: every method maps to a
//! single `OpenMLS` primitive with no SCP orchestration in between. The SCP
//! ciphersuite is fixed to
//! [`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`](scp_mls::group::SCP_CIPHERSUITE).
//!
//! # Method contracts
//!
//! - `validate_key_package` / `generate_key_package` are cancel-safe and
//!   side-effect-free on `ScpMlsGroup`. They construct fresh values; no
//!   caller state changes if the future is dropped mid-flight.
//! - All other mutating methods are **cancel-hostile** on `&mut ScpMlsGroup`:
//!   the group's internal epoch state may advance (via `merge_pending_commit`
//!   or `merge_staged_commit`) before the future returns. Dropping the future
//!   mid-call can leave the group in a partially-committed state. Cancel-safe
//!   wrappers live at the supervisor layer — see the saga journal for the
//!   rollback discipline.
//! - There is no dedicated rollback helper in this commit; the supervisor
//!   layer (commit ≥5) is the sole rollback point. Any rollback helper added
//!   later will be idempotent by construction (the handler must recompute
//!   rollback target state from `PerContextState`).
//!
//! # Production impl
//!
//! [`super::production_backend::ProductionMlsBackend`] delegates to the
//! existing [`scp_mls::group`] and [`scp_mls::encrypt`] free functions — the same
//! primitives the pre-refactor `NodeMlsFactory` calls today. The
//! byte-identical output test in `production_backend.rs` feeds the same input
//! to both the backend and a bare `NodeMlsFactory` and asserts equality on
//! the produced ciphertext / Welcome / Commit bytes.

use std::sync::Arc;

use async_trait::async_trait;
use openmls::prelude::LeafNodeIndex;

use super::storage_adapter::OpenMlsStorageAdapter;
use scp_clock::Clock;
use scp_mls::credential::ScpCredential;
use scp_mls::encrypt::DecryptedContent;
use scp_mls::error::MlsError;
use scp_mls::group::ScpMlsGroup;

// ---------------------------------------------------------------------------
// Wrapper output types
// ---------------------------------------------------------------------------

/// Raw output of an `add_member` primitive.
///
/// Exposes the wire-serialized `commit`, `welcome`, and optional `group_info`
/// bytes that `OpenMLS` produces. Handlers (in later commits) wrap these raw
/// bytes into the richer `AddMemberOutput` the old trait produced; keeping
/// this type primitive-only is deliberate — it is the exact abstraction
/// boundary of the `MlsBackend` trait.
#[derive(Debug, Clone)]
pub struct AddMemberRaw {
    /// TLS-serialized MLS Commit message. Sent to all existing members to
    /// advance the group epoch.
    pub commit: Vec<u8>,
    /// TLS-serialized MLS Welcome message. HPKE-encrypted to the new
    /// member's `KeyPackage`; contains the group state they need.
    pub welcome: Vec<u8>,
    /// TLS-serialized MLS `GroupInfo`, if `OpenMLS` produced one. Optional per
    /// RFC 9420.
    pub group_info: Option<Vec<u8>>,
}

/// Raw output of a `remove_member` primitive.
///
/// Exposes the wire-serialized `commit` and optional `group_info` bytes that
/// `OpenMLS` produces. See [`AddMemberRaw`] for why this is primitive-only.
#[derive(Debug, Clone)]
pub struct RemoveMemberRaw {
    /// TLS-serialized MLS Commit message. Sent to remaining members.
    pub commit: Vec<u8>,
    /// TLS-serialized MLS `GroupInfo`, if `OpenMLS` produced one.
    pub group_info: Option<Vec<u8>>,
}

/// Output of `validate_key_package` — the validated bytes plus the identity
/// the validated leaf credential authenticates.
///
/// `validate_key_package` runs the full stateless `KeyPackage` validation
/// (signature / protocol / hardened-clock lifetime / SCP ciphersuite) exactly
/// once and returns both the canonical bytes of the validated `KeyPackage` and
/// the credential DID extracted from that same validated leaf. Callers use
/// `key_package_bytes` to re-serialize for storage (key package pool) and
/// `credential_did` to bind the `KeyPackage` to an expected identity — both
/// WITHOUT re-running validation or re-parsing the bytes to re-extract the DID
/// (which would re-validate the same `KeyPackage` a second time).
#[derive(Debug, Clone)]
pub struct ValidatedKeyPackage {
    /// The TLS-serialized `KeyPackage` bytes that passed validation.
    pub key_package_bytes: Vec<u8>,
    /// The DID authenticated by the validated leaf credential.
    ///
    /// Extracted from the SAME validated `KeyPackage` leaf that produced
    /// `key_package_bytes` (leaf credential → `BasicCredential` → SCP
    /// credential → `did`), so it is authenticated under the exact validation
    /// (and hardened-clock lifetime) the bytes passed. Callers compare this
    /// against the expected owner / member DID to bind the `KeyPackage` to an
    /// identity, with no second validation pass.
    pub credential_did: String,
}

/// Output of `generate_key_package` — pairs the wire bytes with the opaque
/// signer state the caller must retain to later join from a Welcome.
#[derive(Debug, Clone)]
pub struct GeneratedKeyPackage {
    /// The TLS-serialized `KeyPackage` bytes ready for publication.
    pub key_package_bytes: Vec<u8>,
    /// Opaque signer-state handle the caller retains to join a group from a
    /// Welcome message addressed to this `KeyPackage`. The bytes are an
    /// implementation-defined serialization of the signer / provider state
    /// and MUST NOT be interpreted by callers; they are passed verbatim to
    /// [`MlsBackend::join_from_welcome`].
    ///
    /// Contains the Ed25519 signing key and `OpenMLS` in-memory storage needed
    /// to process the Welcome. Wire format is not stable across `OpenMLS`
    /// upgrades — callers persist alongside schema versioning per §17.15.3.
    pub signer_state: SignerState,
}

/// Opaque signer-state handle produced by `generate_key_package` and consumed
/// by `join_from_welcome`.
///
/// The byte layout is defined by the [`MlsBackend`] implementation. Callers
/// MUST treat the bytes as opaque and MUST NOT attempt to parse them.
///
/// The enclosed Ed25519 signing key bytes are wrapped in
/// [`zeroize::Zeroizing`] via the implementation's serialization format.
///
/// The [`std::fmt::Debug`] impl is hand-written to REDACT the private bytes:
/// it prints only the byte length, never the contents, so an accidental
/// `{:?}` of a `SignerState` (or any struct that embeds it) can never leak
/// the private signing / HPKE material into a log or panic payload.
#[derive(Clone)]
pub struct SignerState {
    /// Implementation-defined serialization of the signer + provider state.
    ///
    /// Wrapped in [`zeroize::Zeroizing`] so the private signing / HPKE
    /// material it carries is zeroed when the `SignerState` is dropped —
    /// including the transient copy made when handing a reserved KP's
    /// signer-state to `join_from_welcome`.
    pub bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SignerState {
    /// Redacted: prints the byte length, never the raw private bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerState")
            .field(
                "bytes",
                &format_args!("<redacted, {} bytes>", self.bytes.len()),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Narrow MLS primitive surface.
///
/// Every method maps to a single RFC 9420 primitive. State flows in as
/// `&mut ScpMlsGroup` parameters; the trait owns no state. Implementations
/// are `Send + Sync` and shared across actors via `Arc<dyn MlsBackend>`.
///
/// # Cancel-safety
///
/// - `validate_key_package`, `generate_key_package`: cancel-safe,
///   side-effect-free on external state.
/// - All other methods: cancel-hostile on `&mut ScpMlsGroup`. The supervisor
///   layer owns the rollback discipline (see saga journal).
#[async_trait]
pub trait MlsBackend: Send + Sync {
    /// Creates a new MLS group with the caller as the sole member.
    ///
    /// Wraps [`scp_mls::group::create_group_with_wrapping_key`] exactly.
    ///
    /// # Errors
    ///
    /// See [`MlsError`] for failure modes (credential serialization, group
    /// creation, storage).
    async fn create_group(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<ScpMlsGroup, MlsError>;

    /// Adds a member to `group` by their TLS-serialized `KeyPackage` bytes
    /// and advances the group epoch.
    ///
    /// Returns the raw Commit / Welcome / `GroupInfo` bytes per RFC 9420.
    ///
    /// # Errors
    ///
    /// See [`MlsError`]. On failure the group state may be partially
    /// advanced — callers MUST treat this as cancel-hostile and rely on
    /// supervisor-side rollback.
    async fn add_member_raw(
        &self,
        group: &mut ScpMlsGroup,
        key_package_bytes: &[u8],
    ) -> Result<AddMemberRaw, MlsError>;

    /// Removes the member at `leaf_index` from `group` and advances the
    /// group epoch.
    ///
    /// # Errors
    ///
    /// See [`MlsError`]. Cancel-hostile on `&mut ScpMlsGroup`.
    async fn remove_member_raw(
        &self,
        group: &mut ScpMlsGroup,
        leaf_index: LeafNodeIndex,
    ) -> Result<RemoveMemberRaw, MlsError>;

    /// Encrypts `plaintext` as an MLS application `PrivateMessage` for the
    /// current epoch of `group`.
    ///
    /// Returns the TLS-serialized ciphertext bytes.
    ///
    /// # Errors
    ///
    /// See [`MlsError`]. `MlsError::EncryptionFailed` maps to `OpenMLS`
    /// failures (pending proposals, evicted member).
    async fn encrypt(&self, group: &mut ScpMlsGroup, plaintext: &[u8])
    -> Result<Vec<u8>, MlsError>;

    /// Decrypts an MLS `PrivateMessage` against `group`, returning a
    /// [`DecryptedContent`] discriminating Application / Commit / Proposal
    /// and carrying the sender DID.
    ///
    /// For `Commit` messages the staged commit is merged before the call
    /// returns — this matches today's `decrypt_with_sender_did` contract.
    ///
    /// # Errors
    ///
    /// See [`MlsError`].
    async fn decrypt(
        &self,
        group: &mut ScpMlsGroup,
        ciphertext: &[u8],
    ) -> Result<DecryptedContent, MlsError>;

    /// Processes a TLS-serialized MLS Commit (external; not produced by this
    /// local group) against `group` and merges the staged commit. This is
    /// the lower-level alternative to `decrypt` when the caller has already
    /// decomposed the incoming wire bytes (e.g. federation / restore).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::DecryptionFailed`] for parse / verification
    /// failures; [`MlsError::CommitProcessingFailed`] if merging fails.
    async fn process_commit(
        &self,
        group: &mut ScpMlsGroup,
        commit_bytes: &[u8],
    ) -> Result<(), MlsError>;

    /// Advances the group epoch via a self-update Commit that republishes
    /// the caller's `LeafNode` with `wrapping_pubkey` (§9.16.1). Returns the
    /// TLS-serialized Commit bytes.
    ///
    /// # Errors
    ///
    /// See [`MlsError`]. Cancel-hostile — the epoch may advance before the
    /// future returns.
    async fn advance_epoch(
        &self,
        group: &mut ScpMlsGroup,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, MlsError>;

    /// Validates a TLS-serialized `KeyPackage` for joinability. Does not
    /// touch any group state; callers use this before committing an add.
    ///
    /// Stateless with respect to the backend: the hardened [`Clock`] used to
    /// re-validate the accepted `Lifetime` (ADR-057 §Prereq-1) is threaded in
    /// as the `clock` parameter rather than read from backend state, so this
    /// method depends on no per-context or per-backend state (ADR-049
    /// Decision 6 / SCP-CRYPTOMOVE-000c). Callers pass the same hardened clock
    /// they inject everywhere else (never openmls's internal wall clock).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::AddMemberFailed`] on validation failure (malformed
    /// KP, signature invalid, ciphersuite mismatch), or
    /// [`MlsError::KeyPackageLifetimeInvalid`] when the accepted `Lifetime`
    /// is expired / out of range under `clock`.
    async fn validate_key_package(
        &self,
        key_package_bytes: &[u8],
        clock: &dyn Clock,
    ) -> Result<ValidatedKeyPackage, MlsError>;

    /// Generates a fresh `KeyPackage` for `credential`, optionally with an
    /// `scp_wrapping_key` `LeafNode` extension. Returns the TLS-serialized KP
    /// bytes plus an opaque signer-state handle the caller retains to later
    /// join a group from a Welcome addressed to this KP.
    ///
    /// # Errors
    ///
    /// See [`MlsError`]. Side-effect-free on external state.
    async fn generate_key_package(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<GeneratedKeyPackage, MlsError>;

    /// Joins a group from a TLS-serialized MLS Welcome message using the
    /// opaque `signer_state` previously returned by `generate_key_package`.
    ///
    /// `key_package_public_bytes` is the TLS-serialized public `KeyPackage`
    /// this signer-state was generated for. It is the single-use anchor's
    /// crypto-layer key: the implementation derives the KP's HPKE init key
    /// (the cryptographically-unique single-use element, RFC 9420 §10) from
    /// these bytes and consults the durable consumed-init-key set (see
    /// [`Self::set_consumed_init_key_store`]) BEFORE completing the join. An
    /// init key already in the set means this KP was already consumed by some
    /// join — the call is rejected with a typed error, defeating a replay at
    /// the crypto layer independent of any higher-level reservation
    /// bookkeeping. On a successful join the init key is durably added to the
    /// set. The backstop covers every join because THIS method
    /// (`MlsBackend::join_from_welcome`) is the only join primitive: the
    /// ADR-049 §9(b) 2F-residual slice deleted the legacy single-slot
    /// `NodeMlsFactory::join_from_welcome` path, which called
    /// `group::join_group_from_bytes` directly, and
    /// `scripts/check-deleted-primitives.sh` rejects its reintroduction.
    /// The production implementation FAILS CLOSED when no store has been
    /// attached — it never silently skips the check.
    ///
    /// The implementation MUST also bind `key_package_public_bytes` to the
    /// init key the Welcome actually consumes, so a mismatched
    /// `(key_package_public_bytes, signer_state)` pair cannot key the marker
    /// against an unrelated init key.
    ///
    /// # Errors
    ///
    /// See [`MlsError`]. Cancel-hostile on the caller's key material.
    /// Returns [`MlsError::KeyPackageReplay`] if the KP's init key is already
    /// in the durable consumed-init-key set.
    async fn join_from_welcome(
        &self,
        welcome_bytes: &[u8],
        signer_state: SignerState,
        key_package_public_bytes: &[u8],
    ) -> Result<ScpMlsGroup, MlsError>;

    /// Attach the durable consumed-init-key set used by
    /// [`Self::join_from_welcome`] as a crypto-layer single-use backstop.
    ///
    /// Production wires the supervisor's shared `mls_storage` here so that a
    /// second join with the same KP init key is rejected durably even if the
    /// `KeyPackageStoreActor`'s reservation bookkeeping has a bug. The
    /// production implementation requires the store to be attached before any
    /// join: with no store attached its `join_from_welcome` fails closed
    /// (deny-by-default). The default trait implementation is a no-op so a
    /// backend that does not maintain the set (a test mock) can opt out of the
    /// crypto-layer set entirely; such a backend's own `join_from_welcome`
    /// defines its single-use policy.
    fn set_consumed_init_key_store(&self, _store: Arc<dyn OpenMlsStorageAdapter>) {}
}
