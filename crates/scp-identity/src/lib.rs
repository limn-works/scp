#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Decentralized identity (DID) management for SCP.
//!
//! This module implements decentralized identity (DID) creation, verification,
//! and document management for the SCP protocol. The primary DID method is
//! `did:dht`, which uses the `BitTorrent` Mainline DHT for resolution and the
//! Ed25519 public key as the self-certifying identifier.
//!
//! # Architecture
//!
//! - [`ScpIdentity`] — The identity handle containing key handles, DID string,
//!   and pre-rotation commitment.
//! - [`DidMethod`] — Abstract trait enabling DID method swaps (e.g., `did:web`
//!   fallback) without changing calling code.
//! - [`DidDht`] — The `did:dht` implementation of [`DidMethod`].
//! - [`DidDocument`] — W3C DID Document JSON-LD construction and serialization.
//!
//! # Key Separation
//!
//! SCP separates four key roles (three verification methods per ADR-039):
//! 1. **Identity Key (`#0`)** — Derives the DID string. Highest-security custody
//!    (hardware-backed). Used only for DID document updates. Never rotates.
//! 2. **Active Signing Key (`#active`)** — Human's operational key. Used for MLS,
//!    envelopes, UCANs. Rotatable via Layer 1 rotation.
//! 3. **Agent Signing Key (`#agent`)** — Optional. Software-held key for autonomous
//!    agent operations. Rotatable independently. Generated only when agent
//!    delegation is needed. See ADR-039.
//! 4. **Pre-Rotation Key** — Cold/offline custody. Provides the commitment
//!    for identity migration.
//!
//! See ADR-003 and ADR-039 in `.docs/adrs/phase-1.md` for the full design.

pub mod cache;
pub mod config;
pub mod dht;
pub mod dht_client;
pub mod republish;
pub mod resolution;
pub mod resolver;

pub use cache::{DidCache, DidResolutionResult, Staleness};
pub use config::{CreatedIdentity, Identity, IdentityConfig, NoPersistence};
pub use dht::{
    DidDht, InMemorySequenceStore, MigrationOutcome, MigrationPartialState, MigrationResumePhase,
    PostResolveHook, SequenceStore, did_from_ed25519_public_key, extract_public_key,
    verify_bep44_signature, verify_migration, verify_self_certification,
};
pub use dht_client::{DhtClient, InMemoryDhtClient};
#[cfg(feature = "production-dht")]
pub use dht_client::{PkarrDhtClient, PkarrDhtClientBuilder};
pub use republish::RepublishManager;
pub use resolution::{
    InMemoryRelayQuerier, RelayQuerier, RelayQueryRecord, RelayResolveResult, did_routing_id,
    relay_resolve,
};
pub use resolver::{
    DidResolver, DualLayerHealingPublisher, DualLayerResolver, HealingPublisher, MultiRelayQuerier,
    NoOpHealer, NoOpRelayQuerier, ResolutionSource, ResolvedDidDocument, StaleLayer,
};

use serde::{Deserialize, Serialize};

use scp_did::DidDocument;
use scp_platform::traits::{KeyCustody, KeyHandle, PreRotationCustody, PreRotationKeyHandle};

/// An SCP identity containing the DID string, key handles, and pre-rotation
/// commitment.
///
/// Key material never leaves the [`KeyCustody`] boundary — only opaque
/// [`KeyHandle`]s are stored here. The pre-rotation commitment is the SHA-256
/// hash of the pre-rotation key's public key bytes, published in the DID
/// document as a `PreRotationCommitment` service.
///
/// See ADR-003 acceptance criterion 1 and ADR-039 for the full construction.
///
/// `Debug` is implemented manually to redact opaque [`KeyHandle`] slot
/// indices: leaking them via logs/traces enables cross-identity
/// correlation (ordering of key creation across identities sharing a
/// custody) without revealing key material. The DID and commitment
/// hash are public values, so they print verbatim.
#[derive(Clone, Serialize, Deserialize)]
pub struct ScpIdentity {
    /// `did:dht` Identity Key (`#0`). Derives the DID string. Stored in
    /// highest-security custody (Secure Enclave, HSM). Used ONLY for DID
    /// document updates and signing pre-rotation commitments. NEVER for MLS,
    /// envelopes, or UCANs.
    pub identity_key: KeyHandle,

    /// Current Active Signing Key (`#active`). A verification method in the
    /// DID document. Used for MLS credentials, inner envelope signatures, UCAN
    /// issuance. Rotatable via `rotate_active_key` (DID string stays the same).
    pub active_signing_key: KeyHandle,

    /// Optional Agent Signing Key (`#agent`). Software-held key for autonomous
    /// agent operations. `None` when no agent is delegated. Rotatable
    /// independently of `#active`. See ADR-039.
    pub agent_signing_key: Option<KeyHandle>,

    /// SHA-256 hash of the next Identity Key's public key.
    /// Published in DID document as a `PreRotationCommitment` service.
    ///
    /// The corresponding pre-rotation private key is held in a separate
    /// [`PreRotationCustody`](scp_platform::PreRotationCustody) instance
    /// — never in operational [`KeyCustody`] alongside `identity_key` or
    /// `active_signing_key`. Per spec §9.7.4.1 step 3 ("storage isolation")
    /// the pre-rotation key MUST be on a separate custody provider /
    /// authentication flow from daily operations, so that compromise of
    /// the operational custody path does not compromise the recovery path.
    ///
    /// **Snapshot semantics — not authoritative for verification.** This
    /// field is captured at `create_identity` / `migrate_identity` time
    /// and is a convenience cache only. The authoritative source for
    /// migration verification is the `PreRotationCommitment` service
    /// entry on the published [`DidDocument`](scp_did::DidDocument)
    /// (consulted by [`crate::dht::verify_migration`]). If a future SDK
    /// path were to mutate pre-rotation custody outside
    /// `migrate_identity` and the cached value drifted from the
    /// document, the document is canonical — verifiers MUST consult
    /// the document service entry, not this snapshot.
    pub pre_rotation_commitment: [u8; 32],

    /// The DID string: `did:dht:z<z-base-32(identity_key.public)>`.
    pub did: String,
}

impl std::fmt::Debug for ScpIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScpIdentity")
            .field("did", &self.did)
            .field("identity_key", &"KeyHandle(<redacted>)")
            .field("active_signing_key", &"KeyHandle(<redacted>)")
            .field(
                "agent_signing_key",
                &self
                    .agent_signing_key
                    .map_or("None", |_| "KeyHandle(<redacted>)"),
            )
            .field(
                "pre_rotation_commitment",
                &format_args!("{}", hex::encode(self.pre_rotation_commitment)),
            )
            .finish()
    }
}

/// Errors produced by identity operations.
///
/// Covers key generation failures, encoding errors, DID verification
/// failures, and DHT publish/resolve errors. Platform-level key custody
/// errors are wrapped via the `Platform` variant.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// A platform key custody operation failed.
    #[error("platform error: {0}")]
    Platform(#[from] scp_platform::PlatformError),

    /// A pre-rotation custody operation failed.
    ///
    /// Distinct from [`Platform`](Self::Platform) so that callers can
    /// distinguish a daily-operations custody failure from a recovery-path
    /// failure — the two surfaces have different SDK UX implications
    /// (re-authenticate vs. re-prompt for the cold-storage substrate).
    #[error("pre-rotation custody error: {0}")]
    PreRotation(#[from] scp_platform::PreRotationCustodyError),

    /// The DID string has an invalid format.
    #[error("invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// z-base-32 decoding failed.
    #[error("z-base-32 decode error: {0}")]
    ZBase32DecodeError(String),

    /// DID document serialization failed.
    #[error("document serialization error: {0}")]
    DocumentSerializationError(String),

    /// Publishing a DID document to the DHT failed.
    #[error("DHT publish failed: {0}")]
    DhtPublishFailed(String),

    /// Resolving a DID from the DHT failed.
    #[error("DHT resolve failed: {0}")]
    DhtResolveFailed(String),

    /// BEP44 signature verification failed on a resolved DHT record.
    #[error("BEP44 signature verification failed: {0}")]
    Bep44SignatureInvalid(String),

    /// Self-certification check failed: the public key in the resolved
    /// document does not match the z-base-32 decoded DID suffix.
    #[error("self-certification failed: {0}")]
    SelfCertificationFailed(String),

    /// The resolved DID document could not be deserialized.
    #[error("DID document deserialization error: {0}")]
    DocumentDeserializationError(String),

    /// The DID was not found on the DHT.
    #[error("DID not found on DHT: {0}")]
    DhtNotFound(String),

    /// Migration verification failed.
    #[error("migration verification failed: {0}")]
    MigrationVerificationFailed(String),

    /// Key rotation failed.
    #[error("key rotation failed: {0}")]
    KeyRotationFailed(String),

    /// An invalid relay URL was provided (must use wss:// scheme and /scp/v1 path).
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),

    /// Publishing a DID document to an SCP relay failed.
    #[error("relay publish failed: {0}")]
    RelayPublishFailed(String),

    /// Querying an SCP relay for a DID document failed.
    #[error("relay query failed: {0}")]
    RelayQueryFailed(String),

    /// The resolved document has a stale sequence number (lower than last known).
    #[error("stale sequence number: received {received}, last known {last_known}")]
    StaleSequenceNumber {
        /// The sequence number in the received document.
        received: u64,
        /// The last known sequence number for this DID.
        last_known: u64,
    },

    /// An `#agent` verification method already exists in the DID document.
    #[error("agent key already exists in DID document")]
    AgentKeyAlreadyExists,

    /// No `#agent` verification method exists in the DID document.
    #[error("no agent key exists in DID document")]
    AgentKeyNotFound,

    /// The DID document contains multiple `#agent` verification methods.
    #[error("DID document contains {count} #agent verification methods, expected at most 1")]
    MultipleAgentKeys {
        /// The number of `#agent` VMs found.
        count: usize,
    },

    /// Too many retired agent keys in the DID document.
    #[error("too many retired agent keys: found {count}, maximum is {max}")]
    TooManyRetiredAgentKeys {
        /// The number of retired agent keys found.
        count: usize,
        /// The maximum allowed.
        max: usize,
    },

    /// A DHT publish step inside [`DidDht::migrate_identity`](crate::dht::DidDht::migrate_identity)
    /// failed AFTER the irreversible cold-custody mutation (step 5
    /// `destroy_after_migration`) — meaning the caller cannot simply
    /// re-invoke `migrate_identity`. The carried
    /// [`MigrationPartialState`](crate::dht::MigrationPartialState) is the
    /// byte-identical artifact set needed by
    /// [`DidDht::resume_migration_publish`](crate::dht::DidDht::resume_migration_publish)
    /// to finish the migration without re-deriving keys.
    ///
    /// `partial` is boxed to keep [`IdentityError`]'s size bounded — the
    /// partial state holds two full identities, two documents, and a
    /// rotation event, which would otherwise inflate every `Err` path in
    /// the crate.
    #[error("migration publish failed at {phase:?}: {source}")]
    MigrationPublishFailed {
        /// Which publish step failed; dictates which steps the resume
        /// path must re-run.
        phase: MigrationResumePhase,
        /// The recovery handle — pass to
        /// [`DidDht::resume_migration_publish`](crate::dht::DidDht::resume_migration_publish)
        /// to finish the migration. Boxed to keep [`IdentityError`] size
        /// bounded; the partial state aggregates two full identities,
        /// two documents, the rotation event, and a pre-rotation handle.
        partial: Box<crate::dht::MigrationPartialState>,
        /// The underlying publish failure (DHT, relay, or sequence-store
        /// error). Boxed for `IdentityError` size, and surfaced via
        /// [`std::error::Error::source`] so callers can drill into the
        /// root cause.
        #[source]
        source: Box<Self>,
    },
}

impl IdentityError {
    /// Borrows the partial state from a
    /// [`IdentityError::MigrationPublishFailed`] variant. Returns
    /// `None` for any other variant.
    ///
    /// Useful when a caller bubbled the error up through `?` and only
    /// wants to peek at the recovery handle without destructuring the
    /// `IdentityError` enum manually (for example, to log the in-flight
    /// migration's old/new DID strings via
    /// [`crate::dht::MigrationPartialState::old_did`] and
    /// [`crate::dht::MigrationPartialState::new_did`]).
    ///
    /// For owning access — needed when calling
    /// [`crate::dht::DidDht::resume_migration_publish`] — use
    /// [`Self::into_migration_partial`] instead.
    #[must_use]
    pub fn as_migration_partial(&self) -> Option<&crate::dht::MigrationPartialState> {
        match self {
            Self::MigrationPublishFailed { partial, .. } => Some(partial),
            _ => None,
        }
    }

    /// Consumes this error, returning the owned partial state when the
    /// variant is [`IdentityError::MigrationPublishFailed`]. Otherwise
    /// returns the original error verbatim in the `Err` arm so the
    /// caller can re-propagate it.
    ///
    /// This is the idiomatic shape for handing a recovery handle to
    /// [`crate::dht::DidDht::resume_migration_publish`], which consumes
    /// the partial state by value:
    ///
    /// ```ignore
    /// match err.into_migration_partial() {
    ///     Ok(partial) => dht.resume_migration_publish(partial, &custody).await?,
    ///     Err(other) => return Err(other),
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Err(self)` if the variant is not
    /// [`IdentityError::MigrationPublishFailed`] — the original error is
    /// returned unchanged so callers can re-propagate without
    /// allocating a fresh wrapper.
    pub fn into_migration_partial(self) -> Result<crate::dht::MigrationPartialState, Self> {
        match self {
            Self::MigrationPublishFailed { partial, .. } => Ok(*partial),
            other => Err(other),
        }
    }
}

/// Maps the wasm-safe [`DidError`](scp_did::DidError) (raised by the
/// DID-document, verification-method, attestation, and multibase-decode types
/// that live in `scp-did` per ADR-057) onto the corresponding `IdentityError`
/// variant.
///
/// The mapping is variant-for-variant onto the pre-existing `IdentityError`
/// variants, so `?`-propagation from a `scp-did` method yields the *identical*
/// observable error (`IdentityError::InvalidRelayUrl(..)`, etc.) it did before
/// the move — the split is behavior-preserving for every existing consumer,
/// not just compile-preserving. `scp-identity`'s own code constructs these
/// same variants directly for its DHT/config paths, so no new variant is
/// introduced.
impl From<scp_did::DidError> for IdentityError {
    fn from(err: scp_did::DidError) -> Self {
        match err {
            scp_did::DidError::InvalidDidFormat(msg) => Self::InvalidDidFormat(msg),
            scp_did::DidError::DocumentSerializationError(msg) => {
                Self::DocumentSerializationError(msg)
            }
            scp_did::DidError::DocumentDeserializationError(msg) => {
                Self::DocumentDeserializationError(msg)
            }
            scp_did::DidError::InvalidRelayUrl(msg) => Self::InvalidRelayUrl(msg),
            scp_did::DidError::AgentKeyAlreadyExists => Self::AgentKeyAlreadyExists,
            scp_did::DidError::AgentKeyNotFound => Self::AgentKeyNotFound,
            scp_did::DidError::MultipleAgentKeys { count } => Self::MultipleAgentKeys { count },
        }
    }
}

/// Abstract trait for DID method implementations.
///
/// Enables swapping between `did:dht` (primary) and `did:web` (contingency
/// fallback) without changing calling code. See ADR-003 acceptance criterion 6.
///
/// # Implementors
///
/// - [`DidDht`] — Primary implementation using the `BitTorrent` Mainline DHT.
///
/// # Async Methods
///
/// All methods are async because production implementations may involve
/// network I/O (DHT publish/resolve) or hardware security module access.
pub trait DidMethod: Send + Sync {
    /// Creates a new identity with three Ed25519 keypairs.
    ///
    /// Generates the Identity Key and Active Signing Key in the operational
    /// `key_custody`. Generates an ephemeral pre-rotation keypair, hashes
    /// the public key as the `PreRotationCommitment`, hands the private
    /// bytes off to the cold-storage `pre_rotation_custody`, and discards
    /// the operational copy (spec §9.7.4.1 §1, §5(a), §5(f)). The two
    /// custodies MUST be distinct instances on distinct substrates per
    /// §9.7.4.1 §3 (storage isolation).
    ///
    /// Returns the [`ScpIdentity`] handle, the constructed [`DidDocument`],
    /// and the [`PreRotationKeyHandle`] referencing the cold-stored
    /// pre-rotation key. The caller persists the handle alongside the
    /// identity so it can be presented to `migrate_identity` later.
    ///
    /// See ADR-003 acceptance criterion 1.
    fn create(
        &self,
        key_custody: &impl KeyCustody,
        pre_rotation_custody: &impl PreRotationCustody,
    ) -> impl Future<
        Output = Result<(ScpIdentity, DidDocument, PreRotationKeyHandle), IdentityError>,
    > + Send;

    /// Verifies that a DID string is self-certifying for the given public key.
    ///
    /// Decodes the z-base-32 suffix of the DID and compares it to the provided
    /// public key bytes. This is a local operation with no network I/O.
    ///
    /// See ADR-003 acceptance criterion 5.
    fn verify(&self, did_string: &str, public_key: &[u8]) -> bool;

    /// Publishes a DID document to the underlying DID infrastructure.
    ///
    /// For `did:dht`, this publishes to the Mainline DHT as a BEP44 signed
    /// mutable item. See ADR-003 acceptance criterion 2.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-007, not SCP-006.
    fn publish(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;

    /// Resolves a DID string to its DID document via the underlying infrastructure.
    ///
    /// For `did:dht`, this performs a Mainline DHT lookup. See ADR-003
    /// acceptance criterion 3.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-007, not SCP-006.
    fn resolve(
        &self,
        did_string: &str,
    ) -> impl Future<Output = Result<DidDocument, IdentityError>> + Send;

    /// Rotates the active signing key for an identity.
    ///
    /// Generates a new Active Signing Key, updates the DID document, and
    /// publishes the update. See ADR-003 acceptance criterion 4a.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-008, not SCP-006.
    fn rotate(
        &self,
        identity: &ScpIdentity,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send;
}
