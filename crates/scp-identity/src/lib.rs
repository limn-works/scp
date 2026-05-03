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

pub mod attestation;
pub mod cache;
pub mod dht;
pub mod dht_client;
pub mod document;
pub mod republish;
pub mod resolution;
pub mod resolver;

pub use attestation::{
    AttestationPlatform, IdentityLinkPlatform, IdentityLinkServiceEntry, KeyCustodyModel, Platform,
    PlatformAttestation, ScpKeyCustodyAttestation, ServiceRevocationStatus, UnknownPlatformError,
};
pub use cache::{DidCache, DidResolutionResult, Staleness};
pub use dht::{
    DidDht, InMemorySequenceStore, PostResolveHook, SequenceStore, decode_multibase_key,
    did_from_ed25519_public_key, extract_public_key, verify_bep44_signature, verify_migration,
    verify_self_certification,
};
// SigningKeyId re-exported from scp-primitives (see pub use above).
pub use dht_client::{DhtClient, InMemoryDhtClient};
#[cfg(feature = "production-dht")]
pub use dht_client::{PkarrDhtClient, PkarrDhtClientBuilder};
pub use document::{DidDocument, DidRotationEvent, MigrationProof, PreRotationProof};
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

use scp_platform::traits::{KeyCustody, KeyHandle, PreRotationCustody, PreRotationKeyHandle};

// Re-export DID and SigningKeyId from scp-primitives for backward compatibility.
pub use scp_primitives::{DID, SigningKeyId};

/// An SCP identity containing the DID string, key handles, and pre-rotation
/// commitment.
///
/// Key material never leaves the [`KeyCustody`] boundary — only opaque
/// [`KeyHandle`]s are stored here. The pre-rotation commitment is the SHA-256
/// hash of the pre-rotation key's public key bytes, published in the DID
/// document as a `PreRotationCommitment` service.
///
/// See ADR-003 acceptance criterion 1 and ADR-039 for the full construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub pre_rotation_commitment: [u8; 32],

    /// The DID string: `did:dht:z<z-base-32(identity_key.public)>`.
    pub did: String,
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
