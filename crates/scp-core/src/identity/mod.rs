//! DID identity module for SCP.
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
//! SCP separates three key roles:
//! 1. **Identity Key** — Derives the DID string. Highest-security custody.
//!    Used only for DID document updates.
//! 2. **Active Signing Key** — Used for MLS, envelopes, UCANs. Rotatable.
//! 3. **Pre-Rotation Key** — Cold/offline custody. Provides the commitment
//!    for identity migration.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

pub mod dht;
pub mod document;

pub use dht::DidDht;
pub use document::DidDocument;

use scp_platform::traits::{KeyCustody, KeyHandle};

/// An SCP identity containing the DID string, key handles, and pre-rotation
/// commitment.
///
/// Key material never leaves the [`KeyCustody`] boundary — only opaque
/// [`KeyHandle`]s are stored here. The pre-rotation commitment is the SHA-256
/// hash of the pre-rotation key's public key bytes, published in the DID
/// document as a `PreRotationCommitment` service.
///
/// See ADR-003 acceptance criterion 1 for the full construction.
#[derive(Debug)]
pub struct ScpIdentity {
    /// `did:dht` Identity Key. Derives the DID string. Stored in highest-security
    /// custody (Secure Enclave, HSM). Used ONLY for DID document updates and
    /// signing pre-rotation commitments. NEVER for MLS, envelopes, or UCANs.
    pub identity_key: KeyHandle,

    /// Current Active Signing Key. A verification method in the DID document.
    /// Used for MLS credentials, inner envelope signatures, UCAN issuance.
    /// Rotatable via `rotate_active_key` (DID string stays the same).
    pub active_signing_key: KeyHandle,

    /// SHA-256 hash of the next Identity Key's public key.
    /// Published in DID document as a `PreRotationCommitment` service.
    pub pre_rotation_commitment: [u8; 32],

    /// The DID string: `did:dht:z<z-base-32(identity_key.public)>`.
    pub did: String,
}

/// Errors produced by identity operations.
///
/// Covers key generation failures, encoding errors, and DID verification
/// failures. Platform-level key custody errors are wrapped via the `Platform`
/// variant.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// A platform key custody operation failed.
    #[error("platform error: {0}")]
    Platform(#[from] scp_platform::PlatformError),

    /// The DID string has an invalid format.
    #[error("invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// z-base-32 decoding failed.
    #[error("z-base-32 decode error: {0}")]
    ZBase32DecodeError(String),

    /// DID document serialization failed.
    #[error("document serialization error: {0}")]
    DocumentSerializationError(String),
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
    /// Generates the Identity Key, Active Signing Key, and Pre-Rotation Key
    /// via the provided [`KeyCustody`] implementation. Returns the
    /// [`ScpIdentity`] handle and the constructed [`DidDocument`].
    ///
    /// See ADR-003 acceptance criterion 1.
    fn create(
        &self,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send;

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
