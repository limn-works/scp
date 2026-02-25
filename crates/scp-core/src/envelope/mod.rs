//! SCP envelope wire format — inner and outer envelope types, bucket padding,
//! and pseudonym derivation.
//!
//! The SCP envelope is the wire format for all protocol messages. It has two
//! layers:
//!
//! - **Outer envelope** ([`OuterEnvelope`]): visible to relays. Contains only
//!   a pseudonym-based `routing_id`, an optional `recipient_hint`, a `blob_ttl`,
//!   and an opaque `encrypted_blob`.
//!
//! - **Inner envelope** ([`InnerEnvelope`]): visible only to MLS group members
//!   after decryption. Contains the sender's DID, sequence numbers, timestamp,
//!   the bucket-padded payload, provenance metadata, and an Ed25519 signature.
//!
//! See ADR-002 in `.docs/adrs/phase-1.md` for the full envelope design.
//!
//! # Modules
//!
//! - [`inner`] — Inner envelope creation, signing, and verification.
//! - [`outer`] — Outer envelope construction and serialization.
//! - [`padding`] — Bucket padding: [`pad_to_bucket`], [`strip_padding`].
//! - [`pseudonym`] — Per-context pseudonym derivation via [`derive_pseudonym`].

pub mod inner;
pub mod outer;
pub mod padding;
pub mod pseudonym;

// Re-export primary types and functions at the envelope module level.
pub use inner::{InnerEnvelope, Provenance, create_inner_envelope, verify_inner_signature};
pub use outer::{OuterEnvelope, create_outer_envelope, open_envelope, seal_envelope};
pub use padding::{BUCKET_SIZES, pad_to_bucket, strip_padding};
pub use pseudonym::derive_pseudonym;

/// Errors produced by envelope operations.
///
/// Each variant covers a distinct failure mode in envelope creation,
/// verification, padding, or serialization. See ADR-002.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// The payload exceeds the maximum bucket size after accounting for the
    /// 4-byte length suffix.
    #[error("payload too large: {size} bytes, maximum is {max}")]
    PayloadTooLarge {
        /// Actual payload size in bytes.
        size: usize,
        /// Maximum allowed payload size in bytes.
        max: usize,
    },

    /// Padding data is malformed and cannot be stripped.
    #[error("invalid padding: {0}")]
    InvalidPadding(String),

    /// Ed25519 signing via [`KeyCustody`](scp_platform::traits::KeyCustody)
    /// failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Ed25519 signature verification failed due to malformed input (not a
    /// signature mismatch — that returns `Ok(false)`).
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// `MessagePack` serialization failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// `MessagePack` deserialization failed.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    /// Pseudonym derivation via [`KeyCustody`](scp_platform::traits::KeyCustody)
    /// failed.
    #[error("pseudonym derivation failed: {0}")]
    PseudonymDerivationFailed(String),

    /// The `routing_id` field is not a valid 32-byte identifier.
    #[error("invalid routing_id: {0}")]
    InvalidRoutingId(String),

    /// The `recipient_hint` field is not a valid 32-byte identifier.
    #[error("invalid recipient_hint: {0}")]
    InvalidRecipientHint(String),

    /// MLS encryption failed during envelope sealing.
    #[error("MLS encryption failed: {0}")]
    MlsEncryptionFailed(String),

    /// MLS decryption failed during envelope opening.
    #[error("MLS decryption failed: {0}")]
    MlsDecryptionFailed(String),

    /// Content integrity verification failed: `payload_hash` does not match
    /// `SHA-256(stripped_payload)`.
    #[error("content integrity failed: payload_hash mismatch")]
    ContentIntegrityFailed,

    /// The inner envelope signature is valid in form but does not match the
    /// sender's public key — the message has been tampered with or was not
    /// sent by the claimed sender.
    #[error("inner signature mismatch: message rejected")]
    InnerSignatureMismatch,
}
