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

pub mod chunk;
pub mod inner;
pub mod outer;
pub mod padding;
pub mod pseudonym;
pub mod validation;

/// SCP protocol version for wire structures (§13.2).
///
/// Encoded as `(major << 8) | minor`. SCP/1.0 = `0x0100` (decimal 256).
/// All envelope types include this as their first serialized field.
pub const SCP_PROTOCOL_VERSION: u16 = 0x0100;

// Re-export primary types and functions at the envelope module level.
pub use inner::{
    InnerEnvelope, InnerEnvelopeParams, MessageType, Provenance, create_inner_envelope,
    enforce_inner_envelope_category_a, validate_inner_version, verify_inner_signature,
};
pub use outer::{OuterEnvelope, create_outer_envelope, open_envelope, seal_envelope};
pub use padding::{BUCKET_SIZES, pad_to_bucket, strip_padding};
pub use pseudonym::{derive_pseudonym, derive_rotatable_pseudonym};
pub use validation::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_MS, DEFAULT_MAX_MESSAGE_AGE_MS, SequenceTracker,
    TimestampValidator, validate_received_envelope,
};

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

    /// The serialized envelope exceeds [`MAX_ENVELOPE_SIZE`] (#347).
    ///
    /// Checked *before* deserialization to reject obviously oversized inputs
    /// without allocating memory for parsing. This is the first line of
    /// defense against OOM denial-of-service from oversized payloads.
    ///
    /// [`MAX_ENVELOPE_SIZE`]: crate::serde_util::MAX_ENVELOPE_SIZE
    #[error("envelope too large: {size} bytes, maximum is {max}")]
    EnvelopeTooLarge {
        /// Actual wire size in bytes.
        size: usize,
        /// Maximum allowed wire size in bytes.
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

    /// The envelope's `version` field is not supported by this implementation.
    ///
    /// Currently only version `0x0100` (SCP/1.0) is supported. This error
    /// triggers on deserialization or validation to future-proof the wire
    /// format (§13.2).
    #[error("unsupported envelope version: {version:#06x}")]
    UnsupportedVersion {
        /// The version value from the wire.
        version: u16,
    },

    /// An agent key (`#agent`) attempted a Category A action (DID document
    /// modification) via an inner envelope. The action was rejected and a
    /// custody violation attestation was generated.
    ///
    /// See ADR-039 and SCP-AB-020.
    #[error("Category A violation: {0}")]
    CategoryAViolation(String),

    /// The inner envelope signature is valid in form but does not match the
    /// sender's public key — the message has been tampered with or was not
    /// sent by the claimed sender.
    #[error("inner signature mismatch: message rejected")]
    InnerSignatureMismatch,

    /// Sender key AES-256-GCM encryption failed during envelope sealing.
    #[error("sender key encryption failed: {0}")]
    SenderKeyEncryptionFailed(String),

    /// Sender key AES-256-GCM decryption failed during envelope opening.
    ///
    /// This indicates the ciphertext was tampered with, corrupted, or the
    /// wrong sender key was used. Raised before inner envelope deserialization
    /// is attempted.
    #[error("sender key decryption failed: {0}")]
    SenderKeyDecryptionFailed(String),

    /// The sender is not a member of the MLS group.
    ///
    /// The `sender_did` from the inner envelope does not match any credential
    /// in the MLS group's member list. This indicates the inner envelope was
    /// constructed with a DID that is not part of the group.
    #[error("unknown sender: {0}")]
    UnknownSender(String),

    /// The envelope timestamp is too far in the future (§9.8.2(c)).
    ///
    /// The `created_at` timestamp exceeds the local clock plus the configured
    /// clock skew tolerance. This may indicate a replay attack with a
    /// fabricated timestamp or severe clock desynchronization.
    #[error(
        "timestamp in future: envelope={envelope_timestamp}, local={local_time}, \
         tolerance={tolerance_ms}ms"
    )]
    TimestampInFuture {
        /// The envelope's `timestamp` field (Unix milliseconds).
        envelope_timestamp: u64,
        /// The local clock reading (Unix milliseconds).
        local_time: u64,
        /// The configured clock skew tolerance (milliseconds).
        tolerance_ms: u64,
    },

    /// The envelope timestamp is too old (§9.8.2(c)).
    ///
    /// The `created_at` timestamp is more than `max_message_age` behind the
    /// local clock. This may indicate a time-shifted replay attack.
    #[error(
        "timestamp too old: envelope={envelope_timestamp}, local={local_time}, \
         max_age={max_age_ms}ms"
    )]
    TimestampTooOld {
        /// The envelope's `timestamp` field (Unix milliseconds).
        envelope_timestamp: u64,
        /// The local clock reading (Unix milliseconds).
        local_time: u64,
        /// The configured maximum message age (milliseconds).
        max_age_ms: u64,
    },

    /// The envelope's sequence number is not monotonically increasing
    /// (§9.8.2, §9.8.5).
    ///
    /// The received sequence number is less than or equal to the last seen
    /// sequence from the same sender in the same context. This is a replay.
    #[error(
        "sequence regression: sender={sender_did} in context={context_id}, \
         received={received_sequence}, last_seen={last_seen_sequence}"
    )]
    SequenceRegression {
        /// The sender's DID.
        sender_did: String,
        /// The context identifier.
        context_id: String,
        /// The received (regressed) sequence number.
        received_sequence: u64,
        /// The highest previously seen sequence number from this sender.
        last_seen_sequence: u64,
    },

    /// The envelope's timestamp is not monotonically non-decreasing for this
    /// sender (§9.8.2(c)).
    ///
    /// The received timestamp is strictly less than the last seen timestamp
    /// from the same sender in the same context. This catches time-shifted
    /// replays where an attacker bumps the sequence number but uses an older
    /// timestamp.
    #[error(
        "timestamp regression: sender={sender_did} in context={context_id}, \
         received={received_timestamp}, last_seen={last_seen_timestamp}"
    )]
    TimestampRegression {
        /// The sender's DID.
        sender_did: String,
        /// The context identifier.
        context_id: String,
        /// The received (regressed) timestamp.
        received_timestamp: u64,
        /// The highest previously seen timestamp from this sender.
        last_seen_timestamp: u64,
    },
}
