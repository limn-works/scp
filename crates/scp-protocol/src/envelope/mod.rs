//! SCP envelope wire format — pure protocol types.
//!
//! SCP_PROTOCOL_VERSION, EnvelopeError, VersionCompatibility.
//! Async modules (pseudonym, inner/sign, outer/ops) stay in scp-runtime.

pub mod chunk;
pub mod inner;
pub mod outer;
pub mod padding;
pub mod validation;

/// SCP protocol version for wire structures (§13.2).
///
/// Encoded as `(major << 8) | minor`. SCP/1.0 = `0x0100` (decimal 256).
/// All envelope types include this as their first serialized field.
pub const SCP_PROTOCOL_VERSION: u16 = 0x0100;

/// Extracts the major version component from a `u16` protocol version.
#[inline]
#[must_use]
pub const fn version_major(version: u16) -> u8 {
    (version >> 8) as u8
}

/// Extracts the minor version component from a `u16` protocol version.
#[inline]
#[must_use]
pub const fn version_minor(version: u16) -> u8 {
    (version & 0xFF) as u8
}

/// Result of checking version compatibility per spec §13.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCompatibility {
    /// Exact version match — fully compatible.
    Exact,
    /// Same major version, different minor — degraded mode (§13.6).
    DegradedMode {
        /// The local implementation's minor version.
        local_minor: u8,
        /// The remote (wire) minor version.
        remote_minor: u8,
    },
}

impl VersionCompatibility {
    /// Returns `true` if this result indicates degraded mode (§13.6).
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self, Self::DegradedMode { .. })
    }

    /// Returns `true` if this result indicates exact version match.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        matches!(self, Self::Exact)
    }

    /// Returns the local and remote minor versions if degraded, or `None` if
    /// the versions match exactly.
    #[must_use]
    pub const fn degraded_versions(&self) -> Option<(u8, u8)> {
        match self {
            Self::DegradedMode {
                local_minor,
                remote_minor,
            } => Some((*local_minor, *remote_minor)),
            Self::Exact => None,
        }
    }
}

/// Checks whether a wire version is compatible with the local protocol version.
pub const fn check_version_compatibility(
    wire_version: u16,
) -> Result<VersionCompatibility, EnvelopeError> {
    let local_major = version_major(SCP_PROTOCOL_VERSION);
    let local_minor = version_minor(SCP_PROTOCOL_VERSION);
    let remote_major = version_major(wire_version);
    let remote_minor = version_minor(wire_version);

    if remote_major != local_major {
        return Err(EnvelopeError::UnsupportedVersion {
            version: wire_version,
        });
    }

    if remote_minor == local_minor {
        Ok(VersionCompatibility::Exact)
    } else {
        Ok(VersionCompatibility::DegradedMode {
            local_minor,
            remote_minor,
        })
    }
}

/// Errors produced by envelope operations.
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

    /// The serialized envelope exceeds `MAX_ENVELOPE_SIZE` (#347).
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

    /// Ed25519 signing via `KeyCustody` failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Ed25519 signature verification failed due to malformed input.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// `MessagePack` serialization failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// `MessagePack` deserialization failed.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    /// Pseudonym derivation via `KeyCustody` failed.
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

    /// Content integrity verification failed.
    #[error("content integrity failed: payload_hash mismatch")]
    ContentIntegrityFailed,

    /// The envelope's major version is incompatible with this implementation.
    #[error("unsupported envelope version: {version:#06x}")]
    UnsupportedVersion {
        /// The version value from the wire.
        version: u16,
    },

    /// Category A violation.
    #[error("Category A violation: {0}")]
    CategoryAViolation(String),

    /// Inner signature mismatch.
    #[error("inner signature mismatch: message rejected")]
    InnerSignatureMismatch,

    /// Sender key encryption failed.
    #[error("sender key encryption failed: {0}")]
    SenderKeyEncryptionFailed(String),

    /// Sender key decryption failed.
    #[error("sender key decryption failed: {0}")]
    SenderKeyDecryptionFailed(String),

    /// The sender is not a member of the MLS group.
    #[error("unknown sender: {0}")]
    UnknownSender(String),

    /// The envelope timestamp is too far in the future (§9.8.2(c)).
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

    /// Sequence regression.
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

    /// Timestamp regression.
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
