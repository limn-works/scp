//! Context creation shared types and errors.
//!
//! Pure sync data types and associated errors. The crypto provider itself
//! (`MlsCryptoProvider`) and the async builder implementation
//! (`create_context`, `CreateContextPhases`) live in
//! `scp-runtime::context::builder` and `scp-runtime::crypto::mls::provider`.
//! After ADR-049 commit 12c.9e, the `ContextCryptoProvider` trait was
//! deleted — callers name the concrete `MlsCryptoProvider` directly.

use super::ContextError;
use crate::envelope::inner::InnerEnvelope;

// ---------------------------------------------------------------------------
// OpenedEnvelope — result of successfully opening a received envelope
// ---------------------------------------------------------------------------

/// Result of successfully opening and verifying a received envelope.
///
/// Returned by `MlsCryptoProvider::open` (in `scp-runtime`) for application messages.
/// Contains the deserialized inner envelope (with all integrity checks
/// passed) and the sender's DID extracted from MLS credentials.
#[derive(Debug, Clone)]
pub struct OpenedEnvelope {
    /// The verified inner envelope with all integrity checks passed.
    pub inner: InnerEnvelope,
    /// The sender's DID extracted from MLS credentials.
    pub sender_did: String,
}

/// Discriminated result of `MlsCryptoProvider::open` (in `scp-runtime`).
///
/// After MLS decryption, the plaintext may be an application message,
/// an MLS control message, or a management message (e.g., sender key
/// distribution). The `SCPM` magic prefix distinguishes management
/// payloads from application payloads.
#[derive(Debug, Clone)]
pub enum OpenResult {
    /// Application message containing a verified inner envelope.
    Application(Box<OpenedEnvelope>),
    /// MLS control message (Commit or Proposal) with no application payload.
    Control,
    /// MLS-wrapped management message (e.g., sender key distribution).
    Management {
        /// The sender's DID extracted from MLS credentials.
        sender_did: String,
        /// The raw management payload after stripping the `SCPM` prefix.
        payload: Vec<u8>,
    },
}

/// 4-byte magic prefix for management messages inside MLS application payloads.
///
/// ASCII `SCPM` (Shared Context Protocol Management). Prepended by
/// `MlsCryptoProvider::mls_encrypt_management` (in `scp-runtime`) and detected by
/// `MlsCryptoProvider::open` (in `scp-runtime`) to distinguish management traffic
/// from application messages.
pub const MANAGEMENT_MSG_MAGIC: [u8; 4] = [0x53, 0x43, 0x50, 0x4D];

/// Maximum management payload size in bytes (64 KiB).
///
/// Management payloads MUST NOT exceed this limit (§9.16.1). Enforced on
/// both send side (`MlsCryptoProvider::mls_encrypt_management` (in `scp-runtime`)) and
/// receive side (`MlsCryptoProvider::open` (in `scp-runtime`)).
pub const MAX_MANAGEMENT_PAYLOAD_SIZE: usize = 65_536;

/// Attempts to strip the [`MANAGEMENT_MSG_MAGIC`] prefix from an MLS
/// plaintext. Returns `Some(payload)` if the first 4 bytes match `SCPM`
/// byte-for-byte, `None` otherwise.
///
/// Per spec §9.16.1 "Management prefix exclusivity", this check MUST
/// occur exactly once per incoming message, at the MLS plaintext →
/// application message boundary. No other layer — transport, relay,
/// outer-envelope processing, sender-key decryption, or any post-dispatch
/// application code — is permitted to strip, test, or depend on the
/// magic prefix. Crypto-provider implementations of
/// `MlsCryptoProvider::open` (in `scp-runtime`) MUST use this helper rather than
/// re-implementing the check inline, so the single-responsibility
/// invariant for management-message framing stays enforceable.
///
/// This function is infallible against any input length (including
/// shorter than 4 bytes — it returns `None` without panicking) and
/// performs no allocation. It does NOT enforce the
/// [`MAX_MANAGEMENT_PAYLOAD_SIZE`] limit — callers MUST apply that check
/// to the returned slice before passing the payload to downstream
/// processing.
#[inline]
#[must_use]
pub fn try_strip_management_prefix(plaintext: &[u8]) -> Option<&[u8]> {
    if plaintext.len() >= MANAGEMENT_MSG_MAGIC.len()
        && plaintext[..MANAGEMENT_MSG_MAGIC.len()] == MANAGEMENT_MSG_MAGIC
    {
        Some(&plaintext[MANAGEMENT_MSG_MAGIC.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod mgmt_prefix_tests {
    use super::{MANAGEMENT_MSG_MAGIC, try_strip_management_prefix};
    use proptest::prelude::*;

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(try_strip_management_prefix(&[]), None);
    }

    #[test]
    fn single_byte_returns_none() {
        assert_eq!(try_strip_management_prefix(&[0x53]), None);
    }

    #[test]
    fn three_byte_prefix_returns_none() {
        // First 3 bytes of SCPM — still too short.
        assert_eq!(try_strip_management_prefix(&[0x53, 0x43, 0x50]), None);
    }

    #[test]
    fn exact_magic_returns_empty_slice() {
        let out = try_strip_management_prefix(&MANAGEMENT_MSG_MAGIC);
        assert_eq!(out, Some(&[][..]));
    }

    #[test]
    fn magic_plus_payload_returns_payload() {
        let mut msg = MANAGEMENT_MSG_MAGIC.to_vec();
        msg.extend_from_slice(b"hello world");
        assert_eq!(try_strip_management_prefix(&msg), Some(&b"hello world"[..]));
    }

    #[test]
    fn fourth_byte_mismatch_returns_none() {
        // SCPN — wrong 4th byte.
        let bytes = [0x53, 0x43, 0x50, 0x4E, 0xAA, 0xBB];
        assert_eq!(try_strip_management_prefix(&bytes), None);
    }

    #[test]
    fn reversed_prefix_returns_none() {
        let bytes = [0x4D, 0x50, 0x43, 0x53, 0xDE, 0xAD];
        assert_eq!(try_strip_management_prefix(&bytes), None);
    }

    proptest! {
        /// Infallibility: the helper must never panic on any input.
        #[test]
        fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..=4096)) {
            let _ = try_strip_management_prefix(&bytes);
        }

        /// Round-trip: prepending the magic and then stripping recovers the
        /// original payload byte-for-byte.
        #[test]
        fn prepend_then_strip_roundtrip(payload in proptest::collection::vec(any::<u8>(), 0..=4096)) {
            let mut msg = MANAGEMENT_MSG_MAGIC.to_vec();
            msg.extend_from_slice(&payload);
            prop_assert_eq!(try_strip_management_prefix(&msg), Some(payload.as_slice()));
        }

        /// Rejection: any input whose first 4 bytes do not match the magic
        /// must return None, regardless of length. Guards against partial
        /// matches on the first 1, 2, or 3 bytes of SCPM.
        #[test]
        fn non_matching_prefix_returns_none(
            prefix_mut in 0u8..=255,
            rest in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            // Build an input where the first byte is replaced by prefix_mut
            // and then arbitrary tail bytes. If prefix_mut happens to start
            // a valid SCPM, skip.
            let mut bytes = vec![prefix_mut];
            bytes.extend_from_slice(&rest);
            if bytes.len() >= MANAGEMENT_MSG_MAGIC.len()
                && bytes[..MANAGEMENT_MSG_MAGIC.len()] == MANAGEMENT_MSG_MAGIC
            {
                return Ok(());
            }
            prop_assert_eq!(try_strip_management_prefix(&bytes), None);
        }
    }
}

// ---------------------------------------------------------------------------
// ContextCreationError
// ---------------------------------------------------------------------------

/// Errors produced by the two-phase context creation flow.
#[derive(Debug, thiserror::Error)]
pub enum ContextCreationError {
    /// Transport layer is not connected or no relay is reachable.
    #[error("transport is not connected")]
    TransportNotConnected,

    /// The creator's identity is invalid or the signing key is not accessible.
    #[error("identity validation failed: {0}")]
    IdentityValidationFailed(String),

    /// An MLS group creation, sender key generation, broadcast key
    /// initialisation, or other crypto operation failed.
    #[error("crypto operation failed: {0}")]
    CryptoFailed(String),

    /// Transport publication or deletion failed.
    #[error("transport operation failed: {0}")]
    TransportFailed(String),

    /// Event log initialisation or append failed.
    #[error("event log operation failed: {0}")]
    EventLogFailed(String),

    /// A context state transition failed.
    #[error(transparent)]
    StateTransition(#[from] ContextError),

    /// Template validation failed.
    #[error("template validation failed: {0}")]
    TemplateValidationFailed(String),

    /// Generic creation failure with a descriptive message.
    #[error("context creation failed: {0}")]
    CreationFailed(String),
}

// ---------------------------------------------------------------------------
// AddMemberOutput
// ---------------------------------------------------------------------------

/// Output of a successful `add_member` operation on a crypto provider.
#[derive(Debug, Clone, Default)]
pub struct AddMemberOutput {
    /// TLS-serialized MLS Welcome message for the newly added member.
    /// Empty for non-MLS providers.
    pub welcome_bytes: Vec<u8>,
    /// TLS-serialized MLS Commit message for existing group members.
    /// Empty for non-MLS providers.
    pub commit_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// RemoveMemberOutput
// ---------------------------------------------------------------------------

/// Output of a successful `remove_member` operation on a crypto provider.
#[derive(Debug, Clone, Default)]
pub struct RemoveMemberOutput {
    /// TLS-serialized MLS Commit message that advances the group epoch.
    /// Must be distributed to all remaining group members so they ratchet
    /// to new key material. Empty for non-MLS providers.
    pub commit_bytes: Vec<u8>,
    /// Optional TLS-serialized `GroupInfo` for external joins.
    /// Empty for non-MLS providers.
    pub group_info_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// AdvanceEpochOutput
// ---------------------------------------------------------------------------

/// Output of a successful `advance_epoch` operation on a crypto provider.
#[derive(Debug, Clone, Default)]
pub struct AdvanceEpochOutput {
    /// TLS-serialized MLS Commit message (Update + self-Commit) that
    /// advances the group epoch. Must be distributed to all group members
    /// so they ratchet to new key material. Empty for non-MLS providers.
    pub commit_bytes: Vec<u8>,
}
