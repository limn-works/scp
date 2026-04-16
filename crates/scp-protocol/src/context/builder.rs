//! Context creation types and the `ContextCryptoProvider` trait.
//!
//! Async trait definition (via `#[async_trait]`) and associated error types.
//! The async builder implementation (`create_context`, `CreateContextPhases`)
//! remains in `scp-runtime::context::builder`.

use std::collections::HashSet;

use super::ContextError;
use crate::envelope::inner::InnerEnvelope;

// ---------------------------------------------------------------------------
// OpenedEnvelope — result of successfully opening a received envelope
// ---------------------------------------------------------------------------

/// Result of successfully opening and verifying a received envelope.
///
/// Returned by [`ContextCryptoProvider::open`] for application messages.
/// Contains the deserialized inner envelope (with all integrity checks
/// passed) and the sender's DID extracted from MLS credentials.
#[derive(Debug, Clone)]
pub struct OpenedEnvelope {
    /// The verified inner envelope with all integrity checks passed.
    pub inner: InnerEnvelope,
    /// The sender's DID extracted from MLS credentials.
    pub sender_did: String,
}

/// Discriminated result of [`ContextCryptoProvider::open`].
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
/// [`ContextCryptoProvider::mls_encrypt_management`] and detected by
/// [`ContextCryptoProvider::open`] to distinguish management traffic
/// from application messages.
pub const MANAGEMENT_MSG_MAGIC: [u8; 4] = [0x53, 0x43, 0x50, 0x4D];

/// Maximum management payload size in bytes (64 KiB).
///
/// Management payloads MUST NOT exceed this limit (§9.16.1). Enforced on
/// both send side ([`ContextCryptoProvider::mls_encrypt_management`]) and
/// receive side ([`ContextCryptoProvider::open`]).
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
/// [`ContextCryptoProvider::open`] MUST use this helper rather than
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

/// Trait for MLS-backed context crypto operations (create group, add/remove member, encrypt/decrypt).
///
/// All methods are async to support the actor-per-context architecture where
/// every operation crosses an actor message boundary. Current production
/// implementations (`MlsCryptoProvider`) are synchronous in their bodies;
/// the async wrapper adds negligible overhead (one `Box` allocation per call)
/// compared to the MLS crypto operations inside.
#[async_trait::async_trait]
pub trait ContextCryptoProvider: Send + Sync {
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
    async fn validate_creator_identity(&self) -> Result<(), ContextCreationError>;

    /// Creates an MLS group for the given context.
    ///
    /// Called only when `mode == Encrypted`. The provider stores the group
    /// state internally, keyed by `context_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if MLS group creation fails.
    async fn create_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Generates a sender key for the given context.
    ///
    /// For `Encrypted` mode this is an AES-256 sender key.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if sender key generation fails.
    async fn generate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Initializes a broadcast key for the given context.
    ///
    /// Called only when `mode == Broadcast`. The provider stores the
    /// broadcast key internally, keyed by `context_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if broadcast key initialisation fails.
    async fn init_broadcast_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Destroys the MLS group created for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails.
    async fn destroy_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Destroys the sender key created for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails.
    async fn destroy_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    // -- Membership operations (SCP-020) -----------------------------------

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
    async fn validate_key_package(
        &self,
        owner_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError>;

    /// Adds a member to the MLS group (ADR-001 `add_member()`).
    ///
    /// Returns an [`AddMemberOutput`] containing the TLS-serialized MLS
    /// Welcome (for the joiner) and Commit (for existing members). Non-MLS
    /// providers return `AddMemberOutput::default()` (empty bytes).
    ///
    /// # Arguments
    ///
    /// * `context_id` - The 32-byte context identifier.
    /// * `member_did` - The DID of the member to add.
    /// * `key_package_bytes` - Optional TLS-serialized MLS `KeyPackage` bytes.
    ///   `None` for mock providers; production providers require `Some`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS operation fails.
    async fn add_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
        key_package_bytes: Option<&[u8]>,
    ) -> Result<AddMemberOutput, ContextError>;

    /// Removes a member from the MLS group (ADR-001 `remove_member()`).
    ///
    /// Returns a [`RemoveMemberOutput`] containing the TLS-serialized MLS
    /// Commit (for remaining members to process). Non-MLS providers return
    /// `RemoveMemberOutput::default()` (empty bytes).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS operation fails.
    async fn remove_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<RemoveMemberOutput, ContextError>;

    /// Distributes sender key bundle to a new member via ADR-007.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if distribution fails.
    async fn distribute_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError>;

    /// Removes a member's sender key from all members' stores.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if removal fails.
    async fn remove_member_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError>;

    /// Rotates the local sender key for a context (§9.16.4).
    ///
    /// Generates a fresh AES-256 sender key, increments `sender_key_epoch`,
    /// updates the local sender key store, HPKE-seals the new key to each
    /// remaining member's wrapping public key, and queues distribution
    /// messages in `pending_distributions`.
    ///
    /// Called after a member is removed (governance or voluntary departure)
    /// so that the removed party cannot decrypt future messages encrypted
    /// with the new sender key.
    ///
    /// The default implementation is a no-op (`Ok(())`) so that mock and
    /// test providers compile without changes.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key generation, HPKE
    /// sealing, or internal lock acquisition fails.
    async fn rotate_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextError> {
        Ok(())
    }

    /// Drains pending sender key distribution messages for a context.
    ///
    /// Returns `(target_did, serialized_message)` pairs that should be
    /// delivered to the target members via transport. Each message is a
    /// serialized `SenderKeyDistributionMessage::KeyResponse` containing
    /// an HPKE-sealed sender key.
    ///
    /// The default implementation returns an empty vector (no pending
    /// distributions). Production providers that HPKE-seal sender keys
    /// during [`distribute_sender_key`](Self::distribute_sender_key) should
    /// override this to drain their pending queue.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the internal lock is
    /// poisoned.
    async fn drain_pending_sender_key_messages(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        Ok(Vec::new())
    }

    /// Processes an incoming sender key distribution message from a remote
    /// member.
    ///
    /// Deserializes the message, extracts the sender key, and stores it in
    /// the local sender key store so subsequent messages from `sender_did`
    /// can be decrypted.
    ///
    /// The default implementation is a no-op. Production providers that
    /// support HPKE sender key distribution should override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if deserialization, HPKE
    /// decryption, or storage fails.
    async fn process_incoming_sender_key(
        &self,
        _context_id: &[u8; 32],
        _sender_did: &str,
        _message_bytes: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }

    /// Handles an incoming sender key request from a remote member.
    ///
    /// Verifies the request, checks replay protection, and HPKE-seals the
    /// local sender key to the requester's wrapping pubkey.
    ///
    /// Returns `Some(serialized_response)` if the requester should receive
    /// a key, or `None` if the request was silently dropped (e.g., blocked).
    ///
    /// The default implementation returns an error indicating the provider
    /// does not support sender key request handling.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if signature verification,
    /// HPKE encryption, or serialization fails.
    async fn handle_sender_key_request(
        &self,
        _context_id: &[u8; 32],
        _request_bytes: &[u8],
        _requester_public_key: &[u8],
        _blocked_dids: &HashSet<String>,
    ) -> Result<Option<Vec<u8>>, ContextError> {
        Err(ContextError::CryptoFailed(
            "sender key request handling not supported by this provider".to_string(),
        ))
    }

    /// Seals an inner envelope for transport: serializes, sender-key encrypts,
    /// MLS encrypts, wraps in outer envelope.
    ///
    /// This is the primary send-path crypto operation. The caller constructs
    /// the `InnerEnvelope` (including signing); this method handles all
    /// encryption layers.
    ///
    /// The default implementation returns an error. Production providers
    /// (`MlsCryptoProvider`) override this with the full envelope pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if any encryption step fails.
    async fn seal(
        &self,
        _context_id: &[u8; 32],
        _inner: &InnerEnvelope,
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        Err(ContextError::CryptoFailed(
            "seal not supported by this provider".to_string(),
        ))
    }

    /// Opens a received envelope: MLS decrypts, sender-key decrypts,
    /// deserializes, verifies membership + padding + integrity check.
    ///
    /// Returns [`OpenResult::Application`] for application messages,
    /// [`OpenResult::Control`] for MLS Commit/Proposal messages, or
    /// [`OpenResult::Management`] for MLS-wrapped management messages
    /// (identified by the [`MANAGEMENT_MSG_MAGIC`] prefix).
    ///
    /// Signature verification is NOT performed here — the caller
    /// (`ContextManager`) handles it via `key_resolver` after `open` returns.
    ///
    /// The default implementation returns an error. Production providers
    /// (`MlsCryptoProvider`) override this with the full receive pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if MLS decryption, sender key
    /// decryption, deserialization, padding strip, or integrity check fails.
    async fn open(
        &self,
        _context_id: &[u8; 32],
        _outer_bytes: &[u8],
    ) -> Result<OpenResult, ContextError> {
        Err(ContextError::CryptoFailed(
            "open not supported by this provider".to_string(),
        ))
    }

    /// MLS-encrypts a management payload for group-authenticated delivery.
    ///
    /// Prepends the [`MANAGEMENT_MSG_MAGIC`] prefix, MLS-encrypts the result,
    /// and wraps in an outer envelope. Used to send sender key distributions
    /// that are authenticated by MLS membership.
    ///
    /// The default implementation returns an error. Production providers
    /// (`MlsCryptoProvider`) override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if MLS encryption or
    /// serialization fails.
    async fn mls_encrypt_management(
        &self,
        _context_id: &[u8; 32],
        _plaintext: &[u8],
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        Err(ContextError::CryptoFailed(
            "mls_encrypt_management not supported".to_string(),
        ))
    }

    /// Deposits a content access key for a member.
    ///
    /// Called by `ContextManager` after generating an access key for a member
    /// during `create_context` (for the creator) or `join_context` (for new
    /// members). The crypto provider may forward this key to the member
    /// through an out-of-band channel (e.g., `KeyExchange` in tests).
    ///
    /// The default implementation is a no-op. Test providers that need to
    /// share access keys between separate crypto instances should override.
    async fn deposit_access_key(
        &self,
        _context_id: &str,
        _member_did: &str,
        _key: &crate::crypto::access_keys::AccessKey,
    ) {
        // No-op by default.
    }

    // -- Recovery operations (§9.12) -----------------------------------------

    /// Advances the MLS epoch for post-compromise security (§9.12 step 2).
    ///
    /// Issues an MLS Update proposal + self-Commit, ratcheting the group to
    /// a new epoch with fresh key material. After this call, the compromised
    /// old epoch key is useless for future messages.
    ///
    /// Returns an [`AdvanceEpochOutput`] containing the TLS-serialized MLS
    /// Commit message that must be distributed to all group members.
    ///
    /// The default implementation is a no-op returning empty output so that
    /// mock and test providers compile without changes.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS update/commit fails.
    async fn advance_epoch(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<AdvanceEpochOutput, ContextError> {
        Ok(AdvanceEpochOutput::default())
    }

    // -- Persistence operations (§23.11, #645) ------------------------------

    /// Exports the per-context cryptographic state as an opaque byte blob
    /// for persistence alongside the `ContextSnapshot`.
    ///
    /// The returned bytes capture all state needed to resume MLS encryption
    /// and decryption for this context after a process restart: the MLS group
    /// state (tree, epoch secrets, key schedule), the local sender key, the
    /// sender key store (all member keys), the sender key epoch, and per-member
    /// wrapping public keys.
    ///
    /// Returns an empty `Vec` if no crypto state exists for the given context
    /// (e.g., mock providers or broadcast-only contexts).
    ///
    /// The default implementation returns an empty `Vec` (no state to persist).
    /// Production providers that manage MLS groups MUST override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if serialization fails.
    async fn export_crypto_state(&self, _context_id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
        Ok(Vec::new())
    }

    /// Restores per-context cryptographic state from a previously exported
    /// byte blob (produced by [`export_crypto_state`](Self::export_crypto_state)).
    ///
    /// Called during `ContextManager::restore_context` to reinstate MLS
    /// groups and sender keys after a process restart. If `data` is empty,
    /// this is a no-op (the provider was never persisted or is a mock).
    ///
    /// The default implementation is a no-op. Production providers that
    /// manage MLS groups MUST override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if deserialization fails or
    /// the data is corrupt.
    async fn restore_crypto_state(
        &self,
        _context_id: &[u8; 32],
        _data: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }

    /// Returns the per-sender epoch high-water marks for a given context.
    ///
    /// Each `(sender_did, epoch)` pair represents the highest sender key epoch
    /// seen from that participant.  Used by [`ContextManager::import_context`]
    /// to capture the local floors **before** destroying existing crypto state
    /// so the incoming snapshot can be validated against them.
    ///
    /// Returns an empty `Vec` when the context has no epoch state (mock
    /// providers, broadcast-only contexts, or providers that do not track
    /// epochs).
    ///
    /// The default implementation returns an empty `Vec`.  Production
    /// providers that maintain a `SenderKeyStore` MUST override this.
    async fn export_sender_key_epochs(&self, _context_id: &[u8; 32]) -> Vec<(String, u64)> {
        Vec::new()
    }

    /// Validates that the per-sender epoch floors in the just-restored crypto
    /// state do not regress any entry in `local_floors`, then applies a
    /// max-merge so `max(local, imported)` is the effective floor for every
    /// sender (spec §23.17 Invariant 3 + Invariant 4).
    ///
    /// Call this AFTER `restore_crypto_state` during `import_context`, passing
    /// the floors captured via `export_sender_key_epochs` **before** the
    /// destroy+restore cycle.
    ///
    /// Rejects (returns `Err`) if any imported epoch is below its local floor
    /// (regression) **or** exceeds `local_floor + max_advance_per_sender`
    /// (epoch-poisoning guard). No state is mutated on failure.
    ///
    /// The default implementation is a no-op (`Ok`). Production providers MUST
    /// override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::SnapshotFloorRegression`] on regression or
    /// ceiling violation.
    async fn validate_and_merge_epoch_floors(
        &self,
        _context_id: &[u8; 32],
        _local_floors: Vec<(String, u64)>,
        _max_advance_per_sender: u64,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    // -- Welcome delivery operations (§5.12.3, issue #1311) ------------------

    /// Generates a key package for joining a group via Welcome.
    /// Returns TLS-serialized key package bytes. The provider retains the
    /// private state needed to process the incoming Welcome.
    ///
    /// Default: not supported (returns error).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key package generation fails.
    async fn prepare_key_package_for_join(&self) -> Result<Vec<u8>, ContextError> {
        Err(ContextError::CryptoFailed(
            "prepare_key_package_for_join not supported".into(),
        ))
    }

    /// Joins an MLS group from a TLS-serialized Welcome message.
    /// Consumes the retained key package state from `prepare_key_package_for_join`.
    ///
    /// Default: not supported (returns error).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if Welcome processing fails.
    async fn join_from_welcome(
        &self,
        _context_id: &[u8; 32],
        _welcome_bytes: &[u8],
    ) -> Result<(), ContextError> {
        Err(ContextError::CryptoFailed(
            "join_from_welcome not supported".into(),
        ))
    }
}
