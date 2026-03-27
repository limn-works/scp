//! Context creation types and the `ContextCryptoProvider` trait.
//!
//! Pure sync trait definition and associated error types. The async builder
//! implementation (`create_context`, `CreateContextPhases`) remains in
//! `scp-runtime::context::builder`.

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
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError>;

    /// Creates an MLS group for the given context.
    ///
    /// Called only when `mode == Encrypted`. The provider stores the group
    /// state internally, keyed by `context_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if MLS group creation fails.
    fn create_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Generates a sender key for the given context.
    ///
    /// For `Encrypted` mode this is an AES-256 sender key.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if sender key generation fails.
    fn generate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Initializes a broadcast key for the given context.
    ///
    /// Called only when `mode == Broadcast`. The provider stores the
    /// broadcast key internally, keyed by `context_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if broadcast key initialisation fails.
    fn init_broadcast_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Destroys the MLS group created for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails.
    fn destroy_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Destroys the sender key created for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails.
    fn destroy_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

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
    fn validate_key_package(
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
    fn add_member(
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
    fn remove_member(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<RemoveMemberOutput, ContextError>;

    /// Distributes sender key bundle to a new member via ADR-007.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if distribution fails.
    fn distribute_sender_key(
        &self,
        context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError>;

    /// Removes a member's sender key from all members' stores.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if removal fails.
    fn remove_member_sender_key(
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
    fn rotate_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextError> {
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
    fn drain_pending_sender_key_messages(
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
    fn process_incoming_sender_key(
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
    fn handle_sender_key_request(
        &self,
        _context_id: &[u8; 32],
        _request_bytes: &[u8],
        _requester_public_key: &[u8],
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
    fn seal(
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
    /// Returns `Some(OpenedEnvelope)` for application messages, `None` for
    /// MLS Commit/Proposal messages (no application payload).
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
    fn open(
        &self,
        _context_id: &[u8; 32],
        _outer_bytes: &[u8],
    ) -> Result<Option<OpenedEnvelope>, ContextError> {
        Err(ContextError::CryptoFailed(
            "open not supported by this provider".to_string(),
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
    fn deposit_access_key(
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
    fn advance_epoch(&self, _context_id: &[u8; 32]) -> Result<AdvanceEpochOutput, ContextError> {
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
    fn export_crypto_state(&self, _context_id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
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
    fn restore_crypto_state(
        &self,
        _context_id: &[u8; 32],
        _data: &[u8],
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
    fn prepare_key_package_for_join(&self) -> Result<Vec<u8>, ContextError> {
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
    fn join_from_welcome(
        &self,
        _context_id: &[u8; 32],
        _welcome_bytes: &[u8],
    ) -> Result<(), ContextError> {
        Err(ContextError::CryptoFailed(
            "join_from_welcome not supported".into(),
        ))
    }
}
