//! Context creation types and the `ContextCryptoProvider` trait.
//!
//! Pure sync trait definition and associated error types. The async builder
//! implementation (`create_context`, `CreateContextPhases`) remains in
//! scp-runtime::context::builder.

use super::ContextError;

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
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS operation fails.
    fn remove_member(&self, context_id: &[u8; 32], member_did: &str) -> Result<(), ContextError>;

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

    /// Drains pending sender key distribution messages for a context.
    ///
    /// Returns `(target_did, serialized_message)` pairs that should be
    /// delivered to the target members via transport. Each message is a
    /// serialized [`crate::crypto::sender_keys::key_protocol::SenderKeyDistributionMessage::KeyResponse`] containing
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

    /// Encrypts a payload with sender key (ADR-007), wraps in inner envelope
    /// (ADR-002), encrypts with MLS (ADR-001), wraps in outer envelope.
    ///
    /// `epoch` and `sequence` are bound as Additional Authenticated Data
    /// (AAD) in the sender-key AES-256-GCM layer to prevent ciphertext
    /// relocation across contexts, epochs, and sequence positions.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if any encryption step fails.
    fn encrypt_message(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        payload: &[u8],
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ContextError>;

    /// Decrypts a message received from transport: MLS decrypt (ADR-001),
    /// extract sender DID from the MLS credential, then sender key decrypt
    /// (ADR-007).
    ///
    /// Returns `Ok(Some((plaintext, sender_did)))` for application messages,
    /// or `Ok(None)` when the MLS message was a Commit or Proposal (processed
    /// successfully but containing no application payload).
    ///
    /// `epoch` and `sequence` are the sender-key AAD values. For standard
    /// sender keys these are `(0, 0)` matching the encrypt path.
    ///
    /// The default implementation returns an error. Production providers
    /// (`MlsCryptoProvider`) and E2E test providers override this.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if MLS decryption, credential
    /// extraction, or sender key decryption fails.
    fn decrypt_message(
        &self,
        _context_id: &[u8; 32],
        _ciphertext: &[u8],
        _epoch: u64,
        _sequence: u64,
    ) -> Result<Option<(Vec<u8>, String)>, ContextError> {
        Err(ContextError::CryptoFailed(
            "decrypt_message not supported by this provider".to_string(),
        ))
    }

    // -- Recovery operations (§9.12) -----------------------------------------

    /// Advances the MLS epoch for post-compromise security (§9.12 step 2).
    ///
    /// Issues an MLS Update proposal + self-Commit, ratcheting the group to
    /// a new epoch with fresh key material. After this call, the compromised
    /// old epoch key is useless for future messages.
    ///
    /// The default implementation is a no-op (`Ok(())`) so that mock and
    /// test providers compile without changes.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if the MLS update/commit fails.
    fn advance_epoch(&self, _context_id: &[u8; 32]) -> Result<(), ContextError> {
        Ok(())
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
    /// Called during [`crate::context::manager::ContextManager::restore_context`] to reinstate MLS
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
