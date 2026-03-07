//! Two-phase commit context creation with ordered rollback.
//!
//! Implements the `create_context` flow defined in ADR-008 (`.docs/adrs/phase-2.md`):
//!
//! - **Phase 1 -- Validate:** Checks all preconditions with zero side effects.
//! - **Phase 2 -- Execute:** Steps through context creation, recording each
//!   completed step in a [`CreationReceipt`]. On failure at any step, all
//!   previously completed steps are rolled back in reverse order.
//!
//! External dependencies (crypto, transport, event log) are injected via
//! traits ([`ContextCryptoProvider`], [`ContextTransportProvider`],
//! [`ContextEventLogProvider`]) so the builder is fully testable with mocks.

use super::templates::validate_against_template;
use super::{ContextError, ContextHandle, ContextMode, ContextParams, ContextState};

// ---------------------------------------------------------------------------
// ContextCreationError -- errors specific to context creation
// ---------------------------------------------------------------------------

/// Errors produced by the two-phase context creation flow.
///
/// Extends the base [`ContextError`] with creation-specific failure modes
/// (transport connectivity, crypto operations, event log operations). When
/// module declarations are wired, these variants can be merged into
/// `ContextError` if desired.
#[derive(Debug, thiserror::Error)]
pub enum ContextCreationError {
    /// Transport layer is not connected or no relay is reachable.
    /// Returned during Phase 1 validation.
    #[error("transport is not connected")]
    TransportNotConnected,

    /// The creator's identity is invalid or the signing key is not accessible.
    /// Returned during Phase 1 validation before any side effects.
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

    /// A context state transition failed. Wraps the underlying
    /// [`ContextError`].
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
// Provider traits -- dependency injection for external subsystems
// ---------------------------------------------------------------------------

/// Provides crypto operations needed during context creation.
///
/// Implementors wrap MLS group creation, sender key generation, and their
/// corresponding destruction (rollback). All methods take a `context_id` to
/// scope the created state.
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
    ) -> Result<(), ContextError>;

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

    /// Encrypts a payload with sender key (ADR-007), wraps in inner envelope
    /// (ADR-002), encrypts with MLS (ADR-001), wraps in outer envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if any encryption step fails.
    fn encrypt_message(
        &self,
        context_id: &[u8; 32],
        sender_did: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, ContextError>;
}

/// Provides transport operations needed during context creation.
///
/// Implementors handle relay connectivity checks and context publication /
/// deletion.
pub trait ContextTransportProvider: Send + Sync {
    /// Returns `true` if the transport layer is connected and at least one
    /// relay is reachable.
    fn is_connected(&self) -> bool;

    /// Publishes the context announcement to connected relays.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if publication fails.
    fn publish_context(
        &self,
        context_id: &[u8; 32],
        params: &ContextParams,
    ) -> Result<(), ContextCreationError>;

    /// Best-effort deletion of any published blobs for the context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if deletion fails. Callers may
    /// ignore this error during rollback (best-effort).
    fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    // -- Messaging operations (SCP-020) ------------------------------------

    /// Sends an encrypted message via transport.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if sending fails.
    fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError>;
}

/// Provides event log operations needed during context creation.
///
/// Implementors initialise the Merkle event log and append events.
pub trait ContextEventLogProvider: Send + Sync {
    /// Initialises an empty event log for the given context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if initialisation fails.
    fn init_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    /// Appends a named event to the context's event log.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if the append fails.
    fn append_event(&self, context_id: &[u8; 32], event: &str) -> Result<(), ContextCreationError>;

    /// Destroys the event log for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails. Callers may
    /// ignore this error during rollback (best-effort).
    fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    // -- Membership/messaging event logging (SCP-020) ----------------------

    /// Appends a named event to the context's event log.
    ///
    /// This variant returns [`ContextError`] for use in membership and
    /// messaging operations (as opposed to creation-time operations).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if the append fails.
    fn append_context_event(&self, context_id: &[u8; 32], event: &str) -> Result<(), ContextError> {
        self.append_event(context_id, event)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Opaque resource handles -- represent ownership for rollback tracking
// ---------------------------------------------------------------------------

/// Opaque handle representing ownership of a created MLS group.
///
/// Exists solely to carry type-level evidence that an MLS group was created
/// and needs rollback. The actual MLS group state lives inside the
/// [`ContextCryptoProvider`]; this handle tracks that the provider holds
/// state on behalf of this creation flow.
#[derive(Debug)]
pub struct MlsGroupHandle {
    _private: (),
}

impl MlsGroupHandle {
    /// Creates a new handle (builder-internal only).
    const fn new() -> Self {
        Self { _private: () }
    }
}

/// Opaque handle representing ownership of a created sender key (or broadcast key).
///
/// Like [`MlsGroupHandle`], the actual key material lives inside the
/// [`ContextCryptoProvider`]; this handle tracks that the provider holds
/// sender key state for this context.
#[derive(Debug)]
pub struct SenderKeyHandle {
    _private: (),
}

impl SenderKeyHandle {
    /// Creates a new handle (builder-internal only).
    const fn new() -> Self {
        Self { _private: () }
    }
}

/// Opaque handle representing ownership of a created event log.
///
/// The actual event log state lives inside the [`ContextEventLogProvider`];
/// this handle tracks that the provider holds event log state for this context.
#[derive(Debug)]
pub struct EventLogHandle {
    _private: (),
}

impl EventLogHandle {
    /// Creates a new handle (builder-internal only).
    const fn new() -> Self {
        Self { _private: () }
    }
}

// ---------------------------------------------------------------------------
// CreationReceipt -- tracks completed steps for ordered rollback
// ---------------------------------------------------------------------------

/// Tracks which creation steps have completed so that rollback can reverse
/// them in order.
///
/// Each field corresponds to a creation step. On failure at any subsequent
/// step, [`rollback`](CreationReceipt::rollback) destroys resources in
/// reverse order.
///
/// See ADR-008 section "Two-phase commit steps" for the step ordering.
///
/// ## Design note: `Option<Handle>` vs `Option<T>` vs `bool`
///
/// The ADR-008 spec shows `Option<MlsGroup>`, `Option<SenderKey>`,
/// `Option<EventLog>`. In this implementation, the actual resource state
/// (MLS groups, sender keys, event logs) lives inside the provider traits
/// ([`ContextCryptoProvider`], [`ContextEventLogProvider`]) which own and
/// manage the state. The receipt holds opaque handle types
/// ([`MlsGroupHandle`], [`SenderKeyHandle`], [`EventLogHandle`]) that
/// carry type-level evidence of resource creation without duplicating
/// provider-owned state. `published` remains a `bool` because transport
/// publication has no recoverable local state -- rollback issues a
/// best-effort DELETE to remote relays.
#[derive(Debug, Default)]
pub struct CreationReceipt {
    /// Handle to the MLS group created during step 2 (Encrypted mode only).
    /// `None` for Broadcast mode or if step 2 has not completed.
    pub mls_group: Option<MlsGroupHandle>,
    /// Handle to the sender key (Encrypted) or broadcast key (Broadcast)
    /// created during step 2/3. `None` if the key step has not completed.
    pub sender_key: Option<SenderKeyHandle>,
    /// Handle to the event log initialised during step 4.
    /// `None` if the event log step has not completed.
    pub event_log: Option<EventLogHandle>,
    /// Whether the context was published to transport (step 5).
    pub published: bool,
}

impl CreationReceipt {
    /// Rolls back all completed steps in reverse order.
    ///
    /// Rollback is best-effort: if a destruction step fails, it is ignored
    /// so that subsequent rollback steps still execute. This ensures that a
    /// failure during rollback does not leave additional orphaned state.
    pub fn rollback(
        &self,
        context_id: &[u8; 32],
        crypto: &dyn ContextCryptoProvider,
        transport: &dyn ContextTransportProvider,
        event_log: &dyn ContextEventLogProvider,
    ) {
        // Reverse order: published -> event_log -> sender_key -> mls_group
        if self.published {
            // Best-effort: relays are untrusted, orphaned blobs are encrypted
            // with destroyed keys.
            let _ = transport.delete_published(context_id);
        }
        if self.event_log.is_some() {
            let _ = event_log.destroy_event_log(context_id);
        }
        if self.sender_key.is_some() {
            let _ = crypto.destroy_sender_key(context_id);
        }
        if self.mls_group.is_some() {
            let _ = crypto.destroy_mls_group(context_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Validation (Phase 1)
// ---------------------------------------------------------------------------

/// Validates `ContextParams` for internal consistency.
///
/// Checks that required fields are present and consistent, including template
/// validation when `template_id` is present. This is a pure function with no
/// side effects.
///
/// # Errors
///
/// Returns [`ContextCreationError::TemplateValidationFailed`] if a template
/// is specified and the params do not match the template definition.
fn validate_params(params: &ContextParams) -> Result<(), ContextCreationError> {
    // Governance model validation (SCP-267, ADR-031).
    // GovernanceModel is a variant-only enum in ContextParams. Structural
    // validation (e.g., threshold bounds, signer counts) happens in the
    // ContextManager's create_context/create_context_with_governance methods
    // where the rich GovernanceModelConfig is available. Here we validate
    // only that the governance field is set (it always is — enforced by the
    // type system, since GovernanceModel has no Option wrapper).
    let _ = &params.governance; // field presence guaranteed by the type

    // Validate ceiling policy / ceiling consistency: if ceiling is empty and
    // policy is Governed, that is technically valid (no capabilities to
    // narrow). No structural constraint to enforce here.

    // Validate memory scope is permitted for the context mode (§5.11).
    // Broadcast contexts only support MemoryScope::Full — Ephemeral and
    // Summary require MLS group state destruction which broadcast mode lacks.
    super::memory_scope::validate_memory_scope_for_broadcast(params.mode, params.memory_scope)
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;

    // If a template is specified, validate all params match the template
    // definition exactly.
    if params.template_id.is_some() {
        validate_against_template(params)
            .map_err(|e| ContextCreationError::TemplateValidationFailed(e.to_string()))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Context creation (Phase 2)
// ---------------------------------------------------------------------------

/// Generates a deterministic 32-byte context identifier from the context's
/// string ID.
///
/// Uses the canonical SHA-256 context ID byte derivation.
/// Delegates to [`super::context_id_bytes`].
fn context_id_bytes(context_id: &str) -> [u8; 32] {
    super::context_id_bytes(context_id)
}

/// Executes the two-phase context creation flow.
///
/// **Phase 1 (validate):** Checks params, identity, and transport with zero
/// side effects. Returns early on any validation failure.
///
/// **Phase 2 (execute):** Steps through creation, recording progress in a
/// [`CreationReceipt`]. On failure at any step, all previously completed
/// steps are rolled back in reverse order via
/// [`CreationReceipt::rollback`].
///
/// # Arguments
///
/// * `context_id` -- Unique string identifier for the new context.
/// * `params` -- Full context configuration.
/// * `crypto` -- Provider for MLS and sender key operations.
/// * `transport` -- Provider for relay connectivity and publication.
/// * `event_log_provider` -- Provider for event log initialisation and append.
///
/// # Returns
///
/// A [`ContextHandle`] in the `Active` state on success.
///
/// # Errors
///
/// Returns [`ContextCreationError`] if any validation or execution step
/// fails. After an error, no MLS group state, sender key material, or event
/// log state persists (atomic from the caller's perspective).
///
/// See ADR-008 acceptance criterion 2.
pub async fn create_context(
    context_id: String,
    params: ContextParams,
    crypto: &dyn ContextCryptoProvider,
    transport: &dyn ContextTransportProvider,
    event_log_provider: &dyn ContextEventLogProvider,
) -> Result<ContextHandle, ContextCreationError> {
    // ------------------------------------------------------------------
    // Phase 1 -- Validate (no side effects)
    // ------------------------------------------------------------------

    // 1. Validate ContextParams (including template validation).
    validate_params(&params)?;

    // 2. Validate the creator's identity and signing key accessibility.
    crypto.validate_creator_identity()?;

    // 3. Validate transport connectivity.
    if !transport.is_connected() {
        return Err(ContextCreationError::TransportNotConnected);
    }

    // ------------------------------------------------------------------
    // Phase 2 -- Execute (with ordered rollback)
    // ------------------------------------------------------------------

    let id_bytes = context_id_bytes(&context_id);
    let mut receipt = CreationReceipt::default();

    // Step 1: Create the handle in `Creating` state.
    let handle = ContextHandle::new(context_id, params.clone());

    // Step 2: Create MLS group (Encrypted) or init broadcast key (Broadcast).
    match params.mode {
        ContextMode::Encrypted => {
            if let Err(e) = crypto.create_mls_group(&id_bytes) {
                receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
                return Err(e);
            }
            receipt.mls_group = Some(MlsGroupHandle::new());
        }
        ContextMode::Broadcast => {
            if let Err(e) = crypto.init_broadcast_key(&id_bytes) {
                receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
                return Err(e);
            }
            // No MLS group for Broadcast mode -- mls_group stays None.
        }
    }

    // Step 3: Generate sender key (Encrypted) -- broadcast key already done
    // in step 2 for Broadcast mode.
    if params.mode == ContextMode::Encrypted
        && let Err(e) = crypto.generate_sender_key(&id_bytes)
    {
        receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
        return Err(e);
    }
    // Mark sender_key for both modes: Encrypted has an explicit key,
    // Broadcast's key was initialised in step 2. Rollback destroys it
    // either way.
    receipt.sender_key = Some(SenderKeyHandle::new());

    // Step 4: Initialise event log.
    if let Err(e) = event_log_provider.init_event_log(&id_bytes) {
        receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
        return Err(e);
    }
    receipt.event_log = Some(EventLogHandle::new());

    // Step 5: Publish to transport.
    //
    // If publish_context fails, the transport may have partially published
    // (e.g., sent to 1 of 3 relays). Issue a best-effort DELETE for any
    // partial blobs before rolling back all prior steps. Orphaned blobs on
    // relays are encrypted with keys that will be destroyed during rollback,
    // so they are unusable even if DELETE fails.
    if let Err(e) = transport.publish_context(&id_bytes, &params) {
        // Best-effort cleanup of any partially published blobs.
        let _ = transport.delete_published(&id_bytes);
        receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
        return Err(e);
    }
    receipt.published = true;

    // Step 6: Transition state to Active.
    if let Err(e) = handle.transition_to(&ContextState::Active).await {
        receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
        return Err(e.into());
    }

    // Step 7: Append ContextCreated event.
    if let Err(e) = event_log_provider.append_event(&id_bytes, "ContextCreated") {
        // Even though the handle is Active, we must roll back everything.
        receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
        return Err(e);
    }

    // Step 8: Return the handle.
    Ok(handle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    // -----------------------------------------------------------------------
    // Mock providers
    // -----------------------------------------------------------------------

    /// Tracks which operations were called and allows injecting failures at
    /// specific steps.
    #[derive(Default)]
    struct MockCryptoProvider {
        fail_validate_identity: AtomicBool,
        fail_create_mls: AtomicBool,
        fail_generate_sender_key: AtomicBool,
        fail_init_broadcast_key: AtomicBool,
        mls_groups_created: Mutex<Vec<[u8; 32]>>,
        sender_keys_created: Mutex<Vec<[u8; 32]>>,
        broadcast_keys_created: Mutex<Vec<[u8; 32]>>,
        mls_groups_destroyed: Mutex<Vec<[u8; 32]>>,
        sender_keys_destroyed: Mutex<Vec<[u8; 32]>>,
    }

    impl ContextCryptoProvider for MockCryptoProvider {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            if self.fail_validate_identity.load(Ordering::Relaxed) {
                return Err(ContextCreationError::IdentityValidationFailed(
                    "mock identity validation failure".into(),
                ));
            }
            Ok(())
        }

        fn create_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_create_mls.load(Ordering::Relaxed) {
                return Err(ContextCreationError::CryptoFailed(
                    "mock MLS group creation failure".into(),
                ));
            }
            self.mls_groups_created.lock().unwrap().push(*context_id);
            Ok(())
        }

        fn generate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_generate_sender_key.load(Ordering::Relaxed) {
                return Err(ContextCreationError::CryptoFailed(
                    "mock sender key generation failure".into(),
                ));
            }
            self.sender_keys_created.lock().unwrap().push(*context_id);
            Ok(())
        }

        fn init_broadcast_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_init_broadcast_key.load(Ordering::Relaxed) {
                return Err(ContextCreationError::CryptoFailed(
                    "mock broadcast key init failure".into(),
                ));
            }
            self.broadcast_keys_created
                .lock()
                .unwrap()
                .push(*context_id);
            Ok(())
        }

        fn destroy_mls_group(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.mls_groups_destroyed.lock().unwrap().push(*context_id);
            Ok(())
        }

        fn destroy_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_destroyed.lock().unwrap().push(*context_id);
            Ok(())
        }

        fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn add_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            payload: &[u8],
        ) -> Result<Vec<u8>, ContextError> {
            Ok(payload.to_vec())
        }
    }

    #[derive(Default)]
    struct MockTransportProvider {
        connected: AtomicBool,
        fail_publish: AtomicBool,
        published: Mutex<Vec<[u8; 32]>>,
        deleted: Mutex<Vec<[u8; 32]>>,
    }

    impl MockTransportProvider {
        fn connected() -> Self {
            let p = Self::default();
            p.connected.store(true, Ordering::Relaxed);
            p
        }
    }

    impl ContextTransportProvider for MockTransportProvider {
        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }

        fn publish_context(
            &self,
            context_id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            if self.fail_publish.load(Ordering::Relaxed) {
                return Err(ContextCreationError::TransportFailed(
                    "mock publish failure".into(),
                ));
            }
            self.published.lock().unwrap().push(*context_id);
            Ok(())
        }

        fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.deleted.lock().unwrap().push(*context_id);
            Ok(())
        }

        fn send_message(
            &self,
            _context_id: &[u8; 32],
            _encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockEventLogProvider {
        fail_init: AtomicBool,
        fail_append: AtomicBool,
        inited: Mutex<Vec<[u8; 32]>>,
        events: Mutex<Vec<([u8; 32], String)>>,
        destroyed: Mutex<Vec<[u8; 32]>>,
    }

    impl ContextEventLogProvider for MockEventLogProvider {
        fn init_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_init.load(Ordering::Relaxed) {
                return Err(ContextCreationError::EventLogFailed(
                    "mock event log init failure".into(),
                ));
            }
            self.inited.lock().unwrap().push(*context_id);
            Ok(())
        }

        fn append_event(
            &self,
            context_id: &[u8; 32],
            event: &str,
        ) -> Result<(), ContextCreationError> {
            if self.fail_append.load(Ordering::Relaxed) {
                return Err(ContextCreationError::EventLogFailed(
                    "mock event append failure".into(),
                ));
            }
            self.events
                .lock()
                .unwrap()
                .push((*context_id, event.to_owned()));
            Ok(())
        }

        fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.destroyed.lock().unwrap().push(*context_id);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Success paths
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_encrypted_success() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams::default(); // Encrypted mode by default

        let result = create_context("ctx-1".into(), params, &crypto, &transport, &event_log).await;

        assert!(result.is_ok());
        let handle = result.unwrap();
        assert_eq!(handle.context_id(), "ctx-1");
        assert_eq!(handle.state().await, ContextState::Active);

        // Verify MLS group was created.
        assert_eq!(crypto.mls_groups_created.lock().unwrap().len(), 1);
        // Verify sender key was generated.
        assert_eq!(crypto.sender_keys_created.lock().unwrap().len(), 1);
        // Verify event log was initialised.
        assert_eq!(event_log.inited.lock().unwrap().len(), 1);
        // Verify context was published.
        assert_eq!(transport.published.lock().unwrap().len(), 1);
        // Verify ContextCreated event was appended.
        let events = event_log.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, "ContextCreated");

        // Verify no rollback operations.
        assert!(crypto.mls_groups_destroyed.lock().unwrap().is_empty());
        assert!(crypto.sender_keys_destroyed.lock().unwrap().is_empty());
        assert!(event_log.destroyed.lock().unwrap().is_empty());
        assert!(transport.deleted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_broadcast_success() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: crate::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let result = create_context("ctx-bc".into(), params, &crypto, &transport, &event_log).await;

        assert!(result.is_ok());
        let handle = result.unwrap();
        assert_eq!(handle.context_id(), "ctx-bc");
        assert_eq!(handle.state().await, ContextState::Active);

        // No MLS group for Broadcast mode.
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
        // Broadcast key was initialised.
        assert_eq!(crypto.broadcast_keys_created.lock().unwrap().len(), 1);
        // No separate sender key generation (broadcast key covers it).
        assert!(crypto.sender_keys_created.lock().unwrap().is_empty());
        // Event log initialised and event appended.
        assert_eq!(event_log.inited.lock().unwrap().len(), 1);
        let events = event_log.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, "ContextCreated");
    }

    // -----------------------------------------------------------------------
    // Validation failures (Phase 1 -- no side effects)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_fails_when_transport_disconnected() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::default(); // not connected
        let event_log = MockEventLogProvider::default();

        let result = create_context(
            "ctx-no-transport".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TransportNotConnected
        ));

        // No side effects.
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
        assert!(crypto.sender_keys_created.lock().unwrap().is_empty());
        assert!(event_log.inited.lock().unwrap().is_empty());
        assert!(transport.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_fails_when_identity_invalid() {
        let crypto = MockCryptoProvider::default();
        crypto.fail_validate_identity.store(true, Ordering::Relaxed);
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let result = create_context(
            "ctx-bad-identity".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::IdentityValidationFailed(_)
        ));

        // No side effects -- identity check is in Phase 1.
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
        assert!(crypto.sender_keys_created.lock().unwrap().is_empty());
        assert!(event_log.inited.lock().unwrap().is_empty());
        assert!(transport.published.lock().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // Failure at each step with rollback verification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_rollback_on_mls_group_failure() {
        let crypto = MockCryptoProvider::default();
        crypto.fail_create_mls.store(true, Ordering::Relaxed);
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let result = create_context(
            "ctx-fail-mls".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());

        // Nothing was created (MLS group creation failed before anything
        // was recorded).
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
        assert!(crypto.sender_keys_created.lock().unwrap().is_empty());
        assert!(event_log.inited.lock().unwrap().is_empty());
        assert!(transport.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_rollback_on_sender_key_failure() {
        let crypto = MockCryptoProvider::default();
        crypto
            .fail_generate_sender_key
            .store(true, Ordering::Relaxed);
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let result = create_context(
            "ctx-fail-sk".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());

        // MLS group was created, then rolled back.
        assert_eq!(crypto.mls_groups_created.lock().unwrap().len(), 1);
        assert_eq!(crypto.mls_groups_destroyed.lock().unwrap().len(), 1);

        // No sender key was created.
        assert!(crypto.sender_keys_created.lock().unwrap().is_empty());
        // Event log was not initialised.
        assert!(event_log.inited.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_rollback_on_broadcast_key_failure() {
        let crypto = MockCryptoProvider::default();
        crypto
            .fail_init_broadcast_key
            .store(true, Ordering::Relaxed);
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: crate::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let result = create_context(
            "ctx-fail-bc".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());

        // No MLS group in broadcast mode.
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
        // Broadcast key creation failed.
        assert!(crypto.broadcast_keys_created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_rollback_on_event_log_failure() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();
        event_log.fail_init.store(true, Ordering::Relaxed);

        let result = create_context(
            "ctx-fail-elog".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());

        // MLS group and sender key were created, then rolled back.
        assert_eq!(crypto.mls_groups_created.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_created.lock().unwrap().len(), 1);
        assert_eq!(crypto.mls_groups_destroyed.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap().len(), 1);

        // Event log was not initialised.
        assert!(event_log.inited.lock().unwrap().is_empty());
        // Nothing was published.
        assert!(transport.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_rollback_on_publish_failure() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        transport.fail_publish.store(true, Ordering::Relaxed);
        let event_log = MockEventLogProvider::default();

        let result = create_context(
            "ctx-fail-pub".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());

        // Everything up to publish was created.
        assert_eq!(crypto.mls_groups_created.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_created.lock().unwrap().len(), 1);
        assert_eq!(event_log.inited.lock().unwrap().len(), 1);

        // All rolled back.
        assert_eq!(crypto.mls_groups_destroyed.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap().len(), 1);
        assert_eq!(event_log.destroyed.lock().unwrap().len(), 1);
        // Publish failed, but partial publication rollback issues a
        // best-effort DELETE to clean up any partially published blobs.
        assert!(transport.published.lock().unwrap().is_empty());
        assert_eq!(transport.deleted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn create_context_rollback_on_event_append_failure() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();
        event_log.fail_append.store(true, Ordering::Relaxed);

        let result = create_context(
            "ctx-fail-append".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());

        // Everything was created (including publish).
        assert_eq!(crypto.mls_groups_created.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_created.lock().unwrap().len(), 1);
        assert_eq!(event_log.inited.lock().unwrap().len(), 1);
        assert_eq!(transport.published.lock().unwrap().len(), 1);

        // All rolled back (including delete_published).
        assert_eq!(crypto.mls_groups_destroyed.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap().len(), 1);
        assert_eq!(event_log.destroyed.lock().unwrap().len(), 1);
        assert_eq!(transport.deleted.lock().unwrap().len(), 1);
    }

    // -----------------------------------------------------------------------
    // Receipt rollback ordering
    // -----------------------------------------------------------------------

    #[test]
    fn creation_receipt_rollback_only_destroys_completed_steps() {
        // Simulate a receipt where only MLS group and sender key were created.
        let receipt = CreationReceipt {
            mls_group: Some(MlsGroupHandle::new()),
            sender_key: Some(SenderKeyHandle::new()),
            event_log: None,
            published: false,
        };

        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();
        let id = [0u8; 32];

        receipt.rollback(&id, &crypto, &transport, &event_log);

        // Only MLS group and sender key should be destroyed.
        assert_eq!(crypto.mls_groups_destroyed.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap().len(), 1);
        assert!(event_log.destroyed.lock().unwrap().is_empty());
        assert!(transport.deleted.lock().unwrap().is_empty());
    }

    #[test]
    fn creation_receipt_default_rollback_destroys_nothing() {
        let receipt = CreationReceipt::default();

        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();
        let id = [0u8; 32];

        receipt.rollback(&id, &crypto, &transport, &event_log);

        assert!(crypto.mls_groups_destroyed.lock().unwrap().is_empty());
        assert!(crypto.sender_keys_destroyed.lock().unwrap().is_empty());
        assert!(event_log.destroyed.lock().unwrap().is_empty());
        assert!(transport.deleted.lock().unwrap().is_empty());
    }

    #[test]
    fn creation_receipt_full_rollback_destroys_everything() {
        let receipt = CreationReceipt {
            mls_group: Some(MlsGroupHandle::new()),
            sender_key: Some(SenderKeyHandle::new()),
            event_log: Some(EventLogHandle::new()),
            published: true,
        };

        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();
        let id = [42u8; 32];

        receipt.rollback(&id, &crypto, &transport, &event_log);

        assert_eq!(crypto.mls_groups_destroyed.lock().unwrap().len(), 1);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap().len(), 1);
        assert_eq!(event_log.destroyed.lock().unwrap().len(), 1);
        assert_eq!(transport.deleted.lock().unwrap().len(), 1);

        // Verify the correct context_id was passed.
        assert_eq!(crypto.mls_groups_destroyed.lock().unwrap()[0], id);
        assert_eq!(crypto.sender_keys_destroyed.lock().unwrap()[0], id);
        assert_eq!(event_log.destroyed.lock().unwrap()[0], id);
        assert_eq!(transport.deleted.lock().unwrap()[0], id);
    }

    // -----------------------------------------------------------------------
    // Handle state after successful creation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_handle_preserves_params() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: crate::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let handle = create_context(
            "ctx-params".into(),
            params.clone(),
            &crypto,
            &transport,
            &event_log,
        )
        .await
        .unwrap();

        assert_eq!(*handle.params(), params);
    }

    // -----------------------------------------------------------------------
    // Error variant matching
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_crypto_failure_returns_crypto_error() {
        let crypto = MockCryptoProvider::default();
        crypto.fail_create_mls.store(true, Ordering::Relaxed);
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let result = create_context(
            "ctx-err".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::CryptoFailed(_)
        ));
    }

    #[tokio::test]
    async fn create_context_transport_failure_returns_transport_error() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        transport.fail_publish.store(true, Ordering::Relaxed);
        let event_log = MockEventLogProvider::default();

        let result = create_context(
            "ctx-err".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TransportFailed(_)
        ));
    }

    #[tokio::test]
    async fn create_context_event_log_failure_returns_event_log_error() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();
        event_log.fail_init.store(true, Ordering::Relaxed);

        let result = create_context(
            "ctx-err".into(),
            ContextParams::default(),
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::EventLogFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Template validation during creation (Phase 1)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_context_rejects_mismatched_template_params() {
        use std::time::Duration;

        use crate::context::params::{MemoryScope, TemplateId};
        use crate::context::templates::template_params;

        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        // Start from BilateralEphemeral template but change memory_scope to
        // Full (template expects Ephemeral). This should fail Phase 1
        // validation with no side effects.
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.memory_scope = MemoryScope::Full;

        let result = create_context(
            "ctx-template-mismatch".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TemplateValidationFailed(_)
        ));

        // No side effects -- nothing was created.
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
        assert!(crypto.sender_keys_created.lock().unwrap().is_empty());
        assert!(event_log.inited.lock().unwrap().is_empty());
        assert!(transport.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_rejects_template_missing_required_ttl() {
        use crate::context::params::TemplateId;
        use crate::context::templates::template_params;

        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        // BilateralEphemeral requires a TTL but template_params returns None.
        let params = template_params(&TemplateId::BilateralEphemeral);
        assert!(params.ttl.is_none());

        let result = create_context(
            "ctx-template-no-ttl".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TemplateValidationFailed(_)
        ));

        // No side effects.
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_accepts_valid_template_params() {
        use std::time::Duration;

        use crate::context::params::TemplateId;
        use crate::context::templates::template_params;

        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        // BilateralEphemeral with required TTL should succeed.
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(3600));

        let result = create_context(
            "ctx-template-valid".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_ok());
        let handle = result.unwrap();
        assert_eq!(handle.context_id(), "ctx-template-valid");
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn create_context_rejects_wrong_mode_for_template() {
        use std::time::Duration;

        use crate::context::params::TemplateId;
        use crate::context::templates::template_params;

        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        // BilateralEphemeral expects Encrypted mode; switch to Broadcast.
        // This now fails at broadcast scope validation (§5.11) because
        // BilateralEphemeral has Ephemeral memory scope, which is invalid
        // for broadcast contexts. The scope validation runs before template
        // validation, so CreationFailed is the expected error.
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.mode = ContextMode::Broadcast;

        let result = create_context(
            "ctx-wrong-mode".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::CreationFailed(msg) if msg.contains("MemoryScope::Full")
        ));

        // No side effects.
        assert!(crypto.mls_groups_created.lock().unwrap().is_empty());
        assert!(crypto.broadcast_keys_created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_context_no_template_skips_template_validation() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        // Default params have no template_id -- no template validation runs.
        let params = ContextParams::default();
        assert!(params.template_id.is_none());

        let result = create_context(
            "ctx-no-template".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Broadcast context scope restriction (#337, §5.11)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_broadcast_context_with_ephemeral_scope_rejected() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: crate::context::MemoryScope::Ephemeral,
            ..ContextParams::default()
        };

        let result =
            create_context("ctx-bc-eph".into(), params, &crypto, &transport, &event_log).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::CreationFailed(msg) if msg.contains("MemoryScope::Full")
        ));
    }

    #[tokio::test]
    async fn create_broadcast_context_with_summary_scope_rejected() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: crate::context::MemoryScope::Summary,
            ..ContextParams::default()
        };

        let result =
            create_context("ctx-bc-sum".into(), params, &crypto, &transport, &event_log).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::CreationFailed(msg) if msg.contains("MemoryScope::Full")
        ));
    }

    #[tokio::test]
    async fn create_broadcast_context_with_full_scope_succeeds() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: crate::context::MemoryScope::Full,
            ..ContextParams::default()
        };

        let result = create_context(
            "ctx-bc-full".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn create_encrypted_context_with_ephemeral_scope_succeeds() {
        let crypto = MockCryptoProvider::default();
        let transport = MockTransportProvider::connected();
        let event_log = MockEventLogProvider::default();

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            memory_scope: crate::context::MemoryScope::Ephemeral,
            ..ContextParams::default()
        };

        let result = create_context(
            "ctx-enc-eph".into(),
            params,
            &crypto,
            &transport,
            &event_log,
        )
        .await;

        assert!(result.is_ok());
    }
}
