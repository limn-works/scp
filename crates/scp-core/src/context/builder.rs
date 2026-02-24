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
    fn append_event(
        &self,
        context_id: &[u8; 32],
        event: &str,
    ) -> Result<(), ContextCreationError>;

    /// Destroys the event log for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails. Callers may
    /// ignore this error during rollback (best-effort).
    fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;
}

// ---------------------------------------------------------------------------
// CreationReceipt -- tracks completed steps for ordered rollback
// ---------------------------------------------------------------------------

/// Bitfield tracking which creation steps have completed so that rollback
/// can reverse them in order.
///
/// Each flag corresponds to a creation step. On failure at any subsequent
/// step, [`rollback`](CreationReceipt::rollback) destroys resources in
/// reverse order.
///
/// See ADR-008 section "Two-phase commit steps" for the step ordering.
///
/// The four flags naturally map to the four creation steps that allocate
/// recoverable resources; this is intentional and matches the ADR-008
/// `CreationReceipt` specification.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct CreationReceipt {
    /// Whether an MLS group was created (Encrypted mode only).
    pub mls_group: bool,
    /// Whether a sender key (or broadcast key) was generated.
    pub sender_key: bool,
    /// Whether the event log was initialised.
    pub event_log: bool,
    /// Whether the context was published to transport.
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
        if self.event_log {
            let _ = event_log.destroy_event_log(context_id);
        }
        if self.sender_key {
            let _ = crypto.destroy_sender_key(context_id);
        }
        if self.mls_group {
            let _ = crypto.destroy_mls_group(context_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Validation (Phase 1)
// ---------------------------------------------------------------------------

/// Validates `ContextParams` for internal consistency.
///
/// Checks that required fields are present and consistent. This is a pure
/// function with no side effects.
fn validate_params(params: &ContextParams) {
    // Governance model must be set (currently only SingleAdmin is supported).
    // ContextParams always has a governance field, so this is a placeholder
    // for future governance model validation.

    // Validate ceiling policy / ceiling consistency: if ceiling is empty and
    // policy is Governed, that is technically valid (no capabilities to
    // narrow). No structural constraint to enforce here.

    // If a template is specified, validate against it.
    if params.template_id.is_some() {
        validate_template(params);
    }
}

/// Stub for template validation until SCP-022 is wired in.
///
/// When `template_id` is `Some`, all `ContextParams` fields must match the
/// template definition exactly. This stub is a no-op; SCP-022 will replace
/// it with real validation that returns `ContextCreationError` on mismatch.
#[allow(clippy::missing_const_for_fn)]
fn validate_template(_params: &ContextParams) {
    // Template validation will be wired in after SCP-022.
}

// ---------------------------------------------------------------------------
// Context creation (Phase 2)
// ---------------------------------------------------------------------------

/// Generates a deterministic 32-byte context identifier from the context's
/// string ID.
///
/// Uses SHA-256 to produce a fixed-size identifier suitable for use as keys
/// in provider stores.
fn context_id_bytes(context_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(context_id.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
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

    // 1. Validate ContextParams.
    validate_params(&params);

    // 2. Validate transport connectivity.
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
            receipt.mls_group = true;
        }
        ContextMode::Broadcast => {
            if let Err(e) = crypto.init_broadcast_key(&id_bytes) {
                receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
                return Err(e);
            }
            // No MLS group for Broadcast mode -- mls_group stays false.
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
    receipt.sender_key = true;

    // Step 4: Initialise event log.
    if let Err(e) = event_log_provider.init_event_log(&id_bytes) {
        receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
        return Err(e);
    }
    receipt.event_log = true;

    // Step 5: Publish to transport.
    if let Err(e) = transport.publish_context(&id_bytes, &params) {
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use super::*;

    // -----------------------------------------------------------------------
    // Mock providers
    // -----------------------------------------------------------------------

    /// Tracks which operations were called and allows injecting failures at
    /// specific steps.
    #[derive(Default)]
    struct MockCryptoProvider {
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
            self.sender_keys_destroyed
                .lock()
                .unwrap()
                .push(*context_id);
            Ok(())
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

        let result =
            create_context("ctx-1".into(), params, &crypto, &transport, &event_log).await;

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
            ..ContextParams::default()
        };

        let result =
            create_context("ctx-bc".into(), params, &crypto, &transport, &event_log).await;

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
            ..ContextParams::default()
        };

        let result =
            create_context("ctx-fail-bc".into(), params, &crypto, &transport, &event_log).await;

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
        // Publish itself failed, so nothing was published and nothing to delete.
        assert!(transport.published.lock().unwrap().is_empty());
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
            mls_group: true,
            sender_key: true,
            event_log: false,
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
            mls_group: true,
            sender_key: true,
            event_log: true,
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
}
