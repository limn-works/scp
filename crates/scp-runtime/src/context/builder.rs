//! Two-phase commit context creation with ordered rollback.
//!
//! Implements the `create_context` flow defined in ADR-008 (`.docs/adrs/phase-2.md`):
//!
//! - **Phase 1 -- Validate:** Checks all preconditions with zero side effects.
//! - **Phase 2 -- Execute:** Steps through context creation, recording each
//!   completed step in a [`CreationReceipt`]. On failure at any step, all
//!   previously completed steps are rolled back in reverse order.
//!
//! External dependencies (transport, event log) are injected via traits
//! ([`ContextTransportProvider`], [`ContextEventLogProvider`]). The crypto
//! layer is the concrete [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider)
//! — the old `ContextCryptoProvider` trait was deleted in ADR-049 commit
//! 12c.9e; the builder names the concrete type directly.

use super::ContextHandle;
use crate::crypto::mls::provider::MlsCryptoProvider;
use scp_protocol::context::templates::validate_against_template;
use scp_protocol::context::{ContextError, ContextMode, ContextParams, ContextState};

pub use scp_protocol::context::builder::{
    AddMemberOutput, AdvanceEpochOutput, ContextCreationError, MANAGEMENT_MSG_MAGIC,
    MAX_MANAGEMENT_PAYLOAD_SIZE, OpenResult, OpenedEnvelope, RemoveMemberOutput,
    try_strip_management_prefix,
};

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

    /// Sends a payload to a specific routing ID (e.g., personal invitation routing ID).
    ///
    /// Used for Welcome delivery (spec §5.12.3). The `ttl` is seconds.
    ///
    /// Default: not supported (returns error).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if sending fails.
    fn send_to_routing_id(
        &self,
        _routing_id: &[u8; 32],
        _payload: &[u8],
        _ttl: u32,
    ) -> Result<(), ContextError> {
        Err(ContextError::TransportFailed(
            "send_to_routing_id not supported".into(),
        ))
    }

    /// Publishes a public `KeyPackage`'s TLS-serialized bytes so other members
    /// can fetch it for offline member addition (§9.16.1). The
    /// `KeyPackageStoreActor` calls this for each pooled KP not yet published.
    ///
    /// `owner_did` is the DID that owns the `KeyPackage`. The relay routing id
    /// is the canonical `derive_key_package_routing_id(owner_did)` (spec
    /// §5.12.3) so a peer can fetch this identity's published `KeyPackage`s with
    /// the SAME id the canonical fetcher computes from the owner's DID. The id
    /// MUST be per-DID: a relay-URL-only id collides every identity onto one
    /// bucket and makes published KPs unfetchable by the canonical path.
    ///
    /// There is no `relay_url` parameter: routing is fully determined by
    /// `owner_did`, and the relay the bytes land on is the adapter's OWN
    /// connection (the production impl publishes through its single configured
    /// adapter). Each `KeyPackage` is therefore published exactly once, not
    /// fanned out per relay URL — a `relay_url` argument would be silently
    /// discarded and imply a fan-out that does not happen.
    ///
    /// Publication is idempotent at the relay: the same `kp_bytes` published
    /// twice resolves to the same content-addressed blob, so a re-publish
    /// (e.g. after an actor respawn) is harmless.
    ///
    /// Default: not supported (returns error). Production transports override.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if publication fails.
    fn publish_key_package(&self, _owner_did: &str, _kp_bytes: &[u8]) -> Result<(), ContextError> {
        Err(ContextError::TransportFailed(
            "publish_key_package not supported".into(),
        ))
    }
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

    /// Appends a typed event to the context's event log.
    ///
    /// `actor_did` is the DID of the actor who produced this event (the sender
    /// for messages, the proposer for governance, the joiner for membership
    /// events). Pass an empty string when the actor is unknown or not
    /// applicable (e.g., system-initiated events).
    ///
    /// `event_type` is the closed-taxonomy [`scp_event_log::EventType`] variant
    /// for this event. `payload` is the structured event payload included in
    /// the Merkle leaf preimage. Parameterized events carry positional
    /// `MessagePack` bytes built via [`scp_event_log::payload::encode_payload`];
    /// non-parameterized events carry an empty [`scp_event_log::EventPayload`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if the append fails.
    fn append_event(
        &self,
        context_id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        payload: scp_event_log::EventPayload,
    ) -> Result<(), ContextCreationError>;

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
    /// `actor_did` is the DID of the actor who produced this event.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if the append fails.
    fn append_context_event(
        &self,
        context_id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
    ) -> Result<(), ContextError> {
        self.append_event(
            context_id,
            event_type,
            actor_did,
            scp_event_log::EventPayload::default(),
        )
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Appends a typed event with a structured payload.
    ///
    /// Like [`append_context_event`](Self::append_context_event) but accepts
    /// a structured [`scp_event_log::EventPayload`] included in the Merkle leaf
    /// preimage (parameterized events).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if the append fails.
    fn append_context_event_with_payload(
        &self,
        context_id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        payload: scp_event_log::EventPayload,
    ) -> Result<(), ContextError> {
        self.append_event(context_id, event_type, actor_did, payload)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    // -- Entry reading (symmetric with append) --------------------------------

    /// Returns the event log entries for a context.
    ///
    /// Completes the read side of the event log interface: `append_event`
    /// writes, `event_log_entries` reads. Without this method, callers holding
    /// a `Box<dyn ContextEventLogProvider>` can write but not read.
    ///
    /// Returns `Ok(None)` if no log exists for the context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if this provider does not
    /// support entry reading.
    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
        let _ = context_id;
        Err(ContextError::EventLogFailed(
            "event log entry reading not supported by this provider".into(),
        ))
    }

    // -- Export/import for context state portability (#363) -------------------

    /// Exports the event log entries for a context as serialized bytes
    /// (MessagePack-encoded `Vec<scp_event_log::Event>`).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if the context has no event
    /// log or serialization fails.
    fn export_event_log_data(&self, context_id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
        let _ = context_id;
        Err(ContextError::EventLogFailed(
            "event log export not supported by this provider".into(),
        ))
    }

    /// Imports serialized event log entries into this provider, replacing
    /// any existing log for the context. The implementation must verify
    /// Merkle chain integrity before accepting.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if deserialization fails or
    /// the Merkle chain is broken.
    fn import_event_log_data(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), ContextError> {
        let _ = (context_id, data);
        Err(ContextError::EventLogFailed(
            "event log import not supported by this provider".into(),
        ))
    }

    /// Returns the Merkle root hash of the event log for a context.
    ///
    /// Returns all zeros if the log is empty. Returns an error if no log
    /// exists for the context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if the provider does not
    /// support Merkle root computation.
    fn event_log_merkle_root(&self, context_id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
        let _ = context_id;
        Err(ContextError::EventLogFailed(
            "merkle root not supported by this provider".into(),
        ))
    }

    // -- Persistence for process restart recovery (#636) --------------------

    /// Restores the event log for a context from persistent storage.
    ///
    /// Called during [`crate::context::supervisor::Supervisor::restore_context`] to reload event log
    /// entries that were persisted before the process restarted.
    ///
    /// The default implementation initializes an empty event log (no-op for
    /// providers without persistence support).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if the persisted data is corrupt
    /// (e.g., broken Merkle chain).
    fn restore_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        // Default: initialize empty event log (no persistence).
        self.init_event_log(context_id)
    }

    /// Prunes event log entries before a checkpoint boundary based on a
    /// [`PruningPolicy`](scp_protocol::context::governance::PruningPolicy).
    ///
    /// Called after creating a governance checkpoint (#1474). The default
    /// implementation is a no-op — providers that support pruning override
    /// this method.
    ///
    /// # Returns
    ///
    /// The number of entries removed, or `None` if no log exists for the
    /// context or the provider does not support pruning.
    fn prune_before_checkpoint(
        &self,
        _context_id: &[u8; 32],
        _checkpoint_event_count: u64,
        _policy: &scp_protocol::context::governance::PruningPolicy,
    ) -> Option<usize> {
        None
    }
}

// ---------------------------------------------------------------------------
// LocalTransportProvider -- production no-op transport for single-user apps
// ---------------------------------------------------------------------------

/// No-op [`ContextTransportProvider`] for single-user or local-only applications.
///
/// All operations succeed immediately with no side effects. Use this when
/// there is no relay to connect to — for example, in a single-user desktop
/// app where all contexts are local.
///
/// Unlike the test-only `MockTransportProvider`, this type is available in
/// production builds and carries no failure-injection machinery.
pub struct LocalTransportProvider;

impl ContextTransportProvider for LocalTransportProvider {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
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

// ---------------------------------------------------------------------------
// NotConfiguredTransportProvider -- returns errors for unconfigured transport
// ---------------------------------------------------------------------------

/// [`ContextTransportProvider`] that returns descriptive errors for all operations.
///
/// Use this at the FFI bridge layer when no relay transport has been configured.
/// Unlike [`LocalTransportProvider`] (which silently succeeds), this provider
/// makes it explicit that transport is not configured — all publish/send/delete
/// calls return errors, and `is_connected()` returns `false`.
///
/// This prevents silent data loss where callers believe messages were sent
/// successfully when no relay is actually reachable.
pub struct NotConfiguredTransportProvider;

impl ContextTransportProvider for NotConfiguredTransportProvider {
    fn is_connected(&self) -> bool {
        false
    }

    fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Err(ContextCreationError::TransportFailed(
            "transport not configured — call transport_connect() to set up a relay \
             before publishing contexts"
                .to_owned(),
        ))
    }

    fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Err(ContextCreationError::TransportFailed(
            "transport not configured — call transport_connect() to set up a relay \
             before deleting published contexts"
                .to_owned(),
        ))
    }

    fn send_message(
        &self,
        _context_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Err(ContextError::TransportFailed(
            "transport not configured — call transport_connect() to set up a relay \
             before sending messages"
                .to_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Opaque resource handles -- represent ownership for rollback tracking
// ---------------------------------------------------------------------------

/// Opaque handle representing ownership of a created MLS group.
///
/// Exists solely to carry type-level evidence that an MLS group was created
/// and needs rollback. The actual MLS group state lives inside the
/// `ContextCryptoProvider`; this handle tracks that the provider holds
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
/// `ContextCryptoProvider`; this handle tracks that the provider holds
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
/// (`ContextCryptoProvider`, [`ContextEventLogProvider`]) which own and
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
        crypto: &MlsCryptoProvider,
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
    scp_protocol::context::memory_scope::validate_memory_scope_for_broadcast(
        params.mode,
        params.memory_scope,
    )
    .map_err(|e: scp_protocol::context::ContextError| {
        ContextCreationError::CreationFailed(e.to_string())
    })?;

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
/// **Phase 1 (validate):** Checks params and identity with zero side effects.
/// Returns early on any validation failure. Transport connectivity is NOT
/// checked — context creation is a local operation.
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
    crypto: &MlsCryptoProvider,
    transport: &dyn ContextTransportProvider,
    event_log_provider: &dyn ContextEventLogProvider,
    creator_did: &str,
) -> Result<ContextHandle, ContextCreationError> {
    // ------------------------------------------------------------------
    // Phase 1 -- Validate (no side effects)
    // ------------------------------------------------------------------

    // 1. Validate ContextParams (including template validation).
    validate_params(&params)?;

    // 2. Validate the creator's identity and signing key accessibility.
    crypto.validate_creator_identity()?;

    // 3. Transport connectivity is NOT checked here. Context creation is a
    //    local operation (MLS group init, sender key generation, event log
    //    bootstrap). Publishing to a relay is a separate step (step 5) that
    //    will surface its own error if the transport is unavailable.

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

    // Step 5: Publish to transport (best-effort).
    //
    // Context creation is a local operation — the context is fully
    // functional even without relay publication.  If publish fails
    // (e.g., transport not configured, relay unreachable), we log a
    // warning and continue.  The context won't be discoverable via
    // relay until a subsequent publish or sync, but all local state
    // (MLS group, sender key, event log) remains valid.
    match transport.publish_context(&id_bytes, &params) {
        Ok(()) => {
            receipt.published = true;
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "context created locally but publish failed — \
                 context is not discoverable via relay"
            );
        }
    }

    // Step 6: Transition state to Active.
    if let Err(e) = handle.transition_to(&ContextState::Active).await {
        receipt.rollback(&id_bytes, crypto, transport, event_log_provider);
        return Err(e.into());
    }

    // Step 7: Append ContextCreated event.
    if let Err(e) = event_log_provider.append_event(
        &id_bytes,
        scp_event_log::EventType::ContextCreated,
        creator_did,
        scp_event_log::EventPayload::default(),
    ) {
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
    clippy::significant_drop_tightening,
    dead_code,
    reason = "ADR-049 commit 12c.9e: scaffolding for tests ignored pending 12c.9f MlsBackend injection"
)]
mod tests {
    use super::*;
    use scp_protocol::context::{ContextParams, MemoryScope};

    /// Test DID for the real [`MlsCryptoProvider`].
    ///
    /// The prior `MockCryptoProvider` fail-injection scaffold was deleted
    /// along with the `ContextCryptoProvider` trait in ADR-049 commit
    /// 12c.9e. Success-path tests bind a real provider; fail-injection
    /// tests are `#[ignore]`d pending `MlsBackend` injection in commit
    /// 12c.9f.
    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    struct TestTransport;
    impl ContextTransportProvider for TestTransport {
        fn is_connected(&self) -> bool {
            true
        }
        fn publish_context(
            &self,
            _: &[u8; 32],
            _: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn send_message(&self, _: &[u8; 32], _: &[u8]) -> Result<(), ContextError> {
            Ok(())
        }
    }

    struct TestEventLog;
    impl ContextEventLogProvider for TestEventLog {
        fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _: &[u8; 32],
            _event_type: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    #[test]
    fn validate_params_full_scope_permitted() {
        // Pure data test — no crypto provider needed.
        let params = ContextParams {
            memory_scope: MemoryScope::Full,
            ..Default::default()
        };
        assert!(validate_params(&params).is_ok());
    }

    /// Smoke verifying that ADR-049 commit 12c.9f's
    /// [`MlsCryptoProvider::with_backends`] seam compiles and that
    /// inherent backend accessors return the injected pointers.
    /// Functional fail-injection tests (one per orchestration path)
    /// extend this seam with mock `MlsBackend`/`HpkeBackend` impls
    /// that return `Err(...)` on a single primitive call; the harness
    /// for those mocks lives next to the production-backend tests in
    /// `crate::crypto::mls::production_backend`.
    #[tokio::test]
    async fn create_context_fail_paths_use_backend_injection() {
        use crate::crypto::hpke_backend::ProductionHpkeBackend;
        use crate::crypto::mls::production_backend::ProductionMlsBackend;
        use crate::crypto::mls::provider::MlsCryptoProvider;
        use std::sync::Arc;

        let provider = MlsCryptoProvider::with_backends(
            TEST_DID.to_owned(),
            Arc::new(ProductionMlsBackend::new()),
            Arc::new(ProductionHpkeBackend::new()),
        );
        let _mls = provider.mls_backend();
        let _hpke = provider.hpke_backend();
    }
}
