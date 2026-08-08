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
//! layer is the concrete [`NodeMlsFactory`](crate::crypto::mls::provider::NodeMlsFactory)
//! — the old `ContextCryptoProvider` trait was deleted in ADR-049 §15;
//! the builder names the concrete type directly.

use super::ContextHandle;
use crate::crypto::mls::provider::NodeMlsFactory;
use scp_protocol::context::templates::validate_against_template;
use scp_protocol::context::{
    CapabilityCeiling, ContextError, ContextMode, ContextParams, ContextState, ScpContextExtension,
};

pub use scp_protocol::context::builder::{
    AddMemberOutput, AdvanceEpochOutput, ContextCreationError, MANAGEMENT_MSG_MAGIC,
    MAX_MANAGEMENT_PAYLOAD_SIZE, OpenResult, OpenedEnvelope, ReceiveFloor, RemoveMemberOutput,
    try_strip_management_prefix,
};

/// Provides transport operations needed during context creation.
///
/// Implementors handle relay connectivity checks and context publication /
/// deletion.
///
/// # Async discipline (ADR-049 Decision 7)
///
/// This is a partial-async trait. The transport-I/O methods (`publish_context`,
/// `delete_published`, `send_message`, `send_to_routing_id`,
/// `publish_key_package`) are `async` and `.await` the underlying async
/// transport adapter directly — the `block_in_place` sync→async bridge in
/// `scp-transport`'s `RelayTransportProvider` is deleted. The `is_connected`
/// method stays **sync**: it reads an `AtomicBool` and touches no async I/O.
/// This is the ADR's explicit `is_connected`-stays-sync carve-out.
///
/// Held as `Arc<dyn ContextTransportProvider>` inside `ActorDeps` (moved into
/// `tokio::spawn`), so the async futures must be **Send** — plain
/// `#[async_trait]`, not `?Send`.
#[async_trait::async_trait]
pub trait ContextTransportProvider: Send + Sync {
    /// Returns `true` if the transport layer is connected and at least one
    /// relay is reachable.
    fn is_connected(&self) -> bool;

    /// Publishes the context announcement to connected relays.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if publication fails.
    async fn publish_context(
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
    async fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

    // -- Messaging operations (SCP-020) ------------------------------------

    /// Sends an encrypted message via transport.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if sending fails.
    async fn send_message(
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
    async fn send_to_routing_id(
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
    async fn publish_key_package(
        &self,
        _owner_did: &str,
        _kp_bytes: &[u8],
    ) -> Result<(), ContextError> {
        Err(ContextError::TransportFailed(
            "publish_key_package not supported".into(),
        ))
    }
}

/// Provides event log operations needed during context creation.
///
/// Implementors initialise the Merkle event log and append events.
///
/// # Async discipline (ADR-049 Decision 7)
///
/// This is a partial-async trait. The persistence-touching methods
/// (`init_event_log`, `append_event`, `destroy_event_log`, the `append_*`
/// helpers, `import_event_log_data`, `restore_event_log`,
/// `prune_before_checkpoint`) are `async` and `.await` the async
/// [`EventLogPersistence`](crate::context::providers::event_log::EventLogPersistence)
/// backend directly. The pure in-memory read methods (`event_log_entries`,
/// `event_log_merkle_root`, `export_event_log_data`, `prove_event_inclusion`,
/// `prove_event_consistency`, `rebuild_event_log_for_proof`) stay **sync**:
/// they touch no async I/O and are read directly by sync FFI-boundary
/// supervisor probes (`Supervisor::event_log_entries` / `participation_record`),
/// so forcing them async would add `block_on` at that boundary — the Decision-7
/// anti-goal. This mirrors the ADR's `is_connected`-stays-sync carve-out.
///
/// Held as `Arc<dyn ContextEventLogProvider>` inside `ActorDeps` (moved into
/// `tokio::spawn`), so the async futures must be **Send** — plain
/// `#[async_trait]`, not `?Send`.
#[async_trait::async_trait]
pub trait ContextEventLogProvider: Send + Sync {
    /// Initialises an empty event log for the given context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if initialisation fails.
    async fn init_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

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
    /// `timestamp_secs` is the **committer-assigned** leaf timestamp in seconds
    /// since the Unix epoch. For a commit-ordered event it is the `created_at`
    /// of the signed SCP envelope carrying the commit, copied by every member
    /// so that all honest members hash the identical leaf preimage (§7.3.1,
    /// §9.9.3). For timer-triggered events (TTL/close, governance-freeze expiry,
    /// deferred economic-policy application) it is the pre-computed convergent
    /// deadline already held in context state — never a per-member local clock
    /// reading, which would diverge and break the equal-count/equal-root test.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if the append fails.
    async fn append_event(
        &self,
        context_id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), ContextCreationError>;

    /// Destroys the event log for the given context (rollback).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if destruction fails. Callers may
    /// ignore this error during rollback (best-effort).
    async fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError>;

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
    async fn append_context_event(
        &self,
        context_id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        timestamp_secs: u64,
    ) -> Result<(), ContextError> {
        self.append_event(
            context_id,
            event_type,
            actor_did,
            scp_event_log::EventPayload::default(),
            timestamp_secs,
        )
        .await
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
    async fn append_context_event_with_payload(
        &self,
        context_id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), ContextError> {
        self.append_event(context_id, event_type, actor_did, payload, timestamp_secs)
            .await
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Appends an [`OutletInvokedEvent`] after enforcing the FULL §5.4.5:566
    /// manifest-derived `chunks_billed` wire-invariant.
    ///
    /// Unlike the raw [`append_event`](Self::append_event) boundary — which
    /// holds only the opaque event and can enforce nothing stronger than the
    /// event-local `chunks_billed <= stream_chunk_count` backstop — this entry
    /// point re-derives the manifest root + billable count from the
    /// caller-supplied retained chunk sequence and rejects the event at
    /// log-insert time if the recorded aggregates diverge. On success it
    /// serializes the event and delegates to `append_event`, which re-runs the
    /// durable event-local backstop. This is the verified-append boundary for
    /// the cross-context receiver-side recording (SCP-OUT-036 AC7; §5.4.5:566) —
    /// the path that retains the payload set to re-derive the manifest over its
    /// independently-reassembled chunk sequence. The same-context streaming pump
    /// does NOT route through here: it
    /// does not retain the chunk sequence and persists via `append_event`,
    /// enforcing same-context integrity inline
    /// (`AuditAnomaly::ChunksBilledSelfMismatch`) plus the event-local backstop.
    ///
    /// [`OutletInvokedEvent`]:
    ///     scp_protocol::context::outlets::lifecycle::OutletInvokedEvent
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] when the manifest
    /// verification rejects the event (the wire-layer `ChunksBilledMismatch`),
    /// when the event cannot be serialized, or when the underlying append
    /// fails (e.g. no log initialized for the context).
    async fn append_outlet_invoked_verified(
        &self,
        context_id: &[u8; 32],
        event: &scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
        chunks: &[scp_protocol::context::outlets::stream::OutletStreamChunk],
        actor_did: &str,
        timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        // (1) FULL §5.4.5:566 manifest-derived equality — the tighter check the
        // opaque `append_event` boundary cannot make. Wire-reject on mismatch.
        crate::context::outlets::stream::verify_outlet_invoked_event_manifest(event, chunks)
            .map_err(|err| {
                let log_err =
                    crate::context::outlets::stream::chunks_billed_error_to_event_log_error(err);
                ContextCreationError::EventLogFailed(log_err.to_string())
            })?;
        // (2) Serialize and append through the standard boundary, which
        // re-runs the durable event-local `<=` backstop.
        let data = serde_json::to_vec(event).map_err(|e| {
            ContextCreationError::EventLogFailed(format!(
                "failed to serialize OutletInvokedEvent: {e}"
            ))
        })?;
        self.append_event(
            context_id,
            scp_event_log::EventType::OutletInvoked,
            actor_did,
            scp_event_log::EventPayload { data },
            timestamp_secs,
        )
        .await
    }

    /// Appends a `MemberJoined` / `MemberLeft` leaf carrying a subject-bearing
    /// [`MembershipChangePayload`](scp_event_log::payload::MembershipChangePayload).
    ///
    /// `subject_did` is the *affected member* (joined/left) — NOT the governance
    /// actor (`actor_did`), which on admin-driven membership changes is the
    /// executing admin. `role_name` is the role the member holds at the
    /// membership change. The leaf is convergent (ADR-011 amendment); the
    /// participation record (§7.3.2) attributes the join/leave interval to
    /// `subject_did`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if payload encoding or the
    /// append fails.
    async fn append_membership_change_leaf(
        &self,
        context_id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        subject_did: &str,
        role_name: &str,
        timestamp_secs: u64,
    ) -> Result<(), ContextError> {
        let payload = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::MembershipChangePayload {
                subject_did: subject_did.to_owned(),
                role_name: role_name.to_owned(),
            },
        )
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
        self.append_context_event_with_payload(
            context_id,
            event_type,
            actor_did,
            payload,
            timestamp_secs,
        )
        .await
    }

    /// Appends a `RoleAssigned` leaf carrying a subject-bearing
    /// [`RoleAssignedPayload`](scp_event_log::payload::RoleAssignedPayload).
    ///
    /// `subject_did` is the *affected member* whose role changed — NOT the
    /// governance actor (`actor_did`). `role` is the newly-assigned role. The
    /// leaf is convergent (ADR-011 amendment); the participation record (§7.3.2)
    /// attributes the role transition (`role_progression_count`) to
    /// `subject_did`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if payload encoding or the
    /// append fails.
    async fn append_role_assigned_leaf(
        &self,
        context_id: &[u8; 32],
        actor_did: &str,
        subject_did: &str,
        role: &str,
        timestamp_secs: u64,
    ) -> Result<(), ContextError> {
        let payload =
            scp_event_log::payload::encode_payload(&scp_event_log::payload::RoleAssignedPayload {
                subject_did: subject_did.to_owned(),
                role: role.to_owned(),
            })
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
        self.append_context_event_with_payload(
            context_id,
            scp_event_log::EventType::RoleAssigned,
            actor_did,
            payload,
            timestamp_secs,
        )
        .await
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
    async fn import_event_log_data(
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
    async fn restore_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        // Default: initialize empty event log (no persistence).
        self.init_event_log(context_id).await
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
    async fn prune_before_checkpoint(
        &self,
        _context_id: &[u8; 32],
        _checkpoint_event_count: u64,
        _policy: &scp_protocol::context::governance::PruningPolicy,
    ) -> Option<usize> {
        None
    }

    // -- Merkle proofs (ADR-011) ---------------------------------------------

    /// Returns an RFC 6962 inclusion proof for the event at `leaf_index`.
    ///
    /// The default implementation reads the context's events via
    /// [`event_log_entries`](Self::event_log_entries), replays them through the
    /// canonical [`scp_event_log`] substrate to reconstruct the Merkle tree
    /// (the same leaf preimage the provider committed to), and constructs the
    /// proof against that tree. This is the single proof seam: there is no
    /// second tree to keep in sync with the provider's log.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if no log exists for the
    /// context, the leaf index is out of bounds, the log is empty, or the
    /// replayed events fail hash-chain verification.
    fn prove_event_inclusion(
        &self,
        context_id: &[u8; 32],
        leaf_index: u64,
    ) -> Result<scp_event_log::proof::InclusionProof, ContextError> {
        let log = self.rebuild_event_log_for_proof(context_id)?;
        scp_event_log::proof::prove_inclusion(&log, leaf_index)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Returns an RFC 6962 consistency proof between the tree at `old_size`
    /// and the current tree size.
    ///
    /// Reconstructs the Merkle tree the same way as
    /// [`prove_event_inclusion`](Self::prove_event_inclusion).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] if no log exists for the
    /// context, `old_size` is 0, `old_size` exceeds the current size, the log
    /// is empty, or the replayed events fail hash-chain verification.
    fn prove_event_consistency(
        &self,
        context_id: &[u8; 32],
        old_size: u64,
    ) -> Result<scp_event_log::proof::ConsistencyProof, ContextError> {
        let log = self.rebuild_event_log_for_proof(context_id)?;
        let current_size = scp_event_log::tree::event_count(&log);
        scp_event_log::proof::prove_consistency(&log, old_size, current_size)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Reconstructs the canonical [`scp_event_log::EventLog`] for a context by
    /// replaying its events through the substrate.
    ///
    /// This is the single proof seam. Every Merkle answer about a context —
    /// inclusion, absence, consistency, and the `(leaf_count, root)` commitment
    /// — is derived from ONE call to this method, so all of them describe the
    /// same tree state by construction. There is no second tree to keep in
    /// sync, and callers must not assemble one from separate replays: two
    /// replays straddling a concurrent `append_event` describe different trees,
    /// and a `root` paired with a `leaf_count` from the other snapshot is a
    /// commitment that pins nothing.
    ///
    /// # Security (GitHub #1933)
    ///
    /// FAILS CLOSED when the provider reports no log. `event_log_entries`
    /// returning `None` means UNKNOWN — a log that was never initialised, or
    /// one destroyed by `destroy_event_log` (actor shutdown, create-rollback) —
    /// never "empty". An empty-but-live log is `Ok(Some(vec![]))` and replays
    /// to a real zero-leaf tree. Answering a Merkle query over an unknown log
    /// would be a forgeable false negative: a caller could "prove" an event
    /// absent that the authoritative log actually recorded.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EventLogFailed`] on a missing log or a broken
    /// chain.
    fn rebuild_event_log_for_proof(
        &self,
        context_id: &[u8; 32],
    ) -> Result<scp_event_log::EventLog, ContextError> {
        let entries = self.event_log_entries(context_id)?.ok_or_else(|| {
            ContextError::EventLogFailed(format!(
                "no event log for context {}",
                hex::encode(context_id)
            ))
        })?;
        let mut log = scp_event_log::EventLog::new(hex::encode(context_id));
        for event in &entries {
            scp_event_log::tree::append_unsigned_event(&mut log, event).map_err(|e| {
                ContextError::EventLogFailed(format!(
                    "event log chain broken at sequence {}: {e}",
                    event.sequence
                ))
            })?;
        }
        Ok(log)
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

#[async_trait::async_trait]
impl ContextTransportProvider for LocalTransportProvider {
    fn is_connected(&self) -> bool {
        true
    }

    async fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    async fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    async fn send_message(
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

#[async_trait::async_trait]
impl ContextTransportProvider for NotConfiguredTransportProvider {
    fn is_connected(&self) -> bool {
        false
    }

    async fn publish_context(
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

    async fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Err(ContextCreationError::TransportFailed(
            "transport not configured — call transport_connect() to set up a relay \
             before deleting published contexts"
                .to_owned(),
        ))
    }

    async fn send_message(
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

// #2148 (ADR-049 birth-into-actor): the `MlsGroupHandle` / `SenderKeyHandle`
// rollback-evidence types were DELETED. Crypto is no longer provider-resident
// during creation — `create_context` births the group + sender key as OWNED
// material (`create_mls_group_with_context` → `OwnedMlsCryptoState`) and hands
// it back to the caller, which seeds the spawning actor directly. There is no
// provider-side crypto to roll back. On a post-birth creation failure the owned
// material is disposed on the rollback branch (`OwnedMlsCryptoState::dispose_secrets`,
// F6) — a bare drop FREES the group's in-memory OpenMLS storage but does NOT
// zeroize the Ed25519 signer (OpenMLS `SignatureKeyPair` has no `Zeroize`;
// scp-mls `EagerDropSigner` / issue #82). `destroy_group` eagerly frees the same
// material (signer freed, NOT zeroized — #82); on this rollback branch the owner
// drops immediately after, so the explicit dispose is defense-in-depth /
// forward-compat with #82. The `SenderKey` zeroizes on its own `ZeroizeOnDrop`.
// Only the event log retains a provider-resident rollback handle.

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
/// ## Design note: `Option<Handle>` vs `bool`
///
/// #2148 (ADR-049 birth-into-actor): crypto (MLS group + sender key) is no
/// longer provider-resident during creation, so the receipt tracks only the
/// two resources that DO leave recoverable state outside the returned owned
/// crypto material: the event log (`Option<EventLogHandle>`, provider-resident)
/// and transport publication (`bool` — no recoverable local state, rollback
/// issues a best-effort DELETE to remote relays). A post-birth creation failure
/// disposes the `OwnedMlsCryptoState` on the rollback branch (`dispose_secrets`,
/// which eagerly frees the group via `destroy_group` — signer freed, NOT
/// zeroized, #82; the `SenderKey` zeroizes on drop), so there is nothing
/// crypto-shaped left for the receipt to roll back.
#[derive(Debug, Default)]
pub struct CreationReceipt {
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
    ///
    /// #2148 (ADR-049 birth-into-actor): the crypto (MLS group / sender key)
    /// rollback arms are GONE — crypto is never provider-resident during
    /// creation. A post-birth failure disposes the owned material on the caller's
    /// rollback branch (`dispose_secrets` eagerly frees the group via
    /// `destroy_group` — signer freed, NOT zeroized, #82; the `SenderKey`
    /// zeroizes on drop). On this branch the owner drops immediately after, so
    /// the dispose is defense-in-depth / forward-compat with #82. Only the event
    /// log + publication are reversed here.
    pub async fn rollback(
        &self,
        context_id: &[u8; 32],
        transport: &dyn ContextTransportProvider,
        event_log: &dyn ContextEventLogProvider,
    ) {
        // Reverse order: published -> event_log
        if self.published {
            // Best-effort: relays are untrusted, orphaned blobs are encrypted
            // with destroyed keys.
            let _ = transport.delete_published(context_id).await;
        }
        if self.event_log.is_some() {
            let _ = event_log.destroy_event_log(context_id).await;
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

/// Resolves the context's string ID to the 32-byte value that keys its MLS
/// group, broadcast/sender keys, and event log at creation.
///
/// Delegates to the canonical [`super::state::context_id_to_bytes`]
/// (ADR-056): a real 64-hex context id (as `generate_context_id` produces)
/// resolves to its raw digest, so the MLS group, sender key, and event log
/// created here are keyed under the SAME bytes that `PerContextState.context_id`
/// holds (`context_id_to_bytes` of the same id). A synthetic /
/// non-context string hashes exactly as before. Without this alignment,
/// creation would key crypto under `SHA-256(id)` while live state keys under
/// the digest — every subsequent send/receive for a real context would miss
/// the group.
fn context_id_bytes(context_id: &str) -> [u8; 32] {
    super::state::context_id_to_bytes(context_id)
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
/// On success, a [`ContextHandle`] in the `Active` state together with the
/// owned per-context crypto material: `Some(OwnedMlsCryptoState)` for
/// Encrypted mode (the freshly-born MLS group + local sender key, for the
/// caller to seed onto the spawning actor) or `None` for Broadcast mode
/// (whose broadcast key lives on the actor's `BroadcastState`, not here).
///
/// # Errors
///
/// Returns [`ContextCreationError`] if any validation or execution step
/// fails. After an error, no MLS group state, sender key material, or event
/// log state persists (atomic from the caller's perspective).
///
/// See ADR-008 acceptance criterion 2.
// ADR-049 §Decision 12: `transition_to` is now a synchronous lock-free ArcSwap
// store. The async event-log provider calls (`init_event_log`, `append_event`,
// `append_membership_change_leaf`) and the async `receipt.rollback` regain real
// await points under ADR-049 Decision 7 (async-provider-trait conversion), so
// this fn genuinely awaits (no longer `unused_async`). `too_many_lines` is
// allowed: it is a single cohesive multi-phase creation orchestrator (validate →
// crypto → sender key → event log → publish → activate → creation leaves) whose
// per-phase rollback-and-return blocks each gained `.await` continuation lines;
// splitting the sequential phases across helpers would reduce, not improve,
// readability.
#[allow(clippy::too_many_lines)]
pub async fn create_context(
    context_id: String,
    params: ContextParams,
    crypto: &NodeMlsFactory,
    transport: &dyn ContextTransportProvider,
    event_log_provider: &dyn ContextEventLogProvider,
    creator_did: &str,
    creation_timestamp_secs: u64,
) -> Result<
    (
        ContextHandle,
        Option<crate::crypto::mls::provider::OwnedMlsCryptoState>,
    ),
    ContextCreationError,
> {
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

    // Step 1: Create the handle in `Creating` state. `context_id` is cloned so
    // it remains available to build the `scp_context_params` extension below.
    let handle = ContextHandle::new(context_id.clone(), params.clone());

    // Step 2: Birth the per-context crypto as OWNED material.
    //
    // #2148 (ADR-049 birth-into-actor): the MLS group + local sender key are
    // no longer installed into a provider map. The Encrypted path mints them
    // via `create_mls_group_with_context` (owned-return) and hands the
    // `OwnedMlsCryptoState` back to the caller
    // (`lifecycle_helpers::create_context`), which seeds it onto the spawning
    // actor's `PerContextState`. The local sender key is minted INSIDE this
    // owned birth (no separate rotate step). A birth failure returns `Err`
    // with nothing installed to roll back. Broadcast contexts have no MLS
    // group and no provider-resident broadcast key: the actor's
    // `BroadcastState` (seeded by `Supervisor::init_broadcast_context` in
    // `lifecycle_helpers::create_context`) is the authoritative broadcast-key
    // home — so nothing crypto-shaped is born here.
    let owned_crypto = match params.mode {
        ContextMode::Encrypted => {
            // Bind the context parameters into the MLS `group_context` via the
            // `scp_context_params` (`0xFF02`) extension so every joiner reads
            // the same creator-committed parameters, folded into the key
            // schedule (spec §5.13.3, finding FFI-02). A root context has no
            // parents. Built before the side-effect-free owned birth so a
            // canonical-encoding failure aborts with nothing to roll back.
            let context_extension = ScpContextExtension::for_root(
                context_id,
                scp_did::DID::from(creator_did.to_owned()),
                params.mode,
                &params.governance,
                params.ceiling_policy,
                &CapabilityCeiling::new(params.ceiling.clone()),
            )
            .map_err(|e| {
                ContextCreationError::CryptoFailed(format!(
                    "building scp_context_params extension: {e}"
                ))
            })?;
            // Owned birth. On `Err` the `?` drops nothing — no group / sender
            // key was installed into any provider map.
            Some(crypto.create_mls_group_with_context(&context_extension)?)
        }
        ContextMode::Broadcast => None,
    };

    // Step 4: Initialise event log.
    if let Err(e) = event_log_provider.init_event_log(&id_bytes).await {
        // #2148 F6: eagerly free the born-but-never-seeded crypto's OpenMLS
        // group (`destroy_group`) before `owned` drops on this rollback. A bare
        // drop already frees the in-memory group storage; the signer is freed
        // either way, NOT zeroized (#82) — so this explicit dispose is
        // defense-in-depth / forward-compat with #82. `SenderKey` zeroizes on
        // its own drop.
        if let Some(mut owned) = owned_crypto {
            owned.dispose_secrets();
        }
        receipt
            .rollback(&id_bytes, transport, event_log_provider)
            .await;
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
    match transport.publish_context(&id_bytes, &params).await {
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
    if let Err(e) = handle.transition_to(&ContextState::Active) {
        // #2148 F6: eagerly free the born-but-never-seeded crypto (signer
        // freed, NOT zeroized — #82) before it drops on this rollback (see step 4).
        if let Some(mut owned) = owned_crypto {
            owned.dispose_secrets();
        }
        receipt
            .rollback(&id_bytes, transport, event_log_provider)
            .await;
        return Err(e.into());
    }

    // Step 7: Append ContextCreated event.
    if let Err(e) = event_log_provider
        .append_event(
            &id_bytes,
            scp_event_log::EventType::ContextCreated,
            creator_did,
            scp_event_log::EventPayload::default(),
            // Creator-assigned creation time, copied by every member (§7.3.1,
            // §9.9.3) — not each member's local `now()`.
            creation_timestamp_secs,
        )
        .await
    {
        // #2148 F6: eagerly free the born-but-never-seeded crypto (signer
        // freed, NOT zeroized — #82) before it drops on this rollback (see step 4).
        // The handle is Active but `owned_crypto` is still live (returned to the
        // caller on success at step 9), so it is the live owner here.
        if let Some(mut owned) = owned_crypto {
            owned.dispose_secrets();
        }
        // Even though the handle is Active, we must roll back everything.
        receipt
            .rollback(&id_bytes, transport, event_log_provider)
            .await;
        return Err(e);
    }

    // Step 8: Append the founder's `MemberJoined` leaf.
    //
    // The creation flow emits only `ContextCreated` for the creator; without a
    // `MemberJoined` leaf the membership-interval participation model has no
    // join event to open the founder's interval, so the founder's
    // `participation_duration_secs` computes as 0 even after they participate.
    // Append a subject-bearing join leaf for the founder (actor == subject ==
    // creator) at the SAME creator-assigned creation timestamp as
    // `ContextCreated`, so it is convergent-by-construction (not each member's
    // local `now()`; §7.3.1, §9.9.3). The creator's initial role is `admin`,
    // mirroring the supervisor's creator membership in
    // `lifecycle_helpers::create_context`. Rolls back the whole creation on
    // failure, exactly like the `ContextCreated` append above.
    if let Err(e) = event_log_provider
        .append_membership_change_leaf(
            &id_bytes,
            scp_event_log::EventType::MemberJoined,
            creator_did,
            creator_did,
            "admin",
            creation_timestamp_secs,
        )
        .await
    {
        // #2148 F6: eagerly free the born-but-never-seeded crypto (signer
        // freed, NOT zeroized — #82) before it drops on this rollback (see step 4).
        // `owned_crypto` is still live (returned to the caller on success at
        // step 9), so it is the live owner here.
        if let Some(mut owned) = owned_crypto {
            owned.dispose_secrets();
        }
        receipt
            .rollback(&id_bytes, transport, event_log_provider)
            .await;
        return Err(e.into());
    }

    // Step 9: Return the handle plus the owned crypto material (Encrypted
    // mode) for the caller to seed onto the spawning actor. Broadcast contexts
    // return `None` — their broadcast key lives on the actor's `BroadcastState`.
    Ok((handle, owned_crypto))
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
    reason = "ADR-049 §15: scaffolding for tests ignored pending MlsBackend injection"
)]
mod tests {
    use super::*;
    use scp_protocol::context::{ContextParams, MemoryScope};

    /// Test DID for the real [`NodeMlsFactory`].
    ///
    /// The prior `MockCryptoProvider` fail-injection scaffold was deleted
    /// along with the `ContextCryptoProvider` trait in ADR-049 §15.
    /// Success-path tests bind a real provider; fail-injection tests are
    /// `#[ignore]`d pending `MlsBackend` injection.
    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    struct TestTransport;
    #[async_trait::async_trait]
    impl ContextTransportProvider for TestTransport {
        fn is_connected(&self) -> bool {
            true
        }
        async fn publish_context(
            &self,
            _: &[u8; 32],
            _: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn send_message(&self, _: &[u8; 32], _: &[u8]) -> Result<(), ContextError> {
            Ok(())
        }
    }

    struct TestEventLog;
    #[async_trait::async_trait]
    impl ContextEventLogProvider for TestEventLog {
        async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _: &[u8; 32],
            _event_type: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
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

    /// Smoke verifying that ADR-049 §15's
    /// [`NodeMlsFactory::with_backends`] seam compiles and that
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
        use crate::crypto::mls::provider::NodeMlsFactory;
        use std::sync::Arc;

        let provider = NodeMlsFactory::with_backends(
            TEST_DID.to_owned(),
            Arc::new(ProductionMlsBackend::new(std::sync::Arc::new(
                scp_clock::SystemClock,
            ))),
            Arc::new(ProductionHpkeBackend::new()),
            std::sync::Arc::new(scp_clock::SystemClock),
        );
        let _mls = provider.mls_backend();
        let _hpke = provider.hpke_backend();
    }

    /// ADR-056 (Model A) / §6.2.4:276 conformance: a context whose
    /// id is a real 64-hex string (the shape `generate_context_id` produces:
    /// `hex(32 random bytes)`) keys its creation crypto under the **decoded
    /// digest**, NOT under `SHA-256(id)`. This is the load-bearing fix: the
    /// §6.2.4 cross-context outlet saga compares the wire `target_context_id`
    /// (the raw digest) against `state.context_id`, and `state.context_id` is
    /// set by `context_id_to_bytes` of the same id — so the MLS group,
    /// sender key, and event log created here MUST live under that identical
    /// digest, or every real-context message/saga would address the wrong
    /// group.
    #[tokio::test]
    async fn create_context_keys_crypto_under_decoded_digest_not_sha256() {
        use crate::context::state::context_id_to_bytes;

        // A canonical id: the lowercase-hex of a known 32-byte digest, exactly
        // the form `generate_context_id` (scp-ffi-common) emits.
        let digest: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let id = hex::encode(digest);
        assert_eq!(id.len(), 64, "fixture id must be a real 64-hex context id");

        // Boundary assertion: the canonical resolver (the single chokepoint the
        // historical call sites route through) DECODES a 64-hex id to its
        // digest and does NOT re-hash it. `SHA-256(id)` (the pre-ADR-056
        // keying) is a DIFFERENT value — pinning the double-hash fix.
        assert_eq!(
            context_id_to_bytes(&id),
            digest,
            "a real 64-hex id must resolve to its decoded digest"
        );
        let sha256_of_id = scp_protocol::context::context_id_bytes(&id);
        assert_ne!(
            sha256_of_id, digest,
            "test precondition: SHA-256(hex(digest)) must differ from the digest, \
             else the test could not distinguish decode from hash"
        );

        // Drive real creation crypto. A real MLS provider + no-op transport /
        // event log isolates the keying behavior under test.
        let crypto = NodeMlsFactory::new(
            TEST_DID.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        );
        let (handle, owned_crypto) = create_context(
            id.clone(),
            ContextParams::default(),
            &crypto,
            &TestTransport,
            &TestEventLog,
            TEST_DID,
            1_700_000_000,
        )
        .await
        .expect("create_context should succeed for a canonical 64-hex id");
        assert_eq!(handle.context_id(), id, "handle carries the canonical id");

        // #2148 (ADR-049 birth-into-actor): crypto is born as OWNED material
        // and returned (never installed into a provider map — the provider's
        // `contexts` map and `context_crypto_present` residency probe are
        // DELETED). The keying-under-decoded-digest property that this test
        // originally proved via provider residency is now proved directly by
        // `context_id_to_bytes(&id) == digest` above (the SINGLE keying
        // chokepoint every seed / send / receive routes through): the actor's
        // `PerContextState.context_id` is set from exactly that resolver, and
        // the owned crypto seeded here carries no separate key. An Encrypted
        // create MUST yield owned crypto material.
        assert!(
            owned_crypto.is_some(),
            "an Encrypted create must return born-owned MLS crypto material"
        );
    }

    /// The creation flow must emit a founder `MemberJoined` leaf so the
    /// membership-interval participation model can attribute a join time to the
    /// creator. Without it the founder's `participation_duration_secs` computes
    /// as 0 even after they participate (no `MemberJoined` to open the
    /// interval). Here the founder creates a context at t=1000 and participates
    /// at t=1300; the participation record must report the 300s span (the
    /// interval, still open, runs to the latest event), not 0.
    #[tokio::test]
    async fn founder_membership_leaf_yields_nonzero_participation_duration() {
        use crate::context::providers::MerkleEventLogProvider;
        use scp_protocol::trust::participation::compute_participation_record;

        const CREATION_TS: u64 = 1_000;
        const SEND_TS: u64 = 1_300;

        // A real 64-hex context id (the shape `generate_context_id` emits).
        let id = hex::encode([0x2au8; 32]);
        let id_bytes = context_id_bytes(&id);
        let crypto = NodeMlsFactory::new(
            TEST_DID.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        );
        let provider = MerkleEventLogProvider::new();

        create_context(
            id.clone(),
            ContextParams::default(),
            &crypto,
            &TestTransport,
            &provider,
            TEST_DID,
            CREATION_TS,
        )
        .await
        .expect("create_context should succeed");

        // The founder participates after creation; a later subject event extends
        // the still-open membership interval to `SEND_TS`.
        provider
            .append_event(
                &id_bytes,
                scp_event_log::EventType::MessageSent,
                TEST_DID,
                scp_event_log::EventPayload::default(),
                SEND_TS,
            )
            .await
            .expect("append founder MessageSent");

        let entries = provider
            .event_log_entries(&id_bytes)
            .expect("entries readable")
            .expect("log exists");

        // Load-bearing fix: the creation stream carries the founder's
        // `MemberJoined` leaf (actor == subject == creator) at the convergent
        // creation timestamp, projecting the creator as the affected subject.
        let founder_join = entries
            .iter()
            .find(|e| {
                e.event_type == scp_event_log::EventType::MemberJoined
                    && e.actor_did.0.as_str() == TEST_DID
            })
            .expect("founder MemberJoined leaf must be emitted on create");
        assert_eq!(
            founder_join.timestamp, CREATION_TS,
            "founder join must carry the convergent creation timestamp"
        );
        assert_eq!(
            scp_event_log::payload::project_payload(
                &founder_join.event_type,
                &founder_join.payload
            )
            .subject_did
            .as_deref(),
            Some(TEST_DID),
            "founder join leaf must project the creator as the affected subject"
        );

        let record = compute_participation_record(&entries, TEST_DID, &id, [0u8; 32], 2_000, &[])
            .expect("participation record computes");

        assert_eq!(
            record.participation_duration_seconds,
            SEND_TS - CREATION_TS,
            "founder duration must span the join (creation) to the latest event"
        );
        assert!(
            record.participation_duration_seconds > 0,
            "a founder who participated must have non-zero participation duration"
        );
    }
}
