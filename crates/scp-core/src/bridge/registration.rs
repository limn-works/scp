//! Bridge registration and governance approval.
//!
//! Handles the lifecycle of registering a bridge connector with a context:
//! the operator DID presents a registration request, context governance
//! approves or rejects, and the registered bridge becomes visible in context
//! metadata. Registration is recorded as a context event in the Merkle log.
//!
//! # Workflow
//!
//! 1. Operator DID calls [`register_bridge`] to create a
//!    [`BridgeRegistrationRequest`].
//! 2. Context governance calls [`approve_registration`] or
//!    [`reject_registration`] to produce a [`BridgeRegistrationEvent`].
//! 3. On approval, a [`BridgeConnector`] is created and stored in the
//!    [`BridgeRegistry`].
//! 4. Context governance may later call [`revoke_bridge`] to disconnect a
//!    bridge and all its shadow identities.
//! 5. [`list_bridges`] returns all registered bridges for a context
//!    (visible before opt-in per legibility tenet).
//!
//! # Context isolation
//!
//! A bridge in Context A has zero access to Context B. The same platform
//! bridged into two contexts requires two separate bridge instances with
//! separate registrations. The [`BridgeRegistry`] enforces this by scoping
//! all operations to a single [`ContextId`].
//!
//! # Self-hosted bridges
//!
//! The protocol treats self-hosted and managed bridges identically.
//! Self-hosted eliminates third-party credential delegation (puppet mode).
//!
//! See ADR-023 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

use super::{BridgeConnector, BridgeMode, BridgeStatus, ContextId, DID, ShadowIdentity};

// ---------------------------------------------------------------------------
// BridgeRegistrationError
// ---------------------------------------------------------------------------

/// Errors produced by bridge registration operations.
#[derive(Debug, thiserror::Error)]
pub enum BridgeRegistrationError {
    /// The registration request references a context that does not match
    /// the registry's context.
    #[error(
        "context mismatch: registry serves {registry_context}, \
         request targets {request_context}"
    )]
    ContextMismatch {
        /// The context the registry serves.
        registry_context: ContextId,
        /// The context the request targets.
        request_context: ContextId,
    },

    /// A bridge with the given ID already exists in the registry.
    #[error("bridge already registered: {bridge_id}")]
    BridgeAlreadyRegistered {
        /// The duplicate bridge ID.
        bridge_id: String,
    },

    /// The specified bridge was not found in the registry.
    #[error("bridge not found: {bridge_id}")]
    BridgeNotFound {
        /// The bridge ID that was not found.
        bridge_id: String,
    },

    /// The bridge has already been revoked and cannot be modified.
    #[error("bridge already revoked: {bridge_id}")]
    BridgeAlreadyRevoked {
        /// The bridge ID that is already revoked.
        bridge_id: String,
    },

    /// The request references a bridge that is not in the pending requests.
    #[error("no pending registration request for bridge: {bridge_id}")]
    NoPendingRequest {
        /// The bridge ID with no pending request.
        bridge_id: String,
    },

    /// The approver DID is the same as the operator DID, which is not
    /// permitted (governance must be independent of the operator).
    #[error("approver cannot be the same as operator: {did}")]
    SelfApproval {
        /// The DID that attempted self-approval.
        did: DID,
    },
}

// ---------------------------------------------------------------------------
// BridgeRegistrationMetadata
// ---------------------------------------------------------------------------

/// Human-readable metadata for a bridge registration request (spec §12.2.1).
///
/// Carries display name, description, and operator contact info so that
/// context governance can make informed approval decisions. Defaults to
/// empty strings when not provided.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRegistrationMetadata {
    /// Human-readable display name for the bridge (e.g., `"Acme Discord Bridge"`).
    pub display_name: String,

    /// Free-text description of the bridge's purpose or scope.
    pub description: String,

    /// Contact information for the bridge operator (e.g., email, URL).
    pub operator_contact: String,
}

// ---------------------------------------------------------------------------
// BridgeRegistrationRequest
// ---------------------------------------------------------------------------

/// A request to register a bridge connector with a context.
///
/// Created by the bridge operator via [`register_bridge`]. The request is
/// presented to context governance for approval or rejection.
///
/// Fields align with the spec §12.2.1 `RegisterBridge` governance action.
///
/// See ADR-023 acceptance criterion 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRegistrationRequest {
    /// Proposed unique identifier for the bridge instance.
    pub bridge_id: String,

    /// DID of the human operator accountable for this bridge.
    pub operator_did: DID,

    /// Name of the external platform to bridge (e.g., `"discord"`,
    /// `"slack"`).
    pub platform: String,

    /// Requested operating mode for the bridge.
    pub mode: BridgeMode,

    /// The context this bridge requests registration in.
    pub context_id: ContextId,

    /// Unix timestamp (seconds) when the request was created.
    pub requested_at: u64,

    /// Whether this is a self-hosted bridge.
    ///
    /// Self-hosted bridges eliminate third-party credential delegation
    /// (puppet mode). The protocol treats self-hosted and managed bridges
    /// identically (ADR-023 acceptance criterion 11).
    pub self_hosted: bool,

    /// For cooperative mode: the platform's webhook receiver URL (spec §12.2.1).
    ///
    /// Required for cooperative mode bridges; the bridge node uses this URL
    /// to push events to the external platform. `None` for non-cooperative modes.
    pub webhook_url: Option<String>,

    /// For cooperative mode: the platform's Ed25519 public key (spec §12.2.1, §12.10.2).
    ///
    /// Used to verify webhook request signatures from the platform. Required
    /// for cooperative mode; `None` for non-cooperative modes.
    pub platform_key: Option<[u8; 32]>,

    /// Governance-configured shadow limit for this bridge (spec §12.2.1).
    ///
    /// Overrides the default `max_shadows_per_bridge` (10,000) in the
    /// `ShadowRegistry`. Contexts MAY set lower limits to prevent resource
    /// exhaustion from unbounded shadow creation.
    pub max_shadows: u32,

    /// Human-readable metadata: display name, description, operator contact
    /// (spec §12.2.1).
    pub metadata: BridgeRegistrationMetadata,
}

// ---------------------------------------------------------------------------
// RegistrationDecision
// ---------------------------------------------------------------------------

/// The outcome of governance review of a bridge registration request.
///
/// Produced by [`approve_registration`] or [`reject_registration`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationDecision {
    /// Governance approved the registration.
    Approved,
    /// Governance rejected the registration.
    Rejected {
        /// Human-readable reason for rejection.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// BridgeRegistrationEvent
// ---------------------------------------------------------------------------

/// A context event recording a bridge registration action.
///
/// This event is appended to the context's Merkle log to provide an
/// auditable record of all bridge lifecycle changes.
///
/// See ADR-023 acceptance criterion 2: "Registration is a context event
/// in the Merkle log."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRegistrationEvent {
    /// The type of registration action.
    pub action: BridgeRegistrationAction,

    /// The bridge ID this event pertains to.
    pub bridge_id: String,

    /// DID of the bridge operator.
    pub operator_did: DID,

    /// DID of the governance actor who approved, rejected, or revoked.
    pub governance_did: DID,

    /// The context this event belongs to.
    pub context_id: ContextId,

    /// Unix timestamp (seconds) when the action occurred.
    pub timestamp: u64,
}

/// The specific registration action recorded in the event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeRegistrationAction {
    /// A registration request was submitted.
    Requested,
    /// The registration was approved by governance.
    Approved,
    /// The registration was rejected by governance.
    Rejected {
        /// Human-readable reason for rejection.
        reason: String,
    },
    /// The bridge was revoked by governance.
    Revoked,
}

// ---------------------------------------------------------------------------
// BridgeRegistry
// ---------------------------------------------------------------------------

/// In-memory registry of bridge connectors for a single context.
///
/// The registry is scoped to exactly one context (context isolation tenet).
/// A bridge in Context A has zero access to Context B. The same platform
/// bridged into two contexts requires two separate registry instances.
///
/// Registered bridges are visible in context metadata before opt-in
/// (legibility tenet, ADR-023 acceptance criterion 2).
///
/// See ADR-023 acceptance criteria 2, 9, 10.
#[derive(Debug)]
pub struct BridgeRegistry {
    /// The context this registry belongs to.
    context_id: ContextId,

    /// Active and revoked bridge connectors keyed by bridge ID.
    bridges: Vec<BridgeConnector>,

    /// Pending registration requests keyed by bridge ID.
    pending_requests: Vec<BridgeRegistrationRequest>,

    /// Event log of all registration actions (for Merkle log integration).
    events: Vec<BridgeRegistrationEvent>,
}

impl BridgeRegistry {
    /// Creates a new empty bridge registry for the given context.
    #[must_use]
    // Contains HashMap::new() which is not const.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(context_id: ContextId) -> Self {
        Self {
            context_id,
            bridges: Vec::new(),
            pending_requests: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Returns the context ID this registry is scoped to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns all registered bridges (active, suspended, and revoked).
    ///
    /// This is the data visible in context metadata before opt-in
    /// (legibility tenet).
    #[must_use]
    pub fn bridges(&self) -> &[BridgeConnector] {
        &self.bridges
    }

    /// Returns all pending registration requests.
    #[must_use]
    pub fn pending_requests(&self) -> &[BridgeRegistrationRequest] {
        &self.pending_requests
    }

    /// Returns all registration events (the audit log).
    #[must_use]
    pub fn events(&self) -> &[BridgeRegistrationEvent] {
        &self.events
    }

    /// Returns deduplicated operator DIDs for all active bridges.
    ///
    /// Used to populate `bridge_operator_dids` in context metadata (§5.7)
    /// per the MUST requirement in §12.6.1. The result is deduplicated: if
    /// the same operator runs multiple bridges in this context, their DID
    /// appears only once. Only active bridges are included — revoked and
    /// suspended bridges are excluded.
    #[must_use]
    pub fn bridge_operator_dids(&self) -> Vec<DID> {
        let mut dids: Vec<DID> = Vec::new();
        for bridge in &self.bridges {
            if bridge.status == BridgeStatus::Active && !dids.contains(&bridge.operator_did) {
                dids.push(bridge.operator_did.clone());
            }
        }
        dids
    }
}

// ---------------------------------------------------------------------------
// register_bridge
// ---------------------------------------------------------------------------

/// Creates a bridge registration request for governance review.
///
/// The operator DID presents a registration request specifying the
/// platform, operating mode, and whether the bridge is self-hosted.
/// The request is added to the registry's pending queue and a
/// [`BridgeRegistrationEvent`] is recorded.
///
/// # Errors
///
/// Returns [`BridgeRegistrationError::ContextMismatch`] if the request
/// targets a different context than the registry serves.
///
/// Returns [`BridgeRegistrationError::BridgeAlreadyRegistered`] if a
/// bridge with the same ID already exists (either registered or pending).
///
/// See ADR-023 acceptance criterion 2.
pub fn register_bridge(
    registry: &mut BridgeRegistry,
    request: BridgeRegistrationRequest,
) -> Result<BridgeRegistrationEvent, BridgeRegistrationError> {
    // Enforce context isolation.
    if request.context_id != registry.context_id {
        return Err(BridgeRegistrationError::ContextMismatch {
            registry_context: registry.context_id.clone(),
            request_context: request.context_id,
        });
    }

    // Check for duplicate bridge ID in registered bridges.
    if registry
        .bridges
        .iter()
        .any(|b| b.bridge_id == request.bridge_id)
    {
        return Err(BridgeRegistrationError::BridgeAlreadyRegistered {
            bridge_id: request.bridge_id,
        });
    }

    // Check for duplicate bridge ID in pending requests.
    if registry
        .pending_requests
        .iter()
        .any(|r| r.bridge_id == request.bridge_id)
    {
        return Err(BridgeRegistrationError::BridgeAlreadyRegistered {
            bridge_id: request.bridge_id,
        });
    }

    let event = BridgeRegistrationEvent {
        action: BridgeRegistrationAction::Requested,
        bridge_id: request.bridge_id.clone(),
        operator_did: request.operator_did.clone(),
        governance_did: request.operator_did.clone(),
        context_id: registry.context_id.clone(),
        timestamp: request.requested_at,
    };

    registry.pending_requests.push(request);
    registry.events.push(event.clone());

    Ok(event)
}

// ---------------------------------------------------------------------------
// approve_registration
// ---------------------------------------------------------------------------

/// Approves a pending bridge registration request.
///
/// Context governance approves the registration, creating a
/// [`BridgeConnector`] in [`BridgeStatus::Active`] state. The connector
/// is added to the registry and becomes visible in context metadata.
///
/// # Arguments
///
/// - `registry` -- The bridge registry for this context.
/// - `bridge_id` -- The ID of the pending registration to approve.
/// - `governance_did` -- The DID of the governance actor approving.
/// - `timestamp` -- Unix timestamp (seconds) of the approval.
///
/// # Errors
///
/// Returns [`BridgeRegistrationError::NoPendingRequest`] if no pending
/// request exists for the given bridge ID.
///
/// Returns [`BridgeRegistrationError::SelfApproval`] if the governance
/// DID matches the operator DID.
///
/// See ADR-023 acceptance criterion 2.
pub fn approve_registration(
    registry: &mut BridgeRegistry,
    bridge_id: &str,
    governance_did: &DID,
    timestamp: u64,
) -> Result<(BridgeConnector, BridgeRegistrationEvent), BridgeRegistrationError> {
    // Find and remove the pending request.
    let pos = registry
        .pending_requests
        .iter()
        .position(|r| r.bridge_id == bridge_id)
        .ok_or_else(|| BridgeRegistrationError::NoPendingRequest {
            bridge_id: bridge_id.to_owned(),
        })?;

    let request = registry.pending_requests.remove(pos);

    // Governance must be independent of the operator.
    if *governance_did == request.operator_did {
        // Put the request back before returning the error.
        registry.pending_requests.push(request);
        return Err(BridgeRegistrationError::SelfApproval {
            did: governance_did.clone(),
        });
    }

    let connector = BridgeConnector {
        bridge_id: request.bridge_id.clone(),
        operator_did: request.operator_did.clone(),
        platform: request.platform.clone(),
        mode: request.mode.clone(),
        status: BridgeStatus::Active,
        registration_context: registry.context_id.clone(),
        registered_at: timestamp,
    };

    let event = BridgeRegistrationEvent {
        action: BridgeRegistrationAction::Approved,
        bridge_id: request.bridge_id.clone(),
        operator_did: request.operator_did,
        governance_did: governance_did.clone(),
        context_id: registry.context_id.clone(),
        timestamp,
    };

    registry.bridges.push(connector.clone());
    registry.events.push(event.clone());

    Ok((connector, event))
}

// ---------------------------------------------------------------------------
// reject_registration
// ---------------------------------------------------------------------------

/// Rejects a pending bridge registration request.
///
/// Context governance rejects the registration with a human-readable
/// reason. The request is removed from the pending queue and a rejection
/// event is recorded.
///
/// # Arguments
///
/// - `registry` -- The bridge registry for this context.
/// - `bridge_id` -- The ID of the pending registration to reject.
/// - `governance_did` -- The DID of the governance actor rejecting.
/// - `reason` -- Human-readable reason for rejection.
/// - `timestamp` -- Unix timestamp (seconds) of the rejection.
///
/// # Errors
///
/// Returns [`BridgeRegistrationError::NoPendingRequest`] if no pending
/// request exists for the given bridge ID.
///
/// See ADR-023 acceptance criterion 2.
pub fn reject_registration(
    registry: &mut BridgeRegistry,
    bridge_id: &str,
    governance_did: &DID,
    reason: &str,
    timestamp: u64,
) -> Result<BridgeRegistrationEvent, BridgeRegistrationError> {
    let pos = registry
        .pending_requests
        .iter()
        .position(|r| r.bridge_id == bridge_id)
        .ok_or_else(|| BridgeRegistrationError::NoPendingRequest {
            bridge_id: bridge_id.to_owned(),
        })?;

    let request = registry.pending_requests.remove(pos);

    let event = BridgeRegistrationEvent {
        action: BridgeRegistrationAction::Rejected {
            reason: reason.to_owned(),
        },
        bridge_id: request.bridge_id.clone(),
        operator_did: request.operator_did,
        governance_did: governance_did.clone(),
        context_id: registry.context_id.clone(),
        timestamp,
    };

    registry.events.push(event.clone());

    Ok(event)
}

// ---------------------------------------------------------------------------
// revoke_bridge
// ---------------------------------------------------------------------------

/// Revokes an active bridge, disconnecting all shadow identities.
///
/// Context governance removes the bridge at any time. Severing the bridge
/// disconnects all shadow identities from the external platform. Shadows
/// retain their attributed actions but can no longer receive or send.
///
/// # Arguments
///
/// - `registry` -- The bridge registry for this context.
/// - `bridge_id` -- The ID of the bridge to revoke.
/// - `governance_did` -- The DID of the governance actor revoking.
/// - `shadows` -- Mutable slice of shadow identities to disconnect.
///   All shadows belonging to the revoked bridge will have their roles
///   set to `"revoked"` to prevent further send/receive.
/// - `timestamp` -- Unix timestamp (seconds) of the revocation.
///
/// # Errors
///
/// Returns [`BridgeRegistrationError::BridgeNotFound`] if no bridge
/// with the given ID exists.
///
/// Returns [`BridgeRegistrationError::BridgeAlreadyRevoked`] if the
/// bridge has already been revoked.
///
/// See ADR-023 acceptance criterion 9.
pub fn revoke_bridge(
    registry: &mut BridgeRegistry,
    bridge_id: &str,
    governance_did: &DID,
    shadows: &mut [ShadowIdentity],
    timestamp: u64,
) -> Result<BridgeRegistrationEvent, BridgeRegistrationError> {
    let bridge = registry
        .bridges
        .iter_mut()
        .find(|b| b.bridge_id == bridge_id)
        .ok_or_else(|| BridgeRegistrationError::BridgeNotFound {
            bridge_id: bridge_id.to_owned(),
        })?;

    if bridge.status == BridgeStatus::Revoked {
        return Err(BridgeRegistrationError::BridgeAlreadyRevoked {
            bridge_id: bridge_id.to_owned(),
        });
    }

    bridge.status = BridgeStatus::Revoked;

    // Sever all shadow identities belonging to this bridge.
    // Shadows retain attributed actions (provenance_status unchanged)
    // but can no longer receive/send (role set to "revoked").
    for shadow in shadows.iter_mut() {
        if shadow.bridge_id == bridge_id {
            "revoked".clone_into(&mut shadow.attributed_role);
        }
    }

    let event = BridgeRegistrationEvent {
        action: BridgeRegistrationAction::Revoked,
        bridge_id: bridge_id.to_owned(),
        operator_did: bridge.operator_did.clone(),
        governance_did: governance_did.clone(),
        context_id: registry.context_id.clone(),
        timestamp,
    };

    registry.events.push(event.clone());

    Ok(event)
}

// ---------------------------------------------------------------------------
// list_bridges
// ---------------------------------------------------------------------------

/// Returns all registered bridges for the context.
///
/// This includes active, suspended, and revoked bridges. The list is
/// visible in context metadata before opt-in (legibility tenet).
///
/// # Arguments
///
/// - `registry` -- The bridge registry to query.
///
/// See ADR-023 acceptance criterion 2.
#[must_use]
pub fn list_bridges(registry: &BridgeRegistry) -> &[BridgeConnector] {
    registry.bridges()
}

// ---------------------------------------------------------------------------
// list_active_bridges
// ---------------------------------------------------------------------------

/// Returns only active (non-revoked, non-suspended) bridges.
///
/// Useful for determining which bridges are currently operational.
///
/// # Arguments
///
/// - `registry` -- The bridge registry to query.
#[must_use]
pub fn list_active_bridges(registry: &BridgeRegistry) -> Vec<&BridgeConnector> {
    registry
        .bridges
        .iter()
        .filter(|b| b.status == BridgeStatus::Active)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::single_char_pattern
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------

    const CTX_A: &str = "ctx-alpha";
    const CTX_B: &str = "ctx-beta";
    const OPERATOR_DID: &str = "did:dht:z6MkOperator";
    const GOVERNANCE_DID: &str = "did:dht:z6MkGovernance";

    fn make_request(bridge_id: &str, context_id: &str) -> BridgeRegistrationRequest {
        BridgeRegistrationRequest {
            bridge_id: bridge_id.to_owned(),
            operator_did: OPERATOR_DID.into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Relay,
            context_id: context_id.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: false,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        }
    }

    fn make_shadow(bridge_id: &str, shadow_id: &str) -> ShadowIdentity {
        ShadowIdentity {
            shadow_id: shadow_id.to_owned(),
            platform_handle: "@user#1234".to_owned(),
            bridge_id: bridge_id.to_owned(),
            attributed_role: "observer".to_owned(),
            provenance_status: super::super::ShadowProvenanceStatus::Shadow,
            created_at: 1_700_000_100,
        }
    }

    /// Registers and approves a bridge in one step.
    fn register_and_approve(registry: &mut BridgeRegistry, bridge_id: &str) -> BridgeConnector {
        let request = make_request(bridge_id, CTX_A);
        register_bridge(registry, request).unwrap();
        let (connector, _event) = approve_registration(
            registry,
            bridge_id,
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();
        connector
    }

    // -------------------------------------------------------------------
    // BridgeRegistry construction
    // -------------------------------------------------------------------

    #[test]
    fn registry_new_has_correct_context() {
        let registry = BridgeRegistry::new(CTX_A.to_owned());
        assert_eq!(registry.context_id(), CTX_A);
    }

    #[test]
    fn registry_new_has_empty_bridges() {
        let registry = BridgeRegistry::new(CTX_A.to_owned());
        assert!(registry.bridges().is_empty());
    }

    #[test]
    fn registry_new_has_empty_pending_requests() {
        let registry = BridgeRegistry::new(CTX_A.to_owned());
        assert!(registry.pending_requests().is_empty());
    }

    #[test]
    fn registry_new_has_empty_events() {
        let registry = BridgeRegistry::new(CTX_A.to_owned());
        assert!(registry.events().is_empty());
    }

    // -------------------------------------------------------------------
    // register_bridge
    // -------------------------------------------------------------------

    #[test]
    fn register_bridge_adds_pending_request() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        let result = register_bridge(&mut registry, request);
        assert!(result.is_ok());
        assert_eq!(registry.pending_requests().len(), 1);
        assert_eq!(registry.pending_requests()[0].bridge_id, "bridge-001");
    }

    #[test]
    fn register_bridge_records_requested_event() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        let event = register_bridge(&mut registry, request).unwrap();
        assert_eq!(event.action, BridgeRegistrationAction::Requested);
        assert_eq!(event.bridge_id, "bridge-001");
        assert_eq!(event.operator_did, OPERATOR_DID);
        assert_eq!(event.context_id, CTX_A);
        assert_eq!(registry.events().len(), 1);
    }

    #[test]
    fn register_bridge_rejects_context_mismatch() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_B);
        let result = register_bridge(&mut registry, request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeRegistrationError::ContextMismatch { .. }),
            "expected ContextMismatch, got {err:?}"
        );
    }

    #[test]
    fn register_bridge_rejects_duplicate_id_in_registered() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        let request = make_request("bridge-001", CTX_A);
        let result = register_bridge(&mut registry, request);
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::BridgeAlreadyRegistered { .. })
        ));
    }

    #[test]
    fn register_bridge_rejects_duplicate_id_in_pending() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request1 = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request1).unwrap();

        let request2 = make_request("bridge-001", CTX_A);
        let result = register_bridge(&mut registry, request2);
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::BridgeAlreadyRegistered { .. })
        ));
    }

    #[test]
    fn register_bridge_does_not_add_to_active_bridges() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();
        assert!(registry.bridges().is_empty());
    }

    // -------------------------------------------------------------------
    // approve_registration
    // -------------------------------------------------------------------

    #[test]
    fn approve_creates_active_connector() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        let (connector, _event) = approve_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        assert_eq!(connector.bridge_id, "bridge-001");
        assert_eq!(connector.operator_did, OPERATOR_DID);
        assert_eq!(connector.platform, "discord");
        assert_eq!(connector.mode, BridgeMode::Relay);
        assert_eq!(connector.status, BridgeStatus::Active);
        assert_eq!(connector.registration_context, CTX_A);
        assert_eq!(connector.registered_at, 1_700_000_001);
    }

    #[test]
    fn approve_removes_pending_request() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();
        assert_eq!(registry.pending_requests().len(), 1);

        approve_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();
        assert!(registry.pending_requests().is_empty());
    }

    #[test]
    fn approve_adds_to_bridges() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");
        assert_eq!(registry.bridges().len(), 1);
        assert_eq!(registry.bridges()[0].bridge_id, "bridge-001");
    }

    #[test]
    fn approve_records_approved_event() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        let (_connector, event) = approve_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        assert_eq!(event.action, BridgeRegistrationAction::Approved);
        assert_eq!(event.governance_did, GOVERNANCE_DID);
        // 2 events: Requested + Approved.
        assert_eq!(registry.events().len(), 2);
    }

    #[test]
    fn approve_rejects_no_pending_request() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let result = approve_registration(
            &mut registry,
            "bridge-nonexistent",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        );
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::NoPendingRequest { .. })
        ));
    }

    #[test]
    fn approve_rejects_self_approval() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        // Operator tries to approve their own bridge.
        let result = approve_registration(
            &mut registry,
            "bridge-001",
            &DID::from(OPERATOR_DID),
            1_700_000_001,
        );
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::SelfApproval { .. })
        ));

        // Request should still be pending.
        assert_eq!(registry.pending_requests().len(), 1);
    }

    // -------------------------------------------------------------------
    // reject_registration
    // -------------------------------------------------------------------

    #[test]
    fn reject_removes_pending_request() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        reject_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            "platform not allowed",
            1_700_000_001,
        )
        .unwrap();

        assert!(registry.pending_requests().is_empty());
    }

    #[test]
    fn reject_does_not_add_to_bridges() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        reject_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            "not needed",
            1_700_000_001,
        )
        .unwrap();

        assert!(registry.bridges().is_empty());
    }

    #[test]
    fn reject_records_rejected_event() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        let event = reject_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            "policy violation",
            1_700_000_001,
        )
        .unwrap();

        assert_eq!(
            event.action,
            BridgeRegistrationAction::Rejected {
                reason: "policy violation".to_owned()
            }
        );
        assert_eq!(event.governance_did, GOVERNANCE_DID);
    }

    #[test]
    fn reject_rejects_no_pending_request() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let result = reject_registration(
            &mut registry,
            "bridge-nonexistent",
            &DID::from(GOVERNANCE_DID),
            "reason",
            1_700_000_001,
        );
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::NoPendingRequest { .. })
        ));
    }

    // -------------------------------------------------------------------
    // revoke_bridge
    // -------------------------------------------------------------------

    #[test]
    fn revoke_sets_status_to_revoked() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        let mut shadows = vec![];
        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        assert_eq!(registry.bridges()[0].status, BridgeStatus::Revoked);
    }

    #[test]
    fn revoke_disconnects_shadow_identities() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        let mut shadows = vec![
            make_shadow("bridge-001", "shadow-001"),
            make_shadow("bridge-001", "shadow-002"),
            make_shadow("bridge-other", "shadow-003"),
        ];

        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        // Shadows belonging to revoked bridge are disconnected.
        assert_eq!(shadows[0].attributed_role, "revoked");
        assert_eq!(shadows[1].attributed_role, "revoked");
        // Shadow from a different bridge is unaffected.
        assert_eq!(shadows[2].attributed_role, "observer");
    }

    #[test]
    fn revoke_shadows_retain_provenance_status() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        let mut shadows = vec![make_shadow("bridge-001", "shadow-001")];
        let original_status = shadows[0].provenance_status.clone();

        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        // Provenance status preserved (shadows retain actions).
        assert_eq!(shadows[0].provenance_status, original_status);
    }

    #[test]
    fn revoke_records_revoked_event() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        let mut shadows = vec![];
        let event = revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        assert_eq!(event.action, BridgeRegistrationAction::Revoked);
        assert_eq!(event.bridge_id, "bridge-001");
        assert_eq!(event.governance_did, GOVERNANCE_DID);
    }

    #[test]
    fn revoke_rejects_nonexistent_bridge() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        let mut shadows = vec![];
        let result = revoke_bridge(
            &mut registry,
            "bridge-nonexistent",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        );
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::BridgeNotFound { .. })
        ));
    }

    #[test]
    fn revoke_rejects_already_revoked() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        let mut shadows = vec![];
        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        // Try to revoke again.
        let result = revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_003,
        );
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::BridgeAlreadyRevoked { .. })
        ));
    }

    // -------------------------------------------------------------------
    // list_bridges / list_active_bridges
    // -------------------------------------------------------------------

    #[test]
    fn list_bridges_returns_all_bridges() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");
        register_and_approve(&mut registry, "bridge-002");

        let bridges = list_bridges(&registry);
        assert_eq!(bridges.len(), 2);
    }

    #[test]
    fn list_bridges_includes_revoked() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");
        register_and_approve(&mut registry, "bridge-002");

        let mut shadows = vec![];
        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        let bridges = list_bridges(&registry);
        assert_eq!(bridges.len(), 2);
    }

    #[test]
    fn list_active_bridges_excludes_revoked() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");
        register_and_approve(&mut registry, "bridge-002");

        let mut shadows = vec![];
        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        let active = list_active_bridges(&registry);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].bridge_id, "bridge-002");
    }

    #[test]
    fn list_bridges_empty_registry() {
        let registry = BridgeRegistry::new(CTX_A.to_owned());
        assert!(list_bridges(&registry).is_empty());
        assert!(list_active_bridges(&registry).is_empty());
    }

    // -------------------------------------------------------------------
    // Context isolation (ADR-023 AC 10)
    // -------------------------------------------------------------------

    #[test]
    fn separate_registries_for_separate_contexts() {
        let mut registry_a = BridgeRegistry::new(CTX_A.to_owned());
        let mut registry_b = BridgeRegistry::new(CTX_B.to_owned());

        register_and_approve(&mut registry_a, "bridge-discord-a");

        // Register same platform in context B.
        let request_b = BridgeRegistrationRequest {
            bridge_id: "bridge-discord-b".to_owned(),
            operator_did: OPERATOR_DID.into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Relay,
            context_id: CTX_B.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: false,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry_b, request_b).unwrap();
        approve_registration(
            &mut registry_b,
            "bridge-discord-b",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        // Each context has exactly one bridge.
        assert_eq!(registry_a.bridges().len(), 1);
        assert_eq!(registry_b.bridges().len(), 1);

        // Bridge IDs are distinct.
        assert_ne!(
            registry_a.bridges()[0].bridge_id,
            registry_b.bridges()[0].bridge_id
        );

        // Each bridge scoped to its own context.
        assert_eq!(registry_a.bridges()[0].registration_context, CTX_A);
        assert_eq!(registry_b.bridges()[0].registration_context, CTX_B);
    }

    #[test]
    fn context_a_request_rejected_by_context_b_registry() {
        let mut registry_b = BridgeRegistry::new(CTX_B.to_owned());
        let request_for_a = make_request("bridge-001", CTX_A);

        let result = register_bridge(&mut registry_b, request_for_a);
        assert!(matches!(
            result,
            Err(BridgeRegistrationError::ContextMismatch { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Same platform, two contexts = separate instances (AC 10)
    // -------------------------------------------------------------------

    #[test]
    fn same_platform_two_contexts_separate_instances() {
        let mut registry_a = BridgeRegistry::new(CTX_A.to_owned());
        let mut registry_b = BridgeRegistry::new(CTX_B.to_owned());

        let req_a = BridgeRegistrationRequest {
            bridge_id: "bridge-discord-ctx-a".to_owned(),
            operator_did: OPERATOR_DID.into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Relay,
            context_id: CTX_A.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: false,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry_a, req_a).unwrap();
        approve_registration(
            &mut registry_a,
            "bridge-discord-ctx-a",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        let req_b = BridgeRegistrationRequest {
            bridge_id: "bridge-discord-ctx-b".to_owned(),
            operator_did: OPERATOR_DID.into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Puppet,
            context_id: CTX_B.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: true,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry_b, req_b).unwrap();
        approve_registration(
            &mut registry_b,
            "bridge-discord-ctx-b",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        // Same platform, separate instances.
        assert_eq!(registry_a.bridges()[0].platform, "discord");
        assert_eq!(registry_b.bridges()[0].platform, "discord");
        assert_ne!(
            registry_a.bridges()[0].bridge_id,
            registry_b.bridges()[0].bridge_id
        );
    }

    // -------------------------------------------------------------------
    // Self-hosted bridges (ADR-023 AC 11)
    // -------------------------------------------------------------------

    #[test]
    fn self_hosted_and_managed_treated_identically() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());

        // Self-hosted bridge.
        let req_self = BridgeRegistrationRequest {
            bridge_id: "bridge-self".to_owned(),
            operator_did: OPERATOR_DID.into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Puppet,
            context_id: CTX_A.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: true,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry, req_self).unwrap();
        let (self_hosted, _) = approve_registration(
            &mut registry,
            "bridge-self",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        // Managed bridge.
        let req_managed = BridgeRegistrationRequest {
            bridge_id: "bridge-managed".to_owned(),
            operator_did: "did:dht:z6MkOther".into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Puppet,
            context_id: CTX_A.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: false,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry, req_managed).unwrap();
        let (managed, _) = approve_registration(
            &mut registry,
            "bridge-managed",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        // Both are active (treated identically).
        assert_eq!(self_hosted.status, BridgeStatus::Active);
        assert_eq!(managed.status, BridgeStatus::Active);
        assert_eq!(self_hosted.mode, managed.mode);
    }

    // -------------------------------------------------------------------
    // Event log completeness
    // -------------------------------------------------------------------

    #[test]
    fn full_lifecycle_produces_correct_event_sequence() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());

        // Request.
        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        // Approve.
        approve_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        // Revoke.
        let mut shadows = vec![];
        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        let events = registry.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].action, BridgeRegistrationAction::Requested);
        assert_eq!(events[1].action, BridgeRegistrationAction::Approved);
        assert_eq!(events[2].action, BridgeRegistrationAction::Revoked);
    }

    #[test]
    fn reject_lifecycle_produces_correct_event_sequence() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());

        let request = make_request("bridge-001", CTX_A);
        register_bridge(&mut registry, request).unwrap();

        reject_registration(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            "policy violation",
            1_700_000_001,
        )
        .unwrap();

        let events = registry.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, BridgeRegistrationAction::Requested);
        assert_eq!(
            events[1].action,
            BridgeRegistrationAction::Rejected {
                reason: "policy violation".to_owned()
            }
        );
    }

    // -------------------------------------------------------------------
    // Serialization roundtrips
    // -------------------------------------------------------------------

    #[test]
    fn request_serialization_roundtrip() {
        let request = make_request("bridge-001", CTX_A);
        let json = serde_json::to_string(&request).unwrap();
        let restored: BridgeRegistrationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.bridge_id, request.bridge_id);
        assert_eq!(restored.operator_did, request.operator_did);
        assert_eq!(restored.platform, request.platform);
        assert_eq!(restored.mode, request.mode);
        assert_eq!(restored.context_id, request.context_id);
        assert_eq!(restored.requested_at, request.requested_at);
        assert_eq!(restored.self_hosted, request.self_hosted);
    }

    #[test]
    fn event_serialization_roundtrip() {
        let event = BridgeRegistrationEvent {
            action: BridgeRegistrationAction::Approved,
            bridge_id: "bridge-001".to_owned(),
            operator_did: OPERATOR_DID.into(),
            governance_did: GOVERNANCE_DID.into(),
            context_id: CTX_A.to_owned(),
            timestamp: 1_700_000_001,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: BridgeRegistrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.action, event.action);
        assert_eq!(restored.bridge_id, event.bridge_id);
        assert_eq!(restored.operator_did, event.operator_did);
        assert_eq!(restored.governance_did, event.governance_did);
        assert_eq!(restored.context_id, event.context_id);
        assert_eq!(restored.timestamp, event.timestamp);
    }

    #[test]
    fn decision_serialization_roundtrip() {
        let decisions = [
            RegistrationDecision::Approved,
            RegistrationDecision::Rejected {
                reason: "not allowed".to_owned(),
            },
        ];
        for decision in &decisions {
            let json = serde_json::to_string(decision).unwrap();
            let restored: RegistrationDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, decision);
        }
    }

    #[test]
    fn action_serialization_roundtrip() {
        let actions = [
            BridgeRegistrationAction::Requested,
            BridgeRegistrationAction::Approved,
            BridgeRegistrationAction::Rejected {
                reason: "test".to_owned(),
            },
            BridgeRegistrationAction::Revoked,
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let restored: BridgeRegistrationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, action);
        }
    }

    // -------------------------------------------------------------------
    // Error display messages
    // -------------------------------------------------------------------

    #[test]
    fn error_display_messages() {
        let err = BridgeRegistrationError::ContextMismatch {
            registry_context: CTX_A.to_owned(),
            request_context: CTX_B.to_owned(),
        };
        assert!(format!("{err}").contains(CTX_A));
        assert!(format!("{err}").contains(CTX_B));

        let err = BridgeRegistrationError::BridgeAlreadyRegistered {
            bridge_id: "b-1".to_owned(),
        };
        assert!(format!("{err}").contains("b-1"));

        let err = BridgeRegistrationError::BridgeNotFound {
            bridge_id: "b-2".to_owned(),
        };
        assert!(format!("{err}").contains("b-2"));

        let err = BridgeRegistrationError::BridgeAlreadyRevoked {
            bridge_id: "b-3".to_owned(),
        };
        assert!(format!("{err}").contains("b-3"));

        let err = BridgeRegistrationError::NoPendingRequest {
            bridge_id: "b-4".to_owned(),
        };
        assert!(format!("{err}").contains("b-4"));

        let err = BridgeRegistrationError::SelfApproval {
            did: OPERATOR_DID.into(),
        };
        assert!(format!("{err}").contains(OPERATOR_DID));
    }

    // -------------------------------------------------------------------
    // Multiple bridges in one context
    // -------------------------------------------------------------------

    #[test]
    fn multiple_bridges_coexist_in_same_context() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());

        register_and_approve(&mut registry, "bridge-discord");

        let req_slack = BridgeRegistrationRequest {
            bridge_id: "bridge-slack".to_owned(),
            operator_did: "did:dht:z6MkSlackOp".into(),
            platform: "slack".to_owned(),
            mode: BridgeMode::Api,
            context_id: CTX_A.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: true,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry, req_slack).unwrap();
        approve_registration(
            &mut registry,
            "bridge-slack",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        assert_eq!(registry.bridges().len(), 2);

        let platforms: Vec<&str> = registry
            .bridges()
            .iter()
            .map(|b| b.platform.as_str())
            .collect();
        assert!(platforms.contains(&"discord"));
        assert!(platforms.contains(&"slack"));
    }

    // -------------------------------------------------------------------
    // Revoke only affects target bridge's shadows
    // -------------------------------------------------------------------

    #[test]
    fn revoke_only_affects_target_bridge_shadows() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");
        register_and_approve(&mut registry, "bridge-002");

        let mut shadows = vec![
            make_shadow("bridge-001", "s1"),
            make_shadow("bridge-002", "s2"),
            make_shadow("bridge-001", "s3"),
        ];

        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        // bridge-001 shadows revoked.
        assert_eq!(shadows[0].attributed_role, "revoked");
        assert_eq!(shadows[2].attributed_role, "revoked");
        // bridge-002 shadow untouched.
        assert_eq!(shadows[1].attributed_role, "observer");
        // bridge-002 still active.
        let active = list_active_bridges(&registry);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].bridge_id, "bridge-002");
    }

    // -------------------------------------------------------------------
    // All bridge modes can be registered
    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // bridge_operator_dids (SCP-BCH-013, §12.6.1)
    // -------------------------------------------------------------------

    #[test]
    fn bridge_operator_dids_empty_when_no_bridges() {
        let registry = BridgeRegistry::new(CTX_A.to_owned());
        assert!(registry.bridge_operator_dids().is_empty());
    }

    #[test]
    fn bridge_operator_dids_after_registration() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");
        let dids = registry.bridge_operator_dids();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], DID::from(OPERATOR_DID));
    }

    #[test]
    fn bridge_operator_dids_removed_after_revocation() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        let mut shadows = vec![];
        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        assert!(registry.bridge_operator_dids().is_empty());
    }

    #[test]
    fn bridge_operator_dids_multiple_operators() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());
        register_and_approve(&mut registry, "bridge-001");

        // Register a second bridge with a different operator.
        let req = BridgeRegistrationRequest {
            bridge_id: "bridge-002".to_owned(),
            operator_did: "did:dht:z6MkOther".into(),
            platform: "slack".to_owned(),
            mode: BridgeMode::Api,
            context_id: CTX_A.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: false,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry, req).unwrap();
        approve_registration(
            &mut registry,
            "bridge-002",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        let dids = registry.bridge_operator_dids();
        assert_eq!(dids.len(), 2);
        assert!(dids.contains(&DID::from(OPERATOR_DID)));
        assert!(dids.contains(&DID::from("did:dht:z6MkOther")));
    }

    #[test]
    fn bridge_operator_dids_deduplicates_same_operator() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());

        // Same operator registers two bridges.
        register_and_approve(&mut registry, "bridge-001");

        let req = BridgeRegistrationRequest {
            bridge_id: "bridge-002".to_owned(),
            operator_did: OPERATOR_DID.into(),
            platform: "slack".to_owned(),
            mode: BridgeMode::Api,
            context_id: CTX_A.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: false,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry, req).unwrap();
        approve_registration(
            &mut registry,
            "bridge-002",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        // Same operator — should appear only once.
        let dids = registry.bridge_operator_dids();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], DID::from(OPERATOR_DID));
    }

    #[test]
    fn bridge_operator_dids_operator_retained_if_other_bridges_active() {
        let mut registry = BridgeRegistry::new(CTX_A.to_owned());

        // Same operator registers two bridges.
        register_and_approve(&mut registry, "bridge-001");

        let req = BridgeRegistrationRequest {
            bridge_id: "bridge-002".to_owned(),
            operator_did: OPERATOR_DID.into(),
            platform: "slack".to_owned(),
            mode: BridgeMode::Api,
            context_id: CTX_A.to_owned(),
            requested_at: 1_700_000_000,
            self_hosted: false,
            webhook_url: None,
            platform_key: None,
            max_shadows: 10_000,
            metadata: BridgeRegistrationMetadata::default(),
        };
        register_bridge(&mut registry, req).unwrap();
        approve_registration(
            &mut registry,
            "bridge-002",
            &DID::from(GOVERNANCE_DID),
            1_700_000_001,
        )
        .unwrap();

        // Revoke one bridge — operator still has another active.
        let mut shadows = vec![];
        revoke_bridge(
            &mut registry,
            "bridge-001",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_002,
        )
        .unwrap();

        let dids = registry.bridge_operator_dids();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], DID::from(OPERATOR_DID));

        // Revoke the second bridge — operator should now be removed.
        revoke_bridge(
            &mut registry,
            "bridge-002",
            &DID::from(GOVERNANCE_DID),
            &mut shadows,
            1_700_000_003,
        )
        .unwrap();

        assert!(registry.bridge_operator_dids().is_empty());
    }

    // -------------------------------------------------------------------
    // All bridge modes can be registered
    // -------------------------------------------------------------------

    #[test]
    fn all_bridge_modes_can_be_registered() {
        let modes = [
            ("relay", BridgeMode::Relay),
            ("puppet", BridgeMode::Puppet),
            ("api", BridgeMode::Api),
            ("coop", BridgeMode::Cooperative),
        ];

        for (suffix, mode) in &modes {
            let mut registry = BridgeRegistry::new(CTX_A.to_owned());
            let bridge_id = format!("bridge-{suffix}");
            let request = BridgeRegistrationRequest {
                bridge_id: bridge_id.clone(),
                operator_did: OPERATOR_DID.into(),
                platform: "discord".to_owned(),
                mode: mode.clone(),
                context_id: CTX_A.to_owned(),
                requested_at: 1_700_000_000,
                self_hosted: false,
                webhook_url: None,
                platform_key: None,
                max_shadows: 10_000,
                metadata: BridgeRegistrationMetadata::default(),
            };
            register_bridge(&mut registry, request).unwrap();
            let (connector, _) = approve_registration(
                &mut registry,
                &bridge_id,
                &DID::from(GOVERNANCE_DID),
                1_700_000_001,
            )
            .unwrap();
            assert_eq!(connector.mode, *mode);
        }
    }
}
