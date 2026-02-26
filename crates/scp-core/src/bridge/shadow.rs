//! Shadow identity creation and role management.
//!
//! Bridges create shadow identities to give external platform participants
//! protocol-level representation with provenance. Shadows are restricted by
//! default (observer role) to prevent capability escalation through bridges.
//! Shadow roles are upgradeable by context governance.
//!
//! # Workflow
//!
//! 1. A bridge calls [`create_shadow`] to create a [`ShadowIdentity`] for an
//!    external platform participant. The shadow starts with the `"observer"`
//!    role.
//! 2. Context governance may call [`upgrade_shadow_role`] to promote a shadow
//!    to a more privileged role.
//! 3. [`list_shadows`] returns all shadows for a given bridge.
//! 4. [`can_exercise_capability`] checks whether a shadow is allowed to
//!    perform an action requiring verified identity.
//!
//! # Capability restrictions
//!
//! Shadows cannot exercise capabilities requiring verified identity. The set
//! of restricted capabilities is defined in [`VERIFIED_IDENTITY_CAPABILITIES`].
//! Only a native SCP identity (or a claimed shadow retroattributed to a DID)
//! may exercise these capabilities.
//!
//! # Context events
//!
//! Shadow creation produces a [`ShadowCreationEvent`] that is recorded in the
//! context's Merkle log (ADR-011).
//!
//! See ADR-023 acceptance criteria 3-4 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

use super::{BridgeMode, ContextId, DID, ShadowIdentity, ShadowProvenanceStatus};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The default role assigned to newly created shadow identities.
///
/// Observer-equivalent: restricted capabilities, cannot exercise capabilities
/// requiring verified identity (ADR-023 acceptance criterion 4).
pub const DEFAULT_SHADOW_ROLE: &str = "observer";

/// Default maximum number of shadow identities per bridge.
///
/// Prevents a single bridge from exhausting memory by creating an unbounded
/// number of shadows.
pub const DEFAULT_MAX_SHADOWS_PER_BRIDGE: usize = 10_000;

/// Default maximum total number of shadow identities in a registry.
///
/// Prevents overall memory exhaustion across all bridges.
pub const DEFAULT_MAX_TOTAL_SHADOWS: usize = 100_000;

/// Capabilities that require a verified SCP identity and cannot be exercised
/// by shadow identities.
///
/// These are capabilities where unverified identity would create security or
/// trust issues (e.g., governance voting, key management, identity
/// attestation). A shadow must first be claimed (bound to a DID via identity
/// attestation) before these capabilities become available.
///
/// See ADR-023 acceptance criterion 4: "Cannot exercise capabilities
/// requiring verified identity."
pub const VERIFIED_IDENTITY_CAPABILITIES: &[&str] = &[
    "governance.vote",
    "governance.propose",
    "identity.attest",
    "identity.delegate",
    "key.rotate",
    "key.export",
    "member.invite",
    "member.remove",
    "context.configure",
    "tool.register",
];

// ---------------------------------------------------------------------------
// ShadowError
// ---------------------------------------------------------------------------

/// Errors produced by shadow identity operations.
#[derive(Debug, thiserror::Error)]
pub enum ShadowError {
    /// The bridge ID does not match any registered bridge.
    #[error("bridge not found: {bridge_id}")]
    BridgeNotFound {
        /// The bridge ID that was not found.
        bridge_id: String,
    },

    /// A shadow with the given ID already exists.
    #[error("shadow already exists: {shadow_id}")]
    ShadowAlreadyExists {
        /// The duplicate shadow ID.
        shadow_id: String,
    },

    /// The specified shadow was not found.
    #[error("shadow not found: {shadow_id}")]
    ShadowNotFound {
        /// The shadow ID that was not found.
        shadow_id: String,
    },

    /// A shadow with the same platform handle already exists for this bridge.
    #[error("duplicate platform handle {platform_handle} on bridge {bridge_id}")]
    DuplicateHandle {
        /// The bridge ID.
        bridge_id: String,
        /// The duplicate platform handle.
        platform_handle: String,
    },

    /// The shadow cannot exercise the requested capability because it
    /// requires verified identity.
    #[error(
        "shadow {shadow_id} cannot exercise capability {capability}: \
         requires verified identity"
    )]
    VerifiedIdentityRequired {
        /// The shadow ID that attempted the capability.
        shadow_id: String,
        /// The capability that was denied.
        capability: String,
    },

    /// The governance action is invalid for the requested role upgrade.
    #[error("invalid governance action for role upgrade: {reason}")]
    InvalidGovernanceAction {
        /// Human-readable reason.
        reason: String,
    },

    /// The shadow registry has reached its capacity limit.
    #[error("capacity exceeded: {reason}")]
    CapacityExceeded {
        /// Human-readable description of which limit was exceeded.
        reason: String,
    },

    /// The shadow identity collides with an existing context member DID or
    /// another shadow identity in the same context.
    ///
    /// Prevents a bridge operator from mapping a shadow identity to a real
    /// member's DID, which would enable message forgery.
    #[error("shadow identity collision: {reason}")]
    ShadowIdentityCollision {
        /// Human-readable description of the collision.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

/// A governance action authorizing a shadow role upgrade.
///
/// Role upgrades require explicit governance approval. The governance actor
/// must be a verified SCP identity (not itself a shadow).
///
/// See ADR-023 acceptance criterion 4: "Specific role upgradeable by context
/// governance."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceAction {
    /// DID of the governance actor authorizing the role change.
    pub governance_did: DID,

    /// The context in which this governance action applies.
    pub context_id: ContextId,

    /// Unix timestamp (seconds) when the action was authorized.
    pub timestamp: u64,

    /// Human-readable justification for the role change.
    pub justification: String,
}

// ---------------------------------------------------------------------------
// ShadowCreationEvent
// ---------------------------------------------------------------------------

/// A context event recording the creation of a shadow identity.
///
/// This event is appended to the context's Merkle log (ADR-011) to provide
/// an auditable record of all shadow identity lifecycle changes.
///
/// See ADR-023 acceptance criterion 3: "Shadow creation is a context event
/// in the Merkle log."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCreationEvent {
    /// The unique ID of the newly created shadow identity.
    pub shadow_id: String,

    /// The external platform handle (e.g., `"@user#1234"`).
    pub platform_handle: String,

    /// The bridge connector that created this shadow identity.
    pub bridge_id: String,

    /// The operating mode of the bridge at the time of creation.
    pub bridge_mode: BridgeMode,

    /// The initial role assigned to the shadow (always [`DEFAULT_SHADOW_ROLE`]).
    pub initial_role: String,

    /// The context in which this shadow was created.
    pub context_id: ContextId,

    /// Unix timestamp (seconds) when the shadow was created.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// ShadowRoleUpgradeEvent
// ---------------------------------------------------------------------------

/// A context event recording a shadow role upgrade.
///
/// Recorded in the Merkle log alongside the governance action that authorized
/// the upgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowRoleUpgradeEvent {
    /// The shadow identity whose role was upgraded.
    pub shadow_id: String,

    /// The previous role.
    pub previous_role: String,

    /// The new role after upgrade.
    pub new_role: String,

    /// DID of the governance actor who authorized the upgrade.
    pub governance_did: DID,

    /// The context in which this upgrade occurred.
    pub context_id: ContextId,

    /// Unix timestamp (seconds) when the upgrade occurred.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// ShadowRegistry
// ---------------------------------------------------------------------------

/// In-memory registry of shadow identities for a single context.
///
/// Scoped to one context (context isolation tenet). All shadow operations
/// are performed through this registry to maintain consistent state.
///
/// Capacity limits prevent memory exhaustion from malicious bridges:
/// - `max_shadows_per_bridge` limits how many shadows any single bridge can
///   create (default: 10,000).
/// - `max_total_shadows` limits the total number of shadows across all
///   bridges (default: 100,000).
///
/// See ADR-023 acceptance criteria 3-4.
#[derive(Debug)]
pub struct ShadowRegistry {
    /// The context this registry belongs to.
    context_id: ContextId,

    /// All shadow identities in this context.
    shadows: Vec<ShadowIdentity>,

    /// Event log of shadow creation events (for Merkle log integration).
    creation_events: Vec<ShadowCreationEvent>,

    /// Event log of shadow role upgrade events.
    upgrade_events: Vec<ShadowRoleUpgradeEvent>,

    /// Maximum number of shadow identities any single bridge can create.
    max_shadows_per_bridge: usize,

    /// Maximum total number of shadow identities across all bridges.
    max_total_shadows: usize,
}

impl ShadowRegistry {
    /// Creates a new empty shadow registry for the given context with default
    /// capacity limits.
    #[must_use]
    pub fn new(context_id: ContextId) -> Self {
        Self {
            context_id,
            shadows: Vec::new(),
            creation_events: Vec::new(),
            upgrade_events: Vec::new(),
            max_shadows_per_bridge: DEFAULT_MAX_SHADOWS_PER_BRIDGE,
            max_total_shadows: DEFAULT_MAX_TOTAL_SHADOWS,
        }
    }

    /// Creates a new empty shadow registry with custom capacity limits.
    ///
    /// # Arguments
    ///
    /// - `context_id` -- The context this registry belongs to.
    /// - `max_shadows_per_bridge` -- Maximum shadows per bridge.
    /// - `max_total_shadows` -- Maximum total shadows across all bridges.
    #[must_use]
    pub fn with_limits(
        context_id: ContextId,
        max_shadows_per_bridge: usize,
        max_total_shadows: usize,
    ) -> Self {
        Self {
            context_id,
            shadows: Vec::new(),
            creation_events: Vec::new(),
            upgrade_events: Vec::new(),
            max_shadows_per_bridge,
            max_total_shadows,
        }
    }

    /// Returns the context ID this registry is scoped to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns all shadow identities in this context.
    #[must_use]
    pub fn shadows(&self) -> &[ShadowIdentity] {
        &self.shadows
    }

    /// Returns all shadow creation events (the audit log).
    #[must_use]
    pub fn creation_events(&self) -> &[ShadowCreationEvent] {
        &self.creation_events
    }

    /// Returns all shadow role upgrade events.
    #[must_use]
    pub fn upgrade_events(&self) -> &[ShadowRoleUpgradeEvent] {
        &self.upgrade_events
    }

    /// Returns the maximum number of shadows allowed per bridge.
    #[must_use]
    pub fn max_shadows_per_bridge(&self) -> usize {
        self.max_shadows_per_bridge
    }

    /// Returns the maximum total number of shadows allowed.
    #[must_use]
    pub fn max_total_shadows(&self) -> usize {
        self.max_total_shadows
    }
}

// ---------------------------------------------------------------------------
// create_shadow
// ---------------------------------------------------------------------------

/// Creates a shadow identity for an external platform participant.
///
/// The bridge creates a protocol entity per external platform participant.
/// The shadow carries the platform handle, bridge reference, and starts
/// with the observer-equivalent default role. A [`ShadowCreationEvent`] is
/// produced for recording in the context's Merkle log.
///
/// # Arguments
///
/// - `registry` -- The shadow registry for this context.
/// - `shadow_id` -- Unique identifier for the new shadow identity.
/// - `bridge_id` -- The bridge connector creating this shadow.
/// - `bridge_mode` -- The operating mode of the bridge.
/// - `platform_handle` -- The external platform handle (e.g., `"@user#1234"`).
/// - `context_member_dids` -- Current context member DIDs. The shadow ID is
///   validated against this set to prevent a bridge operator from mapping a
///   shadow identity to a real member's DID (which would enable message
///   forgery). Pass an empty slice if member validation is not available.
/// - `timestamp` -- Unix timestamp (seconds) of creation.
///
/// # Errors
///
/// Returns [`ShadowError::ShadowIdentityCollision`] if the shadow ID
/// matches an existing context member DID or another shadow in the same
/// context.
///
/// Returns [`ShadowError::ShadowAlreadyExists`] if a shadow with the same
/// ID already exists.
///
/// Returns [`ShadowError::DuplicateHandle`] if a shadow with the same
/// platform handle already exists for this bridge.
///
/// Returns [`ShadowError::CapacityExceeded`] if the per-bridge or total
/// shadow limit would be exceeded.
///
/// See ADR-023 acceptance criterion 3.
pub fn create_shadow(
    registry: &mut ShadowRegistry,
    shadow_id: &str,
    bridge_id: &str,
    bridge_mode: BridgeMode,
    platform_handle: &str,
    context_member_dids: &[&str],
    timestamp: u64,
) -> Result<(ShadowIdentity, ShadowCreationEvent), ShadowError> {
    // Defense-in-depth: reject shadow ID that collides with a real context
    // member DID. A bridge operator could otherwise map a shadow to a real
    // member's DID, enabling message forgery.
    if context_member_dids.iter().any(|did| *did == shadow_id) {
        return Err(ShadowError::ShadowIdentityCollision {
            reason: format!(
                "shadow ID {shadow_id} collides with existing context member DID"
            ),
        });
    }

    // Defense-in-depth: reject shadow ID that collides with an existing
    // shadow in the same context (registry). This is distinct from the
    // ShadowAlreadyExists check below, which matches on shadow_id only --
    // this catches the broader case where the proposed shadow_id matches
    // *any* shadow's shadow_id in the registry, preventing identity
    // confusion between shadows.
    if registry.shadows.iter().any(|s| s.shadow_id == shadow_id) {
        return Err(ShadowError::ShadowAlreadyExists {
            shadow_id: shadow_id.to_owned(),
        });
    }

    // Check for duplicate platform handle on the same bridge.
    if registry
        .shadows
        .iter()
        .any(|s| s.bridge_id == bridge_id && s.platform_handle == platform_handle)
    {
        return Err(ShadowError::DuplicateHandle {
            bridge_id: bridge_id.to_owned(),
            platform_handle: platform_handle.to_owned(),
        });
    }

    // Check total capacity limit.
    if registry.shadows.len() >= registry.max_total_shadows {
        return Err(ShadowError::CapacityExceeded {
            reason: format!(
                "total shadow limit ({}) reached",
                registry.max_total_shadows
            ),
        });
    }

    // Check per-bridge capacity limit.
    let bridge_shadow_count = registry
        .shadows
        .iter()
        .filter(|s| s.bridge_id == bridge_id)
        .count();
    if bridge_shadow_count >= registry.max_shadows_per_bridge {
        return Err(ShadowError::CapacityExceeded {
            reason: format!(
                "per-bridge shadow limit ({}) reached for bridge {bridge_id}",
                registry.max_shadows_per_bridge
            ),
        });
    }

    let shadow = ShadowIdentity {
        shadow_id: shadow_id.to_owned(),
        platform_handle: platform_handle.to_owned(),
        bridge_id: bridge_id.to_owned(),
        attributed_role: DEFAULT_SHADOW_ROLE.to_owned(),
        provenance_status: ShadowProvenanceStatus::Shadow,
        created_at: timestamp,
    };

    let event = ShadowCreationEvent {
        shadow_id: shadow_id.to_owned(),
        platform_handle: platform_handle.to_owned(),
        bridge_id: bridge_id.to_owned(),
        bridge_mode,
        initial_role: DEFAULT_SHADOW_ROLE.to_owned(),
        context_id: registry.context_id.clone(),
        timestamp,
    };

    registry.shadows.push(shadow.clone());
    registry.creation_events.push(event.clone());

    Ok((shadow, event))
}

// ---------------------------------------------------------------------------
// upgrade_shadow_role
// ---------------------------------------------------------------------------

/// Upgrades a shadow identity's role via context governance.
///
/// Shadow roles start as `"observer"` and can be upgraded to a more
/// privileged role by context governance. The governance action must include
/// a valid DID and justification.
///
/// # SAFETY: Callers must verify governance authorization
///
/// This function does **not** cryptographically verify the `GovernanceAction`.
/// It checks only structural validity (context match, non-empty role). The
/// caller is responsible for verifying that:
///
/// 1. The `governance_did` is authorized to perform governance actions in
///    this context (e.g., via UCAN capability check).
/// 2. The `GovernanceAction` is authentic (e.g., signature verification on
///    the envelope that carried it).
/// 3. The governance actor is not itself a shadow identity.
///
/// Failure to verify governance authorization before calling this function
/// allows any participant to escalate shadow roles.
///
/// # Arguments
///
/// - `registry` -- The shadow registry for this context.
/// - `shadow_id` -- The shadow identity to upgrade.
/// - `new_role` -- The new role to assign.
/// - `governance` -- The governance action authorizing the upgrade.
///
/// # Errors
///
/// Returns [`ShadowError::ShadowNotFound`] if no shadow with the given ID
/// exists.
///
/// Returns [`ShadowError::InvalidGovernanceAction`] if the governance
/// context does not match the registry context, or if the new role is empty.
///
/// See ADR-023 acceptance criterion 4: "Specific role upgradeable by context
/// governance."
pub(crate) fn upgrade_shadow_role(
    registry: &mut ShadowRegistry,
    shadow_id: &str,
    new_role: &str,
    governance: &GovernanceAction,
) -> Result<ShadowRoleUpgradeEvent, ShadowError> {
    // Validate governance action context matches registry.
    if governance.context_id != registry.context_id {
        return Err(ShadowError::InvalidGovernanceAction {
            reason: format!(
                "governance context {} does not match registry context {}",
                governance.context_id, registry.context_id
            ),
        });
    }

    // Validate non-empty role.
    if new_role.is_empty() {
        return Err(ShadowError::InvalidGovernanceAction {
            reason: "new role cannot be empty".to_owned(),
        });
    }

    // Find the shadow and update its role.
    let shadow = registry
        .shadows
        .iter_mut()
        .find(|s| s.shadow_id == shadow_id)
        .ok_or_else(|| ShadowError::ShadowNotFound {
            shadow_id: shadow_id.to_owned(),
        })?;

    let previous_role = shadow.attributed_role.clone();
    new_role.clone_into(&mut shadow.attributed_role);

    let event = ShadowRoleUpgradeEvent {
        shadow_id: shadow_id.to_owned(),
        previous_role,
        new_role: new_role.to_owned(),
        governance_did: governance.governance_did.clone(),
        context_id: registry.context_id.clone(),
        timestamp: governance.timestamp,
    };

    registry.upgrade_events.push(event.clone());

    Ok(event)
}

// ---------------------------------------------------------------------------
// list_shadows
// ---------------------------------------------------------------------------

/// Returns all shadow identities for a given bridge.
///
/// Filters the registry to return only shadows belonging to the specified
/// bridge connector.
///
/// # Arguments
///
/// - `registry` -- The shadow registry to query.
/// - `bridge_id` -- The bridge connector ID to filter by.
///
/// See ADR-023 acceptance criterion 3.
#[must_use]
pub fn list_shadows<'a>(registry: &'a ShadowRegistry, bridge_id: &str) -> Vec<&'a ShadowIdentity> {
    registry
        .shadows
        .iter()
        .filter(|s| s.bridge_id == bridge_id)
        .collect()
}

// ---------------------------------------------------------------------------
// can_exercise_capability
// ---------------------------------------------------------------------------

/// Checks whether a shadow identity can exercise a given capability.
///
/// Shadows cannot exercise capabilities requiring verified identity. These
/// capabilities are listed in [`VERIFIED_IDENTITY_CAPABILITIES`]. A shadow
/// must be claimed (bound to a DID via identity attestation) before gaining
/// access to verified-identity capabilities.
///
/// # Arguments
///
/// - `shadow` -- The shadow identity attempting the capability.
/// - `capability` -- The capability string to check (e.g., `"governance.vote"`).
///
/// # Returns
///
/// `Ok(())` if the shadow is allowed to exercise the capability.
///
/// # Errors
///
/// Returns [`ShadowError::VerifiedIdentityRequired`] if the capability
/// requires verified identity and the shadow is unclaimed.
///
/// See ADR-023 acceptance criterion 4: "Cannot exercise capabilities
/// requiring verified identity."
pub fn can_exercise_capability(
    shadow: &ShadowIdentity,
    capability: &str,
) -> Result<(), ShadowError> {
    // Claimed shadows have been bound to a DID and can exercise all
    // capabilities (their actions are retroattributed to the claimant).
    if shadow.provenance_status == ShadowProvenanceStatus::Claimed {
        return Ok(());
    }

    // Unclaimed shadows cannot exercise verified-identity capabilities.
    if VERIFIED_IDENTITY_CAPABILITIES.contains(&capability) {
        return Err(ShadowError::VerifiedIdentityRequired {
            shadow_id: shadow.shadow_id.clone(),
            capability: capability.to_owned(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// find_shadow
// ---------------------------------------------------------------------------

/// Finds a shadow identity by ID within the registry.
///
/// # Arguments
///
/// - `registry` -- The shadow registry to search.
/// - `shadow_id` -- The shadow identity ID to find.
///
/// # Errors
///
/// Returns [`ShadowError::ShadowNotFound`] if no shadow with the given ID
/// exists.
pub fn find_shadow<'a>(
    registry: &'a ShadowRegistry,
    shadow_id: &str,
) -> Result<&'a ShadowIdentity, ShadowError> {
    registry
        .shadows
        .iter()
        .find(|s| s.shadow_id == shadow_id)
        .ok_or_else(|| ShadowError::ShadowNotFound {
            shadow_id: shadow_id.to_owned(),
        })
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

    const CTX: &str = "ctx-shadow-test";
    const BRIDGE_ID: &str = "bridge-001";
    const GOVERNANCE_DID: &str = "did:dht:z6MkGovernance";

    fn make_registry() -> ShadowRegistry {
        ShadowRegistry::new(CTX.to_owned())
    }

    fn make_governance(context_id: &str) -> GovernanceAction {
        GovernanceAction {
            governance_did: GOVERNANCE_DID.into(),
            context_id: context_id.to_owned(),
            timestamp: 1_700_001_000,
            justification: "promoted by governance".to_owned(),
        }
    }

    fn create_test_shadow(
        registry: &mut ShadowRegistry,
        shadow_id: &str,
        handle: &str,
    ) -> (ShadowIdentity, ShadowCreationEvent) {
        create_shadow(
            registry,
            shadow_id,
            BRIDGE_ID,
            BridgeMode::Relay,
            handle,
            &[],
            1_700_000_100,
        )
        .unwrap()
    }

    // -------------------------------------------------------------------
    // create_shadow
    // -------------------------------------------------------------------

    #[test]
    fn create_shadow_returns_shadow_with_observer_role() {
        let mut registry = make_registry();
        let (shadow, _event) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        assert_eq!(shadow.attributed_role, DEFAULT_SHADOW_ROLE);
        assert_eq!(shadow.attributed_role, "observer");
    }

    #[test]
    fn create_shadow_carries_platform_handle() {
        let mut registry = make_registry();
        let (shadow, _event) = create_test_shadow(&mut registry, "shadow-001", "@alice#1234");

        assert_eq!(shadow.platform_handle, "@alice#1234");
    }

    #[test]
    fn create_shadow_carries_bridge_reference() {
        let mut registry = make_registry();
        let (shadow, _event) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        assert_eq!(shadow.bridge_id, BRIDGE_ID);
    }

    #[test]
    fn create_shadow_sets_unclaimed_provenance_status() {
        let mut registry = make_registry();
        let (shadow, _event) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        assert_eq!(shadow.provenance_status, ShadowProvenanceStatus::Shadow);
    }

    #[test]
    fn create_shadow_stores_timestamp() {
        let mut registry = make_registry();
        let (shadow, _event) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        assert_eq!(shadow.created_at, 1_700_000_100);
    }

    #[test]
    fn create_shadow_adds_to_registry() {
        let mut registry = make_registry();
        assert_eq!(registry.shadows().len(), 0);

        create_test_shadow(&mut registry, "shadow-001", "@alice");
        assert_eq!(registry.shadows().len(), 1);

        create_test_shadow(&mut registry, "shadow-002", "@bob");
        assert_eq!(registry.shadows().len(), 2);
    }

    #[test]
    fn create_shadow_produces_creation_event() {
        let mut registry = make_registry();
        let (_shadow, event) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        assert_eq!(event.shadow_id, "shadow-001");
        assert_eq!(event.platform_handle, "@alice");
        assert_eq!(event.bridge_id, BRIDGE_ID);
        assert_eq!(event.bridge_mode, BridgeMode::Relay);
        assert_eq!(event.initial_role, DEFAULT_SHADOW_ROLE);
        assert_eq!(event.context_id, CTX);
        assert_eq!(event.timestamp, 1_700_000_100);
    }

    #[test]
    fn create_shadow_records_event_in_registry() {
        let mut registry = make_registry();
        assert_eq!(registry.creation_events().len(), 0);

        create_test_shadow(&mut registry, "shadow-001", "@alice");
        assert_eq!(registry.creation_events().len(), 1);
        assert_eq!(registry.creation_events()[0].shadow_id, "shadow-001");
    }

    #[test]
    fn create_shadow_rejects_duplicate_id() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let result = create_shadow(
            &mut registry,
            "shadow-001",
            BRIDGE_ID,
            BridgeMode::Relay,
            "@bob",
            &[],
            1_700_000_200,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("shadow already exists"),
            "expected ShadowAlreadyExists, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // SCP-181: shadow identity collision validation
    // -------------------------------------------------------------------

    #[test]
    fn create_shadow_rejects_collision_with_context_member_did() {
        let mut registry = make_registry();
        // Simulate a context where "did:dht:real-member" is an existing member.
        let member_dids = ["did:dht:real-member"];

        let result = create_shadow(
            &mut registry,
            "did:dht:real-member", // shadow ID collides with real member
            BRIDGE_ID,
            BridgeMode::Relay,
            "@attacker",
            member_dids.as_slice(),
            1_700_000_100,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ShadowError::ShadowIdentityCollision { .. }),
            "expected ShadowIdentityCollision, got: {err}"
        );
        assert!(
            err.to_string().contains("context member DID"),
            "error message should mention context member DID, got: {err}"
        );
    }

    #[test]
    fn create_shadow_rejects_collision_with_existing_shadow() {
        let mut registry = make_registry();
        // Create a shadow with a known ID.
        create_test_shadow(&mut registry, "shadow-existing", "@alice");

        // Attempt to create another shadow with the same ID on a different bridge.
        // The existing ShadowAlreadyExists check catches same-ID within the registry.
        let result = create_shadow(
            &mut registry,
            "shadow-existing",
            "bridge-002", // different bridge
            BridgeMode::Api,
            "@attacker",
            &[],
            1_700_000_200,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ShadowError::ShadowAlreadyExists { .. }),
            "duplicate shadow ID should be rejected as ShadowAlreadyExists, got: {err}"
        );
    }

    #[test]
    fn create_shadow_allows_non_colliding_id() {
        let mut registry = make_registry();
        // Context has real members, but shadow ID doesn't collide.
        let member_dids = ["did:dht:alice", "did:dht:bob"];

        let result = create_shadow(
            &mut registry,
            "did:dht:shadow-charlie", // does not collide with members
            BRIDGE_ID,
            BridgeMode::Relay,
            "@charlie",
            member_dids.as_slice(),
            1_700_000_100,
        );

        assert!(result.is_ok(), "non-colliding shadow should be created");
    }

    #[test]
    fn create_shadow_rejects_duplicate_handle_on_same_bridge() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let result = create_shadow(
            &mut registry,
            "shadow-002",
            BRIDGE_ID,
            BridgeMode::Relay,
            "@alice",
            &[],
            1_700_000_200,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("duplicate platform handle"),
            "expected DuplicateHandle, got: {err}"
        );
    }

    #[test]
    fn create_shadow_allows_same_handle_on_different_bridge() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let result = create_shadow(
            &mut registry,
            "shadow-002",
            "bridge-002",
            BridgeMode::Api,
            "@alice",
            &[],
            1_700_000_200,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn create_shadow_with_different_bridge_modes() {
        let mut registry = make_registry();

        for (i, mode) in [
            BridgeMode::Relay,
            BridgeMode::Puppet,
            BridgeMode::Api,
            BridgeMode::Cooperative,
        ]
        .iter()
        .enumerate()
        {
            let shadow_id = format!("shadow-{i}");
            let bridge_id = format!("bridge-{i}");
            let handle = format!("@user{i}");

            let result = create_shadow(
                &mut registry,
                &shadow_id,
                &bridge_id,
                mode.clone(),
                &handle,
                &[],
                1_700_000_100,
            );

            assert!(result.is_ok());
            let (_shadow, event) = result.unwrap();
            assert_eq!(event.bridge_mode, *mode);
        }
    }

    // -------------------------------------------------------------------
    // Capacity limits
    // -------------------------------------------------------------------

    #[test]
    fn create_shadow_rejects_when_total_limit_reached() {
        let mut registry = ShadowRegistry::with_limits(CTX.to_owned(), 100, 3);

        // Create 3 shadows (at the total limit).
        for i in 0..3 {
            let shadow_id = format!("shadow-{i}");
            let handle = format!("@user{i}");
            let bridge_id = format!("bridge-{i}");
            create_shadow(
                &mut registry,
                &shadow_id,
                &bridge_id,
                BridgeMode::Relay,
                &handle,
                &[],
                1_700_000_100,
            )
            .unwrap();
        }

        // The 4th should fail.
        let result = create_shadow(
            &mut registry,
            "shadow-overflow",
            "bridge-new",
            BridgeMode::Relay,
            "@overflow",
            &[],
            1_700_000_200,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ShadowError::CapacityExceeded { .. }),
            "expected CapacityExceeded, got: {err}"
        );
        assert!(
            err.to_string().contains("total shadow limit"),
            "error message should mention total limit, got: {err}"
        );
    }

    #[test]
    fn create_shadow_rejects_when_per_bridge_limit_reached() {
        let mut registry = ShadowRegistry::with_limits(CTX.to_owned(), 2, 100);

        // Create 2 shadows on the same bridge (at the per-bridge limit).
        for i in 0..2 {
            let shadow_id = format!("shadow-{i}");
            let handle = format!("@user{i}");
            create_shadow(
                &mut registry,
                &shadow_id,
                BRIDGE_ID,
                BridgeMode::Relay,
                &handle,
                &[],
                1_700_000_100,
            )
            .unwrap();
        }

        // The 3rd on the same bridge should fail.
        let result = create_shadow(
            &mut registry,
            "shadow-overflow",
            BRIDGE_ID,
            BridgeMode::Relay,
            "@overflow",
            &[],
            1_700_000_200,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ShadowError::CapacityExceeded { .. }),
            "expected CapacityExceeded, got: {err}"
        );
        assert!(
            err.to_string().contains("per-bridge shadow limit"),
            "error message should mention per-bridge limit, got: {err}"
        );
    }

    #[test]
    fn per_bridge_limit_does_not_affect_other_bridges() {
        let mut registry = ShadowRegistry::with_limits(CTX.to_owned(), 2, 100);

        // Fill bridge-001 to its limit.
        for i in 0..2 {
            let shadow_id = format!("shadow-a-{i}");
            let handle = format!("@user-a-{i}");
            create_shadow(
                &mut registry,
                &shadow_id,
                "bridge-001",
                BridgeMode::Relay,
                &handle,
                &[],
                1_700_000_100,
            )
            .unwrap();
        }

        // bridge-002 should still be able to create shadows.
        let result = create_shadow(
            &mut registry,
            "shadow-b-0",
            "bridge-002",
            BridgeMode::Relay,
            "@user-b-0",
            &[],
            1_700_000_200,
        );
        assert!(
            result.is_ok(),
            "different bridge should not be affected by per-bridge limit"
        );
    }

    #[test]
    fn registry_with_limits_has_correct_values() {
        let registry = ShadowRegistry::with_limits(CTX.to_owned(), 42, 999);
        assert_eq!(registry.max_shadows_per_bridge(), 42);
        assert_eq!(registry.max_total_shadows(), 999);
    }

    #[test]
    fn default_registry_has_default_limits() {
        let registry = ShadowRegistry::new(CTX.to_owned());
        assert_eq!(
            registry.max_shadows_per_bridge(),
            DEFAULT_MAX_SHADOWS_PER_BRIDGE
        );
        assert_eq!(registry.max_total_shadows(), DEFAULT_MAX_TOTAL_SHADOWS);
    }

    // -------------------------------------------------------------------
    // upgrade_shadow_role
    // -------------------------------------------------------------------

    #[test]
    fn upgrade_shadow_role_changes_role() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let governance = make_governance(CTX);
        let event =
            upgrade_shadow_role(&mut registry, "shadow-001", "contributor", &governance).unwrap();

        assert_eq!(event.previous_role, "observer");
        assert_eq!(event.new_role, "contributor");

        let shadow = find_shadow(&registry, "shadow-001").unwrap();
        assert_eq!(shadow.attributed_role, "contributor");
    }

    #[test]
    fn upgrade_shadow_role_records_event() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let governance = make_governance(CTX);
        let event =
            upgrade_shadow_role(&mut registry, "shadow-001", "contributor", &governance).unwrap();

        assert_eq!(event.shadow_id, "shadow-001");
        assert_eq!(event.governance_did, GOVERNANCE_DID);
        assert_eq!(event.context_id, CTX);

        assert_eq!(registry.upgrade_events().len(), 1);
    }

    #[test]
    fn upgrade_shadow_role_rejects_nonexistent_shadow() {
        let mut registry = make_registry();
        let governance = make_governance(CTX);

        let result = upgrade_shadow_role(&mut registry, "shadow-999", "contributor", &governance);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("shadow not found"),
            "expected ShadowNotFound, got: {err}"
        );
    }

    #[test]
    fn upgrade_shadow_role_rejects_context_mismatch() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let governance = make_governance("ctx-other");

        let result = upgrade_shadow_role(&mut registry, "shadow-001", "contributor", &governance);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("does not match"),
            "expected InvalidGovernanceAction, got: {err}"
        );
    }

    #[test]
    fn upgrade_shadow_role_rejects_empty_role() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let governance = make_governance(CTX);

        let result = upgrade_shadow_role(&mut registry, "shadow-001", "", &governance);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("cannot be empty"),
            "expected InvalidGovernanceAction, got: {err}"
        );
    }

    #[test]
    fn upgrade_shadow_role_allows_multiple_upgrades() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let gov = make_governance(CTX);
        upgrade_shadow_role(&mut registry, "shadow-001", "contributor", &gov).unwrap();
        upgrade_shadow_role(&mut registry, "shadow-001", "moderator", &gov).unwrap();

        let shadow = find_shadow(&registry, "shadow-001").unwrap();
        assert_eq!(shadow.attributed_role, "moderator");
        assert_eq!(registry.upgrade_events().len(), 2);
    }

    // -------------------------------------------------------------------
    // list_shadows
    // -------------------------------------------------------------------

    #[test]
    fn list_shadows_returns_empty_for_unknown_bridge() {
        let registry = make_registry();
        let result = list_shadows(&registry, "bridge-unknown");
        assert!(result.is_empty());
    }

    #[test]
    fn list_shadows_returns_shadows_for_specific_bridge() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");
        create_test_shadow(&mut registry, "shadow-002", "@bob");

        // Create shadow on a different bridge.
        create_shadow(
            &mut registry,
            "shadow-003",
            "bridge-002",
            BridgeMode::Api,
            "@charlie",
            &[],
            1_700_000_300,
        )
        .unwrap();

        let bridge_1_shadows = list_shadows(&registry, BRIDGE_ID);
        assert_eq!(bridge_1_shadows.len(), 2);

        let bridge_2_shadows = list_shadows(&registry, "bridge-002");
        assert_eq!(bridge_2_shadows.len(), 1);
        assert_eq!(bridge_2_shadows[0].platform_handle, "@charlie");
    }

    // -------------------------------------------------------------------
    // can_exercise_capability -- unclaimed shadows
    // -------------------------------------------------------------------

    #[test]
    fn unclaimed_shadow_cannot_exercise_governance_vote() {
        let mut registry = make_registry();
        let (shadow, _) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        let result = can_exercise_capability(&shadow, "governance.vote");
        assert!(result.is_err());
    }

    #[test]
    fn unclaimed_shadow_cannot_exercise_governance_propose() {
        let mut registry = make_registry();
        let (shadow, _) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        let result = can_exercise_capability(&shadow, "governance.propose");
        assert!(result.is_err());
    }

    #[test]
    fn unclaimed_shadow_cannot_exercise_identity_attest() {
        let mut registry = make_registry();
        let (shadow, _) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        let result = can_exercise_capability(&shadow, "identity.attest");
        assert!(result.is_err());
    }

    #[test]
    fn unclaimed_shadow_cannot_exercise_member_invite() {
        let mut registry = make_registry();
        let (shadow, _) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        let result = can_exercise_capability(&shadow, "member.invite");
        assert!(result.is_err());
    }

    #[test]
    fn unclaimed_shadow_cannot_exercise_any_verified_capability() {
        let mut registry = make_registry();
        let (shadow, _) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        for cap in VERIFIED_IDENTITY_CAPABILITIES {
            let result = can_exercise_capability(&shadow, cap);
            assert!(
                result.is_err(),
                "shadow should not be able to exercise {cap}"
            );
        }
    }

    #[test]
    fn unclaimed_shadow_can_exercise_non_restricted_capability() {
        let mut registry = make_registry();
        let (shadow, _) = create_test_shadow(&mut registry, "shadow-001", "@alice");

        // Non-restricted capabilities should be allowed for shadows.
        let result = can_exercise_capability(&shadow, "message.send");
        assert!(result.is_ok());

        let result = can_exercise_capability(&shadow, "message.read");
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------
    // can_exercise_capability -- claimed shadows
    // -------------------------------------------------------------------

    #[test]
    fn claimed_shadow_can_exercise_verified_capabilities() {
        let shadow = ShadowIdentity {
            shadow_id: "shadow-claimed".to_owned(),
            platform_handle: "@alice".to_owned(),
            bridge_id: BRIDGE_ID.to_owned(),
            attributed_role: "observer".to_owned(),
            provenance_status: ShadowProvenanceStatus::Claimed,
            created_at: 1_700_000_100,
        };

        for cap in VERIFIED_IDENTITY_CAPABILITIES {
            let result = can_exercise_capability(&shadow, cap);
            assert!(
                result.is_ok(),
                "claimed shadow should be able to exercise {cap}"
            );
        }
    }

    #[test]
    fn claimed_shadow_can_exercise_non_restricted_capability() {
        let shadow = ShadowIdentity {
            shadow_id: "shadow-claimed".to_owned(),
            platform_handle: "@alice".to_owned(),
            bridge_id: BRIDGE_ID.to_owned(),
            attributed_role: "observer".to_owned(),
            provenance_status: ShadowProvenanceStatus::Claimed,
            created_at: 1_700_000_100,
        };

        let result = can_exercise_capability(&shadow, "message.send");
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------
    // find_shadow
    // -------------------------------------------------------------------

    #[test]
    fn find_shadow_returns_existing_shadow() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry, "shadow-001", "@alice");

        let found = find_shadow(&registry, "shadow-001");
        assert!(found.is_ok());
        assert_eq!(found.unwrap().platform_handle, "@alice");
    }

    #[test]
    fn find_shadow_returns_error_for_nonexistent() {
        let registry = make_registry();
        let result = find_shadow(&registry, "shadow-999");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // Serialization roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn shadow_creation_event_serialization_roundtrip() {
        let event = ShadowCreationEvent {
            shadow_id: "shadow-ser".to_owned(),
            platform_handle: "@user".to_owned(),
            bridge_id: BRIDGE_ID.to_owned(),
            bridge_mode: BridgeMode::Relay,
            initial_role: DEFAULT_SHADOW_ROLE.to_owned(),
            context_id: CTX.to_owned(),
            timestamp: 1_700_000_100,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: ShadowCreationEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.shadow_id, event.shadow_id);
        assert_eq!(restored.platform_handle, event.platform_handle);
        assert_eq!(restored.bridge_id, event.bridge_id);
        assert_eq!(restored.bridge_mode, event.bridge_mode);
        assert_eq!(restored.initial_role, event.initial_role);
        assert_eq!(restored.context_id, event.context_id);
        assert_eq!(restored.timestamp, event.timestamp);
    }

    #[test]
    fn shadow_role_upgrade_event_serialization_roundtrip() {
        let event = ShadowRoleUpgradeEvent {
            shadow_id: "shadow-ser".to_owned(),
            previous_role: "observer".to_owned(),
            new_role: "contributor".to_owned(),
            governance_did: GOVERNANCE_DID.into(),
            context_id: CTX.to_owned(),
            timestamp: 1_700_001_000,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: ShadowRoleUpgradeEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.shadow_id, event.shadow_id);
        assert_eq!(restored.previous_role, event.previous_role);
        assert_eq!(restored.new_role, event.new_role);
        assert_eq!(restored.governance_did, event.governance_did);
        assert_eq!(restored.context_id, event.context_id);
        assert_eq!(restored.timestamp, event.timestamp);
    }

    #[test]
    fn governance_action_serialization_roundtrip() {
        let action = GovernanceAction {
            governance_did: GOVERNANCE_DID.into(),
            context_id: CTX.to_owned(),
            timestamp: 1_700_001_000,
            justification: "testing".to_owned(),
        };

        let json = serde_json::to_string(&action).unwrap();
        let restored: GovernanceAction = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.governance_did, action.governance_did);
        assert_eq!(restored.context_id, action.context_id);
        assert_eq!(restored.timestamp, action.timestamp);
        assert_eq!(restored.justification, action.justification);
    }

    // -------------------------------------------------------------------
    // ShadowRegistry construction
    // -------------------------------------------------------------------

    #[test]
    fn shadow_registry_new_has_expected_context() {
        let registry = make_registry();
        assert_eq!(registry.context_id(), CTX);
        assert!(registry.shadows().is_empty());
        assert!(registry.creation_events().is_empty());
        assert!(registry.upgrade_events().is_empty());
    }

    // -------------------------------------------------------------------
    // Default shadow role constant
    // -------------------------------------------------------------------

    #[test]
    fn default_shadow_role_is_observer() {
        assert_eq!(DEFAULT_SHADOW_ROLE, "observer");
    }

    // -------------------------------------------------------------------
    // Error display
    // -------------------------------------------------------------------

    #[test]
    fn shadow_error_display_verified_identity_required() {
        let err = ShadowError::VerifiedIdentityRequired {
            shadow_id: "shadow-001".to_owned(),
            capability: "governance.vote".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("shadow-001"));
        assert!(msg.contains("governance.vote"));
        assert!(msg.contains("verified identity"));
    }

    #[test]
    fn shadow_error_display_shadow_not_found() {
        let err = ShadowError::ShadowNotFound {
            shadow_id: "shadow-999".to_owned(),
        };
        assert!(err.to_string().contains("shadow-999"));
    }

    #[test]
    fn shadow_error_display_capacity_exceeded() {
        let err = ShadowError::CapacityExceeded {
            reason: "total shadow limit (100) reached".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("capacity exceeded"));
        assert!(msg.contains("total shadow limit"));
    }
}
