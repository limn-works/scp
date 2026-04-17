//! Context nesting: parent-child relationships for SCP contexts (spec section 5.13).
//!
//! A child context is a full context -- its own MLS group, event log, governance,
//! roles, tools, ceiling, and membership -- that is structurally and
//! cryptographically linked to one or more parent contexts. The parent
//! relationship constrains the child:
//!
//! - **Ceiling inheritance (section 5.13.1):** A child's capability ceiling must be a
//!   subset of the intersection of all parent ceilings.
//! - **Membership eligibility (section 5.13.2):** Members must belong to at least one
//!   parent. Eligibility is continuous -- losing your last parent means eviction.
//! - **Lifecycle coupling (section 5.13.5):** Children cannot outlive all parents.
//!   Parent closure cascades per the `on_sever` policy.
//! - **Parent governance config (section 5.13.4):** Configurable per-parent authority
//!   over the child (close, evict, restrict ceiling, approval requirements).
//! - **MLS `group_context` extension (section 5.13.3):** Parent context IDs and
//!   governance config content hash are bound into the child's MLS group identity.
//!
//! # Nesting purposes
//!
//! - **Single-parent child** -- a sub-space within a context (per-task rooms,
//!   per-topic channels).
//! - **Multi-parent child** -- a governed bridge between contexts for symmetric
//!   cross-context collaboration.
//!
//! See ADR-008 in `.docs/adrs/phase-2.md` and spec section 5.13 for full details.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::roles::{Capability, CapabilityCeiling};
use scp_primitives::DID;

/// Context identifier (string alias used throughout the context module).
pub type ContextId = String;

// After ADR-043, nesting depth has no protocol ceiling. It is context-
// configurable via `ContextParams::max_nesting_depth`. When `None`,
// nesting is unbounded (no depth limit). When `Some(n)`, depth is
// enforced at creation time. The old `MAX_NESTING_DEPTH = 3` constant
// has been removed.

// ---------------------------------------------------------------------------
// OnSeverPolicy
// ---------------------------------------------------------------------------

/// Action to take when a parent context severs its relationship with the child.
///
/// Configured per-parent at child creation time. Immutable after creation.
/// See spec section 5.13.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OnSeverPolicy {
    /// Evict members who are eligible only through the severed parent.
    /// Members with eligibility through other parents are unaffected.
    EvictUniqueMembers,
    /// Close the child context entirely when this parent severs.
    CascadeClose,
    /// Child continues with all current members. Members who were eligible
    /// only through the severed parent keep their seat -- a deliberate
    /// governance choice to prioritize continuity over strict eligibility.
    PreserveMembership,
}

// ---------------------------------------------------------------------------
// ApprovalRequirement
// ---------------------------------------------------------------------------

/// Child operations that may require a parent's governance approval.
///
/// Used in [`ParentGovernanceConfig::requires_approval_for`].
/// See spec section 5.13.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ApprovalRequirement {
    /// Changes to the child's governance model.
    GovernanceChange,
    /// New tools registered in the child.
    ToolRegistration,
    /// Modifications to the child's capability ceiling (only applicable
    /// if the child has `Governed` ceiling policy).
    CeilingChange,
    /// Members added to or removed from the child.
    MembershipChange,
}

// ---------------------------------------------------------------------------
// ParentGovernanceConfig
// ---------------------------------------------------------------------------

/// Governance relationship between a single parent and the child context.
///
/// Configured at child creation time with mutual consent from all parents.
/// Immutable after creation -- changing it requires creating a new child.
/// See spec section 5.13.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentGovernanceConfig {
    /// Can this parent unilaterally close the child?
    pub can_close_child: bool,
    /// Can this parent evict members from the child?
    pub can_evict_members: bool,
    /// Can this parent further restrict the child's ceiling?
    pub can_restrict_ceiling: bool,
    /// Child operations that require this parent's governance approval.
    pub requires_approval_for: BTreeSet<ApprovalRequirement>,
    /// Action to take when this parent severs (closes or disconnects).
    pub on_sever: OnSeverPolicy,
}

impl ParentGovernanceConfig {
    /// Returns the canonical content hash of this governance configuration.
    ///
    /// Used in the MLS `group_context` extension to make the governance config
    /// tamper-evident. Any discrepancy between the claimed config and the
    /// cryptographically committed hash is detectable.
    /// # Errors
    ///
    /// Returns [`NestingError::SerializationFailed`] if the governance
    /// configuration cannot be serialized to JSON.
    pub fn content_hash(&self) -> Result<[u8; 32], NestingError> {
        // RFC 8785 JCS canonical serialization for cross-implementation
        // deterministic hashing.
        let json = crate::jcs::to_string(self).map_err(NestingError::SerializationFailed)?;
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// ParentRef
// ---------------------------------------------------------------------------

/// Reference to a parent context within a nesting relationship.
///
/// Holds the parent's context ID, its capability ceiling, and the governance
/// config that defines what authority the parent has over the child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentRef {
    /// The parent context's identifier.
    pub context_id: ContextId,
    /// The parent's capability ceiling at the time the child was created.
    pub ceiling: CapabilityCeiling,
    /// The governance config for this parent's relationship with the child.
    pub governance_config: ParentGovernanceConfig,
    /// Members of this parent context (tracked for eligibility enforcement).
    pub members: HashSet<DID>,
}

// ---------------------------------------------------------------------------
// NestingError
// ---------------------------------------------------------------------------

/// Errors produced by context nesting operations.
#[derive(Debug, thiserror::Error)]
pub enum NestingError {
    /// The child's ceiling contains capabilities not in the intersection of
    /// all parent ceilings.
    #[error(
        "child ceiling is not a subset of parent ceiling intersection: {0:?} not in intersection"
    )]
    CeilingNotSubset(Vec<Capability>),

    /// No parents were provided for child context creation.
    #[error("at least one parent context is required")]
    NoParents,

    /// The creator does not have `ChildContextCreate` capability in any
    /// parent context.
    #[error("creator {creator} does not have ChildContextCreate capability in any parent")]
    CreatorLacksCapability {
        /// The DID of the creator.
        creator: DID,
    },

    /// A member is not eligible for the child context because they are not
    /// in any parent context.
    #[error("member {member} is not in any parent context")]
    MemberNotEligible {
        /// The DID of the ineligible member.
        member: DID,
    },

    /// A parent governance approval is missing.
    #[error("governance approval missing from parent {parent_id}")]
    ApprovalMissing {
        /// The context ID of the parent that has not approved.
        parent_id: ContextId,
    },

    /// The child's TTL exceeds the minimum parent TTL.
    #[error("child TTL ({child_ttl:?}) exceeds minimum parent TTL ({min_parent_ttl:?})")]
    TtlExceedsParent {
        /// The child's requested TTL.
        child_ttl: std::time::Duration,
        /// The minimum TTL among parents that have TTLs.
        min_parent_ttl: std::time::Duration,
    },

    /// Nesting depth would exceed the context-configured maximum.
    #[error("nesting depth {depth} exceeds maximum {max}")]
    DepthExceeded {
        /// The depth that would result.
        depth: u32,
        /// The context-configured maximum nesting depth.
        max: u32,
    },

    /// A parent context is not in Active state.
    #[error("parent context {parent_id} is not in Active state")]
    ParentNotActive {
        /// The context ID of the non-active parent.
        parent_id: ContextId,
    },

    /// The child context has already been closed.
    #[error("child context is already closed")]
    ChildAlreadyClosed,

    /// Serialization failed during content hashing.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// A child context with no TTL cannot be created under parents with finite TTLs.
    #[error("child has no TTL (infinite) but at least one parent has a finite TTL")]
    ChildOutlivesParent,
}

// ---------------------------------------------------------------------------
// SeverAction
// ---------------------------------------------------------------------------

/// Result of processing a parent sever event.
///
/// Returned by [`ContextNesting::sever_parent`] to indicate what action the
/// caller should take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeverAction {
    /// Evict the listed members (they were eligible only through the severed
    /// parent).
    EvictMembers(Vec<DID>),
    /// Close the child context entirely.
    CloseChild,
    /// No member changes needed. The child continues as-is.
    NoAction,
    /// The child is orphaned (last parent severed). Child must close regardless
    /// of `on_sever` policy.
    Orphaned,
}

// ---------------------------------------------------------------------------
// MlsGroupContextExtension
// ---------------------------------------------------------------------------

/// Data for the MLS `group_context` extensions field that binds parent lineage
/// into the child's cryptographic group identity.
///
/// Includes parent context IDs and the content hash of each parent's governance
/// config. This makes lineage unforgeable -- claiming different parents after
/// creation would require a new MLS group with a different `group_id`.
///
/// See spec section 5.13.3 (Cryptographic binding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupContextExtension {
    /// Parent context IDs in deterministic order (sorted).
    pub parent_context_ids: Vec<ContextId>,
    /// Content hash of the combined parent governance configurations.
    /// SHA-256 over the concatenation of individual config hashes (sorted by
    /// parent context ID).
    pub governance_config_hash: [u8; 32],
}

impl MlsGroupContextExtension {
    /// Constructs the extension from parent references.
    ///
    /// Parent IDs are sorted to ensure deterministic ordering. The governance
    /// config hash is computed over the concatenation of individual config
    /// content hashes (sorted by parent context ID).
    /// # Errors
    ///
    /// Returns [`NestingError::SerializationFailed`] if any parent's governance
    /// configuration cannot be serialized.
    pub fn from_parents(parents: &[ParentRef]) -> Result<Self, NestingError> {
        let mut sorted_parents: Vec<&ParentRef> = parents.iter().collect();
        sorted_parents.sort_by(|a, b| a.context_id.cmp(&b.context_id));

        let parent_context_ids: Vec<ContextId> = sorted_parents
            .iter()
            .map(|p| p.context_id.clone())
            .collect();

        // Hash concatenation of individual governance config hashes.
        let mut hasher = Sha256::new();
        for parent in &sorted_parents {
            hasher.update(parent.governance_config.content_hash()?);
        }
        let result = hasher.finalize();
        let mut governance_config_hash = [0u8; 32];
        governance_config_hash.copy_from_slice(&result);

        Ok(Self {
            parent_context_ids,
            governance_config_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// ContextNesting
// ---------------------------------------------------------------------------

/// Manages the parent-child relationships for a child context.
///
/// Tracks parent references, enforces ceiling intersection, validates
/// membership eligibility, and handles lifecycle coupling when parents sever.
///
/// Created during child context creation and persisted with the child context
/// state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextNesting {
    /// The child context's identifier.
    child_context_id: ContextId,
    /// Parent context references, keyed by parent context ID.
    parents: HashMap<ContextId, ParentRef>,
    /// The validated child ceiling (subset of parent ceiling intersection).
    child_ceiling: CapabilityCeiling,
    /// Current members of the child context (tracked for eligibility).
    child_members: HashSet<DID>,
    /// The nesting depth of this child (1 = direct child of root context).
    depth: u32,
    /// Whether the child context has been closed.
    closed: bool,
}

impl ContextNesting {
    /// Validates and creates a new context nesting relationship.
    ///
    /// # Validation
    ///
    /// 1. At least one parent must be provided.
    /// 2. Nesting depth must not exceed the context-configured limit (if any).
    /// 3. The child ceiling must be a subset of the intersection of all parent
    ///    ceilings.
    /// 4. The creator must have `ChildContextCreate` capability in at least one
    ///    parent's ceiling.
    /// 5. All governance approvals must be present.
    ///
    /// # Errors
    ///
    /// Returns [`NestingError`] if any validation fails.
    pub fn new(
        child_context_id: ContextId,
        parents: Vec<ParentRef>,
        child_ceiling: CapabilityCeiling,
        creator: &DID,
        governance_approvals: &HashSet<ContextId>,
        depth: u32,
        max_nesting_depth: Option<u32>,
    ) -> Result<Self, NestingError> {
        // 1. At least one parent.
        if parents.is_empty() {
            return Err(NestingError::NoParents);
        }

        // 2. Nesting depth check (only if context-configured limit is set).
        if let Some(max) = max_nesting_depth
            && depth > max
        {
            return Err(NestingError::DepthExceeded { depth, max });
        }

        // 3. Ceiling intersection validation.
        let intersection = compute_ceiling_intersection(&parents);
        let violating: Vec<Capability> = child_ceiling
            .capabilities
            .iter()
            .filter(|cap| !intersection.contains(cap))
            .cloned()
            .collect();
        if !violating.is_empty() {
            return Err(NestingError::CeilingNotSubset(violating));
        }

        // 4. Creator must have ChildContextCreate in at least one parent.
        let creator_has_capability = parents.iter().any(|p| {
            p.ceiling.contains(&Capability::ChildContextCreate) && p.members.contains(creator)
        });
        if !creator_has_capability {
            return Err(NestingError::CreatorLacksCapability {
                creator: creator.clone(),
            });
        }

        // 5. All parents must have governance approval.
        for parent in &parents {
            if !governance_approvals.contains(&parent.context_id) {
                return Err(NestingError::ApprovalMissing {
                    parent_id: parent.context_id.clone(),
                });
            }
        }

        let parent_map: HashMap<ContextId, ParentRef> = parents
            .into_iter()
            .map(|p| (p.context_id.clone(), p))
            .collect();

        Ok(Self {
            child_context_id,
            parents: parent_map,
            child_ceiling,
            child_members: HashSet::new(),
            depth,
            closed: false,
        })
    }

    /// Returns the child context's identifier.
    #[must_use]
    pub fn child_context_id(&self) -> &str {
        &self.child_context_id
    }

    /// Returns the nesting depth.
    #[must_use]
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Returns the parent context IDs.
    #[must_use]
    pub fn parent_ids(&self) -> Vec<&ContextId> {
        self.parents.keys().collect()
    }

    /// Returns the number of active parents.
    #[must_use]
    pub fn parent_count(&self) -> usize {
        self.parents.len()
    }

    /// Returns the child ceiling.
    #[must_use]
    pub const fn child_ceiling(&self) -> &CapabilityCeiling {
        &self.child_ceiling
    }

    /// Returns the current child members.
    #[must_use]
    pub const fn child_members(&self) -> &HashSet<DID> {
        &self.child_members
    }

    /// Returns whether the child context is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns the parent governance config for a given parent, if it exists.
    #[must_use]
    pub fn parent_governance_config(&self, parent_id: &str) -> Option<&ParentGovernanceConfig> {
        self.parents.get(parent_id).map(|p| &p.governance_config)
    }

    /// Checks whether a member is eligible to join the child context.
    ///
    /// A member is eligible if they are a member of at least one parent.
    /// See spec section 5.13.2.
    #[must_use]
    pub fn is_eligible(&self, member: &DID) -> bool {
        self.parents.values().any(|p| p.members.contains(member))
    }

    /// Adds a member to the child context after validating eligibility.
    ///
    /// # Errors
    ///
    /// Returns [`NestingError::MemberNotEligible`] if the member is not in any
    /// parent context. Returns [`NestingError::ChildAlreadyClosed`] if the
    /// child is closed.
    pub fn add_member(&mut self, member: &DID) -> Result<(), NestingError> {
        if self.closed {
            return Err(NestingError::ChildAlreadyClosed);
        }
        if !self.is_eligible(member) {
            return Err(NestingError::MemberNotEligible {
                member: member.clone(),
            });
        }
        self.child_members.insert(member.clone());
        Ok(())
    }

    /// Removes a member from the child context.
    pub fn remove_member(&mut self, member: &DID) {
        self.child_members.remove(member);
    }

    /// Checks continuous eligibility for all current child members.
    ///
    /// Returns the list of members who have lost eligibility (no longer in any
    /// parent). These members should be evicted from the child context.
    ///
    /// Eligibility is continuous, not one-time (spec section 5.13.2).
    #[must_use]
    pub fn check_eligibility(&self) -> Vec<DID> {
        self.child_members
            .iter()
            .filter(|m| !self.is_eligible(m))
            .cloned()
            .collect()
    }

    /// Updates a parent's member list and returns any child members who lost
    /// eligibility as a result.
    ///
    /// Call this when a member is removed from a parent context. The returned
    /// members should be evicted from the child.
    pub fn update_parent_members(
        &mut self,
        parent_id: &str,
        new_members: HashSet<DID>,
    ) -> Vec<DID> {
        if let Some(parent) = self.parents.get_mut(parent_id) {
            parent.members = new_members;
        }
        self.check_eligibility()
    }

    /// Removes a single member from a parent's member list and returns any
    /// child members who lost eligibility.
    ///
    /// Convenience method for the common case of a single member removal.
    pub fn remove_member_from_parent(&mut self, parent_id: &str, member: &DID) -> Vec<DID> {
        if let Some(parent) = self.parents.get_mut(parent_id) {
            parent.members.remove(member);
        }
        self.check_eligibility()
    }

    /// Processes a parent context severance (parent closes or disconnects).
    ///
    /// Executes the `on_sever` policy configured for the severed parent.
    /// If the last parent severs, the child is orphaned and must close
    /// regardless of the `on_sever` policy.
    ///
    /// See spec section 5.13.5.
    pub fn sever_parent(&mut self, parent_id: &str) -> SeverAction {
        let Some(parent) = self.parents.remove(parent_id) else {
            return SeverAction::NoAction;
        };

        // If no parents remain, child is orphaned and must close.
        if self.parents.is_empty() {
            self.closed = true;
            return SeverAction::Orphaned;
        }

        match parent.governance_config.on_sever {
            OnSeverPolicy::CascadeClose => {
                self.closed = true;
                SeverAction::CloseChild
            }
            OnSeverPolicy::EvictUniqueMembers => {
                // Find members who were eligible only through the severed parent.
                let ineligible = self.check_eligibility();
                for m in &ineligible {
                    self.child_members.remove(m);
                }
                SeverAction::EvictMembers(ineligible)
            }
            OnSeverPolicy::PreserveMembership => {
                // Members keep their seat even if they lose their eligibility
                // anchor through this parent.
                SeverAction::NoAction
            }
        }
    }

    /// Constructs the MLS `group_context` extension for this nesting relationship.
    ///
    /// Includes parent context IDs and governance config content hash. This
    /// makes the parent lineage part of the child's cryptographic group
    /// identity.
    /// # Errors
    ///
    /// Returns [`NestingError::SerializationFailed`] if governance config
    /// serialization fails.
    pub fn mls_group_context_extension(&self) -> Result<MlsGroupContextExtension, NestingError> {
        let refs: Vec<ParentRef> = self.parents.values().cloned().collect();
        MlsGroupContextExtension::from_parents(&refs)
    }

    /// Marks the child context as closed.
    pub const fn close(&mut self) {
        self.closed = true;
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Computes the ceiling intersection of all parent ceilings.
///
/// Returns a `CapabilityCeiling` containing only capabilities present in
/// every parent's ceiling. See spec section 5.13.1.
#[must_use]
pub fn compute_ceiling_intersection(parents: &[ParentRef]) -> CapabilityCeiling {
    if parents.is_empty() {
        return CapabilityCeiling::new(std::iter::empty::<Capability>());
    }

    let mut intersection: HashSet<Capability> = parents[0].ceiling.capabilities.clone();
    for parent in &parents[1..] {
        intersection = intersection
            .intersection(&parent.ceiling.capabilities)
            .cloned()
            .collect();
    }

    CapabilityCeiling::new(intersection)
}

/// Validates that a child TTL does not exceed the minimum parent TTL.
///
/// If no parent has a TTL, the child's TTL is unconstrained. If any parent
/// has a TTL, the child's TTL must not exceed the minimum among them.
///
/// See spec section 5.13.5.
///
/// # Errors
///
/// Returns [`NestingError::TtlExceedsParent`] if the child's TTL exceeds
/// the minimum parent TTL.
pub fn validate_child_ttl(
    child_ttl: Option<std::time::Duration>,
    parent_ttls: &[Option<std::time::Duration>],
) -> Result<(), NestingError> {
    let Some(child_ttl) = child_ttl else {
        // Child has no TTL (infinite). Check that no parent has a finite TTL,
        // since a child must not outlive its parents.
        if parent_ttls.iter().any(std::option::Option::is_some) {
            return Err(NestingError::ChildOutlivesParent);
        }
        return Ok(());
    };

    // Find the minimum TTL among parents that have TTLs.
    let min_parent_ttl = parent_ttls.iter().filter_map(|t| t.as_ref()).min().copied();

    if let Some(min_ttl) = min_parent_ttl
        && child_ttl > min_ttl
    {
        return Err(NestingError::TtlExceedsParent {
            child_ttl,
            min_parent_ttl: min_ttl,
        });
    }

    Ok(())
}

/// Validates that the proposed nesting depth does not exceed the context-
/// configured maximum.
///
/// When `max_nesting_depth` is `None`, no validation is performed (unbounded).
/// When `Some(n)`, rejects depths exceeding `n`.
///
/// # Errors
///
/// Returns [`NestingError::DepthExceeded`] if the depth exceeds the limit.
pub const fn validate_nesting_depth(
    depth: u32,
    max_nesting_depth: Option<u32>,
) -> Result<(), NestingError> {
    match max_nesting_depth {
        Some(max) if depth > max => Err(NestingError::DepthExceeded { depth, max }),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::needless_collect,
    clippy::significant_drop_tightening,
    clippy::match_same_arms,
    clippy::cloned_ref_to_slice_refs,
    clippy::iter_on_single_items,
    clippy::manual_let_else
)]
mod tests {
    use super::*;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn did(name: &str) -> DID {
        DID::from(format!("did:dht:z6Mk{name}"))
    }

    fn make_ceiling(caps: &[Capability]) -> CapabilityCeiling {
        CapabilityCeiling::new(caps.iter().cloned())
    }

    fn make_parent(
        id: &str,
        caps: &[Capability],
        members: &[DID],
        on_sever: OnSeverPolicy,
    ) -> ParentRef {
        ParentRef {
            context_id: id.to_owned(),
            ceiling: make_ceiling(caps),
            governance_config: ParentGovernanceConfig {
                can_close_child: false,
                can_evict_members: false,
                can_restrict_ceiling: false,
                requires_approval_for: BTreeSet::new(),
                on_sever,
            },
            members: members.iter().cloned().collect(),
        }
    }

    fn approvals(ids: &[&str]) -> HashSet<ContextId> {
        ids.iter().map(std::string::ToString::to_string).collect()
    }

    // -----------------------------------------------------------------------
    // Ceiling intersection validation
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_intersection_single_parent() {
        let caps = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let parent = make_parent("A", &caps, &[], OnSeverPolicy::EvictUniqueMembers);
        let intersection = compute_ceiling_intersection(&[parent]);
        assert!(intersection.contains(&Capability::MessagesRead));
        assert!(intersection.contains(&Capability::MessagesWrite));
        assert!(!intersection.contains(&Capability::ToolInvokeAll));
    }

    #[test]
    fn ceiling_intersection_two_parents() {
        let parent_a = make_parent(
            "A",
            &[
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::ToolInvokeAll,
            ],
            &[],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::MessagesWrite],
            &[],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let intersection = compute_ceiling_intersection(&[parent_a, parent_b]);
        assert!(intersection.contains(&Capability::MessagesRead));
        assert!(intersection.contains(&Capability::MessagesWrite));
        assert!(
            !intersection.contains(&Capability::ToolInvokeAll),
            "ToolInvokeAll is only in parent A, not in intersection"
        );
    }

    #[test]
    fn child_ceiling_must_be_subset_of_intersection() {
        let alice = did("Alice");
        let parent_a = make_parent(
            "A",
            &[
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::ChildContextCreate,
            ],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        // Child ceiling includes MessagesWrite which is not in B.
        let child_ceiling = make_ceiling(&[Capability::MessagesRead, Capability::MessagesWrite]);
        let result = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a.clone(), parent_b.clone()],
            child_ceiling,
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NestingError::CeilingNotSubset(violating) => {
                assert!(violating.contains(&Capability::MessagesWrite));
            }
            other => panic!("expected CeilingNotSubset, got: {other:?}"),
        }

        // Valid child ceiling (subset of intersection).
        let valid_ceiling = make_ceiling(&[Capability::MessagesRead]);
        let result = ContextNesting::new(
            "child-2".to_owned(),
            vec![parent_a, parent_b],
            valid_ceiling,
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn child_ceiling_equal_to_intersection_is_valid() {
        let alice = did("Alice");
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ChildContextCreate,
        ];
        let parent = make_parent("A", &caps, &[alice.clone()], OnSeverPolicy::CascadeClose);
        let child_ceiling = make_ceiling(&[
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ChildContextCreate,
        ]);

        let result = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent],
            child_ceiling,
            &alice,
            &approvals(&["A"]),
            1,
            None,
        );
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Lifecycle coupling -- child closes when parent closes
    // -----------------------------------------------------------------------

    #[test]
    fn parent_sever_cascade_close() {
        let alice = did("Alice");
        let parent = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::CascadeClose,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent, parent_b],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        )
        .unwrap();

        nesting.add_member(&alice).unwrap();

        // Sever parent A (cascade close policy).
        let action = nesting.sever_parent("A");
        assert_eq!(action, SeverAction::CloseChild);
        assert!(nesting.is_closed());
    }

    #[test]
    fn last_parent_sever_orphans_child() {
        let alice = did("Alice");
        let parent = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::PreserveMembership,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        )
        .unwrap();

        nesting.add_member(&alice).unwrap();

        // Sever the only parent -- child is orphaned regardless of policy.
        let action = nesting.sever_parent("A");
        assert_eq!(action, SeverAction::Orphaned);
        assert!(nesting.is_closed());
    }

    #[test]
    fn parent_sever_evict_unique_members() {
        let alice = did("Alice");
        let bob = did("Bob");
        let carol = did("Carol");

        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone(), carol.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[bob.clone(), carol.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a, parent_b],
            make_ceiling(&[Capability::MessagesRead]),
            &carol,
            &approvals(&["A", "B"]),
            1,
            None,
        )
        .unwrap();

        nesting.add_member(&alice).unwrap();
        nesting.add_member(&bob).unwrap();
        nesting.add_member(&carol).unwrap();

        // Sever parent A -- Alice is unique to A, so she gets evicted.
        // Carol is in both parents, so she stays.
        let action = nesting.sever_parent("A");
        match action {
            SeverAction::EvictMembers(evicted) => {
                assert!(evicted.contains(&alice), "Alice should be evicted");
                assert!(!evicted.contains(&carol), "Carol should not be evicted");
                assert!(!evicted.contains(&bob), "Bob should not be evicted");
            }
            other => panic!("expected EvictMembers, got: {other:?}"),
        }
        assert!(!nesting.is_closed());
        assert!(!nesting.child_members().contains(&alice));
        assert!(nesting.child_members().contains(&bob));
        assert!(nesting.child_members().contains(&carol));
    }

    #[test]
    fn parent_sever_preserve_membership() {
        let alice = did("Alice");
        let bob = did("Bob");

        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::PreserveMembership,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[bob.clone()],
            OnSeverPolicy::PreserveMembership,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a, parent_b],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        )
        .unwrap();

        nesting.add_member(&alice).unwrap();
        nesting.add_member(&bob).unwrap();

        // Sever parent A -- preserve membership policy keeps everyone.
        let action = nesting.sever_parent("A");
        assert_eq!(action, SeverAction::NoAction);
        assert!(!nesting.is_closed());
        assert!(nesting.child_members().contains(&alice));
        assert!(nesting.child_members().contains(&bob));
    }

    // -----------------------------------------------------------------------
    // Eligibility -- member loses access when removed from all parents
    // -----------------------------------------------------------------------

    #[test]
    fn member_loses_eligibility_when_removed_from_all_parents() {
        let alice = did("Alice");
        let bob = did("Bob");

        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone(), bob.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a, parent_b],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        )
        .unwrap();

        nesting.add_member(&alice).unwrap();
        nesting.add_member(&bob).unwrap();

        // Bob is only in parent A. Remove Bob from parent A.
        let ineligible = nesting.remove_member_from_parent("A", &bob);
        assert!(ineligible.contains(&bob), "Bob should lose eligibility");
        assert!(
            !ineligible.contains(&alice),
            "Alice is still in both parents"
        );
    }

    #[test]
    fn member_retains_eligibility_through_remaining_parent() {
        let alice = did("Alice");

        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a, parent_b],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        )
        .unwrap();

        nesting.add_member(&alice).unwrap();

        // Remove Alice from parent A, but she's still in parent B.
        let ineligible = nesting.remove_member_from_parent("A", &alice);
        assert!(
            ineligible.is_empty(),
            "Alice should retain eligibility through B"
        );
    }

    #[test]
    fn ineligible_member_cannot_join() {
        let alice = did("Alice");
        let frank = did("Frank");

        let parent = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        )
        .unwrap();

        // Frank is not in any parent.
        let result = nesting.add_member(&frank);
        assert!(result.is_err());
        match result.unwrap_err() {
            NestingError::MemberNotEligible { member } => {
                assert_eq!(member, frank);
            }
            other => panic!("expected MemberNotEligible, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Multi-parent approval flow
    // -----------------------------------------------------------------------

    #[test]
    fn multi_parent_requires_all_approvals() {
        let alice = did("Alice");

        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        // Only A has approved.
        let result = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a.clone(), parent_b.clone()],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NestingError::ApprovalMissing { parent_id } => {
                assert_eq!(parent_id, "B");
            }
            other => panic!("expected ApprovalMissing, got: {other:?}"),
        }

        // Both approved.
        let result = ContextNesting::new(
            "child-2".to_owned(),
            vec![parent_a, parent_b],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn creator_needs_capability_in_at_least_one_parent() {
        let alice = did("Alice");

        // Parent without ChildContextCreate in ceiling.
        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let result = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NestingError::CreatorLacksCapability { creator } => {
                assert_eq!(creator, alice);
            }
            other => panic!("expected CreatorLacksCapability, got: {other:?}"),
        }
    }

    #[test]
    fn creator_needs_membership_in_parent_with_capability() {
        let alice = did("Alice");
        let bob = did("Bob");

        // Parent A has ChildContextCreate but Alice is not a member.
        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[bob],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let result = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NestingError::CreatorLacksCapability { creator } => {
                assert_eq!(creator, alice);
            }
            other => panic!("expected CreatorLacksCapability, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // TTL validation
    // -----------------------------------------------------------------------

    #[test]
    fn child_ttl_must_not_exceed_min_parent_ttl() {
        let result = validate_child_ttl(
            Some(Duration::from_hours(2)),
            &[Some(Duration::from_hours(1))],
        );
        assert!(result.is_err());

        let result = validate_child_ttl(
            Some(Duration::from_hours(1)),
            &[Some(Duration::from_hours(1))],
        );
        assert!(result.is_ok());

        let result = validate_child_ttl(
            Some(Duration::from_mins(30)),
            &[Some(Duration::from_hours(1))],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn child_ttl_unconstrained_when_no_parent_has_ttl() {
        let result = validate_child_ttl(Some(Duration::from_secs(999_999)), &[None, None]);
        assert!(result.is_ok());
    }

    #[test]
    fn child_ttl_bounded_by_min_across_multiple_parents() {
        // Parent A: 1 hour, Parent B: 2 hours, Parent C: no TTL.
        let result = validate_child_ttl(
            Some(Duration::from_mins(90)), // 90 min
            &[
                Some(Duration::from_hours(1)),
                Some(Duration::from_hours(2)),
                None,
            ],
        );
        assert!(result.is_err());

        let result = validate_child_ttl(
            Some(Duration::from_hours(1)),
            &[
                Some(Duration::from_hours(1)),
                Some(Duration::from_hours(2)),
                None,
            ],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn no_child_ttl_rejected_when_parent_has_finite_ttl() {
        let result = validate_child_ttl(None, &[Some(Duration::from_hours(1))]);
        assert!(result.is_err());
    }

    #[test]
    fn no_child_ttl_allowed_when_no_parent_has_ttl() {
        let result = validate_child_ttl(None, &[None, None]);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Nesting depth
    // -----------------------------------------------------------------------

    #[test]
    fn nesting_depth_unbounded_when_none() {
        // No context-configured limit — any depth is valid.
        assert!(validate_nesting_depth(0, None).is_ok());
        assert!(validate_nesting_depth(100, None).is_ok());
        assert!(validate_nesting_depth(u32::MAX, None).is_ok());
    }

    #[test]
    fn nesting_depth_at_configured_max_is_allowed() {
        assert!(validate_nesting_depth(10, Some(10)).is_ok());
    }

    #[test]
    fn nesting_depth_exceeds_configured_max_is_rejected() {
        let result = validate_nesting_depth(11, Some(10));
        assert!(result.is_err());
        match result.unwrap_err() {
            NestingError::DepthExceeded { depth, max } => {
                assert_eq!(depth, 11);
                assert_eq!(max, 10);
            }
            other => panic!("expected DepthExceeded, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // MLS group_context extension
    // -----------------------------------------------------------------------

    #[test]
    fn mls_extension_includes_parent_ids_sorted() {
        let alice = did("Alice");
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_b, parent_a],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        )
        .unwrap();

        let ext = nesting.mls_group_context_extension().unwrap();
        assert_eq!(ext.parent_context_ids, vec!["A", "B"]);
    }

    #[test]
    fn mls_extension_governance_hash_is_deterministic() {
        let alice = did("Alice");
        let parent = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent.clone()],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        )
        .unwrap();

        let ext1 = nesting.mls_group_context_extension().unwrap();

        // Create another identical nesting to verify hash determinism.
        let nesting2 = ContextNesting::new(
            "child-2".to_owned(),
            vec![parent],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        )
        .unwrap();

        let ext2 = nesting2.mls_group_context_extension().unwrap();
        assert_eq!(ext1.governance_config_hash, ext2.governance_config_hash);
    }

    #[test]
    fn mls_extension_different_config_produces_different_hash() {
        let alice = did("Alice");

        let parent_a = ParentRef {
            context_id: "A".to_owned(),
            ceiling: make_ceiling(&[Capability::MessagesRead, Capability::ChildContextCreate]),
            governance_config: ParentGovernanceConfig {
                can_close_child: true,
                can_evict_members: false,
                can_restrict_ceiling: false,
                requires_approval_for: BTreeSet::new(),
                on_sever: OnSeverPolicy::CascadeClose,
            },
            members: [alice.clone()].into_iter().collect(),
        };

        let parent_a_different = ParentRef {
            context_id: "A".to_owned(),
            ceiling: make_ceiling(&[Capability::MessagesRead, Capability::ChildContextCreate]),
            governance_config: ParentGovernanceConfig {
                can_close_child: false,
                can_evict_members: true,
                can_restrict_ceiling: false,
                requires_approval_for: BTreeSet::new(),
                on_sever: OnSeverPolicy::EvictUniqueMembers,
            },
            members: [alice].into_iter().collect(),
        };

        let ext1 = MlsGroupContextExtension::from_parents(&[parent_a]).unwrap();
        let ext2 = MlsGroupContextExtension::from_parents(&[parent_a_different]).unwrap();
        assert_ne!(ext1.governance_config_hash, ext2.governance_config_hash);
    }

    // -----------------------------------------------------------------------
    // ParentGovernanceConfig
    // -----------------------------------------------------------------------

    #[test]
    fn parent_governance_config_serde_roundtrip() {
        let config = ParentGovernanceConfig {
            can_close_child: true,
            can_evict_members: false,
            can_restrict_ceiling: true,
            requires_approval_for: [
                ApprovalRequirement::GovernanceChange,
                ApprovalRequirement::ToolRegistration,
            ]
            .into_iter()
            .collect(),
            on_sever: OnSeverPolicy::CascadeClose,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ParentGovernanceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn on_sever_policy_variants_are_distinct() {
        assert_ne!(
            OnSeverPolicy::EvictUniqueMembers,
            OnSeverPolicy::CascadeClose
        );
        assert_ne!(
            OnSeverPolicy::CascadeClose,
            OnSeverPolicy::PreserveMembership
        );
        assert_ne!(
            OnSeverPolicy::EvictUniqueMembers,
            OnSeverPolicy::PreserveMembership
        );
    }

    #[test]
    fn approval_requirement_variants_are_distinct() {
        let variants = [
            ApprovalRequirement::GovernanceChange,
            ApprovalRequirement::ToolRegistration,
            ApprovalRequirement::CeilingChange,
            ApprovalRequirement::MembershipChange,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // No parents error
    // -----------------------------------------------------------------------

    #[test]
    fn creation_with_no_parents_fails() {
        let alice = did("Alice");
        let result = ContextNesting::new(
            "child-1".to_owned(),
            vec![],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &HashSet::new(),
            1,
            None,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NestingError::NoParents));
    }

    // -----------------------------------------------------------------------
    // Closed child rejects new members
    // -----------------------------------------------------------------------

    #[test]
    fn closed_child_rejects_add_member() {
        let alice = did("Alice");
        let parent = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::CascadeClose,
        );

        let mut nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            1,
            None,
        )
        .unwrap();

        nesting.close();
        let result = nesting.add_member(&alice);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NestingError::ChildAlreadyClosed
        ));
    }

    // -----------------------------------------------------------------------
    // Empty ceiling intersection
    // -----------------------------------------------------------------------

    #[test]
    fn empty_ceiling_intersection_rejects_non_empty_child() {
        let alice = did("Alice");
        let parent_a = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );
        let parent_b = make_parent(
            "B",
            &[Capability::MessagesWrite, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        // Intersection is empty (no overlap except ChildContextCreate).
        // Child requests MessagesRead which is not in intersection.
        let result = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent_a, parent_b],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A", "B"]),
            1,
            None,
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    #[test]
    fn accessors_return_correct_values() {
        let alice = did("Alice");
        let parent = make_parent(
            "A",
            &[Capability::MessagesRead, Capability::ChildContextCreate],
            &[alice.clone()],
            OnSeverPolicy::EvictUniqueMembers,
        );

        let nesting = ContextNesting::new(
            "child-1".to_owned(),
            vec![parent],
            make_ceiling(&[Capability::MessagesRead]),
            &alice,
            &approvals(&["A"]),
            2,
            None,
        )
        .unwrap();

        assert_eq!(nesting.child_context_id(), "child-1");
        assert_eq!(nesting.depth(), 2);
        assert_eq!(nesting.parent_count(), 1);
        assert!(!nesting.is_closed());
        assert!(nesting.child_members().is_empty());
        assert!(nesting.parent_governance_config("A").is_some());
        assert!(nesting.parent_governance_config("Z").is_none());
    }
}
