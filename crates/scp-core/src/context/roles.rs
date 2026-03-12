//! Capability ceiling, role definitions, and role assignment for SCP contexts.
//!
//! This module implements the UCAN-based capability model from ADR-009 in
//! `.docs/adrs/phase-2.md`. Every action in a context requires a valid UCAN
//! capability token. The capability ceiling bounds the maximum set of operations
//! possible in a context, and roles define subsets of the ceiling that specific
//! agents can exercise.
//!
//! # Types
//!
//! - [`Capability`] -- Enumeration of all protocol-defined capabilities.
//! - [`CapabilityCeiling`] -- Immutable set of capabilities declared at context
//!   creation.
//! - [`RoleDefinition`] -- Named role mapping to a capability subset.
//! - [`UcanToken`] -- Lightweight UCAN token representation for role-based access control in broadcast contexts.
//! - [`RoleError`] -- Error type for role and capability operations.
//!
//! # Built-in Roles
//!
//! Built-in roles are always available in every context:
//! - `admin` -- all capabilities in the ceiling.
//! - `moderator` -- `MessagesRead`, `MessagesWrite`, `ToolInvokeAll`,
//!   `MemberRemove`, `GovernancePropose` (§5.9 elected moderators).
//! - `member` -- `MessagesRead`, `MessagesWrite`, `ToolInvokeAll`.
//! - `observer` -- `MessagesRead` only.
//!
//! Broadcast-specific roles:
//! - `author` -- `MessagesWrite`, `MessagesRead`, `ToolInvokeAll`.
//! - `subscriber` -- `MessagesRead` only.
//!
//! Custom roles are defined at context creation with arbitrary capability
//! subsets of the ceiling.
//!
//! See ADR-009 in `.docs/adrs/phase-2.md` for the full specification.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::ContextError;
use crate::crypto::ucan::nonce::generate_nonce;

// ---------------------------------------------------------------------------
// ToolId
// ---------------------------------------------------------------------------

/// Identifier for a tool registered within a context.
///
/// This is a simple string type alias. The full `ToolRegistration` type is
/// defined in `params.rs`; this type identifies a specific tool for
/// capability scoping (e.g., `ToolInvoke(tool_id)`).
pub type ToolId = String;

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// A single protocol-defined capability within an SCP context.
///
/// Capabilities define the atomic operations a participant can perform.
/// Every action in a context requires a valid UCAN token scoped to the
/// corresponding capability. Capabilities are mode-agnostic: `MessagesRead`
/// and `MessagesWrite` apply to both Encrypted and Broadcast context modes.
///
/// See ADR-009 acceptance criterion 1 and spec sections 5.3, 5.5, 7.2.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Read messages in the context.
    MessagesRead,
    /// Write (send) messages in the context.
    MessagesWrite,
    /// Invoke a specific registered tool, identified by [`ToolId`].
    ToolInvoke(ToolId),
    /// Invoke any registered tool in the context.
    ToolInvokeAll,
    /// Register new tools in the context.
    ToolRegister,
    /// Invite new members to the context.
    MemberInvite,
    /// Remove members from the context.
    MemberRemove,
    /// Assign roles to members.
    RoleAssign,
    /// Propose governance actions.
    GovernancePropose,
    /// Vote on governance proposals.
    GovernanceVote,
    /// Close the context.
    ContextClose,
    /// Create child contexts with this context as parent (spec section 5.13).
    ChildContextCreate,
    /// Cross-context tool interface exposure (spec section 6.2).
    ToolInterface,
    /// Bridge connector participation (spec section 12).
    Bridging,
    /// Real-time voice communication via delegated media transport (spec section 10.9.1).
    MediaVoice,
    /// Real-time video communication via delegated media transport (spec section 10.9.1).
    MediaVideo,
    /// Screen sharing via delegated media transport (spec section 10.9.1).
    MediaScreenShare,
    /// Ban a member from the context, revoking all access permanently (spec section 5.3).
    /// Gates the `RevokeReadAccess` governance action.
    MemberBan,
    /// Context-specific custom capability.
    Custom(String),
}

impl Capability {
    /// Creates a capability from a string name.
    ///
    /// Recognized names: `"messages:read"`, `"messages:write"`,
    /// `"tool:invoke:*"`, `"tool:register"`, `"member:invite"`,
    /// `"member:remove"`, `"role:assign"`, `"governance:propose"`,
    /// `"governance:vote"`, `"context:close"`, `"context:child:create"`,
    /// `"tool:interface"`, `"bridging"`, `"media:voice"`, `"media:video"`,
    /// `"media:screen_share"`, `"member:ban"`.
    /// Names starting with `"tool:invoke:"` are parsed as `ToolInvoke(id)`.
    /// Anything else maps to `Custom(name)`.
    #[must_use]
    pub fn new(name: impl AsRef<str>) -> Self {
        match name.as_ref() {
            "messages:read" => Self::MessagesRead,
            "messages:write" => Self::MessagesWrite,
            "tool:invoke:*" => Self::ToolInvokeAll,
            "tool:register" => Self::ToolRegister,
            "member:invite" => Self::MemberInvite,
            "member:remove" => Self::MemberRemove,
            "role:assign" => Self::RoleAssign,
            "governance:propose" => Self::GovernancePropose,
            "governance:vote" => Self::GovernanceVote,
            "context:close" => Self::ContextClose,
            "context:child:create" => Self::ChildContextCreate,
            "tool:interface" => Self::ToolInterface,
            "bridging" => Self::Bridging,
            "media:voice" => Self::MediaVoice,
            "media:video" => Self::MediaVideo,
            "media:screen_share" => Self::MediaScreenShare,
            "member:ban" => Self::MemberBan,
            other => other.strip_prefix("tool:invoke:").map_or_else(
                || Self::Custom(other.to_owned()),
                |tool_id| Self::ToolInvoke(tool_id.to_owned()),
            ),
        }
    }

    /// Returns the canonical string name of this capability.
    ///
    /// For [`ToolInvoke`](Self::ToolInvoke) variants, includes the tool ID
    /// (e.g. `"tool:invoke:my_tool"`), matching the `Display` impl.
    #[must_use]
    pub fn name(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::MessagesRead => std::borrow::Cow::Borrowed("messages:read"),
            Self::MessagesWrite => std::borrow::Cow::Borrowed("messages:write"),
            Self::ToolInvoke(id) => std::borrow::Cow::Owned(format!("tool:invoke:{id}")),
            Self::ToolInvokeAll => std::borrow::Cow::Borrowed("tool:invoke:*"),
            Self::ToolRegister => std::borrow::Cow::Borrowed("tool:register"),
            Self::MemberInvite => std::borrow::Cow::Borrowed("member:invite"),
            Self::MemberRemove => std::borrow::Cow::Borrowed("member:remove"),
            Self::RoleAssign => std::borrow::Cow::Borrowed("role:assign"),
            Self::GovernancePropose => std::borrow::Cow::Borrowed("governance:propose"),
            Self::GovernanceVote => std::borrow::Cow::Borrowed("governance:vote"),
            Self::ContextClose => std::borrow::Cow::Borrowed("context:close"),
            Self::ChildContextCreate => std::borrow::Cow::Borrowed("context:child:create"),
            Self::ToolInterface => std::borrow::Cow::Borrowed("tool:interface"),
            Self::Bridging => std::borrow::Cow::Borrowed("bridging"),
            Self::MediaVoice => std::borrow::Cow::Borrowed("media:voice"),
            Self::MediaVideo => std::borrow::Cow::Borrowed("media:video"),
            Self::MediaScreenShare => std::borrow::Cow::Borrowed("media:screen_share"),
            Self::MemberBan => std::borrow::Cow::Borrowed("member:ban"),
            Self::Custom(name) => std::borrow::Cow::Borrowed(name.as_str()),
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessagesRead => write!(f, "messages:read"),
            Self::MessagesWrite => write!(f, "messages:write"),
            Self::ToolInvoke(id) => write!(f, "tool:invoke:{id}"),
            Self::ToolInvokeAll => write!(f, "tool:invoke:*"),
            Self::ToolRegister => write!(f, "tool:register"),
            Self::MemberInvite => write!(f, "member:invite"),
            Self::MemberRemove => write!(f, "member:remove"),
            Self::RoleAssign => write!(f, "role:assign"),
            Self::GovernancePropose => write!(f, "governance:propose"),
            Self::GovernanceVote => write!(f, "governance:vote"),
            Self::ContextClose => write!(f, "context:close"),
            Self::ChildContextCreate => write!(f, "context:child:create"),
            Self::ToolInterface => write!(f, "tool:interface"),
            Self::Bridging => write!(f, "bridging"),
            Self::MediaVoice => write!(f, "media:voice"),
            Self::MediaVideo => write!(f, "media:video"),
            Self::MediaScreenShare => write!(f, "media:screen_share"),
            Self::MemberBan => write!(f, "member:ban"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityCeiling
// ---------------------------------------------------------------------------

/// The capability ceiling for an SCP context.
///
/// Declared at context creation and immutable for the lifetime of the context
/// (spec section 5.3). The ceiling bounds the maximum set of operations any
/// participant can perform. Role permission sets must be subsets of the
/// ceiling. Members see the ceiling before joining -- it is part of the
/// opt-in contract (spec section 5.7).
///
/// See ADR-009 acceptance criterion 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCeiling {
    /// The set of capabilities permitted in this context.
    pub capabilities: HashSet<Capability>,
}

impl CapabilityCeiling {
    /// Creates a new capability ceiling from an iterator of capabilities.
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
        }
    }

    /// Returns `true` if the given capability is within the ceiling.
    ///
    /// This is the core ceiling check used during UCAN validation and role
    /// definition. `ToolInvoke(id)` is considered within the ceiling if either
    /// `ToolInvoke(id)` or `ToolInvokeAll` is in the ceiling.
    #[must_use]
    pub fn contains(&self, capability: &Capability) -> bool {
        if self.capabilities.contains(capability) {
            return true;
        }
        // ToolInvoke(id) is implicitly allowed if ToolInvokeAll is in the ceiling.
        if let Capability::ToolInvoke(_) = capability {
            return self.capabilities.contains(&Capability::ToolInvokeAll);
        }
        false
    }

    /// Returns `true` if all capabilities in the given set are within the ceiling.
    #[must_use]
    pub fn contains_all(&self, capabilities: &HashSet<Capability>) -> bool {
        capabilities.iter().all(|cap| self.contains(cap))
    }

    /// Returns `true` if the ceiling has no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Returns the number of capabilities in the ceiling.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }
}

/// Returns the default capability ceiling for new contexts.
///
/// Includes all standard SCP capabilities: messaging, tool management, role
/// assignment, membership control, governance, and context close. Used by
/// all FFI bridges when no explicit ceiling is provided.
#[must_use]
pub fn default_ceiling() -> CapabilityCeiling {
    CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
        Capability::ToolInvokeAll,
        Capability::RoleAssign,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::GovernancePropose,
        Capability::GovernanceVote,
        Capability::ContextClose,
    ])
}

// ---------------------------------------------------------------------------
// check_ceiling (free function)
// ---------------------------------------------------------------------------

/// Returns `true` if the given capability is within the ceiling.
///
/// This is the top-level convenience function called during every UCAN
/// validation and at role definition time. Delegates to
/// [`CapabilityCeiling::contains`].
///
/// See ADR-009 acceptance criterion 6.
#[must_use]
pub fn check_ceiling(ceiling: &CapabilityCeiling, capability: &Capability) -> bool {
    ceiling.contains(capability)
}

// ---------------------------------------------------------------------------
// RoleDefinition
// ---------------------------------------------------------------------------

/// Definition of a role within an SCP context.
///
/// A role maps a name to a set of capabilities that are a subset of the
/// context's capability ceiling. Roles are defined at context creation or
/// via role management operations. Built-in roles (`admin`, `member`,
/// `observer`) are always available.
///
/// See ADR-009 acceptance criterion 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// The role name (e.g., `"admin"`, `"member"`, `"observer"`).
    pub name: String,
    /// The set of capabilities granted to participants with this role.
    /// Must be a subset of the context's capability ceiling.
    pub capabilities: HashSet<Capability>,
}

impl RoleDefinition {
    /// Creates a new role definition.
    ///
    /// # Errors
    ///
    /// Returns [`RoleError::CapabilityOutsideCeiling`] if any capability in
    /// the role is not within the provided ceiling.
    pub fn new(
        name: impl Into<String>,
        capabilities: HashSet<Capability>,
        ceiling: &CapabilityCeiling,
    ) -> Result<Self, RoleError> {
        let name = name.into();
        validate_role_name(&name)?;
        for cap in &capabilities {
            if !ceiling.contains(cap) {
                return Err(RoleError::CapabilityOutsideCeiling {
                    role: name,
                    capability: cap.clone(),
                });
            }
        }
        Ok(Self { name, capabilities })
    }

    /// Creates a role definition without ceiling validation.
    ///
    /// Used internally for built-in role constructors where the capabilities
    /// are derived from the ceiling itself.
    fn new_unchecked(name: impl Into<String>, capabilities: HashSet<Capability>) -> Self {
        Self {
            name: name.into(),
            capabilities,
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in role constructors
// ---------------------------------------------------------------------------

/// Returns the `admin` built-in role definition.
///
/// The admin role grants all capabilities in the ceiling. This is the most
/// privileged role -- context creators are typically assigned admin.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_admin(ceiling: &CapabilityCeiling) -> RoleDefinition {
    RoleDefinition::new_unchecked("admin", ceiling.capabilities.clone())
}

/// Returns the `member` built-in role definition.
///
/// Members can read and write messages and invoke any registered tool.
/// Capabilities are intersected with the ceiling -- if a capability is not
/// in the ceiling, it is not granted.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_member(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolInvokeAll,
    ]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("member", capabilities)
}

/// Returns the `moderator` built-in role definition.
///
/// Moderators can read/write messages, invoke tools, remove members, and
/// propose governance actions. This fills the gap between `member` (no
/// moderation power) and `admin` (full control). Referenced in §5.9 as
/// "elected moderators" governance pattern. Capabilities are intersected
/// with the ceiling.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_moderator(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolInvokeAll,
        Capability::MemberRemove,
        Capability::GovernancePropose,
    ]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("moderator", capabilities)
}

/// Returns the `observer` built-in role definition.
///
/// Observers can only read messages. The capability is intersected with the
/// ceiling.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_observer(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([Capability::MessagesRead]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("observer", capabilities)
}

/// Returns the `author` broadcast-specific role definition.
///
/// Authors can write and read messages and invoke any registered tool.
/// Designed for one-to-many publishing scenarios (spec section 5.14).
/// Capabilities are intersected with the ceiling.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_author(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesWrite,
        Capability::MessagesRead,
        Capability::ToolInvokeAll,
    ]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("author", capabilities)
}

/// Returns the `subscriber` broadcast-specific role definition.
///
/// Subscribers can only read messages. Designed for broadcast contexts
/// (spec section 5.14). The capability is intersected with the ceiling.
///
/// See ADR-009 acceptance criterion 2.
#[must_use]
pub fn builtin_subscriber(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([Capability::MessagesRead]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("subscriber", capabilities)
}

/// Returns all standard built-in role definitions for a given ceiling.
///
/// Includes `admin`, `moderator`, `member`, and `observer`.
#[must_use]
pub fn builtin_roles(ceiling: &CapabilityCeiling) -> Vec<RoleDefinition> {
    vec![
        builtin_admin(ceiling),
        builtin_moderator(ceiling),
        builtin_member(ceiling),
        builtin_observer(ceiling),
    ]
}

/// Returns all broadcast-specific built-in role definitions for a given ceiling.
///
/// Includes `author` and `subscriber`.
#[must_use]
pub fn builtin_broadcast_roles(ceiling: &CapabilityCeiling) -> Vec<RoleDefinition> {
    vec![builtin_author(ceiling), builtin_subscriber(ceiling)]
}

// ---------------------------------------------------------------------------
// UcanToken
// ---------------------------------------------------------------------------

/// Lightweight UCAN token representation for role-based access control
/// in broadcast contexts.
///
/// Contains the core UCAN fields specified by ADR-009: issuer DID,
/// audience DID, capability attestations, and a unique nonce. Full
/// cryptographic UCAN validation (Ed25519 signatures, delegation chains,
/// nonce tracking) is implemented in `scp-core/ucan/` (see ADR-016).
///
/// Each token: `iss` = context creator DID, `aud` = member DID,
/// `att` = capability attestations, `nnc` = unique nonce.
///
/// See ADR-009 acceptance criterion 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanToken {
    /// Issuer DID -- the context creator who delegates the capability.
    pub iss: String,
    /// Audience DID -- the member who receives the capability.
    pub aud: String,
    /// Attestations -- list of capability attestation strings.
    /// Format: `scp:ctx:{context_id}/{capability}`.
    pub att: Vec<UcanAttestation>,
    /// Unique nonce preventing token replay (spec section 9.5).
    pub nnc: String,
}

/// A single UCAN attestation entry.
///
/// Each attestation grants a specific capability within a context.
/// Format follows ADR-009: `with` = `scp:ctx:{context_id}/{capability}`,
/// `can` = `"invoke"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcanAttestation {
    /// Resource URI: `scp:ctx:{context_id}/{capability}`.
    pub with: String,
    /// Action: always `"invoke"` in the current protocol version.
    pub can: String,
}

// ---------------------------------------------------------------------------
// RoleError
// ---------------------------------------------------------------------------

/// Errors produced by role and capability operations.
///
/// Covers role validation failures, ceiling violations, and assignment errors.
/// See ADR-009 for the error conditions.
#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    /// A role definition includes a capability that is not in the context's
    /// capability ceiling.
    #[error("role \"{role}\" includes capability {capability} which is outside the ceiling")]
    CapabilityOutsideCeiling {
        /// The role that contains the offending capability.
        role: String,
        /// The capability that exceeds the ceiling.
        capability: Capability,
    },

    /// The requested role does not exist in the context's role definitions.
    #[error("role \"{0}\" not found in context")]
    RoleNotFound(String),

    /// The assigner does not have the `RoleAssign` capability.
    #[error("assigner \"{0}\" does not have RoleAssign capability")]
    AssignerNotAuthorized(String),

    /// The member is not a participant in the context.
    #[error("member \"{0}\" is not in the context")]
    MemberNotInContext(String),

    /// A custom role name is invalid (empty, too long, uses reserved name,
    /// or contains invalid characters).
    #[error("invalid role name: {0}")]
    InvalidRoleName(String),

    /// A context lifecycle error occurred during role assignment.
    #[error("context error: {0}")]
    Context(#[from] ContextError),

    /// The system clock is unavailable or before the Unix epoch.
    #[error("clock error: {0}")]
    ClockError(#[from] crate::time::ClockError),
}

// ---------------------------------------------------------------------------
// RoleAssignment
// ---------------------------------------------------------------------------

/// Tracks a member's assigned role and corresponding UCAN tokens.
///
/// Used internally to maintain the mapping of members to roles within a
/// context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignment {
    /// The member's DID string.
    pub member_did: String,
    /// The name of the assigned role.
    pub role_name: String,
    /// The UCAN tokens minted for this assignment.
    pub tokens: Vec<UcanToken>,
}

// ---------------------------------------------------------------------------
// ContextRoleState
// ---------------------------------------------------------------------------

/// Encapsulates the role-related state for a context.
///
/// This type is designed to be held alongside the context handle and provides
/// all the state needed for role assignment operations without requiring
/// access to `ContextHandle` internals. It is the primary input for
/// [`assign_role`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRoleState {
    /// The context's unique identifier.
    pub context_id: String,
    /// The DID of the context creator (UCAN root issuer).
    pub creator_did: String,
    /// The immutable capability ceiling.
    pub ceiling: CapabilityCeiling,
    /// All role definitions (built-in and custom).
    pub role_definitions: HashMap<String, RoleDefinition>,
    /// Current role assignments: member DID -> assignment.
    pub assignments: HashMap<String, RoleAssignment>,
    /// Set of member DIDs currently in the context.
    pub members: HashSet<String>,
    /// Capabilities held by each member (derived from assignments).
    pub member_capabilities: HashMap<String, HashSet<Capability>>,
}

impl ContextRoleState {
    /// Creates a new `ContextRoleState` with the given parameters.
    ///
    /// Built-in roles are automatically added to the role definitions.
    /// The creator is automatically assigned the `admin` role.
    ///
    /// # Errors
    ///
    /// Returns [`RoleError::CapabilityOutsideCeiling`] if any custom role
    /// definition includes capabilities outside the ceiling.
    pub fn new(
        context_id: impl Into<String>,
        creator_did: impl Into<String>,
        ceiling: CapabilityCeiling,
        custom_roles: Vec<RoleDefinition>,
    ) -> Result<Self, RoleError> {
        let context_id = context_id.into();
        let creator_did = creator_did.into();

        // Validate custom roles: name format + capabilities against ceiling.
        for role in &custom_roles {
            validate_role_name(&role.name)?;
            for cap in &role.capabilities {
                if !ceiling.contains(cap) {
                    return Err(RoleError::CapabilityOutsideCeiling {
                        role: role.name.clone(),
                        capability: cap.clone(),
                    });
                }
            }
        }

        // Build role definitions map with built-in roles.
        let mut role_definitions = HashMap::new();
        for role in builtin_roles(&ceiling) {
            role_definitions.insert(role.name.clone(), role);
        }
        for role in builtin_broadcast_roles(&ceiling) {
            role_definitions.insert(role.name.clone(), role);
        }
        for role in custom_roles {
            role_definitions.insert(role.name.clone(), role);
        }

        let mut members = HashSet::new();
        members.insert(creator_did.clone());

        // Auto-assign creator as admin.
        let admin_role = role_definitions
            .get("admin")
            .cloned()
            .unwrap_or_else(|| builtin_admin(&ceiling));

        let tokens = mint_role_tokens(&context_id, &creator_did, &creator_did, &admin_role)?;

        let mut assignments = HashMap::new();
        let assignment = RoleAssignment {
            member_did: creator_did.clone(),
            role_name: "admin".to_owned(),
            tokens,
        };
        assignments.insert(creator_did.clone(), assignment);

        let mut member_capabilities = HashMap::new();
        member_capabilities.insert(creator_did.clone(), admin_role.capabilities);

        Ok(Self {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
        })
    }

    /// Returns `true` if the given member has the specified capability.
    #[must_use]
    pub fn member_has_capability(&self, member_did: &str, capability: &Capability) -> bool {
        self.member_capabilities
            .get(member_did)
            .is_some_and(|caps| caps.contains(capability))
    }

    /// Revokes `GovernanceVote` and `GovernancePropose` capabilities from a
    /// member (§5.9: presence-only members lose governance capabilities).
    ///
    /// Called when a member has both read and write access revoked. The member
    /// remains in the context but cannot influence governance decisions about
    /// content they cannot see.
    pub fn revoke_governance_capabilities(&mut self, member_did: &scp_identity::DID) {
        let did_str = member_did.as_ref();
        if let Some(caps) = self.member_capabilities.get_mut(did_str) {
            caps.remove(&Capability::GovernanceVote);
            caps.remove(&Capability::GovernancePropose);
        }
    }

    /// Restores `GovernanceVote` and `GovernancePropose` capabilities for a
    /// member, re-deriving them from the member's current role definition.
    ///
    /// Called when a presence-only member has read or write access restored,
    /// taking them out of presence-only state. Only restores capabilities
    /// that exist in the member's role definition AND the context ceiling.
    pub fn restore_governance_capabilities(&mut self, member_did: &scp_identity::DID) {
        let did_str = member_did.as_ref();
        // Look up the member's current role to see which capabilities they
        // should have. Only restore governance capabilities that are in the
        // role definition AND the ceiling.
        let role_caps: Option<HashSet<Capability>> = self
            .assignments
            .get(did_str)
            .and_then(|assignment| self.role_definitions.get(&assignment.role_name))
            .map(|def| def.capabilities.clone());

        if let Some(role_caps) = role_caps
            && let Some(caps) = self.member_capabilities.get_mut(did_str)
        {
            if role_caps.contains(&Capability::GovernanceVote)
                && self.ceiling.contains(&Capability::GovernanceVote)
            {
                caps.insert(Capability::GovernanceVote);
            }
            if role_caps.contains(&Capability::GovernancePropose)
                && self.ceiling.contains(&Capability::GovernancePropose)
            {
                caps.insert(Capability::GovernancePropose);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// assign_role
// ---------------------------------------------------------------------------

/// Assigns a role to a member within a context.
///
/// This is a free function that takes all needed state as parameters, per
/// the design instruction. It validates that:
/// 1. The assigner has the `RoleAssign` capability.
/// 2. The member is in the context's member set.
/// 3. The role exists in the context's role definitions.
///
/// On success, it updates the context role state in place and returns the
/// minted UCAN tokens. Integration points (MLS distribution, event log
/// append) are handled by the caller.
///
/// See ADR-009 acceptance criterion 3.
///
/// # Errors
///
/// - [`RoleError::AssignerNotAuthorized`] if the assigner lacks `RoleAssign`.
/// - [`RoleError::MemberNotInContext`] if the member is not in the context.
/// - [`RoleError::RoleNotFound`] if the role name is not defined.
pub fn assign_role(
    state: &mut ContextRoleState,
    member_did: &str,
    role_name: &str,
    assigner_did: &str,
) -> Result<Vec<UcanToken>, RoleError> {
    // 1. Verify assigner has RoleAssign capability.
    if !state.member_has_capability(assigner_did, &Capability::RoleAssign) {
        return Err(RoleError::AssignerNotAuthorized(assigner_did.to_owned()));
    }

    // 2. Verify member is in the context.
    if !state.members.contains(member_did) {
        return Err(RoleError::MemberNotInContext(member_did.to_owned()));
    }

    // 3. Look up the role definition.
    let role_def = state
        .role_definitions
        .get(role_name)
        .ok_or_else(|| RoleError::RoleNotFound(role_name.to_owned()))?
        .clone();

    // 4. Mint UCAN tokens for each capability in the role.
    let tokens = mint_role_tokens(&state.context_id, &state.creator_did, member_did, &role_def)?;

    // 5. Update state: replace any previous assignment.
    let assignment = RoleAssignment {
        member_did: member_did.to_owned(),
        role_name: role_name.to_owned(),
        tokens: tokens.clone(),
    };
    state.assignments.insert(member_did.to_owned(), assignment);
    state
        .member_capabilities
        .insert(member_did.to_owned(), role_def.capabilities);

    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Role name validation (M3)
// ---------------------------------------------------------------------------

/// Maximum length of a custom role name in bytes.
///
/// Role names are stored in `ContextSnapshot` and serialized into event log
/// entries. 64 bytes is generous for any practical role name while preventing
/// unbounded growth.
pub const MAX_ROLE_NAME_LENGTH: usize = 64;

/// Built-in role names that custom roles MUST NOT shadow.
///
/// These are the protocol-defined role names from §5.5 and §5.14. Custom
/// roles using these names would collide with built-in role constructors,
/// causing ambiguous role resolution.
const RESERVED_ROLE_NAMES: &[&str] = &[
    "admin",
    "moderator",
    "member",
    "observer",
    "author",
    "subscriber",
];

/// Validates a custom role name.
///
/// Role names MUST:
/// - Be non-empty.
/// - Not exceed [`MAX_ROLE_NAME_LENGTH`] bytes.
/// - Not collide with reserved built-in role names.
/// - Contain only lowercase ASCII letters, digits, hyphens, and underscores
///   (`[a-z0-9_-]`), and not start or end with a hyphen or underscore.
///
/// # Errors
///
/// Returns [`RoleError::InvalidRoleName`] on validation failure.
pub fn validate_role_name(name: &str) -> Result<(), RoleError> {
    if name.is_empty() {
        return Err(RoleError::InvalidRoleName(
            "role name must not be empty".into(),
        ));
    }

    if name.len() > MAX_ROLE_NAME_LENGTH {
        return Err(RoleError::InvalidRoleName(format!(
            "role name exceeds maximum length of {MAX_ROLE_NAME_LENGTH} bytes (got {} bytes)",
            name.len()
        )));
    }

    if RESERVED_ROLE_NAMES.contains(&name) {
        return Err(RoleError::InvalidRoleName(format!(
            "'{name}' is a reserved built-in role name"
        )));
    }

    // Format: lowercase ASCII letters, digits, hyphens, underscores.
    // Must not start or end with hyphen/underscore.
    let first = name.as_bytes()[0];
    if first == b'-' || first == b'_' {
        return Err(RoleError::InvalidRoleName(format!(
            "'{name}' must not start with a hyphen or underscore"
        )));
    }

    let last = name.as_bytes()[name.len() - 1];
    if last == b'-' || last == b'_' {
        return Err(RoleError::InvalidRoleName(format!(
            "'{name}' must not end with a hyphen or underscore"
        )));
    }

    for ch in name.chars() {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_') {
            return Err(RoleError::InvalidRoleName(format!(
                "'{name}' contains invalid character '{ch}' (only lowercase ASCII letters, digits, hyphens, and underscores allowed)"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// validate_role_definition
// ---------------------------------------------------------------------------

/// Validates that a role definition's capabilities are all within the ceiling.
///
/// This is called at context creation time and when custom roles are added.
///
/// # Errors
///
/// Returns [`RoleError::CapabilityOutsideCeiling`] if any capability in
/// the role is not within the ceiling.
pub fn validate_role_definition(
    role: &RoleDefinition,
    ceiling: &CapabilityCeiling,
) -> Result<(), RoleError> {
    for cap in &role.capabilities {
        if !ceiling.contains(cap) {
            return Err(RoleError::CapabilityOutsideCeiling {
                role: role.name.clone(),
                capability: cap.clone(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Mints UCAN tokens for all capabilities in a role.
///
/// Creates one [`UcanToken`] per capability in the role definition, following
/// the ADR-009 token format: `iss` = creator DID, `aud` = member DID,
/// `att` = capability attestation, `nnc` = unique nonce.
///
/// Phase 2 stub: tokens are structurally correct but not cryptographically
/// signed. Full signing will be added in SCP-024.
fn mint_role_tokens(
    context_id: &str,
    creator_did: &str,
    member_did: &str,
    role: &RoleDefinition,
) -> Result<Vec<UcanToken>, crate::time::ClockError> {
    role.capabilities
        .iter()
        .map(|cap| {
            let att = UcanAttestation {
                with: format!("scp:ctx:{context_id}/{cap}"),
                can: "invoke".to_owned(),
            };
            Ok(UcanToken {
                iss: creator_did.to_owned(),
                aud: member_did.to_owned(),
                att: vec![att],
                nnc: generate_nonce()?,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Creates a standard ceiling with common capabilities for testing.
    fn test_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolInvokeAll,
            Capability::ToolRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
        ])
    }

    /// Creates a minimal ceiling with only messaging capabilities.
    fn minimal_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite])
    }

    // -----------------------------------------------------------------------
    // Capability enum
    // -----------------------------------------------------------------------

    #[test]
    fn capability_variants_are_distinct() {
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolInvoke("tool-1".to_owned()),
            Capability::ToolInvokeAll,
            Capability::ToolRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::Custom("custom-1".to_owned()),
        ];
        for (i, a) in caps.iter().enumerate() {
            for (j, b) in caps.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "variants at index {i} and {j} should differ");
                }
            }
        }
    }

    #[test]
    fn capability_clone_preserves_equality() {
        let cap = Capability::ToolInvoke("my-tool".to_owned());
        let cloned = cap.clone();
        assert_eq!(cap, cloned);
    }

    #[test]
    fn capability_hash_consistent_with_equality() {
        use std::hash::{Hash, Hasher};
        let cap1 = Capability::Custom("test".to_owned());
        let cap2 = Capability::Custom("test".to_owned());
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        cap1.hash(&mut h1);
        cap2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn capability_display_formats() {
        assert_eq!(format!("{}", Capability::MessagesRead), "messages:read");
        assert_eq!(format!("{}", Capability::MessagesWrite), "messages:write");
        assert_eq!(
            format!("{}", Capability::ToolInvoke("foo".to_owned())),
            "tool:invoke:foo"
        );
        assert_eq!(format!("{}", Capability::ToolInvokeAll), "tool:invoke:*");
        assert_eq!(format!("{}", Capability::ToolRegister), "tool:register");
        assert_eq!(format!("{}", Capability::MemberInvite), "member:invite");
        assert_eq!(format!("{}", Capability::MemberRemove), "member:remove");
        assert_eq!(format!("{}", Capability::RoleAssign), "role:assign");
        assert_eq!(
            format!("{}", Capability::GovernancePropose),
            "governance:propose"
        );
        assert_eq!(format!("{}", Capability::GovernanceVote), "governance:vote");
        assert_eq!(format!("{}", Capability::ContextClose), "context:close");
        assert_eq!(
            format!("{}", Capability::ChildContextCreate),
            "context:child:create"
        );
        assert_eq!(
            format!("{}", Capability::Custom("x".to_owned())),
            "custom:x"
        );
    }

    #[test]
    fn capability_serialization_roundtrip() {
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolInvoke("search".to_owned()),
            Capability::ToolInvokeAll,
            Capability::MemberBan,
            Capability::Custom("my-cap".to_owned()),
        ];
        for cap in &caps {
            let json = serde_json::to_string(cap).unwrap();
            let deserialized: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, &deserialized, "roundtrip failed for {cap:?}");
        }
    }

    #[test]
    fn member_ban_capability_new_and_name() {
        let cap = Capability::new("member:ban");
        assert_eq!(cap, Capability::MemberBan);
        assert_eq!(cap.name(), "member:ban");
        assert_eq!(format!("{cap}"), "member:ban");
    }

    // -----------------------------------------------------------------------
    // CapabilityCeiling
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_new_creates_from_iterator() {
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        assert_eq!(ceiling.len(), 2);
        assert!(!ceiling.is_empty());
    }

    #[test]
    fn ceiling_empty() {
        let ceiling = CapabilityCeiling::new(std::iter::empty());
        assert!(ceiling.is_empty());
        assert_eq!(ceiling.len(), 0);
    }

    #[test]
    fn ceiling_contains_direct_capability() {
        let ceiling = test_ceiling();
        assert!(ceiling.contains(&Capability::MessagesRead));
        assert!(ceiling.contains(&Capability::RoleAssign));
    }

    #[test]
    fn ceiling_does_not_contain_absent_capability() {
        let ceiling = minimal_ceiling();
        assert!(!ceiling.contains(&Capability::RoleAssign));
        assert!(!ceiling.contains(&Capability::MemberInvite));
    }

    #[test]
    fn ceiling_tool_invoke_all_implies_specific_tool() {
        let ceiling = CapabilityCeiling::new([Capability::ToolInvokeAll, Capability::MessagesRead]);
        assert!(ceiling.contains(&Capability::ToolInvoke("any-tool".to_owned())));
        assert!(ceiling.contains(&Capability::ToolInvoke("another-tool".to_owned())));
    }

    #[test]
    fn ceiling_specific_tool_does_not_imply_all() {
        let ceiling = CapabilityCeiling::new([
            Capability::ToolInvoke("specific-tool".to_owned()),
            Capability::MessagesRead,
        ]);
        assert!(ceiling.contains(&Capability::ToolInvoke("specific-tool".to_owned())));
        assert!(!ceiling.contains(&Capability::ToolInvoke("other-tool".to_owned())));
        assert!(!ceiling.contains(&Capability::ToolInvokeAll));
    }

    #[test]
    fn ceiling_contains_all_succeeds_for_subset() {
        let ceiling = test_ceiling();
        let subset = HashSet::from([Capability::MessagesRead, Capability::MessagesWrite]);
        assert!(ceiling.contains_all(&subset));
    }

    #[test]
    fn ceiling_contains_all_fails_for_superset() {
        let ceiling = minimal_ceiling();
        let superset = HashSet::from([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
        ]);
        assert!(!ceiling.contains_all(&superset));
    }

    #[test]
    fn ceiling_dedup_duplicates() {
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesRead,
            Capability::MessagesWrite,
        ]);
        assert_eq!(ceiling.len(), 2);
    }

    // -----------------------------------------------------------------------
    // check_ceiling (free function)
    // -----------------------------------------------------------------------

    #[test]
    fn check_ceiling_returns_true_for_present_capability() {
        let ceiling = test_ceiling();
        assert!(check_ceiling(&ceiling, &Capability::MessagesRead));
    }

    #[test]
    fn check_ceiling_returns_false_for_absent_capability() {
        let ceiling = minimal_ceiling();
        assert!(!check_ceiling(&ceiling, &Capability::ContextClose));
    }

    #[test]
    fn check_ceiling_tool_invoke_all_covers_specific() {
        let ceiling = CapabilityCeiling::new([Capability::ToolInvokeAll]);
        assert!(check_ceiling(
            &ceiling,
            &Capability::ToolInvoke("test-tool".to_owned())
        ));
    }

    // -----------------------------------------------------------------------
    // RoleDefinition
    // -----------------------------------------------------------------------

    #[test]
    fn role_definition_new_validates_against_ceiling() {
        let ceiling = minimal_ceiling();
        let caps = HashSet::from([Capability::MessagesRead]);
        let result = RoleDefinition::new("reader", caps, &ceiling);
        assert!(result.is_ok());
        let role = result.unwrap();
        assert_eq!(role.name, "reader");
    }

    #[test]
    fn role_definition_new_rejects_capability_outside_ceiling() {
        let ceiling = minimal_ceiling();
        let caps = HashSet::from([Capability::MessagesRead, Capability::RoleAssign]);
        let result = RoleDefinition::new("bad-role", caps, &ceiling);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, RoleError::CapabilityOutsideCeiling { ref role, .. } if role == "bad-role")
        );
    }

    #[test]
    fn role_definition_serialization_roundtrip() {
        let ceiling = test_ceiling();
        let caps = HashSet::from([Capability::MessagesRead, Capability::MessagesWrite]);
        let role = RoleDefinition::new("custom", caps, &ceiling).unwrap();
        let json = serde_json::to_string(&role).unwrap();
        let deserialized: RoleDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(role, deserialized);
    }

    // -----------------------------------------------------------------------
    // Built-in roles
    // -----------------------------------------------------------------------

    #[test]
    fn builtin_admin_has_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let admin = builtin_admin(&ceiling);
        assert_eq!(admin.name, "admin");
        assert_eq!(admin.capabilities, ceiling.capabilities);
    }

    #[test]
    fn builtin_member_has_expected_capabilities() {
        let ceiling = test_ceiling();
        let member = builtin_member(&ceiling);
        assert_eq!(member.name, "member");
        assert!(member.capabilities.contains(&Capability::MessagesRead));
        assert!(member.capabilities.contains(&Capability::MessagesWrite));
        assert!(member.capabilities.contains(&Capability::ToolInvokeAll));
        assert_eq!(member.capabilities.len(), 3);
    }

    #[test]
    fn builtin_observer_has_messages_read_only() {
        let ceiling = test_ceiling();
        let observer = builtin_observer(&ceiling);
        assert_eq!(observer.name, "observer");
        assert!(observer.capabilities.contains(&Capability::MessagesRead));
        assert_eq!(observer.capabilities.len(), 1);
    }

    #[test]
    fn builtin_moderator_has_expected_capabilities() {
        let ceiling = test_ceiling();
        let moderator = builtin_moderator(&ceiling);
        assert_eq!(moderator.name, "moderator");
        assert!(moderator.capabilities.contains(&Capability::MessagesRead));
        assert!(moderator.capabilities.contains(&Capability::MessagesWrite));
        assert!(moderator.capabilities.contains(&Capability::ToolInvokeAll));
        assert!(moderator.capabilities.contains(&Capability::MemberRemove));
        assert!(
            moderator
                .capabilities
                .contains(&Capability::GovernancePropose)
        );
        assert_eq!(moderator.capabilities.len(), 5);
    }

    #[test]
    fn builtin_moderator_respects_ceiling() {
        // If GovernancePropose is not in the ceiling, moderator should not have it.
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolInvokeAll,
            Capability::MemberRemove,
        ]);
        let moderator = builtin_moderator(&ceiling);
        assert!(
            !moderator
                .capabilities
                .contains(&Capability::GovernancePropose)
        );
        assert_eq!(moderator.capabilities.len(), 4);
    }

    #[test]
    fn builtin_author_has_expected_capabilities() {
        let ceiling = test_ceiling();
        let author = builtin_author(&ceiling);
        assert_eq!(author.name, "author");
        assert!(author.capabilities.contains(&Capability::MessagesWrite));
        assert!(author.capabilities.contains(&Capability::MessagesRead));
        assert!(author.capabilities.contains(&Capability::ToolInvokeAll));
        assert_eq!(author.capabilities.len(), 3);
    }

    #[test]
    fn builtin_subscriber_has_messages_read_only() {
        let ceiling = test_ceiling();
        let subscriber = builtin_subscriber(&ceiling);
        assert_eq!(subscriber.name, "subscriber");
        assert!(subscriber.capabilities.contains(&Capability::MessagesRead));
        assert_eq!(subscriber.capabilities.len(), 1);
    }

    #[test]
    fn builtin_member_respects_ceiling() {
        // If ToolInvokeAll is not in the ceiling, member should not have it.
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        let member = builtin_member(&ceiling);
        assert!(!member.capabilities.contains(&Capability::ToolInvokeAll));
        assert_eq!(member.capabilities.len(), 2);
    }

    #[test]
    fn builtin_roles_returns_four_roles() {
        let ceiling = test_ceiling();
        let roles = builtin_roles(&ceiling);
        assert_eq!(roles.len(), 4);
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"admin"));
        assert!(names.contains(&"moderator"));
        assert!(names.contains(&"member"));
        assert!(names.contains(&"observer"));
    }

    #[test]
    fn builtin_broadcast_roles_returns_two_roles() {
        let ceiling = test_ceiling();
        let roles = builtin_broadcast_roles(&ceiling);
        assert_eq!(roles.len(), 2);
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"author"));
        assert!(names.contains(&"subscriber"));
    }

    // -----------------------------------------------------------------------
    // UcanToken
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_token_serialization_roundtrip() {
        let token = UcanToken {
            iss: "did:dht:creator".to_owned(),
            aud: "did:dht:member".to_owned(),
            att: vec![UcanAttestation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "invoke".to_owned(),
            }],
            nnc: "1708646400000-aabbccdd".to_owned(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let deserialized: UcanToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, deserialized);
    }

    // -----------------------------------------------------------------------
    // ContextRoleState
    // -----------------------------------------------------------------------

    #[test]
    fn context_role_state_new_creates_with_builtins() {
        let ceiling = test_ceiling();
        let state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        // Creator is a member.
        assert!(state.members.contains("did:dht:creator"));

        // Creator is assigned admin role.
        let assignment = state.assignments.get("did:dht:creator").unwrap();
        assert_eq!(assignment.role_name, "admin");

        // Built-in roles are available.
        assert!(state.role_definitions.contains_key("admin"));
        assert!(state.role_definitions.contains_key("member"));
        assert!(state.role_definitions.contains_key("observer"));
        assert!(state.role_definitions.contains_key("author"));
        assert!(state.role_definitions.contains_key("subscriber"));
    }

    #[test]
    fn context_role_state_new_with_custom_role() {
        let ceiling = test_ceiling();
        let custom = RoleDefinition::new(
            "content-mod",
            HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::MemberRemove,
            ]),
            &ceiling,
        )
        .unwrap();

        let state =
            ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![custom]).unwrap();
        assert!(state.role_definitions.contains_key("content-mod"));
        let mod_role = state.role_definitions.get("content-mod").unwrap();
        assert_eq!(mod_role.capabilities.len(), 3);
    }

    #[test]
    fn context_role_state_new_rejects_invalid_custom_role() {
        let ceiling = minimal_ceiling();
        let bad_custom = RoleDefinition::new_unchecked(
            "overpowered",
            HashSet::from([Capability::MessagesRead, Capability::RoleAssign]),
        );

        let result = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![bad_custom]);
        assert!(result.is_err());
    }

    #[test]
    fn context_role_state_creator_has_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let state =
            ContextRoleState::new("ctx-1", "did:dht:creator", ceiling.clone(), vec![]).unwrap();

        for cap in &ceiling.capabilities {
            assert!(
                state.member_has_capability("did:dht:creator", cap),
                "creator should have capability {cap:?}"
            );
        }
    }

    #[test]
    fn context_role_state_non_member_has_no_capabilities() {
        let ceiling = test_ceiling();
        let state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        assert!(!state.member_has_capability("did:dht:nobody", &Capability::MessagesRead));
    }

    // -----------------------------------------------------------------------
    // assign_role
    // -----------------------------------------------------------------------

    #[test]
    fn assign_role_succeeds_for_authorized_assigner() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        // Add a member to the context.
        state.members.insert("did:dht:alice".to_owned());

        let result = assign_role(&mut state, "did:dht:alice", "member", "did:dht:creator");
        assert!(result.is_ok());

        let tokens = result.unwrap();
        // member role has 3 capabilities -> 3 tokens.
        assert_eq!(tokens.len(), 3);

        // Alice should now have member capabilities.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::ToolInvokeAll));
    }

    #[test]
    fn assign_role_fails_for_unauthorized_assigner() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        // Add members.
        state.members.insert("did:dht:alice".to_owned());
        state.members.insert("did:dht:bob".to_owned());

        // Assign alice as member (no RoleAssign capability).
        assign_role(&mut state, "did:dht:alice", "member", "did:dht:creator").unwrap();

        // Alice tries to assign bob -- should fail.
        let result = assign_role(&mut state, "did:dht:bob", "member", "did:dht:alice");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::AssignerNotAuthorized(ref did) if did == "did:dht:alice"
        ));
    }

    #[test]
    fn assign_role_fails_for_nonexistent_member() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        let result = assign_role(&mut state, "did:dht:nobody", "member", "did:dht:creator");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::MemberNotInContext(ref did) if did == "did:dht:nobody"
        ));
    }

    #[test]
    fn assign_role_fails_for_nonexistent_role() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let result = assign_role(
            &mut state,
            "did:dht:alice",
            "nonexistent",
            "did:dht:creator",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::RoleNotFound(ref name) if name == "nonexistent"
        ));
    }

    #[test]
    fn assign_role_replaces_previous_assignment() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Assign as member first.
        assign_role(&mut state, "did:dht:alice", "member", "did:dht:creator").unwrap();
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        // Reassign as observer.
        assign_role(&mut state, "did:dht:alice", "observer", "did:dht:creator").unwrap();
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(!state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        let assignment = state.assignments.get("did:dht:alice").unwrap();
        assert_eq!(assignment.role_name, "observer");
    }

    #[test]
    fn assign_role_mints_correct_token_format() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens =
            assign_role(&mut state, "did:dht:alice", "observer", "did:dht:creator").unwrap();

        assert_eq!(tokens.len(), 1);
        let token = &tokens[0];
        assert_eq!(token.iss, "did:dht:creator");
        assert_eq!(token.aud, "did:dht:alice");
        assert_eq!(token.att.len(), 1);
        assert_eq!(token.att[0].with, "scp:ctx:ctx-1/messages:read");
        assert_eq!(token.att[0].can, "invoke");
        assert!(!token.nnc.is_empty());
        // Verify nonce format: {millis}-{hex}.
        assert!(token.nnc.contains('-'));
    }

    #[test]
    fn assign_role_admin_grants_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let mut state =
            ContextRoleState::new("ctx-1", "did:dht:creator", ceiling.clone(), vec![]).unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(&mut state, "did:dht:alice", "admin", "did:dht:creator").unwrap();

        // Admin gets all ceiling capabilities.
        assert_eq!(tokens.len(), ceiling.len());

        for cap in &ceiling.capabilities {
            assert!(
                state.member_has_capability("did:dht:alice", cap),
                "admin should have capability {cap:?}"
            );
        }
    }

    #[test]
    fn assign_role_custom_role() {
        let ceiling = test_ceiling();
        let custom = RoleDefinition::new(
            "content-mod",
            HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::MemberRemove,
            ]),
            &ceiling,
        )
        .unwrap();

        let mut state =
            ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![custom]).unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(
            &mut state,
            "did:dht:alice",
            "content-mod",
            "did:dht:creator",
        )
        .unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(state.member_has_capability("did:dht:alice", &Capability::MemberRemove));
    }

    // -----------------------------------------------------------------------
    // validate_role_definition
    // -----------------------------------------------------------------------

    #[test]
    fn validate_role_definition_succeeds_for_valid_subset() {
        let ceiling = test_ceiling();
        let role =
            RoleDefinition::new_unchecked("custom", HashSet::from([Capability::MessagesRead]));
        assert!(validate_role_definition(&role, &ceiling).is_ok());
    }

    #[test]
    fn validate_role_definition_fails_for_capability_outside_ceiling() {
        let ceiling = minimal_ceiling();
        let role = RoleDefinition::new_unchecked(
            "bad",
            HashSet::from([Capability::MessagesRead, Capability::ContextClose]),
        );
        let result = validate_role_definition(&role, &ceiling);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::CapabilityOutsideCeiling { ref role, ref capability }
                if role == "bad" && *capability == Capability::ContextClose
        ));
    }

    // -----------------------------------------------------------------------
    // Ceiling immutability
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_immutability_error_variant_exists() {
        // Verify the ContextError::CeilingImmutable variant exists and has
        // the correct error message. This is defined in mod.rs but the
        // roles module depends on it.
        let err = ContextError::CeilingImmutable;
        assert_eq!(
            format!("{err}"),
            "capability ceiling is immutable and cannot be modified"
        );
    }

    // -----------------------------------------------------------------------
    // RoleError display messages
    // -----------------------------------------------------------------------

    #[test]
    fn role_error_display_messages() {
        let err = RoleError::CapabilityOutsideCeiling {
            role: "test".to_owned(),
            capability: Capability::RoleAssign,
        };
        assert!(format!("{err}").contains("test"));
        assert!(format!("{err}").contains("role:assign"));

        let err = RoleError::RoleNotFound("ghost".to_owned());
        assert!(format!("{err}").contains("ghost"));

        let err = RoleError::AssignerNotAuthorized("did:dht:bad".to_owned());
        assert!(format!("{err}").contains("did:dht:bad"));

        let err = RoleError::MemberNotInContext("did:dht:nobody".to_owned());
        assert!(format!("{err}").contains("did:dht:nobody"));
    }

    // -----------------------------------------------------------------------
    // Nonce uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn generated_nonces_are_unique() {
        let nonces: Vec<String> = (0..100).map(|_| generate_nonce().unwrap()).collect();
        let unique: HashSet<&String> = nonces.iter().collect();
        assert_eq!(
            nonces.len(),
            unique.len(),
            "all generated nonces should be unique"
        );
    }

    #[test]
    fn nonce_format_is_valid() {
        let nonce = generate_nonce().unwrap();
        let parts: Vec<&str> = nonce.splitn(2, '-').collect();
        assert_eq!(parts.len(), 2, "nonce should have timestamp-hex format");
        // Timestamp part should be a valid number.
        assert!(
            parts[0].parse::<u128>().is_ok(),
            "timestamp portion should be numeric"
        );
        // Hex part should be 32 hex characters (16 bytes).
        assert_eq!(parts[1].len(), 32, "random hex should be 32 characters");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "random portion should be hex"
        );
    }

    // -----------------------------------------------------------------------
    // Mode-agnostic capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn messages_capabilities_work_in_both_modes() {
        // MessagesRead and MessagesWrite are mode-agnostic per ADR-009.
        // Verify they appear in both standard and broadcast role sets.
        let ceiling = test_ceiling();

        let member = builtin_member(&ceiling);
        let author = builtin_author(&ceiling);
        let observer = builtin_observer(&ceiling);
        let subscriber = builtin_subscriber(&ceiling);

        // Standard roles.
        assert!(member.capabilities.contains(&Capability::MessagesRead));
        assert!(member.capabilities.contains(&Capability::MessagesWrite));
        assert!(observer.capabilities.contains(&Capability::MessagesRead));

        // Broadcast roles use the same capability variants.
        assert!(author.capabilities.contains(&Capability::MessagesRead));
        assert!(author.capabilities.contains(&Capability::MessagesWrite));
        assert!(subscriber.capabilities.contains(&Capability::MessagesRead));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_ceiling_admin_has_no_capabilities() {
        let ceiling = CapabilityCeiling::new(std::iter::empty());
        let admin = builtin_admin(&ceiling);
        assert!(admin.capabilities.is_empty());
    }

    #[test]
    fn empty_ceiling_member_has_no_capabilities() {
        let ceiling = CapabilityCeiling::new(std::iter::empty());
        let member = builtin_member(&ceiling);
        assert!(member.capabilities.is_empty());
    }

    #[test]
    fn ceiling_with_custom_capability() {
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::Custom("special-action".to_owned()),
        ]);
        assert!(ceiling.contains(&Capability::Custom("special-action".to_owned())));
        assert!(!ceiling.contains(&Capability::Custom("other-action".to_owned())));
    }

    #[test]
    fn ceiling_serialization_roundtrip() {
        let ceiling = test_ceiling();
        let json = serde_json::to_string(&ceiling).unwrap();
        let deserialized: CapabilityCeiling = serde_json::from_str(&json).unwrap();
        assert_eq!(ceiling, deserialized);
    }

    #[test]
    fn multiple_role_assignments_tracked_independently() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![]).unwrap();

        state.members.insert("did:dht:alice".to_owned());
        state.members.insert("did:dht:bob".to_owned());

        assign_role(&mut state, "did:dht:alice", "member", "did:dht:creator").unwrap();
        assign_role(&mut state, "did:dht:bob", "observer", "did:dht:creator").unwrap();

        // Alice is member.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        // Bob is observer -- no write.
        assert!(!state.member_has_capability("did:dht:bob", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:bob", &Capability::MessagesRead));
    }

    // -----------------------------------------------------------------------
    // MessagePack roundtrip -- SCP-PERSIST-001
    // -----------------------------------------------------------------------

    /// SCP-PERSIST-001: `ContextRoleState` survives `MessagePack` roundtrip.
    #[test]
    fn context_role_state_msgpack_roundtrip() {
        let ceiling = test_ceiling();
        let custom = RoleDefinition::new(
            "content-mod",
            HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::MemberRemove,
            ]),
            &ceiling,
        )
        .unwrap();

        let mut state =
            ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![custom]).unwrap();

        // Add a second member with a non-admin role.
        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "content-mod",
            "did:dht:creator",
        )
        .unwrap();

        // Serialize to MessagePack.
        let bytes = rmp_serde::to_vec(&state).expect("ContextRoleState serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize back.
        let decoded: ContextRoleState =
            rmp_serde::from_slice(&bytes).expect("ContextRoleState deserialization failed");

        assert_eq!(state, decoded);
    }

    // -----------------------------------------------------------------------
    // validate_role_name (M3)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_role_name_accepts_valid_names() {
        assert!(validate_role_name("custom-role").is_ok());
        assert!(validate_role_name("my-role-1").is_ok());
        assert!(validate_role_name("role123").is_ok());
        assert!(validate_role_name("a").is_ok());
        assert!(validate_role_name("role_with_underscores").is_ok());
    }

    #[test]
    fn validate_role_name_rejects_empty() {
        let err = validate_role_name("").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_too_long() {
        let long_name = "a".repeat(MAX_ROLE_NAME_LENGTH + 1);
        let err = validate_role_name(&long_name).unwrap_err();
        assert!(
            matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("maximum length")),
            "expected max length error, got: {err}"
        );
    }

    #[test]
    fn validate_role_name_rejects_reserved_names() {
        for name in &[
            "admin",
            "moderator",
            "member",
            "observer",
            "author",
            "subscriber",
        ] {
            let err = validate_role_name(name).unwrap_err();
            assert!(
                matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("reserved")),
                "expected reserved name error for '{name}', got: {err}"
            );
        }
    }

    #[test]
    fn validate_role_name_rejects_uppercase() {
        let err = validate_role_name("Admin").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_leading_hyphen() {
        let err = validate_role_name("-leading").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_trailing_underscore() {
        let err = validate_role_name("trailing_").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn validate_role_name_rejects_spaces() {
        let err = validate_role_name("has space").unwrap_err();
        assert!(matches!(err, RoleError::InvalidRoleName(_)));
    }

    #[test]
    fn role_definition_new_validates_name() {
        let ceiling = test_ceiling();
        let caps = HashSet::from([Capability::MessagesRead]);
        let err = RoleDefinition::new("admin", caps, &ceiling).unwrap_err();
        assert!(
            matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("reserved")),
            "expected reserved name error, got: {err}"
        );
    }

    #[test]
    fn context_role_state_rejects_reserved_custom_role() {
        let ceiling = test_ceiling();
        let custom =
            RoleDefinition::new_unchecked("member", HashSet::from([Capability::MessagesRead]));
        let err =
            ContextRoleState::new("ctx-1", "did:dht:creator", ceiling, vec![custom]).unwrap_err();
        assert!(
            matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("reserved")),
            "expected reserved name error, got: {err}"
        );
    }
}
