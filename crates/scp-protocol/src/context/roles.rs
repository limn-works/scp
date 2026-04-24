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
//! - `moderator` -- `MessagesRead`, `MessagesWrite`, `OutletQueryAll`,
//!   `OutletCallAll`, `MemberRemove`, `GovernancePropose` (§5.9 elected
//!   moderators).
//! - `member` -- `MessagesRead`, `MessagesWrite`, `OutletQueryAll`,
//!   `OutletCallAll`.
//! - `observer` -- `MessagesRead` only.
//!
//! Broadcast-specific roles:
//! - `author` -- `MessagesWrite`, `MessagesRead`, `OutletQueryAll`,
//!   `OutletCallAll`.
//! - `subscriber` -- `MessagesRead` only.
//!
//! Custom roles are defined at context creation with arbitrary capability
//! subsets of the ceiling.
//!
//! See ADR-009 in `.docs/adrs/phase-2.md` for the full specification.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use scp_primitives::Clock;

use super::ContextError;
use crate::crypto::ucan::nonce::generate_nonce;

// ---------------------------------------------------------------------------
// OutletId
// ---------------------------------------------------------------------------

/// Identifier for an outlet registered within a context.
///
/// This is a simple string type alias. The full `OutletRegistration` type is
/// defined in `params.rs`; this type identifies a specific outlet for
/// capability scoping (e.g., `OutletCall(outlet_id)`, `OutletQuery(outlet_id)`).
pub type OutletId = String;

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
    /// Invoke a specific registered Query (read-only) outlet, identified by
    /// [`OutletId`] (§5.4.2).
    OutletQuery(OutletId),
    /// Invoke any registered Query outlet in the context (§5.4.2).
    OutletQueryAll,
    /// Invoke a specific registered Action (mutating) outlet, identified by
    /// [`OutletId`] (§5.4.2).
    OutletCall(OutletId),
    /// Invoke any registered Action outlet in the context (§5.4.2).
    OutletCallAll,
    /// Register new outlets in the context.
    OutletRegister,
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
    /// Cross-context outlet interface exposure (spec section 6.2).
    OutletInterface,
    /// Bridge connector participation (spec section 12).
    Bridging,
    /// Real-time voice communication via delegated media transport (spec section 10.9.1).
    MediaVoice,
    /// Real-time video communication via delegated media transport (spec section 10.9.1).
    MediaVideo,
    /// Screen sharing via delegated media transport (spec section 10.9.1).
    MediaScreenShare,
    /// Ban a member from the context, revoking all access permanently (spec section 5.3).
    /// Gates the `Revoke` governance action.
    MemberBan,
    /// Edit context operational metadata (spec section 5.7, §5.3.1).
    MetadataEdit,
    /// Context-specific custom capability.
    Custom(String),
}

impl Capability {
    /// Creates a capability from a string name.
    ///
    /// Recognized names: `"messages:read"`, `"messages:write"`,
    /// `"outlet:query:*"`, `"outlet:call:*"`, `"outlet:register"`,
    /// `"member:invite"`, `"member:remove"`, `"role:assign"`,
    /// `"governance:propose"`, `"governance:vote"`, `"context:close"`,
    /// `"context:child:create"`, `"outlet:interface"`, `"bridging"`,
    /// `"media:voice"`, `"media:video"`, `"media:screen_share"`,
    /// `"member:ban"`, `"metadata:edit"`.
    /// Names starting with `"outlet:query:"` are parsed as `OutletQuery(id)`.
    /// Names starting with `"outlet:call:"` are parsed as `OutletCall(id)`.
    /// Names starting with `"custom:"` are parsed as `Custom(remainder)`.
    /// Anything else maps to `Custom(name)`.
    #[must_use]
    pub fn new(name: impl AsRef<str>) -> Self {
        match name.as_ref() {
            "messages:read" => Self::MessagesRead,
            "messages:write" => Self::MessagesWrite,
            "outlet:query:*" => Self::OutletQueryAll,
            "outlet:call:*" => Self::OutletCallAll,
            "outlet:register" => Self::OutletRegister,
            "member:invite" => Self::MemberInvite,
            "member:remove" => Self::MemberRemove,
            "role:assign" => Self::RoleAssign,
            "governance:propose" => Self::GovernancePropose,
            "governance:vote" => Self::GovernanceVote,
            "context:close" => Self::ContextClose,
            "context:child:create" => Self::ChildContextCreate,
            "outlet:interface" => Self::OutletInterface,
            "bridging" => Self::Bridging,
            "media:voice" => Self::MediaVoice,
            "media:video" => Self::MediaVideo,
            "media:screen_share" => Self::MediaScreenShare,
            "member:ban" => Self::MemberBan,
            "metadata:edit" => Self::MetadataEdit,
            other => other.strip_prefix("outlet:query:").map_or_else(
                || {
                    other.strip_prefix("outlet:call:").map_or_else(
                        || {
                            other.strip_prefix("custom:").map_or_else(
                                || Self::Custom(other.to_owned()),
                                |custom_name| Self::Custom(custom_name.to_owned()),
                            )
                        },
                        |id| Self::OutletCall(id.to_owned()),
                    )
                },
                |id| Self::OutletQuery(id.to_owned()),
            ),
        }
    }

    /// Returns the canonical input name of this capability.
    ///
    /// For [`OutletQuery`](Self::OutletQuery) and [`OutletCall`](Self::OutletCall)
    /// variants, includes the outlet ID (e.g. `"outlet:query:my_outlet"`,
    /// `"outlet:call:my_outlet"`). For [`Custom`](Self::Custom) variants,
    /// returns the raw name without prefix (e.g. `"foo"`, not `"custom:foo"`).
    ///
    /// **Note:** This differs from [`Display`](std::fmt::Display) for Custom
    /// variants — Display prefixes `"custom:"` for disambiguation in logs.
    /// Both `new(name())` and `new(to_string())` roundtrip correctly.
    #[must_use]
    pub fn name(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::MessagesRead => std::borrow::Cow::Borrowed("messages:read"),
            Self::MessagesWrite => std::borrow::Cow::Borrowed("messages:write"),
            Self::OutletQuery(id) => std::borrow::Cow::Owned(format!("outlet:query:{id}")),
            Self::OutletQueryAll => std::borrow::Cow::Borrowed("outlet:query:*"),
            Self::OutletCall(id) => std::borrow::Cow::Owned(format!("outlet:call:{id}")),
            Self::OutletCallAll => std::borrow::Cow::Borrowed("outlet:call:*"),
            Self::OutletRegister => std::borrow::Cow::Borrowed("outlet:register"),
            Self::MemberInvite => std::borrow::Cow::Borrowed("member:invite"),
            Self::MemberRemove => std::borrow::Cow::Borrowed("member:remove"),
            Self::RoleAssign => std::borrow::Cow::Borrowed("role:assign"),
            Self::GovernancePropose => std::borrow::Cow::Borrowed("governance:propose"),
            Self::GovernanceVote => std::borrow::Cow::Borrowed("governance:vote"),
            Self::ContextClose => std::borrow::Cow::Borrowed("context:close"),
            Self::ChildContextCreate => std::borrow::Cow::Borrowed("context:child:create"),
            Self::OutletInterface => std::borrow::Cow::Borrowed("outlet:interface"),
            Self::Bridging => std::borrow::Cow::Borrowed("bridging"),
            Self::MediaVoice => std::borrow::Cow::Borrowed("media:voice"),
            Self::MediaVideo => std::borrow::Cow::Borrowed("media:video"),
            Self::MediaScreenShare => std::borrow::Cow::Borrowed("media:screen_share"),
            Self::MemberBan => std::borrow::Cow::Borrowed("member:ban"),
            Self::MetadataEdit => std::borrow::Cow::Borrowed("metadata:edit"),
            Self::Custom(name) => std::borrow::Cow::Borrowed(name.as_str()),
        }
    }

    /// Returns the `(resource, action)` pair for UCAN capability URIs.
    ///
    /// The canonical user-facing format uses colons (e.g., `"outlet:call:*"`),
    /// but UCAN URIs use `{resource}:{action}` where `resource` is a single
    /// underscore-joined token. This method bridges the two formats:
    ///
    /// - `outlet:query:*`         -> `("outlet_query", "*")`
    /// - `outlet:query:calculator` -> `("outlet_query", "calculator")`
    /// - `outlet:call:*`          -> `("outlet_call", "*")`
    /// - `outlet:call:calculator`  -> `("outlet_call", "calculator")`
    /// - `context:child:create`   -> `("context_child", "create")`
    /// - `messages:write`         -> `("messages", "write")`
    /// - `context:close`          -> `("context", "close")`
    /// - `role:assign`            -> `("role", "assign")`
    /// - `bridging`               -> `("bridging", "*")`
    ///
    /// The returned strings are suitable for constructing
    /// [`CapabilityUri`](crate::crypto::ucan::capability::CapabilityUri) values
    /// and for building ceiling string sets (`{resource}:{action}`).
    ///
    /// See issue #1293 for the mismatch this method resolves and §5.4.2.1 for
    /// the outlet stem parser semantics.
    #[must_use]
    pub fn ucan_resource_action(&self) -> (std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>) {
        match self {
            Self::MessagesRead => (
                std::borrow::Cow::Borrowed("messages"),
                std::borrow::Cow::Borrowed("read"),
            ),
            Self::MessagesWrite => (
                std::borrow::Cow::Borrowed("messages"),
                std::borrow::Cow::Borrowed("write"),
            ),
            Self::OutletQuery(id) => (
                std::borrow::Cow::Borrowed("outlet_query"),
                std::borrow::Cow::Borrowed(id.as_str()),
            ),
            Self::OutletQueryAll => (
                std::borrow::Cow::Borrowed("outlet_query"),
                std::borrow::Cow::Borrowed("*"),
            ),
            Self::OutletCall(id) => (
                std::borrow::Cow::Borrowed("outlet_call"),
                std::borrow::Cow::Borrowed(id.as_str()),
            ),
            Self::OutletCallAll => (
                std::borrow::Cow::Borrowed("outlet_call"),
                std::borrow::Cow::Borrowed("*"),
            ),
            Self::OutletRegister => (
                std::borrow::Cow::Borrowed("outlet"),
                std::borrow::Cow::Borrowed("register"),
            ),
            Self::MemberInvite => (
                std::borrow::Cow::Borrowed("member"),
                std::borrow::Cow::Borrowed("invite"),
            ),
            Self::MemberRemove => (
                std::borrow::Cow::Borrowed("member"),
                std::borrow::Cow::Borrowed("remove"),
            ),
            Self::RoleAssign => (
                std::borrow::Cow::Borrowed("role"),
                std::borrow::Cow::Borrowed("assign"),
            ),
            Self::GovernancePropose => (
                std::borrow::Cow::Borrowed("governance"),
                std::borrow::Cow::Borrowed("propose"),
            ),
            Self::GovernanceVote => (
                std::borrow::Cow::Borrowed("governance"),
                std::borrow::Cow::Borrowed("vote"),
            ),
            Self::ContextClose => (
                std::borrow::Cow::Borrowed("context"),
                std::borrow::Cow::Borrowed("close"),
            ),
            Self::ChildContextCreate => (
                std::borrow::Cow::Borrowed("context_child"),
                std::borrow::Cow::Borrowed("create"),
            ),
            Self::OutletInterface => (
                std::borrow::Cow::Borrowed("outlet"),
                std::borrow::Cow::Borrowed("interface"),
            ),
            Self::Bridging => (
                std::borrow::Cow::Borrowed("bridging"),
                std::borrow::Cow::Borrowed("*"),
            ),
            Self::MediaVoice => (
                std::borrow::Cow::Borrowed("media"),
                std::borrow::Cow::Borrowed("voice"),
            ),
            Self::MediaVideo => (
                std::borrow::Cow::Borrowed("media"),
                std::borrow::Cow::Borrowed("video"),
            ),
            Self::MediaScreenShare => (
                std::borrow::Cow::Borrowed("media"),
                std::borrow::Cow::Borrowed("screen_share"),
            ),
            Self::MemberBan => (
                std::borrow::Cow::Borrowed("member"),
                std::borrow::Cow::Borrowed("ban"),
            ),
            Self::MetadataEdit => (
                std::borrow::Cow::Borrowed("metadata"),
                std::borrow::Cow::Borrowed("edit"),
            ),
            Self::Custom(name) => {
                // Custom capabilities may use either colon or underscore format.
                // Split on the last colon to separate resource from action.
                if let Some((resource, action)) = name.rsplit_once(':') {
                    (
                        std::borrow::Cow::Owned(resource.replace(':', "_")),
                        std::borrow::Cow::Borrowed(action),
                    )
                } else {
                    // No colon — treat entire name as resource with wildcard action.
                    (
                        std::borrow::Cow::Borrowed(name.as_str()),
                        std::borrow::Cow::Borrowed("*"),
                    )
                }
            }
        }
    }

    /// Returns the UCAN capability name string in `{resource}:{action}` format.
    ///
    /// This is the format used in capability ceiling sets and
    /// [`CapabilityUri::capability_name()`](crate::crypto::ucan::capability::CapabilityUri::capability_name).
    /// Unlike [`name()`](Self::name) which returns the canonical user-facing
    /// colon format, this returns the UCAN-internal format with underscores
    /// for multi-segment resources.
    ///
    /// # Examples
    ///
    /// ```
    /// use scp_protocol::context::roles::Capability;
    ///
    /// assert_eq!(Capability::OutletCallAll.ucan_capability_name(), "outlet_call:*");
    /// assert_eq!(Capability::OutletQueryAll.ucan_capability_name(), "outlet_query:*");
    /// assert_eq!(Capability::MessagesWrite.ucan_capability_name(), "messages:write");
    /// assert_eq!(Capability::ChildContextCreate.ucan_capability_name(), "context_child:create");
    /// ```
    #[must_use]
    pub fn ucan_capability_name(&self) -> String {
        let (resource, action) = self.ucan_resource_action();
        format!("{resource}:{action}")
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessagesRead => write!(f, "messages:read"),
            Self::MessagesWrite => write!(f, "messages:write"),
            Self::OutletQuery(id) => write!(f, "outlet:query:{id}"),
            Self::OutletQueryAll => write!(f, "outlet:query:*"),
            Self::OutletCall(id) => write!(f, "outlet:call:{id}"),
            Self::OutletCallAll => write!(f, "outlet:call:*"),
            Self::OutletRegister => write!(f, "outlet:register"),
            Self::MemberInvite => write!(f, "member:invite"),
            Self::MemberRemove => write!(f, "member:remove"),
            Self::RoleAssign => write!(f, "role:assign"),
            Self::GovernancePropose => write!(f, "governance:propose"),
            Self::GovernanceVote => write!(f, "governance:vote"),
            Self::ContextClose => write!(f, "context:close"),
            Self::ChildContextCreate => write!(f, "context:child:create"),
            Self::OutletInterface => write!(f, "outlet:interface"),
            Self::Bridging => write!(f, "bridging"),
            Self::MediaVoice => write!(f, "media:voice"),
            Self::MediaVideo => write!(f, "media:video"),
            Self::MediaScreenShare => write!(f, "media:screen_share"),
            Self::MemberBan => write!(f, "member:ban"),
            Self::MetadataEdit => write!(f, "metadata:edit"),
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
    /// definition. `OutletQuery(id)` is considered within the ceiling if either
    /// `OutletQuery(id)` or `OutletQueryAll` is in the ceiling. Likewise
    /// `OutletCall(id)` is implied by `OutletCallAll`.
    #[must_use]
    pub fn contains(&self, capability: &Capability) -> bool {
        if self.capabilities.contains(capability) {
            return true;
        }
        // OutletQuery(id) is implicitly allowed if OutletQueryAll is in the ceiling.
        if let Capability::OutletQuery(_) = capability {
            return self.capabilities.contains(&Capability::OutletQueryAll);
        }
        // OutletCall(id) is implicitly allowed if OutletCallAll is in the ceiling.
        if let Capability::OutletCall(_) = capability {
            return self.capabilities.contains(&Capability::OutletCallAll);
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

    /// Returns the capabilities as UCAN-formatted string names.
    ///
    /// Each capability is converted to its UCAN wire-format name via
    /// [`Capability::ucan_capability_name`]. Useful for passing ceilings
    /// to UCAN mint/delegate operations.
    #[must_use]
    pub fn to_ucan_string_set(&self) -> HashSet<String> {
        self.capabilities
            .iter()
            .map(Capability::ucan_capability_name)
            .collect()
    }
}

/// Returns the default capability ceiling for new contexts.
///
/// Includes all standard SCP capabilities: messaging, outlet management, role
/// assignment, membership control, governance, and context close. Used by
/// all FFI bridges when no explicit ceiling is provided.
#[must_use]
pub fn default_ceiling() -> CapabilityCeiling {
    CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletRegister,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
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
/// Members can read and write messages and invoke any registered Query or
/// Action outlet. Capabilities are intersected with the ceiling -- if a
/// capability is not in the ceiling, it is not granted.
///
/// See ADR-009 acceptance criterion 2 and §5.5.1 / §5.4.2.
#[must_use]
pub fn builtin_member(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
    ]);
    let capabilities = desired
        .into_iter()
        .filter(|cap| ceiling.contains(cap))
        .collect();
    RoleDefinition::new_unchecked("member", capabilities)
}

/// Returns the `moderator` built-in role definition.
///
/// Moderators can read/write messages, invoke Query and Action outlets,
/// remove members, and propose governance actions. This fills the gap
/// between `member` (no moderation power) and `admin` (full control).
/// Referenced in §5.9 as "elected moderators" governance pattern.
/// Capabilities are intersected with the ceiling.
///
/// See ADR-009 acceptance criterion 2 and §5.5.1 / §5.4.2.
#[must_use]
pub fn builtin_moderator(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
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
/// Authors can write and read messages and invoke any registered Query or
/// Action outlet. Designed for one-to-many publishing scenarios
/// (spec section 5.14). Capabilities are intersected with the ceiling.
///
/// See ADR-009 acceptance criterion 2 and §5.5.1 / §5.4.2.
#[must_use]
pub fn builtin_author(ceiling: &CapabilityCeiling) -> RoleDefinition {
    let desired = HashSet::from([
        Capability::MessagesWrite,
        Capability::MessagesRead,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
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
    /// Suspended capabilities per member DID. A member whose DID appears here
    /// is denied the listed capabilities even if their role grants them.
    #[serde(default)]
    pub suspended_capabilities: HashMap<String, HashSet<Capability>>,
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
        clock: &dyn Clock,
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

        let tokens = mint_role_tokens(&context_id, &creator_did, &creator_did, &admin_role, clock);

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
            suspended_capabilities: HashMap::new(),
        })
    }

    /// Returns `true` if the given member has the specified capability.
    ///
    /// Suspension-aware: returns `false` if the capability is in the member's
    /// suspended set, even if their role grants it.
    #[must_use]
    pub fn member_has_capability(&self, member_did: &str, capability: &Capability) -> bool {
        // Check suspension first.
        if self
            .suspended_capabilities
            .get(member_did)
            .is_some_and(|suspended| suspended.contains(capability))
        {
            return false;
        }
        self.member_capabilities
            .get(member_did)
            .is_some_and(|caps| caps.contains(capability))
    }

    /// Suspends specific capabilities for a member.
    ///
    /// The capabilities are added to the member's suspended set. While
    /// suspended, `member_has_capability` returns `false` for these
    /// capabilities even if the member's role grants them.
    pub fn suspend_capabilities(
        &mut self,
        member_did: &str,
        capabilities: impl IntoIterator<Item = Capability>,
    ) {
        self.suspended_capabilities
            .entry(member_did.to_owned())
            .or_default()
            .extend(capabilities);
    }

    /// Restores previously suspended capabilities for a member.
    ///
    /// Removes the specified capabilities from the member's suspended set.
    /// If the member has no remaining suspensions, the entry is removed.
    pub fn restore_capabilities(&mut self, member_did: &str, capabilities: &[Capability]) {
        if let Some(suspended) = self.suspended_capabilities.get_mut(member_did) {
            for cap in capabilities {
                suspended.remove(cap);
            }
            if suspended.is_empty() {
                self.suspended_capabilities.remove(member_did);
            }
        }
    }

    /// Suspends ALL capabilities for a member.
    ///
    /// Copies every capability from the member's current capability set into
    /// their suspended set. Equivalent to a full application-level block.
    pub fn suspend_all(&mut self, member_did: &str) {
        if let Some(caps) = self.member_capabilities.get(member_did) {
            let all_caps: HashSet<Capability> = caps.clone();
            self.suspended_capabilities
                .insert(member_did.to_owned(), all_caps);
        }
    }

    /// Prunes a member's suspended capabilities to only those that the
    /// `new_role_capabilities` set actually grants. Called by
    /// [`assign_role`] and [`system_assign_role`] after a role
    /// replacement so suspensions for capabilities the member no longer
    /// has become meaningless entries and are dropped.
    ///
    /// If all of a member's suspensions become meaningless, the entire
    /// entry is removed from the map to avoid leaving dangling empty
    /// sets.
    ///
    /// Semantics: suspensions PERSIST across role changes for
    /// capabilities the new role still grants (a banned voter who
    /// becomes an admin is still banned from voting), but are dropped
    /// for capabilities the new role no longer grants (a banned voter
    /// who becomes an observer has no vote to suspend).
    pub fn prune_suspensions_to_role_grants(
        &mut self,
        member_did: &str,
        new_role_capabilities: &HashSet<Capability>,
    ) {
        if let Some(suspended) = self.suspended_capabilities.get_mut(member_did) {
            suspended.retain(|cap| new_role_capabilities.contains(cap));
            if suspended.is_empty() {
                self.suspended_capabilities.remove(member_did);
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
    clock: &dyn Clock,
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
    let tokens = mint_role_tokens(
        &state.context_id,
        &state.creator_did,
        member_did,
        &role_def,
        clock,
    );

    // 5. Update state: replace any previous assignment.
    let assignment = RoleAssignment {
        member_did: member_did.to_owned(),
        role_name: role_name.to_owned(),
        tokens: tokens.clone(),
    };
    state.assignments.insert(member_did.to_owned(), assignment);
    state
        .member_capabilities
        .insert(member_did.to_owned(), role_def.capabilities.clone());

    // Prune suspensions outside the new role's grant set. Otherwise
    // `suspended_capabilities` would retain entries for capabilities
    // the member no longer holds, which could accidentally re-engage
    // if the member cycles back to a granting role later.
    state.prune_suspensions_to_role_grants(member_did, &role_def.capabilities);

    Ok(tokens)
}

/// System-level role assignment that bypasses the `RoleAssign` capability check.
///
/// Used by the governance consequence engine when demoting a member. The system
/// must be able to enforce role demotions regardless of which member (if any)
/// currently holds `RoleAssign`. All other checks (member existence, role
/// existence) still apply.
///
/// # Errors
///
/// Returns [`RoleError::MemberNotInContext`] if the member is not in the
/// context, or [`RoleError::RoleNotFound`] if the role doesn't exist.
// SAFETY: Called only by governance consequence engine. Do not use for direct role assignment.
// This must remain `pub` (not `pub(crate)`) because scp-runtime calls it
// from enforce_assign_role(). Hidden from public API docs.
#[doc(hidden)]
pub fn system_assign_role(
    state: &mut ContextRoleState,
    member_did: &str,
    role_name: &str,
    clock: &dyn Clock,
) -> Result<Vec<UcanToken>, RoleError> {
    // 1. Verify member is in the context.
    if !state.members.contains(member_did) {
        return Err(RoleError::MemberNotInContext(member_did.to_owned()));
    }

    // 2. Look up the role definition.
    let role_def = state
        .role_definitions
        .get(role_name)
        .ok_or_else(|| RoleError::RoleNotFound(role_name.to_owned()))?
        .clone();

    // 3. Mint UCAN tokens for each capability in the role.
    let tokens = mint_role_tokens(
        &state.context_id,
        &state.creator_did,
        member_did,
        &role_def,
        clock,
    );

    // 4. Update state: replace any previous assignment.
    let assignment = RoleAssignment {
        member_did: member_did.to_owned(),
        role_name: role_name.to_owned(),
        tokens: tokens.clone(),
    };
    state.assignments.insert(member_did.to_owned(), assignment);
    state
        .member_capabilities
        .insert(member_did.to_owned(), role_def.capabilities.clone());

    // Same prune-suspensions-to-role-grants invariant as
    // `assign_role` — system-level reassignment must also clean up
    // stale suspensions so a consequence-engine-triggered demotion
    // cannot leave dangling entries for capabilities the demoted
    // role no longer grants.
    state.prune_suspensions_to_role_grants(member_did, &role_def.capabilities);

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
    clock: &dyn Clock,
) -> Vec<UcanToken> {
    role.capabilities
        .iter()
        .map(|cap| {
            let (resource, action) = cap.ucan_resource_action();
            let att = UcanAttestation {
                with: format!("scp:ctx:{context_id}/{resource}:{action}"),
                can: action.into_owned(),
            };
            UcanToken {
                iss: creator_did.to_owned(),
                aud: member_did.to_owned(),
                att: vec![att],
                nnc: generate_nonce(clock),
            }
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
            Capability::OutletCallAll,
            Capability::OutletRegister,
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
            Capability::OutletCall("tool-1".to_owned()),
            Capability::OutletCallAll,
            Capability::OutletRegister,
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
        let cap = Capability::OutletCall("my-tool".to_owned());
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
            format!("{}", Capability::OutletCall("foo".to_owned())),
            "outlet:call:foo"
        );
        assert_eq!(format!("{}", Capability::OutletCallAll), "outlet:call:*");
        assert_eq!(format!("{}", Capability::OutletRegister), "outlet:register");
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
    fn capability_display_new_roundtrip() {
        // All standard variants must roundtrip through Display → new.
        let standard_caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCall("my-tool".to_owned()),
            Capability::OutletCallAll,
            Capability::OutletRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::OutletInterface,
            Capability::Bridging,
            Capability::MediaVoice,
            Capability::MediaVideo,
            Capability::MediaScreenShare,
            Capability::MemberBan,
            Capability::MetadataEdit,
        ];
        for cap in &standard_caps {
            let displayed = cap.to_string();
            let roundtripped = Capability::new(&displayed);
            assert_eq!(
                *cap, roundtripped,
                "Display→new roundtrip failed for {cap:?} (displayed as {displayed:?})"
            );
        }

        // Custom variants must also roundtrip through Display → new.
        // This was a bug: Display output "custom:my-cap" but new() didn't
        // strip the "custom:" prefix, creating Custom("custom:my-cap").
        //
        // Note: Custom names starting with "custom:" are ambiguous through
        // new() — the prefix is always stripped. Avoid such names.
        let custom_caps = vec![
            Capability::Custom("my-cap".to_owned()),
            Capability::Custom("x".to_owned()),
            Capability::Custom("some:nested:name".to_owned()),
            Capability::Custom(String::new()),
        ];
        for cap in &custom_caps {
            let displayed = cap.to_string();
            let roundtripped = Capability::new(&displayed);
            assert_eq!(
                *cap, roundtripped,
                "Display→new roundtrip failed for {cap:?} (displayed as {displayed:?})"
            );
        }

        // name() → new() roundtrip: name() returns the raw name (no prefix
        // for Custom), and new() falls through to Custom(...) for unrecognized
        // names, so the roundtrip holds.
        for cap in standard_caps.iter().chain(&custom_caps) {
            let via_name = Capability::new(cap.name());
            assert_eq!(
                *cap,
                via_name,
                "name()→new() roundtrip failed for {cap:?} (name = {:?})",
                cap.name()
            );
        }
    }

    #[test]
    fn capability_serialization_roundtrip() {
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCall("search".to_owned()),
            Capability::OutletCallAll,
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
        let ceiling = CapabilityCeiling::new([Capability::OutletCallAll, Capability::MessagesRead]);
        assert!(ceiling.contains(&Capability::OutletCall("any-tool".to_owned())));
        assert!(ceiling.contains(&Capability::OutletCall("another-tool".to_owned())));
    }

    #[test]
    fn ceiling_specific_tool_does_not_imply_all() {
        let ceiling = CapabilityCeiling::new([
            Capability::OutletCall("specific-tool".to_owned()),
            Capability::MessagesRead,
        ]);
        assert!(ceiling.contains(&Capability::OutletCall("specific-tool".to_owned())));
        assert!(!ceiling.contains(&Capability::OutletCall("other-tool".to_owned())));
        assert!(!ceiling.contains(&Capability::OutletCallAll));
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
        let ceiling = CapabilityCeiling::new([Capability::OutletCallAll]);
        assert!(check_ceiling(
            &ceiling,
            &Capability::OutletCall("test-tool".to_owned())
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
        assert!(member.capabilities.contains(&Capability::OutletCallAll));
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
        assert!(moderator.capabilities.contains(&Capability::OutletCallAll));
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
            Capability::OutletCallAll,
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
        assert!(author.capabilities.contains(&Capability::OutletCallAll));
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
        // If OutletCallAll / OutletQueryAll are not in the ceiling, member should not have them.
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        let member = builtin_member(&ceiling);
        assert!(!member.capabilities.contains(&Capability::OutletCallAll));
        assert!(!member.capabilities.contains(&Capability::OutletQueryAll));
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
        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

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

        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_primitives::SystemClock,
        )
        .unwrap();
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

        let result = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![bad_custom],
            &scp_primitives::SystemClock,
        );
        assert!(result.is_err());
    }

    #[test]
    fn context_role_state_creator_has_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling.clone(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

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
        let state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        assert!(!state.member_has_capability("did:dht:nobody", &Capability::MessagesRead));
    }

    // -----------------------------------------------------------------------
    // assign_role
    // -----------------------------------------------------------------------

    #[test]
    fn assign_role_succeeds_for_authorized_assigner() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Add a member to the context.
        state.members.insert("did:dht:alice".to_owned());

        let result = assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        );
        assert!(result.is_ok());

        let tokens = result.unwrap();
        // member role has 3 capabilities -> 3 tokens.
        assert_eq!(tokens.len(), 3);

        // Alice should now have member capabilities.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::OutletCallAll));
    }

    #[test]
    fn assign_role_fails_for_unauthorized_assigner() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Add members.
        state.members.insert("did:dht:alice".to_owned());
        state.members.insert("did:dht:bob".to_owned());

        // Assign alice as member (no RoleAssign capability).
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Alice tries to assign bob -- should fail.
        let result = assign_role(
            &mut state,
            "did:dht:bob",
            "member",
            "did:dht:alice",
            &scp_primitives::SystemClock,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::AssignerNotAuthorized(ref did) if did == "did:dht:alice"
        ));
    }

    #[test]
    fn assign_role_fails_for_nonexistent_member() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        let result = assign_role(
            &mut state,
            "did:dht:nobody",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RoleError::MemberNotInContext(ref did) if did == "did:dht:nobody"
        ));
    }

    #[test]
    fn assign_role_fails_for_nonexistent_role() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let result = assign_role(
            &mut state,
            "did:dht:alice",
            "nonexistent",
            "did:dht:creator",
            &scp_primitives::SystemClock,
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
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Assign as member first.
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        // Reassign as observer.
        assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(!state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        let assignment = state.assignments.get("did:dht:alice").unwrap();
        assert_eq!(assignment.role_name, "observer");
    }

    #[test]
    fn assign_role_prunes_suspensions_outside_new_role_grants() {
        // Reassigning from a role that granted GovernanceVote to a
        // role that does NOT grant it must prune the now-meaningless
        // suspended-capability entry.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b5-prune",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Start Alice as member (grants MessagesWrite, GovernanceVote, etc).
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Suspend Alice's GovernanceVote capability.
        state.suspend_capabilities("did:dht:alice", [Capability::GovernanceVote]);
        assert!(
            state
                .suspended_capabilities
                .get("did:dht:alice")
                .unwrap()
                .contains(&Capability::GovernanceVote)
        );

        // Demote Alice to observer (which only grants MessagesRead).
        assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // The GovernanceVote suspension is meaningless now — observer
        // doesn't grant GovernanceVote. The prune should have dropped
        // the empty set entirely.
        assert!(
            !state.suspended_capabilities.contains_key("did:dht:alice"),
            "stale suspension set must be dropped when new role grants none of the suspended capabilities"
        );
    }

    #[test]
    fn assign_role_retains_suspensions_still_granted_by_new_role() {
        // Reassigning to a role that still grants the suspended
        // capability must keep the suspension in place: a banned
        // voter promoted to admin is still banned from voting.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b5-retain",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        // Start Alice as member.
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Suspend GovernanceVote.
        state.suspend_capabilities("did:dht:alice", [Capability::GovernanceVote]);

        // Promote Alice to admin (which also grants GovernanceVote).
        assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // The GovernanceVote suspension must still be in place.
        assert!(
            state
                .suspended_capabilities
                .get("did:dht:alice")
                .is_some_and(|s| s.contains(&Capability::GovernanceVote)),
            "suspension must persist across role change when new role still grants the capability"
        );
        assert!(
            !state.member_has_capability("did:dht:alice", &Capability::GovernanceVote),
            "member_has_capability must still block the suspended capability"
        );
    }

    #[test]
    fn assign_role_prunes_mixed_suspensions() {
        // When only some suspensions are outside the new role's
        // grants, only those specific entries are dropped — the
        // rest persist.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b5-mixed",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Suspend BOTH GovernanceVote (not granted by observer) AND
        // MessagesRead (still granted by observer).
        state.suspend_capabilities(
            "did:dht:alice",
            [Capability::GovernanceVote, Capability::MessagesRead],
        );

        // Demote to observer.
        assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // GovernanceVote suspension → dropped (observer does not grant it).
        // MessagesRead suspension → retained (observer grants MessagesRead).
        let suspended = state
            .suspended_capabilities
            .get("did:dht:alice")
            .expect("suspension entry must still exist because MessagesRead is retained");
        assert!(!suspended.contains(&Capability::GovernanceVote));
        assert!(suspended.contains(&Capability::MessagesRead));
    }

    #[test]
    fn assign_role_mints_correct_token_format() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(
            &mut state,
            "did:dht:alice",
            "observer",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        assert_eq!(tokens.len(), 1);
        let token = &tokens[0];
        assert_eq!(token.iss, "did:dht:creator");
        assert_eq!(token.aud, "did:dht:alice");
        assert_eq!(token.att.len(), 1);
        assert_eq!(token.att[0].with, "scp:ctx:ctx-1/messages:read");
        assert_eq!(token.att[0].can, "read");
        assert!(!token.nnc.is_empty());
        // Verify nonce format: {millis}-{hex}.
        assert!(token.nnc.contains('-'));
    }

    #[test]
    fn assign_role_admin_grants_all_ceiling_capabilities() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling.clone(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

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

        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());

        let tokens = assign_role(
            &mut state,
            "did:dht:alice",
            "content-mod",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(state.member_has_capability("did:dht:alice", &Capability::MemberRemove));
    }

    // `suspended_capabilities` fold must check the exact capability
    // being queried, so suspending one capability blocks only that
    // capability — other gates remain passable.

    #[test]
    fn suspension_blocks_only_the_exact_capability() {
        // Suspend MessagesWrite. MessagesRead and GovernanceVote
        // must remain passable.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-precise",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        // Use admin so alice has all ceiling capabilities (incl. GovernanceVote/Propose).
        assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Sanity: admin has all four before suspension.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernanceVote));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernancePropose));

        // Suspend only MessagesWrite.
        state.suspend_capabilities("did:dht:alice", [Capability::MessagesWrite]);

        // Only MessagesWrite is blocked. Everything else still passes.
        assert!(!state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernanceVote));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernancePropose));
    }

    #[test]
    fn suspension_blocks_custom_capability_without_escalating() {
        // Suspending a `Capability::Custom` must block the exact
        // capability and leave standard variants passable —
        // surgical, not an escalation to "write access revoked".
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-custom",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Grant a custom capability by injecting it directly into the
        // member's capability set (roles.rs doesn't add custom
        // capabilities via the standard role flow but the fold must
        // handle them correctly if someone does).
        let custom = Capability::Custom("outlet:call:calculator".to_owned());
        state
            .member_capabilities
            .get_mut("did:dht:alice")
            .unwrap()
            .insert(custom.clone());
        assert!(state.member_has_capability("did:dht:alice", &custom));

        // Suspend the custom capability.
        state.suspend_capabilities("did:dht:alice", [custom.clone()]);

        // The custom capability is blocked; standard ones remain passable.
        assert!(!state.member_has_capability("did:dht:alice", &custom));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
    }

    #[test]
    fn suspension_of_mixed_standard_and_custom_capabilities() {
        // Suspending a set containing both a standard variant AND a
        // custom string must block both surgically without affecting
        // unrelated capabilities.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-mixed",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        // Use admin so alice has GovernanceVote/GovernancePropose.
        assign_role(
            &mut state,
            "did:dht:alice",
            "admin",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let custom = Capability::Custom("payments:approve".to_owned());
        state
            .member_capabilities
            .get_mut("did:dht:alice")
            .unwrap()
            .insert(custom.clone());

        state.suspend_capabilities(
            "did:dht:alice",
            [Capability::GovernanceVote, custom.clone()],
        );

        // Both suspended capabilities are blocked.
        assert!(!state.member_has_capability("did:dht:alice", &Capability::GovernanceVote));
        assert!(!state.member_has_capability("did:dht:alice", &custom));
        // Unrelated capabilities remain passable.
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesRead));
        assert!(state.member_has_capability("did:dht:alice", &Capability::GovernancePropose));
    }

    #[test]
    fn restoring_capability_lifts_the_suspension() {
        // restore_capabilities removes entries from the suspended set
        // and drops the whole entry if empty. After restore, the gate
        // passes again.
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-b2-restore",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();
        state.suspend_capabilities("did:dht:alice", [Capability::MessagesWrite]);
        assert!(!state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));

        state.restore_capabilities("did:dht:alice", &[Capability::MessagesWrite]);
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        assert!(
            !state.suspended_capabilities.contains_key("did:dht:alice"),
            "empty suspension set should be removed after full restore"
        );
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
        let nonces: Vec<String> = (0..100)
            .map(|_| generate_nonce(&scp_primitives::SystemClock))
            .collect();
        let unique: HashSet<&String> = nonces.iter().collect();
        assert_eq!(
            nonces.len(),
            unique.len(),
            "all generated nonces should be unique"
        );
    }

    #[test]
    fn nonce_format_is_valid() {
        let nonce = generate_nonce(&scp_primitives::SystemClock);
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
        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        state.members.insert("did:dht:alice".to_owned());
        state.members.insert("did:dht:bob".to_owned());

        assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();
        assign_role(
            &mut state,
            "did:dht:bob",
            "observer",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();

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

        let mut state = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Add a second member with a non-admin role.
        state.members.insert("did:dht:alice".to_owned());
        assign_role(
            &mut state,
            "did:dht:alice",
            "content-mod",
            "did:dht:creator",
            &scp_primitives::SystemClock,
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
        let err = ContextRoleState::new(
            "ctx-1",
            "did:dht:creator",
            ceiling,
            vec![custom],
            &scp_primitives::SystemClock,
        )
        .unwrap_err();
        assert!(
            matches!(&err, RoleError::InvalidRoleName(msg) if msg.contains("reserved")),
            "expected reserved name error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // ucan_resource_action (#1293)
    // -----------------------------------------------------------------------

    #[test]
    fn ucan_resource_action_tool_invoke_all() {
        let (resource, action) = Capability::OutletCallAll.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "*");
    }

    #[test]
    fn ucan_resource_action_tool_invoke_specific() {
        let cap = Capability::OutletCall("calculator".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "calculator");
    }

    #[test]
    fn ucan_resource_action_messages() {
        let (resource, action) = Capability::MessagesRead.ucan_resource_action();
        assert_eq!(resource.as_ref(), "messages");
        assert_eq!(action.as_ref(), "read");

        let (resource, action) = Capability::MessagesWrite.ucan_resource_action();
        assert_eq!(resource.as_ref(), "messages");
        assert_eq!(action.as_ref(), "write");
    }

    #[test]
    fn ucan_resource_action_context_close() {
        let (resource, action) = Capability::ContextClose.ucan_resource_action();
        assert_eq!(resource.as_ref(), "context");
        assert_eq!(action.as_ref(), "close");
    }

    #[test]
    fn ucan_resource_action_child_context_create() {
        let (resource, action) = Capability::ChildContextCreate.ucan_resource_action();
        assert_eq!(resource.as_ref(), "context_child");
        assert_eq!(action.as_ref(), "create");
    }

    #[test]
    fn ucan_resource_action_role_assign() {
        let (resource, action) = Capability::RoleAssign.ucan_resource_action();
        assert_eq!(resource.as_ref(), "role");
        assert_eq!(action.as_ref(), "assign");
    }

    #[test]
    fn ucan_resource_action_bridging() {
        let (resource, action) = Capability::Bridging.ucan_resource_action();
        assert_eq!(resource.as_ref(), "bridging");
        assert_eq!(action.as_ref(), "*");
    }

    #[test]
    fn ucan_resource_action_from_name_string() {
        // Parsing from the canonical colon name produces the correct UCAN pair.
        let cap = Capability::new("outlet:call:*");
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "*");
    }

    #[test]
    fn ucan_resource_action_tool_invoke_specific_from_name() {
        let cap = Capability::new("outlet:call:calculator");
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "outlet_call");
        assert_eq!(action.as_ref(), "calculator");
    }

    #[test]
    fn ucan_capability_name_format() {
        assert_eq!(
            Capability::OutletCallAll.ucan_capability_name(),
            "outlet_call:*"
        );
        assert_eq!(
            Capability::MessagesWrite.ucan_capability_name(),
            "messages:write"
        );
        assert_eq!(
            Capability::ChildContextCreate.ucan_capability_name(),
            "context_child:create"
        );
        assert_eq!(
            Capability::OutletCall("calc".to_owned()).ucan_capability_name(),
            "outlet_call:calc"
        );
        assert_eq!(Capability::Bridging.ucan_capability_name(), "bridging:*");
        assert_eq!(
            Capability::OutletRegister.ucan_capability_name(),
            "outlet:register"
        );
    }

    #[test]
    fn ucan_resource_action_custom_with_colons() {
        let cap = Capability::Custom("some:nested:name".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "some_nested");
        assert_eq!(action.as_ref(), "name");
    }

    #[test]
    fn ucan_resource_action_custom_no_colons() {
        let cap = Capability::Custom("single".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "single");
        assert_eq!(action.as_ref(), "*");
    }

    #[test]
    fn ucan_resource_action_custom_simple_colon() {
        let cap = Capability::Custom("foo:bar".to_owned());
        let (resource, action) = cap.ucan_resource_action();
        assert_eq!(resource.as_ref(), "foo");
        assert_eq!(action.as_ref(), "bar");
    }

    #[test]
    fn ucan_resource_action_all_standard_variants() {
        // Every standard variant must produce a non-empty resource and action.
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletCall("test".to_owned()),
            Capability::OutletCallAll,
            Capability::OutletRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::OutletInterface,
            Capability::Bridging,
            Capability::MediaVoice,
            Capability::MediaVideo,
            Capability::MediaScreenShare,
            Capability::MemberBan,
            Capability::MetadataEdit,
        ];
        for cap in &caps {
            let (resource, action) = cap.ucan_resource_action();
            assert!(!resource.is_empty(), "empty resource for {cap:?}");
            assert!(!action.is_empty(), "empty action for {cap:?}");
            // Resource must not contain colons (UCAN uses underscores).
            assert!(
                !resource.contains(':'),
                "resource for {cap:?} contains colon: {resource}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Regression tests — consequence enforcement is per-context opt-in and
    // app-level only (spec §7.3.7). A `SuspendAll` consequence MUST NOT
    // remove the target from the context membership set (that would be an
    // `RemoveMember` governance action, O(N), MLS-level) and MUST block every
    // capability including governance participation. These tests pin that
    // contract so a future refactor cannot accidentally escalate a
    // consequence-tier suspension into a membership-destroying action.
    // -----------------------------------------------------------------------

    /// `suspend_all` MUST NOT remove the member from
    /// `ContextRoleState.members` or clear their granted
    /// `member_capabilities`. The suspension is an overlay in
    /// `suspended_capabilities`; the underlying role state is intact and
    /// can be reversed by `restore_capabilities`. This is the protocol-
    /// level analogue of "MLS membership preserved" at the spec layer
    /// (§7.3.7, §5.9) — the crypto provider's MLS group is never touched
    /// by a consequence path.
    #[test]
    fn consequence_suspend_all_preserves_membership_and_roles() {
        let ceiling = test_ceiling();
        let mut state = ContextRoleState::new(
            "ctx-suspend-membership",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Add alice and give her the member role so she has concrete
        // capabilities to suspend.
        state.members.insert("did:dht:alice".to_owned());
        let _ = assign_role(
            &mut state,
            "did:dht:alice",
            "member",
            "did:dht:creator",
            &scp_primitives::SystemClock,
        )
        .expect("creator can assign member role");

        // Sanity — alice is a member and has role-granted caps before suspension.
        assert!(state.members.contains("did:dht:alice"));
        assert!(state.member_has_capability("did:dht:alice", &Capability::MessagesWrite));
        let pre_caps = state
            .member_capabilities
            .get("did:dht:alice")
            .cloned()
            .expect("alice has role-granted capability set");

        // Apply the consequence.
        state.suspend_all("did:dht:alice");

        // Membership set: UNCHANGED. A consequence does not destroy
        // membership.
        assert!(
            state.members.contains("did:dht:alice"),
            "consequence SuspendAll must not remove the subject from members; \
             that is a RemoveMember governance action"
        );

        // Role-granted capability set: UNCHANGED. Suspension is an overlay
        // in `suspended_capabilities`, not a role mutation — so the
        // underlying capability set survives and `restore_capabilities`
        // can reverse it.
        assert_eq!(
            state.member_capabilities.get("did:dht:alice"),
            Some(&pre_caps),
            "consequence SuspendAll must not purge the member's role-granted \
             capabilities — it overlays suspensions, not mutates roles"
        );

        // Every capability alice was granted via her role is now gated by
        // the suspension check.
        for cap in &pre_caps {
            assert!(
                !state.member_has_capability("did:dht:alice", cap),
                "capability {cap:?} should be blocked after SuspendAll"
            );
        }
    }

    /// `suspend_all` MUST block governance participation capabilities
    /// (`GovernancePropose`, `GovernanceVote`) so a suspended member
    /// cannot submit proposals or vote. This pins the §7.3.7 contract
    /// that `SuspendAll` is a full app-level gate block — not just
    /// messaging, but every capability the member holds.
    #[test]
    fn consequence_suspend_all_blocks_governance_participation() {
        let ceiling = CapabilityCeiling {
            capabilities: std::collections::HashSet::from([
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::GovernancePropose,
                Capability::GovernanceVote,
            ]),
        };
        let mut state = ContextRoleState::new(
            "ctx-governance-suspension",
            "did:dht:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        // Creator is admin and has the full ceiling. Precondition: the
        // creator can propose and vote.
        assert!(state.member_has_capability("did:dht:creator", &Capability::GovernancePropose));
        assert!(state.member_has_capability("did:dht:creator", &Capability::GovernanceVote));
        assert!(state.member_has_capability("did:dht:creator", &Capability::MessagesWrite));

        // Apply the consequence against the creator (standing in for a
        // policy-violating participant).
        state.suspend_all("did:dht:creator");

        // Governance participation is blocked.
        assert!(
            !state.member_has_capability("did:dht:creator", &Capability::GovernancePropose),
            "SuspendAll must block governance:propose — suspended members cannot submit proposals"
        );
        assert!(
            !state.member_has_capability("did:dht:creator", &Capability::GovernanceVote),
            "SuspendAll must block governance:vote — suspended members cannot vote"
        );
        // And messaging is also blocked, for completeness.
        assert!(
            !state.member_has_capability("did:dht:creator", &Capability::MessagesWrite),
            "SuspendAll must block messages:write"
        );
        // But the subject is still a context member (spec §7.3.7: app-level
        // consequence, not a membership action).
        assert!(
            state.members.contains("did:dht:creator"),
            "SuspendAll must preserve membership — that's what RemoveMember is for"
        );
    }
}
