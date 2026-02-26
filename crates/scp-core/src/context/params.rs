//! Context parameter types for SCP context creation and governance.
//!
//! Defines [`ContextParams`] and its constituent types: [`ContextMode`],
//! [`CeilingPolicy`], [`PromotionPolicy`], [`MemoryScope`], [`GovernanceModel`],
//! and [`TemplateId`]. These types capture the full configuration surface of an
//! SCP context at creation time. See ADR-008 in `.docs/adrs/phase-2.md`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Capability (unified type from roles module)
// ---------------------------------------------------------------------------

/// Re-export of the unified [`Capability`](super::roles::Capability) type.
///
/// This was previously a separate `Capability(String)` newtype. It is now the
/// same enum used in `roles.rs`, supporting well-known variants (e.g.,
/// `MessagesRead`, `MessagesWrite`) plus `Custom(String)`. Use
/// [`Capability::new`] to construct from a string name.
pub use super::roles::Capability;

// ---------------------------------------------------------------------------
// RoleDefinition (placeholder)
// ---------------------------------------------------------------------------

/// Definition of a role within a context, mapping a role name to a set of
/// capabilities.
///
/// Phase 2 placeholder: roles carry only a name. Full role definitions with
/// permission sets and hierarchy will be introduced in SCP-023.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// The role name (e.g., `"admin"`, `"member"`, `"observer"`).
    pub name: String,
}

// ---------------------------------------------------------------------------
// ToolRegistration (placeholder)
// ---------------------------------------------------------------------------

/// Registration entry for a tool available within a context.
///
/// Phase 2 placeholder: tool registrations carry only a name. Full tool
/// registration with schemas, invocation policies, and verification will be
/// introduced in SCP-024.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRegistration {
    /// The tool name (e.g., `"recipe-search"`, `"nutrition-lookup"`).
    pub name: String,
}

// ---------------------------------------------------------------------------
// ContextMode
// ---------------------------------------------------------------------------

/// Context processing mode. Immutable after creation.
///
/// Determines the encryption strategy for the context:
/// - [`Encrypted`](ContextMode::Encrypted): Full MLS-backed encryption with
///   sender-side keys and forward secrecy. This is the default and recommended
///   mode for private contexts.
/// - [`Broadcast`](ContextMode::Broadcast): Per-author AES-256-GCM broadcast
///   keys without MLS group creation. Designed for one-to-many publishing
///   scenarios with unlimited subscriber count. See spec section 5.14.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextMode {
    /// MLS-backed encryption with sender-side keys and full forward secrecy.
    /// This is the default mode.
    #[default]
    Encrypted,
    /// Per-author AES-256-GCM broadcast keys. No MLS group is created.
    /// Subscriber count is unlimited. See spec section 5.14.
    Broadcast,
}

// ---------------------------------------------------------------------------
// CeilingPolicy
// ---------------------------------------------------------------------------

/// Ceiling mutability policy. Declared at creation, immutable thereafter.
///
/// Determines whether the capability ceiling can be modified after context
/// creation. See ADR-008 and spec section 5.3.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeilingPolicy {
    /// Ceiling is fixed at creation. Any attempt to modify returns
    /// `ContextError::CeilingImmutable`. This is the default and the
    /// security-conservative choice -- members see the ceiling before
    /// joining, and it cannot change (no bait-and-switch).
    #[default]
    Immutable,
    /// Ceiling can be modified through the context's governance model.
    /// Changes require governance approval (e.g., unanimous consent,
    /// admin decision). Ceiling can only be narrowed (capabilities
    /// removed), never expanded beyond the original creation ceiling.
    Governed,
}

// ---------------------------------------------------------------------------
// PromotionPolicy
// ---------------------------------------------------------------------------

/// Context promotion policy. Declared at creation, immutable thereafter.
///
/// Controls whether a context can be promoted (e.g., from ephemeral to
/// persistent, or from child to standalone). See ADR-008.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionPolicy {
    /// Context cannot be promoted. Immutable lifecycle constraints.
    NoPromotion,
    /// Context can be promoted through governance approval. Promotion
    /// conditions and requirements are governed by the context's
    /// governance model.
    Promotable,
}

// ---------------------------------------------------------------------------
// MemoryScope
// ---------------------------------------------------------------------------

/// Memory scope for a context, controlling data retention behavior after
/// context closure.
///
/// - [`Ephemeral`](MemoryScope::Ephemeral): All data is destroyed on close.
///   Keys are destroyed immediately, making content physically unreadable.
/// - [`Summary`](MemoryScope::Summary): A verified summary is generated during
///   the closing window, then keys are destroyed. Only the summary persists.
/// - [`Full`](MemoryScope::Full): All data and keys are retained after close.
///   Content remains readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryScope {
    /// All data is destroyed on context close. Keys are destroyed immediately.
    Ephemeral,
    /// A verified summary is generated during the closing window, then keys
    /// are destroyed. Only the summary persists.
    Summary,
    /// All data and keys are retained after context close.
    Full,
}

impl std::fmt::Display for MemoryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ephemeral => write!(f, "Ephemeral"),
            Self::Summary => write!(f, "Summary"),
            Self::Full => write!(f, "Full"),
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceModel
// ---------------------------------------------------------------------------

/// Governance model for a context, controlling how administrative decisions
/// are made.
///
/// Phase 2 implements only `SingleAdmin`. More sophisticated governance models
/// (multi-admin, consensus, delegation) will be added in later phases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceModel {
    /// A single administrator controls all governance decisions. The context
    /// creator is the admin by default.
    SingleAdmin,
}

// ---------------------------------------------------------------------------
// TemplateId
// ---------------------------------------------------------------------------

/// Well-known context templates (spec section 5.12.1).
///
/// Templates are protocol constants -- not user-extensible. When present, all
/// other [`ContextParams`] fields must match the template definition exactly.
/// Template validation is enforced during context creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplateId {
    /// Messaging-only, ephemeral memory, TTL required.
    BilateralEphemeral,
    /// Messaging-only, full memory, no TTL.
    BilateralPersistent,
    /// Messaging + tools, summary memory, TTL required.
    Coordination,
    /// Messaging + invites, full memory, optional TTL.
    GroupDiscussion,
    /// Broadcast mode, open subscriber registration (spec section 5.14).
    PublicBroadcast,
    /// Broadcast mode, UCAN-gated subscriber access (spec section 5.14).
    GatedBroadcast,
}

// ---------------------------------------------------------------------------
// ContextParams
// ---------------------------------------------------------------------------

/// Full configuration for an SCP context, declared at creation time.
///
/// `ContextParams` captures every parameter that defines a context's behavior:
/// encryption mode, capability ceiling, roles, tools, time-to-live, memory
/// retention, and governance model. Most fields are immutable after creation.
///
/// For template-based creation, all fields must match the template definition
/// exactly. For explicit creation, the caller specifies all parameters directly.
///
/// See ADR-008 in `.docs/adrs/phase-2.md` for the full specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextParams {
    /// Context processing mode: [`Encrypted`](ContextMode::Encrypted) (default)
    /// or [`Broadcast`](ContextMode::Broadcast). Immutable after creation.
    pub mode: ContextMode,

    /// Capability ceiling -- the maximum set of capabilities any participant
    /// can hold in this context. Individual role capabilities must be subsets
    /// of this ceiling.
    pub ceiling: Vec<Capability>,

    /// Whether the capability ceiling can be modified after creation.
    /// Defaults to [`Immutable`](CeilingPolicy::Immutable).
    pub ceiling_policy: CeilingPolicy,

    /// Whether the context can be promoted (e.g., from ephemeral to persistent).
    pub promotion_policy: PromotionPolicy,

    /// Role definitions with permission sets. Each role maps to a subset of
    /// the capability ceiling.
    pub roles: Vec<RoleDefinition>,

    /// Initial tool registrations available within this context.
    pub tools: Vec<ToolRegistration>,

    /// Optional time-to-live. When set, the context automatically expires
    /// after this duration. Extension requires unanimous member consent.
    /// See spec section 5.10.
    pub ttl: Option<Duration>,

    /// Memory scope controlling data retention after context closure.
    pub memory_scope: MemoryScope,

    /// Governance model controlling administrative decisions.
    pub governance: GovernanceModel,

    /// Well-known template identifier, if this context was created from a
    /// template. When present, all other fields must match the template
    /// definition exactly.
    pub template_id: Option<TemplateId>,
}

impl Default for ContextParams {
    fn default() -> Self {
        Self {
            mode: ContextMode::default(),
            ceiling: Vec::new(),
            ceiling_policy: CeilingPolicy::default(),
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Ephemeral,
            governance: GovernanceModel::SingleAdmin,
            template_id: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn context_mode_default_is_encrypted() {
        assert_eq!(ContextMode::default(), ContextMode::Encrypted);
    }

    #[test]
    fn ceiling_policy_default_is_immutable() {
        assert_eq!(CeilingPolicy::default(), CeilingPolicy::Immutable);
    }

    #[test]
    fn context_params_default_has_expected_values() {
        let params = ContextParams::default();
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert!(params.ceiling.is_empty());
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert!(params.template_id.is_none());
    }

    #[test]
    fn context_params_construction_with_all_fields() {
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                Capability::new("messages:read"),
                Capability::new("messages:write"),
            ],
            ceiling_policy: CeilingPolicy::Governed,
            promotion_policy: PromotionPolicy::Promotable,
            roles: vec![
                RoleDefinition {
                    name: "admin".to_owned(),
                },
                RoleDefinition {
                    name: "member".to_owned(),
                },
            ],
            tools: vec![ToolRegistration {
                name: "recipe-search".to_owned(),
            }],
            ttl: Some(Duration::from_secs(3600)),
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::PublicBroadcast),
        };

        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 2);
        assert_eq!(params.ceiling[0].name(), "messages:read");
        assert_eq!(params.ceiling_policy, CeilingPolicy::Governed);
        assert_eq!(params.promotion_policy, PromotionPolicy::Promotable);
        assert_eq!(params.roles.len(), 2);
        assert_eq!(params.tools.len(), 1);
        assert_eq!(params.ttl, Some(Duration::from_secs(3600)));
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.template_id, Some(TemplateId::PublicBroadcast));
    }

    #[test]
    fn capability_new_and_name() {
        let cap = Capability::new("messages:write");
        assert_eq!(cap.name(), "messages:write");
    }

    #[test]
    fn role_definition_clone_eq() {
        let role = RoleDefinition {
            name: "admin".to_owned(),
        };
        let cloned = role.clone();
        assert_eq!(role, cloned);
    }

    #[test]
    fn tool_registration_clone_eq() {
        let tool = ToolRegistration {
            name: "search".to_owned(),
        };
        let cloned = tool.clone();
        assert_eq!(tool, cloned);
    }

    #[test]
    fn context_mode_serialization_roundtrip() {
        let mode = ContextMode::Broadcast;
        let json = serde_json::to_string(&mode).ok();
        assert!(json.is_some());
        let deserialized: Result<ContextMode, _> =
            serde_json::from_str(json.as_deref().unwrap_or(""));
        assert_eq!(deserialized.ok(), Some(ContextMode::Broadcast));
    }

    #[test]
    fn template_id_variants_are_distinct() {
        let variants = [
            TemplateId::BilateralEphemeral,
            TemplateId::BilateralPersistent,
            TemplateId::Coordination,
            TemplateId::GroupDiscussion,
            TemplateId::PublicBroadcast,
            TemplateId::GatedBroadcast,
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

    #[test]
    fn memory_scope_variants_are_distinct() {
        assert_ne!(MemoryScope::Ephemeral, MemoryScope::Summary);
        assert_ne!(MemoryScope::Summary, MemoryScope::Full);
        assert_ne!(MemoryScope::Ephemeral, MemoryScope::Full);
    }

    #[test]
    fn context_params_serialization_roundtrip() {
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![Capability::new("messages:read")],
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: vec![RoleDefinition {
                name: "member".to_owned(),
            }],
            tools: vec![],
            ttl: Some(Duration::from_secs(300)),
            memory_scope: MemoryScope::Summary,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralEphemeral),
        };

        let json = serde_json::to_string(&params).ok();
        assert!(json.is_some());
        let deserialized: Result<ContextParams, _> =
            serde_json::from_str(json.as_deref().unwrap_or(""));
        assert_eq!(deserialized.ok(), Some(params));
    }
}
