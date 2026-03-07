//! Context parameter types for SCP context creation and governance.
//!
//! Defines [`ContextParams`] and its constituent types: [`ContextMode`],
//! [`CeilingPolicy`], [`PromotionPolicy`], [`MemoryScope`], [`GovernanceModel`],
//! [`TemplateId`], [`FieldVisibility`], [`MetadataVisibilityPolicy`],
//! [`ProjectionRule`], [`ProjectionOverride`], [`ProjectionPolicy`],
//! [`PublicMetadata`], and [`RuntimeMetadata`].
//! These types capture the full configuration surface of an SCP context at
//! creation time. [`PublicMetadata`] is the filtered projection returned by
//! [`ContextParams::public_metadata()`] for pre-join observers (spec §5.7).
//! See ADR-008 in `.docs/adrs/phase-2.md`.

use std::time::Duration;

use scp_identity::DID;
use serde::{Deserialize, Serialize};

use crate::economy::EconomicPolicy;

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
    /// Ceiling can be modified through the context's governance model
    /// (admin, multi-sig, consensus). Changes are logged in the event
    /// log and visible to all members before taking effect. Members who
    /// joined under a narrower ceiling are notified and may leave before
    /// an expansion takes effect. See spec section 5.3.
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
/// This is a simple variant-only enum that lives in `ContextParams`. It
/// selects the governance model; the rich per-model configuration lives in
/// [`GovernanceModelConfig`](super::governance::GovernanceModelConfig).
/// The builder maps `GovernanceModel` + creation arguments to the appropriate
/// `GovernanceModelConfig` and constructs the engine.
///
/// All four models per ADR-031 §4:
/// - `SingleAdmin` -- single admin auto-approve.
/// - `Threshold` -- M-of-N threshold approval.
/// - `Majority` -- majority vote among eligible voters.
/// - `Unanimity` -- all eligible voters must approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceModel {
    /// A single administrator controls all governance decisions. The context
    /// creator is the admin by default.
    SingleAdmin,
    /// M-of-N threshold approval. A fixed set of designated signers;
    /// a proposal passes when at least `threshold` of them approve.
    Threshold,
    /// Majority vote among all context members holding `GovernanceVote`
    /// capability.
    Majority,
    /// Unanimity among all context members holding `GovernanceVote`
    /// capability. Every eligible voter must approve.
    Unanimity,
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
    /// Cross-context tool interface template (spec section 5.12.1, 6.2).
    /// Messaging + tools + tool interface exposure, full memory, TTL optional.
    #[serde(rename = "scp:template/tool-interface")]
    ToolInterfaceTemplate,
    /// Tool invocation context with per-invoke cost. Extends `tool-interface`.
    /// Requires `economic_policy` with `per_tool_invoke` set at creation.
    ///
    /// See spec section 19.10 and ADR-033.
    #[serde(rename = "scp:template/paid-service")]
    PaidService,
    /// Subscription-based broadcast context. Extends `gated-broadcast`.
    /// Requires `economic_policy` with `per_period` set at creation.
    ///
    /// See spec section 19.10 and ADR-033.
    #[serde(rename = "scp:template/paid-broadcast")]
    PaidBroadcast,
}

// ---------------------------------------------------------------------------
// FieldVisibility
// ---------------------------------------------------------------------------

/// Controls whether metadata fields are visible before joining a context.
///
/// Used by [`MetadataVisibilityPolicy`] to declare per-field visibility.
/// Structural fields (ceiling, governance, mode, etc.) are always visible
/// regardless of this setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldVisibility {
    /// Visible to anyone with the `context_id` (pre-join legibility).
    #[default]
    PreJoin,
    /// Visible only to context members.
    MemberOnly,
}

// ---------------------------------------------------------------------------
// MetadataVisibilityPolicy
// ---------------------------------------------------------------------------

/// Per-field metadata visibility policy (spec section 5.7).
///
/// Structural fields (ceiling, governance, mode, etc.) are always visible.
/// This policy governs operational fields only. By default, all operational
/// fields are [`FieldVisibility::PreJoin`] -- visible to anyone with the
/// `context_id`, supporting informed consent before joining.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataVisibilityPolicy {
    /// Visibility of the context's member count.
    pub member_count: FieldVisibility,
    /// Visibility of the context's age (time since creation).
    pub context_age: FieldVisibility,
    /// Visibility of the context creator's identity (DID).
    pub creator_identity: FieldVisibility,
    /// Visibility of the context's human-readable name.
    pub name: FieldVisibility,
    /// Visibility of the context's description.
    pub description: FieldVisibility,
    /// Visibility of the context's economic policy.
    pub economic_policy: FieldVisibility,
    /// Visibility of the count of registered tool interfaces.
    pub tool_interface_count: FieldVisibility,
    /// Visibility of child context summary information.
    pub child_context_info: FieldVisibility,
}

// ---------------------------------------------------------------------------
// ProjectionRule / ProjectionPolicy
// ---------------------------------------------------------------------------

/// Rule for HTTP broadcast projection access control (spec section 18.11.2.1).
///
/// Controls whether projected broadcast content requires authentication to access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectionRule {
    /// Content served without authentication.
    Public,
    /// Content requires valid `messagesRead` UCAN in Authorization header.
    Gated,
    /// Author chooses their own projection rule.
    AuthorChoice,
}

/// Per-author projection access override.
///
/// Allows individual authors within a broadcast context to have a projection
/// rule that differs from the context's default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionOverride {
    /// The DID of the author this override applies to.
    pub did: DID,
    /// The projection rule for this specific author.
    pub rule: ProjectionRule,
}

/// Per-author projection access policy for broadcast contexts (spec section 18.11.2.1).
///
/// Controls whether projected content requires authentication, with per-author
/// overrides within the bounds of the context's admission mode. Only meaningful
/// for [`ContextMode::Broadcast`] contexts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionPolicy {
    /// Default rule for all authors without an explicit override.
    pub default_rule: ProjectionRule,
    /// Per-author overrides.
    pub overrides: Vec<ProjectionOverride>,
}

// ---------------------------------------------------------------------------
// PublicMetadata
// ---------------------------------------------------------------------------

/// Metadata visible to pre-join observers (spec section 5.7).
///
/// Structural fields are always included — they are the parameters a
/// prospective member needs to evaluate whether to join. Operational fields
/// are included only when the corresponding [`FieldVisibility`] in the
/// context's [`MetadataVisibilityPolicy`] is [`FieldVisibility::PreJoin`];
/// otherwise they are `None`.
///
/// Constructed via [`ContextParams::public_metadata()`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMetadata {
    // --- Structural fields (always visible) ---
    /// Well-known template identifier, if created from a template.
    pub template_id: Option<TemplateId>,
    /// Capability ceiling.
    pub ceiling: Vec<Capability>,
    /// Ceiling mutability policy.
    pub ceiling_policy: CeilingPolicy,
    /// Role definitions.
    pub roles: Vec<RoleDefinition>,
    /// Governance model.
    pub governance: GovernanceModel,
    /// Context processing mode.
    pub mode: ContextMode,
    /// Time-to-live, if set.
    pub ttl: Option<Duration>,
    /// Promotion policy.
    pub promotion_policy: PromotionPolicy,
    /// Memory scope.
    pub memory_scope: MemoryScope,
    /// The visibility policy itself (so prospective members know what's hidden).
    pub metadata_visibility: MetadataVisibilityPolicy,

    // --- Operational fields (governed by MetadataVisibilityPolicy) ---
    /// Current member count. `None` when hidden by `MemberOnly` or unavailable.
    pub member_count: Option<u64>,
    /// Context age in seconds since creation. `None` when hidden by `MemberOnly` or unavailable.
    pub context_age: Option<u64>,
    /// Creator's DID. `None` when hidden by `MemberOnly` or unavailable.
    pub creator_identity: Option<DID>,
    /// Human-readable name. `None` when hidden by `MemberOnly` or unavailable.
    pub name: Option<String>,
    /// Human-readable description. `None` when hidden by `MemberOnly` or unavailable.
    pub description: Option<String>,
    /// Economic policy. `None` when hidden by `MemberOnly`, absent, or unavailable.
    pub economic_policy: Option<EconomicPolicy>,
    /// Count of registered tool interfaces. `None` when hidden by `MemberOnly` or unavailable.
    pub tool_interface_count: Option<u32>,
    /// Child context summary information. `None` when hidden by `MemberOnly` or unavailable.
    pub child_context_info: Option<Vec<String>>,
}

/// Runtime context state that is not captured in [`ContextParams`] but may
/// be published as operational metadata. Pass to
/// [`ContextParams::public_metadata()`] to populate the corresponding fields.
#[derive(Debug, Clone, Default)]
pub struct RuntimeMetadata {
    /// Current member count.
    pub member_count: Option<u64>,
    /// Context age in seconds since creation.
    pub context_age: Option<u64>,
    /// Creator's DID.
    pub creator_identity: Option<DID>,
    /// Human-readable context name.
    pub name: Option<String>,
    /// Human-readable context description.
    pub description: Option<String>,
    /// Count of registered tool interfaces.
    pub tool_interface_count: Option<u32>,
    /// Child context summary information (e.g., parent context IDs, summaries).
    pub child_context_info: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// filter_field helper
// ---------------------------------------------------------------------------

/// Returns `value` when `visibility` is [`FieldVisibility::PreJoin`], or
/// `None` when it is [`FieldVisibility::MemberOnly`].
fn filter_field<T>(visibility: FieldVisibility, value: Option<T>) -> Option<T> {
    match visibility {
        FieldVisibility::PreJoin => value,
        FieldVisibility::MemberOnly => None,
    }
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

    /// Economic policy for this context. `None` means the context is free
    /// (no economic policy). When present, defines costs, accepted payment
    /// adapters, optional dynamic pricing, and the payee DID.
    ///
    /// See spec section 19.3 and ADR-033.
    #[serde(default)]
    pub economic_policy: Option<EconomicPolicy>,

    /// Per-field metadata visibility policy controlling which operational fields
    /// are visible before joining (spec section 5.7). Structural fields are
    /// always visible regardless. Defaults to all fields [`FieldVisibility::PreJoin`].
    #[serde(default)]
    pub metadata_visibility: MetadataVisibilityPolicy,

    /// Projection access policy for broadcast contexts (spec section 18.11.2.1).
    /// Controls whether projected HTTP content requires authentication, with
    /// per-author overrides. `None` for non-broadcast contexts.
    #[serde(default)]
    pub projection_policy: Option<ProjectionPolicy>,
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
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
        }
    }
}

impl ContextParams {
    /// Return metadata filtered by the visibility policy (spec section 5.7).
    ///
    /// Structural fields are always included. Operational fields are included
    /// only when the corresponding [`FieldVisibility`] is
    /// [`FieldVisibility::PreJoin`]; otherwise the field is `None`.
    ///
    /// Fields that live on `ContextParams` (e.g., `economic_policy`) are
    /// filtered directly. Fields that are runtime state (member count, context
    /// age, creator identity, name, description, tool interface count, child
    /// context info) must be supplied via [`RuntimeMetadata`].
    #[must_use]
    pub fn public_metadata(&self, runtime: &RuntimeMetadata) -> PublicMetadata {
        let vis = &self.metadata_visibility;

        PublicMetadata {
            // Structural fields — always visible.
            template_id: self.template_id,
            ceiling: self.ceiling.clone(),
            ceiling_policy: self.ceiling_policy,
            roles: self.roles.clone(),
            governance: self.governance.clone(),
            mode: self.mode,
            ttl: self.ttl,
            promotion_policy: self.promotion_policy,
            memory_scope: self.memory_scope,
            metadata_visibility: self.metadata_visibility.clone(),

            // Operational fields — filtered by visibility policy.
            member_count: filter_field(vis.member_count, runtime.member_count),
            context_age: filter_field(vis.context_age, runtime.context_age),
            creator_identity: filter_field(vis.creator_identity, runtime.creator_identity.clone()),
            name: filter_field(vis.name, runtime.name.clone()),
            description: filter_field(vis.description, runtime.description.clone()),
            economic_policy: filter_field(vis.economic_policy, self.economic_policy.clone()),
            tool_interface_count: filter_field(
                vis.tool_interface_count,
                runtime.tool_interface_count,
            ),
            child_context_info: filter_field(
                vis.child_context_info,
                runtime.child_context_info.clone(),
            ),
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
        assert!(params.economic_policy.is_none());
        assert_eq!(
            params.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );
        assert!(params.projection_policy.is_none());
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
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
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
        assert!(params.economic_policy.is_none());
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
            TemplateId::PaidService,
            TemplateId::PaidBroadcast,
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
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
        };

        let json = serde_json::to_string(&params).ok();
        assert!(json.is_some());
        let deserialized: Result<ContextParams, _> =
            serde_json::from_str(json.as_deref().unwrap_or(""));
        assert_eq!(deserialized.ok(), Some(params));
    }

    #[test]
    fn context_params_with_economic_policy_serde_roundtrip() {
        use crate::economy::{
            Amount, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy, PricingFormula,
            PricingMetric, PricingVariable,
        };

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![Capability::new("messages:read")],
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: vec![],
            tools: vec![],
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: None,
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_tool_invoke: None,
                    per_join: Some(Amount(100)),
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: Some(PricingFormula {
                    base_cost: Amount(10),
                    variables: vec![PricingVariable::Linear {
                        metric: PricingMetric::MemberCount,
                        coefficient: Coefficient(500_000),
                    }],
                    cap: Some(Amount(1000)),
                    floor: None,
                }),
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: ContextParams = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, params);
        assert!(deserialized.economic_policy.is_some());
    }

    #[test]
    fn context_params_deserialize_without_economic_policy_field() {
        // Verify that JSON without economic_policy field still deserializes
        // (backwards compatibility via #[serde(default)]).
        let json = r#"{
            "mode": "Encrypted",
            "ceiling": [],
            "ceiling_policy": "Immutable",
            "promotion_policy": "NoPromotion",
            "roles": [],
            "tools": [],
            "ttl": null,
            "memory_scope": "Ephemeral",
            "governance": "SingleAdmin",
            "template_id": null
        }"#;
        let params: ContextParams = serde_json::from_str(json).unwrap();
        assert!(params.economic_policy.is_none());
        // New fields should also get defaults via #[serde(default)].
        assert_eq!(
            params.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );
        assert!(params.projection_policy.is_none());
    }

    // -----------------------------------------------------------------------
    // FieldVisibility
    // -----------------------------------------------------------------------

    #[test]
    fn field_visibility_default_is_pre_join() {
        assert_eq!(FieldVisibility::default(), FieldVisibility::PreJoin);
    }

    #[test]
    fn field_visibility_serialization_roundtrip() {
        for vis in [FieldVisibility::PreJoin, FieldVisibility::MemberOnly] {
            let json = serde_json::to_string(&vis).unwrap();
            let deserialized: FieldVisibility = serde_json::from_str(&json).unwrap();
            assert_eq!(vis, deserialized);
        }
    }

    // -----------------------------------------------------------------------
    // MetadataVisibilityPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn metadata_visibility_policy_default_all_pre_join() {
        let policy = MetadataVisibilityPolicy::default();
        assert_eq!(policy.member_count, FieldVisibility::PreJoin);
        assert_eq!(policy.context_age, FieldVisibility::PreJoin);
        assert_eq!(policy.creator_identity, FieldVisibility::PreJoin);
        assert_eq!(policy.name, FieldVisibility::PreJoin);
        assert_eq!(policy.description, FieldVisibility::PreJoin);
        assert_eq!(policy.economic_policy, FieldVisibility::PreJoin);
        assert_eq!(policy.tool_interface_count, FieldVisibility::PreJoin);
        assert_eq!(policy.child_context_info, FieldVisibility::PreJoin);
    }

    #[test]
    fn metadata_visibility_policy_serialization_roundtrip() {
        let policy = MetadataVisibilityPolicy {
            member_count: FieldVisibility::MemberOnly,
            context_age: FieldVisibility::PreJoin,
            creator_identity: FieldVisibility::MemberOnly,
            name: FieldVisibility::PreJoin,
            description: FieldVisibility::PreJoin,
            economic_policy: FieldVisibility::MemberOnly,
            tool_interface_count: FieldVisibility::PreJoin,
            child_context_info: FieldVisibility::MemberOnly,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: MetadataVisibilityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    // -----------------------------------------------------------------------
    // ProjectionRule / ProjectionPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn projection_rule_serialization_roundtrip() {
        for rule in [
            ProjectionRule::Public,
            ProjectionRule::Gated,
            ProjectionRule::AuthorChoice,
        ] {
            let json = serde_json::to_string(&rule).unwrap();
            let deserialized: ProjectionRule = serde_json::from_str(&json).unwrap();
            assert_eq!(rule, deserialized);
        }
    }

    #[test]
    fn projection_policy_serialization_roundtrip() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![ProjectionOverride {
                did: DID::from("did:dht:z6MkAuthor1"),
                rule: ProjectionRule::Public,
            }],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: ProjectionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn projection_override_equality() {
        let a = ProjectionOverride {
            did: DID::from("did:dht:z6MkA"),
            rule: ProjectionRule::Public,
        };
        let b = ProjectionOverride {
            did: DID::from("did:dht:z6MkA"),
            rule: ProjectionRule::Public,
        };
        let c = ProjectionOverride {
            did: DID::from("did:dht:z6MkB"),
            rule: ProjectionRule::Gated,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // PublicMetadata / public_metadata()
    // -----------------------------------------------------------------------

    /// Helper: build a `RuntimeMetadata` with all fields populated.
    fn full_runtime() -> RuntimeMetadata {
        RuntimeMetadata {
            member_count: Some(42),
            context_age: Some(86400),
            creator_identity: Some(DID::from("did:dht:z6MkCreator")),
            name: Some("Test Context".to_owned()),
            description: Some("A test context".to_owned()),
            tool_interface_count: Some(3),
            child_context_info: Some(vec!["child-1".to_owned(), "child-2".to_owned()]),
        }
    }

    #[test]
    fn public_metadata_default_policy_returns_all_fields() {
        // Default MetadataVisibilityPolicy has all fields PreJoin,
        // so public_metadata() should return everything.
        let params = ContextParams {
            ceiling: vec![Capability::new("messages:read")],
            mode: ContextMode::Encrypted,
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Structural fields always present.
        assert_eq!(meta.ceiling, params.ceiling);
        assert_eq!(meta.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(meta.mode, ContextMode::Encrypted);
        assert_eq!(meta.promotion_policy, PromotionPolicy::NoPromotion);
        assert_eq!(meta.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(meta.governance, GovernanceModel::SingleAdmin);
        assert!(meta.template_id.is_none());
        assert!(meta.ttl.is_none());
        assert!(meta.roles.is_empty());
        assert_eq!(
            meta.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );

        // Operational fields all visible (PreJoin default).
        assert_eq!(meta.member_count, Some(42));
        assert_eq!(meta.context_age, Some(86400));
        assert_eq!(
            meta.creator_identity,
            Some(DID::from("did:dht:z6MkCreator"))
        );
        assert_eq!(meta.name, Some("Test Context".to_owned()));
        assert_eq!(meta.description, Some("A test context".to_owned()));
        assert_eq!(meta.tool_interface_count, Some(3));
        assert_eq!(
            meta.child_context_info,
            Some(vec!["child-1".to_owned(), "child-2".to_owned()])
        );
    }

    #[test]
    fn public_metadata_member_count_hidden_when_member_only() {
        let params = ContextParams {
            metadata_visibility: MetadataVisibilityPolicy {
                member_count: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // member_count hidden.
        assert!(meta.member_count.is_none());

        // Other operational fields still visible.
        assert_eq!(meta.context_age, Some(86400));
        assert_eq!(
            meta.creator_identity,
            Some(DID::from("did:dht:z6MkCreator"))
        );
        assert_eq!(meta.name, Some("Test Context".to_owned()));
    }

    #[test]
    fn public_metadata_name_hidden_when_member_only() {
        let params = ContextParams {
            metadata_visibility: MetadataVisibilityPolicy {
                name: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        assert!(meta.name.is_none());
        // Description still visible.
        assert_eq!(meta.description, Some("A test context".to_owned()));
    }

    #[test]
    fn public_metadata_structural_fields_always_present_regardless_of_policy() {
        // Even with all operational fields MemberOnly, structural fields persist.
        let params = ContextParams {
            ceiling: vec![
                Capability::new("messages:read"),
                Capability::new("messages:write"),
            ],
            ceiling_policy: CeilingPolicy::Governed,
            mode: ContextMode::Broadcast,
            ttl: Some(Duration::from_secs(7200)),
            promotion_policy: PromotionPolicy::Promotable,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::PublicBroadcast),
            roles: vec![RoleDefinition {
                name: "admin".to_owned(),
            }],
            metadata_visibility: MetadataVisibilityPolicy {
                member_count: FieldVisibility::MemberOnly,
                context_age: FieldVisibility::MemberOnly,
                creator_identity: FieldVisibility::MemberOnly,
                name: FieldVisibility::MemberOnly,
                description: FieldVisibility::MemberOnly,
                economic_policy: FieldVisibility::MemberOnly,
                tool_interface_count: FieldVisibility::MemberOnly,
                child_context_info: FieldVisibility::MemberOnly,
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Structural fields present.
        assert_eq!(meta.ceiling.len(), 2);
        assert_eq!(meta.ceiling_policy, CeilingPolicy::Governed);
        assert_eq!(meta.mode, ContextMode::Broadcast);
        assert_eq!(meta.ttl, Some(Duration::from_secs(7200)));
        assert_eq!(meta.promotion_policy, PromotionPolicy::Promotable);
        assert_eq!(meta.memory_scope, MemoryScope::Full);
        assert_eq!(meta.governance, GovernanceModel::SingleAdmin);
        assert_eq!(meta.template_id, Some(TemplateId::PublicBroadcast));
        assert_eq!(meta.roles.len(), 1);
        assert_eq!(
            meta.metadata_visibility.member_count,
            FieldVisibility::MemberOnly
        );

        // All operational fields hidden.
        assert!(meta.member_count.is_none());
        assert!(meta.context_age.is_none());
        assert!(meta.creator_identity.is_none());
        assert!(meta.name.is_none());
        assert!(meta.description.is_none());
        assert!(meta.economic_policy.is_none());
        assert!(meta.tool_interface_count.is_none());
        assert!(meta.child_context_info.is_none());
    }

    #[test]
    fn public_metadata_economic_policy_filtered_from_context_params() {
        // economic_policy is the one operational field that lives on ContextParams,
        // not on RuntimeMetadata.
        use crate::economy::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: Some(Amount(1)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        };

        // Visible when PreJoin.
        let params = ContextParams {
            economic_policy: Some(policy.clone()),
            metadata_visibility: MetadataVisibilityPolicy::default(),
            ..ContextParams::default()
        };
        let meta = params.public_metadata(&RuntimeMetadata::default());
        assert_eq!(meta.economic_policy, Some(policy.clone()));

        // Hidden when MemberOnly.
        let params_hidden = ContextParams {
            economic_policy: Some(policy),
            metadata_visibility: MetadataVisibilityPolicy {
                economic_policy: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let meta_hidden = params_hidden.public_metadata(&RuntimeMetadata::default());
        assert!(meta_hidden.economic_policy.is_none());
    }

    #[test]
    fn public_metadata_runtime_none_stays_none_even_when_pre_join() {
        // When runtime doesn't supply a value, field is None regardless of policy.
        let params = ContextParams::default();
        let runtime = RuntimeMetadata::default();
        let meta = params.public_metadata(&runtime);

        assert!(meta.member_count.is_none());
        assert!(meta.context_age.is_none());
        assert!(meta.creator_identity.is_none());
        assert!(meta.name.is_none());
        assert!(meta.description.is_none());
        assert!(meta.tool_interface_count.is_none());
        assert!(meta.child_context_info.is_none());
    }

    #[test]
    fn public_metadata_selective_field_hiding() {
        // Hide member_count, context_age, and creator_identity (bilateral-ephemeral style).
        let params = ContextParams {
            metadata_visibility: MetadataVisibilityPolicy {
                member_count: FieldVisibility::MemberOnly,
                context_age: FieldVisibility::MemberOnly,
                creator_identity: FieldVisibility::MemberOnly,
                ..MetadataVisibilityPolicy::default()
            },
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // These three are hidden.
        assert!(meta.member_count.is_none());
        assert!(meta.context_age.is_none());
        assert!(meta.creator_identity.is_none());

        // Remaining operational fields still visible.
        assert_eq!(meta.name, Some("Test Context".to_owned()));
        assert_eq!(meta.description, Some("A test context".to_owned()));
        assert_eq!(meta.tool_interface_count, Some(3));
        assert_eq!(
            meta.child_context_info,
            Some(vec!["child-1".to_owned(), "child-2".to_owned()])
        );
    }

    #[test]
    fn public_metadata_gated_broadcast_template_hides_member_count() {
        use crate::context::templates::template_params;
        let params = template_params(&TemplateId::GatedBroadcast);
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Gated-broadcast template: member_count MemberOnly, all others PreJoin.
        assert!(meta.member_count.is_none(), "member_count should be hidden");
        // Other operational fields remain visible.
        assert!(meta.name.is_some());
        assert!(meta.description.is_some());
        assert!(meta.context_age.is_some());
        assert!(meta.creator_identity.is_some());
    }

    #[test]
    fn public_metadata_bilateral_ephemeral_template_hides_private_fields() {
        use crate::context::templates::template_params;
        let params = template_params(&TemplateId::BilateralEphemeral);
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        // Bilateral-ephemeral: member_count, context_age, creator_identity
        // (and description, economic_policy, tool_interface_count, child_context_info)
        // are all MemberOnly. Only name is PreJoin.
        assert!(meta.member_count.is_none(), "member_count should be hidden");
        assert!(meta.context_age.is_none(), "context_age should be hidden");
        assert!(
            meta.creator_identity.is_none(),
            "creator_identity should be hidden"
        );
        assert!(
            meta.description.is_none(),
            "description should be hidden for bilateral-ephemeral"
        );
        // Name is PreJoin.
        assert!(meta.name.is_some(), "name should be visible");
        // Structural fields always present.
        assert!(!meta.ceiling.is_empty());
    }

    #[test]
    fn public_metadata_serialization_roundtrip() {
        let params = ContextParams {
            ceiling: vec![Capability::new("messages:read")],
            ..ContextParams::default()
        };
        let runtime = full_runtime();
        let meta = params.public_metadata(&runtime);

        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: PublicMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, deserialized);
    }
}
