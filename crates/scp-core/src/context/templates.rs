//! Well-known context template definitions, validation, and construction.
//!
//! Templates are protocol constants (spec section 5.12.1) -- not user-extensible.
//! When a [`TemplateId`] is present in [`ContextParams`], all other fields must
//! match the template definition exactly. This module provides:
//!
//! - [`template_params`] -- constructs default [`ContextParams`] for a given
//!   template, with `ttl` set to `None` (the caller must supply it when
//!   required).
//! - [`ContextParams::from_template`] -- convenience method equivalent to
//!   [`template_params`].
//! - [`validate_against_template`] -- validates that a [`ContextParams`] matches
//!   the template definition when `template_id` is present.
//!
//! See ADR-008 in `.docs/adrs/phase-2.md` for the base template specification
//! and ADR-033 in `.docs/adrs/phase-3.md` for paid templates (§19.10).

use crate::provenance::CounterpartyPolicy;

use super::params::{
    Capability, CeilingPolicy, ContextMode, ContextParams, FieldVisibility, GovernanceModel,
    IncompleteVerificationPolicy, MemoryScope, MetadataVisibilityPolicy, ProjectionPolicy,
    ProjectionRule, PromotionPolicy, TemplateId,
};

// ---------------------------------------------------------------------------
// TemplateError
// ---------------------------------------------------------------------------

/// Errors produced by template validation.
///
/// Returned by [`validate_against_template`] when `ContextParams` fields do not
/// match the template definition.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// One or more `ContextParams` fields do not match the template definition.
    #[error("template mismatch for {template:?}: {field} -- expected {expected}, got {actual}")]
    Mismatch {
        /// The template that was expected.
        template: TemplateId,
        /// The field that did not match.
        field: &'static str,
        /// Description of the expected value.
        expected: String,
        /// Description of the actual value.
        actual: String,
    },

    /// A TTL is required by the template but was not provided.
    #[error("template {template:?} requires a TTL, but none was provided")]
    TtlRequired {
        /// The template that requires a TTL.
        template: TemplateId,
    },

    /// A TTL was provided but the template forbids it.
    #[error("template {template:?} forbids a TTL, but one was provided")]
    TtlForbidden {
        /// The template that forbids a TTL.
        template: TemplateId,
    },

    /// The template requires an economic policy, but none was provided.
    #[error("template {template:?} requires an economic_policy, but none was provided")]
    EconomicPolicyRequired {
        /// The template that requires an economic policy.
        template: TemplateId,
    },

    /// The template requires a specific cost field to be set in the economic
    /// policy, but it was `None`.
    #[error("template {template:?} requires {field} to be set in economic_policy.cost_schedule")]
    CostFieldRequired {
        /// The template that requires the cost field.
        template: TemplateId,
        /// The cost field that must be set (e.g., `"per_tool_invoke"`).
        field: &'static str,
    },

    /// A projection policy was set on an encrypted context, which is not
    /// permitted. Projection is only meaningful for broadcast contexts.
    #[error("projection_policy is only valid for Broadcast contexts, but mode is Encrypted")]
    ProjectionPolicyOnEncrypted,
}

// ---------------------------------------------------------------------------
// Well-known capability names
// ---------------------------------------------------------------------------

/// Standard capability name for reading messages.
const CAP_MESSAGES_READ: &str = "messages:read";
/// Standard capability name for writing messages.
const CAP_MESSAGES_WRITE: &str = "messages:write";
/// Standard capability name for invoking any registered tool.
const CAP_TOOL_INVOKE_ALL: &str = "tool:invoke:*";
/// Standard capability name for registering new tools.
const CAP_TOOL_REGISTER: &str = "tool:register";
/// Standard capability name for inviting new members.
const CAP_MEMBER_INVITE: &str = "member:invite";
/// Standard capability name for banning members from a context.
const CAP_MEMBER_BAN: &str = "member:ban";

// ---------------------------------------------------------------------------
// Template definitions
// ---------------------------------------------------------------------------

/// Returns the messaging-only ceiling: `messages:read` + `messages:write`.
///
/// Used by broadcast templates where `member:ban` is not applicable.
fn messaging_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
    ]
}

/// Returns the messaging ceiling with ban: `messages:read` + `messages:write`
/// + `member:ban`.
///
/// Used by encrypted templates that support member banning (bilateral
/// ephemeral, bilateral persistent).
fn messaging_ban_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_MEMBER_BAN),
    ]
}

/// Returns the messaging + tool invoke + ban ceiling: messaging +
/// `tool:invoke_all` + `member:ban`.
///
/// Used by the Coordination template (spec section 5.12.1). Tools are
/// creator-defined at creation time, so only `tool:invoke_all` is in the
/// ceiling — members can invoke tools but not dynamically register new ones.
fn messaging_tool_invoke_ban_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_TOOL_INVOKE_ALL),
        Capability::new(CAP_MEMBER_BAN),
    ]
}

/// Returns the messaging + full tools ceiling: messaging + `tool:invoke_all` +
/// `tool:register`.
///
/// Used by broadcast templates (spec section 5.12.1) where participants can
/// both invoke and register tools. Does NOT include `member:ban` — broadcast
/// contexts do not support member banning.
fn messaging_tools_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_TOOL_INVOKE_ALL),
        Capability::new(CAP_TOOL_REGISTER),
    ]
}

/// Returns the messaging + full tools + ban ceiling: messaging +
/// `tool:invoke_all` + `tool:register` + `member:ban`.
///
/// Used by encrypted templates with full tool support (tool-interface,
/// paid-service) where participants can invoke and register tools, and
/// member banning is supported.
fn messaging_tools_ban_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_TOOL_INVOKE_ALL),
        Capability::new(CAP_TOOL_REGISTER),
        Capability::new(CAP_MEMBER_BAN),
    ]
}

/// Returns the messaging + invite + ban ceiling: messaging + `member:invite`
/// + `member:ban`.
fn messaging_invite_ban_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_MEMBER_INVITE),
        Capability::new(CAP_MEMBER_BAN),
    ]
}

// ---------------------------------------------------------------------------
// Metadata visibility helpers
// ---------------------------------------------------------------------------

/// Returns the private-encrypted metadata visibility policy.
///
/// Used by bilateral-ephemeral, bilateral-persistent, and coordination
/// templates. Only the context name is visible pre-join; all other operational
/// fields are member-only.
const fn private_encrypted_visibility() -> MetadataVisibilityPolicy {
    MetadataVisibilityPolicy {
        member_count: FieldVisibility::MemberOnly,
        context_age: FieldVisibility::MemberOnly,
        creator_identity: FieldVisibility::MemberOnly,
        name: FieldVisibility::PreJoin,
        description: FieldVisibility::MemberOnly,
        economic_policy: FieldVisibility::MemberOnly,
        tool_interface_count: FieldVisibility::MemberOnly,
        child_context_info: FieldVisibility::MemberOnly,
    }
}

/// Returns the group-discussion metadata visibility policy.
///
/// Name, description, member count, and creator identity are pre-join visible
/// to help potential members evaluate the group. Other fields are member-only.
const fn group_discussion_visibility() -> MetadataVisibilityPolicy {
    MetadataVisibilityPolicy {
        member_count: FieldVisibility::PreJoin,
        context_age: FieldVisibility::MemberOnly,
        creator_identity: FieldVisibility::PreJoin,
        name: FieldVisibility::PreJoin,
        description: FieldVisibility::PreJoin,
        economic_policy: FieldVisibility::MemberOnly,
        tool_interface_count: FieldVisibility::MemberOnly,
        child_context_info: FieldVisibility::MemberOnly,
    }
}

/// Returns a metadata visibility policy with only `member_count` set to
/// member-only and all other fields pre-join visible.
///
/// Used by gated-broadcast, paid-service, and paid-broadcast templates.
const fn member_count_hidden_visibility() -> MetadataVisibilityPolicy {
    MetadataVisibilityPolicy {
        member_count: FieldVisibility::MemberOnly,
        context_age: FieldVisibility::PreJoin,
        creator_identity: FieldVisibility::PreJoin,
        name: FieldVisibility::PreJoin,
        description: FieldVisibility::PreJoin,
        economic_policy: FieldVisibility::PreJoin,
        tool_interface_count: FieldVisibility::PreJoin,
        child_context_info: FieldVisibility::PreJoin,
    }
}

/// Constructs the canonical [`ContextParams`] for a given [`TemplateId`].
///
/// The returned params have `ttl` set to `None`. For templates that require a
/// TTL (`BilateralEphemeral`, `Coordination`), the caller must set the `ttl`
/// field before passing to context creation. For templates where TTL is
/// optional (`GroupDiscussion`, `PublicBroadcast`, `GatedBroadcast`), the
/// caller may set it. For templates that forbid TTL (`BilateralPersistent`),
/// the `ttl` field must remain `None`.
///
/// # Template definitions
///
/// | Template | Mode | Ceiling | MemberBan | Metadata | Projection | TTL | Economic |
/// |----------|------|---------|-----------|----------|------------|-----|----------|
/// | `BilateralEphemeral` | Encrypted | messages + ban | Yes | private | None | Required | None |
/// | `BilateralPersistent` | Encrypted | messages + ban | Yes | private | None | Forbidden | None |
/// | `Coordination` | Encrypted | messages + invoke + ban | Yes | private | None | Required | None |
/// | `GroupDiscussion` | Encrypted | messages + invite + ban | Yes | group | None | Optional | None |
/// | `PublicBroadcast` | Broadcast | messages + tools | No | default | Public | Optional | None |
/// | `GatedBroadcast` | Broadcast | messages + tools | No | member_count_hidden | Gated | Optional | None |
/// | `ToolInterfaceTemplate` | Encrypted | messages + tools + ban | Yes | default | None | Optional | None |
/// | `PaidService` | Encrypted | messages + tools + ban | Yes | member_count_hidden | None | Optional | Required (per_tool_invoke) |
/// | `PaidBroadcast` | Broadcast | messages | No | member_count_hidden | Gated | Optional | Required (per_period) |
#[must_use]
#[allow(clippy::too_many_lines)] // one arm per template variant; splitting hurts readability
pub fn template_params(template_id: &TemplateId) -> ContextParams {
    match template_id {
        TemplateId::BilateralEphemeral => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_ban_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Ephemeral,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralEphemeral),
            economic_policy: None,
            metadata_visibility: private_encrypted_visibility(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        TemplateId::BilateralPersistent => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_ban_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralPersistent),
            economic_policy: None,
            metadata_visibility: private_encrypted_visibility(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        TemplateId::Coordination => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_tool_invoke_ban_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Summary,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::Coordination),
            economic_policy: None,
            metadata_visibility: private_encrypted_visibility(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        TemplateId::GroupDiscussion => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_invite_ban_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::Promotable,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::GroupDiscussion),
            economic_policy: None,
            metadata_visibility: group_discussion_visibility(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        TemplateId::PublicBroadcast => ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: messaging_tools_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::PublicBroadcast),
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: Some(ProjectionPolicy {
                default_rule: ProjectionRule::Public,
                overrides: vec![],
            }),
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        TemplateId::GatedBroadcast => ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: messaging_tools_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::GatedBroadcast),
            economic_policy: None,
            metadata_visibility: member_count_hidden_visibility(),
            projection_policy: Some(ProjectionPolicy {
                default_rule: ProjectionRule::Gated,
                overrides: vec![],
            }),
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        TemplateId::ToolInterfaceTemplate => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_tools_ban_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::ToolInterfaceTemplate),
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        // Extends scp:template/tool-interface -- same ceiling and governance,
        // but economic_policy is caller-provided and validated separately.
        TemplateId::PaidService => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_tools_ban_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::PaidService),
            economic_policy: None,
            metadata_visibility: member_count_hidden_visibility(),
            projection_policy: None,
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        // Extends scp:template/gated-broadcast -- broadcast mode with gated
        // subscriber admission. economic_policy is caller-provided.
        TemplateId::PaidBroadcast => ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: messaging_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::PaidBroadcast),
            economic_policy: None,
            metadata_visibility: member_count_hidden_visibility(),
            projection_policy: Some(ProjectionPolicy {
                default_rule: ProjectionRule::Gated,
                overrides: vec![],
            }),
            discoverable: false,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
        // Discovery context: encrypted mode with messaging + tool invocation
        // ceiling. Discoverable by default so it can be found via DHT. Used
        // to bootstrap agent discovery via standardized tool schemas (ADR-020).
        TemplateId::DiscoveryContext => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_tool_invoke_ban_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::DiscoveryContext),
            economic_policy: None,
            metadata_visibility: MetadataVisibilityPolicy::default(),
            projection_policy: None,
            discoverable: true,
            max_chain_depth: None,
            counterparty_policy: CounterpartyPolicy::default(),
            participation_requirements: Vec::new(),
            incomplete_verification_policy: IncompleteVerificationPolicy::default(),
            min_protocol_version: None,
            migration_source: None,
        },
    }
}

// ---------------------------------------------------------------------------
// ContextParams::from_template -- convenience constructor
// ---------------------------------------------------------------------------

impl ContextParams {
    /// Constructs a [`ContextParams`] from a well-known template.
    ///
    /// This is a convenience method equivalent to [`template_params`]. The
    /// returned params have `ttl` set to `None`. For templates that require a
    /// TTL (`BilateralEphemeral`, `Coordination`), the caller must set the
    /// `ttl` field before passing to context creation.
    #[must_use]
    pub fn from_template(template_id: TemplateId) -> Self {
        template_params(&template_id)
    }
}

// ---------------------------------------------------------------------------
// TTL policy per template
// ---------------------------------------------------------------------------

/// TTL constraint for a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TtlPolicy {
    /// TTL must be present.
    Required,
    /// TTL must not be present.
    Forbidden,
    /// TTL may or may not be present.
    Optional,
}

/// Returns the TTL policy for a given template.
const fn ttl_policy(template_id: TemplateId) -> TtlPolicy {
    match template_id {
        TemplateId::BilateralEphemeral | TemplateId::Coordination => TtlPolicy::Required,
        TemplateId::BilateralPersistent => TtlPolicy::Forbidden,
        TemplateId::GroupDiscussion
        | TemplateId::PublicBroadcast
        | TemplateId::GatedBroadcast
        | TemplateId::ToolInterfaceTemplate
        | TemplateId::PaidService
        | TemplateId::PaidBroadcast
        | TemplateId::DiscoveryContext => TtlPolicy::Optional,
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates that a [`ContextParams`] matches its template definition, if a
/// `template_id` is present.
///
/// When `params.template_id` is `None`, this function returns `Ok(())`
/// immediately -- no template validation is needed for explicitly-configured
/// contexts.
///
/// When `params.template_id` is `Some(template)`, every field is compared
/// against the canonical template definition from [`template_params`]. The TTL
/// value itself is not compared (since the caller provides it), but the TTL
/// *policy* is enforced: templates that require a TTL reject `None`, and
/// templates that forbid a TTL reject `Some(_)`.
///
/// For paid templates (`PaidService`, `PaidBroadcast`), the `economic_policy`
/// field is validated: it must be present and contain the required cost fields.
/// See spec section 19.10 and ADR-033 criterion 13.
///
/// # Errors
///
/// Returns [`TemplateError::Mismatch`] if any non-TTL field does not match
/// the template definition.
///
/// Returns [`TemplateError::TtlRequired`] if the template requires a TTL but
/// `params.ttl` is `None`.
///
/// Returns [`TemplateError::TtlForbidden`] if the template forbids a TTL but
/// `params.ttl` is `Some(_)`.
///
/// Returns [`TemplateError::EconomicPolicyRequired`] if a paid template is
/// missing `economic_policy`.
///
/// Returns [`TemplateError::CostFieldRequired`] if a paid template's
/// `economic_policy` is missing a required cost field.
pub fn validate_against_template(params: &ContextParams) -> Result<(), TemplateError> {
    let Some(template_id) = &params.template_id else {
        return Ok(());
    };

    let expected = template_params(template_id);

    // Mode
    if params.mode != expected.mode {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "mode",
            expected: format!("{:?}", expected.mode),
            actual: format!("{:?}", params.mode),
        });
    }

    // Ceiling (order-independent comparison)
    if !capabilities_match(&params.ceiling, &expected.ceiling) {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "ceiling",
            expected: format_capabilities(&expected.ceiling),
            actual: format_capabilities(&params.ceiling),
        });
    }

    // Ceiling policy
    if params.ceiling_policy != expected.ceiling_policy {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "ceiling_policy",
            expected: format!("{:?}", expected.ceiling_policy),
            actual: format!("{:?}", params.ceiling_policy),
        });
    }

    // Promotion policy
    if params.promotion_policy != expected.promotion_policy {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "promotion_policy",
            expected: format!("{:?}", expected.promotion_policy),
            actual: format!("{:?}", params.promotion_policy),
        });
    }

    // Memory scope
    if params.memory_scope != expected.memory_scope {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "memory_scope",
            expected: format!("{:?}", expected.memory_scope),
            actual: format!("{:?}", params.memory_scope),
        });
    }

    // Governance
    if params.governance != expected.governance {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "governance",
            expected: format!("{:?}", expected.governance),
            actual: format!("{:?}", params.governance),
        });
    }

    // Roles
    if params.roles != expected.roles {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "roles",
            expected: format!("{:?}", expected.roles),
            actual: format!("{:?}", params.roles),
        });
    }

    // Tools
    if params.tools != expected.tools {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "tools",
            expected: format!("{:?}", expected.tools),
            actual: format!("{:?}", params.tools),
        });
    }

    // Governance-gaps fields: metadata visibility and projection policy.
    validate_governance_gaps_fields(*template_id, params, &expected)?;

    // Discoverable flag
    if params.discoverable != expected.discoverable {
        return Err(TemplateError::Mismatch {
            template: *template_id,
            field: "discoverable",
            expected: format!("{}", expected.discoverable),
            actual: format!("{}", params.discoverable),
        });
    }

    // TTL policy enforcement
    match ttl_policy(*template_id) {
        TtlPolicy::Required => {
            if params.ttl.is_none() {
                return Err(TemplateError::TtlRequired {
                    template: *template_id,
                });
            }
        }
        TtlPolicy::Forbidden => {
            if params.ttl.is_some() {
                return Err(TemplateError::TtlForbidden {
                    template: *template_id,
                });
            }
        }
        TtlPolicy::Optional => { /* TTL may or may not be present */ }
    }

    // Economic policy validation for paid templates.
    // Paid templates require economic_policy to be present and specific cost
    // fields to be set. See spec section 19.10 and ADR-033 criterion 13.
    validate_economic_policy_for_template(*template_id, params.economic_policy.as_ref())?;

    Ok(())
}

/// Validates cross-field invariants for [`ContextParams`] that apply regardless
/// of whether a template is used.
///
/// Currently enforces:
/// - `projection_policy` must be `None` for [`ContextMode::Encrypted`] contexts.
///   Projection is a broadcast-only feature (spec section 18.11.2.1).
///
/// # Errors
///
/// Returns [`TemplateError::ProjectionPolicyOnEncrypted`] if `projection_policy`
/// is `Some(_)` and `mode` is `Encrypted`.
pub fn validate_context_params(params: &ContextParams) -> Result<(), TemplateError> {
    if params.mode == ContextMode::Encrypted && params.projection_policy.is_some() {
        return Err(TemplateError::ProjectionPolicyOnEncrypted);
    }
    Ok(())
}

/// Validates metadata visibility and projection policy against template
/// definitions.
fn validate_governance_gaps_fields(
    template_id: TemplateId,
    params: &ContextParams,
    expected: &ContextParams,
) -> Result<(), TemplateError> {
    if params.metadata_visibility != expected.metadata_visibility {
        return Err(TemplateError::Mismatch {
            template: template_id,
            field: "metadata_visibility",
            expected: format!("{:?}", expected.metadata_visibility),
            actual: format!("{:?}", params.metadata_visibility),
        });
    }

    if params.projection_policy != expected.projection_policy {
        return Err(TemplateError::Mismatch {
            template: template_id,
            field: "projection_policy",
            expected: format!("{:?}", expected.projection_policy),
            actual: format!("{:?}", params.projection_policy),
        });
    }

    Ok(())
}

/// Validates economic policy requirements for paid templates.
///
/// - `PaidService` requires `economic_policy` with `per_tool_invoke` set.
/// - `PaidBroadcast` requires `economic_policy` with `per_period` set.
/// - All other templates have no economic policy requirements.
fn validate_economic_policy_for_template(
    template_id: TemplateId,
    economic_policy: Option<&crate::economy::EconomicPolicy>,
) -> Result<(), TemplateError> {
    match template_id {
        TemplateId::PaidService => {
            let policy = economic_policy.ok_or(TemplateError::EconomicPolicyRequired {
                template: template_id,
            })?;
            if policy.cost_schedule.per_tool_invoke.is_none() {
                return Err(TemplateError::CostFieldRequired {
                    template: template_id,
                    field: "per_tool_invoke",
                });
            }
        }
        TemplateId::PaidBroadcast => {
            let policy = economic_policy.ok_or(TemplateError::EconomicPolicyRequired {
                template: template_id,
            })?;
            if policy.cost_schedule.per_period.is_none() {
                return Err(TemplateError::CostFieldRequired {
                    template: template_id,
                    field: "per_period",
                });
            }
        }
        _ => { /* No economic policy requirements for other templates */ }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compares two capability slices for set equality (order-independent).
///
/// Two capability lists match if they contain the same capability names,
/// regardless of order. Duplicate capabilities are compared by count.
fn capabilities_match(a: &[Capability], b: &[Capability]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Sort names for comparison.
    let mut a_names: Vec<String> = a.iter().map(|c| c.name().into_owned()).collect();
    let mut b_names: Vec<String> = b.iter().map(|c| c.name().into_owned()).collect();
    a_names.sort_unstable();
    b_names.sort_unstable();
    a_names == b_names
}

/// Formats a capability list for error messages.
fn format_capabilities(caps: &[Capability]) -> String {
    let mut names: Vec<String> = caps.iter().map(|c| c.name().into_owned()).collect();
    names.sort_unstable();
    format!("[{}]", names.join(", "))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use super::*;

    // -----------------------------------------------------------------------
    // template_params produces valid ContextParams for each template
    // -----------------------------------------------------------------------

    #[test]
    fn bilateral_ephemeral_params_have_correct_fields() {
        let params = template_params(&TemplateId::BilateralEphemeral);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 3);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::BilateralEphemeral));
        assert_eq!(params.metadata_visibility, private_encrypted_visibility());
        assert!(params.projection_policy.is_none());
    }

    #[test]
    fn bilateral_persistent_params_have_correct_fields() {
        let params = template_params(&TemplateId::BilateralPersistent);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 3);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::BilateralPersistent));
        assert_eq!(params.metadata_visibility, private_encrypted_visibility());
        assert!(params.projection_policy.is_none());
    }

    #[test]
    fn coordination_params_have_correct_fields() {
        let params = template_params(&TemplateId::Coordination);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 4);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_TOOL_INVOKE_ALL)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Summary);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::Coordination));
        assert_eq!(params.metadata_visibility, private_encrypted_visibility());
        assert!(params.projection_policy.is_none());
    }

    #[test]
    fn group_discussion_params_have_correct_fields() {
        let params = template_params(&TemplateId::GroupDiscussion);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 4);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_INVITE));
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::Promotable);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::GroupDiscussion));
        assert_eq!(params.metadata_visibility, group_discussion_visibility());
        assert!(params.projection_policy.is_none());
    }

    #[test]
    fn public_broadcast_params_have_correct_fields() {
        let params = template_params(&TemplateId::PublicBroadcast);
        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 4);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_TOOL_INVOKE_ALL)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_TOOL_REGISTER));
        assert!(!params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::PublicBroadcast));
        assert_eq!(
            params.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );
        assert_eq!(
            params.projection_policy,
            Some(ProjectionPolicy {
                default_rule: ProjectionRule::Public,
                overrides: vec![],
            })
        );
    }

    #[test]
    fn gated_broadcast_params_have_correct_fields() {
        let params = template_params(&TemplateId::GatedBroadcast);
        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 4);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_TOOL_INVOKE_ALL)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_TOOL_REGISTER));
        assert!(!params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::GatedBroadcast));
        assert_eq!(params.metadata_visibility, member_count_hidden_visibility());
        assert_eq!(
            params.projection_policy,
            Some(ProjectionPolicy {
                default_rule: ProjectionRule::Gated,
                overrides: vec![],
            })
        );
    }

    // -----------------------------------------------------------------------
    // validate_against_template: no template_id passes immediately
    // -----------------------------------------------------------------------

    #[test]
    fn validate_no_template_id_returns_ok() {
        let params = ContextParams::default();
        assert!(validate_against_template(&params).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_against_template: valid params pass validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_bilateral_ephemeral_with_ttl_passes() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(3600));
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_bilateral_persistent_without_ttl_passes() {
        let params = template_params(&TemplateId::BilateralPersistent);
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_coordination_with_ttl_passes() {
        let mut params = template_params(&TemplateId::Coordination);
        params.ttl = Some(Duration::from_secs(7200));
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_group_discussion_without_ttl_passes() {
        let params = template_params(&TemplateId::GroupDiscussion);
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_group_discussion_with_ttl_passes() {
        let mut params = template_params(&TemplateId::GroupDiscussion);
        params.ttl = Some(Duration::from_secs(86400));
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_public_broadcast_without_ttl_passes() {
        let params = template_params(&TemplateId::PublicBroadcast);
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_gated_broadcast_without_ttl_passes() {
        let params = template_params(&TemplateId::GatedBroadcast);
        assert!(validate_against_template(&params).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_against_template: TTL policy enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn validate_bilateral_ephemeral_without_ttl_returns_ttl_required() {
        let params = template_params(&TemplateId::BilateralEphemeral);
        // ttl is None, but template requires it
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(err, TemplateError::TtlRequired { .. }));
    }

    #[test]
    fn validate_coordination_without_ttl_returns_ttl_required() {
        let params = template_params(&TemplateId::Coordination);
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(err, TemplateError::TtlRequired { .. }));
    }

    #[test]
    fn validate_bilateral_persistent_with_ttl_returns_ttl_forbidden() {
        let mut params = template_params(&TemplateId::BilateralPersistent);
        params.ttl = Some(Duration::from_secs(300));
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(err, TemplateError::TtlForbidden { .. }));
    }

    #[test]
    fn validate_public_broadcast_with_ttl_passes() {
        let mut params = template_params(&TemplateId::PublicBroadcast);
        params.ttl = Some(Duration::from_secs(600));
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_gated_broadcast_with_ttl_passes() {
        let mut params = template_params(&TemplateId::GatedBroadcast);
        params.ttl = Some(Duration::from_secs(600));
        assert!(validate_against_template(&params).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_against_template: field mismatch detection
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_wrong_mode() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.mode = ContextMode::Broadcast;
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(err, TemplateError::Mismatch { field: "mode", .. }));
    }

    #[test]
    fn validate_rejects_wrong_ceiling() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.ceiling.push(Capability::new(CAP_TOOL_INVOKE_ALL));
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "ceiling",
                ..
            }
        ));
    }

    #[test]
    fn validate_rejects_wrong_ceiling_policy() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.ceiling_policy = CeilingPolicy::Governed;
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "ceiling_policy",
                ..
            }
        ));
    }

    #[test]
    fn validate_rejects_wrong_promotion_policy() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.promotion_policy = PromotionPolicy::Promotable;
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "promotion_policy",
                ..
            }
        ));
    }

    #[test]
    fn validate_rejects_wrong_memory_scope() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.memory_scope = MemoryScope::Full;
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "memory_scope",
                ..
            }
        ));
    }

    #[test]
    fn validate_rejects_empty_ceiling_for_template() {
        let mut params = template_params(&TemplateId::Coordination);
        params.ttl = Some(Duration::from_secs(300));
        params.ceiling = Vec::new();
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "ceiling",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // validate_against_template: ceiling comparison is order-independent
    // -----------------------------------------------------------------------

    #[test]
    fn validate_accepts_ceiling_in_different_order() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        // Reverse the ceiling order
        params.ceiling = vec![
            Capability::new(CAP_MEMBER_BAN),
            Capability::new(CAP_MESSAGES_WRITE),
            Capability::new(CAP_MESSAGES_READ),
        ];
        assert!(validate_against_template(&params).is_ok());
    }

    // -----------------------------------------------------------------------
    // capabilities_match helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn capabilities_match_same_order() {
        let a = vec![Capability::new("a"), Capability::new("b")];
        let b = vec![Capability::new("a"), Capability::new("b")];
        assert!(capabilities_match(&a, &b));
    }

    #[test]
    fn capabilities_match_different_order() {
        let a = vec![Capability::new("b"), Capability::new("a")];
        let b = vec![Capability::new("a"), Capability::new("b")];
        assert!(capabilities_match(&a, &b));
    }

    #[test]
    fn capabilities_match_different_lengths() {
        let a = vec![Capability::new("a")];
        let b = vec![Capability::new("a"), Capability::new("b")];
        assert!(!capabilities_match(&a, &b));
    }

    #[test]
    fn capabilities_match_different_names() {
        let a = vec![Capability::new("a")];
        let b = vec![Capability::new("b")];
        assert!(!capabilities_match(&a, &b));
    }

    #[test]
    fn capabilities_match_empty() {
        let a: Vec<Capability> = vec![];
        let b: Vec<Capability> = vec![];
        assert!(capabilities_match(&a, &b));
    }

    // -----------------------------------------------------------------------
    // template_params sets template_id in output
    // -----------------------------------------------------------------------

    #[test]
    fn template_params_sets_template_id_for_all_variants() {
        let variants = [
            TemplateId::BilateralEphemeral,
            TemplateId::BilateralPersistent,
            TemplateId::Coordination,
            TemplateId::GroupDiscussion,
            TemplateId::PublicBroadcast,
            TemplateId::GatedBroadcast,
            TemplateId::ToolInterfaceTemplate,
            TemplateId::PaidService,
            TemplateId::PaidBroadcast,
            TemplateId::DiscoveryContext,
        ];
        for variant in &variants {
            let params = template_params(variant);
            assert_eq!(
                params.template_id.as_ref(),
                Some(variant),
                "template_id mismatch for {variant:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // TemplateError display messages
    // -----------------------------------------------------------------------

    #[test]
    fn template_error_mismatch_display() {
        let err = TemplateError::Mismatch {
            template: TemplateId::BilateralEphemeral,
            field: "mode",
            expected: "Encrypted".to_owned(),
            actual: "Broadcast".to_owned(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("template mismatch"));
        assert!(msg.contains("mode"));
        assert!(msg.contains("Encrypted"));
        assert!(msg.contains("Broadcast"));
    }

    #[test]
    fn template_error_ttl_required_display() {
        let err = TemplateError::TtlRequired {
            template: TemplateId::BilateralEphemeral,
        };
        let msg = format!("{err}");
        assert!(msg.contains("requires a TTL"));
    }

    #[test]
    fn template_error_ttl_forbidden_display() {
        let err = TemplateError::TtlForbidden {
            template: TemplateId::BilateralPersistent,
        };
        let msg = format!("{err}");
        assert!(msg.contains("forbids a TTL"));
    }

    // -----------------------------------------------------------------------
    // Broadcast templates use Broadcast mode, encrypted templates use Encrypted
    // -----------------------------------------------------------------------

    #[test]
    fn broadcast_templates_use_broadcast_mode() {
        assert_eq!(
            template_params(&TemplateId::PublicBroadcast).mode,
            ContextMode::Broadcast
        );
        assert_eq!(
            template_params(&TemplateId::GatedBroadcast).mode,
            ContextMode::Broadcast
        );
        assert_eq!(
            template_params(&TemplateId::PaidBroadcast).mode,
            ContextMode::Broadcast
        );
    }

    #[test]
    fn encrypted_templates_use_encrypted_mode() {
        assert_eq!(
            template_params(&TemplateId::BilateralEphemeral).mode,
            ContextMode::Encrypted
        );
        assert_eq!(
            template_params(&TemplateId::BilateralPersistent).mode,
            ContextMode::Encrypted
        );
        assert_eq!(
            template_params(&TemplateId::Coordination).mode,
            ContextMode::Encrypted
        );
        assert_eq!(
            template_params(&TemplateId::GroupDiscussion).mode,
            ContextMode::Encrypted
        );
        assert_eq!(
            template_params(&TemplateId::PaidService).mode,
            ContextMode::Encrypted
        );
        assert_eq!(
            template_params(&TemplateId::DiscoveryContext).mode,
            ContextMode::Encrypted
        );
    }

    // -----------------------------------------------------------------------
    // Cross-template validation: wrong template_id
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_bilateral_ephemeral_params_with_persistent_template_id() {
        // Start from BilateralEphemeral params but label as BilateralPersistent.
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.template_id = Some(TemplateId::BilateralPersistent);
        // BilateralPersistent expects Full memory, but BilateralEphemeral has Ephemeral.
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(err, TemplateError::Mismatch { .. }));
    }

    #[test]
    fn validate_rejects_coordination_params_with_bilateral_template_id() {
        // Coordination has 3 ceiling caps but BilateralEphemeral expects 2.
        let mut params = template_params(&TemplateId::Coordination);
        params.ttl = Some(Duration::from_secs(300));
        params.template_id = Some(TemplateId::BilateralEphemeral);
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(err, TemplateError::Mismatch { .. }));
    }

    // -----------------------------------------------------------------------
    // ContextParams::from_template -- convenience constructor
    // -----------------------------------------------------------------------

    #[test]
    fn from_template_matches_template_params_for_all_variants() {
        let variants = [
            TemplateId::BilateralEphemeral,
            TemplateId::BilateralPersistent,
            TemplateId::Coordination,
            TemplateId::GroupDiscussion,
            TemplateId::PublicBroadcast,
            TemplateId::GatedBroadcast,
            TemplateId::ToolInterfaceTemplate,
            TemplateId::PaidService,
            TemplateId::PaidBroadcast,
            TemplateId::DiscoveryContext,
        ];
        for variant in &variants {
            let from_method = ContextParams::from_template(*variant);
            let from_fn = template_params(variant);
            assert_eq!(
                from_method, from_fn,
                "from_template mismatch for {variant:?}"
            );
        }
    }

    #[test]
    fn from_template_bilateral_ephemeral_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::BilateralEphemeral);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(params.template_id, Some(TemplateId::BilateralEphemeral));
    }

    #[test]
    fn from_template_bilateral_persistent_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::BilateralPersistent);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.template_id, Some(TemplateId::BilateralPersistent));
    }

    #[test]
    fn from_template_coordination_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::Coordination);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 4);
        assert_eq!(params.memory_scope, MemoryScope::Summary);
        assert_eq!(params.template_id, Some(TemplateId::Coordination));
    }

    #[test]
    fn from_template_group_discussion_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::GroupDiscussion);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 4);
        assert_eq!(params.promotion_policy, PromotionPolicy::Promotable);
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.template_id, Some(TemplateId::GroupDiscussion));
    }

    #[test]
    fn from_template_public_broadcast_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::PublicBroadcast);
        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 4);
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.template_id, Some(TemplateId::PublicBroadcast));
    }

    #[test]
    fn from_template_gated_broadcast_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::GatedBroadcast);
        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 4);
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.template_id, Some(TemplateId::GatedBroadcast));
    }

    // -----------------------------------------------------------------------
    // validate_against_template: roles and tools validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_unexpected_roles() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.roles = vec![super::super::roles::RoleDefinition {
            name: "smuggled".to_owned(),
            capabilities: std::collections::HashSet::from([
                super::super::params::Capability::MessagesRead,
            ]),
        }];
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch { field: "roles", .. }
        ));
    }

    #[test]
    fn validate_rejects_unexpected_tools() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        params.tools = vec![super::super::tools::ToolRegistration {
            tool_id: "rogue-tool".to_owned(),
            name: "rogue-tool".to_owned(),
            description: "Rogue tool for testing".to_owned(),
            schema: super::super::tools::ToolSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkTestOperator".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        }];
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch { field: "tools", .. }
        ));
    }

    // -----------------------------------------------------------------------
    // TemplateError converts to ContextError via From impl
    // -----------------------------------------------------------------------

    #[test]
    fn template_error_converts_to_context_error() {
        use super::super::ContextError;

        let template_err = TemplateError::TtlRequired {
            template: TemplateId::BilateralEphemeral,
        };
        let context_err: ContextError = template_err.into();
        assert!(
            matches!(context_err, ContextError::TemplateMismatch(_)),
            "expected ContextError::TemplateMismatch, got {context_err:?}"
        );
    }

    #[test]
    fn validate_against_template_error_converts_to_context_error() {
        use super::super::ContextError;

        // BilateralEphemeral requires TTL but template_params returns ttl=None.
        let params = template_params(&TemplateId::BilateralEphemeral);
        let result: Result<(), ContextError> =
            validate_against_template(&params).map_err(ContextError::from);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("requires a TTL"));
    }

    // -----------------------------------------------------------------------
    // Paid template helpers
    // -----------------------------------------------------------------------

    /// Creates a minimal `EconomicPolicy` with `per_tool_invoke` set.
    fn paid_service_policy() -> crate::economy::EconomicPolicy {
        crate::economy::EconomicPolicy {
            locked: false,
            cost_schedule: crate::economy::CostSchedule {
                currency: crate::economy::CurrencyCode::from("USD"),
                per_message: None,
                per_tool_invoke: Some(crate::economy::Amount(100)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: scp_identity::DID::from("did:dht:z6MkTestPayee"),
        }
    }

    /// Creates a minimal `EconomicPolicy` with `per_period` set.
    fn paid_broadcast_policy() -> crate::economy::EconomicPolicy {
        crate::economy::EconomicPolicy {
            locked: false,
            cost_schedule: crate::economy::CostSchedule {
                currency: crate::economy::CurrencyCode::from("USD"),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: Some(crate::economy::SubscriptionCost {
                    amount: crate::economy::Amount(999),
                    period: crate::economy::SubscriptionPeriod::Monthly,
                    currency: crate::economy::CurrencyCode::from("USD"),
                }),
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: scp_identity::DID::from("did:dht:z6MkTestPayee"),
        }
    }

    // -----------------------------------------------------------------------
    // PaidService template: template_params correctness
    // -----------------------------------------------------------------------

    #[test]
    fn paid_service_params_have_correct_fields() {
        let params = template_params(&TemplateId::PaidService);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 5);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_TOOL_INVOKE_ALL)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_TOOL_REGISTER));
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::PaidService));
        // economic_policy is None in template defaults; caller must supply it.
        assert!(params.economic_policy.is_none());
        assert_eq!(params.metadata_visibility, member_count_hidden_visibility());
        assert!(params.projection_policy.is_none());
    }

    // -----------------------------------------------------------------------
    // PaidBroadcast template: template_params correctness
    // -----------------------------------------------------------------------

    #[test]
    fn paid_broadcast_params_have_correct_fields() {
        let params = template_params(&TemplateId::PaidBroadcast);
        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 2);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(!params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::PaidBroadcast));
        assert!(params.economic_policy.is_none());
        assert_eq!(params.metadata_visibility, member_count_hidden_visibility());
        assert_eq!(
            params.projection_policy,
            Some(ProjectionPolicy {
                default_rule: ProjectionRule::Gated,
                overrides: vec![],
            })
        );
    }

    // -----------------------------------------------------------------------
    // PaidService: valid creation with economic_policy
    // -----------------------------------------------------------------------

    #[test]
    fn validate_paid_service_with_valid_economic_policy_passes() {
        let mut params = template_params(&TemplateId::PaidService);
        params.economic_policy = Some(paid_service_policy());
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_paid_service_with_ttl_passes() {
        let mut params = template_params(&TemplateId::PaidService);
        params.economic_policy = Some(paid_service_policy());
        params.ttl = Some(Duration::from_secs(3600));
        assert!(validate_against_template(&params).is_ok());
    }

    // -----------------------------------------------------------------------
    // PaidService: missing economic_policy rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_paid_service_without_economic_policy_rejected() {
        let params = template_params(&TemplateId::PaidService);
        // economic_policy is None (not supplied)
        let err = validate_against_template(&params).unwrap_err();
        assert!(
            matches!(err, TemplateError::EconomicPolicyRequired { .. }),
            "expected EconomicPolicyRequired, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // PaidService: missing per_tool_invoke rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_paid_service_without_per_tool_invoke_rejected() {
        let mut params = template_params(&TemplateId::PaidService);
        let mut policy = paid_service_policy();
        policy.cost_schedule.per_tool_invoke = None;
        params.economic_policy = Some(policy);
        let err = validate_against_template(&params).unwrap_err();
        assert!(
            matches!(
                err,
                TemplateError::CostFieldRequired {
                    field: "per_tool_invoke",
                    ..
                }
            ),
            "expected CostFieldRequired(per_tool_invoke), got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // PaidBroadcast: valid creation with economic_policy
    // -----------------------------------------------------------------------

    #[test]
    fn validate_paid_broadcast_with_valid_economic_policy_passes() {
        let mut params = template_params(&TemplateId::PaidBroadcast);
        params.economic_policy = Some(paid_broadcast_policy());
        assert!(validate_against_template(&params).is_ok());
    }

    #[test]
    fn validate_paid_broadcast_with_ttl_passes() {
        let mut params = template_params(&TemplateId::PaidBroadcast);
        params.economic_policy = Some(paid_broadcast_policy());
        params.ttl = Some(Duration::from_secs(86400));
        assert!(validate_against_template(&params).is_ok());
    }

    // -----------------------------------------------------------------------
    // PaidBroadcast: missing economic_policy rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_paid_broadcast_without_economic_policy_rejected() {
        let params = template_params(&TemplateId::PaidBroadcast);
        let err = validate_against_template(&params).unwrap_err();
        assert!(
            matches!(err, TemplateError::EconomicPolicyRequired { .. }),
            "expected EconomicPolicyRequired, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // PaidBroadcast: missing per_period rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_paid_broadcast_without_per_period_rejected() {
        let mut params = template_params(&TemplateId::PaidBroadcast);
        let mut policy = paid_broadcast_policy();
        policy.cost_schedule.per_period = None;
        params.economic_policy = Some(policy);
        let err = validate_against_template(&params).unwrap_err();
        assert!(
            matches!(
                err,
                TemplateError::CostFieldRequired {
                    field: "per_period",
                    ..
                }
            ),
            "expected CostFieldRequired(per_period), got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // TemplateId serialization: paid variants use scp:template/ URIs
    // -----------------------------------------------------------------------

    #[test]
    fn template_id_paid_service_serializes_to_uri() {
        let json = serde_json::to_string(&TemplateId::PaidService).unwrap();
        assert_eq!(json, r#""scp:template/paid-service""#);
    }

    #[test]
    fn template_id_paid_broadcast_serializes_to_uri() {
        let json = serde_json::to_string(&TemplateId::PaidBroadcast).unwrap();
        assert_eq!(json, r#""scp:template/paid-broadcast""#);
    }

    #[test]
    fn template_id_paid_service_deserializes_from_uri() {
        let deserialized: TemplateId =
            serde_json::from_str(r#""scp:template/paid-service""#).unwrap();
        assert_eq!(deserialized, TemplateId::PaidService);
    }

    #[test]
    fn template_id_paid_broadcast_deserializes_from_uri() {
        let deserialized: TemplateId =
            serde_json::from_str(r#""scp:template/paid-broadcast""#).unwrap();
        assert_eq!(deserialized, TemplateId::PaidBroadcast);
    }

    #[test]
    fn template_id_paid_service_serde_roundtrip() {
        let json = serde_json::to_string(&TemplateId::PaidService).unwrap();
        let deserialized: TemplateId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, TemplateId::PaidService);
    }

    #[test]
    fn template_id_paid_broadcast_serde_roundtrip() {
        let json = serde_json::to_string(&TemplateId::PaidBroadcast).unwrap();
        let deserialized: TemplateId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, TemplateId::PaidBroadcast);
    }

    // -----------------------------------------------------------------------
    // TemplateError display messages for economic policy errors
    // -----------------------------------------------------------------------

    #[test]
    fn template_error_economic_policy_required_display() {
        let err = TemplateError::EconomicPolicyRequired {
            template: TemplateId::PaidService,
        };
        let msg = format!("{err}");
        assert!(msg.contains("requires an economic_policy"));
        assert!(msg.contains("PaidService"));
    }

    #[test]
    fn template_error_cost_field_required_display() {
        let err = TemplateError::CostFieldRequired {
            template: TemplateId::PaidService,
            field: "per_tool_invoke",
        };
        let msg = format!("{err}");
        assert!(msg.contains("per_tool_invoke"));
        assert!(msg.contains("PaidService"));
    }

    // -----------------------------------------------------------------------
    // Paid templates: from_template convenience constructor
    // -----------------------------------------------------------------------

    #[test]
    fn from_template_paid_service_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::PaidService);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 5);
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::PaidService));
    }

    #[test]
    fn from_template_paid_broadcast_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::PaidBroadcast);
        assert_eq!(params.mode, ContextMode::Broadcast);
        assert_eq!(params.ceiling.len(), 2);
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::PaidBroadcast));
    }

    // -----------------------------------------------------------------------
    // Paid template economic policy errors convert to ContextError
    // -----------------------------------------------------------------------

    #[test]
    fn economic_policy_required_error_converts_to_context_error() {
        use super::super::ContextError;

        let params = template_params(&TemplateId::PaidService);
        let result: Result<(), ContextError> =
            validate_against_template(&params).map_err(ContextError::from);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::TemplateMismatch(_)),
            "expected ContextError::TemplateMismatch, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // MemberBan: encrypted templates include it, broadcast templates do not
    // -----------------------------------------------------------------------

    #[test]
    fn encrypted_templates_include_member_ban_in_ceiling() {
        let encrypted_templates = [
            TemplateId::BilateralEphemeral,
            TemplateId::BilateralPersistent,
            TemplateId::Coordination,
            TemplateId::GroupDiscussion,
            TemplateId::ToolInterfaceTemplate,
            TemplateId::PaidService,
            TemplateId::DiscoveryContext,
        ];
        for tid in &encrypted_templates {
            let params = template_params(tid);
            assert!(
                params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN),
                "encrypted template {tid:?} should include member:ban in ceiling"
            );
        }
    }

    #[test]
    fn broadcast_templates_do_not_include_member_ban_in_ceiling() {
        let broadcast_templates = [
            TemplateId::PublicBroadcast,
            TemplateId::GatedBroadcast,
            TemplateId::PaidBroadcast,
        ];
        for tid in &broadcast_templates {
            let params = template_params(tid);
            assert!(
                !params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_BAN),
                "broadcast template {tid:?} should NOT include member:ban in ceiling"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Metadata visibility: template-specific defaults
    // -----------------------------------------------------------------------

    #[test]
    fn private_encrypted_templates_have_private_visibility() {
        let private_templates = [
            TemplateId::BilateralEphemeral,
            TemplateId::BilateralPersistent,
            TemplateId::Coordination,
        ];
        let expected = private_encrypted_visibility();
        for tid in &private_templates {
            let params = template_params(tid);
            assert_eq!(
                params.metadata_visibility, expected,
                "template {tid:?} should have private encrypted visibility"
            );
        }
    }

    #[test]
    fn group_discussion_has_group_visibility() {
        let params = template_params(&TemplateId::GroupDiscussion);
        let expected = group_discussion_visibility();
        assert_eq!(params.metadata_visibility, expected);
        // Verify specific fields
        assert_eq!(
            params.metadata_visibility.member_count,
            FieldVisibility::PreJoin
        );
        assert_eq!(
            params.metadata_visibility.creator_identity,
            FieldVisibility::PreJoin
        );
        assert_eq!(
            params.metadata_visibility.context_age,
            FieldVisibility::MemberOnly
        );
    }

    #[test]
    fn public_broadcast_has_all_pre_join_visibility() {
        let params = template_params(&TemplateId::PublicBroadcast);
        assert_eq!(
            params.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );
    }

    #[test]
    fn tool_interface_has_all_pre_join_visibility() {
        let params = template_params(&TemplateId::ToolInterfaceTemplate);
        assert_eq!(
            params.metadata_visibility,
            MetadataVisibilityPolicy::default()
        );
    }

    #[test]
    fn gated_broadcast_has_member_count_hidden_visibility() {
        let params = template_params(&TemplateId::GatedBroadcast);
        assert_eq!(
            params.metadata_visibility.member_count,
            FieldVisibility::MemberOnly
        );
        // All other fields remain PreJoin.
        assert_eq!(
            params.metadata_visibility.context_age,
            FieldVisibility::PreJoin
        );
        assert_eq!(params.metadata_visibility.name, FieldVisibility::PreJoin);
    }

    #[test]
    fn paid_service_has_member_count_hidden_visibility() {
        let params = template_params(&TemplateId::PaidService);
        assert_eq!(params.metadata_visibility, member_count_hidden_visibility());
    }

    #[test]
    fn paid_broadcast_has_member_count_hidden_visibility() {
        let params = template_params(&TemplateId::PaidBroadcast);
        assert_eq!(params.metadata_visibility, member_count_hidden_visibility());
    }

    // -----------------------------------------------------------------------
    // Projection policy: template-specific defaults
    // -----------------------------------------------------------------------

    #[test]
    fn encrypted_templates_have_no_projection_policy() {
        let encrypted_templates = [
            TemplateId::BilateralEphemeral,
            TemplateId::BilateralPersistent,
            TemplateId::Coordination,
            TemplateId::GroupDiscussion,
            TemplateId::ToolInterfaceTemplate,
            TemplateId::PaidService,
            TemplateId::DiscoveryContext,
        ];
        for tid in &encrypted_templates {
            let params = template_params(tid);
            assert!(
                params.projection_policy.is_none(),
                "encrypted template {tid:?} should have no projection_policy"
            );
        }
    }

    #[test]
    fn public_broadcast_has_public_projection_policy() {
        let params = template_params(&TemplateId::PublicBroadcast);
        let policy = params.projection_policy.unwrap();
        assert_eq!(policy.default_rule, ProjectionRule::Public);
        assert!(policy.overrides.is_empty());
    }

    #[test]
    fn gated_broadcast_has_gated_projection_policy() {
        let params = template_params(&TemplateId::GatedBroadcast);
        let policy = params.projection_policy.unwrap();
        assert_eq!(policy.default_rule, ProjectionRule::Gated);
        assert!(policy.overrides.is_empty());
    }

    #[test]
    fn paid_broadcast_has_gated_projection_policy() {
        let params = template_params(&TemplateId::PaidBroadcast);
        let policy = params.projection_policy.unwrap();
        assert_eq!(policy.default_rule, ProjectionRule::Gated);
        assert!(policy.overrides.is_empty());
    }

    // -----------------------------------------------------------------------
    // validate_context_params: projection_policy on encrypted is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_context_params_rejects_projection_policy_on_encrypted() {
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            projection_policy: Some(ProjectionPolicy {
                default_rule: ProjectionRule::Public,
                overrides: vec![],
            }),
            ..ContextParams::default()
        };
        let err = validate_context_params(&params).unwrap_err();
        assert!(matches!(err, TemplateError::ProjectionPolicyOnEncrypted));
    }

    #[test]
    fn validate_context_params_accepts_projection_policy_on_broadcast() {
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            projection_policy: Some(ProjectionPolicy {
                default_rule: ProjectionRule::Public,
                overrides: vec![],
            }),
            ..ContextParams::default()
        };
        assert!(validate_context_params(&params).is_ok());
    }

    #[test]
    fn validate_context_params_accepts_no_projection_policy_on_encrypted() {
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            projection_policy: None,
            ..ContextParams::default()
        };
        assert!(validate_context_params(&params).is_ok());
    }

    #[test]
    fn validate_context_params_accepts_no_projection_policy_on_broadcast() {
        let params = ContextParams {
            mode: ContextMode::Broadcast,
            projection_policy: None,
            ..ContextParams::default()
        };
        assert!(validate_context_params(&params).is_ok());
    }

    #[test]
    fn projection_policy_on_encrypted_error_display() {
        let err = TemplateError::ProjectionPolicyOnEncrypted;
        let msg = format!("{err}");
        assert!(msg.contains("projection_policy"));
        assert!(msg.contains("Broadcast"));
        assert!(msg.contains("Encrypted"));
    }

    // -----------------------------------------------------------------------
    // validate_against_template: metadata_visibility mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_wrong_metadata_visibility() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        // Set all-PreJoin visibility (the default), which does not match the
        // private_encrypted_visibility expected by BilateralEphemeral.
        params.metadata_visibility = MetadataVisibilityPolicy::default();
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "metadata_visibility",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // validate_against_template: projection_policy mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_wrong_projection_policy_for_broadcast() {
        let mut params = template_params(&TemplateId::PublicBroadcast);
        // PublicBroadcast expects Public projection, set to Gated.
        params.projection_policy = Some(ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![],
        });
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "projection_policy",
                ..
            }
        ));
    }

    #[test]
    fn validate_rejects_projection_policy_on_encrypted_template() {
        let mut params = template_params(&TemplateId::BilateralEphemeral);
        params.ttl = Some(Duration::from_secs(300));
        // BilateralEphemeral expects projection_policy: None
        params.projection_policy = Some(ProjectionPolicy {
            default_rule: ProjectionRule::Public,
            overrides: vec![],
        });
        let err = validate_against_template(&params).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Mismatch {
                field: "projection_policy",
                ..
            }
        ));
    }
}
