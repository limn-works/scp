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
//! See ADR-008 in `.docs/adrs/phase-2.md` for the full specification.

use super::params::{
    Capability, CeilingPolicy, ContextMode, ContextParams, GovernanceModel, MemoryScope,
    PromotionPolicy, TemplateId,
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
}

// ---------------------------------------------------------------------------
// Well-known capability names
// ---------------------------------------------------------------------------

/// Standard capability name for reading messages.
const CAP_MESSAGES_READ: &str = "messages:read";
/// Standard capability name for writing messages.
const CAP_MESSAGES_WRITE: &str = "messages:write";
/// Standard capability name for invoking any registered tool.
const CAP_TOOL_INVOKE_ALL: &str = "tool:invoke_all";
/// Standard capability name for registering new tools.
const CAP_TOOL_REGISTER: &str = "tool:register";
/// Standard capability name for inviting new members.
const CAP_MEMBER_INVITE: &str = "member:invite";

// ---------------------------------------------------------------------------
// Template definitions
// ---------------------------------------------------------------------------

/// Returns the messaging-only ceiling: `messages:read` + `messages:write`.
fn messaging_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
    ]
}

/// Returns the messaging + tool invoke ceiling: messaging + `tool:invoke_all`.
///
/// Used by the Coordination template (spec section 5.12.1). Tools are
/// creator-defined at creation time, so only `tool:invoke_all` is in the
/// ceiling — members can invoke tools but not dynamically register new ones.
fn messaging_tool_invoke_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_TOOL_INVOKE_ALL),
    ]
}

/// Returns the messaging + full tools ceiling: messaging + `tool:invoke_all` +
/// `tool:register`.
///
/// Used by broadcast templates (spec section 5.12.1) where authors can both
/// invoke and register tools.
fn messaging_tools_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_TOOL_INVOKE_ALL),
        Capability::new(CAP_TOOL_REGISTER),
    ]
}

/// Returns the messaging + invite ceiling: messaging + `member:invite`.
fn messaging_invite_ceiling() -> Vec<Capability> {
    vec![
        Capability::new(CAP_MESSAGES_READ),
        Capability::new(CAP_MESSAGES_WRITE),
        Capability::new(CAP_MEMBER_INVITE),
    ]
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
/// | Template | Mode | Ceiling | Ceiling Policy | Promotion | Memory | Governance | TTL |
/// |----------|------|---------|----------------|-----------|--------|------------|-----|
/// | `BilateralEphemeral` | Encrypted | messages | Immutable | NoPromotion | Ephemeral | SingleAdmin | Required |
/// | `BilateralPersistent` | Encrypted | messages | Immutable | NoPromotion | Full | SingleAdmin | Forbidden |
/// | `Coordination` | Encrypted | messages + invoke | Immutable | NoPromotion | Summary | SingleAdmin | Required |
/// | `GroupDiscussion` | Encrypted | messages + invite | Immutable | Promotable | Full | SingleAdmin | Optional |
/// | `PublicBroadcast` | Broadcast | messages + tools | Immutable | NoPromotion | Full | SingleAdmin | Optional |
/// | `GatedBroadcast` | Broadcast | messages + tools | Immutable | NoPromotion | Full | SingleAdmin | Optional |
#[must_use]
pub fn template_params(template_id: &TemplateId) -> ContextParams {
    match template_id {
        TemplateId::BilateralEphemeral => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Ephemeral,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralEphemeral),
        },
        TemplateId::BilateralPersistent => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralPersistent),
        },
        TemplateId::Coordination => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_tool_invoke_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Summary,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::Coordination),
        },
        TemplateId::GroupDiscussion => ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: messaging_invite_ceiling(),
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::Promotable,
            roles: Vec::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: MemoryScope::Full,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::GroupDiscussion),
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
        TemplateId::GroupDiscussion | TemplateId::PublicBroadcast | TemplateId::GatedBroadcast => {
            TtlPolicy::Optional
        }
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
    let mut a_names: Vec<&str> = a.iter().map(Capability::name).collect();
    let mut b_names: Vec<&str> = b.iter().map(Capability::name).collect();
    a_names.sort_unstable();
    b_names.sort_unstable();
    a_names == b_names
}

/// Formats a capability list for error messages.
fn format_capabilities(caps: &[Capability]) -> String {
    let mut names: Vec<&str> = caps.iter().map(Capability::name).collect();
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
        assert_eq!(params.ceiling.len(), 2);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::BilateralEphemeral));
    }

    #[test]
    fn bilateral_persistent_params_have_correct_fields() {
        let params = template_params(&TemplateId::BilateralPersistent);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 2);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::BilateralPersistent));
    }

    #[test]
    fn coordination_params_have_correct_fields() {
        let params = template_params(&TemplateId::Coordination);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 3);
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
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Summary);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::Coordination));
    }

    #[test]
    fn group_discussion_params_have_correct_fields() {
        let params = template_params(&TemplateId::GroupDiscussion);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 3);
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MESSAGES_READ));
        assert!(
            params
                .ceiling
                .iter()
                .any(|c| c.name() == CAP_MESSAGES_WRITE)
        );
        assert!(params.ceiling.iter().any(|c| c.name() == CAP_MEMBER_INVITE));
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::Promotable);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::GroupDiscussion));
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
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::PublicBroadcast));
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
        assert_eq!(params.ceiling_policy, CeilingPolicy::Immutable);
        assert_eq!(params.promotion_policy, PromotionPolicy::NoPromotion);
        assert!(params.roles.is_empty());
        assert!(params.tools.is_empty());
        assert!(params.ttl.is_none());
        assert_eq!(params.memory_scope, MemoryScope::Full);
        assert_eq!(params.governance, GovernanceModel::SingleAdmin);
        assert_eq!(params.template_id, Some(TemplateId::GatedBroadcast));
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
        assert_eq!(params.ceiling.len(), 3);
        assert_eq!(params.memory_scope, MemoryScope::Summary);
        assert_eq!(params.template_id, Some(TemplateId::Coordination));
    }

    #[test]
    fn from_template_group_discussion_produces_valid_params() {
        let params = ContextParams::from_template(TemplateId::GroupDiscussion);
        assert_eq!(params.mode, ContextMode::Encrypted);
        assert_eq!(params.ceiling.len(), 3);
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
        params.roles = vec![super::super::params::RoleDefinition {
            name: "smuggled".to_owned(),
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
        params.tools = vec![super::super::params::ToolRegistration {
            name: "rogue-tool".to_owned(),
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
}
