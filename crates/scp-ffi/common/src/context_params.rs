//! Shared context-parameter builder for all FFI bridges.
//!
//! Each bridge (`PyO3`, napi-rs, `UniFFI`) converts its native input type
//! (`PyDict`, JSON, `UniFFI` Record) into [`CommonContextParams`], then calls
//! [`build_context_params`] to produce the core [`ContextParams`]. This
//! eliminates the duplicated ceiling parsing, governance model construction,
//! TTL configuration, consequence-rule validation, etc. that previously lived
//! independently in each bridge (the duplication class that caused #1419).
//!
//! Requires the `resolvers` feature (scp-core dependency).

use std::time::Duration;

use scp_core::context::ContextParams;
use scp_core::context::params::{
    CeilingPolicy, ConsequenceConfig, ContextMode, GovernanceModel, IncompleteVerificationPolicy,
    MemoryScope, MetadataVisibilityPolicy, OutletRegistration, PromotionPolicy, RoleDefinition,
};
use scp_core::context::roles::Capability;
use scp_core::provenance::CounterpartyPolicy;
use scp_core::trust::ConsequenceRule;

// ---------------------------------------------------------------------------
// Bridge-agnostic intermediate type
// ---------------------------------------------------------------------------

/// Bridge-agnostic context creation parameters.
///
/// Each FFI bridge converts its native input type (`PyDict`, JSON, `UniFFI` Record)
/// into this common struct, then calls [`build_context_params`] to produce the
/// core [`ContextParams`].
///
/// All string fields use the same canonical values as the core types:
/// - `mode`: `"encrypted"` or `"broadcast"`
/// - `ceiling_policy`: `"immutable"` or `"governed"`
/// - `promotion_policy`: `"no_promotion"` or `"promotable"`
/// - `memory_scope`: `"ephemeral"`, `"summary"`, or `"full"`
/// - `governance`: `"single_admin"`
#[derive(Debug, Clone, Default)]
pub struct CommonContextParams {
    /// Context processing mode: `"encrypted"` (default) or `"broadcast"`.
    pub mode: String,

    /// Capability ceiling — maximum capabilities any participant can hold.
    /// Each string is parsed via [`Capability::new`].
    pub ceiling: Vec<String>,

    /// Ceiling mutability policy: `"immutable"` (default) or `"governed"`.
    pub ceiling_policy: String,

    /// Promotion policy: `"no_promotion"` (default) or `"promotable"`.
    pub promotion_policy: String,

    /// Memory scope: `"ephemeral"` (default), `"summary"`, or `"full"`.
    pub memory_scope: String,

    /// Governance model: `"single_admin"`, `"threshold"`, `"majority"`, `"unanimity"`.
    pub governance: String,

    /// Threshold for threshold governance (required when governance = "threshold").
    pub governance_threshold: Option<u32>,

    /// Signer DIDs for threshold governance.
    pub governance_signers: Option<Vec<String>>,

    /// Eligible voter DIDs for majority/unanimity governance.
    pub governance_voters: Option<Vec<String>>,

    /// Optional time-to-live. Each bridge converts its native TTL
    /// representation into a [`Duration`] before populating this field.
    pub ttl: Option<Duration>,

    /// Optional minimum protocol version as `(major, minor)`.
    pub min_protocol_version: Option<(u8, u8)>,

    /// Maximum cross-context chain depth (spec §24.4, ADR-043).
    pub max_chain_depth: Option<u8>,

    /// Maximum nesting depth for sub-contexts (spec §5.6, ADR-043).
    pub max_nesting_depth: Option<u32>,

    /// Per-caller session cap (spec §6.2.1, ADR-043).
    pub session_cap: Option<u32>,

    /// Optional economic policy as a JSON string (spec §19, ADR-033).
    pub economic_policy_json: Option<String>,

    /// Consequence rules as a JSON string (ADR-017, #1531).
    /// `None` or empty string means no rules.
    pub consequence_rules_json: Option<String>,

    /// Consequence config as a JSON string (ADR-017, #1531).
    /// `None` means default config.
    pub consequence_config_json: Option<String>,

    /// Role definitions mapping role names to capability lists.
    /// Used by `PyO3` bridge; others leave empty.
    pub roles: Vec<(String, Vec<String>)>,

    /// Initial outlet names. Used by `PyO3` bridge; others leave empty.
    pub outlets: Vec<String>,

    /// Optional template identifier (spec §5.14). Used by `PyO3` bridge.
    pub template_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Converts bridge-agnostic [`CommonContextParams`] into the core
/// [`ContextParams`], performing all shared parsing and validation.
///
/// # Errors
///
/// Returns `Err(String)` on:
/// - Unsupported governance model (only `"single_admin"` is currently valid)
/// - Invalid JSON in `economic_policy_json`, `consequence_rules_json`, or
///   `consequence_config_json`
/// - Consequence rule validation failure against the config
pub fn build_context_params(params: &CommonContextParams) -> Result<ContextParams, String> {
    let mode = match params.mode.as_str() {
        "broadcast" | "Broadcast" => ContextMode::Broadcast,
        _ => ContextMode::Encrypted,
    };
    let ceiling: Vec<Capability> = params.ceiling.iter().map(Capability::new).collect();
    let ceiling_policy = match params.ceiling_policy.as_str() {
        "governed" => CeilingPolicy::Governed,
        _ => CeilingPolicy::Immutable,
    };
    let promotion_policy = match params.promotion_policy.as_str() {
        "promotable" => PromotionPolicy::Promotable,
        _ => PromotionPolicy::NoPromotion,
    };
    let memory_scope = match params.memory_scope.as_str() {
        "summary" => MemoryScope::Summary,
        "full" => MemoryScope::Full,
        _ => MemoryScope::Ephemeral,
    };
    let governance = parse_governance(&params.governance, params)?;
    let ttl = params.ttl;
    let economic_policy = parse_economic_policy(params.economic_policy_json.as_ref())?;
    let (consequence_rules, consequence_config) = parse_and_validate_consequences(
        params.consequence_rules_json.as_ref(),
        params.consequence_config_json.as_ref(),
    )?;
    let template_id = params
        .template_id
        .as_deref()
        .and_then(|tid| parse_template_id(tid).ok());

    Ok(ContextParams {
        mode,
        ceiling,
        ceiling_policy,
        promotion_policy,
        roles: build_roles(&params.roles),
        tools: build_outlets(&params.outlets),
        ttl,
        memory_scope,
        governance,
        template_id,
        economic_policy,
        metadata_visibility: MetadataVisibilityPolicy::default(),
        projection_policy: None,
        discoverable: false,
        max_chain_depth: params.max_chain_depth,
        max_nesting_depth: params.max_nesting_depth,
        session_cap: params.session_cap,
        counterparty_policy: CounterpartyPolicy::default(),
        participation_requirements: Vec::new(),
        capability_requirements: Vec::new(),
        incomplete_verification_policy: IncompleteVerificationPolicy::default(),
        min_protocol_version: params.min_protocol_version,
        migration_source: None,
        consequence_rules,
        consequence_config,
        sybil_policy: None,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers (keep build_context_params under 100 lines)
// ---------------------------------------------------------------------------

/// Validates and parses the governance model string.
fn parse_governance(
    governance: &str,
    params: &CommonContextParams,
) -> Result<GovernanceModel, String> {
    match governance {
        "single_admin" | "" => Ok(GovernanceModel::SingleAdmin),
        "threshold" | "multisig" => {
            let threshold = params.governance_threshold.unwrap_or(1);
            let signers = params.governance_signers.clone().unwrap_or_default();
            if signers.is_empty() {
                // No signers provided — fall back to SingleAdmin.
                // This preserves backward compatibility for UniFFI callers
                // using the legacy Multisig variant without signer parameters.
                return Ok(GovernanceModel::SingleAdmin);
            }
            Ok(GovernanceModel::Threshold {
                threshold,
                signers: signers.into_iter().map(scp_did::DID::from).collect(),
            })
        }
        "majority" | "token_voting" => {
            let voters = params.governance_voters.clone().unwrap_or_default();
            if voters.is_empty() {
                // No voters provided — fall back to SingleAdmin.
                // Preserves backward compat for UniFFI TokenVoting without voters.
                return Ok(GovernanceModel::SingleAdmin);
            }
            Ok(GovernanceModel::Majority {
                eligible_voters: voters.into_iter().map(scp_did::DID::from).collect(),
            })
        }
        "unanimity" => {
            let voters = params.governance_voters.clone().unwrap_or_default();
            if voters.is_empty() {
                return Ok(GovernanceModel::SingleAdmin);
            }
            Ok(GovernanceModel::Unanimity {
                eligible_voters: voters.into_iter().map(scp_did::DID::from).collect(),
            })
        }
        other => Err(format!(
            "unsupported governance model: {other:?} — \
             expected \"single_admin\", \"threshold\", \"majority\", or \"unanimity\""
        )),
    }
}

/// Parses an optional economic policy JSON string.
fn parse_economic_policy(
    json: Option<&String>,
) -> Result<Option<scp_core::economy::EconomicPolicy>, String> {
    json.map(String::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(s).map_err(|e| format!("invalid economic_policy JSON: {e}")))
        .transpose()
}

/// Parses and cross-validates consequence rules and config from JSON strings.
fn parse_and_validate_consequences(
    rules_json: Option<&String>,
    config_json: Option<&String>,
) -> Result<(Vec<ConsequenceRule>, ConsequenceConfig), String> {
    let rules: Vec<ConsequenceRule> = rules_json
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| {
            serde_json::from_str(s).map_err(|e| format!("invalid consequence_rules JSON: {e}"))
        })
        .transpose()?
        .unwrap_or_default();
    let config: ConsequenceConfig = config_json
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| {
            serde_json::from_str(s).map_err(|e| format!("invalid consequence_config JSON: {e}"))
        })
        .transpose()?
        .unwrap_or_default();
    for rule in &rules {
        rule.validate_against_config(&config)
            .map_err(|e| format!("consequence rule validation failed: {e}"))?;
    }
    Ok((rules, config))
}

/// Converts role name/capabilities pairs into core `RoleDefinition` values.
fn build_roles(roles: &[(String, Vec<String>)]) -> Vec<RoleDefinition> {
    roles
        .iter()
        .map(|(name, caps)| RoleDefinition {
            name: name.clone(),
            capabilities: caps.iter().map(Capability::new).collect(),
        })
        .collect()
}

/// Converts outlet name strings into core `OutletRegistration` values with
/// placeholder schemas and metadata (matching the existing `PyO3` bridge
/// behavior for bridge-level outlet declarations).
fn build_outlets(outlets: &[String]) -> Vec<OutletRegistration> {
    outlets
        .iter()
        .map(|name| OutletRegistration {
            outlet_id: name.clone(),
            name: name.clone(),
            description: String::new(),
            schema: scp_core::context::outlets::OutletSchema {
                input_schema: serde_json::Value::Object(serde_json::Map::default()),
                output_schema: serde_json::Value::Object(serde_json::Map::default()),
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![],
            operator_did: scp_did::DID("did:key:placeholder".to_owned()),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Template ID parsing (shared across all FFI bridges)
// ---------------------------------------------------------------------------

/// Parses a template ID string into the core `TemplateId` type.
///
/// Accepts both the variant name and the serde-renamed form. Returns `Err` if
/// the string is not a recognized template identifier.
fn parse_template_id(tid: &str) -> Result<scp_core::context::params::TemplateId, String> {
    use scp_core::context::params::TemplateId;
    match tid {
        "BilateralEphemeral" => Ok(TemplateId::BilateralEphemeral),
        "BilateralPersistent" => Ok(TemplateId::BilateralPersistent),
        "Coordination" => Ok(TemplateId::Coordination),
        "GroupDiscussion" => Ok(TemplateId::GroupDiscussion),
        "PublicBroadcast" => Ok(TemplateId::PublicBroadcast),
        "GatedBroadcast" => Ok(TemplateId::GatedBroadcast),
        "scp:template/tool-interface" | "OutletInterfaceTemplate" => {
            Ok(TemplateId::ToolInterfaceTemplate)
        }
        "PaidService" | "scp:template/paid-service" => Ok(TemplateId::PaidService),
        "PaidBroadcast" | "scp:template/paid-broadcast" => Ok(TemplateId::PaidBroadcast),
        "scp:template/handle-registry"
        | "HandleRegistry"
        | "scp:template/discovery-context"
        | "DiscoveryContext" => Ok(TemplateId::HandleRegistry),
        _ => Err(format!(
            "unknown template ID: {tid:?} — valid values: BilateralEphemeral, \
             BilateralPersistent, Coordination, GroupDiscussion, PublicBroadcast, \
             GatedBroadcast, scp:template/tool-interface, PaidService, PaidBroadcast, \
             HandleRegistry, scp:template/handle-registry, DiscoveryContext, \
             scp:template/discovery-context"
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper: build and assert success.
    fn build_ok(params: &CommonContextParams) -> ContextParams {
        build_context_params(params).unwrap()
    }

    /// Helper: build and assert failure.
    fn build_err(params: &CommonContextParams) -> String {
        build_context_params(params).unwrap_err()
    }

    #[test]
    fn default_params_produce_valid_context_params() {
        let ctx = build_ok(&CommonContextParams::default());
        assert!(matches!(ctx.mode, ContextMode::Encrypted));
        assert!(ctx.ceiling.is_empty());
        assert!(matches!(ctx.ceiling_policy, CeilingPolicy::Immutable));
        assert!(matches!(ctx.promotion_policy, PromotionPolicy::NoPromotion));
        assert!(matches!(ctx.memory_scope, MemoryScope::Ephemeral));
        assert!(matches!(ctx.governance, GovernanceModel::SingleAdmin));
        assert!(ctx.ttl.is_none());
        assert!(ctx.economic_policy.is_none());
        assert!(ctx.consequence_rules.is_empty());
    }

    #[test]
    fn broadcast_mode_parsed() {
        let ctx = build_ok(&CommonContextParams {
            mode: "broadcast".to_owned(),
            ..Default::default()
        });
        assert!(matches!(ctx.mode, ContextMode::Broadcast));
    }

    #[test]
    fn broadcast_mode_titlecase_parsed() {
        let ctx = build_ok(&CommonContextParams {
            mode: "Broadcast".to_owned(),
            ..Default::default()
        });
        assert!(matches!(ctx.mode, ContextMode::Broadcast));
    }

    #[test]
    fn ceiling_parsed() {
        let ctx = build_ok(&CommonContextParams {
            ceiling: vec!["messages:write".to_owned(), "tools:invoke".to_owned()],
            ..Default::default()
        });
        assert_eq!(ctx.ceiling.len(), 2);
    }

    #[test]
    fn governed_ceiling_policy() {
        let ctx = build_ok(&CommonContextParams {
            ceiling_policy: "governed".to_owned(),
            ..Default::default()
        });
        assert!(matches!(ctx.ceiling_policy, CeilingPolicy::Governed));
    }

    #[test]
    fn promotable_policy() {
        let ctx = build_ok(&CommonContextParams {
            promotion_policy: "promotable".to_owned(),
            ..Default::default()
        });
        assert!(matches!(ctx.promotion_policy, PromotionPolicy::Promotable));
    }

    #[test]
    fn memory_scope_full() {
        let ctx = build_ok(&CommonContextParams {
            memory_scope: "full".to_owned(),
            ..Default::default()
        });
        assert!(matches!(ctx.memory_scope, MemoryScope::Full));
    }

    #[test]
    fn memory_scope_summary() {
        let ctx = build_ok(&CommonContextParams {
            memory_scope: "summary".to_owned(),
            ..Default::default()
        });
        assert!(matches!(ctx.memory_scope, MemoryScope::Summary));
    }

    #[test]
    fn unsupported_governance_rejected() {
        let err = build_err(&CommonContextParams {
            governance: "federation".to_owned(),
            ..Default::default()
        });
        assert!(err.contains("unsupported governance model"));
    }

    #[test]
    fn ttl_set() {
        let ctx = build_ok(&CommonContextParams {
            ttl: Some(Duration::from_hours(1)),
            ..Default::default()
        });
        assert_eq!(ctx.ttl, Some(Duration::from_hours(1)));
    }

    #[test]
    fn ttl_none_when_not_provided() {
        let ctx = build_ok(&CommonContextParams::default());
        assert!(ctx.ttl.is_none());
    }

    #[test]
    fn min_protocol_version_set() {
        let ctx = build_ok(&CommonContextParams {
            min_protocol_version: Some((1, 2)),
            ..Default::default()
        });
        assert_eq!(ctx.min_protocol_version, Some((1, 2)));
    }

    #[test]
    fn invalid_economic_policy_json_rejected() {
        let err = build_err(&CommonContextParams {
            economic_policy_json: Some("not json".to_owned()),
            ..Default::default()
        });
        assert!(err.contains("invalid economic_policy JSON"));
    }

    #[test]
    fn invalid_consequence_rules_json_rejected() {
        let err = build_err(&CommonContextParams {
            consequence_rules_json: Some("not json".to_owned()),
            ..Default::default()
        });
        assert!(err.contains("invalid consequence_rules JSON"));
    }

    #[test]
    fn invalid_consequence_config_json_rejected() {
        let err = build_err(&CommonContextParams {
            consequence_config_json: Some("not json".to_owned()),
            ..Default::default()
        });
        assert!(err.contains("invalid consequence_config JSON"));
    }

    #[test]
    fn template_id_parsed_variant_name() {
        let ctx = build_ok(&CommonContextParams {
            template_id: Some("GroupDiscussion".to_owned()),
            ..Default::default()
        });
        assert!(ctx.template_id.is_some());
    }

    #[test]
    fn template_id_parsed_serde_form() {
        let ctx = build_ok(&CommonContextParams {
            template_id: Some("scp:template/tool-interface".to_owned()),
            ..Default::default()
        });
        assert!(ctx.template_id.is_some());
    }

    #[test]
    fn invalid_template_id_ignored() {
        // Invalid template IDs are silently ignored (None), matching existing behavior
        let ctx = build_ok(&CommonContextParams {
            template_id: Some("invalid:template".to_owned()),
            ..Default::default()
        });
        assert!(ctx.template_id.is_none());
    }

    #[test]
    fn roles_converted() {
        let ctx = build_ok(&CommonContextParams {
            roles: vec![("admin".to_owned(), vec!["messages:write".to_owned()])],
            ..Default::default()
        });
        assert_eq!(ctx.roles.len(), 1);
        assert_eq!(ctx.roles[0].name, "admin");
    }

    #[test]
    fn outlets_converted() {
        let ctx = build_ok(&CommonContextParams {
            outlets: vec!["calculator".to_owned()],
            ..Default::default()
        });
        assert_eq!(ctx.tools.len(), 1);
        assert_eq!(ctx.tools[0].name, "calculator");
    }

    #[test]
    fn limits_passed_through() {
        let ctx = build_ok(&CommonContextParams {
            max_chain_depth: Some(4),
            max_nesting_depth: Some(10),
            session_cap: Some(500),
            ..Default::default()
        });
        assert_eq!(ctx.max_chain_depth, Some(4));
        assert_eq!(ctx.max_nesting_depth, Some(10));
        assert_eq!(ctx.session_cap, Some(500));
    }
}
