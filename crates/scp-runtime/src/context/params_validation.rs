//! The one validator of every check that reads only [`ContextParams`].
//!
//! Every entry point that admits a `ContextParams` calls [`validate_params`]:
//! context creation (`lifecycle_helpers::create_context` and the Phase 1 of
//! `builder::create_context`), import and restore
//! (`lifecycle_logic::validate_context_params_for_import`), the Welcome join's
//! Precheck C (`Supervisor::spawn_actor_from_welcome`, before the `KeyPackage`
//! consume), and the migration and child-context proposals
//! (`governance_helpers::propose_governance_action_inner`). Each entry point
//! maps the typed [`ParamsRejection`] to its own error surface.
//!
//! A check that needs input beyond the params stays at its site, and the doc
//! comment there names that input: the snapshot's live consequence rules and
//! its role-state ceiling at import and restore, and the registered outlet set
//! at import.

use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::roles::{CapabilityCeiling, CeilingEntryError};
use scp_protocol::context::templates::{
    TemplateError, validate_against_template, validate_context_params,
};
use scp_protocol::context::{
    CeilingDeclaration, ContextError, ContextParams, PseudonymRotationPolicyError,
};
use scp_protocol::economy::policy::UnavailableMetricError;
use scp_protocol::trust::consequence::ConsequenceValidationError;

/// Where the params being validated come from, which decides whether the
/// template check runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParamsOrigin {
    /// Params for a context about to be created: a create call, a migration's
    /// destination, or a child context. Every check runs, the template check
    /// included.
    Creation,
    /// Params of a context that already exists: an import, a restore, or the
    /// inviter's params a Welcome joiner receives. The template check does not
    /// run, because §5.10 promotion (`ContextHandle::promote_params`) sets
    /// `memory_scope` to `Full` and clears `ttl` after creation, so a promoted
    /// context's params legitimately differ from its template. Whether a
    /// context was promoted is input beyond the params.
    Existing,
}

/// Why [`validate_params`] refused a `ContextParams`. Each variant keeps the
/// error of the check that refused, and its `Display` names the field.
#[derive(Debug, thiserror::Error)]
pub(super) enum ParamsRejection {
    /// `ceiling` is empty (construction.md M2).
    #[error("ceiling is empty: a context with no capabilities is unusable")]
    CeilingEmpty,
    /// A `ceiling` entry breaks the §5.3.1.1 ceiling-entry grammar.
    #[error("ceiling entry invalid: {0}")]
    CeilingEntry(#[source] CeilingEntryError),
    /// The running SDK does not satisfy `min_protocol_version`.
    #[error("min_protocol_version unsatisfied: {0}")]
    Version(#[source] ContextError),
    /// `governance` describes a model no quorum can satisfy.
    #[error("governance invalid: {0}")]
    GovernanceModel(String),
    /// A `consequence_rules` entry fails its shape check or the
    /// `consequence_config` eligibility gate.
    #[error("consequence_rules[{index}] invalid: {source}")]
    ConsequenceRule {
        /// Index of the refused rule in `consequence_rules`.
        index: usize,
        /// The rule's validation error.
        #[source]
        source: ConsequenceValidationError,
    },
    /// `economic_policy`'s pricing formula reads a metric the runtime does not
    /// populate.
    #[error("economic_policy invalid: {0}")]
    EconomicPolicy(#[source] UnavailableMetricError),
    /// `pseudonym_rotation` fails the §9.10.4.1 validity criterion.
    #[error("pseudonym_rotation invalid: {0}")]
    PseudonymRotation(#[source] PseudonymRotationPolicyError),
    /// A genesis `outlets` declaration fails a check `register_outlet`
    /// applies.
    #[error("outlets invalid: {0}")]
    GenesisOutlets(String),
    /// `memory_scope` is not `Full` on a Broadcast context (§5.11).
    #[error("memory_scope invalid: {0}")]
    MemoryScope(#[source] ContextError),
    /// `projection_policy` or `sybil_policy` fails
    /// [`validate_context_params`] (§18.11.2.1, §9.3.1).
    #[error(transparent)]
    Params(TemplateError),
    /// The params differ from the template `template_id` names.
    #[error("template_id mismatch: {0}")]
    Template(#[source] TemplateError),
}

/// Runs every check that reads only `params`, in a fixed order, and returns
/// the first refusal.
///
/// # Errors
///
/// The [`ParamsRejection`] variant of the first check `params` fails.
pub(super) fn validate_params(
    params: &ContextParams,
    origin: ParamsOrigin,
) -> Result<(), ParamsRejection> {
    if params.ceiling.is_empty() {
        return Err(ParamsRejection::CeilingEmpty);
    }
    CapabilityCeiling::new(params.ceiling.iter().cloned())
        .validate_entries()
        .map_err(ParamsRejection::CeilingEntry)?;
    params
        .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)
        .map_err(ParamsRejection::Version)?;
    crate::context::state::validate_governance_model(&params.governance)
        .map_err(|e| ParamsRejection::GovernanceModel(creation_reason(e)))?;
    for (index, rule) in params.consequence_rules.iter().enumerate() {
        rule.validate_against_config(&params.consequence_config)
            .map_err(|source| ParamsRejection::ConsequenceRule { index, source })?;
    }
    scp_protocol::economy::policy::validate_economic_policy_metrics(
        params.economic_policy.as_ref(),
    )
    .map_err(ParamsRejection::EconomicPolicy)?;
    if let Some(policy) = &params.pseudonym_rotation {
        policy
            .validate()
            .map_err(ParamsRejection::PseudonymRotation)?;
    }
    crate::context::state::validate_genesis_outlets(&params.outlets)
        .map_err(|e| ParamsRejection::GenesisOutlets(creation_reason(e)))?;
    scp_protocol::context::memory_scope::validate_memory_scope_for_broadcast(
        params.mode,
        params.memory_scope,
    )
    .map_err(ParamsRejection::MemoryScope)?;
    validate_context_params(params).map_err(ParamsRejection::Params)?;
    if origin == ParamsOrigin::Creation && params.template_id.is_some() {
        validate_against_template(params).map_err(ParamsRejection::Template)?;
    }
    Ok(())
}

/// The reason string a `CreationFailed` carries, without the variant's
/// "context creation failed" prefix, so an import or Welcome refusal does not
/// claim a creation failed.
fn creation_reason(error: ContextCreationError) -> String {
    match error {
        ContextCreationError::CreationFailed(reason) => reason,
        other => other.to_string(),
    }
}

impl ParamsRejection {
    /// The governance proposal-time refusal for a migration's destination or
    /// a child context whose params fail [`validate_params`]: the typed
    /// `ContextError` where one exists, `CreationFailed` naming the field
    /// otherwise.
    pub(super) fn into_proposal_error(self) -> ContextError {
        match self {
            Self::CeilingEmpty => ContextError::CeilingRequired(CeilingDeclaration::Empty),
            Self::Version(e) | Self::MemoryScope(e) => e,
            Self::Params(e) | Self::Template(e) => ContextError::TemplateMismatch(e),
            other => ContextError::CreationFailed(other.to_string()),
        }
    }
}

impl From<ParamsRejection> for ContextCreationError {
    fn from(rejection: ParamsRejection) -> Self {
        match rejection {
            ParamsRejection::CeilingEmpty => {
                Self::StateTransition(ContextError::CeilingRequired(CeilingDeclaration::Empty))
            }
            ParamsRejection::CeilingEntry(e) => Self::InvalidCeilingCategory(e),
            ParamsRejection::Version(e) => Self::StateTransition(e),
            ParamsRejection::PseudonymRotation(e) => Self::InvalidPseudonymRotationPolicy(e),
            ParamsRejection::Params(TemplateError::InvalidSybilPolicy(e)) => {
                Self::InvalidSybilPolicy(e)
            }
            ParamsRejection::Params(e) | ParamsRejection::Template(e) => {
                Self::TemplateValidationFailed(e.to_string())
            }
            ParamsRejection::GovernanceModel(reason) | ParamsRejection::GenesisOutlets(reason) => {
                Self::CreationFailed(reason)
            }
            ParamsRejection::ConsequenceRule { source, .. } => {
                Self::CreationFailed(source.to_string())
            }
            ParamsRejection::EconomicPolicy(e) => Self::CreationFailed(e.to_string()),
            ParamsRejection::MemoryScope(e) => Self::CreationFailed(e.to_string()),
        }
    }
}

/// Inputs that each fail exactly one [`validate_params`] check. Each function
/// takes params that pass every check and changes the one field its check
/// reads, so a test that feeds the result to an entry point proves that entry
/// point runs that check. `tests::each_fixture_fails_its_check_alone` pins
/// each fixture to its variant.
#[cfg(test)]
pub(super) mod failing {
    use scp_did::DID;
    use scp_protocol::context::outlets::{OutletKind, OutletRegistration, OutletSchema};
    use scp_protocol::context::params::TemplateId;
    use scp_protocol::context::roles::Capability;
    use scp_protocol::context::{
        ContextMode, ContextParams, GovernanceModel, MemoryScope, PseudonymRotationPolicy,
    };
    use scp_protocol::economy::{
        Amount, Coefficient, CostSchedule, CurrencyCode, EconomicPolicy, PricingFormula,
        PricingMetric, PricingVariable,
    };
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
    };

    /// Fails `CeilingEmpty`.
    pub(in crate::context) fn empty_ceiling(base: ContextParams) -> ContextParams {
        ContextParams {
            ceiling: Vec::new(),
            ..base
        }
    }

    /// Fails `CeilingEntry`: a custom entry that spells the `messages:read`
    /// built-in (§5.3.1.1 no privileged-built-in collision).
    pub(in crate::context) fn malformed_ceiling_entry(base: ContextParams) -> ContextParams {
        let mut ceiling = base.ceiling.clone();
        ceiling.push(Capability::Custom("messages:read".to_owned()));
        ContextParams { ceiling, ..base }
    }

    /// Fails `Version`: a protocol major this SDK does not speak.
    pub(in crate::context) fn unsupported_version(base: ContextParams) -> ContextParams {
        ContextParams {
            min_protocol_version: Some((9, 0)),
            ..base
        }
    }

    /// Fails `GovernanceModel`: majority governance with no eligible voter.
    pub(in crate::context) fn voterless_governance(base: ContextParams) -> ContextParams {
        ContextParams {
            governance: GovernanceModel::Majority {
                eligible_voters: Vec::new(),
            },
            ..base
        }
    }

    /// Fails `ConsequenceRule`: a capability suspension that names no
    /// capability.
    pub(in crate::context) fn empty_suspension_rule(base: ContextParams) -> ContextParams {
        ContextParams {
            consequence_rules: vec![ConsequenceRule {
                trigger: ConsequenceTrigger::WarningCount,
                action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                    capabilities: Vec::new(),
                }),
                threshold: 1,
                window: std::time::Duration::from_hours(1),
            }],
            ..base
        }
    }

    /// Fails `EconomicPolicy`: a pricing formula over `StorageUsage`, which
    /// the runtime does not populate.
    pub(in crate::context) fn unavailable_pricing_metric(base: ContextParams) -> ContextParams {
        ContextParams {
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_outlet_call: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: Vec::new(),
                pricing_formula: Some(PricingFormula {
                    base_cost: Amount(1),
                    variables: vec![PricingVariable::Linear {
                        metric: PricingMetric::StorageUsage,
                        coefficient: Coefficient(1),
                    }],
                    cap: None,
                    floor: None,
                }),
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..base
        }
    }

    /// Fails `PseudonymRotation`: a policy that sets no trigger (§9.10.4.1).
    pub(in crate::context) fn triggerless_rotation(base: ContextParams) -> ContextParams {
        ContextParams {
            pseudonym_rotation: Some(PseudonymRotationPolicy {
                interval_secs: None,
                on_membership_change: false,
            }),
            ..base
        }
    }

    /// Fails `GenesisOutlets`: an outlet whose schemas declare no property,
    /// under the §6.2/§9.2.1 specificity floor.
    pub(in crate::context) fn property_free_outlet(base: ContextParams) -> ContextParams {
        ContextParams {
            outlets: vec![OutletRegistration {
                outlet_id: "weather".to_owned(),
                kind: OutletKind::Action,
                name: "weather".to_owned(),
                description: "genesis outlet fixture".to_owned(),
                schema: OutletSchema {
                    input_schema: serde_json::Value::Object(serde_json::Map::default()),
                    output_schema: serde_json::Value::Object(serde_json::Map::default()),
                    aggregate_schema: None,
                },
                implementation_hash: [7u8; 32],
                test_vectors: Vec::new(),
                message_catalog: Vec::new(),
                operator_did: "did:dht:z6MkOperator".into(),
                cost: None,
                registered_at: 0,
                signature: Vec::new(),
            }],
            ..base
        }
    }

    /// Fails `MemoryScope`: a Broadcast context whose memory is not `Full`
    /// (§5.11).
    pub(in crate::context) fn ephemeral_broadcast(base: ContextParams) -> ContextParams {
        ContextParams {
            mode: ContextMode::Broadcast,
            memory_scope: MemoryScope::Ephemeral,
            ..base
        }
    }

    /// Fails `Template`: names `BilateralPersistent`, whose ceiling the base
    /// params do not match.
    pub(in crate::context) fn template_mismatch(base: ContextParams) -> ContextParams {
        ContextParams {
            template_id: Some(TemplateId::BilateralPersistent),
            ..base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::failing;
    use super::{ParamsOrigin, ParamsRejection, validate_params};
    use scp_protocol::context::ContextParams;
    use scp_protocol::context::roles::Capability;

    type Fixture = fn(ContextParams) -> ContextParams;
    type Expect = fn(&ParamsRejection) -> bool;

    fn base() -> ContextParams {
        ContextParams {
            ceiling: vec![Capability::MessagesRead],
            ..ContextParams::default()
        }
    }

    /// Each `failing` fixture, applied to params that pass every check, is
    /// refused by exactly the check it names, at both origins. The base
    /// passes at both.
    #[test]
    fn each_fixture_fails_its_check_alone() {
        let cases: [(&str, Fixture, Expect); 9] = [
            ("empty ceiling", failing::empty_ceiling, |r| {
                matches!(r, ParamsRejection::CeilingEmpty)
            }),
            ("ceiling entry", failing::malformed_ceiling_entry, |r| {
                matches!(r, ParamsRejection::CeilingEntry(_))
            }),
            ("version", failing::unsupported_version, |r| {
                matches!(r, ParamsRejection::Version(_))
            }),
            ("governance", failing::voterless_governance, |r| {
                matches!(r, ParamsRejection::GovernanceModel(_))
            }),
            ("consequence rule", failing::empty_suspension_rule, |r| {
                matches!(r, ParamsRejection::ConsequenceRule { index: 0, .. })
            }),
            (
                "economic policy",
                failing::unavailable_pricing_metric,
                |r| matches!(r, ParamsRejection::EconomicPolicy(_)),
            ),
            ("rotation", failing::triggerless_rotation, |r| {
                matches!(r, ParamsRejection::PseudonymRotation(_))
            }),
            ("outlets", failing::property_free_outlet, |r| {
                matches!(r, ParamsRejection::GenesisOutlets(_))
            }),
            ("memory scope", failing::ephemeral_broadcast, |r| {
                matches!(r, ParamsRejection::MemoryScope(_))
            }),
        ];
        for origin in [ParamsOrigin::Creation, ParamsOrigin::Existing] {
            assert!(
                validate_params(&base(), origin).is_ok(),
                "the base passes every check at {origin:?}"
            );
            for (label, fixture, expect) in cases {
                let refused = validate_params(&fixture(base()), origin);
                assert!(
                    refused.as_ref().is_err_and(expect),
                    "{label} at {origin:?}: got {refused:?}"
                );
            }
        }
    }

    /// The template check runs for params about to be created and not for
    /// params of an existing, possibly §5.10-promoted context.
    #[test]
    fn template_check_runs_only_at_creation() {
        let params = failing::template_mismatch(base());
        let refused = validate_params(&params, ParamsOrigin::Creation);
        assert!(
            matches!(refused, Err(ParamsRejection::Template(_))),
            "got {refused:?}"
        );
        assert!(validate_params(&params, ParamsOrigin::Existing).is_ok());
    }
}
