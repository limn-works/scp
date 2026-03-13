//! napi-rs bridge for provenance operations.
//!
//! Exposes SCP provenance quality evaluation to Node.js/Bun:
//!
//! - [`evaluate_provenance_quality`] -- Evaluate the provenance quality tier.
//! - [`provenance_attach`] -- Attach provenance metadata at cross-context
//!   boundaries.
//! - [`provenance_check_chain_depth`] -- Check whether a provenance chain
//!   depth is within the allowed limit.
//!
//! See spec section 24 (Provenance System) and ADR-019.

use napi_derive::napi;

use scp_core::context::MemoryScope;
use scp_core::provenance::attach::{
    DEFAULT_MAX_CHAIN_DEPTH, SourceContextInfo, attach_provenance, check_chain_depth,
};
use scp_core::provenance::evaluate::{SourceContextState, evaluate_quality};
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Evaluates the provenance quality tier for a given data provenance record.
///
/// Returns an integer (0-3) representing the quality tier.
#[napi]
#[allow(clippy::unused_async)]
#[allow(clippy::needless_pass_by_value)]
pub async fn evaluate_provenance_quality(
    source_context: Option<String>,
    source_type: String,
    context_state: String,
    counterparties: Option<Vec<String>>,
) -> napi::Result<u32> {
    let st = parse_source_type(&source_type)?;
    let cs = parse_context_state(&context_state)?;

    let provenance = source_context.map(|ctx| DataProvenance {
        source_context: ctx,
        source_type: st,
        counterparties: counterparties
            .unwrap_or_default()
            .into_iter()
            .map(scp_identity::DID::from)
            .collect(),
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_core::context::MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    });

    let quality = evaluate_quality(provenance.as_ref(), &cs);

    Ok(quality as u32)
}

/// Attaches provenance metadata when data crosses a context boundary.
///
/// Returns a JSON string with the attached provenance record.
#[napi]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)] // napi-rs requires explicit params
pub fn provenance_attach(
    source_context_id: String,
    source_type: String,
    memory_scope: String,
    members: Vec<String>,
    target_context_id: String,
    existing_chain_depth: Option<u32>,
    discovery_method: Option<String>,
    purpose: Option<String>,
    counterparty_policy: Option<String>,
) -> napi::Result<String> {
    let st = parse_source_type(&source_type)?;
    let ms = parse_memory_scope(&memory_scope)?;
    let dm = parse_discovery_method(discovery_method.as_deref())?;
    let cp = parse_counterparty_policy(counterparty_policy.as_deref())?;

    let source_info = SourceContextInfo {
        context_id: source_context_id,
        source_type: st,
        memory_scope: ms,
        members: members.into_iter().map(scp_identity::DID::from).collect(),
        discovery_method: dm,
        data_age: std::time::Duration::from_secs(0),
        purpose,
        counterparty_policy: cp,
    };

    #[allow(clippy::cast_possible_truncation)]
    let existing_prov = existing_chain_depth.map(|depth| DataProvenance {
        source_context: String::new(),
        source_type: SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: MemoryScope::Full,
        chain_depth: depth as u8,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    });

    let prov = attach_provenance(
        &source_info,
        &target_context_id,
        existing_prov.as_ref(),
        None,
        None,
    );

    let discovery_method_str = match &prov.discovery_method {
        DiscoveryMethod::SharedContext(ctx_id) => {
            serde_json::json!({"SharedContext": ctx_id})
        }
        DiscoveryMethod::Registry(ctx_id) => {
            serde_json::json!({"Registry": ctx_id})
        }
        DiscoveryMethod::OutOfBand => serde_json::json!("OutOfBand"),
    };

    let result = serde_json::json!({
        "source_context": prov.source_context,
        "source_type": format!("{:?}", prov.source_type),
        "chain_depth": prov.chain_depth,
        "counterparties": prov.counterparties.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "age_secs": prov.age.as_secs(),
        "memory_scope": format!("{:?}", prov.memory_scope),
        "chain_path": prov.chain_path,
        "purpose": prov.purpose,
        "discovery_method": discovery_method_str,
        "payment_amount": prov.payment_amount.map(|a| a.0),
        "payment_adapter": prov.payment_adapter,
        "payment_receipt_id": prov.payment_receipt_id.map(hex::encode),
    });

    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize provenance: {e}"),
            code: "SCP-VALID-7002".to_owned(),
        })
    })
}

/// Checks whether the provenance chain depth is within the allowed limit.
///
/// Returns `true` if within limit, `false` otherwise.
#[napi]
#[must_use]
pub fn provenance_check_chain_depth(chain_depth: u32, max_depth: Option<u32>) -> bool {
    #[allow(clippy::cast_possible_truncation)]
    let depth = chain_depth as u8;
    #[allow(clippy::cast_possible_truncation)]
    let max = max_depth.map_or(DEFAULT_MAX_CHAIN_DEPTH, |d| d as u8);
    let prov = DataProvenance {
        source_context: String::new(),
        source_type: SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: MemoryScope::Full,
        chain_depth: depth,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };
    check_chain_depth(&prov, max).is_ok()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_source_type(s: &str) -> napi::Result<SourceType> {
    match s {
        "persistent" => Ok(SourceType::Persistent),
        "ephemeral" => Ok(SourceType::Ephemeral),
        "summary" => Ok(SourceType::Summary),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid source_type '{other}': expected 'persistent', 'ephemeral', or 'summary'"
            ),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into()),
    }
}

fn parse_context_state(s: &str) -> napi::Result<SourceContextState> {
    match s {
        "active" => Ok(SourceContextState::Active),
        "closed_with_summary_verified" => Ok(SourceContextState::ClosedWithSummary {
            summary_verified: true,
        }),
        "closed_with_summary_unverified" => Ok(SourceContextState::ClosedWithSummary {
            summary_verified: false,
        }),
        "closed_ephemeral" => Ok(SourceContextState::ClosedEphemeral),
        "unknown" => Ok(SourceContextState::Unknown),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid context_state '{other}': expected 'active', \
                 'closed_with_summary_verified', 'closed_with_summary_unverified', \
                 'closed_ephemeral', or 'unknown'"
            ),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into()),
    }
}

fn parse_memory_scope(s: &str) -> napi::Result<MemoryScope> {
    match s {
        "full" => Ok(MemoryScope::Full),
        "summary" => Ok(MemoryScope::Summary),
        "ephemeral" => Ok(MemoryScope::Ephemeral),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid memory_scope '{other}': expected 'full', 'summary', or 'ephemeral'"
            ),
            code: "SCP-VALID-7001".to_owned(),
        }
        .into()),
    }
}

/// Parses a discovery method string into a `DiscoveryMethod` enum (§24.2.3).
///
/// Accepted formats:
/// - `OutOfBand`, `out_of_band`, `None`, `none`, or absent → `DiscoveryMethod::OutOfBand`
/// - `shared_context:<context_id>` → `DiscoveryMethod::SharedContext(context_id)`
/// - `registry:<context_id>` → `DiscoveryMethod::Registry(context_id)`
///
/// `"None"` is accepted for backward compatibility (renamed to `OutOfBand`
/// in issue #772).
fn parse_discovery_method(s: Option<&str>) -> napi::Result<DiscoveryMethod> {
    let Some(s) = s else {
        return Ok(DiscoveryMethod::OutOfBand);
    };
    match s {
        "none" | "None" | "OutOfBand" | "out_of_band" => Ok(DiscoveryMethod::OutOfBand),
        _ if s.starts_with("shared_context:") => {
            let ctx_id = &s["shared_context:".len()..];
            if ctx_id.is_empty() {
                return Err(ScpNapiError::Validation {
                    message:
                        "invalid discovery_method 'shared_context:': context ID must not be empty"
                            .to_owned(),
                    code: "SCP-VALID-7216".to_owned(),
                }
                .into());
            }
            Ok(DiscoveryMethod::SharedContext(ctx_id.to_owned()))
        }
        _ if s.starts_with("registry:") => {
            let ctx_id = &s["registry:".len()..];
            if ctx_id.is_empty() {
                return Err(ScpNapiError::Validation {
                    message: "invalid discovery_method 'registry:': context ID must not be empty"
                        .to_owned(),
                    code: "SCP-VALID-7216".to_owned(),
                }
                .into());
            }
            Ok(DiscoveryMethod::Registry(ctx_id.to_owned()))
        }
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid discovery_method '{other}': expected 'OutOfBand', 'out_of_band', \
                 'none', 'shared_context:<context_id>', or 'registry:<context_id>'"
            ),
            code: "SCP-VALID-7216".to_owned(),
        }
        .into()),
    }
}

/// Parses a counterparty policy string into a `CounterpartyPolicy` enum (§7.7.1).
fn parse_counterparty_policy(
    s: Option<&str>,
) -> napi::Result<scp_core::provenance::CounterpartyPolicy> {
    let Some(s) = s else {
        return Ok(scp_core::provenance::CounterpartyPolicy::default());
    };
    match s {
        "full" => Ok(scp_core::provenance::CounterpartyPolicy::Full),
        "pseudonymized" => Ok(scp_core::provenance::CounterpartyPolicy::Pseudonymized),
        "redacted" => Ok(scp_core::provenance::CounterpartyPolicy::Redacted),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid counterparty_policy '{other}': expected 'full', \
                 'pseudonymized', or 'redacted'"
            ),
            code: "SCP-VALID-7004".to_owned(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn check_chain_depth_within_limit() {
        assert!(provenance_check_chain_depth(0, None));
        assert!(provenance_check_chain_depth(3, None));
    }

    #[test]
    fn check_chain_depth_exceeds_limit() {
        assert!(!provenance_check_chain_depth(4, None));
        assert!(!provenance_check_chain_depth(2, Some(1)));
    }

    #[test]
    fn parse_discovery_method_rejects_empty_shared_context_id() {
        let result = parse_discovery_method(Some("shared_context:"));
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("context ID must not be empty"));
    }

    #[test]
    fn parse_discovery_method_rejects_empty_registry_id() {
        let result = parse_discovery_method(Some("registry:"));
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("context ID must not be empty"));
    }

    #[test]
    fn parse_discovery_method_accepts_valid_ids() {
        let shared = parse_discovery_method(Some("shared_context:ctx-123")).unwrap();
        assert!(matches!(shared, DiscoveryMethod::SharedContext(id) if id == "ctx-123"));

        let registry = parse_discovery_method(Some("registry:reg-456")).unwrap();
        assert!(matches!(registry, DiscoveryMethod::Registry(id) if id == "reg-456"));

        let none = parse_discovery_method(None).unwrap();
        assert!(matches!(none, DiscoveryMethod::OutOfBand));
    }
}
