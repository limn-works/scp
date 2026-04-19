//! napi-rs bridge for provenance operations.
//!
//! Exposes SCP provenance quality evaluation and privacy operations to
//! Node.js/Bun:
//!
//! - [`evaluate_provenance_quality`] -- Evaluate the provenance quality tier.
//! - [`provenance_attach`] -- Attach provenance metadata at cross-context
//!   boundaries.
//! - [`provenance_check_chain_depth`] -- Check whether a provenance chain
//!   depth is within the allowed limit.
//! - [`provenance_redact_counterparties`] -- Remove counterparty DIDs (§24.3.5).
//! - [`provenance_pseudonymize_counterparties`] -- Replace DIDs with
//!   pseudonyms (§24.3.5).
//! - [`provenance_update_source_type`] -- Update source type for state
//!   changes (ADR-019 AC5).
//!
//! See spec section 24 (Provenance System) and ADR-019.

use napi_derive::napi;
use scp_ffi_common::error_codes as codes;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use scp_core::context::MemoryScope;
use scp_core::provenance::attach::{
    DEFAULT_MAX_CHAIN_DEPTH, SourceContextInfo, attach_provenance, check_chain_depth,
    pseudonymize_counterparties, redact_counterparties,
};
use scp_core::provenance::evaluate::{SourceContextState, evaluate_quality, update_source_type};
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
/// Records dual events in the event log: `ProvenanceAttached` in the source
/// context and `ProvenanceReceived` in the target context (issue #586).
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
    actor_did: String,
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
        context_id: source_context_id.clone(),
        source_type: st,
        memory_scope: ms,
        members: members.into_iter().map(scp_identity::DID::from).collect(),
        discovery_method: dm,
        data_age: std::time::Duration::from_secs(0),
        purpose,
        counterparty_policy: cp,
    };

    let existing_prov = existing_chain_depth
        .map(|depth| -> napi::Result<DataProvenance> {
            let chain_depth = u8::try_from(depth).map_err(|_| {
                napi::Error::from_reason(format!(
                    "existing_chain_depth {depth} exceeds u8 range (max 255)"
                ))
            })?;
            Ok(DataProvenance {
                source_context: String::new(),
                source_type: SourceType::Persistent,
                counterparties: vec![],
                purpose: None,
                discovery_method: DiscoveryMethod::OutOfBand,
                age: std::time::Duration::from_secs(0),
                memory_scope: MemoryScope::Full,
                chain_depth,
                chain_path: None,
                payment_amount: None,
                payment_adapter: None,
                payment_receipt_id: None,
            })
        })
        .transpose()?;

    let prov = attach_provenance(
        &source_info,
        &target_context_id,
        existing_prov.as_ref(),
        None,
        None,
    );

    // Compute provenance hash: SHA-256 of JSON-serialized provenance record.
    let prov_json_bytes = serde_json::to_vec(&prov).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize provenance for hashing: {e}"),
            code: codes::VALID_7053.to_owned(),
        })
    })?;
    let prov_hash: [u8; 32] = Sha256::digest(&prov_json_bytes).into();

    // Record ProvenanceAttached in the source context event log.
    // Best-effort: log warning if context not found (provenance_attach
    // can be called without a runtime context, e.g. in unit tests).
    if let Err(e) = append_provenance_event(
        &source_context_id,
        &actor_did,
        scp_event_log::EventType::ProvenanceAttached,
        &prov_hash,
    ) {
        tracing::warn!(
            context = %source_context_id,
            error = %e,
            "failed to append ProvenanceAttached event to source context event log"
        );
    }

    // Record ProvenanceReceived in the target context event log.
    if let Err(e) = append_provenance_event(
        &target_context_id,
        &actor_did,
        scp_event_log::EventType::ProvenanceReceived,
        &prov_hash,
    ) {
        tracing::warn!(
            context = %target_context_id,
            error = %e,
            "failed to append ProvenanceReceived event to target context event log"
        );
    }

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
            code: codes::VALID_7002.to_owned(),
        })
    })
}

/// Checks whether the provenance chain depth is within the allowed limit.
///
/// Returns `true` if within limit, `false` otherwise.
#[napi]
pub fn provenance_check_chain_depth(
    chain_depth: u32,
    max_depth: Option<u32>,
) -> napi::Result<bool> {
    let depth = u8::try_from(chain_depth).map_err(|_| {
        napi::Error::from_reason(format!(
            "chain_depth {chain_depth} exceeds u8 range (max 255)"
        ))
    })?;
    let max = match max_depth {
        Some(d) => u8::try_from(d).map_err(|_| {
            napi::Error::from_reason(format!("max_depth {d} exceeds u8 range (max 255)"))
        })?,
        None => DEFAULT_MAX_CHAIN_DEPTH,
    };
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
    Ok(check_chain_depth(&prov, max).is_ok())
}

/// Redacts counterparties from a provenance record (§24.3.5).
///
/// Accepts a JSON-serialized provenance record, removes all counterparty DIDs,
/// and returns the modified record as a JSON string.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn provenance_redact_counterparties(provenance_json: String) -> napi::Result<String> {
    let mut prov: DataProvenance = serde_json::from_str(&provenance_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid provenance JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })
    })?;

    redact_counterparties(&mut prov);

    serde_json::to_string(&prov).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize provenance: {e}"),
            code: codes::VALID_7051.to_owned(),
        })
    })
}

/// Pseudonymizes counterparties in a provenance record (§24.3.5).
///
/// Accepts a JSON-serialized provenance record and a hex-encoded pseudonym key.
/// Replaces real counterparty DIDs with deterministic context-scoped pseudonyms.
/// Returns the modified record as a JSON string.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn provenance_pseudonymize_counterparties(
    provenance_json: String,
    pseudonym_key_hex: String,
) -> napi::Result<String> {
    let mut prov: DataProvenance = serde_json::from_str(&provenance_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid provenance JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })
    })?;

    let key = Zeroizing::new(hex::decode(&pseudonym_key_hex).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid pseudonym_key_hex: {e}"),
            code: codes::VALID_7052.to_owned(),
        })
    })?);

    pseudonymize_counterparties(&mut prov, &key);

    serde_json::to_string(&prov).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize provenance: {e}"),
            code: codes::VALID_7051.to_owned(),
        })
    })
}

/// Updates the source type of a provenance record to reflect a new context
/// state (ADR-019 AC5).
///
/// Accepts a JSON-serialized provenance record and a context state string.
/// Returns the modified record as a JSON string.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn provenance_update_source_type(
    provenance_json: String,
    new_state: String,
) -> napi::Result<String> {
    let mut prov: DataProvenance = serde_json::from_str(&provenance_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid provenance JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })
    })?;

    let state = parse_context_state(&new_state)?;

    update_source_type(&mut prov, &state);

    serde_json::to_string(&prov).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize provenance: {e}"),
            code: codes::VALID_7051.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Appends a provenance event (`ProvenanceAttached` or `ProvenanceReceived`)
/// to the event log for the given context.
///
/// Follows the unsigned-event pattern used by `ToolInvoked` in the MCP bridge.
fn append_provenance_event(
    context_id: &str,
    actor_did: &str,
    event_type: scp_event_log::EventType,
    provenance_hash: &[u8; 32],
) -> napi::Result<()> {
    #[allow(clippy::cast_possible_truncation)]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    crate::runtime::with_context(context_id, |state| {
        let sequence = scp_event_log::tree::event_count(&state.core.event_log);
        let prev_hash = if state.core.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            state.core.event_log.leaves()[state.core.event_log.leaves().len() - 1]
        };

        let event = scp_event_log::Event {
            event_type,
            actor_did: scp_identity::DID::from(actor_did.to_owned()),
            timestamp,
            sequence,
            payload: scp_event_log::EventPayload {
                data: provenance_hash.to_vec(),
            },
            prev_hash,
            signature: Vec::new(),
        };

        scp_event_log::tree::append_unsigned_event(&mut state.core.event_log, &event).map_err(
            |e| ScpNapiError::Context {
                message: format!("failed to append provenance event: {e}"),
                code: codes::CTX_2060.to_owned(),
            },
        )?;

        Ok(())
    })?;

    Ok(())
}

fn parse_source_type(s: &str) -> napi::Result<SourceType> {
    match s {
        "persistent" => Ok(SourceType::Persistent),
        "ephemeral" => Ok(SourceType::Ephemeral),
        "summary" => Ok(SourceType::Summary),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid source_type '{other}': expected 'persistent', 'ephemeral', or 'summary'"
            ),
            code: codes::VALID_7000.to_owned(),
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
            code: codes::VALID_7000.to_owned(),
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
            code: codes::VALID_7001.to_owned(),
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
                    code: codes::VALID_7216.to_owned(),
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
                    code: codes::VALID_7216.to_owned(),
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
            code: codes::VALID_7216.to_owned(),
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
            code: codes::VALID_7004.to_owned(),
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
        assert!(provenance_check_chain_depth(0, None).unwrap());
        assert!(provenance_check_chain_depth(8, None).unwrap()); // default is 8 (ADR-043)
    }

    #[test]
    fn check_chain_depth_exceeds_limit() {
        assert!(!provenance_check_chain_depth(9, None).unwrap()); // 9 > default 8
        assert!(!provenance_check_chain_depth(2, Some(1)).unwrap());
    }

    #[test]
    fn check_chain_depth_rejects_out_of_u8_range() {
        assert!(provenance_check_chain_depth(256, None).is_err());
        assert!(provenance_check_chain_depth(0, Some(256)).is_err());
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

    #[test]
    fn redact_counterparties_removes_dids() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": ["did:dht:z6MkAlice", "did:dht:z6MkBob"],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        let result = provenance_redact_counterparties(prov_json.to_string()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["counterparties"], serde_json::json!([]));
        assert_eq!(parsed["source_context"], "ctx-test");
    }

    #[test]
    fn pseudonymize_counterparties_deterministic() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": ["did:dht:z6MkAlice"],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        let key_hex = hex::encode(b"test-key");
        let result1 =
            provenance_pseudonymize_counterparties(prov_json.to_string(), key_hex.clone()).unwrap();
        let result2 =
            provenance_pseudonymize_counterparties(prov_json.to_string(), key_hex).unwrap();
        assert_eq!(result1, result2);

        let parsed: serde_json::Value = serde_json::from_str(&result1).unwrap();
        let parties = parsed["counterparties"].as_array().unwrap();
        assert_eq!(parties.len(), 1);
        assert!(parties[0].as_str().unwrap().starts_with("did:pseudo:"));
    }

    #[test]
    fn update_source_type_changes_type() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": [],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        let result =
            provenance_update_source_type(prov_json.to_string(), "closed_ephemeral".to_owned())
                .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["source_type"], "Ephemeral");
    }

    #[test]
    fn redact_counterparties_invalid_json_fails() {
        assert!(provenance_redact_counterparties("not json".to_owned()).is_err());
    }

    #[test]
    fn pseudonymize_counterparties_invalid_hex_fails() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": ["did:dht:z6MkAlice"],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        assert!(
            provenance_pseudonymize_counterparties(prov_json.to_string(), "not-hex-zz".to_owned())
                .is_err()
        );
    }

    #[test]
    fn update_source_type_invalid_state_fails() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": [],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        assert!(
            provenance_update_source_type(prov_json.to_string(), "invalid".to_owned()).is_err()
        );
    }
}
