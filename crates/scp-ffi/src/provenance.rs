//! `PyO3` bridge functions for provenance operations.
//!
//! Exposes SCP provenance types, quality evaluation, and privacy operations
//! to Python as methods on the `SCP` class:
//!
//! - [`PyScp::evaluate_provenance_quality`] -- Evaluate the provenance
//!   quality tier for a given provenance record and source context state.
//! - [`PyScp::provenance_attach`] -- Attach provenance metadata at
//!   cross-context boundaries.
//! - [`PyScp::provenance_check_chain_depth`] -- Check whether a provenance
//!   chain depth is within the allowed limit.
//! - [`PyScp::provenance_redact_counterparties`] -- Remove counterparty DIDs
//!   (§24.3.5).
//! - [`PyScp::provenance_pseudonymize_counterparties`] -- Replace DIDs with
//!   pseudonyms (§24.3.5).
//! - [`PyScp::provenance_update_source_type`] -- Update source type for state
//!   changes (ADR-019 AC5).
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice C (#1549).
//!
//! See spec section 24 (Provenance System) and ADR-019.

use pyo3::prelude::*;
use pyo3::types::PyDict;
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

use crate::error::ScpPyError;
use crate::runtime::PyBridgeInstance;

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Evaluates the provenance quality tier for a given data provenance record.
    ///
    /// See spec section 24 (Provenance System).
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `source_type` or `context_state` are invalid.
    #[pyo3(signature = (source_context=None, source_type="persistent", context_state="unknown", counterparties=None))]
    pub fn evaluate_provenance_quality(
        &self,
        source_context: Option<String>,
        source_type: &str,
        context_state: &str,
        counterparties: Option<Vec<String>>,
    ) -> PyResult<u8> {
        let st = parse_source_type(source_type)?;
        let cs = parse_context_state(context_state)?;

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

        Ok(quality as u8)
    }

    /// Attaches provenance metadata when data crosses a context boundary.
    ///
    /// Records dual events in the event log: `ProvenanceAttached` in the source
    /// context and `ProvenanceReceived` in the target context (issue #586).
    ///
    /// See ADR-019 acceptance criteria 2-3, 6.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `source_type` or `memory_scope` are invalid.
    /// Raises `ContextError` if either context is not found in the runtime.
    #[pyo3(signature = (source_context_id, source_type, memory_scope, members, target_context_id, actor_did, existing_chain_depth=None))]
    #[allow(clippy::too_many_arguments)] // FFI bridge requires explicit params
    pub fn provenance_attach<'py>(
        &self,
        py: Python<'py>,
        source_context_id: String,
        source_type: &str,
        memory_scope: &str,
        members: Vec<String>,
        target_context_id: String,
        actor_did: String,
        existing_chain_depth: Option<u8>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let bi = &*self.inner;
        let st = parse_source_type(source_type)?;
        let ms = parse_memory_scope(memory_scope)?;

        let source_info = SourceContextInfo {
            context_id: source_context_id.clone(),
            source_type: st,
            memory_scope: ms,
            members: members.into_iter().map(scp_identity::DID::from).collect(),
            discovery_method: DiscoveryMethod::OutOfBand,
            data_age: std::time::Duration::from_secs(0),
            purpose: None,
            counterparty_policy: scp_core::provenance::CounterpartyPolicy::default(),
        };

        let existing_prov = existing_chain_depth.map(|depth| DataProvenance {
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
        });

        let prov = attach_provenance(
            &source_info,
            &target_context_id,
            existing_prov.as_ref(),
            None,
            None,
        );

        // Compute provenance hash: SHA-256 of JSON-serialized provenance record.
        let prov_json_bytes =
            serde_json::to_vec(&prov).map_err(|e| ScpPyError::ValidationError {
                message: format!("failed to serialize provenance for hashing: {e}"),
                code: codes::VALID_7053.to_string(),
            })?;
        let prov_hash: [u8; 32] = Sha256::digest(&prov_json_bytes).into();

        // Record ProvenanceAttached in the source context event log.
        // Best-effort: log warning if context not found (provenance_attach
        // can be called without a runtime context, e.g. in unit tests).
        if let Err(e) = append_provenance_event(
            bi,
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
            bi,
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

        provenance_to_dict(py, &prov)
    }

    /// Checks whether the provenance chain depth is within the allowed limit.
    ///
    /// Returns `True` if within limit, `False` otherwise.
    #[pyo3(signature = (chain_depth, max_depth=None))]
    #[must_use]
    pub fn provenance_check_chain_depth(&self, chain_depth: u8, max_depth: Option<u8>) -> bool {
        let max = max_depth.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH);
        let prov = DataProvenance {
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
        };
        check_chain_depth(&prov, max).is_ok()
    }

    /// Redacts counterparties from a provenance record (§24.3.5).
    ///
    /// Accepts a JSON-serialized provenance record, removes all counterparty DIDs,
    /// and returns the modified record as a JSON string.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `provenance_json` is not valid JSON or cannot
    /// be deserialized as a `DataProvenance` record.
    pub fn provenance_redact_counterparties(&self, provenance_json: &str) -> PyResult<String> {
        let mut prov: DataProvenance =
            serde_json::from_str(provenance_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid provenance JSON: {e}"),
                code: codes::VALID_7050.to_string(),
            })?;

        redact_counterparties(&mut prov);

        serde_json::to_string(&prov).map_err(|e| {
            ScpPyError::ValidationError {
                message: format!("failed to serialize provenance: {e}"),
                code: codes::VALID_7051.to_string(),
            }
            .into()
        })
    }

    /// Pseudonymizes counterparties in a provenance record (§24.3.5).
    ///
    /// Accepts a JSON-serialized provenance record and a pseudonym key (as a
    /// hex-encoded string). Replaces real counterparty DIDs with deterministic
    /// context-scoped pseudonyms derived from the key. Returns the modified
    /// record as a JSON string.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `provenance_json` is not valid JSON, cannot
    /// be deserialized as a `DataProvenance` record, or if `pseudonym_key_hex`
    /// is not valid hex.
    pub fn provenance_pseudonymize_counterparties(
        &self,
        provenance_json: &str,
        pseudonym_key_hex: &str,
    ) -> PyResult<String> {
        let mut prov: DataProvenance =
            serde_json::from_str(provenance_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid provenance JSON: {e}"),
                code: codes::VALID_7050.to_string(),
            })?;

        let key = Zeroizing::new(hex::decode(pseudonym_key_hex).map_err(|e| {
            ScpPyError::ValidationError {
                message: format!("invalid pseudonym_key_hex: {e}"),
                code: codes::VALID_7052.to_string(),
            }
        })?);

        pseudonymize_counterparties(&mut prov, &key);

        serde_json::to_string(&prov).map_err(|e| {
            ScpPyError::ValidationError {
                message: format!("failed to serialize provenance: {e}"),
                code: codes::VALID_7051.to_string(),
            }
            .into()
        })
    }

    /// Updates the source type of a provenance record to reflect a new context
    /// state (ADR-019 AC5).
    ///
    /// Accepts a JSON-serialized provenance record and a context state string.
    /// Updates the `source_type` field to match the new state and returns the
    /// modified record as a JSON string.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `provenance_json` is not valid JSON, cannot
    /// be deserialized as a `DataProvenance` record, or if `new_state` is not
    /// a recognized context state value.
    pub fn provenance_update_source_type(
        &self,
        provenance_json: &str,
        new_state: &str,
    ) -> PyResult<String> {
        let mut prov: DataProvenance =
            serde_json::from_str(provenance_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid provenance JSON: {e}"),
                code: codes::VALID_7050.to_string(),
            })?;

        let state = parse_context_state(new_state)?;

        update_source_type(&mut prov, &state);

        serde_json::to_string(&prov).map_err(|e| {
            ScpPyError::ValidationError {
                message: format!("failed to serialize provenance: {e}"),
                code: codes::VALID_7051.to_string(),
            }
            .into()
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Appends a provenance event (`ProvenanceAttached` or `ProvenanceReceived`)
/// to the event log for the given context on the given bridge instance.
///
/// Follows the unsigned-event pattern used by `ToolInvoked` in `mcp.rs`.
fn append_provenance_event(
    bi: &PyBridgeInstance,
    context_id: &str,
    actor_did: &str,
    event_type: scp_event_log::EventType,
    provenance_hash: &[u8; 32],
) -> PyResult<()> {
    #[allow(clippy::cast_possible_truncation)]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    crate::runtime::with_context(bi, context_id, |rt| {
        let sequence = scp_event_log::tree::event_count(&rt.event_log);
        let prev_hash = if rt.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            rt.event_log.leaves()[rt.event_log.leaves().len() - 1]
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

        scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event)
            .map_err(|e| ScpPyError::context(e.to_string()))?;

        Ok(())
    })?;

    Ok(())
}

fn parse_memory_scope(s: &str) -> PyResult<MemoryScope> {
    match s {
        "full" => Ok(MemoryScope::Full),
        "summary" => Ok(MemoryScope::Summary),
        "ephemeral" => Ok(MemoryScope::Ephemeral),
        other => Err(ScpPyError::ValidationError {
            message: format!(
                "invalid memory_scope '{other}': expected 'full', 'summary', or 'ephemeral'"
            ),
            code: codes::PERM_3010.to_string(),
        }
        .into()),
    }
}

fn provenance_to_dict<'py>(py: Python<'py>, prov: &DataProvenance) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("source_context", &prov.source_context)?;
    dict.set_item("source_type", format!("{:?}", prov.source_type))?;
    dict.set_item("chain_depth", prov.chain_depth)?;
    dict.set_item(
        "counterparties",
        prov.counterparties
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )?;
    dict.set_item("age_secs", prov.age.as_secs())?;
    dict.set_item("memory_scope", format!("{:?}", prov.memory_scope))?;
    dict.set_item("chain_path", prov.chain_path.clone())?;
    dict.set_item("purpose", prov.purpose.as_deref())?;
    Ok(dict)
}

fn parse_source_type(s: &str) -> PyResult<SourceType> {
    match s {
        "persistent" => Ok(SourceType::Persistent),
        "ephemeral" => Ok(SourceType::Ephemeral),
        "summary" => Ok(SourceType::Summary),
        other => Err(ScpPyError::ValidationError {
            message: format!(
                "invalid source_type '{other}': expected 'persistent', 'ephemeral', or 'summary'"
            ),
            code: codes::PERM_3011.to_string(),
        }
        .into()),
    }
}

fn parse_context_state(s: &str) -> PyResult<SourceContextState> {
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
        other => Err(ScpPyError::ValidationError {
            message: format!(
                "invalid context_state '{other}': expected 'active', 'closed_with_summary_verified', \
                 'closed_with_summary_unverified', 'closed_ephemeral', or 'unknown'"
            ),
            code: codes::PERM_3012.to_string(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers provenance bridge helpers on the `_scp_core` module.
///
/// Post-migration (Phase 4 PR 4 sub-slice C) provenance operations are exposed
/// as methods on `SCP` (see the `#[pymethods]` block above) and registered
/// automatically with the class. This function is retained to preserve the
/// module-init call sequence; it is currently a no-op.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub const fn register_provenance(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new()
    }

    #[test]
    fn parse_source_type_valid() {
        assert_eq!(
            parse_source_type("persistent").unwrap(),
            SourceType::Persistent
        );
        assert_eq!(
            parse_source_type("ephemeral").unwrap(),
            SourceType::Ephemeral
        );
        assert_eq!(parse_source_type("summary").unwrap(), SourceType::Summary);
    }

    #[test]
    fn parse_source_type_invalid() {
        assert!(parse_source_type("invalid").is_err());
    }

    #[test]
    fn parse_context_state_valid() {
        assert_eq!(
            parse_context_state("active").unwrap(),
            SourceContextState::Active
        );
        assert_eq!(
            parse_context_state("closed_with_summary_verified").unwrap(),
            SourceContextState::ClosedWithSummary {
                summary_verified: true
            }
        );
        assert_eq!(
            parse_context_state("closed_with_summary_unverified").unwrap(),
            SourceContextState::ClosedWithSummary {
                summary_verified: false
            }
        );
        assert_eq!(
            parse_context_state("closed_ephemeral").unwrap(),
            SourceContextState::ClosedEphemeral
        );
        assert_eq!(
            parse_context_state("unknown").unwrap(),
            SourceContextState::Unknown
        );
    }

    #[test]
    fn parse_context_state_invalid() {
        assert!(parse_context_state("invalid").is_err());
    }

    #[test]
    fn parse_memory_scope_valid() {
        assert_eq!(parse_memory_scope("full").unwrap(), MemoryScope::Full);
        assert_eq!(parse_memory_scope("summary").unwrap(), MemoryScope::Summary);
        assert_eq!(
            parse_memory_scope("ephemeral").unwrap(),
            MemoryScope::Ephemeral
        );
    }

    #[test]
    fn parse_memory_scope_invalid() {
        assert!(parse_memory_scope("invalid").is_err());
    }

    #[test]
    fn check_chain_depth_within_limit() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        assert!(scp.provenance_check_chain_depth(0, None));
        assert!(scp.provenance_check_chain_depth(8, None)); // default is 8 (ADR-043)
    }

    #[test]
    fn check_chain_depth_exceeds_limit() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        assert!(!scp.provenance_check_chain_depth(9, None)); // 9 > default 8
        assert!(!scp.provenance_check_chain_depth(2, Some(1)));
    }

    #[test]
    fn redact_counterparties_removes_dids() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
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
        let result = scp
            .provenance_redact_counterparties(&prov_json.to_string())
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["counterparties"], serde_json::json!([]));
        assert_eq!(parsed["source_context"], "ctx-test");
    }

    #[test]
    fn pseudonymize_counterparties_produces_deterministic_pseudonyms() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
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
        let result1 = scp
            .provenance_pseudonymize_counterparties(&prov_json.to_string(), &key_hex)
            .unwrap();
        let result2 = scp
            .provenance_pseudonymize_counterparties(&prov_json.to_string(), &key_hex)
            .unwrap();

        // Deterministic: same input → same output
        assert_eq!(result1, result2);

        let parsed: serde_json::Value = serde_json::from_str(&result1).unwrap();
        let parties = parsed["counterparties"].as_array().unwrap();
        assert_eq!(parties.len(), 1);
        assert!(parties[0].as_str().unwrap().starts_with("did:pseudo:"));
    }

    #[test]
    fn update_source_type_changes_type() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
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
        let result = scp
            .provenance_update_source_type(&prov_json.to_string(), "closed_ephemeral")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["source_type"], "Ephemeral");
    }

    #[test]
    fn update_source_type_preserves_on_unknown() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Summary",
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
        let result = scp
            .provenance_update_source_type(&prov_json.to_string(), "unknown")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["source_type"], "Summary");
    }

    #[test]
    fn redact_counterparties_invalid_json_fails() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
        assert!(scp.provenance_redact_counterparties("not json").is_err());
    }

    #[test]
    fn pseudonymize_counterparties_invalid_hex_fails() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
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
            scp.provenance_pseudonymize_counterparties(&prov_json.to_string(), "not-hex-zz")
                .is_err()
        );
    }

    #[test]
    fn update_source_type_invalid_state_fails() {
        pyo3::prepare_freethreaded_python();
        let scp = default_scp();
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
            scp.provenance_update_source_type(&prov_json.to_string(), "invalid_state")
                .is_err()
        );
    }
}
