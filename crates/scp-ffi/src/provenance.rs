//! `PyO3` bridge functions for provenance operations.
//!
//! Exposes SCP provenance types and quality evaluation to Python:
//!
//! - [`py_evaluate_provenance_quality`] -- Evaluate the provenance quality tier
//!   for a given provenance record and source context state.
//! - [`py_provenance_attach`] -- Attach provenance metadata at cross-context
//!   boundaries.
//! - [`py_provenance_check_chain_depth`] -- Check whether a provenance chain
//!   depth is within the allowed limit.
//!
//! See spec section 24 (Provenance System) and ADR-019.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use scp_core::context::MemoryScope;
use scp_core::provenance::attach::{
    DEFAULT_MAX_CHAIN_DEPTH, SourceContextInfo, attach_provenance, check_chain_depth,
};
use scp_core::provenance::evaluate::{SourceContextState, evaluate_quality};
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Evaluates the provenance quality tier for a given data provenance record.
///
/// See spec section 24 (Provenance System).
///
/// # Errors
///
/// Raises `ValidationError` if `source_type` or `context_state` are invalid.
#[pyfunction]
#[pyo3(name = "evaluate_provenance_quality")]
#[pyo3(signature = (source_context=None, source_type="persistent", context_state="unknown", counterparties=None))]
pub fn py_evaluate_provenance_quality(
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
        discovery_method: DiscoveryMethod::None,
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
/// See ADR-019 acceptance criteria 2-3, 6.
///
/// # Errors
///
/// Raises `ValidationError` if `source_type` or `memory_scope` are invalid.
#[pyfunction]
#[pyo3(name = "provenance_attach")]
#[pyo3(signature = (source_context_id, source_type, memory_scope, members, target_context_id, existing_chain_depth=None))]
pub fn py_provenance_attach<'py>(
    py: Python<'py>,
    source_context_id: String,
    source_type: &str,
    memory_scope: &str,
    members: Vec<String>,
    target_context_id: String,
    existing_chain_depth: Option<u8>,
) -> PyResult<Bound<'py, PyDict>> {
    let st = parse_source_type(source_type)?;
    let ms = parse_memory_scope(memory_scope)?;

    let source_info = SourceContextInfo {
        context_id: source_context_id,
        source_type: st,
        memory_scope: ms,
        members: members.into_iter().map(scp_identity::DID::from).collect(),
        discovery_method: DiscoveryMethod::None,
        data_age: std::time::Duration::from_secs(0),
        purpose: None,
    };

    let existing_prov = existing_chain_depth.map(|depth| DataProvenance {
        source_context: String::new(),
        source_type: SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: DiscoveryMethod::None,
        age: std::time::Duration::from_secs(0),
        memory_scope: MemoryScope::Full,
        chain_depth: depth,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    });

    let prov = attach_provenance(&source_info, &target_context_id, existing_prov.as_ref());

    provenance_to_dict(py, &prov)
}

/// Checks whether the provenance chain depth is within the allowed limit.
///
/// Returns `True` if within limit, `False` otherwise.
#[pyfunction]
#[pyo3(name = "provenance_check_chain_depth")]
#[pyo3(signature = (chain_depth, max_depth=None))]
#[must_use]
pub fn py_provenance_check_chain_depth(chain_depth: u8, max_depth: Option<u8>) -> bool {
    let max = max_depth.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH);
    let prov = DataProvenance {
        source_context: String::new(),
        source_type: SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: DiscoveryMethod::None,
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_memory_scope(s: &str) -> PyResult<MemoryScope> {
    match s {
        "full" => Ok(MemoryScope::Full),
        "summary" => Ok(MemoryScope::Summary),
        "ephemeral" => Ok(MemoryScope::Ephemeral),
        other => Err(ScpPyError::ValidationError {
            message: format!(
                "invalid memory_scope '{other}': expected 'full', 'summary', or 'ephemeral'"
            ),
            code: "SCP-PERM-9003".to_string(),
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
            code: "SCP-PERM-9001".to_string(),
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
            code: "SCP-PERM-9002".to_string(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers provenance bridge functions on the `_scp_core` module.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_provenance(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_evaluate_provenance_quality, m)?)?;
    m.add_function(wrap_pyfunction!(py_provenance_attach, m)?)?;
    m.add_function(wrap_pyfunction!(py_provenance_check_chain_depth, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
        assert!(py_provenance_check_chain_depth(0, None));
        assert!(py_provenance_check_chain_depth(3, None));
    }

    #[test]
    fn check_chain_depth_exceeds_limit() {
        assert!(!py_provenance_check_chain_depth(4, None));
        assert!(!py_provenance_check_chain_depth(2, Some(1)));
    }
}
