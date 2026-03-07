//! `PyO3` bridge functions for provenance operations.
//!
//! Exposes SCP provenance types and quality evaluation to Python:
//!
//! - [`py_evaluate_provenance_quality`] -- Evaluate the provenance quality tier
//!   for a given provenance record and source context state.
//!
//! See spec section 24 (Provenance System) and ADR-019.

use pyo3::prelude::*;

use scp_core::provenance::evaluate::{SourceContextState, evaluate_quality};
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Evaluates the provenance quality tier for a given data provenance record.
///
/// Maps a provenance record and the current state of its source context to
/// one of four quality tiers:
///
/// - `0` = `NoProvenance` -- no protocol-level origin tracking
/// - `1` = `EphemeralKnownParties` -- source ephemeral, parties known
/// - `2` = `SummaryVerified` -- source closed with verified summary
/// - `3` = `PersistentVerifiable` -- source persistent and active
///
/// # Arguments
///
/// * `source_context` -- The context ID where the data originated, or `None`
///   if no provenance is available.
/// * `source_type` -- Current data availability: `"persistent"`, `"ephemeral"`,
///   or `"summary"`.
/// * `context_state` -- Current operational state: `"active"`,
///   `"closed_with_summary_verified"`, `"closed_with_summary_unverified"`,
///   `"closed_ephemeral"`, or `"unknown"`.
/// * `counterparties` -- List of DIDs of parties in the source interaction.
///
/// # Returns
///
/// An integer (0-3) representing the [`ProvenanceQuality`] tier.
///
/// # Errors
///
/// Raises `ValidationError` if `source_type` or `context_state` contain
/// unrecognized values.
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

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
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_provenance(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_evaluate_provenance_quality, m)?)?;
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
}
