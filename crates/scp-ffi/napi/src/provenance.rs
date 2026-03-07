//! napi-rs bridge for provenance operations.
//!
//! Exposes SCP provenance quality evaluation to Node.js/Bun:
//!
//! - [`evaluate_provenance_quality`] -- Evaluate the provenance quality tier.
//!
//! See spec section 24 (Provenance System) and ADR-019.

use napi_derive::napi;

use scp_core::provenance::evaluate::{SourceContextState, evaluate_quality};
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Evaluates the provenance quality tier for a given data provenance record.
///
/// Returns an integer (0-3) representing the quality tier:
/// - `0` = `NoProvenance`
/// - `1` = `EphemeralKnownParties`
/// - `2` = `SummaryVerified`
/// - `3` = `PersistentVerifiable`
///
/// # Arguments
///
/// * `source_context` -- Context ID where data originated, or `null`.
/// * `source_type` -- `"persistent"`, `"ephemeral"`, or `"summary"`.
/// * `context_state` -- `"active"`, `"closed_with_summary_verified"`,
///   `"closed_with_summary_unverified"`, `"closed_ephemeral"`, or `"unknown"`.
/// * `counterparties` -- Array of DID strings, or `null`.
///
/// # Errors
///
/// Rejects with `SCP-VALID-7000` if `source_type` or `context_state` are invalid.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String parameters
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

    Ok(quality as u32)
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
