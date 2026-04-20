//! `PyO3` bridge functions for SCP economic governance.
//!
//! Exposes economic operations to Python:
//!
//! - [`py_economy_estimate_cost`] — Estimate cost for an action in a context.
//! - [`py_economy_policy_requires_payment`] — Check if a policy requires payment.
//! - [`py_economy_auto_accept_blocked`] — Check if auto-accept is blocked by economics.
//! - [`py_economy_check_policy_lock`] — Check if economic policy mutation is allowed.
//! - [`py_economy_validate_policy_change`] — Validate a proposed policy change.
//! - [`py_economy_evaluate_formula`] — Evaluate a pricing formula against metrics.
//! - [`py_economy_budget_remaining`] — Query remaining budget for a member.
//! - [`py_economy_budget_grant`] — Grant spending budget to a member.
//! - [`py_economy_budget_record_spend`] — Record a spend against a member's budget.
//! - [`py_economy_antispam_record`] — Record a message for velocity tracking.
//! - [`py_economy_antispam_velocity`] — Query sender velocity.
//! - [`py_economy_antispam_escalated_cost`] — Compute escalated cost for a sender.
//!
//! See spec section 19 (Economic Governance) and ADR-033.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::validate;

// ---------------------------------------------------------------------------
// Helper: parse PaidActionType from string
// ---------------------------------------------------------------------------

fn parse_action_type(s: &str) -> PyResult<scp_core::economy::PaidActionType> {
    match s {
        "MessageSend" | "message_send" => Ok(scp_core::economy::PaidActionType::MessageSend),
        "ToolInvoke" | "tool_invoke" => Ok(scp_core::economy::PaidActionType::ToolInvoke),
        "ContextJoin" | "context_join" => Ok(scp_core::economy::PaidActionType::ContextJoin),
        "SubscriptionPeriod" | "subscription_period" => {
            Ok(scp_core::economy::PaidActionType::SubscriptionPeriod)
        }
        "ByteStored" | "byte_stored" => Ok(scp_core::economy::PaidActionType::ByteStored),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "invalid action type: {s:?} — expected one of: MessageSend, ToolInvoke, \
             ContextJoin, SubscriptionPeriod, ByteStored"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Helper: parse EconomicPolicy from JSON string
// ---------------------------------------------------------------------------

fn parse_economic_policy(json: &str) -> PyResult<scp_core::economy::EconomicPolicy> {
    serde_json::from_str(json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "failed to parse economic policy JSON: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Helper: parse ObservableMetrics from Python dict
// ---------------------------------------------------------------------------

fn parse_metrics(dict: &Bound<'_, PyDict>) -> PyResult<scp_core::economy::ObservableMetrics> {
    Ok(scp_core::economy::ObservableMetrics {
        context_message_rate: dict
            .get_item("context_message_rate")?
            .and_then(|v| v.extract::<u64>().ok())
            .unwrap_or(0),
        member_count: dict
            .get_item("member_count")?
            .and_then(|v| v.extract::<u64>().ok())
            .unwrap_or(0),
        relay_queue_depth: dict
            .get_item("relay_queue_depth")?
            .and_then(|v| v.extract::<u64>().ok())
            .unwrap_or(0),
        time_of_day: dict
            .get_item("time_of_day")?
            .and_then(|v| v.extract::<u64>().ok())
            .unwrap_or(0),
        sender_velocity: dict
            .get_item("sender_velocity")?
            .and_then(|v| v.extract::<u64>().ok())
            .unwrap_or(0),
        storage_usage: dict
            .get_item("storage_usage")?
            .and_then(|v| v.extract::<u64>().ok())
            .unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// estimate_cost
// ---------------------------------------------------------------------------

/// Estimates the cost for a given action in a context.
///
/// This is the SDK-facing function (`SCP.Economy.estimateCost`) described in
/// spec section 19.11. Returns the estimated cost as an integer (smallest
/// currency unit), or `None` on arithmetic overflow.
///
/// # Arguments
///
/// * `policy_json` — The context's economic policy as a JSON string. Pass
///   empty string or `"null"` for free contexts (returns 0).
/// * `action_type` — The action type string: `"MessageSend"`, `"ToolInvoke"`,
///   `"ContextJoin"`, `"SubscriptionPeriod"`, or `"ByteStored"`.
/// * `metrics` — Dict with observable metric values: `context_message_rate`,
///   `member_count`, `relay_queue_depth`, `time_of_day`, `sender_velocity`,
///   `storage_usage`. All optional, default to 0.
///
/// # Returns
///
/// Cost as integer (smallest currency unit), or `None` on overflow.
#[pyfunction]
#[pyo3(name = "economy_estimate_cost")]
pub fn py_economy_estimate_cost(
    policy_json: &str,
    action_type: &str,
    metrics: &Bound<'_, PyDict>,
) -> PyResult<Option<u64>> {
    let action = parse_action_type(action_type)?;
    let observable = parse_metrics(metrics)?;

    let policy = if policy_json.is_empty() || policy_json == "null" {
        None
    } else {
        Some(parse_economic_policy(policy_json)?)
    };

    let result = scp_core::economy::estimate_cost(policy.as_ref(), &action, &observable)
        .map(scp_core::economy::Amount::value);
    Ok(result)
}

// ---------------------------------------------------------------------------
// policy_requires_payment
// ---------------------------------------------------------------------------

/// Returns `True` if the given economic policy requires payment for any action.
///
/// A policy requires payment if it has a non-empty cost schedule with at least
/// one non-zero cost, or a pricing formula. Returns `False` for `None`/empty
/// policy (free context).
#[pyfunction]
#[pyo3(name = "economy_policy_requires_payment")]
pub fn py_economy_policy_requires_payment(policy_json: &str) -> PyResult<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy = parse_economic_policy(policy_json)?;
    Ok(scp_core::economy::policy_requires_payment(&policy))
}

// ---------------------------------------------------------------------------
// auto_accept_blocked_by_economics
// ---------------------------------------------------------------------------

/// Returns `True` if context auto-accept is blocked by the economic policy.
///
/// Contexts with economic policies requiring payment must never auto-accept
/// invitations. This is a hard rule per spec section 19.3.
#[pyfunction]
#[pyo3(name = "economy_auto_accept_blocked")]
pub fn py_economy_auto_accept_blocked(policy_json: &str) -> PyResult<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy = parse_economic_policy(policy_json)?;
    Ok(scp_core::economy::auto_accept_blocked_by_economics(Some(
        &policy,
    )))
}

// ---------------------------------------------------------------------------
// check_policy_lock
// ---------------------------------------------------------------------------

/// Checks if an economic policy is locked (immutable).
///
/// Returns `True` if the policy is locked (mutation forbidden).
/// Returns `False` if unlocked (mutation allowed through governance).
#[pyfunction]
#[pyo3(name = "economy_check_policy_lock")]
pub fn py_economy_check_policy_lock(policy_json: &str) -> PyResult<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy = parse_economic_policy(policy_json)?;
    Ok(scp_core::economy::check_policy_lock(&policy).is_err())
}

// ---------------------------------------------------------------------------
// validate_policy_change
// ---------------------------------------------------------------------------

/// Validates a proposed economic policy change.
///
/// Checks that the new policy is valid and that the change is allowed
/// (policy not locked). Returns `True` if the change is valid.
///
/// # Errors
///
/// Raises `ValueError` if the current policy is locked or JSON is invalid.
#[pyfunction]
#[pyo3(name = "economy_validate_policy_change")]
pub fn py_economy_validate_policy_change(
    current_policy_json: &str,
    proposed_policy_json: &str,
) -> PyResult<bool> {
    let current = parse_economic_policy(current_policy_json)?;
    let proposed = parse_economic_policy(proposed_policy_json)?;
    scp_core::economy::validate_policy_change(&current, &proposed).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("policy change rejected: {e}"))
    })?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// evaluate_formula
// ---------------------------------------------------------------------------

/// Evaluates a pricing formula against observable metrics.
///
/// Returns the computed cost as an integer (smallest currency unit), or `None`
/// on arithmetic overflow.
///
/// # Arguments
///
/// * `formula_json` — The pricing formula as a JSON string.
/// * `metrics` — Dict with observable metric values.
#[pyfunction]
#[pyo3(name = "economy_evaluate_formula")]
pub fn py_economy_evaluate_formula(
    formula_json: &str,
    metrics: &Bound<'_, PyDict>,
) -> PyResult<Option<u64>> {
    let formula: scp_core::economy::PricingFormula =
        serde_json::from_str(formula_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse pricing formula JSON: {e}"
            ))
        })?;
    let observable = parse_metrics(metrics)?;
    let result = scp_core::economy::evaluate_formula(&formula, &observable)
        .map(scp_core::economy::Amount::value);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Budget tracker (stateful, per-context via runtime registry)
// ---------------------------------------------------------------------------

/// Queries the remaining budget for a member in a context.
///
/// Returns the remaining budget as an integer, or 0 if no budget is allocated.
#[pyfunction]
#[pyo3(name = "economy_budget_remaining")]
pub fn py_economy_budget_remaining(context_id: &str, did: &str) -> PyResult<u64> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(did)?;

    let member_did = scp_identity::DID::from(did);
    let remaining = crate::runtime::bridge_instance()?
        .core
        .with_economy_budget(context_id, |tracker| tracker.remaining(&member_did));
    Ok(remaining.value())
}

/// Grants spending budget to a member in a context.
///
/// Grants are additive: granting 100 twice gives a total limit of 200.
#[pyfunction]
#[pyo3(name = "economy_budget_grant")]
pub fn py_economy_budget_grant(context_id: &str, did: &str, amount: u64) -> PyResult<()> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(did)?;

    let member_did = scp_identity::DID::from(did);
    crate::runtime::bridge_instance()?
        .core
        .with_economy_budget_mut(context_id, |tracker| {
            tracker.grant(&member_did, scp_core::economy::Amount::new(amount));
        });
    Ok(())
}

/// Records a spend against a member's budget in a context.
///
/// # Errors
///
/// Raises `ValueError` if the member has no budget or the spend would exceed
/// the remaining budget.
#[pyfunction]
#[pyo3(name = "economy_budget_record_spend")]
pub fn py_economy_budget_record_spend(context_id: &str, did: &str, amount: u64) -> PyResult<()> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(did)?;

    let member_did = scp_identity::DID::from(did);
    crate::runtime::bridge_instance()?
        .core
        .with_economy_budget_mut(context_id, |tracker| {
            tracker
                .record_spend(&member_did, scp_core::economy::Amount::new(amount))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e}")))
        })
}

// ---------------------------------------------------------------------------
// Antispam velocity tracker (stateful, per-context via runtime registry)
// ---------------------------------------------------------------------------

/// Records a message from a sender for antispam velocity tracking.
///
/// # Arguments
///
/// * `context_id` — The context ID.
/// * `sender_did` — The sender's DID.
/// * `timestamp` — Unix timestamp in seconds.
#[pyfunction]
#[pyo3(name = "economy_antispam_record")]
pub fn py_economy_antispam_record(
    context_id: &str,
    sender_did: &str,
    timestamp: u64,
) -> PyResult<()> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(sender_did)?;

    let did = scp_identity::DID::from(sender_did);
    crate::runtime::bridge_instance()?
        .core
        .with_economy_antispam(context_id, |tracker| {
            tracker.record_message(&did, timestamp);
        });
    Ok(())
}

/// Queries the sender's message velocity (messages within the sliding window).
///
/// # Arguments
///
/// * `context_id` — The context ID.
/// * `sender_did` — The sender's DID.
/// * `now` — Current Unix timestamp in seconds.
///
/// # Returns
///
/// Message count within the sliding window.
#[pyfunction]
#[pyo3(name = "economy_antispam_velocity")]
pub fn py_economy_antispam_velocity(context_id: &str, sender_did: &str, now: u64) -> PyResult<u64> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(sender_did)?;

    let did = scp_identity::DID::from(sender_did);
    let velocity = crate::runtime::bridge_instance()?
        .core
        .with_economy_antispam(context_id, |tracker| tracker.get_velocity(&did, now));
    Ok(velocity)
}

/// Computes the escalated cost for a sender based on antispam velocity.
///
/// # Arguments
///
/// * `context_id` — The context ID.
/// * `sender_did` — The sender's DID.
/// * `now` — Current Unix timestamp in seconds.
/// * `base_cost` — Base cost (smallest currency unit).
/// * `thresholds_json` — JSON array of `[velocity_threshold, additional_cost]`
///   pairs.
/// * `floor` — Optional minimum cost.
/// * `cap` — Optional maximum cost.
///
/// # Returns
///
/// Escalated cost as integer (smallest currency unit).
#[pyfunction]
#[pyo3(name = "economy_antispam_escalated_cost", signature = (context_id, sender_did, now, base_cost, thresholds_json, floor=None, cap=None))]
#[allow(clippy::too_many_arguments)]
pub fn py_economy_antispam_escalated_cost(
    context_id: &str,
    sender_did: &str,
    now: u64,
    base_cost: u64,
    thresholds_json: &str,
    floor: Option<u64>,
    cap: Option<u64>,
) -> PyResult<u64> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(sender_did)?;

    let thresholds: Vec<(u64, u64)> = serde_json::from_str(thresholds_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("failed to parse thresholds JSON: {e}"))
    })?;

    let config = scp_core::economy::EscalationConfig {
        thresholds: thresholds
            .into_iter()
            .map(|(vel, cost)| scp_core::economy::EscalationThreshold {
                velocity_threshold: vel,
                additional_cost: scp_core::economy::Amount::new(cost),
            })
            .collect(),
    };

    let did = scp_identity::DID::from(sender_did);
    let cost = crate::runtime::bridge_instance()?
        .core
        .with_economy_antispam(context_id, |tracker| {
            tracker.compute_escalated_cost(
                &did,
                now,
                scp_core::economy::Amount::new(base_cost),
                &config,
                floor.map(scp_core::economy::Amount::new),
                cap.map(scp_core::economy::Amount::new),
            )
        });
    Ok(cost.value())
}

// ---------------------------------------------------------------------------
// Payment receipt verification (ADR-049 commit-10 shim — routes through
// Supervisor::dispatch_economy_command)
// ---------------------------------------------------------------------------

/// Verifies a batch of payment receipts against the configured payment
/// adapter.
///
/// Routes through the ADR-049 commit-10 economy shim
/// ([`Supervisor::dispatch_economy_command`](scp_core::context::supervisor::Supervisor::dispatch_economy_command))
/// rather than calling `ContextManager::verify_payment_receipts`
/// directly. The shim wraps the delegated call in a 30s transport-
/// timeout budget and is the entry point commit 12 will keep after
/// `ContextManager` is deleted.
///
/// # Arguments
///
/// * `receipts_json` — JSON-encoded array of `PaymentReceipt` objects.
///
/// # Returns
///
/// JSON string: array of per-receipt results. Each entry is either
/// `{"receipt_id": hex, "result": ...}` on success or
/// `{"error": "...", "code": "..."}` on failure.
///
/// # Errors
///
/// Returns `RuntimeError` if the receipts JSON is invalid or the
/// supervisor is not initialized.
#[pyo3::pyfunction]
pub fn py_economy_verify_payment_receipts(receipts_json: &str) -> PyResult<String> {
    use pyo3::exceptions::{PyRuntimeError, PyValueError};
    use std::sync::Arc;

    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);

    let receipts: Vec<scp_core::economy::PaymentReceipt> = serde_json::from_str(receipts_json)
        .map_err(|e| PyValueError::new_err(format!("invalid receipts JSON: {e}")))?;

    rt.block_on(async move {
        use scp_core::context::actor::commands::EconomyCommand;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = EconomyCommand::VerifyPaymentReceipts {
            receipts: Box::new(receipts),
            reply: tx,
        };
        sup.dispatch_economy_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_economy_command failed: {e}"))
        })?;
        let results = rx.await.map_err(|e| {
            PyRuntimeError::new_err(format!("verify_payment_receipts shim reply dropped: {e}"))
        })?;

        // Serialize results. Each entry is a
        // `Result<ReceiptVerification, ReceiptVerificationError>`.
        let entries: Vec<serde_json::Value> = results
            .into_iter()
            .map(|r| match r {
                Ok(v) => serde_json::json!({
                    "ok": true,
                    "receipt_id": hex::encode(v.receipt_id),
                    "result": format!("{:?}", v.result),
                }),
                Err(e) => serde_json::json!({
                    "ok": false,
                    "error": format!("{e}"),
                }),
            })
            .collect();
        Ok(serde_json::json!({ "results": entries }).to_string())
    })
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Registers all economy bridge functions with the Python module.
pub fn register_economy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_economy_estimate_cost, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_policy_requires_payment, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_auto_accept_blocked, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_check_policy_lock, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_validate_policy_change, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_evaluate_formula, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_budget_remaining, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_budget_grant, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_budget_record_spend, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_antispam_record, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_antispam_velocity, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_antispam_escalated_cost, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_verify_payment_receipts, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_action_type_all_variants() {
        assert!(parse_action_type("MessageSend").is_ok());
        assert!(parse_action_type("message_send").is_ok());
        assert!(parse_action_type("ToolInvoke").is_ok());
        assert!(parse_action_type("ContextJoin").is_ok());
        assert!(parse_action_type("SubscriptionPeriod").is_ok());
        assert!(parse_action_type("ByteStored").is_ok());
        assert!(parse_action_type("invalid").is_err());
    }

    #[test]
    fn parse_economic_policy_valid_json() {
        let json = r#"{
            "locked": false,
            "cost_schedule": {
                "currency": [85,83,68,0],
                "per_message": 10,
                "per_tool_invoke": null,
                "per_join": null,
                "per_period": null,
                "per_byte_stored": null
            },
            "payment_adapters": ["x402"],
            "pricing_formula": null,
            "payee": "did:dht:z6MkPayee"
        }"#;
        assert!(parse_economic_policy(json).is_ok());
    }

    #[test]
    fn parse_economic_policy_invalid_json() {
        assert!(parse_economic_policy("not json").is_err());
    }
}
