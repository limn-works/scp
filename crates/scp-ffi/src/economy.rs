//! `PyO3` bridge functions for SCP economic governance.
//!
//! Exposes economic operations to Python as methods on the `SCP` class:
//!
//! - `PyScp::economy_estimate_cost` — Estimate cost for an action in a context.
//! - `PyScp::economy_policy_requires_payment` — Check if a policy requires payment.
//! - `PyScp::economy_auto_accept_blocked` — Check if auto-accept is blocked by economics.
//! - `PyScp::economy_check_policy_lock` — Check if economic policy mutation is allowed.
//! - `PyScp::economy_validate_policy_change` — Validate a proposed policy change.
//! - `PyScp::economy_evaluate_formula` — Evaluate a pricing formula against metrics.
//! - `PyScp::economy_budget_remaining` — Query remaining budget for a member.
//! - `PyScp::economy_budget_grant` — Grant spending budget to a member.
//! - `PyScp::economy_budget_record_spend` — Record a spend against a member's budget.
//! - `PyScp::economy_antispam_record` — Record a message for velocity tracking.
//! - `PyScp::economy_antispam_velocity` — Query sender velocity.
//! - `PyScp::economy_antispam_escalated_cost` — Compute escalated cost for a sender.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice D (#1549). Pure helpers
//! (`economy_estimate_cost`, `economy_policy_requires_payment`,
//! `economy_auto_accept_blocked`, `economy_check_policy_lock`,
//! `economy_validate_policy_change`, `economy_evaluate_formula`) remain as
//! free `#[pyfunction]` exports — they have no bridge-state dependency.
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
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Queries the remaining budget for a member in a context.
    ///
    /// Returns the remaining budget as an integer, or 0 if no budget is allocated.
    #[pyo3(name = "economy_budget_remaining")]
    pub fn economy_budget_remaining(&self, context_id: &str, did: &str) -> PyResult<u64> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(did)?;

        let member_did = scp_did::DID::from(did);
        let remaining = bi
            .core
            .with_economy_budget(context_id, |tracker| tracker.remaining(&member_did));
        Ok(remaining.value())
    }

    /// Grants spending budget to a member in a context.
    ///
    /// Grants are additive: granting 100 twice gives a total limit of 200.
    #[pyo3(name = "economy_budget_grant")]
    pub fn economy_budget_grant(&self, context_id: &str, did: &str, amount: u64) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(did)?;

        let member_did = scp_did::DID::from(did);
        bi.core.with_economy_budget_mut(context_id, |tracker| {
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
    #[pyo3(name = "economy_budget_record_spend")]
    pub fn economy_budget_record_spend(
        &self,
        context_id: &str,
        did: &str,
        amount: u64,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(did)?;

        let member_did = scp_did::DID::from(did);
        bi.core.with_economy_budget_mut(context_id, |tracker| {
            tracker
                .record_spend(&member_did, scp_core::economy::Amount::new(amount))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e}")))
        })
    }

    /// Records a message from a sender for antispam velocity tracking.
    ///
    /// # Arguments
    ///
    /// * `context_id` — The context ID.
    /// * `sender_did` — The sender's DID.
    /// * `timestamp` — Unix timestamp in seconds.
    #[pyo3(name = "economy_antispam_record")]
    pub fn economy_antispam_record(
        &self,
        context_id: &str,
        sender_did: &str,
        timestamp: u64,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(sender_did)?;

        let did = scp_did::DID::from(sender_did);
        bi.core.with_economy_antispam(context_id, |tracker| {
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
    #[pyo3(name = "economy_antispam_velocity")]
    pub fn economy_antispam_velocity(
        &self,
        context_id: &str,
        sender_did: &str,
        now: u64,
    ) -> PyResult<u64> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(sender_did)?;

        let did = scp_did::DID::from(sender_did);
        let velocity = bi
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
    #[pyo3(name = "economy_antispam_escalated_cost", signature = (context_id, sender_did, now, base_cost, thresholds_json, floor=None, cap=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn economy_antispam_escalated_cost(
        &self,
        context_id: &str,
        sender_did: &str,
        now: u64,
        base_cost: u64,
        thresholds_json: &str,
        floor: Option<u64>,
        cap: Option<u64>,
    ) -> PyResult<u64> {
        let bi = &*self.inner;
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

        let did = scp_did::DID::from(sender_did);
        let cost = bi.core.with_economy_antispam(context_id, |tracker| {
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
    /// Maximum 10,000 receipts per call.
    ///
    /// # Arguments
    ///
    /// * `receipts_json` — JSON-encoded array of `PaymentReceipt` objects.
    ///
    /// # Returns
    ///
    /// A JSON object `{"all_valid": <bool>, "results": [...]}`. `all_valid`
    /// is `true` iff every entry both reached the adapter (`ok == true`) and
    /// the adapter reported the receipt valid (`result.valid == true`); it is
    /// vacuously `true` for an empty batch. Each `results` entry is either
    /// `{"receipt_id": <hex>, "ok": true, "valid": <bool>, "result": <structured
    /// VerificationResult>}` on success or `{"ok": false, "error": "..."}` on
    /// failure.
    ///
    /// `ok` means the adapter *responded* — NOT that the payment is valid.
    /// Payment validity is carried by the per-entry `valid` field (and the
    /// structured `result.valid`) and aggregated into top-level `all_valid`.
    /// A caller scanning for failures must inspect `valid`/`all_valid`, not
    /// `ok` — an invalid-but-reachable receipt has `ok == true`, `valid ==
    /// false`.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the receipts JSON is invalid or the
    /// supervisor is not initialized.
    #[pyo3(name = "economy_verify_payment_receipts")]
    pub fn economy_verify_payment_receipts(&self, receipts_json: &str) -> PyResult<String> {
        use pyo3::exceptions::{PyRuntimeError, PyValueError};

        let bi = &*self.inner;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();

        let receipts: Vec<scp_core::economy::PaymentReceipt> = serde_json::from_str(receipts_json)
            .map_err(|e| PyValueError::new_err(format!("invalid receipts JSON: {e}")))?;

        // Bound the per-call batch before dispatch: each receipt fans out to a
        // serial payment-adapter verification round-trip, so an unbounded batch
        // is a denial-of-service vector. See `MAX_RECEIPT_BATCH`.
        if receipts.len() > scp_core::economy::MAX_RECEIPT_BATCH {
            return Err(PyValueError::new_err(format!(
                "receipt batch too large: {} (max {})",
                receipts.len(),
                scp_core::economy::MAX_RECEIPT_BATCH
            )));
        }

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

            // Serialize via the single canonical helper shared by all bridges,
            // so the JSON contract (string currency, numeric amount, `ok` vs
            // `valid`/`all_valid` semantics) cannot drift across PyO3, napi, and
            // UniFFI. See `scp_runtime::economy::receipt::verification_results_to_json`.
            Ok(scp_core::economy::verification_results_to_json(results))
        })
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Registers all economy bridge functions with the Python module.
///
/// Post-migration (Phase 4 PR 4 sub-slice D), stateful economy operations are
/// exposed as methods on `SCP` (see the `#[pymethods]` block above). Only pure
/// helpers (cost estimation, policy inspection, formula evaluation) remain as
/// free `#[pyfunction]` exports.
pub fn register_economy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_economy_estimate_cost, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_policy_requires_payment, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_auto_accept_blocked, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_check_policy_lock, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_validate_policy_change, m)?)?;
    m.add_function(wrap_pyfunction!(py_economy_evaluate_formula, m)?)?;
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
