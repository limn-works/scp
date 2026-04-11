//! `wasm-bindgen` bridge for SCP economic governance operations.
//!
//! Exposes economic governance operations to JavaScript (browser target).
//! Pricing formula evaluation delegates to `scp-protocol::economy::policy::evaluate_formula`
//! to stay in lockstep with native implementations.
//!
//! See spec section 19 (Economic Governance) and ADR-033.

use js_sys::Promise;
use scp_protocol::economy::policy::{ObservableMetrics, evaluate_formula};
use scp_protocol::economy::types::PricingFormula;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// Internal helpers — metrics JSON → ObservableMetrics conversion
// ---------------------------------------------------------------------------

/// Converts a JSON object of metric values into typed [`ObservableMetrics`].
///
/// Unrecognized or missing fields default to 0 (matching the previous
/// WASM-local `resolve_metric` behavior).
fn metrics_from_json(metrics: &serde_json::Value) -> ObservableMetrics {
    ObservableMetrics {
        context_message_rate: metrics
            .get("context_message_rate")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        member_count: metrics
            .get("member_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        relay_queue_depth: metrics
            .get("relay_queue_depth")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        time_of_day: metrics
            .get("time_of_day")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        sender_velocity: metrics
            .get("sender_velocity")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        storage_usage: metrics
            .get("storage_usage")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// economy_estimate_cost
// ---------------------------------------------------------------------------

/// Estimates the cost for a given action in a context.
///
/// Accepts the economic policy and pricing metrics as JSON strings. Returns
/// a JSON string with `{ "cost": <number> | null }`. `null` indicates
/// arithmetic overflow. Returns `0` for free contexts (empty/null policy).
///
/// # Arguments
///
/// - `policy_json` — Economic policy as JSON, or `""` / `"null"` for free.
/// - `action_type` — One of: `"MessageSend"`, `"ToolInvoke"`,
///   `"ContextJoin"`, `"SubscriptionPeriod"`, `"ByteStored"`.
/// - `metrics_json` — Observable metrics as JSON object.
#[wasm_bindgen]
pub fn economy_estimate_cost(
    policy_json: String,
    action_type: String,
    metrics_json: String,
) -> Promise {
    future_to_promise(async move {
        // Parse action type
        let action_key = match action_type.as_str() {
            "MessageSend" | "message_send" => "per_message",
            "ToolInvoke" | "tool_invoke" => "per_tool_invoke",
            "ContextJoin" | "context_join" => "per_join",
            "SubscriptionPeriod" | "subscription_period" => "per_period",
            "ByteStored" | "byte_stored" => "per_byte_stored",
            _ => {
                return Err(ScpWasmError::validation(&format!(
                    "invalid action type: {action_type}"
                )));
            }
        };

        // Free context
        if policy_json.is_empty() || policy_json == "null" {
            let result = serde_json::json!({ "cost": 0 });
            return Ok(JsValue::from_str(&result.to_string()));
        }

        // Parse policy
        let policy: serde_json::Value = serde_json::from_str(&policy_json).map_err(|e| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7050] invalid economic policy JSON: {e}"
            ))
        })?;

        // Parse metrics
        let metrics: serde_json::Value = if metrics_json.is_empty() || metrics_json == "null" {
            serde_json::json!({})
        } else {
            serde_json::from_str(&metrics_json).map_err(|e| {
                JsValue::from_str(&format!("[SCP-VALID-7050] invalid metrics JSON: {e}"))
            })?
        };

        // Look up schedule cost. For per_period (SubscriptionCost), extract the
        // nested `amount` field since it serializes as an object.
        let schedule_cost = if action_key == "per_period" {
            policy
                .get("cost_schedule")
                .and_then(|cs| cs.get("per_period"))
                .and_then(|pp| pp.get("amount"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        } else {
            policy
                .get("cost_schedule")
                .and_then(|cs| cs.get(action_key))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        };

        // Evaluate formula if present — delegates to scp-protocol's
        // evaluate_formula (shared implementation).
        let formula_cost = policy.get("pricing_formula").and_then(|f| {
            if f.is_null() {
                return Some(0);
            }
            // Deserialize the pricing formula JSON into the typed struct.
            let formula: PricingFormula = serde_json::from_value(f.clone()).ok()?;
            let observable = metrics_from_json(&metrics);
            // evaluate_formula returns Option<Amount>; None means overflow.
            evaluate_formula(&formula, &observable).map(scp_protocol::economy::Amount::value)
        });

        // N4: propagate overflow as null (not 0) so callers know the estimate
        // failed, matching the doc comment and native SCP-ECON-12040 behavior.
        let result = formula_cost.map_or_else(
            || serde_json::json!({ "cost": null }),
            |fc| serde_json::json!({ "cost": schedule_cost.saturating_add(fc) }),
        );
        Ok(JsValue::from_str(&result.to_string()))
    })
}

// ---------------------------------------------------------------------------
// economy_policy_requires_payment
// ---------------------------------------------------------------------------

/// Returns whether the economic policy requires payment for any action.
///
/// Returns a JSON string `{ "requires_payment": bool }`.
#[wasm_bindgen]
pub fn economy_policy_requires_payment(policy_json: String) -> Promise {
    future_to_promise(async move {
        if policy_json.is_empty() || policy_json == "null" {
            return Ok(JsValue::from_str(
                &serde_json::json!({ "requires_payment": false }).to_string(),
            ));
        }

        let policy: serde_json::Value = serde_json::from_str(&policy_json).map_err(|e| {
            JsValue::from_str(&format!("[SCP-VALID-7050] invalid policy JSON: {e}"))
        })?;

        // Check if any per-action cost is non-zero
        let has_cost = policy.get("cost_schedule").is_some_and(|cs| {
            let has_simple = [
                "per_message",
                "per_tool_invoke",
                "per_join",
                "per_byte_stored",
            ]
            .iter()
            .any(|key| cs.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0) > 0);

            // per_period is a SubscriptionCost object with an `amount` field
            let has_subscription = cs.get("per_period").is_some_and(|pp| {
                !pp.is_null()
                    && pp
                        .get("amount")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                        > 0
            });

            has_simple || has_subscription
        });

        let has_formula = policy.get("pricing_formula").is_some_and(|f| !f.is_null());

        let result = serde_json::json!({ "requires_payment": has_cost || has_formula });
        Ok(JsValue::from_str(&result.to_string()))
    })
}

// ---------------------------------------------------------------------------
// economy_check_policy_lock
// ---------------------------------------------------------------------------

/// Returns whether the economic policy is locked (immutable).
///
/// Returns a JSON string `{ "locked": bool }`.
#[wasm_bindgen]
pub fn economy_check_policy_lock(policy_json: String) -> Promise {
    future_to_promise(async move {
        if policy_json.is_empty() || policy_json == "null" {
            return Ok(JsValue::from_str(
                &serde_json::json!({ "locked": false }).to_string(),
            ));
        }

        let policy: serde_json::Value = serde_json::from_str(&policy_json).map_err(|e| {
            JsValue::from_str(&format!("[SCP-VALID-7050] invalid policy JSON: {e}"))
        })?;

        let locked = policy
            .get("locked")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let result = serde_json::json!({ "locked": locked });
        Ok(JsValue::from_str(&result.to_string()))
    })
}
