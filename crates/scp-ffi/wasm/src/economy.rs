//! `wasm-bindgen` bridge for SCP economic governance operations.
//!
//! Exposes economic governance operations to JavaScript (browser target).
//! Since this bridge does NOT depend on `scp-core` (tokio multi-thread
//! incompatible with `wasm32-unknown-unknown`), pure functions that need
//! scp-core types parse JSON and evaluate locally.
//!
//! See spec section 19 (Economic Governance) and ADR-033.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// Internal helpers — pricing formula evaluation (algorithm-identical to
// scp-core policy::evaluate_formula)
// ---------------------------------------------------------------------------

/// Fixed-point scale for Coefficient (6 decimal places).
const COEFFICIENT_SCALE: i64 = 1_000_000;

/// Resolves a `PricingMetric` enum name to the corresponding metric value
/// from the metrics JSON object. Returns 0 for unknown/missing metrics.
fn resolve_metric(metric_name: &str, metrics: &serde_json::Value) -> u64 {
    match metric_name {
        "ContextMessageRate" => metrics
            .get("context_message_rate")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        "MemberCount" => metrics
            .get("member_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        "RelayQueueDepth" => metrics
            .get("relay_queue_depth")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        "TimeOfDay" => metrics
            .get("time_of_day")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        "SenderVelocity" => metrics
            .get("sender_velocity")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        "StorageUsage" => metrics
            .get("storage_usage")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        _ => 0,
    }
}

/// Evaluates a pricing formula JSON value against observable metrics.
///
/// Mirrors `scp_core::economy::policy::evaluate_formula` exactly:
/// - Starts with `base_cost`
/// - Iterates `variables` (Linear / Step)
/// - Applies `floor` and `cap`
///
/// Returns 0 on overflow (saturating).
fn evaluate_pricing_formula(formula: &serde_json::Value, metrics: &serde_json::Value) -> u64 {
    let base_cost = formula
        .get("base_cost")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let mut cost = base_cost;

    if let Some(variables) = formula
        .get("variables")
        .and_then(serde_json::Value::as_array)
    {
        for var in variables {
            if let Some(linear) = var.get("Linear") {
                // Linear: cost += (coefficient * metric_value) / COEFFICIENT_SCALE
                let metric_name = linear
                    .get("metric")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let coefficient = linear
                    .get("coefficient")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);
                let metric_value = resolve_metric(metric_name, metrics);

                // Checked multiply to detect overflow, matching scp-core
                if i64::try_from(metric_value).is_ok()
                    && let Some(product) = coefficient.checked_mul(metric_value.cast_signed())
                {
                    let delta = product / COEFFICIENT_SCALE;
                    if delta >= 0 {
                        cost = cost.saturating_add(delta.cast_unsigned());
                    } else {
                        cost = cost.saturating_sub(delta.unsigned_abs());
                    }
                }
                // On overflow, skip this variable (scp-core returns None
                // for the whole formula, but WASM saturates per-variable)
            } else if let Some(step) = var.get("Step") {
                // Step: cost += amount for each threshold the metric exceeds
                let metric_name = step
                    .get("metric")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let metric_value = resolve_metric(metric_name, metrics);

                if let Some(thresholds) =
                    step.get("thresholds").and_then(serde_json::Value::as_array)
                {
                    for threshold_pair in thresholds {
                        // Thresholds serialize as [u64, u64] tuples
                        if let Some(arr) = threshold_pair.as_array() {
                            let threshold =
                                arr.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
                            let additional =
                                arr.get(1).and_then(serde_json::Value::as_u64).unwrap_or(0);
                            if metric_value >= threshold {
                                cost = cost.saturating_add(additional);
                            }
                        }
                    }
                }
            }
        }
    }

    // Apply floor
    if let Some(floor) = formula.get("floor").and_then(serde_json::Value::as_u64)
        && cost < floor
    {
        cost = floor;
    }

    // Apply cap
    if let Some(cap) = formula.get("cap").and_then(serde_json::Value::as_u64)
        && cost > cap
    {
        cost = cap;
    }

    cost
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

        // Evaluate formula if present, including variable components against
        // metrics. Algorithm-identical to scp-core evaluate_formula.
        let formula_cost = policy
            .get("pricing_formula")
            .and_then(|f| {
                if f.is_null() {
                    None
                } else {
                    Some(evaluate_pricing_formula(f, &metrics))
                }
            })
            .unwrap_or(0);

        let total = schedule_cost.saturating_add(formula_cost);

        let result = serde_json::json!({ "cost": total });
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

// ---------------------------------------------------------------------------
// economy_adjust_relay_price
// ---------------------------------------------------------------------------

/// Computes an EIP-1559-style relay price adjustment.
///
/// Returns a JSON string with `new_base_price`, `previous_base_price`, and
/// `direction`.
#[wasm_bindgen]
pub fn economy_adjust_relay_price(config_json: String, actual_utilization_pct: u32) -> Promise {
    future_to_promise(async move {
        let config: serde_json::Value = serde_json::from_str(&config_json).map_err(|e| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7050] invalid relay pricing config JSON: {e}"
            ))
        })?;

        let target = config
            .get("target_utilization_pct")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(50);
        let current = config
            .get("current_base_price")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let max_change_per_mille = config
            .get("max_change_per_mille")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(125);
        let floor = config
            .get("floor")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let cap = config
            .get("cap")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(u64::MAX);

        let actual = u64::from(actual_utilization_pct);
        let max_change = current.saturating_mul(max_change_per_mille) / 1000;

        let (above_target, delta_pct) = if actual >= target {
            (true, actual.saturating_sub(target))
        } else {
            (false, target.saturating_sub(actual))
        };

        let change = if delta_pct >= 100 {
            max_change
        } else {
            max_change.saturating_mul(delta_pct) / 100
        };

        let new_price = if above_target {
            current.saturating_add(change)
        } else {
            current.saturating_sub(change)
        };

        let clamped = new_price.max(floor).min(cap);

        let direction = match clamped.cmp(&current) {
            std::cmp::Ordering::Greater => "Increased",
            std::cmp::Ordering::Less => "Decreased",
            std::cmp::Ordering::Equal => "Unchanged",
        };

        let result = serde_json::json!({
            "new_base_price": clamped,
            "previous_base_price": current,
            "direction": direction,
        });

        Ok(JsValue::from_str(&result.to_string()))
    })
}
