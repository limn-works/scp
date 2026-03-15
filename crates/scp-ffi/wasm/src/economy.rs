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
    _metrics_json: String,
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

        // Look up schedule cost
        let schedule_cost = policy
            .get("cost_schedule")
            .and_then(|cs| cs.get(action_key))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        // Evaluate formula if present (simplified — base_cost only for WASM)
        let formula_cost = policy
            .get("pricing_formula")
            .and_then(|f| {
                if f.is_null() {
                    None
                } else {
                    f.get("base_cost").and_then(serde_json::Value::as_u64)
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
            [
                "per_message",
                "per_tool_invoke",
                "per_join",
                "per_byte_stored",
            ]
            .iter()
            .any(|key| cs.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0) > 0)
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
