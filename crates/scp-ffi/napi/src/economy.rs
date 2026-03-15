//! napi-rs bridge for SCP economic governance operations.
//!
//! Exposes economic operations to Node.js/Bun:
//!
//! - [`economy_estimate_cost`] — Estimate cost for an action.
//! - [`economy_policy_requires_payment`] — Check if a policy requires payment.
//! - [`economy_auto_accept_blocked`] — Check if auto-accept is blocked.
//! - [`economy_check_policy_lock`] — Check if policy is locked.
//! - [`economy_validate_policy_change`] — Validate a proposed policy change.
//! - [`economy_evaluate_formula`] — Evaluate a pricing formula.
//! - [`economy_adjust_relay_price`] — Compute EIP-1559-style relay price.
//! - [`economy_budget_remaining`] — Query remaining budget.
//! - [`economy_budget_grant`] — Grant spending budget.
//! - [`economy_budget_record_spend`] — Record a spend.
//! - [`economy_antispam_record`] — Record a message for velocity tracking.
//! - [`economy_antispam_velocity`] — Query sender velocity.
//! - [`economy_antispam_escalated_cost`] — Compute escalated cost.
//!
//! See spec section 19 (Economic Governance) and ADR-033.

use napi_derive::napi;

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Relay price adjustment result.
#[napi(object)]
pub struct NapiRelayPriceAdjustment {
    /// New base price (smallest currency unit).
    pub new_base_price: i64,
    /// Previous base price.
    pub previous_base_price: i64,
    /// Price direction: "Increased", "Decreased", or "Unchanged".
    pub direction: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validation_error(msg: &str) -> napi::Error {
    napi::Error::from(ScpNapiError::Validation {
        message: msg.to_owned(),
        code: "SCP-VALID-7050".to_owned(),
    })
}

fn parse_action_type(s: &str) -> Result<scp_core::economy::PaidActionType, napi::Error> {
    match s {
        "MessageSend" | "message_send" => Ok(scp_core::economy::PaidActionType::MessageSend),
        "ToolInvoke" | "tool_invoke" => Ok(scp_core::economy::PaidActionType::ToolInvoke),
        "ContextJoin" | "context_join" => Ok(scp_core::economy::PaidActionType::ContextJoin),
        "SubscriptionPeriod" | "subscription_period" => {
            Ok(scp_core::economy::PaidActionType::SubscriptionPeriod)
        }
        "ByteStored" | "byte_stored" => Ok(scp_core::economy::PaidActionType::ByteStored),
        _ => Err(validation_error(&format!(
            "invalid action type: {s:?} — expected one of: MessageSend, ToolInvoke, \
             ContextJoin, SubscriptionPeriod, ByteStored"
        ))),
    }
}

fn parse_metrics(json: &str) -> Result<scp_core::economy::ObservableMetrics, napi::Error> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| validation_error(&format!("invalid metrics JSON: {e}")))?;
    Ok(scp_core::economy::ObservableMetrics {
        context_message_rate: v
            .get("context_message_rate")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        member_count: v
            .get("member_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        relay_queue_depth: v
            .get("relay_queue_depth")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        time_of_day: v
            .get("time_of_day")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        sender_velocity: v
            .get("sender_velocity")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        storage_usage: v
            .get("storage_usage")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Estimates the cost for a given action in a context.
///
/// Returns the cost (smallest currency unit), or -1 on arithmetic overflow.
#[napi]
pub fn economy_estimate_cost(
    policy_json: String,
    action_type: String,
    metrics_json: String,
) -> napi::Result<i64> {
    let action = parse_action_type(&action_type)?;
    let metrics = parse_metrics(&metrics_json)?;

    let policy = if policy_json.is_empty() || policy_json == "null" {
        None
    } else {
        let p: scp_core::economy::EconomicPolicy = serde_json::from_str(&policy_json)
            .map_err(|e| validation_error(&format!("invalid economic policy JSON: {e}")))?;
        Some(p)
    };

    #[allow(clippy::cast_possible_wrap)]
    Ok(
        scp_core::economy::estimate_cost(policy.as_ref(), &action, &metrics)
            .map_or(-1, |a| a.value() as i64),
    )
}

/// Returns `true` if the policy requires payment for any action.
#[napi]
pub fn economy_policy_requires_payment(policy_json: String) -> napi::Result<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy = serde_json::from_str(&policy_json)
        .map_err(|e| validation_error(&format!("invalid economic policy JSON: {e}")))?;
    Ok(scp_core::economy::policy_requires_payment(&policy))
}

/// Returns `true` if auto-accept is blocked by the economic policy.
#[napi]
pub fn economy_auto_accept_blocked(policy_json: String) -> napi::Result<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy = serde_json::from_str(&policy_json)
        .map_err(|e| validation_error(&format!("invalid economic policy JSON: {e}")))?;
    Ok(scp_core::economy::auto_accept_blocked_by_economics(Some(
        &policy,
    )))
}

/// Returns `true` if the economic policy is locked (immutable).
#[napi]
pub fn economy_check_policy_lock(policy_json: String) -> napi::Result<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy = serde_json::from_str(&policy_json)
        .map_err(|e| validation_error(&format!("invalid economic policy JSON: {e}")))?;
    Ok(scp_core::economy::check_policy_lock(&policy).is_err())
}

/// Validates a proposed economic policy change.
#[napi]
pub fn economy_validate_policy_change(
    current_policy_json: String,
    proposed_policy_json: String,
) -> napi::Result<bool> {
    let current: scp_core::economy::EconomicPolicy = serde_json::from_str(&current_policy_json)
        .map_err(|e| validation_error(&format!("invalid current policy JSON: {e}")))?;
    let proposed: scp_core::economy::EconomicPolicy =
        serde_json::from_str(&proposed_policy_json)
            .map_err(|e| validation_error(&format!("invalid proposed policy JSON: {e}")))?;
    scp_core::economy::validate_policy_change(&current, &proposed)
        .map_err(|e| validation_error(&format!("policy change rejected: {e}")))?;
    Ok(true)
}

/// Evaluates a pricing formula against observable metrics.
///
/// Returns the cost, or -1 on arithmetic overflow.
#[napi]
pub fn economy_evaluate_formula(formula_json: String, metrics_json: String) -> napi::Result<i64> {
    let formula: scp_core::economy::PricingFormula = serde_json::from_str(&formula_json)
        .map_err(|e| validation_error(&format!("invalid formula JSON: {e}")))?;
    let metrics = parse_metrics(&metrics_json)?;
    #[allow(clippy::cast_possible_wrap)]
    Ok(scp_core::economy::evaluate_formula(&formula, &metrics).map_or(-1, |a| a.value() as i64))
}

/// Computes an EIP-1559-style relay price adjustment.
#[napi]
pub fn economy_adjust_relay_price(
    config_json: String,
    actual_utilization_pct: i64,
) -> napi::Result<NapiRelayPriceAdjustment> {
    let config: scp_core::economy::RelayPricingConfig = serde_json::from_str(&config_json)
        .map_err(|e| validation_error(&format!("invalid relay pricing config JSON: {e}")))?;

    #[allow(clippy::cast_sign_loss)]
    let result = scp_core::economy::adjust_relay_price(&config, actual_utilization_pct as u64);

    #[allow(clippy::cast_possible_wrap)]
    Ok(NapiRelayPriceAdjustment {
        new_base_price: result.new_base_price.value() as i64,
        previous_base_price: result.previous_base_price.value() as i64,
        direction: match result.direction {
            scp_core::economy::PriceDirection::Increased => "Increased".to_owned(),
            scp_core::economy::PriceDirection::Decreased => "Decreased".to_owned(),
            scp_core::economy::PriceDirection::Unchanged => "Unchanged".to_owned(),
        },
    })
}

/// Queries the remaining budget for a member in a context.
#[napi]
pub fn economy_budget_remaining(context_id: String, did: String) -> napi::Result<i64> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if did.is_empty() {
        return Err(validation_error("DID must not be empty"));
    }
    let member_did = scp_identity::DID::from(did.as_str());
    let remaining =
        crate::runtime::with_economy_budget(&context_id, |tracker| tracker.remaining(&member_did));
    #[allow(clippy::cast_possible_wrap)]
    Ok(remaining.value() as i64)
}

/// Grants spending budget to a member in a context.
#[napi]
pub fn economy_budget_grant(context_id: String, did: String, amount: i64) -> napi::Result<()> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if did.is_empty() {
        return Err(validation_error("DID must not be empty"));
    }
    let member_did = scp_identity::DID::from(did.as_str());
    #[allow(clippy::cast_sign_loss)]
    crate::runtime::with_economy_budget_mut(&context_id, |tracker| {
        tracker.grant(&member_did, scp_core::economy::Amount::new(amount as u64));
    });
    Ok(())
}

/// Records a spend against a member's budget in a context.
#[napi]
pub fn economy_budget_record_spend(
    context_id: String,
    did: String,
    amount: i64,
) -> napi::Result<()> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if did.is_empty() {
        return Err(validation_error("DID must not be empty"));
    }
    let member_did = scp_identity::DID::from(did.as_str());
    #[allow(clippy::cast_sign_loss)]
    crate::runtime::with_economy_budget_mut(&context_id, |tracker| {
        tracker
            .record_spend(&member_did, scp_core::economy::Amount::new(amount as u64))
            .map_err(|e| validation_error(&format!("{e}")))
    })
}

/// Records a message from a sender for antispam velocity tracking.
#[napi]
pub fn economy_antispam_record(
    context_id: String,
    sender_did: String,
    timestamp: i64,
) -> napi::Result<()> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if sender_did.is_empty() {
        return Err(validation_error("sender DID must not be empty"));
    }
    let did = scp_identity::DID::from(sender_did.as_str());
    #[allow(clippy::cast_sign_loss)]
    crate::runtime::with_economy_antispam(&context_id, |tracker| {
        tracker.record_message(&did, timestamp as u64);
    });
    Ok(())
}

/// Queries the sender's message velocity within the sliding window.
#[napi]
pub fn economy_antispam_velocity(
    context_id: String,
    sender_did: String,
    now: i64,
) -> napi::Result<i64> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if sender_did.is_empty() {
        return Err(validation_error("sender DID must not be empty"));
    }
    let did = scp_identity::DID::from(sender_did.as_str());
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    let velocity = crate::runtime::with_economy_antispam(&context_id, |tracker| {
        tracker.get_velocity(&did, now as u64)
    });
    #[allow(clippy::cast_possible_wrap)]
    Ok(velocity as i64)
}

/// Computes the escalated cost for a sender based on antispam velocity.
#[napi]
pub fn economy_antispam_escalated_cost(
    context_id: String,
    sender_did: String,
    now: i64,
    base_cost: i64,
    thresholds_json: String,
    floor: Option<i64>,
    cap: Option<i64>,
) -> napi::Result<i64> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if sender_did.is_empty() {
        return Err(validation_error("sender DID must not be empty"));
    }
    let thresholds: Vec<(u64, u64)> = serde_json::from_str(&thresholds_json)
        .map_err(|e| validation_error(&format!("invalid thresholds JSON: {e}")))?;

    let config = scp_core::economy::EscalationConfig {
        thresholds: thresholds
            .into_iter()
            .map(|(vel, cost)| scp_core::economy::EscalationThreshold {
                velocity_threshold: vel,
                additional_cost: scp_core::economy::Amount::new(cost),
            })
            .collect(),
    };

    let did = scp_identity::DID::from(sender_did.as_str());
    #[allow(clippy::cast_sign_loss)]
    let cost = crate::runtime::with_economy_antispam(&context_id, |tracker| {
        tracker.compute_escalated_cost(
            &did,
            now as u64,
            scp_core::economy::Amount::new(base_cost as u64),
            &config,
            floor.map(|f| scp_core::economy::Amount::new(f as u64)),
            cap.map(|c| scp_core::economy::Amount::new(c as u64)),
        )
    });
    #[allow(clippy::cast_possible_wrap)]
    Ok(cost.value() as i64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn estimate_cost_no_policy_returns_zero() {
        let result =
            economy_estimate_cost(String::new(), "MessageSend".to_owned(), "{}".to_owned());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn estimate_cost_invalid_action() {
        let result = economy_estimate_cost("null".to_owned(), "bad".to_owned(), "{}".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn policy_requires_payment_empty() {
        assert!(!economy_policy_requires_payment(String::new()).unwrap());
    }

    #[test]
    fn check_policy_lock_empty() {
        assert!(!economy_check_policy_lock(String::new()).unwrap());
    }

    #[test]
    fn budget_remaining_empty_context_returns_zero() {
        let result = economy_budget_remaining("test-ctx".to_owned(), "did:key:test".to_owned());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn budget_grant_and_spend() {
        economy_budget_grant("napi-econ-ctx".to_owned(), "did:key:alice".to_owned(), 1000).unwrap();
        let r = economy_budget_remaining("napi-econ-ctx".to_owned(), "did:key:alice".to_owned())
            .unwrap();
        assert_eq!(r, 1000);

        economy_budget_record_spend("napi-econ-ctx".to_owned(), "did:key:alice".to_owned(), 400)
            .unwrap();
        let r = economy_budget_remaining("napi-econ-ctx".to_owned(), "did:key:alice".to_owned())
            .unwrap();
        assert_eq!(r, 600);
    }

    #[test]
    fn antispam_velocity_starts_at_zero() {
        let v =
            economy_antispam_velocity("napi-spam-ctx".to_owned(), "did:key:bob".to_owned(), 1000);
        assert_eq!(v.unwrap(), 0);
    }

    #[test]
    fn budget_validates_empty_inputs() {
        assert!(economy_budget_remaining(String::new(), "did:key:x".to_owned()).is_err());
        assert!(economy_budget_remaining("ctx".to_owned(), String::new()).is_err());
    }
}
