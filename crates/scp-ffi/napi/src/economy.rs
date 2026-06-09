//! napi-rs bridge for SCP economic governance operations.
//!
//! Per-bridge-instance (`_on`) implementations consumed by the corresponding
//! methods on [`crate::scp::Scp`]. Phase D (#1695) deleted the
//! free-function wrappers that routed through the process-global default
//! bridge instance.
//!
//! See spec section 19 (Economic Governance) and ADR-033.

use scp_ffi_common::error_codes as codes;

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validation_error(msg: &str) -> napi::Error {
    napi::Error::from(ScpNapiError::Validation {
        message: msg.to_owned(),
        code: codes::VALID_7050.to_owned(),
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
// Per-bridge-instance implementations
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `economy_estimate_cost`.
///
/// Pure computation — the bridge instance is unused but accepted for API
/// symmetry with the other `_on` helpers in this module.
pub(crate) fn economy_estimate_cost_on(
    _bi: &NapiBridgeInstance,
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

/// Per-bridge-instance implementation of `economy_policy_requires_payment`.
pub(crate) fn economy_policy_requires_payment_on(
    _bi: &NapiBridgeInstance,
    policy_json: String,
) -> napi::Result<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy = serde_json::from_str(&policy_json)
        .map_err(|e| validation_error(&format!("invalid economic policy JSON: {e}")))?;
    Ok(scp_core::economy::policy_requires_payment(&policy))
}

/// Per-bridge-instance implementation of `economy_auto_accept_blocked`.
pub(crate) fn economy_auto_accept_blocked_on(
    _bi: &NapiBridgeInstance,
    policy_json: String,
) -> napi::Result<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy = serde_json::from_str(&policy_json)
        .map_err(|e| validation_error(&format!("invalid economic policy JSON: {e}")))?;
    Ok(scp_core::economy::auto_accept_blocked_by_economics(Some(
        &policy,
    )))
}

/// Per-bridge-instance implementation of `economy_check_policy_lock`.
pub(crate) fn economy_check_policy_lock_on(
    _bi: &NapiBridgeInstance,
    policy_json: String,
) -> napi::Result<bool> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy = serde_json::from_str(&policy_json)
        .map_err(|e| validation_error(&format!("invalid economic policy JSON: {e}")))?;
    Ok(scp_core::economy::check_policy_lock(&policy).is_err())
}

/// Per-bridge-instance implementation of `economy_validate_policy_change`.
pub(crate) fn economy_validate_policy_change_on(
    _bi: &NapiBridgeInstance,
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

/// Per-bridge-instance implementation of `economy_evaluate_formula`.
pub(crate) fn economy_evaluate_formula_on(
    _bi: &NapiBridgeInstance,
    formula_json: String,
    metrics_json: String,
) -> napi::Result<i64> {
    let formula: scp_core::economy::PricingFormula = serde_json::from_str(&formula_json)
        .map_err(|e| validation_error(&format!("invalid formula JSON: {e}")))?;
    let metrics = parse_metrics(&metrics_json)?;
    #[allow(clippy::cast_possible_wrap)]
    Ok(scp_core::economy::evaluate_formula(&formula, &metrics).map_or(-1, |a| a.value() as i64))
}

/// Per-bridge-instance implementation of `economy_budget_remaining`.
pub(crate) fn economy_budget_remaining_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    did: String,
) -> napi::Result<i64> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if did.is_empty() {
        return Err(validation_error("DID must not be empty"));
    }
    let member_did = scp_identity::DID::from(did.as_str());
    let remaining = bi
        .core
        .with_economy_budget(&context_id, |tracker| tracker.remaining(&member_did));
    #[allow(clippy::cast_possible_wrap)]
    Ok(remaining.value() as i64)
}

/// Per-bridge-instance implementation of `economy_budget_grant`.
pub(crate) fn economy_budget_grant_on(
    bi: &NapiBridgeInstance,
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
    if amount < 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("amount must be non-negative, got {amount}"),
            code: codes::VALID_7001.to_owned(),
        }));
    }
    let member_did = scp_identity::DID::from(did.as_str());
    bi.core.with_economy_budget_mut(&context_id, |tracker| {
        tracker.grant(
            &member_did,
            scp_core::economy::Amount::new(amount.cast_unsigned()),
        );
    });
    Ok(())
}

/// Per-bridge-instance implementation of `economy_budget_record_spend`.
pub(crate) fn economy_budget_record_spend_on(
    bi: &NapiBridgeInstance,
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
    if amount < 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("amount must be non-negative, got {amount}"),
            code: codes::VALID_7001.to_owned(),
        }));
    }
    let member_did = scp_identity::DID::from(did.as_str());
    bi.core.with_economy_budget_mut(&context_id, |tracker| {
        tracker
            .record_spend(
                &member_did,
                scp_core::economy::Amount::new(amount.cast_unsigned()),
            )
            .map_err(|e| validation_error(&format!("{e}")))
    })
}

/// Per-bridge-instance implementation of `economy_antispam_record`.
pub(crate) fn economy_antispam_record_on(
    bi: &NapiBridgeInstance,
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
    if timestamp < 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("timestamp must be non-negative, got {timestamp}"),
            code: codes::VALID_7001.to_owned(),
        }));
    }
    let did = scp_identity::DID::from(sender_did.as_str());
    bi.core.with_economy_antispam(&context_id, |tracker| {
        tracker.record_message(&did, timestamp.cast_unsigned());
    });
    Ok(())
}

/// Per-bridge-instance implementation of `economy_antispam_velocity`.
pub(crate) fn economy_antispam_velocity_on(
    bi: &NapiBridgeInstance,
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
    if now < 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("now must be non-negative, got {now}"),
            code: codes::VALID_7001.to_owned(),
        }));
    }
    let did = scp_identity::DID::from(sender_did.as_str());
    #[allow(clippy::cast_possible_wrap)]
    let velocity = bi.core.with_economy_antispam(&context_id, |tracker| {
        tracker.get_velocity(&did, now.cast_unsigned())
    });
    #[allow(clippy::cast_possible_wrap)]
    Ok(velocity as i64)
}

/// Per-bridge-instance implementation of `economy_antispam_escalated_cost`.
#[allow(clippy::too_many_arguments)] // napi-rs signature matches the free-function wrapper.
pub(crate) fn economy_antispam_escalated_cost_on(
    bi: &NapiBridgeInstance,
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

    if now < 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("now must be non-negative, got {now}"),
            code: codes::VALID_7001.to_owned(),
        }));
    }
    if base_cost < 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("base_cost must be non-negative, got {base_cost}"),
            code: codes::VALID_7001.to_owned(),
        }));
    }
    if floor.is_some_and(|f| f < 0) {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "floor must be non-negative, got {}",
                floor.unwrap_or_default()
            ),
            code: codes::VALID_7001.to_owned(),
        }));
    }
    if cap.is_some_and(|c| c < 0) {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("cap must be non-negative, got {}", cap.unwrap_or_default()),
            code: codes::VALID_7001.to_owned(),
        }));
    }

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
    let cost = bi.core.with_economy_antispam(&context_id, |tracker| {
        tracker.compute_escalated_cost(
            &did,
            now.cast_unsigned(),
            scp_core::economy::Amount::new(base_cost.cast_unsigned()),
            &config,
            floor.map(|f| scp_core::economy::Amount::new(f.cast_unsigned())),
            cap.map(|c| scp_core::economy::Amount::new(c.cast_unsigned())),
        )
    });
    #[allow(clippy::cast_possible_wrap)]
    Ok(cost.value() as i64)
}

/// Per-bridge-instance implementation of `economy_verify_payment_receipts`.
///
/// Deserializes a JSON array of [`scp_core::economy::PaymentReceipt`] and
/// dispatches an [`EconomyCommand::VerifyPaymentReceipts`] to the supervisor,
/// returning a JSON `{"all_valid": <bool>, "results": [...]}` document with one
/// entry per receipt. Mirrors the `PyO3` reference bridge exactly. Maximum
/// 10,000 receipts per call.
///
/// `all_valid` is `true` iff every entry both reached the adapter (`ok ==
/// true`) and the adapter reported the receipt valid (`result.valid == true`);
/// it is vacuously `true` for an empty batch. Each `results` entry is either
/// `{"receipt_id": <hex>, "ok": true, "valid": <bool>, "result": <structured
/// VerificationResult>}` on success or `{"ok": false, "error": "..."}` on
/// failure. `ok` means the adapter *responded* — NOT that the payment is
/// valid; callers scanning for failures must inspect `valid`/`all_valid`.
///
/// Runs synchronously on a libuv worker thread — there is no ambient tokio
/// context, so the actual dispatch is driven via the shared runtime's
/// `block_on`.
///
/// # Errors
///
/// Returns a `Validation` error if `receipts_json` is malformed, a suspended
/// `Context` error if the bridge is suspended, or a `Context` error if the
/// supervisor dispatch fails or the reply channel is dropped.
pub(crate) fn economy_verify_payment_receipts_on(
    bi: &NapiBridgeInstance,
    receipts_json: String,
) -> napi::Result<String> {
    // Validate input at the FFI boundary before touching supervisor state,
    // so a malformed payload fails fast with a `Validation` error rather than
    // a misleading supervisor-state error.
    let receipts: Vec<scp_core::economy::PaymentReceipt> = serde_json::from_str(&receipts_json)
        .map_err(|e| validation_error(&format!("invalid receipts JSON: {e}")))?;

    // Bound the per-call batch before dispatch: each receipt fans out to a
    // serial payment-adapter verification round-trip, so an unbounded batch
    // is a denial-of-service vector. See `MAX_RECEIPT_BATCH`.
    if receipts.len() > scp_core::economy::MAX_RECEIPT_BATCH {
        return Err(validation_error(&format!(
            "receipt batch too large: {} (max {})",
            receipts.len(),
            scp_core::economy::MAX_RECEIPT_BATCH
        )));
    }

    let rt = crate::runtime();
    let sup = crate::runtime::supervisor(bi)?.clone();

    rt.block_on(async move {
        use scp_core::context::actor::commands::EconomyCommand;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = EconomyCommand::VerifyPaymentReceipts {
            receipts: Box::new(receipts),
            reply: tx,
        };
        sup.dispatch_economy_command(cmd).await.map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("supervisor dispatch_economy_command failed: {e}"),
                code: codes::ECON_12091.to_owned(),
            })
        })?;
        let results = rx.await.map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("verify_payment_receipts shim reply dropped: {e}"),
                code: codes::ECON_12091.to_owned(),
            })
        })?;

        // Serialize via the single canonical helper shared by all bridges,
        // so the JSON contract (string currency, numeric amount, `ok` vs
        // `valid`/`all_valid` semantics) cannot drift across PyO3, napi, and
        // UniFFI. See `scp_runtime::economy::receipt::verification_results_to_json`.
        Ok(scp_core::economy::verification_results_to_json(results))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::runtime::NapiBridgeInstance;

    fn test_bi() -> NapiBridgeInstance {
        NapiBridgeInstance::new_napi()
    }

    #[test]
    fn estimate_cost_no_policy_returns_zero() {
        let bi = test_bi();
        let result = economy_estimate_cost_on(
            &bi,
            String::new(),
            "MessageSend".to_owned(),
            "{}".to_owned(),
        );
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn estimate_cost_invalid_action() {
        let bi = test_bi();
        let result =
            economy_estimate_cost_on(&bi, "null".to_owned(), "bad".to_owned(), "{}".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn policy_requires_payment_empty() {
        let bi = test_bi();
        assert!(!economy_policy_requires_payment_on(&bi, String::new()).unwrap());
    }

    #[test]
    fn check_policy_lock_empty() {
        let bi = test_bi();
        assert!(!economy_check_policy_lock_on(&bi, String::new()).unwrap());
    }

    #[test]
    fn budget_remaining_empty_context_returns_zero() {
        let bi = test_bi();
        let result =
            economy_budget_remaining_on(&bi, "test-ctx".to_owned(), "did:key:test".to_owned());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn budget_grant_and_spend() {
        let bi = test_bi();
        economy_budget_grant_on(
            &bi,
            "napi-econ-ctx".to_owned(),
            "did:key:alice".to_owned(),
            1000,
        )
        .unwrap();
        let r = economy_budget_remaining_on(
            &bi,
            "napi-econ-ctx".to_owned(),
            "did:key:alice".to_owned(),
        )
        .unwrap();
        assert_eq!(r, 1000);

        economy_budget_record_spend_on(
            &bi,
            "napi-econ-ctx".to_owned(),
            "did:key:alice".to_owned(),
            400,
        )
        .unwrap();
        let r = economy_budget_remaining_on(
            &bi,
            "napi-econ-ctx".to_owned(),
            "did:key:alice".to_owned(),
        )
        .unwrap();
        assert_eq!(r, 600);
    }

    #[test]
    fn antispam_velocity_starts_at_zero() {
        let bi = test_bi();
        let v = economy_antispam_velocity_on(
            &bi,
            "napi-spam-ctx".to_owned(),
            "did:key:bob".to_owned(),
            1000,
        );
        assert_eq!(v.unwrap(), 0);
    }

    #[test]
    fn budget_validates_empty_inputs() {
        let bi = test_bi();
        assert!(economy_budget_remaining_on(&bi, String::new(), "did:key:x".to_owned()).is_err());
        assert!(economy_budget_remaining_on(&bi, "ctx".to_owned(), String::new()).is_err());
    }

    #[test]
    fn budget_grant_rejects_negative_amount() {
        let bi = test_bi();
        let err = economy_budget_grant_on(&bi, "ctx".to_owned(), "did:key:alice".to_owned(), -1)
            .unwrap_err();
        assert!(
            err.reason.contains("non-negative"),
            "error should mention 'non-negative': {err:?}"
        );
    }

    #[test]
    fn verify_payment_receipts_rejects_malformed_json() {
        // The invalid-JSON path is reached before any supervisor lookup,
        // so a bare `new_napi()` instance (no supervisor) suffices.
        let bi = NapiBridgeInstance::new_napi();
        let err = economy_verify_payment_receipts_on(&bi, "not json".to_owned()).unwrap_err();
        assert!(
            err.reason.contains("invalid receipts JSON"),
            "error should mention 'invalid receipts JSON': {err:?}"
        );
    }

    #[test]
    fn verify_payment_receipts_empty_batch_returns_all_valid_true() {
        // An empty receipt batch is the clean supervisor-backed happy path —
        // it needs no payment adapter but still dispatches an `EconomyCommand`
        // to the supervisor, so a supervisor must be attached first. The new
        // output contract returns `{"all_valid":true,"results":[]}` —
        // `all_valid` is vacuously `true` for an empty batch.
        //
        // `economy_verify_payment_receipts_on` drives its own `block_on`, so
        // it is exercised from a plain `#[test]` (no ambient tokio runtime,
        // mirroring the libuv worker-thread execution context).
        let bi = NapiBridgeInstance::new_napi();
        crate::runtime::init_supervisor_for_test_on(&bi);

        let out = economy_verify_payment_receipts_on(&bi, "[]".to_owned()).unwrap();
        assert_eq!(out, r#"{"all_valid":true,"results":[]}"#);
    }

    #[test]
    fn verify_payment_receipts_rejects_oversized_batch() {
        use scp_core::economy::{
            Amount, CurrencyCode, MAX_RECEIPT_BATCH, PaidActionType, PaymentReceipt,
        };
        use scp_identity::DID;

        // Build one more than the cap of minimal-but-valid receipts. The cap
        // check runs before any supervisor lookup, so a bare `new_napi()`
        // instance (no supervisor) suffices — proving the oversized batch is
        // rejected without dispatching to the payment adapter.
        let receipts: Vec<PaymentReceipt> = (0..=MAX_RECEIPT_BATCH)
            .map(|_| PaymentReceipt {
                receipt_id: [0u8; 32],
                payer: DID("did:key:alice".to_owned()),
                payee: DID("did:key:bob".to_owned()),
                amount: Amount::new(1),
                currency: CurrencyCode(*b"USDC"),
                action_type: PaidActionType::MessageSend,
                context_id: None,
                adapter_id: "noop".to_owned(),
                adapter_proof: Vec::new(),
                timestamp: 0,
                signature: Vec::new(),
            })
            .collect();
        assert_eq!(receipts.len(), MAX_RECEIPT_BATCH + 1);
        let receipts_json = serde_json::to_string(&receipts).unwrap();

        let bi = NapiBridgeInstance::new_napi();
        let err = economy_verify_payment_receipts_on(&bi, receipts_json).unwrap_err();
        assert!(
            err.reason.contains("receipt batch too large"),
            "error should mention 'receipt batch too large': {err:?}"
        );
    }

    #[test]
    fn budget_record_spend_rejects_negative_amount() {
        let bi = test_bi();
        let err =
            economy_budget_record_spend_on(&bi, "ctx".to_owned(), "did:key:alice".to_owned(), -100)
                .unwrap_err();
        assert!(
            err.reason.contains("non-negative"),
            "error should mention 'non-negative': {err:?}"
        );
    }

    #[test]
    fn antispam_record_rejects_negative_timestamp() {
        let bi = test_bi();
        let err = economy_antispam_record_on(&bi, "ctx".to_owned(), "did:key:bob".to_owned(), -1)
            .unwrap_err();
        assert!(
            err.reason.contains("non-negative"),
            "error should mention 'non-negative': {err:?}"
        );
    }

    #[test]
    fn antispam_velocity_rejects_negative_now() {
        let bi = test_bi();
        let err = economy_antispam_velocity_on(&bi, "ctx".to_owned(), "did:key:bob".to_owned(), -1)
            .unwrap_err();
        assert!(
            err.reason.contains("non-negative"),
            "error should mention 'non-negative': {err:?}"
        );
    }
}
