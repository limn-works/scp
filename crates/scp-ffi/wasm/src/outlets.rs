//! `wasm-bindgen` bridge for tool registration, invocation, and verification.
//!
//! All operations delegate to [`WasmContextManager`](crate::manager::WasmContextManager)
//! via [`with_manager`](crate::manager::with_manager). No local state management.
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` and issue #389.

use js_sys::Promise;
use scp_ffi_common::error_codes as codes;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use scp_ffi_common::validate::{
    json_value_type_name, validate_did, validate_outlet_id, validate_outlet_name,
    validate_ucan_token,
};

use crate::context::WasmContextHandle;
use crate::error::ScpWasmError;
use crate::manager::with_manager;
use crate::runtime;

// ---------------------------------------------------------------------------
// WasmOutletVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its registered test vectors.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmOutletVerificationResult {
    outlet_id: String,
    passed: bool,
    failures_json: String,
}

#[wasm_bindgen]
impl WasmOutletVerificationResult {
    /// Returns the ID of the tool that was verified.
    #[must_use]
    #[wasm_bindgen(getter, js_name = outletId)]
    pub fn outlet_id(&self) -> String {
        self.outlet_id.clone()
    }

    /// Returns whether all test vectors passed.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn passed(&self) -> bool {
        self.passed
    }

    /// Returns the verification failures as a JSON string (empty array if all passed).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "failuresJson")]
    pub fn failures_json(&self) -> String {
        self.failures_json.clone()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers for tool registration inputs
// ---------------------------------------------------------------------------

/// Validates a required JSON Schema field from a definition object, returning
/// the extracted value or a typed `ScpWasmError`.
///
/// Returns `SCP-VALID-7035` for `"schema"` (input) or `SCP-VALID-7036` for
/// `"outputSchema"` (output) when the field is missing or not a JSON object.
fn validate_schema_field(
    def: &serde_json::Value,
    field_name: &str,
) -> Result<serde_json::Value, ScpWasmError> {
    let code = match field_name {
        "schema" => codes::VALID_7035,
        _ => codes::VALID_7036,
    };

    let schema = def
        .get(field_name)
        .cloned()
        .ok_or_else(|| ScpWasmError::Validation {
            message: format!(
                "missing '{field_name}' field in definition — a JSON Schema object is required"
            ),
            code: code.to_owned(),
        })?;

    if !schema.is_object() {
        return Err(ScpWasmError::Validation {
            message: format!(
                "invalid '{field_name}': expected a JSON object, got {}",
                json_value_type_name(&schema)
            ),
            code: code.to_owned(),
        });
    }

    runtime::validate_schema(&schema).map_err(|e| ScpWasmError::Validation {
        message: format!("invalid {field_name}: {e}"),
        code: code.to_owned(),
    })?;

    Ok(schema)
}

// ---------------------------------------------------------------------------
// Test vector validation (extracted for testability on native targets)
// ---------------------------------------------------------------------------

/// Validates and parses optional test vectors from a JSON definition.
///
/// Returns `Ok(Vec<TestVector>)` when `testVectors` is absent or is a valid
/// array with every entry containing `input`, `expectedOutput`, and
/// `description` fields. Returns `Err(ScpWasmError::Validation)` with code
/// `SCP-VALID-7037` on any structural violation.
fn validate_test_vectors(
    def: &serde_json::Value,
) -> Result<Vec<runtime::OutletTestVector>, ScpWasmError> {
    let Some(tv_val) = def.get("testVectors") else {
        return Ok(Vec::new());
    };

    let arr = tv_val.as_array().ok_or_else(|| ScpWasmError::Validation {
        message: "testVectors must be an array".to_owned(),
        code: codes::VALID_7037.to_owned(),
    })?;

    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            let input = v.get("input").ok_or_else(|| ScpWasmError::Validation {
                message: format!("testVectors[{i}] missing required 'input' field"),
                code: codes::VALID_7037.to_owned(),
            })?;
            let expected_output =
                v.get("expectedOutput")
                    .ok_or_else(|| ScpWasmError::Validation {
                        message: format!(
                            "testVectors[{i}] missing required 'expectedOutput' field"
                        ),
                        code: codes::VALID_7037.to_owned(),
                    })?;
            let description = match v.get("description") {
                Some(d) => d
                    .as_str()
                    .ok_or_else(|| ScpWasmError::Validation {
                        message: format!(
                            "testVectors[{i}] invalid 'description': expected a string, got {}",
                            json_value_type_name(d)
                        ),
                        code: codes::VALID_7037.to_owned(),
                    })?
                    .to_owned(),
                None => {
                    return Err(ScpWasmError::Validation {
                        message: format!("testVectors[{i}] missing required 'description' field"),
                        code: codes::VALID_7037.to_owned(),
                    });
                }
            };
            Ok(runtime::OutletTestVector {
                input: input.clone(),
                expected_output: expected_output.clone(),
                description,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Provenance field parsing
// ---------------------------------------------------------------------------

/// Parsed provenance fields: `(implementation_hash, signature, cost, registered_at)`.
type ProvenanceFields = ([u8; 32], Vec<u8>, Option<runtime::OutletCost>, u64);

/// Parses optional provenance and cost fields from the definition JSON.
///
/// When a field is absent, a safe default is used. When a field is present but
/// malformed, returns `SCP-VALID-7038`.
fn parse_provenance_fields(def: &serde_json::Value) -> Result<ProvenanceFields, JsValue> {
    let implementation_hash = match def.get("implementationHash").and_then(|v| v.as_str()) {
        None => [0u8; 32],
        Some(hex_str) => {
            let bytes = hex::decode(hex_str).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid 'implementationHash': invalid hex: {e}"),
                    code: codes::VALID_7038.to_owned(),
                }
                .into_js()
            })?;
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                ScpWasmError::Validation {
                    message: format!(
                        "invalid 'implementationHash': must be exactly 32 bytes, got {}",
                        bytes.len()
                    ),
                    code: codes::VALID_7038.to_owned(),
                }
                .into_js()
            })?
        }
    };

    let signature = match def.get("signature").and_then(|v| v.as_str()) {
        None => Vec::new(),
        Some(b64) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("invalid 'signature': invalid base64: {e}"),
                        code: codes::VALID_7038.to_owned(),
                    }
                    .into_js()
                })?
        }
    };

    let cost = match def.get("cost") {
        None => None,
        Some(c) => {
            let amount = c
                .get("amount")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "invalid 'cost': missing or non-numeric 'amount'".to_owned(),
                        code: codes::VALID_7038.to_owned(),
                    }
                    .into_js()
                })?;
            let currency = c
                .get("currency")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "invalid 'cost': missing or non-string 'currency'".to_owned(),
                        code: codes::VALID_7038.to_owned(),
                    }
                    .into_js()
                })?
                .to_owned();
            let payee = c
                .get("payee")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: "invalid 'cost': missing or non-string 'payee'".to_owned(),
                        code: codes::VALID_7038.to_owned(),
                    }
                    .into_js()
                })?
                .to_owned();
            let cost_formula = c
                .get("costFormula")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            Some(runtime::OutletCost {
                amount,
                currency,
                payee: scp_event_log::DID::from(payee),
                cost_formula,
            })
        }
    };

    // Use the hardened time source (captured Date.now) for the registration
    // timestamp in seconds per spec §5.4.1. std::time::SystemTime is not
    // available on wasm32 — see crate::time module docs.
    let registered_at = crate::time::now_secs();

    Ok((implementation_hash, signature, cost, registered_at))
}

// ---------------------------------------------------------------------------
// Rate limit parsing — constructs protocol RateLimit from JSON (F9)
// ---------------------------------------------------------------------------

use scp_protocol::context::outlets::interface::RateLimit;

/// Parses a rate limit JSON string into the protocol `RateLimit` type.
///
/// The JSON must contain `max_calls` (u64) and `window_seconds` (u64).
/// Optional fields: `burst_allowance` (u32, default: 5 per §6.2.0.2),
/// `burst_window_seconds` (u64, default: 1 per §6.2.0.2).
///
/// The `clock` parameter initializes the rate limiter's window start time.
/// Bridge callers pass `WasmClock`; tests pass `TestClock`.
fn parse_rate_limit_json_with_clock(
    json: &str,
    clock: &dyn scp_protocol::time::Clock,
) -> Result<RateLimit, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid rate_limit_json: {e}"))?;

    let max_calls = value
        .get("max_calls")
        .and_then(serde_json::Value::as_u64)
        .ok_or("rate_limit_json missing or invalid 'max_calls' (u64)")?;

    let window_seconds = value
        .get("window_seconds")
        .and_then(serde_json::Value::as_u64)
        .ok_or("rate_limit_json missing or invalid 'window_seconds' (u64)")?;

    let burst_allowance = value
        .get("burst_allowance")
        .and_then(serde_json::Value::as_u64)
        .map_or(
            scp_protocol::context::outlets::interface::DEFAULT_BURST_ALLOWANCE,
            |v| {
                #[allow(clippy::cast_possible_truncation)]
                {
                    v as u32
                }
            },
        );

    let burst_window_seconds = value
        .get("burst_window_seconds")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(scp_protocol::context::outlets::interface::DEFAULT_BURST_WINDOW_SECS);

    Ok(RateLimit::with_burst(
        max_calls,
        std::time::Duration::from_secs(window_seconds),
        burst_allowance,
        std::time::Duration::from_secs(burst_window_seconds),
        clock,
    ))
}

/// Convenience wrapper for bridge code that uses `WasmClock`.
fn parse_rate_limit_json(json: &str) -> Result<RateLimit, String> {
    parse_rate_limit_json_with_clock(json, &crate::time::WasmClock)
}

/// Extracts the REQUIRED `kind` field from the outlet definition JSON
/// (SCP-OUT-017).
///
/// Accepts the lowercase strings `"query"` or `"action"` (matching the §5.4.2
/// wire vocabulary). Missing or `null` `kind` returns a `ValidationError`.
/// The TypeScript SDK enforces this at compile time as a non-optional field
/// on `OutletDefinition`; the bridge re-enforces it for defense in depth.
fn extract_outlet_kind(
    def: &serde_json::Value,
) -> Result<scp_protocol::context::outlets::OutletKind, ScpWasmError> {
    use scp_protocol::context::outlets::OutletKind;
    let val = def
        .get("kind")
        .filter(|v| !v.is_null())
        .ok_or_else(|| ScpWasmError::Validation {
            message: "missing required 'kind' field — must be 'query' or 'action' \
                      (§5.4.2 wire vocabulary, SCP-OUT-017)"
                .to_owned(),
            code: codes::VALID_7000.to_owned(),
        })?;
    let s = val.as_str().ok_or_else(|| ScpWasmError::Validation {
        message: format!("'kind' must be a string, got {}", json_value_type_name(val)),
        code: codes::VALID_7000.to_owned(),
    })?;
    match s {
        "query" => Ok(OutletKind::Query),
        "action" => Ok(OutletKind::Action),
        other => Err(ScpWasmError::Validation {
            message: format!(
                "'kind' must be 'query' or 'action' (§5.4.2 wire vocabulary), got {other:?}"
            ),
            code: codes::VALID_7000.to_owned(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Registers a tool in an SCP context.
///
/// Delegates to `WasmContextManager::register_outlet`.
///
/// # Returns
///
/// `Promise<string>` — resolves to the assigned tool ID.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7035` if `schema` is missing, not a JSON object,
///   or structurally invalid.
/// - Rejects with `SCP-VALID-7036` if `outputSchema` is missing, not a JSON
///   object, or structurally invalid.
#[wasm_bindgen(js_name = outletRegister)]
pub fn outlet_register(context: &WasmContextHandle, definition_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let def: serde_json::Value = serde_json::from_str(&definition_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("definition_json is not valid JSON: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        // Extract fields from the definition.
        let name = def["name"]
            .as_str()
            .ok_or_else(|| {
                ScpWasmError::Validation {
                    message: "definition_json missing required 'name' field".to_owned(),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?
            .to_owned();

        validate_outlet_name(&name).map_err(|e| ScpWasmError::from(e).into_js())?;

        let description = match def.get("description") {
            Some(v) => v
                .as_str()
                .ok_or_else(|| {
                    ScpWasmError::Validation {
                        message: format!(
                            "invalid 'description': expected a string, got {}",
                            json_value_type_name(v)
                        ),
                        code: codes::VALID_7000.to_owned(),
                    }
                    .into_js()
                })?
                .to_owned(),
            None => String::new(),
        };

        let input_schema = validate_schema_field(&def, "schema").map_err(ScpWasmError::into_js)?;
        let output_schema =
            validate_schema_field(&def, "outputSchema").map_err(ScpWasmError::into_js)?;

        let operator_did = def["operatorDid"].as_str().unwrap_or("").to_owned();

        // Parse test vectors — reject malformed input instead of silently
        // dropping entries (aligned with NAPI bridge SCP-VALID-7037).
        let test_vectors = validate_test_vectors(&def).map_err(ScpWasmError::into_js)?;

        let outlet_id = format!("tool-{}", name.replace(' ', "-").to_lowercase());

        let (implementation_hash, signature, cost, registered_at) = parse_provenance_fields(&def)?;

        // SCP-OUT-017: kind is REQUIRED in the WASM outlet definition JSON.
        // The TypeScript SDK enforces this at compile time on
        // `OutletDefinition`; the bridge re-enforces it as defense in depth.
        let kind = extract_outlet_kind(&def).map_err(ScpWasmError::into_js)?;

        let registration = runtime::OutletRegistration {
            outlet_id: outlet_id.clone(),
            kind,
            name,
            description,
            schema: runtime::OutletSchema {
                input_schema,
                output_schema,
            },
            implementation_hash,
            test_vectors,
            operator_did: scp_event_log::DID::from(operator_did),
            cost,
            registered_at,
            signature,
            message_catalog: Vec::new(),
        };

        with_manager(|mgr| mgr.register_outlet(&context_id, registration))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&outlet_id))
    })
}

/// Invokes a registered tool within an SCP context.
///
/// Delegates to `WasmContextManager::invoke_outlet`. When `ucan_token` is
/// provided, validates the token before dispatch using the WASM-local UCAN
/// validation pipeline, requiring `outlet_call:{outlet_id}` or `outlet_call:*`
/// capability. See spec §6.2, §8, ADR-016, and issue #319.
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON string of the tool's output.
#[wasm_bindgen(js_name = outletInvoke)]
pub fn outlet_invoke(
    context: &WasmContextHandle,
    outlet_id: String,
    input_json: String,
    identity_did: String,
    ucan_token: Option<String>,
    spending_ucan_jwt: Option<String>,
) -> Promise {
    // N1/C2: Fail-closed for spending UCANs on WASM — the WASM bridge cannot
    // validate spending UCANs cryptographically (no payment adapter, no budget
    // tracker, no velocity tracker). Reject if a spending UCAN is provided for
    // a paid tool invocation, matching the fail-closed gates on context_join
    // and context_send.
    // NEW-1 fix: Check stored economic policy (matches context_join/context_send
    // pattern). Reject paid tool invocations regardless of whether spending UCAN
    // is present — WASM cannot enforce payment.
    {
        let context_id_check = context.context_id();
        let has_paid_policy =
            crate::manager::with_manager(|mgr| mgr.context_has_paid_policy(&context_id_check));
        if has_paid_policy.unwrap_or(false) {
            return future_to_promise(async move {
                Err(ScpWasmError::Context {
                    message: "WASM bridge cannot enforce tool payment for paid contexts. \
                              Use a native (Python/Node/Swift/Kotlin) client for paid tools."
                        .to_owned(),
                    code: codes::ECON_12096.to_owned(),
                }
                .into_js()
                .into())
            });
        }
    }
    if spending_ucan_jwt.is_some() {
        return future_to_promise(async move {
            Err(ScpWasmError::Context {
                message: "WASM bridge cannot validate spending UCANs for tool invocations. \
                          Use a native (Python/Node/Swift/Kotlin) client for paid tools."
                    .to_owned(),
                code: codes::ECON_12096.to_owned(),
            }
            .into_js()
            .into())
        });
    }
    if let Err(e) = validate_outlet_id(&outlet_id) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Err(e) = validate_did(&identity_did) {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    if let Some(ref token) = ucan_token
        && let Err(e) = validate_ucan_token(token)
    {
        return future_to_promise(async move { Err(ScpWasmError::from(e).into_js().into()) });
    }
    let context_id = context.context_id();
    future_to_promise(async move {
        // UCAN authorization: validate the token via the WASM-local
        // 11-step pipeline. See spec §6.2, §8, ADR-016, and issue #319.
        // Look up the outlet's registered kind so the UCAN validator
        // checks the correct split capability stem (SCP-OUT-014).
        let outlet_kind_for_ucan =
            crate::manager::with_manager(|mgr| mgr.outlet_kind(&context_id, &outlet_id))
                .map_err(ScpWasmError::into_js)?;
        match ucan_token {
            Some(ref token) if !token.is_empty() => {
                crate::ucan::validate_outlet_ucan_wasm(
                    &context_id,
                    &outlet_id,
                    outlet_kind_for_ucan,
                    token,
                    &identity_did,
                )
                .map_err(|e| {
                    ScpWasmError::Permission {
                        message: format!("UCAN authorization failed for tool '{outlet_id}': {e}"),
                        code: codes::PERM_3000.to_owned(),
                    }
                    .into_js()
                })?;
            }
            _ => {
                return Err(JsValue::from(
                    ScpWasmError::Validation {
                        message: "ucan_token is required for tool invocation".to_owned(),
                        code: codes::VALID_7000.to_owned(),
                    }
                    .into_js(),
                ));
            }
        }

        let parsed_input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let result = with_manager(|mgr| {
            mgr.invoke_outlet(&context_id, &outlet_id, &parsed_input, &identity_did)
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize tool output: {e}"),
                code: codes::TOOL_6002.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Verifies a tool against its registered test vectors.
///
/// Delegates to `WasmContextManager::verify_outlet`.
///
/// # Returns
///
/// `Promise<WasmOutletVerificationResult>` — resolves to the verification result.
#[wasm_bindgen(js_name = outletVerify)]
pub fn outlet_verify(context: &WasmContextHandle, outlet_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let (passed, failures) = with_manager(|mgr| mgr.verify_outlet(&context_id, &outlet_id))
            .map_err(ScpWasmError::into_js)?;

        let failures_json = serde_json::to_string(&failures).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize verification failures: {e}"),
                code: codes::TOOL_6003.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from(WasmOutletVerificationResult {
            outlet_id,
            passed,
            failures_json,
        }))
    })
}

// ---------------------------------------------------------------------------
// Registry lookup / management (SCP-OUT-005)
// ---------------------------------------------------------------------------

/// Builds a core `OutletRegistration` from the shared JSON definition shape
/// used by `outlet_register`/`outlet_update`. Factored out so update reuses
/// the same validation pipeline as register.
fn build_outlet_registration_from_json(
    def: &serde_json::Value,
    outlet_id: String,
) -> Result<runtime::OutletRegistration, JsValue> {
    let name = def["name"]
        .as_str()
        .ok_or_else(|| {
            ScpWasmError::Validation {
                message: "definition_json missing required 'name' field".to_owned(),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?
        .to_owned();
    validate_outlet_name(&name).map_err(|e| ScpWasmError::from(e).into_js())?;

    let description = match def.get("description") {
        Some(v) => v
            .as_str()
            .ok_or_else(|| {
                ScpWasmError::Validation {
                    message: format!(
                        "invalid 'description': expected a string, got {}",
                        json_value_type_name(v)
                    ),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?
            .to_owned(),
        None => String::new(),
    };

    let input_schema = validate_schema_field(def, "schema").map_err(ScpWasmError::into_js)?;
    let output_schema =
        validate_schema_field(def, "outputSchema").map_err(ScpWasmError::into_js)?;
    let operator_did = def["operatorDid"].as_str().unwrap_or("").to_owned();
    let test_vectors = validate_test_vectors(def).map_err(ScpWasmError::into_js)?;
    let (implementation_hash, signature, cost, registered_at) = parse_provenance_fields(def)?;

    // SCP-OUT-017: kind is required on update too — the §5.4.2 cost-floor
    // check rejects updates flipping to Query while retaining a positive
    // cost.
    let kind = extract_outlet_kind(def).map_err(ScpWasmError::into_js)?;

    Ok(runtime::OutletRegistration {
        outlet_id,
        kind,
        name,
        description,
        schema: runtime::OutletSchema {
            input_schema,
            output_schema,
        },
        implementation_hash,
        test_vectors,
        operator_did: scp_event_log::DID::from(operator_did),
        cost,
        registered_at,
        signature,
        message_catalog: Vec::new(),
    })
}

/// Updates an existing outlet registration.
///
/// The caller (`updater_did`) must be the outlet's operator or the context
/// creator. Validates schemas and that the outlet ID on the new
/// registration matches the existing one.
///
/// # Returns
///
/// `Promise<string>` — resolves to the outlet ID of the updated outlet.
#[wasm_bindgen(js_name = outletUpdate)]
pub fn outlet_update(
    context: &WasmContextHandle,
    outlet_id: String,
    definition_json: String,
    updater_did: String,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        validate_outlet_id(&outlet_id).map_err(|e| ScpWasmError::from(e).into_js())?;
        validate_did(&updater_did).map_err(|e| ScpWasmError::from(e).into_js())?;

        let def: serde_json::Value = serde_json::from_str(&definition_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("definition_json is not valid JSON: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let new_registration = build_outlet_registration_from_json(&def, outlet_id.clone())?;

        with_manager(|mgr| {
            mgr.update_outlet(&context_id, &outlet_id, new_registration, &updater_did)
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&outlet_id))
    })
}

/// Deregisters (removes) an outlet from the context.
///
/// The caller must be the outlet's operator or the context creator.
///
/// # Returns
///
/// `Promise<void>` — resolves when the outlet has been removed.
#[wasm_bindgen(js_name = outletDeregister)]
pub fn outlet_deregister(
    context: &WasmContextHandle,
    outlet_id: String,
    actor_did: String,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        validate_outlet_id(&outlet_id).map_err(|e| ScpWasmError::from(e).into_js())?;
        validate_did(&actor_did).map_err(|e| ScpWasmError::from(e).into_js())?;

        with_manager(|mgr| mgr.deregister_outlet(&context_id, &outlet_id, &actor_did))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}

/// Lists all outlet IDs registered in a context.
///
/// # Returns
///
/// `Promise<string[]>` — resolves to the sorted list of outlet IDs as a JSON
/// string array serialized via `JsValue::from_serde`.
#[wasm_bindgen(js_name = outletList)]
pub fn outlet_list(context: &WasmContextHandle) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let ids =
            with_manager(|mgr| mgr.list_outlets(&context_id)).map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&ids).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize outlet list: {e}"),
                code: codes::TOOL_6002.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Retrieves an outlet registration as a JSON string.
///
/// # Returns
///
/// `Promise<string>` — resolves to the `OutletRegistration` as JSON.
/// Rejects with `SCP-TOOL-6002` if the outlet is not found.
#[wasm_bindgen(js_name = outletGet)]
pub fn outlet_get(context: &WasmContextHandle, outlet_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        validate_outlet_id(&outlet_id).map_err(|e| ScpWasmError::from(e).into_js())?;

        let registration = with_manager(|mgr| mgr.get_outlet(&context_id, &outlet_id))
            .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&registration).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize outlet registration: {e}"),
                code: codes::TOOL_6002.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// Cross-context tool invocation (spec section 6.2)
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// Validates UCAN authorization against the target context before dispatch.
///
/// # Returns
///
/// `Promise<string>` — resolves to a JSON string of the tool's output.
#[wasm_bindgen(js_name = outletInvokeCrossContext)]
pub fn outlet_invoke_cross_context(
    source_context: &WasmContextHandle,
    target_context: &WasmContextHandle,
    outlet_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
    chain_depth: u8,
) -> Promise {
    let source_id = source_context.context_id();
    let target_id = target_context.context_id();
    future_to_promise(async move {
        // UCAN authorization: validate the token against the TARGET context's
        // ceiling via the WASM-local 11-step pipeline.
        // See spec §6.2, §8, ADR-016, and issue #319.
        if ucan_token.is_empty() {
            return Err(ScpWasmError::Validation {
                message: "ucan_token is required for cross-context tool invocation".to_owned(),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
            .into());
        }
        // Look up the outlet kind in the TARGET context (the cross-context
        // delegation must carry the right split stem; SCP-OUT-014).
        let outlet_kind_for_ucan =
            crate::manager::with_manager(|mgr| mgr.outlet_kind(&target_id, &outlet_id))
                .map_err(ScpWasmError::into_js)?;
        crate::ucan::validate_outlet_ucan_wasm(
            &target_id,
            &outlet_id,
            outlet_kind_for_ucan,
            &ucan_token,
            &invoker_did,
        )
        .map_err(|e| {
            ScpWasmError::Permission {
                message: format!(
                    "UCAN authorization failed for cross-context tool '{outlet_id}': {e}"
                ),
                code: codes::PERM_3000.to_owned(),
            }
            .into_js()
        })?;

        let input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let result = with_manager(|mgr| {
            mgr.invoke_tool_cross_context(
                &source_id,
                &target_id,
                &outlet_id,
                &input,
                &invoker_did,
                chain_depth,
            )
        })
        .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize cross-context output: {e}"),
                code: codes::TOOL_6013.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Creates a stateful tool session.
///
/// # Returns
///
/// `Promise<string>` — resolves to the session ID (UUID).
#[wasm_bindgen(js_name = outletSessionOpen)]
pub fn outlet_session_open(
    context: &WasmContextHandle,
    outlet_id: String,
    source_context_id: String,
    ttl_seconds: Option<u32>,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let session_id = with_manager(|mgr| {
            mgr.session_create(
                &context_id,
                &outlet_id,
                &source_context_id,
                ttl_seconds.map(u64::from),
            )
        })
        .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::from_str(&session_id))
    })
}

/// Invokes a tool within an active session.
///
/// Each call is individually governed: the invoker must present a valid
/// UCAN token.
///
/// # Returns
///
/// `Promise<string>` — resolves to the tool output as a JSON string.
#[wasm_bindgen(js_name = outletSessionInvoke)]
pub fn outlet_session_invoke(
    context: &WasmContextHandle,
    session_id: String,
    input_json: String,
    invoker_did: String,
    ucan_token: String,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // UCAN authorization: look up the outlet_id from the session, then
        // validate the token via the WASM-local 11-step pipeline.
        // See spec §6.2, §8, ADR-016, and issue #319.
        if ucan_token.is_empty() {
            return Err(ScpWasmError::Validation {
                message: "ucan_token is required for session tool invocation".to_owned(),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
            .into());
        }

        let outlet_id_for_ucan =
            with_manager(|mgr| mgr.session_outlet_id(&context_id, &session_id))
                .map_err(ScpWasmError::into_js)?;

        let outlet_kind_for_ucan =
            with_manager(|mgr| mgr.outlet_kind(&context_id, &outlet_id_for_ucan))
                .map_err(ScpWasmError::into_js)?;
        crate::ucan::validate_outlet_ucan_wasm(
            &context_id,
            &outlet_id_for_ucan,
            outlet_kind_for_ucan,
            &ucan_token,
            &invoker_did,
        )
        .map_err(|e| {
            ScpWasmError::Permission {
                message: format!("UCAN authorization failed for tool '{outlet_id_for_ucan}': {e}"),
                code: codes::PERM_3000.to_owned(),
            }
            .into_js()
        })?;

        let input: serde_json::Value = serde_json::from_str(&input_json).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("input_json is not valid JSON: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let result =
            with_manager(|mgr| mgr.session_invoke(&context_id, &session_id, &input, &invoker_did))
                .map_err(ScpWasmError::into_js)?;

        let json_str = serde_json::to_string(&result).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize session invoke output: {e}"),
                code: codes::TOOL_6020.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Closes a stateful tool session.
///
/// # Returns
///
/// `Promise<void>` — resolves when the session is closed.
#[wasm_bindgen(js_name = outletSessionClose)]
pub fn outlet_session_close(context: &WasmContextHandle, session_id: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        with_manager(|mgr| mgr.session_close(&context_id, &session_id))
            .map_err(ScpWasmError::into_js)?;

        Ok(JsValue::UNDEFINED)
    })
}

// ---------------------------------------------------------------------------
// Bidirectional consent protocol (spec §6.2.0.1)
// ---------------------------------------------------------------------------

/// Exposes a tool interface for cross-context sharing (§6.2.0.1 step 1).
///
/// Creates a `OutletInterface` JSON with `approved_by_source = true` and
/// `approved_by_target = false`. Requires the caller to be an admin of the
/// source context (matching `scp-core::expose_tool` authorization).
///
/// The admin DID is resolved from the context's membership state (the
/// context creator), matching how PyO3/NAPI/UniFFI bridges pass
/// `rt.creator_did` to `scp-core::expose_tool`.
///
/// # Returns
///
/// `Promise<string>` — resolves to the `OutletInterface` as a JSON string.
#[wasm_bindgen(js_name = outletInterfaceOffer)]
pub fn outlet_interface_offer(
    context: &WasmContextHandle,
    outlet_id: String,
    target_context_id: String,
    rate_limit_json: Option<String>,
) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        validate_outlet_id(&outlet_id).map_err(|e| ScpWasmError::from(e).into_js())?;

        // Resolve the admin DID from the context's creator — mirrors how
        // PyO3/NAPI/UniFFI bridges use `rt.creator_did` internally.
        let admin_did = with_manager(|mgr| {
            mgr.context_creator(&context_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!("context '{context_id}' not found"),
                    code: codes::CTX_2000.to_owned(),
                })
        })
        .map_err(ScpWasmError::into_js)?;

        // Require admin role — mirrors scp-core::expose_tool authorization.
        let role = with_manager(|mgr| Ok(mgr.member_role(&context_id, &admin_did)))
            .map_err(ScpWasmError::into_js)?;
        match role.as_deref() {
            Some("admin") => {}
            _ => {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "tool interface expose requires admin role — '{admin_did}' \
                         is not an admin of context '{context_id}'"
                    ),
                    code: codes::PERM_3001.to_owned(),
                }
                .into_js()
                .into());
            }
        }

        // Validate the tool exists in the source context's registry.
        let exists = with_manager(|mgr| mgr.tool_exists(&context_id, &outlet_id))
            .map_err(ScpWasmError::into_js)?;
        if !exists {
            return Err(ScpWasmError::Tool {
                message: format!("tool '{outlet_id}' not found in context '{context_id}'"),
                code: codes::TOOL_6030.to_owned(),
            }
            .into_js()
            .into());
        }

        // Parse optional rate limit into the protocol RateLimit type.
        let rate_limit: Option<RateLimit> = match rate_limit_json {
            Some(ref json) => {
                let parsed = parse_rate_limit_json(json).map_err(|e| {
                    ScpWasmError::Validation {
                        message: e,
                        code: codes::VALID_7040.to_owned(),
                    }
                    .into_js()
                })?;
                Some(parsed)
            }
            None => None,
        };

        let interface = serde_json::json!({
            "source_context": context_id,
            "target_context": target_context_id,
            "outlet_id": outlet_id,
            "rate_limit": rate_limit,
            "per_caller_rate_limit": {
                "max_calls_per_caller": 10,
                "window": { "secs": 60, "nanos": 0 },
                "burst_allowance": 5,
                "burst_window": { "secs": 1, "nanos": 0 },
                "callers": {}
            },
            "approved_by_source": true,
            "approved_by_target": false,
            "outbound_policy": {
                "allowed_callers": [],
                "max_calls_per_minute": 60,
                "max_payload_bytes": 65536,
                "require_provenance": true
            },
            "inbound_policy": null
        });

        let json_str = serde_json::to_string(&interface).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize OutletInterface: {e}"),
                code: codes::TOOL_6031.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Accepts a cross-context tool interface (§6.2.0.1 step 4).
///
/// Requires the caller to be an admin of the target context (matching
/// `scp-core::accept_tool_interface` authorization). The admin DID is
/// resolved from the context's membership state (the context creator),
/// matching how PyO3/NAPI/UniFFI bridges pass `rt.creator_did`.
///
/// Verifies that the interface's `target_context` matches this context, then
/// sets `approved_by_target = true`. Mirrors `scp-core::accept_tool_interface`
/// context-mismatch check.
///
/// # Returns
///
/// `Promise<string>` — resolves to the updated `OutletInterface` as JSON.
#[wasm_bindgen(js_name = outletInterfaceAccept)]
pub fn outlet_interface_accept(context: &WasmContextHandle, interface_json: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        // Resolve the admin DID from the context's creator — mirrors how
        // scp-core::accept_tool_interface checks has_admin_role(role_state, admin_did).
        let admin_did = with_manager(|mgr| {
            mgr.context_creator(&context_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!("context '{context_id}' not found"),
                    code: codes::CTX_2000.to_owned(),
                })
        })
        .map_err(ScpWasmError::into_js)?;

        // Require admin role — mirrors scp-core::accept_tool_interface authorization.
        let role = with_manager(|mgr| Ok(mgr.member_role(&context_id, &admin_did)))
            .map_err(ScpWasmError::into_js)?;
        match role.as_deref() {
            Some("admin") => {}
            _ => {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "tool interface accept requires admin role — '{admin_did}' \
                         is not an admin of context '{context_id}'"
                    ),
                    code: codes::PERM_3001.to_owned(),
                }
                .into_js()
                .into());
            }
        }

        let mut interface: serde_json::Value =
            serde_json::from_str(&interface_json).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid interface_json: {e}"),
                    code: codes::VALID_7041.to_owned(),
                }
                .into_js()
            })?;

        // Verify the interface targets this context — mirrors
        // scp-core::accept_tool_interface context-mismatch check.
        let target = interface
            .get("target_context")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if target != context_id {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "interface target_context '{target}' does not match \
                     accepting context '{context_id}'"
                ),
                code: codes::TOOL_6032.to_owned(),
            }
            .into_js()
            .into());
        }

        // Set approved_by_target to true and add default inbound policy.
        interface["approved_by_target"] = serde_json::json!(true);
        if interface.get("inbound_policy").is_none() || interface["inbound_policy"].is_null() {
            interface["inbound_policy"] = serde_json::json!({
                "allowed_source_roles": [],
                "max_calls_per_minute": 60,
                "max_response_bytes": 65536,
                "require_spending_ucan": false
            });
        }

        let json_str = serde_json::to_string(&interface).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize OutletInterface: {e}"),
                code: codes::TOOL_6033.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

/// Revokes a cross-context tool interface (§6.2.0.1 step 5).
///
/// Either context may revoke unilaterally.
///
/// # Returns
///
/// `Promise<string>` — resolves to the `InterfaceRevoked` event as JSON.
#[wasm_bindgen(js_name = outletInterfaceRevoke)]
pub fn outlet_interface_revoke(context: &WasmContextHandle, interface_id_hex: String) -> Promise {
    let context_id = context.context_id();
    future_to_promise(async move {
        let interface_id_bytes = hex::decode(&interface_id_hex).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid interface_id_hex: not valid hex: {e}"),
                code: codes::VALID_7042.to_owned(),
            }
            .into_js()
        })?;
        if interface_id_bytes.len() != 32 {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "interface_id_hex must be exactly 32 bytes (64 hex chars), got {}",
                    interface_id_bytes.len()
                ),
                code: codes::VALID_7042.to_owned(),
            }
            .into_js()
            .into());
        }

        let now_ms = crate::time::now_ms();
        // now_ms is always non-negative (milliseconds since epoch) and well within u64 range.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let now_ms_u64 = now_ms as u64;

        let event = serde_json::json!({
            "interface_id": interface_id_bytes,
            "revoking_context": context_id,
            "revoked_at": now_ms_u64
        });

        let json_str = serde_json::to_string(&event).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("failed to serialize InterfaceRevoked: {e}"),
                code: codes::TOOL_6035.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json_str))
    })
}

// ---------------------------------------------------------------------------
// SCP-OUT-041d — outlet_error_new + outlet_catalog_rotation_validator
// ---------------------------------------------------------------------------

/// Pins a per-outlet `outlet_message_key` (§5.4.4 round-5,
/// SCP-OUT-041a/d) for use by `outletErrorNew`.
///
/// The WASM bridge mirrors the runtime's
/// `GovernanceState::pinned_outlet_message_keys` map locally because
/// scp-runtime cannot compile to wasm32. Callers (typically the SDK
/// receiver layer that derives the key from MLS exporter material at
/// registration acceptance time) MUST pin the key here so the
/// envelope-construction path can compute the §5.4.4 wire-message
/// HMAC at the FFI boundary.
#[wasm_bindgen(js_name = outletStoreMessageKey)]
pub fn outlet_store_message_key(
    context: &WasmContextHandle,
    outlet_id: String,
    registration_event_id_hex: String,
    outlet_message_key_hex: String,
) -> Result<(), JsError> {
    let context_id = context.context_id();
    validate_outlet_id(&outlet_id).map_err(|e| ScpWasmError::from(e).into_js())?;

    let reg_event_id_vec = hex::decode(&registration_event_id_hex).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid registration_event_id_hex: {e}"),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
    })?;
    let reg_event_id: [u8; 32] = reg_event_id_vec.as_slice().try_into().map_err(|_| {
        ScpWasmError::Validation {
            message: "registration_event_id must be 32 bytes".to_owned(),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
    })?;

    let key_vec = hex::decode(&outlet_message_key_hex).map_err(|e| {
        ScpWasmError::Validation {
            message: format!("invalid outlet_message_key_hex: {e}"),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
    })?;
    let outlet_message_key: [u8; 32] = key_vec.as_slice().try_into().map_err(|_| {
        ScpWasmError::Validation {
            message: "outlet_message_key must be 32 bytes".to_owned(),
            code: codes::VALID_7000.to_owned(),
        }
        .into_js()
    })?;

    with_manager(|mgr| {
        mgr.store_outlet_message_key(&context_id, &outlet_id, reg_event_id, outlet_message_key)
    })
    .map_err(ScpWasmError::into_js)
}

/// SCP-OUT-041d outlet_error_new bridge (WASM).
///
/// Constructs an `OutletError` envelope at the FFI boundary using the
/// pinned per-outlet `outlet_message_key`. Returns the envelope as a
/// JSON string. The HMAC happens inside this bridge so the SDK never
/// sees the raw key.
#[wasm_bindgen(js_name = outletErrorNew)]
#[allow(clippy::too_many_arguments)] // 11-field §5.4.4 OutletErrorNewOpts.
#[allow(clippy::too_many_lines)] // Per-field validation surface.
pub fn outlet_error_new(
    context: &WasmContextHandle,
    outlet_id: String,
    registration_event_id_hex: String,
    catalog_key: String,
    class_str: String,
    code: String,
    slug: String,
    retry_str: String,
    pad_nonce_hex: String,
    detail_json: Option<String>,
    source_chain_json: Option<String>,
) -> Promise {
    use scp_protocol::context::outlets::OutletId;
    use scp_protocol::context::outlets::errors::{
        CatalogKey, ContextHop, DetailBody, OutletError, OutletErrorClass, OutletErrorNewOpts,
        PAD_NONCE_LEN, REGISTRATION_EVENT_ID_LEN, RetryPolicy,
    };

    let context_id = context.context_id();
    future_to_promise(async move {
        validate_outlet_id(&outlet_id).map_err(|e| ScpWasmError::from(e).into_js())?;

        let reg_event_id_vec = hex::decode(&registration_event_id_hex).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid registration_event_id_hex: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        let reg_event_id: [u8; REGISTRATION_EVENT_ID_LEN] =
            reg_event_id_vec.as_slice().try_into().map_err(|_| {
                ScpWasmError::Validation {
                    message: format!(
                        "registration_event_id must be {REGISTRATION_EVENT_ID_LEN} bytes"
                    ),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?;

        let pad_nonce_vec = hex::decode(&pad_nonce_hex).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid pad_nonce_hex: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;
        let pad_nonce: [u8; PAD_NONCE_LEN] = pad_nonce_vec.as_slice().try_into().map_err(|_| {
            ScpWasmError::Validation {
                message: format!("pad_nonce must be {PAD_NONCE_LEN} bytes"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let class: OutletErrorClass =
            serde_json::from_value(serde_json::Value::String(class_str.clone())).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid OutletErrorClass {class_str:?}: {e}"),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?;

        let retry: RetryPolicy =
            serde_json::from_value(serde_json::Value::String(retry_str.clone()))
                .or_else(|_| serde_json::from_str::<RetryPolicy>(&retry_str))
                .map_err(|e| {
                    ScpWasmError::Validation {
                        message: format!("invalid retry policy {retry_str:?}: {e}"),
                        code: codes::VALID_7000.to_owned(),
                    }
                    .into_js()
                })?;

        let catalog_key_typed = CatalogKey::try_new(&catalog_key).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid catalog_key: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let detail: Option<DetailBody> = match detail_json.as_deref() {
            None => None,
            Some(s) => Some(serde_json::from_str::<DetailBody>(s).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid detail_json: {e}"),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?),
        };

        let source_chain: Vec<ContextHop> = match source_chain_json.as_deref() {
            None => Vec::new(),
            Some(s) => serde_json::from_str::<Vec<ContextHop>>(s).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid source_chain_json: {e}"),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?,
        };

        let outlet_id_typed = OutletId::from(outlet_id.as_str());

        // Snapshot from manager: pinned key + registered catalog keys.
        let (pinned_key, registered_keys): ([u8; 32], Vec<CatalogKey>) =
            with_manager(|mgr| {
                let pinned = mgr
                    .pinned_outlet_message_key_for(&context_id, &outlet_id, &reg_event_id)?
                    .ok_or_else(|| ScpWasmError::Validation {
                        message: format!(
                            "no pinned outlet_message_key for outlet {outlet_id}, registration {registration_event_id_hex}"
                        ),
                        code: codes::VALID_7000.to_owned(),
                    })?;
                let catalog_keys = mgr.outlet_catalog_keys(&context_id, &outlet_id)?;
                Ok((pinned, catalog_keys))
            })
            .map_err(ScpWasmError::into_js)?;

        let envelope = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id_typed,
            outlet_message_key: &pinned_key,
            registration_event_id: reg_event_id,
            catalog_key: &catalog_key_typed,
            registered_keys: &registered_keys,
            class,
            code: &code,
            slug: &slug,
            retry,
            detail,
            source_chain,
            pad_nonce,
        })
        .map_err(|e| {
            ScpWasmError::Validation {
                message: format!("OutletError construction failed: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let json = serde_json::to_string(&serialize_outlet_error_wire(&envelope)).map_err(|e| {
            ScpWasmError::Context {
                message: e.to_string(),
                code: codes::CTX_2000.to_owned(),
            }
            .into_js()
        })?;

        Ok(JsValue::from_str(&json))
    })
}

/// SCP-OUT-041d catalog-rotation dwell-time validator bridge (WASM).
///
/// Pure-function wrapper that mirrors the SCP-OUT-041c semantics in
/// WASM. WASM cannot depend on scp-runtime; we re-implement the
/// 24-hour dwell rule locally against `MessageTemplate` from
/// scp-protocol. Returns the empty string on success; a JSON-serialized
/// `OutletError` envelope otherwise.
#[wasm_bindgen(js_name = outletCatalogRotationValidator)]
pub fn outlet_catalog_rotation_validator(
    prior_catalog_json: String,
    new_catalog_json: String,
    prior_append_time_secs: u64,
    new_append_time_secs: u64,
) -> Promise {
    use scp_protocol::context::outlets::MessageTemplate;
    use scp_protocol::context::outlets::error_codes::{
        CODE_PROTOCOL_VIOLATION, SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
    };
    use scp_protocol::context::outlets::errors::{OutletError, OutletErrorClass, RetryPolicy};

    /// §5.4.4 round-5 24h dwell floor — re-declared here to avoid the
    /// scp-runtime dependency. Identical to
    /// `scp_runtime::context::manager::CATALOG_ROTATION_DWELL_SECS`.
    const CATALOG_ROTATION_DWELL_SECS: u64 = 86_400;

    future_to_promise(async move {
        let prior: Vec<MessageTemplate> =
            serde_json::from_str(&prior_catalog_json).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid prior_catalog_json: {e}"),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?;
        let new_cat: Vec<MessageTemplate> =
            serde_json::from_str(&new_catalog_json).map_err(|e| {
                ScpWasmError::Validation {
                    message: format!("invalid new_catalog_json: {e}"),
                    code: codes::VALID_7000.to_owned(),
                }
                .into_js()
            })?;

        if prior == new_cat {
            return Ok(JsValue::from_str(""));
        }
        let elapsed_secs = new_append_time_secs.saturating_sub(prior_append_time_secs);
        if elapsed_secs >= CATALOG_ROTATION_DWELL_SECS {
            return Ok(JsValue::from_str(""));
        }

        let envelope = OutletError::from_invocation_error_template(
            OutletErrorClass::Protocol,
            CODE_PROTOCOL_VIOLATION,
            SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
            RetryPolicy::Never,
        )
        .map_err(|e| {
            ScpWasmError::Validation {
                message: format!("envelope construction failed: {e}"),
                code: codes::VALID_7000.to_owned(),
            }
            .into_js()
        })?;

        let json = serde_json::to_string(&serialize_outlet_error_wire(&envelope)).map_err(|e| {
            ScpWasmError::Context {
                message: e.to_string(),
                code: codes::CTX_2000.to_owned(),
            }
            .into_js()
        })?;
        Ok(JsValue::from_str(&json))
    })
}

/// SCP-OUT-041d wire-form helper — see PyO3 bridge for schema docs.
fn serialize_outlet_error_wire(
    envelope: &scp_protocol::context::outlets::errors::OutletError,
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    out.insert(
        "code".to_owned(),
        serde_json::Value::String(envelope.code.clone()),
    );
    out.insert(
        "slug".to_owned(),
        serde_json::Value::String(envelope.slug.clone()),
    );
    out.insert(
        "class".to_owned(),
        serde_json::Value::String(envelope.class.as_wire().to_owned()),
    );
    out.insert(
        "message".to_owned(),
        serde_json::Value::String(hex::encode(envelope.message)),
    );
    if let Ok(retry_v) = serde_json::to_value(&envelope.retry) {
        out.insert("retry".to_owned(), retry_v);
    }
    if let Some(d) = &envelope.detail
        && let Ok(detail_v) = serde_json::to_value(d)
    {
        out.insert("detail".to_owned(), detail_v);
    }
    if let Ok(chain_v) = serde_json::to_value(&envelope.source_chain) {
        out.insert("source_chain".to_owned(), chain_v);
    }
    out.insert(
        "pad_nonce".to_owned(),
        serde_json::Value::String(hex::encode(envelope.pad_nonce)),
    );
    out.insert(
        "registration_event_id".to_owned(),
        serde_json::Value::String(hex::encode(envelope.registration_event_id)),
    );
    serde_json::Value::Object(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Tests for schema and test vector validation helpers. These test the
/// pure-Rust validation functions which return `Result<_, ScpWasmError>` —
/// no wasm-bindgen calls, safe on native targets.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    // -----------------------------------------------------------------------
    // validate_schema_field — missing field (input schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_missing_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "outputSchema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "schema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(codes::VALID_7035),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
        assert!(
            msg.contains("schema"),
            "error should mention schema, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — non-object value (input schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_non_object_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": "not an object",
            "outputSchema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "schema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(codes::VALID_7035),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
        assert!(
            msg.contains("string"),
            "error should mention the actual type, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — structurally invalid input (missing "type")
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_structurally_invalid_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"description": "no type field"},
            "outputSchema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "schema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(codes::VALID_7035),
            "error should contain SCP-VALID-7035, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — valid input schema
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_accepts_valid_input() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object", "properties": {"x": {"type": "number"}}},
            "outputSchema": {"type": "object"}
        });
        let result = validate_schema_field(&def, "schema");
        assert!(result.is_ok(), "valid schema should succeed");
        let schema = result.unwrap();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — missing field (output schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_missing_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"}
        });
        let err = validate_schema_field(&def, "outputSchema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(codes::VALID_7036),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
        assert!(
            msg.contains("outputSchema"),
            "error should mention outputSchema, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — non-object value (output schema)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_non_object_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"},
            "outputSchema": [1, 2, 3]
        });
        let err = validate_schema_field(&def, "outputSchema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(codes::VALID_7036),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
        assert!(
            msg.contains("array"),
            "error should mention the actual type, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — structurally invalid output (missing "type")
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_rejects_structurally_invalid_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"},
            "outputSchema": {"description": "no type field"}
        });
        let err = validate_schema_field(&def, "outputSchema").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(codes::VALID_7036),
            "error should contain SCP-VALID-7036, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_schema_field — valid output schema
    // -----------------------------------------------------------------------

    #[test]
    fn validate_schema_field_accepts_valid_output() {
        let def = serde_json::json!({
            "name": "test-tool",
            "schema": {"type": "object"},
            "outputSchema": {"type": "object", "properties": {"result": {"type": "string"}}}
        });
        let result = validate_schema_field(&def, "outputSchema");
        assert!(result.is_ok(), "valid outputSchema should succeed");
        let schema = result.unwrap();
        assert!(schema.is_object());
        assert_eq!(schema["type"], "object");
    }

    // -----------------------------------------------------------------------
    // validate_test_vectors
    // -----------------------------------------------------------------------

    #[test]
    fn validate_test_vectors_absent() {
        let def = serde_json::json!({});
        let result = validate_test_vectors(&def);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_test_vectors_accepts_valid() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2},
                    "description": "adds one"
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(result.is_ok());
        let vecs = result.unwrap();
        assert_eq!(vecs.len(), 1);
        assert_eq!(vecs[0].description, "adds one");
    }

    #[test]
    fn validate_test_vectors_rejects_non_array() {
        let def = serde_json::json!({
            "testVectors": "not an array"
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, .. }) if code == codes::VALID_7037
            ),
            "expected SCP-VALID-7037, got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_missing_input() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "expectedOutput": {"y": 2},
                    "description": "no input"
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == codes::VALID_7037 && message.contains("'input'")
            ),
            "expected SCP-VALID-7037 mentioning 'input', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_missing_expected_output() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "description": "no output"
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == codes::VALID_7037 && message.contains("'expectedOutput'")
            ),
            "expected SCP-VALID-7037 mentioning 'expectedOutput', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_missing_description() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2}
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == codes::VALID_7037 && message.contains("'description'")
            ),
            "expected SCP-VALID-7037 mentioning 'description', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_non_string_description() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2},
                    "description": 42
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == codes::VALID_7037
                        && message.contains("'description'")
                        && message.contains("number")
            ),
            "expected SCP-VALID-7037 mentioning 'description' and type 'number', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_rejects_boolean_description() {
        let def = serde_json::json!({
            "testVectors": [
                {
                    "input": {"x": 1},
                    "expectedOutput": {"y": 2},
                    "description": true
                }
            ]
        });
        let result = validate_test_vectors(&def);
        assert!(
            matches!(
                result,
                Err(ScpWasmError::Validation { ref code, ref message, .. })
                    if code == codes::VALID_7037
                        && message.contains("'description'")
                        && message.contains("boolean")
            ),
            "expected SCP-VALID-7037 mentioning 'description' and type 'boolean', got: {result:?}"
        );
    }

    #[test]
    fn validate_test_vectors_accepts_empty_array() {
        let def = serde_json::json!({
            "testVectors": []
        });
        let result = validate_test_vectors(&def);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_rate_limit_json (F9 — protocol RateLimit)
    // -----------------------------------------------------------------------

    fn test_clock() -> scp_protocol::time::TestClock {
        scp_protocol::time::TestClock::new(0)
    }

    #[test]
    fn rate_limit_parses_valid() {
        let json = r#"{"max_calls": 10, "window_seconds": 60}"#;
        let rl = parse_rate_limit_json_with_clock(json, &test_clock()).unwrap();
        assert_eq!(rl.max_calls, 10);
        assert_eq!(rl.window, std::time::Duration::from_mins(1));
        assert_eq!(
            rl.burst_allowance,
            scp_protocol::context::outlets::interface::DEFAULT_BURST_ALLOWANCE
        );
        assert_eq!(
            rl.burst_window,
            std::time::Duration::from_secs(
                scp_protocol::context::outlets::interface::DEFAULT_BURST_WINDOW_SECS
            )
        );
    }

    #[test]
    fn rate_limit_rejects_missing_max_calls() {
        let json = r#"{"window_seconds": 60}"#;
        let result = parse_rate_limit_json_with_clock(json, &test_clock());
        assert!(result.is_err(), "missing max_calls should fail");
    }

    #[test]
    fn rate_limit_rejects_string_max_calls() {
        let json = r#"{"max_calls": "ten", "window_seconds": 60}"#;
        let result = parse_rate_limit_json_with_clock(json, &test_clock());
        assert!(result.is_err(), "string max_calls should fail");
    }

    // -----------------------------------------------------------------------
    // Consent protocol lifecycle tests (F3)
    //
    // These test the pure-Rust validation logic used by the consent protocol
    // bridge functions. Tests that require the WasmContextManager (which
    // calls wasm-bindgen time functions) live in manager::tests.
    // -----------------------------------------------------------------------

    #[test]
    fn consent_expose_builds_valid_interface_json() {
        let context_id = "ctx-source";
        let target_context_id = "ctx-target";
        let outlet_id = "tool-calculator";

        let interface = serde_json::json!({
            "source_context": context_id,
            "target_context": target_context_id,
            "outlet_id": outlet_id,
            "rate_limit": null,
            "per_caller_rate_limit": {
                "max_calls_per_caller": 10,
                "window": { "secs": 60, "nanos": 0 },
                "burst_allowance": 5,
                "burst_window": { "secs": 1, "nanos": 0 },
                "callers": {}
            },
            "approved_by_source": true,
            "approved_by_target": false,
            "outbound_policy": {
                "allowed_callers": [],
                "max_calls_per_minute": 60,
                "max_payload_bytes": 65536,
                "require_provenance": true
            },
            "inbound_policy": null
        });

        assert_eq!(interface["approved_by_source"], true);
        assert_eq!(interface["approved_by_target"], false);
        assert_eq!(interface["source_context"], context_id);
        assert_eq!(interface["target_context"], target_context_id);
        assert_eq!(interface["outlet_id"], outlet_id);
        assert!(interface["outbound_policy"].is_object());
        assert!(interface["inbound_policy"].is_null());

        // Serialization roundtrip should succeed.
        let json_str = serde_json::to_string(&interface).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["source_context"], context_id);
    }

    #[test]
    fn consent_expose_admin_role_check_logic() {
        // Simulates the admin role check that outlet_interface_offer performs.
        // "admin" passes; all other roles are rejected.
        let admin_role: Option<&str> = Some("admin");
        let member_role: Option<&str> = Some("member");
        let no_role: Option<&str> = None;

        assert!(matches!(admin_role, Some("admin")));
        assert!(!matches!(member_role, Some("admin")));
        assert!(!matches!(no_role, Some("admin")));
    }

    #[test]
    fn consent_accept_validates_context_match() {
        let interface_json = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "outlet_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": null
        });

        let context_id = "ctx-target";
        let target = interface_json
            .get("target_context")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert_eq!(target, context_id, "target should match accepting context");
    }

    #[test]
    fn consent_accept_rejects_context_mismatch() {
        let interface_json = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "outlet_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": null
        });

        let context_id = "ctx-wrong";
        let target = interface_json
            .get("target_context")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert_ne!(target, context_id, "target should NOT match wrong context");
    }

    #[test]
    fn consent_accept_sets_approved_by_target() {
        let mut interface = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "outlet_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": null
        });

        // Simulate the accept logic from outlet_interface_accept.
        interface["approved_by_target"] = serde_json::json!(true);
        if interface.get("inbound_policy").is_none() || interface["inbound_policy"].is_null() {
            interface["inbound_policy"] = serde_json::json!({
                "allowed_source_roles": [],
                "max_calls_per_minute": 60,
                "max_response_bytes": 65536,
                "require_spending_ucan": false
            });
        }

        assert_eq!(interface["approved_by_target"], true);
        assert!(interface["approved_by_source"].as_bool().unwrap());
        assert!(interface["inbound_policy"].is_object());
        assert_eq!(interface["inbound_policy"]["max_calls_per_minute"], 60);
        assert_eq!(interface["inbound_policy"]["max_response_bytes"], 65536);
    }

    #[test]
    fn consent_accept_preserves_existing_inbound_policy() {
        let mut interface = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "outlet_id": "tool-calc",
            "approved_by_source": true,
            "approved_by_target": false,
            "inbound_policy": {
                "allowed_source_roles": ["member"],
                "max_calls_per_minute": 30,
                "max_response_bytes": 32768,
                "require_spending_ucan": true
            }
        });

        // Existing inbound_policy should not be overwritten.
        interface["approved_by_target"] = serde_json::json!(true);
        if interface.get("inbound_policy").is_none() || interface["inbound_policy"].is_null() {
            interface["inbound_policy"] = serde_json::json!({
                "allowed_source_roles": [],
                "max_calls_per_minute": 60,
                "max_response_bytes": 65536,
                "require_spending_ucan": false
            });
        }

        // Should keep the original policy.
        assert_eq!(interface["inbound_policy"]["max_calls_per_minute"], 30);
        assert_eq!(interface["inbound_policy"]["max_response_bytes"], 32768);
    }

    #[test]
    fn consent_revoke_produces_valid_event() {
        let interface_id_hex = "aa".repeat(32); // 64 hex chars = 32 bytes
        let interface_id_bytes = hex::decode(&interface_id_hex).unwrap();
        assert_eq!(interface_id_bytes.len(), 32);

        let context_id = "ctx-revoker";
        let now_ms: u64 = 1_700_000_000_000;

        let event = serde_json::json!({
            "interface_id": interface_id_bytes,
            "revoking_context": context_id,
            "revoked_at": now_ms
        });

        assert_eq!(event["revoking_context"], "ctx-revoker");
        assert_eq!(event["revoked_at"], 1_700_000_000_000_u64);
        assert!(event["interface_id"].is_array());
    }

    #[test]
    fn consent_revoke_rejects_invalid_hex() {
        let result = hex::decode("not_valid_hex");
        assert!(result.is_err(), "non-hex should fail");
    }

    #[test]
    fn consent_revoke_rejects_wrong_length() {
        let short_hex = "aa".repeat(16); // 32 hex chars = 16 bytes, need 32
        let bytes = hex::decode(&short_hex).unwrap();
        assert_ne!(bytes.len(), 32, "16 bytes should fail 32-byte check");
    }

    #[test]
    fn consent_expose_with_rate_limit() {
        let rl_json = r#"{"max_calls": 20, "window_seconds": 120}"#;
        let rl = parse_rate_limit_json_with_clock(rl_json, &test_clock()).unwrap();
        assert_eq!(rl.max_calls, 20);
        assert_eq!(rl.window, std::time::Duration::from_mins(2));

        // Serialized rate_limit should appear in the interface JSON.
        let interface = serde_json::json!({
            "source_context": "ctx-source",
            "target_context": "ctx-target",
            "outlet_id": "tool-calc",
            "rate_limit": rl,
            "approved_by_source": true,
            "approved_by_target": false,
        });

        assert!(interface["rate_limit"].is_object());
        assert_eq!(interface["rate_limit"]["max_calls"], 20);
    }
}
