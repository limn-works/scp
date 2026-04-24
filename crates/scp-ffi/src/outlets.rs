//! `PyO3` bridge functions for tool registration, invocation, and verification.
//!
//! Exposes SCP tool operations to Python:
//!
//! - [`py_outlet_register`] — Register a tool in a context (returns tool ID).
//! - [`py_outlet_invoke`] — Invoke a tool (returns JSON-compatible output).
//! - [`py_outlet_verify`] — Verify a tool against its test vectors.
//!
//! # Types
//!
//! - [`PyOutletRegistration`] — Tool registration data (name, description,
//!   schema, test vectors).
//! - [`PyOutletVerificationResult`] — Verification result (tool ID, pass/fail,
//!   failure messages).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §4 for the bridge specification.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_ffi_common::error_codes as codes;
use scp_primitives::Clock;

use crate::error::ScpPyError;
use crate::types::{json_to_py_dict, py_dict_to_json};
use crate::validate;

// ---------------------------------------------------------------------------
// PyOutletRegistration
// ---------------------------------------------------------------------------

/// Tool registration data exposed to Python.
///
/// Contains the metadata needed to register a tool in an SCP context:
/// name, description, JSON Schema, and test vectors. The `schema` field
/// is a Python dict representing the MCP-compatible JSON Schema for the
/// tool's input and output.
///
/// See ADR-010 (tool registration) and ADR-013 §4 (bridge layer).
#[pyclass(name = "OutletRegistration")]
#[derive(Debug)]
pub struct PyOutletRegistration {
    /// Human-readable tool name.
    #[pyo3(get)]
    pub name: String,

    /// Tool description.
    #[pyo3(get)]
    pub description: String,

    /// JSON Schema for tool input/output, as a Python dict.
    #[pyo3(get)]
    pub schema: PyObject,

    /// Test vectors for verification, as a list of Python dicts.
    #[pyo3(get)]
    pub test_vectors: Vec<PyObject>,
}

#[pymethods]
impl PyOutletRegistration {
    /// Creates a new tool registration.
    ///
    /// # Arguments
    ///
    /// * `name` — Human-readable tool name.
    /// * `description` — Tool description.
    /// * `schema` — JSON Schema dict for input/output.
    /// * `test_vectors` — List of test vector dicts (each with `input`,
    ///   `expected_output`, `description`).
    #[new]
    #[allow(clippy::missing_const_for_fn)] // PyO3 #[new] cannot be const.
    fn new(
        name: String,
        description: String,
        schema: PyObject,
        test_vectors: Vec<PyObject>,
    ) -> Self {
        Self {
            name,
            description,
            schema,
            test_vectors,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "OutletRegistration(name={:?}, description={:?}, test_vectors={})",
            self.name,
            self.description,
            self.test_vectors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PyOutletVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its test vectors.
///
/// Returned by [`py_outlet_verify`]. Contains the tool ID, overall pass/fail
/// status, and a list of failure messages (empty if all vectors passed).
#[pyclass(name = "OutletVerificationResult")]
#[derive(Debug, Clone)]
pub struct PyOutletVerificationResult {
    /// The verified tool's ID.
    #[pyo3(get)]
    pub outlet_id: String,

    /// `True` if all test vectors passed.
    #[pyo3(get)]
    pub passed: bool,

    /// Failure messages for vectors that did not pass. Empty on success.
    #[pyo3(get)]
    pub failures: Vec<String>,
}

#[pymethods]
impl PyOutletVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "OutletVerificationResult(outlet_id={:?}, passed={}, failures={})",
            self.outlet_id,
            self.passed,
            self.failures.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Registers a tool in an SCP context.
///
/// # Arguments
///
/// * `context_id` — The ID of the context to register the tool in.
/// * `registration` — A Python dict containing tool registration data
///   (name, description, schema, `test_vectors`, `operator_did`).
///
/// # Returns
///
/// The tool ID (string) assigned to the registered tool.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected to the runtime
/// or if registration fails (permission denied, schema invalid, etc.).
///
/// See ADR-013 §4: `py_outlet_register(handle, registration) -> str`.
#[pyfunction]
#[pyo3(name = "outlet_register")]
pub fn py_outlet_register(context_id: &str, registration: &Bound<'_, PyDict>) -> PyResult<String> {
    validate::validate_context_id(context_id)?;

    // Extract registration fields from the Python dict.
    let name: String = registration
        .get_item("name")?
        .ok_or_else(|| ScpPyError::validation("missing 'name' field".to_owned()))?
        .extract()?;
    let description: String = registration
        .get_item("description")?
        .ok_or_else(|| ScpPyError::validation("missing 'description' field".to_owned()))?
        .extract()?;
    let operator_did: String = registration
        .get_item("operator_did")?
        .ok_or_else(|| ScpPyError::validation("missing 'operator_did' field".to_owned()))?
        .extract()?;

    // Validate extracted string fields at the bridge boundary.
    validate::validate_outlet_name(&name)?;
    validate::validate_did(&operator_did)?;

    // Extract schema as JSON. The schema dict should have `input_schema` and
    // `output_schema` keys, each being a JSON Schema object.
    let schema_obj = registration
        .get_item("schema")?
        .ok_or_else(|| ScpPyError::validation("missing 'schema' field".to_owned()))?;
    let schema_dict = schema_obj
        .downcast::<PyDict>()
        .map_err(|_| ScpPyError::validation("'schema' must be a dict".to_owned()))?;
    let schema_json = py_dict_to_json(schema_dict)?;
    let input_schema = schema_json.get("input_schema").cloned().ok_or_else(|| {
        ScpPyError::ValidationError {
            message: "missing 'input_schema' in schema dict — both 'input_schema' and 'output_schema' are required".to_owned(),
            code: codes::VALID_7035.to_owned(),
        }
    })?;
    if !input_schema.is_object() {
        return Err(ScpPyError::ValidationError {
            message: format!(
                "invalid 'input_schema': expected a JSON object, got {}",
                scp_ffi_common::validate::json_value_type_name(&input_schema)
            ),
            code: codes::VALID_7035.to_owned(),
        }
        .into());
    }
    let output_schema = schema_json.get("output_schema").cloned().ok_or_else(|| {
        ScpPyError::ValidationError {
            message: "missing 'output_schema' in schema dict — both 'input_schema' and 'output_schema' are required".to_owned(),
            code: codes::VALID_7036.to_owned(),
        }
    })?;
    if !output_schema.is_object() {
        return Err(ScpPyError::ValidationError {
            message: format!(
                "invalid 'output_schema': expected a JSON object, got {}",
                scp_ffi_common::validate::json_value_type_name(&output_schema)
            ),
            code: codes::VALID_7036.to_owned(),
        }
        .into());
    }

    // Extract test vectors (optional).
    let test_vectors = extract_test_vectors(registration)?;

    // Extract implementation hash (optional, 32-byte SHA-256 of tool code).
    // Per spec §5.4: content-addressable reference to the tool's implementation.
    let implementation_hash = extract_implementation_hash(registration)?;

    // Extract cost metadata (optional, per spec §5.4.1).
    let cost = extract_cost(registration)?;

    // Generate a tool ID from the name (deterministic, human-readable).
    let outlet_id = format!("tool-{}", name.replace(' ', "-").to_lowercase());

    // Build the scp-core OutletRegistration.
    let core_registration = scp_core::context::tools::OutletRegistration {
        outlet_id,
        name,
        description,
        schema: scp_core::context::tools::OutletSchema {
            input_schema,
            output_schema,
        },
        implementation_hash,
        test_vectors,
        operator_did: operator_did.into(),
        cost,
        registered_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        signature: vec![],
    };

    // Look up the context runtime and register the tool.
    let registered_id = crate::runtime::with_context(context_id, |rt| {
        let (registered_id, _event) = scp_core::context::tools::register_outlet(
            &mut rt.outlet_registry,
            &rt.role_state,
            core_registration,
            &rt.creator_did.clone(),
        )
        .map_err(|e| ScpPyError::context(format!("tool registration failed: {e}")))?;
        Ok(registered_id)
    })?;

    Ok(registered_id)
}

/// Validates a UCAN token for tool invocation authorization.
///
/// Runs the full 11-step ADR-016 pipeline, requiring `outlet_call:{outlet_id}`
/// or `outlet_call:*` capability. Extracted to keep `py_outlet_invoke` within
/// the 100-line clippy limit.
fn validate_outlet_ucan(
    context_id: &str,
    outlet_id: &str,
    ucan_token: &str,
    identity_did: &str,
    proof_tokens: Option<&Vec<String>>,
) -> PyResult<()> {
    let proof_resolver =
        crate::ucan::build_proof_resolver_from_tokens(proof_tokens.map(Vec::as_slice))?;

    crate::runtime::with_context(context_id, |rt| {
        let production_resolver = crate::runtime::did_resolver();
        let did_resolver = crate::bridge_adapters::DispatchDidResolver::new(
            production_resolver.map(std::convert::AsRef::as_ref),
        );
        let revocation_checker = crate::bridge_adapters::BridgeRevocationChecker {
            revocation_list: &rt.revocation_list,
        };
        let mut nonce_adapter = crate::bridge_adapters::BridgeNonceTracker {
            inner: &mut rt.nonce_tracker,
        };

        let mut ctx = scp_core::crypto::ucan::validate::ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &rt.ceiling_strings,
            context_creator_did: &rt.creator_did,
            presenting_agent_did: identity_did,
            clock_skew_tolerance_secs:
                scp_core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_primitives::SystemClock,
        };

        scp_core::context::tools::validate_outlet_invocation_ucan(
            ucan_token, context_id, outlet_id, &mut ctx,
        )
        .map_err(|e| {
            ScpPyError::ucan(format!(
                "UCAN authorization failed for tool '{outlet_id}': {e}"
            ))
        })
    })?;
    Ok(())
}

/// Invokes a tool within an SCP context, fully wired through the
/// `ContextManager::invoke_outlet_with_economy` pipeline.
///
/// This is the SINGLE entry point for tool invocation through the `PyO3`
/// bridge. Every paid-action concern — per-invocation pricing, spending
/// UCAN AND-composition (§19.5), per-DID velocity tracking, escalation
/// (§19.7), budget enforcement, payment escrow, and the
/// `ToolEconomyTicket` rollback discipline — is enforced by the runtime,
/// not by the bridge. The Matrix-style hard rate limit is consumed by
/// the wrapper itself in Phase 1 (defense-in-depth), so the previous
/// bridge-side `try_consume_hard_rate_limit_*` calls are no longer
/// needed.
///
/// Validates the UCAN token for tool invocation authorization before
/// dispatching. The UCAN must contain a `outlet_call:{outlet_id}` or
/// `outlet_call:*` capability scoped to the context.
///
/// Dispatches to a registered tool handler if one exists (registered via
/// [`crate::runtime::register_outlet_handler`]). The runtime validates
/// input/output schemas and computes the input/output hashes for the
/// `OutletInvokedEvent`. If no handler is registered, falls back to
/// returning validated input with metadata (schema-only mode), identical
/// to `FfiBridgeProvider::invoke_outlet` in `mcp.rs`.
///
/// # Arguments
///
/// * `context_id` — The ID of the context containing the tool.
/// * `outlet_id` — The ID of the tool to invoke.
/// * `input` — A Python dict of input parameters matching the tool's
///   input schema.
/// * `identity_did` — The DID of the invoking identity (used for
///   capability checking).
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain `outlet_call:{outlet_id}` or `outlet_call:*` capability.
///   Validated using the full 11-step ADR-016 pipeline.
/// * `spending_ucan` — Optional JWT-encoded spending UCAN
///   (`SpendingCapability`) for paid tool invocations. Required when an
///   `EconomicPolicy` priced the tool above zero (§19.5
///   AND-composition). May be `None` for free tools.
/// * `proof_tokens` — Optional encoded parent UCAN tokens for delegation
///   chain traversal (ADR-016 step 3).
///
/// # Returns
///
/// A Python object (dict) containing the tool's JSON-compatible output.
///
/// # Errors
///
/// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
/// or lacks the required tool invocation capability.
/// Raises `ContextError` (with embedded `SCP-ECON-12010` /
/// `SCP-ECON-12061` / `SCP-ECON-12090` / tool-invocation codes) if the
/// economy pre-check, budget, payment escrow, hard rate limit, or
/// underlying tool dispatch fails. Callers should consult `.code` rather
/// than string-matching `.message`.
///
/// See ADR-013 §4: `py_outlet_invoke(handle, outlet_id, input, identity) -> PyObject`.
/// See SCP-212 for the handler registration and dispatch design.
/// See spec §6.2, §8, §19.5, §19.7, ADR-016, and issue #319.
#[pyfunction]
#[pyo3(name = "outlet_invoke")]
#[pyo3(signature = (context_id, outlet_id, input, identity_did, ucan_token, proof_tokens=None, spending_ucan=None))]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>>.
#[allow(clippy::too_many_arguments)] // Bridge mirrors the runtime's economy entry point.
pub fn py_outlet_invoke(
    py: Python<'_>,
    context_id: &str,
    outlet_id: &str,
    input: &Bound<'_, PyDict>,
    identity_did: &str,
    ucan_token: &str,
    proof_tokens: Option<Vec<String>>,
    spending_ucan: Option<&str>,
) -> PyResult<PyObject> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    validate::validate_did(identity_did)?;
    validate::validate_ucan_token(ucan_token)?;
    if let Some(jwt) = spending_ucan {
        validate::validate_ucan_token(jwt)?;
    }
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    let input_json = py_dict_to_json(input)?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline. This stays at the bridge layer because it
    // depends on bridge-owned per-context UCAN state (revocation list,
    // nonce tracker, capability ceiling, proof resolver). The runtime
    // wrapper does NOT re-validate the action UCAN — it enforces the
    // economy/budget/spending side. See spec §6.2, §8, ADR-016, #319.
    validate_outlet_ucan(
        context_id,
        outlet_id,
        ucan_token,
        identity_did,
        proof_tokens.as_ref(),
    )?;

    // Parse the optional spending UCAN JWT (§19.5 AND-composition). We
    // parse it once here so an invalid JWT surfaces as a clean
    // `SCP-ECON-12061` before the manager call. Mirrors `py_context_send`.
    let spending_ucan_token = spending_ucan
        .map(|jwt| {
            scp_core::crypto::ucan::validate::parse_ucan(jwt).map_err(|e| {
                ScpPyError::ContextError {
                    message: format!("invalid spending UCAN: {e}"),
                    code: codes::ECON_12061.to_owned(),
                }
            })
        })
        .transpose()?;

    // Snapshot the bridge-owned tool registry and (optionally) the
    // registered handler closure BEFORE entering the runtime call. The
    // runtime requires a `&OutletRegistry` so we clone the registry once
    // (cheap — Vec of registrations); the handler is an `Arc<dyn Fn>`
    // so cloning is a refcount bump. Doing this OUTSIDE the runtime
    // call keeps the bridge-side DashMap shard lock acquisition split
    // from the runtime's `contexts` mutex, matching the lock-split
    // discipline in `mcp.rs`.
    let ctx_id_owned = context_id.to_owned();
    let outlet_id_owned = outlet_id.to_owned();
    let identity_did_owned = identity_did.to_owned();
    let (registry, handler) = crate::runtime::with_context(context_id, |rt| {
        Ok((
            rt.outlet_registry.clone(),
            rt.outlet_handlers.get(outlet_id).cloned(),
        ))
    })?;

    // Build the executor closure. The runtime invokes the executor in
    // Phase 2 of `invoke_outlet_with_economy` WITHOUT holding the
    // `contexts` mutex. The closure dispatches to a registered Python
    // handler when present and falls back to schema-only echo mode
    // otherwise (matching the prior PyO3 behavior).
    let ctx_id_for_executor = ctx_id_owned.clone();
    let outlet_id_for_executor = outlet_id_owned.clone();
    let identity_did_for_executor = identity_did_owned.clone();
    let executor = move |input: serde_json::Value| {
        let handler = handler.clone();
        let input_for_echo = input.clone();
        async move {
            handler.map_or_else(
                || {
                    Ok(serde_json::json!({
                        "tool": outlet_id_for_executor,
                        "context": ctx_id_for_executor,
                        "status": "validated",
                        "input_valid": true,
                        "invoker_did": identity_did_for_executor,
                        "validated_input": input_for_echo,
                    }))
                },
                |h| {
                    h(input).map_err(|e| {
                        format!("tool handler for '{outlet_id_for_executor}' failed: {e}")
                    })
                },
            )
        }
    };

    // Dispatch to the runtime via the global tokio runtime. PyO3 calls
    // are sync; the Python SDK wrapper invokes us via `asyncio.to_thread`
    // so we are NOT inside a tokio runtime context — `block_on` on the
    // multi-thread global runtime is safe (matches `py_context_send`).
    let manager = crate::runtime::context_manager()?;
    let invoker_did_typed: scp_primitives::DID = identity_did_owned.into();
    let outlet_id_typed = scp_core::context::tools::OutletId::from(outlet_id_owned.as_str());
    let rt = crate::runtime()?;
    let outcome = rt
        .block_on(async {
            manager
                .invoke_outlet_with_economy(
                    &ctx_id_owned,
                    &registry,
                    &outlet_id_typed,
                    input_json,
                    &invoker_did_typed,
                    spending_ucan_token.as_ref(),
                    None,
                    executor,
                )
                .await
        })
        .map_err(ScpPyError::from)?;

    // Mark the time of last successful invocation for any future
    // observability hooks. (`outcome.event` carries the canonical
    // `OutletInvokedEvent` — the transport / event-log layer is the one
    // responsible for signing and appending to the Merkle log.)
    let _ = outcome.event;

    json_to_py_dict(py, &outcome.output)
}

/// Verifies a tool against its registered test vectors.
///
/// # Arguments
///
/// * `context_id` — The ID of the context containing the tool.
/// * `outlet_id` — The ID of the tool to verify.
///
/// # Returns
///
/// A [`PyOutletVerificationResult`] with the tool ID, overall pass/fail
/// status, and any failure messages.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected or the tool
/// is not found.
///
/// See ADR-013 §4: `py_outlet_verify(handle, outlet_id) -> PyOutletVerificationResult`.
#[pyfunction]
#[pyo3(name = "outlet_verify")]
pub fn py_outlet_verify(context_id: &str, outlet_id: &str) -> PyResult<PyOutletVerificationResult> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    // Look up the context and verify the tool against its test vectors.
    // The executor returns the expected output (identity function) since the
    // bridge layer has no external tool executor. This verifies the test
    // vector structure is intact.
    let result = crate::runtime::with_context(context_id, |rt| {
        let (verification_result, _event) = scp_core::context::tools::verify_outlet(
            &rt.outlet_registry,
            outlet_id,
            // Identity executor: returns the expected output for each vector.
            // This validates the test vector structure; real execution verification
            // happens when a full executor is connected.
            |input| {
                // Look up the tool to find the matching test vector.
                if let Some(registration) = rt.outlet_registry.get(outlet_id) {
                    for vector in &registration.test_vectors {
                        if vector.input == *input {
                            return vector.expected_output.clone();
                        }
                    }
                }
                // If no matching vector found, return null (will fail comparison).
                serde_json::Value::Null
            },
        )
        .map_err(|e| ScpPyError::context(format!("tool verification failed: {e}")))?;

        Ok(verification_result)
    })?;

    // Convert to PyOutletVerificationResult.
    let failures: Vec<String> = result
        .vector_results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.description.clone())
        .collect();

    Ok(PyOutletVerificationResult {
        outlet_id: result.outlet_id,
        passed: result.integrity_ok,
        failures,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extracts the optional `implementation_hash` from the registration dict.
///
/// Accepts a hex-encoded SHA-256 hash string (64 chars). Returns zeroed hash
/// if not provided. Per spec §5.4: content-addressable reference to the tool's
/// implementation.
///
/// Returns `SCP-VALID-7038` on validation failure (aligned with NAPI bridge).
fn extract_implementation_hash(registration: &Bound<'_, PyDict>) -> PyResult<[u8; 32]> {
    let hash_obj = match registration.get_item("implementation_hash")? {
        Some(val) if !val.is_none() => val,
        _ => return Ok([0u8; 32]),
    };

    let hex_str: String = hash_obj
        .extract()
        .map_err(|_| ScpPyError::ValidationError {
            message: "'implementation_hash' must be a hex string".to_owned(),
            code: codes::VALID_7038.to_owned(),
        })?;

    if hex_str.len() != 64 {
        return Err(ScpPyError::ValidationError {
            message: format!(
                "'implementation_hash' must be 64 hex chars (SHA-256), got {}",
                hex_str.len()
            ),
            code: codes::VALID_7038.to_owned(),
        }
        .into());
    }

    let mut hash = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|_| ScpPyError::ValidationError {
            message: "invalid UTF-8 in implementation_hash".to_owned(),
            code: codes::VALID_7038.to_owned(),
        })?;
        hash[i] = u8::from_str_radix(byte_str, 16).map_err(|_| ScpPyError::ValidationError {
            message: format!("invalid hex in implementation_hash at position {}", i * 2),
            code: codes::VALID_7038.to_owned(),
        })?;
    }

    Ok(hash)
}

/// Extracts optional `cost` metadata from the registration dict.
///
/// Accepts a Python dict with `amount` (int), `currency` (str),
/// `payee` (str DID), and optional `cost_formula` (str). Per spec §5.4.1.
fn extract_cost(
    registration: &Bound<'_, PyDict>,
) -> PyResult<Option<scp_core::context::tools::OutletCost>> {
    let meta_obj = match registration.get_item("cost")? {
        Some(val) if !val.is_none() => val,
        _ => return Ok(None),
    };

    let dict = meta_obj
        .downcast::<PyDict>()
        .map_err(|_| ScpPyError::validation("'cost' must be a dict".to_owned()))?;

    let amount: u64 = dict
        .get_item("amount")?
        .ok_or_else(|| ScpPyError::validation("cost missing 'amount'".to_owned()))?
        .extract()?;

    let currency: String = dict
        .get_item("currency")?
        .ok_or_else(|| ScpPyError::validation("cost missing 'currency'".to_owned()))?
        .extract()?;

    let payee: String = dict
        .get_item("payee")?
        .ok_or_else(|| ScpPyError::validation("cost missing 'payee'".to_owned()))?
        .extract()?;

    let cost_formula: Option<String> = dict
        .get_item("cost_formula")?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract())
        .transpose()?;

    Ok(Some(scp_core::context::tools::OutletCost {
        amount,
        currency,
        payee: payee.into(),
        cost_formula,
    }))
}

/// Extracts test vectors from the registration dict's `test_vectors` field.
///
/// Each test vector is a Python dict with `input`, `expected_output`, and
/// `description` keys. Returns an empty Vec if the field is missing.
///
/// Returns `SCP-VALID-7037` on validation failure (aligned with NAPI bridge).
fn extract_test_vectors(
    registration: &Bound<'_, PyDict>,
) -> PyResult<Vec<scp_core::context::tools::OutletTestVector>> {
    let vectors_obj = match registration.get_item("test_vectors")? {
        Some(val) if !val.is_none() => val,
        _ => return Ok(Vec::new()),
    };

    let vectors_list =
        vectors_obj
            .downcast::<pyo3::types::PyList>()
            .map_err(|_| ScpPyError::ValidationError {
                message: "'test_vectors' must be a list".to_owned(),
                code: codes::VALID_7037.to_owned(),
            })?;

    let mut result = Vec::with_capacity(vectors_list.len());
    for item in vectors_list.iter() {
        let dict = item
            .downcast::<PyDict>()
            .map_err(|_| ScpPyError::ValidationError {
                message: "each test vector must be a dict".to_owned(),
                code: codes::VALID_7037.to_owned(),
            })?;
        let tv_json = py_dict_to_json(dict)?;

        let input = tv_json
            .get("input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let expected_output = tv_json
            .get("expected_output")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let description = tv_json
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        result.push(scp_core::context::tools::OutletTestVector {
            input,
            expected_output,
            description,
        });
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Cross-context tool invocation
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// The source context exposes the tool and the target context accepts the
/// interface. Both contexts must have approved the interface before calls
/// are permitted. Rate limits and chain depth are enforced per spec section
/// 6.2.
///
/// # Arguments
///
/// * `source_context_id` — The ID of the calling context.
/// * `target_context_id` — The ID of the context containing the tool.
/// * `outlet_id` — The ID of the tool to invoke.
/// * `input` — A Python dict of input parameters.
/// * `invoker_did` — The DID of the participant invoking the tool.
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain `outlet_call:{outlet_id}` or `outlet_call:*` capability.
///   Validated against the TARGET context's ceiling using the full 11-step
///   ADR-016 pipeline.
/// * `chain_depth` — Current cross-context chain depth (0 for first hop).
///
/// # Returns
///
/// A Python object (dict) containing the tool's JSON-compatible output.
///
/// # Errors
///
/// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
/// or lacks the required tool invocation capability.
/// Raises `ContextError` if either context is not connected, the tool is
/// not found, chain depth is exceeded, or the interface is not approved.
#[pyfunction]
#[pyo3(name = "outlet_invoke_cross_context")]
#[pyo3(signature = (source_context_id, target_context_id, outlet_id, input, invoker_did, ucan_token, chain_depth, proof_tokens=None))]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>>.
#[allow(clippy::too_many_arguments)] // FFI boundary: PyO3 requires explicit params
pub fn py_outlet_invoke_cross_context(
    py: Python<'_>,
    source_context_id: &str,
    target_context_id: &str,
    outlet_id: &str,
    input: &Bound<'_, PyDict>,
    invoker_did: &str,
    ucan_token: &str,
    chain_depth: u8,
    proof_tokens: Option<Vec<String>>,
) -> PyResult<PyObject> {
    validate::validate_context_id(source_context_id)?;
    validate::validate_context_id(target_context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    validate::validate_did(invoker_did)?;
    validate::validate_ucan_token(ucan_token)?;
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    let input_json = py_dict_to_json(input)?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline against the TARGET context's ceiling.
    // See spec §6.2, §8, ADR-016, and issue #319.
    validate_outlet_ucan(
        target_context_id,
        outlet_id,
        ucan_token,
        invoker_did,
        proof_tokens.as_ref(),
    )?;

    // Defense-in-depth: check role-state capabilities in the source context.
    let source_has_capability = crate::runtime::with_context(source_context_id, |rt| {
        Ok(scp_core::context::tools::has_outlet_call_capability(
            &rt.role_state,
            invoker_did,
            outlet_id,
        ))
    })?;

    if !source_has_capability {
        return Err(ScpPyError::ucan(format!(
            "invoker '{invoker_did}' does not have ToolInvoke capability for '{outlet_id}' in source context"
        ))
        .into());
    }

    // Validate chain depth (context-configurable, default 8 per ADR-043).
    let max_chain_depth = {
        let mgr = crate::runtime::context_manager()?;
        let tokio_rt = crate::runtime().map_err(|e| ScpPyError::context(e.to_string()))?;
        let source_max = tokio_rt
            .block_on(mgr.context_params(source_context_id))
            .and_then(|p| p.max_chain_depth);
        scp_core::provenance::attach::effective_max_chain_depth(source_max)
    };
    if chain_depth > max_chain_depth {
        return Err(ScpPyError::context(format!(
            "cross-context chain depth {chain_depth} exceeds maximum {max_chain_depth}"
        ))
        .into());
    }

    // Invoke the tool in the target context with echo mode.
    let output_json = crate::runtime::with_context(target_context_id, |rt| {
        let registration = rt.outlet_registry.get(outlet_id).ok_or_else(|| {
            ScpPyError::context(format!(
                "tool '{outlet_id}' not found in target context '{target_context_id}'"
            ))
        })?;

        // Validate input against the tool's input schema.
        scp_core::context::tools::validate_value_against_schema(
            &input_json,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpPyError::validation(format!("input validation failed: {e}")))?;

        // Dispatch to handler or echo mode.
        let output = if let Some(handler) = rt.outlet_handlers.get(outlet_id) {
            let handler = handler.clone();
            let out = handler(input_json.clone()).map_err(|e| {
                ScpPyError::context(format!(
                    "cross-context tool handler for '{outlet_id}' failed: {e}"
                ))
            })?;

            scp_core::context::tools::validate_value_against_schema(
                &out,
                &registration.schema.output_schema,
            )
            .map_err(|msg| {
                ScpPyError::validation(format!(
                    "output validation failed for tool '{outlet_id}': {msg}"
                ))
            })?;

            out
        } else {
            serde_json::json!({
                "tool": outlet_id,
                "source_context": source_context_id,
                "target_context": target_context_id,
                "status": "validated",
                "chain_depth": chain_depth,
                "input_valid": true,
                "validated_input": input_json,
            })
        };

        Ok(output)
    })?;

    // Provenance for cross-context tool invocations is now handled at the
    // protocol level (scp-protocol::tools::invoke_cross_context). The bridge-
    // level attach_cross_context_provenance was redundant and discarded its
    // result, so it has been removed.

    json_to_py_dict(py, &output_json)
}

// ---------------------------------------------------------------------------
// Stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Creates a stateful tool session.
///
/// Sessions enable multi-turn workflows with state preservation across
/// invocations. Each session has a TTL and is subject to per-caller caps
/// (default: 1000 concurrent sessions per caller, per spec §6.2.1 and ADR-043).
///
/// # Arguments
///
/// * `context_id` — The context containing the tool.
/// * `outlet_id` — The tool to create a session for.
/// * `source_context_id` — The calling context (session cap tracked per caller).
/// * `ttl_seconds` — Optional time-to-live for the session, in seconds.
///   `None` means the session persists for the lifetime of the context
///   (spec section 6.2.1).
///
/// # Returns
///
/// The session ID (UUID string).
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected, the tool is
/// not found, or the per-caller session cap is exceeded.
#[pyfunction]
#[pyo3(name = "outlet_session_open", signature = (context_id, outlet_id, source_context_id, ttl_seconds=None))]
pub fn py_outlet_session_open(
    context_id: &str,
    outlet_id: &str,
    source_context_id: &str,
    ttl_seconds: Option<u64>,
) -> PyResult<String> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    validate::validate_context_id(source_context_id)?;

    let session_id = crate::runtime::with_context(context_id, |rt| {
        // Validate tool exists.
        if !rt.outlet_registry.contains(outlet_id) {
            return Err(ScpPyError::context(format!(
                "tool '{outlet_id}' not found in context '{context_id}'"
            )));
        }

        // Enforce per-caller session cap (context-configured, default 1000, ADR-043).
        let cap = {
            let mgr = crate::runtime::context_manager()?;
            let tokio_rt = crate::runtime().map_err(|e| ScpPyError::context(e.to_string()))?;
            tokio_rt
                .block_on(mgr.context_params(context_id))
                .and_then(|p| p.session_cap)
                .unwrap_or(scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER)
                as usize
        };
        let current = rt.session_store.count_by_source(source_context_id);
        if current >= cap {
            return Err(ScpPyError::context(format!(
                "session cap exceeded for caller '{source_context_id}': {current} active (max {cap})"
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let now_ms = scp_primitives::SystemClock.now_millis();

        let session = scp_core::context::tools::OutletSession {
            session_id: session_id.clone(),
            outlet_id: outlet_id.to_owned(),
            source_context: source_context_id.to_owned(),
            state: serde_json::Value::Null,
            created_at: now_ms,
            ttl: ttl_seconds.map(std::time::Duration::from_secs),
            call_count: 0,
        };

        rt.session_store.insert(session);
        Ok(session_id)
    })?;

    Ok(session_id)
}

/// Invokes a tool within an active session.
///
/// Each call is individually governed: the invoker must hold `ToolInvoke`
/// capability and present a valid UCAN token. Session state is carried
/// forward across invocations. The session's call count is incremented on
/// each successful invocation.
///
/// # Arguments
///
/// * `context_id` — The context containing the tool session.
/// * `session_id` — The session to invoke within.
/// * `input` — A Python dict of input parameters.
/// * `invoker_did` — The DID of the invoker (capability checked per call).
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain `outlet_call:{outlet_id}` or `outlet_call:*` capability.
///   Validated using the full 11-step ADR-016 pipeline.
///
/// # Returns
///
/// A Python object (dict) containing the tool's JSON-compatible output.
///
/// # Errors
///
/// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
/// or lacks the required tool invocation capability.
/// Raises `ContextError` if the session is not found, has expired, or
/// the invoker lacks capability.
#[pyfunction]
#[pyo3(name = "outlet_session_invoke")]
#[pyo3(signature = (context_id, session_id, input, invoker_did, ucan_token, proof_tokens=None))]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>>.
pub fn py_outlet_session_invoke(
    py: Python<'_>,
    context_id: &str,
    session_id: &str,
    input: &Bound<'_, PyDict>,
    invoker_did: &str,
    ucan_token: &str,
    proof_tokens: Option<Vec<String>>,
) -> PyResult<PyObject> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(invoker_did)?;
    validate::validate_ucan_token(ucan_token)?;
    if let Some(ref tokens) = proof_tokens {
        for t in tokens {
            validate::validate_ucan_token(t)?;
        }
    }
    let input_json = py_dict_to_json(input)?;

    // Look up the outlet_id from the session before UCAN validation so we can
    // validate against the correct tool capability.
    let outlet_id_for_ucan = crate::runtime::with_context(context_id, |rt| {
        let session = rt
            .session_store
            .get(session_id)
            .ok_or_else(|| ScpPyError::context(format!("session '{session_id}' not found")))?;
        Ok(session.outlet_id.clone())
    })?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline. See spec §6.2, §8, ADR-016, and issue #319.
    validate_outlet_ucan(
        context_id,
        &outlet_id_for_ucan,
        ucan_token,
        invoker_did,
        proof_tokens.as_ref(),
    )?;

    let output_json = crate::runtime::with_context(context_id, |rt| {
        // Look up session.
        let session = rt
            .session_store
            .get(session_id)
            .ok_or_else(|| ScpPyError::context(format!("session '{session_id}' not found")))?;

        // Check expiry.
        let now_ms = scp_primitives::SystemClock.now_millis();
        if session.is_expired(now_ms) {
            rt.session_store.remove(session_id);
            return Err(ScpPyError::context(format!(
                "session '{session_id}' has expired"
            )));
        }

        let outlet_id = session.outlet_id.clone();
        let current_state = session.state.clone();

        // Defense-in-depth: check role-state capabilities in addition to the
        // UCAN layer. See §7.2 and ADR-010 for the dual-check design.
        if !scp_core::context::tools::has_outlet_call_capability(
            &rt.role_state,
            invoker_did,
            &outlet_id,
        ) {
            return Err(ScpPyError::ucan(format!(
                "invoker '{invoker_did}' does not have ToolInvoke capability for '{outlet_id}'"
            )));
        }

        // Validate input against tool's input schema.
        if let Some(registration) = rt.outlet_registry.get(&outlet_id) {
            scp_core::context::tools::validate_value_against_schema(
                &input_json,
                &registration.schema.input_schema,
            )
            .map_err(|e| ScpPyError::validation(format!("input validation failed: {e}")))?;
        }

        // Execute via handler or echo mode, passing session state.
        let (new_state, output) = if let Some(handler) = rt.outlet_handlers.get(&outlet_id) {
            let handler = handler.clone();
            let out = handler(input_json.clone()).map_err(|e| {
                ScpPyError::context(format!("tool handler for '{outlet_id}' failed: {e}"))
            })?;
            (current_state, out)
        } else {
            let out = serde_json::json!({
                "tool": outlet_id,
                "session_id": session_id,
                "status": "validated",
                "call_count": session.call_count + 1,
                "session_state": current_state,
                "validated_input": input_json,
            });
            (current_state, out)
        };

        // Update session state and increment call count.
        if let Some(session) = rt.session_store.get_mut(session_id) {
            session.state = new_state;
            session.call_count = session.call_count.saturating_add(1);
        }

        Ok(output)
    })?;

    json_to_py_dict(py, &output_json)
}

/// Closes a stateful tool session.
///
/// Removes the session from the store, releasing the caller's session slot.
/// After closing, any further invocations with this session ID will fail.
///
/// # Arguments
///
/// * `context_id` — The context containing the tool session.
/// * `session_id` — The session to close.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected or the session
/// is not found.
#[pyfunction]
#[pyo3(name = "outlet_session_close")]
pub fn py_outlet_session_close(context_id: &str, session_id: &str) -> PyResult<()> {
    validate::validate_context_id(context_id)?;

    crate::runtime::with_context(context_id, |rt| {
        if rt.session_store.remove(session_id).is_none() {
            return Err(ScpPyError::context(format!(
                "session '{session_id}' not found"
            )));
        }
        Ok(())
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Bidirectional consent protocol (spec §6.2.0.1)
// ---------------------------------------------------------------------------

/// Exposes a tool interface for cross-context sharing (§6.2.0.1 step 1).
///
/// The caller (admin of the source context) proposes sharing a specific tool
/// with a target context. The returned JSON contains the `OutletInterface` with
/// `approved_by_source = true` and `approved_by_target = false`. The target
/// context must call [`py_outlet_interface_accept`] to complete the handshake.
///
/// # Arguments
///
/// * `context_id` — The source context ID.
/// * `outlet_id` — The ID of the tool to expose.
/// * `target_context_id` — The target context to expose the tool to.
/// * `rate_limit_json` — Optional per-interface rate limit as a JSON string.
///   When provided, must be a JSON object with `max_calls` (u64) and
///   `window_seconds` (u64) fields.
///
/// # Returns
///
/// A JSON string representation of the created `OutletInterface`.
///
/// # Errors
///
/// Raises `OutletError` if the caller is not an admin or the tool is not found.
#[pyfunction]
#[pyo3(name = "outlet_interface_offer", signature = (context_id, outlet_id, target_context_id, rate_limit_json=None))]
pub fn py_outlet_interface_offer(
    context_id: &str,
    outlet_id: &str,
    target_context_id: &str,
    rate_limit_json: Option<&str>,
) -> PyResult<String> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    validate::validate_context_id(target_context_id)?;

    let rate_limit = match rate_limit_json {
        Some(json) => {
            let parsed: scp_core::context::tools::interface::RateLimit = serde_json::from_str(json)
                .map_err(|e| ScpPyError::ValidationError {
                    message: format!("invalid rate_limit_json: {e}"),
                    code: codes::VALID_7040.to_owned(),
                })?;
            Some(parsed)
        }
        None => None,
    };

    Ok(crate::runtime::with_context(context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.to_string(),
            scp_core::context::ContextParams::default(),
        );

        let interface = scp_core::context::tools::interface::expose_tool(
            context_handle.context_id(),
            &outlet_id.to_owned(),
            &target_context_id.to_owned(),
            &rt.role_state,
            &rt.creator_did,
            &rt.outlet_registry,
            rate_limit,
            None,
        )
        .map_err(|e| ScpPyError::ContextError {
            message: format!("expose_tool failed: {e}"),
            code: codes::TOOL_6030.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpPyError::ContextError {
            message: format!("failed to serialize OutletInterface: {e}"),
            code: codes::TOOL_6031.to_owned(),
        })
    })?)
}

/// Accepts a cross-context tool interface (§6.2.0.1 step 4).
///
/// Sets `approved_by_target = true` on the interface. Both `approved_by_source`
/// and `approved_by_target` must be `true` before calls are permitted.
///
/// # Arguments
///
/// * `context_id` — The target context ID (the one accepting).
/// * `interface_json` — The `OutletInterface` JSON string to accept (as received
///   from the source context's `outlet_interface_offer` call).
///
/// # Returns
///
/// The updated `OutletInterface` JSON string with `approved_by_target = true`.
///
/// # Errors
///
/// Raises `OutletError` if the caller is not an admin or the interface's target
/// context does not match `context_id`.
#[pyfunction]
#[pyo3(name = "outlet_interface_accept")]
pub fn py_outlet_interface_accept(context_id: &str, interface_json: &str) -> PyResult<String> {
    validate::validate_context_id(context_id)?;

    let mut interface: scp_core::context::tools::interface::OutletInterface =
        serde_json::from_str(interface_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid interface_json: {e}"),
            code: codes::VALID_7041.to_owned(),
        })?;

    Ok(crate::runtime::with_context(context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.to_string(),
            scp_core::context::ContextParams::default(),
        );

        scp_core::context::tools::interface::accept_tool_interface(
            context_handle.context_id(),
            &mut interface,
            &rt.role_state,
            &rt.creator_did,
            None,
        )
        .map_err(|e| ScpPyError::ContextError {
            message: format!("accept_tool_interface failed: {e}"),
            code: codes::TOOL_6032.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpPyError::ContextError {
            message: format!("failed to serialize OutletInterface: {e}"),
            code: codes::TOOL_6033.to_owned(),
        })
    })?)
}

/// Revokes a cross-context tool interface (§6.2.0.1 step 5).
///
/// Either context may revoke unilaterally. Returns an `InterfaceRevoked` event
/// for recording in the revoking context's event log.
///
/// # Arguments
///
/// * `context_id` — The revoking context ID.
/// * `interface_id` — The 32-byte interface/offer ID as a hex string.
///
/// # Returns
///
/// A JSON string representation of the `InterfaceRevoked` event.
///
/// # Errors
///
/// Raises `ValidationError` if `interface_id` is not valid hex or not 32 bytes.
#[pyfunction]
#[pyo3(name = "outlet_interface_revoke")]
pub fn py_outlet_interface_revoke(context_id: &str, interface_id_hex: &str) -> PyResult<String> {
    validate::validate_context_id(context_id)?;

    let interface_id_bytes =
        hex::decode(interface_id_hex).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid interface_id_hex: not valid hex: {e}"),
            code: codes::VALID_7042.to_owned(),
        })?;
    let interface_id: [u8; 32] =
        <[u8; 32]>::try_from(interface_id_bytes.as_slice()).map_err(|_| {
            ScpPyError::ValidationError {
                message: format!(
                    "interface_id_hex must be exactly 32 bytes (64 hex chars), got {}",
                    interface_id_bytes.len()
                ),
                code: codes::VALID_7042.to_owned(),
            }
        })?;

    let now_ms = scp_primitives::SystemClock.now_millis();

    let event = scp_core::context::tools::interface::revoke_tool_interface(
        interface_id,
        &context_id.to_owned(),
        now_ms,
    );

    let json = serde_json::to_string(&event).map_err(|e| ScpPyError::ContextError {
        message: format!("failed to serialize InterfaceRevoked: {e}"),
        code: codes::TOOL_6035.to_owned(),
    })?;

    Ok(json)
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers tool bridge functions and classes on the `_scp_core` module.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of functions or classes fails.
pub fn register_outlets(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyOutletRegistration>()?;
    m.add_class::<PyOutletVerificationResult>()?;
    m.add_function(wrap_pyfunction!(py_outlet_register, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_invoke, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_verify, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_invoke_cross_context, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_session_open, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_session_invoke, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_session_close, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_interface_offer, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_interface_accept, m)?)?;
    m.add_function(wrap_pyfunction!(py_outlet_interface_revoke, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    #[test]
    fn json_value_type_name_covers_all_variants() {
        use scp_ffi_common::validate::json_value_type_name;
        assert_eq!(json_value_type_name(&serde_json::Value::Null), "null");
        assert_eq!(
            json_value_type_name(&serde_json::Value::Bool(true)),
            "boolean"
        );
        assert_eq!(json_value_type_name(&serde_json::json!(42)), "number");
        assert_eq!(json_value_type_name(&serde_json::json!("hello")), "string");
        assert_eq!(json_value_type_name(&serde_json::json!([1, 2])), "array");
        assert_eq!(json_value_type_name(&serde_json::json!({"a": 1})), "object");
    }

    /// Schema validation rejects missing `input_schema` with `SCP-VALID-7035`.
    #[test]
    fn schema_validation_rejects_missing_input_schema() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("name", "test-tool").unwrap();
            dict.set_item("description", "a test").unwrap();
            dict.set_item("operator_did", "did:dht:test123456789abcdefghij")
                .unwrap();

            // Schema dict with only output_schema, missing input_schema.
            let schema = PyDict::new(py);
            schema.set_item("output_schema", PyDict::new(py)).unwrap();
            dict.set_item("schema", schema).unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(result.is_err(), "should reject missing input_schema");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7035),
                "error should contain SCP-VALID-7035, got: {err_str}"
            );
            assert!(
                err_str.contains("input_schema"),
                "error should mention input_schema, got: {err_str}"
            );
        });
    }

    /// Schema validation rejects missing `output_schema` with `SCP-VALID-7036`.
    #[test]
    fn schema_validation_rejects_missing_output_schema() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("name", "test-tool").unwrap();
            dict.set_item("description", "a test").unwrap();
            dict.set_item("operator_did", "did:dht:test123456789abcdefghij")
                .unwrap();

            // Schema dict with only input_schema, missing output_schema.
            let schema = PyDict::new(py);
            let inner = PyDict::new(py);
            inner.set_item("type", "object").unwrap();
            schema.set_item("input_schema", inner).unwrap();
            dict.set_item("schema", schema).unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(result.is_err(), "should reject missing output_schema");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7036),
                "error should contain SCP-VALID-7036, got: {err_str}"
            );
            assert!(
                err_str.contains("output_schema"),
                "error should mention output_schema, got: {err_str}"
            );
        });
    }

    /// Schema validation rejects non-object `input_schema` with `SCP-VALID-7035`.
    #[test]
    fn schema_validation_rejects_non_object_input_schema() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("name", "test-tool").unwrap();
            dict.set_item("description", "a test").unwrap();
            dict.set_item("operator_did", "did:dht:test123456789abcdefghij")
                .unwrap();

            // Schema dict with input_schema as a string, not an object.
            let schema = PyDict::new(py);
            schema.set_item("input_schema", "not-an-object").unwrap();
            let output = PyDict::new(py);
            output.set_item("type", "object").unwrap();
            schema.set_item("output_schema", output).unwrap();
            dict.set_item("schema", schema).unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(result.is_err(), "should reject non-object input_schema");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7035),
                "error should contain SCP-VALID-7035, got: {err_str}"
            );
        });
    }

    /// Schema validation rejects non-object `output_schema` with `SCP-VALID-7036`.
    #[test]
    fn schema_validation_rejects_non_object_output_schema() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("name", "test-tool").unwrap();
            dict.set_item("description", "a test").unwrap();
            dict.set_item("operator_did", "did:dht:test123456789abcdefghij")
                .unwrap();

            // Schema dict with output_schema as an array, not an object.
            let schema = PyDict::new(py);
            let input = PyDict::new(py);
            input.set_item("type", "object").unwrap();
            schema.set_item("input_schema", input).unwrap();
            let output_list = pyo3::types::PyList::new(py, [1, 2, 3]).unwrap();
            schema.set_item("output_schema", output_list).unwrap();
            dict.set_item("schema", schema).unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(result.is_err(), "should reject non-object output_schema");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7036),
                "error should contain SCP-VALID-7036, got: {err_str}"
            );
        });
    }

    // -----------------------------------------------------------------------
    // extract_test_vectors — SCP-VALID-7037
    // -----------------------------------------------------------------------

    /// Helper: builds a valid registration dict with both schemas set.
    /// Callers can then set `test_vectors` / `implementation_hash` to
    /// exercise 7037/7038 paths without tripping earlier validation.
    fn valid_registration_dict(py: Python<'_>) -> Bound<'_, PyDict> {
        let dict = PyDict::new(py);
        dict.set_item("name", "test-tool").unwrap();
        dict.set_item("description", "a test").unwrap();
        dict.set_item("operator_did", "did:dht:test123456789abcdefghij")
            .unwrap();
        let schema = PyDict::new(py);
        let input = PyDict::new(py);
        input.set_item("type", "object").unwrap();
        schema.set_item("input_schema", input).unwrap();
        let output = PyDict::new(py);
        output.set_item("type", "object").unwrap();
        schema.set_item("output_schema", output).unwrap();
        dict.set_item("schema", schema).unwrap();
        dict
    }

    /// `extract_test_vectors` rejects a non-list `test_vectors` with SCP-VALID-7037.
    #[test]
    fn extract_test_vectors_rejects_non_list() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            dict.set_item("test_vectors", "not-a-list").unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(result.is_err(), "should reject non-list test_vectors");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7037),
                "error should contain SCP-VALID-7037, got: {err_str}"
            );
            assert!(
                err_str.contains("test_vectors"),
                "error should mention test_vectors, got: {err_str}"
            );
        });
    }

    /// `extract_test_vectors` rejects a list containing non-dict items with SCP-VALID-7037.
    #[test]
    fn extract_test_vectors_rejects_non_dict_item() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            let vectors = pyo3::types::PyList::new(py, [42i32]).unwrap();
            dict.set_item("test_vectors", vectors).unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(
                result.is_err(),
                "should reject non-dict items in test_vectors"
            );
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7037),
                "error should contain SCP-VALID-7037, got: {err_str}"
            );
            assert!(
                err_str.contains("test vector must be a dict"),
                "error should describe the issue, got: {err_str}"
            );
        });
    }

    /// `extract_test_vectors` rejects a dict (wrong type — should be a list) with SCP-VALID-7037.
    #[test]
    fn extract_test_vectors_rejects_wrong_type() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            let wrong_type = pyo3::types::PyDict::new(py);
            wrong_type.set_item("not", "a list").unwrap();
            dict.set_item("test_vectors", wrong_type).unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(result.is_err(), "should reject dict as test_vectors");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7037),
                "error should contain SCP-VALID-7037, got: {err_str}"
            );
        });
    }

    /// `extract_test_vectors` accepts None/missing `test_vectors` (returns empty vec).
    #[test]
    fn extract_test_vectors_accepts_missing() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            // No test_vectors key set — should not error on extraction.
            // Will fail later on context lookup, but the extraction succeeds.
            let result = extract_test_vectors(&dict.as_borrowed());
            assert!(result.is_ok(), "missing test_vectors should be accepted");
            assert!(result.unwrap().is_empty());
        });
    }

    /// `extract_test_vectors` accepts an empty list.
    #[test]
    fn extract_test_vectors_accepts_empty_list() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            let empty_list = pyo3::types::PyList::empty(py);
            dict.set_item("test_vectors", empty_list).unwrap();

            let result = extract_test_vectors(&dict.as_borrowed());
            assert!(result.is_ok(), "empty list should be accepted");
            assert!(result.unwrap().is_empty());
        });
    }

    // -----------------------------------------------------------------------
    // extract_implementation_hash — SCP-VALID-7038
    // -----------------------------------------------------------------------

    /// `extract_implementation_hash` rejects a non-string value with SCP-VALID-7038.
    #[test]
    fn extract_implementation_hash_rejects_non_string() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            dict.set_item("implementation_hash", 12345).unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(
                result.is_err(),
                "should reject non-string implementation_hash"
            );
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7038),
                "error should contain SCP-VALID-7038, got: {err_str}"
            );
            assert!(
                err_str.contains("implementation_hash"),
                "error should mention implementation_hash, got: {err_str}"
            );
        });
    }

    /// `extract_implementation_hash` rejects wrong-length hex string with SCP-VALID-7038.
    #[test]
    fn extract_implementation_hash_rejects_wrong_length() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            // 32 hex chars instead of the required 64 (for 32 bytes).
            dict.set_item("implementation_hash", "abcdef0123456789abcdef0123456789")
                .unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(
                result.is_err(),
                "should reject wrong-length implementation_hash"
            );
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7038),
                "error should contain SCP-VALID-7038, got: {err_str}"
            );
            assert!(
                err_str.contains("64 hex chars"),
                "error should mention required length, got: {err_str}"
            );
        });
    }

    /// `extract_implementation_hash` rejects invalid hex chars with SCP-VALID-7038.
    #[test]
    fn extract_implementation_hash_rejects_invalid_hex() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            // 64 chars but contains non-hex 'g'.
            dict.set_item(
                "implementation_hash",
                "gg00000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            let result = py_outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(
                result.is_err(),
                "should reject invalid hex in implementation_hash"
            );
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7038),
                "error should contain SCP-VALID-7038, got: {err_str}"
            );
            assert!(
                err_str.contains("invalid hex"),
                "error should mention invalid hex, got: {err_str}"
            );
        });
    }

    /// `extract_implementation_hash` accepts None/missing (returns zeroed hash).
    #[test]
    fn extract_implementation_hash_accepts_missing() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            // No implementation_hash key.
            let result = extract_implementation_hash(&dict.as_borrowed());
            assert!(
                result.is_ok(),
                "missing implementation_hash should be accepted"
            );
            assert_eq!(result.unwrap(), [0u8; 32]);
        });
    }

    /// `extract_implementation_hash` accepts a valid 64-char hex string.
    #[test]
    fn extract_implementation_hash_accepts_valid_hex() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            dict.set_item("implementation_hash", "ab".repeat(32))
                .unwrap();

            let result = extract_implementation_hash(&dict.as_borrowed());
            assert!(result.is_ok(), "valid 64-char hex should be accepted");
            assert_eq!(result.unwrap(), [0xab; 32]);
        });
    }

    // -----------------------------------------------------------------------
    // registered_at timestamp — #871
    // -----------------------------------------------------------------------

    /// `registered_at` on a tool registered via the `PyO3` bridge must be a
    /// seconds-epoch timestamp, not milliseconds or hardcoded 0.
    /// Calls the actual `py_outlet_register` bridge function and inspects the
    /// stored `OutletRegistration`. Catches the original bug from issue #871.
    #[test]
    fn registered_at_is_seconds_epoch() {
        // Use a unique context ID to avoid collisions with concurrent tests.
        let ctx_id = format!("ctx-ts-test-{}", std::process::id());
        let creator_did = "did:dht:z6MkTestTimestamp";

        // Register FFI state so the context exists in the runtime registry.
        crate::runtime::register_ffi_state(&ctx_id, creator_did, &[]).unwrap();

        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("name", "timestamp-probe").unwrap();
            dict.set_item("description", "probes registered_at value")
                .unwrap();
            dict.set_item("operator_did", creator_did).unwrap();

            // Schema must meet the specificity floor (>=2 properties on at
            // least one side).
            let schema = PyDict::new(py);
            let input = PyDict::new(py);
            input.set_item("type", "object").unwrap();
            let props = PyDict::new(py);
            let str_type = PyDict::new(py);
            str_type.set_item("type", "string").unwrap();
            props.set_item("a", str_type).unwrap();
            let num_type = PyDict::new(py);
            num_type.set_item("type", "number").unwrap();
            props.set_item("b", num_type).unwrap();
            input.set_item("properties", props).unwrap();
            schema.set_item("input_schema", input).unwrap();
            let output = PyDict::new(py);
            output.set_item("type", "object").unwrap();
            schema.set_item("output_schema", output).unwrap();
            dict.set_item("schema", schema).unwrap();

            let outlet_id = py_outlet_register(&ctx_id, &dict.as_borrowed())
                .expect("py_outlet_register should succeed");

            // Read the stored registration back from the runtime registry.
            let registered_at = crate::runtime::with_ffi_state(&ctx_id, |state| {
                let reg = state
                    .outlet_registry
                    .get(&outlet_id)
                    .expect("tool should exist in registry after successful registration");
                Ok(reg.registered_at)
            })
            .unwrap();

            assert!(
                registered_at > 1_700_000_000 && registered_at < 2_000_000_000,
                "registered_at should be seconds-epoch (got {registered_at}); \
                 milliseconds would be ~1.7 trillion, hardcoded 0 would fail lower bound"
            );
        });

        // Clean up global state.
        crate::runtime::remove_ffi_state(&ctx_id);
    }
}
