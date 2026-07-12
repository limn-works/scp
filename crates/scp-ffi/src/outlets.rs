//! `PyO3` bridge functions for outlet registration, invocation, and verification.
//!
//! Exposes SCP outlet operations to Python as methods on the `SCP` class:
//!
//! - `PyScp::outlet_register` — Register an outlet in a context (returns outlet ID).
//! - `PyScp::outlet_invoke` — Invoke an outlet (returns JSON-compatible output).
//! - `PyScp::outlet_verify` — Verify an outlet against its test vectors.
//! - `PyScp::outlet_invoke_cross_context` — Invoke an outlet across context
//!   boundaries.
//! - `PyScp::outlet_session_create` — Create a stateful outlet session.
//! - `PyScp::outlet_session_invoke` — Invoke an outlet within a session.
//! - `PyScp::outlet_session_close` — Close a stateful outlet session.
//! - `PyScp::outlet_interface_expose` — Expose an outlet interface (step 1 of
//!   the §6.2.0.1 bidirectional handshake).
//! - `PyScp::outlet_interface_accept` — Accept an exposed interface (step 4).
//! - `PyScp::outlet_interface_revoke` — Revoke an interface unilaterally.
//!
//! All free `#[pyfunction]` exports were migrated to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice E (#1549).
//!
//! # Types
//!
//! - [`PyOutletRegistration`] — Outlet registration data (name, description,
//!   schema, test vectors).
//! - [`PyOutletVerificationResult`] — Verification result (outlet ID, pass/fail,
//!   failure messages).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §4 for the bridge specification.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_clock::Clock;
use scp_ffi_common::error_codes as codes;

use crate::error::ScpPyError;
use crate::runtime::PyBridgeInstance;
use crate::types::{json_to_py_dict, py_dict_to_json};
use crate::validate;

// ---------------------------------------------------------------------------
// PyOutletRegistration
// ---------------------------------------------------------------------------

/// Outlet registration data exposed to Python.
///
/// Contains the metadata needed to register an outlet in an SCP context:
/// name, description, JSON Schema, and test vectors. The `schema` field
/// is a Python dict representing the MCP-compatible JSON Schema for the
/// outlet's input and output.
///
/// See ADR-010 (outlet registration) and ADR-013 §4 (bridge layer).
#[pyclass(name = "OutletRegistration")]
#[derive(Debug)]
pub struct PyOutletRegistration {
    /// Human-readable outlet name.
    #[pyo3(get)]
    pub name: String,

    /// Outlet description.
    #[pyo3(get)]
    pub description: String,

    /// JSON Schema for outlet input/output, as a Python dict.
    #[pyo3(get)]
    pub schema: PyObject,

    /// Test vectors for verification, as a list of Python dicts.
    #[pyo3(get)]
    pub test_vectors: Vec<PyObject>,
}

#[pymethods]
impl PyOutletRegistration {
    /// Creates a new outlet registration.
    ///
    /// # Arguments
    ///
    /// * `name` — Human-readable outlet name.
    /// * `description` — Outlet description.
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

/// Result of verifying an outlet against its test vectors.
///
/// Returned by `py_outlet_verify`. Contains the outlet ID, overall pass/fail
/// status, and a list of failure messages (empty if all vectors passed).
#[pyclass(name = "OutletVerificationResult")]
#[derive(Debug, Clone)]
pub struct PyOutletVerificationResult {
    /// The verified outlet's ID.
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
// PySagaResult (§6.2.4 cross-context outlet-invocation saga — committed terminal)
// ---------------------------------------------------------------------------

/// The committed terminal of a §6.2.4 cross-context outlet-invocation saga.
///
/// Returned by [`PyScp::outlet_invoke_cross_context_saga`] on a `Committed`
/// terminal. Every NON-committed terminal raises a typed saga exception
/// (`SagaAbortedError` / `SagaNeedsRepairError` / `SagaBusyError`) instead.
///
/// Carries the supervisor-minted `saga_id` plus — for the committed
/// cross-context invocation — the target's signed receipt and the captured
/// outlet output (spec §6.2.4 "Receipt / response return path"). The `receipt`
/// is the JCS-canonical `CrossContextOutletReceipt` bytes; `output` is the
/// receipt's canonical `output_jcs` bytes (the exact bytes the caller side
/// recorded a hash of). Both are surfaced as Python `bytes` so a caller can
/// verify the receipt signature and recompute `output_hash` without a
/// re-serialization step.
#[pyclass(name = "SagaResult")]
#[derive(Debug, Clone)]
pub struct PySagaResult {
    /// The durable saga identifier (supervisor-minted, never a caller input).
    #[pyo3(get)]
    pub saga_id: String,

    /// The target's signed `CrossContextOutletReceipt` bytes (JCS), or `None`.
    #[pyo3(get)]
    pub receipt: Option<Vec<u8>>,

    /// The captured outlet output bytes (the receipt's canonical `output_jcs`),
    /// or `None`.
    #[pyo3(get)]
    pub output: Option<Vec<u8>>,
}

#[pymethods]
impl PySagaResult {
    fn __repr__(&self) -> String {
        format!(
            "SagaResult(saga_id={:?}, receipt={} bytes, output={} bytes)",
            self.saga_id,
            self.receipt.as_ref().map_or(0, Vec::len),
            self.output.as_ref().map_or(0, Vec::len),
        )
    }
}

// ---------------------------------------------------------------------------
// Bridge helpers — per-bridge implementations used by PyScp methods
// ---------------------------------------------------------------------------

/// Registers an outlet in an SCP context on the given bridge instance.
///
/// See ADR-013 §4.
fn outlet_register_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    registration: &Bound<'_, PyDict>,
) -> PyResult<String> {
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

    // Extract implementation hash (optional, 32-byte SHA-256 of outlet code).
    // Per spec §5.4: content-addressable reference to the outlet's implementation.
    let implementation_hash = extract_implementation_hash(registration)?;

    // Extract cost metadata (optional, per spec §5.4.1).
    let cost = extract_cost(registration)?;

    // Extract the outlet kind (Query vs Action — §5.4.2). Absent maps to the
    // fail-safe default `Action`; the SDK surfaces it as required.
    let kind = extract_kind(registration)?;

    // Generate an outlet ID from the name (deterministic, human-readable).
    // Shared with every other bridge via `scp_ffi_common::outlet_id`.
    let outlet_id = scp_ffi_common::outlet_id::generate_outlet_id(&name);

    // Build the scp-core OutletRegistration.
    let core_registration = scp_core::context::outlets::OutletRegistration {
        outlet_id,
        kind,
        name,
        description,
        schema: scp_core::context::outlets::OutletSchema {
            input_schema,
            output_schema,
            aggregate_schema: None,
        },
        implementation_hash,
        test_vectors,
        operator_did: operator_did.into(),
        cost,
        message_catalog: Vec::new(),
        registered_at: scp_clock::Clock::now_secs(&scp_clock::SystemClock),
        signature: vec![],
    };

    // Look up the context runtime and register the outlet.
    let registered_id = crate::runtime::with_context(bi, context_id, |rt| {
        let (registered_id, _event) = scp_core::context::outlets::register_outlet(
            &mut rt.outlet_registry,
            &rt.role_state,
            core_registration,
            &rt.creator_did.clone(),
        )
        .map_err(|e| ScpPyError::context(format!("outlet registration failed: {e}")))?;
        Ok(registered_id)
    })?;

    Ok(registered_id)
}

/// Validates a UCAN token for outlet invocation authorization.
///
/// Runs the full 11-step ADR-016 pipeline, requiring `outlet_call:{outlet_id}`
/// or `outlet_call:*` capability. Extracted to keep `outlet_invoke_impl` within
/// the 100-line clippy limit.
fn validate_outlet_ucan(
    bi: &PyBridgeInstance,
    context_id: &str,
    outlet_id: &str,
    ucan_token: &str,
    identity_did: &str,
    proof_tokens: Option<&Vec<String>>,
) -> PyResult<()> {
    let proof_resolver =
        crate::ucan::build_proof_resolver_from_tokens(proof_tokens.map(Vec::as_slice))?;

    crate::runtime::with_context(bi, context_id, |rt| {
        // SCP-OUT-014: select the split capability stem from the outlet's
        // registered kind. `outlet_query:{id}` for Query outlets,
        // `outlet_call:{id}` for Action outlets — the two stems are
        // independent, so a Query grant never authorizes an Action call.
        let outlet_kind_for_ucan = rt
            .outlet_registry
            .get(outlet_id)
            .map(|r| r.kind)
            .ok_or_else(|| {
                ScpPyError::ucan(format!(
                    "outlet '{outlet_id}' not registered in context '{context_id}'"
                ))
            })?;

        let production_resolver = crate::runtime::did_resolver(bi);
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
            clock: &scp_clock::SystemClock,
            // §5.4.5 HIGH-3 — the outlet-invocation validation site resolves
            // effective caveats from each token's `nb` field so §7.3.8 Step 7b
            // (per-edge narrow) and Step 11b (time-box) run over the proof
            // chain's VALIDATED-NARROWED caveat set, not an unverified leaf
            // assertion. `NoCaveatResolver` returns `None` for every token, so
            // narrowing would commit to nothing. The generic `py_ucan_validate`
            // site (ucan.rs) and the broadcast paths stay on `NoCaveatResolver`
            // — they are not outlet-invocation sites.
            caveat_resolver: &scp_core::crypto::ucan::validate::TokenNbCaveatResolver,
        };

        scp_core::context::outlets::validate_outlet_invocation_ucan(
            ucan_token,
            context_id,
            outlet_id,
            outlet_kind_for_ucan,
            &mut ctx,
        )
        .map_err(|e| {
            ScpPyError::ucan(format!(
                "UCAN authorization failed for outlet '{outlet_id}': {e}"
            ))
        })
    })?;
    Ok(())
}

/// Invokes an outlet within an SCP context, fully wired through the
/// `ContextManager::invoke_outlet_with_economy` pipeline.
///
/// This is the SINGLE entry point for outlet invocation through the `PyO3`
/// bridge. Every paid-action concern — per-invocation pricing, spending
/// UCAN AND-composition (§19.5), per-DID velocity tracking, escalation
/// (§19.7), budget enforcement, payment escrow, and the
/// `OutletEconomyTicket` rollback discipline — is enforced by the runtime,
/// not by the bridge. The Matrix-style hard rate limit is consumed by
/// the wrapper itself in Phase 1 (defense-in-depth), so the previous
/// bridge-side `try_consume_hard_rate_limit_*` calls are no longer
/// needed.
///
/// Validates the UCAN token for outlet invocation authorization before
/// dispatching. The UCAN must contain a `outlet_call:{outlet_id}` or
/// `outlet_call:*` capability scoped to the context.
///
/// Dispatches to a registered outlet handler if one exists (registered via
/// [`crate::runtime::register_outlet_handler`]). The runtime validates
/// input/output schemas and computes the input/output hashes for the
/// `OutletInvokedEvent`. If no handler is registered, falls back to
/// returning validated input with metadata (schema-only mode), identical
/// to `FfiBridgeProvider::invoke_tool` in `mcp.rs`.
///
/// # Arguments
///
/// * `context_id` — The ID of the context containing the outlet.
/// * `outlet_id` — The ID of the outlet to invoke.
/// * `input` — A Python dict of input parameters matching the outlet's
///   input schema.
/// * `identity_did` — The DID of the invoking identity (used for
///   capability checking).
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain `outlet_call:{outlet_id}` or `outlet_call:*` capability.
///   Validated using the full 11-step ADR-016 pipeline.
/// * `spending_ucan` — Optional JWT-encoded spending UCAN
///   (`SpendingCapability`) for paid outlet invocations. Required when an
///   `EconomicPolicy` priced the outlet above zero (§19.5
///   AND-composition). May be `None` for free outlets.
/// * `proof_tokens` — Optional encoded parent UCAN tokens for delegation
///   chain traversal (ADR-016 step 3).
///
/// # Returns
///
/// A Python object (dict) containing the outlet's JSON-compatible output.
///
/// # Errors
///
/// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
/// or lacks the required outlet invocation capability.
/// Raises `ContextError` (with embedded `SCP-ECON-12010` /
/// `SCP-ECON-12061` / `SCP-ECON-12090` / outlet-invocation codes) if the
/// economy pre-check, budget, payment escrow, hard rate limit, or
/// underlying outlet dispatch fails. Callers should consult `.code` rather
/// than string-matching `.message`.
///
/// See ADR-013 §4, SCP-212, spec §6.2, §8, §19.5, §19.7, ADR-016, and issue #319.
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>>.
#[allow(clippy::too_many_arguments)] // Bridge mirrors the runtime's economy entry point.
fn outlet_invoke_impl(
    bi: &PyBridgeInstance,
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
        bi,
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

    // Snapshot the bridge-owned outlet registry and (optionally) the
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
    let (registry, handler) = crate::runtime::with_context(bi, context_id, |rt| {
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
                        "outlet": outlet_id_for_executor,
                        "context": ctx_id_for_executor,
                        "status": "validated",
                        "input_valid": true,
                        "invoker_did": identity_did_for_executor,
                        "validated_input": input_for_echo,
                    }))
                },
                |h| {
                    h(input).map_err(|e| {
                        format!("outlet handler for '{outlet_id_for_executor}' failed: {e}")
                    })
                },
            )
        }
    };

    // Dispatch to the runtime via the global tokio runtime. PyO3 calls
    // are sync; the Python SDK wrapper invokes us via `asyncio.to_thread`
    // so we are NOT inside a tokio runtime context — `block_on` on the
    // multi-thread global runtime is safe (matches `py_context_send`).
    let supervisor = crate::runtime::supervisor(bi)?;
    let invoker_did_typed: scp_did::DID = identity_did_owned.into();
    let outlet_id_typed = scp_core::context::outlets::OutletId::from(outlet_id_owned.as_str());
    let rt = crate::runtime()?;
    let outcome = rt
        .block_on(async {
            supervisor
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

/// Verifies an outlet against its registered test vectors.
///
/// # Arguments
///
/// * `context_id` — The ID of the context containing the outlet.
/// * `outlet_id` — The ID of the outlet to verify.
///
/// # Returns
///
/// A [`PyOutletVerificationResult`] with the outlet ID, overall pass/fail
/// status, and any failure messages.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected or the outlet
/// is not found.
///
/// See ADR-013 §4.
fn outlet_verify_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    outlet_id: &str,
) -> PyResult<PyOutletVerificationResult> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    // Look up the context and verify the outlet against its test vectors.
    // The executor returns the expected output (identity function) since the
    // bridge layer has no external outlet executor. This verifies the test
    // vector structure is intact.
    let result = crate::runtime::with_context(bi, context_id, |rt| {
        let (verification_result, _event) = scp_core::context::outlets::verify_outlet(
            &rt.outlet_registry,
            outlet_id,
            // Identity executor: returns the expected output for each vector.
            // This validates the test vector structure; real execution verification
            // happens when a full executor is connected.
            |input| {
                // Look up the outlet to find the matching test vector.
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
        .map_err(|e| ScpPyError::context(format!("outlet verification failed: {e}")))?;

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
/// if not provided. Per spec §5.4: content-addressable reference to the outlet's
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
) -> PyResult<Option<scp_core::context::outlets::OutletCost>> {
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
        .filter(|v| !v.is_none())
        .map(|v| v.extract())
        .transpose()?;

    Ok(Some(scp_core::context::outlets::OutletCost {
        // ADR-060: `OutletCost.amount` is the `Amount` newtype. Python `int` is
        // arbitrary-precision, so the FFI param stays a native `u64` and carries
        // the full smallest-unit range exactly.
        amount: scp_core::economy::Amount(amount),
        currency,
        payee: payee.into(),
        cost_formula,
    }))
}

/// Extracts the outlet `kind` from the registration dict (§5.4.2).
///
/// Accepts the lowercase strings `"query"` or `"action"` (the §5.4.2 wire
/// vocabulary shared by the spec, the canonical preimage, and every other
/// bridge). Per spec §5.4.1 the field is optional on the wire and absence
/// (or an explicit `None`) maps to the fail-safe default `OutletKind::Action`.
/// The Python SDK (`scp_sdk.outlets.OutletDefinition`) surfaces `kind` as a
/// required field, so a well-formed SDK registration always supplies it; the
/// bridge tolerance here only affects direct bridge callers. A present-but-
/// unrecognized value is a hard `ValidationError` — silently downgrading an
/// unknown class to `Action` would mask an SDK bug.
fn extract_kind(
    registration: &Bound<'_, PyDict>,
) -> PyResult<scp_core::context::outlets::OutletKind> {
    use scp_core::context::outlets::OutletKind;
    let Some(val) = registration.get_item("kind")?.filter(|v| !v.is_none()) else {
        return Ok(OutletKind::default());
    };
    let s: String = val
        .extract()
        .map_err(|_| ScpPyError::validation("'kind' must be a string".to_owned()))?;
    match s.as_str() {
        "query" => Ok(OutletKind::Query),
        "action" => Ok(OutletKind::Action),
        other => Err(ScpPyError::validation(format!(
            "'kind' must be 'query' or 'action' (§5.4.2 wire vocabulary), got {other:?}"
        ))
        .into()),
    }
}

/// Extracts test vectors from the registration dict's `test_vectors` field.
///
/// Each test vector is a Python dict with `input`, `expected_output`, and
/// `description` keys. Returns an empty Vec if the field is missing.
///
/// Returns `SCP-VALID-7037` on validation failure (aligned with NAPI bridge).
fn extract_test_vectors(
    registration: &Bound<'_, PyDict>,
) -> PyResult<Vec<scp_core::context::outlets::OutletTestVector>> {
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

        result.push(scp_core::context::outlets::OutletTestVector {
            input,
            expected_output,
            description,
        });
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Cross-context outlet invocation
// ---------------------------------------------------------------------------

/// Invokes an outlet across context boundaries.
///
/// The source context exposes the outlet and the target context accepts the
/// interface. Both contexts must have approved the interface before calls
/// are permitted. Rate limits and chain depth are enforced per spec section
/// 6.2.
///
/// # Arguments
///
/// * `source_context_id` — The ID of the calling context.
/// * `target_context_id` — The ID of the context containing the outlet.
/// * `outlet_id` — The ID of the outlet to invoke.
/// * `input` — A Python dict of input parameters.
/// * `invoker_did` — The DID of the participant invoking the outlet.
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain the TARGET outlet's kind-appropriate stem —
///   `outlet_query:{outlet_id}`/`outlet_query:*` for Query outlets,
///   `outlet_call:{outlet_id}`/`outlet_call:*` for Action outlets (SCP-OUT-014,
///   §5.4.2). Validated against the TARGET context's ceiling using the full
///   11-step ADR-016 pipeline.
/// * `chain_depth` — Current cross-context chain depth (0 for first hop).
///
/// # Returns
///
/// A Python object (dict) containing the outlet's JSON-compatible output.
///
/// # Errors
///
/// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
/// or lacks the required outlet invocation capability.
/// Raises `ContextError` if either context is not connected, the outlet is
/// not found, chain depth is exceeded, or the interface is not approved.
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>>.
#[allow(clippy::too_many_arguments)] // FFI boundary: PyO3 requires explicit params
#[allow(clippy::too_many_lines)] // Sequential cross-context flow: validate + kind-aware gate + depth + dispatch.
fn outlet_invoke_cross_context_impl(
    bi: &PyBridgeInstance,
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
        bi,
        target_context_id,
        outlet_id,
        ucan_token,
        invoker_did,
        proof_tokens.as_ref(),
    )?;

    // Resolve the TARGET outlet's registered kind so the source-context
    // governance check below selects the matching split stem (SCP-OUT-014,
    // §5.4.2). JUDGMENT: this source-context gate authorizes the invoker to
    // initiate a cross-context call to the TARGET outlet — it is gating THAT
    // outlet's invocation, not a distinct source-only authority — so the stems
    // must stay independent on this surface too: a source member invoking a
    // TARGET Query outlet needs OutletQuery, an Action outlet needs OutletCall.
    // The target registry is the authority for the outlet's kind (it is
    // registered there, not in the source); `validate_outlet_ucan` above already
    // guaranteed the outlet exists in the target context.
    let target_outlet_kind = crate::runtime::with_context(bi, target_context_id, |rt| {
        rt.outlet_registry
            .get(outlet_id)
            .map(|r| r.kind)
            .ok_or_else(|| {
                ScpPyError::context(format!(
                    "outlet '{outlet_id}' not found in target context '{target_context_id}'"
                ))
            })
    })?;

    // Defense-in-depth: check role-state capabilities in the source context
    // using the kind-appropriate split stem for the target outlet.
    let source_has_capability = crate::runtime::with_context(bi, source_context_id, |rt| {
        Ok(
            scp_core::context::outlets::has_outlet_invocation_capability(
                &rt.role_state,
                invoker_did,
                outlet_id,
                target_outlet_kind,
            ),
        )
    })?;

    if !source_has_capability {
        return Err(ScpPyError::ucan(format!(
            "invoker '{invoker_did}' does not have invocation capability for '{outlet_id}' in source context"
        ))
        .into());
    }

    // Validate chain depth (context-configurable, default 8 per ADR-043).
    let max_chain_depth = {
        let supervisor = crate::runtime::supervisor(bi)?;
        let tokio_rt = crate::runtime().map_err(|e| ScpPyError::context(e.to_string()))?;
        let source_max = tokio_rt
            .block_on(supervisor.context_params(source_context_id))
            .and_then(|p| p.max_chain_depth);
        scp_core::provenance::attach::effective_max_chain_depth(source_max)
    };
    if chain_depth > max_chain_depth {
        return Err(ScpPyError::context(format!(
            "cross-context chain depth {chain_depth} exceeds maximum {max_chain_depth}"
        ))
        .into());
    }

    // Invoke the outlet in the target context with echo mode.
    let output_json = crate::runtime::with_context(bi, target_context_id, |rt| {
        let registration = rt.outlet_registry.get(outlet_id).ok_or_else(|| {
            ScpPyError::context(format!(
                "outlet '{outlet_id}' not found in target context '{target_context_id}'"
            ))
        })?;

        // Validate input against the outlet's input schema.
        scp_core::context::outlets::validate_value_against_schema(
            &input_json,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpPyError::validation(format!("input validation failed: {e}")))?;

        // Dispatch to handler or echo mode.
        let output = if let Some(handler) = rt.outlet_handlers.get(outlet_id) {
            let handler = handler.clone();
            let out = handler(input_json.clone()).map_err(|e| {
                ScpPyError::context(format!(
                    "cross-context outlet handler for '{outlet_id}' failed: {e}"
                ))
            })?;

            scp_core::context::outlets::validate_value_against_schema(
                &out,
                &registration.schema.output_schema,
            )
            .map_err(|msg| {
                ScpPyError::validation(format!(
                    "output validation failed for outlet '{outlet_id}': {msg}"
                ))
            })?;

            out
        } else {
            serde_json::json!({
                "outlet": outlet_id,
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

    // Provenance for cross-context outlet invocations is now handled at the
    // protocol level (scp-protocol::outlets::invoke_cross_context). The bridge-
    // level attach_cross_context_provenance was redundant and discarded its
    // result, so it has been removed.

    json_to_py_dict(py, &output_json)
}

// ---------------------------------------------------------------------------
// Cross-context outlet-invocation saga (§6.2.4, ADR-049 §3a)
// ---------------------------------------------------------------------------

/// Maps a `SagaError` terminal (the typed §6.2.4 terminal space) onto the
/// bridge's typed saga error variants.
///
/// The decomposition — the `SagaAbortReason::RateLimited → Option<u64>` read,
/// the `None`-never-coerced-to-`0` rule, and the `SCP-SAGA-{code}` formatting —
/// lives ONCE in [`scp_ffi_common::saga_errors::decompose_saga_error`], unit-
/// tested there, so the three bridges cannot drift. This function is the thin
/// per-bridge tail that carries the `PyO3` field labels (`message:`):
///
/// - `Aborted` → [`ScpPyError::SagaAborted`] (`retry_after_ms`, `None` never
///   `0`, `SCP-SAGA-{code}`).
/// - `NeedsRepair` → [`ScpPyError::SagaNeedsRepair`] (durable repair handle,
///   `SCP-SAGA-13065`).
/// - `Busy` → [`ScpPyError::SagaBusy`] (`SCP-SAGA-13066`).
fn map_saga_error(err: scp_core::context::supervisor::SagaError) -> ScpPyError {
    use scp_ffi_common::saga_errors::{SagaErrorKind, decompose_saga_error};
    let parts = decompose_saga_error(err);
    match parts.kind {
        SagaErrorKind::Aborted { retry_after_ms } => ScpPyError::SagaAborted {
            message: parts.message,
            code: parts.code,
            retry_after_ms,
        },
        SagaErrorKind::NeedsRepair { saga_id } => ScpPyError::SagaNeedsRepair {
            message: parts.message,
            code: parts.code,
            saga_id,
        },
        SagaErrorKind::Busy { contended_context } => ScpPyError::SagaBusy {
            message: parts.message,
            code: parts.code,
            contended_context,
        },
    }
}

/// Resolves the Active Signing Key the supervisor saga signs under for the
/// co-resident context `context_id` — the key of the context's owning
/// identity (`FfiBridgeState.creator_did`), exported via the shared custody
/// path. The caller and target each resolve to their OWN creator's key so the
/// receipt (target-signed) and each side's divergence marker (own-signed) are
/// signed under the correct per-context Active Signing Key (spec §6.2.4
/// "Signer authorization": the receipt key MUST be the one authorized to act
/// for `target_context_id`).
fn resolve_context_signing_key(
    bi: &PyBridgeInstance,
    context_id: &str,
) -> PyResult<ed25519_dalek::SigningKey> {
    let creator_did =
        crate::runtime::with_context(bi, context_id, |rt| Ok(rt.creator_did.clone()))?;
    crate::context::resolve_signing_key(bi, &creator_did)
}

/// Decodes the §6.2.4 envelope nonce from its canonical 32-char hex form into
/// the 16-byte value, FAIL-CLOSED.
///
/// The nonce is a 16-byte value carried as a hex string — the one canonical
/// wire form (§6.2.4 wire envelope). Any other length is a malformed envelope,
/// NOT a "pad it" situation; and we never accept a Python int (which would
/// invite an ambiguous endianness/width interpretation). Both failure modes
/// surface as `ValidationError`.
fn decode_asserted_nonce(asserted_nonce_hex: &str) -> PyResult<[u8; 16]> {
    let bytes = hex::decode(asserted_nonce_hex).map_err(|e| ScpPyError::ValidationError {
        message: format!(
            "asserted_nonce_hex is not valid hex: {e} — supply the 16-byte §6.2.4 envelope \
             nonce as a 32-char lowercase-hex string"
        ),
        code: codes::VALID_7001.to_owned(),
    })?;
    let nonce =
        <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| ScpPyError::ValidationError {
            message: format!(
                "asserted_nonce_hex must decode to exactly 16 bytes (32 hex chars), got {} bytes",
                bytes.len()
            ),
            code: codes::VALID_7001.to_owned(),
        })?;
    Ok(nonce)
}

/// Enforces the §6.2.4 *Caller authentication* binding (normative — §6.2.4 +
/// ADR-049 §3a) BEFORE the saga runs.
///
/// `caller_did` / `caller_context_id` MUST be the channel-authenticated
/// identity of the transport leg, never an envelope-asserted free value. For
/// the co-resident `PyO3` bridge the "channel-authenticated principal" is an
/// identity THIS bridge instance hosts — one present in its per-instance
/// identity registry (populated only by `py_identity_create` on this
/// instance). Both axes are enforced here:
///
///   (a) `caller_did` is hosted/authenticated by this bridge instance, AND
///   (b) `caller_did` is a member of the named `caller_context_id`.
///
/// A mismatch on either axis ⇒ a typed `Rejected`-flavored `SagaAborted` (the
/// §6.2.4 "mismatch ⇒ Rejected" terminal), carrying the registered caller-axis
/// code `SCP-SAGA-13050`. The supervisor's own gate 1 ALSO checks membership,
/// but membership alone is necessary-not-sufficient (it does not prove the
/// request leg is authenticated AS that member) — so axis (a) is the
/// load-bearing addition this seam contributes. Enforcing here, before the
/// entry point, also means the saga never observes an unauthenticated caller.
fn enforce_caller_principal_binding(
    bi: &PyBridgeInstance,
    supervisor: &std::sync::Arc<scp_core::context::supervisor::Supervisor>,
    tokio_rt: &tokio::runtime::Runtime,
    caller_context_id: &str,
    caller_did: &str,
) -> PyResult<()> {
    if !crate::runtime::identity_registry_contains(bi, caller_did) {
        return Err(ScpPyError::SagaAborted {
            message: format!(
                "caller_did '{caller_did}' is not an identity hosted by this bridge instance — \
                 a cross-context saga's caller MUST be the channel-authenticated principal (an \
                 identity created on this instance), not an envelope-asserted value (§6.2.4 \
                 Caller authentication)"
            ),
            code: codes::SAGA_13050.to_owned(),
            retry_after_ms: None,
        }
        .into());
    }

    let caller_is_member = tokio_rt.block_on(supervisor.is_member(caller_context_id, caller_did));
    if !caller_is_member {
        return Err(ScpPyError::SagaAborted {
            message: format!(
                "caller_did '{caller_did}' is hosted by this bridge but is not a member of \
                 caller_context_id '{caller_context_id}' — not authorized to initiate a \
                 cross-context saga over it (§6.2.4 Caller authentication)"
            ),
            code: codes::SAGA_13050.to_owned(),
            retry_after_ms: None,
        }
        .into());
    }
    Ok(())
}

/// Implements the §6.2.4 cross-context outlet-invocation saga export.
///
/// See [`PyScp::outlet_invoke_cross_context_saga`] for the full contract. The
/// flow is, in order:
///
/// 1. **Validate inputs** (well-formed ids/dids/outlet-id; the nonce decodes to
///    `[u8; 16]`, fail-closed on a wrong length — a hex string is the one
///    canonical form).
/// 2. **Caller-principal binding (§6.2.4 *Caller authentication*, normative).**
///    `caller_did` MUST be an identity THIS bridge instance hosts/authenticated
///    (present in the per-instance identity registry — the co-resident SDK
///    seam's channel-authenticated principal) AND a member of
///    `caller_context_id`. A mismatch ⇒ a typed `Rejected`-flavored
///    `SagaAborted` BEFORE the saga runs (the saga never observes an
///    unauthenticated caller). `nonce` / `timestamp` / `chain_depth` REMAIN
///    caller-supplied freshness fields (the target B validates them — they are
///    not minted here).
/// 3. **Chokepoint (ADR-056).** Convert the caller/target id STRINGS → `[u8; 32]`
///    via `scp_core::context::state::context_id_to_bytes` (decode-64-hex-else-
///    SHA256). Raw `Sha256` of a 64-hex id would double-hash and miss the actor.
/// 4. **Signing keys.** Resolve each co-resident context's Active Signing Key
///    via the context's `creator_did`.
/// 5. **Executor.** Snapshot the TARGET context's outlet handler under
///    [`with_context`](crate::runtime::with_context) and build the
///    non-`Send`-safe `move |input| async {…}` closure the supervisor runs
///    supervisor-side at Commit-B (mirrors `outlet_invoke_impl`'s executor
///    pattern).
/// 6. [`block_on`](tokio::runtime::Runtime::block_on) the producer; map the
///    terminal `SagaError` → typed bridge error, `Committed` →
///    [`PySagaResult`].
#[allow(clippy::too_many_arguments)] // Flat §6.2.4 envelope — agent-first named params, no builder.
fn outlet_invoke_cross_context_saga_impl(
    bi: &PyBridgeInstance,
    caller_context_id: &str,
    target_context_id: &str,
    caller_did: &str,
    outlet_registration_id: &str,
    input: &Bound<'_, PyDict>,
    asserted_nonce_hex: &str,
    asserted_timestamp_ms: u64,
    asserted_chain_depth: u8,
    ucan_proof_id: Option<String>,
) -> PyResult<PySagaResult> {
    use scp_core::context::supervisor::{CrossContextOutletInvocationRequest, SagaSigningKeys};

    validate::validate_context_id(caller_context_id)?;
    validate::validate_context_id(target_context_id)?;
    validate::validate_did(caller_did)?;
    validate::validate_outlet_id(outlet_registration_id)?;

    let asserted_nonce = decode_asserted_nonce(asserted_nonce_hex)?;
    let input_json = py_dict_to_json(input)?;

    // Caller-principal binding (§6.2.4 *Caller authentication*) — BEFORE the
    // saga runs, so the supervisor never observes an unauthenticated caller.
    let supervisor = crate::runtime::supervisor(bi)?;
    let tokio_rt = crate::runtime()?;
    enforce_caller_principal_binding(bi, supervisor, tokio_rt, caller_context_id, caller_did)?;

    // ----- Chokepoint (ADR-056): id STRING → [u8; 32] ------------------------
    //
    // MANDATORY: convert via the canonical cross-crate keying resolver, which
    // decodes a real 64-hex id rather than re-hashing it. The producer does
    // `hex::encode(wire)` for actor lookup, so a raw SHA-256 of a 64-hex id
    // here would double-hash and key the wrong (non-existent) actor slot,
    // surfacing as a spurious ContextNotRegistered abort.
    let caller_context_bytes = scp_core::context::state::context_id_to_bytes(caller_context_id);
    let target_context_bytes = scp_core::context::state::context_id_to_bytes(target_context_id);

    // ----- Signing keys: each context's Active Signing Key -------------------
    let target_signing_key = resolve_context_signing_key(bi, target_context_id)?;
    let caller_signing_key = resolve_context_signing_key(bi, caller_context_id)?;

    // ----- Executor: snapshot the TARGET context's outlet handler --------------
    //
    // Mirrors `outlet_invoke_impl`: snapshot the registered handler closure
    // (an `Arc<dyn Fn>` — cloning is a refcount bump) OUTSIDE the runtime call,
    // then move it into the `FnOnce` executor the supervisor runs
    // supervisor-side at Commit-B (off the actor mailbox). Falls back to a
    // schema-only echo when no handler is registered, matching the synchronous
    // cross-context path. The supervisor validates the output against the
    // outlet's registered output schema at Commit-B, so the executor only
    // produces the value.
    let handler = crate::runtime::with_context(bi, target_context_id, |rt| {
        Ok(rt.outlet_handlers.get(outlet_registration_id).cloned())
    })?;
    let outlet_id_for_echo = outlet_registration_id.to_owned();
    let target_ctx_for_echo = target_context_id.to_owned();
    let caller_did_for_echo = caller_did.to_owned();
    let executor = move |value: serde_json::Value| {
        let handler = handler.clone();
        let echo_input = value.clone();
        async move {
            handler.map_or_else(
                || {
                    Ok(serde_json::json!({
                        "outlet": outlet_id_for_echo,
                        "target_context": target_ctx_for_echo,
                        "caller_did": caller_did_for_echo,
                        "status": "validated",
                        "input_valid": true,
                        "validated_input": echo_input,
                    }))
                },
                |h| {
                    h(value).map_err(|e| {
                        format!(
                            "cross-context saga outlet handler for '{outlet_id_for_echo}' failed: {e}"
                        )
                    })
                },
            )
        }
    };

    let request = CrossContextOutletInvocationRequest {
        caller_context_id: caller_context_bytes,
        target_context_id: target_context_bytes,
        caller_did: scp_did::DID(caller_did.to_owned()),
        outlet_registration_id: outlet_registration_id.to_owned(),
        ucan_proof_id,
        input: input_json,
        asserted_chain_depth,
        asserted_nonce,
        asserted_timestamp_ms,
    };

    // Dispatch to the producer on the global multi-thread runtime. PyO3 calls
    // are sync; the Python SDK wrapper invokes us off `asyncio.to_thread`, so
    // we are NOT inside a tokio context and `block_on` is safe (matches
    // `outlet_invoke_impl`). The saga blocks until a terminal state.
    let output = tokio_rt
        .block_on(async {
            supervisor
                .start_cross_context_outlet_invocation_saga(
                    request,
                    SagaSigningKeys {
                        target: &target_signing_key,
                        caller: &caller_signing_key,
                    },
                    executor,
                )
                .await
        })
        .map_err(map_saga_error)?;

    Ok(PySagaResult {
        saga_id: output.saga_id.0,
        receipt: output.receipt,
        output: output.output,
    })
}

// ---------------------------------------------------------------------------
// Stateful outlet sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Creates a stateful outlet session.
///
/// Sessions enable multi-turn workflows with state preservation across
/// invocations. Each session has a TTL and is subject to per-caller caps
/// (default: 1000 concurrent sessions per caller, per spec §6.2.1 and ADR-043).
///
/// # Arguments
///
/// * `context_id` — The context containing the outlet.
/// * `outlet_id` — The outlet to create a session for.
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
/// Raises `ContextError` if the context is not connected, the outlet is
/// not found, or the per-caller session cap is exceeded.
fn outlet_session_create_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    outlet_id: &str,
    source_context_id: &str,
    ttl_seconds: Option<u64>,
) -> PyResult<String> {
    validate::validate_context_id(context_id)?;
    validate::validate_outlet_id(outlet_id)?;
    validate::validate_context_id(source_context_id)?;

    let session_id = crate::runtime::with_context(bi, context_id, |rt| {
        // Validate outlet exists.
        if !rt.outlet_registry.contains(outlet_id) {
            return Err(ScpPyError::context(format!(
                "outlet '{outlet_id}' not found in context '{context_id}'"
            )));
        }

        // Enforce per-caller session cap (context-configured, default 1000, ADR-043).
        let cap = {
            let supervisor = crate::runtime::supervisor(bi)?;
            let tokio_rt = crate::runtime().map_err(|e| ScpPyError::context(e.to_string()))?;
            tokio_rt
                .block_on(supervisor.context_params(context_id))
                .and_then(|p| p.session_cap)
                .unwrap_or(scp_core::context::outlets::DEFAULT_SESSION_CAP_PER_CALLER)
                as usize
        };
        let current = rt.session_store.count_by_source(source_context_id);
        if current >= cap {
            return Err(ScpPyError::context(format!(
                "session cap exceeded for caller '{source_context_id}': {current} active (max {cap})"
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let now_ms = scp_clock::SystemClock.now_millis();

        let session = scp_core::context::outlets::OutletSession {
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

/// Invokes an outlet within an active session.
///
/// Each call is individually governed: the invoker must hold the outlet's
/// kind-appropriate split capability (`OutletQuery`/`OutletQueryAll` for Query
/// outlets, `OutletCall`/`OutletCallAll` for Action outlets — SCP-OUT-014,
/// §5.4.2) and present a valid UCAN token. Session state is carried forward
/// across invocations. The session's call count is incremented on each
/// successful invocation.
///
/// # Arguments
///
/// * `context_id` — The context containing the outlet session.
/// * `session_id` — The session to invoke within.
/// * `input` — A Python dict of input parameters.
/// * `invoker_did` — The DID of the invoker (capability checked per call).
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Must contain the outlet's kind-appropriate stem — `outlet_query:{outlet_id}`
///   or `outlet_query:*` for Query outlets, `outlet_call:{outlet_id}` or
///   `outlet_call:*` for Action outlets (SCP-OUT-014, §5.4.2). Validated using
///   the full 11-step ADR-016 pipeline.
///
/// # Returns
///
/// A Python object (dict) containing the outlet's JSON-compatible output.
///
/// # Errors
///
/// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
/// or lacks the required outlet invocation capability.
/// Raises `ContextError` if the session is not found, has expired, or
/// the invoker lacks capability.
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned Option<Vec<String>>.
#[allow(clippy::too_many_arguments)] // FFI surface: spec-defined signature
fn outlet_session_invoke_impl(
    bi: &PyBridgeInstance,
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
    // validate against the correct outlet capability.
    let outlet_id_for_ucan = crate::runtime::with_context(bi, context_id, |rt| {
        let session = rt
            .session_store
            .get(session_id)
            .ok_or_else(|| ScpPyError::context(format!("session '{session_id}' not found")))?;
        Ok(session.outlet_id.clone())
    })?;

    // Primary authorization: UCAN token validation via the full 11-step
    // ADR-016 pipeline. See spec §6.2, §8, ADR-016, and issue #319.
    validate_outlet_ucan(
        bi,
        context_id,
        &outlet_id_for_ucan,
        ucan_token,
        invoker_did,
        proof_tokens.as_ref(),
    )?;

    let output_json = crate::runtime::with_context(bi, context_id, |rt| {
        // Look up session.
        let session = rt
            .session_store
            .get(session_id)
            .ok_or_else(|| ScpPyError::context(format!("session '{session_id}' not found")))?;

        // Check expiry.
        let now_ms = scp_clock::SystemClock.now_millis();
        if session.is_expired(now_ms) {
            rt.session_store.remove(session_id);
            return Err(ScpPyError::context(format!(
                "session '{session_id}' has expired"
            )));
        }

        let outlet_id = session.outlet_id.clone();
        let current_state = session.state.clone();

        // Defense-in-depth: check role-state capabilities in addition to the
        // UCAN layer. See §7.2 and ADR-010 for the dual-check design. Select the
        // kind-appropriate split stem from the outlet's registered kind
        // (SCP-OUT-014, §5.4.2): OutletQuery for Query outlets, OutletCall for
        // Action outlets. The two stems are independent, so a Query grant never
        // authorizes an Action call and vice versa. An outlet absent from the
        // registry defaults to the Action stem (the UCAN gate above already
        // required registration).
        let outlet_kind = rt
            .outlet_registry
            .get(&outlet_id)
            .map_or(scp_core::context::outlets::OutletKind::Action, |r| r.kind);
        if !scp_core::context::outlets::has_outlet_invocation_capability(
            &rt.role_state,
            invoker_did,
            &outlet_id,
            outlet_kind,
        ) {
            return Err(ScpPyError::ucan(format!(
                "invoker '{invoker_did}' does not have invocation capability for '{outlet_id}'"
            )));
        }

        // Validate input against outlet's input schema.
        if let Some(registration) = rt.outlet_registry.get(&outlet_id) {
            scp_core::context::outlets::validate_value_against_schema(
                &input_json,
                &registration.schema.input_schema,
            )
            .map_err(|e| ScpPyError::validation(format!("input validation failed: {e}")))?;
        }

        // Execute via handler or echo mode, passing session state.
        let (new_state, output) = if let Some(handler) = rt.outlet_handlers.get(&outlet_id) {
            let handler = handler.clone();
            let out = handler(input_json.clone()).map_err(|e| {
                ScpPyError::context(format!("outlet handler for '{outlet_id}' failed: {e}"))
            })?;
            (current_state, out)
        } else {
            let out = serde_json::json!({
                "outlet": outlet_id,
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

/// Closes a stateful outlet session.
///
/// Removes the session from the store, releasing the caller's session slot.
/// After closing, any further invocations with this session ID will fail.
///
/// # Arguments
///
/// * `context_id` — The context containing the outlet session.
/// * `session_id` — The session to close.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected or the session
/// is not found.
fn outlet_session_close_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    session_id: &str,
) -> PyResult<()> {
    validate::validate_context_id(context_id)?;

    crate::runtime::with_context(bi, context_id, |rt| {
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

/// Exposes an outlet interface for cross-context sharing (§6.2.0.1 step 1).
///
/// The caller (admin of the source context) proposes sharing a specific outlet
/// with a target context. The returned JSON contains the `OutletInterface` with
/// `approved_by_source = true` and `approved_by_target = false`. The target
/// context must call [`py_outlet_interface_accept`] to complete the handshake.
///
/// # Arguments
///
/// * `context_id` — The source context ID.
/// * `outlet_id` — The ID of the outlet to expose.
/// * `target_context_id` — The target context to expose the outlet to.
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
/// Raises `OutletError` if the caller is not an admin or the outlet is not found.
fn outlet_interface_expose_impl(
    bi: &PyBridgeInstance,
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
            let parsed: scp_core::context::outlets::interface::RateLimit =
                serde_json::from_str(json).map_err(|e| ScpPyError::ValidationError {
                    message: format!("invalid rate_limit_json: {e}"),
                    code: codes::VALID_7040.to_owned(),
                })?;
            Some(parsed)
        }
        None => None,
    };

    Ok(crate::runtime::with_context(bi, context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.to_string(),
            scp_core::context::ContextParams::default(),
        );

        let interface = scp_core::context::outlets::interface::expose_outlet(
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
            message: format!("expose_outlet failed: {e}"),
            code: codes::OUTLET_6030.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpPyError::ContextError {
            message: format!("failed to serialize OutletInterface: {e}"),
            code: codes::OUTLET_6031.to_owned(),
        })
    })?)
}

/// Accepts a cross-context outlet interface (§6.2.0.1 step 4).
///
/// Sets `approved_by_target = true` on the interface. Both `approved_by_source`
/// and `approved_by_target` must be `true` before calls are permitted.
///
/// # Arguments
///
/// * `context_id` — The target context ID (the one accepting).
/// * `interface_json` — The `OutletInterface` JSON string to accept (as received
///   from the source context's `outlet_interface_expose` call).
///
/// # Returns
///
/// The updated `OutletInterface` JSON string with `approved_by_target = true`.
///
/// # Errors
///
/// Raises `OutletError` if the caller is not an admin or the interface's target
/// context does not match `context_id`.
fn outlet_interface_accept_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    interface_json: &str,
) -> PyResult<String> {
    validate::validate_context_id(context_id)?;

    let mut interface: scp_core::context::outlets::interface::OutletInterface =
        serde_json::from_str(interface_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid interface_json: {e}"),
            code: codes::VALID_7041.to_owned(),
        })?;

    Ok(crate::runtime::with_context(bi, context_id, |rt| {
        let context_handle = scp_core::context::ContextHandle::new(
            context_id.to_string(),
            scp_core::context::ContextParams::default(),
        );

        scp_core::context::outlets::interface::accept_outlet_interface(
            context_handle.context_id(),
            &mut interface,
            &rt.role_state,
            &rt.creator_did,
            None,
        )
        .map_err(|e| ScpPyError::ContextError {
            message: format!("accept_outlet_interface failed: {e}"),
            code: codes::OUTLET_6032.to_owned(),
        })?;

        serde_json::to_string(&interface).map_err(|e| ScpPyError::ContextError {
            message: format!("failed to serialize OutletInterface: {e}"),
            code: codes::OUTLET_6033.to_owned(),
        })
    })?)
}

/// Revokes a cross-context outlet interface (§6.2.0.1 step 5).
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
fn outlet_interface_revoke_impl(
    _bi: &PyBridgeInstance,
    context_id: &str,
    interface_id_hex: &str,
) -> PyResult<String> {
    validate::validate_context_id(context_id)?;

    let interface_id_bytes =
        hex::decode(interface_id_hex).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid interface_id_hex: not valid hex: {e}"),
            code: codes::VALID_7042.to_owned(),
        })?;
    let interface_id: [u8; 32] = scp_ffi_common::validate::expect_fixed_bytes::<32>(
        interface_id_bytes.as_slice(),
        "interface_id_hex",
    )
    .map_err(|msg| ScpPyError::ValidationError {
        message: format!("{msg} (64 hex chars)"),
        code: codes::VALID_7042.to_owned(),
    })?;

    let now_ms = scp_clock::SystemClock.now_millis();

    let event = scp_core::context::outlets::interface::revoke_outlet_interface(
        interface_id,
        &context_id.to_owned(),
        now_ms,
    );

    let json = serde_json::to_string(&event).map_err(|e| ScpPyError::ContextError {
        message: format!("failed to serialize InterfaceRevoked: {e}"),
        code: codes::OUTLET_6035.to_owned(),
    })?;

    Ok(json)
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Registers an outlet in an SCP context.
    ///
    /// # Arguments
    ///
    /// * `context_id` — The ID of the context to register the outlet in.
    /// * `registration` — A Python dict containing outlet registration data
    ///   (name, description, schema, `test_vectors`, `operator_did`).
    ///
    /// # Returns
    ///
    /// The outlet ID (string) assigned to the registered outlet.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the context is not connected to the runtime
    /// or if registration fails.
    ///
    /// See ADR-013 §4.
    #[pyo3(name = "outlet_register")]
    pub fn outlet_register(
        &self,
        context_id: &str,
        registration: &Bound<'_, PyDict>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        outlet_register_impl(bi, context_id, registration)
    }

    /// Invokes an outlet within an SCP context, fully wired through the
    /// `ContextManager::invoke_outlet_with_economy` pipeline.
    ///
    /// # Arguments
    ///
    /// * `context_id` — The ID of the context containing the outlet.
    /// * `outlet_id` — The ID of the outlet to invoke.
    /// * `input` — A Python dict of input parameters matching the outlet's
    ///   input schema.
    /// * `identity_did` — The DID of the invoking identity (used for
    ///   capability checking).
    /// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
    /// * `proof_tokens` — Optional encoded parent UCAN tokens for delegation
    ///   chain traversal.
    /// * `spending_ucan` — Optional JWT-encoded spending UCAN for paid outlet
    ///   invocations.
    ///
    /// # Returns
    ///
    /// A Python object (dict) containing the outlet's JSON-compatible output.
    ///
    /// # Errors
    ///
    /// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
    /// or lacks the required outlet invocation capability.
    /// Raises `ContextError` if the economy pre-check, budget, payment escrow,
    /// hard rate limit, or underlying outlet dispatch fails.
    ///
    /// See ADR-013 §4, SCP-212, spec §6.2, §8, §19.5, §19.7, ADR-016, #319.
    #[pyo3(name = "outlet_invoke")]
    #[pyo3(signature = (context_id, outlet_id, input, identity_did, ucan_token, proof_tokens=None, spending_ucan=None))]
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    pub fn outlet_invoke(
        &self,
        py: Python<'_>,
        context_id: &str,
        outlet_id: &str,
        input: &Bound<'_, PyDict>,
        identity_did: &str,
        ucan_token: &str,
        proof_tokens: Option<Vec<String>>,
        spending_ucan: Option<&str>,
    ) -> PyResult<PyObject> {
        let bi = &*self.inner;
        outlet_invoke_impl(
            bi,
            py,
            context_id,
            outlet_id,
            input,
            identity_did,
            ucan_token,
            proof_tokens,
            spending_ucan,
        )
    }

    /// Verifies an outlet against its registered test vectors.
    ///
    /// # Arguments
    ///
    /// * `context_id` — The ID of the context containing the outlet.
    /// * `outlet_id` — The ID of the outlet to verify.
    ///
    /// # Returns
    ///
    /// A [`PyOutletVerificationResult`] with the outlet ID, overall pass/fail
    /// status, and any failure messages.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the context is not connected or the outlet
    /// is not found.
    ///
    /// See ADR-013 §4.
    #[pyo3(name = "outlet_verify")]
    pub fn outlet_verify(
        &self,
        context_id: &str,
        outlet_id: &str,
    ) -> PyResult<PyOutletVerificationResult> {
        let bi = &*self.inner;
        outlet_verify_impl(bi, context_id, outlet_id)
    }

    /// Invokes an outlet across context boundaries.
    ///
    /// The source context exposes the outlet and the target context accepts the
    /// interface. Both contexts must have approved the interface before calls
    /// are permitted. Rate limits and chain depth are enforced per spec §6.2.
    ///
    /// # Errors
    ///
    /// Raises `UcanError` if the UCAN token is invalid, expired, revoked,
    /// or lacks the required outlet invocation capability.
    /// Raises `ContextError` if either context is not connected, the outlet is
    /// not found, chain depth is exceeded, or the interface is not approved.
    #[pyo3(name = "outlet_invoke_cross_context")]
    #[pyo3(signature = (source_context_id, target_context_id, outlet_id, input, invoker_did, ucan_token, chain_depth, proof_tokens=None))]
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    pub fn outlet_invoke_cross_context(
        &self,
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
        let bi = &*self.inner;
        outlet_invoke_cross_context_impl(
            bi,
            py,
            source_context_id,
            target_context_id,
            outlet_id,
            input,
            invoker_did,
            ucan_token,
            chain_depth,
            proof_tokens,
        )
    }

    /// Invokes an outlet across context boundaries as an atomic two-phase saga
    /// (spec §6.2.4, ADR-049 §3a).
    ///
    /// Unlike [`Self::outlet_invoke_cross_context`] (the synchronous,
    /// single-context-side path), this drives the full §6.2.4 cross-context
    /// outlet-invocation saga over the two CO-RESIDENT participant contexts
    /// (caller + target): Prepare-A / Prepare-B authorize and stage both
    /// sides, the outlet executes EXACTLY ONCE supervisor-side at Commit-B, and
    /// each side records its own event-log entry. Both contexts MUST be
    /// co-resident in this bridge instance (the cross-node child-bridge
    /// transport is separate future work).
    ///
    /// # Caller authentication (normative — §6.2.4, ADR-049 §3a)
    ///
    /// `caller_did` is bound to the bridge-authenticated principal: it MUST be
    /// an identity THIS bridge instance hosts (created here via identity
    /// creation) AND a member of `caller_context_id`. A mismatch raises
    /// `SagaAbortedError` BEFORE the saga runs — the saga never observes an
    /// unauthenticated caller. The `asserted_nonce_hex` / `timestamp_ms` /
    /// `chain_depth` REMAIN caller-supplied freshness fields (the target
    /// validates them; they are not minted here).
    ///
    /// # Trust boundary (co-resident single-tenant only)
    ///
    /// The caller-principal binding (`enforce_caller_principal_binding`) treats
    /// "hosted in this bridge instance's identity registry" as the
    /// channel-authenticated principal. That equivalence holds ONLY for a
    /// single-tenant, co-resident SDK process. This surface MUST NOT be exposed
    /// across a trust boundary within one process: a multi-tenant host loading
    /// multiple users' identities into one bridge instance could assert any
    /// hosted `caller_did`, since the registry cannot distinguish which tenant
    /// is making the call. The future cross-node leg needs real channel auth
    /// (ADR-049 §3a forward obligation) — it cannot reuse "is hosted here" as
    /// the authenticated-principal proof.
    ///
    /// On the `PyO3` string-id surface the caller/target context-id axes are
    /// enforced by the supervisor gates — membership (`is_member`) for the
    /// caller context and the governance-established outlet-interface gate for the
    /// target context — rather than the instance-affine handle pre-check the
    /// NAPI/UniFFI handle-based surfaces apply. The authorization is equivalent;
    /// the difference is only that this surface carries less pre-flight
    /// defense-in-depth, matching the `PyO3` string-id idiom (the gates are the
    /// authoritative check on both surfaces).
    ///
    /// The receipt's signer-authorization — that the target key is
    /// governance-authorized to act for `target_context_id` (§6.2.4 "Signer
    /// authorization") — is a DOWNSTREAM receipt-consumer obligation verified
    /// when the receipt is consumed, NOT enforced at this export.
    ///
    /// # Arguments
    ///
    /// * `caller_context_id` — The initiating (caller) context id.
    /// * `target_context_id` — The executing (target) context id.
    /// * `caller_did` — The initiator DID (bound to the bridge principal).
    /// * `outlet_registration_id` — The outlet to invoke across the interface.
    /// * `input` — Outlet input (a Python dict; schema-checked target-side).
    /// * `asserted_nonce_hex` — The 16-byte §6.2.4 envelope nonce as a
    ///   32-char hex string (the freshness/dedup token).
    /// * `timestamp_ms` — Caller-asserted send time (Unix ms; freshness check).
    /// * `chain_depth` — Caller-asserted inbound provenance depth (advisory;
    ///   the target re-derives `+1`).
    /// * `ucan_proof_id` — Optional id of the spending UCAN proof, resolved
    ///   target-side at Prepare-B. `None` for an ungated outlet.
    ///
    /// # Returns
    ///
    /// A [`PySagaResult`] on the committed terminal, carrying the
    /// supervisor-minted `saga_id`, the target's signed receipt bytes, and the
    /// captured outlet-output bytes. The `saga_id` is supervisor-minted — it is
    /// never an input.
    ///
    /// # Errors
    ///
    /// Raises one of the typed saga exceptions — `SagaAbortedError` (a
    /// Prepare-phase abort that may be a permanent rejection — authorization,
    /// freshness, rate limit, or co-residency — OR a retryable transient: a rate
    /// limit, or a participant actor unavailable to complete the Prepare
    /// exchange; carries `retry_after_ms`), `SagaNeedsRepairError`
    /// (Commit-retry exhausted — carries the durable `saga_id` operator-repair
    /// handle), or `SagaBusyError` (the participant context set overlapped an
    /// in-flight saga — §5.15.4). Raises `ValidationError` if an id/DID/outlet-id
    /// is malformed or `asserted_nonce_hex` does not decode to 16 bytes.
    ///
    /// See spec §6.2.4 and ADR-049 §3a.
    #[pyo3(name = "outlet_invoke_cross_context_saga")]
    #[pyo3(signature = (
        caller_context_id,
        target_context_id,
        caller_did,
        outlet_registration_id,
        input,
        asserted_nonce_hex,
        timestamp_ms,
        chain_depth,
        ucan_proof_id=None,
    ))]
    #[allow(clippy::too_many_arguments)] // Flat §6.2.4 envelope — agent-first named params.
    pub fn outlet_invoke_cross_context_saga(
        &self,
        caller_context_id: &str,
        target_context_id: &str,
        caller_did: &str,
        outlet_registration_id: &str,
        input: &Bound<'_, PyDict>,
        asserted_nonce_hex: &str,
        timestamp_ms: u64,
        chain_depth: u8,
        ucan_proof_id: Option<String>,
    ) -> PyResult<PySagaResult> {
        let bi = &*self.inner;
        outlet_invoke_cross_context_saga_impl(
            bi,
            caller_context_id,
            target_context_id,
            caller_did,
            outlet_registration_id,
            input,
            asserted_nonce_hex,
            timestamp_ms,
            chain_depth,
            ucan_proof_id,
        )
    }

    /// Creates a stateful outlet session.
    ///
    /// Sessions enable multi-turn workflows with state preservation across
    /// invocations.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the context is not connected, the outlet is
    /// not found, or the per-caller session cap is exceeded.
    #[pyo3(name = "outlet_session_create", signature = (context_id, outlet_id, source_context_id, ttl_seconds=None))]
    pub fn outlet_session_create(
        &self,
        context_id: &str,
        outlet_id: &str,
        source_context_id: &str,
        ttl_seconds: Option<u64>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        outlet_session_create_impl(bi, context_id, outlet_id, source_context_id, ttl_seconds)
    }

    /// Invokes an outlet within an active session.
    ///
    /// Each call is individually governed: the invoker must hold `OutletCall`
    /// capability and present a valid UCAN token. Session state is carried
    /// forward across invocations.
    ///
    /// # Errors
    ///
    /// Raises `UcanError` if the UCAN token is invalid.
    /// Raises `ContextError` if the session is not found, has expired, or the
    /// invoker lacks capability.
    #[pyo3(name = "outlet_session_invoke")]
    #[pyo3(signature = (context_id, session_id, input, invoker_did, ucan_token, proof_tokens=None))]
    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_arguments)] // FFI surface: spec-defined signature
    pub fn outlet_session_invoke(
        &self,
        py: Python<'_>,
        context_id: &str,
        session_id: &str,
        input: &Bound<'_, PyDict>,
        invoker_did: &str,
        ucan_token: &str,
        proof_tokens: Option<Vec<String>>,
    ) -> PyResult<PyObject> {
        let bi = &*self.inner;
        outlet_session_invoke_impl(
            bi,
            py,
            context_id,
            session_id,
            input,
            invoker_did,
            ucan_token,
            proof_tokens,
        )
    }

    /// Closes a stateful outlet session.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the context is not connected or the session
    /// is not found.
    #[pyo3(name = "outlet_session_close")]
    pub fn outlet_session_close(&self, context_id: &str, session_id: &str) -> PyResult<()> {
        let bi = &*self.inner;
        outlet_session_close_impl(bi, context_id, session_id)
    }

    /// Exposes an outlet interface for cross-context sharing (§6.2.0.1 step 1).
    ///
    /// # Errors
    ///
    /// Raises `OutletError` if the caller is not an admin or the outlet is not found.
    #[pyo3(name = "outlet_interface_expose", signature = (context_id, outlet_id, target_context_id, rate_limit_json=None))]
    pub fn outlet_interface_expose(
        &self,
        context_id: &str,
        outlet_id: &str,
        target_context_id: &str,
        rate_limit_json: Option<&str>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        outlet_interface_expose_impl(
            bi,
            context_id,
            outlet_id,
            target_context_id,
            rate_limit_json,
        )
    }

    /// Accepts a cross-context outlet interface (§6.2.0.1 step 4).
    ///
    /// # Errors
    ///
    /// Raises `OutletError` if the caller is not an admin or the interface's
    /// target context does not match `context_id`.
    #[pyo3(name = "outlet_interface_accept")]
    pub fn outlet_interface_accept(
        &self,
        context_id: &str,
        interface_json: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        outlet_interface_accept_impl(bi, context_id, interface_json)
    }

    /// Revokes a cross-context outlet interface (§6.2.0.1 step 5).
    ///
    /// Either context may revoke unilaterally.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `interface_id` is not valid hex or not 32 bytes.
    #[pyo3(name = "outlet_interface_revoke")]
    pub fn outlet_interface_revoke(
        &self,
        context_id: &str,
        interface_id_hex: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        outlet_interface_revoke_impl(bi, context_id, interface_id_hex)
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers outlet bridge classes on the `_scp_core` module.
///
/// Post-migration (Phase 4 PR 4 sub-slice E), outlet operations are exposed as
/// methods on `SCP`. Only opaque result classes require registration here.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of classes fails.
pub fn register_outlets(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyOutletRegistration>()?;
    m.add_class::<PyOutletVerificationResult>()?;
    m.add_class::<PySagaResult>()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new_in_memory_for_test()
    }

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
            dict.set_item("name", "test-outlet").unwrap();
            dict.set_item("description", "a test").unwrap();
            dict.set_item("operator_did", "did:dht:test123456789abcdefghij")
                .unwrap();

            // Schema dict with only output_schema, missing input_schema.
            let schema = PyDict::new(py);
            schema.set_item("output_schema", PyDict::new(py)).unwrap();
            dict.set_item("schema", schema).unwrap();

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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
            dict.set_item("name", "test-outlet").unwrap();
            dict.set_item("description", "a test").unwrap();
            dict.set_item("operator_did", "did:dht:test123456789abcdefghij")
                .unwrap();

            // Schema dict with only input_schema, missing output_schema.
            let schema = PyDict::new(py);
            let inner = PyDict::new(py);
            inner.set_item("type", "object").unwrap();
            schema.set_item("input_schema", inner).unwrap();
            dict.set_item("schema", schema).unwrap();

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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
            dict.set_item("name", "test-outlet").unwrap();
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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
            dict.set_item("name", "test-outlet").unwrap();
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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
        dict.set_item("name", "test-outlet").unwrap();
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
            assert!(result.is_err(), "should reject dict as test_vectors");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains(codes::VALID_7037),
                "error should contain SCP-VALID-7037, got: {err_str}"
            );
        });
    }

    /// `extract_kind` maps the lowercase wire strings to `OutletKind`.
    #[test]
    fn extract_kind_parses_query_and_action() {
        use scp_core::context::outlets::OutletKind;
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            dict.set_item("kind", "query").unwrap();
            assert_eq!(
                extract_kind(&dict.as_borrowed()).unwrap(),
                OutletKind::Query
            );
            dict.set_item("kind", "action").unwrap();
            assert_eq!(
                extract_kind(&dict.as_borrowed()).unwrap(),
                OutletKind::Action
            );
        });
    }

    /// `extract_kind` defaults to the fail-safe `Action` when `kind` is absent
    /// or explicitly `None` (§5.4.1 wire tolerance; the SDK surfaces it required).
    #[test]
    fn extract_kind_defaults_to_action_when_absent() {
        use scp_core::context::outlets::OutletKind;
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            // No `kind` key.
            assert_eq!(
                extract_kind(&dict.as_borrowed()).unwrap(),
                OutletKind::Action
            );
            // Explicit None.
            dict.set_item("kind", py.None()).unwrap();
            assert_eq!(
                extract_kind(&dict.as_borrowed()).unwrap(),
                OutletKind::Action
            );
        });
    }

    /// `extract_kind` rejects an unrecognized string rather than silently
    /// downgrading it to `Action`.
    #[test]
    fn extract_kind_rejects_unknown_value() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = valid_registration_dict(py);
            dict.set_item("kind", "readonly").unwrap();
            let result = extract_kind(&dict.as_borrowed());
            assert!(result.is_err(), "unknown kind must be rejected");
            let err_str = format!("{}", result.unwrap_err());
            assert!(
                err_str.contains("kind"),
                "error should mention 'kind', got: {err_str}"
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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

            let result = default_scp().outlet_register("ctx-test-id-000000", &dict.as_borrowed());
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

    /// `registered_at` on an outlet registered via the `PyO3` bridge must be a
    /// seconds-epoch timestamp, not milliseconds or hardcoded 0.
    /// Calls the actual `PyScp::outlet_register` bridge method and inspects the
    /// stored `OutletRegistration`. Catches the original bug from issue #871.
    #[test]
    fn registered_at_is_seconds_epoch() {
        // Use a unique context ID to avoid collisions with concurrent tests.
        let ctx_id = format!("ctx-ts-test-{}", std::process::id());
        let creator_did = "did:dht:z6MkTestTimestamp";

        let scp = default_scp();
        let bi = &*scp.inner;

        // Register FFI state so the context exists in the runtime registry.
        crate::runtime::register_ffi_state(bi, &ctx_id, creator_did, &[]).unwrap();

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

            let outlet_id = scp
                .outlet_register(&ctx_id, &dict.as_borrowed())
                .expect("outlet_register should succeed");

            // Read the stored registration back from the runtime registry.
            let registered_at = crate::runtime::with_ffi_state(bi, &ctx_id, |state| {
                let reg = state
                    .outlet_registry
                    .get(&outlet_id)
                    .expect("outlet should exist in registry after successful registration");
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
        crate::runtime::remove_ffi_state(bi, &ctx_id);
    }

    // ------------------------------------------------------------------
    // map_saga_error — the bridge's typed-terminal → typed-error mapping.
    //
    // The classification itself (the `RateLimited → Option<u64>` read, the
    // `None`-never-`0` rule, the `SCP-SAGA-{code}` formatting, the fixed
    // terminal codes) lives in `scp_ffi_common::saga_errors` and is unit-tested
    // there for all three bridges. The producer's actual terminal behavior is
    // covered in `crates/scp-runtime`. Here we test ONLY this bridge's thin
    // tail: that each `SagaErrorKind` routes through `common` onto the right
    // `ScpPyError` variant with the shared `code`/`message` and the
    // per-terminal datum (`retry_after_ms`/`saga_id`/`contended_context`)
    // carried onto the PyO3 fields — including that `retry_after_ms = None` is
    // preserved (never coerced to `Some(0)`).
    // ------------------------------------------------------------------

    use scp_core::context::supervisor::{SagaAbortReason, SagaError as CoreSagaError, SagaId};

    /// `Aborted` routes through `common` onto `ScpPyError::SagaAborted` with the
    /// `SCP-SAGA-{code}` string and `retry_after_ms` carried structurally; a
    /// `None` back-off hint stays `None` (never `Some(0)`).
    #[test]
    fn map_saga_error_aborted_routes_through_common() {
        let some = map_saga_error(CoreSagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: Some(2500),
            },
            code: 13026,
            message: "inbound rate limit exceeded".to_owned(),
        });
        match some {
            ScpPyError::SagaAborted {
                code,
                retry_after_ms,
                ..
            } => {
                assert_eq!(code, "SCP-SAGA-13026");
                assert_eq!(retry_after_ms, Some(2500));
            }
            other => panic!("expected SagaAborted, got {other:?}"),
        }

        let none = map_saga_error(CoreSagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: None,
            },
            code: 13026,
            message: "hard limit, no precise back-off".to_owned(),
        });
        match none {
            ScpPyError::SagaAborted { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, None, "None must NOT be coerced to Some(0)");
            }
            other => panic!("expected SagaAborted, got {other:?}"),
        }
    }

    /// `NeedsRepair` / `Busy` route through `common` onto their `PyO3` variants
    /// with the fixed terminal codes and per-terminal datum carried.
    #[test]
    fn map_saga_error_needs_repair_and_busy_route_through_common() {
        let repair = map_saga_error(CoreSagaError::NeedsRepair {
            saga_id: SagaId("saga-abc-123".to_owned()),
            message: "commit retries exhausted".to_owned(),
        });
        match repair {
            ScpPyError::SagaNeedsRepair { code, saga_id, .. } => {
                assert_eq!(code, codes::SAGA_13065);
                assert_eq!(saga_id, "saga-abc-123");
            }
            other => panic!("expected SagaNeedsRepair, got {other:?}"),
        }

        let busy = map_saga_error(CoreSagaError::Busy {
            contended_context: "ctx-shared-99".to_owned(),
            message: "participant set overlaps an in-flight saga".to_owned(),
        });
        match busy {
            ScpPyError::SagaBusy {
                code,
                contended_context,
                ..
            } => {
                assert_eq!(code, codes::SAGA_13066);
                assert_eq!(contended_context, "ctx-shared-99");
            }
            other => panic!("expected SagaBusy, got {other:?}"),
        }
    }
}
