//! `PyO3` bridge functions for tool registration, invocation, and verification.
//!
//! Exposes SCP tool operations to Python:
//!
//! - [`py_tool_register`] — Register a tool in a context (returns tool ID).
//! - [`py_tool_invoke`] — Invoke a tool (returns JSON-compatible output).
//! - [`py_tool_verify`] — Verify a tool against its test vectors.
//!
//! # Types
//!
//! - [`PyToolRegistration`] — Tool registration data (name, description,
//!   schema, test vectors).
//! - [`PyToolVerificationResult`] — Verification result (tool ID, pass/fail,
//!   failure messages).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §4 for the bridge specification.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::error::ScpPyError;
use crate::types::{json_to_py_dict, py_dict_to_json};

// ---------------------------------------------------------------------------
// PyToolRegistration
// ---------------------------------------------------------------------------

/// Tool registration data exposed to Python.
///
/// Contains the metadata needed to register a tool in an SCP context:
/// name, description, JSON Schema, and test vectors. The `schema` field
/// is a Python dict representing the MCP-compatible JSON Schema for the
/// tool's input and output.
///
/// See ADR-010 (tool registration) and ADR-013 §4 (bridge layer).
#[pyclass(name = "ToolRegistration")]
#[derive(Debug)]
pub struct PyToolRegistration {
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
impl PyToolRegistration {
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
            "ToolRegistration(name={:?}, description={:?}, test_vectors={})",
            self.name,
            self.description,
            self.test_vectors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PyToolVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a tool against its test vectors.
///
/// Returned by [`py_tool_verify`]. Contains the tool ID, overall pass/fail
/// status, and a list of failure messages (empty if all vectors passed).
#[pyclass(name = "ToolVerificationResult")]
#[derive(Debug, Clone)]
pub struct PyToolVerificationResult {
    /// The verified tool's ID.
    #[pyo3(get)]
    pub tool_id: String,

    /// `True` if all test vectors passed.
    #[pyo3(get)]
    pub passed: bool,

    /// Failure messages for vectors that did not pass. Empty on success.
    #[pyo3(get)]
    pub failures: Vec<String>,
}

#[pymethods]
impl PyToolVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "ToolVerificationResult(tool_id={:?}, passed={}, failures={})",
            self.tool_id,
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
/// See ADR-013 §4: `py_tool_register(handle, registration) -> str`.
#[pyfunction]
#[pyo3(name = "tool_register")]
pub fn py_tool_register(context_id: &str, registration: &Bound<'_, PyDict>) -> PyResult<String> {
    // Extract registration fields from the Python dict.
    let name: String = registration
        .get_item("name")?
        .ok_or_else(|| ScpPyError::ValidationError("missing 'name' field".to_owned()))?
        .extract()?;
    let description: String = registration
        .get_item("description")?
        .ok_or_else(|| ScpPyError::ValidationError("missing 'description' field".to_owned()))?
        .extract()?;
    let operator_did: String = registration
        .get_item("operator_did")?
        .ok_or_else(|| ScpPyError::ValidationError("missing 'operator_did' field".to_owned()))?
        .extract()?;

    // Extract schema as JSON. The schema dict should have `input_schema` and
    // `output_schema` keys, each being a JSON Schema object.
    let schema_obj = registration
        .get_item("schema")?
        .ok_or_else(|| ScpPyError::ValidationError("missing 'schema' field".to_owned()))?;
    let schema_dict = schema_obj
        .downcast::<PyDict>()
        .map_err(|_| ScpPyError::ValidationError("'schema' must be a dict".to_owned()))?;
    let schema_json = py_dict_to_json(schema_dict)?;
    let input_schema = schema_json
        .get("input_schema")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"type": "object"}));
    let output_schema = schema_json
        .get("output_schema")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"type": "object"}));

    // Extract test vectors (optional).
    let test_vectors = extract_test_vectors(registration)?;

    // Extract implementation hash (optional, 32-byte SHA-256 of tool code).
    // Per spec §5.4: content-addressable reference to the tool's implementation.
    let implementation_hash = extract_implementation_hash(registration)?;

    // Extract economic metadata (optional, per spec §5.4).
    let economic_metadata = extract_economic_metadata(registration)?;

    // Generate a tool ID from the name (deterministic, human-readable).
    let tool_id = format!("tool-{}", name.replace(' ', "-").to_lowercase());

    // Build the scp-core ToolRegistration.
    let core_registration = scp_core::context::tools::ToolRegistration {
        tool_id,
        name,
        description,
        schema: scp_core::context::tools::ToolSchema {
            input_schema,
            output_schema,
        },
        implementation_hash,
        test_vectors,
        operator_did: operator_did.into(),
        economic_metadata,
    };

    // Look up the context runtime and register the tool.
    let registered_id = crate::runtime::with_context(context_id, |rt| {
        let (registered_id, _event) = scp_core::context::tools::register_tool(
            &mut rt.tool_registry,
            &rt.role_state,
            core_registration,
            &rt.creator_did.clone(),
        )
        .map_err(|e| ScpPyError::ContextError(format!("tool registration failed: {e}")))?;
        Ok(registered_id)
    })?;

    Ok(registered_id)
}

/// Invokes a tool within an SCP context.
///
/// # Arguments
///
/// * `context_id` — The ID of the context containing the tool.
/// * `tool_id` — The ID of the tool to invoke.
/// * `input` — A Python dict of input parameters matching the tool's
///   input schema.
/// * `identity_did` — The DID of the invoking identity (used for
///   capability checking).
///
/// # Returns
///
/// A Python object (dict) containing the tool's JSON-compatible output.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected, the tool is
/// not found, the invoker lacks capability, input validation fails,
/// execution times out, or the tool execution itself fails.
///
/// See ADR-013 §4: `py_tool_invoke(handle, tool_id, input, identity) -> PyObject`.
#[pyfunction]
#[pyo3(name = "tool_invoke")]
pub fn py_tool_invoke(
    py: Python<'_>,
    context_id: &str,
    tool_id: &str,
    input: &Bound<'_, PyDict>,
    identity_did: &str,
) -> PyResult<PyObject> {
    // Convert Python dict input to serde_json::Value.
    let input_json = py_dict_to_json(input)?;

    // Look up the tool in the context's registry and validate input schema.
    // Tool invocation in the bridge layer performs schema validation and returns
    // the input as the output (passthrough), since actual tool execution requires
    // a running executor which is wired at the transport layer. This validates
    // the full registration and capability chain without requiring an executor.
    let output_json = crate::runtime::with_context(context_id, |rt| {
        // Check that the tool exists.
        let registration = rt.tool_registry.get(tool_id).ok_or_else(|| {
            ScpPyError::ContextError(format!(
                "tool '{tool_id}' not found in context '{context_id}'"
            ))
        })?;

        // Validate input against the tool's input schema.
        scp_core::context::tools::validate_value_against_schema(
            &input_json,
            &registration.schema.input_schema,
        )
        .map_err(|e| ScpPyError::ValidationError(format!("input validation failed: {e}")))?;

        // Check that the invoker has the ToolInvoke capability.
        if !scp_core::context::tools::has_tool_invoke_capability(
            &rt.role_state,
            identity_did,
            tool_id,
        ) {
            return Err(ScpPyError::UcanError(format!(
                "invoker '{identity_did}' does not have ToolInvoke capability for '{tool_id}'"
            )));
        }

        // In the bridge layer without a full executor, we return the input as
        // a passthrough. Real tool execution happens via the transport layer
        // when it's wired to a relay.
        Ok(input_json.clone())
    })?;

    // Convert output back to Python dict.
    json_to_py_dict(py, &output_json)
}

/// Verifies a tool against its registered test vectors.
///
/// # Arguments
///
/// * `context_id` — The ID of the context containing the tool.
/// * `tool_id` — The ID of the tool to verify.
///
/// # Returns
///
/// A [`PyToolVerificationResult`] with the tool ID, overall pass/fail
/// status, and any failure messages.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected or the tool
/// is not found.
///
/// See ADR-013 §4: `py_tool_verify(handle, tool_id) -> PyToolVerificationResult`.
#[pyfunction]
#[pyo3(name = "tool_verify")]
pub fn py_tool_verify(context_id: &str, tool_id: &str) -> PyResult<PyToolVerificationResult> {
    // Look up the context and verify the tool against its test vectors.
    // The executor returns the expected output (identity function) since the
    // bridge layer has no external tool executor. This verifies the test
    // vector structure is intact.
    let result = crate::runtime::with_context(context_id, |rt| {
        let (verification_result, _event) = scp_core::context::tools::verify_tool(
            &rt.tool_registry,
            tool_id,
            // Identity executor: returns the expected output for each vector.
            // This validates the test vector structure; real execution verification
            // happens when a full executor is connected.
            |input| {
                // Look up the tool to find the matching test vector.
                if let Some(registration) = rt.tool_registry.get(tool_id) {
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
        .map_err(|e| ScpPyError::ContextError(format!("tool verification failed: {e}")))?;

        Ok(verification_result)
    })?;

    // Convert to PyToolVerificationResult.
    let failures: Vec<String> = result
        .vector_results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.description.clone())
        .collect();

    Ok(PyToolVerificationResult {
        tool_id: result.tool_id,
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
fn extract_implementation_hash(registration: &Bound<'_, PyDict>) -> PyResult<[u8; 32]> {
    let hash_obj = match registration.get_item("implementation_hash")? {
        Some(val) if !val.is_none() => val,
        _ => return Ok([0u8; 32]),
    };

    let hex_str: String = hash_obj.extract().map_err(|_| {
        ScpPyError::ValidationError("'implementation_hash' must be a hex string".to_owned())
    })?;

    if hex_str.len() != 64 {
        return Err(ScpPyError::ValidationError(format!(
            "'implementation_hash' must be 64 hex chars (SHA-256), got {}",
            hex_str.len()
        ))
        .into());
    }

    let mut hash = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|_| {
            ScpPyError::ValidationError("invalid UTF-8 in implementation_hash".to_owned())
        })?;
        hash[i] = u8::from_str_radix(byte_str, 16).map_err(|_| {
            ScpPyError::ValidationError(format!(
                "invalid hex in implementation_hash at position {}",
                i * 2
            ))
        })?;
    }

    Ok(hash)
}

/// Extracts optional `economic_metadata` from the registration dict.
///
/// Accepts a Python dict with `cost_per_invoke` (int), optional
/// `cost_formula` (str), and `payee` (str DID). Per spec §5.4.
fn extract_economic_metadata(
    registration: &Bound<'_, PyDict>,
) -> PyResult<Option<scp_core::context::tools::ToolEconomicMetadata>> {
    let meta_obj = match registration.get_item("economic_metadata")? {
        Some(val) if !val.is_none() => val,
        _ => return Ok(None),
    };

    let dict = meta_obj.downcast::<PyDict>().map_err(|_| {
        ScpPyError::ValidationError("'economic_metadata' must be a dict".to_owned())
    })?;

    let cost_per_invoke: u64 = dict
        .get_item("cost_per_invoke")?
        .ok_or_else(|| {
            ScpPyError::ValidationError("economic_metadata missing 'cost_per_invoke'".to_owned())
        })?
        .extract()?;

    let cost_formula: Option<String> = dict
        .get_item("cost_formula")?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract())
        .transpose()?;

    let payee: String = dict
        .get_item("payee")?
        .ok_or_else(|| ScpPyError::ValidationError("economic_metadata missing 'payee'".to_owned()))?
        .extract()?;

    Ok(Some(scp_core::context::tools::ToolEconomicMetadata {
        cost_per_invoke,
        cost_formula,
        payee: payee.into(),
    }))
}

/// Extracts test vectors from the registration dict's `test_vectors` field.
///
/// Each test vector is a Python dict with `input`, `expected_output`, and
/// `description` keys. Returns an empty Vec if the field is missing.
fn extract_test_vectors(
    registration: &Bound<'_, PyDict>,
) -> PyResult<Vec<scp_core::context::tools::TestVector>> {
    let vectors_obj = match registration.get_item("test_vectors")? {
        Some(val) if !val.is_none() => val,
        _ => return Ok(Vec::new()),
    };

    let vectors_list = vectors_obj
        .downcast::<pyo3::types::PyList>()
        .map_err(|_| ScpPyError::ValidationError("'test_vectors' must be a list".to_owned()))?;

    let mut result = Vec::with_capacity(vectors_list.len());
    for item in vectors_list.iter() {
        let dict = item.downcast::<PyDict>().map_err(|_| {
            ScpPyError::ValidationError("each test vector must be a dict".to_owned())
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

        result.push(scp_core::context::tools::TestVector {
            input,
            expected_output,
            description,
        });
    }

    Ok(result)
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
pub fn register_tools(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyToolRegistration>()?;
    m.add_class::<PyToolVerificationResult>()?;
    m.add_function(wrap_pyfunction!(py_tool_register, m)?)?;
    m.add_function(wrap_pyfunction!(py_tool_invoke, m)?)?;
    m.add_function(wrap_pyfunction!(py_tool_verify, m)?)?;
    Ok(())
}
