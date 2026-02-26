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
use crate::types::json_to_py_dict;

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
pub fn py_tool_register(
    _context_id: &str,
    _registration: &Bound<'_, PyDict>,
) -> PyResult<String> {
    Err(ScpPyError::ContextError(
        "not yet connected to runtime — tool registration requires a live context handle"
            .to_owned(),
    )
    .into())
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
    _context_id: &str,
    _tool_id: &str,
    _input: &Bound<'_, PyDict>,
    _identity_did: &str,
) -> PyResult<PyObject> {
    // Return an empty dict as placeholder to satisfy the return type.
    let empty = serde_json::Value::Object(serde_json::Map::new());
    let _ = json_to_py_dict(py, &empty)?;
    Err(ScpPyError::ContextError(
        "not yet connected to runtime — tool invocation requires a live context handle"
            .to_owned(),
    )
    .into())
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
pub fn py_tool_verify(
    _context_id: &str,
    _tool_id: &str,
) -> PyResult<PyToolVerificationResult> {
    Err(ScpPyError::ContextError(
        "not yet connected to runtime — tool verification requires a live context handle"
            .to_owned(),
    )
    .into())
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
