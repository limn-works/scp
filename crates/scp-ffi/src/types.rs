//! Shared type conversion helpers for the `PyO3` bridge.
//!
//! Provides bidirectional conversion between Python dicts and Rust types:
//!
//! - [`py_dict_to_json`]: `Python dict` -> [`serde_json::Value`]
//! - [`json_to_py_dict`]: [`serde_json::Value`] -> `Python object`
//! - [`encode_hex`]: `&[u8]` -> lowercase hex `String` (delegates to `hex::encode`)
//! - [`generate_context_id`]: CSPRNG context ID (pure hex, spec-compliant)
//! - [`generate_random_id`]: CSPRNG prefixed handle ID (internal use)
//!
//! These are the foundational conversion functions used by all bridge modules
//! that pass structured data between Python and Rust (context params, tool
//! definitions, event filters, etc.).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` for the full specification.

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyList, PyString};
use serde_json::Value;

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------

/// Encodes a byte slice as a lowercase hex string.
///
/// Used across the bridge for Merkle roots, token CIDs, nonces, and proof
/// details. Delegates to `hex::encode`.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Random ID generation
// ---------------------------------------------------------------------------

/// Generates a spec-compliant context ID: 32 cryptographically random bytes,
/// hex-encoded to 64 characters.
///
/// Context IDs MUST be valid hexadecimal per §18.4.1 (addressability spec)
/// so they can be embedded directly in `scp://context/<context_id_hex>` URIs.
///
/// Uses `rand::thread_rng()` (backed by `OsRng`) for unpredictable,
/// collision-resistant identifiers.
pub(crate) fn generate_context_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    encode_hex(&bytes)
}

/// Generates a prefixed random handle ID for internal use.
///
/// Produces `{prefix}-{32_hex_chars}` (128 bits of CSPRNG). Used for opaque
/// handles that never appear in `scp://` URIs (MCP server/client handles).
pub(crate) fn generate_random_id(prefix: &str) -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    format!("{prefix}-{}", encode_hex(&bytes))
}

// ---------------------------------------------------------------------------
// Python dict -> serde_json::Value
// ---------------------------------------------------------------------------

/// Converts a Python `dict` to a [`serde_json::Value`].
///
/// Recursively walks the dict, converting:
/// - `str` -> `Value::String`
/// - `int` / `float` -> `Value::Number`
/// - `bool` -> `Value::Bool`
/// - `None` -> `Value::Null`
/// - `list` -> `Value::Array`
/// - `dict` -> `Value::Object`
///
/// # Errors
///
/// Returns `ScpPyError::ValidationError` if a dict value has an unsupported
/// Python type (e.g., custom objects, bytes, sets).
pub fn py_dict_to_json(dict: &Bound<'_, PyDict>) -> Result<Value, ScpPyError> {
    let mut map = serde_json::Map::new();
    for (key, value) in dict.iter() {
        let key_str: String = key.extract().map_err(|e| {
            let type_name = key
                .get_type()
                .name()
                .map_or_else(|_| "<unknown>".to_owned(), |n| n.to_string());
            ScpPyError::ValidationError(format!("dict key must be a string, got {type_name}: {e}",))
        })?;
        let json_value = py_any_to_json(&value)?;
        map.insert(key_str, json_value);
    }
    Ok(Value::Object(map))
}

/// Converts an arbitrary Python object to a [`serde_json::Value`].
///
/// This is the recursive workhorse called by [`py_dict_to_json`] for nested
/// structures.
fn py_any_to_json(obj: &Bound<'_, PyAny>) -> Result<Value, ScpPyError> {
    // Check bool BEFORE int — in Python, `bool` is a subclass of `int`.
    if obj.is_instance_of::<PyBool>() {
        let b: bool = obj
            .extract()
            .map_err(|e| ScpPyError::ValidationError(format!("failed to extract bool: {e}")))?;
        return Ok(Value::Bool(b));
    }

    if obj.is_none() {
        return Ok(Value::Null);
    }

    if obj.is_instance_of::<PyString>() {
        let s: String = obj
            .extract()
            .map_err(|e| ScpPyError::ValidationError(format!("failed to extract string: {e}")))?;
        return Ok(Value::String(s));
    }

    if obj.is_instance_of::<PyFloat>() {
        let f: f64 = obj
            .extract()
            .map_err(|e| ScpPyError::ValidationError(format!("failed to extract float: {e}")))?;
        return serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| {
                ScpPyError::ValidationError(format!(
                    "float value {f} is not representable in JSON (NaN or Infinity)"
                ))
            });
    }

    // Try int extraction (Python int can be arbitrarily large, but JSON numbers
    // are limited to i64/u64/f64).
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(Value::Number(serde_json::Number::from(i)));
    }

    if obj.is_instance_of::<PyDict>() {
        let dict = obj
            .downcast::<PyDict>()
            .map_err(|e| ScpPyError::ValidationError(format!("failed to downcast to dict: {e}")))?;
        return py_dict_to_json(dict);
    }

    if obj.is_instance_of::<PyList>() {
        let list = obj
            .downcast::<PyList>()
            .map_err(|e| ScpPyError::ValidationError(format!("failed to downcast to list: {e}")))?;
        let mut arr = Vec::with_capacity(list.len());
        for item in list.iter() {
            arr.push(py_any_to_json(&item)?);
        }
        return Ok(Value::Array(arr));
    }

    let type_name = obj
        .get_type()
        .name()
        .map_or_else(|_| "<unknown>".to_owned(), |n| n.to_string());
    Err(ScpPyError::ValidationError(format!(
        "unsupported Python type for JSON conversion: {type_name} — \
         only str, int, float, bool, None, list, and dict are supported",
    )))
}

// ---------------------------------------------------------------------------
// serde_json::Value -> Python object
// ---------------------------------------------------------------------------

/// Converts a [`serde_json::Value`] to a Python object.
///
/// Recursively walks the JSON value, producing:
/// - `Value::Object` -> `dict`
/// - `Value::Array` -> `list`
/// - `Value::String` -> `str`
/// - `Value::Number` -> `int` or `float`
/// - `Value::Bool` -> `bool`
/// - `Value::Null` -> `None`
///
/// # Errors
///
/// Returns `PyErr` if Python object creation fails (should only happen on
/// memory exhaustion).
pub fn json_to_py_dict(py: Python<'_>, value: &Value) -> PyResult<PyObject> {
    json_value_to_py(py, value)
}

/// Converts a single JSON value to the corresponding Python object.
fn json_value_to_py(py: Python<'_>, value: &Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),

        Value::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any().unbind()),

        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                // Should never happen with valid serde_json numbers.
                Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unrepresentable JSON number: {n}"
                )))
            }
        }

        Value::String(s) => Ok(PyString::new(py, s).into_any().unbind()),

        Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                let py_item = json_value_to_py(py, item)?;
                list.append(py_item)?;
            }
            Ok(list.into_any().unbind())
        }

        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                let py_val = json_value_to_py(py, v)?;
                dict.set_item(k, py_val)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}
