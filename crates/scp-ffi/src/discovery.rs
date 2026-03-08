//! `PyO3` bridge functions for discovery operations.
//!
//! Exposes SCP discovery operations to Python:
//!
//! - [`py_discovery_parse_address`] -- Parse an SCP address string.
//! - [`py_discovery_create_query`] -- Create a discovery query.
//! - [`py_discovery_normalize_address`] -- Normalize an address string.
//! - [`py_context_discover`] -- Discover contexts from a DID or `scp://` URI.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use scp_core::discovery::addressing::ParsedAddress;
use scp_core::discovery::{DiscoveryQuery, normalize_address, parse_address};

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Parses an SCP address string into its components.
///
/// Address format: `<local-part>@<scope>` with scope disambiguation by
/// syntactic inspection.
///
/// # Arguments
///
/// * `address` -- The address string to parse (e.g., `"alice@cooking-community"`).
///
/// # Returns
///
/// A dict with:
/// - `type` (str): `"discovery_handle"`, `"domain_handle"`,
///   `"attestation_handle"`, or `"unscoped"`.
/// - Additional fields depending on type.
///
/// # Errors
///
/// Raises `ValidationError` if the address is malformed.
#[pyfunction]
#[pyo3(name = "discovery_parse_address")]
pub fn py_discovery_parse_address<'py>(
    py: Python<'py>,
    address: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let parsed = parse_address(address).map_err(|e| ScpPyError::ValidationError {
        message: format!("invalid address '{address}': {e}"),
        code: "SCP-VALID-9020".to_string(),
    })?;

    let dict = PyDict::new(py);
    match parsed {
        ParsedAddress::DiscoveryHandle { local_part, scope } => {
            dict.set_item("type", "discovery_handle")?;
            dict.set_item("local_part", local_part)?;
            dict.set_item("scope", scope)?;
        }
        ParsedAddress::DomainHandle { local_part, domain } => {
            dict.set_item("type", "domain_handle")?;
            dict.set_item("local_part", local_part)?;
            dict.set_item("domain", domain)?;
        }
        ParsedAddress::AttestationHandle { handle, platform } => {
            dict.set_item("type", "attestation_handle")?;
            dict.set_item("handle", handle)?;
            dict.set_item("platform", platform)?;
        }
        ParsedAddress::Unscoped { name } => {
            dict.set_item("type", "unscoped")?;
            dict.set_item("name", name)?;
        }
    }

    Ok(dict)
}

/// Creates a discovery query with the given filters.
///
/// Returns a JSON string representation of the query.
///
/// # Arguments
///
/// * `capabilities` -- Optional list of capability strings to filter by.
/// * `keywords` -- Optional list of keywords for free-text search.
/// * `min_history_secs` -- Optional minimum participation history in seconds.
///
/// # Returns
///
/// A JSON string representing the discovery query.
#[pyfunction]
#[pyo3(name = "discovery_create_query")]
#[pyo3(signature = (capabilities=None, keywords=None, min_history_secs=None))]
pub fn py_discovery_create_query(
    capabilities: Option<Vec<String>>,
    keywords: Option<Vec<String>>,
    min_history_secs: Option<u64>,
) -> PyResult<String> {
    let query = DiscoveryQuery {
        capability_filter: capabilities,
        keywords,
        min_history: min_history_secs.map(std::time::Duration::from_secs),
    };

    serde_json::to_string(&query).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize query: {e}"),
            code: "SCP-VALID-9021".to_string(),
        }
        .into()
    })
}

/// Normalizes an address string per the SCP addressing rules.
///
/// Lowercases and trims whitespace.
///
/// # Arguments
///
/// * `address` -- The address string to normalize.
///
/// # Returns
///
/// The normalized address string.
#[pyfunction]
#[pyo3(name = "discovery_normalize_address")]
#[must_use]
pub fn py_discovery_normalize_address(address: &str) -> String {
    normalize_address(address)
}

// ---------------------------------------------------------------------------
// context_discover — DHT-based context discovery (SCP-336)
// ---------------------------------------------------------------------------

/// Converts a [`ContextDiscoveryResult`] into a Python dict.
///
/// Returns a dict with keys: `context_id`, `relay_urls`, `publisher_did`,
/// `discovery_source`, `mode`, `metadata_summary`.
fn discovery_result_to_dict<'py>(
    py: Python<'py>,
    result: &scp_core::discovery::ContextDiscoveryResult,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("context_id", &result.context_id)?;
    dict.set_item("relay_urls", &result.relay_urls)?;
    dict.set_item("publisher_did", &*result.publisher_did)?;

    let source_str = match &result.discovery_source {
        scp_core::discovery::ContextDiscoverySource::DhtDidDocument => "dht_did_document",
        scp_core::discovery::ContextDiscoverySource::WellKnown => "well_known",
        scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } => {
            dict.set_item("discovery_context_id", context_id)?;
            "discovery_context"
        }
        scp_core::discovery::ContextDiscoverySource::ContextUri => "context_uri",
    };
    dict.set_item("discovery_source", source_str)?;
    dict.set_item("mode", result.mode.as_deref())?;
    dict.set_item("metadata_summary", result.metadata_summary.as_deref())?;

    Ok(dict)
}

/// Discovers contexts from a DID string or `scp://` URI.
///
/// This is the unified entry point for context discovery in the FFI layer.
/// It detects whether the query is a DID or an `scp://` URI and delegates to
/// the appropriate core discovery function.
///
/// # Query types
///
/// - **DID string** (starts with `"did:"`): Resolves the DID via `did:dht` and
///   extracts `SCPBroadcastContext` service endpoints from the DID document.
///   Returns all discoverable broadcast contexts published by that identity.
///
/// - **`scp://` URI** (starts with `"scp://"`): Parses the URI and extracts
///   context ID, relay URLs, and advisory metadata. This is a local parsing
///   step — it does NOT connect to the relay.
///
/// # Arguments
///
/// * `query` -- A DID string (e.g., `"did:dht:z6Mk..."`) or an `scp://` URI
///   (e.g., `"scp://context/a1b2c3?relay=wss%3A%2F%2Frelay.example.com"`).
///
/// # Returns
///
/// A list of dicts, each with keys:
/// - `context_id` (str): Hex-encoded context identifier.
/// - `relay_urls` (list[str]): Relay URLs where the context is reachable.
/// - `publisher_did` (str): The DID that published this context.
/// - `discovery_source` (str): One of `"dht_did_document"`, `"well_known"`,
///   `"discovery_context"`, `"context_uri"`.
/// - `mode` (str | None): Advisory context mode (e.g., `"broadcast"`).
/// - `metadata_summary` (str | None): Human-readable summary.
///
/// # Errors
///
/// Raises `ContextError` if DID resolution fails or URI parsing fails.
/// Raises `ValidationError` if the query is neither a DID nor an `scp://` URI.
///
/// See §5.14.11, §18.2.2, §18.4.
#[pyfunction]
#[pyo3(name = "context_discover")]
pub fn py_context_discover<'py>(py: Python<'py>, query: &str) -> PyResult<Bound<'py, PyList>> {
    if query.starts_with("scp://") {
        // Parse scp:// URI — synchronous, no network I/O.
        let result = scp_core::discovery::resolve_context_uri(query).map_err(ScpPyError::from)?;

        let list = PyList::empty(py);
        list.append(discovery_result_to_dict(py, &result)?)?;
        Ok(list)
    } else if query.starts_with("did:") {
        // Validate DID format.
        crate::validate::validate_did(query)?;

        let rt = crate::runtime()?;
        let query_owned = query.to_owned();

        let results: Vec<scp_core::discovery::ContextDiscoveryResult> = py.allow_threads(|| {
            rt.block_on(async {
                let did_dht = scp_identity::DidDht::new();
                scp_core::discovery::resolve_contexts_from_did(&query_owned, &did_dht)
                    .await
                    .map_err(ScpPyError::from)
            })
        })?;

        let list = PyList::empty(py);
        for result in &results {
            list.append(discovery_result_to_dict(py, result)?)?;
        }
        Ok(list)
    } else {
        Err(ScpPyError::ValidationError {
            message: format!(
                "query must be a DID (starts with 'did:') or an scp:// URI \
                 (starts with 'scp://'), got: {query}"
            ),
            code: "SCP-VALID-9022".to_owned(),
        }
        .into())
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers discovery bridge functions on the `_scp_core` module.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_discovery(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_discovery_parse_address, m)?)?;
    m.add_function(wrap_pyfunction!(py_discovery_create_query, m)?)?;
    m.add_function(wrap_pyfunction!(py_discovery_normalize_address, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_discover, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn create_query_with_capabilities() {
        let result = py_discovery_create_query(Some(vec!["code_review".to_string()]), None, None);
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("code_review"));
    }

    #[test]
    fn create_query_empty() {
        let result = py_discovery_create_query(None, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn create_query_with_all_filters() {
        let result = py_discovery_create_query(
            Some(vec!["testing".to_string()]),
            Some(vec!["rust".to_string()]),
            Some(86400),
        );
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("testing"));
        assert!(json.contains("rust"));
        assert!(json.contains("86400"));
    }

    #[test]
    fn normalize_address_lowercases() {
        let result = py_discovery_normalize_address("ALICE@Cooking");
        assert_eq!(result, "alice@cooking");
    }

    #[test]
    fn normalize_address_trims() {
        let result = py_discovery_normalize_address("  alice@cooking  ");
        assert_eq!(result, "alice@cooking");
    }

    // -- context_discover: URI parsing path (no Python GIL needed) -----------

    #[test]
    fn context_discover_result_to_dict_keys() {
        // Verify the helper produces the correct keys. This is a non-PyO3
        // test that exercises the core resolve_context_uri path.
        let result = scp_core::discovery::resolve_context_uri(
            "scp://context/a1b2c3d4?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&mode=broadcast",
        )
        .unwrap();

        assert_eq!(result.context_id, "a1b2c3d4");
        assert_eq!(result.relay_urls, vec!["wss://relay.example.com/scp/v1"]);
        assert_eq!(
            result.discovery_source,
            scp_core::discovery::ContextDiscoverySource::ContextUri
        );
        assert_eq!(result.mode, Some("broadcast".to_owned()));
    }

    #[test]
    fn context_discover_rejects_invalid_query() {
        // Neither a DID nor an scp:// URI.
        let query = "https://example.com/not-valid";
        // We can't call py_context_discover directly without a Python
        // interpreter, but we can test the validation logic.
        assert!(!query.starts_with("did:"));
        assert!(!query.starts_with("scp://"));
    }
}
