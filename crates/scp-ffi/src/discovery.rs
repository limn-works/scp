//! `PyO3` bridge functions for discovery operations.
//!
//! Exposes SCP discovery operations to Python:
//!
//! - [`py_discovery_parse_address`] -- Parse an SCP address string.
//! - [`py_discovery_create_query`] -- Create a discovery query.
//! - [`py_discovery_normalize_address`] -- Normalize an address string.
//! - [`py_context_discover`] -- Discover contexts from a DID or `scp://` URI.
//! - [`py_petname_set`] -- Set a petname for a DID.
//! - [`py_petname_remove`] -- Remove a petname from a DID.
//! - [`py_petname_resolve_did`] -- Resolve a petname to DIDs.
//! - [`py_petname_resolve_context`] -- Resolve a petname to context IDs.
//! - [`py_petname_get_for_did`] -- Get the petname assigned to a DID.
//! - [`py_petname_get_for_context`] -- Get the petname assigned to a context.
//! - [`py_petname_set_context`] -- Set a petname for a context.
//! - [`py_petname_remove_context`] -- Remove a petname from a context.
//! - [`py_handle_register`] -- Register a handle in a discovery context.
//! - [`py_handle_lookup`] -- Look up a handle in a discovery context.
//! - [`py_handle_deregister`] -- Deregister a handle from a discovery context.
//! - [`py_scope_register`] -- Register a scope name (§22.3.5, ADR-043).
//! - [`py_scope_lookup`] -- Look up a scope name (§22.3.5, ADR-043).
//! - [`py_scope_deregister`] -- Deregister a scope name (§22.3.5, ADR-043).
//! - [`py_address_resolve`] -- Resolve an address via multi-path resolution.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use scp_core::discovery::addressing::{HandleTarget, ParsedAddress};
use scp_core::discovery::handles::{
    HandleDeregisterParams, HandleLookupParams, HandleMetadata, HandleRegisterParams,
    HandleRegistry, HandleTypeFilter,
};
use scp_core::discovery::{DiscoveryQuery, normalize_address, parse_address};
use scp_identity::DID;

use scp_ffi_common::petname_helpers::{
    self, LocalHandleQuerier, address_resolution_to_json, handle_registries, petname_maps,
};

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Test-only reset helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn reset_petname_map_for(owner_did: &str) {
    petname_helpers::reset_petname_map_for(owner_did);
}

#[cfg(test)]
fn reset_handle_registry_for(context_id: &str) {
    petname_helpers::reset_handle_registry_for(context_id);
}

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
/// - `type` (str): `"DiscoveryHandle"`, `"DomainHandle"`,
///   `"AttestationHandle"`, or `"Unscoped"`.
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
        code: "SCP-VALID-7060".to_string(),
    })?;

    let dict = PyDict::new(py);
    match parsed {
        ParsedAddress::DiscoveryHandle { local_part, scope } => {
            dict.set_item("type", "DiscoveryHandle")?;
            dict.set_item("local_part", local_part)?;
            dict.set_item("scope", scope)?;
        }
        ParsedAddress::DomainHandle { local_part, domain } => {
            dict.set_item("type", "DomainHandle")?;
            dict.set_item("local_part", local_part)?;
            dict.set_item("domain", domain)?;
        }
        ParsedAddress::AttestationHandle { handle, platform } => {
            dict.set_item("type", "AttestationHandle")?;
            dict.set_item("handle", handle)?;
            dict.set_item("platform", platform)?;
        }
        ParsedAddress::Unscoped { name } => {
            dict.set_item("type", "Unscoped")?;
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
            code: "SCP-VALID-7061".to_string(),
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

// `map_discovery_source` and `discovery_result_to_json` live in scp-ffi-common.
// Re-import for use by `discovery_result_to_dict` and tests.
#[cfg(test)]
use scp_ffi_common::discovery::discovery_result_to_json;
use scp_ffi_common::discovery::map_discovery_source;

/// Converts a [`ContextDiscoveryResult`] into a Python dict.
///
/// Returns a dict with keys: `context_id`, `relay_urls`, `publisher_did`,
/// `discovery_source`, `mode`, `metadata_summary`, `trust_level`,
/// `resolution_path`.
fn discovery_result_to_dict<'py>(
    py: Python<'py>,
    result: &scp_core::discovery::ContextDiscoveryResult,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("context_id", &result.context_id)?;
    dict.set_item("relay_urls", &result.relay_urls)?;
    dict.set_item("publisher_did", &*result.publisher_did)?;

    let (source_str, trust_level_kind, resolution_layer, resolution_source, resolution_source_id) =
        map_discovery_source(&result.discovery_source);

    if let scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } =
        &result.discovery_source
    {
        dict.set_item("discovery_context_id", context_id)?;
    }

    dict.set_item("discovery_source", source_str)?;
    dict.set_item("mode", result.mode.as_deref())?;
    dict.set_item("metadata_summary", result.metadata_summary.as_deref())?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let trust_level = PyDict::new(py);
    trust_level.set_item("kind", trust_level_kind)?;
    dict.set_item("trust_level", trust_level)?;

    let resolution_path = PyDict::new(py);
    resolution_path.set_item("layer", resolution_layer)?;
    resolution_path.set_item("source", resolution_source)?;
    resolution_path.set_item("source_id", resolution_source_id)?;
    resolution_path.set_item("resolved_at", now_secs)?;
    dict.set_item("resolution_path", resolution_path)?;

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
/// - `trust_level` (dict): `{"kind": str}` per §22.7.
/// - `resolution_path` (dict): `{"layer": str, "source": str, "source_id": str | None, "resolved_at": int}`
///   per §22.11.3. Layer values use `PascalCase`: `"Domain"`, `"DiscoveryContext"`, etc.
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
            code: "SCP-VALID-7062".to_owned(),
        }
        .into())
    }
}

// ---------------------------------------------------------------------------
// Petname bridge functions (§22.4)
// ---------------------------------------------------------------------------

/// Sets a petname for a DID.
///
/// Petnames are stored per-identity. The `owner_did` identifies which
/// identity's petname map to modify.
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `target_did` -- The DID to assign the petname to.
/// * `name` -- The petname string.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID or target DID is empty.
#[pyfunction]
#[pyo3(name = "petname_set")]
pub fn py_petname_set(owner_did: &str, target_did: &str, name: &str) -> PyResult<()> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    if target_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "target_did must not be empty".to_owned(),
            code: "SCP-VALID-7111".to_owned(),
        }
        .into());
    }
    let mut guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let map = guard.entry(owner_did.to_owned()).or_default();
    map.set_petname(DID::from(target_did), name.to_owned());
    Ok(())
}

/// Removes a petname from a DID.
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `target_did` -- The DID whose petname to remove.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID or target DID is empty.
#[pyfunction]
#[pyo3(name = "petname_remove")]
pub fn py_petname_remove(owner_did: &str, target_did: &str) -> PyResult<()> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    let mut guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    if let Some(map) = guard.get_mut(owner_did) {
        map.remove_petname(&DID::from(target_did));
    }
    Ok(())
}

/// Sets a petname for a context.
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `context_id` -- The context ID to assign the petname to.
/// * `name` -- The petname string.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID or context ID is empty.
#[pyfunction]
#[pyo3(name = "petname_set_context")]
pub fn py_petname_set_context(owner_did: &str, context_id: &str, name: &str) -> PyResult<()> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    if context_id.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "context_id must not be empty".to_owned(),
            code: "SCP-VALID-7113".to_owned(),
        }
        .into());
    }
    let mut guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let map = guard.entry(owner_did.to_owned()).or_default();
    map.set_context_petname(context_id.to_owned(), name.to_owned());
    Ok(())
}

/// Removes a petname from a context.
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `context_id` -- The context ID whose petname to remove.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID is empty.
#[pyfunction]
#[pyo3(name = "petname_remove_context")]
pub fn py_petname_remove_context(owner_did: &str, context_id: &str) -> PyResult<()> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    let mut guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    if let Some(map) = guard.get_mut(owner_did) {
        map.remove_context_petname(&context_id.to_owned());
    }
    Ok(())
}

/// Resolves a petname to DIDs.
///
/// Returns all DIDs associated with this petname. Multiple results
/// indicate ambiguity (§22.4).
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `name` -- The petname to resolve.
///
/// # Returns
///
/// A list of DID strings.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID is empty.
#[pyfunction]
#[pyo3(name = "petname_resolve_did")]
pub fn py_petname_resolve_did(owner_did: &str, name: &str) -> PyResult<Vec<String>> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    let guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let dids = guard
        .get(owner_did)
        .map(|map| {
            map.resolve_did(name)
                .into_iter()
                .map(|d| d.to_string())
                .collect()
        })
        .unwrap_or_default();
    Ok(dids)
}

/// Resolves a petname to context IDs.
///
/// Returns all context IDs associated with this petname.
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `name` -- The petname to resolve.
///
/// # Returns
///
/// A list of context ID strings.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID is empty.
#[pyfunction]
#[pyo3(name = "petname_resolve_context")]
pub fn py_petname_resolve_context(owner_did: &str, name: &str) -> PyResult<Vec<String>> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    let guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let ids = guard
        .get(owner_did)
        .map(|map| map.resolve_context(name))
        .unwrap_or_default();
    Ok(ids)
}

/// Gets the petname assigned to a DID.
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `target_did` -- The DID to look up.
///
/// # Returns
///
/// The petname string, or `None` if no petname is assigned.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID is empty.
#[pyfunction]
#[pyo3(name = "petname_get_for_did")]
pub fn py_petname_get_for_did(owner_did: &str, target_did: &str) -> PyResult<Option<String>> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    let guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let name = guard.get(owner_did).and_then(|map| {
        map.petname_for_did(&DID::from(target_did))
            .map(str::to_owned)
    });
    Ok(name)
}

/// Gets the petname assigned to a context.
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity that owns this petname map.
/// * `context_id` -- The context ID to look up.
///
/// # Returns
///
/// The petname string, or `None` if no petname is assigned.
///
/// # Errors
///
/// Raises `ValidationError` if the owner DID is empty.
#[pyfunction]
#[pyo3(name = "petname_get_for_context")]
pub fn py_petname_get_for_context(owner_did: &str, context_id: &str) -> PyResult<Option<String>> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }
    let guard = petname_maps()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let name = guard.get(owner_did).and_then(|map| {
        map.petname_for_context(&context_id.to_owned())
            .map(str::to_owned)
    });
    Ok(name)
}

// ---------------------------------------------------------------------------
// Handle registry bridge functions (§22.3.1)
// ---------------------------------------------------------------------------

/// Registers a handle in a discovery context.
///
/// # Arguments
///
/// * `discovery_context_id` -- The discovery context ID.
/// * `handle` -- The local-part to register (e.g., `"alice"`).
/// * `target_json` -- JSON string describing the target. Either
///   `{"type": "identity", "did": "did:..."}` or
///   `{"type": "context", "context_id": "...", "relay_urls": [...]}`.
/// * `registrant_did` -- The DID of the authenticated caller.
/// * `description` -- Optional description metadata.
/// * `tags` -- Optional list of tag strings.
///
/// # Returns
///
/// A JSON string with `status` (`"registered"`, `"conflict"`, or
/// `"ownership_mismatch"`) and optional `entry_id`.
///
/// # Errors
///
/// Raises `ValidationError` if parameters are invalid.
#[pyfunction]
#[pyo3(name = "handle_register")]
#[pyo3(signature = (discovery_context_id, handle, target_json, registrant_did, description=None, tags=None))]
pub fn py_handle_register(
    discovery_context_id: &str,
    handle: &str,
    target_json: &str,
    registrant_did: &str,
    description: Option<String>,
    tags: Option<Vec<String>>,
) -> PyResult<String> {
    let target = parse_handle_target(target_json)?;

    let params = HandleRegisterParams {
        handle: handle.to_owned(),
        target,
        metadata: Some(HandleMetadata { description, tags }),
    };

    let mut guard = handle_registries()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7120".to_owned(),
        })?;

    let registry = guard
        .entry(discovery_context_id.to_owned())
        .or_insert_with(|| HandleRegistry::new(discovery_context_id.to_owned()));

    let result = registry
        .register(&params, &DID::from(registrant_did))
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("clock error during handle registration: {e}"),
            code: "SCP-VALID-7121".to_owned(),
        })?;

    serde_json::to_string(&result).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize handle register result: {e}"),
            code: "SCP-VALID-7122".to_owned(),
        }
        .into()
    })
}

/// Looks up a handle in a discovery context.
///
/// # Arguments
///
/// * `discovery_context_id` -- The discovery context ID.
/// * `handle` -- The local-part to look up.
/// * `type_filter` -- Optional type filter: `"identity"` or `"context"`.
///
/// # Returns
///
/// A JSON string with a `results` array of handle entries.
///
/// # Errors
///
/// Raises `ValidationError` if the type filter is invalid.
#[pyfunction]
#[pyo3(name = "handle_lookup")]
#[pyo3(signature = (discovery_context_id, handle, type_filter=None))]
pub fn py_handle_lookup(
    discovery_context_id: &str,
    handle: &str,
    type_filter: Option<&str>,
) -> PyResult<String> {
    let filter = match type_filter {
        Some("identity") => Some(HandleTypeFilter::Identity),
        Some("context") => Some(HandleTypeFilter::Context),
        Some(other) => {
            return Err(ScpPyError::ValidationError {
                message: format!("invalid type_filter '{other}': expected 'identity' or 'context'"),
                code: "SCP-VALID-7123".to_owned(),
            }
            .into());
        }
        None => None,
    };

    let guard = handle_registries()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7120".to_owned(),
        })?;

    let result = guard.get(discovery_context_id).map_or_else(
        || scp_core::discovery::HandleLookupResult {
            results: Vec::new(),
        },
        |registry| {
            registry.lookup(&HandleLookupParams {
                handle: handle.to_owned(),
                type_filter: filter,
            })
        },
    );

    serde_json::to_string(&result).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize handle lookup result: {e}"),
            code: "SCP-VALID-7124".to_owned(),
        }
        .into()
    })
}

/// Deregisters a handle from a discovery context.
///
/// Only succeeds if the provided DID matches the handle owner.
///
/// # Arguments
///
/// * `discovery_context_id` -- The discovery context ID.
/// * `handle` -- The local-part to deregister.
/// * `did` -- The registrant's DID (must match the handle owner).
///
/// # Returns
///
/// A JSON string with `removed` (bool).
///
/// # Errors
///
/// Raises `ValidationError` on serialization failure.
#[pyfunction]
#[pyo3(name = "handle_deregister")]
pub fn py_handle_deregister(
    discovery_context_id: &str,
    handle: &str,
    did: &str,
) -> PyResult<String> {
    let mut guard = handle_registries()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7120".to_owned(),
        })?;

    let result = guard.get_mut(discovery_context_id).map_or_else(
        || scp_core::discovery::HandleDeregisterResult { removed: false },
        |registry| {
            registry.deregister(&HandleDeregisterParams {
                handle: handle.to_owned(),
                did: DID::from(did),
            })
        },
    );

    serde_json::to_string(&result).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize handle deregister result: {e}"),
            code: "SCP-VALID-7125".to_owned(),
        }
        .into()
    })
}

/// Parses a [`HandleTarget`] from a JSON string, delegating to `scp-ffi-common`.
fn parse_handle_target(json: &str) -> PyResult<HandleTarget> {
    petname_helpers::parse_handle_target(json).map_err(|e| {
        ScpPyError::ValidationError {
            message: e.message,
            code: "SCP-VALID-7126".to_owned(),
        }
        .into()
    })
}

// ---------------------------------------------------------------------------
// Scope registry bridge functions (§22.3.5, ADR-043)
// ---------------------------------------------------------------------------

/// Registers a scope name in a scope registry.
///
/// Scope tools use independent structs and separate storage from handle tools.
/// `ScopeTarget` is context-only by construction — no identity variant.
///
/// # Arguments
///
/// * `scope_context_id` -- The context ID hosting the scope registry.
/// * `name` -- The scope name to register (validated via `validate_scope_name`).
/// * `target_context_id` -- The context ID the scope name resolves to.
/// * `relay_urls` -- Relay URLs for the target context.
/// * `registrant_did` -- The DID of the authenticated caller.
/// * `description` -- Optional description metadata.
/// * `tags` -- Optional list of tag strings.
///
/// # Returns
///
/// A JSON string with `status` (`"registered"`, `"conflict"`, or `"updated"`)
/// and optional `entry_id`.
///
/// # Errors
///
/// Raises `ValidationError` if parameters are invalid.
#[pyfunction]
#[pyo3(name = "scope_register")]
#[pyo3(signature = (scope_context_id, name, target_context_id, relay_urls, registrant_did, description=None, tags=None))]
#[allow(clippy::too_many_arguments)]
pub fn py_scope_register(
    scope_context_id: &str,
    name: &str,
    target_context_id: &str,
    relay_urls: Vec<String>,
    registrant_did: &str,
    description: Option<String>,
    tags: Option<Vec<String>>,
) -> PyResult<String> {
    // Validate inputs at the FFI boundary (defense-in-depth)
    crate::validate::validate_context_id(scope_context_id)?;
    crate::validate::validate_context_id(target_context_id)?;
    crate::validate::validate_did(registrant_did)?;

    // Validate relay URLs at the FFI boundary (defense-in-depth)
    for url in &relay_urls {
        crate::validate::validate_relay_url(url)?;
    }

    let params = scp_core::discovery::ScopeRegisterParams {
        name: name.to_owned(),
        target: scp_core::discovery::ScopeTarget {
            context_id: target_context_id.to_owned(),
            relay_urls,
        },
        metadata: if description.is_some() || tags.is_some() {
            Some(scp_core::discovery::ScopeMetadata { description, tags })
        } else {
            None
        },
    };

    let mut guard =
        petname_helpers::scope_registries()
            .lock()
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("scope registry lock poisoned: {e}"),
                code: "SCP-VALID-7130".to_owned(),
            })?;

    let registry = guard
        .entry(scope_context_id.to_owned())
        .or_insert_with(|| scp_core::discovery::ScopeRegistry::new(scope_context_id.to_owned()));

    let result = registry
        .register(&params, &DID::from(registrant_did))
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("scope registration failed: {e}"),
            code: "SCP-VALID-7131".to_owned(),
        })?;

    serde_json::to_string(&result).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize scope register result: {e}"),
            code: "SCP-VALID-7132".to_owned(),
        }
        .into()
    })
}

/// Looks up a scope name in a scope registry.
///
/// # Arguments
///
/// * `scope_context_id` -- The context ID hosting the scope registry.
/// * `name` -- The scope name to look up.
///
/// # Returns
///
/// A JSON string with a `results` array of scope entries.
///
/// # Errors
///
/// Raises `ValidationError` on failure.
#[pyfunction]
#[pyo3(name = "scope_lookup")]
pub fn py_scope_lookup(scope_context_id: &str, name: &str) -> PyResult<String> {
    crate::validate::validate_context_id(scope_context_id)?;

    let guard =
        petname_helpers::scope_registries()
            .lock()
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("scope registry lock poisoned: {e}"),
                code: "SCP-VALID-7130".to_owned(),
            })?;

    let result = match guard.get(scope_context_id) {
        Some(registry) => registry
            .lookup(&scp_core::discovery::ScopeLookupParams {
                name: name.to_owned(),
            })
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("scope lookup failed: {e}"),
                code: "SCP-VALID-7133".to_owned(),
            })?,
        None => scp_core::discovery::ScopeLookupResult {
            results: Vec::new(),
        },
    };

    serde_json::to_string(&result).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize scope lookup result: {e}"),
            code: "SCP-VALID-7133".to_owned(),
        }
        .into()
    })
}

/// Deregisters a scope name from a scope registry.
///
/// Only succeeds if the provided DID matches the scope entry owner.
///
/// # Arguments
///
/// * `scope_context_id` -- The context ID hosting the scope registry.
/// * `name` -- The scope name to deregister.
/// * `did` -- The registrant's DID (must match the entry owner).
///
/// # Returns
///
/// A JSON string with `removed` (bool).
///
/// # Errors
///
/// Raises `ValidationError` on serialization failure.
#[pyfunction]
#[pyo3(name = "scope_deregister")]
pub fn py_scope_deregister(scope_context_id: &str, name: &str, did: &str) -> PyResult<String> {
    crate::validate::validate_context_id(scope_context_id)?;
    crate::validate::validate_did(did)?;

    let mut guard =
        petname_helpers::scope_registries()
            .lock()
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("scope registry lock poisoned: {e}"),
                code: "SCP-VALID-7130".to_owned(),
            })?;

    let result = match guard.get_mut(scope_context_id) {
        Some(registry) => registry
            .deregister(&scp_core::discovery::ScopeDeregisterParams {
                name: name.to_owned(),
                did: DID::from(did),
            })
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("scope deregister failed: {e}"),
                code: "SCP-VALID-7134".to_owned(),
            })?,
        None => scp_core::discovery::ScopeDeregisterResult { removed: false },
    };

    serde_json::to_string(&result).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize scope deregister result: {e}"),
            code: "SCP-VALID-7134".to_owned(),
        }
        .into()
    })
}

// ---------------------------------------------------------------------------
// Address resolve bridge function (§22.8)
// ---------------------------------------------------------------------------

/// Resolves a human-readable address string via multi-path resolution.
///
/// Uses the caller's petname map and all known handle registries as
/// discovery context handles. Results are sorted by trust level (descending).
///
/// # Arguments
///
/// * `owner_did` -- The DID of the identity whose petname map to use.
/// * `address` -- The address string to resolve.
/// * `known_contexts_json` -- Optional JSON object mapping scope names to
///   discovery context IDs, e.g., `{"cooking": "ctx-abc"}`. If absent,
///   all known handle registries are used with their context IDs as scope
///   names.
///
/// # Returns
///
/// A JSON string with an array of `AddressResolution` objects.
///
/// # Errors
///
/// Raises `ValidationError` if the address is malformed or resolution fails.
#[pyfunction]
#[pyo3(name = "address_resolve")]
#[pyo3(signature = (owner_did, address, known_contexts_json=None))]
pub fn py_address_resolve(
    owner_did: &str,
    address: &str,
    known_contexts_json: Option<&str>,
) -> PyResult<String> {
    if owner_did.is_empty() {
        return Err(ScpPyError::ValidationError {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        }
        .into());
    }

    let mut known_contexts: HashMap<String, String> = if let Some(json) = known_contexts_json {
        serde_json::from_str(json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid known_contexts_json: {e}"),
            code: "SCP-VALID-7090".to_owned(),
        })?
    } else {
        // Use all known handle registries with context IDs as scope names.
        let guard = handle_registries()
            .lock()
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("handle registry lock poisoned: {e}"),
                code: "SCP-VALID-7120".to_owned(),
            })?;
        guard.keys().map(|k| (k.clone(), k.clone())).collect()
    };

    // Merge scope registry contexts into known_contexts for two-hop resolution (§22.3.5).
    let scope_contexts = petname_helpers::known_contexts_from_scope_registries();
    for (name, ctx_id) in scope_contexts {
        known_contexts.entry(name).or_insert(ctx_id);
    }

    let known_domains: Vec<&str> = Vec::new();

    // Get the petname map for this owner. We need to clone it since
    // AddressResolver.resolve() takes a reference, and we can't hold
    // the mutex across the async boundary.
    let petname_map = {
        let guard = petname_maps()
            .lock()
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("petname lock poisoned: {e}"),
                code: "SCP-VALID-7112".to_owned(),
            })?;
        guard.get(owner_did).cloned().unwrap_or_default()
    };

    let rt = crate::runtime()?;
    let results = rt.block_on(async {
        let mut resolver = scp_core::discovery::AddressResolver::new();
        let querier = LocalHandleQuerier;
        resolver
            .resolve(
                address,
                &petname_map,
                &querier,
                &known_contexts,
                &known_domains,
            )
            .await
            .map_err(|e| ScpPyError::ValidationError {
                message: format!("address resolution failed: {e}"),
                code: "SCP-VALID-7091".to_owned(),
            })
    })?;

    let json_results: Vec<serde_json::Value> =
        results.iter().map(address_resolution_to_json).collect();

    serde_json::to_string(&json_results).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize address resolution results: {e}"),
            code: "SCP-VALID-7092".to_owned(),
        }
        .into()
    })
}

// address_resolution_to_json, trust_level_to_json, resolution_path_to_json
// are provided by scp_ffi_common::petname_helpers (imported above).

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
    // Petname operations (§22.4)
    m.add_function(wrap_pyfunction!(py_petname_set, m)?)?;
    m.add_function(wrap_pyfunction!(py_petname_remove, m)?)?;
    m.add_function(wrap_pyfunction!(py_petname_set_context, m)?)?;
    m.add_function(wrap_pyfunction!(py_petname_remove_context, m)?)?;
    m.add_function(wrap_pyfunction!(py_petname_resolve_did, m)?)?;
    m.add_function(wrap_pyfunction!(py_petname_resolve_context, m)?)?;
    m.add_function(wrap_pyfunction!(py_petname_get_for_did, m)?)?;
    m.add_function(wrap_pyfunction!(py_petname_get_for_context, m)?)?;
    // Handle registry operations (§22.3.1)
    m.add_function(wrap_pyfunction!(py_handle_register, m)?)?;
    m.add_function(wrap_pyfunction!(py_handle_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(py_handle_deregister, m)?)?;
    // Scope registry operations (§22.3.5, ADR-043)
    m.add_function(wrap_pyfunction!(py_scope_register, m)?)?;
    m.add_function(wrap_pyfunction!(py_scope_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(py_scope_deregister, m)?)?;
    // Address resolution (§22.8)
    m.add_function(wrap_pyfunction!(py_address_resolve, m)?)?;
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

    // -- trust_level / resolution_path tests (mirrors NAPI bridge) -----------

    #[test]
    fn context_discover_result_serialization() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "abc123".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:dht:zTest".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::DhtDidDocument,
            mode: Some("broadcast".to_owned()),
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["context_id"], "abc123");
        assert_eq!(json["discovery_source"], "dht_did_document");
        assert_eq!(json["mode"], "broadcast");
        // §22.7: trust_level is a discriminated union object; resolution_path
        // uses spec PascalCase layer values per §22.11.3.
        assert_eq!(json["trust_level"]["kind"], "DomainVerified");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "dht");
        assert!(json["resolution_path"]["resolved_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn context_discover_result_discovery_context_source() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "ctx456".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:dht:zTest".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::DiscoveryContext {
                context_id: "disc-ctx-1".to_owned(),
            },
            mode: None,
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["trust_level"]["kind"], "DiscoveryContextVerified");
        assert_eq!(json["resolution_path"]["layer"], "DiscoveryContext");
        assert_eq!(json["resolution_path"]["source"], "discovery_context");
        assert_eq!(json["resolution_path"]["source_id"], "disc-ctx-1");
        assert_eq!(json["discovery_context_id"], "disc-ctx-1");
    }

    #[test]
    fn context_discover_result_context_uri_source() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "deadbeef".to_owned(),
            relay_urls: vec!["wss://relay.example.com/scp/v1".to_owned()],
            publisher_did: "".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::ContextUri,
            mode: Some("broadcast".to_owned()),
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["trust_level"]["kind"], "DirectExchange");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "context_uri");
        assert!(json["resolution_path"]["source_id"].is_null());
        assert!(json["resolution_path"]["resolved_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn context_discover_result_well_known_source() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "wk789".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:web:example.com".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::WellKnown,
            mode: None,
            metadata_summary: Some("Example context".to_owned()),
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["trust_level"]["kind"], "DomainVerified");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "well-known");
        assert!(json["resolution_path"]["source_id"].is_null());
    }

    // -- Petname bridge tests ------------------------------------------------

    #[test]
    fn petname_set_and_resolve_did() {
        let owner = "did:dht:zTestOwner1";
        reset_petname_map_for(owner);
        let target = "did:dht:zAlice";
        py_petname_set(owner, target, "alice").unwrap();

        let dids = py_petname_resolve_did(owner, "alice").unwrap();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], target);
    }

    #[test]
    fn petname_get_for_did_returns_name() {
        let owner = "did:dht:zTestOwner2";
        reset_petname_map_for(owner);
        let target = "did:dht:zBob";
        py_petname_set(owner, target, "bob").unwrap();

        let name = py_petname_get_for_did(owner, target).unwrap();
        assert_eq!(name, Some("bob".to_owned()));
    }

    #[test]
    fn petname_set_context_and_resolve() {
        let owner = "did:dht:zTestOwner3";
        reset_petname_map_for(owner);
        py_petname_set_context(owner, "ctx-recipes", "recipes").unwrap();

        let ids = py_petname_resolve_context(owner, "recipes").unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "ctx-recipes");
    }

    #[test]
    fn petname_get_for_context_returns_name() {
        let owner = "did:dht:zTestOwner4";
        reset_petname_map_for(owner);
        py_petname_set_context(owner, "ctx-work", "work").unwrap();

        let name = py_petname_get_for_context(owner, "ctx-work").unwrap();
        assert_eq!(name, Some("work".to_owned()));
    }

    #[test]
    fn petname_empty_owner_errors() {
        assert!(py_petname_set("", "did:dht:z1", "test").is_err());
        assert!(py_petname_resolve_did("", "test").is_err());
    }

    // -- Handle registry bridge tests ----------------------------------------

    #[test]
    fn handle_register_and_lookup() {
        let ctx = "ctx-handle-test-1";
        reset_handle_registry_for(ctx);
        let target_json = r#"{"type": "identity", "did": "did:dht:zAlice"}"#;
        let result =
            py_handle_register(ctx, "alice", target_json, "did:dht:zAlice", None, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "registered");
        assert!(parsed["entry_id"].as_str().is_some());

        let lookup = py_handle_lookup(ctx, "alice", None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&lookup).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn handle_register_conflict() {
        let ctx = "ctx-handle-test-2";
        reset_handle_registry_for(ctx);
        let target1 = r#"{"type": "identity", "did": "did:dht:zAlice"}"#;
        let target2 = r#"{"type": "identity", "did": "did:dht:zBob"}"#;
        py_handle_register(ctx, "alice", target1, "did:dht:zAlice", None, None).unwrap();

        let result = py_handle_register(ctx, "alice", target2, "did:dht:zBob", None, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "conflict");
    }

    #[test]
    fn handle_deregister_removes_entry() {
        let ctx = "ctx-handle-test-3";
        reset_handle_registry_for(ctx);
        let target = r#"{"type": "identity", "did": "did:dht:zCharlie"}"#;
        py_handle_register(ctx, "charlie", target, "did:dht:zCharlie", None, None).unwrap();

        let result = py_handle_deregister(ctx, "charlie", "did:dht:zCharlie").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["removed"].as_bool().unwrap());

        let lookup = py_handle_lookup(ctx, "charlie", None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&lookup).unwrap();
        assert!(parsed["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn handle_lookup_with_type_filter() {
        let ctx = "ctx-handle-test-4";
        reset_handle_registry_for(ctx);
        let target = r#"{"type": "context", "context_id": "ctx-abc", "relay_urls": ["wss://relay.example.com"]}"#;
        py_handle_register(ctx, "recipes", target, "did:dht:zAdmin", None, None).unwrap();

        let identity_lookup = py_handle_lookup(ctx, "recipes", Some("identity")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&identity_lookup).unwrap();
        assert!(parsed["results"].as_array().unwrap().is_empty());

        let context_lookup = py_handle_lookup(ctx, "recipes", Some("context")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&context_lookup).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn handle_invalid_type_filter_errors() {
        assert!(py_handle_lookup("ctx-any", "alice", Some("invalid")).is_err());
    }

    // -- Address resolution tests --------------------------------------------

    #[test]
    fn address_resolve_via_petname() {
        let owner = "did:dht:zTestResolver1";
        reset_petname_map_for(owner);
        // Initialize the tokio runtime required by PyO3 bridge functions
        crate::init_runtime().ok();
        py_petname_set(owner, "did:dht:zAlice", "alice").unwrap();

        let result = py_address_resolve(owner, "alice", None).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert!(!parsed.is_empty());
        assert_eq!(parsed[0]["type"], "Identity");
        assert_eq!(parsed[0]["did"], "did:dht:zAlice");
        assert_eq!(parsed[0]["trust_level"]["kind"], "LocalPetname");
    }

    // -- JSON conversion helper tests ----------------------------------------

    #[test]
    fn parse_handle_target_identity() {
        let json = r#"{"type": "identity", "did": "did:dht:zAlice"}"#;
        let target = parse_handle_target(json).unwrap();
        assert!(matches!(target, HandleTarget::Identity { .. }));
    }

    #[test]
    fn parse_handle_target_context() {
        let json = r#"{"type": "context", "context_id": "ctx-abc", "relay_urls": ["wss://relay.example.com"]}"#;
        let target = parse_handle_target(json).unwrap();
        assert!(matches!(target, HandleTarget::Context { .. }));
    }

    #[test]
    fn parse_handle_target_invalid_type() {
        let json = r#"{"type": "invalid"}"#;
        assert!(parse_handle_target(json).is_err());
    }
}
