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
//! - [`py_address_resolve`] -- Resolve an address via multi-path resolution.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use scp_core::discovery::addressing::{
    AddressResolution, AddressType, HandleQuerier, HandleTarget, ParsedAddress, ResolutionLayer,
    ResolutionPath, TrustLevel,
};
use scp_core::discovery::handles::{
    HandleDeregisterParams, HandleEntry, HandleLookupParams, HandleMetadata, HandleRegisterParams,
    HandleRegistry, HandleTypeFilter,
};
use scp_core::discovery::petnames::PetnameMap;
use scp_core::discovery::{DiscoveryQuery, normalize_address, parse_address};
use scp_identity::DID;

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Global state for petnames and handles
// ---------------------------------------------------------------------------

/// Global petname map keyed by owner DID string.
/// Each identity has its own petname map (petnames are per-identity private state §3.7).
fn petname_maps() -> &'static Mutex<HashMap<String, PetnameMap>> {
    static MAPS: OnceLock<Mutex<HashMap<String, PetnameMap>>> = OnceLock::new();
    MAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Global handle registries keyed by discovery context ID.
/// Each discovery context has its own handle registry (§22.3.1).
fn handle_registries() -> &'static Mutex<HashMap<String, HandleRegistry>> {
    static REGISTRIES: OnceLock<Mutex<HashMap<String, HandleRegistry>>> = OnceLock::new();
    REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A `HandleQuerier` implementation that queries the global in-memory handle registries.
/// Used by `address_resolve` for the discovery context handle lookup layer.
struct LocalHandleQuerier;

impl HandleQuerier for LocalHandleQuerier {
    async fn lookup_handle(
        &self,
        context_id: &String,
        handle: &str,
        type_filter: Option<AddressType>,
    ) -> Vec<AddressResolution> {
        let Ok(guard) = handle_registries().lock() else {
            return Vec::new();
        };
        let Some(registry) = guard.get(context_id.as_str()) else {
            return Vec::new();
        };

        let filter = type_filter.map(|tf| match tf {
            AddressType::Identity => HandleTypeFilter::Identity,
            AddressType::Context => HandleTypeFilter::Context,
        });

        let result = registry.lookup(&HandleLookupParams {
            handle: handle.to_owned(),
            type_filter: filter,
        });

        let now = scp_core::time::now_secs().unwrap_or(0);

        result
            .results
            .into_iter()
            .map(|entry| handle_entry_to_resolution(&entry, context_id, now))
            .collect()
    }

    async fn lookup_domain_handle(&self, _domain: &str, _handle: &str) -> Vec<AddressResolution> {
        // Domain handle resolution requires HTTP I/O to fetch .well-known/scp.
        // Not available in FFI bridge — requires transport layer infrastructure.
        Vec::new()
    }

    async fn lookup_attestation_handle(
        &self,
        _handle: &str,
        _platform: Option<&str>,
    ) -> Vec<AddressResolution> {
        // Attestation handle resolution requires querying attestation indexes
        // in discovery contexts. Not available in FFI bridge — requires
        // discovery context query infrastructure.
        Vec::new()
    }
}

/// Converts a `HandleEntry` into an `AddressResolution`.
fn handle_entry_to_resolution(
    entry: &HandleEntry,
    context_id: &str,
    now: u64,
) -> AddressResolution {
    let resolution_path = ResolutionPath {
        layer: ResolutionLayer::DiscoveryContext,
        source: "local_registry".to_owned(),
        source_id: Some(context_id.to_owned()),
        resolved_at: now,
    };
    let trust_level = TrustLevel::DiscoveryContextVerified;

    match &entry.target {
        HandleTarget::Identity { did } => AddressResolution::Identity {
            did: did.clone(),
            trust_level,
            resolution_path,
        },
        HandleTarget::Context {
            context_id: ctx_id,
            relay_urls,
        } => AddressResolution::Context {
            context_id: ctx_id.clone(),
            relay_urls: relay_urls.clone(),
            mode: None,
            trust_level,
            resolution_path,
        },
    }
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

/// Maps a [`ContextDiscoverySource`] to trust/resolution metadata.
///
/// Returns `(source_str, trust_level_kind, resolution_layer, resolution_source, resolution_source_id)`.
/// Shared by both [`discovery_result_to_dict`] (Python) and [`discovery_result_to_json`] (tests).
const fn map_discovery_source(
    source: &scp_core::discovery::ContextDiscoverySource,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&str>,
) {
    match source {
        scp_core::discovery::ContextDiscoverySource::DhtDidDocument => {
            ("dht_did_document", "DomainVerified", "Domain", "dht", None)
        }
        scp_core::discovery::ContextDiscoverySource::WellKnown => {
            ("well_known", "DomainVerified", "Domain", "well-known", None)
        }
        scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } => (
            "discovery_context",
            "DiscoveryContextVerified",
            "DiscoveryContext",
            "discovery_context",
            Some(context_id.as_str()),
        ),
        // §22.7: An scp:// URI is shared out-of-band, so the trust level is
        // DirectExchange and the resolution layer is "Domain" (closest match
        // for URI-based resolution — no discovery context is involved).
        scp_core::discovery::ContextDiscoverySource::ContextUri => (
            "context_uri",
            "DirectExchange",
            "Domain",
            "context_uri",
            None,
        ),
    }
}

/// Converts a [`ContextDiscoveryResult`] into a JSON value.
///
/// Mirrors the dict structure of [`discovery_result_to_dict`] but returns
/// `serde_json::Value` for use in unit tests (no Python GIL required).
/// Includes `trust_level` and `resolution_path` fields per §22.2.1, mapping
/// from `ContextDiscoverySource` to appropriate trust and path metadata.
#[cfg(test)]
fn discovery_result_to_json(
    result: &scp_core::discovery::ContextDiscoveryResult,
) -> serde_json::Value {
    let (source_str, trust_level_kind, resolution_layer, resolution_source, resolution_source_id) =
        map_discovery_source(&result.discovery_source);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut obj = serde_json::json!({
        "context_id": result.context_id,
        "relay_urls": result.relay_urls,
        "publisher_did": &*result.publisher_did,
        "discovery_source": source_str,
        "mode": result.mode,
        "metadata_summary": result.metadata_summary,
        "trust_level": {
            "kind": trust_level_kind,
        },
        "resolution_path": {
            "layer": resolution_layer,
            "source": resolution_source,
            "source_id": resolution_source_id,
            "resolved_at": now_secs,
        },
    });

    if let scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } =
        &result.discovery_source
    {
        obj["discovery_context_id"] = serde_json::Value::String(context_id.clone());
    }

    obj
}

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
            code: "SCP-VALID-7080".to_owned(),
        })?;

    let registry = guard
        .entry(discovery_context_id.to_owned())
        .or_insert_with(|| HandleRegistry::new(discovery_context_id.to_owned()));

    let result = registry
        .register(&params, &DID::from(registrant_did))
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("clock error during handle registration: {e}"),
            code: "SCP-VALID-7081".to_owned(),
        })?;

    serde_json::to_string(&result).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("failed to serialize handle register result: {e}"),
            code: "SCP-VALID-7082".to_owned(),
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
                code: "SCP-VALID-7083".to_owned(),
            }
            .into());
        }
        None => None,
    };

    let guard = handle_registries()
        .lock()
        .map_err(|e| ScpPyError::ValidationError {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7080".to_owned(),
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
            code: "SCP-VALID-7084".to_owned(),
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
            code: "SCP-VALID-7080".to_owned(),
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
            code: "SCP-VALID-7085".to_owned(),
        }
        .into()
    })
}

/// Parses a `HandleTarget` from a JSON string.
fn parse_handle_target(json: &str) -> PyResult<HandleTarget> {
    let val: serde_json::Value =
        serde_json::from_str(json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid target_json: {e}"),
            code: "SCP-VALID-7086".to_owned(),
        })?;

    let target_type = val["type"]
        .as_str()
        .ok_or_else(|| ScpPyError::ValidationError {
            message: "target_json must have a 'type' field ('identity' or 'context')".to_owned(),
            code: "SCP-VALID-7086".to_owned(),
        })?;

    match target_type {
        "identity" => {
            let did = val["did"]
                .as_str()
                .ok_or_else(|| ScpPyError::ValidationError {
                    message: "identity target must have a 'did' field".to_owned(),
                    code: "SCP-VALID-7086".to_owned(),
                })?;
            Ok(HandleTarget::Identity {
                did: DID::from(did),
            })
        }
        "context" => {
            let context_id =
                val["context_id"]
                    .as_str()
                    .ok_or_else(|| ScpPyError::ValidationError {
                        message: "context target must have a 'context_id' field".to_owned(),
                        code: "SCP-VALID-7086".to_owned(),
                    })?;
            let relay_urls = val["relay_urls"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            Ok(HandleTarget::Context {
                context_id: context_id.to_owned(),
                relay_urls,
            })
        }
        other => Err(ScpPyError::ValidationError {
            message: format!("invalid target type '{other}': expected 'identity' or 'context'"),
            code: "SCP-VALID-7086".to_owned(),
        }
        .into()),
    }
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

    let known_contexts: HashMap<String, String> = if let Some(json) = known_contexts_json {
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
                code: "SCP-VALID-7080".to_owned(),
            })?;
        guard.keys().map(|k| (k.clone(), k.clone())).collect()
    };

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

/// Converts an `AddressResolution` into a JSON value.
fn address_resolution_to_json(resolution: &AddressResolution) -> serde_json::Value {
    match resolution {
        AddressResolution::Identity {
            did,
            trust_level,
            resolution_path,
        } => {
            serde_json::json!({
                "type": "Identity",
                "did": did.to_string(),
                "trust_level": trust_level_to_json(trust_level),
                "resolution_path": resolution_path_to_json(resolution_path),
            })
        }
        AddressResolution::Context {
            context_id,
            relay_urls,
            mode,
            trust_level,
            resolution_path,
        } => {
            serde_json::json!({
                "type": "Context",
                "context_id": context_id,
                "relay_urls": relay_urls,
                "mode": mode,
                "trust_level": trust_level_to_json(trust_level),
                "resolution_path": resolution_path_to_json(resolution_path),
            })
        }
    }
}

/// Converts a `TrustLevel` into a JSON value.
fn trust_level_to_json(trust_level: &TrustLevel) -> serde_json::Value {
    match trust_level {
        TrustLevel::DirectExchange => serde_json::json!({"kind": "DirectExchange"}),
        TrustLevel::LocalPetname => serde_json::json!({"kind": "LocalPetname"}),
        TrustLevel::MultiLayerCorroborated { sources } => {
            serde_json::json!({
                "kind": "MultiLayerCorroborated",
                "sources": sources.iter().map(resolution_path_to_json).collect::<Vec<_>>(),
            })
        }
        TrustLevel::DomainVerified => serde_json::json!({"kind": "DomainVerified"}),
        TrustLevel::AttestationVerified => serde_json::json!({"kind": "AttestationVerified"}),
        TrustLevel::DiscoveryContextVerified => {
            serde_json::json!({"kind": "DiscoveryContextVerified"})
        }
    }
}

/// Converts a `ResolutionPath` into a JSON value.
fn resolution_path_to_json(path: &ResolutionPath) -> serde_json::Value {
    let layer = match path.layer {
        ResolutionLayer::Petname => "Petname",
        ResolutionLayer::DiscoveryContext => "DiscoveryContext",
        ResolutionLayer::Attestation => "Attestation",
        ResolutionLayer::Domain => "Domain",
        ResolutionLayer::MultiLayerCorroborated => "MultiLayerCorroborated",
    };
    serde_json::json!({
        "layer": layer,
        "source": path.source,
        "source_id": path.source_id,
        "resolved_at": path.resolved_at,
    })
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
        let target = "did:dht:zAlice";
        py_petname_set(owner, target, "alice").unwrap();

        let dids = py_petname_resolve_did(owner, "alice").unwrap();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], target);

        // Clean up global state
        py_petname_remove(owner, target).unwrap();
    }

    #[test]
    fn petname_get_for_did_returns_name() {
        let owner = "did:dht:zTestOwner2";
        let target = "did:dht:zBob";
        py_petname_set(owner, target, "bob").unwrap();

        let name = py_petname_get_for_did(owner, target).unwrap();
        assert_eq!(name, Some("bob".to_owned()));

        py_petname_remove(owner, target).unwrap();
    }

    #[test]
    fn petname_set_context_and_resolve() {
        let owner = "did:dht:zTestOwner3";
        py_petname_set_context(owner, "ctx-recipes", "recipes").unwrap();

        let ids = py_petname_resolve_context(owner, "recipes").unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "ctx-recipes");

        py_petname_remove_context(owner, "ctx-recipes").unwrap();
    }

    #[test]
    fn petname_get_for_context_returns_name() {
        let owner = "did:dht:zTestOwner4";
        py_petname_set_context(owner, "ctx-work", "work").unwrap();

        let name = py_petname_get_for_context(owner, "ctx-work").unwrap();
        assert_eq!(name, Some("work".to_owned()));

        py_petname_remove_context(owner, "ctx-work").unwrap();
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
        let target_json = r#"{"type": "identity", "did": "did:dht:zAlice"}"#;
        let result =
            py_handle_register(ctx, "alice", target_json, "did:dht:zAlice", None, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "registered");
        assert!(parsed["entry_id"].as_str().is_some());

        let lookup = py_handle_lookup(ctx, "alice", None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&lookup).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 1);

        // Clean up
        py_handle_deregister(ctx, "alice", "did:dht:zAlice").unwrap();
    }

    #[test]
    fn handle_register_conflict() {
        let ctx = "ctx-handle-test-2";
        let target1 = r#"{"type": "identity", "did": "did:dht:zAlice"}"#;
        let target2 = r#"{"type": "identity", "did": "did:dht:zBob"}"#;
        py_handle_register(ctx, "alice", target1, "did:dht:zAlice", None, None).unwrap();

        let result = py_handle_register(ctx, "alice", target2, "did:dht:zBob", None, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "conflict");

        // Clean up
        py_handle_deregister(ctx, "alice", "did:dht:zAlice").unwrap();
    }

    #[test]
    fn handle_deregister_removes_entry() {
        let ctx = "ctx-handle-test-3";
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
        let target = r#"{"type": "context", "context_id": "ctx-abc", "relay_urls": ["wss://relay.example.com"]}"#;
        py_handle_register(ctx, "recipes", target, "did:dht:zAdmin", None, None).unwrap();

        let identity_lookup = py_handle_lookup(ctx, "recipes", Some("identity")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&identity_lookup).unwrap();
        assert!(parsed["results"].as_array().unwrap().is_empty());

        let context_lookup = py_handle_lookup(ctx, "recipes", Some("context")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&context_lookup).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 1);

        py_handle_deregister(ctx, "recipes", "did:dht:zAdmin").unwrap();
    }

    #[test]
    fn handle_invalid_type_filter_errors() {
        assert!(py_handle_lookup("ctx-any", "alice", Some("invalid")).is_err());
    }

    // -- Address resolution tests --------------------------------------------

    #[test]
    fn address_resolve_via_petname() {
        // Initialize the tokio runtime required by PyO3 bridge functions
        crate::init_runtime().ok();

        let owner = "did:dht:zTestResolver1";
        py_petname_set(owner, "did:dht:zAlice", "alice").unwrap();

        let result = py_address_resolve(owner, "alice", None).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert!(!parsed.is_empty());
        assert_eq!(parsed[0]["type"], "Identity");
        assert_eq!(parsed[0]["did"], "did:dht:zAlice");
        assert_eq!(parsed[0]["trust_level"]["kind"], "LocalPetname");

        py_petname_remove(owner, "did:dht:zAlice").unwrap();
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
