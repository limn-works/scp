//! napi-rs bridge for discovery operations.
//!
//! Exposes SCP discovery operations to Node.js/Bun:
//!
//! - [`discovery_parse_address`] -- Parse an SCP address string.
//! - [`discovery_create_query`] -- Create a discovery query.
//! - [`discovery_normalize_address`] -- Normalize an address string.
//! - [`context_discover`] -- Discover contexts from a DID or `scp://` URI.
//! - [`petname_set`] -- Set a petname for a DID.
//! - [`petname_remove`] -- Remove a petname from a DID.
//! - [`petname_set_context`] -- Set a petname for a context.
//! - [`petname_remove_context`] -- Remove a petname from a context.
//! - [`petname_resolve_did`] -- Resolve a petname to DIDs.
//! - [`petname_resolve_context`] -- Resolve a petname to context IDs.
//! - [`petname_get_for_did`] -- Get the petname for a DID.
//! - [`petname_get_for_context`] -- Get the petname for a context.
//! - [`handle_register`] -- Register a handle in a discovery context.
//! - [`handle_lookup`] -- Look up a handle in a discovery context.
//! - [`handle_deregister`] -- Deregister a handle from a discovery context.
//! - [`address_resolve`] -- Resolve an address via multi-path resolution.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use napi_derive::napi;

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

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Global state for petnames and handles
// ---------------------------------------------------------------------------

fn petname_maps() -> &'static Mutex<HashMap<String, PetnameMap>> {
    static MAPS: OnceLock<Mutex<HashMap<String, PetnameMap>>> = OnceLock::new();
    MAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn handle_registries() -> &'static Mutex<HashMap<String, HandleRegistry>> {
    static REGISTRIES: OnceLock<Mutex<HashMap<String, HandleRegistry>>> = OnceLock::new();
    REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

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
        Vec::new()
    }

    async fn lookup_attestation_handle(
        &self,
        _handle: &str,
        _platform: Option<&str>,
    ) -> Vec<AddressResolution> {
        Vec::new()
    }
}

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

fn address_resolution_to_json(resolution: &AddressResolution) -> serde_json::Value {
    match resolution {
        AddressResolution::Identity {
            did,
            trust_level,
            resolution_path,
        } => serde_json::json!({
            "type": "Identity",
            "did": did.to_string(),
            "trust_level": trust_level_to_json(trust_level),
            "resolution_path": resolution_path_to_json(resolution_path),
        }),
        AddressResolution::Context {
            context_id,
            relay_urls,
            mode,
            trust_level,
            resolution_path,
        } => serde_json::json!({
            "type": "Context",
            "context_id": context_id,
            "relay_urls": relay_urls,
            "mode": mode,
            "trust_level": trust_level_to_json(trust_level),
            "resolution_path": resolution_path_to_json(resolution_path),
        }),
    }
}

fn trust_level_to_json(trust_level: &TrustLevel) -> serde_json::Value {
    match trust_level {
        TrustLevel::DirectExchange => serde_json::json!({"kind": "DirectExchange"}),
        TrustLevel::LocalPetname => serde_json::json!({"kind": "LocalPetname"}),
        TrustLevel::MultiLayerCorroborated { sources } => serde_json::json!({
            "kind": "MultiLayerCorroborated",
            "sources": sources.iter().map(resolution_path_to_json).collect::<Vec<_>>(),
        }),
        TrustLevel::DomainVerified => serde_json::json!({"kind": "DomainVerified"}),
        TrustLevel::AttestationVerified => serde_json::json!({"kind": "AttestationVerified"}),
        TrustLevel::DiscoveryContextVerified => {
            serde_json::json!({"kind": "DiscoveryContextVerified"})
        }
    }
}

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

fn parse_handle_target(json: &str) -> napi::Result<HandleTarget> {
    let val: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid target_json: {e}"),
            code: "SCP-VALID-7050".to_owned(),
        })
    })?;
    let target_type = val["type"].as_str().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Validation {
            message: "target_json must have a 'type' field ('identity' or 'context')".to_owned(),
            code: "SCP-VALID-7050".to_owned(),
        })
    })?;
    match target_type {
        "identity" => {
            let did = val["did"].as_str().ok_or_else(|| {
                napi::Error::from(ScpNapiError::Validation {
                    message: "identity target must have a 'did' field".to_owned(),
                    code: "SCP-VALID-7050".to_owned(),
                })
            })?;
            Ok(HandleTarget::Identity {
                did: DID::from(did),
            })
        }
        "context" => {
            let ctx_id = val["context_id"].as_str().ok_or_else(|| {
                napi::Error::from(ScpNapiError::Validation {
                    message: "context target must have a 'context_id' field".to_owned(),
                    code: "SCP-VALID-7050".to_owned(),
                })
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
                context_id: ctx_id.to_owned(),
                relay_urls,
            })
        }
        other => Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid target type '{other}': expected 'identity' or 'context'"),
            code: "SCP-VALID-7050".to_owned(),
        })),
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Parses an SCP address string into its components.
///
/// Returns a JSON string with the parsed address type and fields.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn discovery_parse_address(address: String) -> napi::Result<String> {
    let parsed = parse_address(&address).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid address '{address}': {e}"),
            code: "SCP-VALID-7020".to_owned(),
        })
    })?;

    let result = match parsed {
        ParsedAddress::DiscoveryHandle { local_part, scope } => {
            serde_json::json!({
                "type": "DiscoveryHandle",
                "local_part": local_part,
                "scope": scope,
            })
        }
        ParsedAddress::DomainHandle { local_part, domain } => {
            serde_json::json!({
                "type": "DomainHandle",
                "local_part": local_part,
                "domain": domain,
            })
        }
        ParsedAddress::AttestationHandle { handle, platform } => {
            serde_json::json!({
                "type": "AttestationHandle",
                "handle": handle,
                "platform": platform,
            })
        }
        ParsedAddress::Unscoped { name } => {
            serde_json::json!({
                "type": "Unscoped",
                "name": name,
            })
        }
    };

    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize parsed address: {e}"),
            code: "SCP-VALID-7021".to_owned(),
        })
    })
}

/// Creates a discovery query as a JSON string.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn discovery_create_query(
    capabilities: Option<Vec<String>>,
    keywords: Option<Vec<String>>,
    min_history_secs: Option<i64>,
) -> napi::Result<String> {
    let min_history = match min_history_secs {
        Some(s) if s < 0 => {
            return Err(napi::Error::from(ScpNapiError::Validation {
                message: format!("min_history_secs must be non-negative, got {s}"),
                code: "SCP-VALID-7040".to_owned(),
            }));
        }
        #[allow(clippy::cast_sign_loss)]
        Some(s) => Some(std::time::Duration::from_secs(s as u64)),
        None => None,
    };
    let query = DiscoveryQuery {
        capability_filter: capabilities,
        keywords,
        min_history,
    };

    serde_json::to_string(&query).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize query: {e}"),
            code: "SCP-VALID-7022".to_owned(),
        })
    })
}

/// Normalizes an address string per SCP addressing rules.
///
/// Lowercases and trims whitespace.
#[napi]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn discovery_normalize_address(address: String) -> String {
    normalize_address(&address)
}

// ---------------------------------------------------------------------------
// context_discover — DHT-based context discovery (SCP-336)
// ---------------------------------------------------------------------------

/// Converts a [`ContextDiscoveryResult`] into a JSON value.
///
/// Includes `trust_level` and `resolution_path` fields per §22.2.1, mapping
/// from `ContextDiscoverySource` to appropriate trust and path metadata.
fn discovery_result_to_json(
    result: &scp_core::discovery::ContextDiscoveryResult,
) -> serde_json::Value {
    let (source_str, trust_level_kind, resolution_layer, resolution_source, resolution_source_id) =
        match &result.discovery_source {
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
            // `DirectExchange` and the resolution layer is `"Domain"` (closest match
            // for URI-based resolution — no discovery context is involved).
            scp_core::discovery::ContextDiscoverySource::ContextUri => (
                "context_uri",
                "DirectExchange",
                "Domain",
                "context_uri",
                None,
            ),
        };

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

    // Add discovery_context_id if applicable.
    if let scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } =
        &result.discovery_source
    {
        obj["discovery_context_id"] = serde_json::Value::String(context_id.clone());
    }

    obj
}

/// Discovers contexts from a DID string or `scp://` URI.
///
/// Detects whether the query is a DID or an `scp://` URI and delegates to
/// the appropriate core discovery function.
///
/// Returns a JSON string containing an array of discovery results, each with:
/// `context_id`, `relay_urls`, `publisher_did`, `discovery_source`, `mode`,
/// `metadata_summary`.
///
/// See §5.14.11, §18.2.2, §18.4.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_discover(query: String) -> napi::Result<String> {
    if query.starts_with("scp://") {
        // Parse scp:// URI — synchronous, no network I/O.
        let result = scp_core::discovery::resolve_context_uri(&query).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to resolve scp:// URI: {e}"),
                code: "SCP-CTX-2020".to_owned(),
            })
        })?;

        let results = vec![discovery_result_to_json(&result)];
        serde_json::to_string(&results).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to serialize discovery results: {e}"),
                code: "SCP-CTX-2021".to_owned(),
            })
        })
    } else if query.starts_with("did:") {
        let did_dht = scp_identity::DidDht::new();
        let results = scp_core::discovery::resolve_contexts_from_did(&query, &did_dht)
            .await
            .map_err(|e| {
                napi::Error::from(ScpNapiError::Context {
                    message: format!("DHT discovery failed for '{query}': {e}"),
                    code: "SCP-CTX-2022".to_owned(),
                })
            })?;

        let json_results: Vec<serde_json::Value> =
            results.iter().map(discovery_result_to_json).collect();
        serde_json::to_string(&json_results).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to serialize discovery results: {e}"),
                code: "SCP-CTX-2023".to_owned(),
            })
        })
    } else {
        Err(napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "query must be a DID (starts with 'did:') or an scp:// URI \
                 (starts with 'scp://'), got: {query}"
            ),
            code: "SCP-VALID-7027".to_owned(),
        }))
    }
}

// ---------------------------------------------------------------------------
// Petname bridge functions (§22.4)
// ---------------------------------------------------------------------------

/// Sets a petname for a DID.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_set(owner_did: String, target_did: String, name: String) -> napi::Result<()> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let mut guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    let map = guard.entry(owner_did).or_default();
    map.set_petname(DID::from(target_did.as_str()), name);
    Ok(())
}

/// Removes a petname from a DID.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_remove(owner_did: String, target_did: String) -> napi::Result<()> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let mut guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    if let Some(map) = guard.get_mut(&owner_did) {
        map.remove_petname(&DID::from(target_did.as_str()));
    }
    Ok(())
}

/// Sets a petname for a context.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_set_context(
    owner_did: String,
    context_id: String,
    name: String,
) -> napi::Result<()> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let mut guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    let map = guard.entry(owner_did).or_default();
    map.set_context_petname(context_id, name);
    Ok(())
}

/// Removes a petname from a context.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_remove_context(owner_did: String, context_id: String) -> napi::Result<()> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let mut guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    if let Some(map) = guard.get_mut(&owner_did) {
        map.remove_context_petname(&context_id);
    }
    Ok(())
}

/// Resolves a petname to DIDs. Returns a JSON array of DID strings.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_resolve_did(owner_did: String, name: String) -> napi::Result<String> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    let dids: Vec<String> = guard
        .get(&owner_did)
        .map(|map| {
            map.resolve_did(&name)
                .into_iter()
                .map(|d| d.to_string())
                .collect()
        })
        .unwrap_or_default();
    serde_json::to_string(&dids).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize petname resolve result: {e}"),
            code: "SCP-VALID-7074".to_owned(),
        })
    })
}

/// Resolves a petname to context IDs. Returns a JSON array of strings.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_resolve_context(owner_did: String, name: String) -> napi::Result<String> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    let ids: Vec<String> = guard
        .get(&owner_did)
        .map(|map| map.resolve_context(&name))
        .unwrap_or_default();
    serde_json::to_string(&ids).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize petname resolve result: {e}"),
            code: "SCP-VALID-7074".to_owned(),
        })
    })
}

/// Gets the petname for a DID. Returns `null` if none.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_get_for_did(owner_did: String, target_did: String) -> napi::Result<Option<String>> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    Ok(guard.get(&owner_did).and_then(|map| {
        map.petname_for_did(&DID::from(target_did.as_str()))
            .map(str::to_owned)
    }))
}

/// Gets the petname for a context. Returns `null` if none.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn petname_get_for_context(
    owner_did: String,
    context_id: String,
) -> napi::Result<Option<String>> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let guard = petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7072".to_owned(),
        })
    })?;
    Ok(guard
        .get(&owner_did)
        .and_then(|map| map.petname_for_context(&context_id).map(str::to_owned)))
}

// ---------------------------------------------------------------------------
// Handle registry bridge functions (§22.3.1)
// ---------------------------------------------------------------------------

/// Registers a handle in a discovery context. Returns JSON result.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn handle_register(
    discovery_context_id: String,
    handle: String,
    target_json: String,
    registrant_did: String,
    description: Option<String>,
    tags: Option<Vec<String>>,
) -> napi::Result<String> {
    let target = parse_handle_target(&target_json)?;
    let params = HandleRegisterParams {
        handle,
        target,
        metadata: Some(HandleMetadata { description, tags }),
    };
    let mut guard = handle_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7080".to_owned(),
        })
    })?;
    let registry = guard
        .entry(discovery_context_id.clone())
        .or_insert_with(|| HandleRegistry::new(discovery_context_id));
    let result = registry
        .register(&params, &DID::from(registrant_did.as_str()))
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("clock error during handle registration: {e}"),
                code: "SCP-VALID-7081".to_owned(),
            })
        })?;
    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize handle register result: {e}"),
            code: "SCP-VALID-7082".to_owned(),
        })
    })
}

/// Looks up a handle in a discovery context. Returns JSON result.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn handle_lookup(
    discovery_context_id: String,
    handle: String,
    type_filter: Option<String>,
) -> napi::Result<String> {
    let filter = match type_filter.as_deref() {
        Some("identity") => Some(HandleTypeFilter::Identity),
        Some("context") => Some(HandleTypeFilter::Context),
        Some(other) => {
            return Err(napi::Error::from(ScpNapiError::Validation {
                message: format!("invalid type_filter '{other}': expected 'identity' or 'context'"),
                code: "SCP-VALID-7083".to_owned(),
            }));
        }
        None => None,
    };
    let guard = handle_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7080".to_owned(),
        })
    })?;
    let result = guard.get(&discovery_context_id).map_or_else(
        || scp_core::discovery::HandleLookupResult {
            results: Vec::new(),
        },
        |registry| {
            registry.lookup(&HandleLookupParams {
                handle,
                type_filter: filter,
            })
        },
    );
    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize handle lookup result: {e}"),
            code: "SCP-VALID-7084".to_owned(),
        })
    })
}

/// Deregisters a handle from a discovery context. Returns JSON result.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn handle_deregister(
    discovery_context_id: String,
    handle: String,
    did: String,
) -> napi::Result<String> {
    let mut guard = handle_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7080".to_owned(),
        })
    })?;
    let result = guard.get_mut(&discovery_context_id).map_or_else(
        || scp_core::discovery::HandleDeregisterResult { removed: false },
        |registry| {
            registry.deregister(&HandleDeregisterParams {
                handle,
                did: DID::from(did.as_str()),
            })
        },
    );
    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize handle deregister result: {e}"),
            code: "SCP-VALID-7085".to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Address resolve (§22.8)
// ---------------------------------------------------------------------------

/// Resolves a human-readable address via multi-path resolution.
/// Returns a JSON array of `AddressResolution` objects.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub async fn address_resolve(
    owner_did: String,
    address: String,
    known_contexts_json: Option<String>,
) -> napi::Result<String> {
    if owner_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7070".to_owned(),
        }));
    }
    let known_contexts: HashMap<String, String> = if let Some(ref json) = known_contexts_json {
        serde_json::from_str(json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("invalid known_contexts_json: {e}"),
                code: "SCP-VALID-7090".to_owned(),
            })
        })?
    } else {
        let guard = handle_registries().lock().map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("handle registry lock poisoned: {e}"),
                code: "SCP-VALID-7080".to_owned(),
            })
        })?;
        guard.keys().map(|k| (k.clone(), k.clone())).collect()
    };
    let known_domains: Vec<&str> = Vec::new();
    let petname_map = {
        let guard = petname_maps().lock().map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: "SCP-VALID-7072".to_owned(),
            })
        })?;
        guard.get(&owner_did).cloned().unwrap_or_default()
    };
    let mut resolver = scp_core::discovery::AddressResolver::new();
    let querier = LocalHandleQuerier;
    let results = resolver
        .resolve(
            &address,
            &petname_map,
            &querier,
            &known_contexts,
            &known_domains,
        )
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("address resolution failed: {e}"),
                code: "SCP-VALID-7091".to_owned(),
            })
        })?;
    let json_results: Vec<serde_json::Value> =
        results.iter().map(address_resolution_to_json).collect();
    serde_json::to_string(&json_results).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize address resolution results: {e}"),
            code: "SCP-VALID-7092".to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn create_query_with_capabilities() {
        let result = discovery_create_query(Some(vec!["code_review".to_string()]), None, None);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("code_review"));
    }

    #[test]
    fn create_query_empty() {
        let result = discovery_create_query(None, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn normalize_lowercases_and_trims() {
        let result = discovery_normalize_address("  ALICE@Cooking  ".to_string());
        assert_eq!(result, "alice@cooking");
    }

    #[test]
    fn context_discover_uri_path() {
        // Test the URI parsing path directly via core.
        let result = scp_core::discovery::resolve_context_uri(
            "scp://context/deadbeef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&mode=broadcast",
        )
        .unwrap();

        assert_eq!(result.context_id, "deadbeef");
        assert_eq!(result.relay_urls, vec!["wss://relay.example.com/scp/v1"]);
        assert_eq!(
            result.discovery_source,
            scp_core::discovery::ContextDiscoverySource::ContextUri
        );
    }

    #[test]
    fn create_query_negative_min_history_errors() {
        let result = discovery_create_query(None, None, Some(-1));
        assert!(result.is_err(), "negative min_history_secs should error");
    }

    #[test]
    fn create_query_i64_min_min_history_errors() {
        let result = discovery_create_query(None, None, Some(i64::MIN));
        assert!(result.is_err(), "i64::MIN min_history_secs should error");
    }

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

    // -- Petname bridge tests ------------------------------------------------

    #[test]
    fn petname_set_and_resolve() {
        let owner = "did:dht:zNapiTest1".to_owned();
        petname_set(
            owner.clone(),
            "did:dht:zAlice".to_owned(),
            "alice".to_owned(),
        )
        .unwrap();
        let json = petname_resolve_did(owner.clone(), "alice".to_owned()).unwrap();
        let dids: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], "did:dht:zAlice");
        petname_remove(owner, "did:dht:zAlice".to_owned()).unwrap();
    }

    #[test]
    fn petname_context_set_and_resolve() {
        let owner = "did:dht:zNapiTest2".to_owned();
        petname_set_context(owner.clone(), "ctx-napi-1".to_owned(), "work".to_owned()).unwrap();
        let json = petname_resolve_context(owner.clone(), "work".to_owned()).unwrap();
        let ids: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "ctx-napi-1");
        petname_remove_context(owner, "ctx-napi-1".to_owned()).unwrap();
    }

    // -- Handle bridge tests -------------------------------------------------

    #[test]
    fn handle_register_and_lookup_napi() {
        let ctx = "ctx-napi-handle-1".to_owned();
        let target = r#"{"type": "identity", "did": "did:dht:zNapiAlice"}"#.to_owned();
        let result = handle_register(
            ctx.clone(),
            "alice".to_owned(),
            target,
            "did:dht:zNapiAlice".to_owned(),
            None,
            None,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "registered");

        let lookup = handle_lookup(ctx.clone(), "alice".to_owned(), None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&lookup).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 1);

        handle_deregister(ctx, "alice".to_owned(), "did:dht:zNapiAlice".to_owned()).unwrap();
    }

    // -- Parse handle target tests -------------------------------------------

    #[test]
    fn parse_handle_target_identity_napi() {
        let target = parse_handle_target(r#"{"type": "identity", "did": "did:dht:z1"}"#).unwrap();
        assert!(matches!(target, HandleTarget::Identity { .. }));
    }

    #[test]
    fn parse_handle_target_context_napi() {
        let target = parse_handle_target(
            r#"{"type": "context", "context_id": "abc", "relay_urls": ["wss://r.example.com"]}"#,
        )
        .unwrap();
        assert!(matches!(target, HandleTarget::Context { .. }));
    }
}
