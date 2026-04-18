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
//! - [`handle_register`] -- Register a handle in a context with discovery tools.
//! - [`handle_lookup`] -- Look up a handle in a context with discovery tools.
//! - [`handle_deregister`] -- Deregister a handle from a context with discovery tools.
//! - [`address_resolve`] -- Resolve an address via multi-path resolution.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).

use scp_ffi_common::error_codes as codes;
use std::collections::HashMap;

use napi_derive::napi;

use scp_core::discovery::addressing::{HandleTarget, ParsedAddress};
use scp_core::discovery::handles::{
    HandleDeregisterParams, HandleLookupParams, HandleMetadata, HandleRegisterParams,
    HandleRegistry, HandleTypeFilter,
};
use scp_core::discovery::{DiscoveryQuery, normalize_address, parse_address};
use scp_identity::DID;

use scp_ffi_common::petname_helpers::{self, LocalHandleQuerier, address_resolution_to_json};

use crate::error::ScpNapiError;
use crate::runtime::default_bridge_instance;

// ---------------------------------------------------------------------------
// Test-only reset helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn reset_petname_map_for(owner_did: &str) {
    if let Ok(bi) = default_bridge_instance() {
        petname_helpers::reset_petname_map_for(&bi.core, owner_did);
    }
}

#[cfg(test)]
fn reset_handle_registry_for(context_id: &str) {
    if let Ok(bi) = default_bridge_instance() {
        petname_helpers::reset_handle_registry_for(&bi.core, context_id);
    }
}

fn parse_handle_target(json: &str) -> napi::Result<HandleTarget> {
    petname_helpers::parse_handle_target(json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: e.message,
            code: codes::VALID_7126.to_owned(),
        })
    })
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
            code: codes::VALID_7020.to_owned(),
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
            code: codes::VALID_7021.to_owned(),
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
                code: codes::VALID_7040.to_owned(),
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
            code: codes::VALID_7022.to_owned(),
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

// `discovery_result_to_json` lives in scp-ffi-common::discovery.
use scp_ffi_common::discovery::discovery_result_to_json;

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
                code: codes::CTX_2020.to_owned(),
            })
        })?;

        let results = vec![discovery_result_to_json(&result).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: e,
                code: codes::CTX_2020.to_owned(),
            })
        })?];
        serde_json::to_string(&results).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to serialize discovery results: {e}"),
                code: codes::CTX_2021.to_owned(),
            })
        })
    } else if query.starts_with("did:") {
        let did_dht = scp_identity::DidDht::new();
        let results = scp_core::discovery::resolve_contexts_from_did(&query, &did_dht)
            .await
            .map_err(|e| {
                napi::Error::from(ScpNapiError::Context {
                    message: format!("DHT discovery failed for '{query}': {e}"),
                    code: codes::CTX_2022.to_owned(),
                })
            })?;

        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                discovery_result_to_json(r).map_err(|e| {
                    napi::Error::from(ScpNapiError::Context {
                        message: e,
                        code: codes::CTX_2022.to_owned(),
                    })
                })
            })
            .collect::<napi::Result<Vec<_>>>()?;
        serde_json::to_string(&json_results).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to serialize discovery results: {e}"),
                code: codes::CTX_2023.to_owned(),
            })
        })
    } else {
        Err(napi::Error::from(ScpNapiError::Validation {
            message: format!(
                "query must be a DID (starts with 'did:') or an scp:// URI \
                 (starts with 'scp://'), got: {query}"
            ),
            code: codes::VALID_7027.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    if target_did.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "target_did must not be empty".to_owned(),
            code: codes::VALID_7111.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let mut guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let mut guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    if context_id.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: "context_id must not be empty".to_owned(),
            code: codes::VALID_7113.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let mut guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let mut guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
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
            code: codes::VALID_7114.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
        })
    })?;
    let ids: Vec<String> = guard
        .get(&owner_did)
        .map(|map| map.resolve_context(&name))
        .unwrap_or_default();
    serde_json::to_string(&ids).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize petname resolve result: {e}"),
            code: codes::VALID_7114.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let guard = bi.core.petname_maps().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: codes::VALID_7112.to_owned(),
        })
    })?;
    Ok(guard
        .get(&owner_did)
        .and_then(|map| map.petname_for_context(&context_id).map(str::to_owned)))
}

// ---------------------------------------------------------------------------
// Handle registry bridge functions (§22.3.1)
// ---------------------------------------------------------------------------

/// Registers a handle in a context with discovery tools. Returns JSON result.
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
    let bi = default_bridge_instance()?;
    let mut guard = bi.core.handle_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: codes::VALID_7120.to_owned(),
        })
    })?;
    let registry = guard
        .entry(discovery_context_id.clone())
        .or_insert_with(|| HandleRegistry::new(discovery_context_id));
    let result = registry.register(
        &params,
        &DID::from(registrant_did.as_str()),
        &scp_primitives::SystemClock,
    );
    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize handle register result: {e}"),
            code: codes::VALID_7122.to_owned(),
        })
    })
}

/// Looks up a handle in a context with discovery tools. Returns JSON result.
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
                code: codes::VALID_7123.to_owned(),
            }));
        }
        None => None,
    };
    let bi = default_bridge_instance()?;
    let guard = bi.core.handle_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: codes::VALID_7120.to_owned(),
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
            code: codes::VALID_7124.to_owned(),
        })
    })
}

/// Deregisters a handle from a context with discovery tools. Returns JSON result.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn handle_deregister(
    discovery_context_id: String,
    handle: String,
    did: String,
) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    let mut guard = bi.core.handle_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: codes::VALID_7120.to_owned(),
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
            code: codes::VALID_7125.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Scope registry bridge functions (§22.3.5, ADR-043)
// ---------------------------------------------------------------------------

/// Registers a scope name in a scope registry. Returns JSON result.
#[napi]
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn scope_register(
    scope_context_id: String,
    name: String,
    target_context_id: String,
    relay_urls: Vec<String>,
    registrant_did: String,
    description: Option<String>,
    tags: Option<Vec<String>>,
) -> napi::Result<String> {
    // Validate inputs at the FFI boundary (defense-in-depth)
    scp_ffi_common::validate::validate_context_id(&scope_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_context_id(&target_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&registrant_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // Validate relay URLs at the FFI boundary
    for url in &relay_urls {
        scp_ffi_common::validate::validate_relay_url(url).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: e.to_string(),
                code: codes::VALID_7135.to_owned(),
            })
        })?;
    }

    let params = scp_core::discovery::ScopeRegisterParams {
        name,
        target: scp_core::discovery::ScopeTarget {
            context_id: target_context_id,
            relay_urls,
        },
        metadata: if description.is_some() || tags.is_some() {
            Some(scp_core::discovery::ScopeMetadata { description, tags })
        } else {
            None
        },
    };

    let bi = default_bridge_instance()?;
    let mut guard = bi.core.scope_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("scope registry lock poisoned: {e}"),
            code: codes::VALID_7130.to_owned(),
        })
    })?;

    let registry = guard
        .entry(scope_context_id.clone())
        .or_insert_with(|| scp_core::discovery::ScopeRegistry::new(scope_context_id));

    let result = registry
        .register(
            &params,
            &DID::from(registrant_did.as_str()),
            &scp_primitives::SystemClock,
        )
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("scope registration failed: {e}"),
                code: codes::VALID_7131.to_owned(),
            })
        })?;

    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize scope register result: {e}"),
            code: codes::VALID_7132.to_owned(),
        })
    })
}

/// Looks up a scope name in a scope registry. Returns JSON result.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn scope_lookup(scope_context_id: String, name: String) -> napi::Result<String> {
    scp_ffi_common::validate::validate_context_id(&scope_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let bi = default_bridge_instance()?;
    let guard = bi.core.scope_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("scope registry lock poisoned: {e}"),
            code: codes::VALID_7130.to_owned(),
        })
    })?;

    let result = match guard.get(&scope_context_id) {
        Some(registry) => registry
            .lookup(&scp_core::discovery::ScopeLookupParams { name })
            .map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("scope lookup failed: {e}"),
                    code: codes::VALID_7133.to_owned(),
                })
            })?,
        None => scp_core::discovery::ScopeLookupResult {
            results: Vec::new(),
        },
    };

    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize scope lookup result: {e}"),
            code: codes::VALID_7133.to_owned(),
        })
    })
}

/// Deregisters a scope name from a scope registry. Returns JSON result.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn scope_deregister(
    scope_context_id: String,
    name: String,
    did: String,
) -> napi::Result<String> {
    scp_ffi_common::validate::validate_context_id(&scope_context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let bi = default_bridge_instance()?;
    let mut guard = bi.core.scope_registries().lock().map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("scope registry lock poisoned: {e}"),
            code: codes::VALID_7130.to_owned(),
        })
    })?;

    let result = match guard.get_mut(&scope_context_id) {
        Some(registry) => registry
            .deregister(&scp_core::discovery::ScopeDeregisterParams {
                name,
                did: DID::from(did.as_str()),
            })
            .map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("scope deregister failed: {e}"),
                    code: codes::VALID_7134.to_owned(),
                })
            })?,
        None => scp_core::discovery::ScopeDeregisterResult { removed: false },
    };

    serde_json::to_string(&result).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize scope deregister result: {e}"),
            code: codes::VALID_7134.to_owned(),
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
            code: codes::VALID_7110.to_owned(),
        }));
    }
    let bi = default_bridge_instance()?;
    let mut known_contexts: HashMap<String, String> = if let Some(ref json) = known_contexts_json {
        serde_json::from_str(json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("invalid known_contexts_json: {e}"),
                code: codes::VALID_7090.to_owned(),
            })
        })?
    } else {
        let guard = bi.core.handle_registries().lock().map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("handle registry lock poisoned: {e}"),
                code: codes::VALID_7120.to_owned(),
            })
        })?;
        guard.keys().map(|k| (k.clone(), k.clone())).collect()
    };

    // Merge scope registry contexts for two-hop resolution (§22.3.5).
    let scope_contexts = petname_helpers::known_contexts_from_scope_registries(&bi.core);
    for (name, ctx_id) in scope_contexts {
        known_contexts.entry(name).or_insert(ctx_id);
    }
    let known_domains: Vec<&str> = Vec::new();
    let petname_map = {
        let guard = bi.core.petname_maps().lock().map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })
        })?;
        guard.get(&owner_did).cloned().unwrap_or_default()
    };
    let mut resolver = scp_core::discovery::AddressResolver::new();
    let querier = LocalHandleQuerier::new(&bi.core);
    let results = resolver
        .resolve(
            &address,
            &petname_map,
            &querier,
            &known_contexts,
            &known_domains,
            &scp_primitives::SystemClock,
        )
        .await
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("address resolution failed: {e}"),
                code: codes::VALID_7091.to_owned(),
            })
        })?;
    let json_results: Vec<serde_json::Value> =
        results.iter().map(address_resolution_to_json).collect();
    serde_json::to_string(&json_results).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize address resolution results: {e}"),
            code: codes::VALID_7092.to_owned(),
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

        let json = discovery_result_to_json(&result).unwrap();
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
            discovery_source: scp_core::discovery::ContextDiscoverySource::HandleRegistry {
                context_id: "disc-ctx-1".to_owned(),
            },
            mode: None,
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result).unwrap();
        assert_eq!(json["trust_level"]["kind"], "HandleRegistryVerified");
        assert_eq!(json["resolution_path"]["layer"], "HandleRegistry");
        assert_eq!(json["resolution_path"]["source"], "handle_registry");
        assert_eq!(json["resolution_path"]["source_id"], "disc-ctx-1");
        assert_eq!(json["discovery_context_id"], "disc-ctx-1");
    }

    // -- Petname bridge tests ------------------------------------------------

    #[test]
    fn petname_set_and_resolve() {
        let owner = "did:dht:zNapiTest1".to_owned();
        reset_petname_map_for(&owner);
        petname_set(
            owner.clone(),
            "did:dht:zAlice".to_owned(),
            "alice".to_owned(),
        )
        .unwrap();
        let json = petname_resolve_did(owner, "alice".to_owned()).unwrap();
        let dids: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], "did:dht:zAlice");
    }

    #[test]
    fn petname_context_set_and_resolve() {
        let owner = "did:dht:zNapiTest2".to_owned();
        reset_petname_map_for(&owner);
        petname_set_context(owner.clone(), "ctx-napi-1".to_owned(), "work".to_owned()).unwrap();
        let json = petname_resolve_context(owner, "work".to_owned()).unwrap();
        let ids: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "ctx-napi-1");
    }

    // -- Handle bridge tests -------------------------------------------------

    #[test]
    fn handle_register_and_lookup_napi() {
        let ctx = "ctx-napi-handle-1".to_owned();
        reset_handle_registry_for(&ctx);
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

        let lookup = handle_lookup(ctx, "alice".to_owned(), None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&lookup).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 1);
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
