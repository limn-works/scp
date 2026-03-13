//! Shared petname/handle/address-resolution helpers for non-WASM FFI bridges.
//!
//! Extracts duplicated logic from `PyO3`, napi-rs, and `UniFFI` bridges:
//!
//! - JSON serialization of `AddressResolution`, `TrustLevel`, `ResolutionPath`
//! - `HandleTarget` JSON parsing
//! - `HandleEntry` → `AddressResolution` conversion
//! - `HandleQuerier` implementation for in-memory handle registries
//! - Global petname map and handle registry singletons
//!
//! WASM bridge reimplements `PetnameMap` locally per ADR-034 and builds JSON
//! manually, so these helpers are gated behind the `resolvers` feature.
//!
//! See spec §22.3.1, §22.4, §22.8 and ADR-020.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use scp_core::discovery::addressing::{
    AddressResolution, AddressType, HandleQuerier, HandleTarget, ResolutionLayer, ResolutionPath,
    TrustLevel,
};
use scp_core::discovery::handles::{
    HandleEntry, HandleLookupParams, HandleRegistry, HandleTypeFilter,
};
use scp_core::discovery::petnames::PetnameMap;

// ---------------------------------------------------------------------------
// Global singletons
// ---------------------------------------------------------------------------

/// Global petname map keyed by owner DID string.
/// Each identity has its own petname map (petnames are per-identity private state §3.7).
pub fn petname_maps() -> &'static Mutex<HashMap<String, PetnameMap>> {
    static MAPS: OnceLock<Mutex<HashMap<String, PetnameMap>>> = OnceLock::new();
    MAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Global handle registries keyed by discovery context ID.
/// Each discovery context has its own handle registry (§22.3.1).
pub fn handle_registries() -> &'static Mutex<HashMap<String, HandleRegistry>> {
    static REGISTRIES: OnceLock<Mutex<HashMap<String, HandleRegistry>>> = OnceLock::new();
    REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Removes a specific owner's petname map. Test-only — ensures each test starts
/// with clean state even if a previous test panicked before manual cleanup.
#[cfg(any(test, feature = "testing"))]
pub fn reset_petname_map_for(owner_did: &str) {
    if let Ok(mut guard) = petname_maps().lock() {
        guard.remove(owner_did);
    }
}

/// Removes a specific context's handle registry. Test-only — ensures each test starts
/// with clean state even if a previous test panicked before manual cleanup.
#[cfg(any(test, feature = "testing"))]
pub fn reset_handle_registry_for(context_id: &str) {
    if let Ok(mut guard) = handle_registries().lock() {
        guard.remove(context_id);
    }
}

// ---------------------------------------------------------------------------
// JSON serialization helpers
// ---------------------------------------------------------------------------

/// Converts an [`AddressResolution`] into a JSON value.
#[must_use]
pub fn address_resolution_to_json(resolution: &AddressResolution) -> serde_json::Value {
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

/// Converts a [`TrustLevel`] into a JSON value.
#[must_use]
pub fn trust_level_to_json(trust_level: &TrustLevel) -> serde_json::Value {
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

/// Converts a [`ResolutionPath`] into a JSON value.
#[must_use]
pub fn resolution_path_to_json(path: &ResolutionPath) -> serde_json::Value {
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
// HandleTarget JSON parsing
// ---------------------------------------------------------------------------

/// Parses a [`HandleTarget`] from a JSON string.
///
/// Accepts `{"type": "identity", "did": "..."}` or
/// `{"type": "context", "context_id": "...", "relay_urls": [...]}`.
///
/// Returns `Ok(target)` on success or `Err(HandleTargetError)` on failure.
/// The caller wraps the error into bridge-specific error types (`PyO3`, NAPI, `UniFFI`).
///
/// # Errors
///
/// Returns [`HandleTargetError`] if the JSON is malformed, the `type` field is missing
/// or invalid, or required fields (`did`, `context_id`) are absent.
pub fn parse_handle_target(json: &str) -> Result<HandleTarget, HandleTargetError> {
    let val: serde_json::Value = serde_json::from_str(json).map_err(|e| HandleTargetError {
        message: format!("invalid target_json: {e}"),
    })?;

    let target_type = val["type"].as_str().ok_or_else(|| HandleTargetError {
        message: "target_json must have a 'type' field ('identity' or 'context')".to_owned(),
    })?;

    match target_type {
        "identity" => {
            let did = val["did"].as_str().ok_or_else(|| HandleTargetError {
                message: "identity target must have a 'did' field".to_owned(),
            })?;
            Ok(HandleTarget::Identity {
                did: scp_identity::DID::from(did),
            })
        }
        "context" => {
            let context_id = val["context_id"]
                .as_str()
                .ok_or_else(|| HandleTargetError {
                    message: "context target must have a 'context_id' field".to_owned(),
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
        other => Err(HandleTargetError {
            message: format!("invalid target type '{other}': expected 'identity' or 'context'"),
        }),
    }
}

/// Error from [`parse_handle_target`]. Callers wrap into bridge-specific error types.
/// Error code is always `SCP-VALID-7126`.
#[derive(Debug)]
pub struct HandleTargetError {
    pub message: String,
}

// ---------------------------------------------------------------------------
// HandleEntry → AddressResolution conversion
// ---------------------------------------------------------------------------

/// Converts a [`HandleEntry`] into an [`AddressResolution`].
#[must_use]
pub fn handle_entry_to_resolution(
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
// HandleQuerier implementation
// ---------------------------------------------------------------------------

/// A [`HandleQuerier`] implementation that queries the global in-memory handle registries.
/// Used by `address_resolve` for the discovery context handle lookup layer.
pub struct LocalHandleQuerier;

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
