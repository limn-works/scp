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
use scp_core::discovery::scope::ScopeRegistry;
use scp_primitives::Clock;

// ---------------------------------------------------------------------------
// Global singletons
// ---------------------------------------------------------------------------

/// Global petname map keyed by owner DID string.
/// Each identity has its own petname map (petnames are per-identity private state §3.7).
pub fn petname_maps() -> &'static Mutex<HashMap<String, PetnameMap>> {
    static MAPS: OnceLock<Mutex<HashMap<String, PetnameMap>>> = OnceLock::new();
    MAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Global handle registries keyed by context ID.
/// Each context has its own handle registry (§22.3.1).
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

/// Global scope registries keyed by context ID.
///
/// Each context that hosts scope tools has its own scope registry (§22.3.5, ADR-043).
/// Separate from handle registries — scope entries and handle entries never share storage.
pub fn scope_registries() -> &'static Mutex<HashMap<String, ScopeRegistry>> {
    static REGISTRIES: OnceLock<Mutex<HashMap<String, ScopeRegistry>>> = OnceLock::new();
    REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Removes a specific context's scope registry. Test-only — ensures each test starts
/// with clean state even if a previous test panicked before manual cleanup.
#[cfg(any(test, feature = "testing"))]
pub fn reset_scope_registry_for(context_id: &str) {
    if let Ok(mut guard) = scope_registries().lock() {
        guard.remove(context_id);
    }
}

/// Collects scope name -> context ID mappings from all scope registries.
///
/// Iterates all scope registries, collecting `entry.name -> entry.target.context_id`
/// for every scope entry. Used by `address_resolve` to merge scope registry
/// output into `known_contexts` for two-hop resolution (§22.3.5).
///
/// **Cross-context note:** This merges all scope registries globally, matching
/// how `handle_registries` merges all handle registries in `address_resolve`.
/// Both approaches expose entries from all contexts the caller has interacted
/// with (registered in). A future refinement could scope to a caller-provided
/// list of trusted registry context IDs for stricter context isolation.
#[must_use]
pub fn known_contexts_from_scope_registries() -> HashMap<String, String> {
    let mut result = HashMap::new();
    if let Ok(guard) = scope_registries().lock() {
        for registry in guard.values() {
            for entry in registry.entries() {
                result
                    .entry(entry.name.clone())
                    .or_insert_with(|| entry.target.context_id.clone());
            }
        }
    }
    result
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
        TrustLevel::HandleRegistryVerified => {
            serde_json::json!({"kind": "HandleRegistryVerified"})
        }
    }
}

/// Converts a [`ResolutionPath`] into a JSON value.
#[must_use]
pub fn resolution_path_to_json(path: &ResolutionPath) -> serde_json::Value {
    let layer = match path.layer {
        ResolutionLayer::Petname => "Petname",
        ResolutionLayer::HandleRegistry => "HandleRegistry",
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

impl std::fmt::Display for HandleTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HandleTargetError {}

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
        layer: ResolutionLayer::HandleRegistry,
        source: "local_registry".to_owned(),
        source_id: Some(context_id.to_owned()),
        resolved_at: now,
    };
    let trust_level = TrustLevel::HandleRegistryVerified;

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
/// Used by `address_resolve` for the context handle lookup layer.
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

        let now = scp_primitives::SystemClock.now_secs();

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
        // in contexts with discovery tools. Not available in FFI bridge — requires
        // context query infrastructure.
        Vec::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use scp_core::discovery::PetnameStore;
    use scp_core::discovery::handles::{HandleMetadata, HandleRegisterParams};

    // -----------------------------------------------------------------------
    // F3: HandleTargetError Display/Error
    // -----------------------------------------------------------------------

    #[test]
    fn handle_target_error_display() {
        let err = HandleTargetError {
            message: "something went wrong".to_owned(),
        };
        assert_eq!(err.to_string(), "something went wrong");
    }

    #[test]
    fn handle_target_error_is_std_error() {
        let err = HandleTargetError {
            message: "test".to_owned(),
        };
        // Verify it can be used as a trait object (implements std::error::Error).
        let _: &dyn std::error::Error = &err;
    }

    // -----------------------------------------------------------------------
    // JSON serialization: address_resolution_to_json
    // -----------------------------------------------------------------------

    #[test]
    fn address_resolution_to_json_identity() {
        let resolution = AddressResolution::Identity {
            did: scp_identity::DID::from("did:dht:alice"),
            trust_level: TrustLevel::LocalPetname,
            resolution_path: ResolutionPath {
                layer: ResolutionLayer::Petname,
                source: "local".to_owned(),
                source_id: None,
                resolved_at: 1_000_000,
            },
        };
        let json = address_resolution_to_json(&resolution);
        assert_eq!(json["type"], "Identity");
        assert_eq!(json["did"], "did:dht:alice");
        assert_eq!(json["trust_level"]["kind"], "LocalPetname");
        assert_eq!(json["resolution_path"]["layer"], "Petname");
        assert_eq!(json["resolution_path"]["source"], "local");
        assert!(json["resolution_path"]["source_id"].is_null());
        assert_eq!(json["resolution_path"]["resolved_at"], 1_000_000);
    }

    #[test]
    fn address_resolution_to_json_context() {
        let resolution = AddressResolution::Context {
            context_id: "ctx-abc".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            mode: Some("open".to_owned()),
            trust_level: TrustLevel::HandleRegistryVerified,
            resolution_path: ResolutionPath {
                layer: ResolutionLayer::HandleRegistry,
                source: "handle_registry".to_owned(),
                source_id: Some("ctx-abc".to_owned()),
                resolved_at: 2_000_000,
            },
        };
        let json = address_resolution_to_json(&resolution);
        assert_eq!(json["type"], "Context");
        assert_eq!(json["context_id"], "ctx-abc");
        assert_eq!(json["relay_urls"][0], "wss://relay.example.com");
        assert_eq!(json["mode"], "open");
        assert_eq!(json["trust_level"]["kind"], "HandleRegistryVerified");
        assert_eq!(json["resolution_path"]["layer"], "HandleRegistry");
        assert_eq!(json["resolution_path"]["source_id"], "ctx-abc");
    }

    // -----------------------------------------------------------------------
    // JSON serialization: trust_level_to_json (all 6 variants)
    // -----------------------------------------------------------------------

    #[test]
    fn trust_level_to_json_all_variants() {
        assert_eq!(
            trust_level_to_json(&TrustLevel::DirectExchange)["kind"],
            "DirectExchange"
        );
        assert_eq!(
            trust_level_to_json(&TrustLevel::LocalPetname)["kind"],
            "LocalPetname"
        );
        assert_eq!(
            trust_level_to_json(&TrustLevel::DomainVerified)["kind"],
            "DomainVerified"
        );
        assert_eq!(
            trust_level_to_json(&TrustLevel::AttestationVerified)["kind"],
            "AttestationVerified"
        );
        assert_eq!(
            trust_level_to_json(&TrustLevel::HandleRegistryVerified)["kind"],
            "HandleRegistryVerified"
        );
    }

    #[test]
    fn trust_level_to_json_multi_layer_corroborated() {
        let sources = vec![
            ResolutionPath {
                layer: ResolutionLayer::Petname,
                source: "local".to_owned(),
                source_id: None,
                resolved_at: 100,
            },
            ResolutionPath {
                layer: ResolutionLayer::Domain,
                source: "example.com".to_owned(),
                source_id: None,
                resolved_at: 200,
            },
        ];
        let json = trust_level_to_json(&TrustLevel::MultiLayerCorroborated { sources });
        assert_eq!(json["kind"], "MultiLayerCorroborated");
        let arr = json["sources"].as_array().expect("sources should be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["layer"], "Petname");
        assert_eq!(arr[1]["layer"], "Domain");
    }

    // -----------------------------------------------------------------------
    // JSON serialization: resolution_path_to_json (all ResolutionLayer variants)
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_path_to_json_all_layers() {
        let layers = [
            (ResolutionLayer::Petname, "Petname"),
            (ResolutionLayer::HandleRegistry, "HandleRegistry"),
            (ResolutionLayer::Attestation, "Attestation"),
            (ResolutionLayer::Domain, "Domain"),
            (
                ResolutionLayer::MultiLayerCorroborated,
                "MultiLayerCorroborated",
            ),
        ];
        for (layer, expected_str) in layers {
            let path = ResolutionPath {
                layer,
                source: "src".to_owned(),
                source_id: Some("id".to_owned()),
                resolved_at: 42,
            };
            let json = resolution_path_to_json(&path);
            assert_eq!(json["layer"], expected_str);
            assert_eq!(json["source"], "src");
            assert_eq!(json["source_id"], "id");
            assert_eq!(json["resolved_at"], 42);
        }
    }

    // -----------------------------------------------------------------------
    // parse_handle_target
    // -----------------------------------------------------------------------

    #[test]
    fn parse_handle_target_identity_valid() {
        let json = r#"{"type": "identity", "did": "did:dht:ztest123"}"#;
        let target = parse_handle_target(json).expect("should parse");
        match target {
            HandleTarget::Identity { did } => {
                assert_eq!(did.to_string(), "did:dht:ztest123");
            }
            HandleTarget::Context { .. } => panic!("expected Identity variant"),
        }
    }

    #[test]
    fn parse_handle_target_context_with_relay_urls() {
        let json =
            r#"{"type": "context", "context_id": "ctx-1", "relay_urls": ["wss://r1", "wss://r2"]}"#;
        let target = parse_handle_target(json).expect("should parse");
        match target {
            HandleTarget::Context {
                context_id,
                relay_urls,
            } => {
                assert_eq!(context_id, "ctx-1");
                assert_eq!(relay_urls, vec!["wss://r1", "wss://r2"]);
            }
            HandleTarget::Identity { .. } => panic!("expected Context variant"),
        }
    }

    #[test]
    fn parse_handle_target_context_without_relay_urls() {
        let json = r#"{"type": "context", "context_id": "ctx-2"}"#;
        let target = parse_handle_target(json).expect("should parse");
        match target {
            HandleTarget::Context {
                context_id,
                relay_urls,
            } => {
                assert_eq!(context_id, "ctx-2");
                assert!(relay_urls.is_empty());
            }
            HandleTarget::Identity { .. } => panic!("expected Context variant"),
        }
    }

    #[test]
    fn parse_handle_target_invalid_json() {
        let result = parse_handle_target("not json at all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.message.contains("invalid target_json"),
            "error message should mention invalid JSON: {}",
            err.message
        );
    }

    #[test]
    fn parse_handle_target_missing_type() {
        let result = parse_handle_target(r#"{"did": "did:dht:z1"}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("'type' field"));
    }

    #[test]
    fn parse_handle_target_invalid_type() {
        let result = parse_handle_target(r#"{"type": "unknown"}"#);
        assert!(result.is_err());
        let msg = result.unwrap_err().message;
        assert!(msg.contains("invalid target type 'unknown'"), "{msg}");
    }

    #[test]
    fn parse_handle_target_identity_missing_did() {
        let result = parse_handle_target(r#"{"type": "identity"}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("'did' field"));
    }

    #[test]
    fn parse_handle_target_context_missing_context_id() {
        let result = parse_handle_target(r#"{"type": "context"}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("'context_id' field"));
    }

    // -----------------------------------------------------------------------
    // handle_entry_to_resolution
    // -----------------------------------------------------------------------

    #[test]
    fn handle_entry_to_resolution_identity() {
        let entry = HandleEntry {
            handle: "alice".to_owned(),
            target: HandleTarget::Identity {
                did: scp_identity::DID::from("did:dht:zalice"),
            },
            owner_did: scp_identity::DID::from("did:dht:zalice"),
            registered_at: 100,
            metadata: HandleMetadata::default(),
            entry_id: "entry-1".to_owned(),
        };
        let resolution = handle_entry_to_resolution(&entry, "ctx-test", 999);
        match resolution {
            AddressResolution::Identity {
                did,
                trust_level,
                resolution_path,
            } => {
                assert_eq!(did.to_string(), "did:dht:zalice");
                assert!(matches!(trust_level, TrustLevel::HandleRegistryVerified));
                assert!(matches!(
                    resolution_path.layer,
                    ResolutionLayer::HandleRegistry
                ));
                assert_eq!(resolution_path.source, "local_registry");
                assert_eq!(resolution_path.source_id.as_deref(), Some("ctx-test"));
                assert_eq!(resolution_path.resolved_at, 999);
            }
            AddressResolution::Context { .. } => panic!("expected Identity"),
        }
    }

    #[test]
    fn handle_entry_to_resolution_context() {
        let entry = HandleEntry {
            handle: "general".to_owned(),
            target: HandleTarget::Context {
                context_id: "ctx-target".to_owned(),
                relay_urls: vec!["wss://relay.example.com".to_owned()],
            },
            owner_did: scp_identity::DID::from("did:dht:zowner"),
            registered_at: 200,
            metadata: HandleMetadata::default(),
            entry_id: "entry-2".to_owned(),
        };
        let resolution = handle_entry_to_resolution(&entry, "ctx-src", 1234);
        match resolution {
            AddressResolution::Context {
                context_id,
                relay_urls,
                mode,
                trust_level,
                resolution_path,
            } => {
                assert_eq!(context_id, "ctx-target");
                assert_eq!(relay_urls, vec!["wss://relay.example.com"]);
                assert!(mode.is_none());
                assert!(matches!(trust_level, TrustLevel::HandleRegistryVerified));
                assert_eq!(resolution_path.source_id.as_deref(), Some("ctx-src"));
                assert_eq!(resolution_path.resolved_at, 1234);
            }
            AddressResolution::Identity { .. } => panic!("expected Context"),
        }
    }

    // -----------------------------------------------------------------------
    // Global singletons: petname_maps / handle_registries
    // -----------------------------------------------------------------------

    #[test]
    fn petname_map_insert_retrieve_reset() {
        let owner = "did:dht:zsingleton-pm-test";
        reset_petname_map_for(owner);

        // Insert a petname map entry.
        {
            let mut guard = petname_maps().lock().expect("lock");
            let pm = guard.entry(owner.to_owned()).or_default();
            pm.set_petname(scp_identity::DID::from("did:dht:zbob"), "bob".to_owned());
        }

        // Retrieve and verify.
        {
            let guard = petname_maps().lock().expect("lock");
            let pm = guard.get(owner).expect("should exist");
            let resolved = pm.resolve_petname("bob", &scp_primitives::SystemClock);
            assert!(!resolved.is_empty());
        }

        // Reset and verify it's gone.
        reset_petname_map_for(owner);
        {
            let guard = petname_maps().lock().expect("lock");
            assert!(guard.get(owner).is_none());
        }
    }

    #[test]
    fn handle_registry_insert_retrieve_reset() {
        let ctx = "singleton-hr-test-ctx";
        reset_handle_registry_for(ctx);

        // Insert a handle.
        {
            let mut guard = handle_registries().lock().expect("lock");
            let registry = guard
                .entry(ctx.to_owned())
                .or_insert_with(|| HandleRegistry::new(ctx.to_owned()));
            let did = scp_identity::DID::from("did:dht:zcharlie");
            let params = HandleRegisterParams {
                handle: "charlie".to_owned(),
                target: HandleTarget::Identity { did: did.clone() },
                metadata: None,
            };
            let result = registry.register(&params, &did, &scp_primitives::SystemClock);
            assert_eq!(
                result.status,
                scp_core::discovery::handles::HandleRegisterStatus::Registered
            );
        }

        // Lookup.
        {
            let guard = handle_registries().lock().expect("lock");
            let registry = guard.get(ctx).expect("should exist");
            let result = registry.lookup(&HandleLookupParams {
                handle: "charlie".to_owned(),
                type_filter: None,
            });
            assert_eq!(result.results.len(), 1);
            assert_eq!(result.results[0].handle, "charlie");
        }

        // Reset and verify it's gone.
        reset_handle_registry_for(ctx);
        {
            let guard = handle_registries().lock().expect("lock");
            assert!(guard.get(ctx).is_none());
        }
    }

    // -----------------------------------------------------------------------
    // LocalHandleQuerier
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn local_handle_querier_lookup_returns_results() {
        let ctx = "lhq-test-ctx-returns";
        reset_handle_registry_for(ctx);

        // Register a handle.
        {
            let mut guard = handle_registries().lock().expect("lock");
            let registry = guard
                .entry(ctx.to_owned())
                .or_insert_with(|| HandleRegistry::new(ctx.to_owned()));
            let did = scp_identity::DID::from("did:dht:zdave");
            let params = HandleRegisterParams {
                handle: "dave".to_owned(),
                target: HandleTarget::Identity { did: did.clone() },
                metadata: None,
            };
            registry.register(&params, &did, &scp_primitives::SystemClock);
        }

        let querier = LocalHandleQuerier;
        let results = querier.lookup_handle(&ctx.to_owned(), "dave", None).await;
        assert_eq!(results.len(), 1);
        match &results[0] {
            AddressResolution::Identity { did, .. } => {
                assert_eq!(did.to_string(), "did:dht:zdave");
            }
            AddressResolution::Context { .. } => panic!("expected Identity"),
        }

        reset_handle_registry_for(ctx);
    }

    #[tokio::test]
    async fn local_handle_querier_lookup_empty_when_context_not_found() {
        let querier = LocalHandleQuerier;
        let results = querier
            .lookup_handle(&"nonexistent-ctx-xyz".to_owned(), "anyone", None)
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn local_handle_querier_type_filter() {
        let ctx = "lhq-filter-test-ctx";
        reset_handle_registry_for(ctx);

        // Register an identity handle.
        {
            let mut guard = handle_registries().lock().expect("lock");
            let registry = guard
                .entry(ctx.to_owned())
                .or_insert_with(|| HandleRegistry::new(ctx.to_owned()));
            let did = scp_identity::DID::from("did:dht:zeve");
            let params = HandleRegisterParams {
                handle: "eve".to_owned(),
                target: HandleTarget::Identity { did: did.clone() },
                metadata: None,
            };
            registry.register(&params, &did, &scp_primitives::SystemClock);
        }

        let querier = LocalHandleQuerier;

        // Filter for Identity — should find the entry.
        let identity_results = querier
            .lookup_handle(&ctx.to_owned(), "eve", Some(AddressType::Identity))
            .await;
        assert_eq!(identity_results.len(), 1);

        // Filter for Context — should find nothing (entry is Identity).
        let context_results = querier
            .lookup_handle(&ctx.to_owned(), "eve", Some(AddressType::Context))
            .await;
        assert!(context_results.is_empty());

        reset_handle_registry_for(ctx);
    }

    #[tokio::test]
    async fn local_handle_querier_domain_and_attestation_return_empty() {
        let querier = LocalHandleQuerier;
        assert!(
            querier
                .lookup_domain_handle("example.com", "alice")
                .await
                .is_empty()
        );
        assert!(
            querier
                .lookup_attestation_handle("alice", Some("github"))
                .await
                .is_empty()
        );
    }
}
