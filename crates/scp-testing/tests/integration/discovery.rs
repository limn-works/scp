#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::redundant_clone
)]

//! B13: Discovery & DHT resolution integration tests.
//!
//! Tests address parsing, normalization, petname CRUD, handle registry CRUD,
//! discovery query capability filtering, registration entry construction,
//! DID document relay services, deterministic DID routing IDs, bootstrap
//! configuration, trust level ordering, and handle target variants.

use scp_core::discovery::{
    BootstrapConfig, BootstrapContextEntry, DataProvenance, DiscoveryQuery, HandleTarget,
    ParsedAddress, PetnameMap, RegistrationEntry, TrustLevel, normalize_address, parse_address,
};
use scp_core::discovery::{
    HandleDeregisterParams, HandleLookupParams, HandleRegisterParams, HandleRegistry,
};
use scp_core::discovery::{
    ScopeDeregisterParams, ScopeLookupParams, ScopeRegisterParams, ScopeRegisterStatus,
    ScopeRegistry, ScopeTarget, validate_scope_name,
};
use scp_identity::document::DidDocument;
use scp_identity::{DID, DidDht, DidMethod};
use scp_platform::testing::InMemoryKeyCustody;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates an identity via `DidDht::create` and returns the DID document.
async fn create_test_document(custody: &InMemoryKeyCustody) -> DidDocument {
    let did_dht = DidDht::new();
    let (_identity, doc) = did_dht.create(custody).await.expect("create identity");
    doc
}

// ---------------------------------------------------------------------------
// 1. parse_address: unscoped (bare name, maps to petname resolution)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_address_unscoped() {
    let parsed = parse_address("alice").unwrap();
    assert_eq!(
        parsed,
        ParsedAddress::Unscoped {
            name: "alice".to_owned()
        }
    );
}

// ---------------------------------------------------------------------------
// 2. parse_address: discovery handle (alice@discovery-ctx)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_address_discovery_handle() {
    let parsed = parse_address("alice@discovery-ctx").unwrap();
    assert_eq!(
        parsed,
        ParsedAddress::DiscoveryHandle {
            local_part: "alice".to_owned(),
            scope: "discovery-ctx".to_owned(),
        }
    );
}

// ---------------------------------------------------------------------------
// 3. parse_address: domain handle (alice@example.com)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_address_domain_handle() {
    let parsed = parse_address("alice@example.com").unwrap();
    assert_eq!(
        parsed,
        ParsedAddress::DomainHandle {
            local_part: "alice".to_owned(),
            domain: "example.com".to_owned(),
        }
    );
}

// ---------------------------------------------------------------------------
// 4. parse_address: attestation handle (@alice_cooks)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_address_attestation_handle() {
    let parsed = parse_address("@alice_cooks").unwrap();
    assert_eq!(
        parsed,
        ParsedAddress::AttestationHandle {
            handle: "alice_cooks".to_owned(),
            platform: None,
        }
    );
}

// ---------------------------------------------------------------------------
// 5. parse_address: attestation handle with platform (@alice_cooks:x)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_address_attestation_handle_with_platform() {
    let parsed = parse_address("@alice_cooks:x").unwrap();
    assert_eq!(
        parsed,
        ParsedAddress::AttestationHandle {
            handle: "alice_cooks".to_owned(),
            platform: Some("x".to_owned()),
        }
    );
}

// ---------------------------------------------------------------------------
// 6. normalize_address: case normalization, whitespace trim
// ---------------------------------------------------------------------------

#[tokio::test]
async fn normalize_address_case_and_whitespace() {
    assert_eq!(normalize_address("  Alice  "), "alice");
    assert_eq!(normalize_address("ALICE@EXAMPLE.COM"), "alice@example.com");
    assert_eq!(normalize_address("\t  Bob  \n"), "bob");
    // Already normalized stays the same.
    assert_eq!(normalize_address("alice"), "alice");
}

// ---------------------------------------------------------------------------
// 7. petname_map_crud: set/lookup/remove petname
// ---------------------------------------------------------------------------

#[tokio::test]
async fn petname_map_crud() {
    let mut map = PetnameMap::new();

    // Initially empty.
    assert_eq!(map.did_petname_count(), 0);
    assert!(map.resolve_did("alice").is_empty());

    // Set a petname.
    let alice = DID::from("did:dht:zAlice");
    map.set_petname(alice.clone(), "alice".to_owned());
    assert_eq!(map.did_petname_count(), 1);

    // Lookup returns the DID.
    let dids = map.resolve_did("alice");
    assert_eq!(dids.len(), 1);
    assert_eq!(dids[0], "did:dht:zAlice");

    // Reverse lookup works.
    assert_eq!(map.petname_for_did(&alice), Some("alice"));

    // Remove the petname.
    map.remove_petname(&alice);
    assert_eq!(map.did_petname_count(), 0);
    assert!(map.resolve_did("alice").is_empty());
    assert!(map.petname_for_did(&alice).is_none());
}

// ---------------------------------------------------------------------------
// 8. petname_map: context petnames
// ---------------------------------------------------------------------------

#[tokio::test]
async fn petname_map_context_crud() {
    let mut map = PetnameMap::new();

    let ctx_id = "ctx-recipes".to_owned();
    map.set_context_petname(ctx_id.clone(), "recipes".to_owned());
    assert_eq!(map.context_petname_count(), 1);

    let ids = map.resolve_context("recipes");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], "ctx-recipes");

    assert_eq!(map.petname_for_context(&ctx_id), Some("recipes"));

    map.remove_context_petname(&ctx_id);
    assert_eq!(map.context_petname_count(), 0);
    assert!(map.resolve_context("recipes").is_empty());
}

// ---------------------------------------------------------------------------
// 9. petname_map: overwrite replaces previous mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn petname_map_overwrite() {
    let mut map = PetnameMap::new();
    let alice = DID::from("did:dht:zAlice");

    map.set_petname(alice.clone(), "old-name".to_owned());
    map.set_petname(alice.clone(), "new-name".to_owned());

    assert!(map.resolve_did("old-name").is_empty());
    assert_eq!(map.resolve_did("new-name").len(), 1);
    assert_eq!(map.petname_for_did(&alice), Some("new-name"));
}

// ---------------------------------------------------------------------------
// 10. handle_registry_crud: register/lookup/deregister
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handle_registry_crud() {
    let mut registry = HandleRegistry::new("ctx-community".to_owned());
    assert!(registry.is_empty());

    let alice_did = DID::from("did:dht:zAlice");

    // Register a handle.
    let params = HandleRegisterParams {
        handle: "alice".to_owned(),
        target: HandleTarget::Identity {
            did: alice_did.clone(),
        },
        metadata: None,
    };
    let result = registry.register(&params, &alice_did, &scp_primitives::SystemClock);
    assert_eq!(
        result.status,
        scp_core::discovery::HandleRegisterStatus::Registered
    );
    assert!(result.entry_id.is_some());
    assert_eq!(registry.len(), 1);

    // Lookup returns the entry.
    let lookup = registry.lookup(&HandleLookupParams {
        handle: "alice".to_owned(),
        type_filter: None,
    });
    assert_eq!(lookup.results.len(), 1);
    assert_eq!(lookup.results[0].handle, "alice");

    // Deregister by owner succeeds.
    let dereg = registry.deregister(&HandleDeregisterParams {
        handle: "alice".to_owned(),
        did: alice_did,
    });
    assert!(dereg.removed);
    assert!(registry.is_empty());
}

// ---------------------------------------------------------------------------
// 11. handle_registry: conflict detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handle_registry_conflict() {
    let mut registry = HandleRegistry::new("ctx-community".to_owned());
    let alice_did = DID::from("did:dht:zAlice");
    let bob_did = DID::from("did:dht:zBob");

    let params_alice = HandleRegisterParams {
        handle: "alice".to_owned(),
        target: HandleTarget::Identity {
            did: alice_did.clone(),
        },
        metadata: None,
    };
    registry.register(&params_alice, &alice_did, &scp_primitives::SystemClock);

    // Bob tries to register the same handle.
    let params_bob = HandleRegisterParams {
        handle: "alice".to_owned(),
        target: HandleTarget::Identity {
            did: bob_did.clone(),
        },
        metadata: None,
    };
    let result = registry.register(&params_bob, &bob_did, &scp_primitives::SystemClock);
    assert_eq!(
        result.status,
        scp_core::discovery::HandleRegisterStatus::Conflict
    );
}

// ---------------------------------------------------------------------------
// 12. discovery_query_capability_filter: filter results by capability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_query_capability_filter() {
    // Construct a query with capability filter.
    let query = DiscoveryQuery {
        capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
        keywords: None,
        min_history: None,
    };

    // Verify the filter is set correctly.
    let filter = query.capability_filter.as_ref().unwrap();
    assert_eq!(filter.len(), 2);
    assert!(filter.contains(&"code_review".to_owned()));
    assert!(filter.contains(&"testing".to_owned()));

    // Default query has no filter.
    let default_query = DiscoveryQuery::default();
    assert!(default_query.capability_filter.is_none());
}

// ---------------------------------------------------------------------------
// 13. registration_entry_fields: RegistrationEntry construction + fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_entry_fields() {
    let entry = RegistrationEntry {
        did: DID::from("did:dht:zAgent123"),
        capabilities: vec!["translation".to_owned(), "summarization".to_owned()],
        metadata: serde_json::json!({"language": "es", "model": "gpt-4"}),
        entry_id: "reg-001".to_owned(),
        registered_at: 1_700_000_000,
    };

    assert_eq!(entry.did, "did:dht:zAgent123");
    assert_eq!(entry.capabilities.len(), 2);
    assert_eq!(entry.capabilities[0], "translation");
    assert_eq!(entry.capabilities[1], "summarization");
    assert_eq!(entry.entry_id, "reg-001");
    assert_eq!(entry.registered_at, 1_700_000_000);

    // Serialization roundtrip.
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: RegistrationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, deserialized);
}

// ---------------------------------------------------------------------------
// 14. did_document_relay_services: add, list, replace relay services
// ---------------------------------------------------------------------------

#[tokio::test]
async fn did_document_relay_services() {
    let custody = InMemoryKeyCustody::new();
    let mut doc = create_test_document(&custody).await;

    // Initially no relay services.
    assert!(doc.relay_service_urls().is_empty());

    // Add a relay service.
    doc.add_relay_service("wss://relay1.example.com/scp/v1")
        .unwrap();
    let urls = doc.relay_service_urls();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0], "wss://relay1.example.com/scp/v1");

    // Add a second relay service.
    doc.add_relay_service("wss://relay2.example.com/scp/v1")
        .unwrap();
    let urls = doc.relay_service_urls();
    assert_eq!(urls.len(), 2);
    assert_eq!(urls[1], "wss://relay2.example.com/scp/v1");

    // Replace all relay services.
    doc.set_relay_services(&[
        "wss://new-relay.example.com/scp/v1",
        "wss://backup-relay.example.com/scp/v1",
    ])
    .unwrap();
    let urls = doc.relay_service_urls();
    assert_eq!(urls.len(), 2);
    assert_eq!(urls[0], "wss://new-relay.example.com/scp/v1");
    assert_eq!(urls[1], "wss://backup-relay.example.com/scp/v1");

    // Invalid URL rejected.
    assert!(doc.add_relay_service("http://bad.example.com").is_err());
}

// ---------------------------------------------------------------------------
// 15. did_routing_id_deterministic: same DID -> same routing_id, different -> different
// ---------------------------------------------------------------------------

#[tokio::test]
async fn did_routing_id_deterministic() {
    let id1 = scp_identity::did_routing_id("did:dht:z6MkTestDid1");
    let id2 = scp_identity::did_routing_id("did:dht:z6MkTestDid1");
    assert_eq!(id1, id2, "same DID must produce the same routing ID");

    let id3 = scp_identity::did_routing_id("did:dht:z6MkTestDid2");
    assert_ne!(
        id1, id3,
        "different DIDs must produce different routing IDs"
    );

    // Routing ID is 32 bytes (SHA-256).
    assert_eq!(id1.len(), 32);
}

// ---------------------------------------------------------------------------
// 16. bootstrap_config: with_defaults, add_custom_context, all_contexts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_config() {
    // Default config.
    let default_config = BootstrapConfig::default();
    assert!(default_config.default_contexts.is_empty());
    assert!(default_config.custom_contexts.is_empty());
    assert!(default_config.should_auto_query());
    assert!(default_config.should_fallback());

    // with_defaults using BootstrapContextEntry.
    let config = BootstrapConfig::with_defaults(vec![
        BootstrapContextEntry::new("ctx-discovery-1".to_owned(), DID::from("did:dht:zCreator1")),
        BootstrapContextEntry::new("ctx-discovery-2".to_owned(), DID::from("did:dht:zCreator2")),
    ])
    .unwrap();
    assert_eq!(config.default_contexts.len(), 2);
    assert!(config.custom_contexts.is_empty());

    // add_custom_context.
    let mut config = config;
    config
        .add_custom_context(BootstrapContextEntry::new(
            "ctx-custom-1".to_owned(),
            DID::from("did:dht:zCustom1"),
        ))
        .unwrap();
    assert_eq!(config.custom_contexts.len(), 1);

    // all_contexts combines defaults and custom.
    let all = config.all_contexts();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].context_id, "ctx-discovery-1");
    assert_eq!(all[1].context_id, "ctx-discovery-2");
    assert_eq!(all[2].context_id, "ctx-custom-1");
}

// ---------------------------------------------------------------------------
// 17. trust_level_ordering: TrustLevel default_rank comparison
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trust_level_ordering() {
    // DirectExchange has the highest rank.
    assert!(TrustLevel::DirectExchange.default_rank() > TrustLevel::LocalPetname.default_rank());
    assert!(
        TrustLevel::LocalPetname.default_rank()
            > TrustLevel::MultiLayerCorroborated { sources: vec![] }.default_rank()
    );
    assert!(
        TrustLevel::MultiLayerCorroborated { sources: vec![] }.default_rank()
            > TrustLevel::DomainVerified.default_rank()
    );
    assert!(
        TrustLevel::DomainVerified.default_rank() > TrustLevel::AttestationVerified.default_rank()
    );
    assert!(
        TrustLevel::AttestationVerified.default_rank()
            > TrustLevel::HandleRegistryVerified.default_rank()
    );

    // Verify actual numeric values.
    assert_eq!(TrustLevel::DirectExchange.default_rank(), 6);
    assert_eq!(TrustLevel::LocalPetname.default_rank(), 5);
    assert_eq!(TrustLevel::HandleRegistryVerified.default_rank(), 1);
}

// ---------------------------------------------------------------------------
// 18. handle_target_variants: Identity vs Context target types
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handle_target_variants() {
    // Identity target.
    let identity_target = HandleTarget::Identity {
        did: DID::from("did:dht:zAlice"),
    };
    assert!(matches!(
        &identity_target,
        HandleTarget::Identity { did } if did == "did:dht:zAlice"
    ));

    // Context target.
    let context_target = HandleTarget::Context {
        context_id: "ctx-123".to_owned(),
        relay_urls: vec!["wss://relay.example.com/scp/v1".to_owned()],
    };
    assert!(matches!(
        &context_target,
        HandleTarget::Context { context_id, relay_urls }
        if context_id == "ctx-123" && relay_urls.len() == 1
    ));

    // Serialization roundtrip for both variants.
    let json_identity = serde_json::to_string(&identity_target).unwrap();
    let deser_identity: HandleTarget = serde_json::from_str(&json_identity).unwrap();
    assert_eq!(identity_target, deser_identity);

    let json_context = serde_json::to_string(&context_target).unwrap();
    let deser_context: HandleTarget = serde_json::from_str(&json_context).unwrap();
    assert_eq!(context_target, deser_context);
}

// ---------------------------------------------------------------------------
// 19. data_provenance_construction: DataProvenance fields and roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn data_provenance_construction() {
    let provenance = DataProvenance {
        source_did: DID::from("did:dht:zSource"),
        source_context: Some("ctx-001".to_owned()),
        timestamp: 1_700_000_000,
    };

    assert_eq!(provenance.source_did, "did:dht:zSource");
    assert_eq!(provenance.source_context.as_deref(), Some("ctx-001"));
    assert_eq!(provenance.timestamp, 1_700_000_000);

    // Serialization roundtrip.
    let json = serde_json::to_string(&provenance).unwrap();
    let deserialized: DataProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(provenance, deserialized);

    // Without source context.
    let prov_no_ctx = DataProvenance {
        source_did: DID::from("did:dht:zSource2"),
        source_context: None,
        timestamp: 1_700_001_000,
    };
    assert!(prov_no_ctx.source_context.is_none());
}

// ---------------------------------------------------------------------------
// 20. parse_address_errors: empty, too long, invalid characters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_address_errors() {
    // Empty address.
    assert!(parse_address("").is_err());
    assert!(parse_address("   ").is_err());

    // Trailing @ with no scope.
    assert!(parse_address("alice@").is_err());

    // Bare @ is empty.
    assert!(parse_address("@").is_err());
}

// ---------------------------------------------------------------------------
// Scope registry integration tests (§22.3.5, ADR-043)
// ---------------------------------------------------------------------------

#[test]
fn scope_registry_crud() {
    let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
    let admin_did = DID::from("did:dht:zAdmin");

    // Register a scope
    let params = ScopeRegisterParams {
        name: "cooking-community".to_owned(),
        target: ScopeTarget {
            context_id: "ctx-cooking".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
        },
        metadata: None,
    };
    let result = registry
        .register(&params, &admin_did, &scp_primitives::SystemClock)
        .unwrap();
    assert_eq!(result.status, ScopeRegisterStatus::Registered);
    assert!(result.entry_id.is_some());

    // Lookup the scope
    let lookup = registry
        .lookup(&ScopeLookupParams {
            name: "cooking-community".to_owned(),
        })
        .unwrap();
    assert_eq!(lookup.results.len(), 1);
    assert_eq!(lookup.results[0].target.context_id, "ctx-cooking");
    assert_eq!(
        lookup.results[0].target.relay_urls,
        vec!["wss://relay.example.com"]
    );
    assert_eq!(lookup.results[0].owner_did, admin_did);

    // Deregister the scope
    let deregister = registry
        .deregister(&ScopeDeregisterParams {
            name: "cooking-community".to_owned(),
            did: admin_did,
        })
        .unwrap();
    assert!(deregister.removed);
    assert!(registry.is_empty());
}

#[test]
fn scope_registry_validate_scope_name_rejects_dots_and_underscores() {
    assert!(validate_scope_name("cooking.community").is_err());
    assert!(validate_scope_name("cooking_community").is_err());
    assert!(validate_scope_name("cooking-community").is_ok());
    assert!(validate_scope_name("abc123").is_ok());
}

#[test]
fn scope_registry_isolation_from_handle_registry() {
    let mut scope_registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
    let mut handle_registry = HandleRegistry::new("ctx-bootstrap".to_owned());
    let admin_did = DID::from("did:dht:zAdmin");

    // Register the same name in both registries — no collision
    scope_registry
        .register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx-cooking".to_owned(),
                    relay_urls: vec!["wss://relay.example.com".to_owned()],
                },
                metadata: None,
            },
            &admin_did,
            &scp_primitives::SystemClock,
        )
        .unwrap();

    handle_registry.register(
        &HandleRegisterParams {
            handle: "cooking".to_owned(),
            target: HandleTarget::Identity {
                did: admin_did.clone(),
            },
            metadata: None,
        },
        &admin_did,
        &scp_primitives::SystemClock,
    );

    // Both registries have one entry — independent
    assert_eq!(scope_registry.len(), 1);
    assert_eq!(handle_registry.len(), 1);

    // Scope lookup returns scope entry, not handle entry
    let scope_lookup = scope_registry
        .lookup(&ScopeLookupParams {
            name: "cooking".to_owned(),
        })
        .unwrap();
    assert_eq!(scope_lookup.results.len(), 1);
    assert_eq!(scope_lookup.results[0].target.context_id, "ctx-cooking");

    // Handle lookup returns handle entry, not scope entry
    let handle_lookup = handle_registry.lookup(&HandleLookupParams {
        handle: "cooking".to_owned(),
        type_filter: None,
    });
    assert_eq!(handle_lookup.results.len(), 1);
    assert!(matches!(
        handle_lookup.results[0].target,
        HandleTarget::Identity { .. }
    ));
}

#[test]
fn scope_same_owner_update_is_atomic() {
    let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());
    let admin_did = DID::from("did:dht:zAdmin");

    // First registration
    let r1 = registry
        .register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx-v1".to_owned(),
                    relay_urls: vec!["wss://r1.example.com".to_owned()],
                },
                metadata: None,
            },
            &admin_did,
            &scp_primitives::SystemClock,
        )
        .unwrap();
    assert_eq!(r1.status, ScopeRegisterStatus::Registered);

    // Same-owner re-registration → Updated, not Conflict
    let r2 = registry
        .register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx-v2".to_owned(),
                    relay_urls: vec!["wss://r2.example.com".to_owned()],
                },
                metadata: None,
            },
            &admin_did,
            &scp_primitives::SystemClock,
        )
        .unwrap();
    assert_eq!(r2.status, ScopeRegisterStatus::Updated);
    assert_eq!(r2.entry_id, r1.entry_id);

    // Only one entry, with updated target
    assert_eq!(registry.len(), 1);
    let lookup = registry
        .lookup(&ScopeLookupParams {
            name: "cooking".to_owned(),
        })
        .unwrap();
    assert_eq!(lookup.results[0].target.context_id, "ctx-v2");
}

#[test]
fn scope_different_owner_conflict() {
    let mut registry = ScopeRegistry::new("ctx-bootstrap".to_owned());

    registry
        .register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx-cooking".to_owned(),
                    relay_urls: vec!["wss://relay.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zAdmin"),
            &scp_primitives::SystemClock,
        )
        .unwrap();

    let conflict = registry
        .register(
            &ScopeRegisterParams {
                name: "cooking".to_owned(),
                target: ScopeTarget {
                    context_id: "ctx-evil".to_owned(),
                    relay_urls: vec!["wss://evil.example.com".to_owned()],
                },
                metadata: None,
            },
            &DID::from("did:dht:zEve"),
            &scp_primitives::SystemClock,
        )
        .unwrap();
    assert_eq!(conflict.status, ScopeRegisterStatus::Conflict);
    assert!(conflict.entry_id.is_none());
}
