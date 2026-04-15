//! Context handle tools: register, lookup, and deregister.
//!
//! Implements §22.3.1 Handle Tools: three standard tool schemas for
//! contexts that support human-readable handles. These follow the same two-tier
//! architecture as existing discovery tools (§6.2.2B): writers (MLS members)
//! process registrations, readers (DID-authenticated, unbounded) perform lookups.
//!
//! Tool schemas:
//! - `handle_register(handle, target, metadata?) -> { status, entry_id? }`
//! - `handle_lookup(handle, type_filter?) -> { results }`
//! - `handle_deregister(handle, did) -> { removed }`
//!
//! See SCP-223 for the implementation story.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_primitives::Clock;
use scp_primitives::DID;

use super::ContextId;
use super::addressing::HandleTarget;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard tool name for handle registration.
pub const TOOL_HANDLE_REGISTER: &str = "handle_register";

/// Standard tool name for handle lookup.
pub const TOOL_HANDLE_LOOKUP: &str = "handle_lookup";

/// Standard tool name for handle deregistration.
pub const TOOL_HANDLE_DEREGISTER: &str = "handle_deregister";

/// Maximum number of entries in a single handle registry (§22.3.1).
const MAX_HANDLE_ENTRIES: usize = 10_000;

// ---------------------------------------------------------------------------
// HandleRegisterParams / HandleRegisterResult (§22.3.1)
// ---------------------------------------------------------------------------

/// Input parameters for the `handle_register` tool.
///
/// Registers a handle in a context with discovery tools. The registrant's DID is
/// authenticated via the DID-signed request. Handle uniqueness is enforced
/// per local-part within the context namespace.
///
/// See §22.3.1 Handle Tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleRegisterParams {
    /// The local-part to register (e.g., `"alice"`).
    pub handle: String,
    /// What the handle points to (identity DID or context ID + relay URLs).
    pub target: HandleTarget,
    /// Optional descriptive metadata.
    pub metadata: Option<HandleMetadata>,
}

/// Optional metadata attached to a handle registration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleMetadata {
    /// Human-readable description of the handle.
    pub description: Option<String>,
    /// Tags for categorization.
    pub tags: Option<Vec<String>>,
}

/// Output of the `handle_register` tool.
///
/// Returns an unambiguous status: `"registered"` on success, `"conflict"` when
/// another DID already holds the requested handle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleRegisterResult {
    /// Outcome: `"registered"` or `"conflict"`.
    pub status: HandleRegisterStatus,
    /// Present when `status` is `Registered`. Unique identifier for this entry.
    pub entry_id: Option<String>,
}

/// The outcome of a handle registration attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleRegisterStatus {
    /// The handle was successfully registered.
    Registered,
    /// Another DID already holds this handle.
    Conflict,
    /// The registrant DID does not match the target identity DID.
    OwnershipMismatch,
    /// The handle registry is at capacity and cannot accept new registrations.
    CapacityExceeded,
}

// ---------------------------------------------------------------------------
// HandleLookupParams / HandleLookupResult (§22.3.1)
// ---------------------------------------------------------------------------

/// Input parameters for the `handle_lookup` tool.
///
/// Looks up a handle in a context with discovery tools. Available to readers
/// (DID-authenticated, unbounded tier).
///
/// See §22.3.1 Handle Tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleLookupParams {
    /// The local-part to look up (e.g., `"alice"`).
    pub handle: String,
    /// Optional type constraint to filter results.
    pub type_filter: Option<HandleTypeFilter>,
}

/// Type filter for handle lookups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandleTypeFilter {
    /// Only return identity (DID) results.
    Identity,
    /// Only return context results.
    Context,
}

/// Output of the `handle_lookup` tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleLookupResult {
    /// The lookup results.
    pub results: Vec<HandleEntry>,
}

/// A single handle entry returned from a lookup.
///
/// Matches the `HandleResult` sum type from §22.3.1, carrying either an
/// identity or context target along with registration metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleEntry {
    /// The handle local-part.
    pub handle: String,
    /// What the handle points to.
    pub target: HandleTarget,
    /// The DID that owns this registration.
    pub owner_did: DID,
    /// Unix timestamp (seconds) when registered.
    pub registered_at: u64,
    /// Descriptive metadata.
    pub metadata: HandleMetadata,
    /// Unique entry identifier.
    pub entry_id: String,
}

// ---------------------------------------------------------------------------
// HandleDeregisterParams / HandleDeregisterResult (§22.3.1)
// ---------------------------------------------------------------------------

/// Input parameters for the `handle_deregister` tool.
///
/// Removes a handle registration. The `did` field is explicit (not inferred
/// from request signature) so the ownership check is visible in the interface.
///
/// See §22.3.1 Handle Tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleDeregisterParams {
    /// The local-part to deregister.
    pub handle: String,
    /// The registrant's DID (must match the handle owner).
    pub did: DID,
}

/// Output of the `handle_deregister` tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleDeregisterResult {
    /// Whether the handle was actually removed.
    pub removed: bool,
}

// ---------------------------------------------------------------------------
// HandleRegistry (in-memory reference implementation)
// ---------------------------------------------------------------------------

/// In-memory handle registry for a single context.
///
/// Enforces handle uniqueness per local-part and owner-only deregistration.
/// Production implementations would back this with a persistent store and
/// event log recording.
///
/// See §22.3.1 Handle Tools and §22.3.2 Scope Naming.
#[derive(Debug)]
pub struct HandleRegistry {
    /// The context ID this registry belongs to.
    context_id: ContextId,
    /// Handle entries keyed by normalized local-part.
    entries: HashMap<String, HandleEntry>,
    /// Counter for generating entry IDs.
    next_entry_id: u64,
}

impl HandleRegistry {
    /// Creates a new empty handle registry for the given context.
    #[must_use]
    pub fn new(context_id: ContextId) -> Self {
        Self {
            context_id,
            entries: HashMap::new(),
            next_entry_id: 1,
        }
    }

    /// Returns the context ID this registry belongs to.
    #[must_use]
    pub const fn context_id(&self) -> &ContextId {
        &self.context_id
    }

    /// Registers a handle.
    ///
    /// The `registrant_did` is the DID of the authenticated caller (verified
    /// via DID-signed request at the transport layer). For identity targets,
    /// `registrant_did` must match the target DID to prevent handle squatting.
    /// Context targets may be registered by any authenticated DID.
    ///
    /// Returns `Registered` on success, `Conflict` if another DID already
    /// holds this handle, or `OwnershipMismatch` if the registrant does not
    /// own the target identity DID.
    ///
    pub fn register(
        &mut self,
        params: &HandleRegisterParams,
        registrant_did: &DID,
        clock: &dyn Clock,
    ) -> HandleRegisterResult {
        if let HandleTarget::Identity { ref did } = params.target
            && did != registrant_did
        {
            return HandleRegisterResult {
                status: HandleRegisterStatus::OwnershipMismatch,
                entry_id: None,
            };
        }

        let normalized = params.handle.to_lowercase();

        if self.entries.contains_key(&normalized) {
            return HandleRegisterResult {
                status: HandleRegisterStatus::Conflict,
                entry_id: None,
            };
        }

        if self.entries.len() >= MAX_HANDLE_ENTRIES {
            return HandleRegisterResult {
                status: HandleRegisterStatus::CapacityExceeded,
                entry_id: None,
            };
        }

        let entry_id = format!("handle-{}", self.next_entry_id);
        self.next_entry_id += 1;

        let now = clock.now_secs();

        let entry = HandleEntry {
            handle: normalized.clone(),
            target: params.target.clone(),
            owner_did: registrant_did.clone(),
            registered_at: now,
            metadata: params.metadata.clone().unwrap_or_default(),
            entry_id: entry_id.clone(),
        };

        self.entries.insert(normalized, entry);

        HandleRegisterResult {
            status: HandleRegisterStatus::Registered,
            entry_id: Some(entry_id),
        }
    }

    /// Looks up a handle.
    ///
    /// Returns matching entries. With `type_filter`, only entries matching
    /// the specified target type are returned.
    #[must_use]
    pub fn lookup(&self, params: &HandleLookupParams) -> HandleLookupResult {
        let normalized = params.handle.to_lowercase();
        let mut results = Vec::new();

        if let Some(entry) = self.entries.get(&normalized) {
            let matches_filter = match &params.type_filter {
                None => true,
                Some(HandleTypeFilter::Identity) => {
                    matches!(entry.target, HandleTarget::Identity { .. })
                }
                Some(HandleTypeFilter::Context) => {
                    matches!(entry.target, HandleTarget::Context { .. })
                }
            };

            if matches_filter {
                results.push(entry.clone());
            }
        }

        HandleLookupResult { results }
    }

    /// Deregisters a handle.
    ///
    /// Only succeeds if the provided DID matches the handle owner.
    pub fn deregister(&mut self, params: &HandleDeregisterParams) -> HandleDeregisterResult {
        let normalized = params.handle.to_lowercase();

        if let Some(entry) = self.entries.get(&normalized)
            && entry.owner_did == params.did
        {
            self.entries.remove(&normalized);
            return HandleDeregisterResult { removed: true };
        }

        HandleDeregisterResult { removed: false }
    }

    /// Returns the number of registered handles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no handles are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_identity_target(did: &str) -> HandleTarget {
        HandleTarget::Identity {
            did: DID::from(did),
        }
    }

    fn make_context_target(context_id: &str) -> HandleTarget {
        HandleTarget::Context {
            context_id: context_id.to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
        }
    }

    // -- HandleRegisterParams serialization ----------------------------------

    #[test]
    fn handle_register_params_serialization_roundtrip() {
        let params = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: Some(HandleMetadata {
                description: Some("Alice's handle".to_owned()),
                tags: Some(vec!["user".to_owned()]),
            }),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: HandleRegisterParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, deserialized);
    }

    // -- HandleRegistry: register -------------------------------------------

    #[test]
    fn register_handle_returns_registered_status() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let params = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };

        let result = registry.register(
            &params,
            &DID::from("did:dht:zAlice"),
            &scp_primitives::SystemClock,
        );
        assert_eq!(result.status, HandleRegisterStatus::Registered);
        assert!(result.entry_id.is_some());
    }

    #[test]
    fn register_handle_returns_conflict_for_duplicate() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let alice_did = DID::from("did:dht:zAlice");
        let bob_did = DID::from("did:dht:zBob");

        let params_alice = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };

        let params_bob = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zBob"),
            metadata: None,
        };

        let result1 = registry.register(&params_alice, &alice_did, &scp_primitives::SystemClock);
        assert_eq!(result1.status, HandleRegisterStatus::Registered);

        let result2 = registry.register(&params_bob, &bob_did, &scp_primitives::SystemClock);
        assert_eq!(result2.status, HandleRegisterStatus::Conflict);
    }

    #[test]
    fn register_handle_case_insensitive() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let alice_did = DID::from("did:dht:zAlice");
        let bob_did = DID::from("did:dht:zBob");

        let params1 = HandleRegisterParams {
            handle: "Alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };
        let params2 = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zBob"),
            metadata: None,
        };

        registry.register(&params1, &alice_did, &scp_primitives::SystemClock);
        let result = registry.register(&params2, &bob_did, &scp_primitives::SystemClock);
        assert_eq!(result.status, HandleRegisterStatus::Conflict);
    }

    #[test]
    fn register_identity_handle_rejects_ownership_mismatch() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let params = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };

        let result = registry.register(
            &params,
            &DID::from("did:dht:zEve"),
            &scp_primitives::SystemClock,
        );
        assert_eq!(result.status, HandleRegisterStatus::OwnershipMismatch);
        assert!(result.entry_id.is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn register_context_handle_succeeds() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let params = HandleRegisterParams {
            handle: "recipes".to_owned(),
            target: make_context_target("a1b2c3"),
            metadata: Some(HandleMetadata {
                description: Some("Recipe collection".to_owned()),
                tags: None,
            }),
        };

        let result = registry.register(
            &params,
            &DID::from("did:dht:zAdmin"),
            &scp_primitives::SystemClock,
        );
        assert_eq!(result.status, HandleRegisterStatus::Registered);
    }

    // -- HandleRegistry: lookup ---------------------------------------------

    #[test]
    fn lookup_existing_handle_returns_entry() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let params = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };
        registry.register(
            &params,
            &DID::from("did:dht:zAlice"),
            &scp_primitives::SystemClock,
        );

        let lookup = registry.lookup(&HandleLookupParams {
            handle: "alice".to_owned(),
            type_filter: None,
        });

        assert_eq!(lookup.results.len(), 1);
        assert_eq!(lookup.results[0].handle, "alice");
        assert!(matches!(
            &lookup.results[0].target,
            HandleTarget::Identity { did } if did == "did:dht:zAlice"
        ));
    }

    #[test]
    fn lookup_nonexistent_handle_returns_empty() {
        let registry = HandleRegistry::new("ctx-cooking".to_owned());

        let lookup = registry.lookup(&HandleLookupParams {
            handle: "nonexistent".to_owned(),
            type_filter: None,
        });

        assert!(lookup.results.is_empty());
    }

    #[test]
    fn lookup_with_identity_type_filter() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());

        let params = HandleRegisterParams {
            handle: "recipes".to_owned(),
            target: make_context_target("a1b2c3"),
            metadata: None,
        };
        registry.register(
            &params,
            &DID::from("did:dht:zAdmin"),
            &scp_primitives::SystemClock,
        );

        let lookup = registry.lookup(&HandleLookupParams {
            handle: "recipes".to_owned(),
            type_filter: Some(HandleTypeFilter::Identity),
        });

        // recipes is a context handle, identity filter should exclude it.
        assert!(lookup.results.is_empty());
    }

    #[test]
    fn lookup_with_context_type_filter() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());

        let params = HandleRegisterParams {
            handle: "recipes".to_owned(),
            target: make_context_target("a1b2c3"),
            metadata: None,
        };
        registry.register(
            &params,
            &DID::from("did:dht:zAdmin"),
            &scp_primitives::SystemClock,
        );

        let lookup = registry.lookup(&HandleLookupParams {
            handle: "recipes".to_owned(),
            type_filter: Some(HandleTypeFilter::Context),
        });

        assert_eq!(lookup.results.len(), 1);
    }

    // -- HandleRegistry: deregister -----------------------------------------

    #[test]
    fn deregister_by_owner_succeeds() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let alice_did = DID::from("did:dht:zAlice");

        let params = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };
        registry.register(&params, &alice_did, &scp_primitives::SystemClock);

        let result = registry.deregister(&HandleDeregisterParams {
            handle: "alice".to_owned(),
            did: alice_did,
        });

        assert!(result.removed);
        assert!(registry.is_empty());
    }

    #[test]
    fn deregister_by_non_owner_fails() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let alice_did = DID::from("did:dht:zAlice");
        let bob_did = DID::from("did:dht:zBob");

        let params = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };
        registry.register(&params, &alice_did, &scp_primitives::SystemClock);

        let result = registry.deregister(&HandleDeregisterParams {
            handle: "alice".to_owned(),
            did: bob_did,
        });

        assert!(!result.removed);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn deregister_nonexistent_handle_returns_false() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());

        let result = registry.deregister(&HandleDeregisterParams {
            handle: "nonexistent".to_owned(),
            did: DID::from("did:dht:zAlice"),
        });

        assert!(!result.removed);
    }

    // -- HandleLookupResult serialization -----------------------------------

    #[test]
    fn handle_lookup_result_serialization_roundtrip() {
        let result = HandleLookupResult {
            results: vec![HandleEntry {
                handle: "alice".to_owned(),
                target: make_identity_target("did:dht:zAlice"),
                owner_did: DID::from("did:dht:zAlice"),
                registered_at: 1_700_000_000,
                metadata: HandleMetadata::default(),
                entry_id: "handle-1".to_owned(),
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: HandleLookupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    // -- HandleDeregisterResult serialization --------------------------------

    #[test]
    fn handle_deregister_result_serialization_roundtrip() {
        let result = HandleDeregisterResult { removed: true };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: HandleDeregisterResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    // -- HandleRegistry: entry_id uniqueness --------------------------------

    #[test]
    fn register_generates_unique_entry_ids() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());

        let r1 = registry.register(
            &HandleRegisterParams {
                handle: "alice".to_owned(),
                target: make_identity_target("did:dht:zAlice"),
                metadata: None,
            },
            &DID::from("did:dht:zAlice"),
            &scp_primitives::SystemClock,
        );

        let r2 = registry.register(
            &HandleRegisterParams {
                handle: "bob".to_owned(),
                target: make_identity_target("did:dht:zBob"),
                metadata: None,
            },
            &DID::from("did:dht:zBob"),
            &scp_primitives::SystemClock,
        );

        assert_ne!(r1.entry_id, r2.entry_id);
    }

    // -- HandleRegistry: re-register after deregister -----------------------

    #[test]
    fn re_register_after_deregister_succeeds() {
        let mut registry = HandleRegistry::new("ctx-cooking".to_owned());
        let alice_did = DID::from("did:dht:zAlice");
        let bob_did = DID::from("did:dht:zBob");

        let params = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zAlice"),
            metadata: None,
        };
        registry.register(&params, &alice_did, &scp_primitives::SystemClock);

        registry.deregister(&HandleDeregisterParams {
            handle: "alice".to_owned(),
            did: alice_did,
        });

        let params2 = HandleRegisterParams {
            handle: "alice".to_owned(),
            target: make_identity_target("did:dht:zBob"),
            metadata: None,
        };
        let result = registry.register(&params2, &bob_did, &scp_primitives::SystemClock);
        assert_eq!(result.status, HandleRegisterStatus::Registered);
    }

    // -- HandleRegistry: capacity limit -------------------------------------

    #[test]
    fn register_returns_capacity_exceeded_at_limit() {
        let owner_did = DID::from("did:dht:testowner");
        let mut registry = HandleRegistry::new("ctx-capacity".to_owned());

        for i in 0..MAX_HANDLE_ENTRIES {
            let params = HandleRegisterParams {
                handle: format!("handle_{i}"),
                target: make_context_target(&format!("ctx-{i}")),
                metadata: None,
            };
            let result = registry.register(&params, &owner_did, &scp_primitives::SystemClock);
            assert_eq!(result.status, HandleRegisterStatus::Registered);
        }

        assert_eq!(registry.len(), MAX_HANDLE_ENTRIES);

        let overflow_params = HandleRegisterParams {
            handle: "handle_overflow".to_owned(),
            target: make_context_target("ctx-overflow"),
            metadata: None,
        };
        let result = registry.register(&overflow_params, &owner_did, &scp_primitives::SystemClock);
        assert_eq!(result.status, HandleRegisterStatus::CapacityExceeded);
        assert!(result.entry_id.is_none());
        assert_eq!(registry.len(), MAX_HANDLE_ENTRIES);
    }

    #[test]
    fn register_succeeds_after_deregister_at_capacity() {
        let owner_did = DID::from("did:dht:testowner");
        let mut registry = HandleRegistry::new("ctx-capacity".to_owned());

        for i in 0..MAX_HANDLE_ENTRIES {
            let params = HandleRegisterParams {
                handle: format!("handle_{i}"),
                target: make_context_target(&format!("ctx-{i}")),
                metadata: None,
            };
            registry.register(&params, &owner_did, &scp_primitives::SystemClock);
        }

        assert_eq!(registry.len(), MAX_HANDLE_ENTRIES);

        registry.deregister(&HandleDeregisterParams {
            handle: "handle_0".to_owned(),
            did: owner_did.clone(),
        });

        assert_eq!(registry.len(), MAX_HANDLE_ENTRIES - 1);

        let new_params = HandleRegisterParams {
            handle: "handle_new".to_owned(),
            target: make_context_target("ctx-new"),
            metadata: None,
        };
        let result = registry.register(&new_params, &owner_did, &scp_primitives::SystemClock);
        assert_eq!(result.status, HandleRegisterStatus::Registered);
        assert!(result.entry_id.is_some());
    }
}
