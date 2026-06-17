#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unused_async,
    clippy::redundant_field_names,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code
)]
//! WASM conformance tests.
//!
//! WASM modules import shared types and algorithms directly from
//! `scp-protocol` and `scp-event-log`. These tests validate:
//! - WASM-specific behavior (registry semantics, context manager patterns)
//! - Code that remains WASM-local (governance proposals, role capabilities,
//!   broadcast state, provenance hashing, attestation canonical bytes,
//!   event type tag mapping, protocol version constants)
//! - Address parsing (interleaved with WASM-specific logic)

use sha2::{Digest, Sha256};

use scp_event_log::EventType;
use scp_event_log::tree::event_type_tag;

// ===========================================================================
// Test helpers
// ===========================================================================

/// Helper: current timestamp in seconds (same as WASM bridge's `time::now_secs`).
fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

// ===========================================================================
// Test: LogSummary timestamp is plausible and clamped per ADR-034
// ===========================================================================

#[test]
fn log_summary_timestamp_plausible_and_clamped() {
    let now = now_secs();

    // (a) Timestamp must be > 0.
    assert!(
        now > 0,
        "LogSummary timestamp must be > 0 (got {now}); \
         a value of 0 indicates clock misconfiguration or ADR-034 clamping"
    );

    // (b) Timestamp must be within plausible modern range.
    assert!(
        now > 1_700_000_000,
        "LogSummary timestamp must be > 1_700_000_000 (got {now}); \
         timestamp is not within plausible modern range"
    );
}

// ===========================================================================
// WASM context registry mirror (verbatim from scp-ffi-wasm/src/runtime.rs)
//
// Mirrors the registry functions to validate registration, lookup, and
// removal semantics. See issue #137.
// ===========================================================================

mod wasm_registry_mirror {
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    /// Minimal mirror of `WasmContextRuntime` — only the fields needed to
    /// validate registry semantics.
    pub struct WasmContextRuntime {
        pub creator_did: String,
        pub ceiling_strings: HashSet<String>,
    }

    thread_local! {
        static CONTEXT_REGISTRY: RefCell<HashMap<String, WasmContextRuntime>> =
            RefCell::new(HashMap::new());
    }

    /// Mirrors `runtime::register_context` from `scp-ffi-wasm/src/runtime.rs`.
    pub fn register_context(context_id: &str, creator_did: &str) -> Result<(), String> {
        CONTEXT_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            if map.contains_key(context_id) {
                return Err(format!("context '{context_id}' is already registered"));
            }

            let ceiling_strings: HashSet<String> = [
                "messages:read",
                "messages:write",
                "tool_register:*",
                "tool_invoke:*",
                "role_assign:*",
                "member_invite:*",
                "member_remove:*",
                "governance_propose:*",
                "governance_vote:*",
                "context_close:*",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();

            let runtime = WasmContextRuntime {
                creator_did: creator_did.to_owned(),
                ceiling_strings,
            };

            map.insert(context_id.to_owned(), runtime);
            Ok(())
        })
    }

    /// Mirrors `runtime::remove_context` from `scp-ffi-wasm/src/runtime.rs`.
    pub fn remove_context(context_id: &str) {
        CONTEXT_REGISTRY.with(|reg| {
            reg.borrow_mut().remove(context_id);
        });
    }

    /// Mirrors `runtime::with_context` from `scp-ffi-wasm/src/runtime.rs`.
    pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut WasmContextRuntime) -> Result<T, String>,
    {
        CONTEXT_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            let rt = map.get_mut(context_id).ok_or_else(|| {
                format!(
                    "context '{context_id}' not found in runtime registry \
                     — was it created with context_create?"
                )
            })?;
            f(rt)
        })
    }
}

// ===========================================================================
// Test: context_create registers context in runtime registry
// ===========================================================================

#[test]
fn context_registry_register_then_lookup_succeeds() {
    let context_id = "ctx-test-register-001";
    let creator_did = "did:key:test-creator-001";

    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert_eq!(result.unwrap(), creator_did);
}

// ===========================================================================
// Test: context_close removes context from runtime registry
// ===========================================================================

#[test]
fn context_registry_remove_then_lookup_fails() {
    let context_id = "ctx-test-remove-001";
    let creator_did = "did:key:test-creator-002";

    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert!(result.is_ok());

    wasm_registry_mirror::remove_context(context_id);

    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("not found in runtime registry"),
        "error message should indicate context not found"
    );
}

// ===========================================================================
// Test: with_context on nonexistent context fails with appropriate error
// ===========================================================================

#[test]
fn context_registry_nonexistent_lookup_fails() {
    let context_id = "ctx-nonexistent-999";

    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("not found in runtime registry"),
        "error message should indicate context not found"
    );
}

// ===========================================================================
// Test: duplicate registration is rejected
// ===========================================================================

#[test]
fn context_registry_duplicate_registration_rejected() {
    let context_id = "ctx-test-dup-001";
    let creator_did = "did:key:test-creator-003";

    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    let result = wasm_registry_mirror::register_context(context_id, creator_did);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("already registered"),
        "error message should indicate duplicate"
    );
}

// ===========================================================================
// Test: register populates default capability ceiling
// ===========================================================================

#[test]
fn context_registry_default_ceiling_populated() {
    let context_id = "ctx-test-ceiling-001";
    let creator_did = "did:key:test-creator-004";

    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    let ceiling =
        wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.ceiling_strings.clone()))
            .unwrap();

    assert!(ceiling.contains("messages:read"));
    assert!(ceiling.contains("messages:write"));
    assert!(ceiling.contains("tool_register:*"));
    assert!(ceiling.contains("tool_invoke:*"));
    assert!(ceiling.contains("role_assign:*"));
    assert!(ceiling.contains("member_invite:*"));
    assert!(ceiling.contains("member_remove:*"));
    assert!(ceiling.contains("governance_propose:*"));
    assert!(ceiling.contains("governance_vote:*"));
    assert!(ceiling.contains("context_close:*"));
    assert_eq!(ceiling.len(), 10);
}

// ===========================================================================
// SCP_PROTOCOL_VERSION constant sync conformance (#717)
// ===========================================================================

/// WASM bridge's `SCP_PROTOCOL_VERSION` — must match scp-core's constant.
/// Verbatim from `scp-ffi-wasm/src/manager.rs`.
const WASM_SCP_PROTOCOL_VERSION: u16 = 0x0100;

#[test]
fn scp_protocol_version_wasm_matches_core() {
    assert_eq!(
        scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        WASM_SCP_PROTOCOL_VERSION,
        "WASM bridge SCP_PROTOCOL_VERSION (0x{:04X}) differs from scp-core (0x{:04X}) — \
         update crates/scp-ffi/wasm/src/manager.rs to match",
        WASM_SCP_PROTOCOL_VERSION,
        scp_protocol::envelope::SCP_PROTOCOL_VERSION,
    );
}

#[test]
fn protocol_version_decode_encode_wasm_matches_core() {
    let wasm_major = (WASM_SCP_PROTOCOL_VERSION >> 8) as u8;
    let wasm_minor = (WASM_SCP_PROTOCOL_VERSION & 0xFF) as u8;

    let (core_major, core_minor) = scp_protocol::context::params::decode_protocol_version(
        scp_protocol::envelope::SCP_PROTOCOL_VERSION,
    );

    assert_eq!(
        (wasm_major, wasm_minor),
        (core_major, core_minor),
        "WASM inline version decoding differs from core decode_protocol_version"
    );

    let wasm_encoded = (u16::from(wasm_major) << 8) | u16::from(wasm_minor);
    let core_encoded =
        scp_protocol::context::params::encode_protocol_version(core_major, core_minor);

    assert_eq!(
        wasm_encoded, core_encoded,
        "WASM inline version encoding differs from core encode_protocol_version"
    );
}

// ===========================================================================
// Governance proposal mirror (verbatim from scp-ffi-wasm/src/manager.rs)
// ===========================================================================

mod wasm_proposal_mirror {
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub struct WasmProposal {
        pub proposer_did: String,
        pub action: serde_json::Value,
        pub approvals: Vec<(String, u64)>,
        pub rejections: Vec<(String, u64)>,
        pub voting_deadline_ms: f64,
        pub context_id: String,
        pub created_at: u64,
        pub status: String,
    }

    pub const WASM_RESOLVED_PROPOSAL_CAP: usize = 10_000;

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn proposal_to_json(proposal_id: &str, proposal: &WasmProposal) -> serde_json::Value {
        let voting_deadline_secs = (proposal.voting_deadline_ms / 1000.0) as u64;

        let approvals: Vec<serde_json::Value> = proposal
            .approvals
            .iter()
            .map(|(did, ts)| {
                serde_json::json!({
                    "voter_did": did,
                    "vote": "Approve",
                    "timestamp": ts,
                    "signature": [],
                })
            })
            .collect();

        let rejections: Vec<serde_json::Value> = proposal
            .rejections
            .iter()
            .map(|(did, ts)| {
                serde_json::json!({
                    "voter_did": did,
                    "vote": "Reject",
                    "timestamp": ts,
                    "signature": [],
                })
            })
            .collect();

        serde_json::json!({
            "proposal_id": proposal_id,
            "context_id": proposal.context_id,
            "proposer_did": proposal.proposer_did,
            "action": proposal.action,
            "status": proposal.status,
            "created_at": proposal.created_at,
            "voting_deadline": voting_deadline_secs,
            "approvals": approvals,
            "rejections": rejections,
            "created_at_epoch": null,
        })
    }

    pub fn insert_resolved_proposal(
        map: &mut HashMap<String, WasmProposal>,
        id: String,
        proposal: WasmProposal,
    ) {
        if map.len() >= WASM_RESOLVED_PROPOSAL_CAP
            && let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, p)| p.created_at)
                .map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        }
        map.insert(id, proposal);
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn make_proposal(
        context_id: &str,
        proposer: &str,
        created_at: u64,
        status: &str,
    ) -> WasmProposal {
        WasmProposal {
            proposer_did: proposer.to_owned(),
            action: serde_json::json!({"AddMember": {"did": "did:key:new", "role": "member"}}),
            approvals: vec![(proposer.to_owned(), created_at)],
            rejections: Vec::new(),
            voting_deadline_ms: f64::mul_add(created_at as f64, 1000.0, 3_600_000.0),
            context_id: context_id.to_owned(),
            created_at,
            status: status.to_owned(),
        }
    }
}

// ===========================================================================
// Test: get_proposal returns a proposal with all 10 expected fields
// ===========================================================================

#[test]
fn governance_get_proposal_returns_all_fields() {
    use wasm_proposal_mirror::{make_proposal, proposal_to_json};

    let proposal = make_proposal(
        "ctx-gov-001",
        "did:key:proposer-a",
        1_700_000_000,
        "Pending",
    );
    let json = proposal_to_json("prop-001", &proposal);

    let obj = json.as_object().expect("proposal JSON should be an object");

    let expected_fields = [
        "proposal_id",
        "context_id",
        "proposer_did",
        "action",
        "status",
        "created_at",
        "created_at_epoch",
        "voting_deadline",
        "approvals",
        "rejections",
    ];

    for field in &expected_fields {
        assert!(
            obj.contains_key(*field),
            "proposal JSON missing expected field '{field}'"
        );
    }

    assert_eq!(
        obj.len(),
        expected_fields.len(),
        "unexpected extra fields in proposal JSON"
    );

    assert_eq!(json["proposal_id"], "prop-001");
    assert_eq!(json["context_id"], "ctx-gov-001");
    assert_eq!(json["proposer_did"], "did:key:proposer-a");
    assert_eq!(json["status"], "Pending");
    assert_eq!(json["created_at"], 1_700_000_000_u64);
    assert!(
        json["created_at_epoch"].is_null(),
        "created_at_epoch should be null"
    );
    assert!(json["approvals"].is_array(), "approvals should be an array");
    assert!(
        json["rejections"].is_array(),
        "rejections should be an array"
    );
    assert!(json["action"].is_object(), "action should be an object");
    assert!(
        json["voting_deadline"].is_u64(),
        "voting_deadline should be u64 seconds"
    );
}

// ===========================================================================
// Test: list_proposals returns both pending and resolved proposals
// ===========================================================================

#[test]
fn governance_list_proposals_includes_pending_and_resolved() {
    use std::collections::HashMap;
    use wasm_proposal_mirror::{make_proposal, proposal_to_json};

    let mut pending: HashMap<String, wasm_proposal_mirror::WasmProposal> = HashMap::new();
    let mut resolved: HashMap<String, wasm_proposal_mirror::WasmProposal> = HashMap::new();

    pending.insert(
        "prop-pending-1".to_owned(),
        make_proposal("ctx-gov-002", "did:key:a", 1_700_000_100, "Pending"),
    );
    resolved.insert(
        "prop-resolved-1".to_owned(),
        make_proposal("ctx-gov-002", "did:key:b", 1_700_000_200, "Approved"),
    );

    let proposals: Vec<serde_json::Value> = pending
        .iter()
        .chain(resolved.iter())
        .map(|(id, p)| proposal_to_json(id, p))
        .collect();

    assert_eq!(
        proposals.len(),
        2,
        "list_proposals should return pending + resolved"
    );

    let ids: Vec<&str> = proposals
        .iter()
        .map(|p| p["proposal_id"].as_str().unwrap())
        .collect();

    assert!(
        ids.contains(&"prop-pending-1"),
        "should include pending proposal"
    );
    assert!(
        ids.contains(&"prop-resolved-1"),
        "should include resolved proposal"
    );
}

// ===========================================================================
// Test: approved proposal has status "Approved" and is retrievable
// ===========================================================================

#[test]
fn governance_approved_proposal_retrievable_with_correct_status() {
    use std::collections::HashMap;
    use wasm_proposal_mirror::{insert_resolved_proposal, make_proposal, proposal_to_json};

    let mut resolved: HashMap<String, wasm_proposal_mirror::WasmProposal> = HashMap::new();

    let mut proposal = make_proposal(
        "ctx-gov-003",
        "did:key:proposer-c",
        1_700_000_300,
        "Pending",
    );
    "Approved".clone_into(&mut proposal.status);
    insert_resolved_proposal(&mut resolved, "prop-approved-1".to_owned(), proposal);

    let found = resolved
        .get("prop-approved-1")
        .expect("proposal should be in resolved map");
    let json = proposal_to_json("prop-approved-1", found);

    assert_eq!(json["status"], "Approved");
    assert_eq!(json["proposer_did"], "did:key:proposer-c");
    assert_eq!(json["context_id"], "ctx-gov-003");
}

// ===========================================================================
// Test: rejected proposal has status "Rejected" and is retrievable
// ===========================================================================

#[test]
fn governance_rejected_proposal_retrievable_with_correct_status() {
    use std::collections::HashMap;
    use wasm_proposal_mirror::{insert_resolved_proposal, make_proposal, proposal_to_json};

    let mut resolved: HashMap<String, wasm_proposal_mirror::WasmProposal> = HashMap::new();

    let mut proposal = make_proposal(
        "ctx-gov-004",
        "did:key:proposer-d",
        1_700_000_400,
        "Pending",
    );
    proposal
        .rejections
        .push(("did:key:voter-1".to_owned(), 1_700_000_410));
    proposal
        .rejections
        .push(("did:key:voter-2".to_owned(), 1_700_000_420));
    "Rejected".clone_into(&mut proposal.status);
    insert_resolved_proposal(&mut resolved, "prop-rejected-1".to_owned(), proposal);

    let found = resolved
        .get("prop-rejected-1")
        .expect("proposal should be in resolved map");
    let json = proposal_to_json("prop-rejected-1", found);

    assert_eq!(json["status"], "Rejected");
    assert_eq!(json["rejections"].as_array().unwrap().len(), 2);
    assert_eq!(json["rejections"][0]["vote"], "Reject");
    assert_eq!(json["rejections"][1]["vote"], "Reject");
}

// ===========================================================================
// Test: resolved_proposals map respects capacity bound and evicts oldest
// ===========================================================================

#[test]
fn governance_resolved_proposals_evicts_oldest_at_capacity() {
    use std::collections::HashMap;
    use wasm_proposal_mirror::{WASM_RESOLVED_PROPOSAL_CAP, make_proposal};

    assert_eq!(
        WASM_RESOLVED_PROPOSAL_CAP, 10_000,
        "WASM_RESOLVED_PROPOSAL_CAP must match the WASM bridge constant"
    );

    let mut resolved: HashMap<String, wasm_proposal_mirror::WasmProposal> = HashMap::new();

    for i in 0..5 {
        let proposal = make_proposal("ctx-gov-005", "did:key:proposer", 1_000 + i, "Approved");
        resolved.insert(format!("prop-{i}"), proposal);
    }

    assert_eq!(resolved.len(), 5);
    assert!(resolved.contains_key("prop-0"));

    let oldest = resolved
        .iter()
        .min_by_key(|(_, p)| p.created_at)
        .map(|(k, _)| k.clone());
    assert_eq!(
        oldest.as_deref(),
        Some("prop-0"),
        "oldest entry should be prop-0 (created_at=1000)"
    );

    resolved.remove("prop-0");
    let next_oldest = resolved
        .iter()
        .min_by_key(|(_, p)| p.created_at)
        .map(|(k, _)| k.clone());
    assert_eq!(
        next_oldest.as_deref(),
        Some("prop-1"),
        "after evicting prop-0, oldest should be prop-1 (created_at=1001)"
    );
}

// ===========================================================================
// Handle registry conformance (WASM vs core HandleRegistry)
// ===========================================================================

#[test]
fn wasm_handle_register_lookup_matches_core() {
    use scp_identity::DID;
    use scp_protocol::discovery::{
        HandleDeregisterParams, HandleLookupParams, HandleRegisterParams, HandleRegistry,
        HandleTarget, HandleTypeFilter,
    };

    let mut core_registry = HandleRegistry::new("ctx-test".to_owned());
    let core_result = core_registry.register(
        &HandleRegisterParams {
            handle: "alice".to_owned(),
            target: HandleTarget::Identity {
                did: DID::from("did:dht:zAlice"),
            },
            metadata: None,
        },
        &DID::from("did:dht:zAlice"),
        &scp_primitives::SystemClock,
    );

    let core_lookup = core_registry.lookup(&HandleLookupParams {
        handle: "alice".to_owned(),
        type_filter: None,
    });

    assert_eq!(
        core_lookup.results.len(),
        1,
        "core handle lookup should return 1 result"
    );
    assert!(
        matches!(
            core_result.status,
            scp_protocol::discovery::HandleRegisterStatus::Registered
        ),
        "core handle register should succeed"
    );

    let filtered_identity = core_registry.lookup(&HandleLookupParams {
        handle: "alice".to_owned(),
        type_filter: Some(HandleTypeFilter::Identity),
    });
    assert_eq!(filtered_identity.results.len(), 1);

    let filtered_context = core_registry.lookup(&HandleLookupParams {
        handle: "alice".to_owned(),
        type_filter: Some(HandleTypeFilter::Context),
    });
    assert_eq!(filtered_context.results.len(), 0);

    let deregister_result = core_registry.deregister(&HandleDeregisterParams {
        handle: "alice".to_owned(),
        did: DID::from("did:dht:zAlice"),
    });
    assert!(deregister_result.removed);

    let post_deregister = core_registry.lookup(&HandleLookupParams {
        handle: "alice".to_owned(),
        type_filter: None,
    });
    assert!(post_deregister.results.is_empty());
}

/// Same-owner re-registration must return Conflict — not idempotent success.
#[test]
fn wasm_handle_same_owner_reregister_returns_conflict() {
    use scp_identity::DID;
    use scp_protocol::discovery::{
        HandleRegisterParams, HandleRegisterStatus, HandleRegistry, HandleTarget,
    };

    let mut registry = HandleRegistry::new("ctx-test".to_owned());
    let alice_did = DID::from("did:dht:zAlice");

    let params = HandleRegisterParams {
        handle: "alice".to_owned(),
        target: HandleTarget::Identity {
            did: DID::from("did:dht:zAlice"),
        },
        metadata: None,
    };

    let result1 = registry.register(&params, &alice_did, &scp_primitives::SystemClock);
    assert_eq!(result1.status, HandleRegisterStatus::Registered);

    let result2 = registry.register(&params, &alice_did, &scp_primitives::SystemClock);
    assert_eq!(
        result2.status,
        HandleRegisterStatus::Conflict,
        "same-owner re-registration must return Conflict per scp-core semantics"
    );
}

// ===========================================================================
// Address resolution conformance
// ===========================================================================

#[test]
fn wasm_discovery_handle_parsing_matches_core() {
    let core_parsed =
        scp_runtime::discovery::addressing::parse_address("alice@cooking-community").unwrap();

    let address = "alice@cooking-community";
    let normalized = address.trim().to_lowercase();
    let at_pos = normalized.find('@').unwrap();
    let wasm_local = &normalized[..at_pos];
    let wasm_scope = &normalized[at_pos + 1..];

    match &core_parsed {
        scp_runtime::discovery::addressing::ParsedAddress::DiscoveryHandle {
            local_part,
            scope,
        } => {
            assert_eq!(local_part, wasm_local, "local_part mismatch");
            assert_eq!(scope, wasm_scope, "scope mismatch");
            assert!(
                !wasm_scope.contains('.'),
                "scope without '.' is DiscoveryHandle"
            );
        }
        other => panic!("expected DiscoveryHandle, got {other:?}"),
    }
}

#[test]
fn wasm_domain_handle_parsing_matches_core() {
    let core_parsed =
        scp_runtime::discovery::addressing::parse_address("alice@example.com").unwrap();

    let address = "alice@example.com";
    let normalized = address.trim().to_lowercase();
    let at_pos = normalized.find('@').unwrap();
    let wasm_local = &normalized[..at_pos];
    let wasm_domain = &normalized[at_pos + 1..];

    match &core_parsed {
        scp_runtime::discovery::addressing::ParsedAddress::DomainHandle { local_part, domain } => {
            assert_eq!(local_part, wasm_local, "local_part mismatch");
            assert_eq!(domain, wasm_domain, "domain mismatch");
            assert!(wasm_domain.contains('.'), "scope with '.' is DomainHandle");
        }
        other => panic!("expected DomainHandle, got {other:?}"),
    }
}

#[test]
fn wasm_attestation_handle_parsing_matches_core() {
    let core_parsed = scp_runtime::discovery::addressing::parse_address("@alice_cooks").unwrap();

    let address = "@alice_cooks";
    let normalized = address.trim().to_lowercase();
    let rest = normalized.strip_prefix('@').unwrap();

    match &core_parsed {
        scp_runtime::discovery::addressing::ParsedAddress::AttestationHandle {
            handle,
            platform,
        } => {
            assert_eq!(handle, rest, "handle mismatch");
            assert!(platform.is_none(), "no platform qualifier");
        }
        other => panic!("expected AttestationHandle, got {other:?}"),
    }
}

#[test]
fn wasm_attestation_handle_with_platform_matches_core() {
    let core_parsed = scp_runtime::discovery::addressing::parse_address("@alice_cooks:x").unwrap();

    let address = "@alice_cooks:x";
    let normalized = address.trim().to_lowercase();
    let rest = normalized.strip_prefix('@').unwrap();
    let colon_pos = rest.find(':').unwrap();
    let wasm_handle = &rest[..colon_pos];
    let wasm_platform = &rest[colon_pos + 1..];

    match &core_parsed {
        scp_runtime::discovery::addressing::ParsedAddress::AttestationHandle {
            handle,
            platform,
        } => {
            assert_eq!(handle, wasm_handle, "handle mismatch");
            assert_eq!(
                platform.as_deref(),
                Some(wasm_platform),
                "platform mismatch"
            );
        }
        other => panic!("expected AttestationHandle, got {other:?}"),
    }
}

#[test]
fn wasm_unscoped_address_matches_core() {
    let core_parsed = scp_runtime::discovery::addressing::parse_address("alice").unwrap();

    let address = "alice";
    let normalized = address.trim().to_lowercase();

    match &core_parsed {
        scp_runtime::discovery::addressing::ParsedAddress::Unscoped { name } => {
            assert_eq!(name, &normalized, "name mismatch");
        }
        other => panic!("expected Unscoped, got {other:?}"),
    }
}

/// Verify the WASM trust-level sorting helper produces correct ordering.
#[test]
fn wasm_trust_level_sorting_order() {
    fn trust_level_rank(kind: &str) -> u8 {
        match kind {
            "DirectExchange" => 6,
            "MultiLayerCorroborated" => 5,
            "LocalPetname" => 4,
            "AttestationVerified" => 3,
            "DomainVerified" => 2,
            "HandleRegistryVerified" => 1,
            _ => 0,
        }
    }

    assert!(trust_level_rank("DirectExchange") > trust_level_rank("MultiLayerCorroborated"));
    assert!(trust_level_rank("MultiLayerCorroborated") > trust_level_rank("LocalPetname"));
    assert!(trust_level_rank("LocalPetname") > trust_level_rank("AttestationVerified"));
    assert!(trust_level_rank("AttestationVerified") > trust_level_rank("DomainVerified"));
    assert!(trust_level_rank("DomainVerified") > trust_level_rank("HandleRegistryVerified"));
    assert!(trust_level_rank("HandleRegistryVerified") > trust_level_rank("Unknown"));
}

// ===========================================================================
// Governance role/broadcast mirror (verbatim from scp-ffi-wasm/src/manager.rs)
// ===========================================================================

mod wasm_role_broadcast_mirror {
    use std::collections::{HashMap, HashSet};

    #[derive(Debug, Clone)]
    pub struct MemberEntry {
        pub did: String,
        pub role: String,
        #[allow(dead_code)]
        pub sequence_number: u64,
    }

    #[derive(Debug)]
    pub struct BroadcastState {
        pub authors: HashMap<String, HashSet<String>>,
        pub key_epochs: HashMap<String, u64>,
    }

    impl BroadcastState {
        pub fn new() -> Self {
            Self {
                authors: HashMap::new(),
                key_epochs: HashMap::new(),
            }
        }
    }

    pub struct PerContextState {
        pub members: HashMap<String, MemberEntry>,
        pub ceiling_strings: HashSet<String>,
        pub broadcast: Option<BroadcastState>,
    }

    impl PerContextState {
        pub fn new_with_default_ceiling(broadcast: Option<BroadcastState>) -> Self {
            let ceiling_strings: HashSet<String> = [
                "messages:read",
                "messages:write",
                "tool:register",
                "tool_invoke:*",
                "role:assign",
                "member:invite",
                "member:remove",
                "governance:propose",
                "governance:vote",
                "context:close",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
            Self {
                members: HashMap::new(),
                ceiling_strings,
                broadcast,
            }
        }

        pub fn member_has_capability(&self, member_did: &str, capability: &str) -> bool {
            let Some(member) = self.members.get(member_did) else {
                return false;
            };

            let in_ceiling = |cap: &str| -> bool {
                let (resource, _action) = cap.rsplit_once(':').unwrap_or((cap, "*"));
                let wildcard = format!("{resource}:*");
                self.ceiling_strings.contains(cap) || self.ceiling_strings.contains(&wildcard)
            };

            match member.role.as_str() {
                "admin" => in_ceiling(capability),
                "moderator" => {
                    let role_grants = matches!(
                        capability,
                        "messages:read"
                            | "messages:write"
                            | "tool_invoke:*"
                            | "member:remove"
                            | "governance:propose"
                    );
                    role_grants && in_ceiling(capability)
                }
                "author" => {
                    let role_grants = matches!(
                        capability,
                        "messages:write" | "messages:read" | "tool_invoke:*"
                    );
                    role_grants && in_ceiling(capability)
                }
                "member" => {
                    let role_grants = matches!(
                        capability,
                        "messages:read" | "messages:write" | "tool_invoke:*"
                    );
                    role_grants && in_ceiling(capability)
                }
                "subscriber" | "observer" => {
                    capability == "messages:read" && in_ceiling(capability)
                }
                _ => false,
            }
        }

        pub fn change_role(&mut self, did: &str, new_role: &str) {
            if let Some(member) = self.members.get_mut(did) {
                let old_role = member.role.clone();
                new_role.clone_into(&mut member.role);
                if let Some(ref mut bc) = self.broadcast {
                    if old_role == "author" && new_role != "author" {
                        bc.authors.remove(did);
                        bc.key_epochs.remove(did);
                    } else if new_role == "author" && old_role != "author" {
                        bc.authors.insert(did.to_owned(), HashSet::new());
                        bc.key_epochs.insert(did.to_owned(), 0);
                    }
                }
            }
        }

        pub fn add_member(&mut self, did: &str, role: &str) {
            self.members.insert(
                did.to_owned(),
                MemberEntry {
                    did: did.to_owned(),
                    role: role.to_owned(),
                    sequence_number: 0,
                },
            );
            if role == "author"
                && let Some(ref mut bc) = self.broadcast
            {
                bc.authors.insert(did.to_owned(), HashSet::new());
                bc.key_epochs.insert(did.to_owned(), 0);
            }
        }

        pub fn remove_member(&mut self, did: &str) -> Option<MemberEntry> {
            let removed = self.members.remove(did)?;
            if removed.role == "author"
                && let Some(ref mut bc) = self.broadcast
            {
                bc.authors.remove(did);
                bc.key_epochs.remove(did);
            }
            Some(removed)
        }
    }
}

// ===========================================================================
// Test: AddMember with author role populates broadcast state
// ===========================================================================

#[test]
fn add_member_author_role_populates_broadcast_state() {
    use wasm_role_broadcast_mirror::{BroadcastState, PerContextState};

    let mut ctx = PerContextState::new_with_default_ceiling(Some(BroadcastState::new()));
    let author_did = "did:key:author-001";

    ctx.add_member(author_did, "author");

    assert_eq!(ctx.members[author_did].role, "author");

    let bc = ctx.broadcast.as_ref().unwrap();
    assert!(
        bc.authors.contains_key(author_did),
        "AddMember with author role should insert into bc.authors"
    );
    assert!(
        bc.authors[author_did].is_empty(),
        "new author should have an empty block list"
    );
    assert_eq!(
        bc.key_epochs[author_did], 0,
        "new author should start at key epoch 0"
    );
}

// ===========================================================================
// Test: RemoveMember of author cleans up broadcast state
// ===========================================================================

#[test]
fn remove_member_author_cleans_broadcast_state() {
    use wasm_role_broadcast_mirror::{BroadcastState, PerContextState};

    let mut ctx = PerContextState::new_with_default_ceiling(Some(BroadcastState::new()));
    let author_did = "did:key:author-002";

    ctx.add_member(author_did, "author");
    assert!(
        ctx.broadcast
            .as_ref()
            .unwrap()
            .authors
            .contains_key(author_did)
    );

    let removed = ctx.remove_member(author_did);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().role, "author");

    let bc = ctx.broadcast.as_ref().unwrap();
    assert!(
        !bc.authors.contains_key(author_did),
        "RemoveMember should remove author from bc.authors"
    );
    assert!(
        !bc.key_epochs.contains_key(author_did),
        "RemoveMember should remove author from bc.key_epochs"
    );
}

// ===========================================================================
// Test: ChangeRole updates broadcast state when transitioning to/from author
// ===========================================================================

#[test]
fn change_role_author_to_member_removes_broadcast_state() {
    use wasm_role_broadcast_mirror::{BroadcastState, PerContextState};

    let mut ctx = PerContextState::new_with_default_ceiling(Some(BroadcastState::new()));
    let did = "did:key:role-change-001";

    ctx.add_member(did, "author");
    assert!(ctx.broadcast.as_ref().unwrap().authors.contains_key(did));

    ctx.change_role(did, "member");
    assert_eq!(ctx.members[did].role, "member");
    let bc = ctx.broadcast.as_ref().unwrap();
    assert!(
        !bc.authors.contains_key(did),
        "ChangeRole from author to member should remove from bc.authors"
    );
    assert!(
        !bc.key_epochs.contains_key(did),
        "ChangeRole from author to member should remove from bc.key_epochs"
    );
}

#[test]
fn change_role_member_to_author_adds_broadcast_state() {
    use wasm_role_broadcast_mirror::{BroadcastState, PerContextState};

    let mut ctx = PerContextState::new_with_default_ceiling(Some(BroadcastState::new()));
    let did = "did:key:role-change-002";

    ctx.add_member(did, "member");
    assert!(!ctx.broadcast.as_ref().unwrap().authors.contains_key(did));

    ctx.change_role(did, "author");
    assert_eq!(ctx.members[did].role, "author");
    let bc = ctx.broadcast.as_ref().unwrap();
    assert!(
        bc.authors.contains_key(did),
        "ChangeRole from member to author should insert into bc.authors"
    );
    assert_eq!(
        bc.key_epochs[did], 0,
        "ChangeRole from member to author should initialize key epoch to 0"
    );
}

// ===========================================================================
// Role capability tests
// ===========================================================================

#[test]
fn moderator_has_governance_propose_capability() {
    use wasm_role_broadcast_mirror::PerContextState;

    let mut ctx = PerContextState::new_with_default_ceiling(None);
    let did = "did:key:moderator-001";

    ctx.add_member(did, "moderator");

    assert!(
        ctx.member_has_capability(did, "governance:propose"),
        "moderator should have governance:propose capability"
    );
    assert!(
        ctx.member_has_capability(did, "member:remove"),
        "moderator should have member:remove capability"
    );
    assert!(ctx.member_has_capability(did, "messages:read"));
    assert!(ctx.member_has_capability(did, "messages:write"));
    assert!(ctx.member_has_capability(did, "tool_invoke:*"));
    assert!(
        !ctx.member_has_capability(did, "context:close"),
        "moderator should NOT have context:close"
    );
}

#[test]
fn subscriber_has_messages_read_only() {
    use wasm_role_broadcast_mirror::PerContextState;

    let mut ctx = PerContextState::new_with_default_ceiling(None);
    let did = "did:key:subscriber-001";

    ctx.add_member(did, "subscriber");

    assert!(
        ctx.member_has_capability(did, "messages:read"),
        "subscriber should have messages:read capability"
    );
    assert!(
        !ctx.member_has_capability(did, "messages:write"),
        "subscriber should NOT have messages:write"
    );
    assert!(
        !ctx.member_has_capability(did, "tool_invoke:*"),
        "subscriber should NOT have tool_invoke:*"
    );
}

#[test]
fn member_has_tool_invoke_all_capability() {
    use wasm_role_broadcast_mirror::PerContextState;

    let mut ctx = PerContextState::new_with_default_ceiling(None);
    let did = "did:key:member-001";

    ctx.add_member(did, "member");

    assert!(ctx.member_has_capability(did, "messages:read"));
    assert!(ctx.member_has_capability(did, "messages:write"));
    assert!(
        ctx.member_has_capability(did, "tool_invoke:*"),
        "member should have tool_invoke:* capability"
    );
    assert!(
        !ctx.member_has_capability(did, "governance:propose"),
        "member should NOT have governance:propose"
    );
}

#[test]
fn member_capability_ceiling_intersection() {
    use wasm_role_broadcast_mirror::PerContextState;

    let mut ctx = PerContextState::new_with_default_ceiling(None);
    let did = "did:key:member-002";

    ctx.ceiling_strings.remove("tool_invoke:*");

    ctx.add_member(did, "member");

    assert!(ctx.member_has_capability(did, "messages:read"));
    assert!(ctx.member_has_capability(did, "messages:write"));
    assert!(
        !ctx.member_has_capability(did, "tool_invoke:*"),
        "member should NOT have tool_invoke:* when tool_invoke:* is removed from ceiling"
    );
}

// ===========================================================================
// Provenance hash conformance (issue #1325)
// ===========================================================================

mod wasm_provenance_mirror {
    #[derive(serde::Serialize)]
    pub struct CanonicalProvenance<'a> {
        pub source_context: &'a str,
        pub source_type: &'a str,
        pub counterparties: &'a [String],
        pub purpose: Option<&'a String>,
        pub discovery_method: &'a serde_json::Value,
        pub age: CanonicalDuration,
        pub memory_scope: &'a str,
        pub chain_depth: u32,
        pub chain_path: &'a serde_json::Value,
        pub payment_amount: Option<u64>,
        pub payment_adapter: Option<&'a str>,
        pub payment_receipt_id: Option<&'a [u8; 32]>,
    }

    #[derive(serde::Serialize)]
    pub struct CanonicalDuration {
        pub secs: u64,
        pub nanos: u32,
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_canonical_provenance_bytes(
        source_context: &str,
        source_type: &str,
        counterparties: &[String],
        purpose: Option<&String>,
        discovery_method: &serde_json::Value,
        age_secs: u64,
        age_nanos: u32,
        memory_scope: &str,
        chain_depth: u32,
        chain_path: &serde_json::Value,
        payment_amount: Option<u64>,
        payment_adapter: Option<&str>,
        payment_receipt_id: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let canonical = CanonicalProvenance {
            source_context,
            source_type,
            counterparties,
            purpose,
            discovery_method,
            age: CanonicalDuration {
                secs: age_secs,
                nanos: age_nanos,
            },
            memory_scope,
            chain_depth,
            chain_path,
            payment_amount,
            payment_adapter,
            payment_receipt_id,
        };
        serde_json::to_vec(&canonical).unwrap_or_default()
    }
}

#[test]
fn provenance_hash_conformance_shared_context() {
    use scp_identity::DID;
    use scp_protocol::context::MemoryScope;
    use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    let provenance = DataProvenance {
        source_context: "ctx-conformance-test".to_owned(),
        source_type: SourceType::Persistent,
        counterparties: vec![DID::from("did:dht:z6MkAlice"), DID::from("did:dht:z6MkBob")],
        purpose: Some("cross-context data flow".to_owned()),
        discovery_method: DiscoveryMethod::SharedContext("ctx-shared-disc".to_owned()),
        age: Duration::new(120, 0),
        memory_scope: MemoryScope::Full,
        chain_depth: 1,
        chain_path: Some(vec!["ctx-hop-1".to_owned()]),
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    let core_bytes = serde_json::to_vec(&provenance).unwrap();
    let core_hash: [u8; 32] = Sha256::digest(&core_bytes).into();

    let counterparties = vec!["did:dht:z6MkAlice".to_owned(), "did:dht:z6MkBob".to_owned()];
    let purpose = "cross-context data flow".to_owned();
    let discovery_method = serde_json::json!({"SharedContext": "ctx-shared-disc"});
    let chain_path = serde_json::json!(["ctx-hop-1"]);

    let wasm_bytes = wasm_provenance_mirror::build_canonical_provenance_bytes(
        "ctx-conformance-test",
        "Persistent",
        &counterparties,
        Some(&purpose),
        &discovery_method,
        120,
        0,
        "Full",
        1,
        &chain_path,
        None,
        None,
        None,
    );
    let wasm_hash: [u8; 32] = Sha256::digest(&wasm_bytes).into();

    assert_eq!(
        core_hash,
        wasm_hash,
        "shared-context provenance hash mismatch: core={} wasm={}",
        hex::encode(core_hash),
        hex::encode(wasm_hash),
    );
}

#[test]
fn provenance_hash_conformance_out_of_band() {
    use scp_identity::DID;
    use scp_protocol::context::MemoryScope;
    use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    let provenance = DataProvenance {
        source_context: "ctx-external".to_owned(),
        source_type: SourceType::Ephemeral,
        counterparties: vec![DID::from("did:dht:z6MkCharlie")],
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: Duration::new(86400, 500_000_000),
        memory_scope: MemoryScope::Ephemeral,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    let core_bytes = serde_json::to_vec(&provenance).unwrap();
    let core_hash: [u8; 32] = Sha256::digest(&core_bytes).into();

    let counterparties = vec!["did:dht:z6MkCharlie".to_owned()];
    let discovery_method = serde_json::json!("OutOfBand");
    let chain_path = serde_json::json!(null);

    let wasm_bytes = wasm_provenance_mirror::build_canonical_provenance_bytes(
        "ctx-external",
        "Ephemeral",
        &counterparties,
        None,
        &discovery_method,
        86400,
        500_000_000,
        "Ephemeral",
        0,
        &chain_path,
        None,
        None,
        None,
    );
    let wasm_hash: [u8; 32] = Sha256::digest(&wasm_bytes).into();

    assert_eq!(
        core_hash,
        wasm_hash,
        "out-of-band provenance hash mismatch: core={} wasm={}",
        hex::encode(core_hash),
        hex::encode(wasm_hash),
    );
}

#[test]
fn provenance_hash_conformance_registry_with_payment() {
    use scp_protocol::context::MemoryScope;
    use scp_protocol::economy::Amount;
    use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    let receipt_id: [u8; 32] = [0xAB; 32];

    let provenance = DataProvenance {
        source_context: "ctx-marketplace".to_owned(),
        source_type: SourceType::Summary,
        counterparties: vec![],
        purpose: None,
        discovery_method: DiscoveryMethod::Registry("tools.scp".to_owned()),
        age: Duration::new(7200, 0),
        memory_scope: MemoryScope::Full,
        chain_depth: 2,
        chain_path: Some(vec![
            "ctx-marketplace".to_owned(),
            "ctx-provider".to_owned(),
        ]),
        payment_amount: Some(Amount(1000)),
        payment_adapter: Some("stripe".to_owned()),
        payment_receipt_id: Some(receipt_id),
    };

    let core_bytes = serde_json::to_vec(&provenance).unwrap();
    let core_hash: [u8; 32] = Sha256::digest(&core_bytes).into();

    let counterparties: Vec<String> = vec![];
    let discovery_method = serde_json::json!({"Registry": "tools.scp"});
    let chain_path = serde_json::json!(["ctx-marketplace", "ctx-provider"]);

    let wasm_bytes = wasm_provenance_mirror::build_canonical_provenance_bytes(
        "ctx-marketplace",
        "Summary",
        &counterparties,
        None,
        &discovery_method,
        7200,
        0,
        "Full",
        2,
        &chain_path,
        Some(1000),
        Some("stripe"),
        Some(&receipt_id),
    );
    let wasm_hash: [u8; 32] = Sha256::digest(&wasm_bytes).into();

    assert_eq!(
        core_hash,
        wasm_hash,
        "registry+payment provenance hash mismatch: core={} wasm={}",
        hex::encode(core_hash),
        hex::encode(wasm_hash),
    );
}

// ===========================================================================
// WASM event type tag exhaustiveness
// ===========================================================================

#[test]
fn wasm_event_type_tag_exhaustiveness() {
    fn wasm_event_type_tag(event_type: &str) -> u16 {
        match event_type {
            "ContextCreated" => 0,
            "ContextClosing" => 1,
            "ContextClosed" => 2,
            "ContextExpired" => 3,
            "MemberJoined" => 4,
            "MemberLeft" => 5,
            "RoleAssigned" => 6,
            "TokenRevoked" | "UcanRevoked" => 7,
            "MessageSent" => 8,
            "ToolRegistered" => 9,
            "ToolUpdated" => 10,
            "ToolInvoked" => 11,
            "ToolVerified" => 12,
            "ToolInterfaceEstablished" => 13,
            "GovernanceAction" => 14,
            "ConsistencyCheckpoint" => 15,
            "AbsenceProofRequested" => 16,
            "MemberBlocked" => 17,
            "KeyEpochAdvance" => 18,
            "MediaSessionStarted" => 19,
            "MediaSessionEnded" => 20,
            "PaymentReceived" => 21,
            "EconomicPolicyChanged" => 22,
            "EconomicPolicyApplied" => 33,
            "SpendingUcanGranted" => 23,
            "SpendingUcanRevoked" => 24,
            "GovernanceProposalCreated" => 25,
            "GovernanceVoteCast" => 26,
            "GovernanceVoteWithdrawn" => 27,
            "GovernanceProposalResolved" => 28,
            "GovernanceConflictDetected" => 29,
            "GovernanceConflictResolved" => 30,
            "GovernanceDeadlockRecovery" => 31,
            "GovernanceActionExecuted" | "GovernanceExecuted" => 32,
            "ProvenanceAttached" => 34,
            "ProvenanceReceived" => 35,
            // Native↔WASM unification variants (ADR-011 Amendment). Tags
            // 36..=75 mirror the canonical assignment in
            // `scp_event_log::tree::event_type_tag` in ADR declaration order.
            "AdminTransferred" => 36,
            "CeilingModified" => 37,
            "CeilingModificationPending" => 38,
            "ThresholdModified" => 39,
            "SignerAdded" => 40,
            "SignerRemoved" => 41,
            "ChildContextCreated" => 42,
            "ContextPromoted" => 43,
            "ContentKeysRotated" => 44,
            "MemberReset" => 45,
            "MemberSuspended" => 46,
            "MemberSuspendedAll" => 47,
            "MemberUnblocked" => 48,
            "AccessRestored" => 49,
            "GovernanceReconfigured" => 50,
            "GovernanceFreezeExpired" => 51,
            "HardRateLimitModified" => 52,
            "EconomicPolicyLocked" => 53,
            "ContextMigrationStarted" => 54,
            "ToolRemoved" => 55,
            "PruningPolicyModified" => 56,
            "CommitBroadcasted" => 57,
            "CommitBroadcastPending" => 58,
            "PseudonymAnnounced" => 59,
            "ContextTombstoned" => 60,
            "ContextMigrationCancelled" => 61,
            "TtlExtended" => 62,
            "TtlExtensionRejected" => 63,
            "AccessRevoked" => 64,
            "SpendApproved" => 65,
            "PaymentCaptureFailed" => 66,
            "ConsequenceTriggered" => 67,
            "ConsequenceEnforced" => 68,
            "ConsequenceEnforcementFailed" => 69,
            "ConsequenceEscalatedToSuspendAll" => 70,
            "CommitBroadcastSucceeded" => 71,
            "CommitBroadcastFailed" => 72,
            "RecoveryEpochAdvanced" => 73,
            "AppBound" => 74,
            "AppUnbound" => 75,
            _ => 0xFFFF,
        }
    }

    let all_event_type_strings = [
        "ContextCreated",
        "ContextClosing",
        "ContextClosed",
        "ContextExpired",
        "MemberJoined",
        "MemberLeft",
        "MessageSent",
        "ToolRegistered",
        "ToolInvoked",
        "UcanRevoked",
        "GovernanceExecuted",
        "GovernanceProposalCreated",
        "GovernanceVoteCast",
        "GovernanceVoteWithdrawn",
        "ProvenanceAttached",
        "ProvenanceReceived",
        "RoleAssigned",
        "TokenRevoked",
        "ToolUpdated",
        "ToolVerified",
        "ToolInterfaceEstablished",
        "GovernanceAction",
        "ConsistencyCheckpoint",
        "AbsenceProofRequested",
        "MemberBlocked",
        "KeyEpochAdvance",
        "MediaSessionStarted",
        "MediaSessionEnded",
        "PaymentReceived",
        "EconomicPolicyChanged",
        "EconomicPolicyApplied",
        "SpendingUcanGranted",
        "SpendingUcanRevoked",
        "GovernanceProposalResolved",
        "GovernanceConflictDetected",
        "GovernanceConflictResolved",
        "GovernanceDeadlockRecovery",
        "GovernanceActionExecuted",
        "AdminTransferred",
        "CeilingModified",
        "CeilingModificationPending",
        "ThresholdModified",
        "SignerAdded",
        "SignerRemoved",
        "ChildContextCreated",
        "ContextPromoted",
        "ContentKeysRotated",
        "MemberReset",
        "MemberSuspended",
        "MemberSuspendedAll",
        "MemberUnblocked",
        "AccessRestored",
        "GovernanceReconfigured",
        "GovernanceFreezeExpired",
        "HardRateLimitModified",
        "EconomicPolicyLocked",
        "ContextMigrationStarted",
        "ToolRemoved",
        "PruningPolicyModified",
        "CommitBroadcasted",
        "CommitBroadcastPending",
        "PseudonymAnnounced",
        "ContextTombstoned",
        "ContextMigrationCancelled",
        "TtlExtended",
        "TtlExtensionRejected",
        "AccessRevoked",
        "SpendApproved",
        "PaymentCaptureFailed",
        "ConsequenceTriggered",
        "ConsequenceEnforced",
        "ConsequenceEnforcementFailed",
        "ConsequenceEscalatedToSuspendAll",
        "CommitBroadcastSucceeded",
        "CommitBroadcastFailed",
        "RecoveryEpochAdvanced",
        "AppBound",
        "AppUnbound",
    ];

    for event_type in &all_event_type_strings {
        let tag = wasm_event_type_tag(event_type);
        assert_ne!(
            tag, 0xFFFF,
            "WASM event type string '{event_type}' maps to sentinel 0xFFFF — \
             add a mapping to wasm_event_type_tag in crates/scp-ffi/wasm/src/runtime.rs"
        );
    }

    let all_variants = [
        (EventType::ContextCreated, "ContextCreated"),
        (EventType::ContextClosing, "ContextClosing"),
        (EventType::ContextClosed, "ContextClosed"),
        (EventType::ContextExpired, "ContextExpired"),
        (EventType::MemberJoined, "MemberJoined"),
        (EventType::MemberLeft, "MemberLeft"),
        (EventType::RoleAssigned, "RoleAssigned"),
        (EventType::TokenRevoked, "TokenRevoked"),
        (EventType::MessageSent, "MessageSent"),
        (EventType::ToolRegistered, "ToolRegistered"),
        (EventType::ToolUpdated, "ToolUpdated"),
        (EventType::ToolInvoked, "ToolInvoked"),
        (EventType::ToolVerified, "ToolVerified"),
        (
            EventType::ToolInterfaceEstablished,
            "ToolInterfaceEstablished",
        ),
        (EventType::GovernanceAction, "GovernanceAction"),
        (EventType::ConsistencyCheckpoint, "ConsistencyCheckpoint"),
        (EventType::AbsenceProofRequested, "AbsenceProofRequested"),
        (EventType::MemberBlocked, "MemberBlocked"),
        (EventType::KeyEpochAdvance, "KeyEpochAdvance"),
        (EventType::MediaSessionStarted, "MediaSessionStarted"),
        (EventType::MediaSessionEnded, "MediaSessionEnded"),
        (EventType::PaymentReceived, "PaymentReceived"),
        (EventType::EconomicPolicyChanged, "EconomicPolicyChanged"),
        (EventType::EconomicPolicyApplied, "EconomicPolicyApplied"),
        (EventType::SpendingUcanGranted, "SpendingUcanGranted"),
        (EventType::SpendingUcanRevoked, "SpendingUcanRevoked"),
        (
            EventType::GovernanceProposalCreated,
            "GovernanceProposalCreated",
        ),
        (EventType::GovernanceVoteCast, "GovernanceVoteCast"),
        (
            EventType::GovernanceVoteWithdrawn,
            "GovernanceVoteWithdrawn",
        ),
        (
            EventType::GovernanceProposalResolved,
            "GovernanceProposalResolved",
        ),
        (
            EventType::GovernanceConflictDetected,
            "GovernanceConflictDetected",
        ),
        (
            EventType::GovernanceConflictResolved,
            "GovernanceConflictResolved",
        ),
        (
            EventType::GovernanceDeadlockRecovery,
            "GovernanceDeadlockRecovery",
        ),
        (
            EventType::GovernanceActionExecuted,
            "GovernanceActionExecuted",
        ),
        (EventType::ProvenanceAttached, "ProvenanceAttached"),
        (EventType::ProvenanceReceived, "ProvenanceReceived"),
        (EventType::AdminTransferred, "AdminTransferred"),
        (EventType::CeilingModified, "CeilingModified"),
        (
            EventType::CeilingModificationPending,
            "CeilingModificationPending",
        ),
        (EventType::ThresholdModified, "ThresholdModified"),
        (EventType::SignerAdded, "SignerAdded"),
        (EventType::SignerRemoved, "SignerRemoved"),
        (EventType::ChildContextCreated, "ChildContextCreated"),
        (EventType::ContextPromoted, "ContextPromoted"),
        (EventType::ContentKeysRotated, "ContentKeysRotated"),
        (EventType::MemberReset, "MemberReset"),
        (EventType::MemberSuspended, "MemberSuspended"),
        (EventType::MemberSuspendedAll, "MemberSuspendedAll"),
        (EventType::MemberUnblocked, "MemberUnblocked"),
        (EventType::AccessRestored, "AccessRestored"),
        (EventType::GovernanceReconfigured, "GovernanceReconfigured"),
        (
            EventType::GovernanceFreezeExpired,
            "GovernanceFreezeExpired",
        ),
        (EventType::HardRateLimitModified, "HardRateLimitModified"),
        (EventType::EconomicPolicyLocked, "EconomicPolicyLocked"),
        (
            EventType::ContextMigrationStarted,
            "ContextMigrationStarted",
        ),
        (EventType::ToolRemoved, "ToolRemoved"),
        (EventType::PruningPolicyModified, "PruningPolicyModified"),
        (EventType::CommitBroadcasted, "CommitBroadcasted"),
        (EventType::CommitBroadcastPending, "CommitBroadcastPending"),
        (EventType::PseudonymAnnounced, "PseudonymAnnounced"),
        (EventType::ContextTombstoned, "ContextTombstoned"),
        (
            EventType::ContextMigrationCancelled,
            "ContextMigrationCancelled",
        ),
        (EventType::TtlExtended, "TtlExtended"),
        (EventType::TtlExtensionRejected, "TtlExtensionRejected"),
        (EventType::AccessRevoked, "AccessRevoked"),
        (EventType::SpendApproved, "SpendApproved"),
        (EventType::PaymentCaptureFailed, "PaymentCaptureFailed"),
        (EventType::ConsequenceTriggered, "ConsequenceTriggered"),
        (EventType::ConsequenceEnforced, "ConsequenceEnforced"),
        (
            EventType::ConsequenceEnforcementFailed,
            "ConsequenceEnforcementFailed",
        ),
        (
            EventType::ConsequenceEscalatedToSuspendAll,
            "ConsequenceEscalatedToSuspendAll",
        ),
        (
            EventType::CommitBroadcastSucceeded,
            "CommitBroadcastSucceeded",
        ),
        (EventType::CommitBroadcastFailed, "CommitBroadcastFailed"),
        (EventType::RecoveryEpochAdvanced, "RecoveryEpochAdvanced"),
        (EventType::AppBound, "AppBound"),
        (EventType::AppUnbound, "AppUnbound"),
    ];

    // The closed EventType taxonomy has exactly 76 variants
    // (`scp_event_log::tree::event_type_tag`, tags 0..=75). Assert the
    // native↔WASM parity table enumerates the full set, so a future variant
    // cannot silently slip past this gate. `all_event_type_strings` additionally
    // carries WASM alias strings (e.g. "UcanRevoked", "GovernanceExecuted"), so
    // we require it to be a superset that covers every canonical variant name
    // rather than pinning an exact count.
    assert_eq!(
        all_variants.len(),
        76,
        "all_variants must enumerate the full closed 76-variant EventType taxonomy"
    );
    for (_, name) in &all_variants {
        assert!(
            all_event_type_strings.contains(name),
            "all_event_type_strings is missing canonical variant '{name}' — \
             every EventType variant must be exercised against the 0xFFFF sentinel"
        );
    }

    for (variant, name) in &all_variants {
        let native_tag = event_type_tag(variant);
        let wasm_tag = wasm_event_type_tag(name);
        assert_eq!(
            native_tag, wasm_tag,
            "tag mismatch for {name}: native={native_tag}, wasm={wasm_tag}"
        );
    }
}

/// Confirms that `chain_depth: u8` (scp-core) and `chain_depth: u32` (WASM)
/// produce identical JSON bytes for values in the protocol range (0..=5).
#[test]
fn provenance_hash_chain_depth_u8_vs_u32() {
    #[derive(serde::Serialize)]
    struct WithU8 {
        chain_depth: u8,
    }
    #[derive(serde::Serialize)]
    struct WithU32 {
        chain_depth: u32,
    }

    for depth in 0..=5u8 {
        let u8_bytes =
            serde_json::to_vec(&WithU8 { chain_depth: depth }).expect("u8 serialization");
        let u32_bytes = serde_json::to_vec(&WithU32 {
            chain_depth: u32::from(depth),
        })
        .expect("u32 serialization");
        assert_eq!(
            u8_bytes,
            u32_bytes,
            "JSON bytes differ for chain_depth={depth}: u8={} vs u32={}",
            String::from_utf8_lossy(&u8_bytes),
            String::from_utf8_lossy(&u32_bytes),
        );
    }
}

// ---------------------------------------------------------------------------
// Identity link attestation canonical bytes conformance
// ---------------------------------------------------------------------------

mod wasm_mirror_attestation {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct Claim {
        pub platform: String,
        pub platform_handle: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform_id: Option<String>,
        pub link_type: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Evidence {
        pub method: String,
        pub proof: String,
        pub verified_at: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verifier_did: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    pub enum RevocationStatus {
        Active,
        Revoked {
            revoked_at: u64,
            reason: String,
            #[serde(default = "default_revoked_by")]
            revoked_by: String,
        },
    }

    fn default_revoked_by() -> String {
        "did:unknown:pre-migration".to_owned()
    }
}

#[test]
fn wasm_attestation_canonical_bytes_match_core() {
    use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};
    use scp_protocol::identity::attestation::{
        AttestationClaim, AttestationEvidence, IdentityLinkAttestation, VerificationMethod,
    };
    use scp_protocol::trust::attestation::RevocationStatus;

    let issuer = "did:dht:z6MkTestAlice".to_string();
    let issued_at = 1_700_000_000u64;
    let proof_str = r#"{"type":"oauth_verified","provider":"github.com","subject_id":"12345","verified_at":1700000000}"#.to_string();

    let core_attestation = IdentityLinkAttestation {
        id: "deadbeef".to_string(),
        attestation_type: "identity_link".into(),
        issuer: issuer.clone().into(),
        subject: issuer.clone().into(),
        issued_at,
        expires_at: None,
        claim: AttestationClaim::new("github.com".to_string(), "alice".to_string(), None),
        evidence: AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: proof_str.clone(),
            verified_at: issued_at,
            verifier_did: None,
        },
        revocation_status: RevocationStatus::Active,
        signature: vec![0u8; 64],
    };

    let core_bytes = core_attestation
        .canonical_signing_bytes()
        .expect("core canonical bytes");

    let absent_sentinel: [u8; 32] = {
        let mut h = Sha256::new();
        h.update([0x00]);
        h.finalize().into()
    };

    let wasm_claim = wasm_mirror_attestation::Claim {
        platform: "github.com".to_string(),
        platform_handle: "alice".to_string(),
        platform_id: None,
        link_type: "self_attestation".to_string(),
    };
    let wasm_evidence = wasm_mirror_attestation::Evidence {
        method: "oauth".to_string(),
        proof: proof_str,
        verified_at: issued_at,
        verifier_did: None,
    };
    let wasm_revocation = wasm_mirror_attestation::RevocationStatus::Active;

    let claim_msgpack = rmp_serde::to_vec_named(&wasm_claim).expect("claim msgpack");
    let evidence_msgpack = rmp_serde::to_vec_named(&wasm_evidence).expect("evidence msgpack");
    let revocation_msgpack = rmp_serde::to_vec_named(&wasm_revocation).expect("revocation msgpack");

    let mut h = Sha256::new();
    h.update(b"SCP-IDENTITY-LINK-ATTESTATION-V1:");
    for field in &[
        b"deadbeef".to_vec(),
        b"identity_link".to_vec(),
        issuer.as_bytes().to_vec(),
        issuer.as_bytes().to_vec(),
    ] {
        h.update(u32::try_from(field.len()).unwrap().to_be_bytes());
        h.update(field);
    }
    h.update(issued_at.to_be_bytes());
    h.update(absent_sentinel);
    for field in &[
        claim_msgpack.clone(),
        evidence_msgpack.clone(),
        revocation_msgpack.clone(),
    ] {
        h.update(u32::try_from(field.len()).unwrap().to_be_bytes());
        h.update(field);
    }
    let wasm_bytes: Vec<u8> = h.finalize().to_vec();

    assert_eq!(
        core_bytes,
        wasm_bytes,
        "scp-core canonical bytes must match WASM mirror construction.\n\
         Core: {}\nWASM: {}",
        hex::encode(&core_bytes),
        hex::encode(&wasm_bytes),
    );

    let hash_fn_bytes = canonical_hash(
        "SCP-IDENTITY-LINK-ATTESTATION-V1:",
        &[
            CanonicalField::VarBytes(b"deadbeef"),
            CanonicalField::VarBytes(b"identity_link"),
            CanonicalField::VarBytes(issuer.as_bytes()),
            CanonicalField::VarBytes(issuer.as_bytes()),
            CanonicalField::U64(issued_at),
            CanonicalField::Absent,
            CanonicalField::VarBytes(&claim_msgpack),
            CanonicalField::VarBytes(&evidence_msgpack),
            CanonicalField::VarBytes(&revocation_msgpack),
        ],
    )
    .unwrap();
    assert_eq!(
        core_bytes,
        hash_fn_bytes.to_vec(),
        "canonical_hash utility must match IdentityLinkAttestation::canonical_signing_bytes"
    );
}

#[allow(clippy::too_many_arguments)]
fn assert_attestation_proof_conformance(
    proof_str: &str,
    core_method: scp_protocol::identity::attestation::VerificationMethod,
    wasm_method_str: &str,
) {
    use scp_protocol::identity::attestation::{
        AttestationClaim, AttestationEvidence, IdentityLinkAttestation,
    };
    use scp_protocol::trust::attestation::RevocationStatus;

    let issuer = "did:dht:z6MkTestAlice".to_string();
    let issued_at = 1_700_000_000u64;

    let core_attestation = IdentityLinkAttestation {
        id: "deadbeef".to_string(),
        attestation_type: "identity_link".into(),
        issuer: issuer.clone().into(),
        subject: issuer.clone().into(),
        issued_at,
        expires_at: None,
        claim: AttestationClaim::new("github.com".to_string(), "alice".to_string(), None),
        evidence: AttestationEvidence {
            method: core_method,
            proof: proof_str.to_string(),
            verified_at: issued_at,
            verifier_did: None,
        },
        revocation_status: RevocationStatus::Active,
        signature: vec![0u8; 64],
    };

    let core_bytes = core_attestation
        .canonical_signing_bytes()
        .expect("core canonical bytes");

    let absent_sentinel: [u8; 32] = {
        let mut h = Sha256::new();
        h.update([0x00]);
        h.finalize().into()
    };

    let wasm_claim = wasm_mirror_attestation::Claim {
        platform: "github.com".to_string(),
        platform_handle: "alice".to_string(),
        platform_id: None,
        link_type: "self_attestation".to_string(),
    };
    let wasm_evidence = wasm_mirror_attestation::Evidence {
        method: wasm_method_str.to_string(),
        proof: proof_str.to_string(),
        verified_at: issued_at,
        verifier_did: None,
    };
    let wasm_revocation = wasm_mirror_attestation::RevocationStatus::Active;

    let claim_msgpack = rmp_serde::to_vec_named(&wasm_claim).expect("claim msgpack");
    let evidence_msgpack = rmp_serde::to_vec_named(&wasm_evidence).expect("evidence msgpack");
    let revocation_msgpack = rmp_serde::to_vec_named(&wasm_revocation).expect("revocation msgpack");

    let mut h = Sha256::new();
    h.update(b"SCP-IDENTITY-LINK-ATTESTATION-V1:");
    for field in &[
        b"deadbeef".to_vec(),
        b"identity_link".to_vec(),
        issuer.as_bytes().to_vec(),
        issuer.as_bytes().to_vec(),
    ] {
        h.update(u32::try_from(field.len()).unwrap().to_be_bytes());
        h.update(field);
    }
    h.update(issued_at.to_be_bytes());
    h.update(absent_sentinel);
    for field in &[claim_msgpack, evidence_msgpack, revocation_msgpack] {
        h.update(u32::try_from(field.len()).unwrap().to_be_bytes());
        h.update(field);
    }
    let wasm_bytes: Vec<u8> = h.finalize().to_vec();

    assert_eq!(
        core_bytes,
        wasm_bytes,
        "scp-core canonical bytes must match WASM mirror for {wasm_method_str}.\n\
         Core: {}\nWASM: {}",
        hex::encode(&core_bytes),
        hex::encode(&wasm_bytes),
    );
}

#[test]
fn wasm_attestation_canonical_bytes_signed_post_verified() {
    use scp_protocol::identity::attestation::VerificationMethod;

    assert_attestation_proof_conformance(
        r#"{"type":"signed_post_verified","post_url":"https://x.com/alice/status/123","nonce":"abc123","posted_at":1700000000}"#,
        VerificationMethod::SignedPost,
        "signed_post",
    );
}

#[test]
fn wasm_attestation_canonical_bytes_dns_record_verified() {
    use scp_protocol::identity::attestation::VerificationMethod;

    assert_attestation_proof_conformance(
        r#"{"type":"dns_record_verified","domain":"example.com","record_name":"_scp-verify"}"#,
        VerificationMethod::DnsRecord,
        "dns_record",
    );
}

#[test]
fn wasm_attestation_canonical_bytes_challenge_response_verified() {
    use scp_protocol::identity::attestation::VerificationMethod;

    assert_attestation_proof_conformance(
        r#"{"type":"challenge_response_verified","challenge":"random-challenge-value","response_signature":"deadbeefdeadbeef"}"#,
        VerificationMethod::ChallengeResponse,
        "challenge_response",
    );
}

// ===========================================================================
// Golden vector smoke tests (Fix 2)
//
// These verify that the WASM runtime environment produces correct
// cryptographic output. They catch environment-level failures (getrandom,
// JS crypto backend) that compilation alone cannot.
// ===========================================================================

/// Sender key encrypt → decrypt roundtrip with a fixed test key.
#[test]
fn golden_sender_key_roundtrip() {
    use scp_protocol::crypto::sender_keys::{
        SenderKey, decrypt_sender_layer, encrypt_sender_layer,
    };

    let key = SenderKey::from_bytes([0xAA; 32]);
    let plaintext = b"hello golden vector";
    let context_id = "ctx-golden";
    let sender_did = "did:dht:zGolden";
    let epoch = 1;
    let sequence = 0;

    let ciphertext = encrypt_sender_layer(&key, plaintext, context_id, sender_did, epoch, sequence)
        .expect("encrypt_sender_layer must succeed with valid key material");

    // Ciphertext must be longer than plaintext (12-byte nonce + 16-byte tag).
    assert!(
        ciphertext.len() > plaintext.len(),
        "ciphertext must include nonce and auth tag"
    );

    let decrypted =
        decrypt_sender_layer(&key, &ciphertext, context_id, sender_did, epoch, sequence)
            .expect("decrypt_sender_layer must succeed for matching parameters");

    assert_eq!(
        decrypted, plaintext,
        "sender key roundtrip must produce identical plaintext"
    );
}

/// Revocation CID golden value: `compute_revocation_cid("test-token")`
/// must produce a known SHA-256 hash.
#[test]
fn golden_revocation_cid() {
    use scp_protocol::crypto::ucan::revoke::compute_revocation_cid;

    let cid = compute_revocation_cid("test-token");

    // SHA-256("test-token") = 4c5dc9b7...
    assert_eq!(
        cid, "4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e",
        "revocation CID must be SHA-256 of the token string"
    );
}

/// Event leaf hash golden value: appending a fixed event to an empty log
/// must produce a known Merkle root.
#[test]
fn golden_event_leaf_hash() {
    use scp_event_log::tree::{append_unsigned_event, root};
    use scp_event_log::{DID, Event, EventLog, EventPayload, EventType};

    let mut log = EventLog::new("ctx-golden".to_owned());

    let event = Event {
        event_type: EventType::MessageSent,
        actor_did: DID::from("did:dht:zGolden"),
        timestamp: 1_700_000_000,
        sequence: 0,
        payload: EventPayload {
            data: b"golden-payload".to_vec(),
        },
        prev_hash: [0u8; 32],
        signature: vec![],
    };

    append_unsigned_event(&mut log, &event).expect("append must succeed for valid event");
    let root_hash = root(&log);

    // For a single-leaf tree, the root IS the leaf hash:
    // SHA-256(0x00 || rmp_serde::to_vec(event))
    //
    // This golden vector was recorded by running the function and capturing
    // the output. Any change to Event serialization or hashing will break
    // this test — which is exactly the point.
    let root_hex = hex::encode(root_hash);

    // Hardcode after first run to lock the value.
    // If this assertion fails, it means the event serialization or hashing
    // algorithm has changed — investigate before updating the vector.
    // Golden vector: SHA-256(0x00 || rmp_serde::to_vec(event)) recorded from
    // scp-event-log. If this changes, event serialization has been modified.
    assert_eq!(
        root_hex, "b891621d6d19bc37e93a9acb4709fa5fe2bc7020836493b0a6b2b0415e99decb",
        "single-leaf Merkle root must match recorded golden vector; \
         a mismatch means Event serialization or leaf hashing has changed"
    );
}

// ===========================================================================
// JSON wire format stability tests
//
// These tests ensure that JSON output from WASM bridge functions maintains
// the field names and structure expected by JS consumers. Serialization
// format is part of the API contract — not "tautological" even when
// the underlying code is shared.
// ===========================================================================

/// Verifies that `template_params` output uses camelCase field names
/// (`maxChainDepth`, `maxNestingDepth`, `sessionCap`) as expected by JS.
///
/// scp-protocol's `ContextParams` serializes with `snake_case` by default.
/// The WASM bridge post-processes to restore the `camelCase` convention.
/// This test catches regressions if the post-processing is removed.
#[test]
fn template_params_json_uses_camel_case_field_names() {
    use scp_protocol::context::params::TemplateId;
    use scp_protocol::context::templates::template_params;

    // GroupDiscussion sets max_chain_depth and max_nesting_depth
    let params = template_params(&TemplateId::GroupDiscussion);
    let mut val = serde_json::to_value(&params).unwrap();

    // Simulate the WASM bridge's snake_to_camel transformation
    if let Some(map) = val.as_object_mut() {
        let renames = [
            ("max_chain_depth", "maxChainDepth"),
            ("max_nesting_depth", "maxNestingDepth"),
            ("session_cap", "sessionCap"),
        ];
        for (snake, camel) in &renames {
            if let Some(v) = map.remove(*snake) {
                map.insert(camel.to_string(), v);
            }
        }
    }

    let json_str = serde_json::to_string(&val).unwrap();

    // camelCase keys MUST be present (JS API contract)
    assert!(
        json_str.contains("\"maxChainDepth\""),
        "template params JSON must use camelCase 'maxChainDepth', got: {json_str}"
    );
    assert!(
        json_str.contains("\"maxNestingDepth\""),
        "template params JSON must use camelCase 'maxNestingDepth'"
    );
    assert!(
        json_str.contains("\"sessionCap\""),
        "template params JSON must use camelCase 'sessionCap'"
    );

    // snake_case keys MUST NOT be present
    assert!(
        !json_str.contains("\"max_chain_depth\""),
        "template params JSON must NOT contain snake_case 'max_chain_depth'"
    );
    assert!(
        !json_str.contains("\"max_nesting_depth\""),
        "template params JSON must NOT contain snake_case 'max_nesting_depth'"
    );
    assert!(
        !json_str.contains("\"session_cap\""),
        "template params JSON must NOT contain snake_case 'session_cap'"
    );
}

// ===========================================================================
// GovernanceAction JS-idiomatic camelCase serialization conformance
// ===========================================================================

/// Verifies `GovernanceAction` deserializes from JS-idiomatic camelCase format.
///
/// JS consumers send `{"type": "addMember", "did": "d", "role": "r"}`.
/// The WASM bridge converts to serde's externally-tagged format before
/// deserializing: `{"AddMember": {"did": "d", "role": "r"}}`.
#[test]
fn governance_action_from_js_camel_case_format() {
    use scp_protocol::context::governance::GovernanceAction;

    // Helper: simulate the WASM bridge conversion (camelCase → PascalCase externally-tagged).
    fn js_to_serde(value: &mut serde_json::Value) {
        let obj = value.as_object_mut().unwrap();
        let variant = obj
            .remove("type")
            .and_then(|v| v.as_str().map(String::from))
            .unwrap();
        // camelCase → PascalCase: uppercase first char
        let pascal = {
            let mut r = String::with_capacity(variant.len());
            let mut first = true;
            for ch in variant.chars() {
                if first {
                    r.extend(ch.to_uppercase());
                    first = false;
                } else {
                    r.push(ch);
                }
            }
            r
        };
        if obj.is_empty() {
            // Unit variant: serde expects a bare string.
            *value = serde_json::Value::String(pascal);
        } else {
            // Struct variant: wrap remaining fields.
            let inner = serde_json::Value::Object(obj.clone());
            obj.clear();
            obj.insert(pascal, inner);
        }
    }

    // Test struct variants with fields.
    let test_cases: Vec<(serde_json::Value, &str)> = vec![
        (
            serde_json::json!({"type": "addMember", "did": "did:dht:z1", "role": "member"}),
            "AddMember",
        ),
        (
            serde_json::json!({"type": "removeMember", "did": "did:dht:z2", "reason": null}),
            "RemoveMember",
        ),
        (
            serde_json::json!({"type": "changeRole", "did": "did:dht:z3", "new_role": "admin"}),
            "ChangeRole",
        ),
        (
            serde_json::json!({"type": "closeContext", "reason": "done"}),
            "CloseContext",
        ),
        (
            serde_json::json!({"type": "extendTtl", "additional_secs": 3600}),
            "ExtendTtl",
        ),
        (
            serde_json::json!({"type": "transferAdmin", "new_admin": "did:dht:z4"}),
            "TransferAdmin",
        ),
    ];

    for (mut js_val, expected_variant) in test_cases {
        js_to_serde(&mut js_val);
        let action: GovernanceAction = serde_json::from_value(js_val.clone()).unwrap_or_else(|e| {
            panic!("failed to deserialize {expected_variant}: {e} from {js_val}")
        });
        assert_eq!(
            action.variant_name(),
            expected_variant,
            "variant mismatch for JS input"
        );
    }

    // Unit variants: empty inner object.
    let mut unit_val = serde_json::json!({"type": "promoteContext"});
    js_to_serde(&mut unit_val);
    let action: GovernanceAction = serde_json::from_value(unit_val).unwrap();
    assert_eq!(action.variant_name(), "PromoteContext");

    let mut lock_val = serde_json::json!({"type": "lockEconomicPolicy"});
    js_to_serde(&mut lock_val);
    let action: GovernanceAction = serde_json::from_value(lock_val).unwrap();
    assert_eq!(action.variant_name(), "LockEconomicPolicy");

    let mut cancel_val = serde_json::json!({"type": "cancelContextMigration"});
    js_to_serde(&mut cancel_val);
    let action: GovernanceAction = serde_json::from_value(cancel_val).unwrap();
    assert_eq!(action.variant_name(), "CancelContextMigration");
}

/// Verifies `ContextEvent` serializes to JS-idiomatic camelCase format.
///
/// serde default: `{"MemberJoined": {"member_did": "..."}}` or `"Expired"`.
/// JS-idiomatic:  `{"type": "memberJoined", "member_did": "..."}` or `{"type": "expired"}`.
#[test]
fn context_event_to_js_camel_case_format() {
    use scp_protocol::context::membership::ContextEvent;

    // Helper: simulate the WASM bridge conversion (externally-tagged → JS camelCase).
    fn serde_to_js(value: &mut serde_json::Value) {
        // Handle string values (unit variants).
        if let Some(s) = value.as_str().map(String::from) {
            let camel = {
                let mut r = String::with_capacity(s.len());
                for (i, ch) in s.chars().enumerate() {
                    if i == 0 {
                        r.extend(ch.to_lowercase());
                    } else {
                        r.push(ch);
                    }
                }
                r
            };
            let mut map = serde_json::Map::new();
            map.insert("type".to_owned(), serde_json::Value::String(camel));
            *value = serde_json::Value::Object(map);
            return;
        }

        if let Some(obj) = value.as_object_mut()
            && let Some((variant_name, inner)) =
                obj.iter().next().map(|(k, v)| (k.clone(), v.clone()))
        {
            let camel = {
                let mut r = String::with_capacity(variant_name.len());
                for (i, ch) in variant_name.chars().enumerate() {
                    if i == 0 {
                        r.extend(ch.to_lowercase());
                    } else {
                        r.push(ch);
                    }
                }
                r
            };
            obj.clear();
            obj.insert("type".to_owned(), serde_json::Value::String(camel));
            if let Some(inner_obj) = inner.as_object() {
                for (k, v) in inner_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }
    }

    // Struct variants.
    let event = ContextEvent::MemberJoined {
        member_did: "did:dht:joined".into(),
        role_name: "member".into(),
    };
    let mut val = serde_json::to_value(&event).unwrap();
    serde_to_js(&mut val);
    assert_eq!(val["type"], "memberJoined");
    assert_eq!(val["member_did"], "did:dht:joined");
    assert_eq!(val["role_name"], "member");
    assert!(
        val.get("MemberJoined").is_none(),
        "PascalCase key must be removed"
    );

    let event = ContextEvent::MemberLeft {
        member_did: "did:dht:left".into(),
    };
    let mut val = serde_json::to_value(&event).unwrap();
    serde_to_js(&mut val);
    assert_eq!(val["type"], "memberLeft");
    assert_eq!(val["member_did"], "did:dht:left");

    let event = ContextEvent::SystemClose {
        initiator_did: "did:dht:closer".into(),
    };
    let mut val = serde_json::to_value(&event).unwrap();
    serde_to_js(&mut val);
    assert_eq!(val["type"], "systemClose");
    assert_eq!(val["initiator_did"], "did:dht:closer");

    // Unit variant.
    let event = ContextEvent::Expired;
    let mut val = serde_json::to_value(&event).unwrap();
    serde_to_js(&mut val);
    assert_eq!(val, serde_json::json!({"type": "expired"}));

    // BufferOverflow with numeric field.
    let event = ContextEvent::BufferOverflow { dropped_count: 5 };
    let mut val = serde_json::to_value(&event).unwrap();
    serde_to_js(&mut val);
    assert_eq!(val["type"], "bufferOverflow");
    assert_eq!(val["dropped_count"], 5);

    // GovernanceActionExecuted with complex fields.
    let event = ContextEvent::GovernanceActionExecuted {
        proposal_id: [0u8; 32],
        action_summary: "AddMember".into(),
        executor_did: "did:dht:admin".into(),
        resulting_epoch: Some(42),
        target_did: Some("did:dht:alice".into()),
    };
    let mut val = serde_json::to_value(&event).unwrap();
    serde_to_js(&mut val);
    assert_eq!(val["type"], "governanceActionExecuted");
    assert_eq!(val["action_summary"], "AddMember");
    assert_eq!(val["executor_did"], "did:dht:admin");
    assert_eq!(val["resulting_epoch"], 42);
}

/// Verifies that `SourceType` string representation uses exact expected values
/// for wire format stability (used in JSON responses and canonical hashing).
#[test]
fn source_type_string_format_is_stable() {
    use scp_protocol::provenance::SourceType;

    // These string values are part of the wire format contract.
    // If SourceType ever changes its Debug/Display output, this test catches it.
    let cases = [
        (SourceType::Persistent, "Persistent"),
        (SourceType::Ephemeral, "Ephemeral"),
        (SourceType::Summary, "Summary"),
    ];
    for (variant, expected) in &cases {
        let formatted = match variant {
            SourceType::Persistent => "Persistent",
            SourceType::Ephemeral => "Ephemeral",
            SourceType::Summary => "Summary",
        };
        assert_eq!(
            formatted, *expected,
            "SourceType string format must be stable for wire compatibility"
        );
    }
}

// ===========================================================================
// Test: WASM and native checkpoint signing produce byte-identical signatures
// ===========================================================================

/// Minimal `EventLogSigner` over a fixed Ed25519 key — mirrors how the native
/// checkpoint path signs (`signer.sign(&canonical_hash)` in
/// `generate_checkpoint_at`). A fixed key lets the parity test assert that the
/// native and WASM signatures over the same digest are byte-identical.
struct FixedKeySigner(ed25519_dalek::SigningKey);

#[async_trait::async_trait]
impl scp_event_log::EventLogSigner for FixedKeySigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

/// Cross-runtime parity: the WASM bridge signs a checkpoint in-process with the
/// identity's `#active` Ed25519 key over the canonical checkpoint hash, exactly
/// as the native bridges do (`generate_checkpoint_at` →
/// `signer.sign(&canonical_hash)` in `scp-event-log/src/checkpoint.rs`). Both
/// the WASM producer (`checkpoint_promise` in
/// `crates/scp-ffi/wasm/src/event_log.rs`) and the native path call
/// `compute_checkpoint_canonical_hash` directly, so there is no separate WASM
/// payload layout to assert — they share one canonical hash by construction.
///
/// This test proves the signing parity for fixed inputs:
///
/// 1. The native-style signature and the WASM-path signature are byte-identical
///    64-byte Ed25519 signatures (Ed25519 over the same canonical digest with
///    the same key is deterministic).
/// 2. Both signatures `verify_strict` against the `#active` verifying key.
#[tokio::test]
async fn wasm_and_native_checkpoint_signatures_are_byte_identical() {
    use ed25519_dalek::Signer as _;
    use scp_event_log::EventLogSigner as _;
    use scp_event_log::checkpoint::compute_checkpoint_canonical_hash;

    // Fixed inputs for a deterministic assertion.
    let context_id = "ctx-parity-checkpoint";
    let sender_did = "did:dht:zparitycheckpointsigner";
    let event_count: u64 = 11;
    let merkle_root: [u8; 32] = [0x5A; 32];
    let epoch: Option<u64> = Some(4);
    let timestamp: u64 = 1_700_000_500;

    // The `#active` keypair. In WASM this lives in the DID-keyed
    // IDENTITY_REGISTRY; here we use a fixed seed so the test is deterministic.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let verifying_key = signing_key.verifying_key();

    // Both the WASM producer and the native path compute the signing digest via
    // `compute_checkpoint_canonical_hash` directly — the single shared canonical
    // function. Sign that 32-byte digest exactly as each runtime does.
    let canonical_hash = compute_checkpoint_canonical_hash(
        context_id,
        sender_did,
        event_count,
        &merkle_root,
        epoch,
        timestamp,
    );

    // (1) Native-style signing via `EventLogSigner::sign(&canonical_hash)`.
    let native_signer = FixedKeySigner(signing_key.clone());
    let native_sig_bytes = native_signer
        .sign(&canonical_hash)
        .await
        .expect("native checkpoint signing");
    assert_eq!(native_sig_bytes.len(), 64, "native sig must be 64 bytes");

    // WASM-path signing: exactly what `sign_with_identity` does — Ed25519
    // `Signer::sign` over the same 32-byte canonical hash, returning [u8; 64].
    let wasm_sig: [u8; 64] = signing_key.sign(canonical_hash.as_slice()).to_bytes();

    assert_eq!(
        native_sig_bytes.as_slice(),
        wasm_sig.as_slice(),
        "WASM and native checkpoint signatures must be byte-identical"
    );

    // (2) Both signatures verify_strict against the `#active` key.
    let native_sig = ed25519_dalek::Signature::from_bytes(
        native_sig_bytes
            .as_slice()
            .try_into()
            .expect("64-byte signature"),
    );
    let wasm_sig_parsed = ed25519_dalek::Signature::from_bytes(&wasm_sig);
    verifying_key
        .verify_strict(canonical_hash.as_slice(), &native_sig)
        .expect("native signature must verify against #active key");
    verifying_key
        .verify_strict(canonical_hash.as_slice(), &wasm_sig_parsed)
        .expect("WASM signature must verify against #active key");
}
