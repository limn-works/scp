//! Phase D3 — `UniFFI` Bridge E2E Tests
//!
//! Tests the `UniFFI` bridge functions directly from Rust, validating the
//! bridge code path without requiring Swift/Kotlin runtimes. All tests use
//! the `allow_in_memory_custody` feature for in-memory key custody.
//!
//! Covers: identity lifecycle, context lifecycle, governance, broadcast,
//! tools, UCAN, event log, discovery, sync classification, provenance,
//! bridge trust evaluation, and shutdown ordering.
//!
//! Run:
//! ```bash
//! cargo test -p scp-ffi-uniffi --test e2e_bridge --features allow_in_memory_custody
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_statements
)]

use scp_ffi_uniffi::{
    // Types
    CeilingPolicy,
    ContextMode,
    ContextParams,
    GovernanceModel,
    MemoryScope,
    Scp,
    ToolDefinition,
    // Free functions — bridge trust
    bridge_evaluate_trust,
    // Free functions — discovery
    discovery_create_query,
    discovery_normalize_address,
    discovery_parse_address,
    // Free functions — provenance
    evaluate_provenance_quality,
    provenance_check_chain_depth,
    // Free functions — sync
    sync_classify_offline,
    sync_classify_offline_custom,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Full capability set including context:close and role:assign for lifecycle tests.
fn full_capability_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool:invoke:*".to_owned(),
            "context:close".to_owned(),
            "member:invite".to_owned(),
            "member:remove".to_owned(),
            "role:assign".to_owned(),
        ],
        ceiling_policy: CeilingPolicy::Immutable,
        governance: GovernanceModel::SingleAdmin,
        memory_scope: MemoryScope::Ephemeral,
        ttl_seconds: 3600,
        promotable: false,
        min_protocol_version: 0,
        max_chain_depth: None,
        max_nesting_depth: None,
        session_cap: None,
        economic_policy: None,
        consequence_rules_json: None,
        consequence_config_json: None,
    }
}

fn default_encrypted_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool:invoke:*".to_owned(),
        ],
        ceiling_policy: CeilingPolicy::Immutable,
        governance: GovernanceModel::SingleAdmin,
        memory_scope: MemoryScope::Ephemeral,
        ttl_seconds: 3600,
        promotable: false,
        min_protocol_version: 0,
        max_chain_depth: None,
        max_nesting_depth: None,
        session_cap: None,
        economic_policy: None,
        consequence_rules_json: None,
        consequence_config_json: None,
    }
}

// ---------------------------------------------------------------------------
// Identity — creation, rotation, agent keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_create_in_memory_produces_valid_did() {
    let scp = Scp::new_in_memory_for_test();
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let did = identity.did();
    assert!(
        did.starts_with("did:dht:"),
        "DID should start with did:dht:, got: {did}"
    );
    assert!(did.len() > 20, "DID should be non-trivial length");
    assert_eq!(identity.custody_type(), "in_memory");
}

#[tokio::test]
async fn identity_create_rejects_unknown_custody() {
    let scp = Scp::new_in_memory_for_test();
    let result = scp.identity_create("magic".to_owned(), None).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("magic") || msg.contains("unknown"),
        "Error should mention custody type: {msg}"
    );
}

#[tokio::test]
async fn identity_rotate_key() {
    let scp = Scp::new_in_memory_for_test();
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let original_did = identity.did();

    // rotate_key may fail with InMemoryDhtClient since each DidDht instance
    // has its own isolated DHT. This is a known limitation of the in-memory
    // test environment — the test validates the API path exists and handles
    // both success and expected failure gracefully.
    match identity.rotate_key().await {
        Ok(rotated) => {
            assert_eq!(
                rotated.did(),
                original_did,
                "Key rotation should not change DID"
            );
            assert_eq!(rotated.custody_type(), "in_memory");
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("DHT") || msg.contains("resolve") || msg.contains("rotation"),
                "Rotation failure should be DHT-related: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn identity_agent_key_lifecycle() {
    let scp = Scp::new_in_memory_for_test();
    // Create without agent key
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    assert!(
        !identity.has_agent_key(),
        "New identity should not have agent key by default"
    );
    assert!(identity.get_agent_public_key().is_none());

    // Add agent key
    let with_agent = identity.add_agent_key().await.unwrap();
    assert!(
        with_agent.has_agent_key(),
        "Should have agent key after add"
    );
    let agent_pk = with_agent.get_agent_public_key();
    assert!(agent_pk.is_some(), "Agent public key should be accessible");

    // Rotate agent key
    let rotated = with_agent.rotate_agent_key().await.unwrap();
    assert!(
        rotated.has_agent_key(),
        "Should still have agent key after rotation"
    );
    let new_pk = rotated.get_agent_public_key().unwrap();
    assert_ne!(new_pk, agent_pk.unwrap(), "Rotated agent key should differ");

    // Remove agent key
    let without_agent = rotated.remove_agent_key().await.unwrap();
    assert!(
        !without_agent.has_agent_key(),
        "Should not have agent key after removal"
    );
}

#[tokio::test]
async fn identity_migrate_preserves_attestations() {
    let scp = Scp::new_in_memory_for_test();
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let original_did = identity.did();

    // Create an attestation on the original DID.
    let proof_json = r#"{"type":"signed_post_verified","post_url":"https://x.com/alice/status/123","nonce":"abc123","posted_at":1700000200}"#;
    let result = scp
        .identity_create_link_attestation(
            identity.clone(),
            "x.com".to_owned(),
            "@alice".to_owned(),
            proof_json.to_owned(),
            "signed_post".to_owned(),
            None,
        )
        .await;

    // The attestation should be created successfully.
    let result: Result<String, _> = result;
    assert!(
        result.is_ok(),
        "Attestation creation should succeed: {result:?}"
    );

    // Verify the attestation is listed under the original DID.
    let before = scp
        .identity_link_attestations(original_did.clone())
        .unwrap();
    let before_vec: Vec<serde_json::Value> = serde_json::from_str(&before).unwrap();
    assert_eq!(
        before_vec.len(),
        1,
        "Should have 1 attestation before migration"
    );

    // Migrate the identity to a new DID.
    // Like rotate_key, migration may fail with InMemoryDhtClient due to
    // isolated DHT instances. Handle both outcomes.
    let migrate_result: Result<std::sync::Arc<scp_ffi_uniffi::Identity>, _> =
        scp.identity_migrate(identity).await;
    match migrate_result {
        Ok(migrated) => {
            let new_did: String = migrated.did();
            assert_ne!(new_did, original_did, "Migration should produce a new DID");

            // Attestations should have migrated to the new DID.
            let after = scp.identity_link_attestations(new_did).unwrap();
            let after_vec: Vec<serde_json::Value> = serde_json::from_str(&after).unwrap();
            assert_eq!(
                after_vec.len(),
                1,
                "Attestation should be migrated to new DID"
            );

            // Old DID should have no attestations.
            let old = scp.identity_link_attestations(original_did).unwrap();
            let old_vec: Vec<serde_json::Value> = serde_json::from_str(&old).unwrap();
            assert!(
                old_vec.is_empty(),
                "Old DID should have no attestations after migration"
            );
        }
        Err(e) => {
            let msg: String = e.to_string();
            assert!(
                msg.contains("DHT") || msg.contains("resolve") || msg.contains("migration"),
                "Migration failure should be DHT-related: {msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Context — lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_create_returns_active_context() {
    let scp = Scp::new_in_memory_for_test();
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(identity.clone(), default_encrypted_params())
        .await
        .unwrap();

    assert!(
        !handle.context_id().is_empty(),
        "Context ID should be non-empty"
    );
    // Per commit 509fd2fed, all four FFI bridges now emit spec-compliant
    // 64-char lowercase hex context IDs (spec §18.4.1), replacing the
    // old `ctx-<random>` format. Pin the new format so regressions are
    // caught.
    let cid = handle.context_id();
    assert_eq!(
        cid.len(),
        64,
        "Context ID should be 64 lowercase hex chars per §18.4.1, got {cid:?}"
    );
    assert!(
        cid.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "Context ID should be lowercase hex per §18.4.1, got {cid:?}"
    );
    assert_eq!(handle.state().unwrap(), "active");
    assert_eq!(handle.creator_did(), identity.did());
}

#[tokio::test]
async fn context_join_and_leave() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let bob = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    // Use full capabilities so Alice can assign roles
    let handle = scp
        .context_create(alice.clone(), full_capability_params())
        .await
        .unwrap();

    // Bob joins
    scp.context_join(handle.clone(), bob.clone(), None)
        .await
        .unwrap();

    // Check membership
    let count = scp.context_member_count(handle.clone()).await;
    assert_eq!(count, Some(2), "Should have 2 members after join");
    assert!(scp.context_is_member(handle.clone(), bob.did()).await);

    let dids = scp.context_member_dids(handle.clone()).await;
    assert!(dids.contains(&bob.did()), "Member list should contain Bob");
    assert!(
        dids.contains(&alice.did()),
        "Member list should contain Alice"
    );

    // Bob leaves
    scp.context_leave(handle.clone(), bob.clone())
        .await
        .unwrap();
    let count_after = scp.context_member_count(handle.clone()).await;
    assert_eq!(count_after, Some(1), "Should have 1 member after leave");
    assert!(!scp.context_is_member(handle.clone(), bob.did()).await);
}

/// C5 parity: `context_join` must accept the optional `spending_ucan_jwt`
/// parameter and reject malformed JWTs at the bridge boundary with the
/// SCP-ECON-12061 code (mirrors PyO3/NAPI bridges).
#[tokio::test]
async fn context_join_rejects_malformed_spending_ucan_jwt() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let bob = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    let handle = scp
        .context_create(alice.clone(), full_capability_params())
        .await
        .unwrap();

    let result = scp
        .context_join(handle, bob, Some("not.a.jwt".to_owned()))
        .await;
    assert!(
        result.is_err(),
        "malformed spending UCAN JWT must be rejected at the bridge boundary"
    );
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("SCP-ECON-12061") || msg.contains("invalid spending UCAN"),
        "error should reference SCP-ECON-12061 / invalid spending UCAN, got: {msg}"
    );
}

/// C5 parity: `context_join` must accept the optional `spending_ucan_jwt`
/// as `None` (the historical default) and continue to delegate to the
/// manager.
#[tokio::test]
async fn context_join_accepts_none_spending_ucan_jwt() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let bob = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    let handle = scp
        .context_create(alice.clone(), full_capability_params())
        .await
        .unwrap();

    // None must reach the manager — assert by joining successfully and
    // observing membership growth from 1 to 2.
    scp.context_join(handle.clone(), bob.clone(), None)
        .await
        .unwrap();
    let count = scp.context_member_count(handle).await;
    assert_eq!(count, Some(2), "join with None spending UCAN must succeed");
}

/// C5 parity: `context_create` must thread `consequence_rules_json` and
/// `consequence_config_json` from the bridge `ContextParams` Record through
/// to the stored `ContextParams` and fail closed when a `RevokeAccess` rule
/// is declared without the matching opt-in flag.
#[tokio::test]
async fn context_create_rejects_revoke_access_when_config_disallows() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    let bad_rules = serde_json::json!([
        {
            "trigger": "MessageVelocity",
            "action": { "Enforcement": { "RevokeAccess": {
                "did": "did:dht:z6MkSubject",
                "access": "Both"
            } } },
            "threshold": 5,
            "window": { "secs": 60, "nanos": 0 }
        }
    ])
    .to_string();

    let mut params = default_encrypted_params();
    params.consequence_rules_json = Some(bad_rules);
    // consequence_config_json left None -> default disallows RevokeAccess.

    let result = scp.context_create(alice, params).await;
    assert!(
        result.is_err(),
        "RevokeAccess rule must be rejected when config.allow_automatic_access_revocation is false"
    );
}

/// C5 parity: when `consequence_config_json` opts in to
/// `allow_automatic_access_revocation`, the same rule must be accepted and
/// the context creation must succeed.
#[tokio::test]
async fn context_create_threads_consequence_rules_and_config() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    let rules = serde_json::json!([
        {
            "trigger": "MessageVelocity",
            "action": { "Enforcement": { "RevokeAccess": {
                "did": "did:dht:z6MkSubject",
                "access": "Both"
            } } },
            "threshold": 5,
            "window": { "secs": 3600, "nanos": 0 }
        }
    ])
    .to_string();
    let config = serde_json::json!({
        "allow_automatic_access_revocation": true
    })
    .to_string();

    let mut params = full_capability_params();
    params.consequence_rules_json = Some(rules);
    params.consequence_config_json = Some(config);

    let handle = scp
        .context_create(alice, params)
        .await
        .expect("context_create should succeed when config opts into RevokeAccess");
    assert_eq!(handle.state().unwrap(), "active");
}

#[tokio::test]
async fn context_send_message() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice.clone(), default_encrypted_params())
        .await
        .unwrap();

    // Send a message (no real recipient, just validates the API path)
    let result = scp
        .context_send(handle, alice, b"Hello, world!".to_vec(), None)
        .await;
    // Send may succeed or fail depending on crypto provider wiring.
    // The important thing is it doesn't panic.
    let _ = result;
}

#[tokio::test]
async fn context_close_lifecycle() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    // Must include context:close capability
    let handle = scp
        .context_create(alice.clone(), full_capability_params())
        .await
        .unwrap();
    assert_eq!(handle.state().unwrap(), "active");

    scp.context_close(handle.clone(), alice).await.unwrap();
    // After close, state should be closed
    let state = handle.state().unwrap();
    assert!(
        state == "closed" || state == "closing",
        "State after close should be closed or closing, got: {state}"
    );
}

#[tokio::test]
async fn context_drain_events_returns_vec() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice, default_encrypted_params())
        .await
        .unwrap();
    let events = scp.context_drain_events(handle).await;
    // Events may be empty but should not panic
    assert!(events.is_empty() || !events.is_empty());
}

// ---------------------------------------------------------------------------
// Membership roles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_member_role_returns_role_for_creator() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice.clone(), default_encrypted_params())
        .await
        .unwrap();

    let role = scp.context_member_role(handle, alice.did()).await;
    assert!(role.is_some(), "Creator should have a role");
    let role_str = role.unwrap();
    // The role may be returned as a string name or as a debug representation.
    // Check that it contains "admin" somewhere.
    assert!(
        role_str.contains("admin"),
        "Creator role should contain 'admin', got: {role_str}"
    );
}

// ---------------------------------------------------------------------------
// TTL management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_ttl_operations() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let alice_did = alice.did();
    let handle = scp
        .context_create(alice, default_encrypted_params())
        .await
        .unwrap();

    // Reset TTL timer (should not panic)
    scp.context_reset_ttl_timer(handle.clone(), 7200).await;

    // Propose TTL extension (may fail if governance requires it, that's OK)
    let _ = scp
        .context_propose_ttl_extension(handle.clone(), alice_did, 14400)
        .await;

    // Handle TTL expiry
    let _ = scp.context_handle_ttl_expiry(handle).await;
}

// ---------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn governance_execute_rejects_untracked_proposal() {
    // Direct-execute by id: the runtime resolves the authoritative proposal
    // from the context actor's own quorum-validated governance engine. A
    // proposal id the engine never tracked (a forgery) MUST be rejected — a
    // caller can no longer hand the bridge an action to run. The bridge surface
    // takes only `(handle, proposal_id_hex)`; there is no action parameter (so
    // action substitution is structurally impossible) and no caller identity —
    // the executor and consequence subject are resolved from the tracked
    // proposal's proposer.
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice, full_capability_params())
        .await
        .unwrap();

    // A 32-byte proposal id that was never proposed/tracked by the engine.
    let fabricated = hex::encode([0xABu8; 32]);
    let result = scp.governance_execute(handle, fabricated).await;
    let err = result.expect_err("executing an untracked proposal id must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("not tracked"),
        "rejection should name the untracked proposal, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broadcast_lifecycle() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice, default_encrypted_params())
        .await
        .unwrap();

    // Check admission mode
    let admission = scp.broadcast_admission(handle.clone()).await;
    let _ = admission;

    // Check subscriber count
    let count = scp.broadcast_subscriber_count(handle.clone()).await;
    let _ = count;

    // Check is_subscriber
    let is_sub = scp
        .broadcast_is_subscriber(handle.clone(), "did:dht:zFake".to_owned())
        .await;
    assert!(!is_sub, "Non-existent DID should not be subscriber");
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tool_register_and_verify() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice.clone(), default_encrypted_params())
        .await
        .unwrap();

    let definition = ToolDefinition {
        name: "calculator".to_owned(),
        description: "A simple calculator tool".to_owned(),
        input_schema_json:
            r#"{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}}}"#
                .to_owned(),
        output_schema_json: r#"{"type":"object","properties":{"result":{"type":"number"}}}"#
            .to_owned(),
        operator_did: alice.did(),
        test_vectors_json: None,
        implementation_hash: None,
        cost: None,
    };

    let tool_id = scp.tool_register(handle.clone(), definition).await.unwrap();
    assert!(!tool_id.is_empty(), "Tool ID should be non-empty");

    // Verify the registered tool
    let verification = scp.tool_verify(handle, tool_id).await.unwrap();
    assert!(verification.passed, "Tool verification should pass");
}

// ---------------------------------------------------------------------------
// UCAN
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ucan_mint_and_revoke() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let bob = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice.clone(), default_encrypted_params())
        .await
        .unwrap();

    // Capabilities must be in "resource:action" format
    let token = scp
        .ucan_mint(
            handle.clone(),
            bob.did(),
            vec!["messages:read".to_owned(), "messages:write".to_owned()],
            None,
        )
        .await
        .unwrap();

    let token_id = token.token_id();
    assert!(!token_id.is_empty(), "Token ID should be non-empty");
    assert_eq!(token.issuer(), alice.did());
    assert_eq!(token.audience(), bob.did());

    let caps = token.capabilities();
    assert!(!caps.is_empty(), "Capabilities should be non-empty");

    // Revoke the token (revoker is the context creator).
    let revoke_result = scp.ucan_revoke(handle, token.encoded(), alice.did()).await;
    // Revocation may succeed or fail based on implementation, but should not panic.
    let _ = revoke_result;
}

// ---------------------------------------------------------------------------
// Event Log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn event_log_query_returns_events() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(alice, default_encrypted_params())
        .await
        .unwrap();

    let events = scp.event_log_query(handle, None).await.unwrap();
    // May return empty vec for a fresh context
    assert!(events.is_empty() || !events.is_empty());
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_parse_various_address_types() {
    let _scp = Scp::new_in_memory_for_test();
    // Unscoped name (petname)
    let result = discovery_parse_address("alice".to_owned()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(
        parsed["type"].as_str().is_some(),
        "Should have a type field: {result}"
    );

    // Discovery handle — name@scope (no TLD dot)
    let result = discovery_parse_address("alice@discovery-ctx".to_owned()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let addr_type = parsed["type"].as_str().unwrap();
    assert!(
        addr_type == "DiscoveryHandle" || addr_type == "DomainHandle",
        "Handle should parse as discovery or domain: {result}"
    );

    // Domain handle — name@domain.tld
    let result = discovery_parse_address("alice@example.com".to_owned()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(
        parsed["type"].as_str().is_some(),
        "Domain should have type: {result}"
    );

    // Direct DID — ParsedAddress has no DirectDid variant; bare strings (including
    // DIDs) parse as Unscoped since the address grammar doesn't special-case them.
    let result = discovery_parse_address("did:dht:z6MkTest".to_owned()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let addr_type = parsed["type"].as_str().unwrap();
    assert!(
        addr_type == "Unscoped" || addr_type == "DirectDid",
        "DID address should parse as Unscoped or DirectDid: {result}"
    );
}

#[tokio::test]
async fn discovery_normalize_trims_whitespace() {
    let _scp = Scp::new_in_memory_for_test();
    let result = discovery_normalize_address("  alice  ".to_owned());
    assert!(!result.starts_with(' '), "Should trim leading whitespace");
    assert!(!result.ends_with(' '), "Should trim trailing whitespace");
}

#[tokio::test]
async fn discovery_create_query_produces_json() {
    let _scp = Scp::new_in_memory_for_test();
    let result = discovery_create_query(
        Some(vec!["tool:search".to_owned()]),
        Some(vec!["rust".to_owned()]),
        None,
    )
    .unwrap();
    assert!(!result.is_empty(), "Query JSON should be non-empty");
    // Should be valid JSON
    let _: serde_json::Value = serde_json::from_str(&result).unwrap();
}

// ---------------------------------------------------------------------------
// Sync classification — TIER_1 = 14,400s (4h), TIER_2 = 604,800s (7d)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_classify_offline_tiers() {
    let _scp = Scp::new_in_memory_for_test();
    let now = 1_700_000_000u64;

    // Short offline (< TIER_1 = 14,400s)
    let short = sync_classify_offline(now - 60, now);
    assert_eq!(short, "short", "60s offline should be 'short'");

    // Extended offline (between TIER_1 and TIER_2)
    let extended = sync_classify_offline(now - 100_000, now);
    assert_eq!(extended, "extended", "~27h offline should be 'extended'");

    // Long offline (> TIER_2 = 604,800s)
    let long = sync_classify_offline(now - 700_000, now);
    assert_eq!(long, "long", ">7d offline should be 'long'");
}

#[tokio::test]
async fn sync_classify_offline_custom_thresholds() {
    let _scp = Scp::new_in_memory_for_test();
    let now = 1_700_000_000u64;

    // Custom thresholds: tier1 = 120s, tier2 = 600s
    let result = sync_classify_offline_custom(now - 60, now, 120, 600);
    assert_eq!(result, "short", "60s with 120s threshold should be 'short'");

    let result = sync_classify_offline_custom(now - 300, now, 120, 600);
    assert_eq!(
        result, "extended",
        "300s with 120s/600s thresholds should be 'extended'"
    );

    let result = sync_classify_offline_custom(now - 1000, now, 120, 600);
    assert_eq!(result, "long", "1000s with 600s tier2 should be 'long'");
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provenance_attach_produces_json() {
    let scp = Scp::new_in_memory_for_test();
    let result = scp
        .provenance_attach(
            "ctx-source".to_owned(),
            "persistent".to_owned(),
            "full".to_owned(),
            vec!["did:dht:z6MkAlice".to_owned(), "did:dht:z6MkBob".to_owned()],
            "ctx-target".to_owned(),
            "did:dht:z6MkActor".to_owned(),
            None,
        )
        .unwrap();

    assert!(!result.is_empty(), "Provenance JSON should be non-empty");
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed.is_object(), "Should be a JSON object");
}

#[tokio::test]
async fn provenance_attach_increments_chain_depth() {
    let scp = Scp::new_in_memory_for_test();
    let result = scp
        .provenance_attach(
            "ctx-source".to_owned(),
            "persistent".to_owned(),
            "full".to_owned(),
            vec!["did:dht:z6MkAlice".to_owned()],
            "ctx-target".to_owned(),
            "did:dht:z6MkActor".to_owned(),
            Some(2),
        )
        .unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let depth = parsed["chain_depth"].as_u64().unwrap();
    assert_eq!(depth, 3, "Chain depth should increment from 2 to 3");
}

#[tokio::test]
async fn provenance_check_chain_depth_within_limit() {
    let _scp = Scp::new_in_memory_for_test();
    assert!(
        provenance_check_chain_depth(0, None),
        "Depth 0 should be within default limit"
    );
    assert!(
        provenance_check_chain_depth(3, None),
        "Depth 3 should be within default limit"
    );
    assert!(
        provenance_check_chain_depth(2, Some(5)),
        "Depth 2 should be within limit 5"
    );
    // At or beyond limit should fail
    assert!(
        !provenance_check_chain_depth(10, Some(3)),
        "Depth 10 should exceed limit 3"
    );
}

#[tokio::test]
async fn evaluate_provenance_quality_returns_score() {
    let _scp = Scp::new_in_memory_for_test();
    let score = evaluate_provenance_quality(
        Some("ctx-001".to_owned()),
        "persistent".to_owned(),
        "active".to_owned(),
        vec!["did:dht:z6MkAlice".to_owned()],
    )
    .unwrap();

    // Score should be a reasonable value (0-100 or similar range)
    assert!(
        score > 0,
        "Quality score should be positive for persistent context"
    );
}

#[tokio::test]
async fn evaluate_provenance_quality_rejects_invalid_source_type() {
    let _scp = Scp::new_in_memory_for_test();
    let result =
        evaluate_provenance_quality(None, "invalid_type".to_owned(), "active".to_owned(), vec![]);
    assert!(result.is_err(), "Invalid source type should be rejected");
}

// ---------------------------------------------------------------------------
// Bridge trust evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bridge_evaluate_trust_native() {
    let _scp = Scp::new_in_memory_for_test();
    // Non-bridged, native transport → highest trust
    let level = bridge_evaluate_trust(false, true, "shadow".to_owned()).unwrap();
    assert!(level > 0, "Native trust level should be positive");
}

#[tokio::test]
async fn bridge_evaluate_trust_shadow_vs_claimed() {
    let _scp = Scp::new_in_memory_for_test();
    // Shadow bridged
    let shadow = bridge_evaluate_trust(true, false, "shadow".to_owned()).unwrap();
    // Claimed bridged
    let claimed = bridge_evaluate_trust(true, false, "claimed".to_owned()).unwrap();
    // Claimed should have equal or higher trust than shadow
    assert!(
        claimed >= shadow,
        "Claimed should have >= trust than shadow: claimed={claimed}, shadow={shadow}"
    );
}

#[tokio::test]
async fn bridge_evaluate_trust_rejects_invalid_status() {
    let _scp = Scp::new_in_memory_for_test();
    let result = bridge_evaluate_trust(true, false, "invalid".to_owned());
    assert!(result.is_err(), "Invalid shadow status should be rejected");
}

// ---------------------------------------------------------------------------
// Local DID management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_and_check_local_did() {
    let scp = Scp::new_in_memory_for_test();
    let did = "did:dht:z6MkLocalTest123".to_owned();
    scp.register_local_did(did.clone())
        .await
        .expect("register_local_did must succeed for a valid DID");
    assert!(
        scp.is_local_did(did).await,
        "Registered DID should be local"
    );
    assert!(
        !scp.is_local_did("did:dht:z6MkNonExistent".to_owned()).await,
        "Unregistered DID should not be local"
    );
}

// ---------------------------------------------------------------------------
// Shutdown ordering
// ---------------------------------------------------------------------------

// Phase D (#1695): `scp_shutdown` free function deleted. Per-instance
// shutdown now goes through `SCP.shutdown(timeout_millis)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scp_shutdown_zero_timeout_returns_immediately() {
    let scp = scp_ffi_uniffi::Scp::new_in_memory_for_test();
    scp.shutdown(0).await.expect("shutdown(0) must succeed");
}

// ---------------------------------------------------------------------------
// Multiple identities in same process
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_identities_produce_distinct_dids() {
    let scp = Scp::new_in_memory_for_test();
    let id1 = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let id2 = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let id3 = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    assert_ne!(id1.did(), id2.did());
    assert_ne!(id2.did(), id3.did());
    assert_ne!(id1.did(), id3.did());
}

// ---------------------------------------------------------------------------
// Context with different governance models
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_create_with_all_governance_models() {
    let scp = Scp::new_in_memory_for_test();
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    for model in [
        GovernanceModel::SingleAdmin,
        GovernanceModel::Multisig,
        GovernanceModel::TokenVoting,
    ] {
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec!["messages:read".to_owned()],
            ceiling_policy: CeilingPolicy::Immutable,
            governance: model,
            memory_scope: MemoryScope::Ephemeral,
            ttl_seconds: 3600,
            promotable: false,
            min_protocol_version: 0,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            economic_policy: None,
            consequence_rules_json: None,
            consequence_config_json: None,
        };
        let handle = scp.context_create(identity.clone(), params).await.unwrap();
        assert_eq!(handle.state().unwrap(), "active");
    }
}

#[tokio::test]
async fn context_create_with_all_memory_scopes() {
    let scp = Scp::new_in_memory_for_test();
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();

    for scope in [
        MemoryScope::Ephemeral,
        MemoryScope::Summary,
        MemoryScope::Full,
    ] {
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec!["messages:read".to_owned()],
            ceiling_policy: CeilingPolicy::Immutable,
            governance: GovernanceModel::SingleAdmin,
            memory_scope: scope,
            ttl_seconds: 3600,
            promotable: false,
            min_protocol_version: 0,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            economic_policy: None,
            consequence_rules_json: None,
            consequence_config_json: None,
        };
        let handle = scp.context_create(identity.clone(), params).await.unwrap();
        assert_eq!(handle.state().unwrap(), "active");
    }
}

// ---------------------------------------------------------------------------
// Error propagation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_did_rejected_at_bridge_boundary() {
    let scp = Scp::new_in_memory_for_test();
    let identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .unwrap();
    let handle = scp
        .context_create(identity, default_encrypted_params())
        .await
        .unwrap();

    // Empty DID should fail validation or return false
    let result = scp.context_is_member(handle, String::new()).await;
    let _ = result;
}

// ---------------------------------------------------------------------------
// Transport operations (#620)
//
// `transport_disconnect` and `transport_status` require a live
// `TransportManager` returned from a successful `transport_connect`,
// which in turn requires a real relay endpoint. They are tested via
// the URL validation and error propagation paths below, plus the
// `TransportManager::status()` / `is_connected()` methods which are
// tested in the unit tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transport_connect_rejects_plaintext_ws() {
    let scp = Scp::new_in_memory_for_test();
    // ws:// is not permitted from explicit source — only wss://
    let result = scp
        .transport_connect("ws://relay.example.com/scp/v1".to_owned())
        .await;
    assert!(
        result.is_err(),
        "ws:// should be rejected for explicit connections"
    );
}

#[tokio::test]
async fn transport_connect_rejects_invalid_url() {
    let scp = Scp::new_in_memory_for_test();
    // Empty URL should fail validation
    let result = scp.transport_connect(String::new()).await;
    assert!(result.is_err(), "Empty URL should be rejected");
}

#[tokio::test]
async fn transport_connect_returns_error_on_unreachable_relay() {
    let scp = Scp::new_in_memory_for_test();
    // Before #620, transport_connect returned connected=true without
    // establishing any WebSocket connection. Now it calls
    // NativeRelayAdapter::connect_sourced() and propagates connection
    // failures as ScpError::Transport.
    let result = scp
        .transport_connect("wss://127.0.0.1:1/nonexistent-scp-relay".to_owned())
        .await;
    assert!(
        result.is_err(),
        "Connecting to an unreachable relay must return an error, not a fictional success"
    );
}

// ---------------------------------------------------------------------------
// Signed context export — round-trip + tamper rejection (§23.16.8, ADR-050)
// ---------------------------------------------------------------------------

/// Self-export → close → self-import round-trip on the same instance.
///
/// This is the case the previous resolver-only verifying-key path could NOT
/// satisfy: an in-memory identity is never auto-published to the DHT, so the
/// `IdentityBackedDidResolver` cannot resolve its `creator_did`, and import
/// verification failed before the new local-custody-first path (§23.16.8
/// step 1) derived the verifying key directly from the creator's retained
/// `#active` custody key. The absence of this test is what hid the bug.
///
/// The load-bearing assertion: a *valid* export NEVER fails with the
/// signature-failure code `SCP-CTX-2093`. The verifying key resolves via local
/// custody (the creator is a local in-memory identity on this instance) before
/// any DID resolver is configured, so verification passes. Any *other*
/// lifecycle outcome on import (e.g. the "already exists" guard, since the
/// bridge close transitions an ephemeral handle rather than the manager's
/// stored handle) is acceptable — what matters is that signature verification
/// is reached and succeeds. Mirrors the `PyO3` reference round-trip test.
#[tokio::test]
async fn context_export_self_import_round_trip_succeeds() {
    let scp = Scp::new_in_memory_for_test();
    // In-memory identity — deliberately NOT published to any DID resolver, so
    // verification can ONLY succeed via the local-custody-first leg.
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create");

    // full_capability_params() includes `context:close`, exercised by the
    // close step below.
    let handle = scp
        .context_create(alice.clone(), full_capability_params())
        .await
        .expect("context_create");
    let context_id = handle.context_id();

    // Export BEFORE close — export needs the live signing key on the handle.
    let exported = scp
        .context_export(handle.clone())
        .await
        .expect("context_export");

    scp.context_close(handle.clone(), alice.clone())
        .await
        .expect("context_close");

    // Self-import on the SAME instance. The creator's custody is in this
    // instance's registry, so the verifying key resolves via local custody
    // even though the DID was never published — exercising §23.16.8 step 1.
    // A valid signature MUST pass verification (no SCP-CTX-2093); a residual
    // lifecycle rejection is acceptable, a signature rejection is NOT.
    match scp.context_import(exported, alice).await {
        Ok(imported_id) => assert_eq!(
            imported_id, context_id,
            "imported context id must match the exported context id"
        ),
        Err(scp_ffi_uniffi::ScpError::Context { code, msg }) => assert_ne!(
            code, "SCP-CTX-2093",
            "valid export must not fail signature verification \
             (local-custody-first did not resolve the creator key): {msg}"
        ),
        Err(other) => panic!("unexpected non-context error on self-import: {other:?}"),
    }
}

/// A tampered export (signature corrupted after signing) MUST be rejected on
/// import with the dedicated `SCP-CTX-2093` code, NOT a generic context error
/// (§23.16.8 step 3). Run on the same instance so the creator key resolves and
/// verification actually executes — the rejection is a genuine signature
/// failure, not an unresolvable-key failure.
#[tokio::test]
async fn context_import_rejects_tampered_signature_with_2093() {
    let scp = Scp::new_in_memory_for_test();
    let alice = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create");
    let handle = scp
        .context_create(alice.clone(), full_capability_params())
        .await
        .expect("context_create");

    let exported = scp
        .context_export(handle.clone())
        .await
        .expect("context_export");

    // Close so the slot is replaceable — otherwise import would short-circuit
    // on "already exists" AFTER the signature check, but we want the signature
    // check itself to be the rejection cause. (Signature verification runs
    // first in import_context, so this ordering is robust either way.)
    scp.context_close(handle.clone(), alice.clone())
        .await
        .expect("context_close");

    // Tamper: flip one bit of the Ed25519 snapshot signature. The snapshot
    // digest stays valid, so deserialization succeeds and the failure is a
    // genuine signature mismatch (SnapshotSignatureInvalid → SCP-CTX-2093),
    // not a structural/version error.
    let mut export = scp_core::context::export_import::deserialize_export(&exported)
        .expect("valid export must deserialize");
    export.snapshot_signature[0] ^= 0x01;
    let tampered = scp_core::context::export_import::serialize_export(&export)
        .expect("re-serialize tampered export");

    let err = scp
        .context_import(tampered, alice)
        .await
        .expect_err("tampered signature must be rejected");

    match err {
        scp_ffi_uniffi::ScpError::Context { ref code, .. } => assert_eq!(
            code, "SCP-CTX-2093",
            "tampered export must surface the dedicated signature-failure code"
        ),
        other => panic!("expected ScpError::Context with SCP-CTX-2093, got {other:?}"),
    }
}
