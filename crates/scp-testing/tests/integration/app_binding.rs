#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

//! Integration tests for AppBound / AppUnbound durable event-log appends (spec §8.4).
//!
//! These tests verify the critical fix: `bind_app` and `unbind_app` MUST use the
//! same [`ContextEventLogProvider`] instance whose `logs` map was populated by
//! `init_event_log` during context creation, not a freshly constructed one.
//!
//! The root cause of the original bug was that all three FFI bridges were
//! calling `build_event_log_provider(bi)` (or `bi.protocol_repository.event_log_provider()`)
//! to obtain a FRESH `MerkleEventLogProvider` whose in-memory `logs` map was
//! empty — so every `append_event` would fail with "log not initialised" and
//! the AppBound/AppUnbound events were silently lost.
//!
//! The fix: call `Supervisor::event_log_provider_arc()` so all three bridges
//! share the ONE provider instance the Supervisor holds in its `event_log`
//! [`OnceLock`].
//!
//! Sources: spec §8.4 (App Sandbox) · error code CTX-2057.

use scp_core::context::app_sandbox::{
    CapabilityDeclaration, CapabilityEntry, bind_app, sign_declaration, unbind_app,
};
use scp_core::context::state::context_id_to_bytes;
use scp_core::context::{Capability, ContextParams};
use scp_did::DID;
use scp_event_log::EventType;
use scp_testing::fullstack::FullStackNetwork;

// DIDs for the actor and an app publisher. Both are fixed strings so this
// test is deterministic and doesn't require any DID resolution infrastructure.
const ACTOR_DID: &str = "did:dht:z6MkAppBindTestNode";
const CONTEXT_ID: &str = "app-binding-integration-ctx";

/// Generates an ephemeral Ed25519 signing key and derives a `did:dht:` DID
/// from the public key.  `did_dht_from_public_key` is the single canonical
/// encoder so this matches what `extract_ed25519_pubkey_from_did` decodes when
/// verifying the declaration signature.
fn app_signing_key_and_did() -> (ed25519_dalek::SigningKey, DID) {
    use rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let app_did = scp_did::did_dht_from_public_key(&pubkey_bytes);
    (signing_key, app_did)
}

// ---------------------------------------------------------------------------
// Test 1: bind_app writes AppBound to the supervisor's shared event log
// ---------------------------------------------------------------------------

/// Verifies that calling `bind_app` with the supervisor's shared
/// `event_log_provider_arc()` results in an `AppBound` event visible through
/// `Supervisor::event_log_entries`.
///
/// This is the primary regression test for the "always-uninitialized provider"
/// blocker: if bind_app uses a fresh provider, the append silently fails and
/// no `AppBound` event is written — this assertion would then fail.
#[tokio::test]
async fn bind_app_writes_appbound_event() {
    // 1. Stand up a real Supervisor node with real MLS crypto.
    let network = FullStackNetwork::new();
    let alice = network.create_node(ACTOR_DID);

    // 2. Create a context with a capability ceiling that includes `MessagesRead`
    //    — this is what CapabilityEntry { resource: ".../messaging", actions: ["read"] }
    //    maps to via CapabilityEntry::to_capabilities().
    let params = ContextParams {
        ceiling: vec![Capability::MessagesRead],
        ..ContextParams::default()
    };
    let handle = alice
        .create_context(CONTEXT_ID, params)
        .await
        .expect("create_context must succeed");

    // 3. Generate an ephemeral app keypair and build a minimal signed declaration.
    let (signing_key, app_did) = app_signing_key_and_did();
    let mut declaration = CapabilityDeclaration {
        scp_version: "1.0".to_owned(),
        app_id: app_did.clone(),
        app_name: "Integration Test App".to_owned(),
        app_version: "1.0.0".to_owned(),
        capabilities: vec![CapabilityEntry {
            // category "messaging", action "read" → Capability::MessagesRead
            resource: format!("scp:ctx:{CONTEXT_ID}/messaging"),
            actions: vec!["read".to_owned()],
            constraints: None,
        }],
        min_role: "member".to_owned(),
        signature: Vec::new(),
    };
    sign_declaration(&mut declaration, &signing_key)
        .expect("sign_declaration must not fail on valid inputs");

    // 4. Obtain the supervisor's shared event-log provider.
    //    CRITICAL: this is the SAME Arc<dyn ContextEventLogProvider> whose
    //    underlying `MerkleEventLogProvider` had its `logs` map populated by
    //    `init_event_log` during `create_context`.  A freshly constructed
    //    provider would have an empty map and all appends would fail.
    let event_log = alice
        .manager
        .event_log_provider_arc()
        .expect("Supervisor must hold an event-log provider after create_context");

    // 5. Define context ceiling and role capabilities — both must cover
    //    `MessagesRead` for `validate_declaration` to accept the request.
    let ceiling = [Capability::MessagesRead];
    let role_caps = [Capability::MessagesRead];

    // 6. Call bind_app.  If `event_log` is the wrong provider instance this
    //    call still succeeds (the append path is fallible but not fatal here)
    //    but the event won't appear in the supervisor's shared log.
    bind_app(
        &declaration,
        &ceiling,
        &role_caps,
        handle,
        event_log.as_ref(),
        ACTOR_DID,
        1_700_000_000,
    )
    .await
    .expect("bind_app must succeed");

    // 7. Query the supervisor's shared event log and assert the AppBound event
    //    is present — this fails if bind_app used the wrong (fresh) provider.
    let context_key = context_id_to_bytes(CONTEXT_ID);
    let events = alice
        .manager
        .event_log_entries(&context_key)
        .expect("event_log_entries must not return Err")
        .expect("event log must be initialised after create_context");

    let has_app_bound = events.iter().any(|e| e.event_type == EventType::AppBound);
    assert!(
        has_app_bound,
        "AppBound (tag 74) event must be present in the supervisor's durable \
         event log after bind_app; got {} events with types: {:?}",
        events.len(),
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Test 2: unbind_app writes AppUnbound after bind_app
// ---------------------------------------------------------------------------

/// Full bind→unbind round trip: verifies that `unbind_app` writes an
/// `AppUnbound` event to the same shared event log, visible after the
/// `AppBound` event from a preceding `bind_app`.
#[tokio::test]
async fn unbind_app_writes_appunbound_event_after_bind() {
    let network = FullStackNetwork::new();
    let alice = network.create_node(ACTOR_DID);

    let params = ContextParams {
        ceiling: vec![Capability::MessagesRead],
        ..ContextParams::default()
    };
    let handle = alice
        .create_context(CONTEXT_ID, params)
        .await
        .expect("create_context must succeed");

    let (signing_key, app_did) = app_signing_key_and_did();
    let mut declaration = CapabilityDeclaration {
        scp_version: "1.0".to_owned(),
        app_id: app_did.clone(),
        app_name: "Roundtrip Test App".to_owned(),
        app_version: "0.1.0".to_owned(),
        capabilities: vec![CapabilityEntry {
            resource: format!("scp:ctx:{CONTEXT_ID}/messaging"),
            actions: vec!["read".to_owned()],
            constraints: None,
        }],
        min_role: "member".to_owned(),
        signature: Vec::new(),
    };
    sign_declaration(&mut declaration, &signing_key)
        .expect("sign_declaration must not fail on valid inputs");

    let event_log = alice
        .manager
        .event_log_provider_arc()
        .expect("Supervisor must hold an event-log provider after create_context");

    let ceiling = [Capability::MessagesRead];
    let role_caps = [Capability::MessagesRead];

    // Bind first.
    bind_app(
        &declaration,
        &ceiling,
        &role_caps,
        handle,
        event_log.as_ref(),
        ACTOR_DID,
        1_700_000_000,
    )
    .await
    .expect("bind_app must succeed");

    // Then unbind.
    unbind_app(
        CONTEXT_ID,
        app_did.as_ref(),
        event_log.as_ref(),
        ACTOR_DID,
        1_700_000_001,
    )
    .await
    .expect("unbind_app must succeed");

    // Both AppBound and AppUnbound must now be visible in the shared log.
    let context_key = context_id_to_bytes(CONTEXT_ID);
    let events = alice
        .manager
        .event_log_entries(&context_key)
        .expect("event_log_entries must not return Err")
        .expect("event log must be initialised");

    let has_app_bound = events.iter().any(|e| e.event_type == EventType::AppBound);
    let has_app_unbound = events.iter().any(|e| e.event_type == EventType::AppUnbound);

    assert!(
        has_app_bound,
        "AppBound event must be present before AppUnbound; \
         got {} events: {:?}",
        events.len(),
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
    assert!(
        has_app_unbound,
        "AppUnbound (tag 75) event must be present after unbind_app; \
         got {} events: {:?}",
        events.len(),
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}
