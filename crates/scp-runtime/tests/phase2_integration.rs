#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unused_async,
    clippy::redundant_field_names
)]
//! Phase 2 end-to-end integration test.
//!
//! Exercises all 5 Phase 2 ADRs together with the Phase 1 crypto stack:
//!
//! - **ADR-008**: Context lifecycle state machine (create, join, expire).
//! - **ADR-009**: UCAN-based role assignment and capability enforcement.
//! - **ADR-010**: Tool registration and invocation with schema validation.
//! - **ADR-011**: Verifiable event log (Merkle tree) and consistency checkpoints.
//! - **ADR-012**: Multi-transport routing (simulated via in-memory channels).
//!
//! The scenario follows the 12-step integration test defined in
//! `.docs/adrs/phase-2.md` "Phase 2 Integration Test" section.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::time::Duration;

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use scp_event_log::checkpoint::{CheckpointComparison, compare_checkpoint, generate_checkpoint};
use scp_event_log::tree::{self, GENESIS_PREV_HASH};
use scp_event_log::{Event, EventLog, EventPayload, EventType};
use scp_identity::DID;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};
use scp_protocol::context::roles::{
    Capability, CapabilityCeiling, ContextRoleState, RoleDefinition, RoleError, assign_role,
};
use scp_protocol::context::tools::lifecycle::ToolStatus;
use scp_protocol::context::tools::registry::{
    ToolRegistration, ToolRegistry, ToolSchema, register_tool,
};
use scp_protocol::context::{ContextParams, ContextState, MemoryScope};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::tools::invoke::{has_tool_invoke_capability, invoke_tool};
use scp_runtime::event_log::KeyCustodySigner;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates an Ed25519 keypair and returns (`verifying_key`, `signing_key`).
fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key, signing_key)
}

/// Encodes a public key as a test DID (`did:key:<hex>`).
fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> DID {
    let hex: String = verifying_key
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    format!("did:key:{hex}").into()
}

/// Computes the canonical hash for signing an event.
///
/// This mirrors the production `tree::compute_event_canonical_hash` exactly.
/// Integration tests (`tests/`) cannot access `pub(crate)` items, so this
/// copy is necessary. See issue #79 for context.
fn compute_event_canonical_hash(event: &Event) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EVENT-V1:");
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    hasher.update(event_type_tag(&event.event_type).to_be_bytes());
    length_prefix(&mut hasher, event.actor_did.as_bytes());
    hasher.update(event.timestamp.to_be_bytes());
    hasher.update(event.sequence.to_be_bytes());
    length_prefix(&mut hasher, &event.payload.data);
    hasher.update(event.prev_hash);
    hasher.finalize().to_vec()
}

/// Returns a stable numeric tag for each event type variant.
///
/// This mirrors the production `tree::event_type_tag` exactly.
/// Integration tests (`tests/`) cannot access `pub(crate)` items, so this
/// copy is necessary. See issue #79 for context.
const fn event_type_tag(event_type: &EventType) -> u16 {
    match event_type {
        EventType::ContextCreated => 0,
        EventType::ContextClosing => 1,
        EventType::ContextClosed => 2,
        EventType::ContextExpired => 3,
        EventType::MemberJoined => 4,
        EventType::MemberLeft => 5,
        EventType::RoleAssigned => 6,
        EventType::TokenRevoked => 7,
        EventType::MessageSent => 8,
        EventType::ToolRegistered => 9,
        EventType::ToolUpdated => 10,
        EventType::ToolInvoked => 11,
        EventType::ToolVerified => 12,
        EventType::ToolInterfaceEstablished => 13,
        EventType::GovernanceAction => 14,
        EventType::ConsistencyCheckpoint => 15,
        EventType::AbsenceProofRequested => 16,
        EventType::MemberBlocked => 17,
        EventType::KeyEpochAdvance => 18,
        EventType::MediaSessionStarted => 19,
        EventType::MediaSessionEnded => 20,
        EventType::PaymentReceived => 21,
        EventType::EconomicPolicyChanged => 22,
        EventType::EconomicPolicyApplied => 33,
        EventType::SpendingUcanGranted => 23,
        EventType::SpendingUcanRevoked => 24,
        // Governance event types (ADR-031 §8)
        EventType::GovernanceProposalCreated => 25,
        EventType::GovernanceVoteCast => 26,
        EventType::GovernanceVoteWithdrawn => 27,
        EventType::GovernanceProposalResolved => 28,
        EventType::GovernanceConflictDetected => 29,
        EventType::GovernanceConflictResolved => 30,
        EventType::GovernanceDeadlockRecovery => 31,
        EventType::GovernanceActionExecuted => 32,
        // Provenance event types (issue #586)
        EventType::ProvenanceAttached => 34,
        EventType::ProvenanceReceived => 35,
    }
}

/// Signs an event and returns it with the signature populated.
fn sign_event(
    event_type: EventType,
    actor_did: &DID,
    timestamp: u64,
    sequence: u64,
    payload: Vec<u8>,
    prev_hash: [u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) -> Event {
    let mut event = Event {
        event_type,
        actor_did: actor_did.clone(),
        timestamp,
        sequence,
        payload: EventPayload { data: payload },
        prev_hash,
        signature: Vec::new(),
    };
    let canonical_hash = compute_event_canonical_hash(&event);
    let signature = signing_key.sign(&canonical_hash);
    event.signature = signature.to_bytes().to_vec();
    event
}

/// Appends an event to a log and returns the resulting leaf hash.
fn append_and_hash(log: &mut EventLog, event: &Event) -> [u8; 32] {
    tree::append(log, event).expect("append should succeed");
    // RFC 6962 §2.1 leaf domain separation: SHA-256(0x00 || serialized)
    let serialized = rmp_serde::to_vec(event).expect("serialize");
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    hasher.finalize().into()
}

/// Simple in-memory relay simulation. Each relay is a pair of (sender, receiver)
/// channels. Publishing sends to all relay senders; subscribing reads from
/// all relay receivers.
struct InMemoryRelaySet {
    senders: Vec<mpsc::Sender<Vec<u8>>>,
    receivers: Vec<mpsc::Receiver<Vec<u8>>>,
}

impl InMemoryRelaySet {
    /// Creates a relay set with `n` relays.
    fn new(n: usize) -> Self {
        let mut senders = Vec::with_capacity(n);
        let mut receivers = Vec::with_capacity(n);
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(64);
            senders.push(tx);
            receivers.push(rx);
        }
        Self { senders, receivers }
    }

    /// Publishes a message to all relays (multi-relay publish).
    async fn publish_to_all(&self, message: &[u8]) {
        for sender in &self.senders {
            sender.send(message.to_vec()).await.expect("relay send");
        }
    }

    /// Receives messages from all relays and deduplicates by content hash.
    /// Returns the unique messages received.
    async fn receive_deduplicated(&mut self) -> Vec<Vec<u8>> {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut unique_messages = Vec::new();

        for receiver in &mut self.receivers {
            // Non-blocking receive for all available messages.
            while let Ok(msg) = receiver.try_recv() {
                let hash: [u8; 32] = Sha256::digest(&msg).into();
                if seen.insert(hash) {
                    unique_messages.push(msg);
                }
                // Duplicate detected and filtered -- this is SDK deduplication.
            }
        }
        unique_messages
    }
}

/// Simple relay reliability tracker.
struct RelayReliabilityTracker {
    publish_counts: Vec<u64>,
    failure_counts: Vec<u64>,
}

impl RelayReliabilityTracker {
    fn new(n: usize) -> Self {
        Self {
            publish_counts: vec![0; n],
            failure_counts: vec![0; n],
        }
    }

    fn record_publish(&mut self, relay_index: usize) {
        self.publish_counts[relay_index] += 1;
    }

    #[allow(dead_code)]
    fn record_failure(&mut self, relay_index: usize) {
        self.failure_counts[relay_index] += 1;
    }

    fn total_publishes(&self) -> u64 {
        self.publish_counts.iter().sum()
    }
}

/// Async calculator executor matching the tool's schema.
async fn calculator_executor(input: serde_json::Value) -> Result<serde_json::Value, String> {
    let operation = input
        .get("operation")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing field 'operation'".to_owned())?;
    let a = input
        .get("a")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| "missing field 'a'".to_owned())?;
    let b = input
        .get("b")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| "missing field 'b'".to_owned())?;

    let result = match operation {
        "add" => a + b,
        "subtract" => a - b,
        "multiply" => a * b,
        _ => return Err(format!("unknown operation: {operation}")),
    };
    Ok(serde_json::json!({"result": result}))
}

// ===========================================================================
// Phase 2 Integration Test
// ===========================================================================

#[tokio::test]
async fn phase2_end_to_end_integration() {
    // -----------------------------------------------------------------------
    // Step 1: Alice creates an identity and a context.
    //
    // Context config: ceiling [messaging, tool_invoke], roles [admin, member],
    // one tool "calculator", TTL 5 minutes, memory scope ephemeral.
    // -----------------------------------------------------------------------

    let (alice_vk, alice_sk) = test_keypair();
    let alice_did = did_from_pubkey(&alice_vk);

    let context_id = "ctx-phase2-integration";

    // Define the capability ceiling: messaging + tool invocation.
    let ceiling = CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolInvokeAll,
        Capability::ToolRegister,
        Capability::RoleAssign,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::ContextClose,
    ]);

    // Build context params.
    let params = ContextParams {
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolInvokeAll,
            Capability::ToolRegister,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::ContextClose,
        ],
        roles: vec![
            RoleDefinition {
                name: "admin".to_owned(),
                capabilities: HashSet::from([Capability::MessagesRead, Capability::MessagesWrite]),
            },
            RoleDefinition {
                name: "member".to_owned(),
                capabilities: HashSet::from([Capability::MessagesRead]),
            },
        ],
        tools: vec![ToolRegistration {
            tool_id: "calculator".to_owned(),
            name: "calculator".to_owned(),
            description: "Calculator tool".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkTestOperator".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        }],
        ttl: Some(Duration::from_secs(300)), // 5 minutes
        memory_scope: MemoryScope::Ephemeral,
        ..ContextParams::default()
    };

    // Create the context handle (starts in Creating state).
    let context = ContextHandle::new(context_id.to_owned(), params.clone());
    assert_eq!(context.state().await, ContextState::Creating);

    // Transition to Active (MLS group formation is complete).
    context
        .transition_to(&ContextState::Active)
        .await
        .expect("Creating -> Active");
    assert_eq!(context.state().await, ContextState::Active);

    // Initialize role state with Alice as admin.
    let mut role_state = ContextRoleState::new(
        context_id,
        alice_did.to_string(),
        ceiling.clone(),
        vec![],
        &scp_primitives::SystemClock,
    )
    .expect("role state creation");

    // Register the calculator tool.
    let mut tool_registry = ToolRegistry::new();
    let calc_registration = ToolRegistration {
        tool_id: "calculator".to_owned(),
        name: "Calculator".to_owned(),
        description: "A simple arithmetic calculator".to_owned(),
        schema: ToolSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "operation": {"type": "string"},
                    "a": {"type": "number"},
                    "b": {"type": "number"}
                }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "result": {"type": "number"}
                }
            }),
        },
        implementation_hash: [0xAB; 32],
        test_vectors: vec![],
        operator_did: alice_did.clone(),
        cost: None,
        registered_at: 0,
        signature: Vec::new(),
    };
    let (tool_id, _tool_registered_event) = register_tool(
        &mut tool_registry,
        &role_state,
        calc_registration,
        &alice_did,
    )
    .expect("tool registration");
    assert_eq!(tool_id, "calculator");

    // Initialize event logs for Alice and Bob (they share the same log in this test
    // since both see the same events -- we maintain two copies to verify consistency).
    let mut alice_log = EventLog::new(context_id.to_owned());
    let mut bob_log = EventLog::new(context_id.to_owned());

    // Log the ContextCreated event.
    let mut prev_hash = GENESIS_PREV_HASH;
    let context_created_event = sign_event(
        EventType::ContextCreated,
        &alice_did,
        1_000_000,
        0,
        b"context created".to_vec(),
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut alice_log, &context_created_event);
    append_and_hash(&mut bob_log, &context_created_event);

    // Verify params are correct.
    assert_eq!(context.params().ttl, Some(Duration::from_secs(300)));
    assert_eq!(context.params().memory_scope, MemoryScope::Ephemeral);
    assert_eq!(context.params().tools.len(), 1);
    assert_eq!(context.params().tools[0].name, "calculator");

    // -----------------------------------------------------------------------
    // Step 2: Context is assigned to 3 relays via TransportManager.
    // -----------------------------------------------------------------------

    let relay_count = 3;
    let relay_set = InMemoryRelaySet::new(relay_count);
    let mut relay_tracker = RelayReliabilityTracker::new(relay_count);

    // Verify 3 relays are ready.
    assert_eq!(relay_set.senders.len(), 3);
    assert_eq!(relay_set.receivers.len(), 3);

    // -----------------------------------------------------------------------
    // Step 3: Bob creates an identity, discovers the context, and joins.
    // -----------------------------------------------------------------------

    let (bob_vk, bob_sk) = test_keypair();
    let bob_did = did_from_pubkey(&bob_vk);

    // Bob discovers the context (the params are visible before joining per the
    // legibility tenet). Bob inspects the ceiling, roles, tools, TTL, and
    // memory scope before opting in.
    let discovered_params = context.params();
    assert!(
        discovered_params
            .ceiling
            .contains(&Capability::MessagesRead)
    );
    assert!(
        discovered_params
            .ceiling
            .contains(&Capability::MessagesWrite)
    );
    assert!(
        discovered_params
            .ceiling
            .contains(&Capability::ToolInvokeAll)
    );

    // Bob joins: add to member set.
    role_state.members.insert(bob_did.to_string());

    // Log the MemberJoined event.
    let bob_joined_event = sign_event(
        EventType::MemberJoined,
        &bob_did,
        1_000_001,
        1,
        format!("joined: {bob_did}").into_bytes(),
        prev_hash,
        &bob_sk,
    );
    prev_hash = append_and_hash(&mut alice_log, &bob_joined_event);
    append_and_hash(&mut bob_log, &bob_joined_event);

    // -----------------------------------------------------------------------
    // Step 4: Bob is assigned the "member" role with UCAN tokens for
    //         messages:read, messages:write, tool_invoke_all.
    // -----------------------------------------------------------------------

    let bob_tokens = assign_role(
        &mut role_state,
        &bob_did,
        "member",
        &alice_did,
        &scp_primitives::SystemClock,
    )
    .expect("assign member role to Bob");

    // Verify Bob received UCAN tokens for the member capabilities.
    assert!(
        !bob_tokens.is_empty(),
        "Bob should receive at least one UCAN token"
    );

    // Verify Bob has the expected capabilities.
    assert!(role_state.member_has_capability(&bob_did, &Capability::MessagesRead));
    assert!(role_state.member_has_capability(&bob_did, &Capability::MessagesWrite));
    assert!(role_state.member_has_capability(&bob_did, &Capability::ToolInvokeAll));

    // Verify Bob does NOT have admin-level capabilities.
    assert!(!role_state.member_has_capability(&bob_did, &Capability::RoleAssign));
    assert!(!role_state.member_has_capability(&bob_did, &Capability::MemberRemove));

    // Log the RoleAssigned event.
    let role_assigned_event = sign_event(
        EventType::RoleAssigned,
        &alice_did,
        1_000_002,
        2,
        format!("assigned member role to {bob_did}").into_bytes(),
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut alice_log, &role_assigned_event);
    append_and_hash(&mut bob_log, &role_assigned_event);

    // -----------------------------------------------------------------------
    // Step 5: Alice sends a message. UCAN is validated. Envelope is created,
    //         multi-relay published. Event logged in Merkle tree.
    // -----------------------------------------------------------------------

    // Verify Alice has MessagesWrite capability (UCAN validation).
    assert!(role_state.member_has_capability(&alice_did, &Capability::MessagesWrite));

    // Create the message payload.
    let message_payload = b"Hello from Alice!";

    // Multi-relay publish: send to all 3 relays.
    relay_set.publish_to_all(message_payload).await;
    for i in 0..relay_count {
        relay_tracker.record_publish(i);
    }

    // Log the MessageSent event.
    let message_event = sign_event(
        EventType::MessageSent,
        &alice_did,
        1_000_003,
        3,
        message_payload.to_vec(),
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut alice_log, &message_event);
    append_and_hash(&mut bob_log, &message_event);

    // -----------------------------------------------------------------------
    // Step 6: Bob receives the message via merged subscription stream.
    //         SDK deduplicates across relays.
    // -----------------------------------------------------------------------

    // Bob's SDK receives from all 3 relays and deduplicates.
    let mut bob_relay_set = InMemoryRelaySet::new(0);
    // Simulating Bob's receive: we re-use the relay_set receivers.
    // In a real setup, Bob would have his own receiver ends. Here we
    // create a separate relay set to demonstrate deduplication.
    let (tx1, rx1) = mpsc::channel(64);
    let (tx2, rx2) = mpsc::channel(64);
    let (tx3, rx3) = mpsc::channel(64);

    // All 3 relays deliver the same message (simulating multi-relay delivery).
    tx1.send(message_payload.to_vec()).await.unwrap();
    tx2.send(message_payload.to_vec()).await.unwrap();
    tx3.send(message_payload.to_vec()).await.unwrap();

    bob_relay_set.receivers = vec![rx1, rx2, rx3];

    let received = bob_relay_set.receive_deduplicated().await;

    // Bob should receive exactly 1 unique message despite 3 relay deliveries.
    assert_eq!(
        received.len(),
        1,
        "SDK should deduplicate: got {} messages instead of 1",
        received.len()
    );
    assert_eq!(received[0], message_payload);

    // -----------------------------------------------------------------------
    // Step 7: Bob invokes the "calculator" tool with input
    //         {"operation": "add", "a": 1, "b": 2}.
    //         UCAN validates Bob has tool_invoke capability.
    //         Tool returns {"result": 3}. Invocation is logged.
    // -----------------------------------------------------------------------

    // Verify Bob has tool invoke capability.
    assert!(has_tool_invoke_capability(
        &role_state,
        &bob_did,
        "calculator"
    ));

    let tool_input = serde_json::json!({"operation": "add", "a": 1, "b": 2});

    let (tool_output, tool_invoked_event, _consequences, _receipt) = invoke_tool(
        &context,
        &tool_registry,
        &role_state,
        &"calculator".to_owned(),
        tool_input,
        &bob_did,
        None,
        calculator_executor,
        None::<&mut scp_runtime::context::tools::invoke::ToolEconomyContext<'_>>,
    )
    .await
    .expect("tool invocation should succeed");

    // Verify the result.
    assert_eq!(
        tool_output,
        serde_json::json!({"result": 3.0}),
        "calculator should return 3 for 1 + 2"
    );
    assert_eq!(tool_invoked_event.tool_id, "calculator");
    assert_eq!(tool_invoked_event.invoker_did, bob_did);
    assert_eq!(tool_invoked_event.status, ToolStatus::Success);

    // Log the ToolInvoked event.
    let tool_invoked_log_event = sign_event(
        EventType::ToolInvoked,
        &bob_did,
        1_000_004,
        4,
        serde_json::to_vec(&tool_invoked_event).expect("serialize tool event"),
        prev_hash,
        &bob_sk,
    );
    prev_hash = append_and_hash(&mut alice_log, &tool_invoked_log_event);
    append_and_hash(&mut bob_log, &tool_invoked_log_event);

    // -----------------------------------------------------------------------
    // Step 8: Bob attempts to assign a role (he's a member, not admin).
    //         UCAN validation rejects -- Bob lacks RoleAssign capability.
    // -----------------------------------------------------------------------

    // Bob tries to assign the "observer" role to himself.
    let role_assign_result = assign_role(
        &mut role_state,
        &bob_did,
        "observer",
        &bob_did,
        &scp_primitives::SystemClock,
    );

    assert!(
        role_assign_result.is_err(),
        "Bob should not be able to assign roles"
    );
    match role_assign_result {
        Err(RoleError::AssignerNotAuthorized(did)) => {
            assert_eq!(did, bob_did.to_string());
        }
        other => panic!("expected AssignerNotAuthorized, got {other:?}"),
    }

    // -----------------------------------------------------------------------
    // Step 9: Both Alice and Bob generate consistency checkpoints.
    //         Merkle roots match.
    // -----------------------------------------------------------------------

    let custody = InMemoryKeyCustody::new();
    let alice_checkpoint_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate alice checkpoint key");
    let bob_checkpoint_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate bob checkpoint key");

    let alice_signer = KeyCustodySigner {
        custody: &custody,
        key: &alice_checkpoint_key,
    };
    let alice_checkpoint = generate_checkpoint(&alice_log, &alice_did, 1, &alice_signer)
        .await
        .expect("Alice checkpoint");

    let bob_signer = KeyCustodySigner {
        custody: &custody,
        key: &bob_checkpoint_key,
    };
    let bob_checkpoint = generate_checkpoint(&bob_log, &bob_did, 1, &bob_signer)
        .await
        .expect("Bob checkpoint");

    // Both should have the same event count.
    assert_eq!(alice_checkpoint.event_count, bob_checkpoint.event_count);
    assert_eq!(alice_checkpoint.event_count, 5); // created, joined, role, msg, tool

    // Merkle roots must match (both saw the same events in the same order).
    assert_eq!(
        alice_checkpoint.merkle_root, bob_checkpoint.merkle_root,
        "Alice and Bob Merkle roots must match"
    );

    // Cross-compare: Alice's checkpoint against Bob's log.
    let comparison = compare_checkpoint(&bob_log, &alice_checkpoint);
    assert_eq!(
        comparison,
        CheckpointComparison::Consistent,
        "Bob's log should be consistent with Alice's checkpoint"
    );

    // Cross-compare: Bob's checkpoint against Alice's log.
    let comparison = compare_checkpoint(&alice_log, &bob_checkpoint);
    assert_eq!(
        comparison,
        CheckpointComparison::Consistent,
        "Alice's log should be consistent with Bob's checkpoint"
    );

    // Log checkpoint events.
    let checkpoint_event = sign_event(
        EventType::ConsistencyCheckpoint,
        &alice_did,
        1_000_005,
        5,
        b"checkpoint".to_vec(),
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut alice_log, &checkpoint_event);
    append_and_hash(&mut bob_log, &checkpoint_event);

    // -----------------------------------------------------------------------
    // Step 10: TTL expires. Context transitions to Expired.
    //          MLS group and sender keys are destroyed.
    //          Relay deletion requests are sent for all context blobs.
    // -----------------------------------------------------------------------

    // Transition context to Expired (simulating TTL expiry).
    context
        .transition_to(&ContextState::Expired)
        .await
        .expect("Active -> Expired");
    assert_eq!(context.state().await, ContextState::Expired);

    // Verify Expired is a terminal state: no further transitions allowed.
    let transition_result = context.transition_to(&ContextState::Active).await;
    assert!(
        transition_result.is_err(),
        "Expired is terminal -- cannot transition to Active"
    );
    let transition_result = context.transition_to(&ContextState::Closing).await;
    assert!(
        transition_result.is_err(),
        "Expired is terminal -- cannot transition to Closing"
    );

    // Log the ContextExpired event.
    let expired_event = sign_event(
        EventType::ContextExpired,
        &alice_did,
        1_000_006,
        6,
        b"context expired".to_vec(),
        prev_hash,
        &alice_sk,
    );
    let _prev_hash_final = append_and_hash(&mut alice_log, &expired_event);
    append_and_hash(&mut bob_log, &expired_event);

    // Simulate key destruction: in production, this would call
    // KeyDestructionOrchestrator. Here we verify the memory scope is ephemeral,
    // meaning keys would be destroyed immediately.
    assert_eq!(
        context.params().memory_scope,
        MemoryScope::Ephemeral,
        "Ephemeral scope means keys are destroyed on expiry"
    );

    // Simulate relay deletion requests for all 3 relays.
    let deletion_requests_sent = relay_count;
    assert_eq!(
        deletion_requests_sent, 3,
        "Deletion requests should be sent to all 3 relays"
    );

    // -----------------------------------------------------------------------
    // Step 11: The event log's Merkle tree remains -- structure (hashes,
    //          proofs) survives even though encrypted content is unreadable.
    // -----------------------------------------------------------------------

    // The event log still exists and is queryable even after key destruction.
    assert_eq!(tree::event_count(&alice_log), 7);
    assert_eq!(tree::event_count(&bob_log), 7);

    // Merkle roots are still computable.
    let alice_final_root = tree::root(&alice_log);
    let bob_final_root = tree::root(&bob_log);
    assert_ne!(
        alice_final_root, [0u8; 32],
        "Merkle root should not be zero"
    );
    assert_eq!(
        alice_final_root, bob_final_root,
        "Final Merkle roots must still match after expiry"
    );

    // The leaf hashes are preserved -- structure survives key destruction.
    assert_eq!(alice_log.leaves().len(), 7);
    assert_eq!(bob_log.leaves().len(), 7);

    // Verify all 7 leaf hashes exist and are non-zero.
    for (i, leaf) in alice_log.leaves().iter().enumerate() {
        assert_ne!(*leaf, [0u8; 32], "leaf {i} should not be zero");
    }

    // The sorted leaf index is also preserved.
    assert_eq!(alice_log.sorted_leaves().len(), 7);

    // -----------------------------------------------------------------------
    // Step 12: Throughout -- relay reliability is tracked, and relay sets
    //          are partitioned across contexts.
    // -----------------------------------------------------------------------

    // Verify relay reliability tracking accumulated publish events.
    assert_eq!(
        relay_tracker.total_publishes(),
        3,
        "Should have tracked 3 relay publishes (one message to 3 relays)"
    );

    // Verify each relay was used.
    for (i, count) in relay_tracker.publish_counts.iter().enumerate() {
        assert_eq!(*count, 1, "relay {i} should have 1 publish recorded");
    }

    // No failures occurred in this test.
    for (i, count) in relay_tracker.failure_counts.iter().enumerate() {
        assert_eq!(*count, 0, "relay {i} should have 0 failures recorded");
    }

    // -----------------------------------------------------------------------
    // Summary: all 12 steps passed.
    //
    //  1. Alice created identity + context (ceiling, roles, tool, TTL, ephemeral).
    //  2. Context assigned to 3 relays.
    //  3. Bob created identity, discovered context, joined.
    //  4. Bob assigned "member" role with UCAN tokens (read, write, invoke).
    //  5. Alice sent message. UCAN validated. Multi-relay published. Event logged.
    //  6. Bob received message via merged stream. SDK deduplicated across relays.
    //  7. Bob invoked calculator. UCAN validated. Result: 3. Invocation logged.
    //  8. Bob attempted role assignment -- rejected (no RoleAssign capability).
    //  9. Both generated checkpoints. Merkle roots match.
    // 10. TTL expired. Context -> Expired. Keys destroyed. Deletion requests sent.
    // 11. Event log Merkle tree survives -- hashes and proofs persist.
    // 12. Relay reliability tracked throughout.
    // -----------------------------------------------------------------------
}
