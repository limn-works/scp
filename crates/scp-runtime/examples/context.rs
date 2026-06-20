//! Context creation and lifecycle management.
//!
//! Demonstrates creating a context with governance parameters,
//! inspecting its state, and sending a message.
//!
//! Uses mock providers — see `scp-testing` for full-stack examples
//! with real MLS encryption.
//!
//! Usage:
//!   `cargo run -p scp-runtime --features testing --example context`

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::{Capability, ContextMode, ContextParams, ContextState};
use scp_runtime::context::supervisor::Supervisor;

mod support;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build a Supervisor with mock providers.
    //    In production, these would be real MLS crypto, relay transport,
    //    and Merkle event log implementations.
    let key_resolver: KeyResolver = Arc::new(|_did: &DID, _kid: scp_identity::SigningKeyId| None);
    let manager = Supervisor::with_providers(
        support::example_crypto("did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        Box::new(support::MockTransport),
        Box::new(support::MockEventLog),
        key_resolver,
        None,
        None,
        None,
        None,
        support::example_mls_storage(),
    );

    // 2. Register our DID so the manager recognizes us as a local participant.
    let alice: DID = "did:dht:z6MkAlice".into();
    manager.register_local_did(alice.clone()).await?;

    // 3. Define context parameters.
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::ToolRegister,
            Capability::ToolInvokeAll,
        ],
        ..ContextParams::default()
    };

    println!(
        "Creating context with {} capabilities...",
        params.ceiling.len()
    );
    println!("  Mode: {:?}", params.mode);
    println!("  Governance: {:?}", params.governance);

    // 4. Create the context — returns a handle for all subsequent operations.
    let handle = manager
        .create_context("demo-context".to_owned(), params, alice.clone(), None)
        .await?;

    println!();
    println!("Context created:");
    println!("  ID: {}", handle.context_id());
    println!("  State: {:?}", handle.state().await);
    assert_eq!(handle.state().await, ContextState::Active);

    // 5. Send a message (mock transport captures it).
    let alice_sk = support::signing_key_for(&alice);
    manager
        .send_message(
            &handle,
            &alice,
            b"Hello, context!",
            Some(&alice_sk),
            scp_identity::SigningKeyId::Active,
            None,
            None,
        )
        .await?;
    println!("  Message sent successfully.");

    // 6. Drain events to see what happened.
    let events = manager.drain_events("demo-context").await;
    println!("  Events generated: {}", events.len());

    println!();
    println!("Context lifecycle complete.");

    Ok(())
}
