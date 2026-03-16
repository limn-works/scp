//! Context creation and lifecycle management.
//!
//! Demonstrates creating a context with governance parameters,
//! inspecting its state, and sending a message.
//!
//! Uses mock providers — see `scp-testing` for full-stack examples
//! with real MLS encryption.
//!
//! Usage:
//!   `cargo run -p scp-core --features testing --example context`

use std::sync::Arc;

use scp_core::context::governance::KeyResolver;
use scp_core::context::manager::ContextManager;
use scp_core::context::{Capability, ContextMode, ContextParams, ContextState};
use scp_identity::DID;

mod support;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build a ContextManager with mock providers.
    //    In production, these would be real MLS crypto, relay transport,
    //    and Merkle event log implementations.
    let key_resolver: KeyResolver = Arc::new(|_did| None);
    let manager = ContextManager::new(
        Box::new(support::MockCrypto),
        Box::new(support::MockTransport),
        Box::new(support::MockEventLog),
        key_resolver,
    );

    // 2. Register our DID so the manager recognizes us as a local participant.
    let alice: DID = "did:dht:z6MkAlice".into();
    manager.register_local_did(alice.clone()).await;

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
        .create_context("demo-context".to_owned(), params, alice.clone())
        .await?;

    println!();
    println!("Context created:");
    println!("  ID: {}", handle.context_id());
    println!("  State: {:?}", handle.state().await);
    assert_eq!(handle.state().await, ContextState::Active);

    // 5. Send a message (mock transport captures it).
    manager
        .send_message(&handle, &alice, b"Hello, context!", None)
        .await?;
    println!("  Message sent successfully.");

    // 6. Drain events to see what happened.
    let events = manager.drain_events("demo-context").await;
    println!("  Events generated: {}", events.len());

    println!();
    println!("Context lifecycle complete.");

    Ok(())
}
