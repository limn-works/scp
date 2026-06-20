//! Two-participant message exchange.
//!
//! Demonstrates creating a context, adding a second participant,
//! and exchanging messages between them. Shows how events are
//! generated for membership changes and message delivery.
//!
//! Uses mock providers — see `scp-testing` for full-stack examples
//! with real MLS encryption.
//!
//! Usage:
//!   `cargo run -p scp-runtime --features testing --example messaging`

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::KeyPackage;
use scp_protocol::context::{Capability, ContextMode, ContextParams};
use scp_runtime::context::supervisor::{MessageSigner, Supervisor};

mod support;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build a Supervisor with mock providers.
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

    // 2. Register two participants.
    let alice: DID = "did:dht:z6MkAlice".into();
    let bob: DID = "did:dht:z6MkBob".into();
    manager.register_local_did(alice.clone()).await?;
    manager.register_local_did(bob.clone()).await?;

    // 3. Alice creates a context with messaging capabilities.
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("chat-demo".to_owned(), params, alice.clone(), None)
        .await?;
    println!("Alice created context: {}", handle.context_id());

    // 4. Bob joins the context with a mock key package.
    let bob_key_package = KeyPackage {
        owner_did: bob.clone(),
        mls_key_package_bytes: None, // mock — no real MLS in this example
    };
    manager
        .join_context(&handle, bob_key_package, None, None)
        .await?;
    println!("Bob joined the context.");

    // Check membership.
    let members = manager.member_dids("chat-demo").await;
    println!("Members: {members:?}");
    assert_eq!(members.len(), 2);

    // 5. Alice sends a message.
    let alice_sk = support::signing_key_for(&alice);
    manager
        .send_message(
            &handle,
            &alice,
            b"Hello Bob!",
            MessageSigner::Active(&alice_sk),
            None,
            None,
        )
        .await?;
    println!("\nAlice: Hello Bob!");

    // 6. Bob sends a reply.
    let bob_sk = support::signing_key_for(&bob);
    manager
        .send_message(
            &handle,
            &bob,
            b"Hi Alice!",
            MessageSigner::Active(&bob_sk),
            None,
            None,
        )
        .await?;
    println!("Bob: Hi Alice!");

    // 7. Drain events to see membership and message activity.
    let events = manager.drain_events("chat-demo").await;
    println!("\nEvents ({} total):", events.len());
    for event in &events {
        println!("  - {event:?}");
    }

    // 8. Bob leaves the context.
    manager.leave_context(&handle, &bob, &bob).await?;
    println!("\nBob left the context.");

    let members = manager.member_dids("chat-demo").await;
    println!("Remaining members: {members:?}");

    println!("\nMessage exchange complete.");

    Ok(())
}
