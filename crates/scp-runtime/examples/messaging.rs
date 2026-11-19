//! Two-participant message exchange.
//!
//! Demonstrates creating a context, adding a second participant,
//! and exchanging messages between them. Shows how events are
//! generated for membership changes and message delivery.
//!
//! Uses a mock transport and event log. Bob's `KeyPackage` is a real MLS
//! one, minted through `Supervisor::mint_attested_key_package`; see
//! `scp-testing` for full-stack runs over a relay.
//!
//! Usage:
//!   `cargo run -p scp-runtime --example messaging`

use std::sync::Arc;

use scp_did::DID;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::KeyPackage;
use scp_protocol::context::{Capability, ContextMode, ContextParams};
use scp_runtime_core::context::supervisor::{MessageSigner, Supervisor, single_custody_source};

mod support;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build a Supervisor with mock providers.
    // Each participant's `#active` key is the one `support::command_signer_for`
    // signs with, so the supervisor can check the attestation on Bob's
    // KeyPackage against the key his DID names.
    let key_resolver: KeyResolver = Arc::new(|did: &DID, kid: scp_did::SigningKeyId| {
        matches!(kid, scp_did::SigningKeyId::Active)
            .then(|| support::signing_key_for(did).verifying_key())
    });
    let (durable, persistence) = support::example_storage_providers();
    let manager = Supervisor::with_providers_and_journal(
        support::example_crypto("did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        Box::new(support::MockTransport),
        Box::new(support::MockEventLog),
        key_resolver,
        persistence,
        None,
        None,
        None,
        durable,
        // Each identity's wrapping key lives in its key custody; a host passes
        // its own custody here.
        single_custody_source(Arc::new(InMemoryKeyCustody::new())),
        scp_runtime::domain_handlers(),
    );

    // 2. Register two participants.
    let alice: DID = "did:dht:z6MkAlice".into();
    let bob: DID = "did:dht:z6MkBob".into();
    manager.register_local_did(alice.clone()).await;
    manager.register_local_did(bob.clone()).await;

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

    // The example runs in process with no relay, so no relay hosts the context.
    let handle = manager
        .create_context(
            "chat-demo".to_owned(),
            params,
            alice.clone(),
            None,
            Vec::new(),
        )
        .await?;
    println!("Alice created context: {}", handle.context_id());

    // 4. Bob joins the context with a real MLS KeyPackage, minted the way every
    // bridge mints one: it carries Bob's wrapping key and an attestation signed
    // through his `#active` key.
    let bob_signer = support::command_signer_for(&bob).await?;
    let bob_key_package = KeyPackage {
        owner_did: bob.clone(),
        mls_key_package_bytes: Some(manager.mint_attested_key_package(&bob, &bob_signer).await?),
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
    let alice_signer = support::command_signer_for(&alice).await?;
    manager
        .send_message(
            &handle,
            &alice,
            b"Hello Bob!",
            MessageSigner::Active(&alice_signer),
            None,
            None,
        )
        .await?;
    println!("\nAlice: Hello Bob!");

    // 6. Bob sends a reply.
    manager
        .send_message(
            &handle,
            &bob,
            b"Hi Alice!",
            MessageSigner::Active(&bob_signer),
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
