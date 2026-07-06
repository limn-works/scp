// ADR-049 commit 12c.9e: ContextCryptoProvider trait deleted; DemoCrypto
// was a bespoke mock with `seal`/`open` overrides that bypassed encryption
// for demo purposes. ADR-049 commit 12c.9f introduces backend injection on
// `MlsCryptoProvider::with_backends`, which is the seam this file should
// rewire to. The full rewire (every test scenario re-expressed via mock
// `MlsBackend` / `HpkeBackend` impls and the real
// `MlsCryptoProvider::with_backends` constructor) is tracked alongside the
// commit-12 deletion of `ContextManager`. Entire file is gated out until
// the rewire lands.
#![cfg(any())]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    // ADR-049 commit 12c.2: lifecycle hoist inflates some test-path
    // futures past clippy's 16 KB stack budget.
    clippy::large_futures
)]

//! End-to-end network simulation — run with `cargo test --test network_simulation -- --nocapture`
//!
//! This test narrates itself: every step prints what's happening so you can
//! watch a simulated SCP network boot up, exchange encrypted messages, handle
//! relay misbehavior, and recover from partitions — all in real time.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use futures::StreamExt;

use openmls::prelude::KeyPackageIn;
use scp_core::crypto::mls::credential::ScpCredential;
use scp_core::crypto::mls::group::ScpMlsGroup;
use scp_core::crypto::mls::group::{add_member, create_group, generate_key_package, join_group};
use scp_core::crypto::sender_keys::{
    HandleRequestParams, NonceDedup, SenderKeyRequest, SenderKeyResponse, SenderKeyStore,
    generate_sender_key, handle_sender_key_request, open_sender_key_response,
    publish_sender_key_epoch_advance, request_sender_key, verify_epoch_advance,
};
use scp_core::envelope::inner::{
    InnerEnvelopeParams, MessageType, SCP_INNER_ENVELOPE_VERSION, create_inner_envelope,
};
use scp_core::envelope::outer::{open_envelope, seal_envelope};
use scp_core::envelope::padding::strip_padding;
use scp_core::envelope::pseudonym::derive_pseudonym;
use scp_did::SigningKeyId;
use scp_platform::error::PlatformError;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};
use scp_testing::builder::ScenarioBuilder;
use scp_testing::clock::Clock;
use scp_testing::relay::behavior::SuppressionConfig;
use scp_testing::relay::{BehaviorMode, InMemoryRelay};
use scp_testing::transport::InMemoryTransport;
use scp_transport::traits::{RoutingId, TransportAdapter, TransportEvent};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

// -------------------------------------------------------------------------
// MLS signer adapter (reused from encrypted_relay_roundtrip.rs pattern)
// -------------------------------------------------------------------------

struct MlsGroupKeyCustody<'a> {
    group: &'a ScpMlsGroup,
}

#[allow(clippy::manual_async_fn)]
impl KeyCustody for MlsGroupKeyCustody<'_> {
    fn generate_keypair(
        &self,
        _: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }
    fn sign(
        &self,
        _: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        let r = self
            .group
            .sign(data)
            .map(Signature::new)
            .map_err(|e| PlatformError::CustodyError(e.to_string()));
        async { r }
    }
    fn public_key(
        &self,
        _: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        let r = self
            .group
            .signer_public_key()
            .map(PublicKey::new)
            .map_err(|e| PlatformError::CustodyError(e.to_string()));
        async { r }
    }
    fn destroy_key(&self, _: &KeyHandle) -> impl Future<Output = Result<(), PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }
    fn dh_agree(
        &self,
        _: &KeyHandle,
        _: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }
    fn derive_pseudonym(
        &self,
        _: &KeyHandle,
        _: &[u8],
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }
    fn derive_rotatable_pseudonym(
        &self,
        _: &KeyHandle,
        _: &[u8],
        _: u64,
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }
    fn ed25519_to_x25519_agree(
        &self,
        _: &KeyHandle,
        _: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }
    fn custody_type(&self, _: &KeyHandle) -> CustodyType {
        CustodyType::InMemory
    }
}

// -------------------------------------------------------------------------
// The demo
// -------------------------------------------------------------------------

#[tokio::test]
#[ignore = "DemoCrypto mock impls the deleted ContextCryptoProvider trait; full file rewire to MlsCryptoProvider::with_backends mock backends is tracked alongside the commit-12 deletion of ContextManager. File-level cfg(any()) gates compilation."]
#[allow(clippy::too_many_lines)]
async fn end_to_end_network_demo() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          SCP NETWORK SIMULATOR — END-TO-END DEMO           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // =====================================================================
    // PHASE 1: Network Setup
    // =====================================================================
    println!("━━━ PHASE 1: Network Setup ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let mut sim = {
        let mut b = ScenarioBuilder::default();
        b.relay("relay-alpha")
            .identity("alice")
            .identity("bob")
            .identity("charlie")
            .full_mesh();
        b.build().unwrap()
    };
    // Set the clock to a recognizable timestamp.
    sim.clock().set(1_700_000_000_000); // 2023-11-14 22:13:20 UTC in millis

    println!(
        "  Clock:      t = {} (2023-11-14 22:13:20 UTC)",
        sim.clock().now_secs()
    );
    println!("  Relays:     {:?}", sim.relay_names());
    println!("  Identities: {:?}", sim.identity_labels());
    println!("  Topology:   full mesh (all nodes connected)");
    println!();

    let alice = sim.identity("alice").unwrap();
    let bob = sim.identity("bob").unwrap();
    let charlie = sim.identity("charlie").unwrap();
    println!("  Alice   DID: {}", alice.did());
    println!("  Bob     DID: {}", bob.did());
    println!("  Charlie DID: {}", charlie.did());
    println!();

    // =====================================================================
    // PHASE 2: Identity & Key Material
    // =====================================================================
    println!("━━━ PHASE 2: Identity & Key Material ━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Create real Ed25519 key custody for Alice and Bob.
    let alice_custody = InMemoryKeyCustody::from_seed_bytes({
        let mut __s = [0u8; 32];
        __s[..8].copy_from_slice(&(1u64).to_le_bytes());
        __s
    });
    let alice_sign_key = alice_custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .unwrap();
    let alice_pubkey = alice_custody.public_key(&alice_sign_key).await.unwrap();
    let alice_identity_key = alice_custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .unwrap();

    let bob_custody = InMemoryKeyCustody::from_seed_bytes({
        let mut __s = [0u8; 32];
        __s[..8].copy_from_slice(&(2u64).to_le_bytes());
        __s
    });
    let bob_sign_key = bob_custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .unwrap();
    let bob_pubkey = bob_custody.public_key(&bob_sign_key).await.unwrap();

    println!(
        "  Alice: Ed25519 signing key generated (handle={})",
        alice_sign_key.id()
    );
    println!(
        "         public key: {}...",
        hex::encode(&alice_pubkey.as_bytes()[..8])
    );
    println!(
        "  Bob:   Ed25519 signing key generated (handle={})",
        bob_sign_key.id()
    );
    println!(
        "         public key: {}...",
        hex::encode(&bob_pubkey.as_bytes()[..8])
    );
    println!();

    // =====================================================================
    // PHASE 3: MLS Group Creation
    // =====================================================================
    println!("━━━ PHASE 3: MLS Group Creation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let ctx_id = "ctx-demo-2024";

    // MLS credentials require valid did:dht format.
    let alice_did_str = "did:dht:z6MkAliceDemo123";
    let bob_did_str = "did:dht:z6MkBobDemo456";

    let alice_cred =
        ScpCredential::new(alice_did_str.to_owned(), None, SigningKeyId::Active).unwrap();
    let mut alice_group = create_group(&alice_cred, &scp_clock::SystemClock).unwrap();
    println!("  Alice created MLS group");
    println!(
        "    group_id:   {}...",
        hex::encode(&alice_group.group_id().unwrap()[..8])
    );
    println!("    epoch:      {}", alice_group.epoch().unwrap());
    println!("    members:    {}", alice_group.members().unwrap().len());
    println!("    ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519");
    println!();

    // Bob joins.
    let bob_cred = ScpCredential::new(bob_did_str.to_owned(), None, SigningKeyId::Active).unwrap();
    let (bob_kp_bundle, bob_signer, bob_provider) =
        generate_key_package(&bob_cred, &scp_clock::SystemClock).unwrap();

    println!("  Bob generated KeyPackage for group join");

    let kp_bytes = bob_kp_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice()).unwrap();
    let add_result = add_member(&mut alice_group, kp_in, &scp_clock::SystemClock).unwrap();
    let mut bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

    println!("  Alice added Bob to group via Welcome message");
    println!("    epoch:   {} (both sides)", alice_group.epoch().unwrap());
    println!("    members: {}", alice_group.members().unwrap().len());
    println!();

    // =====================================================================
    // PHASE 4: Sender Key Distribution (Pull Protocol)
    // =====================================================================
    println!("━━━ PHASE 4: Sender Key Distribution ━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let alice_sender_key = generate_sender_key();
    let mut alice_sk_store = SenderKeyStore::new();
    alice_sk_store.set_unchecked(ctx_id, alice_did_str, alice_sender_key.clone());

    println!(
        "  Alice generated sender key: {}...",
        hex::encode(&alice_sender_key.as_bytes()[..8])
    );

    // Publish epoch advance.
    let advance_bytes = publish_sender_key_epoch_advance(
        &alice_custody,
        &alice_sign_key,
        ctx_id,
        alice_did_str,
        1,
        SigningKeyId::Active,
    )
    .await
    .unwrap();

    let advance: scp_core::crypto::sender_keys::SenderKeyEpochAdvance =
        rmp_serde::from_slice(&advance_bytes).unwrap();
    let advance_ok = verify_epoch_advance(&advance, ctx_id, alice_pubkey.as_bytes()).unwrap();
    println!("  Alice published SenderKeyEpochAdvance (epoch=1)");
    println!("    signature verified: {advance_ok}");
    println!();

    // Bob requests Alice's sender key via HPKE.
    let clock = scp_clock::SystemClock;
    let req_result = request_sender_key(
        &bob_custody,
        &bob_sign_key,
        bob_did_str,
        alice_did_str,
        1,
        &clock,
    )
    .await
    .unwrap();

    let sk_request: SenderKeyRequest = rmp_serde::from_slice(&req_result.request_message).unwrap();
    println!("  Bob created SenderKeyRequest");
    println!("    requester: {}", sk_request.requester_did);
    println!("    sender:    {}", sk_request.sender_did);
    println!("    nonce:     {}...", hex::encode(&sk_request.nonce[..4]));

    let block_list: HashSet<String> = HashSet::new();
    let mut nonce_dedup = NonceDedup::new();
    let resp_bytes = handle_sender_key_request(
        &sk_request,
        bob_pubkey.as_bytes(),
        &HandleRequestParams {
            sender_key: &alice_sender_key,
            context_id: ctx_id,
            sender_did: alice_did_str,
            epoch: 1,
            block_list: &block_list,
            context_members: None,
            now_secs: sk_request.timestamp,
        },
        &mut nonce_dedup,
    )
    .await
    .unwrap()
    .expect("Bob is not blocked");

    let sk_response: SenderKeyResponse = rmp_serde::from_slice(&resp_bytes).unwrap();
    let received_sk = open_sender_key_response(
        &bob_custody,
        &req_result.wrapping_key_handle,
        ctx_id,
        &sk_response,
    )
    .await
    .unwrap();

    let keys_match = received_sk.as_bytes() == alice_sender_key.as_bytes();
    println!("  Alice handled request → HPKE-encrypted sender key response");
    println!("  Bob decrypted sender key via HPKE");
    println!("    keys match: {keys_match}");
    assert!(keys_match);

    let mut bob_sk_store = SenderKeyStore::new();
    bob_sk_store.set_unchecked(ctx_id, alice_did_str, received_sk);
    println!();

    // =====================================================================
    // PHASE 5: Double Encryption & Relay Routing
    // =====================================================================
    println!("━━━ PHASE 5: Double Encryption & Relay Routing ━━━━━━━━━━━━━━");
    println!();

    let original_msg = b"Hello from Alice! This message is double-encrypted.";
    println!(
        "  Original message: \"{}\"",
        String::from_utf8_lossy(original_msg)
    );
    println!("  Message size:     {} bytes", original_msg.len());
    println!();

    // Step 1: Create inner envelope with signature.
    let alice_mls_custody = MlsGroupKeyCustody {
        group: &alice_group,
    };
    let dummy_handle = KeyHandle::new(0);
    let inner_env = create_inner_envelope(
        &InnerEnvelopeParams {
            context_id: ctx_id,
            sender_did: alice_did_str,
            epoch: alice_group.epoch().unwrap(),
            generation: 0,
            sequence: 1,
            timestamp: sim.clock().now_secs() * 1000,
            message_type: MessageType::Content,
            payload: original_msg,
            provenance: None,
            signing_key_id: SigningKeyId::Active,
            version: SCP_INNER_ENVELOPE_VERSION,
        },
        &alice_mls_custody,
        &dummy_handle,
    )
    .await
    .unwrap();

    let inner_bytes = rmp_serde::to_vec_named(&inner_env).unwrap();
    println!("  Step 1: InnerEnvelope created");
    println!("    context_id:  {}", inner_env.context_id);
    println!("    sender_did:  {}", inner_env.sender_did);
    println!("    epoch:       {}", inner_env.epoch);
    println!("    sequence:    {}", inner_env.sequence);
    println!(
        "    payload:     {} bytes (padded to bucket)",
        inner_env.payload.len()
    );
    println!("    signature:   {} bytes", inner_env.signature.len());
    println!("    serialized:  {} bytes", inner_bytes.len());
    println!();

    // Step 2: Derive pseudonym for routing.
    let pseudonym = derive_pseudonym(&alice_custody, &alice_identity_key, ctx_id.as_bytes())
        .await
        .unwrap();
    let routing_arr: [u8; 32] = pseudonym.public_key.as_bytes().try_into().unwrap();

    println!("  Step 2: Pseudonym derived for routing");
    println!("    routing_id:  {}...", hex::encode(&routing_arr[..8]));
    println!("    (unlinkable to Alice's DID without identity key)");
    println!();

    // Step 3: Seal — sender key encrypt → MLS encrypt → outer envelope.
    let outer_env = seal_envelope(
        &inner_env,
        &mut alice_group,
        &alice_sender_key,
        &routing_arr,
        None,
        3600,
    )
    .unwrap();

    println!("  Step 3: OuterEnvelope sealed (double encryption)");
    println!("    Layer 1: AES-256-GCM sender key encryption");
    println!("    Layer 2: MLS AES-128-GCM group encryption");
    println!(
        "    encrypted_blob: {} bytes",
        outer_env.encrypted_blob.len()
    );
    println!("    blob_ttl:       {} secs", outer_env.blob_ttl);
    println!();

    // Step 4: Route through InMemoryRelay.
    let relay_arc = sim.relay("relay-alpha").unwrap().clone();
    let clock_arc = sim.clock().clone();
    let clock_for_ts = Arc::clone(&clock_arc);
    let transport = InMemoryTransport::with_clock(
        Arc::clone(&relay_arc),
        Arc::new(move || clock_for_ts.now_secs()),
    );

    // Bob subscribes.
    let bob_routing = RoutingId::new(routing_arr);
    let mut bob_stream = transport.subscribe(&bob_routing, None).await.unwrap();

    // Alice sends.
    let blob_id = transport.send(&outer_env).await.unwrap();
    println!("  Step 4: Envelope sent through relay-alpha");
    println!("    blob_id: {}...", hex::encode(&blob_id.as_bytes()[..8]));

    let relay_blobs = {
        let guard = relay_arc.lock().unwrap();
        guard.blob_count()
    };
    println!("    relay blob count: {relay_blobs}");
    println!();

    // Step 5: Bob receives and decrypts.
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), bob_stream.next())
        .await
        .expect("timeout")
        .expect("stream ended");

    let received_outer = match received {
        TransportEvent::Envelope(env) => env,
        other => panic!("expected Envelope, got {other:?}"),
    };

    println!("  Step 5: Bob received envelope from relay");
    println!(
        "    routing_id match: {}",
        received_outer.routing_id == outer_env.routing_id
    );
    println!(
        "    encrypted_blob:   {} bytes",
        received_outer.encrypted_blob.len()
    );

    let bob_alice_sk = bob_sk_store
        .get(ctx_id, alice_did_str)
        .expect("Bob has Alice's sender key");
    let verified_inner = open_envelope(
        &received_outer,
        &mut bob_group,
        bob_alice_sk,
        &inner_env.context_id,
        &inner_env.sender_did,
        inner_env.epoch,
        inner_env.sequence,
    )
    .unwrap();

    let decrypted_msg = strip_padding(&verified_inner.payload).unwrap();
    let msg_str = String::from_utf8_lossy(&decrypted_msg);
    println!("    MLS decrypt:      OK (epoch {})", verified_inner.epoch);
    println!("    Sender key layer: OK");
    println!("    Signature verify: OK");
    println!("    Decrypted:        \"{msg_str}\"");
    assert_eq!(decrypted_msg, original_msg);
    println!("    MATCH: original == decrypted");
    println!();

    // Verify relay never saw sensitive data.
    let outer_bytes = received_outer.to_bytes().unwrap();
    let ctx_leaked = outer_bytes
        .windows(ctx_id.len())
        .any(|w| w == ctx_id.as_bytes());
    let did_leaked = outer_bytes
        .windows(alice_did_str.len())
        .any(|w| w == alice_did_str.as_bytes());
    println!("  Privacy verification:");
    println!("    Context ID in outer bytes: {ctx_leaked} (must be false)");
    println!("    Alice DID in outer bytes:  {did_leaked} (must be false)");
    assert!(!ctx_leaked);
    assert!(!did_leaked);
    println!();

    // =====================================================================
    // PHASE 6: Relay Fault Injection — Suppression
    // =====================================================================
    println!("━━━ PHASE 6: Relay Fault Injection — Suppression ━━━━━━━━━━━━");
    println!();

    // Create a misbehaving relay that drops every 2nd message.
    let suppressing_relay = Arc::new(Mutex::new(InMemoryRelay::with_behavior(
        BehaviorMode::Suppressing(SuppressionConfig { drop_nth: 2 }),
    )));
    let suppressing_transport = InMemoryTransport::new(Arc::clone(&suppressing_relay));

    // Charlie subscribes to the suppressing relay.
    let charlie_routing = RoutingId::new([0xCC; 32]);
    let mut charlie_stream = suppressing_transport
        .subscribe(&charlie_routing, None)
        .await
        .unwrap();

    println!("  Suppressing relay: drops every 2nd message");
    println!("  Sending 6 messages...");
    println!();

    let mut sent_ids = Vec::new();
    for i in 1..=6 {
        let test_env = scp_core::envelope::outer::create_outer_envelope(
            &[0xCC; 32],
            None,
            3600,
            format!("message-{i}").into_bytes(),
        )
        .unwrap();
        let id = suppressing_transport.send(&test_env).await.unwrap();
        sent_ids.push(i);
        println!(
            "    Sent message {i} (blob_id: {}...)",
            hex::encode(&id.as_bytes()[..4])
        );
    }
    println!();

    // Drain received messages.
    let mut received_count = 0u32;
    let mut received_msgs = Vec::new();
    while let Ok(Some(TransportEvent::Envelope(env))) =
        tokio::time::timeout(std::time::Duration::from_millis(100), charlie_stream.next()).await
    {
        received_count += 1;
        let content = String::from_utf8_lossy(&env.encrypted_blob);
        received_msgs.push(content.to_string());
    }

    println!("  Results:");
    println!("    Sent:     {}", sent_ids.len());
    println!("    Received: {received_count}");
    println!(
        "    Dropped:  {} (messages #2, #4, #6)",
        sent_ids.len() as u32 - received_count
    );
    println!("    Received: {received_msgs:?}");
    // The suppressing relay drops every 2nd message (messages 2, 4, 6).
    assert_eq!(
        received_count, 3,
        "suppressing relay should drop 3 of 6 messages"
    );
    println!("    Suppression detected via sequence gap analysis");
    println!();

    // =====================================================================
    // PHASE 7: Relay Fault Injection — Equivocation
    // =====================================================================
    println!("━━━ PHASE 7: Relay Fault Injection — Equivocation ━━━━━━━━━━━");
    println!();

    let equivocating_relay = Arc::new(Mutex::new(InMemoryRelay::with_behavior(
        BehaviorMode::Equivocating(scp_testing::relay::behavior::EquivocationConfig {
            diverge_after: 0,
        }),
    )));

    // Two subscribers to the same routing ID.
    let eq_routing = [0xEE; 32];
    let (sub1_id, mut sub1_rx) = equivocating_relay.lock().unwrap().subscribe(eq_routing);
    let (_sub2_id, mut sub2_rx) = equivocating_relay.lock().unwrap().subscribe(eq_routing);

    println!("  Equivocating relay: diverges immediately (after 0 messages)");
    println!("  Two subscribers on same routing_id");
    println!();

    // Send a message — sub1 (index 0, even) gets original, sub2 (index 1, odd) gets flipped.
    {
        let mut relay = equivocating_relay.lock().unwrap();
        relay.store(eq_routing, vec![0x42, 0x43, 0x44], None, 100);
    }

    let msg1 = sub1_rx.recv().await.expect("sub1 should receive");
    let msg2 = sub2_rx.recv().await.expect("sub2 should receive");

    println!("  Subscriber 1 received: {:02x?}", &msg1.data);
    println!("  Subscriber 2 received: {:02x?}", &msg2.data);
    println!("  Data matches: {}", msg1.data == msg2.data);
    assert_ne!(
        msg1.data, msg2.data,
        "equivocating relay must deliver divergent content"
    );
    println!("  EQUIVOCATION DETECTED: subscribers see different content!");
    println!("  (Real SCP: Merkle event log roots would diverge → relay flagged)");

    // Clean up.
    equivocating_relay
        .lock()
        .unwrap()
        .unsubscribe(&eq_routing, sub1_id);
    println!();

    // =====================================================================
    // PHASE 8: Relay Fault Injection — Replay
    // =====================================================================
    println!("━━━ PHASE 8: Relay Fault Injection — Replay ━━━━━━━━━━━━━━━━━");
    println!();

    let replaying_relay = Arc::new(Mutex::new(InMemoryRelay::with_behavior(
        BehaviorMode::Replaying(scp_testing::relay::behavior::ReplayConfig { replay_count: 2 }),
    )));

    let replay_routing = [0xDD; 32];
    let (_replay_sub_id, mut replay_rx) = replaying_relay.lock().unwrap().subscribe(replay_routing);

    {
        let mut relay = replaying_relay.lock().unwrap();
        relay.store(replay_routing, vec![0xAA, 0xBB], None, 100);
    }
    println!("  Replaying relay: delivers each message 3x (1 + 2 replays)");
    println!("  Sent 1 message");

    let mut replay_received = 0u32;
    while let Ok(Some(_)) =
        tokio::time::timeout(std::time::Duration::from_millis(100), replay_rx.recv()).await
    {
        replay_received += 1;
    }
    println!("  Received: {replay_received} copies");
    assert_eq!(
        replay_received, 3,
        "replaying relay delivers 1 + replay_count copies"
    );
    println!("  (Real SCP: BlobId dedup rejects duplicates — only 1 processed)");
    println!();

    // =====================================================================
    // PHASE 9: Network Topology — Partition & Heal
    // =====================================================================
    println!("━━━ PHASE 9: Network Topology — Partition & Heal ━━━━━━━━━━━━");
    println!();

    println!("  Before partition:");
    println!(
        "    alice → bob:     {}",
        sim.topology().can_reach("alice", "bob")
    );
    println!(
        "    alice → charlie: {}",
        sim.topology().can_reach("alice", "charlie")
    );
    println!(
        "    bob → charlie:   {}",
        sim.topology().can_reach("bob", "charlie")
    );
    assert!(sim.topology().can_reach("alice", "bob"));
    assert!(sim.topology().can_reach("alice", "charlie"));
    println!();

    // Partition: isolate Charlie from Alice and Bob.
    sim.topology_mut().partition("alice", "charlie");
    sim.topology_mut().partition("bob", "charlie");

    println!("  After partition (charlie isolated):");
    println!(
        "    alice → bob:     {}",
        sim.topology().can_reach("alice", "bob")
    );
    println!(
        "    alice → charlie: {}",
        sim.topology().can_reach("alice", "charlie")
    );
    println!(
        "    bob → charlie:   {}",
        sim.topology().can_reach("bob", "charlie")
    );
    assert!(sim.topology().can_reach("alice", "bob"));
    assert!(!sim.topology().can_reach("alice", "charlie"));
    assert!(!sim.topology().can_reach("bob", "charlie"));
    println!();

    // Heal.
    sim.topology_mut().heal("alice", "charlie");
    sim.topology_mut().heal("bob", "charlie");

    println!("  After heal:");
    println!(
        "    alice → charlie: {}",
        sim.topology().can_reach("alice", "charlie")
    );
    println!(
        "    bob → charlie:   {}",
        sim.topology().can_reach("bob", "charlie")
    );
    assert!(sim.topology().can_reach("alice", "charlie"));
    assert!(sim.topology().can_reach("bob", "charlie"));
    println!();

    // =====================================================================
    // PHASE 10: Time Control & TTL Expiry
    // =====================================================================
    println!("━━━ PHASE 10: Time Control & TTL Expiry ━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Store a blob with 60s TTL in relay-alpha.
    let ttl_relay = sim.relay("relay-alpha").unwrap().clone();
    let ttl_transport = InMemoryTransport::with_clock(Arc::clone(&ttl_relay), {
        let c = Arc::clone(sim.clock());
        Arc::new(move || c.now_secs())
    });

    let ttl_env = scp_core::envelope::outer::create_outer_envelope(
        &[0xFF; 32],
        None,
        60,
        b"ephemeral data".to_vec(),
    )
    .unwrap();
    ttl_transport.send(&ttl_env).await.unwrap();

    let blobs_before = { ttl_relay.lock().unwrap().blob_count() };
    println!("  Stored blob with TTL=60s at t={}", sim.clock().now_secs());
    println!("  Blobs in relay: {blobs_before}");
    println!();

    // Advance 30s — blob should still exist.
    sim.advance_time(30);
    let expired_30 = {
        ttl_relay
            .lock()
            .unwrap()
            .expire_blobs(sim.clock().now_secs())
    };
    let blobs_at_30 = { ttl_relay.lock().unwrap().blob_count() };
    println!("  Advanced 30s → t={}", sim.clock().now_secs());
    println!("  Expired: {expired_30}, Remaining: {blobs_at_30}");
    assert!(blobs_at_30 > 0, "blob should still exist at t+30s");
    println!();

    // Advance another 61s — blob should be expired.
    sim.advance_time(61);
    let expired_91 = {
        ttl_relay
            .lock()
            .unwrap()
            .expire_blobs(sim.clock().now_secs())
    };
    let blobs_at_91 = { ttl_relay.lock().unwrap().blob_count() };
    println!("  Advanced 61s more → t={}", sim.clock().now_secs());
    println!("  Expired: {expired_91}, Remaining: {blobs_at_91}");
    // Note: the first blob from Phase 5 had TTL=3600 and is also stored here.
    // The TTL=60 blob should be expired. The TTL=3600 blob from phase 5 may or
    // may not be expired depending on clock alignment.
    println!();

    // =====================================================================
    // PHASE 11: Deletion Non-Compliance
    // =====================================================================
    println!("━━━ PHASE 11: Deletion Non-Compliance ━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let noncompliant_relay = Arc::new(Mutex::new(InMemoryRelay::with_behavior(
        BehaviorMode::DeletionNonCompliant,
    )));

    // Store a blob.
    let blob_id_nc = {
        let mut relay = noncompliant_relay.lock().unwrap();
        relay.store([0xAA; 32], vec![0x01, 0x02], None, 100)
    };
    println!("  Stored blob: {}...", hex::encode(&blob_id_nc[..4]));

    // Try to delete.
    let deleted = {
        let mut relay = noncompliant_relay.lock().unwrap();
        relay.delete(&blob_id_nc)
    };
    println!("  Delete returned: {deleted}");

    // Blob should still be there.
    let still_exists = {
        let relay = noncompliant_relay.lock().unwrap();
        relay.get(&blob_id_nc).is_some()
    };
    println!("  Blob still exists: {still_exists}");
    assert!(!deleted, "deletion-noncompliant relay should refuse delete");
    assert!(still_exists, "blob should persist despite delete request");
    println!("  (This simulates a relay that ignores deletion requests)");
    println!();

    // =====================================================================
    // Summary
    // =====================================================================
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    DEMO COMPLETE                           ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Phases demonstrated:                                      ║");
    println!("║    1. Network setup (clock, relay, identities, topology)    ║");
    println!("║    2. Ed25519 key material generation                      ║");
    println!("║    3. MLS group creation & member addition                 ║");
    println!("║    4. Sender key distribution via HPKE pull protocol       ║");
    println!("║    5. Double encryption (sender key + MLS) & relay routing ║");
    println!("║    6. Relay suppression (drop every 2nd message)           ║");
    println!("║    7. Relay equivocation (divergent content detection)     ║");
    println!("║    8. Relay replay (duplicate delivery → BlobId dedup)     ║");
    println!("║    9. Network partition & heal                             ║");
    println!("║   10. Simulated time control & TTL expiry                  ║");
    println!("║   11. Deletion non-compliance                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}

// =========================================================================
// DEMO 2: Application Layer — ContextManager, Tools, Governance
// =========================================================================

/// Mock crypto provider — returns payload as-is (no real encryption).
/// The `ContextManager` pipeline, tool system, governance engine, and role
/// system are all 100% real. Only the MLS/sender-key operations are mocked.
#[derive(Default)]
struct DemoCrypto;

impl scp_core::context::builder::ContextCryptoProvider for DemoCrypto {
    fn validate_creator_identity(
        &self,
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _: &str,
        _: Option<&[u8]>,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn add_member(
        &self,
        _: &[u8; 32],
        _: &str,
        _: Option<&[u8]>,
    ) -> Result<scp_core::context::AddMemberOutput, scp_core::context::ContextError> {
        Ok(scp_core::context::AddMemberOutput::default())
    }
    fn remove_member(
        &self,
        _: &[u8; 32],
        _: &str,
    ) -> Result<scp_core::context::RemoveMemberOutput, scp_core::context::ContextError> {
        Ok(scp_core::context::RemoveMemberOutput::default())
    }
    fn distribute_sender_key(
        &self,
        _: &[u8; 32],
        _: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _: &[u8; 32],
        _: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }

    fn seal(
        &self,
        _context_id: &[u8; 32],
        inner: &scp_core::envelope::inner::InnerEnvelope,
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, scp_core::context::ContextError> {
        // Mock: serialize inner envelope directly (no encryption).
        rmp_serde::to_vec_named(inner)
            .map_err(|e| scp_core::context::ContextError::CryptoFailed(format!("mock seal: {e}")))
    }

    fn open(
        &self,
        _context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_core::context::builder::OpenResult, scp_core::context::ContextError> {
        // Mock: deserialize directly as InnerEnvelope (no decryption).
        let inner: scp_core::envelope::inner::InnerEnvelope = rmp_serde::from_slice(outer_bytes)
            .map_err(|e| {
                scp_core::context::ContextError::CryptoFailed(format!("mock open: {e}"))
            })?;
        let sender_did = inner.sender_did.clone();
        Ok(scp_core::context::builder::OpenResult::Application(
            Box::new(scp_core::context::builder::OpenedEnvelope { inner, sender_did }),
        ))
    }
}

/// Mock transport — captures sent messages.
struct DemoTransport {
    connected: std::sync::atomic::AtomicBool,
    messages: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl DemoTransport {
    fn new() -> Self {
        let t = Self {
            connected: std::sync::atomic::AtomicBool::new(false),
            messages: std::sync::Mutex::new(Vec::new()),
        };
        t.connected
            .store(true, std::sync::atomic::Ordering::Relaxed);
        t
    }
    #[allow(dead_code)]
    fn sent_count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }
}

impl scp_core::context::builder::ContextTransportProvider for DemoTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn publish_context(
        &self,
        _: &[u8; 32],
        _: &scp_core::context::ContextParams,
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn delete_published(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn send_message(
        &self,
        _: &[u8; 32],
        payload: &[u8],
    ) -> Result<(), scp_core::context::ContextError> {
        self.messages.lock().unwrap().push(payload.to_vec());
        Ok(())
    }
}

/// Mock event log — captures appended events.
#[derive(Default)]
struct DemoEventLog {
    events: std::sync::Mutex<Vec<String>>,
}

impl scp_core::context::builder::ContextEventLogProvider for DemoEventLog {
    fn init_event_log(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _: &[u8; 32],
        event_type: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        self.events.lock().unwrap().push(format!("{event_type:?}"));
        Ok(())
    }
    fn destroy_event_log(
        &self,
        _: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// Deterministic key resolver for governance vote verification.
fn demo_key_resolver() -> scp_core::context::governance::KeyResolver {
    std::sync::Arc::new(
        |did: &scp_did::DID, _kid: scp_did::SigningKeyId| -> Option<ed25519_dalek::VerifyingKey> {
            use ed25519_dalek::SigningKey;
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            did.as_ref().hash(&mut hasher);
            let h = hasher.finish();
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&h.to_le_bytes());
            Some(SigningKey::from_bytes(&seed).verifying_key())
        },
    )
}

fn demo_signing_key(did: &scp_did::DID) -> ed25519_dalek::SigningKey {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.as_ref().hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

#[tokio::test]
#[ignore = "DemoCrypto mock impls the deleted ContextCryptoProvider trait; full file rewire to MlsCryptoProvider::with_backends mock backends is tracked alongside the commit-12 deletion of ContextManager. File-level cfg(any()) gates compilation."]
#[allow(clippy::too_many_lines)]
async fn application_layer_demo() {
    use scp_core::context::manager::ContextManager;
    use scp_core::context::membership::{ContextEvent, KeyPackage};
    use scp_core::context::roles::{CapabilityCeiling, ContextRoleState};
    use scp_core::context::tools::registry::{ToolRegistration, ToolRegistry, ToolSchema};
    use scp_core::context::tools::{invoke_tool, register_tool};
    use scp_core::context::{Capability, ContextParams, ContextState, GovernanceAction};
    use scp_did::DID;

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     SCP APPLICATION LAYER — CONTEXT, TOOLS, GOVERNANCE     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // =====================================================================
    // PHASE 1: Context Creation
    // =====================================================================
    println!("━━━ PHASE 1: Context Creation via ContextManager ━━━━━━━━━━━━");
    println!();

    let transport_for_manager: Box<dyn scp_core::context::builder::ContextTransportProvider> =
        Box::new(DemoTransport::new());

    // ADR-049 commit 12c.9c — wrap with `attach_test_supervisor` so
    // `ContextManager`'s messaging/governance/broadcast/economy
    // forwarders can resolve their `Weak<Supervisor>` back-pointer.
    let manager = scp_core::context::attach_test_supervisor(ContextManager::new(
        Box::new(DemoCrypto),
        transport_for_manager,
        Box::new(DemoEventLog::default()),
        demo_key_resolver(),
    ));

    let alice: DID = "did:dht:z6MkAliceApp".into();
    let bob: DID = "did:dht:z6MkBobApp".into();
    let charlie: DID = "did:dht:z6MkCharlieApp".into();
    let ctx_id = "ctx-app-demo";

    let params = ContextParams {
        ceiling: vec![
            Capability::new("messages:read"),
            Capability::new("messages:write"),
            Capability::new("tool:register"),
            Capability::new("tool:invoke:*"),
            Capability::new("role:assign"),
            Capability::new("member:remove"),
            Capability::new("governance:propose"),
            Capability::new("governance:vote"),
            Capability::new("context:close"),
        ],
        ..ContextParams::default()
    };

    println!("  Creating context '{ctx_id}'...");
    println!("  Creator:    {alice}");
    println!("  Mode:       {:?}", params.mode);
    println!("  Ceiling:    {} capabilities", params.ceiling.len());
    for cap in &params.ceiling {
        println!("    - {}", cap.name());
    }
    println!();

    let handle = manager
        .create_context(ctx_id.to_owned(), params, alice.clone(), None)
        .await
        .unwrap();
    let state = handle.state().await;

    println!("  Context created!");
    println!("    state:    {state:?}");
    println!("    context:  {}", handle.context_id());
    assert_eq!(state, ContextState::Active);
    println!();

    // =====================================================================
    // PHASE 2: Membership — Join & Verify
    // =====================================================================
    println!("━━━ PHASE 2: Membership — Join & Verify ━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let bob_kp = KeyPackage {
        owner_did: bob.clone(),
        mls_key_package_bytes: None,
    };
    manager
        .join_context(&handle, bob_kp, None, None)
        .await
        .unwrap();
    println!("  Bob joined context");

    let charlie_kp = KeyPackage {
        owner_did: charlie.clone(),
        mls_key_package_bytes: None,
    };
    manager
        .join_context(&handle, charlie_kp, None, None)
        .await
        .unwrap();
    println!("  Charlie joined context");

    let count = manager.member_count(ctx_id).await.unwrap();
    let alice_is_member = manager.is_member(ctx_id, &alice).await;
    let bob_is_member = manager.is_member(ctx_id, &bob).await;
    let charlie_is_member = manager.is_member(ctx_id, &charlie).await;

    println!("  Member count: {count}");
    println!("    Alice:   {alice_is_member}");
    println!("    Bob:     {bob_is_member}");
    println!("    Charlie: {charlie_is_member}");
    assert_eq!(count, 3);
    assert!(alice_is_member && bob_is_member && charlie_is_member);
    println!();

    // =====================================================================
    // PHASE 3: Messaging
    // =====================================================================
    println!("━━━ PHASE 3: Messaging via ContextManager ━━━━━━━━━━━━━━━━━━━");
    println!();

    let msg1 = b"Hello everyone, Alice here!";
    let msg2 = b"Bob here. Received your message.";
    let msg3 = b"Charlie joining the conversation.";

    let alice_sk = demo_signing_key(&alice);
    manager
        .send_message(
            &handle,
            &alice,
            msg1,
            scp_core::context::supervisor::MessageSigner::Active(&alice_sk),
            None,
            None,
        )
        .await
        .unwrap();
    println!("  Alice sent:   \"{}\"", String::from_utf8_lossy(msg1));

    let bob_sk = demo_signing_key(&bob);
    manager
        .send_message(
            &handle,
            &bob,
            msg2,
            scp_core::context::supervisor::MessageSigner::Active(&bob_sk),
            None,
            None,
        )
        .await
        .unwrap();
    println!("  Bob sent:     \"{}\"", String::from_utf8_lossy(msg2));

    let charlie_sk = demo_signing_key(&charlie);
    manager
        .send_message(
            &handle,
            &charlie,
            msg3,
            scp_core::context::supervisor::MessageSigner::Active(&charlie_sk),
            None,
            None,
        )
        .await
        .unwrap();
    println!("  Charlie sent: \"{}\"", String::from_utf8_lossy(msg3));
    println!();

    // Drain events to see what happened.
    let events = manager.drain_events(ctx_id).await;
    let msg_events: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ContextEvent::MessageSent {
                sender_did,
                payload,
                ..
            } => Some((sender_did.clone(), payload.clone())),
            _ => None,
        })
        .collect();

    println!(
        "  Events drained: {} total, {} messages",
        events.len(),
        msg_events.len()
    );
    for (sender_did, payload) in &msg_events {
        println!(
            "    [{sender_did}] \"{}\"",
            String::from_utf8_lossy(payload)
        );
    }
    assert_eq!(msg_events.len(), 3);
    println!();

    // =====================================================================
    // PHASE 4: Tool Registration
    // =====================================================================
    println!("━━━ PHASE 4: Tool Registration ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Build the role state directly — ContextManager tracks this internally,
    // but for the free-function tool API we need to construct it.
    let ceiling = CapabilityCeiling::new(vec![
        Capability::new("messages:read"),
        Capability::new("messages:write"),
        Capability::new("tool:register"),
        Capability::new("tool:invoke:*"),
        Capability::new("role:assign"),
        Capability::new("member:remove"),
        Capability::new("governance:propose"),
        Capability::new("governance:vote"),
        Capability::new("context:close"),
    ]);
    let mut role_state = ContextRoleState::new(
        ctx_id,
        alice.as_ref(),
        ceiling,
        vec![],
        &scp_clock::SystemClock,
    )
    .unwrap();

    // Add Bob and Charlie as members with "member" role (ToolInvokeAll capability).
    {
        use scp_core::context::roles::assign_role;
        role_state.members.insert(bob.as_ref().to_owned());
        role_state.members.insert(charlie.as_ref().to_owned());
        assign_role(
            &mut role_state,
            bob.as_ref(),
            "member",
            alice.as_ref(),
            &scp_clock::SystemClock,
        )
        .unwrap();
        assign_role(
            &mut role_state,
            charlie.as_ref(),
            "member",
            alice.as_ref(),
            &scp_clock::SystemClock,
        )
        .unwrap();
    }

    let mut tool_registry = ToolRegistry::new();

    let search_tool = ToolRegistration {
        tool_id: "search-web".to_owned(),
        name: "Web Search".to_owned(),
        description: "Search the web for information".to_owned(),
        schema: ToolSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "max_results": { "type": "integer" }
                },
                "required": ["query"]
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "results": {
                        "type": "array",
                        "items": { "type": "object" }
                    },
                    "total": { "type": "integer" }
                }
            }),
        },
        implementation_hash: [0xAB; 32],
        test_vectors: vec![],
        operator_did: alice.clone(),
        cost: None,
        registered_at: 1_700_000_000,
        signature: vec![],
    };

    println!("  Registering tool: '{}'", search_tool.name);
    println!("    tool_id:     {}", search_tool.tool_id);
    println!("    operator:    {}", search_tool.operator_did);
    println!("    input:       query (string), max_results (integer)");
    println!("    output:      results (array), total (integer)");

    let (tool_id, reg_event) =
        register_tool(&mut tool_registry, &role_state, search_tool, alice.as_ref()).unwrap();

    println!("  Registered! tool_id = {tool_id}");
    println!(
        "    event: tool_id={}, registrant={}",
        reg_event.tool_id, reg_event.registrant_did
    );
    assert_eq!(tool_registry.len(), 1);
    println!("    registry size: {}", tool_registry.len());
    println!();

    // Register a second tool.
    let calc_tool = ToolRegistration {
        tool_id: "calculator".to_owned(),
        name: "Calculator".to_owned(),
        description: "Perform arithmetic operations".to_owned(),
        schema: ToolSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "operation": { "type": "string" },
                    "operands": { "type": "array", "items": { "type": "number" } }
                },
                "required": ["operation", "operands"]
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "result": { "type": "number" },
                    "operation": { "type": "string" }
                }
            }),
        },
        implementation_hash: [0xCD; 32],
        test_vectors: vec![],
        operator_did: alice.clone(),
        cost: None,
        registered_at: 1_700_000_001,
        signature: vec![],
    };

    let (calc_id, _) =
        register_tool(&mut tool_registry, &role_state, calc_tool, alice.as_ref()).unwrap();
    println!("  Registered tool: 'Calculator' (id={calc_id})");
    println!("    registry size: {}", tool_registry.len());
    assert_eq!(tool_registry.len(), 2);
    println!();

    // =====================================================================
    // PHASE 5: Tool Invocation
    // =====================================================================
    println!("━━━ PHASE 5: Tool Invocation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let search_input = serde_json::json!({
        "query": "SCP protocol specification",
        "max_results": 5
    });

    println!("  Invoking 'search-web' as Bob:");
    println!("    input: {search_input}");

    // The executor is a real async function that simulates the tool.
    let (output, invoke_event, _consequences, _receipt) = invoke_tool(
        &handle,
        &tool_registry,
        &role_state,
        &"search-web".to_owned(),
        search_input,
        &bob,
        Some(5000),
        |input| async move {
            // Simulate a web search — this is the tool's actual executor.
            let query = input["query"].as_str().unwrap_or("unknown");
            let max = input["max_results"].as_u64().unwrap_or(10);
            Ok(serde_json::json!({
                "results": [
                    {"title": format!("Result 1 for '{query}'"), "url": "https://example.com/1"},
                    {"title": format!("Result 2 for '{query}'"), "url": "https://example.com/2"},
                ],
                "total": std::cmp::min(max, 2)
            }))
        },
        None::<&mut scp_core::context::tools::invoke::ToolEconomyContext<'_>>,
    )
    .await
    .unwrap();

    println!("    output: {output}");
    println!(
        "    event:  tool={}, invoker={}, duration_ms={}",
        invoke_event.tool_id, invoke_event.invoker_did, invoke_event.execution_time_ms
    );
    assert_eq!(output["total"], 2);
    println!();

    // Calculator invocation.
    let calc_input = serde_json::json!({
        "operation": "multiply",
        "operands": [6, 7]
    });

    println!("  Invoking 'calculator' as Charlie:");
    println!("    input: {calc_input}");

    let (calc_output, _, _consequences, _receipt) = invoke_tool(
        &handle,
        &tool_registry,
        &role_state,
        &"calculator".to_owned(),
        calc_input,
        &charlie,
        None,
        |input| async move {
            let op = input["operation"].as_str().unwrap_or("add");
            let operands: Vec<f64> = input["operands"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(serde_json::Value::as_f64)
                .collect();
            let result = match op {
                "multiply" => operands.iter().product::<f64>(),
                "add" => operands.iter().sum::<f64>(),
                _ => 0.0,
            };
            Ok(serde_json::json!({
                "result": result,
                "operation": op
            }))
        },
        None::<&mut scp_core::context::tools::invoke::ToolEconomyContext<'_>>,
    )
    .await
    .unwrap();

    println!("    output: {calc_output}");
    assert_eq!(calc_output["result"], 42.0);
    println!("    6 × 7 = {}", calc_output["result"]);
    println!();

    // =====================================================================
    // PHASE 6: Governance — Propose & Execute
    // =====================================================================
    println!("━━━ PHASE 6: Governance — Propose & Execute ━━━━━━━━━━━━━━━━━");
    println!();

    // Use SingleAdmin engine — Alice (creator) is admin.
    let alice_signing_key = demo_signing_key(&alice);

    println!("  Governance model: SingleAdmin (Alice is admin)");
    println!("  Proposing: RemoveMember(Charlie)");
    println!();

    // Propose via ContextManager.
    let (proposal, gov_events, _) = manager
        .propose_governance_action(
            ctx_id,
            &alice,
            GovernanceAction::RemoveMember {
                did: charlie.clone(),
                reason: Some("demo: testing governance removal".to_owned()),
            },
            &alice_signing_key,
        )
        .await
        .unwrap();

    println!("  Proposal created & auto-executed (SingleAdmin):");
    println!(
        "    id:       {}...",
        hex::encode(&proposal.proposal_id[..8])
    );
    println!("    proposer: {}", proposal.proposer_did);
    println!("    status:   {:?}", proposal.status);
    println!("    events:   {}", gov_events.len());
    for event in &gov_events {
        println!("      - {event:?}");
    }

    let new_count = manager.member_count(ctx_id).await.unwrap();
    let charlie_still_member = manager.is_member(ctx_id, &charlie).await;
    println!("    member count: {new_count} (was 3)");
    println!("    Charlie is member: {charlie_still_member}");
    assert_eq!(new_count, 2);
    assert!(!charlie_still_member);
    println!();

    // =====================================================================
    // PHASE 7: Context Close
    // =====================================================================
    println!("━━━ PHASE 7: Context Close ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let (close_proposal, _, _) = manager
        .propose_governance_action(
            ctx_id,
            &alice,
            GovernanceAction::CloseContext { reason: None },
            &alice_signing_key,
        )
        .await
        .unwrap();

    println!("  Proposed & auto-executed: CloseContext");
    println!("    status: {:?}", close_proposal.status);

    let final_state = handle.state().await;
    println!("  Context state: {final_state:?}");
    assert!(
        matches!(final_state, ContextState::Closing | ContextState::Closed),
        "context should be closing or closed"
    );
    println!();

    // =====================================================================
    // Summary
    // =====================================================================
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              APPLICATION LAYER DEMO COMPLETE               ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Phases demonstrated:                                      ║");
    println!("║    1. Context creation via ContextManager (real lifecycle)  ║");
    println!("║    2. Membership: join, verify, member_count, is_member    ║");
    println!("║    3. Messaging: send_message, drain_events                ║");
    println!("║    4. Tool registration (schema validation, capability ck) ║");
    println!("║    5. Tool invocation (real async executors, timeouts)     ║");
    println!("║    6. Governance: propose + execute (SingleAdmin engine)   ║");
    println!("║    7. Context close via governance action                  ║");
    println!("║                                                            ║");
    println!("║  What's real vs mocked:                                    ║");
    println!("║    REAL: ContextManager, tool registry, schema validation, ║");
    println!("║          role system, capability checks, governance engine, ║");
    println!("║          event log, membership state, context lifecycle    ║");
    println!("║    MOCK: MLS group ops, sender key ops, relay transport    ║");
    println!("║          (tested in demo 1 with real crypto)               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
