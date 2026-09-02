#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    // The `application_layer_demo` full-stack futures (real MLS create → add →
    // join → send → governance) exceed clippy's 16 KB stack budget.
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
use scp_core::crypto::mls::group::{add_member, create_group, join_group};
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

    // Drain EXACTLY the 3 delivered messages (the relay drops #2, #4, #6). Each
    // recv gets a generous timeout so scheduler jitter under CI parallelism can
    // never truncate the count; a fixed 100ms inter-message gap could miscount a
    // delayed in-memory delivery.
    let mut received_msgs = Vec::new();
    for _ in 0..3 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), charlie_stream.next()).await {
            Ok(Some(TransportEvent::Envelope(env))) => {
                received_msgs.push(String::from_utf8_lossy(&env.encrypted_blob).to_string());
            }
            _ => panic!(
                "suppressing relay must deliver 3 of 6 messages — only received {} before timeout",
                received_msgs.len()
            ),
        }
    }
    // No 4th message may arrive: the suppressed messages are dropped at send, so
    // a short negative wait suffices to prove "exactly 3, no more".
    let extra =
        tokio::time::timeout(std::time::Duration::from_millis(500), charlie_stream.next()).await;
    assert!(
        matches!(extra, Err(_) | Ok(None)),
        "suppressing relay must deliver exactly 3 of 6 messages — a 4th arrived"
    );
    let received_count = received_msgs.len() as u32;

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

    println!("  Subscriber 1 received: {:02x?}", msg1.data);
    println!("  Subscriber 2 received: {:02x?}", msg2.data);
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

    // Drain EXACTLY the 3 copies (1 original + 2 replays), each enqueued at
    // store time. A generous per-item timeout absorbs CI scheduler jitter; a
    // fixed 100ms gap could miscount a delayed in-memory delivery.
    let mut replay_received = 0u32;
    for _ in 0..3 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), replay_rx.recv()).await {
            Ok(Some(_)) => replay_received += 1,
            _ => panic!(
                "replaying relay must deliver 3 copies — only received {replay_received} before timeout"
            ),
        }
    }
    // No 4th copy may arrive.
    let extra = tokio::time::timeout(std::time::Duration::from_millis(500), replay_rx.recv()).await;
    assert!(
        matches!(extra, Err(_) | Ok(None)),
        "replaying relay must deliver exactly 3 copies — a 4th arrived"
    );
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

    // Store a blob with 60s TTL in a FRESH relay so the expiry assertion is
    // unambiguous — reusing `relay-alpha` would mix in the Phase-5 TTL=3600 blob
    // and make "how many expired" depend on unrelated state.
    let ttl_relay = Arc::new(Mutex::new(InMemoryRelay::new()));
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
    assert_eq!(
        blobs_before, 1,
        "the fresh relay must hold exactly the one TTL=60 blob just stored"
    );
    println!();

    // Advance 30s (< TTL) — the blob must still exist and nothing expires.
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
    assert_eq!(
        expired_30, 0,
        "nothing may expire before the TTL=60 boundary"
    );
    assert_eq!(blobs_at_30, 1, "the blob must still exist at t+30s (< TTL)");
    println!();

    // Advance another 61s (t+91, > TTL=60) — the blob MUST now expire.
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
    assert_eq!(
        expired_91, 1,
        "the TTL=60 blob must be expired once the clock passes the boundary"
    );
    assert_eq!(
        blobs_at_91, 0,
        "the fresh relay must be empty after its only blob expired"
    );
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
// DEMO 2: Application Layer — Context, Membership, Messaging, Governance, Outlets
// =========================================================================
//
// ADR-049 §15 deleted the old `ContextManager` + `ContextCryptoProvider` /
// `ContextTransportProvider` / `ContextEventLogProvider` mock-provider
// architecture and replaced it with the actor-per-context `Supervisor`. This
// demo exercises the SAME application domains on the CURRENT architecture:
//
//   - context creation, multi-party membership, encrypted messaging, and
//     governance run through the REAL `Supervisor` (real MLS crypto, real
//     sender keys, real event log) via the `FullStackNetwork` harness — the
//     exact substrate the enabled `fullstack.rs` tests drive;
//   - outlet registration + invocation run through the free-function outlet API
//     (`register_outlet` / `invoke_outlet_aggregating`) with a hand-built role
//     state — the runtime-unit pattern used by `invoke.rs`'s own tests and by
//     `outlet_stream_vectors_through_open_path.rs`.

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn application_layer_demo() {
    use scp_core::context::governance::GovernanceAction;
    use scp_core::context::outlets::OutletKind;
    use scp_core::context::outlets::invoke::{OutletEconomyContext, invoke_outlet_aggregating};
    use scp_core::context::outlets::registry::{
        OutletRegistration, OutletRegistry, OutletSchema, register_outlet,
    };
    use scp_core::context::{
        Capability, ContextHandle, ContextMode, ContextParams, ContextState, context_id_bytes,
    };
    use scp_did::DID;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use scp_testing::fullstack::FullStackNetwork;

    const ALICE_DID: &str = "did:dht:z6MkAliceApp";
    const BOB_DID: &str = "did:dht:z6MkBobApp";
    const CHARLIE_DID: &str = "did:dht:z6MkCharlieApp";

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     SCP APPLICATION LAYER — CONTEXT, OUTLETS, GOVERNANCE     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // =====================================================================
    // PHASE 1: Context Creation (real Supervisor via FullStackNetwork)
    // =====================================================================
    println!("━━━ PHASE 1: Context Creation via Supervisor ━━━━━━━━━━━━━━━━");
    println!();

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);
    let charlie = network.create_node(CHARLIE_DID);

    let ctx_id = "ctx-app-demo";
    let ctx_bytes = context_id_bytes(ctx_id);

    // Encrypted context. The ceiling grants the admin the capabilities the demo
    // exercises — membership, governance, and (for the outlet phase's mirrored
    // ceiling) outlet register + call.
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::OutletRegister,
            Capability::OutletCallAll,
        ],
        ..ContextParams::default()
    };

    println!("  Creating context '{ctx_id}'...");
    println!("  Creator:    {ALICE_DID}");
    println!("  Mode:       {:?}", params.mode);
    println!("  Ceiling:    {} capabilities", params.ceiling.len());
    println!();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    let state = handle.state();
    println!("  Context created!");
    println!("    state:    {state:?}");
    println!("    context:  {}", handle.context_id());
    assert_eq!(state, ContextState::Active);
    println!();

    // =====================================================================
    // PHASE 2: Membership — Add, Join & Verify (real MLS group)
    // =====================================================================
    println!("━━━ PHASE 2: Membership — Add, Join & Verify ━━━━━━━━━━━━━━━━");
    println!();

    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  Bob added + joined the context (real MLS Welcome)");

    alice.add_member(&handle, CHARLIE_DID).await.unwrap();
    charlie.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  Charlie added + joined the context (real MLS Welcome)");

    let count = alice.manager.member_count(ctx_id).await;
    let alice_is_member = alice.manager.is_member(ctx_id, ALICE_DID).await;
    let bob_is_member = alice.manager.is_member(ctx_id, BOB_DID).await;
    let charlie_is_member = alice.manager.is_member(ctx_id, CHARLIE_DID).await;

    println!("  Member count: {count:?}");
    println!("    Alice:   {alice_is_member}");
    println!("    Bob:     {bob_is_member}");
    println!("    Charlie: {charlie_is_member}");
    assert_eq!(count, Some(3));
    assert!(alice_is_member && bob_is_member && charlie_is_member);
    println!();

    // =====================================================================
    // PHASE 3: Messaging (real encryption; §9.10.4 per-member fan-out)
    // =====================================================================
    println!("━━━ PHASE 3: Messaging via Supervisor ━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // §9.10.4: an encrypted multi-member send fans the same MLS ciphertext out to
    // each peer's per-member pseudonym routing ID — never the shared
    // context_routing_id. Seed each peer's pseudonym or the send fails closed with
    // PseudonymRegistryEmpty (mirrors `fullstack_three_party_group`).
    let bob_pseudonym = [0x42u8; 32];
    let charlie_pseudonym = [0x43u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(CHARLIE_DID), charlie_pseudonym)
        .await
        .unwrap();

    let plaintext = b"Hello everyone, Alice here!";
    alice.send_message(&handle, plaintext).await.unwrap();
    println!("  Alice sent:   \"{}\"", String::from_utf8_lossy(plaintext));

    let sent = alice.take_sent_ciphertexts();
    assert_eq!(sent.len(), 2, "fan-out must address both peer pseudonyms");
    let bob_ciphertext = sent
        .iter()
        .find(|(rid, _)| rid == &bob_pseudonym)
        .map(|(_, ct)| ct.clone())
        .expect("a send addressed to Bob's pseudonym must exist");
    let charlie_ciphertext = sent
        .iter()
        .find(|(rid, _)| rid == &charlie_pseudonym)
        .map(|(_, ct)| ct.clone())
        .expect("a send addressed to Charlie's pseudonym must exist");

    let bob_decrypted = bob
        .decrypt_message(ctx_id, &ctx_bytes, &bob_ciphertext, ALICE_DID)
        .await
        .unwrap();
    assert_eq!(bob_decrypted.as_slice(), plaintext.as_slice());
    println!(
        "  Bob decrypted:     \"{}\"",
        String::from_utf8_lossy(&bob_decrypted)
    );

    let charlie_decrypted = charlie
        .decrypt_message(ctx_id, &ctx_bytes, &charlie_ciphertext, ALICE_DID)
        .await
        .unwrap();
    assert_eq!(charlie_decrypted.as_slice(), plaintext.as_slice());
    println!(
        "  Charlie decrypted: \"{}\"",
        String::from_utf8_lossy(&charlie_decrypted)
    );

    // Events prove membership + messaging were logged on Alice's side.
    let events = alice.drain_events(ctx_id).await;
    let joined = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                scp_core::context::membership::ContextEvent::MemberJoined { .. }
            )
        })
        .count();
    let messages = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                scp_core::context::membership::ContextEvent::MessageSent { .. }
            )
        })
        .count();
    println!("  Events: {joined} MemberJoined, {messages} MessageSent");
    assert_eq!(joined, 2, "Bob and Charlie each logged a MemberJoined");
    assert_eq!(messages, 1, "one application message was logged");
    println!();

    // =====================================================================
    // PHASE 4: Governance — Propose & Auto-Execute (SingleAdmin engine)
    // =====================================================================
    println!("━━━ PHASE 4: Governance — Propose & Execute ━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Governance model: SingleAdmin (Alice is admin)");
    println!("  Proposing: RemoveMember(Charlie)");
    println!();

    let proposal = alice
        .propose_governance(
            ctx_id,
            GovernanceAction::RemoveMember {
                did: DID::from(CHARLIE_DID),
                reason: Some("demo: testing governance removal".to_owned()),
            },
        )
        .await
        .unwrap();
    // Removing Charlie broadcasts an epoch-advance MLS Commit to the remaining
    // members; drain it so it does not pollute later assertions.
    let _ = alice.take_sent_ciphertexts();

    println!("  Proposal created & auto-executed (SingleAdmin):");
    println!("    proposer: {}", proposal.proposer_did);
    println!("    status:   {:?}", proposal.status);

    let new_count = alice.manager.member_count(ctx_id).await;
    let charlie_still_member = alice.manager.is_member(ctx_id, CHARLIE_DID).await;
    println!("    member count: {new_count:?} (was Some(3))");
    println!("    Charlie is member: {charlie_still_member}");
    assert_eq!(new_count, Some(2));
    assert!(!charlie_still_member);
    println!();

    // =====================================================================
    // PHASE 5: Context Close (governance action)
    // =====================================================================
    println!("━━━ PHASE 5: Context Close ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let close_proposal = alice
        .propose_governance(ctx_id, GovernanceAction::CloseContext { reason: None })
        .await
        .unwrap();
    println!("  Proposed & auto-executed: CloseContext");
    println!("    status: {:?}", close_proposal.status);

    let final_state = handle.state();
    println!("  Context state: {final_state:?}");
    assert!(
        matches!(final_state, ContextState::Closing | ContextState::Closed),
        "context should be closing or closed after CloseContext"
    );
    println!();

    // =====================================================================
    // PHASE 6: Outlet Registration & Invocation (free-function API)
    // =====================================================================
    println!("━━━ PHASE 6: Outlet Registration & Invocation ━━━━━━━━━━━━━━━");
    println!();

    // Build a role state directly (the runtime-unit pattern, mirroring
    // `invoke.rs`'s own tests and `outlet_stream_vectors_through_open_path.rs`).
    // The creator inherits the ceiling; bob/charlie are added as invokers with
    // OutletCallAll so the §9.8.5 membership + capability gates clear.
    let outlet_ctx = "ctx-outlet-demo";
    let mut role_state = ContextRoleState::new(
        outlet_ctx.to_owned(),
        ALICE_DID,
        default_ceiling(),
        vec![],
        &scp_clock::TestClock::new(1_700_000_000),
    )
    .unwrap();
    role_state.members.insert(ALICE_DID.to_owned());
    {
        let caps = role_state
            .member_capabilities
            .entry(ALICE_DID.to_owned())
            .or_default();
        caps.insert(Capability::OutletRegister);
        caps.insert(Capability::OutletCallAll);
    }
    for invoker in [BOB_DID, CHARLIE_DID] {
        role_state.members.insert(invoker.to_owned());
        role_state
            .member_capabilities
            .entry(invoker.to_owned())
            .or_default()
            .insert(Capability::OutletCallAll);
    }

    let mut registry = OutletRegistry::new();

    let search_outlet = OutletRegistration {
        outlet_id: "search-web".to_owned(),
        kind: OutletKind::default(),
        name: "Web Search".to_owned(),
        description: "Search the web for information".to_owned(),
        schema: OutletSchema {
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
                    "results": { "type": "array", "items": { "type": "object" } },
                    "total": { "type": "integer" }
                }
            }),
            aggregate_schema: None,
        },
        implementation_hash: [0xAB; 32],
        test_vectors: vec![],
        operator_did: DID::from(ALICE_DID),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 1_700_000_000,
        signature: vec![],
    };
    let (search_id, _reg_event) =
        register_outlet(&mut registry, &role_state, search_outlet, ALICE_DID).unwrap();
    println!("  Registered outlet: 'Web Search' (id={search_id})");
    assert_eq!(registry.len(), 1);

    let calc_outlet = OutletRegistration {
        outlet_id: "calculator".to_owned(),
        kind: OutletKind::default(),
        name: "Calculator".to_owned(),
        description: "Perform arithmetic operations".to_owned(),
        schema: OutletSchema {
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
            aggregate_schema: None,
        },
        implementation_hash: [0xCD; 32],
        test_vectors: vec![],
        operator_did: DID::from(ALICE_DID),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 1_700_000_001,
        signature: vec![],
    };
    let (calc_id, _) = register_outlet(&mut registry, &role_state, calc_outlet, ALICE_DID).unwrap();
    println!("  Registered outlet: 'Calculator' (id={calc_id})");
    assert_eq!(registry.len(), 2);
    println!();

    // A live handle for invocation (does NOT go through the actor — mirrors the
    // runtime-unit invoke tests).
    let outlet_handle = ContextHandle::new(outlet_ctx.to_owned(), ContextParams::default());
    outlet_handle.transition_to(&ContextState::Active).unwrap();

    // Invoke 'search-web' as Bob.
    let search_input = serde_json::json!({
        "query": "SCP protocol specification",
        "max_results": 5
    });
    println!("  Invoking 'search-web' as Bob: {search_input}");
    let (output, invoke_event, _consequences, _receipt) = invoke_outlet_aggregating(
        &outlet_handle,
        &registry,
        &role_state,
        &"search-web".to_owned(),
        search_input,
        &DID::from(BOB_DID),
        Some(5000),
        |input: serde_json::Value| async move {
            let query = input["query"].as_str().unwrap_or("unknown");
            let max = input["max_results"].as_u64().unwrap_or(10);
            Ok::<_, String>(serde_json::json!({
                "results": [
                    {"title": format!("Result 1 for '{query}'"), "url": "https://example.com/1"},
                    {"title": format!("Result 2 for '{query}'"), "url": "https://example.com/2"},
                ],
                "total": std::cmp::min(max, 2)
            }))
        },
        None::<&mut OutletEconomyContext<'_>>,
        None,
    )
    .await
    .unwrap();
    println!("    output: {output}");
    println!(
        "    event:  outlet={}, invoker={}",
        invoke_event.outlet_id, invoke_event.invoker_did
    );
    assert_eq!(output["total"], 2);
    assert_eq!(invoke_event.invoker_did, BOB_DID);

    // Invoke 'calculator' as Charlie.
    let calc_input = serde_json::json!({
        "operation": "multiply",
        "operands": [6, 7]
    });
    println!("  Invoking 'calculator' as Charlie: {calc_input}");
    let (calc_output, _, _consequences, _receipt) = invoke_outlet_aggregating(
        &outlet_handle,
        &registry,
        &role_state,
        &"calculator".to_owned(),
        calc_input,
        &DID::from(CHARLIE_DID),
        None,
        |input: serde_json::Value| async move {
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
            Ok::<_, String>(serde_json::json!({ "result": result, "operation": op }))
        },
        None::<&mut OutletEconomyContext<'_>>,
        None,
    )
    .await
    .unwrap();
    println!("    output: {calc_output}");
    assert_eq!(calc_output["result"], 42.0);
    println!("    6 × 7 = {}", calc_output["result"]);
    println!();

    // =====================================================================
    // Summary
    // =====================================================================
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              APPLICATION LAYER DEMO COMPLETE               ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  1. Context creation via real Supervisor (real MLS)        ║");
    println!("║  2. Membership: add + join, member_count, is_member        ║");
    println!("║  3. Messaging: real encryption, §9.10.4 fan-out, decrypt   ║");
    println!("║  4. Governance: RemoveMember auto-executes (SingleAdmin)   ║");
    println!("║  5. Context close via governance action                    ║");
    println!("║  6. Outlet registration + invocation (schema + capability) ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
