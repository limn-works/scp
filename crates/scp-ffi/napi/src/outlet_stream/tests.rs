//! Tests for the §5.4.5 streaming-native outlet bridge (SCP-OUT-037, C8a).
//!
//! Three tiers, mirroring the `PyO3` reference bridge's `e2e_bridge.rs`:
//!
//! - **Non-gated** — the two pure protocol wrappers round-trip, and the six
//!   control-plane ops on an UNKNOWN handle return clean, distinct not-found
//!   errors (never a panic, never a silent `None`).
//! - **Live-flow** (gated `all(allow_in_memory_custody, testing,
//!   outlet-capability-test-grant)`) — a REAL member-backed stream driven
//!   through `poll_next` to its terminal, plus CRITICAL #1 (a non-invoker
//!   grant → `SCP-PERM-3001`). Unlike the `PyO3` reference this needs no
//!   GIL-deadlock guard (napi-rs has no GIL), but it still proves the open path
//!   is fully wired to `Supervisor::open_outlet_stream` and drains a genuine
//!   live pump.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// Pure protocol wrappers (non-gated)
// ---------------------------------------------------------------------------

/// The two pure protocol wrappers round-trip: `compute_caveats_binding`
/// produces the 32-byte binding matching the core helper, and
/// `verify_chunk_signature` accepts a correctly-signed chunk while rejecting one
/// signed under a different key (fail-closed).
#[test]
fn pure_wrappers_roundtrip() {
    let empty = scp_core::trust::caveats::InvocationCaveats::empty();
    let caveats_jcs = empty.to_canonical_json_bytes().unwrap();
    let request_id = [7u8; 16];

    let binding = outlet_stream_compute_caveats_binding_impl(
        b"cid-abc",
        &request_id,
        "did:dht:zInvoker",
        3,
        &caveats_jcs,
    )
    .unwrap();
    assert_eq!(binding.len(), 32, "caveats binding is 32 bytes");
    let expected =
        compute_caveats_binding(b"cid-abc", &request_id, "did:dht:zInvoker", 3, &caveats_jcs);
    assert_eq!(binding.as_slice(), expected.as_slice());

    // Sign a chunk with a known key; verify accepts under the matching key.
    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let vk = key.verifying_key();
    let binding32 = <[u8; 32]>::try_from(binding.as_slice()).unwrap();
    let payload = scp_core::context::outlets::stream::ChunkPayload::Data {
        value: serde_json::json!({ "sum": 3 }),
    };
    let sig = scp_core::context::outlets::stream::sign_chunk(
        &key,
        "ctx-1",
        "outlet-1",
        &request_id,
        0,
        &binding32,
        &payload,
    )
    .unwrap();
    let chunk = OutletStreamChunk {
        request_id,
        sequence: 0,
        payload,
        sig,
    };
    let chunk_bytes = serde_json::to_vec(&chunk).unwrap();
    assert!(
        outlet_stream_verify_chunk_signature_impl(
            &chunk_bytes,
            vk.as_bytes(),
            "ctx-1",
            "outlet-1",
            &binding32,
        )
        .unwrap(),
        "verify accepts a chunk signed under the matching operator key"
    );

    // A DIFFERENT key must be rejected (fail-closed).
    let other = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    assert!(
        !outlet_stream_verify_chunk_signature_impl(
            &chunk_bytes,
            other.verifying_key().as_bytes(),
            "ctx-1",
            "outlet-1",
            &binding32,
        )
        .unwrap(),
        "verify rejects a chunk signed under a different key"
    );
}

/// `compute_caveats_binding` rejects a `request_id` that is not 16 bytes
/// (fail-closed input validation).
#[test]
fn compute_caveats_binding_rejects_wrong_request_id_len() {
    let err = outlet_stream_compute_caveats_binding_impl(b"cid", &[0u8; 8], "did:dht:zX", 1, b"{}")
        .expect_err("an 8-byte request_id must be rejected");
    assert!(
        format!("{err}").contains("request_id must be 16 bytes"),
        "wrong-length request_id fails closed: {err}"
    );
}

// ---------------------------------------------------------------------------
// Control-plane not-found (non-gated)
// ---------------------------------------------------------------------------

/// Every control-plane op on an UNKNOWN handle returns a clean, distinct
/// not-found error — never a panic, and (for `poll_next`) never a silent `None`
/// that would masquerade as a clean stream end. The caller==invoker gate fires
/// only against a live entry, so an unknown handle rejects at the registry
/// lookup before any custody/supervisor work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_plane_unknown_handle_is_not_found() {
    let bi = NapiBridgeInstance::new_napi();
    let caller = "did:dht:z6MkUnknownHandleControlPlaneCaller01";
    let bogus = "0".repeat(32);

    let grant_err = outlet_stream_grant_credit_on(&bi, &bogus, caller, 1)
        .await
        .expect_err("grant on an unknown handle is a not-found error");
    assert!(
        format!("{grant_err}").contains("no active outlet stream"),
        "grant not-found: {grant_err}"
    );

    let cancel_err = outlet_stream_cancel_on(&bi, &bogus, caller)
        .await
        .expect_err("cancel on an unknown handle is a not-found error");
    assert!(
        format!("{cancel_err}").contains("no active outlet stream"),
        "cancel not-found: {cancel_err}"
    );

    let terminate_err =
        outlet_stream_terminate_on(&bi, &bogus, caller, "authorization.revoked-mid-stream", "x")
            .await
            .expect_err("terminate on an unknown handle is a not-found error");
    assert!(
        format!("{terminate_err}").contains("no active outlet stream"),
        "terminate not-found: {terminate_err}"
    );

    // An unknown handle is a DISTINCT error, NOT a `None` terminal.
    let poll_err = outlet_stream_poll_next_on(&bi, &bogus)
        .await
        .expect_err("poll on an unknown handle is a distinct not-found error, not None");
    assert!(
        format!("{poll_err}").contains("no active outlet stream"),
        "poll not-found: {poll_err}"
    );
}

/// The `terminate` slug guard is pure input validation (reachable without a
/// live stream): an unknown slug fails closed as a validation error. Because the
/// slug is checked BEFORE the registry lookup, this holds even for a bogus
/// handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminate_unknown_slug_is_rejected() {
    let bi = NapiBridgeInstance::new_napi();
    let caller = "did:dht:z6MkTerminateSlugGuardCaller000000001";
    let bogus = "0".repeat(32);
    let err = outlet_stream_terminate_on(&bi, &bogus, caller, "not.a.terminal.slug", "y")
        .await
        .expect_err("an unknown terminate slug is rejected");
    assert!(
        format!("{err}").contains("unknown terminate slug"),
        "unknown slug fails closed as validation: {err}"
    );
}

// ---------------------------------------------------------------------------
// Live-flow (gated: allow_in_memory_custody + testing + outlet-capability-test-grant)
// ---------------------------------------------------------------------------

/// End-to-end §5.4.5 live-stream flow through the NAPI bridge: open a real
/// member-backed stream, drive `poll_next` to its terminal, and prove CRITICAL
/// #1 (a non-invoker grant → `SCP-PERM-3001`).
///
/// # Why it is constructible
///
/// The invoker is made a real MEMBER via the `testing`-gated
/// `Supervisor::test_insert_member` (clears the §9.8.5 membership gate) AND
/// granted `OutletCallAll` via the dedicated `outlet-capability-test-grant`
/// seam (clears the runtime pump's role-state capability gate — the default
/// `member` role grants only `messages:*`). The outlet is ZERO-cost, so no
/// escrow/funding fixture is needed. `estimated_chunk_count=Some(1)` is declared
/// (an unbounded default coerces to `u32::MAX` and trips SCP-OUTLET-6120).
///
/// # What differs from the `PyO3` reference
///
/// napi-rs has no GIL, so there is no `allow_threads` deadlock to guard. The value
/// this test adds is the same regardless: it proves the open path reaches
/// `Supervisor::open_outlet_stream` and drains a genuine live pump to terminal.
#[cfg(all(
    feature = "allow_in_memory_custody",
    feature = "testing",
    feature = "outlet-capability-test-grant"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn live_poll_next_drains_to_terminal() {
    use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk as Chunk};

    let scp = crate::scp::Scp::new_in_memory_for_test();
    let bi = std::sync::Arc::clone(&scp.inner);

    // Per-instance, caller-retained resolver so this test is hermetic against the
    // process-global `SHARED_DHT_CLIENT` `OnceLock` a concurrent sibling could
    // win first (which otherwise leaves the creator's DID unresolvable at the
    // open-time UCAN signature check).
    let resolver_dht = install_seedable_resolver(&bi);

    // Creator (context owner + outlet operator; its co-resident custody signs
    // chunks), invoker (the pinned stream driver), and a stranger (to prove
    // CRITICAL #1). MUST precede the first context_create (which lazily builds
    // the supervisor + snapshots the resolver installed above).
    let creator_identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create (creator) should succeed");
    let creator = creator_identity.inner.did.clone();
    let invoker_identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create (invoker) should succeed");
    let invoker = invoker_identity.inner.did.clone();
    let stranger_identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create (stranger) should succeed");
    let stranger = stranger_identity.inner.did.clone();

    // Seed the creator's DID document into the per-instance resolver so the
    // open-time UCAN signature check resolves the issuer key.
    seed_owner_document_into_resolver(&creator_identity, &resolver_dht).await;

    // Context owned by the creator; ceiling admits the Action outlet stem.
    let params = serde_json::json!({
        "ceiling": ["outlet:call:*", "messages:read", "messages:write", "governance:propose"],
        "governance": "single_admin",
        "memoryScope": "ephemeral",
    })
    .to_string();
    let handle = crate::context::context_create_on(&bi, &creator_identity, params)
        .await
        .expect("context_create should succeed");
    let ctx = handle.context_id();

    // Zero-cost Action outlet operated by the creator.
    let definition = crate::outlets::NapiOutletDefinition {
        name: "napi_streaming_live".to_owned(),
        description: "live streaming outlet".to_owned(),
        kind: crate::outlets::NapiOutletKind::Action,
        input_schema_json:
            r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}"#
                .to_owned(),
        output_schema_json: r#"{"type":"object"}"#.to_owned(),
        test_vectors_json: None,
        implementation_hash: None,
        operator_did: creator.clone(),
        cost: None,
    };
    let outlet_id = crate::outlets::outlet_register_on(&bi, &handle, definition)
        .await
        .expect("outlet_register should succeed");

    // Deterministic single-shot handler (the producer side of the pump).
    let handler: crate::runtime::OutletHandler =
        std::sync::Arc::new(|_input: serde_json::Value| Ok(serde_json::json!({"sum": 3, "ok": 1})));
    crate::runtime::register_outlet_handler(&bi, &ctx, &outlet_id, handler)
        .expect("register_outlet_handler should succeed");

    // Make the invoker a real member (clears §9.8.5) and grant it OutletCallAll
    // (clears the runtime role-state capability gate).
    let supervisor = crate::runtime::supervisor(&bi).expect("supervisor must be initialized");
    supervisor
        .test_insert_member(&ctx, scp_did::DID(invoker.clone()), "member")
        .await
        .expect("test_insert_member seeds the invoker as a member");
    supervisor
        .test_grant_member_capability(&ctx, scp_did::DID(invoker.clone()), "outlet_call:*")
        .await
        .expect("grant OutletCallAll to the member invoker");

    // Creator-issued outlet_call UCAN delegated to the member invoker.
    let ucan = crate::ucan::ucan_mint_on(
        &bi,
        &handle,
        invoker.clone(),
        vec!["outlet_call:*".to_owned()],
        None,
    )
    .await
    .expect("ucan_mint should succeed");

    // OPEN — succeeds (member + valid UCAN + zero cost), returning the hex
    // StreamHandleId PROMPTLY (Commit transition, never block-until-terminal).
    let handle_id = outlet_stream_open_on(
        &bi,
        &handle,
        outlet_id.clone(),
        r#"{"a":"1","b":"2"}"#.to_owned(),
        invoker.clone(),
        ucan.encoded().clone(),
        None,
        None,
        None,
        Some(1),
    )
    .await
    .expect("member invoker opens a live stream");

    // The context's default credit window (>= 1) admits the first Data chunk with
    // NO grant, so this poll parks on the live pump and returns the handler's
    // Data chunk.
    let first = outlet_stream_poll_next_on(&bi, &handle_id)
        .await
        .unwrap()
        .expect("first poll returns the handler's Data chunk");
    let first_chunk: Chunk = serde_json::from_slice(&first).unwrap();
    assert!(
        matches!(first_chunk.payload, ChunkPayload::Data { .. }),
        "the first poll forwarded the handler's Data chunk"
    );

    // CRITICAL #1: a non-invoker caller cannot steer the stream. The
    // caller==invoker gate fires on the registry lookup BEFORE any signing /
    // reserve, so this is deterministic regardless of pump progress.
    let stranger_err = outlet_stream_grant_credit_on(&bi, &handle_id, &stranger, 1)
        .await
        .expect_err("a non-invoker grant must be rejected");
    assert!(
        format!("{stranger_err}").contains(codes::PERM_3001),
        "a caller that is not the pinned invoker is rejected with SCP-PERM-3001: {stranger_err}"
    );

    // A self-grant exercises the bridge's INTERNAL credit signing + escrow
    // reserve + apply path. The single-shot stream may already have closed (a
    // benign lifecycle race), but a bridge-signed grant must NEVER be rejected as
    // a signature/authorization failure (SCP-OUTLET-6110).
    if let Err(e) = outlet_stream_grant_credit_on(&bi, &handle_id, &invoker, 1).await {
        assert!(
            !format!("{e}").contains("SCP-OUTLET-6110"),
            "a correctly bridge-signed grant must not be rejected as a signature/auth failure: {e}"
        );
    }

    // Drive the REST of the stream to its terminal.
    let mut saw_terminal = false;
    for _ in 0..16 {
        let Some(bytes) = outlet_stream_poll_next_on(&bi, &handle_id).await.unwrap() else {
            break; // abnormal terminal (channel closed without a terminal chunk)
        };
        let chunk: Chunk = serde_json::from_slice(&bytes).unwrap();
        if chunk.payload.is_terminal() {
            saw_terminal = true;
            break;
        }
    }
    assert!(
        saw_terminal,
        "poll_next reached the stream's terminal chunk"
    );

    // The terminal chunk EVICTED the entry, so a further poll is a distinct
    // not-found error, never a silent None.
    let after = outlet_stream_poll_next_on(&bi, &handle_id)
        .await
        .expect_err("the entry is evicted at the terminal chunk (no registry leak)");
    assert!(
        format!("{after}").contains("no active outlet stream"),
        "post-terminal poll is a not-found error: {after}"
    );
}

/// Installs a per-instance DID resolver backed by a caller-retained in-memory
/// DHT client on `bi` and returns that client, so the live test can seed the
/// creator's DID document into the SAME store the open-time UCAN signature check
/// reads from — WITHOUT depending on the process-global `SHARED_DHT_CLIENT`
/// `OnceLock`. Mirrors the `outlets.rs` xctx-saga test's `install_seedable_resolver`.
#[cfg(all(
    feature = "allow_in_memory_custody",
    feature = "testing",
    feature = "outlet-capability-test-grant"
))]
fn install_seedable_resolver(
    bi: &std::sync::Arc<NapiBridgeInstance>,
) -> std::sync::Arc<scp_dht::InMemoryDhtClient> {
    let dht_client = std::sync::Arc::new(scp_dht::InMemoryDhtClient::new());
    let resolver = std::sync::Arc::new(scp_identity::DualLayerResolver::new(
        std::sync::Arc::new(scp_identity::NoOpRelayQuerier),
        std::sync::Arc::clone(&dht_client),
        std::sync::Arc::new(scp_identity::DidCache::new()),
        Vec::new(),
    ));
    crate::runtime::init_did_resolver(bi, resolver, tokio::runtime::Handle::current());
    dht_client
}

/// Publishes `owner_identity`'s DID document into `dht_client` (the
/// resolver-visible store installed by [`install_seedable_resolver`]) by signing
/// the BEP44 record with the identity's retained in-memory custody. Mirrors the
/// `outlets.rs` xctx-saga test's `seed_owner_document_into_resolver`.
#[cfg(all(
    feature = "allow_in_memory_custody",
    feature = "testing",
    feature = "outlet-capability-test-grant"
))]
async fn seed_owner_document_into_resolver(
    owner_identity: &crate::identity::NapiIdentity,
    dht_client: &std::sync::Arc<scp_dht::InMemoryDhtClient>,
) {
    use scp_dht::DhtClient as _;
    use scp_platform::traits::KeyCustody as _;

    let inner = &owner_identity.inner;
    let identity = inner
        .scp_identity
        .as_ref()
        .expect("in-memory owner retains its ScpIdentity");
    let document = inner
        .document
        .as_ref()
        .expect("in-memory owner retains its DID document");
    let custody = inner
        .in_memory_custody
        .as_ref()
        .expect("in-memory owner retains its custody");

    let doc_json = document.to_json().expect("document serializes to JSON");
    let value = doc_json.as_bytes();
    let public_key =
        scp_identity::extract_public_key(&identity.did).expect("DID embeds the public key");
    let seq: u64 = 1;
    let signable = scp_dht::bep44_signable(value, seq);
    let sig_bytes = custody
        .sign(&identity.identity_key, &signable)
        .await
        .expect("identity custody signs the BEP44 record")
        .into_bytes();
    let signature: [u8; 64] = sig_bytes.try_into().expect("Ed25519 signature is 64 bytes");
    dht_client
        .publish(&public_key, &signature, value, seq)
        .await
        .expect("publish into the resolver-visible store");
}
