//! Tests for the §5.4.5 streaming-native outlet bridge (SCP-OUT-037, C8a).
//!
//! Three tiers, mirroring the `PyO3` reference bridge's `e2e_bridge.rs`:
//!
//! - **Non-gated** — the two pure protocol wrappers round-trip, and the six
//!   control-plane ops on an UNKNOWN handle return clean, distinct not-found
//!   errors (never a panic, never a silent `None`).
//! - **Live-flow** (gated `all(testing, testing,
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
// Live-flow (gated: testing + testing + outlet-capability-test-grant)
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
    feature = "testing",
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
            !format!("{e}")
                .contains(scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED),
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
    feature = "testing",
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
    feature = "testing",
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

// ---------------------------------------------------------------------------
// SCP-OUT-039 (§5.4.5) — outlet streaming conformance vectors, NAPI tier.
//
// This lives as an INTERNAL test module (not an external `tests/` file) because
// the napi cdylib's runtime symbols (`napi_wrap` / `napi_unwrap` / …) are only
// satisfiable via the `scp-ffi-napi-test-stubs` static lib inside the crate's
// OWN `#[cfg(test)]` link graph — an external integration-test target fails to
// link them (which is why the crate has zero `[[test]]` blocks and every napi
// test lives in a `#[cfg(test)] mod`). The vectors are replayed through the
// ACTUAL public NAPI bridge exports (`Scp::outlet_stream_verify_chunk_signature`
// / `Scp::outlet_stream_compute_caveats_binding`, `Buffer` in/out).
//
// Coverage here is WIRE INTEGRITY over all 7 vectors + the receiver-side
// `sequence_gap` check. The LIVE open→poll→drain terminal-status behaviour of
// these vectors is covered by the gated `live_poll_next_drains_to_terminal`
// test above and by the runtime tiers (SCP-OUT-039 deliverables 2/3 in
// scp-testing).
// ---------------------------------------------------------------------------
mod streaming_vectors {
    use napi::bindgen_prelude::Buffer;
    use scp_core::context::outlets::stream::{
        ChunkPayload, OutletStreamChunk, compute_caveats_binding, sign_chunk,
    };
    use scp_core::trust::caveats::InvocationCaveats;

    /// The §25.2 reference operator Ed25519 seed (RFC 8032 §7.1 Test Vector 1).
    const REFERENCE_OPERATOR_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const VECTOR_CONTEXT_ID: &str = "scp-out-039-ctx";
    /// The Ed25519 public key the §25.2 seed above actually derives (verified via
    /// `ed25519_dalek`, OpenSSL, and a standalone RFC-8032 impl). Pinned so a
    /// corrupted seed byte fails loudly. Matches the §25.2 public key
    /// (`…daa62325af021a68f707511a`, RFC 8032 §7.1 TV1) and the repo KAT `REF_PUBKEY`.
    const EXPECTED_OPERATOR_PK: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    /// §5.4.5 stream-gap code (shared `CODE_EXECUTION_CREDIT`, slug
    /// `execution.stream-gap`).
    const CODE_STREAM_GAP: &str = scp_core::context::outlets::error_codes::CODE_EXECUTION_CREDIT;

    fn vectors() -> serde_json::Value {
        let raw =
            include_str!("../../../../../tests/conformance/vectors/outlet_stream_vectors.json");
        serde_json::from_str(raw).expect("vectors JSON parses")
    }

    fn sample_provenance() -> scp_core::provenance::DataProvenance {
        use scp_core::context::params::MemoryScope;
        use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        DataProvenance {
            source_context: "scp-out-039-source".to_owned(),
            source_type: SourceType::Persistent,
            counterparties: Vec::new(),
            purpose: None,
            discovery_method: DiscoveryMethod::OutOfBand,
            age: std::time::Duration::from_secs(0),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        }
    }

    fn payload_from_vector(payload: &serde_json::Value) -> ChunkPayload {
        match payload["@type"].as_str().expect("payload @type") {
            "data" => ChunkPayload::Data {
                value: payload["value"].clone(),
            },
            "progress" => ChunkPayload::Progress {
                pct: u16::try_from(payload["pct"].as_u64().expect("pct")).expect("pct u16"),
                note: payload["note"].as_str().map(str::to_owned),
            },
            "end" => ChunkPayload::End {
                aggregate: payload["aggregate"].clone(),
                provenance: sample_provenance(),
                execution_time_ms: payload["execution_time_ms"].as_u64().expect("exec ms"),
            },
            "error" => ChunkPayload::Error {
                code: payload["code"].as_str().expect("code").to_owned(),
                message: payload["message"].as_str().expect("message").to_owned(),
                terminal: payload["terminal"].as_bool().expect("terminal"),
            },
            other => panic!("unknown payload @type: {other}"),
        }
    }

    fn request_id_from_open(open: &serde_json::Value) -> [u8; 16] {
        let arr = open["request_id"].as_array().expect("request_id array");
        assert_eq!(arr.len(), 16, "request_id is 16 bytes");
        let mut id = [0u8; 16];
        for (i, byte) in arr.iter().enumerate() {
            id[i] = u8::try_from(byte.as_u64().expect("byte")).expect("byte u8");
        }
        id
    }

    /// Outcome of observing one chunk against the running sequence expectation.
    /// Uniform `GapOutcome` enum shape shared across the runtime-layer harness
    /// (`outlet_stream_vectors_common.rs`) and the `PyO3` / `UniFFI` per-bridge
    /// trackers — a single canonical shape so the receiver rule cannot drift.
    #[derive(Debug, PartialEq, Eq)]
    enum GapOutcome {
        Continue,
        Cancelled { code: String },
    }

    /// Receiver-side ordering check (§5.4.5 "Ordering and gaps"): a missing
    /// sequence MUST cancel with `execution.stream-gap` (`SCP-OUTLET-6131`).
    struct ReceiverSequenceTracker {
        expected: u64,
    }
    impl ReceiverSequenceTracker {
        fn new() -> Self {
            Self { expected: 0 }
        }
        fn observe(&mut self, sequence: u64) -> GapOutcome {
            if sequence == self.expected {
                self.expected += 1;
                GapOutcome::Continue
            } else {
                GapOutcome::Cancelled {
                    code: CODE_STREAM_GAP.to_owned(),
                }
            }
        }
    }

    /// Every chunk of every vector replayed through the ACTUAL NAPI pure-wrapper
    /// exports: verify is `true` under the §25.2 key, `false` under a wrong key,
    /// and the caveats-binding export equals the core helper byte-for-byte.
    #[test]
    fn all_seven_vectors_wire_integrity_through_napi_exports() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let operator = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
        assert_eq!(
            operator.verifying_key().as_bytes(),
            &EXPECTED_OPERATOR_PK,
            "the §25.2 reference seed must derive its ground-truth public key"
        );
        let operator_pk = operator.verifying_key().as_bytes().to_vec();
        let wrong_pk = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32])
            .verifying_key()
            .as_bytes()
            .to_vec();
        let caveats_jcs = InvocationCaveats::empty()
            .to_canonical_json_bytes()
            .expect("empty caveats JCS");

        let doc = vectors();
        let vecs = doc["vectors"].as_array().expect("vectors array");
        assert_eq!(vecs.len(), 7, "exactly 7 streaming conformance vectors");
        let mut total_chunks = 0usize;
        for vector in vecs {
            let open = &vector["open"];
            let outlet_id = open["outlet_id"].as_str().expect("outlet_id").to_owned();
            let invoker_did = open["invoker_did"]
                .as_str()
                .expect("invoker_did")
                .to_owned();
            let estimated_chunk_count =
                u32::try_from(open["estimated_chunk_count"].as_u64().expect("estimate"))
                    .expect("estimate u32");
            let request_id = request_id_from_open(open);
            let ucan_cid = open["ucan_cid"].as_str().expect("ucan_cid").to_owned();

            // caveats_binding uses the vector's declared ucan_cid, so it equals the
            // vector's pinned KAT (§25.21) at every SDK tier byte-for-byte.
            let binding_wrapper = scp
                .outlet_stream_compute_caveats_binding(
                    Buffer::from(ucan_cid.clone().into_bytes()),
                    Buffer::from(request_id.to_vec()),
                    invoker_did.clone(),
                    estimated_chunk_count,
                    Buffer::from(caveats_jcs.clone()),
                )
                .expect("napi binding wrapper");
            let binding_core = compute_caveats_binding(
                ucan_cid.as_bytes(),
                &request_id,
                &invoker_did,
                estimated_chunk_count,
                &caveats_jcs,
            );
            assert_eq!(
                binding_wrapper.as_ref(),
                binding_core.as_slice(),
                "vector {}: NAPI caveats-binding export must match the core helper",
                vector["name"]
            );
            let binding = <[u8; 32]>::try_from(binding_wrapper.as_ref()).expect("32 bytes");
            let binding_hex = {
                use std::fmt::Write as _;
                let mut h = String::with_capacity(64);
                for b in binding {
                    let _ = write!(h, "{b:02x}");
                }
                h
            };
            assert_eq!(
                binding_hex,
                open["expected_caveats_binding"]
                    .as_str()
                    .expect("expected_caveats_binding"),
                "vector {}: computed caveats_binding must equal the vector's pinned KAT",
                vector["name"]
            );

            for chunk_desc in vector["chunks"].as_array().expect("chunks array") {
                let sequence = chunk_desc["sequence"].as_u64().expect("sequence");
                let payload = payload_from_vector(&chunk_desc["payload"]);
                let sig = sign_chunk(
                    &operator,
                    VECTOR_CONTEXT_ID,
                    &outlet_id,
                    &request_id,
                    sequence,
                    &binding,
                    &payload,
                )
                .expect("chunk signs under §25.2 key");
                let chunk = OutletStreamChunk {
                    request_id,
                    sequence,
                    payload,
                    sig,
                };
                let chunk_bytes = serde_json::to_vec(&chunk).expect("chunk serializes");
                assert!(
                    scp.outlet_stream_verify_chunk_signature(
                        Buffer::from(chunk_bytes.clone()),
                        Buffer::from(operator_pk.clone()),
                        VECTOR_CONTEXT_ID.to_owned(),
                        outlet_id.clone(),
                        Buffer::from(binding.to_vec()),
                    )
                    .expect("napi verify Ok"),
                    "vector {} seq {sequence}: NAPI verify accepts the §25.2-signed chunk",
                    vector["name"]
                );
                assert!(
                    !scp.outlet_stream_verify_chunk_signature(
                        Buffer::from(chunk_bytes),
                        Buffer::from(wrong_pk.clone()),
                        VECTOR_CONTEXT_ID.to_owned(),
                        outlet_id.clone(),
                        Buffer::from(binding.to_vec()),
                    )
                    .expect("napi verify false under wrong key"),
                    "vector {} seq {sequence}: NAPI verify rejects a wrong key",
                    vector["name"]
                );
                total_chunks += 1;
            }
        }
        // 2 + 12 + 4 + 2 + 5 + 3 + 2 == 30 chunk descriptors across the 7 vectors
        // (multi_chunk carries an interleaved Progress chunk — §5.4.5).
        assert_eq!(total_chunks, 30, "every chunk descriptor exercised");
    }

    /// `sequence_gap`: the receiver tracker cancels with `SCP-OUTLET-6131` at the
    /// third chunk of the gapped `[0,1,3]` transcript (each chunk authentically
    /// §25.2-signed and accepted by the NAPI verify export).
    #[test]
    fn sequence_gap_receiver_tracker_cancels_with_6131_through_napi() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let operator = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
        assert_eq!(
            operator.verifying_key().as_bytes(),
            &EXPECTED_OPERATOR_PK,
            "the §25.2 reference seed must derive its ground-truth public key"
        );
        let operator_pk = operator.verifying_key().as_bytes().to_vec();
        let caveats_jcs = InvocationCaveats::empty()
            .to_canonical_json_bytes()
            .expect("empty caveats JCS");

        let doc = vectors();
        let vector = doc["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .find(|v| v["name"] == "sequence_gap")
            .expect("sequence_gap vector");
        let open = &vector["open"];
        let outlet_id = open["outlet_id"].as_str().expect("outlet_id").to_owned();
        let invoker_did = open["invoker_did"]
            .as_str()
            .expect("invoker_did")
            .to_owned();
        let estimated_chunk_count =
            u32::try_from(open["estimated_chunk_count"].as_u64().expect("estimate"))
                .expect("estimate u32");
        let request_id = request_id_from_open(open);
        let ucan_cid = open["ucan_cid"].as_str().expect("ucan_cid").to_owned();
        let binding = compute_caveats_binding(
            ucan_cid.as_bytes(),
            &request_id,
            &invoker_did,
            estimated_chunk_count,
            &caveats_jcs,
        );

        // The tracker is a test-local reimplementation of the §5.4.5 receiver
        // gap-cancel rule (a lossless same-context pump cannot produce a gap; the
        // live trigger is slice-3 transport). It replays the vector's gapped
        // transcript over a really-signed chunk sequence.
        let mut tracker = ReceiverSequenceTracker::new();
        let mut cancelled_at: Option<(u64, String)> = None;
        for chunk_desc in vector["chunks"].as_array().expect("chunks array") {
            let sequence = chunk_desc["sequence"].as_u64().expect("sequence");
            let payload = payload_from_vector(&chunk_desc["payload"]);
            let sig = sign_chunk(
                &operator,
                VECTOR_CONTEXT_ID,
                &outlet_id,
                &request_id,
                sequence,
                &binding,
                &payload,
            )
            .expect("gap chunk signs");
            let chunk = OutletStreamChunk {
                request_id,
                sequence,
                payload,
                sig,
            };
            let chunk_bytes = serde_json::to_vec(&chunk).expect("serializes");
            assert!(
                scp.outlet_stream_verify_chunk_signature(
                    Buffer::from(chunk_bytes),
                    Buffer::from(operator_pk.clone()),
                    VECTOR_CONTEXT_ID.to_owned(),
                    outlet_id.clone(),
                    Buffer::from(binding.to_vec()),
                )
                .expect("napi verify Ok"),
                "gap transcript chunk seq {sequence} is authentically signed"
            );
            if cancelled_at.is_none()
                && let GapOutcome::Cancelled { code } = tracker.observe(sequence)
            {
                cancelled_at = Some((sequence, code));
            }
        }
        assert_eq!(
            cancelled_at,
            Some((3, CODE_STREAM_GAP.to_owned())),
            "receiver tracker cancels with SCP-OUTLET-6131 at gapped sequence 3"
        );
        assert_eq!(vector["expected_end_status"], "Cancelled");
        assert_eq!(vector["expected_error_code"], CODE_STREAM_GAP);
    }
}

// ---------------------------------------------------------------------------
// SCP-OUT-039 (§5.4.5) — LIVE single-shot-seam vectors through the real NAPI
// bridge. The `streaming_vectors` module above covers all-7-vector WIRE
// INTEGRITY (pure wrappers); this section drives the ACTUAL open→poll→drain
// control plane for the vectors the single-shot `BridgeStreamExecutor` seam CAN
// produce — `non_streaming`, `error_terminal`, `cancellation` (the same set the
// PyO3 reference drives live). `multi_chunk` / `error_recoverable` need a
// multi-chunk executor the single-shot handler seam cannot produce, and
// `credit_stall`'s stall cannot be produced by a one-shot handler (it emits
// exactly one billable chunk and closes) — those stay covered at the runtime
// tiers (deliverables 2/3). These live tests reuse the same gated resolver/DID
// seeding helpers as `live_poll_next_drains_to_terminal`. Named
// `streaming_vectors_live` so the `streaming_vectors` test filter selects them
// alongside the wire-integrity module above.
// ---------------------------------------------------------------------------
#[cfg(all(
    feature = "testing",
    feature = "testing",
    feature = "outlet-capability-test-grant"
))]
mod streaming_vectors_live {
    use super::*;

    /// Fixture for a live SCP-OUT-039 vector stream: the retained `Scp` (owns the
    /// bridge instance), the shared `bi`, the opened stream `handle_id`, and the
    /// pinned invoker + a stranger DID (for the CRITICAL #1 caller check).
    struct LiveVectorFixture {
        _scp: crate::scp::Scp,
        bi: std::sync::Arc<NapiBridgeInstance>,
        handle_id: String,
        invoker: String,
        stranger: String,
    }

    /// Stands up a live zero-cost Action outlet stream driven by `handler`, mirroring
    /// `live_poll_next_drains_to_terminal`'s setup exactly (per-instance resolver,
    /// member seeding, `OutletCallAll` grant, delegated UCAN), and returns the opened
    /// stream fixture. `outlet_name` disambiguates the outlet per test.
    #[cfg(all(
        feature = "testing",
        feature = "testing",
        feature = "outlet-capability-test-grant"
    ))]
    async fn open_live_vector_stream(
        outlet_name: &str,
        handler: crate::runtime::OutletHandler,
    ) -> LiveVectorFixture {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let resolver_dht = install_seedable_resolver(&bi);

        let creator_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (creator)");
        let creator = creator_identity.inner.did.clone();
        let invoker_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (invoker)");
        let invoker = invoker_identity.inner.did.clone();
        let stranger_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (stranger)");
        let stranger = stranger_identity.inner.did.clone();

        seed_owner_document_into_resolver(&creator_identity, &resolver_dht).await;

        let params = serde_json::json!({
            "ceiling": ["outlet:call:*", "messages:read", "messages:write", "governance:propose"],
            "governance": "single_admin",
            "memoryScope": "ephemeral",
        })
        .to_string();
        let handle = crate::context::context_create_on(&bi, &creator_identity, params)
            .await
            .expect("context_create");
        let ctx = handle.context_id();

        let definition = crate::outlets::NapiOutletDefinition {
            name: outlet_name.to_owned(),
            description: "SCP-OUT-039 live vector outlet".to_owned(),
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
            .expect("outlet_register");

        crate::runtime::register_outlet_handler(&bi, &ctx, &outlet_id, handler)
            .expect("register_outlet_handler");

        let supervisor = crate::runtime::supervisor(&bi).expect("supervisor");
        supervisor
            .test_insert_member(&ctx, scp_did::DID(invoker.clone()), "member")
            .await
            .expect("test_insert_member");
        supervisor
            .test_grant_member_capability(&ctx, scp_did::DID(invoker.clone()), "outlet_call:*")
            .await
            .expect("grant OutletCallAll");

        let ucan = crate::ucan::ucan_mint_on(
            &bi,
            &handle,
            invoker.clone(),
            vec!["outlet_call:*".to_owned()],
            None,
        )
        .await
        .expect("ucan_mint");

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

        LiveVectorFixture {
            _scp: scp,
            bi,
            handle_id,
            invoker,
            stranger,
        }
    }

    /// `non_streaming` (§5.4.5 degenerate stream): the single-shot handler returns
    /// the vector's aggregate; the live pump delivers exactly one `Data` chunk whose
    /// value equals the vector's first Data, then the framework `End` closes it. The
    /// delivered sequences are monotonic from 0.
    #[cfg(all(
        feature = "testing",
        feature = "testing",
        feature = "outlet-capability-test-grant"
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_streaming_vector_drains_data_then_end_live() {
        use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk as Chunk};

        // The vector's non_streaming Data payload value is {"sum":3}.
        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!({ "sum": 3 })));
        let fx = open_live_vector_stream("napi_vec_non_streaming", handler).await;

        let mut seqs = Vec::new();
        let mut first_data_value = None;
        let mut saw_end = false;
        for _ in 0..16 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                outlet_stream_poll_next_on(&fx.bi, &fx.handle_id),
            )
            .await
            .expect("poll_next resolves within 10s (fail fast, don't hang)")
            {
                Ok(Some(bytes)) => {
                    let chunk: Chunk = serde_json::from_slice(&bytes).unwrap();
                    seqs.push(chunk.sequence);
                    match &chunk.payload {
                        ChunkPayload::Data { value } if first_data_value.is_none() => {
                            first_data_value = Some(value.clone());
                        }
                        ChunkPayload::End { .. } => {
                            saw_end = true;
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        assert!(saw_end, "non_streaming reaches a framework End terminal");
        assert_eq!(
            first_data_value,
            Some(serde_json::json!({ "sum": 3 })),
            "the delivered Data chunk carries the vector's {{\"sum\":3}} value"
        );
        assert!(
            seqs.iter().enumerate().all(|(i, s)| *s == i as u64),
            "delivered sequences are monotonic from 0: {seqs:?}"
        );
    }

    /// `error_terminal` (§5.4.5): a faulting single-shot handler maps to a framework
    /// terminal `Error{terminal:true, code: SCP-OUTLET-6130}` (execution.handler-panic).
    #[cfg(all(
        feature = "testing",
        feature = "testing",
        feature = "outlet-capability-test-grant"
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn error_terminal_vector_maps_handler_fault_to_6130_live() {
        use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk as Chunk};

        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Err("handler fault".to_owned()));
        let fx = open_live_vector_stream("napi_vec_error_terminal", handler).await;

        let mut terminal_code = None;
        for _ in 0..16 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                outlet_stream_poll_next_on(&fx.bi, &fx.handle_id),
            )
            .await
            .expect("poll_next resolves within 10s (fail fast, don't hang)")
            {
                Ok(Some(bytes)) => {
                    let chunk: Chunk = serde_json::from_slice(&bytes).unwrap();
                    if let ChunkPayload::Error { code, terminal, .. } = &chunk.payload
                        && *terminal
                    {
                        terminal_code = Some(code.clone());
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        assert_eq!(
            terminal_code.as_deref(),
            Some(scp_core::context::outlets::error_codes::CODE_EXECUTION_FAULT),
            "a faulting handler yields a terminal Error with the execution-fault code"
        );
    }

    /// `cancellation` (§5.4.5 cancel-ack): the pinned invoker's signed cancel through
    /// the real control plane drives the stream to a framework terminal; a non-invoker
    /// caller is rejected SCP-PERM-3001 (CRITICAL #1).
    #[cfg(all(
        feature = "testing",
        feature = "testing",
        feature = "outlet-capability-test-grant"
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_vector_control_plane_reaches_terminal_live() {
        use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk as Chunk};

        let handler: crate::runtime::OutletHandler =
            std::sync::Arc::new(|_input| Ok(serde_json::json!({ "n": 0 })));
        let fx = open_live_vector_stream("napi_vec_cancellation", handler).await;

        // Drain the first Data chunk (parks on the live pump).
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            outlet_stream_poll_next_on(&fx.bi, &fx.handle_id),
        )
        .await
        .expect("first poll resolves within 10s (fail fast, don't hang)")
        .unwrap()
        .expect("first poll returns the handler's Data chunk");
        let first_chunk: Chunk = serde_json::from_slice(&first).unwrap();
        assert!(matches!(first_chunk.payload, ChunkPayload::Data { .. }));

        // CRITICAL #1: a non-invoker cancel is rejected before any signing.
        let stranger_err = outlet_stream_cancel_on(&fx.bi, &fx.handle_id, &fx.stranger)
            .await
            .expect_err("a non-invoker cancel must be rejected");
        assert!(
            format!("{stranger_err}").contains(codes::PERM_3001),
            "non-invoker cancel is rejected with SCP-PERM-3001: {stranger_err}"
        );

        // The pinned invoker's bridge-signed cancel must NOT be a signature/auth
        // failure (SCP-OUTLET-6110); the stream may already be closing (benign race).
        if let Err(e) = outlet_stream_cancel_on(&fx.bi, &fx.handle_id, &fx.invoker).await {
            assert!(
                !format!("{e}")
                    .contains(scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED),
                "a correctly bridge-signed cancel must not be a signature/auth failure: {e}"
            );
        }

        // Drain to a framework terminal chunk.
        let mut saw_terminal = false;
        for _ in 0..16 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                outlet_stream_poll_next_on(&fx.bi, &fx.handle_id),
            )
            .await
            .expect("poll_next resolves within 10s (fail fast, don't hang)")
            {
                Ok(Some(bytes)) => {
                    let chunk: Chunk = serde_json::from_slice(&bytes).unwrap();
                    if chunk.payload.is_terminal() {
                        saw_terminal = true;
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        assert!(
            saw_terminal,
            "the cancelled stream reaches a terminal chunk"
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-context STREAMING saga (§5.4.5 / §6.2.4, SCP-OUT-047) — NAPI bridge.
//
// The behavioral counterparts of the PyO3 reference `e2e_bridge.rs` streaming-
// saga tests. Like the unary-saga NAPI tests, these exercise what the bridge
// ADDS on top of the supervisor producer (whose full Committed / truncated-close
// paths need actor-state + budget injection with no bridge-public wiring):
//
//   - the §6.2.4 caller-principal binding on the OPEN (caller_did MUST be hosted
//     by this instance) — rejected BEFORE the saga runs, so the receiver is
//     never handed out;
//   - the RECOVER reconnect-caller authentication (hosted axis) AND the
//     money-moving invoker gate (SCP-PERM-3001), which must NOT evict a
//     stranger's saga.
//
// MUTATION-RESISTANCE: the OPEN test asserts the BRIDGE-UNIQUE substring the
// producer never emits, so it fails closed if the binding is removed.
//
// Gated on `testing` (identity_create + the test-only registry
// seam), mirroring the `outlets.rs` `xctx_saga_tests` gating.
#[cfg(feature = "testing")]
mod xctx_streaming_saga_tests {
    use super::*;

    /// Creates an ephemeral single-admin context owned by `owner_identity` whose
    /// ceiling carries the saga-relevant capabilities. Mirrors the `outlets.rs`
    /// saga tests' `create_saga_context`.
    async fn create_saga_context(
        bi: &std::sync::Arc<NapiBridgeInstance>,
        owner_identity: &crate::identity::NapiIdentity,
    ) -> NapiContextHandle {
        let params = serde_json::json!({
            "ceiling": [
                "governance:propose",
                "outlet:interface",
                "outlet:register",
                "outlet:call:*",
                "messages:read",
                "messages:write"
            ],
            "governance": "single_admin",
            "memoryScope": "ephemeral",
        })
        .to_string();
        crate::context::context_create_on(bi, owner_identity, params)
            .await
            .expect("context_create should succeed")
    }

    fn now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }

    /// (a) OPEN caller-principal binding, hosted axis: a `caller_did` this bridge
    /// instance does NOT host is rejected with `SagaAborted` (SCP-SAGA-13050)
    /// BEFORE the streaming saga runs. Asserts the bridge-unique axis-(a)
    /// substring so the test fails if the registry check is removed (the
    /// producer's gate-1 message never carries this phrasing).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_streaming_saga_unhosted_caller_rejected_before_saga() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let owner_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let handle_a = create_saga_context(&bi, &owner_identity).await;
        let handle_b = create_saga_context(&bi, &owner_identity).await;
        let outlet_id =
            scp_ffi_common::outlet_id::generate_outlet_id("xctx_streaming_unhosted_probe");

        // A syntactically valid DID that was never created on this instance.
        let unhosted_caller = "did:dht:z6MkUnhostedStreamingCaller01".to_owned();

        let err = Box::pin(outlet_streaming_saga_open_on(
            &bi,
            &handle_a,
            &handle_b,
            unhosted_caller,
            outlet_id,
            r#"{"a":"x","b":"y"}"#.to_owned(),
            "0123456789abcdef0123456789abcdef".to_owned(),
            now_ms(),
            1,
            "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp0cnVlfQ.placeholder-not-validated".to_owned(),
            None,
            None,
            None,
            None,
        ))
        .await
        .expect_err("an unhosted caller_did must be rejected before the streaming saga runs");

        let msg = format!("{err}");
        assert!(
            msg.contains(codes::SAGA_13050),
            "expected caller-axis SCP-SAGA-13050, got: {msg}"
        );
        // BRIDGE-UNIQUE axis-(a) substring — the producer never emits it.
        assert!(
            msg.contains("is not an identity hosted by this bridge instance"),
            "message must be the BRIDGE axis-(a) hosted-principal rejection, got: {msg}"
        );
    }

    /// The streaming-saga RECOVER authenticates the reconnect caller: a
    /// `caller_did` this bridge instance does NOT host is rejected before any
    /// seal is attempted (§6.2.4 channel-auth). No signing key is ever resolved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_streaming_saga_recover_unhosted_caller_rejected() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let unhosted_caller = "did:dht:z6MkUnhostedStreamingRecover1";
        let err =
            outlet_streaming_saga_recover_truncated_close_on(&bi, "any-saga-id", unhosted_caller)
                .await
                .expect_err("an unhosted caller_did must be rejected by streaming-saga recover");

        assert!(
            format!("{err}").contains("not an identity hosted by this bridge instance"),
            "message must name the channel-auth mismatch, got: {err}"
        );
    }

    /// (SECURITY) The streaming-saga RECOVER is MONEY-MOVING. A `caller_did` that
    /// IS hosted by this instance but is NOT the invoker pinned at open is
    /// rejected with `SCP-PERM-3001` — the SAME invoker gate the same-context
    /// grant/cancel/terminate siblings enforce — BEFORE any signing key is
    /// resolved, and the (stranger's) saga entry is LEFT INTACT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_streaming_saga_recover_hosted_non_invoker_rejected() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        // The invoker who "opened" the saga, and a DIFFERENT hosted identity.
        let invoker_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (invoker)");
        let invoker = invoker_identity.inner.did.clone();
        let stranger_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (stranger)");
        let stranger = stranger_identity.inner.did.clone();

        // Inject a live saga entry pinned to `invoker` (the full committed path
        // needs actor-state/budget injection with no bridge-public wiring —
        // identical to the unary-saga bridge tests).
        let saga_id = "saga-out047-napi-invoker-gate-0001";
        scp.insert_test_streaming_saga_entry(saga_id, "target-ctx-out047", &invoker);

        // A hosted-but-not-invoker caller clears the channel-auth gate, reaches
        // the invoker check, and is rejected there.
        let err = outlet_streaming_saga_recover_truncated_close_on(&bi, saga_id, &stranger)
            .await
            .expect_err("a hosted non-invoker caller must be rejected by streaming-saga recover");

        let msg = format!("{err}");
        assert!(
            msg.contains(codes::PERM_3001),
            "expected the invoker-gate SCP-PERM-3001, got: {msg}"
        );
        assert!(
            msg.contains("is not the invoker"),
            "message must name the pinned-invoker mismatch, got: {msg}"
        );
        // No settle: the rejection is BEFORE the recovery driver and does NOT
        // evict — the invoker's saga entry survives for the legitimate invoker.
        assert!(
            scp.test_streaming_saga_entry_present(saga_id),
            "a rejected non-invoker recover must NOT evict the invoker's saga entry"
        );
    }

    /// Creates a saga context whose CREATOR holds the `ContextClose` capability
    /// (ceiling includes `context:close`), so the test can drive it to a REAL
    /// non-active lifecycle state through the actual supervisor close path — NOT
    /// the stale FFI state cache. Otherwise identical to `create_saga_context`.
    async fn create_closeable_saga_context(
        bi: &std::sync::Arc<NapiBridgeInstance>,
        owner_identity: &crate::identity::NapiIdentity,
    ) -> NapiContextHandle {
        let params = serde_json::json!({
            "ceiling": [
                "context:close",
                "governance:propose",
                "outlet:interface",
                "outlet:register",
                "outlet:call:*",
                "messages:read",
                "messages:write"
            ],
            "governance": "single_admin",
            "memoryScope": "ephemeral",
        })
        .to_string();
        crate::context::context_create_on(bi, owner_identity, params)
            .await
            .expect("context_create should succeed")
    }

    /// Drives `context_id` to a real non-active (`Closed`) lifecycle state through
    /// the REAL supervisor close path — the exact `LifecycleCommand::CloseContext`
    /// dispatch the bridge's close uses — so a subsequent
    /// `supervisor.read_context_state(context_id)` returns a non-`Active` state.
    /// That authoritative state (NOT the bridge-cached handle state) is what the
    /// streaming-saga open's active-state guard now reads. `initiator_did` must be
    /// the creator of a context created with a `ContextClose`-bearing ceiling (see
    /// `create_closeable_saga_context`).
    async fn drive_context_closed(
        bi: &std::sync::Arc<NapiBridgeInstance>,
        context_id: &str,
        initiator_did: &str,
    ) {
        use scp_core::context::actor::commands::{CloseContextPayload, LifecycleCommand};

        let supervisor = crate::runtime::supervisor(bi)
            .expect("supervisor should be attached")
            .clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::CloseContext {
            payload: Box::new(CloseContextPayload {
                context_id: context_id.to_owned(),
                params: scp_core::context::ContextParams::default(),
                initiator_did: scp_did::DID(initiator_did.to_owned()),
            }),
            reply: tx,
        };
        supervisor
            .dispatch_lifecycle_command(cmd)
            .await
            .expect("close dispatch should succeed");
        rx.await
            .expect("close reply channel should not drop")
            .expect("close should succeed");
    }

    /// (LIFECYCLE) A money-moving streaming-saga OPEN against a NON-active source
    /// or target context is rejected with `OUTLET_6010` (caller) / `OUTLET_6011`
    /// (target) — parity with the UNARY cross-context saga export's two-handle
    /// guard — BEFORE any input validation, UCAN check, or saga drive, so no saga
    /// is started and no receiver is handed out.
    ///
    /// The context is driven to a REAL `Closed` state through the actual
    /// supervisor close path; the guard reads the AUTHORITATIVE actor state via
    /// `read_context_state` (NOT the lagging FFI `NapiContextHandle::state()`
    /// cache), so this genuinely exercises the authoritative read that closes the
    /// Closing-cache money gap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_streaming_saga_open_rejects_non_active_context() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let owner_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");
        let hosted_caller = owner_identity.inner.did.clone();
        let outlet_id =
            scp_ffi_common::outlet_id::generate_outlet_id("xctx_streaming_non_active_probe");

        // --- source (caller) context non-active → OUTLET_6010 ---------------
        // Drive the CALLER context to a REAL Closed state through the supervisor;
        // the authoritative guard must reject it.
        let handle_a = create_closeable_saga_context(&bi, &owner_identity).await;
        let handle_b = create_closeable_saga_context(&bi, &owner_identity).await;
        drive_context_closed(&bi, &handle_a.context_id(), &hosted_caller).await;

        // Precondition: the authoritative supervisor state is non-active. This is
        // what the guard reads — proving the test drives a REAL Closing/Closed
        // context, not the FFI cache.
        assert_ne!(
            crate::runtime::supervisor(&bi)
                .expect("supervisor")
                .read_context_state(&handle_a.context_id())
                .await,
            Some(scp_core::context::ContextState::Active),
            "the caller context must be authoritatively non-active before the open"
        );

        let err = Box::pin(outlet_streaming_saga_open_on(
            &bi,
            &handle_a,
            &handle_b,
            hosted_caller.clone(),
            outlet_id.clone(),
            r#"{"a":"x","b":"y"}"#.to_owned(),
            "0123456789abcdef0123456789abcdef".to_owned(),
            now_ms(),
            1,
            "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp0cnVlfQ.placeholder-not-validated".to_owned(),
            None,
            None,
            None,
            None,
        ))
        .await
        .expect_err("a non-active source context must be rejected before the saga runs");
        let msg = format!("{err}");
        assert!(
            msg.contains(codes::OUTLET_6010),
            "expected caller-axis SCP-OUTLET-6010, got: {msg}"
        );
        assert!(
            bi.outlet_streaming_saga_registry.is_empty(),
            "a rejected non-active open must NOT start a saga / hand out a receiver"
        );

        // --- source active, target context non-active → OUTLET_6011 ---------
        // Fresh caller (still authoritatively active); close only the TARGET so
        // only the target axis is non-active.
        let handle_c = create_closeable_saga_context(&bi, &owner_identity).await;
        let handle_d = create_closeable_saga_context(&bi, &owner_identity).await;
        drive_context_closed(&bi, &handle_d.context_id(), &hosted_caller).await;

        let err = Box::pin(outlet_streaming_saga_open_on(
            &bi,
            &handle_c,
            &handle_d,
            hosted_caller,
            outlet_id,
            r#"{"a":"x","b":"y"}"#.to_owned(),
            "0123456789abcdef0123456789abcdef".to_owned(),
            now_ms(),
            1,
            "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp0cnVlfQ.placeholder-not-validated".to_owned(),
            None,
            None,
            None,
            None,
        ))
        .await
        .expect_err("a non-active target context must be rejected before the saga runs");
        let msg = format!("{err}");
        assert!(
            msg.contains(codes::OUTLET_6011),
            "expected target-axis SCP-OUTLET-6011, got: {msg}"
        );
        assert!(
            bi.outlet_streaming_saga_registry.is_empty(),
            "a rejected non-active open must NOT start a saga / hand out a receiver"
        );
    }
}
