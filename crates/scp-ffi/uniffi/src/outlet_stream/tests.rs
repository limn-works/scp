//! Tests for the §5.4.5 streaming-native outlet bridge (SCP-OUT-037, C8b —
//! `UniFFI` / Swift+Kotlin).
//!
//! Three tiers, mirroring the `PyO3` reference bridge's `e2e_bridge.rs` and the
//! NAPI sibling's `outlet_stream/tests.rs`:
//!
//! - **Non-gated** — the two pure protocol wrappers round-trip, and the
//!   control-plane ops on an UNKNOWN handle return clean, distinct not-found
//!   errors (never a panic, never a silent `None`).
//! - **Live-flow** (gated `all(testing, testing,
//!   outlet-capability-test-grant)`) — a REAL member-backed stream driven through
//!   `poll_next` to its terminal, plus CRITICAL #1 (a non-invoker grant →
//!   `SCP-PERM-3001`). Like NAPI (no GIL), it needs no `allow_threads` guard, but
//!   it proves the open path is fully wired to `Supervisor::open_outlet_stream`
//!   and drains a genuine live pump.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

use scp_core::context::outlets::stream::compute_caveats_binding;

// ---------------------------------------------------------------------------
// Pure protocol wrappers (non-gated)
// ---------------------------------------------------------------------------

/// The two pure protocol wrappers round-trip: `compute_caveats_binding` produces
/// the 32-byte binding matching the core helper, and `verify_chunk_signature`
/// accepts a correctly-signed chunk while rejecting one signed under a different
/// key (fail-closed).
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
/// only against a live entry, so an unknown handle rejects at the registry lookup
/// before any custody/supervisor work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_plane_unknown_handle_is_not_found() {
    let scp = crate::scp::Scp::new_in_memory_for_test();
    let bi = std::sync::Arc::clone(&scp.inner);
    let caller = "did:dht:z6MkUnknownHandleControlPlaneCaller01";
    let bogus = "0".repeat(32);

    let grant_err = outlet_stream_grant_credit_impl(&bi, &bogus, caller, 1)
        .await
        .expect_err("grant on an unknown handle is a not-found error");
    assert!(
        format!("{grant_err}").contains("no active outlet stream"),
        "grant not-found: {grant_err}"
    );

    let cancel_err = outlet_stream_cancel_impl(&bi, &bogus, caller)
        .await
        .expect_err("cancel on an unknown handle is a not-found error");
    assert!(
        format!("{cancel_err}").contains("no active outlet stream"),
        "cancel not-found: {cancel_err}"
    );

    let terminate_err =
        outlet_stream_terminate_impl(&bi, &bogus, caller, "authorization.revoked-mid-stream", "x")
            .await
            .expect_err("terminate on an unknown handle is a not-found error");
    assert!(
        format!("{terminate_err}").contains("no active outlet stream"),
        "terminate not-found: {terminate_err}"
    );

    // An unknown handle is a DISTINCT error, NOT a `None` terminal.
    let poll_err = outlet_stream_poll_next_impl(&bi, &bogus)
        .await
        .expect_err("poll on an unknown handle is a distinct not-found error, not None");
    assert!(
        format!("{poll_err}").contains("no active outlet stream"),
        "poll not-found: {poll_err}"
    );
}

/// The `terminate` slug guard is pure input validation (reachable without a live
/// stream): an unknown slug fails closed as a validation error. Because the slug
/// is checked BEFORE the registry lookup, this holds even for a bogus handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminate_unknown_slug_is_rejected() {
    let scp = crate::scp::Scp::new_in_memory_for_test();
    let bi = std::sync::Arc::clone(&scp.inner);
    let caller = "did:dht:z6MkTerminateSlugGuardCaller000000001";
    let bogus = "0".repeat(32);
    let err = outlet_stream_terminate_impl(&bi, &bogus, caller, "not.a.terminal.slug", "y")
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

/// Installs a per-instance DID resolver backed by a caller-retained in-memory DHT
/// client on `bi` and returns that client, so the live test can seed the
/// creator's DID document into the SAME store the open-time UCAN signature check
/// reads from — WITHOUT depending on the process-global resolver. Mirrors the
/// `bridge.rs` saga test's `install_seedable_resolver`.
#[cfg(all(
    feature = "testing",
    feature = "testing",
    feature = "outlet-capability-test-grant"
))]
fn install_seedable_resolver(
    bi: &Arc<UniffiBridgeInstance>,
) -> Arc<scp_ffi_common::dht::FfiDhtClient> {
    // ONE shared client backs BOTH the resolver AND the instance's `dht_client`
    // slot (which `identity_create`'s mint/publish and `rotation_publish_client`
    // read), so the seeded/created documents land where the resolver reads them.
    let dht_client = Arc::new(scp_ffi_common::dht::FfiDhtClient::InMemory(
        scp_dht::InMemoryDhtClient::new(),
    ));
    let cache = Arc::new(scp_identity::DidCache::new());
    let resolver = Arc::new(scp_identity::resolver::DualLayerResolver::new(
        Arc::new(scp_identity::resolver::NoOpRelayQuerier),
        Arc::clone(&dht_client),
        Arc::clone(&cache),
        Vec::new(),
    ));
    bi.set_did_resolver(resolver, tokio::runtime::Handle::current());
    bi.core.set_dht_client(Arc::clone(&dht_client));
    bi.core.set_resolver_cache(cache);
    dht_client
}

/// Publishes `owner_identity`'s DID document into `dht_client` (the
/// resolver-visible store installed by [`install_seedable_resolver`]) by signing
/// the BEP44 record with the identity's retained in-memory custody. Mirrors the
/// `bridge.rs` saga test's `seed_owner_document_into_resolver`.
#[cfg(all(
    feature = "testing",
    feature = "testing",
    feature = "outlet-capability-test-grant"
))]
async fn seed_owner_document_into_resolver(
    owner_identity: &crate::bridge::Identity,
    dht_client: &Arc<scp_ffi_common::dht::FfiDhtClient>,
) {
    use scp_dht::DhtClient as _;

    let identity = owner_identity
        .core_id
        .as_ref()
        .expect("in-memory owner retains its ScpIdentity");
    let document = owner_identity
        .core_document
        .as_ref()
        .expect("in-memory owner retains its DID document");
    let custody = owner_identity
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
        .0
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

/// Builds a single-admin, ephemeral, Encrypted `ContextParams` carrying the given
/// capability ceiling — the streaming context owned by the creator.
#[cfg(all(
    feature = "testing",
    feature = "testing",
    feature = "outlet-capability-test-grant"
))]
fn streaming_context_params(ceiling: &[&str]) -> crate::bridge::ContextParams {
    crate::bridge::ContextParams {
        participation_requirements_json: None,
        capability_requirements_json: None,
        sybil_policy_json: None,
        mode: crate::bridge::ContextMode::Encrypted,
        ceiling: ceiling.iter().map(|s| (*s).to_owned()).collect(),
        ceiling_policy: crate::bridge::CeilingPolicy::Immutable,
        governance: crate::bridge::GovernanceModel::SingleAdmin,
        memory_scope: crate::bridge::MemoryScope::Ephemeral,
        ttl_seconds: 0,
        promotable: false,
        min_protocol_version: 0,
        max_chain_depth: None,
        max_nesting_depth: None,
        session_cap: None,
        economic_policy: None,
        consequence_rules_json: None,
        consequence_config_json: None,
    }
}

/// End-to-end §5.4.5 live-stream flow through the `UniFFI` bridge: open a real
/// member-backed stream, drive `poll_next` to its terminal, and prove CRITICAL #1
/// (a non-invoker grant → `SCP-PERM-3001`).
///
/// # Why it is constructible
///
/// The invoker is made a real MEMBER via the `testing`-gated
/// `Supervisor::test_insert_member` (clears the §9.8.5 membership gate) AND
/// granted `OutletCallAll` via the dedicated `outlet-capability-test-grant` seam
/// (clears the runtime pump's role-state capability gate — the default `member`
/// role grants only `messages:*`). The outlet is ZERO-cost, so no escrow/funding
/// fixture is needed. `estimated_chunk_count=Some(1)` is declared (an unbounded
/// default coerces to `u32::MAX` and trips SCP-OUTLET-6120).
///
/// # What it proves
///
/// The open path reaches `Supervisor::open_outlet_stream` and drains a genuine
/// live pump to terminal, and the caller==invoker gate rejects a stranger before
/// any signing / reserve.
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
    let bi = Arc::clone(&scp.inner);

    // Per-instance, caller-retained resolver installed BEFORE the first
    // identity_create so its store is the one the supervisor snapshots.
    let resolver_dht = install_seedable_resolver(&bi);

    // Creator (context owner + outlet operator; its co-resident custody signs
    // chunks), invoker (the pinned stream driver), and a stranger (CRITICAL #1).
    let creator_identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create (creator) should succeed");
    let creator = creator_identity.did.clone();
    let invoker_identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create (invoker) should succeed");
    let invoker = invoker_identity.did.clone();
    let stranger_identity = scp
        .identity_create("in_memory".to_owned(), None)
        .await
        .expect("identity_create (stranger) should succeed");
    let stranger = stranger_identity.did.clone();

    // Seed the creator's DID document into the resolver-visible store so the
    // open-time UCAN signature check resolves the issuer key.
    seed_owner_document_into_resolver(&creator_identity, &resolver_dht).await;

    // Context owned by the creator; ceiling admits the Action outlet stem.
    let handle = scp
        .context_create(
            Arc::clone(&creator_identity),
            streaming_context_params(&[
                "outlet:call:*",
                "messages:read",
                "messages:write",
                "governance:propose",
            ]),
        )
        .await
        .expect("context_create should succeed");
    let ctx = handle.context_id.clone();

    // Zero-cost Action outlet operated by the creator, registered into the
    // handle's per-context registry (the streaming open reads it from there).
    let definition = crate::bridge::OutletDefinition {
        registered_at: None,
        operator_signature: None,
        name: "uniffi_streaming_live".to_owned(),
        description: "live streaming outlet".to_owned(),
        kind: crate::bridge::OutletKind::Action,
        input_schema_json:
            r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}"#
                .to_owned(),
        output_schema_json: r#"{"type":"object"}"#.to_owned(),
        test_vectors_json: None,
        implementation_hash: None,
        operator_did: creator.clone(),
        cost: None,
    };
    let outlet_id = scp
        .outlet_register(Arc::clone(&handle), definition)
        .await
        .expect("outlet_register should succeed");

    // Deterministic single-shot handler (the producer side of the pump).
    let handler: OutletHandler =
        Arc::new(|_input: serde_json::Value| Ok(serde_json::json!({"sum": 3, "ok": 1})));
    handle
        .outlet_handlers
        .lock()
        .await
        .insert(outlet_id.clone(), handler);

    // Make the invoker a real member (clears §9.8.5) and grant it OutletCallAll
    // (clears the runtime role-state capability gate).
    let supervisor = Arc::clone(
        bi.context_manager_expect()
            .expect("supervisor must be initialized"),
    );
    supervisor
        .test_insert_member(&ctx, scp_did::DID(invoker.clone()), "member")
        .await
        .expect("test_insert_member seeds the invoker as a member");
    supervisor
        .test_grant_member_capability(&ctx, scp_did::DID(invoker.clone()), "outlet_call:*")
        .await
        .expect("grant OutletCallAll to the member invoker");

    // Creator-issued outlet_call UCAN delegated to the member invoker.
    let ucan = scp
        .ucan_mint(
            Arc::clone(&handle),
            invoker.clone(),
            vec!["outlet_call:*".to_owned()],
            None,
        )
        .await
        .expect("ucan_mint should succeed");

    // OPEN — succeeds (member + valid UCAN + zero cost), returning the hex
    // StreamHandleId PROMPTLY (Commit transition, never block-until-terminal).
    let handle_id = outlet_stream_open_impl(
        &bi,
        &handle,
        outlet_id.clone(),
        r#"{"a":"1","b":"2"}"#.to_owned(),
        invoker.clone(),
        ucan.encoded(),
        None,
        None,
        None,
        Some(1),
    )
    .await
    .expect("member invoker opens a live stream");

    // The context's default credit window (>= 1) admits the first Data chunk with
    // NO grant, so this poll parks on the live pump and returns the handler's Data
    // chunk.
    let first = outlet_stream_poll_next_impl(&bi, &handle_id)
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
    let stranger_err = outlet_stream_grant_credit_impl(&bi, &handle_id, &stranger, 1)
        .await
        .expect_err("a non-invoker grant must be rejected");
    assert!(
        format!("{stranger_err}").contains(codes::PERM_3001),
        "a caller that is not the pinned invoker is rejected with SCP-PERM-3001: {stranger_err}"
    );

    // A self-grant exercises the bridge's INTERNAL credit signing + escrow reserve
    // + apply path. The single-shot stream may already have closed (a benign
    // lifecycle race), but a bridge-signed grant must NEVER be rejected as a
    // signature/authorization failure (SCP-OUTLET-6110).
    if let Err(e) = outlet_stream_grant_credit_impl(&bi, &handle_id, &invoker, 1).await {
        assert!(
            !format!("{e}")
                .contains(scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED),
            "a correctly bridge-signed grant must not be rejected as a signature/auth failure: {e}"
        );
    }

    // Drive the REST of the stream to its terminal.
    let mut saw_terminal = false;
    for _ in 0..16 {
        let Some(bytes) = outlet_stream_poll_next_impl(&bi, &handle_id).await.unwrap() else {
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
    let after = outlet_stream_poll_next_impl(&bi, &handle_id)
        .await
        .expect_err("the entry is evicted at the terminal chunk (no registry leak)");
    assert!(
        format!("{after}").contains("no active outlet stream"),
        "post-terminal poll is a not-found error: {after}"
    );
}

// ---------------------------------------------------------------------------
// SCP-OUT-039 (§5.4.5) — LIVE single-shot-seam vectors through the real UniFFI
// bridge. The EXTERNAL `crates/scp-ffi/uniffi/tests/outlet_stream_vectors_real.rs`
// carries all-7-vector WIRE INTEGRITY (pure wrappers); the LIVE open→poll→drain
// control plane requires crate-internal setup seams (`Scp.inner` is `pub(crate)`,
// handler registration goes through `handle.outlet_handlers`, member seeding
// through the `bi`-scoped supervisor), so it lives here as an internal module.
// This drives the vectors the single-shot `BridgeStreamExecutor` seam CAN produce
// — `non_streaming`, `error_terminal`, `cancellation` (the same set the PyO3
// reference drives live). `multi_chunk` / `error_recoverable` need a multi-chunk
// executor and `credit_stall`'s stall cannot be produced by a one-shot
// handler; those stay covered at the runtime tiers (deliverables 2/3). Named
// `streaming_vectors_live` so the `streaming_vectors` test filter selects it.
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
        _scp: Arc<crate::scp::Scp>,
        bi: Arc<UniffiBridgeInstance>,
        handle_id: String,
        invoker: String,
        stranger: String,
    }

    /// Stands up a live zero-cost Action outlet stream driven by `handler`,
    /// mirroring `live_poll_next_drains_to_terminal`'s setup exactly, and returns
    /// the opened stream fixture. `outlet_name` disambiguates the outlet per test.
    async fn open_live_vector_stream(
        outlet_name: &str,
        handler: OutletHandler,
    ) -> LiveVectorFixture {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = Arc::clone(&scp.inner);

        let resolver_dht = install_seedable_resolver(&bi);

        let creator_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (creator)");
        let creator = creator_identity.did.clone();
        let invoker_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (invoker)");
        let invoker = invoker_identity.did.clone();
        let stranger_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (stranger)");
        let stranger = stranger_identity.did.clone();

        seed_owner_document_into_resolver(&creator_identity, &resolver_dht).await;

        let handle = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(&[
                    "outlet:call:*",
                    "messages:read",
                    "messages:write",
                    "governance:propose",
                ]),
            )
            .await
            .expect("context_create");
        let ctx = handle.context_id.clone();

        let definition = crate::bridge::OutletDefinition {
            registered_at: None,
            operator_signature: None,
            name: outlet_name.to_owned(),
            description: "SCP-OUT-039 live vector outlet".to_owned(),
            kind: crate::bridge::OutletKind::Action,
            input_schema_json:
                r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}"#
                    .to_owned(),
            output_schema_json: r#"{"type":"object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: creator.clone(),
            cost: None,
        };
        let outlet_id = scp
            .outlet_register(Arc::clone(&handle), definition)
            .await
            .expect("outlet_register");

        handle
            .outlet_handlers
            .lock()
            .await
            .insert(outlet_id.clone(), handler);

        let supervisor = Arc::clone(
            bi.context_manager_expect()
                .expect("supervisor must be initialized"),
        );
        supervisor
            .test_insert_member(&ctx, scp_did::DID(invoker.clone()), "member")
            .await
            .expect("test_insert_member");
        supervisor
            .test_grant_member_capability(&ctx, scp_did::DID(invoker.clone()), "outlet_call:*")
            .await
            .expect("grant OutletCallAll");

        let ucan = scp
            .ucan_mint(
                Arc::clone(&handle),
                invoker.clone(),
                vec!["outlet_call:*".to_owned()],
                None,
            )
            .await
            .expect("ucan_mint");

        let handle_id = outlet_stream_open_impl(
            &bi,
            &handle,
            outlet_id.clone(),
            r#"{"a":"1","b":"2"}"#.to_owned(),
            invoker.clone(),
            ucan.encoded(),
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
    /// the vector's aggregate; the live pump delivers one `Data` chunk whose value
    /// equals the vector's first Data, then the framework `End` closes it, with
    /// monotonic-from-0 sequences.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_streaming_vector_drains_data_then_end_live() {
        use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk as Chunk};

        let handler: OutletHandler = Arc::new(|_input| Ok(serde_json::json!({ "sum": 3 })));
        let fx = open_live_vector_stream("uniffi_vec_non_streaming", handler).await;

        let mut seqs = Vec::new();
        let mut first_data_value = None;
        let mut saw_end = false;
        for _ in 0..16 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                outlet_stream_poll_next_impl(&fx.bi, &fx.handle_id),
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

    /// `error_terminal` (§5.4.5): a faulting single-shot handler maps to a
    /// framework terminal `Error{terminal:true, code: SCP-OUTLET-6130}`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn error_terminal_vector_maps_handler_fault_to_6130_live() {
        use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk as Chunk};

        let handler: OutletHandler = Arc::new(|_input| Err("handler fault".to_owned()));
        let fx = open_live_vector_stream("uniffi_vec_error_terminal", handler).await;

        let mut terminal_code = None;
        for _ in 0..16 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                outlet_stream_poll_next_impl(&fx.bi, &fx.handle_id),
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

    /// `cancellation` (§5.4.5 cancel-ack): the pinned invoker's signed cancel
    /// through the real control plane drives the stream to a framework terminal; a
    /// non-invoker caller is rejected SCP-PERM-3001 (CRITICAL #1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_vector_control_plane_reaches_terminal_live() {
        use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk as Chunk};

        let handler: OutletHandler = Arc::new(|_input| Ok(serde_json::json!({ "n": 0 })));
        let fx = open_live_vector_stream("uniffi_vec_cancellation", handler).await;

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            outlet_stream_poll_next_impl(&fx.bi, &fx.handle_id),
        )
        .await
        .expect("first poll resolves within 10s (fail fast, don't hang)")
        .unwrap()
        .expect("first poll returns the handler's Data chunk");
        let first_chunk: Chunk = serde_json::from_slice(&first).unwrap();
        assert!(matches!(first_chunk.payload, ChunkPayload::Data { .. }));

        let stranger_err = outlet_stream_cancel_impl(&fx.bi, &fx.handle_id, &fx.stranger)
            .await
            .expect_err("a non-invoker cancel must be rejected");
        assert!(
            format!("{stranger_err}").contains(codes::PERM_3001),
            "non-invoker cancel is rejected with SCP-PERM-3001: {stranger_err}"
        );

        if let Err(e) = outlet_stream_cancel_impl(&fx.bi, &fx.handle_id, &fx.invoker).await {
            assert!(
                !format!("{e}")
                    .contains(scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED),
                "a correctly bridge-signed cancel must not be a signature/auth failure: {e}"
            );
        }

        let mut saw_terminal = false;
        for _ in 0..16 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                outlet_stream_poll_next_impl(&fx.bi, &fx.handle_id),
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
// Cross-context STREAMING saga (§5.4.5 / §6.2.4, SCP-OUT-047) — UniFFI bridge.
//
// The behavioral counterparts of the PyO3 reference `e2e_bridge.rs` streaming-
// saga tests. These exercise what the bridge ADDS on top of the supervisor
// producer (whose full Committed / truncated-close paths need actor-state +
// budget injection with no bridge-public wiring):
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
// Gated on the full live-test pair (identity/context construction via `testing`
// + the seedable resolver), matching `streaming_vectors_live`.
#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
mod xctx_streaming_saga_tests {
    use super::*;

    fn now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }

    const STREAMING_CEILING: &[&str] = &[
        "outlet:call:*",
        "messages:read",
        "messages:write",
        "governance:propose",
    ];

    /// (a) OPEN caller-principal binding, hosted axis: a `caller_did` this bridge
    /// instance does NOT host is rejected with `SagaAborted` (SCP-SAGA-13050)
    /// BEFORE the streaming saga runs — and before any outlet read — so the
    /// receiver is never handed out. Asserts the bridge-unique axis-(a) substring
    /// so the test fails if the registry check is removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_streaming_saga_unhosted_caller_rejected_before_saga() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = Arc::clone(&scp.inner);
        let _resolver = install_seedable_resolver(&bi);

        let creator_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (creator) should succeed");
        let handle_a = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(STREAMING_CEILING),
            )
            .await
            .expect("context_create (caller) should succeed");
        let handle_b = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(STREAMING_CEILING),
            )
            .await
            .expect("context_create (target) should succeed");
        let outlet_id =
            scp_ffi_common::outlet_id::generate_outlet_id("xctx_streaming_unhosted_probe");

        // A syntactically valid DID that was never created on this instance.
        let unhosted_caller = "did:dht:z6MkUnhostedStreamingCaller01".to_owned();

        let err = outlet_streaming_saga_open_impl(
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
        )
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
        let bi = Arc::clone(&scp.inner);
        let _resolver = install_seedable_resolver(&bi);

        let unhosted_caller = "did:dht:z6MkUnhostedStreamingRecover1";
        let err =
            outlet_streaming_saga_recover_truncated_close_impl(&bi, "any-saga-id", unhosted_caller)
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
        let bi = Arc::clone(&scp.inner);
        let _resolver = install_seedable_resolver(&bi);

        // The invoker who "opened" the saga, and a DIFFERENT hosted identity.
        let invoker_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (invoker)");
        let invoker = invoker_identity.did.clone();
        let stranger_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (stranger)");
        let stranger = stranger_identity.did.clone();

        // Inject a live saga entry pinned to `invoker` (the full committed path
        // needs actor-state/budget injection with no bridge-public wiring —
        // identical to the unary-saga bridge tests).
        let saga_id = "saga-out047-uniffi-invoker-gate-0001";
        scp.insert_test_streaming_saga_entry(saga_id, "target-ctx-out047", &invoker);

        // A hosted-but-not-invoker caller clears the channel-auth gate, reaches
        // the invoker check, and is rejected there.
        let err = outlet_streaming_saga_recover_truncated_close_impl(&bi, saga_id, &stranger)
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

    /// A close-capable streaming ceiling: identical to [`STREAMING_CEILING`] but
    /// also grants `context:close`, so the creator can drive the context to a REAL
    /// non-active lifecycle state through the supervisor close path.
    const CLOSEABLE_STREAMING_CEILING: &[&str] = &[
        "context:close",
        "outlet:call:*",
        "messages:read",
        "messages:write",
        "governance:propose",
    ];

    /// Drives `context_id` to a real non-active (`Closed`) lifecycle state through
    /// the REAL supervisor close path — the exact `LifecycleCommand::CloseContext`
    /// dispatch the bridge's close uses — so a subsequent
    /// `supervisor.read_context_state(context_id)` returns a non-`Active` state.
    /// That authoritative state (NOT the bridge-cached `ContextHandle::state`) is
    /// what the streaming-saga open's active-state guard now reads. `initiator_did`
    /// must be the creator of a context created with a `ContextClose`-bearing
    /// ceiling (see [`CLOSEABLE_STREAMING_CEILING`]).
    async fn drive_context_closed(
        bi: &Arc<crate::runtime::UniffiBridgeInstance>,
        context_id: &str,
        initiator_did: &str,
    ) {
        use scp_core::context::actor::commands::{CloseContextPayload, LifecycleCommand};

        let supervisor = Arc::clone(
            bi.context_manager_or_error()
                .expect("supervisor should be attached"),
        );
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
    /// guard and the NAPI streaming open — BEFORE any input validation, UCAN
    /// check, or saga drive, so no saga is started and no receiver is handed out.
    ///
    /// The context is driven to a REAL `Closed` state through the actual
    /// supervisor close path; the guard reads the AUTHORITATIVE actor state via
    /// `read_context_state` (NOT the lagging FFI `ContextHandle::state` cache), so
    /// this genuinely exercises the authoritative read that closes the
    /// Closing-cache money gap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_streaming_saga_open_rejects_non_active_context() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = Arc::clone(&scp.inner);
        let _resolver = install_seedable_resolver(&bi);

        let creator_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (creator) should succeed");
        let hosted_caller = creator_identity.did.clone();
        let outlet_id =
            scp_ffi_common::outlet_id::generate_outlet_id("xctx_streaming_non_active_probe");

        let open_args = |caller: String, outlet: String| {
            (
                caller,
                outlet,
                r#"{"a":"x","b":"y"}"#.to_owned(),
                "0123456789abcdef0123456789abcdef".to_owned(),
                "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp0cnVlfQ.placeholder-not-validated".to_owned(),
            )
        };

        // --- source (caller) context non-active → OUTLET_6010 ---------------
        // Drive the CALLER context to a REAL Closed state through the supervisor;
        // the authoritative guard must reject it.
        let handle_a = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(CLOSEABLE_STREAMING_CEILING),
            )
            .await
            .expect("context_create (caller) should succeed");
        let handle_b = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(CLOSEABLE_STREAMING_CEILING),
            )
            .await
            .expect("context_create (target) should succeed");
        drive_context_closed(&bi, &handle_a.context_id(), &hosted_caller).await;

        // Precondition: the authoritative supervisor state is non-active — this is
        // what the guard reads, proving the test drives a REAL Closing/Closed
        // context, not the FFI cache.
        assert_ne!(
            bi.context_manager_or_error()
                .expect("supervisor")
                .read_context_state(&handle_a.context_id())
                .await,
            Some(scp_core::context::ContextState::Active),
            "the caller context must be authoritatively non-active before the open"
        );

        let (caller, outlet, input, nonce, ucan) =
            open_args(hosted_caller.clone(), outlet_id.clone());
        let err = outlet_streaming_saga_open_impl(
            &bi,
            &handle_a,
            &handle_b,
            caller,
            outlet,
            input,
            nonce,
            now_ms(),
            1,
            ucan,
            None,
            None,
            None,
            None,
        )
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
        // Fresh caller (still authoritatively active); close only the TARGET.
        let handle_c = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(CLOSEABLE_STREAMING_CEILING),
            )
            .await
            .expect("context_create (caller 2) should succeed");
        let handle_d = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(CLOSEABLE_STREAMING_CEILING),
            )
            .await
            .expect("context_create (target 2) should succeed");
        drive_context_closed(&bi, &handle_d.context_id(), &hosted_caller).await;

        let (caller, outlet, input, nonce, ucan) = open_args(hosted_caller, outlet_id);
        let err = outlet_streaming_saga_open_impl(
            &bi,
            &handle_c,
            &handle_d,
            caller,
            outlet,
            input,
            nonce,
            now_ms(),
            1,
            ucan,
            None,
            None,
            None,
            None,
        )
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

    /// (CRYPTO defense-in-depth, SCP-OUT-047) The streaming-saga RECOVER derives
    /// the TARGET context's Active Signing Key from the `creator_did` it reads out
    /// of the UCAN-state registry (`with_ucan_state`), whereas the context handle
    /// carries its OWN `creator_did`. In the co-resident model these are the SAME
    /// fact from two sources; this pins that they never diverge for a registered
    /// context, so a future refactor that lets one drift from the other (letting
    /// recover seal under a different context's key) is caught here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xctx_streaming_saga_ucan_state_creator_did_matches_handle() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = Arc::clone(&scp.inner);
        let _resolver = install_seedable_resolver(&bi);

        let creator_identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");
        let handle = scp
            .context_create(
                Arc::clone(&creator_identity),
                streaming_context_params(STREAMING_CEILING),
            )
            .await
            .expect("context_create should succeed");

        let ucan_creator = bi
            .with_ucan_state(&handle.context_id, |state| state.creator_did.clone())
            .expect("a created context must be registered in the UCAN-state registry");
        assert_eq!(
            ucan_creator, handle.creator_did,
            "the UCAN-state creator_did (the recover signing-key source) must equal the handle's \
             creator_did — a divergence would let streaming-saga recover seal under a different \
             context's Active Signing Key"
        );
    }
}
