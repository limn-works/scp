//! SCP-OUT-039 (C12) — outlet-streaming conformance vectors, THROUGH-OPEN-PATH.
//!
//! Replays `tests/conformance/vectors/outlet_stream_vectors.json` through the
//! REAL supervisor control path [`Supervisor::open_outlet_stream`] against a
//! LIVE context actor (spawned by `Supervisor::create_context`), rather than the
//! raw `open_stream_session` dispatch the sibling `outlet_stream_conformance`
//! test drives. This is the "through-open-path" replay location: it exercises
//! the actor-mailbox escrow reserve, the `ContextParams`-authoritative window /
//! timing overwrite (§5.4.5 / SCP-OUT-034 — the supervisor OVERWRITES
//! `credit_window`, `stream_credit_stall_secs`, `stream_cancel_ack_secs`, and
//! `stream_ucan_recheck_secs` from the hosting context, so those are pinned on
//! the CONTEXT here, not the caller-supplied `OpenStreamParams`), the
//! caveats-binding recompute-and-pin, and the runtime-derived-cursor cancel
//! signing — end to end.
//!
//! The invoker is the CONTEXT CREATOR (admin): `create_context` seeds the
//! creator with every capability in the ceiling, so the §9.8.5 membership gate
//! and the `OutletCallAll` capability gate both clear without the
//! `outlet-capability-test-grant` seam.
//!
//! The shared harness (vector schema, `ScriptedExecutor`, `ReceiverSequenceTracker`,
//! assertions, credit-grant signer, the §25.2 reference key, the caveats-binding
//! KAT, and the `sequence_gap` + schema-shape tests) lives in the sibling
//! [`outlet_stream_vectors_common`] module, included below and shared byte-for-byte
//! with the runtime-direct tier.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[path = "outlet_stream_vectors_common.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use scp_core::context::{Capability, ContextMode, ContextParams};
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::registry::{OutletRegistry, register_outlet};
use scp_protocol::context::outlets::stream::{
    OutletStreamChunk, RequestId, compute_caveats_binding,
};
use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
use scp_protocol::economy::types::Amount;
use scp_protocol::trust::caveats::InvocationCaveats;

use scp_runtime::context::InvocationCaveatBinding;
use scp_runtime::context::outlets::dispatch::{CancelIdentity, OpenStreamParams};
use scp_runtime::context::outlets::signer::InProcessStreamSigner;
use scp_runtime::context::outlets::stream::{AdmissionCaps, StreamIdentity};

use scp_did::DID;
use scp_testing::fullstack::FullStackNetwork;

use common::{
    DrainOutcome, EndStatus, STREAM_EPOCH, ScriptedExecutor, Vector, apply_grant,
    assert_data_prefix, assert_terminal_status, assert_transcript_matches, build_script,
    load_vectors, registration, vector,
};

// ---------------------------------------------------------------------------
// Supervisor harness — creates a live context and opens a stream through
// `Supervisor::open_outlet_stream`.
// ---------------------------------------------------------------------------

/// The context creator == invoker == outlet operator (co-resident custody).
const CREATOR_DID: &str = "did:key:z6MkThroughOpenPathCreator";

/// The operator/invoker Ed25519 key. Operator == invoker (ADR-034): the same key
/// signs chunks (operator) and credit grants / cancels (invoker). It is
/// independent of the `FullStack` node's DID-derived MLS/transport key — the open
/// path pins `invoker_pk` from `OpenStreamParams`, not from a DID resolve.
fn invoker_key() -> SigningKey {
    SigningKey::from_bytes(&[0x24; 32])
}

/// A valid 64-hex context id, unique per vector (each vector gets its own live
/// context on its own supervisor).
fn ctx_id_for(name: &str) -> String {
    let digest = Sha256::digest(name.as_bytes());
    hex::encode(digest)
}

/// A role state granting the creator `OutletRegister` so the local
/// `register_outlet` gate accepts the registration. (The OPEN itself is gated by
/// the ACTOR's `role_state`, which `create_context` seeds with the full ceiling.)
fn registering_role_state(ctx_id: &str, creator: &str) -> ContextRoleState {
    let mut role_state = ContextRoleState::new(
        ctx_id.to_owned(),
        creator,
        default_ceiling(),
        vec![],
        &scp_clock::TestClock::new(1_700_000_000),
    )
    .expect("role state");
    role_state.members.insert(creator.to_owned());
    let caps = role_state
        .member_capabilities
        .entry(creator.to_owned())
        .or_default();
    caps.insert(Capability::OutletRegister);
    caps.insert(Capability::OutletCallAll);
    role_state
}

/// Ceiling for the created context — the creator (admin) inherits every listed
/// capability, so the open's `OutletCallAll` gate clears.
fn context_ceiling() -> Vec<Capability> {
    vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletQueryAll,
        Capability::OutletCallAll,
        Capability::OutletRegister,
    ]
}

/// Creates a live context via the real supervisor, opens a stream for `vector`
/// through `Supervisor::open_outlet_stream`, applies the vector's credit grants
/// and (optionally) a signed cancel, and drains to the terminal chunk.
async fn drive_vector(vec: &Vector) -> DrainOutcome {
    let key = invoker_key();
    let invoker_pk = key.verifying_key();
    let request_id: RequestId = vec.open.request_id;
    let outlet_id: OutletId = vec.open.outlet_id.clone();
    let creator = DID(CREATOR_DID.to_owned());
    let kind = vec.outlet_kind.to_kind();
    let ctx_id = ctx_id_for(&vec.name);

    // Live context on a real supervisor. The window (`stream_window_default`) and
    // timing are CONTEXT-authoritative — `open_outlet_stream` overwrites the
    // caller `OpenStreamParams` values from these, so they are pinned HERE.
    let net = FullStackNetwork::new();
    let node = net.create_node(CREATOR_DID);
    let credit_stall_secs =
        if vec.expected_error_code.as_deref() == Some(scp_protocol::CODE_EXECUTION_CREDIT_STALL) {
            1
        } else {
            3_600
        };
    let cancel_ack_secs = if vec.expected_end_status == EndStatus::Cancelled {
        1
    } else {
        3_600
    };
    let params_ctx = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: context_ceiling(),
        stream_window_default: vec.open.credit_window,
        stream_credit_stall_secs: credit_stall_secs,
        stream_cancel_ack_secs: cancel_ack_secs,
        stream_ucan_recheck_secs: 3_600,
        ..ContextParams::default()
    };
    node.create_context(&ctx_id, params_ctx)
        .await
        .expect("create_context spawns a live actor");

    // §5.4.5 caveats_binding — recomputed EXACTLY (same estimate as
    // `declared_estimated_chunk_count`) or the open is rejected
    // `CaveatsBindingMismatch`. The live open uses the real creator DID / a local
    // ucan_cid; the vector's declared ucan_cid / invoker_did are pinned separately
    // by the caveats-binding KAT.
    let caveats = InvocationCaveats::empty();
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("caveats jcs");
    let ucan_cid = "cid-through-open-path".to_owned();
    let caveats_binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        &creator.0,
        vec.open.estimated_chunk_count,
        &caveats_jcs,
    );

    // Local registry with the outlet registered (the OPEN is gated by the actor's
    // role_state; this registry supplies the registration the pump dispatches).
    let role_state = registering_role_state(&ctx_id, &creator.0);
    let mut registry = OutletRegistry::new();
    register_outlet(
        &mut registry,
        &role_state,
        registration(&outlet_id, kind, &creator),
        &creator.0,
    )
    .expect("register conformance outlet");

    let (emit, terminal) = build_script(vec);
    let executor: Arc<dyn scp_runtime::context::outlets::invoke::OutletExecutor> =
        Arc::new(ScriptedExecutor { emit, terminal });

    let params = OpenStreamParams {
        identity: StreamIdentity {
            context_id: ctx_id.clone(),
            outlet_id: outlet_id.clone(),
            stream_epoch: STREAM_EPOCH,
            caveats_binding,
        },
        // Overwritten by the supervisor from ContextParams — supplied for shape.
        caps: AdmissionCaps {
            per_invoker: 64,
            per_origin_invoker: 64,
            per_outlet: 64,
        },
        invoker_did: creator.0.clone(),
        origin_invoker_did: creator.0.clone(),
        cost_per_chunk: Amount::new(0),
        available_balance: Amount::new(0),
        reserved_escrow: Amount::new(0),
        declared_estimated_chunk_count: Some(vec.open.estimated_chunk_count),
        credit_window: vec.open.credit_window, // overwritten from ctx_params
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer: Arc::new(InProcessStreamSigner::new(key.clone())),
        stream_credit_stall_secs: credit_stall_secs, // overwritten from ctx_params
        stream_cancel_ack_secs: cancel_ack_secs,     // overwritten from ctx_params
        stream_ucan_recheck_secs: 3_600,             // overwritten from ctx_params
        ucan_cid: ucan_cid.clone(),
        request_id,
        revocation_checker: Arc::new(
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
        ),
        economic_policy_snapshot: None,
    };

    let invocation_binding = Some(InvocationCaveatBinding { caveats, ucan_cid });

    let mut handle = node
        .manager
        .open_outlet_stream(
            &ctx_id,
            &registry,
            &outlet_id,
            vec.open.input.clone(),
            &creator,
            Some(vec.open.timeout_ms),
            executor,
            None,
            None,
            None,
            invocation_binding,
            params,
        )
        .await
        .expect("open_outlet_stream accepts a well-formed open");

    let mut rx = handle.receiver().expect("receiver");
    let summary_rx = handle.close_summary().expect("close summary");

    // Apply any credit grant scheduled before the first chunk (after == -1).
    for credit in vec.credits.iter().filter(|c| c.after_chunk_index < 0) {
        apply_grant(
            &handle,
            &key,
            &ctx_id,
            &outlet_id,
            &request_id,
            &caveats_binding,
            credit,
        );
    }

    let mut chunks: Vec<OutletStreamChunk> = Vec::new();
    let cancel_at = vec.cancel_after_chunk_index;
    let mut cancel_sent = false;

    loop {
        let item = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("chunk within 10s");
        let Some(item) = item else {
            break;
        };
        // The third outcome, distinct from a chunk and from the closed
        // sentinel: the operator key refused a chunk AND refused the terminal
        // that would have reported that refusal (§5.4.5 "Signature refusal").
        // These vectors drive the in-process test signer, which signs every
        // preimage, so a refusal here means the pump changed behaviour and the
        // vector's chunk expectations no longer describe what it emits.
        let chunk = item.expect(
            "the in-process test signer signs every chunk, so this vector run must not observe a \
             §5.4.5 signature refusal",
        );
        let terminal = chunk.payload.is_terminal();
        let idx = i64::try_from(chunks.len()).expect("chunk index fits i64");
        chunks.push(chunk);

        for credit in vec.credits.iter().filter(|c| c.after_chunk_index == idx) {
            apply_grant(
                &handle,
                &key,
                &ctx_id,
                &outlet_id,
                &request_id,
                &caveats_binding,
                credit,
            );
        }

        if terminal {
            break;
        }

        if let Some(at) = cancel_at
            && !cancel_sent
            && idx == at
        {
            let cancel_signer = InProcessStreamSigner::new(key.clone());
            let cancel_identity = CancelIdentity {
                context_id: ctx_id.clone(),
                outlet_id: outlet_id.clone(),
                caveats_binding,
            };
            handle
                .apply_outlet_cancel_signed(&cancel_signer, &cancel_identity)
                .await
                .expect("signed cancel applies");
            cancel_sent = true;
        }
    }

    let summary = tokio::time::timeout(Duration::from_secs(10), summary_rx)
        .await
        .expect("close summary within 10s")
        .expect("summary channel not dropped");

    DrainOutcome {
        chunks,
        cancel_ack_seq: summary.cancel_ack_seq,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async fn run_transcript_vector(name: &str) {
    let file = load_vectors();
    let vec = vector(&file, name);
    let outcome = drive_vector(vec).await;
    assert_transcript_matches(vec, &outcome);
    assert_terminal_status(vec, &outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_streaming_through_open_path() {
    run_transcript_vector("non_streaming").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_chunk_through_open_path() {
    run_transcript_vector("multi_chunk").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_terminal_through_open_path() {
    run_transcript_vector("error_terminal").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_recoverable_through_open_path() {
    run_transcript_vector("error_recoverable").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credit_stall_through_open_path() {
    run_transcript_vector("credit_stall").await;
}

/// Cancellation: the transcript is timing-dependent (the forced terminal races
/// the executor's remaining chunks), so assert the §5.4.5 Cancelled signal (a
/// recorded cancel-ack seq + a terminal chunk) and that delivered Data is a
/// prefix of the vector's declared Data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_through_open_path() {
    let file = load_vectors();
    let vec = vector(&file, "cancellation");
    let outcome = drive_vector(vec).await;
    assert_terminal_status(vec, &outcome);
    assert_data_prefix(vec, &outcome);
}
