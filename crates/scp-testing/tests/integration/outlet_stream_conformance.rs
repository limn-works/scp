//! SCP-OUT-039 (C12) — outlet-streaming conformance vectors, RUNTIME layer.
//!
//! Replays `tests/conformance/vectors/outlet_stream_vectors.json` through the
//! RAW runtime dispatch [`open_stream_session`] (§5.4.5 "Progressive Output").
//! This is the runtime-direct replay location: a `ScriptedExecutor` emits each
//! vector's non-terminal payloads, the framework appends the terminal chunk,
//! and the receiver drain is asserted against the vector's declared transcript
//! and `expected_end_status` / `expected_error_code`.
//!
//! The shared harness (vector schema, `ScriptedExecutor`, `ReceiverSequenceTracker`,
//! transcript/terminal assertions, credit-grant signer, the §25.2 reference key,
//! the caveats-binding KAT, and the `sequence_gap` + schema-shape tests) lives in
//! the sibling [`outlet_stream_vectors_common`] module, included below and shared
//! byte-for-byte with the through-open-path tier. This file keeps only the
//! runtime-direct `drive_vector` + its setup and the thin `#[tokio::test]`
//! wrappers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[path = "outlet_stream_vectors_common.rs"]
mod common;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use scp_protocol::context::ContextState;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::registry::{OutletRegistry, register_outlet};
use scp_protocol::context::outlets::stream::{
    OutletStreamChunk, RequestId, compute_caveats_binding,
};
use scp_protocol::context::roles::{Capability, ContextRoleState, default_ceiling};
use scp_protocol::economy::types::Amount;
use scp_protocol::trust::caveats::InvocationCaveats;

use scp_runtime::context::ContextHandle;
use scp_runtime::context::outlets::dispatch::{
    CancelIdentity, OpenStreamParams, open_stream_session,
};
use scp_runtime::context::outlets::signer::InProcessStreamSigner;
use scp_runtime::context::outlets::stream::{
    AdmissionCaps, OriginAdmissionTracker, StreamAdmissionTracker, StreamIdentity,
};

use scp_did::DID;

use common::{
    DrainOutcome, EndStatus, STREAM_EPOCH, ScriptedExecutor, Vector, apply_grant,
    assert_data_prefix, assert_terminal_status, assert_transcript_matches, build_script,
    load_vectors, registration, vector,
};

// ---------------------------------------------------------------------------
// Dispatch harness — opens a raw stream session and drives it to close.
// ---------------------------------------------------------------------------

fn ctx_id() -> String {
    "aa".repeat(32)
}

/// The invoker/operator key. Operator == invoker (co-resident custody, ADR-034):
/// the same key signs chunks (operator) and credit grants / cancels (invoker).
fn invoker_key() -> SigningKey {
    SigningKey::from_bytes(&[0x24; 32])
}

fn invoker_did() -> DID {
    DID("did:dht:z6MkConformanceInvoker".to_owned())
}

/// Builds a role state that makes the invoker a member with `OutletCallAll` +
/// `OutletRegister` (clears the §9.8.5 membership + capability gates).
fn authorizing_role_state() -> ContextRoleState {
    let mut role_state = ContextRoleState::new(
        ctx_id(),
        &invoker_did().0,
        default_ceiling(),
        vec![],
        &scp_clock::TestClock::new(1_700_000_000),
    )
    .expect("role state");
    role_state.members.insert(invoker_did().0);
    let caps = role_state
        .member_capabilities
        .entry(invoker_did().0)
        .or_default();
    caps.insert(Capability::OutletCallAll);
    caps.insert(Capability::OutletRegister);
    role_state
}

/// Opens a raw stream session for `vector`, applies the vector's credit grants
/// and (optionally) a signed cancel, and drains to the terminal chunk.
async fn drive_vector(vec: &Vector) -> DrainOutcome {
    let key = invoker_key();
    let invoker_pk = key.verifying_key();
    let request_id: RequestId = vec.open.request_id;
    let outlet_id: OutletId = vec.open.outlet_id.clone();
    let kind = vec.outlet_kind.to_kind();

    // §5.4.5 caveats_binding — recomputed EXACTLY or `open_stream_session`
    // rejects with `CaveatsBindingMismatch`. The live open legitimately uses the
    // real member DID / a local ucan_cid (the vector's declared ucan_cid /
    // invoker_did are pinned separately by the caveats-binding KAT).
    let caveats = InvocationCaveats::empty();
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("caveats jcs");
    let ucan_cid = "cid-outlet-stream-conformance".to_owned();
    let caveats_binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        &invoker_did().0,
        vec.open.estimated_chunk_count,
        &caveats_jcs,
    );

    let role_state = authorizing_role_state();
    let mut registry = OutletRegistry::new();
    register_outlet(
        &mut registry,
        &role_state,
        registration(&outlet_id, kind, &invoker_did()),
        &invoker_did().0,
    )
    .expect("register conformance outlet");

    let handle_ctx = ContextHandle::new(ctx_id(), scp_protocol::context::ContextParams::default());
    handle_ctx
        .transition_to(&ContextState::Active)
        .expect("context active");

    // Timing: short credit-stall for the credit_stall vector so its
    // framework terminal fires fast; short cancel-ack so the cancellation
    // vector's forced terminal fires fast. Large elsewhere so a well-credited
    // stream never spuriously stalls.
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

    // Build the executor script from the vector's declared transcript.
    let (emit, terminal) = build_script(vec);
    let executor = Arc::new(ScriptedExecutor { emit, terminal });

    let params = OpenStreamParams {
        identity: StreamIdentity {
            context_id: ctx_id(),
            outlet_id: outlet_id.clone(),
            stream_epoch: STREAM_EPOCH,
            caveats_binding,
        },
        caps: AdmissionCaps {
            per_invoker: 64,
            per_origin_invoker: 64,
            per_outlet: 64,
        },
        invoker_did: invoker_did().0,
        origin_invoker_did: invoker_did().0,
        cost_per_chunk: Amount::new(0),
        available_balance: Amount::new(0),
        reserved_escrow: Amount::new(0),
        declared_estimated_chunk_count: Some(vec.open.estimated_chunk_count),
        credit_window: vec.open.credit_window,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer: Arc::new(InProcessStreamSigner::new(key.clone())),
        stream_credit_stall_secs: credit_stall_secs,
        stream_cancel_ack_secs: cancel_ack_secs,
        stream_ucan_recheck_secs: 3_600,
        ucan_cid,
        request_id,
        revocation_checker: Arc::new(
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
        ),
        economic_policy_snapshot: None,
    };

    let admission = Arc::new(RwLock::new(StreamAdmissionTracker::new()));
    let origin_admission = Arc::new(RwLock::new(OriginAdmissionTracker::new()));
    let pump_semaphore = Arc::new(tokio::sync::Semaphore::new(4096));

    let mut handle = open_stream_session(
        &handle_ctx,
        &registry,
        &role_state,
        &outlet_id,
        vec.open.input.clone(),
        &invoker_did(),
        Some(vec.open.timeout_ms),
        executor,
        None,
        None,
        None,
        None,
        params,
        admission,
        origin_admission,
        pump_semaphore,
        None,
        None,
    )
    .await
    .expect("open_stream_session accepts a well-formed open");

    let mut rx = handle.receiver().expect("receiver");
    let summary_rx = handle.close_summary().expect("close summary");

    // Apply any credit grant scheduled before the first chunk (after == -1).
    for credit in vec.credits.iter().filter(|c| c.after_chunk_index < 0) {
        apply_grant(
            &handle,
            &key,
            &ctx_id(),
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
        let chunk = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("chunk within 10s");
        let Some(chunk) = chunk else {
            // Channel closed without a terminal chunk — abnormal.
            break;
        };
        let terminal = chunk.payload.is_terminal();
        let idx = i64::try_from(chunks.len()).expect("chunk index fits i64");
        chunks.push(chunk);

        // Apply any grant scheduled after this chunk index.
        for credit in vec.credits.iter().filter(|c| c.after_chunk_index == idx) {
            apply_grant(
                &handle,
                &key,
                &ctx_id(),
                &outlet_id,
                &request_id,
                &caveats_binding,
                credit,
            );
        }

        if terminal {
            break;
        }

        // Signed cancel after the configured chunk index.
        if let Some(at) = cancel_at
            && !cancel_sent
            && idx == at
        {
            let cancel_signer = InProcessStreamSigner::new(key.clone());
            let cancel_identity = CancelIdentity {
                context_id: ctx_id(),
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
async fn non_streaming_replays_data_then_framework_end() {
    run_transcript_vector("non_streaming").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_chunk_replays_data_progress_then_end() {
    run_transcript_vector("multi_chunk").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_terminal_maps_handler_fault_to_6130() {
    run_transcript_vector("error_terminal").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_recoverable_forwards_nonterminal_error_then_ends_ok() {
    run_transcript_vector("error_recoverable").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credit_stall_stalls_to_6133() {
    run_transcript_vector("credit_stall").await;
}

/// Cancellation: the transcript is timing-dependent (the forced terminal races
/// the executor's remaining chunks), so we assert the §5.4.5 Cancelled signal
/// (a recorded cancel-ack seq + a terminal chunk) and that delivered Data is a
/// prefix of the vector's declared Data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_records_cancel_ack_and_reaches_terminal() {
    let file = load_vectors();
    let vec = vector(&file, "cancellation");
    let outcome = drive_vector(vec).await;
    assert_terminal_status(vec, &outcome);
    assert_data_prefix(vec, &outcome);
}
