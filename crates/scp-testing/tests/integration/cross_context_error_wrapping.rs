//! SCP-OUT-029 — cross-context bridge wraps terminal errors with the typed
//! [`OutletError`] envelope, prepending a [`ContextHop`] for the boundary
//! the error just crossed and applying §5.4.4 oracle-collapse and HMAC
//! pseudonymization rules.
//!
//! Production cross-context return paths (`run_cross_context_bridge` in
//! `scp-runtime::context::manager::outlets`) emit terminal `Error` chunks
//! whose `message` field carries the typed envelope as hex-encoded
//! `MessagePack`. These integration tests verify that:
//!
//!  1. Target-emitted terminal Error chunks are re-wrapped through
//!     `wrap_cross_context_error` so the source observer sees a
//!     `source_chain` with the target-boundary hop.
//!  2. A source observer without an established `hop_salt` for the target
//!     (i.e., not a member of the target context, no per-pair salt
//!     configured) sees the target's `context_id` HMAC-pseudonymized to
//!     a 64-char hex string of opaque bytes — never the raw `ContextId`.
//!  3. A source observer lacking both `outlet_query:{id}` and
//!     `outlet_call:{id}` stems on the inner outlet sees the §5.4.4
//!     round-3 oracle-collapse target (`SCP-TOOL-6110` /
//!     `authorization.denied`) regardless of the underlying executor
//!     error code (output schema-violation, transport fault,
//!     authorization, etc.).
//!
//! These exercise the production wiring that closes the audit gap
//! flagged on SCP-OUT-029: prior to this story the `synth_*` helpers
//! emitted free-form code+message strings without a `ContextHop` chain
//! and without applying the §5.4.4 wire-form rules.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use scp_core::context::manager::{
    BridgeHopSaltClosure, BridgeMemberClosure, CrossContextInvokeInputs, OuterCallerStems,
    invoke_outlet_cross_context,
};
use scp_protocol::context::outlets::OutletKind;
use scp_protocol::context::outlets::error_codes::{
    CODE_AUTHORIZATION_DENIED, CODE_OUTPUT_VIOLATION, CODE_TRANSPORT_FAULT,
    SLUG_AUTHORIZATION_DENIED, SLUG_OUTPUT_SCHEMA_VIOLATION,
};
use scp_protocol::context::outlets::errors::{MAX_TRAIL_PAD_DEPTH, OutletError};
use scp_protocol::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, RequestId, sign_chunk,
};

const SOURCE_CTX: &str = "ctx-source";
const TARGET_CTX: &str = "ctx-target";
const OUTLET_ID: &str = "outlet-bridge";

fn target_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

fn source_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[4u8; 32])
}

fn output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": { "n": { "type": "integer" } },
        "required": ["n"]
    })
}

/// Builds an `OuterCallerStems` for the given (query, call) pair.
const fn stems(holds_query: bool, holds_call: bool) -> OuterCallerStems {
    OuterCallerStems {
        holds_query,
        holds_call,
    }
}

/// Bridge inputs configured for the source observer's view: takes the
/// observer's membership predicate, hop-salt lookup, stems, and outlet
/// kind so each test can vary the §5.4.4 wire-form inputs independently.
fn inputs_for(
    member_of: BridgeMemberClosure,
    hop_salts: BridgeHopSaltClosure,
    outer_stems: OuterCallerStems,
    inner_kind: Option<OutletKind>,
) -> CrossContextInvokeInputs {
    CrossContextInvokeInputs {
        source_context_id: SOURCE_CTX.to_owned(),
        target_context_id: TARGET_CTX.to_owned(),
        outlet_id: OUTLET_ID.to_owned(),
        source_caveats_binding: [0xAB; 32],
        target_caveats_binding: [0xCD; 32],
        chain_depth: 2,
        stream_epoch: 1,
        source_operator_key: Arc::new(source_signing_key()),
        aggregate_schema: None,
        output_schema: output_schema(),
        invoker_did: "did:dht:z6MkInvokerOUT029".to_owned(),
        source_member_of_context: member_of,
        source_hop_salts: hop_salts,
        source_outer_caller_stems: outer_stems,
        inner_outlet_kind: inner_kind,
        max_padded_trail_depth: MAX_TRAIL_PAD_DEPTH,
    }
}

/// Builds a target-side terminal Error chunk with a given outlet-error
/// code, signed by the target operator. Mirrors the wire shape an
/// executor would emit when its own outlet returned a §5.4.4 error.
fn build_target_terminal_error(
    request_id: &RequestId,
    sequence: u64,
    code: &str,
    message: &str,
) -> OutletStreamChunk {
    let key = target_signing_key();
    let payload = ChunkPayload::Error {
        code: code.to_owned(),
        message: message.to_owned(),
        terminal: true,
    };
    let sig = sign_chunk(
        &key,
        TARGET_CTX,
        OUTLET_ID,
        request_id,
        sequence,
        &[0xCD; 32],
        &payload,
    )
    .unwrap();
    OutletStreamChunk {
        request_id: *request_id,
        sequence,
        payload,
        sig,
    }
}

/// Decodes a `ChunkPayload::Error.message` produced by
/// `synth_*_chunk` / `wrap_terminal_error_envelope`. The wire form is
/// hex-encoded canonical `MessagePack` of the typed [`OutletError`]
/// envelope.
fn decode_envelope_from_chunk(chunk: &OutletStreamChunk) -> OutletError {
    let ChunkPayload::Error { message, .. } = &chunk.payload else {
        panic!("expected terminal Error chunk, got {:?}", chunk.payload);
    };
    let bytes = hex::decode(message).expect("envelope hex-encoded");
    rmp_serde::from_slice(&bytes).expect("envelope MessagePack-encoded")
}

/// Drives a single cross-context invocation: feeds the target chunks
/// through the bridge, drains the receiver, and returns the
/// re-issued source-context chunk sequence.
async fn run_bridge(
    inputs: CrossContextInvokeInputs,
    target_chunks: Vec<OutletStreamChunk>,
) -> Vec<OutletStreamChunk> {
    let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(64);
    let (_request_id, mut bridge) = invoke_outlet_cross_context(inputs, erx);

    let exec_task = tokio::spawn(async move {
        for chunk in target_chunks {
            etx.send(chunk).await.unwrap();
        }
        drop(etx);
    });

    let mut received: Vec<OutletStreamChunk> = Vec::new();
    while let Some(c) = bridge.receiver.recv().await {
        received.push(c);
    }
    exec_task.await.unwrap();
    received
}

// ---------------------------------------------------------------------------
// Test 1 — terminal Error from target carries a wrapped envelope with a
// ContextHop chain referencing the target boundary.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn target_terminal_error_carries_context_hop_chain() {
    // Source observer holds both stems on the inner outlet and is a
    // member of both source and target — full visibility, no
    // collapse, no pseudonymization. The wrap still records the
    // target boundary hop.
    let member_of: BridgeMemberClosure = Arc::new(|c: &str| matches!(c, SOURCE_CTX | TARGET_CTX));
    let hop_salts: BridgeHopSaltClosure = Arc::new(|_: &str| Some([0xEE; 32]));
    let inputs = inputs_for(
        member_of,
        hop_salts,
        stems(true, true),
        Some(OutletKind::Action),
    );

    // Synthetic 16-byte request id; bridge generates its own re-issued
    // request id under the source operator regardless.
    let target_request: RequestId = [0xA1u8; 16];
    let target_terminal = build_target_terminal_error(
        &target_request,
        0,
        CODE_OUTPUT_VIOLATION,
        "raw target message",
    );
    let received = run_bridge(inputs, vec![target_terminal]).await;
    assert_eq!(received.len(), 1, "single re-issued terminal chunk");
    let chunk = &received[0];

    // Wire-level: chunk is terminal Error with the §5.4.4 code.
    match &chunk.payload {
        ChunkPayload::Error {
            code,
            terminal,
            message,
        } => {
            assert_eq!(code, CODE_OUTPUT_VIOLATION);
            assert!(*terminal);
            assert!(!message.is_empty(), "message carries hex envelope");
            assert!(
                message.chars().all(|c| c.is_ascii_hexdigit()),
                "message must be hex-encoded MessagePack"
            );
        }
        other => panic!("expected terminal Error, got {other:?}"),
    }

    // Decode the typed envelope and assert structural properties.
    let envelope = decode_envelope_from_chunk(chunk);
    assert_eq!(
        envelope.code, CODE_OUTPUT_VIOLATION,
        "envelope code preserved (full visibility, has stems)"
    );
    assert_eq!(envelope.slug, SLUG_OUTPUT_SCHEMA_VIOLATION);
    assert!(
        !envelope.source_chain.is_empty(),
        "source_chain has at least the target hop"
    );
    let outer_hop = &envelope.source_chain[0];
    assert_eq!(
        outer_hop.context_id, TARGET_CTX,
        "outer hop is the target context (raw — observer is a member)"
    );
    assert_eq!(outer_hop.hop_index, 1, "first wrap hop_index = 1");
    assert_eq!(
        outer_hop.wrapped_code, CODE_OUTPUT_VIOLATION,
        "wrapped_code preserves the inner code at full visibility"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — observer without hop_salt for target sees pseudonymized
// context_id (HMAC opacity, 64 hex chars).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn observer_without_hop_salt_sees_pseudonymized_target_hop() {
    // Observer is a member of source only, NOT target. With no
    // hop_salt configured for target the wrap function uses an
    // all-zero salt (32-byte HMAC pseudonym preserved on-wire).
    let member_of: BridgeMemberClosure = Arc::new(|c: &str| c == SOURCE_CTX);
    // Return None for target so wrap falls back to all-zero salt.
    let hop_salts: BridgeHopSaltClosure = Arc::new(|_: &str| None);
    // Hold both stems so collapse does not fire — isolate the
    // pseudonymization assertion from the collapse assertion.
    let inputs = inputs_for(
        member_of,
        hop_salts,
        stems(true, true),
        Some(OutletKind::Action),
    );

    // Synthetic 16-byte request id; bridge generates its own re-issued
    // request id under the source operator regardless.
    let target_request: RequestId = [0xA1u8; 16];
    let target_terminal = build_target_terminal_error(
        &target_request,
        0,
        CODE_OUTPUT_VIOLATION,
        "schema-violation",
    );
    let received = run_bridge(inputs, vec![target_terminal]).await;
    assert_eq!(received.len(), 1);
    let chunk = &received[0];
    let envelope = decode_envelope_from_chunk(chunk);

    // The target-boundary hop's context_id MUST NOT be the raw
    // "ctx-target" string — it must be the 32-byte HMAC pseudonym
    // hex-encoded as a 64-char string.
    assert!(
        !envelope.source_chain.is_empty(),
        "padded chain has at least one entry"
    );
    let target_hop = envelope
        .source_chain
        .iter()
        .find(|h| h.hop_index == 1)
        .expect("hop_index=1 (target boundary) present");
    assert_ne!(
        target_hop.context_id, TARGET_CTX,
        "non-member observer must NOT see raw target context_id"
    );
    assert_eq!(
        target_hop.context_id.len(),
        64,
        "pseudonym is 32-byte HMAC hex-encoded (64 chars)"
    );
    assert!(
        target_hop.context_id.chars().all(|c| c.is_ascii_hexdigit()),
        "pseudonym is hex-encoded"
    );

    // Trail-padding: any opaque hop forces source_chain length to
    // max_padded_trail_depth. The target hop is opaque (no
    // membership) so the full chain is padded.
    assert_eq!(
        envelope.source_chain.len(),
        usize::from(MAX_TRAIL_PAD_DEPTH),
        "trail-padded to MAX_TRAIL_PAD_DEPTH when any hop opaque"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — observer without query/call stems sees authorization.denied
// regardless of the executor's underlying error code (oracle collapse).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn observer_without_stems_sees_authorization_denied_collapse() {
    // Observer holds NEITHER outlet_query nor outlet_call on the
    // inner outlet. Per §5.4.4 round-3, the outermost code/slug
    // collapses to SCP-TOOL-6110 / authorization.denied so an
    // attacker cannot distinguish the underlying cause.
    let member_of: BridgeMemberClosure = Arc::new(|c: &str| c == SOURCE_CTX);
    let hop_salts: BridgeHopSaltClosure = Arc::new(|_: &str| Some([0xFF; 32]));

    // Run the same bridge under three different underlying causes
    // and assert all three collapse to the same outermost wire code.
    for (raw_code, label) in [
        (CODE_OUTPUT_VIOLATION, "output-violation"),
        (CODE_TRANSPORT_FAULT, "transport-fault"),
        (CODE_AUTHORIZATION_DENIED, "authorization-already-denied"),
    ] {
        let inputs = inputs_for(
            Arc::clone(&member_of),
            Arc::clone(&hop_salts),
            stems(false, false),
            // Kind unknown — drives the kind-mismatch / not-found
            // collapse trigger when caller has no stem.
            None,
        );

        // Synthetic 16-byte request id; bridge generates its own re-issued
        // request id under the source operator regardless.
        let target_request: RequestId = [0xA1u8; 16];
        let target_terminal = build_target_terminal_error(&target_request, 0, raw_code, label);
        let received = run_bridge(inputs, vec![target_terminal]).await;
        assert_eq!(received.len(), 1, "single terminal chunk for {label}");

        let chunk = &received[0];
        match &chunk.payload {
            ChunkPayload::Error {
                code,
                terminal,
                message,
            } => {
                assert!(*terminal, "terminal under {label}");
                assert_eq!(
                    code, CODE_AUTHORIZATION_DENIED,
                    "wire code collapses for {label}"
                );
                assert!(!message.is_empty(), "envelope present for {label}");
            }
            other => panic!("expected Error for {label}, got {other:?}"),
        }

        let envelope = decode_envelope_from_chunk(chunk);
        assert_eq!(
            envelope.code, CODE_AUTHORIZATION_DENIED,
            "envelope code collapses for {label}"
        );
        assert_eq!(
            envelope.slug, SLUG_AUTHORIZATION_DENIED,
            "envelope slug collapses for {label}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 4 — mid-stream bridge failure (executor disconnect) carries the
// wrapped transport-fault envelope through the same path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mid_stream_bridge_failure_wraps_envelope_with_target_hop() {
    let member_of: BridgeMemberClosure = Arc::new(|c: &str| matches!(c, SOURCE_CTX | TARGET_CTX));
    let hop_salts: BridgeHopSaltClosure = Arc::new(|_: &str| Some([0x77; 32]));
    let inputs = inputs_for(
        member_of,
        hop_salts,
        stems(true, true),
        Some(OutletKind::Action),
    );

    // No chunks at all — the bridge will synthesize a terminal
    // bridge-failure on executor disconnect.
    let received = run_bridge(inputs, Vec::new()).await;
    assert_eq!(received.len(), 1, "synthesized terminal bridge-failure");
    let chunk = &received[0];
    match &chunk.payload {
        ChunkPayload::Error {
            code,
            terminal,
            message,
        } => {
            assert!(*terminal);
            assert_eq!(code, CODE_TRANSPORT_FAULT);
            assert!(!message.is_empty(), "envelope hex present");
        }
        other => panic!("expected terminal Error, got {other:?}"),
    }

    let envelope = decode_envelope_from_chunk(chunk);
    assert_eq!(envelope.code, CODE_TRANSPORT_FAULT);
    assert!(!envelope.source_chain.is_empty(), "hop chain present");
    let outer_hop = envelope
        .source_chain
        .iter()
        .find(|h| h.hop_index == 1)
        .expect("target boundary hop present");
    assert_eq!(outer_hop.context_id, TARGET_CTX);
}
