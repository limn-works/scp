//! Cross-target KAT guard for the SCP-OUT-048 unit-B TS-wasm invoker fixture.
//!
//! The TS-wasm browser-invoker streaming test
//! (`bindings/typescript-wasm/tests/outlets-streaming-invoker.test.ts`) drives a
//! mocked node coordinator that forwards operator-signed §5.4.5 chunks, and the
//! browser verifies them on-device via `outletStreamVerifyChunkSignature`. Those
//! chunks are signed by the §25.2 reference operator key (RFC 8032 §7.1 Test
//! Vector 1) in Rust and committed as a fixture — a magic-byte fixture would
//! drift silently from the reference implementation.
//!
//! This guard re-derives every fixture byte from the shared `scp-protocol`
//! §5.4.5 primitives and the §25.2 reference key and asserts the committed
//! fixture matches. It is the §25.2 reference-key KAT-alignment pattern applied
//! to the browser invoker path: the same pattern
//! `outlet_stream_vectors_wire_integrity_across_all_seven` uses in the crate's
//! own unit tests, extended to pin the cross-language fixture the TS test reads.
//! If the §5.4.5 wire/preimage ever changes, this fails loudly so the fixture is
//! regenerated in lockstep.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use scp_protocol::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, compute_caveats_binding, sign_chunk,
};
use scp_protocol::context::params::MemoryScope;
use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
use scp_protocol::trust::caveats::InvocationCaveats;

const FIXTURE: &str =
    include_str!("../../../bindings/typescript-wasm/tests/fixtures/outlet-stream-invoker-kat.json");

/// §25.2 reference operator seed (RFC 8032 §7.1 Test Vector 1).
const OPERATOR_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
/// A distinct invoker outlet-signing seed (RFC 8032 §7.1 Test Vector 2).
const INVOKER_SEED: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
const WRONG_SEED: [u8; 32] = [0x11u8; 32];

const CTX: &str = "ctx-scp-out-048-invoker";
const OUTLET: &str = "echo-stream";
const REQUEST_ID: [u8; 16] = [0x2a; 16];
const UCAN_CID: &str = "bafyreiout048invokerfixtureucancidaaaaaaaaaaaaaaaaaa";
const INVOKER_DID: &str = "did:key:z6MkInvokerOUT048FixtureKeyAAAAAAAAAAAAA";
const ESTIMATED_CHUNK_COUNT: u32 = 11;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn sample_provenance() -> DataProvenance {
    DataProvenance {
        source_context: "scp-out-048-source".to_owned(),
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

#[test]
#[allow(clippy::too_many_lines)] // one linear fixture-vs-reference KAT, read top-to-bottom
fn ts_invoker_fixture_matches_reference_implementation() {
    let doc: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture JSON parses");

    let operator = SigningKey::from_bytes(&OPERATOR_SEED);
    let invoker = SigningKey::from_bytes(&INVOKER_SEED);
    let wrong = SigningKey::from_bytes(&WRONG_SEED);

    // Scalars / keys.
    assert_eq!(doc["contextId"], CTX);
    assert_eq!(doc["outletId"], OUTLET);
    assert_eq!(doc["requestIdHex"], hex(&REQUEST_ID));
    assert_eq!(doc["ucanCid"], UCAN_CID);
    assert_eq!(doc["invokerDid"], INVOKER_DID);
    assert_eq!(doc["estimatedChunkCount"], ESTIMATED_CHUNK_COUNT);
    assert_eq!(doc["operatorSeedHex"], hex(&OPERATOR_SEED));
    assert_eq!(
        doc["operatorPkHex"],
        hex(operator.verifying_key().as_bytes())
    );
    assert_eq!(
        doc["wrongOperatorPkHex"],
        hex(wrong.verifying_key().as_bytes())
    );
    assert_eq!(doc["invokerSeedHex"], hex(&INVOKER_SEED));
    assert_eq!(doc["invokerPkHex"], hex(invoker.verifying_key().as_bytes()));

    // Caveats JCS + binding (a cross-SDK KAT — the TS `outletStreamComputeCaveatsBinding`
    // over these same inputs must reproduce `caveatsBindingHex`).
    let caveats_jcs = InvocationCaveats::empty()
        .to_canonical_json_bytes()
        .expect("empty caveats JCS");
    assert_eq!(doc["caveatsJcsHex"], hex(&caveats_jcs));
    let binding = compute_caveats_binding(
        UCAN_CID.as_bytes(),
        &REQUEST_ID,
        INVOKER_DID,
        ESTIMATED_CHUNK_COUNT,
        &caveats_jcs,
    );
    assert_eq!(doc["caveatsBindingHex"], hex(&binding));

    // The 11 operator-signed chunks (10 Data + terminal End), byte-for-byte.
    let chunks = doc["chunks"].as_array().expect("chunks is an array");
    assert_eq!(chunks.len(), 11, "10 Data chunks + one terminal End");
    for sequence in 0u64..10 {
        let payload = ChunkPayload::Data {
            value: serde_json::json!(sequence),
        };
        let sig = sign_chunk(
            &operator,
            CTX,
            OUTLET,
            &REQUEST_ID,
            sequence,
            &binding,
            &payload,
        )
        .expect("sign data chunk");
        let chunk = OutletStreamChunk {
            request_id: REQUEST_ID,
            sequence,
            payload,
            sig,
        };
        let wire = serde_json::to_vec(&chunk).expect("serialize chunk");
        let entry = &chunks[usize::try_from(sequence).unwrap()];
        assert_eq!(entry["sequence"], sequence);
        assert_eq!(
            entry["wireHex"],
            hex(&wire),
            "chunk {sequence} wire drifted"
        );
    }
    let end_payload = ChunkPayload::End {
        aggregate: serde_json::json!(9),
        provenance: sample_provenance(),
        execution_time_ms: 100,
    };
    let end_sig = sign_chunk(
        &operator,
        CTX,
        OUTLET,
        &REQUEST_ID,
        10,
        &binding,
        &end_payload,
    )
    .expect("sign end chunk");
    let end_chunk = OutletStreamChunk {
        request_id: REQUEST_ID,
        sequence: 10,
        payload: end_payload,
        sig: end_sig,
    };
    let end_wire = serde_json::to_vec(&end_chunk).expect("serialize end");
    assert_eq!(chunks[10]["sequence"], 10u64);
    assert_eq!(
        chunks[10]["wireHex"],
        hex(&end_wire),
        "End chunk wire drifted"
    );

    // The wrong-key chunk (same content, signed by WRONG_SEED) the invoker rejects.
    let wk_payload = ChunkPayload::Data {
        value: serde_json::json!(0u64),
    };
    let wk_sig = sign_chunk(&wrong, CTX, OUTLET, &REQUEST_ID, 0, &binding, &wk_payload)
        .expect("sign wrong chunk");
    let wk_chunk = OutletStreamChunk {
        request_id: REQUEST_ID,
        sequence: 0,
        payload: wk_payload,
        sig: wk_sig,
    };
    let wk_wire = serde_json::to_vec(&wk_chunk).expect("serialize wrong chunk");
    assert_eq!(doc["wrongKeyChunkWireHex"], hex(&wk_wire));
}
