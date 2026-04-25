//! Outlet registration conformance vectors (SCP-OUT-009).
//!
//! Generates and validates the canonical V2 test vectors at
//! `tests/conformance/vectors/outlet_registration_v2.json`.
//!
//! The file documents 12 known-input / known-output cases for the
//! `SCP-OUTLET-REGISTRATION-V2:` canonical hash construction (spec §5.4.1,
//! §25 test vectors, ADR-049). Each entry is sign-verifiable against the
//! reference Ed25519 keypair (RFC 8032 §7.1 Test Vector 1).
//!
//! All four FFI bridges (PyO3, NAPI, UniFFI Swift, UniFFI Kotlin) plus the
//! WASM bridge call into the same `scp_protocol::context::outlets::registry::
//! compute_outlet_registration_canonical_bytes` reference, so this Rust-core
//! validation transitively certifies every bridge that funnels through
//! `register_outlet`.
//!
//! # Negative test
//!
//! A negative-corpus entry confirms the pre-rename `SCP-TOOL-REGISTRATION-V1:`
//! preimage does NOT match the current code-path output. Pre-migration
//! signatures are explicitly invalid post-rename per ADR-049's hard-break
//! policy.
//!
//! # Generation
//!
//! Run `cargo test -p scp-testing --test conformance \
//!   conf_outlet_registration_v2_regen -- --ignored --nocapture` to regenerate
//! the JSON file (writes to disk). The default `cargo test` run only validates
//! the existing JSON against the Rust core.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use scp_core::context::outlets::OutletKind;
use scp_core::context::outlets::registry::{
    OutletCost, OutletRegistration, OutletSchema, OutletTestVector,
    compute_outlet_registration_canonical_bytes, verify_outlet_registration_signature,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// RFC 8032 §7.1 Test Vector 1 seed — primary signing key.
pub const REF_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Operator DID used across every vector (§25.2 test-key DID convention).
pub const REF_OPERATOR_DID: &str = "did:dht:z6MkOperator";

/// Reference timestamp pinned across vectors for determinism (§25 convention).
pub const REF_TIMESTAMP: u64 = 1_700_000_000;

/// On-disk JSON schema for a single conformance entry.
///
/// The wire shape matches the AC contract on SCP-OUT-009: `name`, `input`,
/// `expected_preimage` (raw byte sequence pre-SHA-256, hex), `expected_signature`
/// (Ed25519 signature, hex), `operator_did`, `operator_public_key` (hex). We add
/// `expected_canonical_hash` (the output of
/// `compute_outlet_registration_canonical_bytes`, equal to SHA-256(preimage))
/// and a free-text `notes` field for spec cross-references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletRegistrationVector {
    pub name: String,
    pub notes: String,
    pub input: Value,
    pub expected_preimage: String,
    pub expected_canonical_hash: String,
    pub expected_signature: String,
    pub operator_did: String,
    pub operator_public_key: String,
}

/// On-disk JSON schema for a V1-rejection corpus entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V1RejectionEntry {
    pub name: String,
    pub notes: String,
    pub v1_preimage: String,
    pub v1_canonical_hash: String,
    pub v2_canonical_hash: String,
}

/// Top-level on-disk JSON schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletRegistrationVectorFile {
    pub version: String,
    pub spec_section: String,
    pub adr: String,
    pub story: String,
    pub domain_separator: String,
    pub rejected_predecessor_separator: String,
    pub vectors: Vec<OutletRegistrationVector>,
    pub v1_rejection_corpus: Vec<V1RejectionEntry>,
}

/// Workspace-root path to the canonical V2 vectors JSON.
#[must_use]
pub fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/scp-testing → workspace root: pop twice.
    p.pop();
    p.pop();
    p.push("tests");
    p.push("conformance");
    p.push("vectors");
    p.push("outlet_registration_v2.json");
    p
}

/// Returns the reference signing key (RFC 8032 §7.1 Test Vector 1).
#[must_use]
pub fn reference_signing_key() -> SigningKey {
    SigningKey::from_bytes(&REF_SEED)
}

/// Build the 12 reference registrations.
///
/// Each registration exercises a distinct shape per SCP-OUT-009 ACs:
/// 1. minimal-Query (no cost),
/// 2. minimal-Action (no cost),
/// 3. Query-cost-none,
/// 4. Query-cost-zero,
/// 5. Action-cost-positive,
/// 6. registration-with-aggregate-output-schema,
/// 7. registration-with-max-size-schema (~64 KiB serialized),
/// 8. registration-with-100-test-vectors,
/// 9. registration-with-llm-backed-impl-hash,
/// 10. registration-with-remote-service-impl-hash,
/// 11. registration-targeting-multi-caveat-ucan-invocation,
/// 12. registration-targeting-cross-context-invocation.
///
/// As of SCP-OUT-011 the `OutletRegistration` struct carries an explicit
/// `kind: OutletKind` field; vectors 1, 3, and 4 declare `OutletKind::Query`
/// and the remaining nine declare `OutletKind::Action` (matching their
/// descriptions). The §5.4.1 `kind_byte` (0x00 Query, 0x01 Action) is now
/// driven by the field rather than the SCP-OUT-002 placeholder.
///
/// The `aggregate_schema` and `message_catalog` fields specified in §5.4.1
/// still land with SCP-OUT-013 / SCP-OUT-024 / SCP-OUT-015. Their semantic
/// distinctions remain encoded in `description`, `name`, and `outlet_id`
/// here so independent implementers can regenerate against the in-tree
/// preimage byte-for-byte.
#[must_use]
pub fn reference_registrations() -> Vec<(String, String, OutletRegistration)> {
    let mut out = Vec::with_capacity(12);

    // 1. Minimal Query — read-only outlet, no cost.
    out.push((
        "minimal-query".to_owned(),
        "Read-only outlet (Query semantics). cost = None. Smallest valid registration.".to_owned(),
        OutletRegistration {
            outlet_id: "minimal-query-outlet".to_owned(),
            kind: OutletKind::Query,
            name: "Minimal Query".to_owned(),
            description: "Smallest valid Query outlet — no cost, two-field schema.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}}),
                output_schema: json!({"type": "object", "properties": {"r": {"type": "string"}}}),
            },
            implementation_hash: sha256_label(b"minimal-query-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 2. Minimal Action — mutating outlet, no cost.
    out.push((
        "minimal-action".to_owned(),
        "Mutating outlet (Action semantics, the fail-safe default). cost = None.".to_owned(),
        OutletRegistration {
            outlet_id: "minimal-action-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Minimal Action".to_owned(),
            description: "Smallest valid Action outlet — no cost, two-field schema.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}}),
                output_schema: json!({"type": "object", "properties": {"r": {"type": "string"}}}),
            },
            implementation_hash: sha256_label(b"minimal-action-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 3. Query with cost = None.
    out.push((
        "query-cost-none".to_owned(),
        "Query outlet with explicit cost=None — exercises the absent-cost preimage branch (0x00 sentinel).".to_owned(),
        OutletRegistration {
            outlet_id: "query-cost-none-outlet".to_owned(),
            kind: OutletKind::Query,
            name: "Query Without Cost".to_owned(),
            description: "Query outlet, cost field omitted (None). Free read-only access.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}, "k": {"type": "string"}}}),
                output_schema: json!({"type": "object", "properties": {"v": {"type": "string"}, "meta": {"type": "object"}}}),
            },
            implementation_hash: sha256_label(b"query-cost-none-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 4. Query with cost.amount = 0.
    out.push((
        "query-cost-zero".to_owned(),
        "Query outlet with explicit OutletCost { amount: 0 } — cost present but zero. §5.4.2 Query structural floor.".to_owned(),
        OutletRegistration {
            outlet_id: "query-cost-zero-outlet".to_owned(),
            kind: OutletKind::Query,
            name: "Query With Zero Cost".to_owned(),
            description: "Query outlet, cost present with amount=0. Demonstrates the cost-present-but-zero preimage path.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"key": {"type": "string"}, "tier": {"type": "string"}}}),
                output_schema: json!({"type": "object", "properties": {"value": {"type": "string"}}}),
            },
            implementation_hash: sha256_label(b"query-cost-zero-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: Some(OutletCost {
                amount: 0,
                currency: "USD".to_owned(),
                payee: REF_OPERATOR_DID.into(),
                cost_formula: None,
            }),
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 5. Action with cost > 0.
    out.push((
        "action-cost-positive".to_owned(),
        "Action outlet with cost.amount > 0. Exercises the cost-present-positive preimage path including currency + payee fields.".to_owned(),
        OutletRegistration {
            outlet_id: "action-cost-positive-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Action With Positive Cost".to_owned(),
            description: "Paid Action outlet — cost amount=12345 USD, payee = operator DID.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"target": {"type": "string"}, "amount": {"type": "integer"}}}),
                output_schema: json!({"type": "object", "properties": {"receipt": {"type": "string"}, "ts": {"type": "integer"}}}),
            },
            implementation_hash: sha256_label(b"action-cost-positive-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: Some(OutletCost {
                amount: 12_345,
                currency: "USD".to_owned(),
                payee: REF_OPERATOR_DID.into(),
                cost_formula: None,
            }),
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 6. Registration with aggregate output schema (using the existing
    //    output_schema slot — the dedicated `aggregate_schema` field lands
    //    with SCP-OUT-013/024). The output schema declares an `aggregate`
    //    sub-object describing the streamed-aggregate shape.
    out.push((
        "with-aggregate-schema".to_owned(),
        "Registration whose output_schema declares an `aggregate` sub-object describing the streamed-aggregate shape (§5.4.5). The dedicated `aggregate_schema` field is added by SCP-OUT-013/024; this vector uses the current output_schema slot as its forward-compatible representation.".to_owned(),
        OutletRegistration {
            outlet_id: "aggregate-schema-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Outlet With Aggregate Output Schema".to_owned(),
            description: "Outlet that streams chunks plus an aggregate value. The output_schema describes both per-chunk and aggregate shapes.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"prompt": {"type": "string"}, "model": {"type": "string"}}}),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "chunk": {"type": "object", "properties": {"text": {"type": "string"}}},
                        "aggregate": {"type": "object", "properties": {"full_text": {"type": "string"}, "tokens": {"type": "integer"}}}
                    }
                }),
            },
            implementation_hash: sha256_label(b"aggregate-schema-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 7. Registration with max-size schema (~64 KiB serialized).
    //    Spec §5.4.1 caps each schema at 64 KiB serialized. We build a schema
    //    that comes close to the boundary using a long property whose
    //    `description` field repeats a fixed string.
    let big_description: String = "a".repeat(60_000);
    out.push((
        "max-size-schema".to_owned(),
        "Registration with input schema that approaches the 64 KiB serialized cap (§5.4.1). Stress-tests preimage byte concatenation across large variable-length fields.".to_owned(),
        OutletRegistration {
            outlet_id: "max-size-schema-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Outlet With Maximum-Size Schema".to_owned(),
            description: "Stress vector for large schemas approaching the 64 KiB serialized boundary.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "field_a": {"type": "string", "description": big_description},
                        "field_b": {"type": "string"}
                    }
                }),
                output_schema: json!({"type": "object", "properties": {"r": {"type": "string"}}}),
            },
            implementation_hash: sha256_label(b"max-size-schema-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 8. Registration with 100 test vectors — exercises the test-vector
    //    iteration path in the canonical preimage construction.
    let mut hundred_vectors = Vec::with_capacity(100);
    for i in 0..100u32 {
        hundred_vectors.push(OutletTestVector {
            input: json!({"n": i}),
            expected_output: json!({"square": i * i}),
            description: format!("test vector {i}: square of {i}"),
        });
    }
    out.push((
        "with-100-test-vectors".to_owned(),
        "Registration carrying the §5.4.1 maximum-supported test vector count (100 entries). Exercises the test-vector iteration path in the canonical preimage construction.".to_owned(),
        OutletRegistration {
            outlet_id: "hundred-vectors-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Outlet With 100 Test Vectors".to_owned(),
            description: "Outlet carrying the maximum-supported number of registration test vectors.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"n": {"type": "integer"}, "tag": {"type": "string"}}}),
                output_schema: json!({"type": "object", "properties": {"square": {"type": "integer"}}}),
            },
            implementation_hash: sha256_label(b"hundred-vectors-implementation"),
            test_vectors: hundred_vectors,
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 9. LLM-backed impl hash — implementation_hash =
    //    SHA-256(model_id || ":" || system_prompt) per §5.4.1.
    let llm_impl_hash = {
        let mut h = Sha256::new();
        h.update(b"openai/gpt-4-turbo:");
        h.update(b"You are a helpful assistant.");
        h.finalize().into()
    };
    out.push((
        "llm-backed-impl-hash".to_owned(),
        "Registration whose implementation_hash is computed per §5.4.1 LLM-backed rule (SHA-256(model_id || \":\" || system_prompt_utf8)).".to_owned(),
        OutletRegistration {
            outlet_id: "llm-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "LLM-Backed Outlet".to_owned(),
            description: "Outlet backed by a hosted LLM (model gpt-4-turbo, fixed system prompt).".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"prompt": {"type": "string"}, "max_tokens": {"type": "integer"}}}),
                output_schema: json!({"type": "object", "properties": {"completion": {"type": "string"}}}),
            },
            implementation_hash: llm_impl_hash,
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: Some(OutletCost {
                amount: 100,
                currency: "USD".to_owned(),
                payee: REF_OPERATOR_DID.into(),
                cost_formula: Some("per_token_v1".to_owned()),
            }),
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 10. Remote-service impl hash — SHA-256 of OpenAPI spec (RFC 8785 JCS).
    let remote_impl_hash = sha256_label(b"openapi-spec-canonical-jcs-bytes");
    out.push((
        "remote-service-impl-hash".to_owned(),
        "Registration whose implementation_hash is computed per §5.4.1 remote-service rule (SHA-256(canonical_jcs(openapi_spec))). Includes a cost_formula for dynamic pricing (§19.4).".to_owned(),
        OutletRegistration {
            outlet_id: "remote-service-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Remote-Service Outlet".to_owned(),
            description: "Outlet backed by an external HTTP API; impl hash covers the canonical OpenAPI spec.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"endpoint": {"type": "string"}, "params": {"type": "object"}}}),
                output_schema: json!({"type": "object", "properties": {"status": {"type": "integer"}, "body": {"type": "object"}}}),
            },
            implementation_hash: remote_impl_hash,
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: Some(OutletCost {
                amount: 50,
                currency: "USD".to_owned(),
                payee: REF_OPERATOR_DID.into(),
                cost_formula: Some("per_call_dynamic_v1".to_owned()),
            }),
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 11. Multi-caveat UCAN invocation target — registration whose declared
    //     UCAN-shape supports multi-caveat invocation (encoded in description).
    out.push((
        "multi-caveat-invocation-target".to_owned(),
        "Registration intended for invocation under a UCAN with multiple caveats (§7.3.8 InvocationCaveats — amount_max_per_call, valid_until, allowed_adapters, etc.). The vector exercises a representative paid-Action shape against which a multi-caveat token would be minted.".to_owned(),
        OutletRegistration {
            outlet_id: "multi-caveat-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Multi-Caveat-Compatible Action".to_owned(),
            description: "Action outlet whose registered shape is compatible with multi-caveat UCAN invocation (amount_max_per_call + valid_until + allowed_adapters).".to_owned(),
            schema: OutletSchema {
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string"},
                        "amount": {"type": "integer"},
                        "memo": {"type": "string"}
                    },
                    "required": ["recipient", "amount"]
                }),
                output_schema: json!({"type": "object", "properties": {"tx_id": {"type": "string"}, "confirmed": {"type": "boolean"}}}),
            },
            implementation_hash: sha256_label(b"multi-caveat-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: Some(OutletCost {
                amount: 250,
                currency: "USD".to_owned(),
                payee: REF_OPERATOR_DID.into(),
                cost_formula: None,
            }),
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 12. Cross-context invocation target — registration intended to be
    //     reached via a cross-context interface (§6.2.0.1).
    out.push((
        "cross-context-invocation-target".to_owned(),
        "Registration intended for cross-context invocation through a §6.2.0.1 InterfaceOffer. Description signals the cross-context nature; preimage shape is the same as any Action outlet.".to_owned(),
        OutletRegistration {
            outlet_id: "cross-context-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Cross-Context Action".to_owned(),
            description: "Action outlet exposed via cross-context interface (§6.2.0.1). Operator DID accountable across the bridged peer context.".to_owned(),
            schema: OutletSchema {
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "source_context": {"type": "string"},
                        "target_resource": {"type": "string"},
                        "payload": {"type": "object"}
                    },
                    "required": ["source_context", "target_resource"]
                }),
                output_schema: json!({"type": "object", "properties": {"acknowledged": {"type": "boolean"}, "echo_id": {"type": "string"}}}),
            },
            implementation_hash: sha256_label(b"cross-context-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        },
    ));

    // 13. SCP-OUT-040 cross-SDK fixture (small catalog) — 4 catalog entries.
    //     Exercises the §5.4.1 V2 `catalog_hash` term across all bridges.
    let catalog_small = vec![
        scp_protocol::MessageTemplate::try_new("authorization.expired", "authorization expired")
            .expect("valid catalog template"),
        scp_protocol::MessageTemplate::try_new("authorization.revoked", "authorization revoked")
            .expect("valid catalog template"),
        scp_protocol::MessageTemplate::try_new("input.invalid-shape", "bad input shape")
            .expect("valid catalog template"),
        scp_protocol::MessageTemplate::try_new("output.too-large", "output exceeds size cap")
            .expect("valid catalog template"),
    ];
    out.push((
        "with-message-catalog-small".to_owned(),
        "Registration with a 4-entry message_catalog. Exercises the SCP-OUT-040 \
         `catalog_hash` term of the §5.4.1 V2 preimage. Each bridge must \
         round-trip the catalog with identical canonical MessagePack bytes \
         and therefore identical catalog_hash and signature."
            .to_owned(),
        OutletRegistration {
            outlet_id: "catalog-small-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Catalog Small".to_owned(),
            description: "Outlet with a 4-entry message catalog (SCP-OUT-040).".to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}}),
                output_schema: json!({"type": "object", "properties": {"r": {"type": "string"}}}),
            },
            implementation_hash: sha256_label(b"catalog-small-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: catalog_small,
        },
    ));

    // 14. SCP-OUT-040 cross-SDK fixture (large catalog + description) — 10
    //     catalog entries with realistic dotted-segment keys, non-empty
    //     description that will hash distinctly under `description_hash`.
    let catalog_large: Vec<scp_protocol::MessageTemplate> = (0..10)
        .map(|i| {
            scp_protocol::MessageTemplate::try_new(
                format!("execution.detail-{i:02}"),
                format!("execution detail {i}: synthetic operator-authored prose"),
            )
            .expect("valid catalog template")
        })
        .collect();
    out.push((
        "with-message-catalog-large-and-description".to_owned(),
        "Registration with a 10-entry message_catalog and a non-trivial \
         description. Exercises both the SCP-OUT-040 `catalog_hash` and \
         `description_hash` V2 preimage terms simultaneously. Bridges that \
         drop or reorder the catalog produce a different signature."
            .to_owned(),
        OutletRegistration {
            outlet_id: "catalog-large-outlet".to_owned(),
            kind: OutletKind::Action,
            name: "Catalog Large".to_owned(),
            description: "Outlet with a 10-entry message catalog and a longer \
             operator-authored description body. Both fields are committed to \
             the V2 signature via dedicated hash terms (SCP-OUT-040)."
                .to_owned(),
            schema: OutletSchema {
                input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}, "k": {"type": "string"}}}),
                output_schema: json!({"type": "object", "properties": {"v": {"type": "string"}}}),
            },
            implementation_hash: sha256_label(b"catalog-large-implementation"),
            test_vectors: Vec::new(),
            operator_did: REF_OPERATOR_DID.into(),
            cost: None,
            registered_at: REF_TIMESTAMP,
            signature: Vec::new(),
            message_catalog: catalog_large,
        },
    ));

    debug_assert_eq!(
        out.len(),
        14,
        "must produce 14 vectors (12 base + 2 SCP-OUT-040)"
    );
    out
}

/// Reconstruct the V2 canonical preimage byte sequence.
///
/// The byte sequence is the SHA-256 input that hashes to the canonical
/// V2 outlet-registration digest (§5.4.1). This function mirrors the
/// in-tree [`scp_protocol::context::outlets::hash::outlet_registration_v2_preimage`]
/// builder byte-for-byte so independent implementers can byte-compare an
/// alternative implementation against the published vectors.
///
/// SCP-OUT-040 (round-5 ADR-049) added `description_hash` and
/// `catalog_hash` terms to the preimage. The full §5.4.1 layout is:
///
/// ```text
/// "SCP-OUTLET-REGISTRATION-V2:"
///   || BE32(len(outlet_id)) || outlet_id
///   || kind_byte
///   || BE32(len(name)) || name
///   || description_hash
///   || BE32(len(operator_did)) || operator_did
///   || schema_hash
///   || implementation_hash
///   || test_vectors_hash
///   || cost_hash
///   || catalog_hash
///   || registered_at_be
/// ```
#[must_use]
pub fn compute_v2_preimage(reg: &OutletRegistration) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut buf = Vec::new();
    buf.extend_from_slice(b"SCP-OUTLET-REGISTRATION-V2:");

    let length_prefix = |buf: &mut Vec<u8>, bytes: &[u8]| {
        let n = u32::try_from(bytes.len()).expect("variable field exceeds u32");
        buf.extend_from_slice(&n.to_be_bytes());
        buf.extend_from_slice(bytes);
    };

    length_prefix(&mut buf, reg.outlet_id.as_bytes());
    buf.push(reg.kind.canonical_byte());
    length_prefix(&mut buf, reg.name.as_bytes());

    // description_hash (32 bytes)
    let description_hash: [u8; 32] = Sha256::digest(reg.description.as_bytes()).into();
    buf.extend_from_slice(&description_hash);

    length_prefix(&mut buf, reg.operator_did.as_bytes());

    // schema_hash (32 bytes) = SHA-256(MessagePack(schema))
    let schema_msgpack = rmp_serde::to_vec(&reg.schema).expect("MessagePack schema");
    let schema_hash: [u8; 32] = Sha256::digest(&schema_msgpack).into();
    buf.extend_from_slice(&schema_hash);

    buf.extend_from_slice(&reg.implementation_hash);

    // test_vectors_hash (32 bytes) = SHA-256(MessagePack(test_vectors))
    let tv_msgpack = rmp_serde::to_vec(&reg.test_vectors).expect("MessagePack test_vectors");
    let tv_hash: [u8; 32] = Sha256::digest(&tv_msgpack).into();
    buf.extend_from_slice(&tv_hash);

    // cost_hash (32 bytes) = SHA-256(MessagePack(cost)) | SHA-256(0x00) absent
    let cost_hash: [u8; 32] = reg.cost.as_ref().map_or_else(
        || Sha256::digest([0x00u8]).into(),
        |c| {
            let bytes = rmp_serde::to_vec(c).expect("MessagePack cost");
            Sha256::digest(&bytes).into()
        },
    );
    buf.extend_from_slice(&cost_hash);

    // catalog_hash (32 bytes) = SHA-256(MessagePack(message_catalog))
    let catalog_msgpack =
        rmp_serde::to_vec(&reg.message_catalog).expect("MessagePack message_catalog");
    let catalog_hash: [u8; 32] = Sha256::digest(&catalog_msgpack).into();
    buf.extend_from_slice(&catalog_hash);

    buf.extend_from_slice(&reg.registered_at.to_be_bytes());

    buf
}

/// Reconstruct the rejected V1 canonical preimage for the same logical input.
///
/// The V1 layout is the pre-rename construction (no
/// `SCP-OUTLET-REGISTRATION-V2:` separator, no `kind_byte`, no length
/// prefixes on every variable field — see ADR-049 §5.4.1 for the exact
/// pre-rename shape). Used to demonstrate that the V1 hash differs from the
/// V2 hash for the same input.
#[must_use]
pub fn compute_v1_rejected_preimage(reg: &OutletRegistration) -> Vec<u8> {
    let mut buf = Vec::new();
    // Pre-rename domain separator (deleted post-merge, preserved here only
    // so independent implementers can confirm it does NOT match the V2 hash).
    buf.extend_from_slice(b"SCP-TOOL-REGISTRATION-V1:");

    // Pre-rename construction lacked length prefixes on variable fields
    // (ADR-049 §5.4.1: "the unprefixed pre-rename concatenation" closed by
    // the V2 mandatory length-prefix rule).
    buf.extend_from_slice(reg.outlet_id.as_bytes());
    buf.extend_from_slice(reg.name.as_bytes());
    buf.extend_from_slice(reg.description.as_bytes());

    let input_json = scp_protocol::jcs::to_vec(&reg.schema.input_schema).unwrap_or_default();
    buf.extend_from_slice(&input_json);
    let output_json = scp_protocol::jcs::to_vec(&reg.schema.output_schema).unwrap_or_default();
    buf.extend_from_slice(&output_json);

    buf.extend_from_slice(&reg.implementation_hash);

    // No 4-byte test_vector count under V1; bare iteration.
    for tv in &reg.test_vectors {
        let input_bytes = scp_protocol::jcs::to_vec(&tv.input).unwrap_or_default();
        buf.extend_from_slice(&input_bytes);
        let output_bytes = scp_protocol::jcs::to_vec(&tv.expected_output).unwrap_or_default();
        buf.extend_from_slice(&output_bytes);
        buf.extend_from_slice(tv.description.as_bytes());
    }

    buf.extend_from_slice(reg.operator_did.as_bytes());
    buf.extend_from_slice(&reg.registered_at.to_be_bytes());

    if let Some(tc) = &reg.cost {
        buf.extend_from_slice(&tc.amount.to_be_bytes());
        buf.extend_from_slice(tc.currency.as_bytes());
        if let Some(f) = &tc.cost_formula {
            buf.extend_from_slice(f.as_bytes());
        }
        buf.extend_from_slice(tc.payee.as_bytes());
    }

    buf
}

/// Build the on-disk JSON file content from the reference registrations.
#[must_use]
pub fn build_vector_file() -> OutletRegistrationVectorFile {
    let signing_key = reference_signing_key();
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let mut entries = Vec::with_capacity(12);
    let mut v1_corpus = Vec::with_capacity(12);

    for (name, notes, mut reg) in reference_registrations() {
        // Step 1: compute manual preimage AND check it matches the in-tree hasher.
        let manual_preimage = compute_v2_preimage(&reg);
        let manual_hash: [u8; 32] = Sha256::digest(&manual_preimage).into();
        let core_hash = compute_outlet_registration_canonical_bytes(&reg);
        assert_eq!(
            core_hash.as_slice(),
            manual_hash,
            "manual preimage construction must equal in-tree compute_outlet_registration_canonical_bytes for vector '{name}'"
        );

        // Step 2: sign the canonical hash with the reference key.
        let signature = signing_key.sign(&manual_hash);
        reg.signature = signature.to_bytes().to_vec();

        // Step 3: round-trip verify with verify_outlet_registration_signature.
        verify_outlet_registration_signature(&reg, &signing_key.verifying_key())
            .unwrap_or_else(|e| panic!("vector '{name}' must round-trip verify: {e:?}"));

        // V1-rejection corpus entry: same logical input, V1 preimage, V1 hash.
        let v1_preimage = compute_v1_rejected_preimage(&reg);
        let v1_hash: [u8; 32] = Sha256::digest(&v1_preimage).into();
        v1_corpus.push(V1RejectionEntry {
            name: name.clone(),
            notes: format!(
                "V1 preimage for the same logical input as vector '{name}'. SHA-256 of this byte sequence MUST NOT equal the V2 canonical hash. Pre-rename domain — explicitly rejected post-ADR-049."
            ),
            v1_preimage: hex::encode(&v1_preimage),
            v1_canonical_hash: hex::encode(v1_hash),
            v2_canonical_hash: hex::encode(manual_hash),
        });

        // Build input payload as serde_json::Value (excluding signature, since
        // that's the output not the input).
        let input_payload = serialize_registration_for_json(&reg);

        entries.push(OutletRegistrationVector {
            name,
            notes,
            input: input_payload,
            expected_preimage: hex::encode(&manual_preimage),
            expected_canonical_hash: hex::encode(manual_hash),
            expected_signature: hex::encode(signature.to_bytes()),
            operator_did: REF_OPERATOR_DID.into(),
            operator_public_key: public_key_hex.clone(),
        });
    }

    OutletRegistrationVectorFile {
        version: "v2".to_owned(),
        spec_section: ".docs/specs/05-contexts.md §5.4.1; .docs/specs/25-test-vectors.md §25.19"
            .to_owned(),
        adr: ".docs/adrs/ADR-049-outlet-redesign.md".to_owned(),
        story: "SCP-OUT-009".to_owned(),
        domain_separator: "SCP-OUTLET-REGISTRATION-V2:".to_owned(),
        rejected_predecessor_separator: "SCP-TOOL-REGISTRATION-V1:".to_owned(),
        vectors: entries,
        v1_rejection_corpus: v1_corpus,
    }
}

/// Serialize an `OutletRegistration` into a JSON object that captures every
/// preimage-relevant field except the trailing `signature` (which is the
/// vector's expected output, not its input).
fn serialize_registration_for_json(reg: &OutletRegistration) -> Value {
    let cost_value = reg.cost.as_ref().map(|c| {
        let mut m = serde_json::Map::new();
        m.insert("amount".to_owned(), Value::from(c.amount));
        m.insert("currency".to_owned(), Value::from(c.currency.clone()));
        m.insert("payee".to_owned(), Value::from(c.payee.0.clone()));
        if let Some(f) = &c.cost_formula {
            m.insert("cost_formula".to_owned(), Value::from(f.clone()));
        } else {
            m.insert("cost_formula".to_owned(), Value::Null);
        }
        Value::Object(m)
    });

    let test_vectors_value: Vec<Value> = reg
        .test_vectors
        .iter()
        .map(|tv| {
            let mut m = serde_json::Map::new();
            m.insert("input".to_owned(), tv.input.clone());
            m.insert("expected_output".to_owned(), tv.expected_output.clone());
            m.insert(
                "description".to_owned(),
                Value::from(tv.description.clone()),
            );
            Value::Object(m)
        })
        .collect();

    let mut m = serde_json::Map::new();
    m.insert("outlet_id".to_owned(), Value::from(reg.outlet_id.clone()));
    // SCP-OUT-011: explicit kind in vector input payloads.
    m.insert(
        "kind".to_owned(),
        Value::from(match reg.kind {
            OutletKind::Query => "query",
            OutletKind::Action => "action",
        }),
    );
    m.insert("name".to_owned(), Value::from(reg.name.clone()));
    m.insert(
        "description".to_owned(),
        Value::from(reg.description.clone()),
    );
    let mut schema_m = serde_json::Map::new();
    schema_m.insert("input_schema".to_owned(), reg.schema.input_schema.clone());
    schema_m.insert("output_schema".to_owned(), reg.schema.output_schema.clone());
    m.insert("schema".to_owned(), Value::Object(schema_m));
    m.insert(
        "implementation_hash".to_owned(),
        Value::from(hex::encode(reg.implementation_hash)),
    );
    m.insert("test_vectors".to_owned(), Value::Array(test_vectors_value));
    m.insert(
        "operator_did".to_owned(),
        Value::from(reg.operator_did.0.clone()),
    );
    m.insert("cost".to_owned(), cost_value.unwrap_or(Value::Null));
    // SCP-OUT-040: surface the message_catalog so independent implementers
    // can rebuild the V2 catalog_hash term against the fixture input.
    let catalog_value: Vec<Value> = reg
        .message_catalog
        .iter()
        .map(|t| {
            let mut em = serde_json::Map::new();
            em.insert("key".to_owned(), Value::from(t.key.clone()));
            em.insert("template".to_owned(), Value::from(t.template.clone()));
            Value::Object(em)
        })
        .collect();
    m.insert("message_catalog".to_owned(), Value::Array(catalog_value));
    m.insert("registered_at".to_owned(), Value::from(reg.registered_at));
    Value::Object(m)
}

/// Reconstruct an `OutletRegistration` from the JSON `input` payload (so we
/// can re-run the verifier against the on-disk fixture without trusting the
/// in-memory generator).
///
/// # Errors
///
/// Returns an error string describing the first malformed field encountered.
pub fn registration_from_json_input(
    input: &Value,
    expected_signature_hex: &str,
) -> Result<OutletRegistration, String> {
    let obj = input
        .as_object()
        .ok_or_else(|| "input not an object".to_owned())?;
    let outlet_id = obj
        .get("outlet_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing outlet_id".to_owned())?
        .to_owned();
    // SCP-OUT-011: read explicit kind. Absent field falls back to the
    // §5.4.2 fail-safe default (Action) so legacy fixture inputs still
    // round-trip.
    let kind = match obj.get("kind") {
        None | Some(Value::Null) => OutletKind::default(),
        Some(Value::String(s)) => match s.as_str() {
            "query" => OutletKind::Query,
            "action" => OutletKind::Action,
            other => {
                return Err(format!(
                    "invalid kind: {other:?} (expected 'query' or 'action')"
                ));
            }
        },
        Some(other) => return Err(format!("kind must be string, got {other}")),
    };
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing name".to_owned())?
        .to_owned();
    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing description".to_owned())?
        .to_owned();
    let schema_obj = obj
        .get("schema")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing schema".to_owned())?;
    let input_schema = schema_obj
        .get("input_schema")
        .ok_or_else(|| "missing input_schema".to_owned())?
        .clone();
    let output_schema = schema_obj
        .get("output_schema")
        .ok_or_else(|| "missing output_schema".to_owned())?
        .clone();
    let impl_hash_hex = obj
        .get("implementation_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing implementation_hash".to_owned())?;
    let impl_hash_bytes =
        hex::decode(impl_hash_hex).map_err(|e| format!("bad impl_hash hex: {e}"))?;
    let implementation_hash: [u8; 32] = impl_hash_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "implementation_hash must be 32 bytes".to_owned())?;
    let test_vectors_raw = obj
        .get("test_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing test_vectors".to_owned())?;
    let mut test_vectors = Vec::with_capacity(test_vectors_raw.len());
    for tv in test_vectors_raw {
        let tvm = tv
            .as_object()
            .ok_or_else(|| "test_vector not object".to_owned())?;
        let tv_input = tvm
            .get("input")
            .ok_or_else(|| "missing test_vector.input".to_owned())?
            .clone();
        let expected_output = tvm
            .get("expected_output")
            .ok_or_else(|| "missing test_vector.expected_output".to_owned())?
            .clone();
        let tv_description = tvm
            .get("description")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing test_vector.description".to_owned())?
            .to_owned();
        test_vectors.push(OutletTestVector {
            input: tv_input,
            expected_output,
            description: tv_description,
        });
    }
    let operator_did = obj
        .get("operator_did")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing operator_did".to_owned())?
        .to_owned();
    let cost = match obj.get("cost") {
        None | Some(Value::Null) => None,
        Some(Value::Object(cm)) => {
            let amount = cm
                .get("amount")
                .and_then(Value::as_u64)
                .ok_or_else(|| "missing cost.amount".to_owned())?;
            let currency = cm
                .get("currency")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing cost.currency".to_owned())?
                .to_owned();
            let payee = cm
                .get("payee")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing cost.payee".to_owned())?
                .to_owned();
            let cost_formula = match cm.get("cost_formula") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(other) => {
                    return Err(format!("cost_formula must be string or null, got {other}"));
                }
            };
            Some(OutletCost {
                amount,
                currency,
                payee: payee.into(),
                cost_formula,
            })
        }
        Some(other) => return Err(format!("cost must be object or null, got {other}")),
    };
    let registered_at = obj
        .get("registered_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing registered_at".to_owned())?;
    let signature_bytes =
        hex::decode(expected_signature_hex).map_err(|e| format!("bad signature hex: {e}"))?;

    // SCP-OUT-040: read the message_catalog so the V2 preimage `catalog_hash`
    // term can be reconstructed from the fixture input.
    let message_catalog: Vec<scp_protocol::MessageTemplate> = match obj.get("message_catalog") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let entry = item
                    .as_object()
                    .ok_or_else(|| format!("message_catalog[{i}] not an object"))?;
                let key = entry
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("message_catalog[{i}].key missing"))?
                    .to_owned();
                let template = entry
                    .get("template")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("message_catalog[{i}].template missing"))?
                    .to_owned();
                out.push(scp_protocol::MessageTemplate { key, template });
            }
            out
        }
        Some(other) => {
            return Err(format!(
                "message_catalog must be array or null, got {other}"
            ));
        }
    };

    Ok(OutletRegistration {
        outlet_id,
        kind,
        name,
        description,
        schema: OutletSchema {
            input_schema,
            output_schema,
        },
        implementation_hash,
        test_vectors,
        operator_did: operator_did.into(),
        cost,
        registered_at,
        signature: signature_bytes,
        message_catalog,
    })
}

/// Helper: SHA-256 over a label, returning a fixed [u8; 32].
fn sha256_label(label: &[u8]) -> [u8; 32] {
    Sha256::digest(label).into()
}
