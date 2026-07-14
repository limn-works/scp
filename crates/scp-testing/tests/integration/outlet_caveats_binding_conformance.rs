//! SCP-OUT-039 — outlet caveats-binding conformance (§5.4.5 "JCS Option
//! serialization rule").
//!
//! `.docs/specs/05-contexts.md` §5.4.5 (the `effective_caveats` binding text)
//! states the cross-SDK conformance for the omit-none JCS rule is "verified by
//! `cargo test -p scp-testing --test outlet_caveats_binding_conformance`". This
//! is that test.
//!
//! §5.4.5 mandates that absent `Option`-typed `InvocationCaveats` fields are
//! **OMITTED** from the RFC 8785 (JCS) encoding, NOT serialized as explicit
//! `null` — an SDK that emits `"field": null` produces a distinct
//! `caveats_binding` preimage and its stream-open is rejected. This test pins
//! that rule against the Rust reference: a caveat set carrying ONLY
//! `amount_max_per_call = Some(100)` canonicalizes to JCS bytes that contain the
//! present key and NONE of the other field names (nor the token `null`), and the
//! resulting `caveats_binding` is deterministic and pinned to a known answer.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_protocol::context::outlets::stream::compute_caveats_binding;
use scp_protocol::economy::types::Amount;
use scp_protocol::trust::caveats::InvocationCaveats;

/// A partially-populated caveat set (only `amount_max_per_call` present) proves
/// the §5.4.5 omit-none rule: absent `Option` fields are OMITTED from the JCS
/// object, NOT serialized as explicit `null`. The robust invariant is that the
/// canonical object carries EXACTLY ONE key (the present field) and no `null`
/// token — so all 11 other `Option` fields are structurally absent regardless of
/// their wire spelling.
#[test]
fn jcs_omits_none_option_fields_not_null() {
    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_per_call = Some(Amount::new(100));

    let jcs = caveats
        .to_canonical_json_bytes()
        .expect("caveats canonicalizes to JCS");
    let jcs_str = std::str::from_utf8(&jcs).expect("JCS is UTF-8");

    assert!(
        !jcs_str.contains("null"),
        "no absent field may be serialized as explicit null: {jcs_str}"
    );

    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(jcs_str).expect("JCS is a JSON object");
    assert_eq!(
        obj.len(),
        1,
        "only the present field survives — all absent Option fields are OMITTED (not null): {jcs_str}"
    );
    let (key, value) = obj.iter().next().expect("one entry");
    assert!(
        key.eq_ignore_ascii_case("amountmaxpercall"),
        "the single present key is the amount-max-per-call field, got `{key}`: {jcs_str}"
    );
    // Amount canonicalizes as a decimal string (not a JSON number).
    assert_eq!(
        value,
        &serde_json::Value::String("100".to_owned()),
        "the present field carries the declared amount: {jcs_str}"
    );
}

/// The `caveats_binding` over the partially-populated set is deterministic and
/// equals the pinned known answer (a shared-core binding regression is caught).
#[test]
fn caveats_binding_is_deterministic_and_pinned() {
    use std::fmt::Write;

    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_per_call = Some(Amount::new(100));
    let jcs = caveats.to_canonical_json_bytes().expect("JCS");

    // Fixed preimage inputs (§5.4.5 caveats_binding).
    let ucan_cid = b"cid-caveats-binding-conformance";
    let request_id = [0x11u8; 16];
    let invoker_did = "did:key:z6MkCaveatsBindingConformance";
    let estimated_chunk_count = 4u32;

    let a = compute_caveats_binding(
        ucan_cid,
        &request_id,
        invoker_did,
        estimated_chunk_count,
        &jcs,
    );
    let b = compute_caveats_binding(
        ucan_cid,
        &request_id,
        invoker_did,
        estimated_chunk_count,
        &jcs,
    );
    assert_eq!(a, b, "caveats_binding is deterministic");

    let mut hex = String::with_capacity(a.len() * 2);
    for byte in a {
        let _ = write!(hex, "{byte:02x}");
    }
    assert_eq!(
        hex, EXPECTED_BINDING_HEX,
        "caveats_binding known-answer for the partially-populated caveat set"
    );
}

/// Known answer for `caveats_binding_is_deterministic_and_pinned` (pinned so a
/// preimage-construction or JCS regression is caught, not silently absorbed).
const EXPECTED_BINDING_HEX: &str =
    "fdd051543b0f995f7a0fe09cb91576537442c932a25578b25da41a8a62b86f6e";
