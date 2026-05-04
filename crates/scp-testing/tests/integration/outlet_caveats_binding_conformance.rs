//! SCP-OUT-039 cross-SDK byte-equivalence fixture conformance —
//! `caveats_binding`, `chunk_sig_preimage`, and `credit_sig_preimage`
//! per §5.4.5 line 635 / ADR-049 §5 round-5 JCS Option rule.
//!
//! Spec §5.4.5 line 635 promises:
//!
//! > A cross-SDK conformance fixture covers this: a caveat set
//! > `{ amount_max_per_call: Some(100) }` produces the same 32-byte
//! > `caveats_binding` from Python (PyO3), TypeScript (napi-rs), Swift
//! > (UniFFI), and Kotlin (UniFFI) regardless of the other 11 fields'
//! > absence — verified by `cargo test -p scp-testing --test
//! > outlet_caveats_binding_conformance`.
//!
//! That test target had no fixture and no implementation before this
//! file landed (the alignment-review for SCP-OUT-039 surfaced the gap).
//! This file:
//!
//! 1. Loads the on-disk JSON fixture from
//!    `tests/conformance/vectors/outlet_caveats_binding_fixtures.json`
//!    and asserts the schema is well-formed.
//! 2. Replays every vector through the protocol-level helpers
//!    (`scp_protocol::context::outlets::stream::compute_caveats_binding`
//!    / `compute_chunk_sig_preimage` / `compute_credit_sig_preimage`)
//!    and asserts the recorded golden hashes reproduce byte-for-byte.
//! 3. Holds the on-disk fixture byte-identical to what
//!    [`scp_testing::conformance::outlet_caveats_binding::build_fixture_file`]
//!    would currently produce — drift detection.
//! 4. Provides a `#[ignore]` regenerator that rewrites the on-disk
//!    fixture from the in-tree generator (matches the
//!    `outlet_registration_v2.json` regenerate pattern at
//!    `crates/scp-testing/tests/integration/conformance.rs`).
//!
//! Per-SDK byte-for-byte replays live in:
//!
//! - `bindings/python/tests/test_outlet_caveats_binding_conformance.py`
//! - `bindings/typescript/tests/outlet-caveats-binding-conformance.test.ts`
//! - `crates/scp-ffi/uniffi/tests/outlet_stream_vectors.rs`
//! - `crates/scp-ffi/wasm/tests/outlet_stream_vectors.rs`
//!
//! Each per-SDK test consumes the SAME on-disk JSON fixture and asserts
//! its bridge produces the same goldens — that is the spec's
//! "byte-for-byte identical across all four SDKs" claim made
//! mechanically enforceable.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::items_after_statements
)]

use std::collections::HashSet;

use scp_testing::conformance::outlet_caveats_binding as cb;

/// Loads the on-disk fixture file. The file must exist and parse as
/// [`cb::CaveatsBindingFixtureFile`]; a deserialization failure is a
/// schema-drift bug.
fn load_fixture() -> cb::CaveatsBindingFixtureFile {
    let path = cb::vectors_path();
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture file at {} must exist: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "fixture file at {} must deserialize as CaveatsBindingFixtureFile: {e}",
            path.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Schema / shape assertions
// ---------------------------------------------------------------------------

#[test]
fn fixture_file_carries_required_shape() {
    let f = load_fixture();
    assert!(
        !f.comment.is_empty(),
        "fixture must carry a non-empty comment block"
    );
    assert!(
        f.spec_section.contains("§5.4.5"),
        "spec_section must reference §5.4.5; got {:?}",
        f.spec_section
    );
    assert!(
        f.story.contains("SCP-OUT-039"),
        "story must reference SCP-OUT-039; got {:?}",
        f.story
    );
    assert!(
        !f.caveats_binding.is_empty(),
        "fixture must carry ≥ 1 caveats_binding vector"
    );
    assert!(
        !f.chunk_sig_preimage.is_empty(),
        "fixture must carry ≥ 1 chunk_sig_preimage vector"
    );
    assert!(
        !f.credit_sig_preimage.is_empty(),
        "fixture must carry ≥ 1 credit_sig_preimage vector"
    );
}

#[test]
fn fixture_carries_minimum_vector_counts_per_class() {
    let f = load_fixture();
    assert!(
        f.caveats_binding.len() >= 3,
        "spec demands ≥ 3 caveats_binding vectors; got {}",
        f.caveats_binding.len()
    );
    assert!(
        f.chunk_sig_preimage.len() >= 2,
        "spec demands ≥ 2 chunk_sig_preimage vectors; got {}",
        f.chunk_sig_preimage.len()
    );
    assert!(
        f.credit_sig_preimage.len() >= 2,
        "spec demands ≥ 2 credit_sig_preimage vectors; got {}",
        f.credit_sig_preimage.len()
    );
}

#[test]
fn fixture_vector_names_are_unique() {
    let f = load_fixture();

    let mut cb_names: HashSet<&str> = HashSet::new();
    for v in &f.caveats_binding {
        assert!(
            cb_names.insert(v.name.as_str()),
            "duplicate caveats_binding vector name: {}",
            v.name
        );
    }
    let mut cs_names: HashSet<&str> = HashSet::new();
    for v in &f.chunk_sig_preimage {
        assert!(
            cs_names.insert(v.name.as_str()),
            "duplicate chunk_sig_preimage vector name: {}",
            v.name
        );
    }
    let mut credit_names: HashSet<&str> = HashSet::new();
    for v in &f.credit_sig_preimage {
        assert!(
            credit_names.insert(v.name.as_str()),
            "duplicate credit_sig_preimage vector name: {}",
            v.name
        );
    }
}

#[test]
fn fixture_carries_required_named_caveats_binding_vectors() {
    let f = load_fixture();
    let names: Vec<&str> = f.caveats_binding.iter().map(|v| v.name.as_str()).collect();
    for required in ["cb_minimal", "cb_multifield", "cb_empty"] {
        assert!(
            names.contains(&required),
            "caveats_binding must include the {required} vector; got {names:?}"
        );
    }
}

#[test]
fn fixture_cb_empty_canonicalizes_to_literal_empty_object() {
    let f = load_fixture();
    let empty = f
        .caveats_binding
        .iter()
        .find(|v| v.name == "cb_empty")
        .expect("cb_empty vector required");
    assert_eq!(
        empty.effective_caveats_jcs, "{}",
        "cb_empty MUST encode `InvocationCaveats::empty()` as the literal `{{}}` \
         JCS string per §5.4.5 omit-none rule; got {:?}",
        empty.effective_caveats_jcs
    );
}

// ---------------------------------------------------------------------------
// Helper-level reproduction
// ---------------------------------------------------------------------------

#[test]
fn every_vector_reproduces_under_protocol_helpers() {
    let f = load_fixture();
    match cb::verify_fixture_against_helpers(&f) {
        Ok(()) => {}
        Err(errs) => {
            panic!(
                "on-disk fixture does NOT reproduce under in-tree helpers; this \
                 indicates either a fixture rotation that did not regenerate or a \
                 protocol-level helper change that did not land in the fixture.\n\
                 Errors:\n{}",
                errs.join("\n")
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

#[test]
fn on_disk_fixture_matches_in_tree_generator_byte_for_byte() {
    let on_disk = load_fixture();
    let regenerated = cb::build_fixture_file();
    let on_disk_json =
        serde_json::to_value(&on_disk).expect("on-disk fixture serializable to JSON value");
    let regen_json =
        serde_json::to_value(&regenerated).expect("regen fixture serializable to JSON value");
    assert_eq!(
        on_disk_json, regen_json,
        "outlet_caveats_binding_fixtures.json drifted from in-tree generator — \
         re-run `cargo test -p scp-testing --test outlet_caveats_binding_conformance \
         conf_outlet_caveats_binding_regen -- --ignored --nocapture` to refresh"
    );
}

// ---------------------------------------------------------------------------
// Regenerator (ignored by default)
// ---------------------------------------------------------------------------

/// Regenerator. Run with:
///
/// ```bash
/// cargo test -p scp-testing --test outlet_caveats_binding_conformance \
///   conf_outlet_caveats_binding_regen -- --ignored --nocapture
/// ```
#[test]
#[ignore = "writes to disk; run explicitly when intentionally regenerating fixture"]
fn conf_outlet_caveats_binding_regen() {
    let path = cb::vectors_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create vectors parent directory");
    }
    let file = cb::build_fixture_file();
    let serialized = serde_json::to_string_pretty(&file).expect("serialize fixture file");
    std::fs::write(&path, serialized + "\n").expect("write fixture file");
    println!(
        "Regenerated outlet caveats_binding fixture → {} ({} cb / {} chunk_sig / {} credit_sig)",
        path.display(),
        file.caveats_binding.len(),
        file.chunk_sig_preimage.len(),
        file.credit_sig_preimage.len()
    );
}
