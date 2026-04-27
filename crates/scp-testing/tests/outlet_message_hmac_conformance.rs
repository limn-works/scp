//! SCP-OUT-041d cross-bridge HMAC conformance fixture verification.
//!
//! Loads `tests/conformance/vectors/outlet_message_hmac_fixtures.json`
//! and asserts that every `(outlet_message_key, catalog_key)` pair
//! produces the documented `expected_wire_message_hex` when run through
//! `OutletError::compute_wire_message`. This is the §5.4.4 round-5
//! `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]` invariant.
//!
//! The same fixture file is consumed by the per-SDK conformance suites
//! (Python, TypeScript, Swift, Kotlin) so all four implementations
//! produce byte-identical wire messages for the same input.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_protocol::context::outlets::errors::{CatalogKey, OutletError};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct HmacFixture {
    name: String,
    outlet_id: String,
    outlet_message_key_hex: String,
    catalog_key: String,
    expected_wire_message_hex: String,
}

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/scp-testing -> repo root
    p.pop();
    p.pop();
    p.push("tests/conformance/vectors/outlet_message_hmac_fixtures.json");
    p
}

#[test]
fn outlet_message_hmac_fixtures_match_compute_wire_message() {
    let path = fixture_path();
    let raw =
        std::fs::read_to_string(&path).expect("fixture file should be readable from repo root");
    let fixtures: Vec<HmacFixture> =
        serde_json::from_str(&raw).expect("fixture file should parse as a JSON array");

    assert!(
        fixtures.len() >= 10,
        "SCP-OUT-041d AC requires >= 10 fixtures, found {}",
        fixtures.len()
    );

    for fx in &fixtures {
        let key_bytes =
            hex::decode(&fx.outlet_message_key_hex).expect("outlet_message_key_hex must be hex");
        let key: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .expect("outlet_message_key must be 32 bytes");
        let catalog_key = CatalogKey::try_new(&fx.catalog_key)
            .unwrap_or_else(|e| panic!("fixture {} has invalid catalog_key: {e}", fx.name));
        let actual = OutletError::compute_wire_message(&key, &catalog_key);
        let actual_hex = hex::encode(actual);
        assert_eq!(
            actual_hex, fx.expected_wire_message_hex,
            "fixture {} (outlet_id={}, catalog_key={}) wire-message mismatch: \
             expected {}, got {}",
            fx.name, fx.outlet_id, fx.catalog_key, fx.expected_wire_message_hex, actual_hex
        );
    }
}
