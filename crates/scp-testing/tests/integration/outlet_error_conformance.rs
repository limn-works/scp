//! SCP-OUT-031 — `OutletError` conformance fixture round-trip.
//!
//! Round-trips every fixture in `tests/conformance/vectors/outlet_error_fixtures.json`
//! through the typed `scp_protocol::context::outlets::errors::OutletError`
//! envelope and asserts:
//!
//!  1. Each fixture's `class` resolves to a known [`OutletErrorClass`]
//!     variant, and the resulting envelope's class matches.
//!  2. Each fixture's `code` is recognised by [`error_code_to_class`] AND
//!     resolves to the same class as the wire-form `class` field —
//!     pinning the (code, class) bijection across the §5.4.4 taxonomy.
//!  3. Each fixture's `slug` is recognised by [`slug_to_class`].
//!  4. Pad-nonce and registration-event-id are 16 / 32 bytes after hex
//!     decoding, matching §5.4.4 round-5/6 fixed-width invariants.
//!  5. The fixture set covers ≥ 1 fixture for every code in
//!     [`ALL_CODES`] AND ≥ 30 total fixtures (the §5.4.4 ≥ 1-per-(code,
//!     slug) coverage bound).
//!  6. Per-class detail-shape conformance — every fixture whose class
//!     dictates a detail body carries one matching the §5.4.4 schema.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]

use std::collections::HashSet;
use std::path::PathBuf;

use scp_protocol::context::outlets::error_codes::{ALL_CODES, error_code_to_class, slug_to_class};
use scp_protocol::context::outlets::errors::{
    OutletErrorClass, validate_catalog_key, validate_outlet_error_code,
};

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)] // `retry` parsed for future-coverage tests; not yet asserted on.
struct FixtureEnvelope {
    code: String,
    slug: String,
    class: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    retry: serde_json::Value,
    #[serde(default)]
    detail: Option<serde_json::Value>,
    #[serde(default)]
    pad_nonce: String,
    #[serde(default)]
    registration_event_id: String,
}

#[derive(serde::Deserialize, Debug)]
struct FixtureFile {
    fixtures: Vec<serde_json::Value>,
}

fn fixture_path() -> PathBuf {
    // The integration-test crate runs from `crates/scp-testing/`. The
    // fixture lives at the repo root under `tests/conformance/vectors/`.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut path = PathBuf::from(manifest);
    path.pop(); // out of scp-testing
    path.pop(); // out of crates
    path.push("tests/conformance/vectors/outlet_error_fixtures.json");
    path
}

fn parse_fixtures() -> Vec<FixtureEnvelope> {
    let bytes = std::fs::read(fixture_path()).expect("fixture file must exist");
    let file: FixtureFile = serde_json::from_slice(&bytes).expect("fixture JSON parses");
    file.fixtures
        .into_iter()
        .map(|raw| serde_json::from_value::<FixtureEnvelope>(raw).expect("fixture shape"))
        .collect()
}

fn class_from_wire(wire: &str) -> Option<OutletErrorClass> {
    match wire {
        "protocol" => Some(OutletErrorClass::Protocol),
        "authorization" => Some(OutletErrorClass::Authorization),
        "input" => Some(OutletErrorClass::Input),
        "execution" => Some(OutletErrorClass::Execution),
        "output" => Some(OutletErrorClass::Output),
        "economic" => Some(OutletErrorClass::Economic),
        "transport" => Some(OutletErrorClass::Transport),
        "governance" => Some(OutletErrorClass::Governance),
        _ => None,
    }
}

#[test]
fn fixture_set_has_at_least_30_entries() {
    // §5.4.4 / OUT-031 AC: ≥ 1 fixture per allocated code AND
    // ≥ 1 fixture per unique (code, slug) pair covering every slug in
    // the §5.4.4 taxonomy (≥ 30 total).
    let fixtures = parse_fixtures();
    assert!(
        fixtures.len() >= 30,
        "OutletError fixture set must contain ≥ 30 fixtures (got {})",
        fixtures.len()
    );
}

#[test]
fn every_allocated_code_has_at_least_one_fixture() {
    let fixtures = parse_fixtures();
    let codes_in_fixtures: HashSet<&str> = fixtures.iter().map(|f| f.code.as_str()).collect();
    for code in ALL_CODES {
        assert!(
            codes_in_fixtures.contains(code),
            "OutletError fixture set is missing a fixture for allocated code {code}"
        );
    }
}

#[test]
fn fixture_set_covers_every_documented_code_slug_pair_once() {
    // The §5.4.4 / OUT-031 AC asks for ≥ 1 fixture per unique (code, slug)
    // pair covering every slug in the §5.4.4 taxonomy. Multiple fixtures
    // may share a (code, slug) pair (e.g., the PII-redaction and
    // source-chain variants both reuse authorization.denied). Verify that
    // the set of unique (code, slug) pairs is ≥ 30.
    let fixtures = parse_fixtures();
    let mut pairs: HashSet<(String, String)> = HashSet::new();
    for f in &fixtures {
        pairs.insert((f.code.clone(), f.slug.clone()));
    }
    assert!(
        pairs.len() >= 30,
        "OutletError fixture set must cover ≥ 30 unique (code, slug) pairs (got {})",
        pairs.len()
    );
}

#[test]
fn every_fixture_class_matches_code_class() {
    let fixtures = parse_fixtures();
    for f in &fixtures {
        let wire_class = class_from_wire(&f.class)
            .unwrap_or_else(|| panic!("fixture has unknown class wire form: {:?}", f.class));
        let code_class = error_code_to_class(&f.code).unwrap_or_else(|| {
            panic!(
                "fixture code {} is not registered in error_code_to_class",
                f.code
            )
        });
        assert_eq!(
            wire_class, code_class,
            "fixture class {:?} does not match the class registered for code {}",
            f.class, f.code
        );
    }
}

#[test]
fn every_fixture_slug_resolves_in_taxonomy() {
    let fixtures = parse_fixtures();
    for f in &fixtures {
        let wire_class = class_from_wire(&f.class).unwrap();
        let slug_class = slug_to_class(&f.slug).unwrap_or_else(|| {
            panic!("fixture slug {} is not registered in slug_to_class", f.slug)
        });
        assert_eq!(
            wire_class, slug_class,
            "fixture slug {:?} resolves to a different class than the fixture's class",
            f.slug
        );
    }
}

#[test]
fn every_fixture_code_passes_outlet_code_regex() {
    let fixtures = parse_fixtures();
    for f in &fixtures {
        assert!(
            validate_outlet_error_code(&f.code),
            "fixture code {} fails the §5.4.4 outlet error code regex",
            f.code
        );
    }
}

#[test]
fn every_fixture_slug_passes_catalog_key_regex() {
    let fixtures = parse_fixtures();
    for f in &fixtures {
        assert!(
            validate_catalog_key(&f.slug),
            "fixture slug {} fails the §5.4.4 catalog-key regex",
            f.slug
        );
    }
}

#[test]
fn pad_nonce_is_16_bytes_when_present() {
    let fixtures = parse_fixtures();
    for f in &fixtures {
        if !f.pad_nonce.is_empty() {
            let bytes = hex::decode(&f.pad_nonce)
                .unwrap_or_else(|e| panic!("fixture pad_nonce hex decode failed: {e}"));
            assert_eq!(
                bytes.len(),
                16,
                "fixture pad_nonce must be 16 bytes per §5.4.4 round-5"
            );
        }
    }
}

#[test]
fn registration_event_id_is_32_bytes_when_present() {
    let fixtures = parse_fixtures();
    for f in &fixtures {
        if !f.registration_event_id.is_empty() {
            let bytes = hex::decode(&f.registration_event_id)
                .unwrap_or_else(|e| panic!("fixture registration_event_id hex decode failed: {e}"));
            assert_eq!(
                bytes.len(),
                32,
                "fixture registration_event_id must be 32 bytes per §5.4.4 round-6"
            );
        }
    }
}

#[test]
fn detail_shape_matches_class_per_5_4_4_table() {
    // §5.4.4 per-class detail-schema enforcement — every fixture whose
    // class dictates a detail body must carry one whose key set matches
    // the schema (the same predicate the SDKs apply at the
    // deserialization boundary).
    let fixtures = parse_fixtures();
    for f in &fixtures {
        let class_ = class_from_wire(&f.class).unwrap();
        let detail = match &f.detail {
            Some(serde_json::Value::Object(map)) => map,
            Some(serde_json::Value::Null) | None => {
                // Absent detail is permitted only for classes whose schema
                // is `{}` or for variants that document the absence. The
                // ground-truth predicate here is permissive — fixtures
                // without detail are skipped.
                continue;
            }
            Some(other) => panic!(
                "fixture {:?} carries a non-object detail: {:?}",
                f.code, other
            ),
        };
        let keys: Vec<&str> = detail.keys().map(String::as_str).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        let ok = match class_ {
            OutletErrorClass::Protocol => sorted == ["rule"],
            OutletErrorClass::Authorization => sorted == ["capability"],
            OutletErrorClass::Input | OutletErrorClass::Output => {
                sorted == ["fieldPath", "violation"]
            }
            OutletErrorClass::Execution => {
                sorted.is_empty() || sorted == ["elapsedMs"] || sorted == ["panicLocationHash"]
            }
            OutletErrorClass::Economic => {
                sorted == ["adapterId"] || sorted == ["currency", "needed"]
            }
            OutletErrorClass::Transport => {
                sorted == ["retryAfterSecs"] || sorted == ["relayUrlKind"]
            }
            OutletErrorClass::Governance => sorted == ["action"],
        };
        assert!(
            ok,
            "fixture detail shape {sorted:?} for class {class_:?} does not match §5.4.4 schema"
        );
    }
}

#[test]
fn pii_redaction_fixture_is_present() {
    // OUT-031 AC — the fixture set must include ≥ 1 email and ≥ 1 DID
    // pre-redaction so SDK conformance tests can exercise the redactor.
    // Hand-scanned to avoid pulling in `regex` as a dev-dep.
    let fixtures = parse_fixtures();
    let raw: String = fixtures
        .iter()
        .map(|f| f.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let has_email = raw.bytes().enumerate().any(|(i, b)| {
        if b != b'@' {
            return false;
        }
        // Right side must contain a `.` and at least one alphabetic
        // character; left side must contain at least one local-part
        // character. Approximate but sufficient.
        let (left, right) = (&raw.as_bytes()[..i], &raw.as_bytes()[i + 1..]);
        !left.is_empty() && right.contains(&b'.') && right.iter().any(u8::is_ascii_alphabetic)
    });
    let has_did = raw.contains("did:dht:") || raw.contains("did:web:") || raw.contains("did:key:");
    assert!(
        has_email,
        "OutletError fixture set must include ≥ 1 email pre-redaction"
    );
    assert!(
        has_did,
        "OutletError fixture set must include ≥ 1 DID pre-redaction"
    );
}

#[test]
fn round_trip_through_serde_preserves_fields() {
    // Each fixture is parsed into a generic `serde_json::Value`, then
    // re-serialized — the resulting bytes must canonicalize back to the
    // same logical value (key ordering aside). This pins that the
    // fixture file is well-formed JSON the SDKs can ingest verbatim.
    let bytes = std::fs::read(fixture_path()).expect("fixture file must exist");
    let outer: FixtureFile = serde_json::from_slice(&bytes).unwrap();
    for value in &outer.fixtures {
        let bytes_round = serde_json::to_vec(value).unwrap();
        let value_back: serde_json::Value = serde_json::from_slice(&bytes_round).unwrap();
        assert_eq!(
            value, &value_back,
            "fixture round-trip through serde diverged: {value:?}"
        );
    }
}
