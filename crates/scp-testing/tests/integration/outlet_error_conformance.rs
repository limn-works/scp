//! SCP-OUT-031 (PR-1) — §5.4.4 `OutletError` cross-SDK conformance gate.
//!
//! This is the Rust conformance test that every language SDK later matches
//! (PR-2/3/4). It replays `tests/conformance/vectors/outlet_error_fixtures.json`
//! against the shipped §5.4.4 registry
//! (`crates/scp-protocol/src/context/outlets/error_codes.rs`) and the typed
//! envelope (`.../errors.rs`), establishing the **structural / field-level**
//! contract (class, code, slug, retry, detail shape, and field widths) the four
//! SDK translation layers must reproduce.
//!
//! **Not golden wire bytes.** The fixtures are construction-input descriptors,
//! not serialized envelopes: `message` is a plaintext stand-in for the SDK's
//! reconstructed developer-facing catalog message; the real on-wire tag-4 field
//! is `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]`, never prose. Golden
//! serialized-envelope bytes + the expected HMAC value per fixture are a PR-2
//! deliverable (once the bridge wire format is settled); until then the SDK
//! round-trip proves envelope reconstruction + field self-consistency, not
//! cross-SDK byte identity.
//!
//! Coverage the fixtures assert:
//!   * ≥ 1 VALID fixture per allocated code (all 15 in `ALL_CODES`), AND
//!   * exactly one VALID fixture per unique `(code, slug)` pair covering every
//!     slug in the §5.4.4 taxonomy — pinned against the registry's pub
//!     `CODE_*`/`SLUG_*` constants in [`EXPECTED_PAIRS`] (so a registry rename
//!     breaks compilation) AND set-equated against the registry's enumerable
//!     `ALL_SLUGS` domain (so a slug added to the registry without a matching
//!     fixture fails the coverage assertion by construction, not against a
//!     hand-copied list).
//!   * one MALFORMED-detail fixture per class (detail shape ≠ the class's
//!     `expected_detail`) that the `errors.rs` construction/validation boundary
//!     rejects with `DetailShapeMismatch`.
//!   * `supplementary` fixtures for the top cross-SDK round-trip hazards (a
//!     32-byte `ExecutionPanic` hash; a `u64` > 2^53) — validated for
//!     registry-consistency + constructibility, excluded from the bijection.
//!
//! One VALID fixture embeds an email + DID in its plaintext `message` to
//! exercise the later per-SDK AC9/AC10 redactor.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use serde::Deserialize;

use scp_protocol::context::outlets::OutletId;
// Glob-import the registry: brings every `CODE_*` / `SLUG_*` constant plus the
// lookup functions into scope. The `EXPECTED_PAIRS` table below references the
// constants directly, so a registry rename is a compile error here.
use scp_protocol::context::outlets::error_codes::*;
use scp_protocol::context::outlets::errors::{
    CatalogKey, DetailBody, OutletError, OutletErrorClass, OutletErrorConstructionFailed,
    OutletErrorNewOpts, RetryPolicy, validate_catalog_key, validate_outlet_error_code,
};

/// The fixture corpus, compiled in at build time.
const FIXTURES_JSON: &str =
    include_str!("../../../../tests/conformance/vectors/outlet_error_fixtures.json");

/// One fixture descriptor. `message`/`pad_nonce`/`registration_event_id` are
/// strings on the wire vector; `class`/`retry`/`detail` deserialize straight
/// into the shipped `scp-protocol` types, which is itself a conformance check
/// that the JSON shapes match the Rust serde contract.
#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    code: String,
    slug: String,
    class: OutletErrorClass,
    message: String,
    retry: RetryPolicy,
    detail: DetailBody,
    pad_nonce: String,
    registration_event_id: String,
    /// Present only on the malformed corpus; defaults false for valid fixtures.
    #[serde(default)]
    malformed: bool,
    /// Present only on the supplementary corpus; defaults false otherwise.
    #[serde(default)]
    supplementary: bool,
}

#[derive(Debug, Deserialize)]
struct FixtureFile {
    fixtures: Vec<Fixture>,
    malformed: Vec<Fixture>,
    supplementary: Vec<Fixture>,
}

/// Canonical `(code, slug)` pairs — the cross-SDK contract. Every entry uses
/// the registry's pub `CODE_*` / `SLUG_*` constants (not string literals), so:
///   * a renamed/removed constant fails to compile here, and
///   * a slug added to the registry without a fixture fails the coverage
///     assertion (the fixture set and this table are checked for set-equality).
const EXPECTED_PAIRS: &[(&str, &str)] = &[
    // 6100 — Protocol (registration / validation / classification).
    (CODE_PROTOCOL_VIOLATION, SLUG_PROTOCOL_VIOLATION),
    (CODE_PROTOCOL_VIOLATION, SLUG_QUERY_COST_VIOLATION),
    (CODE_PROTOCOL_VIOLATION, SLUG_QUERY_VIOLATION),
    (CODE_PROTOCOL_VIOLATION, SLUG_KIND_MISMATCH),
    (CODE_PROTOCOL_VIOLATION, SLUG_AMPLIFICATION_VIOLATION),
    (CODE_PROTOCOL_VIOLATION, SLUG_STRUCTURAL_FLOOR_VIOLATION),
    (CODE_PROTOCOL_VIOLATION, SLUG_SCHEMA_IMMUTABILITY_VIOLATION),
    (CODE_PROTOCOL_VIOLATION, SLUG_QUERY_MISDECLARATION),
    (
        CODE_PROTOCOL_VIOLATION,
        SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
    ),
    (CODE_PROTOCOL_VIOLATION, SLUG_PROTOCOL_STREAM_ALREADY_OPEN),
    // 6101 — Protocol (session lifecycle).
    (CODE_PROTOCOL_SESSION, SLUG_PROTOCOL_SESSION_ID_CONFLICT),
    (CODE_PROTOCOL_SESSION, SLUG_PROTOCOL_MALFORMED_SESSION_ID),
    (CODE_PROTOCOL_SESSION, SLUG_PROTOCOL_UNKNOWN_SESSION),
    (
        CODE_PROTOCOL_SESSION,
        SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
    ),
    (CODE_PROTOCOL_SESSION, SLUG_PROTOCOL_STREAM_ALREADY_CLOSED),
    // 6110 — Authorization (general denial + caveat enforcement).
    (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_DENIED),
    (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_EXPIRED),
    (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_REVOKED),
    (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_MISSING),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_ATTENUATION_VIOLATION,
    ),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_MINT_LIMIT_EXCEEDED,
    ),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_TIME_BOX_VIOLATION,
    ),
    (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_RATE_EXCEEDED),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_CUMULATIVE_EXCEEDED,
    ),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_ADAPTER_NOT_ALLOWED,
    ),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_REVOKED_MID_STREAM,
    ),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_CREDIT_STREAM_MISMATCH,
    ),
    (
        CODE_AUTHORIZATION_DENIED,
        SLUG_AUTHORIZATION_IKM_SIGNATURE_INVALID,
    ),
    (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_CREDIT_REPLAY),
    // 6114 — Authorization (attenuation sub-class).
    (
        CODE_AUTHORIZATION_ATTENUATION,
        SLUG_ATTENUATION_MASK_WIDTH_VIOLATION,
    ),
    (
        CODE_AUTHORIZATION_ATTENUATION,
        SLUG_ATTENUATION_CAVEAT_MINT_LIMIT_EXCEEDED,
    ),
    (
        CODE_AUTHORIZATION_ATTENUATION,
        SLUG_ATTENUATION_HOURS_OF_DAY_HIGH_BITS_SET,
    ),
    (
        CODE_AUTHORIZATION_ATTENUATION,
        SLUG_ATTENUATION_DAYS_OF_WEEK_HIGH_BIT_SET,
    ),
    (
        CODE_AUTHORIZATION_ATTENUATION,
        SLUG_ATTENUATION_ORIGIN_KIND_STEM_MISMATCH,
    ),
    (
        CODE_AUTHORIZATION_ATTENUATION,
        SLUG_ATTENUATION_ORIGIN_KIND_MIXED_STEM_ROOT,
    ),
    (
        CODE_AUTHORIZATION_ATTENUATION,
        SLUG_ATTENUATION_ORIGIN_KIND_UNSPECIFIED,
    ),
    // 6115 — Authorization (salt-rotation).
    (
        CODE_AUTHORIZATION_SALT_ROTATION,
        SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED,
    ),
    // 6120 — Input.
    (CODE_INPUT_VIOLATION, SLUG_INPUT_SCHEMA_VIOLATION),
    (CODE_INPUT_VIOLATION, SLUG_INPUT_TOO_LARGE),
    (CODE_INPUT_VIOLATION, SLUG_INPUT_NOT_SERIALIZABLE),
    (CODE_INPUT_VIOLATION, SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND),
    // SCP-OUT-031 PR-1: invalid-grant classified Input, additional slug on 6120
    // (§5.4.5 input.estimate-exceeds-bound precedent — caller-supplied scalar
    // range violation).
    (CODE_INPUT_VIOLATION, SLUG_INPUT_INVALID_GRANT),
    // 6130 — Execution (handler fault).
    (CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC),
    (CODE_EXECUTION_FAULT, SLUG_EXECUTION_TIMEOUT),
    (CODE_EXECUTION_FAULT, SLUG_EXECUTION_NON_DETERMINISTIC),
    // 6131 — Execution (credit / stream-gap, Immediate).
    (CODE_EXECUTION_CREDIT, SLUG_EXECUTION_CREDIT_EXHAUSTED),
    (CODE_EXECUTION_CREDIT, SLUG_EXECUTION_STREAM_GAP),
    // 6132 — Execution (node-level pump ceiling, WithBackoff — #2209 split).
    (
        CODE_EXECUTION_STREAM_CAP,
        SLUG_EXECUTION_STREAM_CAP_EXHAUSTED,
    ),
    // 6133 — Execution (credit-stall).
    (CODE_EXECUTION_CREDIT_STALL, SLUG_EXECUTION_CREDIT_STALL),
    // 6135 — Execution (cancel-ack timeout).
    (
        CODE_EXECUTION_CANCEL_ACK_TIMEOUT,
        SLUG_EXECUTION_CANCEL_ACK_TIMEOUT,
    ),
    // 6140 — Output.
    (CODE_OUTPUT_VIOLATION, SLUG_OUTPUT_SCHEMA_VIOLATION),
    (CODE_OUTPUT_VIOLATION, SLUG_OUTPUT_TOO_LARGE),
    (CODE_OUTPUT_VIOLATION, SLUG_OUTPUT_NOT_SERIALIZABLE),
    // 6150 — Economic (including the Protocol-prefixed cross-class slug).
    (CODE_ECONOMIC_FAULT, SLUG_ECONOMIC_INSUFFICIENT_FUNDS),
    (CODE_ECONOMIC_FAULT, SLUG_ECONOMIC_ADAPTER_FAILURE),
    (CODE_ECONOMIC_FAULT, SLUG_ECONOMIC_PRICING_FORMULA_ERROR),
    (CODE_ECONOMIC_FAULT, SLUG_ECONOMIC_BUDGET_EXCEEDED),
    (CODE_ECONOMIC_FAULT, SLUG_ECONOMIC_ESCROW_OVERFLOW),
    (CODE_ECONOMIC_FAULT, SLUG_PROTOCOL_INTERFACE_SPAM_COST),
    // 6160 — Transport.
    (CODE_TRANSPORT_FAULT, SLUG_TRANSPORT_RELAY_UNAVAILABLE),
    (
        CODE_TRANSPORT_FAULT,
        SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
    ),
    (CODE_TRANSPORT_FAULT, SLUG_TRANSPORT_RATE_LIMITED),
    (
        CODE_TRANSPORT_FAULT,
        SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER,
    ),
    (
        CODE_TRANSPORT_FAULT,
        SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_ORIGIN_INVOKER,
    ),
    (
        CODE_TRANSPORT_FAULT,
        SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_OUTLET,
    ),
    // 6170 — Governance.
    (CODE_GOVERNANCE_FAULT, SLUG_GOVERNANCE_OUTLET_DEREGISTERED),
    (CODE_GOVERNANCE_FAULT, SLUG_GOVERNANCE_OUTLET_SUSPENDED),
    (CODE_GOVERNANCE_FAULT, SLUG_GOVERNANCE_CEILING_EXCEEDED),
    (CODE_GOVERNANCE_FAULT, SLUG_GOVERNANCE_CONSEQUENCE_ACTIVE),
];

fn load() -> FixtureFile {
    serde_json::from_str(FIXTURES_JSON).expect("outlet_error_fixtures.json must parse")
}

/// Decodes a hex string into a fixed-length byte array, panicking (test-only)
/// with the fixture name on any length mismatch.
fn decode_fixed<const N: usize>(name: &str, field: &str, hexstr: &str) -> [u8; N] {
    let bytes = hex::decode(hexstr)
        .unwrap_or_else(|e| panic!("fixture {name}: {field} is not valid hex: {e}"));
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!(
            "fixture {name}: {field} decoded to {} bytes, expected {N}",
            v.len()
        )
    })
}

/// Reconstructs the typed envelope through the shipped `errors.rs` construction
/// boundary — the same path an SDK bridge takes. Registers exactly the
/// fixture's slug-derived catalog key so the membership check passes.
fn construct(f: &Fixture) -> Result<OutletError, OutletErrorConstructionFailed> {
    let outlet_id: OutletId = "outlet-conformance".to_owned();
    let outlet_message_key = [0x42u8; 32];
    let catalog_key =
        CatalogKey::try_new(f.slug.clone()).expect("fixture slug must be a valid catalog key");
    let registered = vec![catalog_key.clone()];
    let pad_nonce: [u8; 16] = decode_fixed(&f.name, "pad_nonce", &f.pad_nonce);
    let registration_event_id: [u8; 32] =
        decode_fixed(&f.name, "registration_event_id", &f.registration_event_id);
    OutletError::new(OutletErrorNewOpts {
        outlet_id: &outlet_id,
        outlet_message_key: &outlet_message_key,
        registration_event_id,
        catalog_key: &catalog_key,
        registered_keys: &registered,
        class: f.class,
        code: &f.code,
        slug: &f.slug,
        retry: f.retry.clone(),
        detail: Some(f.detail.clone()),
        source_chain: Vec::new(),
        pad_nonce,
    })
}

/// The valid fixtures reproduce EXACTLY the canonical `(code, slug)` contract —
/// every registry pair is present, and no extra/unknown pair sneaks in.
#[test]
fn valid_fixtures_cover_every_code_slug_pair() {
    let file = load();
    let fixture_pairs: BTreeSet<(String, String)> = file
        .fixtures
        .iter()
        .map(|f| (f.code.clone(), f.slug.clone()))
        .collect();
    let expected_pairs: BTreeSet<(String, String)> = EXPECTED_PAIRS
        .iter()
        .map(|(c, s)| ((*c).to_owned(), (*s).to_owned()))
        .collect();

    // No duplicate (code, slug) among fixtures.
    assert_eq!(
        fixture_pairs.len(),
        file.fixtures.len(),
        "valid fixtures contain a duplicate (code, slug) pair"
    );
    // Exact set-equality: the fixtures are the registry taxonomy, no more, no less.
    let missing: Vec<_> = expected_pairs.difference(&fixture_pairs).collect();
    let extra: Vec<_> = fixture_pairs.difference(&expected_pairs).collect();
    assert!(
        missing.is_empty(),
        "fixtures missing these (code, slug) pairs: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "fixtures contain unexpected (code, slug) pairs not in the §5.4.4 registry: {extra:?}"
    );

    // Coverage bounds: ≥ 1 per code, and total ≥ the taxonomy count. The AC's
    // "≥ 12 codes / ≥ 30 total" is a floor the current 15-code taxonomy
    // exceeds; assert the real coverage.
    assert_eq!(
        file.fixtures.len(),
        EXPECTED_PAIRS.len(),
        "fixture count must equal the canonical taxonomy pair count"
    );
    assert!(
        file.fixtures.len() >= 30,
        "AC floor: ≥ 30 total valid fixtures"
    );

    // Registry-driven coverage: set-equate the fixtures' slug domain against
    // the registry's enumerable `ALL_SLUGS`, NOT just against the hand-written
    // EXPECTED_PAIRS list. This closes the slug-drift hole — a slug added to
    // the registry (and to ALL_SLUGS, which its own source-parse unit test
    // enforces) but forgotten in the fixtures now FAILS here by construction.
    // EXPECTED_PAIRS is likewise held to ALL_SLUGS so the two can't drift apart.
    let all_slugs: BTreeSet<&str> = ALL_SLUGS.iter().copied().collect();
    let fixture_slugs: BTreeSet<&str> = file.fixtures.iter().map(|f| f.slug.as_str()).collect();
    let expected_slugs: BTreeSet<&str> = EXPECTED_PAIRS.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        fixture_slugs, all_slugs,
        "fixtures' slug set must equal the registry ALL_SLUGS domain (registry slug added without a fixture, or vice versa)"
    );
    assert_eq!(
        expected_slugs, all_slugs,
        "EXPECTED_PAIRS' slug set must equal the registry ALL_SLUGS domain"
    );
    // Every fixture slug carries the code the registry assigns its class-band;
    // combined with ALL_SLUGS equality this makes the fixtures the taxonomy.
    assert_eq!(
        file.fixtures.len(),
        ALL_SLUGS.len(),
        "one fixture per registry slug"
    );
}

/// Every allocated code in `ALL_CODES` (all 15) has at least one valid fixture.
#[test]
fn every_allocated_code_has_a_valid_fixture() {
    let file = load();
    for code in ALL_CODES {
        let count = file.fixtures.iter().filter(|f| f.code == code).count();
        assert!(
            count >= 1,
            "allocated code {code} has no valid fixture (≥ 1 required)"
        );
    }
    // And every fixture code is an allocated code (no orphan codes).
    for f in &file.fixtures {
        assert!(
            ALL_CODES.contains(&f.code.as_str()),
            "fixture {} references non-allocated code {}",
            f.name,
            f.code
        );
    }
}

/// Each valid fixture is registry-consistent (the `error_code_to_class` /
/// `slug_to_class` bijection, the slug/code validators, and the default retry
/// policy) AND constructs cleanly through the `errors.rs` envelope boundary
/// with its per-class detail shape — the round-trip contract every SDK matches.
#[test]
fn valid_fixtures_are_registry_consistent_and_constructible() {
    let file = load();
    assert!(!file.fixtures.is_empty());
    for f in &file.fixtures {
        assert!(
            !f.malformed,
            "fixture {} in `fixtures` is flagged malformed",
            f.name
        );

        // code → class and slug → class both resolve to the fixture's class
        // (the §5.4.4 bijection).
        assert_eq!(
            error_code_to_class(&f.code),
            Some(f.class),
            "fixture {}: error_code_to_class({}) != {:?}",
            f.name,
            f.code,
            f.class
        );
        assert_eq!(
            slug_to_class(&f.slug),
            Some(f.class),
            "fixture {}: slug_to_class({}) != {:?}",
            f.name,
            f.slug,
            f.class
        );

        // Slug + code validators pass.
        validate_slug(&f.slug)
            .unwrap_or_else(|e| panic!("fixture {}: slug fails §5.4.4 regex: {e:?}", f.name));
        assert!(
            validate_catalog_key(&f.slug),
            "fixture {}: slug is not a valid catalog key",
            f.name
        );
        assert!(
            validate_outlet_error_code(&f.code),
            "fixture {}: code fails the §5.4.4 6100-6199 sub-block check",
            f.name
        );

        // Default retry policy for the code is exactly what the fixture carries.
        assert_eq!(
            Some(f.retry.clone()),
            error_code_to_retry_policy(&f.code),
            "fixture {}: retry policy disagrees with the registry default for {}",
            f.name,
            f.code
        );

        // pad_nonce is 16 bytes, registration_event_id is 32 bytes.
        let pad: [u8; 16] = decode_fixed(&f.name, "pad_nonce", &f.pad_nonce);
        let reg: [u8; 32] =
            decode_fixed(&f.name, "registration_event_id", &f.registration_event_id);

        // Full construction through the errors.rs boundary succeeds and
        // preserves every field (this also proves the detail shape matches the
        // class — a mismatch would be rejected here).
        let env = construct(f).unwrap_or_else(|e| {
            panic!(
                "fixture {}: OutletError::new rejected a valid fixture: {e:?}",
                f.name
            )
        });
        assert_eq!(env.code, f.code, "fixture {}", f.name);
        assert_eq!(env.slug, f.slug, "fixture {}", f.name);
        assert_eq!(env.class, f.class, "fixture {}", f.name);
        assert_eq!(env.retry, f.retry, "fixture {}", f.name);
        assert_eq!(env.pad_nonce, pad, "fixture {}", f.name);
        assert_eq!(env.registration_event_id, reg, "fixture {}", f.name);
        assert_eq!(
            env.detail.as_ref(),
            Some(&f.detail),
            "fixture {}: detail not preserved",
            f.name
        );
    }
}

/// At least one valid fixture embeds an email AND a DID in `message`, so the
/// later per-SDK AC9/AC10 redaction tests have a stand-in to exercise. Guards
/// against the corpus silently losing that fixture.
#[test]
fn at_least_one_fixture_carries_email_and_did_for_redaction() {
    let file = load();
    let has_pii_fixture = file.fixtures.iter().any(|f| {
        let m = &f.message;
        m.contains('@') && m.contains('.') && m.contains("did:")
    });
    assert!(
        has_pii_fixture,
        "no valid fixture message carries both an email and a DID (AC9/AC10 stand-in)"
    );
}

/// The malformed corpus: one detail-shape mismatch per class, each rejected at
/// the `errors.rs` construction/validation boundary with `DetailShapeMismatch`.
/// This is the Rust side of the per-SDK AC10 rejection contract.
#[test]
fn malformed_detail_fixtures_are_rejected_at_construction() {
    let file = load();
    assert_eq!(
        file.malformed.len(),
        8,
        "expected one malformed-detail fixture per class (8 classes)"
    );

    let mut classes = BTreeSet::new();
    for f in &file.malformed {
        assert!(
            f.malformed,
            "malformed fixture {} missing malformed flag",
            f.name
        );
        classes.insert(f.class);

        // The detail's kind genuinely disagrees with the class's expected shape.
        assert_ne!(
            f.class.expected_detail(),
            f.detail.kind(),
            "malformed fixture {} is not actually a shape mismatch",
            f.name
        );

        // The code/slug/class triple itself is a VALID, registry-consistent
        // triple (so construction reaches the detail-shape gate rather than
        // failing earlier), but the wrong-shaped detail is rejected.
        match construct(f) {
            Err(OutletErrorConstructionFailed::DetailShapeMismatch { class, actual }) => {
                assert_eq!(class, f.class, "malformed fixture {}", f.name);
                assert_eq!(actual, f.detail.kind(), "malformed fixture {}", f.name);
            }
            other => panic!(
                "malformed fixture {}: expected DetailShapeMismatch, got {other:?}",
                f.name
            ),
        }
    }

    // All eight §5.4.4 classes are exercised by the malformed corpus.
    assert_eq!(
        classes.len(),
        8,
        "malformed corpus must cover all eight OutletErrorClass variants, covered: {classes:?}"
    );
}

/// The supplementary corpus: the top cross-SDK round-trip hazards. Each is
/// registry-consistent and constructs cleanly through the `errors.rs` boundary
/// with its field values preserved exactly. They are NOT part of the
/// per-(code,slug) bijection (their pairs already appear in `fixtures`), so the
/// coverage assertion tolerates them — this test is where they earn their keep.
#[test]
fn supplementary_hazard_fixtures_round_trip_with_exact_field_fidelity() {
    let file = load();
    assert_eq!(
        file.supplementary.len(),
        2,
        "expected the two documented cross-SDK hazard fixtures"
    );

    let mut saw_panic_hash = false;
    let mut saw_large_u64 = false;

    for f in &file.supplementary {
        assert!(
            f.supplementary,
            "supplementary fixture {} missing supplementary flag",
            f.name
        );
        // Registry-consistent triple.
        assert_eq!(
            error_code_to_class(&f.code),
            Some(f.class),
            "supplementary fixture {}: code→class mismatch",
            f.name
        );
        assert_eq!(
            slug_to_class(&f.slug),
            Some(f.class),
            "supplementary fixture {}: slug→class mismatch",
            f.name
        );

        // Constructs cleanly and preserves the detail exactly.
        let env = construct(f).unwrap_or_else(|e| {
            panic!(
                "supplementary fixture {}: OutletError::new rejected it: {e:?}",
                f.name
            )
        });
        assert_eq!(env.detail.as_ref(), Some(&f.detail), "fixture {}", f.name);

        match &f.detail {
            // Hazard 1: the ONLY fixed-length-byte-array + custom-serde detail
            // variant — the 32-byte hash must survive JSON → DetailBody exactly.
            DetailBody::ExecutionPanic {
                panic_location_hash,
            } => {
                let expected: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
                assert_eq!(
                    *panic_location_hash, expected,
                    "supplementary panic-hash fixture: 32-byte hash corrupted through JSON"
                );
                saw_panic_hash = true;
            }
            // Hazard 2: a u64 > 2^53 must survive exactly (the value that forces
            // BigInt handling in JS SDKs; Rust must not truncate it either).
            DetailBody::ExecutionTimeout { elapsed_ms } => {
                assert!(
                    *elapsed_ms > (1u64 << 53),
                    "supplementary large-u64 fixture must exceed 2^53"
                );
                assert_eq!(
                    *elapsed_ms, 9_007_199_254_740_993,
                    "supplementary large-u64 fixture: elapsed_ms corrupted (2^53 + 1 expected)"
                );
                saw_large_u64 = true;
            }
            other => panic!("unexpected supplementary detail variant: {other:?}"),
        }
    }

    assert!(
        saw_panic_hash,
        "missing the 32-byte ExecutionPanic hash hazard fixture"
    );
    assert!(saw_large_u64, "missing the >2^53 u64 hazard fixture");
}
