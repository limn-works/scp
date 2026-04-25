//! Outlet capability stem parser conformance vectors (SCP-OUT-014).
//!
//! Validates the canonical parse fixtures at
//! `tests/conformance/vectors/outlet_capability_parse.json` against the
//! Rust-core reference implementation
//! [`scp_protocol::context::roles::Capability::new`].
//!
//! The fixture documents ≥ 20 positive (must parse) and ≥ 20 negative (must
//! reject as `None`) cases for the §5.4.2.1 two-step parser:
//!
//! 1. Literal byte-match of `outlet_query:` / `outlet_call:` (or their
//!    SDK-facing `outlet:query:` / `outlet:call:` aliases).
//! 2. Opaque suffix matching `^[a-z0-9_-]{1,128}$` or the wildcard `*`.
//!
//! Every bridge (PyO3, NAPI, UniFFI Swift, UniFFI Kotlin, WASM) consumes the
//! same fixture file in its own conformance suite. Divergence between
//! bridges is a parser-differential bug — it would allow authorization-class
//! confusion (e.g., a delegation that parses to `Custom("outlet:invoke:foo")`
//! in one runtime and `None` in another).
//!
//! # Spec references
//!
//! - `.docs/specs/05-contexts.md` §5.4.2 Outlet Classification
//! - `.docs/specs/05-contexts.md` §5.4.2.1 UCAN Capability Stem Parser
//! - `.docs/adrs/ADR-049-outlet-redesign.md` §1 Rename hard break, §2
//!   `OutletKind` split

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use scp_core::context::roles::Capability;
use serde::{Deserialize, Serialize};

/// Expected positive parse outcome for a fixture entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedPositive {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositiveVector {
    pub input: String,
    pub expected: ExpectedPositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeVector {
    pub input: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletCapabilityParseFixture {
    pub version: String,
    pub spec_section: String,
    pub adr: String,
    pub story: String,
    pub description: String,
    pub rules: Vec<String>,
    pub positive: Vec<PositiveVector>,
    pub negative: Vec<NegativeVector>,
}

/// Path to the canonical fixture file relative to the workspace root.
#[must_use]
pub fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // workspace root
    p.push("tests");
    p.push("conformance");
    p.push("vectors");
    p.push("outlet_capability_parse.json");
    p
}

/// Loads the fixture from disk.
#[must_use]
pub fn load_fixture() -> OutletCapabilityParseFixture {
    let path = fixture_path();
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    serde_json::from_slice::<OutletCapabilityParseFixture>(&bytes)
        .unwrap_or_else(|e| panic!("parse fixture {}: {e}", path.display()))
}

/// Maps a positive expected variant to a [`Capability`] value.
#[must_use]
pub fn expected_to_capability(expected: &ExpectedPositive) -> Capability {
    match expected.kind.as_str() {
        "MessagesRead" => Capability::MessagesRead,
        "MessagesWrite" => Capability::MessagesWrite,
        "OutletQuery" => {
            let id = expected.id.as_ref().expect("OutletQuery requires id");
            Capability::OutletQuery(id.clone())
        }
        "OutletQueryAll" => Capability::OutletQueryAll,
        "OutletCall" => {
            let id = expected.id.as_ref().expect("OutletCall requires id");
            Capability::OutletCall(id.clone())
        }
        "OutletCallAll" => Capability::OutletCallAll,
        "OutletRegister" => Capability::OutletRegister,
        "MemberInvite" => Capability::MemberInvite,
        "MemberRemove" => Capability::MemberRemove,
        "RoleAssign" => Capability::RoleAssign,
        "GovernancePropose" => Capability::GovernancePropose,
        "GovernanceVote" => Capability::GovernanceVote,
        "ContextClose" => Capability::ContextClose,
        "ChildContextCreate" => Capability::ChildContextCreate,
        "OutletInterface" => Capability::OutletInterface,
        "Bridging" => Capability::Bridging,
        "MediaVoice" => Capability::MediaVoice,
        "MediaVideo" => Capability::MediaVideo,
        "MediaScreenShare" => Capability::MediaScreenShare,
        "MemberBan" => Capability::MemberBan,
        "MetadataEdit" => Capability::MetadataEdit,
        "Custom" => {
            let name = expected.name.as_ref().expect("Custom requires name");
            Capability::Custom(name.clone())
        }
        other => panic!("unknown expected variant kind: {other}"),
    }
}

/// Validates every positive vector against [`Capability::new`].
pub fn assert_positive_vectors(fixture: &OutletCapabilityParseFixture) {
    for v in &fixture.positive {
        let actual = Capability::new(&v.input);
        let expected = expected_to_capability(&v.expected);
        assert_eq!(
            actual.as_ref(),
            Some(&expected),
            "positive fixture failed: input={:?} expected={:?} got={:?}",
            v.input,
            expected,
            actual
        );
    }
}

/// Validates every negative vector against [`Capability::new`].
pub fn assert_negative_vectors(fixture: &OutletCapabilityParseFixture) {
    for v in &fixture.negative {
        let actual = Capability::new(&v.input);
        assert!(
            actual.is_none(),
            "negative fixture must reject: input={:?} reason={:?} but got Some({:?})",
            v.input,
            v.reason,
            actual
        );
    }
}

/// Top-level conformance entry point — validates BOTH the fixture cardinality
/// (≥ 20 positive, ≥ 20 negative per AC) and every individual vector.
pub fn conf_outlet_capability_parse() {
    let fixture = load_fixture();
    assert!(
        fixture.positive.len() >= 20,
        "AC violation: positive vectors must be >= 20 (got {})",
        fixture.positive.len()
    );
    assert!(
        fixture.negative.len() >= 20,
        "AC violation: negative vectors must be >= 20 (got {})",
        fixture.negative.len()
    );
    assert_positive_vectors(&fixture);
    assert_negative_vectors(&fixture);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_loads() {
        let fixture = load_fixture();
        assert_eq!(fixture.story, "SCP-OUT-014");
        assert!(!fixture.positive.is_empty());
        assert!(!fixture.negative.is_empty());
    }

    #[test]
    fn positive_vectors_parse() {
        let fixture = load_fixture();
        assert_positive_vectors(&fixture);
    }

    #[test]
    fn negative_vectors_reject() {
        let fixture = load_fixture();
        assert_negative_vectors(&fixture);
    }

    #[test]
    fn cardinality_meets_ac() {
        let fixture = load_fixture();
        assert!(fixture.positive.len() >= 20);
        assert!(fixture.negative.len() >= 20);
    }

    #[test]
    fn full_conformance() {
        conf_outlet_capability_parse();
    }
}
