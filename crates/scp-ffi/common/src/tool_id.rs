//! Canonical tool-ID derivation shared by all FFI bridges.
//!
//! Every bridge (`PyO3`, `napi-rs`, `UniFFI`, WASM) used to inline the same
//! `format!("tool-{}", name.replace(' ', "-").to_lowercase())` expression.
//! The cross-bridge parity harness (`OP_TOOL_REGISTER` in
//! `bindings/python/tests/bridge_parity/seed_operations.py`) pins the
//! derivation as a spec-level commitment; keeping the expression in one
//! place removes the "three bridges migrate, one drifts" failure mode
//! called out as MINOR-3 in the round-11 adversarial review.
//!
//! Provenance: `.docs/adrs/ADR-046-bridge-parity-harness.md` round 11
//! MINOR-3 (adversarial).

/// Derives the canonical tool ID from a user-supplied tool name.
///
/// Contract (pinned by `OP_TOOL_REGISTER` across all four bridges):
///
/// * Prepends the literal prefix `tool-`.
/// * Replaces every ASCII space with `-`.
/// * Lowercases the whole string (ASCII-case).
///
/// Non-ASCII whitespace and other characters pass through unchanged —
/// the parity gate only exercises ASCII inputs, and widening the
/// character class here would be a silent cross-bridge divergence.
#[must_use]
pub fn generate_tool_id(name: &str) -> String {
    format!("tool-{}", name.replace(' ', "-").to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_pinned_parity_vector() {
        // Mirrors `OP_TOOL_REGISTER` in the Python harness:
        // `_TOOL_NAME = "parity_probe"`, `_EXPECTED_TOOL_ID = "tool-parity_probe"`.
        assert_eq!(generate_tool_id("parity_probe"), "tool-parity_probe");
    }

    #[test]
    fn spaces_become_hyphens_and_case_is_folded() {
        assert_eq!(generate_tool_id("My Tool"), "tool-my-tool");
        assert_eq!(generate_tool_id("ALREADY_UPPER"), "tool-already_upper");
    }

    #[test]
    fn empty_name_is_tool_prefix_only() {
        assert_eq!(generate_tool_id(""), "tool-");
    }
}
