//! Canonical tool-ID derivation shared by all FFI bridges.
//!
//! Every bridge (`PyO3`, `napi-rs`, `UniFFI`) used to inline the same
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
/// Contract (pinned by `OP_TOOL_REGISTER` across all three bridges):
///
/// * Prepends the literal prefix `tool-`.
/// * Splits on Unicode whitespace (`str::split_whitespace`) — ASCII
///   space, tab, newline, NBSP (U+00A0), ideographic space (U+3000),
///   etc. — collapses consecutive whitespace to a single hyphen, and
///   trims leading/trailing whitespace.
/// * Rejoins tokens with `-`.
/// * Full Unicode lowercase via `str::to_lowercase`.
///
/// The previous implementation (`name.replace(' ', "-")`) was ASCII-only:
/// `"Search\u{A0}Tool"` (NBSP) would round-trip as `"tool-search\u{A0}tool"`
/// and collide with other systems that Unicode-normalise whitespace
/// upstream. Unicode-splitting makes the derivation identifier-stable
/// across the full whitespace character class at the cost of a silent
/// collapse of consecutive ASCII spaces (`"a  b"` → `"tool-a-b"`, was
/// `"tool-a--b"`). The parity gate (`OP_TOOL_REGISTER`) continues to
/// pin the ASCII happy path byte-exactly.
///
/// Provenance: `.docs/adrs/ADR-046-bridge-parity-harness.md`
/// adversarial round 12 MINOR-5.
#[must_use]
pub fn generate_tool_id(name: &str) -> String {
    let joined = name.split_whitespace().collect::<Vec<_>>().join("-");
    format!("tool-{}", joined.to_lowercase())
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

    #[test]
    fn unicode_whitespace_splits_like_ascii_space() {
        // NBSP (U+00A0) between words — was previously passed through
        // unchanged (silent cross-system divergence when another layer
        // Unicode-normalises whitespace). Now splits the same as a
        // regular space.
        assert_eq!(generate_tool_id("Search\u{A0}Tool"), "tool-search-tool");
        // Ideographic space (U+3000) + mixed Unicode whitespace.
        assert_eq!(generate_tool_id("My\u{3000}Tool"), "tool-my-tool");
    }

    #[test]
    fn consecutive_whitespace_collapses_to_single_hyphen() {
        assert_eq!(generate_tool_id("a  b"), "tool-a-b");
        assert_eq!(generate_tool_id("a\t b"), "tool-a-b");
    }

    #[test]
    fn leading_and_trailing_whitespace_is_stripped() {
        assert_eq!(generate_tool_id("  padded  "), "tool-padded");
    }

    #[test]
    fn unicode_case_is_folded() {
        // `str::to_lowercase` is Unicode-aware.
        assert_eq!(generate_tool_id("Ça Ira"), "tool-ça-ira");
    }
}
