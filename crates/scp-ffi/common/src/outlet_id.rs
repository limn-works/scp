//! Canonical outlet-ID derivation shared by all FFI bridges.
//!
//! Every bridge (`PyO3`, `napi-rs`, `UniFFI`) used to inline the same
//! `format!("outlet-{}", name.replace(' ', "-").to_lowercase())` expression.
//! The cross-bridge parity harness (`OP_OUTLET_REGISTER` in
//! `bindings/python/tests/bridge_parity/seed_operations.py`) pins the
//! derivation as a spec-level commitment; keeping the expression in one
//! place removes the "three bridges migrate, one drifts" failure mode
//! called out as MINOR-3 in the round-11 adversarial review.
//!
//! Provenance: `.docs/adrs/ADR-046-bridge-parity-harness.md` round 11
//! MINOR-3 (adversarial).

/// Derives the canonical outlet ID from a user-supplied outlet name.
///
/// Contract (pinned by `OP_OUTLET_REGISTER` across all three bridges):
///
/// * Prepends the literal prefix `outlet-`.
/// * Splits on Unicode whitespace (`str::split_whitespace`) — ASCII
///   space, tab, newline, NBSP (U+00A0), ideographic space (U+3000),
///   etc. — collapses consecutive whitespace to a single hyphen, and
///   trims leading/trailing whitespace.
/// * Rejoins tokens with `-`.
/// * Full Unicode lowercase via `str::to_lowercase`.
///
/// The previous implementation (`name.replace(' ', "-")`) was ASCII-only:
/// `"Search\u{A0}Outlet"` (NBSP) would round-trip as `"outlet-search\u{A0}outlet"`
/// and collide with other systems that Unicode-normalise whitespace
/// upstream. Unicode-splitting makes the derivation identifier-stable
/// across the full whitespace character class at the cost of a silent
/// collapse of consecutive ASCII spaces (`"a  b"` → `"outlet-a-b"`, was
/// `"outlet-a--b"`). The parity gate (`OP_OUTLET_REGISTER`) continues to
/// pin the ASCII happy path byte-exactly.
///
/// Provenance: `.docs/adrs/ADR-046-bridge-parity-harness.md`
/// adversarial round 12 MINOR-5.
#[must_use]
pub fn generate_outlet_id(name: &str) -> String {
    let joined = name.split_whitespace().collect::<Vec<_>>().join("-");
    format!("outlet-{}", joined.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_pinned_parity_vector() {
        // Mirrors `OP_OUTLET_REGISTER` in the Python harness:
        // `_OUTLET_NAME = "parity_probe"`, `_EXPECTED_OUTLET_ID = "outlet-parity_probe"`.
        assert_eq!(generate_outlet_id("parity_probe"), "outlet-parity_probe");
    }

    #[test]
    fn spaces_become_hyphens_and_case_is_folded() {
        assert_eq!(generate_outlet_id("My Outlet"), "outlet-my-outlet");
        assert_eq!(generate_outlet_id("ALREADY_UPPER"), "outlet-already_upper");
    }

    #[test]
    fn empty_name_is_outlet_prefix_only() {
        assert_eq!(generate_outlet_id(""), "outlet-");
    }

    #[test]
    fn unicode_whitespace_splits_like_ascii_space() {
        // NBSP (U+00A0) between words — was previously passed through
        // unchanged (silent cross-system divergence when another layer
        // Unicode-normalises whitespace). Now splits the same as a
        // regular space.
        assert_eq!(
            generate_outlet_id("Search\u{A0}Outlet"),
            "outlet-search-outlet"
        );
        // Ideographic space (U+3000) + mixed Unicode whitespace.
        assert_eq!(generate_outlet_id("My\u{3000}Outlet"), "outlet-my-outlet");
    }

    #[test]
    fn consecutive_whitespace_collapses_to_single_hyphen() {
        assert_eq!(generate_outlet_id("a  b"), "outlet-a-b");
        assert_eq!(generate_outlet_id("a\t b"), "outlet-a-b");
    }

    #[test]
    fn leading_and_trailing_whitespace_is_stripped() {
        assert_eq!(generate_outlet_id("  padded  "), "outlet-padded");
    }

    #[test]
    fn unicode_case_is_folded() {
        // `str::to_lowercase` is Unicode-aware.
        assert_eq!(generate_outlet_id("Ça Ira"), "outlet-ça-ira");
    }
}
