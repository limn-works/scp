#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! UCAN capability stem parser fuzz target (SCP-OUT-014, Tier 2).
//!
//! Exercises [`scp_protocol::context::roles::Capability::new`] with arbitrary
//! UTF-8 input. The parser implements the \u00a75.4.2.1 two-step algorithm:
//!
//! 1. Literal byte-match of `outlet_query:` / `outlet_call:` (and SDK-facing
//!    `outlet:query:` / `outlet:call:` aliases) plus the deleted-stem
//!    rejection set.
//! 2. Opaque suffix matching `^[a-z0-9_-]{1,128}$` or the wildcard `*`.
//!
//! Invariants verified:
//! - I1: `Capability::new` never panics on any string input.
//! - Hard-break: `outlet:invoke:*`, `outlet_invoke:*`, and any string with
//!   the `outlet:invoke:` / `outlet_invoke:` / `tool:invoke:` / `tool_invoke:`
//!   prefix MUST return `None` (ADR-049 \u00a71, SCP-OUT-014).
//! - Suffix bounds: when the result is `Some(OutletQuery(id))` /
//!   `Some(OutletCall(id))`, the inner `id` must be non-empty, \u2264 128 bytes,
//!   and contain only `[a-z0-9_-]` bytes.
//! - Round-trip: a `Some(_)` result must serialize via `Display` to a string
//!   that re-parses to the same variant (parser-differential guard).
//! - Cross-form equivalence: parsing `outlet_query:foo` and
//!   `outlet:query:foo` must yield the same `OutletQuery("foo")` variant.

use libfuzzer_sys::fuzz_target;
use scp_protocol::context::roles::Capability;

fn assert_invariants(input: &str, parsed: &Capability) {
    // Hard-break: deleted stems must NEVER produce a Capability.
    assert!(!input.starts_with("outlet:invoke:"));
    assert!(!input.starts_with("outlet_invoke:"));
    assert!(input != "outlet:invoke:*");
    assert!(input != "outlet_invoke:*");
    assert!(!input.starts_with("tool:invoke:"));
    assert!(!input.starts_with("tool_invoke:"));

    // Suffix bounds for parameterized outlet variants.
    if let Capability::OutletQuery(id) | Capability::OutletCall(id) = parsed {
        assert!(!id.is_empty(), "outlet id must not be empty");
        assert!(id.len() <= 128, "outlet id must be <= 128 bytes");
        for b in id.bytes() {
            assert!(
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-',
                "outlet id must match [a-z0-9_-], got byte 0x{b:02x}"
            );
        }
    }

    // Round-trip: Display output must re-parse to the same variant
    // (parser-differential guard \u2014 every accepted form must be canonical).
    let displayed = parsed.to_string();
    let reparsed = Capability::new(&displayed);
    assert_eq!(
        reparsed.as_ref(),
        Some(parsed),
        "Display round-trip failed: input={input:?} -> parsed={parsed:?} -> displayed={displayed:?} -> reparsed={reparsed:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    // Capability::new takes an `impl AsRef<str>` \u2014 valid UTF-8 only.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // I1: never panic.
    let parsed = Capability::new(s);

    if let Some(ref cap) = parsed {
        assert_invariants(s, cap);
    }

    // Cross-form equivalence: if the input has the `outlet_query:` /
    // `outlet_call:` wire prefix and parses, the SDK-facing colon form must
    // parse to the same variant.
    for (wire, sdk) in [
        ("outlet_query:", "outlet:query:"),
        ("outlet_call:", "outlet:call:"),
    ] {
        if let Some(rest) = s.strip_prefix(wire) {
            let alt = format!("{sdk}{rest}");
            let alt_parsed = Capability::new(&alt);
            assert_eq!(
                parsed.as_ref(),
                alt_parsed.as_ref(),
                "wire/SDK form differential: wire={s:?} -> {parsed:?}, sdk={alt:?} -> {alt_parsed:?}"
            );
        }
    }
});
