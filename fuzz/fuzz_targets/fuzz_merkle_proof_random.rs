#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Random-proof no-panic fuzz target for `verify_inclusion` (Tier 3).
//!
//! Strategy: feed a random (adversarially mutated) `InclusionProof` into
//! `verify_inclusion` and assert it does not panic. For random proofs the
//! probability of the check returning `true` is approximately 2^-256, so this
//! target only catches panics and unexpected crashes on adversarial inputs —
//! not the second-preimage invariant, which is exercised by `fuzz_merkle_proof`.
//!
//! Security invariants verified:
//! - I1: `verify_inclusion` never panics on any input.

use libfuzzer_sys::fuzz_target;
use scp_event_log::proof::verify_inclusion;
use scp_fuzz::ArbInclusionProof;

fuzz_target!(|arb: ArbInclusionProof| {
    // I1: no panic on any input — result is intentionally discarded.
    let _ = verify_inclusion(&arb.into());
});
