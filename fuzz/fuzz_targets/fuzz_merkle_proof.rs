#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_event_log::proof::verify_inclusion;
use scp_fuzz::ArbInclusionProof;

fuzz_target!(|arb: ArbInclusionProof| {
    let proof = arb.clone().into_proof();

    // I1: no panic on any input.
    let result = verify_inclusion(&proof);

    // For random proofs the result is almost always false. That's expected.
    // We DO assert the invariant that flipping one byte in any sibling hash
    // must change the verification result whenever the original verified.
    if result && !proof.path.is_empty() {
        let mut mutated = arb.into_proof();
        // Flip the first byte of the first sibling hash.
        mutated.path[0].sibling_hash[0] ^= 0xff;
        let mutated_result = verify_inclusion(&mutated);
        assert!(
            !mutated_result,
            "security invariant violated: single-byte flip in sibling hash \
             did not change verify_inclusion result (collision risk)"
        );
    }
});
