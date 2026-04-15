#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_fuzz::ArbAadInput;
use scp_protocol::crypto::sender_keys::build_sender_aad_for_testing;

fuzz_target!(|input: ArbAadInput| {
    // Convert byte vecs to UTF-8 strings; skip if not valid UTF-8.
    let Ok(ctx_a) = std::str::from_utf8(&input.a_context_id) else {
        return;
    };
    let Ok(did_a) = std::str::from_utf8(&input.a_sender_did) else {
        return;
    };
    let Ok(ctx_b) = std::str::from_utf8(&input.b_context_id) else {
        return;
    };
    let Ok(did_b) = std::str::from_utf8(&input.b_sender_did) else {
        return;
    };

    // If the two (context_id, sender_did, epoch, seq) tuples are identical,
    // AADs will be equal and no invariant to assert.
    let inputs_differ = ctx_a != ctx_b
        || did_a != did_b
        || input.a_epoch != input.b_epoch
        || input.a_seq != input.b_seq;

    if !inputs_differ {
        return;
    }

    let aad_a = build_sender_aad_for_testing(ctx_a, did_a, input.a_epoch, input.a_seq);
    let aad_b = build_sender_aad_for_testing(ctx_b, did_b, input.b_epoch, input.b_seq);

    assert_ne!(
        aad_a, aad_b,
        "security invariant I9 violated: different (context_id, sender_did, \
         epoch, seq) tuples produced identical AAD bytes \
         (ciphertext relocation across contexts possible)"
    );
});
