#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_fuzz::ArbAadInput;

/// Replicates `scp_protocol::crypto::sender_keys::encrypt::build_sender_aad`,
/// which is `pub(crate)` and cannot be called directly from an external crate.
///
/// The format is: 4-byte BE context_id length + context_id bytes +
///                4-byte BE sender_did length + sender_did bytes +
///                8-byte BE epoch + 8-byte BE sequence.
///
/// See `scp-protocol/src/crypto/sender_keys/encrypt.rs` for the authoritative
/// definition. If that function changes, this replica MUST be updated to match.
fn build_aad(context_id: &str, sender_did: &str, epoch: u64, seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        4 + context_id.len() + 4 + sender_did.len() + 8 + 8,
    );
    aad.extend_from_slice(&(context_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(context_id.as_bytes());
    aad.extend_from_slice(&(sender_did.len() as u32).to_be_bytes());
    aad.extend_from_slice(sender_did.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

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

    let aad_a = build_aad(ctx_a, did_a, input.a_epoch, input.a_seq);
    let aad_b = build_aad(ctx_b, did_b, input.b_epoch, input.b_seq);

    assert_ne!(
        aad_a, aad_b,
        "security invariant I9 violated: different (context_id, sender_did, \
         epoch, seq) tuples produced identical AAD bytes \
         (ciphertext relocation across contexts possible)"
    );
});
