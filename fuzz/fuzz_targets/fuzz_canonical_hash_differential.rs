#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Canonical hash differential fuzz target (Tier 3 — T14).
//!
//! Security invariant I10: for any two distinct sets of `InnerEnvelopeParams`
//! fields, `compute_canonical_hash` MUST produce distinct outputs. A collision
//! would allow signature transferability — a signature over one envelope could
//! be reused for a different envelope with different semantics.
//!
//! # Previous approach and its problem
//!
//! The original target split raw bytes at a midpoint and tried to deserialize
//! two `InnerEnvelope`s. Random bytes almost never produce valid `MessagePack`
//! `InnerEnvelope`s, so the differential assertion rarely fired.
//!
//! # This approach
//!
//! `ArbCanonicalHashInput` generates two independent sets of envelope fields
//! directly via `Arbitrary`. Both sets always reach `compute_canonical_hash`,
//! so the mutation engine gets useful signal on every input.

use libfuzzer_sys::fuzz_target;
use scp_fuzz::ArbCanonicalHashInput;
use scp_primitives::SigningKeyId;
use scp_protocol::envelope::InnerEnvelopeParams;
use scp_protocol::envelope::inner::compute_canonical_hash;

fuzz_target!(|input: ArbCanonicalHashInput| {
    // Convert bounded byte arrays to &str, skipping non-UTF-8 inputs.
    // Using `from_utf8` on the full array means the fuzzer can explore both
    // the "non-UTF-8 → skip" and "valid UTF-8 → hash differs" paths.
    let Ok(ctx_a) = std::str::from_utf8(&input.a.context_id) else {
        return;
    };
    let Ok(did_a) = std::str::from_utf8(&input.a.sender_did) else {
        return;
    };
    let Ok(ctx_b) = std::str::from_utf8(&input.b.context_id) else {
        return;
    };
    let Ok(did_b) = std::str::from_utf8(&input.b.sender_did) else {
        return;
    };

    let msg_type_a: scp_protocol::envelope::MessageType = input.a.message_type.clone().into();
    let msg_type_b: scp_protocol::envelope::MessageType = input.b.message_type.clone().into();

    // Build InnerEnvelopeParams for both sides.
    // `signing_key_id` is fixed to `Active` on both sides intentionally:
    // we want the other fields to drive hash differences. Signing key
    // differentiation is covered separately by canonical hash field coverage.
    let params_a = InnerEnvelopeParams {
        version: input.a.version,
        context_id: ctx_a,
        sender_did: did_a,
        epoch: input.a.epoch,
        generation: input.a.generation,
        sequence: input.a.sequence,
        timestamp: input.a.timestamp,
        message_type: msg_type_a,
        payload: &[],
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    };

    let params_b = InnerEnvelopeParams {
        version: input.b.version,
        context_id: ctx_b,
        sender_did: did_b,
        epoch: input.b.epoch,
        generation: input.b.generation,
        sequence: input.b.sequence,
        timestamp: input.b.timestamp,
        message_type: msg_type_b,
        payload: &[],
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    };

    // Determine whether the canonical inputs actually differ. We compare
    // all fields that enter the canonical hash (spec §13.2.1): version,
    // message_type, context_id, sender_did, epoch, generation, sequence,
    // timestamp, payload_hash, provenance_hash, signing_key_id.
    //
    // `signing_key_id` is always `Active` on both sides here, so it does not
    // contribute to differences in this target. `provenance` is always `None`
    // on both sides, so `provenance_hash` is also equal. Therefore we compare
    // the remaining fields.
    let inputs_differ = input.a.version != input.b.version
        || ctx_a != ctx_b
        || did_a != did_b
        || input.a.epoch != input.b.epoch
        || input.a.generation != input.b.generation
        || input.a.sequence != input.b.sequence
        || input.a.timestamp != input.b.timestamp
        || input.a.payload_hash != input.b.payload_hash
        || input.a.provenance_hash != input.b.provenance_hash
        || msg_type_a.as_discriminator_byte() != msg_type_b.as_discriminator_byte();

    if !inputs_differ {
        return;
    }

    let hash_a = compute_canonical_hash(&params_a, &input.a.payload_hash, &input.a.provenance_hash);
    let hash_b = compute_canonical_hash(&params_b, &input.b.payload_hash, &input.b.provenance_hash);

    assert_ne!(
        hash_a, hash_b,
        "security invariant I10 violated: different InnerEnvelopeParams \
         produced identical canonical hash (signature transferability risk)"
    );
});
