#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_protocol::envelope::InnerEnvelope;
use scp_protocol::envelope::inner::compute_canonical_hash;
use scp_protocol::envelope::InnerEnvelopeParams;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Split the input at the midpoint and try to deserialize two envelopes.
    let mid = data.len() / 2;
    let (left, right) = data.split_at(mid);

    let Ok(env_a) = InnerEnvelope::from_bytes(left) else {
        return;
    };
    let Ok(env_b) = InnerEnvelope::from_bytes(right) else {
        return;
    };

    // If the two envelopes have identical canonical inputs, their hashes
    // should be the same (and we make no assertion). If they differ, the
    // hashes MUST differ (security invariant I10: no hash collision for
    // different InnerEnvelopeParams).
    //
    // We compare the key fields that enter the canonical hash.
    let inputs_differ = env_a.context_id != env_b.context_id
        || env_a.sender_did != env_b.sender_did
        || env_a.epoch != env_b.epoch
        || env_a.generation != env_b.generation
        || env_a.sequence != env_b.sequence
        || env_a.timestamp != env_b.timestamp
        || env_a.message_type != env_b.message_type
        || env_a.payload_hash != env_b.payload_hash
        || env_a.provenance_hash != env_b.provenance_hash
        || env_a.version != env_b.version
        || env_a.signing_key_id != env_b.signing_key_id;

    if !inputs_differ {
        return;
    }

    let params_a = InnerEnvelopeParams {
        version: env_a.version,
        context_id: &env_a.context_id,
        sender_did: &env_a.sender_did,
        epoch: env_a.epoch,
        generation: env_a.generation,
        sequence: env_a.sequence,
        timestamp: env_a.timestamp,
        message_type: env_a.message_type,
        payload: &env_a.payload,
        provenance: env_a.provenance.clone(),
        signing_key_id: env_a.signing_key_id,
    };

    let params_b = InnerEnvelopeParams {
        version: env_b.version,
        context_id: &env_b.context_id,
        sender_did: &env_b.sender_did,
        epoch: env_b.epoch,
        generation: env_b.generation,
        sequence: env_b.sequence,
        timestamp: env_b.timestamp,
        message_type: env_b.message_type,
        payload: &env_b.payload,
        provenance: env_b.provenance.clone(),
        signing_key_id: env_b.signing_key_id,
    };

    let hash_a = compute_canonical_hash(&params_a, &env_a.payload_hash, &env_a.provenance_hash);
    let hash_b = compute_canonical_hash(&params_b, &env_b.payload_hash, &env_b.provenance_hash);

    assert_ne!(
        hash_a, hash_b,
        "security invariant I10 violated: different InnerEnvelopeParams \
         produced identical canonical hash (signature transferability risk)"
    );
});
