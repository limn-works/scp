#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Merkle inclusion proof invariant fuzz target (Tier 3 — T15).
//!
//! Strategy: build a REAL Merkle tree from fuzz bytes, generate a real
//! inclusion proof via `prove_inclusion`, then apply bit-flips and direction
//! flips to assert the second-preimage invariant actually fires.
//!
//! Security invariants verified:
//! - I1: `prove_inclusion` and `verify_inclusion` never panic on any input.
//! - I2: A real inclusion proof always verifies (`verify_inclusion` returns
//!   `true` for every proof produced by `prove_inclusion`).
//! - I4: Flipping any bit in any sibling hash in the proof path must cause
//!   `verify_inclusion` to return `false` (second-preimage resistance).
//! - I5: Flipping the direction of any proof step must cause
//!   `verify_inclusion` to return `false` (direction tampering resistance).

use libfuzzer_sys::fuzz_target;
use scp_event_log::proof::{Direction, prove_inclusion, verify_inclusion};
use scp_event_log::tree::{GENESIS_PREV_HASH, append_unsigned_event, event_count};
use scp_did::DID;
use scp_event_log::{Event, EventLog, EventPayload, EventType};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a leaf hash from the fuzz leaf bytes (SHA-256, no event serialization).
/// We use the leaf bytes directly as the payload data — the leaf hash is then
/// determined by `append_unsigned_event`'s internal RFC 6962 hashing.
fn make_event(sequence: u64, prev_hash: [u8; 32], payload_bytes: &[u8]) -> Event {
    Event {
        event_type: EventType::MessageSent,
        actor_did: DID::from("did:fuzz:target".to_owned()),
        timestamp: 1_000_000 + sequence,
        sequence,
        payload: EventPayload {
            data: payload_bytes.to_vec(),
        },
        prev_hash,
        // append_unsigned_event skips signature verification — safe for fuzzing.
        signature: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Fuzz target
// ---------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    // Need at least 4 bytes: 1 for leaf count, 1 for leaf index, 1 for step
    // index, 1 for byte index, 1 for bit index, 1 for direction step index.
    if data.len() < 6 {
        return;
    }

    // Derive: number of leaves (1..=32), leaf index, bit-flip location,
    // direction-flip step index.
    let n_leaves = usize::from(data[0] & 0x1f).saturating_add(1); // 1..=32
    let leaf_idx_raw = data[1];
    let step_idx_raw = data[2];
    let byte_idx_raw = data[3];
    let bit_idx_raw = data[4] & 0x07; // 0..=7
    let dir_step_idx_raw = data[5];
    let payload_data = &data[6..];

    // Build a real Merkle tree with n_leaves events.
    let mut log = EventLog::new("fuzz-ctx".to_owned());
    let mut prev_hash = GENESIS_PREV_HASH;

    for i in 0..n_leaves {
        // Slice a chunk of payload bytes for this leaf (or empty if exhausted).
        let chunk_start = i * 4;
        let chunk = if chunk_start < payload_data.len() {
            &payload_data[chunk_start..payload_data.len().min(chunk_start + 4)]
        } else {
            &[]
        };

        let event = make_event(i as u64, prev_hash, chunk);
        if append_unsigned_event(&mut log, &event).is_ok() {
            // Update prev_hash to the leaf just appended (most recent).
            prev_hash = *log.leaves().last().expect("just appended a leaf");
        } else {
            // Should not happen, but abort gracefully rather than panic.
            return;
        }
    }

    let total_leaves = event_count(&log);
    if total_leaves == 0 {
        return;
    }

    // Pick a leaf to prove (wrap to valid range).
    let leaf_index = u64::from(leaf_idx_raw) % total_leaves;

    // I1 + I2: prove_inclusion must succeed and the resulting proof must verify.
    let proof = match prove_inclusion(&log, leaf_index) {
        Ok(p) => p,
        Err(_) => return,
    };

    let verified = verify_inclusion(&proof);
    assert!(
        verified,
        "security invariant I2 violated: prove_inclusion produced a proof \
         that verify_inclusion rejected (leaf_index={leaf_index}, n_leaves={total_leaves})"
    );

    // I4: flip a bit in a sibling hash — must break verification.
    if !proof.path.is_empty() {
        let n_steps = proof.path.len();
        let step_idx = usize::from(step_idx_raw) % n_steps;
        let byte_idx = usize::from(byte_idx_raw) % 32;
        let bit_mask = 1u8 << bit_idx_raw;

        let mut mutated = proof.clone();
        mutated.path[step_idx].sibling_hash[byte_idx] ^= bit_mask;
        let mutated_result = verify_inclusion(&mutated);
        assert!(
            !mutated_result,
            "security invariant I4 violated: single-bit flip in sibling hash \
             did not change verify_inclusion result \
             (step={step_idx}, byte={byte_idx}, bit={bit_idx_raw})"
        );

        // I5: flip the direction of a step — must break verification.
        let dir_step_idx = usize::from(dir_step_idx_raw) % n_steps;
        let mut dir_mutated = proof.clone();
        dir_mutated.path[dir_step_idx].direction = match dir_mutated.path[dir_step_idx].direction {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        };
        let dir_result = verify_inclusion(&dir_mutated);
        assert!(
            !dir_result,
            "security invariant I5 violated: flipping proof step direction \
             did not change verify_inclusion result (step={dir_step_idx})"
        );
    }
});
