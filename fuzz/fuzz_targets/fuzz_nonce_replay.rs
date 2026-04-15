#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Nonce replay prevention fuzz target (Tier 4 — covers #1662, I4).
//!
//! # Security invariant I4
//!
//! Once `check_replay(nonce)` returns `Ok`, a subsequent `check_replay` for
//! the same nonce (after `record`) MUST return `Err`. An accepted nonce is
//! permanently consumed.
//!
//! # Strategy
//!
//! Generate sequences of nonces. Each nonce is either:
//! - A fresh nonce with real wall-time timestamp + fuzz-controlled hex suffix.
//! - A previously-accepted nonce (replay attempt).
//!
//! For each nonce in the sequence:
//! 1. Call `check_replay`.
//! 2. If `Ok` → call `record`. Subsequent `check_replay` for the same nonce
//!    MUST return `Err` (replay detected).
//! 3. If `Err` → the nonce was already rejected (expired/future/replayed).
//!    `record` is not called.
//!
//! # Nonce format
//!
//! `InMemoryNonceTracker` requires nonces in the format
//! `{unix_millis}-{32_hex_chars}`. The fuzz-controlled parts are:
//! - `ts_offset_ms`: offset added to real wall time (signed, bounded to ±10 min).
//!   Values within ±5 minutes are "fresh"; outside are "stale/future".
//! - `hex_suffix`: 16-byte suffix as 32 hex chars.
//! - `reuse_index`: if set, the nonce at this index in the accepted list is
//!   replayed to exercise the replay-detection path.
//!
//! # Security invariants
//! - I1: `check_replay` and `record` must never panic.
//! - I4: Accepted nonce → subsequent `check_replay` MUST return `Err`.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use scp_primitives::Clock as _;
use scp_protocol::crypto::ucan::validate::{InMemoryNonceTracker, NonceTracker};

/// One nonce operation in the fuzz sequence.
#[derive(Debug, Arbitrary)]
struct NonceOp {
    /// Signed offset (milliseconds) added to wall-time before formatting.
    /// Positive → future; negative → past. Range mapped to ±600_000 ms (10 min).
    ts_offset_ms: i32,
    /// 16 raw bytes used as the hex suffix (lowercase hex, 32 chars).
    hex_bytes: [u8; 16],
    /// If `Some(idx)`, replay the accepted nonce at position `idx % accepted.len()`.
    /// Ignored if `accepted` is empty.
    reuse_index: Option<u8>,
}

fuzz_target!(|ops: [NonceOp; 8]| {
    let mut tracker = InMemoryNonceTracker::new();
    let mut accepted: Vec<String> = Vec::new();

    let now_millis = scp_primitives::SystemClock.now_millis();

    for op in &ops {
        // --- Mode: replay previously-accepted nonce ---
        if let Some(idx) = op.reuse_index {
            if !accepted.is_empty() {
                let nonce = &accepted[idx as usize % accepted.len()];
                // I4: accepted nonce MUST be rejected on replay.
                let replay_result = tracker.check_replay(nonce, u64::MAX);
                assert!(
                    replay_result.is_err(),
                    "security invariant I4 violated: replay of accepted nonce was accepted \
                     by check_replay. nonce={nonce:?}"
                );
                // Attempting record on a replayed nonce must also fail (or panic).
                let _ = tracker.record(nonce, u64::MAX);
                continue;
            }
        }

        // --- Mode: fresh nonce with fuzz-controlled timestamp ---
        // Map ts_offset_ms to ±600_000 ms range.
        let offset_ms = i64::from(op.ts_offset_ms) % 600_000_i64;
        let nonce_millis = (now_millis as i64).saturating_add(offset_ms) as u64;
        let hex_suffix = hex::encode(op.hex_bytes);
        let nonce = format!("{nonce_millis}-{hex_suffix}");

        // I1: check_replay must not panic.
        let check_result = tracker.check_replay(&nonce, u64::MAX);

        if check_result.is_ok() {
            // Record the nonce. I1: record must not panic.
            let record_result = tracker.record(&nonce, u64::MAX);

            if record_result.is_ok() {
                accepted.push(nonce.clone());

                // I4: Immediately after recording, replay MUST be rejected.
                let replay_check = tracker.check_replay(&nonce, u64::MAX);
                assert!(
                    replay_check.is_err(),
                    "security invariant I4 violated: nonce accepted by check_replay \
                     immediately after record. nonce={nonce:?}"
                );
            }
            // If record returns Err, it means the nonce failed the defensive
            // re-check inside record (e.g., a race — not possible here, but
            // the code handles it defensively). No assertion needed.
        }
        // If check_result is Err, the nonce is invalid/stale/future — skip.
    }
});
