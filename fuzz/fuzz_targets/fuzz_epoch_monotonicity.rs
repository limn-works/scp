#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Epoch monotonicity fuzz target (Tier 4 — covers #1662, I5).
//!
//! # Security invariant I5
//!
//! Once `SenderKeyStore::set_checked(ctx, did, key, epoch)` returns `Ok`,
//! any subsequent `set_checked` call with `epoch' <= epoch` MUST return `Err`.
//! Accepting a lower (or equal) epoch would allow an adversary to replay an
//! old sender key, breaking forward secrecy of the sender-key layer.
//!
//! # Strategy
//!
//! Generate sequences of `(epoch, key_bytes)` pairs for a fixed
//! `(context_id, sender_did)` pair. For each pair:
//! 1. Call `set_checked`. If `Ok`, record the highest accepted epoch.
//! 2. Immediately call `set_checked` again with the same epoch.
//!    MUST return `Err` (same epoch is not strictly greater).
//! 3. Call `set_checked` with `epoch - 1` (if epoch > 0).
//!    MUST return `Err` (rollback).
//!
//! # Security invariants
//! - I1: `set_checked` must never panic.
//! - I5: After accepting epoch N, set_checked with any M ≤ N MUST return Err.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use scp_protocol::crypto::sender_keys::{SenderKey, SenderKeyStore};

/// One epoch-advance operation.
#[derive(Debug, Arbitrary)]
struct EpochOp {
    /// The epoch to attempt.
    epoch: u64,
    /// 32-byte key material.
    key_bytes: [u8; 32],
}

fuzz_target!(|ops: [EpochOp; 16]| {
    let mut store = SenderKeyStore::new();
    let ctx = "fuzz-ctx";
    let did = "did:dht:fuzz-sender";

    // Track the highest successfully accepted epoch.
    let mut last_accepted: Option<u64> = None;

    for op in &ops {
        // Skip epoch 0 — set_checked requires epoch > 0 for the first key.
        if op.epoch == 0 {
            continue;
        }

        let key = SenderKey::from_bytes(op.key_bytes);

        // I1: set_checked must not panic.
        let result = store.set_checked(ctx, did, key, op.epoch);

        if result.is_ok() {
            // This epoch was accepted. Update the high-water mark.
            let accepted_epoch = op.epoch;

            // Verify the high-water mark is monotonically increasing.
            if let Some(prev) = last_accepted {
                assert!(
                    accepted_epoch > prev,
                    "security invariant I5 violated: set_checked accepted epoch \
                     {accepted_epoch} which is not strictly greater than \
                     previously accepted epoch {prev}"
                );
            }
            last_accepted = Some(accepted_epoch);

            // I5a: Immediate replay (same epoch) MUST be rejected.
            let replay_key = SenderKey::from_bytes(op.key_bytes);
            let replay_result = store.set_checked(ctx, did, replay_key, accepted_epoch);
            assert!(
                replay_result.is_err(),
                "security invariant I5 violated: set_checked accepted same epoch \
                 {accepted_epoch} twice (replay)"
            );

            // I5b: Rollback (epoch - 1) MUST be rejected.
            if accepted_epoch > 1 {
                let rollback_key = SenderKey::from_bytes(op.key_bytes);
                let rollback_result =
                    store.set_checked(ctx, did, rollback_key, accepted_epoch - 1);
                assert!(
                    rollback_result.is_err(),
                    "security invariant I5 violated: set_checked accepted epoch rollback \
                     from {accepted_epoch} to {} (rollback attack)",
                    accepted_epoch - 1
                );
            }
        } else {
            // Rejected. Verify the high-water mark was maintained.
            // If we have a previous accepted epoch, the store's epoch should
            // still reflect that.
            if let Some(prev) = last_accepted {
                assert!(
                    op.epoch <= prev,
                    "set_checked rejected epoch {} even though it is > previously \
                     accepted epoch {prev} — this is a false rejection",
                    op.epoch
                );
            }
            // If no epoch has been accepted yet and epoch > 0, it's valid for
            // the first epoch to fail if epoch == 0 (excluded above), but any
            // epoch > 0 should succeed as the first acceptance.
            // However: `set_checked` requires epoch > current (stored as 0
            // for unseen senders). So epoch > 0 should always succeed for
            // the first call. If rejected, something is wrong.
            if last_accepted.is_none() {
                // This means epoch > 0 was rejected for a sender with no
                // prior epoch. set_checked treats missing senders as epoch 0,
                // so any epoch > 0 should be accepted. This is a regression.
                panic!(
                    "security invariant I5 violated: first epoch {} (> 0) was rejected \
                     for a fresh sender (expected Ok)",
                    op.epoch
                );
            }
        }
    }
});
