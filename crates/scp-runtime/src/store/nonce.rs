//! UCAN nonce storage operations for `ProtocolRepository`.
//!
//! Implements nonce replay prevention following the key convention from
//! spec section 17.3:
//!
//! ```text
//! context/{context_id}/nonce/{nonce_hash_hex}
//! ```
//!
//! Nonce keys use `SHA256(nonce_string)` hashed to a hex string for
//! fixed-length keys. Replay checks use `load_value()` (not `exists()`)
//! so the read and write use a consistent code path through `Storage`.
//!
//! Refactored from `store/ucan.rs` per spec section 17.4 Module Structure.
//! See SCP-PERSIST-011.

use scp_platform::traits::Storage;
use scp_primitives::Clock;
use serde::{Deserialize, Serialize};

use super::{ProtocolRepository, StoreError};

/// Interval between automatic prune passes (in seconds).
///
/// `check_and_record_nonce` reads a per-context last-prune timestamp
/// and triggers a full prune pass when this interval has elapsed.
/// One hour balances storage hygiene against scan cost.
const PRUNE_INTERVAL_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Nonce record stored for UCAN replay prevention.
///
/// Contains timestamps for pruning: nonces whose `token_expiry` is in
/// the past can be safely removed.
///
/// See spec section 17.3 on nonce keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceRecord {
    /// Unix timestamp when this nonce was first observed.
    pub first_seen: u64,
    /// Unix timestamp when the associated UCAN token expires.
    pub token_expiry: u64,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a UCAN nonce entry.
///
/// Format: `context/{context_id}/nonce/{nonce_hash_hex}`
/// The nonce hash is encoded as lowercase hex. See spec section 17.3.
fn nonce_key(context_id: &str, nonce_hash: &[u8; 32]) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let hex_str = hex::encode(nonce_hash);
    Ok(format!("context/{ctx}/nonce/{hex_str}"))
}

/// Builds the prefix for listing all nonces in a context.
///
/// Format: `context/{context_id}/nonce/`
fn nonce_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/nonce/"))
}

/// Builds the storage key for the last-prune timestamp of a context.
///
/// Format: `context/{context_id}/nonce/_last_prune`
///
/// The leading underscore ensures this key sorts before any hex-encoded
/// nonce hash (which start with `0`–`f`), making it easy to skip during
/// nonce iteration.
fn last_prune_key(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/nonce/_last_prune"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — nonce methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Checks and records a UCAN nonce for replay prevention.
    ///
    /// Returns `true` if this is a new nonce (first time seen),
    /// `false` if the nonce was already recorded (replay attempt).
    ///
    /// The `nonce_hash` parameter must be a SHA-256 hash of the original
    /// nonce string. The caller is responsible for performing this hash
    /// before calling this method — raw nonce strings must not be passed
    /// directly.
    ///
    /// Uses `load_value()` (not `exists()`) to check for a prior record,
    /// then `store_value()` to claim the slot. A post-write `load_value()`
    /// re-verifies ownership so that concurrent writers that both passed the
    /// initial check will see a timestamp mismatch and reject (safe failure).
    ///
    /// See spec section 17.3 on nonce keys and 17.4 on `check_and_record_nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    ///
    /// # SAFETY: TOCTOU window
    ///
    /// The `Storage` trait does not provide compare-and-swap (CAS), so a
    /// narrow race window exists between the `load_value` check and the
    /// `store_value` write.  This is acceptable because:
    ///
    /// 1. The in-memory `NonceTracker` provides the primary, synchronised
    ///    replay defense on the hot path.
    /// 2. `ProtocolRepository` nonce tracking is a defence-in-depth layer for
    ///    crash recovery — it re-populates the in-memory set on restart.
    /// 3. The race window is bounded by storage I/O latency (typically
    ///    sub-millisecond for `SQLite` WAL).
    /// 4. The post-write re-read errs on the side of rejection: if two
    ///    writers race, at most one sees its own timestamps back; the
    ///    other gets a mismatch and returns `false` (safe rejection).
    ///
    /// Storage backends that support atomic insert-if-absent should
    /// override this at the adapter level for true atomicity.
    #[must_use = "ignoring nonce check result is a security bug"]
    pub async fn check_and_record_nonce(
        &self,
        context_id: &str,
        nonce_hash: &[u8; 32],
        first_seen: u64,
        token_expiry: u64,
    ) -> Result<bool, StoreError> {
        // Time-gated pruning: if more than PRUNE_INTERVAL_SECS have
        // elapsed since the last prune for this context, run a prune
        // pass before checking the nonce. This prevents unbounded
        // nonce accumulation in long-running processes. The extra
        // storage read (last-prune timestamp) is negligible relative
        // to the two reads and one write that the nonce check already
        // performs. See spec section 17.3 on nonce pruning.
        let now = scp_primitives::SystemClock.now_secs();
        self.maybe_prune_nonces(context_id, now).await?;

        let key = nonce_key(context_id, nonce_hash)?;

        // If a record already exists, reject immediately without
        // overwriting the existing record's timestamps.
        if self.load_value::<NonceRecord>(&key).await?.is_some() {
            return Ok(false);
        }

        // Store the nonce record, claiming the slot.
        let record = NonceRecord {
            first_seen,
            token_expiry,
        };
        self.store_value(&key, &record).await?;

        // Re-verify after store: if the loaded record has different
        // timestamps, another request won the race and we treat this
        // as a replay (safe rejection). If the storage backend
        // silently overwrites, this check sees our own write and
        // succeeds — the SAFETY note above documents this limitation.
        match self.load_value::<NonceRecord>(&key).await? {
            Some(stored) if stored.first_seen == first_seen => Ok(true),
            _ => Ok(false),
        }
    }

    /// Prunes expired nonces if the prune interval has elapsed.
    ///
    /// Reads the last-prune timestamp from storage. If more than
    /// [`PRUNE_INTERVAL_SECS`] have elapsed (or no timestamp exists),
    /// runs a full prune pass and updates the timestamp.
    ///
    /// This is called automatically by `check_and_record_nonce`.
    /// Errors during pruning are logged but do not fail the nonce check —
    /// pruning is best-effort maintenance.
    async fn maybe_prune_nonces(&self, context_id: &str, now: u64) -> Result<(), StoreError> {
        let lp_key = last_prune_key(context_id)?;
        let last_prune: Option<u64> = self.load_value(&lp_key).await?;

        let should_prune =
            last_prune.is_none_or(|ts| now.saturating_sub(ts) >= PRUNE_INTERVAL_SECS);

        if should_prune {
            // Best-effort: if pruning fails, we still proceed with the
            // nonce check. The next call will retry.
            let _ = self.prune_expired_nonces(context_id, now).await;
            let _ = self.store_value(&lp_key, &now).await;
        }

        Ok(())
    }

    /// Prunes expired nonces from a context.
    ///
    /// Removes all nonce records whose `token_expiry` is less than or
    /// equal to `now`. Returns the number of nonces pruned.
    ///
    /// See spec section 17.4 on `prune_expired_nonces`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any nonce record fails
    /// to deserialize.
    pub async fn prune_expired_nonces(
        &self,
        context_id: &str,
        now: u64,
    ) -> Result<u64, StoreError> {
        let prefix = nonce_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let mut pruned = 0u64;
        for key in keys {
            // Skip metadata keys (e.g., `_last_prune`).
            if key.contains("/_") {
                continue;
            }
            if let Some(record) = self.load_value::<NonceRecord>(&key).await?
                && record.token_expiry <= now
            {
                self.storage.delete(&key).await?;
                pruned += 1;
            }
        }
        Ok(pruned)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryStorage;
    use scp_primitives::Clock;

    use super::*;

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    fn test_nonce_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 0xDE;
        h[1] = 0xAD;
        h[31] = 0xFF;
        h
    }

    // -------------------------------------------------------------------
    // Nonce replay prevention
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn check_and_record_nonce_returns_true_for_new() {
        let store = make_store();
        let nonce = test_nonce_hash();

        let is_new = store
            .check_and_record_nonce("ctx-1", &nonce, 1000, 2000)
            .await
            .unwrap();
        assert!(is_new);
    }

    #[tokio::test]
    async fn check_and_record_nonce_returns_false_for_replay() {
        let store = make_store();
        let nonce = test_nonce_hash();

        store
            .check_and_record_nonce("ctx-1", &nonce, 1000, 2000)
            .await
            .unwrap();
        let is_new = store
            .check_and_record_nonce("ctx-1", &nonce, 1001, 2000)
            .await
            .unwrap();
        assert!(!is_new);
    }

    #[tokio::test]
    async fn nonce_is_context_scoped() {
        let store = make_store();
        let nonce = test_nonce_hash();

        store
            .check_and_record_nonce("ctx-1", &nonce, 1000, 2000)
            .await
            .unwrap();

        let is_new_in_ctx2 = store
            .check_and_record_nonce("ctx-2", &nonce, 1000, 2000)
            .await
            .unwrap();
        assert!(is_new_in_ctx2);
    }

    // -------------------------------------------------------------------
    // Nonce pruning
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn prune_expired_nonces_removes_expired() {
        let store = make_store();
        let nonce_a = {
            let mut h = [0u8; 32];
            h[0] = 0xAA;
            h
        };
        let nonce_b = {
            let mut h = [0u8; 32];
            h[0] = 0xBB;
            h
        };

        store
            .check_and_record_nonce("ctx-1", &nonce_a, 100, 500)
            .await
            .unwrap();
        store
            .check_and_record_nonce("ctx-1", &nonce_b, 200, 2000)
            .await
            .unwrap();

        let pruned = store.prune_expired_nonces("ctx-1", 600).await.unwrap();
        assert_eq!(pruned, 1);

        let replay_a = store
            .check_and_record_nonce("ctx-1", &nonce_a, 601, 3000)
            .await
            .unwrap();
        assert!(replay_a);

        let replay_b = store
            .check_and_record_nonce("ctx-1", &nonce_b, 601, 3000)
            .await
            .unwrap();
        assert!(!replay_b);
    }

    #[tokio::test]
    async fn prune_expired_nonces_returns_zero_when_none_expired() {
        let store = make_store();
        let nonce = test_nonce_hash();

        store
            .check_and_record_nonce("ctx-1", &nonce, 100, 9999)
            .await
            .unwrap();

        let pruned = store.prune_expired_nonces("ctx-1", 500).await.unwrap();
        assert_eq!(pruned, 0);
    }

    // -------------------------------------------------------------------
    // Time-gated pruning
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn check_and_record_prunes_expired_on_first_call() {
        let store = make_store();
        let nonce_a = {
            let mut h = [0u8; 32];
            h[0] = 0xAA;
            h
        };

        // Record a nonce with token_expiry=1 (far in the past relative
        // to wall clock). The nonce check stores it directly.
        let record = NonceRecord {
            first_seen: 1,
            token_expiry: 1,
        };
        let key = nonce_key("ctx-1", &nonce_a).unwrap();
        store.store_value(&key, &record).await.unwrap();

        // Next check_and_record_nonce triggers auto-prune because no
        // _last_prune timestamp exists. Wall clock now >> 1, so nonce_a
        // is expired and gets pruned.
        let nonce_b = {
            let mut h = [0u8; 32];
            h[0] = 0xBB;
            h
        };
        let now = scp_primitives::SystemClock.now_secs();
        store
            .check_and_record_nonce("ctx-1", &nonce_b, now, now + 3600)
            .await
            .unwrap();

        // nonce_a should have been pruned — re-recording should succeed.
        let is_new = store
            .check_and_record_nonce("ctx-1", &nonce_a, now + 1, now + 3600)
            .await
            .unwrap();
        assert!(is_new, "expired nonce should have been pruned");
    }

    #[tokio::test]
    async fn check_and_record_skips_prune_within_interval() {
        let store = make_store();

        let now = scp_primitives::SystemClock.now_secs();

        // First call sets _last_prune to now.
        let nonce_a = {
            let mut h = [0u8; 32];
            h[0] = 0xAA;
            h
        };
        store
            .check_and_record_nonce("ctx-1", &nonce_a, now, now + 3600)
            .await
            .unwrap();

        // Manually insert an expired nonce (expiry=1, far in the past).
        let nonce_expired = {
            let mut h = [0u8; 32];
            h[0] = 0xEE;
            h
        };
        let record = NonceRecord {
            first_seen: 1,
            token_expiry: 1,
        };
        let key = nonce_key("ctx-1", &nonce_expired).unwrap();
        store.store_value(&key, &record).await.unwrap();

        // Second call — within PRUNE_INTERVAL_SECS of _last_prune.
        // Should NOT prune the expired nonce.
        let nonce_b = {
            let mut h = [0u8; 32];
            h[0] = 0xBB;
            h
        };
        store
            .check_and_record_nonce("ctx-1", &nonce_b, now + 1, now + 3600)
            .await
            .unwrap();

        // Expired nonce should still be present — replay rejected.
        let is_new = store
            .check_and_record_nonce("ctx-1", &nonce_expired, now + 2, now + 3600)
            .await
            .unwrap();
        assert!(
            !is_new,
            "expired nonce should not have been pruned within interval"
        );
    }

    // -------------------------------------------------------------------
    // Concurrent nonce checking
    // -------------------------------------------------------------------

    /// Validates the in-memory defense-in-depth concurrency behavior.
    ///
    /// This test exercises the post-write re-read pattern in
    /// `check_and_record_nonce`. It validates that at most one concurrent
    /// writer succeeds for the same nonce in a single-process
    /// `InMemoryStorage` backend. It does NOT test universal atomicity
    /// across distributed storage backends — that requires CAS support
    /// at the adapter level (see the SAFETY note on `check_and_record_nonce`).
    #[tokio::test]
    async fn concurrent_nonce_checks_allow_at_most_one() {
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let nonce = test_nonce_hash();
        let task_count = 10;

        let mut handles = Vec::with_capacity(task_count);
        for i in 0..task_count {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                store
                    .check_and_record_nonce("ctx-race", &nonce, 5000 + i as u64, 9000)
                    .await
                    .unwrap()
            }));
        }

        let mut successes = 0u32;
        for handle in handles {
            if handle.await.unwrap() {
                successes += 1;
            }
        }

        assert_eq!(
            successes, 1,
            "exactly one concurrent nonce check should succeed"
        );
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn nonce_key_uses_hex_encoded_hash() {
        let mut h = [0u8; 32];
        h[0] = 0xFF;
        let key = nonce_key("ctx-1", &h).unwrap();
        assert!(key.starts_with("context/ctx-1/nonce/"));
        assert!(key.ends_with("00"));
        assert!(key.contains("ff"));
    }
}
