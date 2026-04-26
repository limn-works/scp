//! Caveat-counter storage operations for `ProtocolRepository`.
//!
//! Implements per-(ucan_cid) counter persistence following the §17.3 key
//! convention:
//!
//! ```text
//! context/{context_id}/caveat_counters/{ucan_cid}
//! ```
//!
//! One record per UCAN holds counter state for every counter-bearing caveat
//! kind (`max_calls`, `amount_max_cumulative`, `rate_window`). The runtime
//! [`crate::trust::CaveatCounterStore`] wraps `ProtocolRepository` plus an
//! in-process per-`(context, ucan)` `tokio::sync::Mutex` to enforce CAS
//! atomicity around load-modify-store sequences. The storage operations
//! here are the persistence half of that contract; CAS semantics live in
//! `trust/caveat_counter_store.rs`.
//!
//! See `.docs/specs/07-trust-validation-and-capabilities.md` §7.3.8,
//! `.docs/specs/17-persistence-and-storage.md` §17.3, and SCP-OUT-020.

use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};

use super::{ProtocolRepository, StoreError, sanitize_key_component};

// ---------------------------------------------------------------------------
// Persistence record
// ---------------------------------------------------------------------------

/// Per-UCAN counter record persisted under
/// `context/{context_id}/caveat_counters/{ucan_cid}`.
///
/// One record per `(context_id, ucan_cid)` pair, regardless of which
/// `CaveatKind`s the delegation declares. Storing all kinds together means a
/// single `store_value` call atomically commits every counter change made
/// under one mutex acquisition — the persistence layer cannot observe a
/// partial update where, say, the `max_calls` count moved but the
/// rate-window timestamp was lost.
///
/// **Field-ordering invariant.** `rate_window_timestamps` MUST be sorted in
/// ascending order. The pruner relies on this to short-circuit the scan once
/// it finds a timestamp newer than `now - window_secs`. New timestamps are
/// always appended (and `now` is monotonic enough for our purposes — see
/// `prune_expired_window_entries` in `trust/caveat_counter_store.rs` for the
/// saturating-clamp behaviour against non-monotonic clocks).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaveatCounters {
    /// Cumulative count of invocations charged against `max_calls`.
    pub max_calls_used: u64,
    /// Cumulative amount charged against `amount_max_cumulative`.
    pub amount_cumulative_used: u64,
    /// Ring buffer of invocation timestamps (Unix seconds) for `rate_window`.
    ///
    /// Pruned to entries within the active window on every read. Sorted
    /// ascending by timestamp.
    pub rate_window_timestamps: Vec<u64>,
}

// ---------------------------------------------------------------------------
// Key helper
// ---------------------------------------------------------------------------

/// Builds the storage key for a UCAN's caveat-counter record.
///
/// Format: `context/{context_id}/caveat_counters/{ucan_cid}` per §17.3.
///
/// Both components are sanitized via [`sanitize_key_component`]; values
/// containing path separators or null bytes return
/// [`StoreError::SerializationFailed`] before any storage operation runs.
pub(crate) fn caveat_counters_key(context_id: &str, ucan_cid: &str) -> Result<String, StoreError> {
    let ctx = sanitize_key_component(context_id)?;
    let ucan = sanitize_key_component(ucan_cid)?;
    Ok(format!("context/{ctx}/caveat_counters/{ucan}"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — caveat counter methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Loads the [`CaveatCounters`] record for a UCAN delegation, if any.
    ///
    /// Returns `None` if no invocation has yet been recorded for this UCAN
    /// in this context. Does NOT prune the rate-window ring buffer; the
    /// runtime [`crate::trust::CaveatCounterStore`] applies a sliding-window
    /// prune after loading.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, storage retrieval, or
    /// deserialization fails.
    pub async fn load_caveat_counters(
        &self,
        context_id: &str,
        ucan_cid: &str,
    ) -> Result<Option<CaveatCounters>, StoreError> {
        let key = caveat_counters_key(context_id, ucan_cid)?;
        self.load_value(&key).await
    }

    /// Persists the [`CaveatCounters`] record for a UCAN delegation.
    ///
    /// Replaces any existing record (replace-by-`(context_id, ucan_cid)`
    /// semantics). The runtime store calls this only while holding the
    /// per-UCAN mutex, so concurrent writers cannot interleave updates.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization, serialization, or the
    /// underlying storage write fails.
    pub async fn store_caveat_counters(
        &self,
        context_id: &str,
        ucan_cid: &str,
        counters: &CaveatCounters,
    ) -> Result<(), StoreError> {
        let key = caveat_counters_key(context_id, ucan_cid)?;
        self.store_value(&key, counters).await
    }

    /// Deletes the [`CaveatCounters`] record for a UCAN delegation.
    ///
    /// Used during whole-token revocation (§7.3.8 revocation granularity is
    /// whole-token, so a `UcanRevocation` event invalidates every caveat
    /// including counter state). Idempotent: succeeds even if no record
    /// exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization or the underlying storage
    /// delete fails.
    pub async fn delete_caveat_counters(
        &self,
        context_id: &str,
        ucan_cid: &str,
    ) -> Result<(), StoreError> {
        let key = caveat_counters_key(context_id, ucan_cid)?;
        self.storage().delete(&key).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use super::*;

    fn make_repo() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    #[test]
    fn caveat_counters_key_follows_persistence_layout() {
        let key = caveat_counters_key("ctx-abc", "bafyucan001").unwrap();
        assert_eq!(key, "context/ctx-abc/caveat_counters/bafyucan001");
    }

    #[test]
    fn caveat_counters_key_rejects_path_traversal_in_context_id() {
        let err = caveat_counters_key("../etc/passwd", "tok").unwrap_err();
        match err {
            StoreError::SerializationFailed(msg) => {
                assert!(msg.contains("forbidden characters"), "msg = {}", msg);
            }
            other => panic!("expected SerializationFailed, got {:?}", other),
        }
    }

    #[test]
    fn caveat_counters_key_rejects_null_byte_in_ucan_cid() {
        let err = caveat_counters_key("ctx", "tok\0evil").unwrap_err();
        match err {
            StoreError::SerializationFailed(_) => {}
            other => panic!("expected SerializationFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn store_load_roundtrip_preserves_record() {
        let repo = make_repo();
        let counters = CaveatCounters {
            max_calls_used: 7,
            amount_cumulative_used: 1234,
            rate_window_timestamps: vec![100, 200, 300],
        };
        repo.store_caveat_counters("ctx", "ucan-1", &counters)
            .await
            .unwrap();
        let loaded = repo
            .load_caveat_counters("ctx", "ucan-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, counters);
    }

    #[tokio::test]
    async fn load_returns_none_for_unwritten_ucan() {
        let repo = make_repo();
        let loaded = repo
            .load_caveat_counters("ctx", "never-written")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_removes_record() {
        let repo = make_repo();
        let counters = CaveatCounters {
            max_calls_used: 1,
            ..CaveatCounters::default()
        };
        repo.store_caveat_counters("ctx", "ucan-1", &counters)
            .await
            .unwrap();
        repo.delete_caveat_counters("ctx", "ucan-1").await.unwrap();
        let loaded = repo.load_caveat_counters("ctx", "ucan-1").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_is_idempotent_for_missing_record() {
        let repo = make_repo();
        repo.delete_caveat_counters("ctx", "never-existed")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn records_are_per_context_and_per_ucan_isolated() {
        let repo = make_repo();
        let a = CaveatCounters {
            max_calls_used: 1,
            ..Default::default()
        };
        let b = CaveatCounters {
            max_calls_used: 2,
            ..Default::default()
        };
        let c = CaveatCounters {
            max_calls_used: 3,
            ..Default::default()
        };
        repo.store_caveat_counters("ctx-1", "ucan-A", &a)
            .await
            .unwrap();
        repo.store_caveat_counters("ctx-1", "ucan-B", &b)
            .await
            .unwrap();
        repo.store_caveat_counters("ctx-2", "ucan-A", &c)
            .await
            .unwrap();

        assert_eq!(
            repo.load_caveat_counters("ctx-1", "ucan-A")
                .await
                .unwrap()
                .unwrap(),
            a
        );
        assert_eq!(
            repo.load_caveat_counters("ctx-1", "ucan-B")
                .await
                .unwrap()
                .unwrap(),
            b
        );
        assert_eq!(
            repo.load_caveat_counters("ctx-2", "ucan-A")
                .await
                .unwrap()
                .unwrap(),
            c
        );
    }
}
