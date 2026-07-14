//! Crash-safe per-stream `monotonic_seq` counter shared by all FFI bridges
//! (SCP-OUT-034 AC31).
//!
//! # Why this exists
//!
//! §5.4.5 requires every internally-signed [`OutletStreamCredit`] grant to carry
//! a strictly-increasing `monotonic_seq`; the runtime `CreditTracker` rejects any
//! grant whose seq is not greater than the last it saw (`CreditReplay`,
//! `SCP-OUTLET-6110`). The bridges historically assigned that seq from an
//! **in-memory** per-stream `AtomicU64` (`grant_seq.fetch_add`). That counter is
//! rebuilt from zero when the bridge process restarts, so a stream resumed after
//! an SDK restart would re-issue low seq values and the runtime would reject
//! every resumed grant as a replay — breaking the resumed stream.
//!
//! SCP-OUT-034 AC31 mandates that the seq be **crash-safe**: option (a) —
//! persist the per-stream cursor to durable [`Storage`] so a restart reloads it
//! and never regresses. This module is that single, shared implementation so
//! the three native bridges (`PyO3`, `napi-rs`, `UniFFI`) cannot drift — the
//! same "one place, no drift" rationale as [`crate::outlet_id`].
//!
//! # Mechanism
//!
//! The cursor lives ONLY in durable storage — there is no in-memory copy to fall
//! out of sync, so the durable store is the single source of truth. On each
//! grant the bridge calls [`next_grant_monotonic_seq`], which:
//!
//! 1. Reads the current cursor (absent ⇒ `0`) under the key
//!    `context/{context_id}/stream_credit_counter/{request_id_hex}`.
//! 2. Persists `cursor + 1` **before returning**, so a crash after the persist
//!    but before the grant applies never re-issues the value — the seq is
//!    monotonic and never regresses (it may skip a burned value, which the
//!    runtime accepts: it requires *strictly increasing*, not *gapless*).
//! 3. Returns the pre-increment value as the `monotonic_seq` for this grant.
//!
//! Callers MUST serialize the call with the grant apply under the per-stream
//! control lock so two concurrent self-grants receive strictly-ordered seqs
//! (see each bridge's `outlet_stream_grant_credit`).
//!
//! # Key namespace & cleanup
//!
//! The key sits under the same `context/{context_id}/…` namespace the runtime
//! store layer uses (raw context id via [`sanitize_key_component`], hex
//! `request_id`), so the existing `ProtocolRepository::delete_context` prefix
//! sweep (`delete_prefix("context/{ctx}/")`) reclaims the cursor when the
//! hosting context is torn down — no bespoke cleanup path is required.
//!
//! [`OutletStreamCredit`]: scp_core::context::outlets::stream::OutletStreamCredit

use scp_platform::store_value::{
    from_stored_value_bytes, sanitize_key_component, to_stored_value_bytes,
};
use scp_platform::traits::Storage;

/// Failure assigning a durable `monotonic_seq`. Each bridge maps this onto its
/// own error surface (a `SCP-OUTLET-`/`SCP-CTX-` code) at the call site.
#[derive(Debug, thiserror::Error)]
pub enum StreamCreditCounterError {
    /// The context id could not form a safe storage key component
    /// (`..`, path separators, NUL, etc. — [`sanitize_key_component`]).
    #[error("invalid context id for stream-credit-counter key: {0}")]
    Key(String),
    /// A durable storage read/write failed.
    #[error("stream-credit-counter storage I/O failed: {0}")]
    Storage(String),
    /// The persisted cursor bytes could not be decoded/encoded.
    #[error("stream-credit-counter value codec failed: {0}")]
    Codec(String),
    /// The stream issued more than `u64::MAX` grants — practically unreachable,
    /// surfaced rather than silently wrapping (which would regress the seq).
    #[error("monotonic_seq overflow: stream exceeded u64::MAX credit grants")]
    Overflow,
}

/// Builds the durable key for a stream's monotonic grant cursor.
///
/// Format: `context/{context_id}/stream_credit_counter/{request_id_hex}`.
/// Mirrors the runtime store layer's `context/{ctx}/…` namespacing so the
/// context-teardown prefix sweep reclaims it.
///
/// # Errors
///
/// Returns [`StreamCreditCounterError::Key`] if `context_id` is not a safe key
/// component.
pub fn stream_credit_counter_key(
    context_id: &str,
    request_id: &[u8; 16],
) -> Result<String, StreamCreditCounterError> {
    let ctx = sanitize_key_component(context_id)
        .map_err(|e| StreamCreditCounterError::Key(e.to_string()))?;
    Ok(format!(
        "context/{ctx}/stream_credit_counter/{}",
        hex::encode(request_id)
    ))
}

/// Reads, increments, and persists the durable per-stream grant cursor,
/// returning the `monotonic_seq` to assign to THIS grant (SCP-OUT-034 AC31).
///
/// The pre-increment cursor value is returned; `value + 1` is persisted before
/// returning so a crash never re-issues it. The first grant on a fresh stream
/// returns `0`.
///
/// # Crash-safety
///
/// The persist happens BEFORE the returned seq is used to sign/apply the grant.
/// If the process dies after the persist, the next call reads the incremented
/// value and returns a strictly greater seq — the seq never regresses across an
/// SDK restart, satisfying AC31.
///
/// # Concurrency
///
/// The read-modify-write is NOT internally atomic across concurrent calls for
/// the same `(context_id, request_id)`. Callers MUST hold the per-stream control
/// lock across this call and the subsequent grant apply so concurrent self-grants
/// receive strictly-ordered seqs.
///
/// # Errors
///
/// Returns [`StreamCreditCounterError`] if the key is invalid, storage I/O
/// fails, the persisted bytes cannot be decoded, or the counter would overflow.
pub async fn next_grant_monotonic_seq<S: Storage>(
    storage: &S,
    context_id: &str,
    request_id: &[u8; 16],
) -> Result<u64, StreamCreditCounterError> {
    let key = stream_credit_counter_key(context_id, request_id)?;
    let current: u64 = match storage
        .retrieve(&key)
        .await
        .map_err(|e| StreamCreditCounterError::Storage(e.to_string()))?
    {
        Some(bytes) => from_stored_value_bytes::<u64>(&bytes)
            .map_err(|e| StreamCreditCounterError::Codec(e.to_string()))?,
        None => 0,
    };
    let next = current
        .checked_add(1)
        .ok_or(StreamCreditCounterError::Overflow)?;
    let bytes =
        to_stored_value_bytes(&next).map_err(|e| StreamCreditCounterError::Codec(e.to_string()))?;
    storage
        .store(&key, &bytes)
        .await
        .map_err(|e| StreamCreditCounterError::Storage(e.to_string()))?;
    Ok(current)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryStorage;

    fn rid(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    #[test]
    fn key_format_is_context_scoped_and_hex() {
        let key = stream_credit_counter_key("ctx-1", &rid(0xAB)).unwrap();
        assert_eq!(
            key,
            "context/ctx-1/stream_credit_counter/abababababababababababababababab"
        );
    }

    #[test]
    fn key_rejects_unsafe_context_id() {
        assert!(matches!(
            stream_credit_counter_key("../evil", &rid(1)),
            Err(StreamCreditCounterError::Key(_))
        ));
    }

    #[tokio::test]
    async fn first_grant_is_zero_then_strictly_increases() {
        let storage = InMemoryStorage::new();
        let ctx = "ctx-seq";
        let request_id = rid(7);
        for expected in 0u64..5 {
            let seq = next_grant_monotonic_seq(&storage, ctx, &request_id)
                .await
                .unwrap();
            assert_eq!(seq, expected);
        }
    }

    #[tokio::test]
    async fn distinct_streams_have_independent_cursors() {
        let storage = InMemoryStorage::new();
        let ctx = "ctx-multi";
        let a = rid(1);
        let b = rid(2);
        assert_eq!(
            next_grant_monotonic_seq(&storage, ctx, &a).await.unwrap(),
            0
        );
        assert_eq!(
            next_grant_monotonic_seq(&storage, ctx, &a).await.unwrap(),
            1
        );
        // A different request_id starts its own cursor at 0.
        assert_eq!(
            next_grant_monotonic_seq(&storage, ctx, &b).await.unwrap(),
            0
        );
        assert_eq!(
            next_grant_monotonic_seq(&storage, ctx, &a).await.unwrap(),
            2
        );
    }
}
