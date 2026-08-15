//! Durable per-context UCAN revocation and nonce state shared by all three FFI
//! bridges (`PyO3`, napi-rs, `UniFFI`).
//!
//! # Why this exists
//!
//! Each bridge instance holds per-context UCAN validation state — a
//! [`RevocationList`] and a [`NonceTracker`] — inside
//! [`UcanContextStateCore`](crate::bridge_runtime::UcanContextStateCore). Before
//! this module, both were built by `RevocationList::new` / `NonceTracker::new`
//! on every bridge instance and were never written to or read from durable
//! storage. A UCAN revoked before a process restart therefore validated again
//! after the restart, because the rebuilt bridge instance started with an empty
//! revocation list. That is an authorization bypass: the revoker performed a
//! revocation the protocol then forgot. Replay protection reset with it — every
//! nonce the tracker had recorded became replayable again.
//!
//! ADR-016 acceptance criterion 5 requires `revoke_ucan` to append a
//! `TokenRevoked` event to the context's event log, and the bridges do append
//! one (see `BridgeRevocationEventLogger` in [`crate::resolvers`]). That event
//! lands in the bridge-local `EventLog`, which no bridge persists or reloads, so
//! the event alone cannot rebuild the revocation list. This module supplies the
//! durable record the rebuild reads.
//!
//! # Mechanism
//!
//! Two durable values per context, both written through whichever [`Storage`]
//! backend the bridge instance selected (`SCP.with_storage(...)`):
//!
//! | Key | Value | Written by | Read by |
//! |---|---|---|---|
//! | `context/{ctx}/ucan/revocation_list` | serialized [`RevocationList`] | every bridge's `ucan_revoke`, after `revoke_ucan` succeeds | [`hydrate_core`], at per-context UCAN-state construction |
//! | `context/{ctx}/ucan/nonce_tracker` | serialized [`NonceTracker`] | every bridge's UCAN-validation entry points, after the validation pipeline runs | [`hydrate_core`], at per-context UCAN-state construction |
//!
//! Hydration is monotonic in both directions, so calling it twice cannot
//! un-revoke a token or forget a nonce: the revocation list merges as a set
//! union ([`RevocationList::merge`] is append-only), and the nonce entries merge
//! with the in-memory entry winning on a key collision.
//!
//! # Key namespace and cleanup
//!
//! Both keys sit under the `context/{context_id}/…` namespace the runtime store
//! layer uses, so `ProtocolRepository::delete_context`'s
//! `delete_prefix("context/{ctx}/")` sweep reclaims them when the context is
//! torn down. [`NonceTracker::storage_key`] returns `nonce_tracker/{ctx}`, which
//! sits outside that namespace and would survive the sweep, so this module
//! builds its own key rather than calling it.
//!
//! # Durability is the backend's property, not this module's
//!
//! A bridge instance configured with `{"type":"in_memory"}` writes these records
//! to the encrypted in-memory adapter, and they die with the process — that is
//! the honest property of the backend the caller chose (ADR-062 §0, spec §17.6).
//! A bridge instance configured with `{"type":"sqlite", …}` writes them to the
//! same `SQLCipher` database that holds context snapshots and the Merkle event
//! log, and they survive a restart. This module never substitutes one backend
//! for another and never falls back: when the bridge has no storage selected,
//! the caller receives [`UcanDurableStateError::NoStorage`] and fails closed.

use std::collections::HashMap;

use scp_clock::SystemClock;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_platform::store_value::{
    from_stored_value_bytes, sanitize_key_component, to_stored_value_bytes,
};
use scp_platform::traits::Storage;

use crate::bridge_runtime::UcanContextStateCore;

/// Failure reading or writing the durable UCAN state. Each bridge maps this
/// onto its own error surface (an `SCP-UCAN-`/`SCP-CTX-` code) at the call site.
#[derive(Debug, thiserror::Error)]
pub enum UcanDurableStateError {
    /// The context id could not form a safe storage key component
    /// (`..`, path separators, NUL — see [`sanitize_key_component`]).
    #[error("invalid context id for UCAN durable-state key: {0}")]
    Key(String),
    /// A durable storage read or write failed.
    #[error("UCAN durable-state storage I/O failed: {0}")]
    Storage(String),
    /// The persisted bytes could not be encoded or decoded.
    #[error("UCAN durable-state value codec failed: {0}")]
    Codec(String),
    /// The bridge instance has no storage backend selected, so the revocation
    /// could not be made durable. The caller fails closed rather than
    /// performing a revocation the next process start would forget.
    #[error(
        "bridge instance has no storage backend selected — a UCAN revocation \
         cannot be made durable; select storage via SCP.with_storage(...) first"
    )]
    NoStorage,
    /// The caller asked to run the storage future to completion from a
    /// synchronous FFI entry point while already inside a current-thread tokio
    /// runtime, where neither `block_in_place` nor `Handle::block_on` can run.
    /// Reported rather than risking a panic or a deadlock.
    #[error(
        "cannot run UCAN durable-state storage I/O from inside a current-thread \
         tokio runtime"
    )]
    NoBlockingContext,
}

/// Builds the durable key for a context's UCAN revocation list.
///
/// Format: `context/{context_id}/ucan/revocation_list`.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::Key`] if `context_id` is not a safe key
/// component.
pub fn revocation_list_key(context_id: &str) -> Result<String, UcanDurableStateError> {
    let ctx = sanitize_key_component(context_id)
        .map_err(|e| UcanDurableStateError::Key(e.to_string()))?;
    Ok(format!("context/{ctx}/ucan/revocation_list"))
}

/// Builds the durable key for a context's UCAN nonce tracker.
///
/// Format: `context/{context_id}/ucan/nonce_tracker`.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::Key`] if `context_id` is not a safe key
/// component.
pub fn nonce_tracker_key(context_id: &str) -> Result<String, UcanDurableStateError> {
    let ctx = sanitize_key_component(context_id)
        .map_err(|e| UcanDurableStateError::Key(e.to_string()))?;
    Ok(format!("context/{ctx}/ucan/nonce_tracker"))
}

/// Writes the context's revocation list to durable storage.
///
/// Every bridge calls this immediately after
/// `scp_core::crypto::ucan::revoke::revoke_ucan` returns `Ok`, so the durable
/// record and the in-memory list agree before `ucan_revoke` returns to the
/// caller. A write failure is reported to the caller rather than swallowed: the
/// in-memory list already denies the token (the more restrictive state), and the
/// caller learns that the revocation did not become durable and can retry.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if the key is invalid, the value cannot be
/// encoded, or the storage write fails.
pub async fn persist_revocation_list<S: Storage>(
    storage: &S,
    context_id: &str,
    list: &RevocationList,
) -> Result<(), UcanDurableStateError> {
    let key = revocation_list_key(context_id)?;
    let bytes =
        to_stored_value_bytes(list).map_err(|e| UcanDurableStateError::Codec(e.to_string()))?;
    storage
        .store(&key, &bytes)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))
}

/// Reads the context's revocation list from durable storage.
///
/// Returns `None` when no revocation has ever been persisted for the context.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if the key is invalid, the storage read
/// fails, or the persisted bytes cannot be decoded.
pub async fn load_revocation_list<S: Storage>(
    storage: &S,
    context_id: &str,
) -> Result<Option<RevocationList>, UcanDurableStateError> {
    let key = revocation_list_key(context_id)?;
    let Some(bytes) = storage
        .retrieve(&key)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))?
    else {
        return Ok(None);
    };
    let list: RevocationList =
        from_stored_value_bytes(&bytes).map_err(|e| UcanDurableStateError::Codec(e.to_string()))?;
    Ok(Some(list))
}

/// Writes the context's UCAN nonce entries to durable storage.
///
/// Every bridge calls this after each UCAN-validation pipeline run, because
/// that pipeline is the only thing that records nonces (through
/// `BridgeNonceTracker`). Callers pass
/// [`NonceTracker::snapshot_entries`], which is also what the runtime embeds in
/// a `ContextStateSnapshot` for its own `spending_nonce_tracker`. Writing the
/// whole entry set rather than the single new nonce keeps a pruned tracker from
/// resurrecting entries it dropped.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if the key is invalid, the entries cannot
/// be encoded, or the storage write fails.
pub async fn persist_nonce_entries<S: Storage, H: std::hash::BuildHasher + Sync>(
    storage: &S,
    context_id: &str,
    entries: &HashMap<String, (u64, u64), H>,
) -> Result<(), UcanDurableStateError> {
    let key = nonce_tracker_key(context_id)?;
    let bytes =
        to_stored_value_bytes(entries).map_err(|e| UcanDurableStateError::Codec(e.to_string()))?;
    storage
        .store(&key, &bytes)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))
}

/// Reads the context's persisted nonce entries from durable storage.
///
/// Each entry maps a nonce string to `(first_seen_secs, token_expiry_secs)`.
/// Returns `None` when no nonce has ever been persisted for the context.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if the key is invalid, the storage read
/// fails, or the persisted bytes cannot be decoded.
pub async fn load_nonce_entries<S: Storage>(
    storage: &S,
    context_id: &str,
) -> Result<Option<HashMap<String, (u64, u64)>>, UcanDurableStateError> {
    let key = nonce_tracker_key(context_id)?;
    let Some(bytes) = storage
        .retrieve(&key)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))?
    else {
        return Ok(None);
    };
    let entries: HashMap<String, (u64, u64)> =
        from_stored_value_bytes(&bytes).map_err(|e| UcanDurableStateError::Codec(e.to_string()))?;
    Ok(Some(entries))
}

/// Merges the durable revocation record into a freshly built revocation list.
///
/// [`RevocationList::merge`] is a set union that never un-revokes a token and
/// ignores a list belonging to a different context, so this is safe to call on
/// a list that already holds entries and safe to call more than once.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if the storage read fails or the persisted
/// bytes cannot be decoded.
pub async fn hydrate_revocation_list<S: Storage>(
    storage: &S,
    context_id: &str,
    list: &mut RevocationList,
) -> Result<(), UcanDurableStateError> {
    if let Some(persisted) = load_revocation_list(storage, context_id).await? {
        list.merge(&persisted);
    }
    Ok(())
}

/// Merges the durable nonce record into a freshly built nonce tracker.
///
/// An entry already present in `tracker` wins over the persisted entry, so a
/// nonce recorded in this process is never overwritten by an older durable copy.
/// [`NonceTracker::from_snapshot`] prunes entries that expired while the tracker
/// was not running, so a restored tracker starts normalized.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if the storage read fails or the persisted
/// bytes cannot be decoded.
pub async fn hydrate_nonce_tracker<S: Storage>(
    storage: &S,
    context_id: &str,
    tracker: &mut NonceTracker<SystemClock>,
) -> Result<(), UcanDurableStateError> {
    let Some(persisted) = load_nonce_entries(storage, context_id).await? else {
        return Ok(());
    };
    let mut entries = tracker.snapshot_entries();
    for (nonce, seen) in persisted {
        entries.entry(nonce).or_insert(seen);
    }
    *tracker = NonceTracker::from_snapshot(context_id.to_owned(), SystemClock, entries);
    Ok(())
}

/// Rebuilds a bridge instance's per-context UCAN validation state from the
/// durable record.
///
/// Called from the point where each bridge inserts a new
/// [`UcanContextStateCore`] into its per-context registry, which is the point at
/// which a bridge instance first gains the ability to answer a UCAN validation
/// for that context. Both halves merge rather than replace, so hydrating a
/// non-empty state cannot lose an in-memory revocation or an in-memory nonce.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if either storage read fails or either
/// persisted value cannot be decoded. The caller fails closed: a bridge that
/// cannot read its revocation record must not answer validations as though no
/// token had been revoked.
pub async fn hydrate_core<S: Storage>(
    storage: &S,
    context_id: &str,
    core: &mut UcanContextStateCore,
) -> Result<(), UcanDurableStateError> {
    hydrate_revocation_list(storage, context_id, &mut core.revocation_list).await?;
    hydrate_nonce_tracker(storage, context_id, &mut core.nonce_tracker).await
}

/// Runs a storage future to completion from a synchronous FFI entry point.
///
/// The three bridges expose synchronous functions that must read or write the
/// durable UCAN state, and `Storage` is an async trait. Which bridging primitive
/// works depends on where the caller runs:
///
/// - Outside any tokio runtime (a `PyO3` call arriving from a Python thread):
///   `Handle::block_on` drives the future directly.
/// - Inside a multi-threaded runtime (a napi-rs or `UniFFI` async entry point,
///   or a `PyO3` MCP server task): `block_in_place` moves the current worker off
///   the scheduler first, which is the same sync-to-async bridge
///   `ScpMlsProvider` uses for the sync `OpenMLS` storage trait.
/// - Inside a current-thread runtime: neither primitive is legal, so this
///   returns [`UcanDurableStateError::NoBlockingContext`] and the caller fails
///   closed. The `PyO3` bridge builds a current-thread runtime only when
///   building a multi-threaded one fails.
///
/// `crates/scp-ffi/**` is outside the scope of the `block_in_place` CI gate
/// (`scripts/check-block-in-place.py`), which excludes the whole directory
/// because the FFI boundary is where sync callers meet async protocol code.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::NoBlockingContext`] when called from inside
/// a current-thread tokio runtime.
pub fn block_on_storage<F>(
    handle: &tokio::runtime::Handle,
    fut: F,
) -> Result<F::Output, UcanDurableStateError>
where
    F: std::future::Future,
{
    match tokio::runtime::Handle::try_current() {
        Ok(current) => match current.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                Err(UcanDurableStateError::NoBlockingContext)
            }
            _ => Ok(tokio::task::block_in_place(|| current.block_on(fut))),
        },
        Err(_) => Ok(handle.block_on(fut)), // ci-allow: block-on: sync FFI entry point outside any runtime
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_platform::in_memory::InMemoryStorage;

    fn tracker(context_id: &str) -> NonceTracker<SystemClock> {
        NonceTracker::new(context_id.to_owned(), SystemClock)
    }

    /// A revocation written by one instance must be readable by the next, and
    /// the rebuilt list must report the token as revoked. This is the durable
    /// half of the restart contract at the storage layer.
    #[tokio::test]
    async fn revocation_round_trips_through_storage() {
        let storage = InMemoryStorage::new();
        let mut list = RevocationList::new("ctx-round-trip".to_owned());
        list.revoke("cid-revoked".to_owned());

        persist_revocation_list(&storage, "ctx-round-trip", &list)
            .await
            .expect("persist must succeed");

        let mut rebuilt = RevocationList::new("ctx-round-trip".to_owned());
        assert!(
            !rebuilt.is_revoked("cid-revoked"),
            "a freshly built list must start empty"
        );
        hydrate_revocation_list(&storage, "ctx-round-trip", &mut rebuilt)
            .await
            .expect("hydrate must succeed");
        assert!(
            rebuilt.is_revoked("cid-revoked"),
            "the rebuilt list must report the persisted CID as revoked"
        );
    }

    /// Hydration merges, so an entry the caller already revoked in memory
    /// survives a hydration that does not mention it.
    #[tokio::test]
    async fn hydration_keeps_in_memory_revocations() {
        let storage = InMemoryStorage::new();
        let mut persisted = RevocationList::new("ctx-merge".to_owned());
        persisted.revoke("cid-durable".to_owned());
        persist_revocation_list(&storage, "ctx-merge", &persisted)
            .await
            .unwrap();

        let mut live = RevocationList::new("ctx-merge".to_owned());
        live.revoke("cid-in-memory".to_owned());
        hydrate_revocation_list(&storage, "ctx-merge", &mut live)
            .await
            .unwrap();

        assert!(live.is_revoked("cid-durable"), "durable CID must merge in");
        assert!(
            live.is_revoked("cid-in-memory"),
            "in-memory CID must survive the merge"
        );
    }

    /// Reading a context that never persisted anything leaves the freshly built
    /// state untouched and reports no error.
    #[tokio::test]
    async fn absent_record_leaves_state_empty() {
        let storage = InMemoryStorage::new();
        let mut list = RevocationList::new("ctx-absent".to_owned());
        hydrate_revocation_list(&storage, "ctx-absent", &mut list)
            .await
            .expect("absent record is not an error");
        assert!(list.is_empty(), "absent record must leave the list empty");

        let mut nonces = tracker("ctx-absent");
        hydrate_nonce_tracker(&storage, "ctx-absent", &mut nonces)
            .await
            .expect("absent record is not an error");
        assert!(
            nonces.is_empty(),
            "absent record must leave the tracker empty"
        );
    }

    /// A nonce recorded before a restart must still be refused after one.
    #[tokio::test]
    async fn nonce_round_trips_through_storage() {
        let storage = InMemoryStorage::new();
        let now = scp_clock::Clock::now_secs(&SystemClock);
        let nonce = format!("{}-{}", now.saturating_mul(1000), "a".repeat(32));
        let expiry = now + 600;

        let mut live = tracker("ctx-nonce");
        live.record(&nonce, expiry).expect("record must succeed");
        persist_nonce_entries(&storage, "ctx-nonce", &live.snapshot_entries())
            .await
            .expect("persist must succeed");

        let mut rebuilt = tracker("ctx-nonce");
        assert!(
            rebuilt.check_replay(&nonce, expiry).is_ok(),
            "a freshly built tracker must not know the nonce"
        );
        hydrate_nonce_tracker(&storage, "ctx-nonce", &mut rebuilt)
            .await
            .expect("hydrate must succeed");
        assert!(
            rebuilt.check_replay(&nonce, expiry).is_err(),
            "the rebuilt tracker must refuse the replayed nonce"
        );
    }

    /// The keys sit under `context/{ctx}/` so the context-teardown prefix sweep
    /// reclaims them.
    #[test]
    fn keys_live_under_the_context_prefix() {
        assert_eq!(
            revocation_list_key("ctx-a").unwrap(),
            "context/ctx-a/ucan/revocation_list"
        );
        assert_eq!(
            nonce_tracker_key("ctx-a").unwrap(),
            "context/ctx-a/ucan/nonce_tracker"
        );
    }

    /// A context id that would escape its key namespace is rejected before any
    /// storage call.
    #[test]
    fn traversal_context_id_is_rejected() {
        assert!(matches!(
            revocation_list_key("../escape"),
            Err(UcanDurableStateError::Key(_))
        ));
        assert!(matches!(
            nonce_tracker_key("a/b"),
            Err(UcanDurableStateError::Key(_))
        ));
    }
}
