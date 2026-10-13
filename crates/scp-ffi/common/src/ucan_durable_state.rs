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
//! Durable values per context, all written through whichever [`Storage`]
//! backend the bridge instance selected (`SCP.with_storage(...)`):
//!
//! | Key | Value | Written by | Read by |
//! |---|---|---|---|
//! | `context/{ctx}/ucan/revocation_list` | serialized [`RevocationList`] | every bridge's `ucan_revoke`, after `revoke_ucan` succeeds | [`hydrate_core`], at per-context UCAN-state construction |
//! | `context/{ctx}/ucan/nonce/{hex(nonce)}`, one key per recorded nonce | serialized `(first_seen_secs, token_expiry_secs)` | [`persist_recorded_nonce`], called by every bridge's UCAN-validation entry points after a validation pipeline run that recorded a nonce | [`hydrate_core`], at per-context UCAN-state construction, which lists the `context/{ctx}/ucan/nonce/` prefix |
//!
//! Recording a nonce writes that nonce's key and nothing else, so the bytes
//! written per accepted token do not grow with the number of nonces the
//! context holds. The key suffix is the lowercase hex encoding of the nonce's
//! bytes, so no nonce can contain a path separator, escape the prefix, or
//! collide with another nonce's key.
//!
//! Expired nonce keys are deleted at the two points the tracker itself prunes:
//! at restore, where [`NonceTracker::from_snapshot`] drops expired entries and
//! [`hydrate_nonce_tracker`] deletes their keys, and after a record whose prune
//! pass removed entries, where [`persist_recorded_nonce`] sweeps the prefix and
//! deletes every key whose entry is expired by the tracker's rule
//! ([`NonceTracker::is_expired_entry`]). The durable set therefore stays bounded
//! by the tracker's retention window.
//!
//! Hydration is monotonic in both directions, so calling it twice cannot
//! un-revoke a token or forget a live nonce: the revocation list merges as a set
//! union ([`RevocationList::merge`] is append-only), and the nonce entries merge
//! with the in-memory entry winning on a key collision.
//!
//! # Key namespace and cleanup
//!
//! Every key sits under the `context/{context_id}/…` namespace the runtime store
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
//! for another and never falls back.

use std::collections::HashMap;

use scp_clock::{Clock, SystemClock};
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_platform::store_value::{
    from_stored_value_bytes, sanitize_key_component, to_stored_value_bytes,
};
use scp_platform::traits::Storage;

use crate::bridge_runtime::UcanContextStateCore;
use crate::resolvers::NonceRecorded;

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
    /// A run reported a recorded nonce the context's tracker does not hold.
    /// The tracker is the source of the entry's timestamps, so there is
    /// nothing correct to write; reported rather than writing a guessed value.
    #[error("recorded UCAN nonce is absent from the context's tracker: {0}")]
    NonceNotTracked(String),
    /// The caller asked to run the storage future to completion from a
    /// synchronous FFI entry point with nothing to drive it on: either inside a
    /// current-thread tokio runtime, where neither `block_in_place` nor
    /// `Handle::block_on` can run, or outside any runtime with no fallback
    /// handle. Reported rather than risking a panic or a deadlock.
    #[error(
        "cannot run UCAN durable-state storage I/O: the caller is inside a \
         current-thread tokio runtime, or outside any runtime with no bridge \
         runtime to drive it"
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

/// Builds the key prefix under which a context's recorded UCAN nonces live,
/// one key per nonce.
///
/// Format: `context/{context_id}/ucan/nonce/`.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::Key`] if `context_id` is not a safe key
/// component.
pub fn nonce_key_prefix(context_id: &str) -> Result<String, UcanDurableStateError> {
    let ctx = sanitize_key_component(context_id)
        .map_err(|e| UcanDurableStateError::Key(e.to_string()))?;
    Ok(format!("context/{ctx}/ucan/nonce/"))
}

/// Builds the durable key for one recorded nonce:
/// `context/{context_id}/ucan/nonce/{hex(nonce)}`.
///
/// The suffix is the lowercase hex of the nonce's bytes. Hex has no separator
/// characters, so no nonce can escape the prefix, and the encoding is
/// injective, so two nonces never share a key.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::Key`] if `context_id` is not a safe key
/// component.
pub fn nonce_key(context_id: &str, nonce: &str) -> Result<String, UcanDurableStateError> {
    Ok(format!(
        "{}{}",
        nonce_key_prefix(context_id)?,
        hex::encode(nonce.as_bytes())
    ))
}

/// Recovers the nonce a key under `prefix` names. A key whose suffix is not
/// the hex of a UTF-8 string was not written by [`nonce_key`], and the load
/// refuses it rather than skip a record it cannot read.
fn nonce_from_key(prefix: &str, key: &str) -> Result<String, UcanDurableStateError> {
    let suffix = key.strip_prefix(prefix).ok_or_else(|| {
        UcanDurableStateError::Codec(format!("key {key} is outside prefix {prefix}"))
    })?;
    let bytes = hex::decode(suffix)
        .map_err(|e| UcanDurableStateError::Codec(format!("nonce key {key}: {e}")))?;
    String::from_utf8(bytes)
        .map_err(|e| UcanDurableStateError::Codec(format!("nonce key {key}: {e}")))
}

/// Reads and decodes one nonce key's `(first_seen_secs, token_expiry_secs)`.
async fn read_nonce_entry<S: Storage>(
    storage: &S,
    key: &str,
) -> Result<Option<(u64, u64)>, UcanDurableStateError> {
    let Some(bytes) = storage
        .retrieve(key)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))?
    else {
        return Ok(None);
    };
    from_stored_value_bytes(&bytes)
        .map(Some)
        .map_err(|e| UcanDurableStateError::Codec(e.to_string()))
}

async fn delete_key<S: Storage>(storage: &S, key: &str) -> Result<(), UcanDurableStateError> {
    storage
        .delete(key)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))
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

/// Writes the one nonce a validation run recorded to its own durable key, and
/// deletes the keys of expired nonces when the record pruned the tracker.
///
/// This is the single nonce-persist function every bridge calls (`PyO3`
/// directly against its `StorageProvider`; napi-rs and `UniFFI` through
/// [`ProtocolRepoVariant::persist_ucan_recorded_nonce`](crate::bridge_runtime::ProtocolRepoVariant::persist_ucan_recorded_nonce)),
/// after a UCAN-validation pipeline run whose nonce adapter reported
/// [`NonceRecorded`]. The value written is the tracker's own entry for the
/// nonce, so the durable `first_seen` matches the in-memory one.
///
/// When `recorded` reports that the record's prune pass removed entries, this
/// lists the context's nonce prefix and deletes every key whose nonce the
/// tracker no longer holds and whose stored entry is expired by the tracker's
/// rule. A key the tracker does not hold but that is still live (written by
/// another bridge instance on the same backend) is kept. The sweep runs only
/// when the tracker pruned, which the tracker does at most every 1000 records
/// or 10 minutes, so its listing cost is amortized over those records.
///
/// The result depends only on the store of the recorded nonce's own key. A
/// sweep failure is logged with `tracing::warn!` and not returned: the nonce is
/// already held in the tracker and stored, so reporting the failure would make
/// the bridge refuse a valid first-use token whose nonce it had spent. The keys
/// the sweep could not remove are retried at the next prune or at restore.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::NonceNotTracked`] if the tracker holds no
/// entry for the recorded nonce, and another [`UcanDurableStateError`] if the
/// key is invalid, the value cannot be encoded, or the store of the nonce's
/// key fails.
pub async fn persist_recorded_nonce<S: Storage, C: Clock>(
    storage: &S,
    context_id: &str,
    tracker: &NonceTracker<C>,
    recorded: NonceRecorded,
) -> Result<(), UcanDurableStateError> {
    let entry = tracker
        .entry(&recorded.nonce)
        .ok_or_else(|| UcanDurableStateError::NonceNotTracked(recorded.nonce.clone()))?;
    let key = nonce_key(context_id, &recorded.nonce)?;
    let bytes =
        to_stored_value_bytes(&entry).map_err(|e| UcanDurableStateError::Codec(e.to_string()))?;
    storage
        .store(&key, &bytes)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))?;
    if recorded.pruned
        && let Err(failure) = prune_nonce_keys(storage, context_id, tracker).await
    {
        tracing::warn!(
            context_id,
            failed_keys = failure.failed,
            error = %failure.first,
            "UCAN nonce prune sweep failed; the expired keys it could not remove \
             are retried at the next prune or at restore"
        );
    }
    Ok(())
}

/// The keys a prune sweep could not process: how many, and the first failure.
/// The error carries no key bytes, so it can be logged as is.
#[derive(Debug)]
struct PruneFailure {
    failed: usize,
    first: UcanDurableStateError,
}

/// Deletes the durable key of every nonce the tracker does not hold whose
/// stored entry is expired by the tracker's retention rule.
///
/// A key that cannot be decoded, read, or deleted is counted and skipped, so
/// one bad key cannot keep the sweep from reaching the keys after it.
async fn prune_nonce_keys<S: Storage, C: Clock>(
    storage: &S,
    context_id: &str,
    tracker: &NonceTracker<C>,
) -> Result<(), PruneFailure> {
    let prefix = nonce_key_prefix(context_id).map_err(|first| PruneFailure { failed: 0, first })?;
    let keys = storage.list_keys(&prefix).await.map_err(|e| PruneFailure {
        failed: 0,
        first: UcanDurableStateError::Storage(e.to_string()),
    })?;
    let mut failure: Option<PruneFailure> = None;
    for key in keys {
        if let Err(err) = prune_nonce_key(storage, tracker, &prefix, &key).await {
            match &mut failure {
                Some(f) => f.failed += 1,
                None => {
                    failure = Some(PruneFailure {
                        failed: 1,
                        first: err,
                    });
                }
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

/// Deletes one key under the nonce prefix when the tracker does not hold its
/// nonce and its stored entry is expired. The returned error names no key.
async fn prune_nonce_key<S: Storage, C: Clock>(
    storage: &S,
    tracker: &NonceTracker<C>,
    prefix: &str,
    key: &str,
) -> Result<(), UcanDurableStateError> {
    let nonce = nonce_from_key(prefix, key).map_err(|_| {
        UcanDurableStateError::Codec("a key under the nonce prefix is not a hex nonce".to_owned())
    })?;
    if tracker.entry(&nonce).is_some() {
        return Ok(());
    }
    if let Some((first_seen, token_expiry)) = read_nonce_entry(storage, key).await?
        && tracker.is_expired_entry(first_seen, token_expiry)
    {
        delete_key(storage, key).await?;
    }
    Ok(())
}

/// Reads every persisted nonce entry for the context by listing its nonce
/// prefix. Each entry maps a nonce to `(first_seen_secs, token_expiry_secs)`;
/// the map is empty when no nonce has been persisted.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if the key is invalid, a storage call
/// fails, or a key or value under the prefix cannot be decoded.
pub async fn load_nonce_entries<S: Storage>(
    storage: &S,
    context_id: &str,
) -> Result<HashMap<String, (u64, u64)>, UcanDurableStateError> {
    let prefix = nonce_key_prefix(context_id)?;
    let keys = storage
        .list_keys(&prefix)
        .await
        .map_err(|e| UcanDurableStateError::Storage(e.to_string()))?;
    let mut entries = HashMap::with_capacity(keys.len());
    for key in keys {
        let nonce = nonce_from_key(&prefix, &key)?;
        if let Some(entry) = read_nonce_entry(storage, &key).await? {
            entries.insert(nonce, entry);
        }
    }
    Ok(entries)
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

/// Merges the durable nonce records into a freshly built nonce tracker, and
/// deletes the keys of the persisted nonces that expired while no tracker held
/// them.
///
/// An entry already present in `tracker` wins over the persisted entry, so a
/// nonce recorded in this process is never overwritten by an older durable copy.
/// The merged tracker is rebuilt through [`NonceTracker::from_snapshot`], which
/// drops expired entries, and every persisted entry the tracker's rule
/// ([`NonceTracker::is_expired_entry`]) calls expired has its key deleted, so
/// restore prunes the durable set by the same rule it prunes the tracker.
/// `clock` becomes the rebuilt tracker's time source.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if a storage call fails or a persisted key
/// or value cannot be decoded.
pub async fn hydrate_nonce_tracker<S: Storage, C: Clock>(
    storage: &S,
    context_id: &str,
    tracker: &mut NonceTracker<C>,
    clock: C,
) -> Result<(), UcanDurableStateError> {
    let persisted = load_nonce_entries(storage, context_id).await?;
    if persisted.is_empty() {
        return Ok(());
    }
    let mut entries = tracker.snapshot_entries();
    for (nonce, seen) in &persisted {
        entries.entry(nonce.clone()).or_insert(*seen);
    }
    *tracker = NonceTracker::from_snapshot(context_id.to_owned(), clock, entries);
    for (nonce, (first_seen, token_expiry)) in &persisted {
        if tracker.is_expired_entry(*first_seen, *token_expiry) {
            delete_key(storage, &nonce_key(context_id, nonce)?).await?;
        }
    }
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
    hydrate_nonce_tracker(storage, context_id, &mut core.nonce_tracker, SystemClock).await
}

/// Builds a context's UCAN validation state from the durable record.
///
/// This is the one place a bridge's per-context [`RevocationList`] and
/// [`NonceTracker`] are constructed: the empty values exist only as the
/// starting point [`hydrate_core`] merges the durable record into, and they
/// never leave this function unmerged. The event log starts empty, because no
/// bridge persists it.
///
/// # Errors
///
/// Returns [`UcanDurableStateError`] if either storage read fails or either
/// persisted value cannot be decoded. The caller fails closed: a bridge that
/// cannot read its revocation record must not answer validations as though no
/// token had been revoked.
pub async fn load_core<S: Storage>(
    storage: &S,
    context_id: &str,
) -> Result<UcanContextStateCore, UcanDurableStateError> {
    let mut core = UcanContextStateCore {
        revocation_list: RevocationList::new(context_id.to_owned()),
        nonce_tracker: NonceTracker::new(context_id.to_owned(), SystemClock),
        event_log: scp_event_log::EventLog::new(context_id.to_owned()),
    };
    hydrate_core(storage, context_id, &mut core).await?;
    Ok(core)
}

/// Runs a storage future to completion from a synchronous FFI entry point.
///
/// The three bridges expose synchronous functions that must read or write the
/// durable UCAN state, and `Storage` is an async trait. Which bridging primitive
/// works depends on where the caller runs:
///
/// - Inside a multi-threaded runtime (a napi-rs or `UniFFI` async entry point,
///   or a `PyO3` MCP server task): `block_in_place` moves the current worker off
///   the scheduler first, which is the same sync-to-async bridge
///   `ScpMlsProvider` uses for the sync `OpenMLS` storage trait. `fallback` is
///   not read on this path.
/// - Outside any tokio runtime (a `PyO3` call arriving from a Python thread):
///   `fallback` names the bridge's own runtime and `Handle::block_on` drives the
///   future on it.
/// - Inside a current-thread runtime: neither primitive is legal, so this
///   returns [`UcanDurableStateError::NoBlockingContext`] and the caller fails
///   closed. The `PyO3` bridge builds a current-thread runtime only when
///   building a multi-threaded one fails.
/// - Outside any tokio runtime with `fallback` set to `None`: there is nothing
///   to drive the future on, so this returns
///   [`UcanDurableStateError::NoBlockingContext`] as well.
///
/// `crates/scp-ffi/**` is outside the scope of the `block_in_place` CI gate
/// (`scripts/check-block-in-place.py`), which excludes the whole directory
/// because the FFI boundary is where sync callers meet async protocol code.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::NoBlockingContext`] when called from inside
/// a current-thread tokio runtime, or when the caller is outside any runtime and
/// passes no `fallback` handle.
pub fn block_on_storage<F>(
    fallback: Option<&tokio::runtime::Handle>,
    fut: F,
) -> Result<F::Output, UcanDurableStateError>
where
    F: std::future::Future,
{
    if let Ok(current) = tokio::runtime::Handle::try_current() {
        if current.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
            return Err(UcanDurableStateError::NoBlockingContext);
        }
        return Ok(tokio::task::block_in_place(|| current.block_on(fut)));
    }
    let handle = fallback.ok_or(UcanDurableStateError::NoBlockingContext)?;
    Ok(handle.block_on(fut)) // ci-allow: block-on: sync FFI entry point outside any runtime
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_clock::TestClock;
    use scp_core::crypto::ucan::validate::NonceTracker as _;
    use scp_platform::PlatformError;
    use scp_platform::in_memory::InMemoryStorage;

    use crate::resolvers::BridgeNonceTracker;

    fn tracker(context_id: &str) -> NonceTracker<SystemClock> {
        NonceTracker::new(context_id.to_owned(), SystemClock)
    }

    /// A nonce in the tracker's `{unix_millis}-{32_hex}` format, fresh at
    /// `now_secs`.
    fn fresh_nonce(now_secs: u64, fill: char) -> String {
        format!(
            "{}-{}",
            now_secs.saturating_mul(1000),
            fill.to_string().repeat(32)
        )
    }

    /// Records `nonce` through the bridge adapter, the path every bridge's
    /// validation pipeline takes, and returns the adapter's report.
    fn record<C: Clock>(tracker: &mut NonceTracker<C>, nonce: &str, expiry: u64) -> NonceRecorded {
        let mut recorded = None;
        BridgeNonceTracker::new(tracker, &mut recorded)
            .record(nonce, expiry)
            .expect("record must succeed");
        recorded.expect("a successful record must report NonceRecorded")
    }

    /// A [`Storage`] that counts writes and remembers the keys written, over an
    /// [`InMemoryStorage`].
    #[derive(Default)]
    struct CountingStorage {
        inner: InMemoryStorage,
        stores: AtomicUsize,
        written: std::sync::Mutex<Vec<String>>,
    }

    impl CountingStorage {
        fn reset(&self) {
            self.stores.store(0, Ordering::SeqCst);
            self.written.lock().unwrap().clear();
        }
    }

    impl Storage for CountingStorage {
        async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
            self.stores.fetch_add(1, Ordering::SeqCst);
            self.written.lock().unwrap().push(key.to_owned());
            self.inner.store(key, data).await
        }
        async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
            self.inner.retrieve(key).await
        }
        async fn delete(&self, key: &str) -> Result<(), PlatformError> {
            self.inner.delete(key).await
        }
        async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError> {
            self.inner.list_keys(prefix).await
        }
        async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError> {
            self.inner.delete_prefix(prefix).await
        }
        async fn exists(&self, key: &str) -> Result<bool, PlatformError> {
            self.inner.exists(key).await
        }
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
        hydrate_nonce_tracker(&storage, "ctx-absent", &mut nonces, SystemClock)
            .await
            .expect("absent record is not an error");
        assert!(
            nonces.is_empty(),
            "absent record must leave the tracker empty"
        );
    }

    /// A nonce recorded and persisted by one tracker is refused as a replay by
    /// the tracker a restarted instance rebuilds from storage.
    #[tokio::test]
    async fn replayed_nonce_recorded_before_restart_is_refused_after_it() {
        let storage = InMemoryStorage::new();
        let now = scp_clock::Clock::now_secs(&SystemClock);
        let nonce = fresh_nonce(now, 'a');
        let expiry = now + 600;

        let mut live = tracker("ctx-nonce");
        let recorded = record(&mut live, &nonce, expiry);
        persist_recorded_nonce(&storage, "ctx-nonce", &live, recorded)
            .await
            .expect("persist must succeed");
        drop(live);

        let mut rebuilt = load_core(&storage, "ctx-nonce")
            .await
            .expect("load must succeed")
            .nonce_tracker;
        let mut recorded = None;
        let replay = BridgeNonceTracker::new(&mut rebuilt, &mut recorded).record(&nonce, expiry);
        assert!(
            matches!(
                replay,
                Err(scp_core::crypto::ucan::UcanError::NonceReused(_))
            ),
            "the rebuilt tracker must refuse the replayed nonce, got {replay:?}"
        );
        assert!(recorded.is_none(), "a refused replay must report no record");
    }

    /// Recording one nonce writes exactly one key, that nonce's own, however
    /// many nonces the context already holds.
    #[tokio::test]
    async fn recording_a_nonce_writes_exactly_one_key() {
        let storage = CountingStorage::default();
        let now = scp_clock::Clock::now_secs(&SystemClock);
        let mut live = tracker("ctx-count");
        for i in 0..50_u64 {
            let nonce = format!("{}-{:032x}", now.saturating_mul(1000), i);
            let recorded = record(&mut live, &nonce, now + 600);
            persist_recorded_nonce(&storage, "ctx-count", &live, recorded)
                .await
                .expect("persist must succeed");
        }
        storage.reset();

        let nonce = fresh_nonce(now, 'f');
        let recorded = record(&mut live, &nonce, now + 600);
        persist_recorded_nonce(&storage, "ctx-count", &live, recorded)
            .await
            .expect("persist must succeed");

        assert_eq!(storage.stores.load(Ordering::SeqCst), 1);
        assert_eq!(
            *storage.written.lock().unwrap(),
            vec![nonce_key("ctx-count", &nonce).unwrap()],
            "the one write must be the recorded nonce's own key"
        );
        assert_eq!(
            storage
                .list_keys(&nonce_key_prefix("ctx-count").unwrap())
                .await
                .unwrap()
                .len(),
            51,
            "each recorded nonce must hold its own key"
        );
    }

    /// When a record's prune pass drops an expired nonce, the persist step
    /// deletes that nonce's durable key and keeps the live one's.
    #[tokio::test]
    async fn pruning_deletes_an_expired_nonce_key() {
        let storage = InMemoryStorage::new();
        let start = 1_800_000_000;
        let clock = Arc::new(TestClock::new(start));
        let mut live = NonceTracker::new("ctx-prune".to_owned(), Arc::clone(&clock));

        let old = fresh_nonce(start, 'a');
        let recorded = record(&mut live, &old, start + 60);
        assert!(!recorded.pruned, "a first record prunes nothing");
        persist_recorded_nonce(&storage, "ctx-prune", &live, recorded)
            .await
            .unwrap();
        let old_key = nonce_key("ctx-prune", &old).unwrap();
        assert!(storage.exists(&old_key).await.unwrap());

        // Past both the token's expiry grace and the 24 h retention floor, and
        // past the tracker's 10-minute prune interval.
        let later = start + 86_400 + 1_000;
        clock.set(later);
        let new = fresh_nonce(later, 'b');
        let recorded = record(&mut live, &new, later + 60);
        assert!(
            recorded.pruned,
            "the record's prune pass dropped the expired nonce"
        );
        persist_recorded_nonce(&storage, "ctx-prune", &live, recorded)
            .await
            .unwrap();

        assert!(
            !storage.exists(&old_key).await.unwrap(),
            "the expired nonce's key must be deleted"
        );
        assert!(
            storage
                .exists(&nonce_key("ctx-prune", &new).unwrap())
                .await
                .unwrap(),
            "the live nonce's key must remain"
        );
    }

    /// The prune sweep keeps a live key the tracker does not hold (another
    /// bridge instance on the same backend wrote it).
    #[tokio::test]
    async fn pruning_keeps_a_live_key_the_tracker_does_not_hold() {
        let storage = InMemoryStorage::new();
        let start = 1_800_000_000;
        let clock = Arc::new(TestClock::new(start));
        let mut live = NonceTracker::new("ctx-shared".to_owned(), Arc::clone(&clock));
        let old = fresh_nonce(start, 'a');
        let recorded = record(&mut live, &old, start + 60);
        persist_recorded_nonce(&storage, "ctx-shared", &live, recorded)
            .await
            .unwrap();

        let later = start + 86_400 + 1_000;
        clock.set(later);
        let foreign = fresh_nonce(later, 'c');
        let foreign_key = nonce_key("ctx-shared", &foreign).unwrap();
        storage
            .store(
                &foreign_key,
                &to_stored_value_bytes(&(later, later + 60)).unwrap(),
            )
            .await
            .unwrap();

        let recorded = record(&mut live, &fresh_nonce(later, 'b'), later + 60);
        assert!(recorded.pruned);
        persist_recorded_nonce(&storage, "ctx-shared", &live, recorded)
            .await
            .unwrap();
        assert!(storage.exists(&foreign_key).await.unwrap());
        assert!(
            !storage
                .exists(&nonce_key("ctx-shared", &old).unwrap())
                .await
                .unwrap()
        );
    }

    /// A [`Storage`] over an [`InMemoryStorage`] whose `delete` always fails.
    #[derive(Default)]
    struct FailingDeleteStorage {
        inner: InMemoryStorage,
    }

    impl Storage for FailingDeleteStorage {
        async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
            self.inner.store(key, data).await
        }
        async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
            self.inner.retrieve(key).await
        }
        async fn delete(&self, _key: &str) -> Result<(), PlatformError> {
            Err(PlatformError::StorageError("delete refused".to_owned()))
        }
        async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError> {
            self.inner.list_keys(prefix).await
        }
        async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError> {
            self.inner.delete_prefix(prefix).await
        }
        async fn exists(&self, key: &str) -> Result<bool, PlatformError> {
            self.inner.exists(key).await
        }
    }

    /// A prune sweep that fails (here, every `delete` fails) does not fail the
    /// persist: the recorded nonce's own key is stored and the call returns
    /// `Ok`, so the bridge accepts the first-use token instead of refusing it
    /// after spending its nonce.
    #[tokio::test]
    async fn prune_failure_does_not_fail_the_nonce_persist() {
        let storage = FailingDeleteStorage::default();
        let start = 1_800_000_000;
        let clock = Arc::new(TestClock::new(start));
        let mut live = NonceTracker::new("ctx-prune-fail".to_owned(), Arc::clone(&clock));
        let old = fresh_nonce(start, 'a');
        let recorded = record(&mut live, &old, start + 60);
        persist_recorded_nonce(&storage, "ctx-prune-fail", &live, recorded)
            .await
            .unwrap();

        let later = start + 86_400 + 1_000;
        clock.set(later);
        let new = fresh_nonce(later, 'b');
        let recorded = record(&mut live, &new, later + 60);
        assert!(recorded.pruned, "the record must trigger a prune sweep");
        let result = persist_recorded_nonce(&storage, "ctx-prune-fail", &live, recorded).await;
        assert!(
            result.is_ok(),
            "a failed prune sweep must not fail the persist, got {result:?}"
        );
        assert!(
            storage
                .exists(&nonce_key("ctx-prune-fail", &new).unwrap())
                .await
                .unwrap(),
            "the recorded nonce's key must be stored"
        );
        assert!(
            storage
                .exists(&nonce_key("ctx-prune-fail", &old).unwrap())
                .await
                .unwrap(),
            "the expired key the sweep could not delete stays for the next sweep"
        );
    }

    /// Restore applies the tracker's expiry rule: a nonce that expired while
    /// no tracker ran is neither loaded nor left in storage.
    #[tokio::test]
    async fn restore_drops_and_deletes_an_expired_nonce() {
        let storage = InMemoryStorage::new();
        let start = 1_800_000_000;
        let clock = Arc::new(TestClock::new(start));
        let mut live = NonceTracker::new("ctx-restore".to_owned(), Arc::clone(&clock));
        let old = fresh_nonce(start, 'a');
        let recorded = record(&mut live, &old, start + 60);
        persist_recorded_nonce(&storage, "ctx-restore", &live, recorded)
            .await
            .unwrap();
        drop(live);

        clock.set(start + 86_400 + 1_000);
        let mut rebuilt = NonceTracker::new("ctx-restore".to_owned(), Arc::clone(&clock));
        hydrate_nonce_tracker(&storage, "ctx-restore", &mut rebuilt, Arc::clone(&clock))
            .await
            .unwrap();
        assert!(rebuilt.is_empty(), "the expired nonce must not be loaded");
        assert!(
            !storage
                .exists(&nonce_key("ctx-restore", &old).unwrap())
                .await
                .unwrap(),
            "restore must delete the expired nonce's key"
        );
    }

    /// A key under the nonce prefix that is not the hex of a nonce fails the
    /// load with a typed error instead of being skipped.
    #[tokio::test]
    async fn load_refuses_an_undecodable_nonce_key() {
        let storage = InMemoryStorage::new();
        let key = format!("{}not-hex", nonce_key_prefix("ctx-badkey").unwrap());
        storage
            .store(&key, &to_stored_value_bytes(&(1_u64, 2_u64)).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            load_core(&storage, "ctx-badkey").await,
            Err(UcanDurableStateError::Codec(_))
        ));
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
            nonce_key("ctx-a", "1-ab/../x").unwrap(),
            format!("context/ctx-a/ucan/nonce/{}", hex::encode("1-ab/../x"))
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
            nonce_key("a/b", "n"),
            Err(UcanDurableStateError::Key(_))
        ));
    }

    /// `load_core` returns the state a restarted instance answers from: the
    /// persisted revocation is revoked and the persisted nonce is refused.
    #[tokio::test]
    async fn load_core_rebuilds_revocations_and_nonces() {
        let storage = InMemoryStorage::new();
        let mut list = RevocationList::new("ctx-load".to_owned());
        list.revoke("cid-revoked".to_owned());
        persist_revocation_list(&storage, "ctx-load", &list)
            .await
            .expect("persist must succeed");
        let now = scp_clock::Clock::now_secs(&SystemClock);
        let nonce = fresh_nonce(now, 'b');
        let expiry = now + 600;
        let mut live = tracker("ctx-load");
        let recorded = record(&mut live, &nonce, expiry);
        persist_recorded_nonce(&storage, "ctx-load", &live, recorded)
            .await
            .expect("persist must succeed");

        let core = load_core(&storage, "ctx-load")
            .await
            .expect("load must succeed");
        assert!(core.revocation_list.is_revoked("cid-revoked"));
        assert!(
            core.nonce_tracker.check_replay(&nonce, expiry).is_err(),
            "the loaded tracker must refuse the persisted nonce"
        );
    }

    /// A revocation record that cannot be decoded fails the load with a typed
    /// error; it never yields an empty list.
    #[tokio::test]
    async fn load_core_refuses_an_undecodable_record() {
        use scp_platform::Storage as _;
        let storage = InMemoryStorage::new();
        storage
            .store(
                &revocation_list_key("ctx-corrupt").unwrap(),
                b"not a stored value",
            )
            .await
            .expect("raw store must succeed");

        let result = load_core(&storage, "ctx-corrupt").await;
        assert!(
            matches!(result, Err(UcanDurableStateError::Codec(_))),
            "an undecodable record must refuse the load"
        );
    }
}
