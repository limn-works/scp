//! Durable per-context UCAN revocation and nonce state shared by all three FFI
//! bridges (`PyO3`, napi-rs, `UniFFI`).
//!
//! # Why this exists
//!
//! Each bridge instance holds per-context UCAN validation state — a
//! `RevocationList` and a [`NonceTracker`](scp_core::crypto::ucan::nonce::NonceTracker)
//! — inside [`UcanContextStateCore`](crate::bridge_runtime::UcanContextStateCore).
//! Before this module, both were built fresh on every bridge instance and were
//! never written to or read from durable storage. A UCAN revoked before a
//! process restart therefore validated again after the restart, because the
//! rebuilt bridge instance started with an empty revocation list. That is an
//! authorization bypass: the revoker performed a revocation the protocol then
//! forgot. Replay protection reset with it — every nonce the tracker had
//! recorded became replayable again.
//!
//! ADR-016 acceptance criterion 5 requires `revoke_ucan` to append a
//! `TokenRevoked` event to the context's event log, and the bridges do append
//! one (see `BridgeRevocationEventLogger` in [`crate::resolvers`]). That event
//! lands in the bridge-local `EventLog`, which no bridge persists or reloads, so
//! the event alone cannot rebuild the revocation list.
//!
//! # The durable records are the ones §17.3 of the persistence spec defines
//!
//! This module holds no key format of its own. `ProtocolRepository` already
//! implements both records against the spec's key convention, and the bridges
//! reach them through
//! [`ProtocolRepoVariant`](crate::bridge_runtime::ProtocolRepoVariant):
//!
//! | Record | Key | Repository method |
//! |---|---|---|
//! | a revoked token id | `context/{ctx}/ucan_revocation/{token_id}` | `store_revocation`, `list_revocations` |
//! | a consumed nonce | `context/{ctx}/nonce/{SHA256(nonce)}` | `check_and_record_nonce` |
//!
//! One key per entry is what makes concurrent writers safe. A record that
//! serialized the whole `RevocationList` under a single key would force every
//! revocation to read the list, clone it, drop the lock, and write it back; two
//! revocations running at once then race, and the write that lands second —
//! carrying the older snapshot — drops the other token id. The next process
//! start hydrates a list missing that id, which reinstates as a race the very
//! restart bypass the durable record exists to close. A per-entry key removes
//! the read-modify-write instead of narrowing its window: two revocations of two
//! different tokens address two different keys.
//!
//! One key per entry also bounds what an unauthenticated caller can cost the
//! process. A single-blob nonce record would be re-encoded and re-written on
//! every run of the validation pipeline, including every rejected one, so a
//! caller holding no credential would drive a full re-encode of a map that
//! `nonce.rs` caps at 100 000 entries. A validation now writes the one nonce it
//! consumed, and a validation that consumed none — every run the pipeline
//! refuses before step 9 — performs no storage call at all, because
//! [`NonceRecordOutcome::recorded`] is `None` and each bridge returns on it.
//!
//! # The two records are rebuilt in two different ways
//!
//! The revocation record is read back whole:
//! `ProtocolRepoVariant::hydrate_ucan_revocation_list` lists the revoked token
//! ids and replays them into the freshly built `RevocationList`, so step 10 of
//! the ADR-016 pipeline refuses a pre-restart revocation from the first
//! validation onwards.
//!
//! The nonce record cannot be read back that way, because its key is a hash of
//! the nonce and no read recovers the nonce string. Replay protection crosses a
//! restart through the durable check instead: after step 9 records a nonce in
//! memory, the bridge calls `check_and_record_nonce`, and a `false` reply — the
//! record was already there — refuses the token. §17.3 of the persistence spec
//! states this division: "The in-memory `NonceTracker` remains the primary,
//! synchronised replay defense on the hot path. `ProtocolRepository` nonce
//! tracking is defense-in-depth for crash recovery."
//!
//! # Durability is the backend's property, not this module's
//!
//! A bridge instance configured with `{"type":"in_memory"}` writes these records
//! to the encrypted in-memory adapter, and they die with the process — that is
//! the honest property of the backend the caller chose (ADR-062 §0, spec §17.6).
//! A bridge instance configured with `{"type":"sqlite", …}` writes them to the
//! same `SQLCipher` database that holds context snapshots and the Merkle event
//! log, and they survive a restart. Nothing here substitutes one backend for
//! another, and nothing here selects one: the `PyO3` bridge — the one bridge
//! whose storage slot can be empty — reports its own "no storage backend
//! selected" error before it calls in.

use sha2::{Digest, Sha256};

/// Failure driving the durable UCAN state's storage I/O to completion.
///
/// Each bridge maps this onto its own error surface (an `SCP-UCAN-`/`SCP-CTX-`
/// code) at the call site. A storage or key failure surfaces separately, as
/// `scp_core::store::StoreError` from the repository method itself.
#[derive(Debug, thiserror::Error)]
pub enum UcanDurableStateError {
    /// No executor could run the storage future to completion: building the
    /// dedicated tokio runtime failed, or the thread driving it panicked.
    #[error("UCAN durable-state storage I/O could not be driven to completion: {0}")]
    Executor(String),
}

/// Hashes a nonce string into the fixed-length key component
/// `ProtocolRepository::check_and_record_nonce` expects.
///
/// §17.3 of the persistence spec keys a consumed nonce by `SHA256(nonce_string)`
/// so the key length does not depend on the nonce, and so the stored key does
/// not carry the nonce itself.
#[must_use]
pub fn nonce_hash(nonce: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce.as_bytes());
    hasher.finalize().into()
}

/// What one run of the ADR-016 validation pipeline left for the durable nonce
/// record to absorb.
///
/// `BridgeNonceTracker` (see [`crate::resolvers`]) fills this in as step 9 of
/// the pipeline runs, and the bridge reads it afterwards. A run that recorded no
/// nonce leaves it empty, and the bridge then performs no storage call at all —
/// which is what keeps a rejected request off the storage path.
#[derive(Debug, Default, Clone)]
pub struct NonceRecordOutcome {
    /// The nonce step 9 recorded, with the `(first_seen_secs,
    /// token_expiry_secs)` entry the tracker stored against it. `None` means the
    /// run recorded nothing, and the bridge returns before it touches storage.
    pub recorded: Option<(String, (u64, u64))>,
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
/// - Inside a current-thread runtime: `block_in_place` panics there and
///   `Handle::block_on` deadlocks there, so [`run_on_dedicated_thread`] drives
///   the future on a thread that carries no runtime context of its own. A
///   `PyO3` bridge builds a current-thread runtime whenever building a
///   multi-threaded one fails, and the MCP `invoke_outlet` provider then reaches
///   the durable state from inside it — that caller keeps working rather than
///   having every outlet invocation denied for a reason unrelated to the token
///   it presented. `Supervisor::try_consume_hard_rate_limit_from_any_context`
///   bridges the same regime the same way (ADR-049 §7).
/// - Outside any tokio runtime with `fallback` set to `None`: the dedicated
///   thread serves here too.
///
/// `crates/scp-ffi/**` is outside the scope of the `block_in_place` CI gate
/// (`scripts/check-block-in-place.py`), which excludes the whole directory
/// because the FFI boundary is where sync callers meet async protocol code.
///
/// # Errors
///
/// Returns [`UcanDurableStateError::Executor`] when the dedicated runtime
/// cannot be built or the thread driving it panics.
pub fn block_on_storage<F>(
    fallback: Option<&tokio::runtime::Handle>,
    fut: F,
) -> Result<F::Output, UcanDurableStateError>
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if let Ok(current) = tokio::runtime::Handle::try_current() {
        if current.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
            return run_on_dedicated_thread(fut);
        }
        return Ok(tokio::task::block_in_place(|| current.block_on(fut)));
    }
    match fallback {
        Some(handle) => Ok(handle.block_on(fut)), // ci-allow: block-on: sync FFI entry point outside any runtime
        None => run_on_dedicated_thread(fut),
    }
}

/// Drives a storage future on a thread that carries no runtime context.
///
/// The thread builds its own current-thread runtime, so the future is polled
/// without re-entering the caller's runtime. `std::thread::scope` joins the
/// thread before returning, which is what lets the future borrow the caller's
/// state (hydration takes `&mut UcanContextStateCore`).
fn run_on_dedicated_thread<F>(fut: F) -> Result<F::Output, UcanDurableStateError>
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .thread_name("scp-ucan-durable-state")
                    .build()
                    .map_err(|e| {
                        UcanDurableStateError::Executor(format!(
                            "failed to build the dedicated storage runtime: {e}"
                        ))
                    })?;
                Ok(rt.block_on(fut)) // ci-allow: block-on: dedicated runtime owned by this thread
            })
            .join()
            .unwrap_or_else(|_| {
                Err(UcanDurableStateError::Executor(
                    "the thread driving UCAN durable-state storage I/O panicked".to_owned(),
                ))
            })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::bridge_runtime::ProtocolRepoVariant;
    use scp_clock::{Clock, SystemClock};
    use scp_core::crypto::ucan::revoke::RevocationList;
    use scp_platform::encrypting_adapter::EncryptingAdapter;
    use scp_platform::in_memory::InMemoryStorage;
    use std::sync::Arc;

    fn variant() -> ProtocolRepoVariant {
        ProtocolRepoVariant::from_encrypted_in_memory(Arc::new(EncryptingAdapter::new(
            InMemoryStorage::new(),
            zeroize::Zeroizing::new([7u8; 32]),
        )))
    }

    fn fresh_nonce(suffix: char) -> String {
        let now = Clock::now_millis(&SystemClock);
        format!(
            "{now}-{}",
            std::iter::repeat_n(suffix, 32).collect::<String>()
        )
    }

    /// A revocation written by one instance must be readable by the next, and
    /// the rebuilt list must report the token as revoked. This is the durable
    /// half of the restart contract at the storage layer.
    #[tokio::test]
    async fn revocation_round_trips_through_the_repository() {
        let repo = variant();
        repo.store_ucan_revocation("ctx-round-trip", "cid-revoked")
            .await
            .expect("the write must succeed");

        let mut rebuilt = RevocationList::new("ctx-round-trip".to_owned());
        assert!(
            !rebuilt.is_revoked("cid-revoked"),
            "a freshly built list must start empty"
        );
        repo.hydrate_ucan_revocation_list("ctx-round-trip", &mut rebuilt)
            .await
            .expect("hydration must succeed");
        assert!(
            rebuilt.is_revoked("cid-revoked"),
            "the rebuilt list must report the persisted id as revoked"
        );
    }

    /// Two revocations that interleave — each reading the durable record before
    /// either writes — must both survive, because neither write reads the
    /// other's key.
    #[tokio::test]
    async fn interleaved_revocations_both_survive() {
        let repo = variant();
        assert!(
            repo.list_ucan_revocations("ctx-race")
                .await
                .unwrap()
                .is_empty(),
            "both writers see the empty record first"
        );
        repo.store_ucan_revocation("ctx-race", "cid-a")
            .await
            .unwrap();
        repo.store_ucan_revocation("ctx-race", "cid-b")
            .await
            .unwrap();

        let mut ids = repo.list_ucan_revocations("ctx-race").await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["cid-a".to_owned(), "cid-b".to_owned()]);
    }

    /// Hydration adds to the list rather than replacing it, so an id the caller
    /// already revoked in memory survives.
    #[tokio::test]
    async fn hydration_keeps_in_memory_revocations() {
        let repo = variant();
        repo.store_ucan_revocation("ctx-merge", "cid-durable")
            .await
            .unwrap();

        let mut live = RevocationList::new("ctx-merge".to_owned());
        live.revoke("cid-in-memory".to_owned());
        repo.hydrate_ucan_revocation_list("ctx-merge", &mut live)
            .await
            .unwrap();

        assert!(
            live.is_revoked("cid-durable"),
            "the durable id must merge in"
        );
        assert!(
            live.is_revoked("cid-in-memory"),
            "the in-memory id must survive the merge"
        );
    }

    /// A nonce consumed before a restart must be refused after one: the rebuilt
    /// tracker starts empty, and the durable record is what remembers.
    #[tokio::test]
    async fn a_consumed_nonce_is_refused_the_second_time() {
        let repo = variant();
        let now = Clock::now_secs(&SystemClock);
        let nonce = fresh_nonce('a');

        assert!(
            repo.check_and_record_ucan_nonce("ctx-nonce", &nonce, now, now + 600)
                .await
                .unwrap(),
            "the first sighting of a nonce must be accepted"
        );
        assert!(
            !repo
                .check_and_record_ucan_nonce("ctx-nonce", &nonce, now, now + 600)
                .await
                .unwrap(),
            "a second sighting of the same nonce must be refused"
        );
    }

    /// Two different nonces recorded one after the other both stay recorded,
    /// because each owns its own key.
    #[tokio::test]
    async fn two_nonces_do_not_displace_each_other() {
        let repo = variant();
        let now = Clock::now_secs(&SystemClock);
        let first = fresh_nonce('a');
        let second = fresh_nonce('b');

        assert!(
            repo.check_and_record_ucan_nonce("ctx-two", &first, now, now + 600)
                .await
                .unwrap()
        );
        assert!(
            repo.check_and_record_ucan_nonce("ctx-two", &second, now, now + 600)
                .await
                .unwrap()
        );
        assert!(
            !repo
                .check_and_record_ucan_nonce("ctx-two", &first, now, now + 600)
                .await
                .unwrap(),
            "recording the second nonce must not have erased the first"
        );
    }

    /// The nonce key component is the SHA-256 of the nonce string, which is
    /// what §17.3 of the persistence spec defines.
    #[test]
    fn nonce_hash_is_sha256_of_the_nonce_string() {
        let expected: [u8; 32] = Sha256::digest(b"1700000000000-abc").into();
        assert_eq!(nonce_hash("1700000000000-abc"), expected);
    }

    /// A caller inside a current-thread runtime reaches storage instead of
    /// being refused, which is what keeps the MCP outlet path working on a
    /// bridge whose runtime is current-thread.
    #[tokio::test(flavor = "current_thread")]
    async fn current_thread_caller_reaches_storage() {
        let repo = variant();
        block_on_storage(
            None,
            repo.store_ucan_revocation("ctx-current-thread", "cid-ct"),
        )
        .expect("the dedicated thread must drive the future")
        .expect("the write must succeed");

        assert_eq!(
            repo.list_ucan_revocations("ctx-current-thread")
                .await
                .unwrap(),
            vec!["cid-ct".to_owned()]
        );
    }

    /// A caller on a multi-threaded runtime keeps the `block_in_place` path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_thread_caller_reaches_storage() {
        let repo = variant();
        block_on_storage(None, repo.store_ucan_revocation("ctx-mt", "cid-mt"))
            .expect("block_in_place must drive the future")
            .expect("the write must succeed");

        assert_eq!(
            repo.list_ucan_revocations("ctx-mt").await.unwrap(),
            vec!["cid-mt".to_owned()]
        );
    }

    /// A caller outside any tokio runtime and with no fallback handle still
    /// reaches storage.
    #[test]
    fn caller_outside_any_runtime_reaches_storage() {
        let repo = variant();
        block_on_storage(None, repo.store_ucan_revocation("ctx-bare", "cid-bare"))
            .expect("the dedicated thread must drive the future")
            .expect("the write must succeed");
    }
}
