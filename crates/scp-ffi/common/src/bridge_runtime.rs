//! Shared runtime helpers for the FFI bridges.
//!
//! Contains duplicated logic that was previously copy-pasted across the `PyO3`,
//! NAPI, and `UniFFI` bridges. Each bridge re-exports the relevant
//! helpers via its own `runtime` module — this file is the single source of
//! truth.
//!
//! - [`not_configured_key_resolver`] — governance key resolver that rejects
//!   all lookups (identical in all 3 bridges).
//! - [`init_did_resolver_on`] — stores a DID resolver in a [`CoreFields`].
//!   All three bridges delegate to it from their thin `init_did_resolver`
//!   wrapper.
//! - [`did_resolver_from`] — retrieves the DID resolver from a
//!   [`CoreFields`]. All three bridges delegate to it from their thin
//!   `did_resolver` wrapper.
//! - [`build_event_log_provider`] — constructs a persistent
//!   `MerkleEventLogProvider` backed by
//!   `EncryptingAdapter<scp_platform::in_memory::InMemoryStorage>` (the
//!   durability-only in-memory storage adapter, ADR-062 §0; identical in NAPI
//!   and `UniFFI`). Returns both the provider and the underlying
//!   `ProtocolRepository` so callers can stash it on the per-bridge
//!   concrete struct (alongside [`CoreFields`]).
//! - [`UcanContextStateCore`] — shared UCAN validation state fields common to
//!   NAPI and `UniFFI` bridges.
//!
//! Gated behind the `resolvers` feature.

use std::sync::Arc;

use scp_core::context::builder::ContextEventLogProvider;
use scp_core::context::providers::MerkleEventLogProvider;
use scp_core::store::ProtocolRepository;
use scp_core::store::context::ProtocolRepositoryEventLogBridge;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::in_memory::InMemoryStorage;
use zeroize::Zeroizing;

use crate::IdentityBackedDidResolver;
use crate::bridge_instance::CoreFields;

// ---------------------------------------------------------------------------
// Key resolver
// ---------------------------------------------------------------------------

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Logs an error once (via `std::sync::Once`) to signal that key resolution
/// is not configured. Subsequent lookups silently return `None` to avoid
/// log spam in governance-heavy contexts. The `KeyResolver` type signature
/// does not support `Result`, so `None` is the only way to signal failure.
///
/// This function is identical across all 3 FFI bridges.
#[must_use]
pub fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(
        |_did: &scp_did::DID, _kid: scp_did::SigningKeyId| -> Option<ed25519_dalek::VerifyingKey> {
            static LOG_ONCE: std::sync::Once = std::sync::Once::new();
            LOG_ONCE.call_once(|| {
                tracing::error!(
                    "key resolver not configured — governance vote signature verification is disabled. \
                     Wire a production KeyResolver to enable signature verification."
                );
            });
            None
        },
    )
}

/// Builds a VM-aware governance [`KeyResolver`](scp_core::context::governance::KeyResolver)
/// backed by a production [`IdentityBackedDidResolver`].
///
/// The returned closure resolves the voter's DID document live (cache-backed)
/// and extracts the Ed25519 verifying key for the *exact* signing key the
/// caller claims (`#active` or `#agent`, via
/// [`IdentityBackedDidResolver::verifying_key_for`]). Governance vote signatures
/// are therefore verified against the document-derived key rather than any
/// key supplied by the caller (ADR-039 §3a).
///
/// Per the `KeyResolver` contract, any resolution failure — unknown DID,
/// missing verification method, network-unavailable, downgrade, or a malformed
/// key — collapses to `None` (the closure returns `Option`, not `Result`).
/// `None` causes the governance engine to reject the vote, so failing closed
/// here is the safe default.
///
/// Callers pass the bridge instance's resolver and receive a closure they
/// cannot accidentally make collapse to the always-`None`
/// [`not_configured_key_resolver`]: the only way to get this resolver is to
/// already hold a real [`IdentityBackedDidResolver`].
#[must_use]
pub fn document_vm_key_resolver(
    did_resolver: std::sync::Arc<IdentityBackedDidResolver>,
) -> scp_core::context::governance::KeyResolver {
    std::sync::Arc::new(move |did: &scp_did::DID, kid: scp_did::SigningKeyId| {
        did_resolver.verifying_key_for(did, kid).ok()
    })
}

// ---------------------------------------------------------------------------
// DID resolver helpers
// ---------------------------------------------------------------------------

/// Initializes the production DID resolver on a [`CoreFields`] instance.
///
/// Wraps any `scp_identity::resolver::DidResolver` implementation in an
/// [`IdentityBackedDidResolver`] and stores it in the `CoreFields`
/// for UCAN validation and attestation verification.
///
/// Called once during identity system setup. Subsequent calls are no-ops
/// (`OnceLock` inside `CoreFields` guarantees single initialization).
///
/// If `bridge` is `None` (bridge not yet initialized), logs an error.
/// This helper replaces the per-bridge `init_did_resolver` functions.
pub fn init_did_resolver_on<R>(
    bridge: Option<&Arc<CoreFields>>,
    resolver: Arc<R>,
    handle: tokio::runtime::Handle,
) where
    R: scp_identity::resolver::DidResolver + 'static,
{
    if let Some(bi) = bridge {
        bi.set_did_resolver(Arc::new(IdentityBackedDidResolver::new(resolver, handle)));
    } else {
        tracing::error!(
            "init_did_resolver called before bridge CoreFields initialized — \
             resolver not stored"
        );
    }
}

/// Returns the production DID resolver from a [`CoreFields`] instance, if
/// initialized.
///
/// Delegates to [`CoreFields::did_resolver`]. Returns `None` if the
/// bridge is not initialized or the resolver has not been set.
///
/// This helper replaces the per-bridge `did_resolver` functions.
#[must_use]
pub fn did_resolver_from(
    bridge: Option<&Arc<CoreFields>>,
) -> Option<&Arc<IdentityBackedDidResolver>> {
    bridge.and_then(|bi| bi.did_resolver())
}

// ---------------------------------------------------------------------------
// Event log provider builder
// ---------------------------------------------------------------------------

/// Shared encrypted in-memory storage handle backing the event-log
/// `ProtocolRepository`.
///
/// Backed by the durability-only [`InMemoryStorage`] adapter
/// (`scp_platform::in_memory`, ADR-062 §0) — the shippable in-memory storage
/// arm, selected explicitly for the dev/in-memory path (never a default or
/// fallback). This is the single `Storage` value that path owns. The
/// event-log `ProtocolRepository` is built *over* this `Arc`, and the same
/// `Arc` is returned to the bridge so it can derive the supervisor's
/// `mls_storage` (`OpenMLS`) view via `SpawnBlockingStorageAdapter`. ONE
/// store therefore backs both the event log and `mls_storage` (spec §17.6 —
/// in-memory is the dev affordance; one chosen backend, derived consumers).
pub type EventLogInMemoryStorageHandle = Arc<EncryptingAdapter<InMemoryStorage>>;

/// `ProtocolRepository` built over the shared [`EventLogInMemoryStorageHandle`].
///
/// The repository is generic over the `Arc<EncryptingAdapter<...>>` (rather
/// than an owned `EncryptingAdapter<...>`) so the underlying store can be
/// shared with the `mls_storage` consumer. `Arc<EncryptingAdapter<S>>`
/// satisfies the sealed `EncryptedStorage` bound via the
/// `impl<T: EncryptedStorage> EncryptedStorage for Arc<T>` blanket
/// (`scp-platform`).
pub type EventLogInMemoryRepo = ProtocolRepository<EventLogInMemoryStorageHandle>;

/// Constructs a persistent event log provider backed by encrypted in-memory
/// storage.
///
/// Creates an `EncryptingAdapter<InMemoryStorage>` with a random AES-256-GCM
/// key, wraps it in an `Arc`, builds a `ProtocolRepository` over that `Arc`,
/// then builds a `ProtocolRepositoryEventLogBridge` that implements
/// `EventLogPersistence`. The resulting `MerkleEventLogProvider` persists
/// entries on each append.
///
/// Returns three handles to the SAME underlying store:
/// 1. the event log provider (for `Supervisor`/`ContextManager`
///    initialization),
/// 2. the `ProtocolRepository` (for trust store usage and per-bridge
///    storage; callers stash it on the per-bridge concrete struct, e.g.
///    `NapiBridgeInstance`, `UniffiBridgeInstance`),
/// 3. the raw [`EventLogInMemoryStorageHandle`] — previously dropped. It is now
///    retained so the bridge can wrap it via `SpawnBlockingStorageAdapter`
///    into the supervisor's required `mls_storage` consumer. Because all
///    three derive from one `Arc`, the event log, persistence, and `OpenMLS`
///    storage view read/write a single in-memory store (no split-brain;
///    spec §17.6).
///
/// Backed by the durability-only [`InMemoryStorage`]
/// (`scp_platform::in_memory`) adapter — selected explicitly for this
/// in-memory event-log path, so the `testing` feature (which also exposes the
/// `InMemoryKeyCustody` nullifier) is not required in production mobile
/// builds. See ADR-062 §0 and issue #484.
///
/// This function is identical in the NAPI and `UniFFI` bridges.
pub fn build_event_log_provider() -> (
    Box<dyn ContextEventLogProvider>,
    Arc<EventLogInMemoryRepo>,
    EventLogInMemoryStorageHandle,
) {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);
    // Wrap the encrypted store in an `Arc` first so the SAME store backs the
    // event-log `ProtocolRepository` AND the returned `mls_storage` handle.
    let storage_handle: EventLogInMemoryStorageHandle =
        Arc::new(EncryptingAdapter::new(InMemoryStorage::new(), key));
    let store = Arc::new(ProtocolRepository::new(Arc::clone(&storage_handle)));

    let bridge = ProtocolRepositoryEventLogBridge::new(Arc::clone(&store));
    let event_log = Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)));
    (event_log, store, storage_handle)
}

// ---------------------------------------------------------------------------
// ProtocolRepoVariant — shared storage-backed repository enum
//
// Approved exemption from ADR-048 §2 "per-bridge concrete structs, no
// shared type-erased slots": this is a closed protocol-level enum whose
// variants trace to `StorageConfig` (in-memory vs. persistent SQLCipher).
// Duplicating it per bridge produces three identical match statements
// with no additional type safety — each bridge already owns its own
// concrete instance type, so the enum lives on a per-bridge field
// without ambiguity. See ADR-048 §2 for the rationale.
// ---------------------------------------------------------------------------

/// Protocol repository variant: an `Arc<ProtocolRepository<_>>` whose inner
/// `Storage` matches the bridge's configured persistence backend.
///
/// Before this variant existed, each bridge's `protocol_repository` was
/// always `Arc<ProtocolRepository<EncryptingAdapter<InMemoryStorage>>>`,
/// even when the bridge was constructed with a `Sqlite` storage config.
/// That meant the Merkle event log — which uses the protocol repository
/// as its backing `EventLogPersistence` — silently ran against an ephemeral
/// in-memory store, while context snapshots correctly landed in `SQLite`. On
/// restart the event log would be empty even though the rest of the state
/// survived, producing a split-brain the caller had no way to detect.
///
/// The enum dispatches the event log bridge and the trust bridge onto the
/// real backing store for each variant, so `SCP({storage: sqlite})` now
/// persists *both* snapshots and Merkle event log entries to the same
/// `SQLCipher` database.
pub enum ProtocolRepoVariant {
    /// Encrypted in-memory repository. Event log and trust aggregation are
    /// backed by an `Arc<EncryptingAdapter<InMemoryStorage>>`
    /// ([`EventLogInMemoryStorageHandle`]) with a random per-instance
    /// AES-256-GCM key. The store is held behind an `Arc` so the SAME
    /// encrypted backend feeds the event-log repository AND the supervisor's
    /// `mls_storage` view (spec §17.6 — one chosen backend, derived
    /// consumers). Data is lost when the instance drops.
    InMemory(Arc<EventLogInMemoryRepo>),
    /// SQLCipher-backed repository. Event log and trust aggregation share the
    /// same `Arc<SqliteStorage>` that backs `CoreFields::persistence`, so
    /// context snapshots, trust attestations, and event log entries all
    /// survive restart and share a single `SQLCipher` connection.
    Sqlite(Arc<ProtocolRepository<Arc<scp_platform::sqlite::SqliteStorage>>>),
}

impl ProtocolRepoVariant {
    /// Constructs a [`ContextEventLogProvider`] backed by this repository.
    ///
    /// The bridge is retained by `Arc` inside
    /// `MerkleEventLogProvider`, so subsequent `append` calls persist
    /// entries through the backing store that was configured at
    /// instance-construction time.
    #[must_use]
    pub fn event_log_provider(&self) -> Box<dyn ContextEventLogProvider> {
        match self {
            Self::InMemory(repo) => {
                let bridge = ProtocolRepositoryEventLogBridge::new(Arc::clone(repo));
                Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
            }
            Self::Sqlite(repo) => {
                let bridge = ProtocolRepositoryEventLogBridge::new(Arc::clone(repo));
                Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
            }
        }
    }

    /// Releases persistent resources held by the variant.
    ///
    /// For [`ProtocolRepoVariant::Sqlite`] this walks the
    /// `Arc<ProtocolRepository<Arc<SqliteStorage>>>` chain to reach
    /// the `SqliteStorage` and calls
    /// [`scp_platform::sqlite::SqliteStorage::close`] — releasing the
    /// advisory lock on `{dir}/scp.db.lock` even when other `Arc`
    /// holders (`CoreFields::persistence`, `ContextManager`) keep the
    /// storage struct alive until the bridge instance drops.
    /// [`ProtocolRepoVariant::InMemory`] has no persistent resources
    /// and the call is a no-op.
    ///
    /// Called from `bridge_specific_shutdown` on the NAPI + `UniFFI`
    /// bridges so that `SCP.shutdown()` at the SDK surface releases
    /// the lock without requiring the caller to drop the `SCP` handle
    /// itself.
    pub fn close(&self) {
        match self {
            Self::InMemory(_) => {}
            Self::Sqlite(repo) => {
                // `ProtocolRepository<S>::storage()` returns `&S` — here
                // `&Arc<SqliteStorage>` — and `SqliteStorage::close()` is
                // `&self`, so the `Arc` deref gives us the call we need.
                repo.storage().close();
            }
        }
    }

    /// Reads, increments, and persists the durable per-stream `monotonic_seq`
    /// grant cursor on whichever `Storage` backend this repository wraps
    /// (SCP-OUT-034 AC31), returning the seq to assign to THIS grant.
    ///
    /// Dispatches to
    /// [`next_grant_monotonic_seq`](crate::outlet_stream_credit::next_grant_monotonic_seq)
    /// over the variant's own `Storage` (`ProtocolRepository::storage()`), so
    /// the cursor shares the single per-instance backend that also holds the
    /// event log / snapshots — and is reclaimed by the same
    /// `delete_context` prefix sweep. The `napi-rs` and `UniFFI` bridges call
    /// this from `outlet_stream_grant_credit`; the `PyO3` bridge calls the
    /// underlying helper directly against its `StorageProvider`.
    ///
    /// # Errors
    ///
    /// Returns [`StreamCreditCounterError`](crate::outlet_stream_credit::StreamCreditCounterError)
    /// if the key is invalid, storage I/O fails, the persisted bytes cannot be
    /// decoded, or the counter would overflow.
    pub async fn next_stream_credit_seq(
        &self,
        context_id: &str,
        request_id: &[u8; 16],
    ) -> Result<u64, crate::outlet_stream_credit::StreamCreditCounterError> {
        match self {
            Self::InMemory(repo) => {
                crate::outlet_stream_credit::next_grant_monotonic_seq(
                    repo.storage(),
                    context_id,
                    request_id,
                )
                .await
            }
            Self::Sqlite(repo) => {
                crate::outlet_stream_credit::next_grant_monotonic_seq(
                    repo.storage(),
                    context_id,
                    request_id,
                )
                .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared UCAN validation state
// ---------------------------------------------------------------------------

/// Core per-context UCAN validation state shared by all FFI bridges.
///
/// Retains the `RevocationList` and `NonceTracker` needed by the UCAN
/// validation pipeline (ADR-016). These are NOT duplicates of `ContextManager`
/// state — the manager does not track UCAN revocation or nonces.
///
/// The NAPI bridge extends this with bridge-specific fields
/// (`outlet_registry`, `outlet_handlers`, `session_store`). The `UniFFI` bridge
/// uses this as-is (type alias `UcanContextState = UcanContextStateCore`).
///
/// This struct holds no capability ceiling and no context creator DID. Both
/// belong to the per-context supervisor actor, and every bridge reads them
/// from it at the moment it decides an authorization question: a `ModifyCeiling`
/// governance action moves the ceiling and an `AdminTransferred` action moves
/// the creator, so a copy recorded when a bridge registered the context grants
/// what the supervisor already withdrew. The `PyO3` bridge reads
/// `runtime::live_role_state`, NAPI reads `runtime::live_role_state`, and
/// `UniFFI` reads `UniffiBridgeInstance::live_role_state`. Restoring either
/// field here would give those reads a bridge-local rival that goes stale on
/// every change the supervisor applies by another route.
pub struct UcanContextStateCore {
    /// UCAN revocation list for this context.
    pub revocation_list: scp_core::crypto::ucan::revoke::RevocationList,
    /// UCAN nonce tracker for replay prevention (ADR-016 step 9).
    pub nonce_tracker: scp_core::crypto::ucan::nonce::NonceTracker<scp_clock::SystemClock>,
    /// Event log (Merkle tree) for this context.
    pub event_log: scp_event_log::EventLog,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod bridge_runtime_storage_tests {
    use super::build_event_log_provider;
    use scp_platform::Storage as _;

    /// The raw in-memory storage handle returned by
    /// [`build_event_log_provider`] and the event-log `ProtocolRepository`
    /// must read/write a single underlying store. Writing through the raw
    /// handle (the future `mls_storage` source) must be visible through the
    /// repository's `storage()` view (the event-log / persistence source),
    /// proving one store backs both consumers (spec §17.6).
    #[tokio::test]
    async fn handle_and_repo_share_one_store() {
        let (_event_log, repo, storage_handle) = build_event_log_provider();

        // Write via the raw handle (the `mls_storage` source).
        storage_handle
            .store("scp-test/key", b"value-via-handle")
            .await
            .expect("store via raw handle must succeed");

        // Read via the repository's storage view (the event-log source).
        let read_back = repo
            .storage()
            .retrieve("scp-test/key")
            .await
            .expect("retrieve via repo storage must succeed");
        assert_eq!(
            read_back.as_deref(),
            Some(b"value-via-handle".as_slice()),
            "raw handle write must be visible through the repo store — one backend"
        );

        // And the reverse direction: write via repo storage, read via handle.
        repo.storage()
            .store("scp-test/key2", b"value-via-repo")
            .await
            .expect("store via repo storage must succeed");
        let read_back2 = storage_handle
            .retrieve("scp-test/key2")
            .await
            .expect("retrieve via raw handle must succeed");
        assert_eq!(
            read_back2.as_deref(),
            Some(b"value-via-repo".as_slice()),
            "repo store write must be visible through the raw handle — one backend"
        );
    }
}
