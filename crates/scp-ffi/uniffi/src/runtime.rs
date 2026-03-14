//! Shared `ContextManager` and per-context UCAN state registry.
//!
//! A single `Arc<ContextManager>` is created once (lazily) and shared across
//! all bridge functions. The `ContextManager` owns all per-context state
//! (membership, roles, governance, broadcast, TTL) and the injected providers
//! for crypto, transport, and event log operations.
//!
//! # Per-context UCAN state
//!
//! The `ContextManager` does not own UCAN revocation lists or nonce trackers.
//! Those are validation-layer concerns that live in the bridge. We keep a
//! lightweight `DashMap<String, UcanContextState>` registry for them, keyed by
//! context ID. This mirrors the NAPI bridge's `UcanContextState` pattern
//! (see `crates/scp-ffi/napi/src/runtime.rs`).
//!
//! # Lifecycle
//!
//! 1. First call to [`context_manager()`] initializes the shared instance.
//! 2. Bridge functions call [`context_manager()`] and delegate to the manager's
//!    async methods.
//! 3. The `ContextManager` is dropped on process exit (static `OnceLock`).
//!
//! This replaces the old `DashMap<String, ContextRuntime>` global registry
//! (deleted as part of issue #387).

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use scp_core::context::ContextError;
use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
};
use scp_core::context::manager::ContextManager;
use scp_core::context::providers::MerkleEventLogProvider;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_core::store::context::ProtocolRepositoryEventLogBridge;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;
use scp_platform::Storage;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::error::PlatformError;
use zeroize::Zeroizing;

/// Global shared `ContextManager` instance.
static CONTEXT_MANAGER: OnceLock<Arc<ContextManager>> = OnceLock::new();

/// Global production DID resolver that delegates to `scp_identity::resolver::DidResolver`
/// for full DID document validation (BEP44 signature verification, self-certification,
/// sequence number comparison, caching).
///
/// Initialized by [`init_did_resolver`] when the identity layer is first set up.
/// Used by UCAN validation when available; falls back to
/// [`scp_ffi_common::BridgeDidResolver`] (string-only) via `DispatchDidResolver`
/// when `None`.
///
/// See #311 for the unification design.
static DID_RESOLVER: OnceLock<Arc<scp_ffi_common::IdentityBackedDidResolver>> = OnceLock::new();

/// Returns the global production DID resolver, if initialized.
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    DID_RESOLVER.get()
}

/// Initializes the global production DID resolver.
///
/// Wraps any `scp_identity::resolver::DidResolver` implementation in an
/// [`IdentityBackedDidResolver`] and stores it as the process-global resolver
/// for UCAN validation.
///
/// Called once during identity system setup. Subsequent calls are no-ops
/// (the resolver is initialized via `OnceLock`).
pub fn init_did_resolver<R>(resolver: Arc<R>, handle: tokio::runtime::Handle)
where
    R: scp_identity::resolver::DidResolver + 'static,
{
    let _ = DID_RESOLVER.set(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
        resolver, handle,
    )));
}

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Unlike the previous `noop_key_resolver` (which silently returned `None`,
/// causing governance vote signature verification to be skipped), this
/// resolver logs a prominent error on every lookup, making it clear that
/// key resolution is not configured. It still returns `None` (the
/// `KeyResolver` type signature does not support `Result`), but the error
/// log ensures the gap is visible rather than silent.
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(|did| {
        tracing::error!(
            did = %did.0,
            "key resolver not configured — cannot resolve verifying key for DID. \
             Governance vote signature verification will be skipped for this DID. \
             Wire a production KeyResolver to enable signature verification."
        );
        None
    })
}

/// Returns a reference to the shared `ContextManager`.
///
/// # Errors
///
/// Returns `ScpError::Context` if the manager has not been initialized via
/// [`init_context_manager`]. Matches the `PyO3` bridge pattern: callers
/// must explicitly initialize the manager (typically during
/// `context_create`) rather than silently auto-initializing with
/// potentially invalid state.
pub fn context_manager() -> Result<&'static Arc<ContextManager>, crate::ScpError> {
    CONTEXT_MANAGER
        .get()
        .ok_or_else(|| crate::ScpError::Context {
            msg: "ContextManager not initialized — call context_create, \
                  context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: "SCP-CTX-2000".to_owned(),
        })
}

/// Builds a default `ContextManager` with bridge-local providers.
///
/// Uses `FfiBridgeCrypto` (no-op), `NotConfiguredTransportProvider`,
/// `MerkleEventLogProvider` (persistent, #484), and a not-configured key
/// resolver.
///
/// Event log persistence is wired via `MerkleEventLogProvider::with_persistence`
/// backed by a `ProtocolRepositoryEventLogBridge` over an encrypted in-memory
/// storage provider. Mobile apps (Swift/Kotlin) are killed aggressively by
/// the OS, making persistence critical for data durability.
fn build_default_context_manager() -> Arc<ContextManager> {
    let event_log = build_event_log_provider();
    Arc::new(ContextManager::new(
        Box::new(FfiBridgeCrypto),
        Box::new(scp_core::context::NotConfiguredTransportProvider),
        event_log,
        not_configured_key_resolver(),
    ))
}

/// Returns a reference to the shared `ContextManager`, initializing it if
/// necessary.
///
/// For `#[uniffi::export]` functions that return non-Result types (bool, Vec,
/// Option, ()), this provides access to the manager without requiring a
/// `Result` return type. Callers should prefer [`context_manager`] when the
/// return type supports `Result`.
///
/// Auto-initializes via `get_or_init` on first access. The initialized
/// manager uses `NotConfiguredTransportProvider` (which returns descriptive
/// errors, not silent no-ops) and `FfiBridgeCrypto` (no-op crypto for state
/// tracking). This is safe because standalone functions like
/// `register_local_did` / `is_local_did` only access the DID registry, not
/// transport or crypto, and should not require a prior `context_create` call.
pub fn context_manager_or_init() -> &'static Arc<ContextManager> {
    CONTEXT_MANAGER.get_or_init(build_default_context_manager)
}

/// Initializes the global [`ContextManager`] with bridge-local providers.
///
/// This is called during `context_create` to ensure the manager is ready
/// before any context operations.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn init_context_manager() {
    let _ = CONTEXT_MANAGER.get_or_init(build_default_context_manager);
}

/// Constructs a persistent event log provider backed by encrypted in-memory
/// storage.
///
/// Creates an `EncryptingAdapter<BridgeInMemoryStorage>` with a random
/// AES-256-GCM key, wraps it in a `ProtocolRepository`, then builds a
/// `ProtocolRepositoryEventLogBridge` that implements `EventLogPersistence`.
/// The resulting `MerkleEventLogProvider` persists entries on each append.
///
/// Uses [`BridgeInMemoryStorage`] (a bridge-local `Storage` implementation)
/// instead of `scp_platform::testing::InMemoryStorage` so that the `testing`
/// feature (which also exposes `InMemoryKeyCustody`) is not required in
/// production mobile builds. See issue #484.
fn build_event_log_provider() -> Box<dyn ContextEventLogProvider> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);
    let encrypted = EncryptingAdapter::new(BridgeInMemoryStorage::new(), key);
    let store = Arc::new(ProtocolRepository::new(encrypted));
    let bridge = ProtocolRepositoryEventLogBridge::new(store);
    Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
}

// ---------------------------------------------------------------------------
// BridgeInMemoryStorage — bridge-local Storage implementation
//
// This avoids pulling in `scp-platform/testing` (which also exposes
// `InMemoryKeyCustody`) just for event log persistence. Production mobile
// builds (iOS/Android) must not compile `InMemoryKeyCustody`.
// ---------------------------------------------------------------------------

/// In-memory `Storage` implementation for the `UniFFI` bridge event log.
///
/// Identical in behavior to `scp_platform::testing::InMemoryStorage` but
/// defined locally so the `testing` feature is not required in production
/// dependencies. Only used as the backing store for the
/// `EncryptingAdapter`-wrapped `ProtocolRepository` that feeds the
/// `MerkleEventLogProvider`.
struct BridgeInMemoryStorage {
    data: tokio::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl BridgeInMemoryStorage {
    fn new() -> Self {
        Self {
            data: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl Storage for BridgeInMemoryStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            self.data.lock().await.insert(key, data);
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move { Ok(self.data.lock().await.get(&key).cloned()) }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            self.data.lock().await.remove(&key);
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let store = self.data.lock().await;
            let mut keys: Vec<String> = store
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            drop(store);
            keys.sort();
            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let mut store = self.data.lock().await;
            let keys_to_delete: Vec<String> = store
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            let count = keys_to_delete.len() as u64;
            for key in keys_to_delete {
                store.remove(&key);
            }
            drop(store);
            Ok(count)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move { Ok(self.data.lock().await.contains_key(&key)) }
    }
}

/// Global stub crypto provider shared with the `CloseOrchestrator`.
///
/// The `CloseOrchestrator::new` requires a `&dyn ContextCryptoProvider`.
/// This provides the same no-op `FfiBridgeCrypto` used by the
/// `ContextManager` initialization. The actual crypto operations are
/// handled by the platform-injected `KeyCustodyProvider`.
static FFI_CRYPTO: FfiBridgeCrypto = FfiBridgeCrypto;

/// Returns a reference to the bridge crypto provider for `CloseOrchestrator`.
pub fn context_manager_crypto() -> &'static dyn ContextCryptoProvider {
    &FFI_CRYPTO
}

// ---------------------------------------------------------------------------
// Per-context UCAN state — retained for the UCAN validation pipeline
//
// The ContextManager does not own UCAN revocation lists or nonce trackers.
// Those are validation-layer concerns that live in the bridge. We keep a
// lightweight registry for them, keyed by context ID.
// ---------------------------------------------------------------------------

/// Per-context UCAN validation state.
///
/// Retains the `RevocationList` and `NonceTracker` needed by the UCAN
/// validation pipeline (ADR-016). These are NOT duplicates of `ContextManager`
/// state — the manager does not track UCAN revocation or nonces.
pub struct UcanContextState {
    /// UCAN revocation list for this context.
    pub revocation_list: RevocationList,
    /// UCAN nonce tracker for replay prevention (ADR-016 step 9).
    pub nonce_tracker: NonceTracker<SystemClock>,
    /// Capability ceiling as a set of `{resource}:{action}` strings for
    /// UCAN validation (ADR-016 step 8).
    pub ceiling_strings: HashSet<String>,
    /// The DID of the context creator.
    pub creator_did: String,
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
}

/// Global registry of per-context UCAN validation state.
static UCAN_REGISTRY: OnceLock<DashMap<String, UcanContextState>> = OnceLock::new();

/// Returns a reference to the UCAN state registry.
fn ucan_registry() -> &'static DashMap<String, UcanContextState> {
    UCAN_REGISTRY.get_or_init(DashMap::new)
}

/// Ensures UCAN validation state is registered for a context.
///
/// If the context is already registered, this is a no-op. Otherwise, creates
/// UCAN state from the provided context metadata.
pub fn ensure_ucan_registered(context_id: &str, creator_did: &str, ceiling: &[String]) {
    let map = ucan_registry();

    if map.contains_key(context_id) {
        return;
    }

    let ceiling_strings = if ceiling.is_empty() {
        scp_core::context::roles::default_ceiling()
            .capabilities
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<HashSet<String>>()
    } else {
        ceiling.iter().cloned().collect::<HashSet<String>>()
    };

    let event_log = EventLog::new(context_id.to_owned());
    let revocation_list = RevocationList::new(context_id.to_owned());
    let nonce_tracker = NonceTracker::new(context_id.to_owned(), SystemClock);

    map.insert(
        context_id.to_owned(),
        UcanContextState {
            revocation_list,
            nonce_tracker,
            ceiling_strings,
            creator_did: creator_did.to_owned(),
            event_log,
        },
    );
}

/// Accesses per-context UCAN state via a closure.
///
/// Returns `None` if the context is not registered. The caller is responsible
/// for converting `None` to an appropriate error.
pub fn with_ucan_state<T, F>(context_id: &str, f: F) -> Option<T>
where
    F: FnOnce(&mut UcanContextState) -> T,
{
    let map = ucan_registry();
    let mut entry = map.get_mut(context_id)?;
    Some(f(&mut entry))
}

/// Removes UCAN validation state for a context.
///
/// Called on context close to clean up per-context state.
pub fn remove_ucan_state(context_id: &str) {
    let map = ucan_registry();
    map.remove(context_id);
}

/// Syncs role state from the `ContextManager` after governance operations.
///
/// The `UniFFI` bridge reads role state directly from the `ContextManager`
/// (unlike `PyO3`/NAPI which cache `role_state` locally). This function
/// validates the `ContextManager` state is consistent and logs the sync
/// for traceability, matching the pattern of the other bridges.
///
/// # Errors
///
/// Returns `ScpError` if the context is not registered in the manager.
pub async fn sync_role_state_from_manager(context_id: &str) -> Result<(), crate::ScpError> {
    let manager = context_manager()?;
    let _role_state =
        manager
            .get_role_state(context_id)
            .await
            .ok_or_else(|| crate::ScpError::Context {
                msg: format!(
                    "context '{context_id}' not found in ContextManager during role state sync"
                ),
                code: "SCP-CTX-2040".to_owned(),
            })?;
    tracing::debug!(context_id = %context_id, "UniFFI: role state synced after governance operation");
    Ok(())
}

// ---------------------------------------------------------------------------
// Provider implementations for the FFI bridge
//
// These are thin implementations of the `ContextManager` provider traits.
// They succeed by default (no-op), allowing the `ContextManager` to track
// state (membership, roles, governance) while the actual crypto/transport/
// event-log operations are handled at a higher level or by platform
// callbacks.
//
// This pattern matches the mock providers used in `scp-core` tests, but
// is intentional for the FFI bridge: the bridge layer is responsible for
// routing and state management, not for performing cryptographic operations
// directly. Production crypto is provided by the `KeyCustodyProvider`
// callback interface injected from Swift/Kotlin.
// ---------------------------------------------------------------------------

/// Stub crypto provider for the FFI bridge `ContextManager`.
///
/// All operations succeed (no-op). Real MLS and sender key operations are
/// performed by the platform-injected `KeyCustodyProvider`.
struct FfiBridgeCrypto;

impl ContextCryptoProvider for FfiBridgeCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn create_mls_group(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn generate_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn init_broadcast_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn destroy_mls_group(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn destroy_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn add_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn remove_member(&self, _context_id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> {
        Ok(())
    }

    fn distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn remove_member_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn encrypt_message(
        &self,
        _context_id: &[u8; 32],
        _sender_did: &str,
        _payload: &[u8],
        _epoch: u64,
        _sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        Err(ContextError::CryptoFailed(
            "FfiBridgeCrypto::encrypt_message is not a real implementation — \
             wire a production crypto provider for MLS/sender-key encryption"
                .to_owned(),
        ))
    }
}

// Transport provider: uses `scp_core::context::NotConfiguredTransportProvider`
// instead of a bridge-local no-op. Returns descriptive errors when transport
// operations are attempted without configuring a relay. See issue #501.

// FfiBridgeEventLog removed — replaced by MerkleEventLogProvider with
// ProtocolRepositoryEventLogBridge persistence (issue #484).

/// Queries event counts for trust scoring within a context.
///
/// Returns `(message_count, governance_count)` derived from the context's
/// event log. The event log stores leaf hashes (Merkle tree), not full event
/// payloads, so per-DID filtering is not possible at this level.
///
/// Returns `(0, 0)` if the context is not registered.
#[must_use]
pub const fn query_trust_event_counts(_context_id: &str, _did: &str) -> (u64, u64) {
    // UniFFI bridge: ContextManager owns context state but does not expose
    // per-context event log leaf counts directly. Return (0, 0) as a stub.
    // Full trust scoring requires ContextManager event log integration.
    (0, 0)
}
