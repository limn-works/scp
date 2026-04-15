//! Shared `ContextManager` instance for the NAPI bridge.
//!
//! Replaces the previous `ContextRuntime` / `DashMap` registry with a single
//! `Arc<ContextManager>` that owns all context state. Bridge functions delegate
//! lifecycle, messaging, governance, broadcast, membership, and TTL operations
//! to the manager.
//!
//! The manager is initialized once (via `OnceLock`) with production provider
//! implementations:
//!
//! - `MlsCryptoProvider` — Real OpenMLS-backed encryption, sender key
//!   generation, and group management. Wired in issue #1294.
//! - `NotConfiguredTransportProvider` (from `scp-core`) — Returns descriptive
//!   errors until transport is configured. See issue #501.
//! - `MerkleEventLogProvider` — Persistent Merkle-chained event log backed by
//!   `ProtocolRepositoryEventLogBridge` over encrypted in-memory storage (#484).
//! - `NapiBridgePersistence` — In-memory persistence via `DashMap`.
//!
//! See issue #388 and `.docs/adrs/phase-4.md` (ADR-022).

use scp_ffi_common::bridge_instance::BridgeInstance;
use scp_ffi_common::error_codes as codes;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use scp_core::context::builder::ContextEventLogProvider;
use scp_core::context::manager::{ContextManager, ContextPersistence, ContextSnapshot};
use scp_core::context::providers::MerkleEventLogProvider;
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::tools::{SessionStore, ToolRegistry};
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

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
#[cfg(feature = "allow_in_memory_custody")]
use crate::identity::OpaqueInMemoryKeyCustody;

/// A tool handler is a closure that takes validated JSON input and returns
/// JSON output or an error string. Registered via [`register_tool_handler`].
pub type ToolHandler =
    Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

// ---------------------------------------------------------------------------
// Global ContextManager instance
// ---------------------------------------------------------------------------

/// Global shared `InMemoryDhtClient` used by the DID resolver.
///
/// Stored here so that `identity_create` can publish newly created DID
/// documents to the same DHT client that the resolver reads from. Without
/// this, UCAN validation fails because `IdentityBackedDidResolver` cannot
/// find the issuer's DID document.
///
/// See issue #1144 (UCAN validation tests require shared DHT state).
static SHARED_DHT_CLIENT: OnceLock<Arc<scp_identity::InMemoryDhtClient>> = OnceLock::new();

/// Returns the production DID resolver, if initialized.
///
/// Delegates to [`BridgeInstance::did_resolver`].
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    BRIDGE_INSTANCE.get().and_then(|bi| bi.did_resolver())
}

/// Returns the shared `InMemoryDhtClient`, if initialized.
///
/// Used by `identity_create` to publish DID documents so that the resolver
/// can later find them during UCAN validation (#1144).
#[must_use]
pub fn shared_dht_client() -> Option<&'static Arc<scp_identity::InMemoryDhtClient>> {
    SHARED_DHT_CLIENT.get()
}

/// Stores the shared `InMemoryDhtClient` for the DID resolver.
///
/// Called by `ensure_did_resolver_initialized` in `identity.rs`. Subsequent
/// calls are no-ops (`OnceLock` guarantees single initialization).
pub fn init_shared_dht_client(client: Arc<scp_identity::InMemoryDhtClient>) {
    let _ = SHARED_DHT_CLIENT.set(client);
}

/// Initializes the production DID resolver.
///
/// Stores the resolver in the `BridgeInstance`. If `BridgeInstance` is not
/// initialized yet, logs an error (`identity_create` should always run after
/// `init_context_manager`).
pub fn init_did_resolver<R>(resolver: Arc<R>, handle: tokio::runtime::Handle)
where
    R: scp_identity::resolver::DidResolver + 'static,
{
    if let Some(bi) = BRIDGE_INSTANCE.get() {
        bi.set_did_resolver(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
            resolver, handle,
        )));
    } else {
        tracing::error!(
            "init_did_resolver called before BridgeInstance initialized — resolver not stored"
        );
    }
}

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Logs an error once (via `std::sync::Once`) to signal that key resolution
/// is not configured. Subsequent lookups silently return `None` to avoid
/// log spam in governance-heavy contexts. The `KeyResolver` type signature
/// does not support `Result`, so `None` is the only way to signal failure.
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(|_did| {
        static LOG_ONCE: std::sync::Once = std::sync::Once::new();
        LOG_ONCE.call_once(|| {
            tracing::error!(
                "key resolver not configured — governance vote signature verification is disabled. \
                 Wire a production KeyResolver to enable signature verification."
            );
        });
        None
    })
}

/// Returns a reference to the shared `ContextManager`.
///
/// Delegates to [`BridgeInstance::context_manager`].
///
/// # Errors
///
/// Returns `napi::Error` if the bridge has not been initialized via
/// [`init_context_manager`], or if the bridge is currently suspended.
pub fn context_manager() -> napi::Result<&'static Arc<ContextManager>> {
    let bi = BRIDGE_INSTANCE.get().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "ContextManager not initialized — call context_create, \
                      context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    // Suspended: return error (recoverable — caller should resume()).
    // AlreadyShutDown: warn only — shutdown already destroyed state,
    // operations will fail naturally at MLS/transport layer.
    if bi.is_suspended() {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: "bridge is suspended — call resume() before performing operations".to_owned(),
            code: codes::CTX_2000.to_owned(),
        }));
    }
    if bi.is_shutdown() {
        tracing::warn!("context_manager() called after shutdown — operations may fail");
    }
    Ok(bi.context_manager())
}

// ---------------------------------------------------------------------------
// BridgeInstance (consolidated singleton — #1549)
// ---------------------------------------------------------------------------

/// Global [`BridgeInstance`] that consolidates process-global state.
///
/// Holds the `ContextManager` plus the local DID, shutdown flag, and all
/// shared state registries. Populated during
/// [`init_context_manager`]. Existing callers continue using `context_manager()`
/// and other per-registry accessors; the `BridgeInstance` provides an
/// alternative path that will eventually replace all singletons (#1549).
static BRIDGE_INSTANCE: OnceLock<Arc<BridgeInstance>> = OnceLock::new();

/// Initializes the global [`BridgeInstance`].
///
/// Called by [`init_context_manager`] (and its variants) after the
/// `ContextManager` is created. The `BridgeInstance` wraps the same
/// `Arc<ContextManager>` so that `bridge_instance().context_manager()` and
/// `context_manager()` return pointers to the same allocation.
///
/// Registers NAPI-specific shutdown hooks that clear bridge-specific
/// singletons (`IDENTITY_REGISTRY`, `UCAN_REGISTRY`). Economy state,
/// bridge connector state, and the DID resolver are now owned by
/// `BridgeInstance` and cleared in its `shutdown()` method.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
fn init_bridge_instance(context_manager: Arc<ContextManager>, local_did: &str) {
    // Guard against duplicate hook registration — OnceLock guarantees
    // single BridgeInstance creation, but hooks must only be registered once.
    if BRIDGE_INSTANCE.get().is_some() {
        return;
    }

    let instance = Arc::new(BridgeInstance::new(context_manager, local_did.to_owned()));
    let bi = BRIDGE_INSTANCE.get_or_init(|| instance);

    // Register NAPI-specific cleanup hooks. Economy state, bridge connector
    // state, and DID resolver are now owned by BridgeInstance and cleared in
    // its shutdown() method.
    //
    // Clearing the identity registry drops `Arc<OpaqueInMemoryKeyCustody>`
    // entries — custody providers zeroize key material via `Zeroizing` fields
    // when the refcount reaches zero.
    bi.register_shutdown_hook(Box::new(|| {
        #[cfg(feature = "allow_in_memory_custody")]
        if let Some(reg) = IDENTITY_REGISTRY.get() {
            reg.clear();
        }
        if let Some(reg) = UCAN_REGISTRY.get() {
            reg.clear();
        }
        // MCP server/client registries
        crate::mcp::clear_registries();
    }));
}

/// Returns the raw `BridgeInstance` reference without lifecycle checks.
///
/// Used by [`crate::scp_shutdown`] to call `BridgeInstance::shutdown()`
/// during teardown, when the bridge is transitioning to shut-down state.
/// Returns `None` if the instance was never initialized.
#[must_use]
#[cfg_attr(test, allow(dead_code))]
pub fn bridge_instance_raw() -> Option<&'static Arc<BridgeInstance>> {
    BRIDGE_INSTANCE.get()
}

/// Ensures a `BridgeInstance` exists, creating one from the given
/// `ContextManager` if necessary.
///
/// Used by `set_transport_manager` to lazily create a `BridgeInstance`
/// when it wasn't created during initialization (defensive fallback).
pub fn ensure_bridge_instance(cm: Arc<ContextManager>) {
    if BRIDGE_INSTANCE.get().is_some() {
        return;
    }
    init_bridge_instance(cm, "did:unknown:napi-bridge");
}

/// Returns a reference to the global [`BridgeInstance`].
///
/// # Errors
///
/// Returns `napi::Error` if the bridge has not been initialized via
/// [`init_context_manager`] (which also creates the `BridgeInstance`),
/// or if the bridge has been permanently shut down.
pub fn bridge_instance() -> napi::Result<&'static Arc<BridgeInstance>> {
    let bi = BRIDGE_INSTANCE.get().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "bridge not initialized — call identityCreate first".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    // Suspended: return error (recoverable — caller should resume()).
    // AlreadyShutDown: warn only — shutdown already destroyed state,
    // operations will fail naturally at MLS/transport layer.
    if bi.is_suspended() {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: "bridge is suspended — call resume() before performing operations".to_owned(),
            code: codes::CTX_2000.to_owned(),
        }));
    }
    if bi.is_shutdown() {
        tracing::warn!("bridge_instance() called after shutdown — operations may fail");
    }
    Ok(bi)
}

/// Initializes the global [`ContextManager`] with production providers.
///
/// Uses `MlsCryptoProvider` (real MLS encryption, #1294),
/// `NotConfiguredTransportProvider`, `MerkleEventLogProvider` (persistent,
/// #484), and `NapiBridgePersistence`.
///
/// The `local_did` is passed to `MlsCryptoProvider::new` which uses it as
/// the MLS credential identity for group operations and sender key generation.
///
/// Event log persistence is wired via `MerkleEventLogProvider::with_persistence`
/// backed by a `ProtocolRepositoryEventLogBridge` over an encrypted in-memory
/// storage provider. This ensures event log entries are persisted on each
/// append (issue #484 AC).
///
/// Also populates the global [`BridgeInstance`] with the same `ContextManager`
/// and `local_did`, enabling incremental migration of per-registry singletons
/// to the consolidated `BridgeInstance` (#1549).
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn init_context_manager(local_did: &str) {
    if BRIDGE_INSTANCE.get().is_some() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager already initialized — MLS crypto uses the original DID"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_core::context::NotConfiguredTransportProvider);
    let event_log = build_event_log_provider();
    let persistence = Box::new(NapiBridgePersistence::new());
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    init_bridge_instance(cm_arc, local_did);
}

/// Initializes the global [`ContextManager`] with [`LocalTransportProvider`].
///
/// Identical to [`init_context_manager`] except the transport provider is
/// `LocalTransportProvider` (silently succeeds on all send/publish calls)
/// instead of `NotConfiguredTransportProvider` (rejects everything).
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which
/// will win the `OnceLock` race if called first.
///
/// Exposed to JS/TS via [`crate::transport::configure_local_transport`] so
/// that E2E tests can exercise `contextSend` and `broadcastPublish` without
/// a real relay server.
///
/// Subsequent calls are no-ops (`OnceLock`).
pub fn init_context_manager_with_local_transport(local_did: &str) {
    if BRIDGE_INSTANCE.get().is_some() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager already initialized — ignoring local-transport init"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_core::context::LocalTransportProvider);
    let event_log = build_event_log_provider();
    let persistence = Box::new(NapiBridgePersistence::new());
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    init_bridge_instance(cm_arc, local_did);
}

/// Initializes the global [`ContextManager`] with [`RelayTransportProvider`].
///
/// Identical to [`init_context_manager`] except the transport provider is a
/// `RelayTransportProvider` wrapping a real `NativeRelayAdapter` connected to
/// the given relay URL. This allows `ContextManager::send_message` (and thus
/// `contextSend`) to publish encrypted payloads through the relay.
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which
/// will win the `OnceLock` race if called first.
///
/// Exposed to JS/TS via [`crate::transport::configure_relay_transport`] so
/// that E2E tests can exercise the full send → relay → subscribe → receive
/// pipeline.
///
/// # Arguments
///
/// * `local_did` — The DID of the first identity (MLS credential identity).
/// * `adapter` — A connected `NativeRelayAdapter` to wrap in
///   `RelayTransportProvider`.
///
/// Subsequent calls are no-ops (`OnceLock`).
pub fn init_context_manager_with_relay_transport(
    local_did: &str,
    adapter: scp_transport::native::adapter::NativeRelayAdapter,
) {
    if BRIDGE_INSTANCE.get().is_some() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager already initialized — ignoring relay-transport init"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
    let event_log = build_event_log_provider();
    let persistence = Box::new(NapiBridgePersistence::new());
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    init_bridge_instance(cm_arc, local_did);
}

/// Global `ProtocolRepository` instance, shared between the event log
/// provider and the trust store bridge. Exposed via [`protocol_repository()`]
/// for trust aggregation (issue #502).
static PROTOCOL_REPOSITORY: OnceLock<
    Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
> = OnceLock::new();

/// Returns the global `ProtocolRepository` if initialized.
///
/// Used by the trust aggregation bridge to construct a
/// `ProtocolRepositoryTrustBridge` backed by persistent (in-process) storage.
/// Returns `None` if `build_event_log_provider` has not been called yet.
#[must_use]
pub fn protocol_repository()
-> Option<&'static Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>> {
    PROTOCOL_REPOSITORY.get()
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
/// production builds. See issue #484.
///
/// SDK consumers requiring durable persistence across process restarts
/// should provide a file-backed `Storage` implementation at the application
/// layer (e.g., `SqliteStorage`). The in-memory default is suitable for the
/// Node.js/Bun environment where process lifetime matches context lifetime.
fn build_event_log_provider() -> Box<dyn ContextEventLogProvider> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);
    let encrypted = EncryptingAdapter::new(BridgeInMemoryStorage::new(), key);
    let store = Arc::new(ProtocolRepository::new(encrypted));

    // Expose the ProtocolRepository globally for trust store usage (#502).
    let _ = PROTOCOL_REPOSITORY.set(Arc::clone(&store));

    let bridge = ProtocolRepositoryEventLogBridge::new(store);
    Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
}

/// Test variant of [`context_manager`] initialization that uses
/// [`LocalTransportProvider`](scp_core::context::LocalTransportProvider) instead of
/// [`NotConfiguredTransportProvider`](scp_core::context::NotConfiguredTransportProvider)
/// and a no-op crypto provider for Rust unit tests that pass `None` key
/// package bytes with `did:key:` test DIDs.
///
/// Must be called before the first `context_manager()` call in tests.
/// `OnceLock::get_or_init` ensures only the first initialization wins.
#[cfg(test)]
pub(crate) fn init_context_manager_for_test() {
    if BRIDGE_INSTANCE.get().is_some() {
        return;
    }
    let cm_arc = Arc::new(ContextManager::with_persistence(
        Box::new(TestNoOpCryptoProvider),
        Box::new(scp_core::context::LocalTransportProvider),
        build_event_log_provider(),
        Box::new(NapiBridgePersistence::new()),
        not_configured_key_resolver(),
    ));

    // Populate the BridgeInstance with a synthetic test DID.
    init_bridge_instance(cm_arc, "did:test:napi-bridge");
}

/// No-op crypto provider for Rust unit tests only.
///
/// Accepts `None` key packages and `did:key:` DIDs, unlike the production
/// `MlsCryptoProvider` which requires real MLS key package bytes and
/// `did:dht:z` DIDs.
#[cfg(test)]
struct TestNoOpCryptoProvider;

#[cfg(test)]
impl scp_core::context::builder::ContextCryptoProvider for TestNoOpCryptoProvider {
    fn validate_creator_identity(
        &self,
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn add_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_core::context::AddMemberOutput, scp_core::context::ContextError> {
        Ok(scp_core::context::AddMemberOutput::default())
    }
    fn remove_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<scp_core::context::RemoveMemberOutput, scp_core::context::ContextError> {
        Ok(scp_core::context::RemoveMemberOutput::default())
    }
    fn distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BridgeInMemoryStorage — bridge-local Storage implementation
//
// This avoids pulling in `scp-platform/testing` (which also exposes
// `InMemoryKeyCustody`) just for event log persistence. Production builds
// must not compile `InMemoryKeyCustody` unconditionally.
// ---------------------------------------------------------------------------

/// In-memory `Storage` implementation for the NAPI bridge event log.
///
/// Identical in behavior to `scp_platform::testing::InMemoryStorage` but
/// defined locally so the `testing` feature is not required in production
/// dependencies. Only used as the backing store for the
/// `EncryptingAdapter`-wrapped `ProtocolRepository` that feeds the
/// `MerkleEventLogProvider`.
pub struct BridgeInMemoryStorage {
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

// ---------------------------------------------------------------------------
// Global identity registry — retained identity state for UCAN delegation
//
// The NAPI bridge stores key custody on the NapiIdentity JS object, but
// bridge functions like `ucan_delegate` need to look up the *delegator's*
// key, not the context creator's key. This registry provides that lookup.
// ---------------------------------------------------------------------------

/// Retained identity state for a single DID in the NAPI bridge.
///
/// Stores the `ScpIdentity` (key handles), `InMemoryKeyCustody` (key
/// material), and `DidDocument` so that bridge functions can look up any
/// registered identity by DID — including `identity_load` and
/// `identity_resolve` which need the document without DHT access (#1144 C6).
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) struct NapiIdentityEntry {
    /// The scp-core identity handle (DID string, key handles).
    pub(crate) identity: scp_identity::ScpIdentity,
    /// The key custody provider holding the actual key material.
    pub(crate) custody: Arc<OpaqueInMemoryKeyCustody>,
    /// The DID document at the time of creation (or last key rotation).
    pub(crate) document: scp_identity::DidDocument,
    /// Identity link attestations (§3.5.1). Stored locally per identity.
    pub(crate) identity_link_attestations:
        Vec<scp_core::identity::attestation::IdentityLinkAttestation>,
}

/// Global registry of identity state, keyed by DID string.
#[cfg(feature = "allow_in_memory_custody")]
static IDENTITY_REGISTRY: OnceLock<DashMap<String, NapiIdentityEntry>> = OnceLock::new();

/// Returns a reference to the global identity registry.
#[cfg(feature = "allow_in_memory_custody")]
fn identity_registry() -> &'static DashMap<String, NapiIdentityEntry> {
    IDENTITY_REGISTRY.get_or_init(DashMap::new)
}

/// Registers an identity in the global identity registry.
///
/// Called by `identity_create` and `identity_create_with_agent_key` after
/// successfully creating an identity. Bridge functions (`ucan_delegate`)
/// look up the retained `InMemoryKeyCustody` and `KeyHandle`s via
/// [`with_identity`].
///
/// Overwrites any existing entry for the same DID (idempotent — supports
/// key rotation where the same DID gets new key material).
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn register_identity(did: &str, entry: NapiIdentityEntry) {
    identity_registry().insert(did.to_owned(), entry);
}

/// Removes an identity from the global identity registry.
///
/// Called when an identity is migrated to a new DID or during cleanup.
/// The old entry is removed and its key material is dropped.
///
/// Idempotent: no-op if the DID is not present.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn remove_identity(did: &str) {
    identity_registry().remove(did);
}

/// Removes an identity from the global identity registry if present.
///
/// Returns `true` if the identity was found and removed, `false` if the
/// DID was not in the registry.
///
/// Provided as a cleanup mechanism for long-running processes alongside
/// [`remove_identity`] which is unconditional.
#[cfg(feature = "allow_in_memory_custody")]
#[must_use]
pub(crate) fn remove_identity_if_present(did: &str) -> bool {
    identity_registry().remove(did).is_some()
}

/// Executes a closure with a reference to an identity's retained state.
///
/// Looks up the identity by DID in the global registry and calls `f` with
/// a reference to the [`NapiIdentityEntry`].
///
/// # Errors
///
/// Returns `ScpNapiError::Permission` if the DID is not found (the identity
/// was not created via `identity_create` in this process).
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn with_identity<T, F>(did: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&NapiIdentityEntry) -> Result<T, ScpNapiError>,
{
    let entry = identity_registry()
        .get(did)
        .ok_or_else(|| ScpNapiError::Permission {
            message: format!(
                "identity '{did}' not found in registry — was it created with \
                 identityCreate(\"in_memory\") in this process?"
            ),
            code: codes::PERM_3023.to_owned(),
        })?;

    f(entry.value())
}

/// Executes a closure with mutable access to an identity's retained state.
///
/// Uses `DashMap::get_mut` for fine-grained per-key write locking.
///
/// # Errors
///
/// Returns `ScpNapiError::Permission` if the DID is not found.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn with_identity_mut<T, F>(did: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut NapiIdentityEntry) -> Result<T, ScpNapiError>,
{
    let mut entry = identity_registry()
        .get_mut(did)
        .ok_or_else(|| ScpNapiError::Permission {
            message: format!(
                "identity '{did}' not found in registry — was it created with \
                 identityCreate(\"in_memory\") in this process?"
            ),
            code: codes::PERM_3023.to_owned(),
        })?;

    f(entry.value_mut())
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
    /// Role state for capability checking (tool registration, invocation).
    pub role_state: ContextRoleState,
    /// Tool registry for this context (cross-context + session support).
    pub tool_registry: ToolRegistry,
    /// Registered tool handlers keyed by tool ID.
    ///
    /// When a tool is invoked, the handler is looked up here and called with
    /// the validated JSON input. If no handler is registered, the invocation
    /// falls back to echoing the validated input (echo mode).
    pub tool_handlers: HashMap<String, ToolHandler>,
    /// Session store for stateful tool sessions (spec section 6.2.1).
    pub session_store: SessionStore,
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
/// UCAN state from the `NapiContextHandle` metadata.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context state cannot be determined.
pub fn ensure_registered(handle: &NapiContextHandle) -> Result<(), ScpNapiError> {
    let context_id = handle.context_id();
    let map = ucan_registry();

    if map.contains_key(&context_id) {
        return Ok(());
    }

    let creator_did = handle.creator_did();
    let handle_ceiling = handle.ceiling();

    let ceiling_strings = if handle_ceiling.is_empty() {
        scp_core::context::roles::default_ceiling()
            .capabilities
            .iter()
            .map(scp_core::context::roles::Capability::ucan_capability_name)
            .collect::<HashSet<String>>()
    } else {
        handle_ceiling
            .into_iter()
            .map(|s| scp_core::context::roles::Capability::new(&s).ucan_capability_name())
            .collect::<HashSet<String>>()
    };

    let event_log = EventLog::new(context_id.clone());
    let revocation_list = RevocationList::new(context_id.clone());
    let nonce_tracker = NonceTracker::new(context_id.clone(), SystemClock);

    // No custom roles and default ceiling cannot fail validation.
    let role_state = match ContextRoleState::new(
        context_id.clone(),
        creator_did.clone(),
        default_ceiling(),
        Vec::new(),
        &SystemClock,
    ) {
        Ok(rs) => rs,
        Err(e) => {
            return Err(ScpNapiError::Context {
                message: format!("failed to create role state: {e}"),
                code: codes::CTX_2023.to_owned(),
            });
        }
    };

    let state = UcanContextState {
        revocation_list,
        nonce_tracker,
        ceiling_strings,
        creator_did,
        event_log,
        role_state,
        tool_registry: ToolRegistry::new(),
        tool_handlers: HashMap::new(),
        session_store: SessionStore::new(),
    };

    map.entry(context_id).or_insert(state);
    Ok(())
}

/// Executes a closure with mutable access to a context's UCAN state.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context is not found in the registry.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut UcanContextState) -> Result<T, ScpNapiError>,
{
    let map = ucan_registry();

    let mut entry = map
        .get_mut(context_id)
        .ok_or_else(|| ScpNapiError::Context {
            message: format!(
                "context '{context_id}' not found in UCAN state registry \
             -- call a UCAN or event log function with the context handle first"
            ),
            code: codes::CTX_2023.to_owned(),
        })?;

    f(entry.value_mut())
}

/// Removes UCAN state for a context.
///
/// Called when a context is closed. Idempotent.
pub fn remove_context(context_id: &str) {
    ucan_registry().remove(context_id);
    // Clean up known-context discovery entry via BridgeInstance.
    if let Ok(bi) = bridge_instance() {
        bi.remove_known_context(context_id);
    }
}

/// Re-syncs the `UcanContextState.role_state` for a context from the shared
/// `ContextManager`.
///
/// Must be called after any governance action that modifies role state
/// (`ChangeRole`, `ModifyCeiling`, `AddMember`, `RemoveMember`, etc.) so that
/// the NAPI-side copy used by UCAN/tool capability checks stays current.
///
/// # Errors
///
/// Returns `ScpNapiError` if the context is not registered in either the
/// manager or the UCAN state registry.
pub async fn sync_role_state_from_manager(context_id: &str) -> Result<(), ScpNapiError> {
    let mgr = context_manager().map_err(|e| ScpNapiError::Context {
        message: e.to_string(),
        code: codes::CTX_2000.to_owned(),
    })?;
    let new_role_state =
        mgr.get_role_state(context_id)
            .await
            .ok_or_else(|| ScpNapiError::Context {
                message: format!("context '{context_id}' not found in ContextManager"),
                code: codes::CTX_2023.to_owned(),
            })?;

    with_context(context_id, |st| {
        st.role_state = new_role_state;
        Ok(())
    })
}

/// Registers a tool handler for a tool in a context.
///
/// The handler will be called when the tool is invoked. The tool must already
/// be registered in the context's tool registry.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context is not found or the tool
/// is not registered.
pub fn register_tool_handler(
    context_id: &str,
    tool_id: &str,
    handler: ToolHandler,
) -> Result<(), ScpNapiError> {
    with_context(context_id, |st| {
        if st.tool_registry.get(tool_id).is_none() {
            return Err(ScpNapiError::Context {
                message: format!(
                    "tool '{tool_id}' not found in context '{context_id}' \
                     -- register the tool before adding a handler"
                ),
                code: codes::CTX_2023.to_owned(),
            });
        }
        st.tool_handlers.insert(tool_id.to_owned(), handler);
        Ok(())
    })
}

/// Queries event counts for trust scoring within a context.
///
/// Returns `(message_count, governance_count)` derived from the context's
/// event log. Returns `(0, 0)` if the context is not registered.
#[must_use]
pub fn query_trust_event_counts(context_id: &str, _did: &str) -> (u64, u64) {
    let map = ucan_registry();
    match map.get(context_id) {
        Some(entry) => {
            let total = u64::try_from(entry.event_log.leaves().len()).unwrap_or(u64::MAX);
            (total, 0)
        }
        None => (0, 0),
    }
}

// ---------------------------------------------------------------------------
// Invitation rate limit tracker registry (#614)
//
// Delegates to the `BridgeInstance`'s `rate_limiters` DashMap (#1549).
// ---------------------------------------------------------------------------

/// Returns a mutable reference to the rate limit tracker for the given
/// identity DID, creating one if it does not exist.
///
/// Delegates to [`BridgeInstance::with_rate_limit_tracker`]. If the bridge
/// has not been initialized (unusual — identity must be created before
/// invitation evaluation), falls back to a thread-local default tracker
/// to preserve the original infallible signature.
pub fn with_rate_limit_tracker<F, T>(identity_did: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
{
    if let Ok(bi) = bridge_instance() {
        bi.with_rate_limit_tracker(identity_did, f)
    } else {
        // Bridge not initialized — use a temporary tracker. This path
        // should not be hit in normal operation (identity is always
        // created before invitation evaluation).
        tracing::warn!(
            "with_rate_limit_tracker called before bridge init — using ephemeral tracker"
        );
        let mut tracker = scp_core::context::invitation::RateLimitTracker::default();
        f(&mut tracker)
    }
}

/// Registers a test context in the UCAN state registry.
///
/// # Panics
///
/// Panics if `ContextRoleState::new` fails with default ceiling and no
/// custom roles, which should be infallible.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub fn register_test_context(context_id: &str, creator_did: &str) {
    let map = ucan_registry();

    let ceiling_strings = scp_core::context::roles::default_ceiling()
        .capabilities
        .iter()
        .map(scp_core::context::roles::Capability::ucan_capability_name)
        .collect::<HashSet<String>>();

    // Default ceiling + no custom roles: infallible in practice.
    let role_state = ContextRoleState::new(
        context_id,
        creator_did,
        default_ceiling(),
        Vec::new(),
        &SystemClock,
    )
    .expect("ContextRoleState::new with default ceiling and no custom roles cannot fail");

    let state = UcanContextState {
        event_log: EventLog::new(context_id.to_owned()),
        revocation_list: RevocationList::new(context_id.to_owned()),
        nonce_tracker: NonceTracker::new(context_id.to_owned(), SystemClock),
        ceiling_strings,
        creator_did: creator_did.to_owned(),
        role_state,
        tool_registry: ToolRegistry::new(),
        tool_handlers: HashMap::new(),
        session_store: SessionStore::new(),
    };

    map.entry(context_id.to_owned()).or_insert(state);
}

// ---------------------------------------------------------------------------
// Transport provider — uses NotConfiguredTransportProvider from scp-core
// ---------------------------------------------------------------------------
//
// The NAPI bridge uses `scp_core::context::NotConfiguredTransportProvider`
// instead of a bridge-local no-op. This returns descriptive errors when
// transport operations are attempted without configuring a relay, rather
// than silently succeeding. See issue #501.

// NapiBridgeEventLogProvider removed — replaced by MerkleEventLogProvider
// with ProtocolRepositoryEventLogBridge persistence (issue #484).

// ---------------------------------------------------------------------------
// NapiBridgePersistence — in-memory persistence
// ---------------------------------------------------------------------------

/// In-memory persistence provider for the NAPI bridge.
///
/// Stores context and broadcast snapshots in `DashMap`s. Suitable for
/// the Node.js/Bun environment where process lifetime matches context
/// lifetime. Production persistence (`SQLite`) is configured at the
/// application layer.
struct NapiBridgePersistence {
    contexts: DashMap<String, ContextSnapshot>,
    broadcasts: DashMap<String, scp_core::context::broadcast::BroadcastContextSnapshot>,
}

impl NapiBridgePersistence {
    fn new() -> Self {
        Self {
            contexts: DashMap::new(),
            broadcasts: DashMap::new(),
        }
    }
}

impl ContextPersistence for NapiBridgePersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.contexts.get(context_id).map(|v| v.value().clone()))
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &scp_core::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.broadcasts
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<
        Option<scp_core::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.broadcasts.get(context_id).map(|v| v.value().clone()))
    }

    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts.remove(context_id);
        self.broadcasts.remove(context_id);
        Ok(())
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .contexts
            .iter()
            .map(|entry| entry.key().clone())
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Economy state registries
// ---------------------------------------------------------------------------

// Economy state is now owned by BridgeInstance. Callers access it via
// `bridge_instance()?.with_economy_budget(...)` etc. directly.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // BridgeInstance tests (#1549)
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_instance_populated_by_init_context_manager() {
        // init_context_manager_for_test populates BRIDGE_INSTANCE which owns
        // the ContextManager. Since OnceLock is process-global, the first call
        // BRIDGE_INSTANCE. Since OnceLock is process-global, the first call
        // in any test wins — subsequent calls are no-ops. We rely on this
        // being called (possibly by other tests) before asserting.
        init_context_manager_for_test();

        let cm = context_manager().expect("context_manager should be initialized");
        let bi = bridge_instance().expect("bridge_instance should be initialized");

        // Both should point to the same ContextManager allocation.
        assert!(
            Arc::ptr_eq(cm, bi.context_manager()),
            "bridge_instance().context_manager() must be the same Arc as context_manager()"
        );
    }

    #[test]
    fn bridge_instance_has_local_did() {
        init_context_manager_for_test();

        let bi = bridge_instance().expect("bridge_instance should be initialized");
        // init_context_manager_for_test uses "did:test:napi-bridge" as the
        // synthetic local DID.
        assert!(
            !bi.local_did().is_empty(),
            "bridge_instance local_did should not be empty"
        );
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() {
        init_context_manager_for_test();

        let bi = bridge_instance().expect("bridge_instance should be initialized");
        assert!(
            !bi.is_shutdown(),
            "bridge_instance should not be shutdown immediately after init"
        );
    }
}
