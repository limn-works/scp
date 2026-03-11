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
use std::sync::{Arc, OnceLock, RwLock};

use dashmap::DashMap;
use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::manager::ContextManager;
use scp_core::context::{ContextError, ContextParams};
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;

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

/// Returns a no-op key resolver for bridge-layer `ContextManager` initialization.
///
/// Governance vote signature verification is not yet wired at the `UniFFI` layer —
/// the no-op resolver returns `None` for all DIDs, which causes vote
/// verification to be skipped (permissive mode). A warning is emitted on
/// first invocation to alert operators.
fn noop_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(|_| {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "noop_key_resolver: returning None for all DIDs — \
                 governance vote signature verification is skipped. \
                 Wire a production KeyResolver before deploying."
            );
        });
        None
    })
}

/// Returns (or lazily initializes) the shared `ContextManager`.
///
/// The manager is created with stub provider implementations that delegate
/// to no-op operations. These stubs are sufficient for the FFI bridge layer
/// which validates state and routes calls — the actual crypto, transport,
/// and event log operations occur within `scp-core`. When production
/// providers are wired (e.g., via platform callbacks), they replace these
/// stubs.
///
/// Thread-safe: `OnceLock` guarantees initialization happens exactly once.
pub fn context_manager() -> &'static Arc<ContextManager> {
    CONTEXT_MANAGER.get_or_init(|| {
        Arc::new(ContextManager::new(
            Box::new(FfiBridgeCrypto),
            Box::new(FfiBridgeTransport),
            Box::new(FfiBridgeEventLog),
            noop_key_resolver(),
        ))
    })
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

/// Stub transport provider for the FFI bridge `ContextManager`.
///
/// Reports as connected and succeeds on all operations. Real transport
/// operations are handled by the `TransportManager` and relay adapters.
struct FfiBridgeTransport;

impl ContextTransportProvider for FfiBridgeTransport {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn send_message(
        &self,
        _context_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

/// Stub event log provider for the FFI bridge `ContextManager`.
///
/// All operations succeed (no-op). Real event log operations are handled
/// by `scp-event-log` (Merkle tree) through the `ContextManager`.
struct FfiBridgeEventLog;

impl ContextEventLogProvider for FfiBridgeEventLog {
    fn init_event_log(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn append_event(
        &self,
        _context_id: &[u8; 32],
        _event: &str,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn destroy_event_log(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Relay connection state (transport wiring)
// ---------------------------------------------------------------------------

/// Global relay connection for the `UniFFI` bridge.
///
/// Set by [`set_relay_connection`] when `transport_connect` succeeds.
/// Read by `transport_status` to report actual connection state.
/// Cleared by `transport_disconnect` to tear down the connection.
///
/// Uses `RwLock` for infrequent writes (connect/disconnect) and concurrent
/// reads (status queries).
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. A single relay connection is active
/// at a time — matching the `PyO3` bridge pattern.
static RELAY_CONNECTION: OnceLock<
    RwLock<Option<Arc<scp_transport::native::adapter::NativeRelayAdapter>>>,
> = OnceLock::new();

/// Tracks the URL of the currently connected relay.
///
/// Set by `transport_connect`, cleared by `transport_disconnect`,
/// read by `transport_status`.
static CONNECTED_RELAY_URL: OnceLock<RwLock<Option<String>>> = OnceLock::new();

/// Returns a reference to the global relay connection state.
fn relay_state() -> &'static RwLock<Option<Arc<scp_transport::native::adapter::NativeRelayAdapter>>>
{
    RELAY_CONNECTION.get_or_init(|| RwLock::new(None))
}

/// Returns a reference to the connected relay URL state.
fn connected_url_state() -> &'static RwLock<Option<String>> {
    CONNECTED_RELAY_URL.get_or_init(|| RwLock::new(None))
}

/// Stores a relay adapter connection after a successful connect.
///
/// # Errors
///
/// Returns an error string if the relay state lock is poisoned.
pub fn set_relay_connection(
    adapter: Arc<scp_transport::native::adapter::NativeRelayAdapter>,
    url: String,
) -> Result<(), String> {
    *relay_state()
        .write()
        .map_err(|_| "relay connection state lock is poisoned".to_owned())? = Some(adapter);
    *connected_url_state()
        .write()
        .map_err(|_| "connected relay URL lock is poisoned".to_owned())? = Some(url);
    Ok(())
}

/// Clears the active relay connection.
///
/// Called by `transport_disconnect` to tear down the connection.
/// After this, `transport_status` will report disconnected.
///
/// # Errors
///
/// Returns an error string if the state lock is poisoned.
pub fn clear_relay_connection() -> Result<(), String> {
    *relay_state()
        .write()
        .map_err(|_| "relay connection state lock is poisoned".to_owned())? = None;
    *connected_url_state()
        .write()
        .map_err(|_| "connected relay URL lock is poisoned".to_owned())? = None;
    Ok(())
}

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
