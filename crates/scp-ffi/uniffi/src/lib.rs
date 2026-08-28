// UniFFI requires owned types for exported functions (no &str, no &[u8]).
// These lints are framework constraints, not code quality issues.
#![allow(
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::items_after_statements,
    clippy::significant_drop_tightening,
    clippy::too_many_lines
)]

//! `UniFFI` FFI bridge for SCP — generates Swift and Kotlin bindings.
//!
//! This crate is the Rust half of the Swift and Kotlin SDKs. It uses `UniFFI`'s
//! proc-macros (`#[uniffi::export]`) as the primary definition approach, with
//! a minimal supplementary UDL file (`scp.udl`) containing only the namespace
//! anchor required by `uniffi::include_scaffolding!`.
//!
//! # Architecture
//!
//! The bridge exposes a flat set of exported functions and object interfaces
//! mapping directly to `scp-core`'s public API. Idiomatic Swift (actors,
//! `AsyncSequence`, property wrappers) and idiomatic Kotlin (coroutines,
//! `Flow`, extension functions) are built in the pure language wrapper layers
//! (`bindings/swift/` and `bindings/kotlin/`), not in this FFI bridge. This
//! keeps the bridge thin and testable.
//!
//! # Modules
//!
//! - [`bridge`] — All `#[uniffi::export]` function definitions, opaque object
//!   `impl` blocks, record/enum derive macros, `ScpError` definition, and
//!   `From` conversions from scp-core errors.
//!
//! # Callback interfaces
//!
//! Platform trait injection (`KeyCustodyProvider`, `StorageProvider`,
//! `PushProvider`, `DeviceAttestationProvider`) and the message streaming
//! callback (`MessageListener`)
//! are defined via `#[uniffi::export(callback_interface)]` in this module.
//! `UniFFI` generates the Swift and Kotlin callback wiring from these annotations.
//!
//! # Async runtime
//!
//! A single tokio `Runtime` is created at library initialization and stored
//! in a `OnceLock<Runtime>`. All async bridge functions use `UniFFI`'s native
//! async support, which bridges between the tokio runtime and the caller's
//! concurrency context (Swift structured concurrency / Kotlin coroutines).
//!
//! Runtime shutdown is handled on library unload. The `Runtime` is dropped
//! with a 5-second grace period for in-flight tasks.
//!
//! See ADR-021 in `.docs/adrs/phase-4.md` for the full bridge specification.
//!
//! # Shutdown ordering
//!
//! SCP opaque handle objects (`Identity`, `ContextHandle`, `UcanToken`,
//! `TransportManager`) track their lifetime via a global reference counter,
//! `HANDLE_COUNT`. Call `scp_shutdown` before dropping the tokio runtime
//! to ensure all outstanding FFI handles are released first (see ADR-021
//! acceptance criterion 1 and sdk-common.md §FFI Async Bridging Risks #4).

// FFI bridge requires targeted unsafe for UniFFI scaffolding interop.
// The uniffi::include_scaffolding! macro expands unsafe extern "C" declarations.
#![allow(unsafe_code)]

use scp_ffi_common::error_codes as codes;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub mod bridge;
pub mod outlet_stream;
pub mod runtime;
pub mod scp;

// Server startup (relay + application node) — behind the `server` feature on
// scp-ffi-common.
#[cfg(feature = "server")]
pub mod server;

// Phase D (#1695): `uniffi_check_handle!` macro deleted along with
// `DEFAULT_BRIDGE_INSTANCE` and `bridge_instance_for_affinity`. Every call
// site has been migrated to an `Scp` method that performs the check
// inline with `self.inner.core.check_handle(handle.instance_id())`, so
// the affinity compare routes against the caller's own bridge instance
// instead of a shared default. There are no remaining callers of the
// macro in the bridge surface; a handle passed to a method on a different
// `Scp` will surface the same `SCP-PERM-3030` `HandleAffinityError`
// through that inline check.

// Re-export all bridge public items so UniFFI can find them at the crate root.
pub use bridge::{
    CeilingPolicy,
    ContextHandle,
    ContextMode,
    ContextParams,
    ContextState,
    CustodyMethod,
    DIDDocument,
    DataProvenance,
    Event,
    GovernanceModel,
    Identity,
    McpAllowlistState,
    McpInvokeResult,
    McpOutletInfo,
    McpServerConfig,
    MemoryScope,
    Message,
    OutletDefinition,
    OutletKind,
    OutletVerificationResult,
    Proof,
    ScpError,
    TransportManager,
    TransportStatus,
    TrustInput,
    UcanToken,
    UcanTokenData,
    // Free functions — bridge connector (#370)
    bridge_evaluate_trust,
    // Free functions — broadcast (#387)
    // Free functions — transport
    // Free functions — context lifecycle
    // Free functions — TTL (#387)
    // Free functions — membership queries (#387)
    // Free functions — discovery (#370)
    discovery_create_query,
    discovery_normalize_address,
    discovery_parse_address,
    evaluate_provenance_quality,
    // Free functions — event log
    // Free functions — governance (#387)
    // Free functions — governance proposal lifecycle (#621)
    // Free functions — identity
    // Free functions — MCP (#591)
    // The four mcp_*_stdio_allowlist free functions were deleted in
    // Per-instance allowlist — see `impl Scp::mcp_*` methods.
    // Free functions — provenance (#370)
    provenance_check_chain_depth,
    // Free functions — local DID management (#387)
    // Free functions — app sandboxing (#595)
    sandbox_check_capability,
    sandbox_validate_declaration,
    // Free functions — SCPID authentication (#1056)
    scpid_challenge,
    // Free functions — sync (#370)
    sync_classify_offline,
    sync_classify_offline_custom,
    // Free functions — outlets
    // Free functions — UCAN
};
// Phase D (#1695): `scpid_sign` free-function re-export deleted — use
// `Scp::scpid_sign` instead. The method performs the Identity
// handle-affinity check against the caller's `Scp` (the deleted free
// function read `DEFAULT_BRIDGE_INSTANCE` for that check).

// Server startup re-exports — only available with the `server` feature.
//
// Phase D (#1695): the `relay_start_in_memory` / `relay_start_local` /
// `node_start_in_memory` / `node_start_local` free functions have been
// deleted — every startup path now goes through
// `Scp::relay_start_in_memory`, `Scp::relay_start_local`,
// `Scp::node_start_in_memory`, and `Scp::node_start_local` so the returned
// handles' `instance_id` stamps against the caller's `Scp`.
#[cfg(feature = "server")]
pub use server::{NodeHandle, RelayHandle};

// `SCP` — caller-owned bridge instance, exposed to Swift and Kotlin.
pub use runtime::StorageConfig;
pub use scp::Scp;

// Include the minimal UDL-generated scaffolding. The UDL file contains only
// the namespace anchor. All types and functions are defined via proc-macros.
uniffi::include_scaffolding!("scp");

// ---------------------------------------------------------------------------
// Tokio runtime
// ---------------------------------------------------------------------------

/// Global tokio runtime, created once at library initialization.
///
/// Stored in a `OnceLock` for thread-safe lazy initialization. All async
/// bridge functions access this runtime via [`runtime()`].
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Grace period for in-flight tokio tasks during library unload.
/// 5 seconds per ADR-021 acceptance criterion 1. Exposed on the public
/// API (via `scp_shutdown(timeout_millis)`) in milliseconds for
/// cross-bridge unit unification; the internal constant stays in seconds
/// because the unit divides evenly and `from_secs` is clearer at the
/// definition site.
#[allow(dead_code)]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Handle reference counter — shutdown ordering
//
// Every opaque FFI handle object (`Identity`, `ContextHandle`, `UcanToken`,
// `TransportManager`) increments this counter on construction and decrements
// it in its `Drop` impl.
//
// `scp_shutdown` waits until this counter reaches zero (or times out) before
// allowing the tokio runtime to be dropped. This prevents use-after-free
// panics that would occur if language-side objects still held FFI handles
// when the Rust runtime was dropped.
//
// See sdk-common.md §"FFI Async Bridging Risks" rule 4.
// ---------------------------------------------------------------------------

/// Global count of live opaque FFI handle objects.
///
/// Incremented in each opaque type's constructor and decremented in `Drop`.
/// Used by [`scp_shutdown`] to block runtime teardown until all handles
/// are released.
pub(crate) static HANDLE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Increments the live handle count.
///
/// Called from each opaque type's constructor immediately after the handle
/// is allocated.
#[inline]
pub(crate) fn increment_handle_count() {
    HANDLE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Decrements the live handle count (saturating at zero).
///
/// Called from each opaque type's `Drop` impl immediately before the handle
/// is freed. Uses `fetch_update` with a saturating decrement to prevent
/// wrapping to `usize::MAX` if the count is already zero.
#[inline]
pub(crate) fn decrement_handle_count() {
    HANDLE_COUNT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
            Some(if val > 0 { val - 1 } else { 0 })
        })
        .ok();
}

// Phase D (#1695): `scp_shutdown` free function deleted. The old
// process-wide shutdown helper (and its drain-on-HANDLE_COUNT rationale)
// is replaced by the per-instance `SCP.shutdown(timeout_millis)` method
// on the caller-owned `Scp` handle, which drives its own
// `UniffiBridgeInstance::shutdown` without touching shared global state.

/// Returns a handle to the shared tokio runtime, initializing it on first call.
///
/// Uses `OnceLock::get_or_init` for thread-safe lazy initialization. All async
/// bridge functions call this to obtain the runtime before spawning tasks.
///
/// # Process termination
///
/// If the tokio runtime cannot be constructed, the process is terminated via
/// `std::process::abort()`. This is the correct behavior for a fatal library
/// initialization failure in an FFI context — returning a degraded `Option`
/// or `Result` would cause all subsequent FFI calls to fail in opaque ways
/// rather than surfacing the root cause immediately.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("scp-ffi-uniffi-worker")
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                // Abort is the correct response to a fatal FFI init failure.
                // tracing::error! is used to surface the error before
                // the process terminates without a backtrace.
                tracing::error!("FATAL: failed to create SCP UniFFI tokio runtime: {e}");
                std::process::abort();
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Callback interfaces — proc-macro definitions
//
// These traits define the platform injection surface. UniFFI's
// `#[uniffi::export(callback_interface)]` annotation generates the Swift and
// Kotlin callback wiring.
//
// ADR-021 acceptance criterion 12.
// ---------------------------------------------------------------------------

/// Callback for incoming message streams from subscribed contexts.
///
/// The Swift SDK wraps this in `AsyncStream<Message>` via
/// `AsyncStream.Continuation`. The Kotlin SDK wraps it in `Flow<Message>`
/// via `callbackFlow`. Implemented by Swift/Kotlin code and passed to
/// `context_subscribe`.
///
/// # SAFETY: Thread execution context
///
/// `UniFFI` callbacks execute on whatever Rust tokio thread is currently
/// running — NOT on the Swift/Kotlin main thread. Implementations MUST be
/// thread-safe (`Send + Sync`) and MUST NOT assume main-thread execution.
/// Any UI or main-thread-only operations MUST be dispatched explicitly:
///
/// - **Swift:** `await MainActor.run { /* UI update */ }`
/// - **Kotlin:** `withContext(Dispatchers.Main) { /* UI update */ }`
///
/// See sdk-common.md §"FFI Async Bridging Risks" rule 2.
///
/// See ADR-021 acceptance criterion 12.
#[uniffi::export(callback_interface)]
pub trait MessageListener: Send + Sync {
    /// Called when a new message arrives in the subscribed context.
    fn on_message(&self, message: Message);
    /// Called when a protocol error occurs on the message stream.
    fn on_error(&self, error: ScpError);
    /// Called when the message stream is complete (context closed).
    fn on_complete(&self);
}

/// Callback for platform cryptographic key management.
///
/// Swift SDK: Secure Enclave / Keychain.
/// Kotlin SDK: Android Keystore.
///
/// Implemented by Swift/Kotlin code and injected into the Rust engine.
///
/// # SAFETY: Thread execution context
///
/// `UniFFI` callbacks execute on Rust tokio threads, NOT the Swift/Kotlin main
/// thread. All implementations MUST be thread-safe (`Send + Sync`) and MUST
/// NOT assume main-thread execution. Keychain / Secure Enclave operations are
/// generally thread-safe; UI updates triggered from within implementations
/// MUST dispatch to the main actor/dispatcher explicitly.
///
/// See sdk-common.md §"FFI Async Bridging Risks" rule 2.
///
/// See ADR-006 (Platform Abstraction) and ADR-021 acceptance criterion 12.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait KeyCustodyProvider: Send + Sync {
    /// Sign `message` bytes with the Ed25519 key identified by `key_id`.
    ///
    /// Returns the raw 64-byte Ed25519 signature.
    async fn sign(&self, key_id: String, message: Vec<u8>) -> Result<Vec<u8>, ScpError>;

    /// Return the Ed25519 public key bytes (32 bytes) for `key_id`.
    async fn get_public_key(&self, key_id: String) -> Result<Vec<u8>, ScpError>;

    /// Destroy key material for `key_id`. Subsequent operations must fail.
    async fn destroy_key(&self, key_id: String) -> Result<(), ScpError>;

    /// Generate a new keypair. `key_type` is `"ed25519"` or `"x25519"`.
    ///
    /// Returns an opaque key identifier string.
    async fn generate_keypair(&self, key_type: String) -> Result<String, ScpError>;

    /// Perform X25519 Diffie-Hellman key agreement.
    ///
    /// `key_id` — the X25519 key handle.
    /// `peer_public` — 32-byte peer X25519 public key.
    ///
    /// Returns the 32-byte shared secret. The private key never leaves the
    /// custody boundary.
    async fn dh_agree(&self, key_id: String, peer_public: Vec<u8>) -> Result<Vec<u8>, ScpError>;

    /// Derive a deterministic, context-scoped Ed25519 pseudonym keypair.
    ///
    /// The actual derivation runs inside the injected platform `KeyCustody`
    /// callback (Swift Keychain/Secure Enclave, Kotlin Keystore). Algorithm:
    ///   1. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
    ///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`  // seed is an RFC-8032 Ed25519 seed
    ///
    /// The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key —
    /// public key bytes would be a membership-enumeration oracle (§9.10.4.A).
    /// For software custody, `pseudonym_secret = HKDF-SHA256(ed25519_private_seed,
    /// salt="scp-pseudonym-secret-v1")`, which is cross-platform deterministic
    /// (§25.19 vectors). For hardware custody (Secure Enclave, Keystore TEE) the
    /// private key is non-exportable, so `pseudonym_secret` is a device-local value
    /// computed inside the secure boundary, and those pseudonyms are device-local
    /// by design.
    ///
    /// Returns a two-element list: `[pseudonym_public_key_bytes (32), key_id (string as UTF-8)]`.
    /// The bridge unpacks this into a `PseudonymKeypair`.
    async fn derive_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
    ) -> Result<Vec<u8>, ScpError>;

    /// Derive a rotatable (epoch-versioned) per-context pseudonym keypair.
    ///
    /// Canonical recipe (spec §9.10.4.A / §9.10.4.1): the HMAC key is the
    /// private-derived `pseudonym_secret` (HKDF over the Ed25519 private seed),
    /// NEVER the public key.
    /// `seed = HMAC-SHA256(pseudonym_secret, context_id || BE64(pseudonym_epoch) || "scp-pseudonym-v2")`;
    /// `keypair = Ed25519_keygen(seed[0..32])` (RFC-8032 seed). Returns
    /// `[pseudonym_public_key_bytes (32) || key_id_utf8]`.
    ///
    /// The `pseudonym_epoch` is passed through to the provider so it performs
    /// the canonical v2 derivation itself. Bridges MUST NOT synthesize a
    /// `context_id || BE64(epoch) || "scp-pseudonym-v2"` preimage and feed it to
    /// the v1 `derive_pseudonym` — that double-appends the v1 domain separator
    /// (`"scp-pseudonym"`) and diverges from the Rust reference.
    ///
    /// # Default
    ///
    /// Rust-side providers that do not rotate return `ScpError::Context`
    /// (SCP-CTX-2050) indicating the method is not implemented. Platform SDK
    /// adapters (Swift `AppleKeyCustody`, Kotlin `AndroidKeyCustody`) override
    /// this with real implementations.
    ///
    /// **Note:** `UniFFI` callback interfaces require foreign implementations to
    /// define all methods. The generated Swift protocol / Kotlin interface will
    /// include this method. The default here applies only to Rust-side callers.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if the key is not found, is not an Ed25519 key, or the
    /// provider does not support rotatable pseudonyms.
    async fn derive_rotatable_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
        pseudonym_epoch: u64,
    ) -> Result<Vec<u8>, ScpError> {
        let _ = (key_id, context_id, pseudonym_epoch);
        Err(ScpError::Context {
            msg: "derive_rotatable_pseudonym not implemented by this KeyCustodyProvider".to_owned(),
            code: codes::CTX_2050.to_owned(),
        })
    }

    /// Export the raw Ed25519 private key bytes (32 bytes) for `key_id`.
    ///
    /// Required for governance vote signing, which uses `ed25519_dalek::SigningKey`
    /// directly. Platform implementations using software-backed Ed25519 storage
    /// (e.g., Keychain, Android Keystore with `PURPOSE_SIGN`) MUST support this.
    ///
    /// # Default
    ///
    /// Returns `ScpError::Context` (SCP-CTX-2050) indicating the method is not
    /// implemented. Platform SDKs (Swift `AppleKeyCustody`, Kotlin
    /// `AndroidKeyCustody`) override this with real implementations. Third-party
    /// `KeyCustodyProvider` implementations that do not need governance vote
    /// signing may rely on the default until they add support.
    ///
    /// **Note:** `UniFFI` callback interfaces require foreign implementations to
    /// define all methods. The generated Swift protocol / Kotlin interface will
    /// include this method. The default here applies only to Rust-side callers.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if the key is not found, not exportable, or not
    /// an Ed25519 key.
    async fn export_signing_key_bytes(&self, key_id: String) -> Result<Vec<u8>, ScpError> {
        let _ = key_id;
        Err(ScpError::Context {
            msg: "export_signing_key_bytes not implemented by this KeyCustodyProvider".to_owned(),
            code: codes::CTX_2050.to_owned(),
        })
    }

    /// Return the custody type for `key_id`: `"hardware"`, `"software"`, or
    /// `"in_memory"`. Stays sync — no I/O required.
    ///
    /// The three values name a storage location, which
    /// `scp_platform::CustodyType` consumes. What a DID document publishes
    /// about custody is a different pair of questions, and
    /// [`Self::key_is_extractable`] and [`Self::unlock_factor`] answer those.
    fn custody_type(&self, key_id: String) -> String;

    /// Return whether the private key `key_id` names can leave the store this
    /// provider holds it in.
    ///
    /// One of the two facts a DID document publishes about custody (§3.2.2 of
    /// the identity spec). Stays sync: an Apple adapter reads
    /// `kSecAttrIsExtractable` through `SecItemCopyMatching`, and an Android
    /// adapter reads `KeyInfo`, both of which are synchronous platform calls.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` when the provider cannot read the attribute, for
    /// example when `key_id` names no key it holds. A bridge that reads an
    /// error publishes no custody value for that key.
    fn key_is_extractable(&self, key_id: String) -> Result<bool, ScpError>;

    /// Return which factor unlocks the key `key_id` names: one of
    /// `"biometric"`, `"pin"`, `"passphrase"`, `"caller_supplied_key"`, or
    /// `"unprotected"`.
    ///
    /// The other fact a DID document publishes about custody (§3.2.2 of the
    /// identity spec). A string outside that set publishes no custody value
    /// rather than a guess, so an adapter that cannot name the factor is free
    /// to say so.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` when the provider cannot read the attribute. A
    /// bridge that reads an error publishes no custody value for that key.
    fn unlock_factor(&self, key_id: String) -> Result<String, ScpError>;
}

/// Callback for platform persistent key-value storage.
///
/// Swift SDK: Core Data / Keychain / file-based storage.
/// Kotlin SDK: Room / `SharedPreferences`.
///
/// # SAFETY: Thread execution context
///
/// `UniFFI` callbacks execute on Rust tokio threads, NOT the Swift/Kotlin main
/// thread. All implementations MUST be thread-safe (`Send + Sync`) and MUST
/// NOT assume main-thread execution. Storage operations are generally
/// thread-safe (Core Data with proper context management, Room with DAOs).
/// Any main-thread work triggered within an implementation MUST be dispatched
/// explicitly (`MainActor.run` / `Dispatchers.Main`).
///
/// See sdk-common.md §"FFI Async Bridging Risks" rule 2.
///
/// See ADR-006 (Platform Abstraction) and ADR-021 acceptance criterion 12.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait StorageProvider: Send + Sync {
    /// Retrieve bytes stored under `key`. Returns `None` if not found.
    async fn get(&self, key: String) -> Result<Option<Vec<u8>>, ScpError>;

    /// Store `value` bytes under `key`, overwriting any existing value.
    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ScpError>;

    /// Delete the value stored under `key`. No-op if absent.
    async fn delete(&self, key: String) -> Result<(), ScpError>;

    /// List all keys with `prefix` in lexicographic order.
    async fn list_keys(&self, prefix: String) -> Result<Vec<String>, ScpError>;

    /// Delete all keys with `prefix`. Returns the count deleted.
    async fn delete_prefix(&self, prefix: String) -> Result<u64, ScpError>;

    /// Return `true` if `key` exists without reading its value.
    async fn exists(&self, key: String) -> Result<bool, ScpError>;
}

/// Callback for platform push notification registration and handling.
///
/// Swift SDK: APNs.
/// Kotlin SDK: FCM.
///
/// # SAFETY: Thread execution context
///
/// `UniFFI` callbacks execute on Rust tokio threads, NOT the Swift/Kotlin main
/// thread. All implementations MUST be thread-safe (`Send + Sync`) and MUST
/// NOT assume main-thread execution. APNs and FCM APIs are thread-safe;
/// any UI notification work triggered within an implementation MUST be
/// dispatched to the main actor/dispatcher explicitly.
///
/// See sdk-common.md §"FFI Async Bridging Risks" rule 2.
///
/// See ADR-006 (Platform Abstraction) and ADR-021 acceptance criterion 12.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait PushProvider: Send + Sync {
    /// Register for push notifications.
    ///
    /// Returns the platform-specific token bytes (APNs device token, FCM
    /// registration token).
    ///
    /// Named `register_push` (not `register`) to avoid collision with the
    /// C keyword `register` in the UniFFI-generated callback vtable header.
    async fn register_push(&self) -> Result<Vec<u8>, ScpError>;

    /// Handle an incoming push notification `payload`.
    ///
    /// Returns wake signal bytes indicating which context has new messages.
    async fn handle_notification(&self, payload: Vec<u8>) -> Result<Vec<u8>, ScpError>;
}

/// Callback for platform device attestation.
///
/// Swift SDK: `DCAppAttestService` (App Attest on iOS 14+ / macOS 11+).
/// Kotlin SDK: Play Integrity API on Android.
///
/// Implemented by Swift/Kotlin code and injected into the Rust engine.
///
/// # SAFETY: Thread execution context
///
/// `UniFFI` callbacks execute on Rust tokio threads, NOT the Swift/Kotlin main
/// thread. All implementations MUST be thread-safe (`Send + Sync`) and MUST
/// NOT assume main-thread execution.
///
/// See sdk-common.md §"FFI Async Bridging Risks" rule 2.
///
/// See ADR-025 (Apple Platform Adapter) and ADR-021 acceptance criterion 12.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait DeviceAttestationProvider: Send + Sync {
    /// Generate a cryptographic attestation for this device.
    ///
    /// `challenge` — server-provided challenge bytes (SHA-256 digested with
    ///   `device_id` before submission to the platform attestation service).
    /// `device_id` — stable identifier for this device instance.
    ///
    /// Returns the platform attestation object bytes (Apple: CBOR-encoded
    /// attestation; Android: Play Integrity token bytes).
    async fn attest(&self, challenge: Vec<u8>, device_id: Vec<u8>) -> Result<Vec<u8>, ScpError>;

    /// Generate a per-request assertion proving key possession.
    ///
    /// `request_hash` — SHA-256 hash of the request data being asserted.
    ///
    /// Returns the platform assertion object bytes (Apple: CBOR assertion;
    /// Android: integrity verdict).
    async fn assert_request(&self, request_hash: Vec<u8>) -> Result<Vec<u8>, ScpError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    /// Returns a fresh `Scp` instance for tests. Phase 4 PR 4 demolition
    /// (#1549) deleted the free-function façade.
    fn scp_test() -> std::sync::Arc<crate::scp::Scp> {
        crate::scp::Scp::new_in_memory_for_test()
    }

    #[test]
    fn runtime_is_lazy_initialized_on_first_call() {
        // First call to runtime() should initialize it.
        let rt = runtime();
        assert!(RUNTIME.get().is_some());
        // Verify the runtime can execute a task.
        let result = rt.block_on(async { 42_u32 });
        assert_eq!(result, 42);
    }

    #[test]
    fn runtime_returns_same_instance_on_repeated_calls() {
        let first = std::ptr::from_ref(runtime());
        let second = std::ptr::from_ref(runtime());
        assert_eq!(first, second);
    }

    #[test]
    fn runtime_is_multi_threaded() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let rt = runtime();

        let counter = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let counter = Arc::clone(&counter);
                rt.spawn(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();

        rt.block_on(async {
            for handle in handles {
                handle.await.expect("task should complete");
            }
        });

        assert_eq!(counter.load(Ordering::Relaxed), 4);
    }

    /// `"in_memory"` is the test-harness custody string §3.2.2 of the identity
    /// spec calls a test affordance rather than a value of the vocabulary, and
    /// the `testing` feature decides whether the factory builds a backend for
    /// it. That feature compiles the `InMemoryKeyCustody` nullifier; a shipped
    /// build severs it, so the factory declines the string with
    /// `SCP-IDENT-1008` (ADR-062 §Decision 6).
    #[test]
    fn build_key_custody_admits_in_memory_per_compiled_feature() {
        use crate::bridge::build_key_custody;

        let result = build_key_custody("in_memory", None, None);

        #[cfg(feature = "testing")]
        match result {
            Ok((_, bridge::CustodyMethod::InMemory)) => {}
            Ok((_, other)) => panic!("expected CustodyMethod::InMemory, got: {other:?}"),
            Err(other) => panic!("expected Ok(CustodyMethod::InMemory), got: {other:?}"),
        }

        #[cfg(not(feature = "testing"))]
        match result {
            Err(ScpError::Identity { code, msg }) => {
                assert_eq!(code, "SCP-IDENT-1008");
                assert!(
                    msg.contains("identity_create_with_custody()"),
                    "message must name the injection entry point, got: {msg}"
                );
                // That entry point reaches `no_pre_rotation_backend` on this
                // build, so the message states what it returns rather than
                // sending the reader to a second closed door.
                assert!(
                    msg.contains("SCP-IDENT-1059"),
                    "message must state what that entry point returns on a \
                     shipped build, got: {msg}"
                );
            }
            other => panic!("expected SCP-IDENT-1008 for in_memory, got: {other:?}"),
        }
    }

    /// `"os_keystore"` names the operating system's own key store, which sits
    /// behind a `KeyCustodyProvider` callback. `identity_create` supplies no
    /// provider, so the value fails closed with `SCP-IDENT-1003` rather than
    /// falling back to `encrypted_file` or to an in-memory store. §3.2.2 of the
    /// identity spec states that rule and cites the no-dev-stand-in tenet of
    /// `CLAUDE.md` as the rule it applies.
    #[test]
    fn os_keystore_without_a_provider_fails_closed_with_ident_1003() {
        use crate::bridge::build_key_custody;

        match build_key_custody("os_keystore", None, None) {
            Err(ScpError::Identity { code, msg }) => {
                assert_eq!(code, "SCP-IDENT-1003");
                assert!(
                    msg.contains("identity_create_with_custody()"),
                    "message must name the entry point that takes a provider, got: {msg}"
                );
            }
            other => panic!("expected SCP-IDENT-1003 for os_keystore, got: {other:?}"),
        }
    }

    /// Every string §3.2.2 of the identity spec retired carries
    /// `SCP-VALID-7005`, the code the `PyO3` and napi bridges return for a
    /// string outside the vocabulary.
    ///
    /// `platform` and `software` once parsed into custody backends or into
    /// their own rejections on one bridge or another, `file` was the `PyO3`
    /// bridge's spelling of the encrypted key file, and `platform_managed` and
    /// `hardware` were custody-migration targets. §3.2.2 replaced all five with
    /// `encrypted_file` and `os_keystore`, and divergence D13 of §3.2.2.1
    /// records what the three SDKs said before that change.
    #[test]
    fn every_retired_custody_string_carries_valid_7005() {
        use crate::bridge::build_key_custody;

        for retired in [
            "platform",
            "software",
            "file",
            "platform_managed",
            "hardware",
        ] {
            match build_key_custody(retired, None, None) {
                Err(ScpError::Validation { code, .. }) => {
                    assert_eq!(
                        code, "SCP-VALID-7005",
                        "{retired:?} must carry SCP-VALID-7005"
                    );
                }
                other => panic!("expected SCP-VALID-7005 for {retired:?}, got: {other:?}"),
            }
        }
    }

    /// Every custody rejection that names `identity_create_with_custody` also
    /// states that the call returns `SCP-IDENT-1059` on a shipped build.
    ///
    /// `Scp::identity_create_with_custody` reaches `no_pre_rotation_backend` on
    /// a `#[cfg(not(feature = "testing"))]` build, so a message that names the
    /// entry point without naming that code sends the reader to a second closed
    /// door with nothing explaining it. Section 9.7.4.1 of the security model
    /// requires the pre-rotation commitment that has no production backend;
    /// ADR-062, capability injection and prove-absent dev backends, records
    /// that state.
    #[test]
    fn custody_rejection_messages_name_the_pre_rotation_gap() {
        use crate::bridge::build_key_custody;

        for custody in ["os_keystore", "platform", "software", "unknown"] {
            let msg = match build_key_custody(custody, None, None) {
                Err(ScpError::Identity { msg, .. } | ScpError::Validation { msg, .. }) => msg,
                other => panic!("expected a rejection for {custody:?}, got: {other:?}"),
            };
            assert!(
                msg.contains("identity_create_with_custody()"),
                "{custody:?} message must name the injection entry point, got: {msg}"
            );
            assert!(
                msg.contains("SCP-IDENT-1059"),
                "{custody:?} message must state what that entry point returns on a \
                 shipped build, got: {msg}"
            );
        }
    }

    /// A string outside the vocabulary is a wrong-value error, which
    /// `SCP-VALID-7005` names. This assertion pins the code string, because a
    /// test that checks only the `ScpError::Validation` variant passes while
    /// the code underneath it drifts.
    #[test]
    fn build_key_custody_rejects_unknown_value_with_valid_7005() {
        use crate::bridge::build_key_custody;

        match build_key_custody("unknown", None, None) {
            Err(ScpError::Validation { code, .. }) => {
                assert_eq!(code, "SCP-VALID-7005");
            }
            other => panic!("expected SCP-VALID-7005 for unknown, got: {other:?}"),
        }
    }

    #[test]
    fn scp_error_display_is_descriptive() {
        let identity = ScpError::Identity {
            msg: "test".to_owned(),
            code: codes::IDENT_1001.to_owned(),
        };
        let context = ScpError::Context {
            msg: "test".to_owned(),
            code: codes::CTX_2001.to_owned(),
        };
        assert!(identity.to_string().contains("identity error"));
        assert!(context.to_string().contains("context error"));
    }

    // scp_suspend / scp_resume tests live in tests/lifecycle.rs — in a
    // separate integration test binary — so that flipping the process-wide
    // BridgeInstance `suspended` flag does not interleave with other tests
    // in this binary that read `bridge_instance()` (which errors on
    // suspended state).

    // -----------------------------------------------------------------------
    // Conformance tests (SCP-078)
    // -----------------------------------------------------------------------

    /// Verifies that `identity_create("in_memory")` returns a DID with the
    /// `did:dht:` prefix using the real `scp-core` identity stack.
    ///
    /// Conformance: identity bridge must produce a valid, self-certifying DID.
    /// Requires the `testing` feature.
    #[test]
    #[cfg(feature = "testing")]
    fn identity_create_in_memory_produces_did_dht_prefix() {
        let rt = runtime();
        let result = rt.block_on(scp_test().identity_create("in_memory".to_owned(), None));
        let identity = result.expect("identity_create should succeed for in_memory custody");
        assert!(
            identity.did().starts_with("did:dht:"),
            "expected did:dht: prefix, got: {}",
            identity.did()
        );
    }

    /// Verifies that `identity_create("in_memory")` is rejected when the
    /// `testing` feature is NOT enabled, returning
    /// `ScpError::Identity` with code `SCP-IDENT-1008`.
    ///
    /// See GitHub issue #88 — acceptance criterion 2.
    #[test]
    #[cfg(not(feature = "testing"))]
    fn identity_create_in_memory_rejected_without_feature() {
        let rt = runtime();
        let result = rt.block_on(scp_test().identity_create("in_memory".to_owned(), None));
        match result {
            Err(ScpError::Identity { code, .. }) => {
                assert_eq!(
                    code,
                    codes::IDENT_1008,
                    "expected SCP-IDENT-1008 error code when in_memory custody is disabled"
                );
            }
            Ok(_) => {
                panic!("identity_create(\"in_memory\") should fail without testing feature");
            }
            Err(other) => {
                panic!("expected ScpError::Identity with SCP-IDENT-1008, got: {other:?}");
            }
        }
    }

    /// Verifies that `context_create` produces an `Active` context handle
    /// with a non-empty context ID.
    ///
    /// Conformance: context bridge must produce an active handle on creation.
    /// Requires the `testing` feature (needs in-memory identity).
    #[test]
    #[cfg(feature = "testing")]
    fn context_create_returns_active_context() {
        let rt = runtime();
        let scp = scp_test();

        // First create an identity to pass as the context creator.
        let identity = rt
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .expect("identity_create failed");

        let params = bridge::ContextParams {
            mode: bridge::ContextMode::Encrypted,
            ceiling: Vec::new(),
            ceiling_policy: bridge::CeilingPolicy::Immutable,
            governance: bridge::GovernanceModel::SingleAdmin,
            memory_scope: bridge::MemoryScope::Ephemeral,
            ttl_seconds: 0,
            promotable: false,
            min_protocol_version: 0,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            economic_policy: None,
            consequence_rules_json: None,
            consequence_config_json: None,
        };

        let handle = rt
            .block_on(scp.context_create(identity, params))
            .expect("context_create should succeed");

        assert_eq!(
            handle.state().expect("state() should not fail"),
            "active",
            "newly created context should be active"
        );
        assert!(
            !handle.context_id().is_empty(),
            "context_id should be non-empty"
        );
    }

    /// Verifies that `context_subscribe` accepts a mock `MessageListener`
    /// implementation and calls `on_complete` on the listener.
    ///
    /// Conformance: subscribe bridge must accept a callback interface and
    /// signal completion without panicking.
    /// Requires the `testing` feature (needs in-memory identity).
    #[test]
    #[cfg(feature = "testing")]
    fn context_subscribe_accepts_mock_listener() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct MockListener {
            completed: Arc<AtomicBool>,
        }

        impl MessageListener for MockListener {
            fn on_message(&self, _message: Message) {}
            fn on_error(&self, _error: ScpError) {}
            fn on_complete(&self) {
                self.completed.store(true, Ordering::SeqCst);
            }
        }

        let rt = runtime();
        let scp = scp_test();

        let identity = rt
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .expect("identity_create failed");

        let params = bridge::ContextParams {
            mode: bridge::ContextMode::Encrypted,
            ceiling: Vec::new(),
            ceiling_policy: bridge::CeilingPolicy::Immutable,
            governance: bridge::GovernanceModel::SingleAdmin,
            memory_scope: bridge::MemoryScope::Ephemeral,
            ttl_seconds: 0,
            promotable: false,
            min_protocol_version: 0,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            economic_policy: None,
            consequence_rules_json: None,
            consequence_config_json: None,
        };

        let handle = rt
            .block_on(scp.context_create(identity, params))
            .expect("context_create failed");

        let completed = Arc::new(AtomicBool::new(false));
        let listener = Box::new(MockListener {
            completed: Arc::clone(&completed),
        });

        rt.block_on(scp.context_subscribe(handle, listener))
            .expect("context_subscribe should succeed");

        assert!(
            completed.load(Ordering::SeqCst),
            "on_complete should have been called by context_subscribe"
        );
    }

    /// Verifies that the handle reference counter tracks live opaque objects
    /// and that dropping a handle decrements the counter.
    ///
    /// Conformance (shutdown ordering): `HANDLE_COUNT` must reflect live
    /// handles accurately so `scp_shutdown` can block until safe to teardown.
    ///
    /// Skipped outside nextest — see the in-body note on `HANDLE_COUNT` process
    /// isolation.
    /// Requires the `testing` feature (needs in-memory identity).
    #[test]
    #[cfg(feature = "testing")]
    fn handle_count_tracks_live_opaque_objects() {
        // HANDLE_COUNT is a process-global counter. These relative-delta assertions are
        // only sound when this test has the process to itself — i.e. under nextest's
        // per-test process isolation (CI's primary runner). Under shared-process
        // `cargo test`, concurrent tests in this binary mutate HANDLE_COUNT and make
        // the deltas racy, so skip there rather than assert an unsound invariant.
        if std::env::var_os("NEXTEST").is_none() {
            eprintln!(
                "skipping handle_count_tracks_live_opaque_objects: requires nextest \
                 per-test process isolation (HANDLE_COUNT is a shared process global)"
            );
            return;
        }

        let rt = runtime();

        // Measure create → drop for a single handle. Under nextest's process
        // isolation this test owns HANDLE_COUNT, so the create/drop deltas are
        // deterministic.
        let before_create = HANDLE_COUNT.load(Ordering::SeqCst);
        let id = rt
            .block_on(scp_test().identity_create("in_memory".to_owned(), None))
            .expect("identity_create failed");
        let after_create = HANDLE_COUNT.load(Ordering::SeqCst);

        assert!(
            after_create > before_create,
            "HANDLE_COUNT must increase after identity_create \
             (before={before_create}, after={after_create})"
        );

        drop(id);
        let after_drop = HANDLE_COUNT.load(Ordering::SeqCst);

        assert!(
            after_drop < after_create,
            "HANDLE_COUNT must decrease after dropping identity handle \
             (after_create={after_create}, after_drop={after_drop})"
        );
    }

    // Phase D (#1695): `scp_shutdown` free function deleted; the zero-timeout
    // fast-path test no longer applies. SCP instances are shut down via
    // `SCP.shutdown(timeout_millis)` and tests for that path live in the
    // per-instance lifecycle tests.

    // -----------------------------------------------------------------------
    // Cross-platform pseudonym derivation (SCP-214 criterion 16)
    // -----------------------------------------------------------------------

    // NOTE: routing_id tests removed — SA-15 changed ContextHandle to accept
    // Identity (for KeyCustody signing), which removed the routing_id field.
    // Routing ID tests will be re-added when routing is wired through KeyCustody.
}
