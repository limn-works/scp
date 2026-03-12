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
//! [`HANDLE_COUNT`]. Call [`scp_shutdown`] before dropping the tokio runtime
//! to ensure all outstanding FFI handles are released first (see ADR-021
//! acceptance criterion 1 and sdk-common.md §FFI Async Bridging Risks #4).

// FFI bridge requires targeted unsafe for UniFFI scaffolding interop.
// The uniffi::include_scaffolding! macro expands unsafe extern "C" declarations.
#![allow(unsafe_code)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub mod bridge;
pub(crate) mod runtime;

// Re-export all bridge public items so UniFFI can find them at the crate root.
pub use bridge::{
    ContextHandle,
    ContextParams,
    ContextState,
    CustodyMethod,
    DIDDocument,
    DataProvenance,
    Event,
    GovernanceModel,
    Identity,
    MemoryScope,
    Message,
    Proof,
    ScpError,
    ToolDefinition,
    ToolVerificationResult,
    TransportManager,
    TransportStatus,
    TrustInput,
    UcanToken,
    UcanTokenData,
    // Free functions — bridge connector (#370)
    bridge_evaluate_trust,
    broadcast_admission,
    broadcast_block_subscriber,
    broadcast_handle_key_request,
    broadcast_is_subscriber,
    broadcast_publish,
    // Free functions — broadcast (#387)
    broadcast_subscribe,
    broadcast_subscriber_count,
    broadcast_unblock_subscriber,
    broadcast_unsubscribe,
    // Free functions — context lifecycle
    context_close,
    context_create,
    context_drain_events,
    // Free functions — TTL (#387)
    context_handle_ttl_expiry,
    context_is_member,
    context_join,
    context_leave,
    // Free functions — membership queries (#387)
    context_member_count,
    context_member_dids,
    context_member_role,
    context_propose_ttl_extension,
    context_reset_ttl_timer,
    context_send,
    context_subscribe,
    // Free functions — discovery (#370)
    discovery_create_query,
    discovery_normalize_address,
    discovery_parse_address,
    evaluate_provenance_quality,
    // Free functions — event log
    event_log_query,
    event_log_verify,
    governance_approve,
    // Free functions — governance (#387)
    governance_execute,
    // Free functions — governance proposal lifecycle (#621)
    governance_get_proposal,
    governance_list_proposals,
    governance_propose,
    governance_reject,
    governance_withdraw,
    // Free functions — identity
    identity_create,
    identity_create_with_custody,
    identity_load,
    identity_resolve,
    is_local_did,
    // Free functions — provenance (#370)
    provenance_attach,
    provenance_check_chain_depth,
    // Free functions — local DID management (#387)
    register_local_did,
    // Free functions — sync (#370)
    sync_classify_offline,
    sync_classify_offline_custom,
    // Free functions — tools
    tool_invoke,
    tool_invoke_cross_context,
    tool_register,
    tool_session_close,
    tool_session_create,
    tool_session_invoke,
    tool_verify,
    // Free functions — transport
    transport_connect,
    transport_disconnect,
    transport_status,
    // Free functions — UCAN
    ucan_mint,
    ucan_revoke,
    ucan_validate,
};
// Re-export shutdown function defined in this module.
// (scp_shutdown is defined here and exported via #[uniffi::export] above.)

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
/// 5 seconds per ADR-021 acceptance criterion 1.
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

/// Decrements the live handle count.
///
/// Called from each opaque type's `Drop` impl immediately before the handle
/// is freed.
#[inline]
pub(crate) fn decrement_handle_count() {
    HANDLE_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// Waits for all outstanding FFI handles to be released, then shuts down.
///
/// Call this from Swift/Kotlin before your process exits or before tearing
/// down the SCP library. It blocks (on a background thread) until either:
///
/// - All opaque handle objects (`Identity`, `ContextHandle`, `UcanToken`,
///   `TransportManager`) have been garbage-collected / freed, **or**
/// - The `timeout_secs` deadline has elapsed.
///
/// After this call returns, the tokio runtime may be dropped safely — no
/// outstanding FFI handles remain that could attempt to call into it.
///
/// The default timeout is 5 seconds (per ADR-021 acceptance criterion 1).
/// Pass `0` to return immediately without waiting.
///
/// # Thread safety
///
/// This function is safe to call from any thread. It polls `HANDLE_COUNT`
/// in 10 ms intervals and does not block the tokio runtime.
///
/// # Example (Swift)
///
/// ```swift
/// // Call before application exit:
/// scpShutdown(timeoutSecs: 5)
/// ```
#[uniffi::export]
pub fn scp_shutdown(timeout_secs: u64) {
    if timeout_secs == 0 {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while HANDLE_COUNT.load(Ordering::Relaxed) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // The tokio runtime (`RUNTIME`) is a static and will be dropped on
    // process exit. This function ensures language-side cleanup completes
    // before that point.
}

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
/// [`context_subscribe`].
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
    /// Algorithm (all implementations MUST produce identical output):
    ///   1. `seed = HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")`
    ///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
    ///
    /// ADR-027 amendment: use public key bytes as HMAC key for cross-platform
    /// determinism with hardware TEE keys.
    ///
    /// Returns a two-element list: `[public_key_bytes (32), key_id (string as UTF-8)]`.
    /// The bridge unpacks this into a `PseudonymKeypair`.
    async fn derive_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
    ) -> Result<Vec<u8>, ScpError>;

    /// Export the raw Ed25519 private key bytes (32 bytes) for `key_id`.
    ///
    /// Required for governance vote signing, which uses `ed25519_dalek::SigningKey`
    /// directly. Platform implementations using software-backed Ed25519 storage
    /// (e.g., Keychain, Android Keystore with `PURPOSE_SIGN`) MUST support this.
    ///
    /// # Errors
    ///
    /// Returns `ScpError` if the key is not found, not exportable, or not
    /// an Ed25519 key.
    async fn export_signing_key_bytes(&self, key_id: String) -> Result<Vec<u8>, ScpError>;

    /// Return the custody type for `key_id`: `"hardware"`, `"software"`, or
    /// `"in_memory"`. Stays sync — no I/O required.
    fn custody_type(&self, key_id: String) -> String;
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

    #[test]
    fn parse_custody_method_accepts_known_values() {
        use crate::bridge::parse_custody_method;

        assert!(matches!(
            parse_custody_method("in_memory"),
            Ok(bridge::CustodyMethod::InMemory)
        ));
        assert!(matches!(
            parse_custody_method("platform"),
            Ok(bridge::CustodyMethod::Platform)
        ));
        assert!(matches!(
            parse_custody_method("software"),
            Ok(bridge::CustodyMethod::Software)
        ));
    }

    #[test]
    fn parse_custody_method_rejects_unknown_value() {
        use crate::bridge::parse_custody_method;

        let result = parse_custody_method("unknown");
        assert!(matches!(result, Err(ScpError::Validation { .. })));
    }

    #[test]
    fn scp_error_display_is_descriptive() {
        let identity = ScpError::Identity {
            message: "test".to_owned(),
            code: "SCP-IDENT-1001".to_owned(),
        };
        let context = ScpError::Context {
            message: "test".to_owned(),
            code: "SCP-CTX-2001".to_owned(),
        };
        assert!(identity.to_string().contains("identity error"));
        assert!(context.to_string().contains("context error"));
    }

    // -----------------------------------------------------------------------
    // Conformance tests (SCP-078)
    // -----------------------------------------------------------------------

    /// Verifies that `identity_create("in_memory")` returns a DID with the
    /// `did:dht:` prefix using the real `scp-core` identity stack.
    ///
    /// Conformance: identity bridge must produce a valid, self-certifying DID.
    /// Requires the `allow_in_memory_custody` feature.
    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn identity_create_in_memory_produces_did_dht_prefix() {
        let rt = runtime();
        let result = rt.block_on(identity_create("in_memory".to_owned()));
        let identity = result.expect("identity_create should succeed for in_memory custody");
        assert!(
            identity.did().starts_with("did:dht:"),
            "expected did:dht: prefix, got: {}",
            identity.did()
        );
    }

    /// Verifies that `identity_create("in_memory")` is rejected when the
    /// `allow_in_memory_custody` feature is NOT enabled, returning
    /// `ScpError::Identity` with code `SCP-IDENT-1008`.
    ///
    /// See GitHub issue #88 — acceptance criterion 2.
    #[test]
    #[cfg(not(feature = "allow_in_memory_custody"))]
    fn identity_create_in_memory_rejected_without_feature() {
        let rt = runtime();
        let result = rt.block_on(identity_create("in_memory".to_owned()));
        match result {
            Err(ScpError::Identity { code, .. }) => {
                assert_eq!(
                    code, "SCP-IDENT-1008",
                    "expected SCP-IDENT-1008 error code when in_memory custody is disabled"
                );
            }
            Ok(_) => {
                panic!(
                    "identity_create(\"in_memory\") should fail without allow_in_memory_custody feature"
                );
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
    /// Requires the `allow_in_memory_custody` feature (needs in-memory identity).
    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn context_create_returns_active_context() {
        let rt = runtime();

        // First create an identity to pass as the context creator.
        let identity = rt
            .block_on(identity_create("in_memory".to_owned()))
            .expect("identity_create failed");

        let params = bridge::ContextParams {
            ceiling: Vec::new(),
            governance: bridge::GovernanceModel::SingleAdmin,
            memory_scope: bridge::MemoryScope::Ephemeral,
            ttl_seconds: 0,
            promotable: false,
            min_protocol_version: 0,
        };

        let handle = rt
            .block_on(context_create(identity, params))
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
    /// Requires the `allow_in_memory_custody` feature (needs in-memory identity).
    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
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

        let identity = rt
            .block_on(identity_create("in_memory".to_owned()))
            .expect("identity_create failed");

        let params = bridge::ContextParams {
            ceiling: Vec::new(),
            governance: bridge::GovernanceModel::SingleAdmin,
            memory_scope: bridge::MemoryScope::Ephemeral,
            ttl_seconds: 0,
            promotable: false,
            min_protocol_version: 0,
        };

        let handle = rt
            .block_on(context_create(identity, params))
            .expect("context_create failed");

        let completed = Arc::new(AtomicBool::new(false));
        let listener = Box::new(MockListener {
            completed: Arc::clone(&completed),
        });

        rt.block_on(context_subscribe(handle, listener))
            .expect("context_subscribe should succeed");

        assert!(
            completed.load(Ordering::SeqCst),
            "on_complete should have been called by context_subscribe"
        );
    }

    /// Verifies that the handle reference counter tracks live opaque objects
    /// and returns to the pre-test baseline after all handles are dropped.
    ///
    /// Conformance (shutdown ordering): `HANDLE_COUNT` must reflect live
    /// handles accurately so `scp_shutdown` can block until safe to teardown.
    ///
    /// Tests one handle at a time to avoid interference from concurrent tests
    /// that also modify the global counter.
    /// Requires the `allow_in_memory_custody` feature (needs in-memory identity).
    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn handle_count_tracks_live_opaque_objects() {
        let rt = runtime();

        // Measure create → drop for a single handle. The delta across a single
        // create/drop is guaranteed regardless of concurrent test activity.
        let before_create = HANDLE_COUNT.load(Ordering::SeqCst);
        let id = rt
            .block_on(identity_create("in_memory".to_owned()))
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

    /// Verifies that `scp_shutdown(0)` returns immediately (no waiting).
    #[test]
    fn scp_shutdown_zero_timeout_returns_immediately() {
        // Should return without hanging even if handles are live.
        scp_shutdown(0);
    }

    // -----------------------------------------------------------------------
    // Cross-platform pseudonym derivation (SCP-214 criterion 16)
    // -----------------------------------------------------------------------

    // NOTE: routing_id tests removed — SA-15 changed ContextHandle to accept
    // Identity (for KeyCustody signing), which removed the routing_id field.
    // Routing ID tests will be re-added when routing is wired through KeyCustody.
}
