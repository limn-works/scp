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
pub mod p256_host;
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
/// Used by [`Scp::shutdown`](crate::scp::Scp::shutdown) to block runtime teardown until all handles
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

/// A host-derived §9.10.4 pseudonym, returned by
/// [`KeyCustodyProvider::derive_pseudonym`] and
/// [`KeyCustodyProvider::derive_rotatable_pseudonym`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct PseudonymResult {
    /// The 33-byte SEC1 compressed P-256 pseudonym public key.
    pub public_key: Vec<u8>,
    /// The key id of the pseudonym's signing key in the host's custody.
    pub key_id: String,
}

/// Callback for platform cryptographic key management.
///
/// Implemented by host code and injected into the Rust engine. No in-tree
/// Swift or Kotlin host implements this protocol yet: `AppleKeyCustody` and
/// `AndroidKeyCustody` implement their SDKs' own custody interfaces (UUID or
/// hex key ids, no [`PseudonymResult`]), and S0 PR8 conforms them to it.
///
/// A method reports failure by returning an [`ScpError`]. Return one whose
/// code is `SCP-CRYPTO-4006` (key not found) for a key id that was destroyed or
/// never existed; the bridge reports it as key-not-found. Any other error,
/// whatever its code, becomes the custody error `SCP-CRYPTO-4060` carrying the
/// host's code and message. Every SDK operation that calls the provider
/// reports these two codes, including the pseudonym derivation inside
/// `context_create` and the identity key reads and signatures of identity
/// operations. There are two exceptions: `SCP-IDENT-1055`, reported when the
/// bridge rejects the pseudonym a `derive_pseudonym` call returned, and
/// `SCP-IDENT-1037`, which `scpid_sign` reports for any custody failure (spec
/// §3.11.4). Throw only
/// [`ScpError`]: `UniFFI` 0.29 panics on any other error a callback throws.
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
    /// Sign `message` bytes with the key identified by `key_id`.
    ///
    /// For an Ed25519 key, returns the raw 64-byte Ed25519 signature. For a
    /// pseudonym key id from `derive_pseudonym`, `message` is a 32-byte digest
    /// and the return is the 64-byte low-`s` P-256 `r || s` (§9.5); the
    /// bridge verifies it strictly and rejects anything else, for a pseudonym
    /// key this adapter derived and still holds bound; for a handle the adapter
    /// did not bind, the bridge returns the host's bytes unchecked. A software host
    /// signs with [`crate::p256_host::p256_sign_prehash_rfc6979`] rather than
    /// its own ECDSA.
    async fn sign(&self, key_id: String, message: Vec<u8>) -> Result<Vec<u8>, ScpError>;

    /// Return the public key bytes for `key_id`: 32 bytes for an Ed25519 or
    /// X25519 key, the 33-byte compressed point for a pseudonym key.
    async fn get_public_key(&self, key_id: String) -> Result<Vec<u8>, ScpError>;

    /// Destroy key material for `key_id`. Subsequent operations must fail.
    ///
    /// Destroying an identity key also destroys its `pseudonym_secret` and
    /// every v1 and v2 pseudonym key derived from it, so each such pseudonym
    /// key id then fails too (`09-security-model.md` §9.10.4.A).
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

    /// Derive a deterministic, context-scoped P-256 pseudonym keypair (§9.10.4).
    ///
    /// The derivation runs inside the host's custody. Algorithm:
    ///   1. `pseudonym_secret = HKDF-SHA256(ikm, salt="scp-pseudonym-secret-v1", info="", L=32)`
    ///   2. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
    ///   3. `d = seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed)`; the public key
    ///      is the 33-byte SEC1 compressed point `d·G`.
    ///
    /// The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key —
    /// public key bytes would be a membership-enumeration oracle (§9.10.4).
    /// Routing fields carry `SHA-256("scp-pseudonym-routing-v1:" || point)`,
    /// which the Rust side computes from the returned point.
    ///
    /// Returns the pseudonym's 33-byte compressed point and the key id of its
    /// signing key as a [`PseudonymResult`]. The bridge rejects (fail closed,
    /// `SCP-IDENT-1055`) a point that is not a valid compressed P-256 point, a
    /// non-numeric key id, and a key id whose `get_public_key` fails or does
    /// not return the same 33 bytes. `sign` on that key id receives a 32-byte digest and
    /// must return a 64-byte low-`s` `r || s` that verifies under the point.
    /// A host maps the seed with [`crate::p256_host::p256_seed_to_scalar`]
    /// rather than reducing it itself.
    ///
    /// The pseudonym dies with its identity (`09-security-model.md`
    /// §9.10.4.A): `destroy_key` on `key_id` destroys it, and a derivation
    /// still in flight when `key_id` is destroyed fails with key-not-found
    /// (`SCP-CRYPTO-4006`) and stores nothing.
    ///
    /// The same (`key_id`, `context_id`) MUST return the same pseudonym key id
    /// on every call, so re-deriving names one key rather than minting another;
    /// the bridge's per-key-id point bindings grow with the distinct ids a
    /// host returns.
    async fn derive_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
    ) -> Result<PseudonymResult, ScpError>;

    /// Derive a rotatable (epoch-versioned) per-context pseudonym keypair.
    ///
    /// Canonical recipe (spec §9.10.4.A / §9.10.4.1): the HMAC key is the
    /// private-derived `pseudonym_secret` (HKDF over the identity private seed),
    /// NEVER the public key.
    /// `seed = HMAC-SHA256(pseudonym_secret, context_id || BE64(pseudonym_epoch) || "scp-pseudonym-v2")`;
    /// `d = seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed)`. Returns a
    /// [`PseudonymResult`], checked exactly as for `derive_pseudonym`.
    ///
    /// The same (`key_id`, `context_id`, `pseudonym_epoch`) MUST return the
    /// same pseudonym key id on every call, as for `derive_pseudonym`.
    /// Destroying `key_id` destroys this pseudonym, and an in-flight
    /// derivation fails and stores nothing, as for `derive_pseudonym`
    /// (`09-security-model.md` §9.10.4.A).
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
    /// (SCP-CTX-2050) indicating the method is not implemented. A host that
    /// rotates overrides it; no in-tree Swift or Kotlin host implements this
    /// protocol yet (S0 PR8).
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
    ) -> Result<PseudonymResult, ScpError> {
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
    /// implemented. A host that needs it overrides it (no in-tree Swift or
    /// Kotlin host implements this protocol yet, S0 PR8). Third-party
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
    /// `request_hash` — the assertion digest
    ///   `A = SHA-256("SCP-DEVICE-ASSERTION-V1:" ‖ BE32(len(m)) ‖ m)` of
    ///   `09-security-model.md` §9.3.1 over the caller's request bytes `m`,
    ///   never `SHA-256(m)` and never `m` itself. The domain separator keeps
    ///   every `A` distinct from every attestation binding digest `D`.
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

    /// `"platform"` and `"software"` are production custody kinds, so both
    /// parse in every build. `"in_memory"` names the `InMemoryKeyCustody`
    /// nullifier, so its arm is asserted per build configuration below.
    #[test]
    fn parse_custody_method_accepts_known_values() {
        use crate::bridge::parse_custody_method;

        assert!(matches!(
            parse_custody_method("platform"),
            Ok(bridge::CustodyMethod::Platform)
        ));
        assert!(matches!(
            parse_custody_method("software"),
            Ok(bridge::CustodyMethod::Software)
        ));
    }

    /// A `testing` build admits `"in_memory"`, because that feature is the sole
    /// activation path for the `InMemoryKeyCustody` nullifier backing it
    /// (ADR-062, capability injection and prove-absent dev backends,
    /// §Decision 6).
    #[cfg(feature = "testing")]
    #[test]
    fn parse_custody_method_accepts_in_memory_under_testing() {
        use crate::bridge::parse_custody_method;

        assert!(matches!(
            parse_custody_method("in_memory"),
            Ok(bridge::CustodyMethod::InMemory)
        ));
    }

    /// A shipped (no-`testing`) build rejects `"in_memory"` at the boundary with
    /// `SCP-IDENT-1008` rather than admitting a custody kind whose only backing
    /// implementation the feature severs. This is the shipped half of the
    /// severance. Job rust-build-uniffi-production names this test in its `-E`
    /// filter and runs it against `--features server`, which is the
    /// configuration a released Swift/Kotlin SDK compiles.
    #[cfg(not(feature = "testing"))]
    #[test]
    fn parse_custody_method_rejects_in_memory_on_a_shipped_build() {
        use crate::bridge::parse_custody_method;

        match parse_custody_method("in_memory") {
            Err(ScpError::Identity { code, msg }) => assert_eq!(
                code,
                scp_ffi_common::error_codes::IDENT_1008,
                "expected the custody-unavailable code SCP-IDENT-1008, got code \
                 {code} with message: {msg}"
            ),
            other => panic!("a shipped build must reject \"in_memory\" custody, got: {other:?}"),
        }
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
