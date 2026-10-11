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

// Links the one `#[global_allocator]`, which wipes every heap block before
// freeing it (09-security-model.md §9.15, freed heap memory).
use scp_alloc as _;

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

/// The type of a host custody key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CustodyKeyType {
    /// An Ed25519 signing key.
    Ed25519,
    /// An X25519 key-agreement key.
    X25519,
    /// A P-256 (ECDSA) signing key.
    P256,
    /// A P-256 ECDH key for HPKE.
    HpkeP256,
}

impl From<scp_platform::KeyType> for CustodyKeyType {
    fn from(key_type: scp_platform::KeyType) -> Self {
        match key_type {
            scp_platform::KeyType::Ed25519 => Self::Ed25519,
            scp_platform::KeyType::X25519 => Self::X25519,
            scp_platform::KeyType::P256Signing => Self::P256,
            scp_platform::KeyType::HpkeP256 => Self::HpkeP256,
        }
    }
}

impl From<CustodyKeyType> for scp_platform::KeyType {
    fn from(key_type: CustodyKeyType) -> Self {
        match key_type {
            CustodyKeyType::Ed25519 => Self::Ed25519,
            CustodyKeyType::X25519 => Self::X25519,
            CustodyKeyType::P256 => Self::P256Signing,
            CustodyKeyType::HpkeP256 => Self::HpkeP256,
        }
    }
}

/// The role a host custody key was minted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CustodyKeyRole {
    /// The participant's identity key, the only pseudonym-derivation source.
    Identity,
    /// Any other key.
    Operational,
}

impl From<scp_platform::KeyRole> for CustodyKeyRole {
    fn from(role: scp_platform::KeyRole) -> Self {
        match role {
            scp_platform::KeyRole::Identity => Self::Identity,
            scp_platform::KeyRole::Operational => Self::Operational,
        }
    }
}

impl From<CustodyKeyRole> for scp_platform::KeyRole {
    fn from(role: CustodyKeyRole) -> Self {
        match role {
            CustodyKeyRole::Identity => Self::Identity,
            CustodyKeyRole::Operational => Self::Operational,
        }
    }
}

/// A host key's type, public key and role, returned by
/// [`KeyCustodyProvider::get_public_key`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CustodyPublicKey {
    /// The key's type.
    pub key_type: CustodyKeyType,
    /// The public key in that type's one encoding: 32 bytes (Ed25519,
    /// X25519), the 33-byte compressed SEC1 point (P-256 signing), or the
    /// 65-byte uncompressed SEC1 point (HPKE P-256).
    pub public_key: Vec<u8>,
    /// The role [`KeyCustodyProvider::generate_keypair`] minted the key in.
    pub role: CustodyKeyRole,
}

/// Callback for platform cryptographic key management.
///
/// Implemented by host code and injected into the Rust engine. The Swift SDK's
/// `AppleKeyCustody` conforms to it over the Keychain, and the Kotlin SDK's
/// `UniffiKeyCustody` implements it over `AndroidKeyCustody`; either is the
/// provider the `os_keystore` custody request reaches (spec 03 §3.2.2).
///
/// A method reports failure by returning an [`ScpError`]. Return one whose
/// code is `SCP-CRYPTO-4006` (key not found) for a key id that was destroyed or
/// never existed; the bridge reports it as key-not-found. Any other error,
/// whatever its code, becomes the custody error `SCP-CRYPTO-4060` carrying the
/// host's code and message. Every SDK operation that calls the provider
/// reports these two codes, including the pseudonym derivation inside
/// `context_create` and the identity key reads and signatures of identity
/// operations. There are two exceptions: `SCP-IDENT-1055`, reported when the
/// bytes a `derive_pseudonym` or `derive_rotatable_pseudonym` call returned
/// are not a compressed P-256 point, and `SCP-IDENT-1037`, which `scpid_sign`
/// reports for any custody failure (spec §3.11.4). Throw only
/// [`ScpError`]: `UniFFI` 0.29 panics on any other error a callback throws.
///
/// Every key id the host returns is the canonical decimal form of a `u64`, as
/// `String(n)` (Swift, `UInt64`) or `n.toString()` (Kotlin, `ULong`) writes it:
/// ASCII digits only, with no sign, no leading zero (`"0"` itself is allowed)
/// and no whitespace. The bridge rejects any other id (`"007"`, `"+7"`,
/// `" 7"`, a UUID) from `generate_keypair` with the custody error
/// `SCP-CRYPTO-4060`.
///
/// A pseudonym has no private key (`09-security-model.md` §9.10.4): a host
/// stores no pseudonym key and signs with none, so `sign`, `get_public_key`
/// and `destroy_key` never receive a pseudonym.
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
    /// For an Ed25519 key, returns the raw 64-byte signature. For a P-256 signing
    /// key, `message` is a 32-byte prehash (§9.5.1, no second hash) and the
    /// result is raw `r || s` (64 bytes) or DER (`SecKeyCreateSignature` /
    /// `java.security.Signature` output); the bridge normalises it to low-s
    /// and verifies it strictly against the key's registered public key, and
    /// any mismatch is an error. A software host MUST derive the ECDSA nonce
    /// by RFC 6979 with SHA-256; a hardware host (Secure Enclave,
    /// `StrongBox`/TEE) may use a random nonce.
    async fn sign(&self, key_id: String, message: Vec<u8>) -> Result<Vec<u8>, ScpError>;

    /// Return the type and public key of `key_id` as a [`CustodyPublicKey`].
    ///
    /// The bridge types the key by `key_type` alone and requires exactly that
    /// type's length: 32 bytes (`"ed25519"`, `"x25519"`), the 33-byte
    /// compressed SEC1 point (P-256 signing), or the 65-byte uncompressed
    /// SEC1 point (HPKE P-256). A length that does not match the stated type,
    /// or an invalid point, is an error, and the bridge binds nothing. The bridge asks this for every key id it has not yet
    /// registered, whichever operation names it first.
    ///
    /// `role` is the role `generate_keypair` minted the key in, recorded by
    /// the host for the key's lifetime and reported across sessions. A key id
    /// the bridge has not seen binds as an identity only when `role` is
    /// [`CustodyKeyRole::Identity`], so an identity from an earlier session
    /// can still derive pseudonyms. The bridge cannot check the host's word:
    /// a host that reports an identity for a key it minted as operational
    /// lets that key derive pseudonyms, which is outside Rust's control.
    async fn get_public_key(&self, key_id: String) -> Result<CustodyPublicKey, ScpError>;

    /// Destroy key material for `key_id`. Subsequent operations must fail,
    /// including pseudonym derivation under a destroyed identity key, which
    /// returns `SCP-CRYPTO-4006` (`09-security-model.md` §9.10.4.A).
    async fn destroy_key(&self, key_id: String) -> Result<(), ScpError>;

    /// Generate a new keypair of `key_type` in `role`
    /// ([`CustodyKeyRole::Identity`] is the only pseudonym-derivation
    /// source). The host records `role` and reports it from
    /// [`Self::get_public_key`] for the key's lifetime; the bridge refuses
    /// and destroys a key whose reported type or role differs.
    ///
    /// Returns the new key's id, a canonical decimal `u64` string (see
    /// [`KeyCustodyProvider`]); the bridge rejects any other id with
    /// `SCP-CRYPTO-4060`. A host never reuses a key id: the id returned here
    /// names no other key on the host for the host's lifetime, even after
    /// that key is destroyed.
    async fn generate_keypair(
        &self,
        key_type: CustodyKeyType,
        role: CustodyKeyRole,
    ) -> Result<String, ScpError>;

    /// Perform Diffie-Hellman key agreement.
    ///
    /// `key_id` — the X25519 or HPKE P-256 key handle.
    /// `peer_public` — the 32-byte peer X25519 public key, or for
    /// HPKE P-256 the 65-byte uncompressed SEC1 peer point (validated
    /// on-curve by the bridge before this call).
    ///
    /// Returns the 32-byte shared secret. The private key never leaves the
    /// custody boundary.
    async fn dh_agree(&self, key_id: String, peer_public: Vec<u8>) -> Result<Vec<u8>, ScpError>;

    /// Derive the deterministic, context-scoped P-256 pseudonym point (§9.10.4).
    ///
    /// The derivation runs inside the host's custody. Canonical recipe
    /// (§9.10.4, §9.10.4.A; every software host MUST produce identical bytes;
    /// `ikm` is the identity private key material, the 32-byte Ed25519 seed
    /// until the identity key moves to P-256 (SCP-315)):
    ///   1. `pseudonym_secret = HKDF-SHA256(ikm, salt="scp-pseudonym-secret-v1", info="", L=32)`
    ///   2. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
    ///   3. `d = seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed)`; return the
    ///      33-byte SEC1 compressed point `d·G`. `d` is discarded, never stored.
    ///
    /// The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key —
    /// public key bytes would be a membership-enumeration oracle (§9.10.4.A).
    /// Routing fields carry `SHA-256("scp-pseudonym-routing-v1:" || point)`,
    /// which the Rust side computes from the returned point.
    ///
    /// Returns the 33-byte compressed point and nothing else. The bridge
    /// fails the derivation with `SCP-IDENT-1055` when the bytes are not a
    /// valid compressed P-256 point. A host returns `SCP-CRYPTO-4006` when
    /// `key_id` was destroyed or never existed, and the caller receives
    /// key-not-found.
    async fn derive_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
    ) -> Result<Vec<u8>, ScpError>;

    /// Derive a rotatable (epoch-versioned) per-context pseudonym point.
    ///
    /// Canonical recipe (§9.10.4.1): steps 1 and 3 of `derive_pseudonym`, with
    /// step 2 replaced by
    ///   `seed = HMAC-SHA256(pseudonym_secret, context_id || BE64(pseudonym_epoch) || "scp-pseudonym-v2")`
    /// where `BE64` is the 8-byte big-endian epoch. The HMAC key is the
    /// `pseudonym_secret`, NEVER the public key. Returns the 33-byte
    /// compressed point, checked exactly as for `derive_pseudonym`.
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
    /// rotates overrides it.
    ///
    /// **Note:** `UniFFI` callback interfaces require foreign implementations to
    /// define all methods. The generated Swift protocol / Kotlin interface will
    /// include this method. The default here applies only to Rust-side callers.
    ///
    /// # Errors
    ///
    /// The host returns an `ScpError` with `SCP-CRYPTO-4006` when `key_id` was
    /// destroyed or never existed, and the caller receives key-not-found
    /// (`SCP-CRYPTO-4006`). Any other host error, including the Rust default's
    /// `SCP-CTX-2050`, reaches the caller as the custody error `SCP-CRYPTO-4060`
    /// carrying the host's code and message. A returned result the bridge
    /// rejects is `SCP-IDENT-1055`, as for `derive_pseudonym`.
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
    /// The bridge's signing paths that sign with an `ed25519_dalek::SigningKey`,
    /// governance vote signing among them, build that key from the returned
    /// bytes. A key held in hardware or in Android Keystore does not export its
    /// bytes, and ADR-063 requires every key-export accessor, this callback
    /// included, to leave the custody adapters and all three bridges, because
    /// hardware custody on the governance path is impossible until then.
    ///
    /// # Default
    ///
    /// Returns `ScpError::Context` (SCP-CTX-2050) indicating the method is not
    /// implemented. A host that needs it overrides it. `AppleKeyCustody` and
    /// `UniffiKeyCustody` override it for a software Ed25519 key, and fail
    /// for a key Android Keystore holds. Third-party
    /// `KeyCustodyProvider` implementations that do not need governance vote
    /// signing may rely on the default until they add support.
    ///
    /// **Note:** `UniFFI` callback interfaces require foreign implementations to
    /// define all methods. The generated Swift protocol / Kotlin interface will
    /// include this method. The default here applies only to Rust-side callers.
    ///
    /// # Errors
    ///
    /// The host returns an `ScpError` with `SCP-CRYPTO-4006` when `key_id` was
    /// destroyed or never existed, and the caller receives key-not-found
    /// (`SCP-CRYPTO-4006`). Any other host error, including the Rust default's
    /// `SCP-CTX-2050` and a key that is not exportable or not Ed25519, reaches
    /// the caller as the custody error `SCP-CRYPTO-4060` carrying the host's
    /// code and message.
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
    /// An implementation returns fixed wake signal bytes that do not depend on
    /// `payload` and copy no byte of it. §10.7 of the infrastructure spec
    /// states: "Push payloads MUST contain a wake signal and nothing else. No
    /// context ID, no sender identifier, no message preview, no metadata of any
    /// kind." A wake signal built from the received bytes would hand the caller
    /// whatever a relay put in them. No Rust code calls this method yet.
    async fn handle_notification(&self, payload: Vec<u8>) -> Result<Vec<u8>, ScpError>;
}

/// Callback for platform device attestation.
///
/// Swift SDK: `DCAppAttestService` (App Attest on iOS 14+ / macOS 11+).
/// Kotlin SDK: Play Integrity API on Android.
///
/// The Swift SDK's `AppleDeviceAttestation` conforms to this callback
/// interface. No Rust code holds or calls it yet, so nothing injects an
/// implementation into the Rust engine.
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
    /// `challenge` — Apple: the 32-byte binding digest `D` of
    ///   `09-security-model.md` §9.3.1, which the Swift adapter hands App
    ///   Attest as `clientDataHash` unchanged. When App Attest is supported,
    ///   the adapter rejects a `challenge` that is not 32 bytes with
    ///   `SCP-ATTEST-9026` (ADR-025 acceptance criterion 3); when it is not
    ///   supported, the adapter throws `SCP-ATTEST-9019` before it reads the
    ///   length. Android: ADR-027, the Android platform adapter, states
    ///   what it binds.
    /// `device_id` — stable identifier for this device instance. The Swift
    ///   adapter does not read it.
    ///
    /// Returns the platform attestation bytes. Apple: the raw CBOR attestation
    /// object Apple signed (ADR-025 acceptance criterion 3). Android: the Play
    /// Integrity token bytes.
    async fn attest(&self, challenge: Vec<u8>, device_id: Vec<u8>) -> Result<Vec<u8>, ScpError>;

    /// Generate a per-request assertion proving key possession.
    ///
    /// `request_hash` — the assertion digest
    ///   `A = SHA-256("SCP-DEVICE-ASSERTION-V1:" ‖ BE32(len(m)) ‖ m)` of
    ///   `09-security-model.md` §9.3.1 over the caller's request bytes `m`,
    ///   never `SHA-256(m)` and never `m` itself. The domain separator keeps
    ///   every `A` distinct from every attestation binding digest `D`. The
    ///   Swift adapter hands `A` to App Attest as `clientDataHash` unchanged.
    ///   When App Attest is supported, the adapter rejects an `A` that is not
    ///   32 bytes with `SCP-ATTEST-9026` (ADR-025 acceptance criterion 3);
    ///   when it is not supported, the adapter throws `SCP-ATTEST-9019`
    ///   before it reads the length.
    ///
    /// Returns the platform assertion object bytes (Apple: CBOR assertion;
    /// Android: integrity verdict).
    async fn assert_request(&self, request_hash: Vec<u8>) -> Result<Vec<u8>, ScpError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Runs a test case in a child process with its own environment, so no test
/// mutates the environment of a process whose other threads may read it.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod test_env {
    use std::ffi::OsStr;

    /// The variable that carries the case name into the child process.
    const CASE_VAR: &str = "SCP_UNIFFI_TEST_ENV_CASE";

    /// The case this process runs, or `None` in the parent test process.
    pub fn child_case() -> Option<String> {
        std::env::var(CASE_VAR).ok()
    }

    /// Re-runs the test `test_fn` of module `module` (pass `module_path!()`)
    /// in a fresh process of this test binary with `CASE_VAR` set to `case`,
    /// each `(name, Some(value))` variable set and each `(name, None)` removed.
    /// Panics unless the child ran exactly that one test and it passed.
    pub fn run_case(module: &str, test_fn: &str, case: &str, vars: &[(&str, Option<&OsStr>)]) {
        let module = module.split_once("::").map_or("", |(_, rest)| rest);
        let name = format!("{module}::{test_fn}");
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
        cmd.args([name.as_str(), "--exact", "--test-threads=1"])
            .env(CASE_VAR, case);
        for (var, value) in vars {
            match value {
                Some(value) => cmd.env(var, value),
                None => cmd.env_remove(var),
            };
        }
        let out = cmd.output().expect("spawn the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        // libtest exits 0 when the filter matches no test, so require the
        // count of tests that ran as well as the exit status.
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "case {case} of {name} did not pass in its child process:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    /// `test_env::run_case` passes for a case that ran and passed.
    #[test]
    fn run_case_passes_when_the_child_case_passes() {
        if test_env::child_case().is_some() {
            return;
        }
        test_env::run_case(
            module_path!(),
            "run_case_passes_when_the_child_case_passes",
            "noop",
            &[],
        );
    }

    /// `test_env::run_case` fails for a test name no test carries, because
    /// libtest exits 0 when its filter matches nothing.
    #[test]
    #[should_panic(expected = "did not pass in its child process")]
    fn run_case_fails_when_no_test_matches() {
        test_env::run_case(module_path!(), "no_test_has_this_name", "noop", &[]);
    }

    /// `test_env::run_case` fails when the child case fails. The child exits
    /// nonzero rather than panicking, because `should_panic` would turn a
    /// panic in the child into a pass.
    #[test]
    #[should_panic(expected = "did not pass in its child process")]
    fn run_case_fails_when_the_child_case_fails() {
        if test_env::child_case().is_some() {
            std::process::exit(1);
        }
        test_env::run_case(
            module_path!(),
            "run_case_fails_when_the_child_case_fails",
            "fail",
            &[],
        );
    }

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

    /// Runs one identity-creation entry point and returns the code and message
    /// of the error it answers with, or a marker string when it succeeds.
    fn create_outcome(
        result: Result<std::sync::Arc<bridge::Identity>, ScpError>,
    ) -> (String, String) {
        match result {
            Err(ScpError::Identity { code, msg } | ScpError::Validation { code, msg }) => {
                (code, msg)
            }
            Err(other) => (String::new(), format!("{other:?}")),
            Ok(_) => (String::new(), "created an identity".to_owned()),
        }
    }

    /// Every build answers each rejected custody request with the code spec 03
    /// §3.2.2 gives it, on both entry points that take a custody string, and
    /// every rejection message names the accepted values: `"os_keystore"`
    /// without a provider is `SCP-IDENT-1003`, and a legacy or unknown string
    /// is `SCP-VALID-7005`.
    #[test]
    fn custody_requests_are_rejected_with_their_spec_codes() {
        use scp_ffi_common::custody_request::ACCEPTED_CUSTODY;
        use scp_ffi_common::error_codes::{IDENT_1003, VALID_7005};

        let rt = runtime();
        for (custody, want) in [
            ("os_keystore", IDENT_1003),
            ("callback", VALID_7005),
            ("platform", VALID_7005),
            ("software", VALID_7005),
            ("file", VALID_7005),
            ("unknown", VALID_7005),
        ] {
            let scp = scp_test();
            for (entry, outcome) in [
                (
                    "identity_create",
                    create_outcome(rt.block_on(scp.identity_create(custody.to_owned(), None))),
                ),
                (
                    "identity_create_with_agent_key",
                    create_outcome(
                        rt.block_on(scp.identity_create_with_agent_key(custody.to_owned())),
                    ),
                ),
            ] {
                assert_eq!(outcome.0, want, "{entry}({custody}): {}", outcome.1);
                assert!(
                    outcome.1.contains(ACCEPTED_CUSTODY),
                    "{entry}({custody}): {}",
                    outcome.1
                );
            }
        }
    }

    /// A `testing` build admits `"in_memory"`, because that feature is the sole
    /// activation path for the `InMemoryKeyCustody` nullifier backing it
    /// (ADR-062, capability injection and prove-absent dev backends,
    /// §Decision 6). The handle reports the request value it answers.
    #[cfg(feature = "testing")]
    #[test]
    fn identity_create_accepts_in_memory_under_testing() {
        let rt = runtime();
        let scp = scp_test();
        let identity = rt
            .block_on(scp.identity_create("in_memory".to_owned(), None))
            .expect("in_memory custody on a testing build");
        assert_eq!(identity.custody_type(), "in_memory");
        let seeded = rt
            .block_on(scp.identity_create("in_memory".to_owned(), Some(vec![7u8; 32])))
            .expect("seeded in_memory custody on a testing build");
        assert_eq!(seeded.custody_type(), "in_memory");
        let agent = rt
            .block_on(scp.identity_create_with_agent_key("in_memory".to_owned()))
            .expect("in_memory agent-key identity on a testing build");
        assert_eq!(agent.custody_type(), "in_memory");
    }

    /// A shipped (no-`testing`) build rejects `"in_memory"` at the boundary with
    /// `SCP-IDENT-1008`, on both entry points that take a custody string, rather
    /// than admitting a custody kind whose only backing implementation the
    /// feature severs. This is the shipped half of the severance. Job
    /// rust-build-uniffi-production names this test in its `-E` filter and runs
    /// it against `--features server`, which is the configuration a released
    /// Swift/Kotlin SDK compiles.
    #[cfg(not(feature = "testing"))]
    #[test]
    fn identity_create_entry_points_reject_in_memory_on_a_shipped_build() {
        use scp_ffi_common::custody_request::ACCEPTED_CUSTODY;

        let rt = runtime();
        let scp = scp_test();
        for (entry, outcome) in [
            (
                "identity_create",
                create_outcome(rt.block_on(scp.identity_create("in_memory".to_owned(), None))),
            ),
            (
                "identity_create_with_agent_key",
                create_outcome(
                    rt.block_on(scp.identity_create_with_agent_key("in_memory".to_owned())),
                ),
            ),
        ] {
            assert_eq!(
                outcome.0,
                scp_ffi_common::error_codes::IDENT_1008,
                "{entry}: expected the custody-unavailable code SCP-IDENT-1008: {}",
                outcome.1
            );
            assert!(
                outcome.1.contains(ACCEPTED_CUSTODY),
                "{entry}: {}",
                outcome.1
            );
        }
    }

    /// `"encrypted_file"` on a `testing` build opens `$HOME/.scp/keys.bin`
    /// under `SCP_KEY_PASSPHRASE` and mints the identity over it, on both entry
    /// points that take a custody string. A bad variable is `SCP-VALID-7001`,
    /// and a key directory or key file this process cannot open is
    /// `SCP-IDENT-1008` (`.docs/standards/sdk-common.md` §Custody request).
    ///
    /// Each case runs in a child process that `test_env::run_case` starts with
    /// its own `HOME` and `SCP_KEY_PASSPHRASE`, so this test sets no
    /// environment variable in a process where other tests run. The cases run
    /// in order, because the wrong-passphrase case reads the key file the
    /// first case sealed.
    #[cfg(feature = "testing")]
    #[test]
    fn identity_create_with_encrypted_file_custody_opens_the_key_file() {
        use scp_ffi_common::error_codes::{IDENT_1008, VALID_7001};
        use std::ffi::OsStr;

        if let Some(case) = test_env::child_case() {
            // (uses identity_create_with_agent_key, expected code or None for success)
            let (agent_key, want) = match case.as_str() {
                "create" => (false, None),
                "agent key" => (true, None),
                "wrong passphrase" | "HOME names a file" => (false, Some(IDENT_1008)),
                "relative HOME" => (false, Some(VALID_7001)),
                "unset passphrase" => (true, Some(VALID_7001)),
                other => panic!("unknown case {other}"),
            };
            let rt = runtime();
            let scp = scp_test();
            let result = if agent_key {
                rt.block_on(scp.identity_create_with_agent_key("encrypted_file".to_owned()))
            } else {
                rt.block_on(scp.identity_create("encrypted_file".to_owned(), None))
            };
            match want {
                None => {
                    let identity = result.unwrap_or_else(|e| panic!("{case}: {e:?}"));
                    assert_eq!(identity.custody_type(), "encrypted_file", "{case}");
                    assert!(identity.did().starts_with("did:dht:"), "{case}");
                }
                Some(want) => {
                    let outcome = create_outcome(result);
                    assert_eq!(outcome.0, want, "{case}: {}", outcome.1);
                }
            }
            return;
        }

        let base = tempfile::tempdir().expect("tempdir");
        let home_create = base.path().join("create");
        let home_agent = base.path().join("agent");
        let home_is_a_file = base.path().join("plain-file");
        std::fs::write(&home_is_a_file, b"not a directory").expect("write plain file");
        let passphrase = OsStr::new("encrypted-file-test-passphrase");
        let cases: [(&str, &OsStr, Option<&OsStr>); 6] = [
            ("create", home_create.as_os_str(), Some(passphrase)),
            ("agent key", home_agent.as_os_str(), Some(passphrase)),
            (
                "wrong passphrase",
                home_create.as_os_str(),
                Some(OsStr::new("a-different-passphrase")),
            ),
            (
                "HOME names a file",
                home_is_a_file.as_os_str(),
                Some(passphrase),
            ),
            (
                "relative HOME",
                OsStr::new("relative-home"),
                Some(passphrase),
            ),
            ("unset passphrase", home_create.as_os_str(), None),
        ];
        for (case, home, passphrase) in cases {
            test_env::run_case(
                module_path!(),
                "identity_create_with_encrypted_file_custody_opens_the_key_file",
                case,
                &[("HOME", Some(home)), ("SCP_KEY_PASSPHRASE", passphrase)],
            );
        }
        for home in [&home_create, &home_agent] {
            let key_file = home.join(".scp").join("keys.bin");
            assert!(
                key_file.is_file(),
                "a create must make {}",
                key_file.display()
            );
        }
        assert!(
            !std::path::Path::new("relative-home").exists(),
            "a refused relative HOME must create no directory under the working directory"
        );
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
            ceiling: vec!["messages:read".to_owned()],
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
            ceiling: vec!["messages:read".to_owned()],
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
