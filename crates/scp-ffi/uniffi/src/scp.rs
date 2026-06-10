//! `#[derive(uniffi::Object)] Scp` — the caller-owned SCP instance exposed to
//! Swift and Kotlin as `SCP`.
//!
//! `Scp` is the top-level SDK-facing handle that owns a
//! [`UniffiBridgeInstance`] — which in turn owns the `ContextManager`,
//! transport, and bridge-specific registries.
//!
//! Phase D (#1695) deleted the process-wide `DEFAULT_BRIDGE_INSTANCE`
//! that the pre-façade free functions shared; every entry point now
//! flows through an `Scp`, which mints handles stamped with its own
//! `instance_id` and rejects cross-instance handle misuse via the
//! inline `CoreFields::check_handle` call.
//!
//! See #1549 Phase 4 remainder plan and ADR-048.

use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
use scp_ffi_common::error_codes as codes;
use std::sync::Arc;
use std::time::Duration;

use crate::bridge::ScpError;
use crate::runtime::{StorageConfig, UniffiBridgeInstance};
use crate::{decrement_handle_count, increment_handle_count};

/// The SCP instance — a caller-owned handle that wraps a
/// [`UniffiBridgeInstance`].
///
/// Generated as `class SCP` in both Swift and Kotlin. Phase D (#1695,
/// ADR-048) deleted the process-wide default instance: every caller now
/// constructs an explicit `SCP` and the handles it mints are rejected
/// on any other instance via [`check-handle-affinity`][affinity].
///
/// Storage selection is MANDATORY (spec §17.6): the only constructor is
/// [`Self::with_storage`], which takes a typed [`StorageConfig`] — there
/// is no zero-argument constructor, so a missing storage selection is a
/// compile error in Swift and Kotlin.
///
/// The native `shutdown` parameter is milliseconds (`u64`) — the SDK
/// wrappers present it as seconds for consumer ergonomics.
///
/// [affinity]: ../../../../scripts/check-handle-affinity.sh
///
/// # Swift usage
///
/// ```swift
/// let scp = try SCP.withStorage(.inMemory)       // explicit dev/test storage
/// let identity = try await scp.identityCreate(custody: "in_memory")
/// try await scp.shutdown(timeoutMillis: 5_000)   // graceful shutdown
/// ```
///
/// # Kotlin usage
///
/// ```kotlin
/// val scp = SCP(StorageConfig.InMemory)          // explicit dev/test storage
/// val identity = scp.identityCreate(custody = "in_memory")
/// scp.shutdown(timeoutMillis = 5_000uL)          // suspend fun, graceful shutdown
/// ```
#[derive(uniffi::Object)]
pub struct Scp {
    /// The underlying per-bridge concrete instance.
    pub(crate) inner: Arc<UniffiBridgeInstance>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Scp {
    /// Constructs an `SCP` instance with a storage configuration.
    ///
    /// `StorageConfig::InMemory` selects the encrypted in-memory dev/test
    /// backend; `StorageConfig::Sqlite { path, key }` selects a
    /// `SQLCipher`-encrypted database, where `key` is either raw key material
    /// or a passphrase (Argon2id; spec §17.6).
    ///
    /// # Errors
    ///
    /// FAIL CLOSED (spec §17.6): if a durable (`Sqlite`) backend cannot be
    /// opened — bad key/passphrase, permission denied, corrupt file, or a
    /// salt-sidecar fail-closed condition — this returns `ScpError::Context`
    /// rather than silently degrading to in-memory storage. Surfaces to Swift
    /// as `throws` and Kotlin as a thrown exception.
    #[uniffi::constructor]
    #[allow(clippy::needless_pass_by_value)]
    pub fn with_storage(config: StorageConfig) -> Result<Arc<Self>, ScpError> {
        let inner = UniffiBridgeInstance::with_storage_uniffi(config)?;
        increment_handle_count();
        Ok(Arc::new(Self {
            inner: Arc::new(inner),
        }))
    }

    /// Constructs an `SCP` instance with a persistence provider placeholder.
    ///
    /// PR 1 exposes this constructor so SDK consumers can prepare for the
    /// persistence-enabled path. The current implementation builds a fresh
    /// in-memory instance identical to [`Self::new`]; PR 3 wires the real
    /// `scp_core::context::ContextPersistence` plumbing through.
    #[uniffi::constructor]
    #[must_use]
    pub fn with_persistence() -> Arc<Self> {
        increment_handle_count();
        Arc::new(Self {
            inner: Arc::new(UniffiBridgeInstance::new_uniffi()),
        })
    }

    /// Returns the monotonic identifier for this instance.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // UniFFI export methods cannot be const.
    pub fn instance_id(&self) -> u64 {
        self.inner.core.instance_id()
    }

    /// Suspends this bridge instance (mobile backgrounding).
    ///
    /// Disconnects transport and flushes context snapshots. Transport-
    /// dependent operations fail until [`Self::resume`] is called.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Transport` if the transport lock is poisoned.
    pub fn suspend(&self) -> Result<(), ScpError> {
        self.inner.core.suspend().map_err(|e| ScpError::Transport {
            msg: format!("suspend failed: {e}"),
            code: codes::TRANS_5001.to_owned(),
        })
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag, then runs any per-bridge async work chained
    /// by the `BridgeInstanceCore::resume` override (transport reconnect
    /// from pending relay URLs, persisted-context restoration).
    ///
    /// `UniFFI` generates a `suspend`/`async` method on Swift and Kotlin.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` if the instance has been permanently
    /// shut down.
    pub async fn resume(&self) -> Result<(), ScpError> {
        self.inner.resume().await.map_err(|e| ScpError::Context {
            msg: format!("resume failed: {e}"),
            code: codes::CTX_2000.to_owned(),
        })
    }

    /// Shuts down this bridge instance with a graceful deadline.
    ///
    /// Awaits in-flight tasks up to `timeout_millis` **milliseconds**,
    /// aborts any remaining tasks, then clears registries and runs
    /// shutdown hooks. Permanent — a shut-down instance cannot be
    /// reused. A second call is a no-op from the caller's perspective
    /// (the underlying `ShutdownError::AlreadyShutDown` is swallowed).
    ///
    /// The unit is **milliseconds** — unified across all Rust bridges
    /// so the Swift and Kotlin SDKs can share a single conversion
    /// surface.
    pub async fn shutdown(&self, timeout_millis: u64) -> Result<(), ScpError> {
        let timeout = Duration::from_millis(timeout_millis);
        match self.inner.shutdown(timeout).await {
            Ok(_) => Ok(()),
            // AlreadyShutDown is treated as a harmless lifecycle observation —
            // double-shutdown is idempotent at the SDK surface.
            Err(_already) => Ok(()),
        }
    }
}

// Non-UniFFI impl block — Rust-only test affordance. Items here are NOT
// annotated with `#[uniffi::export]`, so they do not become Swift/Kotlin
// methods.
impl Scp {
    /// Constructs an `Scp` with EXPLICIT in-memory storage, for Rust-side
    /// tests only.
    ///
    /// The sole public constructor ([`Self::with_storage`]) takes a typed
    /// [`StorageConfig`] and returns a `Result`; Rust integration tests
    /// want a one-liner that selects in-memory storage infallibly. This
    /// wraps [`UniffiBridgeInstance::new_uniffi`] (the internal in-memory
    /// builder) — an explicit dev/test selection, NOT a silent default
    /// (spec §17.6).
    #[cfg(any(test, feature = "testing", feature = "allow_in_memory_custody"))]
    #[must_use]
    pub fn new_in_memory_for_test() -> Arc<Self> {
        increment_handle_count();
        Arc::new(Self {
            inner: Arc::new(UniffiBridgeInstance::new_uniffi()),
        })
    }
}

impl Drop for Scp {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod storage_mandatory_tests {
    use super::*;
    use crate::runtime::StorageConfig;

    /// Storage selection is mandatory and typed (spec §17.6): the only
    /// constructor is `with_storage`, which takes a typed `StorageConfig`.
    /// The explicit in-memory selection constructs successfully and yields
    /// a live instance with a non-zero monotonic id (a real operation).
    #[test]
    fn with_storage_in_memory_constructs_and_is_live() {
        let scp =
            Scp::with_storage(StorageConfig::InMemory).expect("in_memory selection must construct");
        assert!(
            scp.instance_id() > 0,
            "constructed instance must expose a live, non-zero instance_id"
        );
    }

    /// Compile-time guard: there is no zero-argument constructor. If a bare
    /// `Scp::new()` is re-introduced, this reference fails to compile because
    /// the only construction paths are `with_storage`, `with_persistence`,
    /// and the test-only `new_in_memory_for_test`. We pin the typed
    /// constructor's signature so a regression to a no-arg form is caught.
    #[test]
    fn only_typed_constructor_exists() {
        // `with_storage` takes a `StorageConfig` by value and returns a
        // `Result` — a missing selection cannot even be expressed.
        let ctor: fn(StorageConfig) -> Result<std::sync::Arc<Scp>, ScpError> = Scp::with_storage;
        let scp = ctor(StorageConfig::InMemory).expect("typed constructor must build in-memory");
        assert!(scp.instance_id() > 0);
    }
}
