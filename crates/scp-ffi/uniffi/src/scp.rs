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
/// Generated as `class SCP` in both Swift and Kotlin.
///
/// # Swift usage
///
/// ```swift
/// let scp = SCP()                                // fresh in-memory instance
/// let shared = try SCP.defaultInstance()         // process-wide default
/// try await scp.shutdown(timeoutSecs: 5)         // graceful shutdown
/// ```
///
/// # Kotlin usage
///
/// ```kotlin
/// val scp = SCP()                                // fresh in-memory instance
/// val shared = SCP.defaultInstance()             // process-wide default
/// scp.shutdown(timeoutSecs = 5uL)                // suspend fun, graceful shutdown
/// ```
#[derive(uniffi::Object)]
pub struct Scp {
    /// The underlying per-bridge concrete instance.
    pub(crate) inner: Arc<UniffiBridgeInstance>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Scp {
    /// Constructs a fresh `SCP` instance with default in-memory state.
    ///
    /// Each call produces a brand-new instance with a fresh monotonic
    /// `instance_id`, a fresh `CancellationToken`, and an empty
    /// `JoinSet`. Handles issued against this instance are incompatible
    /// with any other instance — the `CoreFields::check_handle` path
    /// surfaces the mismatch as `ScpError::Permission` with code
    /// `SCP-PERM-3030`.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        increment_handle_count();
        Arc::new(Self {
            inner: Arc::new(UniffiBridgeInstance::new_uniffi()),
        })
    }

    /// Constructs an `SCP` instance with a storage configuration.
    ///
    /// PR 1 accepts the default (in-memory) configuration only. PR 3 adds
    /// filesystem-backed storage via an additional variant on
    /// [`StorageConfig`]. The `config` parameter is forwarded to the inner
    /// constructor; the current match honours only `InMemory`.
    #[uniffi::constructor]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn with_storage(config: StorageConfig) -> Arc<Self> {
        increment_handle_count();
        Arc::new(Self {
            inner: Arc::new(UniffiBridgeInstance::with_storage_uniffi(config)),
        })
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
    /// by the [`BridgeInstanceCore::resume`] override (transport reconnect
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

impl Drop for Scp {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}
