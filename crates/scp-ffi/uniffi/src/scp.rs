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

use scp_ffi_common::bridge_instance::{
    BridgeInstanceCore as _, ShutdownError, ShutdownOutcome, SuspendError, SuspendFailureClass,
    classify_suspend_failure, sdk_shutdown_result,
};
use scp_ffi_common::error_codes as codes;
use std::sync::Arc;
use std::time::Duration;

use crate::bridge::{ErrorClass, ScpError};
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
    /// salt-sidecar fail-closed condition — this returns
    /// `ScpError::Storage` with `SCP-STORAGE-8004`, or with
    /// `SCP-STORAGE-8005` when another store holds the directory's advisory
    /// lock, rather than silently degrading to in-memory storage. Surfaces to Swift
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

    /// Returns the monotonic identifier for this instance.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // UniFFI export methods cannot be const.
    pub fn instance_id(&self) -> u64 {
        self.inner.core.instance_id()
    }

    /// Suspends this bridge instance (mobile backgrounding).
    ///
    /// Flushes every context snapshot, then disconnects transport.
    /// Transport-dependent operations fail until [`Self::resume`] is called.
    ///
    /// `UniFFI` generates a `suspend`/`async` method on Swift and Kotlin; the
    /// flush runs on the tokio runtime this export names.
    ///
    /// `timeout_millis` bounds the call, in milliseconds. The suspend runs
    /// to completion, or reverts, even when the calling Swift task or Kotlin
    /// coroutine is cancelled.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Storage` with `SCP-STORAGE-8014` when a context
    /// snapshot did not persist or the flush missed the deadline, and
    /// `ScpError::Transport` with `SCP-TRANS-5001` when the transport lock is
    /// poisoned. The instance stays running on either error.
    pub async fn suspend(&self, timeout_millis: u64) -> Result<(), ScpError> {
        let deadline = Duration::from_millis(timeout_millis);
        sdk_suspend(Arc::clone(&self.inner).suspend(deadline).await)
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag, then runs the async work in the
    /// `BridgeInstanceCore::resume` default body (transport reconnect
    /// from pending relay URLs, persisted-context restoration).
    ///
    /// `UniFFI` generates a `suspend`/`async` method on Swift and Kotlin.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` if the instance has been permanently
    /// shut down.
    pub async fn resume(&self) -> Result<(), ScpError> {
        Arc::clone(&self.inner)
            .resume()
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("resume failed: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
    }

    /// Shuts down this bridge instance with a graceful deadline.
    ///
    /// Awaits in-flight tasks up to `timeout_millis` **milliseconds**.
    /// Permanent — a shut-down instance cannot be reused.
    ///
    /// The unit is **milliseconds** — unified across all Rust bridges
    /// so the Swift and Kotlin SDKs can share a single conversion
    /// surface.
    ///
    /// # Errors
    ///
    /// Returns [`ScpError::Storage`] with `SCP-STORAGE-8005` when the
    /// durable store still holds its advisory lock after the call, and with
    /// `SCP-STORAGE-8015` when the store was released but a context snapshot
    /// did not persist (the flush failed or missed the deadline). The
    /// instance is shut down either way.
    pub async fn shutdown(&self, timeout_millis: u64) -> Result<(), ScpError> {
        let timeout = Duration::from_millis(timeout_millis);
        sdk_shutdown(Arc::clone(&self.inner).shutdown(timeout).await)
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
    #[cfg(any(test, feature = "testing"))]
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

/// Maps a bridge suspend result to the SDK result: the class
/// [`classify_suspend_failure`] names picks the [`ScpError`] variant.
fn sdk_suspend(result: Result<(), SuspendError>) -> Result<(), ScpError> {
    result.map_err(|e| {
        let (class, code) = classify_suspend_failure(&e);
        let msg = format!("suspend failed: {e}");
        match class {
            SuspendFailureClass::Storage => ScpError::storage(code, msg),
            SuspendFailureClass::Transport => ScpError::coded(ErrorClass::Transport, code, msg),
        }
    })
}

/// Maps a bridge shutdown result to the SDK result (spec §17.6 "One Opener
/// per Durable Directory"): [`ScpError::Storage`] with the code
/// [`sdk_shutdown_result`] names (`SCP-STORAGE-8005` for a store left holding
/// its advisory lock, `SCP-STORAGE-8015` for a flush that failed).
fn sdk_shutdown(result: Result<ShutdownOutcome, ShutdownError>) -> Result<(), ScpError> {
    sdk_shutdown_result(result).map_err(|failure| ScpError::storage(failure.code, failure.message))
}

#[cfg(test)]
mod sdk_shutdown_tests {
    use super::*;
    use scp_ffi_common::bridge_instance::ShutdownFlush;

    #[test]
    fn suspend_failures_map_to_their_variants() {
        let storage_failures = [
            SuspendError::FlushFailed(scp_core::context::ContextError::PersistenceFailed(
                "disk full".to_owned(),
            )),
            SuspendError::DeadlineElapsed {
                deadline: Duration::from_millis(5),
            },
            SuspendError::Interrupted,
        ];
        for failure in storage_failures {
            let mapped = sdk_suspend(Err(failure));
            assert!(
                matches!(&mapped, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8014),
                "{mapped:?}"
            );
        }
        let lock = sdk_suspend(Err(SuspendError::TransportLock(
            scp_ffi_common::bridge_instance::TransportLockError::Poisoned,
        )));
        assert!(
            matches!(&lock, Err(ScpError::Transport { code, .. }) if code == codes::TRANS_5001),
            "{lock:?}"
        );
        assert!(sdk_suspend(Ok(())).is_ok());
    }

    #[test]
    fn store_left_locked_raises_storage_8005() {
        let timed_out = sdk_shutdown(Ok(ShutdownOutcome::TimedOut {
            aborted_tasks: 0,
            panicked_tasks: 0,
            drain: scp_ffi_common::bridge_instance::DrainState::Panicked,
            durable_store_open: true,
            flush: ShutdownFlush::Flushed,
        }));
        assert!(
            matches!(&timed_out, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8005),
            "{timed_out:?}"
        );
        let refused = sdk_shutdown(Err(ShutdownError::DurableStoreClose(
            scp_platform::PlatformError::StorageError("close refused".to_owned()),
        )));
        assert!(
            matches!(&refused, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8005),
            "{refused:?}"
        );
        let repeat = sdk_shutdown(Err(ShutdownError::AlreadyShutDown {
            durable_store_open: true,
        }));
        assert!(
            matches!(&repeat, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8005),
            "{repeat:?}"
        );
    }

    /// A shutdown that released the store but whose flush failed or timed
    /// out raises `SCP-STORAGE-8015`; one that also left the store locked
    /// raises `SCP-STORAGE-8005`, which wins, as does a cancelled shutdown.
    #[test]
    fn failed_flush_raises_storage_8015() {
        let failed = sdk_shutdown(Ok(ShutdownOutcome::GracefulWithin {
            elapsed: Duration::ZERO,
            panicked_tasks: 0,
            flush: ShutdownFlush::Failed {
                message: "disk full".to_owned(),
            },
        }));
        assert!(
            matches!(&failed, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8015),
            "{failed:?}"
        );
        let late = sdk_shutdown(Ok(ShutdownOutcome::TimedOut {
            aborted_tasks: 0,
            panicked_tasks: 0,
            drain: scp_ffi_common::bridge_instance::DrainState::Finished,
            durable_store_open: false,
            flush: ShutdownFlush::TimedOut,
        }));
        assert!(
            matches!(&late, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8015),
            "{late:?}"
        );
        let locked = sdk_shutdown(Ok(ShutdownOutcome::TimedOut {
            aborted_tasks: 0,
            panicked_tasks: 0,
            drain: scp_ffi_common::bridge_instance::DrainState::Panicked,
            durable_store_open: true,
            flush: ShutdownFlush::Failed {
                message: "disk full".to_owned(),
            },
        }));
        assert!(
            matches!(&locked, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8005),
            "{locked:?}"
        );
        let cut = sdk_shutdown(Err(ShutdownError::Interrupted));
        assert!(
            matches!(&cut, Err(ScpError::Storage { code, .. }) if code == codes::STORAGE_8005),
            "{cut:?}"
        );
    }

    #[test]
    fn released_store_reports_success() {
        assert!(
            sdk_shutdown(Ok(ShutdownOutcome::GracefulWithin {
                elapsed: Duration::ZERO,
                panicked_tasks: 0,
                flush: ShutdownFlush::Flushed,
            }))
            .is_ok()
        );
        assert!(
            sdk_shutdown(Ok(ShutdownOutcome::GracefulWithin {
                elapsed: Duration::ZERO,
                panicked_tasks: 0,
                flush: ShutdownFlush::Skipped,
            }))
            .is_ok()
        );
        assert!(
            sdk_shutdown(Err(ShutdownError::AlreadyShutDown {
                durable_store_open: false
            }))
            .is_ok()
        );
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

    /// Compile-time guard: the ONLY `#[uniffi::constructor]` on `Scp` is the
    /// typed, fallible `with_storage(StorageConfig) -> Result<Arc<Self>, _>`.
    ///
    /// This pins the constructor's exact signature. A regression that
    /// re-introduced an infallible zero-argument constructor (the now-deleted
    /// `with_persistence`, or a bare `new()`) would either not match this
    /// `fn(StorageConfig) -> Result<...>` type — failing to compile here — or
    /// would re-expose a `Scp::with_persistence`/`Scp::new` path that the
    /// `no_infallible_zero_arg_constructor` assertion below catches. Together
    /// they are the mechanical guard that would have caught `with_persistence`:
    /// storage selection is MANDATORY and typed (spec §17.6).
    #[test]
    fn only_typed_constructor_exists() {
        // `with_storage` takes a `StorageConfig` by value and returns a
        // `Result` — a missing selection cannot even be expressed.
        let ctor: fn(StorageConfig) -> Result<std::sync::Arc<Scp>, ScpError> = Scp::with_storage;
        let scp = ctor(StorageConfig::InMemory).expect("typed constructor must build in-memory");
        assert!(scp.instance_id() > 0);
    }

    /// Mechanical guard: there is NO infallible, zero-argument constructor that
    /// silently selects a storage backend (spec §17.6: "No bridge or SDK may
    /// expose a zero-argument constructor that silently selects a storage
    /// backend"). The only zero-argument builder is the testing-gated
    /// `new_in_memory_for_test`, which is an EXPLICIT dev/test selection, not a
    /// `#[uniffi::constructor]`, and so never reaches the Swift/Kotlin surface.
    ///
    /// We coerce that test-only builder to the only legitimate `fn() ->
    /// Arc<Self>` shape. If a public infallible zero-arg `#[uniffi::constructor]`
    /// were re-added (e.g. `with_persistence`), the codebase would once again
    /// contain a second `fn() -> Arc<Scp>` constructor — a state this test
    /// exists to forbid by asserting the sole such builder is the testing-gated
    /// one.
    ///
    /// The signature coercion alone is necessary but NOT sufficient: a sibling
    /// `#[uniffi::constructor] fn() -> Arc<Scp>` re-added next to `with_storage`
    /// would still let `new_in_memory_for_test` coerce cleanly, so the
    /// coercion would not catch it. To make this a REAL structural enforcement,
    /// we additionally inspect this file's own source (compiled in via
    /// `include_str!`) and assert that it contains EXACTLY ONE
    /// `#[uniffi::constructor]` attribute, and that the no-arg testing helper
    /// `new_in_memory_for_test` is NOT annotated with it. Re-introducing a
    /// silent zero-arg `#[uniffi::constructor]` therefore FAILS this test.
    #[test]
    fn no_infallible_zero_arg_constructor() {
        // The sole infallible zero-argument builder is the testing-gated,
        // non-`#[uniffi::constructor]` test helper — never exported to Swift or
        // Kotlin. Pinning its signature here documents that any OTHER
        // `fn() -> Arc<Scp>` (a silent default constructor) is a regression.
        let test_only_ctor: fn() -> std::sync::Arc<Scp> = Scp::new_in_memory_for_test;
        let scp = test_only_ctor();
        assert!(scp.instance_id() > 0);

        // Structural guard (ratchet-style source-count, mirroring the
        // string-count enforcement used elsewhere in the codebase): this file
        // defines the `Scp` UniFFI surface, so the count of `#[uniffi::constructor]`
        // ATTRIBUTES here is the count of constructors Swift/Kotlin can reach.
        // We count only lines whose trimmed text STARTS WITH the attribute —
        // excluding the prose `#[uniffi::constructor]` references inside `///`
        // doc-comments and `//` line comments above (which begin with `/`).
        const SRC: &str = include_str!("scp.rs");
        let constructor_attrs = SRC
            .lines()
            .filter(|line| line.trim_start().starts_with("#[uniffi::constructor]"))
            .count();
        assert_eq!(
            constructor_attrs, 1,
            "exactly ONE `#[uniffi::constructor]` must exist on `Scp` (the typed, \
             fallible `with_storage(StorageConfig) -> Result<...>`). Found {constructor_attrs}. \
             A second constructor re-exposes a storage-selecting path to Swift/Kotlin \
             (spec §17.6) — storage selection is mandatory and typed."
        );

        // The sole `#[uniffi::constructor]` must be `with_storage` returning a
        // `Result`. Find the attribute, then assert the immediately-following
        // non-blank line declares `with_storage` (after the inert
        // `#[allow(...)]` attribute) and that its declared return type is a
        // `Result`. This pins WHICH constructor the single attribute guards.
        let lines: Vec<&str> = SRC.lines().collect();
        let attr_idx = lines
            .iter()
            .position(|line| line.trim_start().starts_with("#[uniffi::constructor]"))
            .expect("the single `#[uniffi::constructor]` attribute must be present");
        // Gather the attribute + signature lines until the opening brace.
        let mut decl = String::new();
        for line in &lines[attr_idx..] {
            decl.push_str(line);
            decl.push('\n');
            if line.contains('{') {
                break;
            }
        }
        assert!(
            decl.contains("pub fn with_storage(config: StorageConfig)"),
            "the sole `#[uniffi::constructor]` must guard \
             `with_storage(config: StorageConfig)`; got:\n{decl}"
        );
        assert!(
            decl.contains("-> Result<Arc<Self>, ScpError>"),
            "the sole `#[uniffi::constructor]` must be FALLIBLE \
             (`-> Result<Arc<Self>, ScpError>`) so storage init can fail closed \
             (spec §17.6); got:\n{decl}"
        );

        // The no-arg testing helper must NOT itself be a `#[uniffi::constructor]`.
        // It is declared `pub fn new_in_memory_for_test()`; assert the source
        // line preceding that declaration is not the constructor attribute.
        let helper_idx = lines
            .iter()
            .position(|line| {
                line.trim_start()
                    .starts_with("pub fn new_in_memory_for_test(")
            })
            .expect("the testing-gated `new_in_memory_for_test` helper must be present");
        // Scan upward over inert attributes (`#[cfg(...)]`, `#[must_use]`) to the
        // nearest preceding attribute/doc line; none of them may be the
        // constructor attribute.
        let preceding_is_constructor = lines[..helper_idx]
            .iter()
            .rev()
            .take_while(|line| {
                let t = line.trim_start();
                t.starts_with("#[") || t.starts_with("///") || t.is_empty()
            })
            .any(|line| line.trim_start().starts_with("#[uniffi::constructor]"));
        assert!(
            !preceding_is_constructor,
            "`new_in_memory_for_test` must NOT be annotated `#[uniffi::constructor]` — \
             it is an explicit Rust-only dev/test selection, never a Swift/Kotlin \
             constructor (spec §17.6)."
        );
    }
}
