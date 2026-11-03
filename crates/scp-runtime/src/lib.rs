#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

// scp-runtime test targets require the `testing` feature: numerous `#[cfg(test)]`
// modules call `#[cfg(feature = "testing")]`-gated helpers. No dev-dependency edge
// turns it on, so every test command names the feature. This tripwire turns a
// missing `--features` into a clear message instead of a cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime/testing` in a multi-package command)."
);

use std::sync::Arc;

use scp_runtime_core::context::domains::DomainHandlers;

mod context;

/// Builds the 13 domain handlers every
/// [`Supervisor`](scp_runtime_core::context::supervisor::Supervisor) takes as its
/// last constructor argument (ADR-070 §3).
///
/// This is the one production constructor of [`DomainHandlers`]: each field
/// holds the field-less struct that forwards to its domain's functions.
#[must_use]
pub fn domain_handlers() -> DomainHandlers {
    use context::actor::handlers;
    DomainHandlers {
        messaging: Arc::new(handlers::messaging::Messaging),
        lifecycle: Arc::new(handlers::lifecycle::Lifecycle),
        governance: Arc::new(handlers::governance::Governance),
        broadcast: Arc::new(handlers::broadcast::Broadcast),
        economy: Arc::new(handlers::economy::Economy),
        trust_recovery: Arc::new(handlers::trust_recovery::TrustRecovery),
        standing: Arc::new(handlers::standing::Standing),
        ttl_close: Arc::new(handlers::ttl_close::TtlClose),
        outlets: Arc::new(handlers::outlets::Outlets),
        push: Arc::new(handlers::push::Push),
        queries: Arc::new(handlers::queries::Queries),
        saga: Arc::new(handlers::saga::Saga),
        lifecycle_control: Arc::new(handlers::lifecycle_control::LifecycleControl),
    }
}

/// Builds a test [`Supervisor`] with every domain installed.
///
/// Mirror of the legacy
/// `attach_test_supervisor(ContextManager::new(...))` shorthand: the
/// `ContextManager` type is gone in ADR-049 §15, so callers now build a
/// supervisor directly via `Supervisor::with_providers` (test-only).
///
/// Returns [`Arc<Supervisor>`] — the supervisor is the
/// authoritative owner of every per-context state, provider, and
/// governance engine, and exposes the public API previously rooted on
/// `ContextManager`.
///
/// # Non-production
///
/// `persistence`, `payment_adapter`, `event_tx`, and `clock` default to
/// `None` (i.e. no-op persistence and a `SystemClock`). The required
/// `mls_storage` provider is wired to an in-memory backend — a
/// test-only dev opt-in; production bridges supply a real `Storage`.
/// Tests that exercise any of those specific surfaces must construct
/// their own supervisor explicitly via
/// `Supervisor::with_providers` (test-only).
///
/// [`Supervisor`]: scp_runtime_core::context::supervisor::Supervisor
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn test_supervisor(
    crypto: Arc<scp_runtime_core::crypto::mls::provider::NodeMlsFactory>,
    transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider>,
    event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
    key_resolver: scp_protocol::context::governance::KeyResolver,
) -> Arc<scp_runtime_core::context::supervisor::Supervisor> {
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(scp_platform::in_memory::InMemoryStorage::new()),
        ),
    );
    scp_runtime_core::context::supervisor::Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        None,
        None,
        mls_storage,
        domain_handlers(),
    )
}
