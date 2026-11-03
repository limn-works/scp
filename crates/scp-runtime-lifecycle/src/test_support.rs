//! Test support (ADR-070 plan §1.2): the 13 domain handlers with this crate's own
//! domain, and a test Supervisor that installs them.

use std::sync::Arc;

use scp_runtime_core::context::domains::DomainHandlers;

/// The 13 domain handlers: this crate's [`crate::Lifecycle`] and the 12 siblings.
pub fn test_domain_handlers() -> DomainHandlers {
    DomainHandlers {
        messaging: Arc::new(scp_runtime_messaging::Messaging),
        lifecycle: Arc::new(crate::Lifecycle),
        governance: Arc::new(scp_runtime_governance::Governance),
        broadcast: Arc::new(scp_runtime_broadcast::Broadcast),
        economy: Arc::new(scp_runtime_economy::Economy),
        trust_recovery: Arc::new(scp_runtime_trust_recovery::TrustRecovery),
        standing: Arc::new(scp_runtime_standing::Standing),
        ttl_close: Arc::new(scp_runtime_ttl_close::TtlClose),
        outlets: Arc::new(scp_runtime_outlets::Outlets),
        push: Arc::new(scp_runtime_push::Push),
        queries: Arc::new(scp_runtime_queries::Queries),
        saga: Arc::new(scp_runtime_saga::Saga),
        lifecycle_control: Arc::new(scp_runtime_lifecycle_control::LifecycleControl),
    }
}

/// [`scp_runtime_core::context::supervisor::test_support::test_supervisor_with_domains`] with
/// [`test_domain_handlers`].
pub fn test_supervisor(
    crypto: Arc<scp_runtime_core::crypto::mls::provider::NodeMlsFactory>,
    transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider>,
    event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
    key_resolver: scp_protocol::context::governance::KeyResolver,
) -> Arc<scp_runtime_core::context::supervisor::Supervisor> {
    scp_runtime_core::context::supervisor::test_support::test_supervisor_with_domains(
        crypto,
        transport,
        event_log,
        key_resolver,
        test_domain_handlers(),
    )
}
