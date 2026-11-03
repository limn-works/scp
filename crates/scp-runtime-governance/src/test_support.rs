//! Test support (ADR-070 plan §1.2): the 13 domain handlers with this crate's own
//! domain.

use std::sync::Arc;

use scp_runtime_core::context::domains::DomainHandlers;

/// The 13 domain handlers: this crate's [`crate::Governance`] and the 12 siblings.
pub fn test_domain_handlers() -> DomainHandlers {
    DomainHandlers {
        messaging: Arc::new(scp_runtime_messaging::Messaging),
        lifecycle: Arc::new(scp_runtime_lifecycle::Lifecycle),
        governance: Arc::new(crate::Governance),
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
