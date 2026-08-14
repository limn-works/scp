//! Verifies the scp-core facade correctly re-exports key types from both
//! scp-protocol and scp-runtime. If a type is added to either crate but
//! not wired through the facade, this test fails to compile.

// ─── Protocol types (from scp-protocol) ───

// Context split
use scp_core::context::ContextParams;
use scp_core::context::ContextState;
use scp_core::context::builder::ContextCreationError;
use scp_core::context::governance::GovernanceAction;
use scp_core::context::outlets::OutletSchema;

// Crypto split
use scp_core::crypto::access_keys::AccessKeyError;
use scp_core::crypto::sender_keys::SenderKey;
use scp_core::crypto::ucan::UcanError;

// Other splits
use scp_core::bridge::BridgeMode;
use scp_core::discovery::DiscoveryError;
use scp_core::economy::EconomicPolicy;
use scp_core::envelope::EnvelopeError;
use scp_core::identity::block_list::BlockListState;
use scp_core::provenance::DataProvenance;
use scp_core::sync::SyncError;
use scp_core::trust::TrustError;

// ─── Runtime types (from scp-runtime) ───

use scp_core::crypto::mls::NodeMlsFactory;

#[test]
fn facade_exposes_protocol_types() {
    // Compile-time check — if any re-export breaks, this fails to compile.
    // Context split
    let _ = std::any::type_name::<ContextState>();
    let _ = std::any::type_name::<ContextParams>();
    let _ = std::any::type_name::<ContextCreationError>();
    let _ = std::any::type_name::<GovernanceAction>();
    let _ = std::any::type_name::<OutletSchema>();

    // Crypto split
    let _ = std::any::type_name::<SenderKey>();
    let _ = std::any::type_name::<UcanError>();
    let _ = std::any::type_name::<AccessKeyError>();

    // Other splits
    let _ = std::any::type_name::<TrustError>();
    let _ = std::any::type_name::<BlockListState>();
    let _ = std::any::type_name::<EconomicPolicy>();
    let _ = std::any::type_name::<DiscoveryError>();
    let _ = std::any::type_name::<EnvelopeError>();
    let _ = std::any::type_name::<BridgeMode>();
    let _ = std::any::type_name::<SyncError>();
    let _ = std::any::type_name::<DataProvenance>();
}

#[test]
fn facade_exposes_runtime_types() {
    let _ = std::any::type_name::<NodeMlsFactory>();
}
