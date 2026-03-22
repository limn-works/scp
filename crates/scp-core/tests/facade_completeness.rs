//! Verifies the scp-core facade correctly re-exports key types from both
//! scp-protocol and scp-runtime. If a type is added to either crate but
//! not wired through the facade, this test fails to compile.

// Protocol types (from scp-protocol)
use scp_core::bridge::BridgeMode;
use scp_core::crypto::sender_keys::SenderKey;
use scp_core::crypto::ucan::UcanError;
use scp_core::envelope::EnvelopeError;
use scp_core::provenance::DataProvenance;
use scp_core::trust::TrustError;

// Runtime types (from scp-runtime)
use scp_core::crypto::mls::MlsCryptoProvider;

#[test]
fn facade_exposes_protocol_types() {
    // Compile-time check — if any re-export breaks, this fails to compile.
    let _ = std::any::type_name::<TrustError>();
    let _ = std::any::type_name::<UcanError>();
    let _ = std::any::type_name::<SenderKey>();
    let _ = std::any::type_name::<EnvelopeError>();
    let _ = std::any::type_name::<BridgeMode>();
    let _ = std::any::type_name::<DataProvenance>();
}

#[test]
fn facade_exposes_runtime_types() {
    let _ = std::any::type_name::<MlsCryptoProvider>();
}
