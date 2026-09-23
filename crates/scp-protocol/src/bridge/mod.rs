//! Bridge connector protocol for SCP — pure protocol types.
//!
//! `BridgeMode`, `BridgeConnector`, `ShadowIdentity` types.
//! Async modules (oauth, credentials) stay in scp-runtime.

pub mod claiming;
pub mod envelope;
pub mod provenance;
pub mod registration;
pub mod shadow;

use serde::{Deserialize, Serialize};

use scp_did::DID;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// A context identifier string.
pub type ContextId = String;

// ---------------------------------------------------------------------------
// BridgeMode
// ---------------------------------------------------------------------------

/// Operating mode of a bridge connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeMode {
    /// Read-only mirroring from external platform.
    Relay,
    /// Bridge acts on behalf of external users.
    Puppet,
    /// Platform API integration.
    Api,
    /// Native SCP support on external platform.
    Cooperative,
}

// ---------------------------------------------------------------------------
// BridgeStatus
// ---------------------------------------------------------------------------

/// Lifecycle status of a bridge connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeStatus {
    /// The bridge is operational.
    Active,
    /// The bridge is temporarily suspended.
    Suspended,
    /// The bridge has been permanently revoked.
    Revoked,
}

// ---------------------------------------------------------------------------
// BridgeConnector
// ---------------------------------------------------------------------------

/// A registered bridge connector bound to a specific SCP context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConnector {
    /// Unique identifier for this bridge instance.
    pub bridge_id: String,
    /// DID of the human operator accountable for this bridge.
    pub operator_did: DID,
    /// Name of the external platform.
    pub platform: String,
    /// Operating mode.
    pub mode: BridgeMode,
    /// Current lifecycle status.
    pub status: BridgeStatus,
    /// The context this bridge is registered in.
    pub registration_context: ContextId,
    /// Unix timestamp (seconds) when the bridge was registered.
    pub registered_at: u64,
    /// Governance-configured shadow limit for this bridge (spec §12.2.1).
    ///
    /// Approval copies this value from a `RegisterBridge` request, so whichever
    /// component reads a connector reads the limit governance set. A context
    /// that approves a bridge at 50 gets a bridge that creates 50 shadows, not
    /// a registry default.
    pub max_shadows: u32,
}

// ---------------------------------------------------------------------------
// ShadowProvenanceStatus
// ---------------------------------------------------------------------------

/// Provenance status of a shadow identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowProvenanceStatus {
    /// Unclaimed — attributed via bridge.
    Shadow,
    /// Claimed — bound to a DID via identity attestation.
    Claimed,
}

// ---------------------------------------------------------------------------
// ShadowIdentity
// ---------------------------------------------------------------------------

/// Protocol-level representation of an external platform participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowIdentity {
    /// Unique identifier for this shadow identity.
    pub shadow_id: String,
    /// The external platform handle.
    pub platform_handle: String,
    /// The bridge connector that created this shadow identity.
    pub bridge_id: String,
    /// The role attributed to this shadow identity.
    pub attributed_role: String,
    /// Whether this shadow identity has been claimed.
    pub provenance_status: ShadowProvenanceStatus,
    /// Unix timestamp (seconds) when the shadow identity was created.
    pub created_at: u64,
}
