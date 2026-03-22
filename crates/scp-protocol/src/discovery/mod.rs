//! Tool-interface discovery for SCP — pure protocol types.
//!
//! DiscoveryError and pure module declarations.
//! Async modules (addressing, search, did_capabilities, bootstrap, dht_context)
//! stay in scp-runtime.

pub mod context;
pub mod handles;
pub mod petnames;
pub mod push;
pub mod scope;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use scp_identity::DID;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// A context identifier string.
pub type ContextId = String;

// ---------------------------------------------------------------------------
// DataProvenance (placeholder)
// ---------------------------------------------------------------------------

/// Placeholder provenance metadata attached to discovery results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataProvenance {
    /// The DID of the data source.
    pub source_did: DID,
    /// The context from which the data originated, if applicable.
    pub source_context: Option<ContextId>,
    /// Unix timestamp (seconds) when the provenance was recorded.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// DiscoveryQuery
// ---------------------------------------------------------------------------

/// A search query for contexts with discovery tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryQuery {
    /// Filter by capability strings.
    pub capability_filter: Option<Vec<String>>,
    /// Free-text keyword filter for metadata search.
    pub keywords: Option<Vec<String>>,
    /// Minimum participation history duration.
    pub min_history: Option<Duration>,
}

// ---------------------------------------------------------------------------
// DiscoveryResult / DiscoveryResultEntry
// ---------------------------------------------------------------------------

/// Merged search results from one or more discovery sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveryResult {
    /// The discovery result entries, ranked by relevance score (descending).
    pub entries: Vec<DiscoveryResultEntry>,
    /// The context IDs that were queried to produce these results.
    pub sources: Vec<ContextId>,
}

/// A single entry in a discovery result set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveryResultEntry {
    /// The agent's DID.
    pub did: DID,
    /// The agent's advertised capabilities.
    pub capabilities: Vec<String>,
    /// Optional participation summary.
    pub participation_summary: Option<serde_json::Value>,
    /// Provenance metadata for this entry.
    pub provenance: DataProvenance,
    /// Relevance score (0.0 to 1.0).
    pub relevance_score: f64,
}

// ---------------------------------------------------------------------------
// RegistrationEntry
// ---------------------------------------------------------------------------

/// A registered agent entry in a context with discovery tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationEntry {
    /// The registered agent's DID.
    pub did: DID,
    /// The agent's advertised capabilities.
    pub capabilities: Vec<String>,
    /// Arbitrary metadata provided at registration time.
    pub metadata: serde_json::Value,
    /// Unique identifier for this registration entry.
    pub entry_id: String,
    /// Unix timestamp (seconds) when the registration was recorded.
    pub registered_at: u64,
}

// ---------------------------------------------------------------------------
// DiscoveryError
// ---------------------------------------------------------------------------

/// Errors produced by discovery operations.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// DID resolution via did:dht failed.
    #[error("DID resolution failed: {0}")]
    DidResolutionFailed(String),

    /// The resolved DID document has no `SCPCapabilities` service entry.
    #[error("no SCPCapabilities service entry in DID document for: {0}")]
    NoCapabilitiesService(String),

    /// The `SCPCapabilities` service entry contains invalid capability data.
    #[error("invalid capabilities in DID document: {0}")]
    InvalidCapabilities(String),

    /// A cache operation failed.
    #[error("cache error: {0}")]
    CacheError(String),
}
