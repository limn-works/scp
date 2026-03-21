//! Tool-interface discovery for SCP.
//!
//! Implements two-tier discovery per ADR-020 (`.docs/adrs/phase-4.md`) and
//! human-readable addressing per §22.
//!
//! 1. **DID document capabilities** -- Direct lookup via `did:dht`. Any agent
//!    can publish capabilities in their DID document's `SCPCapabilities` service
//!    entry. Zero setup, zero registration, zero dependency on contexts with discovery tools.
//!
//! 2. **Contexts with discovery tools** -- Searchable registries operated as standard SCP
//!    contexts with open join policies and standardized tool schemas.
//!
//! 3. **Human-readable addressing** (§22) -- Resolution layer mapping human-
//!    readable strings to DIDs and context IDs via petnames, context
//!    handles, attestation handles, and domain handles.
//!
//! # Modules
//!
//! - [`did_capabilities`] -- DID document capability resolution via `did:dht`.
//! - [`dht_context`] -- DHT-based context discovery via DID document service endpoints (§5.14.11, §18.2.2).
//! - [`addressing`] -- Address format types, trust levels, and unified resolution (§22).
//! - [`handles`] -- Context handle tools: register, lookup, deregister (§22.3).
//! - [`scope`] -- Scope tools: namespace-to-context registration (§22.3.5, ADR-043).
//! - [`petnames`] -- Petname storage in identity private state (§22.4).
//!
//! # Types
//!
//! - [`CapabilityEntry`] -- Capabilities extracted from a DID document.
//! - [`DiscoveryQuery`] -- Search query for contexts with discovery tools.
//! - [`DiscoveryResult`] -- Merged search results with provenance.
//! - [`DiscoveryResultEntry`] -- A single result entry with relevance scoring.
//! - [`RegistrationEntry`] -- A registered agent entry in a context with discovery tools.
//! - [`BootstrapContextEntry`] -- Bootstrap context with creator DID verification (§22.13.2).
//! - [`DataProvenance`] -- Placeholder provenance metadata (replaced by SCP-070).
//! - [`DiscoveryError`] -- Error type for discovery operations.
//! - [`AddressResolver`] -- Multi-path address resolution (§22.8).
//! - [`TrustLevel`] -- Trust level for resolution results (§22.7).
//! - [`HandleRegistry`] -- In-memory handle registry (§22.3).
//! - [`PetnameMap`] -- Petname storage (§22.4).

pub mod addressing;
pub mod bootstrap;
pub mod context;
pub mod dht_context;
pub mod did_capabilities;
pub mod handles;
pub mod petnames;
pub mod push;
pub mod scope;
pub mod search;

use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use addressing::{
    AddressResolution, AddressResolver, AddressType, AddressingError, DISCOVERY_HANDLE_CACHE_TTL,
    DOMAIN_HANDLE_CACHE_TTL, HandleQuerier, HandleTarget, MAX_LOCAL_PART_LENGTH, ParsedAddress,
    PetnameStore, ResolutionCache, ResolutionLayer, ResolutionPath, TrustLevel, normalize_address,
    parse_address,
};
pub use bootstrap::{
    BootstrapConfig, BootstrapContextEntry, BootstrapResolver, BootstrapVerificationError,
    MAX_CUSTOM_CONTEXTS, WellKnownBootstrapError,
};
pub use context::{
    AgentDeregisterParams, AgentDeregisterResult, AgentRegisterParams, AgentRegisterResult,
    AgentSearchParams, AgentSearchResult, RegistrationEvent, TOOL_AGENT_DEREGISTER,
    TOOL_AGENT_REGISTER, TOOL_AGENT_SEARCH, agent_deregister_schema, agent_register_schema,
    agent_search_schema, is_standard_tool,
};
pub use dht_context::{
    ContextDiscoveryResult, ContextDiscoverySource, publish_context_to_did_document,
    resolve_context_uri, resolve_contexts_from_did, unpublish_context_from_did_document,
};
pub use did_capabilities::{CapabilityEntry, resolve_capabilities};
pub use handles::{
    HandleDeregisterParams, HandleDeregisterResult, HandleEntry, HandleLookupParams,
    HandleLookupResult, HandleMetadata, HandleRegisterParams, HandleRegisterResult,
    HandleRegisterStatus, HandleRegistry, HandleTypeFilter, TOOL_HANDLE_DEREGISTER,
    TOOL_HANDLE_LOOKUP, TOOL_HANDLE_REGISTER,
};
pub use petnames::{PetnameEvent, PetnameMap};
pub use scope::{
    ScopeDeregisterParams, ScopeDeregisterResult, ScopeEntry, ScopeLookupParams, ScopeLookupResult,
    ScopeMetadata, ScopeRegisterParams, ScopeRegisterResult, ScopeRegisterStatus,
    ScopeRegistrationEvent, ScopeRegistry, ScopeRegistryError, ScopeTarget, TOOL_SCOPE_DEREGISTER,
    TOOL_SCOPE_LOOKUP, TOOL_SCOPE_REGISTER, validate_scope_name,
};
pub use search::{ContactCache, ContextQuerier, unified_search};

// ---------------------------------------------------------------------------
// Type aliases (match event_log/mod.rs pattern)
// ---------------------------------------------------------------------------

use scp_identity::DID;

/// A context identifier string.
pub type ContextId = String;

// ---------------------------------------------------------------------------
// DataProvenance (placeholder -- replaced by SCP-070 provenance module)
// ---------------------------------------------------------------------------

/// Placeholder provenance metadata attached to discovery results.
///
/// This is a minimal struct that will be replaced by the full `DataProvenance`
/// type from the provenance module (SCP-070). It records the source DID, an
/// optional source context, and a timestamp.
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
///
/// Used to query contexts with discovery tools for agents matching specific capabilities,
/// keywords, or history requirements. All fields are optional filters -- an
/// empty query matches all entries.
///
/// See ADR-020 acceptance criterion 1.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryQuery {
    /// Filter by capability strings. Only agents advertising all listed
    /// capabilities are returned.
    pub capability_filter: Option<Vec<String>>,
    /// Free-text keyword filter for metadata search.
    pub keywords: Option<Vec<String>>,
    /// Minimum participation history duration. Only agents with at least
    /// this much history in contexts with discovery tools are returned.
    pub min_history: Option<Duration>,
}

// ---------------------------------------------------------------------------
// DiscoveryResult / DiscoveryResultEntry
// ---------------------------------------------------------------------------

/// Merged search results from one or more discovery sources.
///
/// Contains deduplicated entries ranked by relevance, with provenance per
/// entry and the list of context sources that were queried.
///
/// See ADR-020 acceptance criterion 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveryResult {
    /// The discovery result entries, ranked by relevance score (descending).
    pub entries: Vec<DiscoveryResultEntry>,
    /// The context IDs that were queried to produce these results.
    pub sources: Vec<ContextId>,
}

/// A single entry in a discovery result set.
///
/// Contains the agent's DID, advertised capabilities, optional participation
/// summary, provenance metadata, and a relevance score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveryResultEntry {
    /// The agent's DID.
    pub did: DID,
    /// The agent's advertised capabilities.
    pub capabilities: Vec<String>,
    /// Optional participation summary (agent-computed from event logs).
    pub participation_summary: Option<serde_json::Value>,
    /// Provenance metadata for this entry.
    pub provenance: DataProvenance,
    /// Relevance score (0.0 to 1.0). Higher is more relevant.
    pub relevance_score: f64,
}

// ---------------------------------------------------------------------------
// RegistrationEntry
// ---------------------------------------------------------------------------

/// A registered agent entry in a context with discovery tools.
///
/// Created when an agent registers via the `agent_register` tool schema.
/// The entry is recorded in the context's event log as an MLS
/// application message.
///
/// See ADR-020 acceptance criterion 1.
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

    /// The system clock is unavailable or before the Unix epoch.
    #[error("clock error: {0}")]
    ClockError(#[from] crate::time::ClockError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn discovery_query_default_has_no_filters() {
        let query = DiscoveryQuery::default();
        assert!(query.capability_filter.is_none());
        assert!(query.keywords.is_none());
        assert!(query.min_history.is_none());
    }

    #[test]
    fn discovery_query_with_filters() {
        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned()]),
            keywords: Some(vec!["rust".to_owned()]),
            min_history: Some(Duration::from_secs(86400)),
        };
        assert_eq!(query.capability_filter.as_ref().unwrap().len(), 1);
        assert_eq!(query.keywords.as_ref().unwrap()[0], "rust");
        assert_eq!(query.min_history.unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn discovery_result_entry_serialization_roundtrip() {
        let entry = DiscoveryResultEntry {
            did: "did:dht:zTestDid".into(),
            capabilities: vec!["code_review".to_owned(), "testing".to_owned()],
            participation_summary: Some(serde_json::json!({"participation": 42})),
            provenance: DataProvenance {
                source_did: "did:dht:zSourceDid".into(),
                source_context: Some("ctx-001".to_owned()),
                timestamp: 1_700_000_000,
            },
            relevance_score: 0.85,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: DiscoveryResultEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn registration_entry_serialization_roundtrip() {
        let entry = RegistrationEntry {
            did: "did:dht:zAgent123".into(),
            capabilities: vec!["translation".to_owned()],
            metadata: serde_json::json!({"language": "es"}),
            entry_id: "reg-001".to_owned(),
            registered_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: RegistrationEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn data_provenance_serialization_roundtrip() {
        let provenance = DataProvenance {
            source_did: "did:dht:zProvSource".into(),
            source_context: None,
            timestamp: 1_700_000_000,
        };

        let json = serde_json::to_string(&provenance).unwrap();
        let deserialized: DataProvenance = serde_json::from_str(&json).unwrap();

        assert_eq!(provenance, deserialized);
    }

    #[test]
    fn discovery_error_display_messages() {
        let err = DiscoveryError::DidResolutionFailed("timeout".to_owned());
        assert!(err.to_string().contains("timeout"));

        let err = DiscoveryError::NoCapabilitiesService("did:dht:z123".to_owned());
        assert!(err.to_string().contains("SCPCapabilities"));

        let err = DiscoveryError::InvalidCapabilities("malformed JSON".to_owned());
        assert!(err.to_string().contains("malformed JSON"));

        let err = DiscoveryError::CacheError("disk full".to_owned());
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn discovery_result_empty() {
        let result = DiscoveryResult {
            entries: Vec::new(),
            sources: vec!["ctx-discovery-1".to_owned()],
        };
        assert!(result.entries.is_empty());
        assert_eq!(result.sources.len(), 1);
    }
}
