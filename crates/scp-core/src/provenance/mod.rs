//! Data provenance types for SCP.
//!
//! Provenance is a core protocol principle (spec section 1, tenet 1): "All
//! non-private data carries verifiable origin metadata." Every message, tool
//! output, attestation, and cross-context data transfer is traceable to its
//! source. The absence of provenance is itself a signal.
//!
//! See ADR-019 in `.docs/adrs/phase-4.md` for the full design.
//!
//! # Types
//!
//! - [`DataProvenance`] -- Provenance metadata attached to cross-context data
//!   flows (spec section 7.7.1).
//! - [`SourceType`] -- Current data availability status of the source context.
//! - [`DiscoveryMethod`] -- How the data source was discovered.
//! - [`ProvenanceQuality`] -- Ordered quality evaluation tiers (spec section
//!   7.7.2).
//! - [`ProvenanceError`] -- Error type for provenance operations.
//!
//! # Modules
//!
//! - [`attach`] -- Provenance attachment at cross-context boundaries (SCP-071).
//! - [`evaluate`] -- Provenance quality evaluation logic (SCP-072).

pub mod attach;
pub mod evaluate;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::context::MemoryScope;
use crate::economy::types::Amount;

// ---------------------------------------------------------------------------
// Type aliases (match event_log/mod.rs pattern)
// ---------------------------------------------------------------------------

use scp_identity::DID;

/// A context identifier string.
///
/// Represented as a plain `String` for Phase 4. This matches the pattern used
/// in the `event_log` module.
pub type ContextId = String;

// ---------------------------------------------------------------------------
// SourceType
// ---------------------------------------------------------------------------

/// Reflects the current data availability of the source context, not the
/// creation-time setting.
///
/// The source type may change over the lifetime of a provenance record as the
/// source context transitions through its lifecycle. For example, a context
/// that was `Persistent` at the time of data flow may later close, changing
/// the source type to `Ephemeral` or `Summary`.
///
/// See ADR-019 acceptance criterion 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    /// Source context is still open and verifiable.
    Persistent,
    /// Source context has closed and keys have been destroyed.
    Ephemeral,
    /// Source context has closed and a verified summary is available.
    Summary,
}

// ---------------------------------------------------------------------------
// DiscoveryMethod
// ---------------------------------------------------------------------------

/// How the data source was discovered by the receiving party.
///
/// Tracks whether the source was found through a shared context membership,
/// via a discovery registry, or was introduced without a protocol-level
/// discovery path.
///
/// See ADR-019 acceptance criterion 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Source was discovered through shared membership in the given context.
    SharedContext(ContextId),
    /// Source was discovered through a discovery registry context.
    Registry(ContextId),
    /// No protocol-level discovery path. Data was introduced outside of SCP
    /// discovery mechanisms (out-of-band introduction).
    ///
    /// Renamed from `None` to avoid shadowing `Optional.none` in Swift
    /// bindings (see issue #772). Accepts `"None"` on deserialization for
    /// backward compatibility.
    #[serde(alias = "None")]
    OutOfBand,
}

// ---------------------------------------------------------------------------
// ProvenanceQuality
// ---------------------------------------------------------------------------

/// Provenance quality evaluation tiers (spec section 7.7.2).
///
/// Ordered from lowest to highest quality. Agents use these tiers in their
/// trust evaluation logic to weight data according to its verifiability.
///
/// The ordering is:
/// `NoProvenance` < `EphemeralKnownParties` < `SummaryVerified` < `PersistentVerifiable`
///
/// See ADR-019 acceptance criterion 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvenanceQuality {
    /// Data introduced without protocol-level origin tracking. The absence of
    /// provenance is itself a signal -- this is the lowest quality tier.
    NoProvenance = 0,
    /// Source context was ephemeral and keys have been destroyed, but the
    /// counterparties are known. Origin is attested but not independently
    /// verifiable.
    EphemeralKnownParties = 1,
    /// Source context closed with summary scope. A verified summary is
    /// available, providing partial verifiability of the original data.
    SummaryVerified = 2,
    /// Source context is persistent and still active. The original data can
    /// be independently verified against the source context's event log.
    /// This is the highest quality tier.
    PersistentVerifiable = 3,
}

impl PartialOrd for ProvenanceQuality {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProvenanceQuality {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

// ---------------------------------------------------------------------------
// CounterpartyPolicy (§7.7.1, §24.3.1, §24.3.5)
// ---------------------------------------------------------------------------

/// Policy governing how counterparty information (membership DIDs) is handled
/// in outbound provenance when data crosses context boundaries (§7.7.1).
///
/// The sending SDK applies this policy at attachment time. The policy
/// determines whether real DIDs, pseudonymized identifiers, or no
/// counterparty information appears in the provenance record.
///
/// - `Full` — real DIDs are included. Appropriate for contexts where
///   membership is public or for intra-context provenance.
/// - `Pseudonymized` — real DIDs are replaced with context-scoped pseudonyms
///   (§9.10.4). Receiving contexts see stable pseudonyms but cannot correlate
///   them to real DIDs without the source context's pseudonym derivation key.
/// - `Redacted` — counterparties list is always empty. Most privacy-preserving.
///
/// **Default for cross-context export:** `Redacted`. Contexts that want to
/// share counterparty information must opt in explicitly.
///
/// **Intra-context:** Always `Full` regardless of policy setting. The policy
/// governs only what is exported across context boundaries.
///
/// See spec §7.7.1, §24.3.1, §24.3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CounterpartyPolicy {
    /// Include real DIDs in provenance counterparties.
    Full,
    /// Replace real DIDs with context-scoped pseudonyms (§9.10.4).
    Pseudonymized,
    /// Set counterparties to an empty list. No identity information exported.
    Redacted,
}

impl Default for CounterpartyPolicy {
    /// Default for cross-context export is `Redacted` (§7.7.1).
    fn default() -> Self {
        Self::Redacted
    }
}

// ---------------------------------------------------------------------------
// DataProvenance
// ---------------------------------------------------------------------------

/// Data provenance metadata (spec section 7.7.1).
///
/// Attached automatically by the protocol when data crosses context boundaries
/// through protocol mechanisms (tool interfaces, structured messages). Records
/// the full lineage of a piece of data: where it came from, who was involved,
/// how it was discovered, and how many context hops it has traversed.
///
/// # Chain depth
///
/// The `chain_depth` field tracks how many cross-context hops this data has
/// traversed. The protocol default maximum is 8 hops to prevent accountability
/// laundering -- data traversing enough contexts that its origin becomes
/// meaningless. See [`ProvenanceError::ChainDepthExceeded`].
///
/// See ADR-019 acceptance criteria 1-6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataProvenance {
    /// The context from which this data originated.
    pub source_context: ContextId,
    /// Current data availability status of the source context.
    pub source_type: SourceType,
    /// DIDs of the parties involved in the source context at the time of
    /// data flow.
    pub counterparties: Vec<DID>,
    /// Optional human-readable purpose description for this data flow.
    pub purpose: Option<String>,
    /// How the data source was discovered.
    pub discovery_method: DiscoveryMethod,
    /// Age of the data at the time provenance was attached.
    pub age: Duration,
    /// Memory scope of the source context, controlling data retention behavior.
    pub memory_scope: MemoryScope,
    /// Number of cross-context hops this data has traversed. Protocol default
    /// maximum is 8.
    pub chain_depth: u8,
    /// Ordered list of intermediary context IDs when `chain_depth > 0`.
    /// Records the full path the data has traversed across contexts.
    pub chain_path: Option<Vec<ContextId>>,
    /// Cost of producing this data, if any (spec section 19.6).
    ///
    /// Receiving contexts see what data cost to produce -- expensive
    /// computations carry economic provenance.
    pub payment_amount: Option<Amount>,
    /// Payment adapter used for the payment, if any (spec section 19.6).
    pub payment_adapter: Option<String>,
    /// Receipt ID for verification of the payment, if any (spec section 19.6).
    pub payment_receipt_id: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// ProvenanceError
// ---------------------------------------------------------------------------

/// Errors produced by provenance operations.
///
/// See ADR-019 acceptance criterion 3.
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    /// The data has exceeded the maximum allowed cross-context hop count.
    ///
    /// The protocol default maximum is 8 hops. At the maximum depth, the data
    /// cannot trigger further cross-context calls. This prevents accountability
    /// laundering where data traverses enough contexts that its origin becomes
    /// meaningless.
    #[error("chain depth {depth} exceeds maximum allowed depth of {max_depth}")]
    ChainDepthExceeded {
        /// The current chain depth of the data.
        depth: u8,
        /// The maximum allowed chain depth.
        max_depth: u8,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::single_char_pattern
)]
mod tests {
    use super::*;

    #[test]
    fn data_provenance_construction_with_all_fields() {
        let provenance = DataProvenance {
            source_context: "ctx-abc-123".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
            purpose: Some("recipe sharing".to_string()),
            discovery_method: DiscoveryMethod::SharedContext("ctx-shared".to_string()),
            age: Duration::from_secs(300),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        assert_eq!(provenance.source_context, "ctx-abc-123");
        assert_eq!(provenance.source_type, SourceType::Persistent);
        assert_eq!(provenance.counterparties.len(), 2);
        assert_eq!(provenance.purpose.as_deref(), Some("recipe sharing"));
        assert_eq!(provenance.memory_scope, MemoryScope::Full);
        assert_eq!(provenance.chain_depth, 0);
        assert!(provenance.chain_path.is_none());
    }

    #[test]
    fn data_provenance_construction_with_chain_path() {
        let provenance = DataProvenance {
            source_context: "ctx-origin".to_string(),
            source_type: SourceType::Ephemeral,
            counterparties: vec!["did:dht:z6MkCharlie".into()],
            purpose: None,
            discovery_method: DiscoveryMethod::Registry("ctx-registry".to_string()),
            age: Duration::from_secs(600),
            memory_scope: MemoryScope::Ephemeral,
            chain_depth: 2,
            chain_path: Some(vec!["ctx-hop-1".to_string(), "ctx-hop-2".to_string()]),
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        assert_eq!(provenance.chain_depth, 2);
        let path = provenance.chain_path.as_ref();
        assert!(path.is_some());
        assert_eq!(path.map(Vec::len), Some(2));
    }

    #[test]
    fn data_provenance_construction_with_out_of_band_discovery() {
        let provenance = DataProvenance {
            source_context: "ctx-unknown".to_string(),
            source_type: SourceType::Summary,
            counterparties: vec![],
            purpose: None,
            discovery_method: DiscoveryMethod::OutOfBand,
            age: Duration::from_secs(0),
            memory_scope: MemoryScope::Summary,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        assert_eq!(provenance.discovery_method, DiscoveryMethod::OutOfBand);
        assert_eq!(provenance.source_type, SourceType::Summary);
        assert!(provenance.counterparties.is_empty());
    }

    #[test]
    fn source_type_variants_are_distinct() {
        assert_ne!(SourceType::Persistent, SourceType::Ephemeral);
        assert_ne!(SourceType::Persistent, SourceType::Summary);
        assert_ne!(SourceType::Ephemeral, SourceType::Summary);
    }

    #[test]
    fn discovery_method_shared_context_holds_context_id() {
        let method = DiscoveryMethod::SharedContext("ctx-shared-abc".to_string());
        if let DiscoveryMethod::SharedContext(ctx) = &method {
            assert_eq!(ctx, "ctx-shared-abc");
        } else {
            panic!("expected SharedContext variant");
        }
    }

    #[test]
    fn discovery_method_registry_holds_context_id() {
        let method = DiscoveryMethod::Registry("ctx-registry-def".to_string());
        if let DiscoveryMethod::Registry(ctx) = &method {
            assert_eq!(ctx, "ctx-registry-def");
        } else {
            panic!("expected Registry variant");
        }
    }

    #[test]
    fn discovery_method_out_of_band_variant() {
        let method = DiscoveryMethod::OutOfBand;
        assert_eq!(method, DiscoveryMethod::OutOfBand);
    }

    #[test]
    fn provenance_quality_ordering_no_provenance_is_lowest() {
        assert!(ProvenanceQuality::NoProvenance < ProvenanceQuality::EphemeralKnownParties);
        assert!(ProvenanceQuality::NoProvenance < ProvenanceQuality::SummaryVerified);
        assert!(ProvenanceQuality::NoProvenance < ProvenanceQuality::PersistentVerifiable);
    }

    #[test]
    fn provenance_quality_ordering_ephemeral_less_than_summary() {
        assert!(ProvenanceQuality::EphemeralKnownParties < ProvenanceQuality::SummaryVerified);
        assert!(ProvenanceQuality::EphemeralKnownParties < ProvenanceQuality::PersistentVerifiable);
    }

    #[test]
    fn provenance_quality_ordering_summary_less_than_persistent() {
        assert!(ProvenanceQuality::SummaryVerified < ProvenanceQuality::PersistentVerifiable);
    }

    #[test]
    fn provenance_quality_ordering_full_chain() {
        let mut qualities = vec![
            ProvenanceQuality::PersistentVerifiable,
            ProvenanceQuality::NoProvenance,
            ProvenanceQuality::SummaryVerified,
            ProvenanceQuality::EphemeralKnownParties,
        ];
        qualities.sort();
        assert_eq!(
            qualities,
            vec![
                ProvenanceQuality::NoProvenance,
                ProvenanceQuality::EphemeralKnownParties,
                ProvenanceQuality::SummaryVerified,
                ProvenanceQuality::PersistentVerifiable,
            ]
        );
    }

    #[test]
    fn provenance_quality_equality() {
        assert_eq!(
            ProvenanceQuality::NoProvenance,
            ProvenanceQuality::NoProvenance
        );
        assert_eq!(
            ProvenanceQuality::PersistentVerifiable,
            ProvenanceQuality::PersistentVerifiable
        );
    }

    #[test]
    fn provenance_error_chain_depth_exceeded_message() {
        let err = ProvenanceError::ChainDepthExceeded {
            depth: 4,
            max_depth: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("4"));
        assert!(msg.contains("3"));
        assert!(msg.contains("chain depth"));
    }

    #[test]
    fn data_provenance_serialization_roundtrip() {
        let provenance = DataProvenance {
            source_context: "ctx-serde-test".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec!["did:dht:z6MkTest".into()],
            purpose: Some("testing serde".to_string()),
            discovery_method: DiscoveryMethod::SharedContext("ctx-disc".to_string()),
            age: Duration::from_secs(42),
            memory_scope: MemoryScope::Full,
            chain_depth: 1,
            chain_path: Some(vec!["ctx-hop".to_string()]),
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        let json = serde_json::to_string(&provenance);
        assert!(json.is_ok(), "serialization should succeed");

        let deserialized: Result<DataProvenance, _> =
            serde_json::from_str(json.as_ref().map(String::as_str).unwrap_or(""));
        assert!(deserialized.is_ok(), "deserialization should succeed");

        let roundtripped = deserialized.unwrap_or_else(|_| panic!("deserialization failed"));
        assert_eq!(roundtripped.source_context, "ctx-serde-test");
        assert_eq!(roundtripped.source_type, SourceType::Persistent);
        assert_eq!(roundtripped.counterparties.len(), 1);
        assert_eq!(roundtripped.purpose.as_deref(), Some("testing serde"));
        assert_eq!(roundtripped.chain_depth, 1);
    }

    #[test]
    fn source_type_serialization_roundtrip() {
        for source_type in [
            SourceType::Persistent,
            SourceType::Ephemeral,
            SourceType::Summary,
        ] {
            let json = serde_json::to_string(&source_type);
            assert!(
                json.is_ok(),
                "serialization of {source_type:?} should succeed"
            );
            let deserialized: Result<SourceType, _> =
                serde_json::from_str(json.as_ref().map(String::as_str).unwrap_or(""));
            assert!(
                deserialized.is_ok(),
                "deserialization of {source_type:?} should succeed"
            );
            assert_eq!(deserialized.unwrap_or(SourceType::Persistent), source_type);
        }
    }

    #[test]
    fn discovery_method_serialization_roundtrip() {
        let methods = vec![
            DiscoveryMethod::SharedContext("ctx-1".to_string()),
            DiscoveryMethod::Registry("ctx-2".to_string()),
            DiscoveryMethod::OutOfBand,
        ];
        for method in methods {
            let json = serde_json::to_string(&method);
            assert!(json.is_ok(), "serialization of {method:?} should succeed");
            let deserialized: Result<DiscoveryMethod, _> =
                serde_json::from_str(json.as_ref().map(String::as_str).unwrap_or(""));
            assert!(
                deserialized.is_ok(),
                "deserialization of {method:?} should succeed"
            );
            assert_eq!(deserialized.unwrap_or(DiscoveryMethod::OutOfBand), method);
        }
    }

    #[test]
    fn provenance_quality_serialization_roundtrip() {
        let qualities = vec![
            ProvenanceQuality::NoProvenance,
            ProvenanceQuality::EphemeralKnownParties,
            ProvenanceQuality::SummaryVerified,
            ProvenanceQuality::PersistentVerifiable,
        ];
        for quality in qualities {
            let json = serde_json::to_string(&quality);
            assert!(json.is_ok(), "serialization of {quality:?} should succeed");
            let deserialized: Result<ProvenanceQuality, _> =
                serde_json::from_str(json.as_ref().map(String::as_str).unwrap_or(""));
            assert!(
                deserialized.is_ok(),
                "deserialization of {quality:?} should succeed"
            );
            assert_eq!(
                deserialized.unwrap_or(ProvenanceQuality::NoProvenance),
                quality
            );
        }
    }

    #[test]
    fn data_provenance_with_empty_counterparties() {
        let provenance = DataProvenance {
            source_context: "ctx-empty".to_string(),
            source_type: SourceType::Ephemeral,
            counterparties: vec![],
            purpose: None,
            discovery_method: DiscoveryMethod::OutOfBand,
            age: Duration::from_secs(0),
            memory_scope: MemoryScope::Ephemeral,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        assert!(provenance.counterparties.is_empty());
        assert!(provenance.purpose.is_none());
        assert!(provenance.chain_path.is_none());
    }

    #[test]
    fn data_provenance_max_chain_depth_value() {
        let provenance = DataProvenance {
            source_context: "ctx-deep".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec!["did:dht:z6MkDeep".into()],
            purpose: None,
            discovery_method: DiscoveryMethod::OutOfBand,
            age: Duration::from_secs(1000),
            memory_scope: MemoryScope::Full,
            chain_depth: 3,
            chain_path: Some(vec![
                "ctx-1".to_string(),
                "ctx-2".to_string(),
                "ctx-3".to_string(),
            ]),
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        assert_eq!(provenance.chain_depth, 3);
        assert_eq!(provenance.chain_path.as_ref().map(Vec::len), Some(3));
    }
}
