//! Addressing types for SCP discovery — pure protocol types.
//!
//! Sync type definitions extracted from `scp-runtime::discovery::addressing`.
//! Async resolution logic remains in scp-runtime.

use serde::{Deserialize, Serialize};

use super::ContextId;
use scp_clock::Clock;
use scp_did::DID;

/// Maximum length of the local-part of an address.
pub const MAX_LOCAL_PART_LENGTH: usize = 64;

/// The target of a handle registration -- what the handle points to.
///
/// Used when registering handles in a context with discovery outlets via `handle_register`.
///
/// See §22.3.1 Handle Outlets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandleTarget {
    /// The handle points to a DID (identity address).
    Identity {
        /// The DID this handle resolves to.
        did: DID,
    },
    /// The handle points to a context (context address).
    Context {
        /// The context ID (hex-encoded).
        context_id: ContextId,
        /// Relay URLs for reaching this context.
        relay_urls: Vec<String>,
    },
}

/// Trust level indicating the strength and source of a handle-to-identifier
/// binding.
///
/// Every resolution result carries a trust level. Trust levels are not strictly
/// ordered -- their relative strength is context-dependent. The SDK exposes
/// them to consumers (agents, client UI); consumers decide what is sufficient
/// for their operation.
///
/// See §22.7 Trust Levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// DID exchanged out-of-band, verified by the user.
    DirectExchange,
    /// User-assigned petname, maximum personal trust.
    LocalPetname,
    /// Multiple resolution paths agree on the same DID.
    MultiLayerCorroborated {
        /// Which resolution paths corroborated this result.
        sources: Vec<ResolutionPath>,
    },
    /// HTTPS-dependent, domain operator controls binding.
    DomainVerified,
    /// Cryptographically signed, platform-dependent verification.
    AttestationVerified,
    /// Community-governed, context controls binding.
    HandleRegistryVerified,
}

impl TrustLevel {
    /// Returns a numeric ordering weight for sorting.
    ///
    /// Higher values indicate stronger trust. This is a default ranking;
    /// consumers may override. Per §22.7 the levels are not strictly ordered
    /// in all threat models, but this provides a useful default.
    #[must_use]
    pub const fn default_rank(&self) -> u8 {
        match self {
            Self::DirectExchange => 6,
            Self::LocalPetname => 5,
            Self::MultiLayerCorroborated { .. } => 4,
            Self::DomainVerified => 3,
            Self::AttestationVerified => 2,
            Self::HandleRegistryVerified => 1,
        }
    }
}

/// Structured metadata recording which layer resolved an address.
///
/// This is provenance for the resolution itself: which layer, what source,
/// and when.
///
/// See §22.7 Resolution Path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionPath {
    /// The resolution layer that produced this result.
    pub layer: ResolutionLayer,
    /// Human-readable source identifier (context name, domain, platform).
    pub source: String,
    /// Context ID (hex), present only for the `HandleRegistry` layer.
    pub source_id: Option<String>,
    /// Unix timestamp (seconds) when resolution occurred.
    pub resolved_at: u64,
}

/// The resolution layer that produced an address resolution result.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResolutionLayer {
    /// Resolved via local petname lookup.
    Petname,
    /// Resolved via context handle lookup.
    HandleRegistry,
    /// Resolved via attestation-backed handle reverse-lookup.
    Attestation,
    /// Resolved via domain `.well-known/scp` handles map.
    Domain,
    /// Multiple independent resolution paths agreed on the same DID (§22.8.2 step 4c).
    MultiLayerCorroborated,
}

/// A single resolution result from the addressing layer.
///
/// An address may resolve to an identity (DID) or a context (context ID +
/// relay URLs). Each result carries a trust level and the resolution path
/// that produced it.
///
/// See §22.2.1 Address Types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressResolution {
    /// The address resolved to a DID.
    Identity {
        /// The resolved DID.
        did: DID,
        /// Trust level of this resolution.
        trust_level: TrustLevel,
        /// How this resolution was produced.
        resolution_path: ResolutionPath,
    },
    /// The address resolved to a context.
    Context {
        /// The context ID (hex-encoded).
        context_id: ContextId,
        /// Relay URLs for reaching this context.
        relay_urls: Vec<String>,
        /// The context mode, if known.
        mode: Option<String>,
        /// Trust level of this resolution.
        trust_level: TrustLevel,
        /// How this resolution was produced.
        resolution_path: ResolutionPath,
    },
}

impl AddressResolution {
    /// Returns the trust level of this resolution result.
    #[must_use]
    pub const fn trust_level(&self) -> &TrustLevel {
        match self {
            Self::Identity { trust_level, .. } | Self::Context { trust_level, .. } => trust_level,
        }
    }

    /// Returns the resolution path of this resolution result.
    #[must_use]
    pub const fn resolution_path(&self) -> &ResolutionPath {
        match self {
            Self::Identity {
                resolution_path, ..
            }
            | Self::Context {
                resolution_path, ..
            } => resolution_path,
        }
    }
}

/// Errors produced by address parsing and resolution.
#[derive(Debug, thiserror::Error)]
pub enum AddressingError {
    /// The address string is empty.
    #[error("address is empty")]
    EmptyAddress,

    /// The local-part exceeds the maximum length.
    #[error("local-part exceeds maximum length of {MAX_LOCAL_PART_LENGTH} characters")]
    LocalPartTooLong,

    /// The local-part contains invalid characters.
    #[error("local-part contains invalid characters: only [a-z0-9._-] allowed")]
    InvalidLocalPartCharacters,

    /// The local-part has a leading or trailing hyphen or period.
    #[error("local-part must not start or end with a hyphen or period")]
    InvalidLocalPartBoundary,

    /// The local-part contains consecutive periods.
    #[error("local-part must not contain consecutive periods")]
    ConsecutivePeriods,

    /// No resolution results found for the given address.
    #[error("address not found: {0}")]
    NotFound(String),

    /// A resolution layer returned an error.
    #[error("resolution error in {layer} layer: {message}")]
    ResolutionFailed {
        /// Which layer failed.
        layer: String,
        /// Error description.
        message: String,
    },
}

/// Trait for local petname store access.
///
/// Provides instant (non-async) access to petname mappings stored in identity
/// private state (§3.7).
pub trait PetnameStore {
    /// Resolves a petname to address resolution results.
    ///
    /// Returns matching entries instantly (no network I/O). Returns an empty
    /// vec if no petname matches.
    fn resolve_petname(&self, name: &str, clock: &dyn Clock) -> Vec<AddressResolution>;
}
