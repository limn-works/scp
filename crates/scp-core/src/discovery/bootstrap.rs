//! Discovery bootstrap and fallback configuration.
//!
//! Provides configurable default bootstrap context IDs (analogous to DNS root
//! servers) and a resolver that combines context queries with
//! fallback to direct DID resolution.
//!
//! The SDK ships with configurable defaults that are auto-queried on first
//! identity creation (opt-out). Users can add custom contexts with discovery tools and
//! configure fallback behavior.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`, acceptance criterion 8.

use serde::{Deserialize, Serialize};

use crate::well_known::{WellKnownScp, WellKnownValidationError};
use scp_identity::DidMethod;

use super::{ContextId, DiscoveryError};

// ---------------------------------------------------------------------------
// BootstrapContextEntry
// ---------------------------------------------------------------------------

/// A bootstrap context entry pairing a context ID with the expected creator DID.
///
/// The `expected_creator_did` enables the SDK to verify that the context was
/// indeed created by the expected operator (spec §22.13), preventing a
/// hijacked context ID from impersonating a bootstrap context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapContextEntry {
    /// The context ID to bootstrap from.
    pub context_id: ContextId,

    /// The expected DID of the context creator. The SDK MUST verify this
    /// against the actual context creator before trusting bootstrap data.
    pub expected_creator_did: String,
}

// ---------------------------------------------------------------------------
// BootstrapConfig
// ---------------------------------------------------------------------------

/// Configuration for discovery bootstrap behavior.
///
/// Controls which contexts with discovery tools the SDK queries on startup, whether
/// auto-query fires on first identity creation, and whether to fall back to
/// direct DID resolution when contexts with discovery tools are unavailable.
///
/// Analogous to DNS root servers: the SDK ships with configurable default
/// bootstrap context entries. Users can add custom contexts with discovery tools. If
/// defaults are unreachable, direct DID resolution still works.
///
/// See ADR-020 acceptance criterion 8, spec §22.13.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// Default bootstrap context entries shipped with the SDK.
    ///
    /// These are queried automatically on first identity creation unless
    /// `auto_query_on_identity_creation` is set to `false`.
    #[serde(default)]
    pub default_contexts: Vec<BootstrapContextEntry>,

    /// Whether to automatically query contexts with discovery tools on first identity
    /// creation.
    ///
    /// Defaults to `true`. Set to `false` to opt out of automatic discovery
    /// queries.
    pub auto_query_on_identity_creation: bool,

    /// User-added custom context entries.
    ///
    /// These are queried alongside the defaults. Users can add contexts via
    /// [`BootstrapConfig::add_custom_context`].
    #[serde(default)]
    pub custom_contexts: Vec<BootstrapContextEntry>,

    /// Whether to fall back to direct DID resolution when contexts with discovery tools
    /// are unavailable or return no results.
    ///
    /// Defaults to `true`. When enabled, the resolver attempts DID document
    /// capability resolution as a last resort.
    pub fallback_to_did_resolution: bool,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            default_contexts: Vec::new(),
            auto_query_on_identity_creation: true,
            custom_contexts: Vec::new(),
            fallback_to_did_resolution: true,
        }
    }
}

impl BootstrapConfig {
    /// Creates a new `BootstrapConfig` with the given default bootstrap
    /// context entries.
    ///
    /// All other fields are set to their defaults: auto-query enabled,
    /// fallback enabled, no custom contexts.
    ///
    /// # Arguments
    ///
    /// * `entries` -- Default bootstrap context entries to query on bootstrap.
    #[must_use]
    pub fn with_defaults(entries: Vec<BootstrapContextEntry>) -> Self {
        Self {
            default_contexts: entries,
            ..Self::default()
        }
    }

    /// Adds a custom context entry.
    ///
    /// Custom contexts are queried alongside the defaults. Duplicate context
    /// IDs are not filtered here -- deduplication happens at query time in
    /// [`BootstrapResolver::resolve_contexts`].
    pub fn add_custom_context(&mut self, entry: BootstrapContextEntry) {
        self.custom_contexts.push(entry);
    }

    /// Returns all context IDs (defaults + custom) as a combined list.
    ///
    /// The returned list contains context IDs from the default entries
    /// followed by those from the custom entries.
    #[must_use]
    pub fn all_context_ids(&self) -> Vec<&ContextId> {
        self.default_contexts
            .iter()
            .chain(self.custom_contexts.iter())
            .map(|entry| &entry.context_id)
            .collect()
    }

    /// Returns all context entries (defaults + custom) as a combined list.
    #[must_use]
    pub fn all_entries(&self) -> Vec<&BootstrapContextEntry> {
        self.default_contexts
            .iter()
            .chain(self.custom_contexts.iter())
            .collect()
    }

    /// Returns whether the SDK should auto-query contexts with discovery tools on first
    /// identity creation.
    #[must_use]
    pub const fn should_auto_query(&self) -> bool {
        self.auto_query_on_identity_creation
    }

    /// Returns whether the resolver should fall back to direct DID resolution
    /// when contexts with discovery tools are unavailable.
    #[must_use]
    pub const fn should_fallback(&self) -> bool {
        self.fallback_to_did_resolution
    }
}

// ---------------------------------------------------------------------------
// BootstrapResolver
// ---------------------------------------------------------------------------

/// Resolves contexts with discovery tools and provides fallback to DID resolution.
///
/// Holds a [`BootstrapConfig`] and provides methods to retrieve all available
/// bootstrap context IDs and to attempt resolution with fallback behavior.
///
/// See ADR-020 acceptance criterion 8.
#[derive(Debug, Clone)]
pub struct BootstrapResolver {
    /// The bootstrap configuration.
    config: BootstrapConfig,
}

impl BootstrapResolver {
    /// Creates a new `BootstrapResolver` with the given configuration.
    #[must_use]
    pub const fn new(config: BootstrapConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the underlying bootstrap configuration.
    #[must_use]
    pub const fn config(&self) -> &BootstrapConfig {
        &self.config
    }

    /// Returns all available context IDs (defaults + custom),
    /// deduplicated while preserving order.
    #[must_use]
    pub fn resolve_contexts(&self) -> Vec<ContextId> {
        let mut seen = std::collections::HashSet::new();
        self.config
            .all_context_ids()
            .into_iter()
            .filter(|id| seen.insert((*id).clone()))
            .cloned()
            .collect()
    }

    /// Processes a `.well-known/scp` document with full DID cross-verification.
    ///
    /// Performs both privacy validation (§18.3) and DHT cross-verification
    /// (§18.3.2) before trusting the document. This method MUST be called on
    /// every fetch — verification is not cached from first use (no TOFU).
    ///
    /// # Verification Steps
    ///
    /// 1. Validate the document against §18.3 privacy constraints.
    /// 2. Resolve the operator DID via DHT and cross-reference the relay URL,
    ///    operator DID, and context listings against the resolved DID document.
    ///
    /// # Arguments
    ///
    /// * `well_known` -- The `.well-known/scp` document to verify.
    /// * `did_method` -- A [`DidMethod`] implementation for DID resolution.
    ///
    /// # Errors
    ///
    /// Returns [`WellKnownBootstrapError::ValidationFailed`] if privacy
    /// validation or DID cross-verification fails.
    pub async fn process_well_known<M: DidMethod>(
        &self,
        well_known: &WellKnownScp,
        did_method: &M,
    ) -> Result<(), WellKnownBootstrapError> {
        // Step 1: Privacy validation.
        well_known.validate()?;

        // Step 2: DHT cross-verification (§18.3.2). Called on every fetch.
        well_known.verify_against_did(did_method).await?;

        Ok(())
    }

    /// Attempts to resolve bootstrap context IDs, falling back to DID
    /// resolution if configured and no contexts are available.
    ///
    /// Resolution strategy:
    /// 1. Collect all configured bootstrap context IDs (defaults + custom).
    /// 2. If contexts are found, return them.
    /// 3. If no contexts are found and fallback is enabled, attempt DID
    ///    document capability resolution by returning an empty list with a
    ///    note that the caller should try direct DID resolution.
    /// 4. If no contexts are found and fallback is disabled, return an error.
    ///
    /// # Arguments
    ///
    /// * `did` -- The DID to fall back to for direct resolution. Used only
    ///   when no bootstrap contexts are available and fallback is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::DidResolutionFailed`] if no bootstrap
    /// contexts are configured and fallback is disabled.
    pub fn resolve_with_fallback(&self, did: &str) -> Result<Vec<ContextId>, DiscoveryError> {
        let contexts = self.resolve_contexts();

        if !contexts.is_empty() {
            return Ok(contexts);
        }

        // No contexts with discovery tools available -- check fallback policy.
        if self.config.should_fallback() {
            // Return an empty list to signal the caller should try direct DID
            // resolution for the given DID. The actual DID resolution is
            // performed by the caller using `did_capabilities::resolve_capabilities`.
            Ok(Vec::new())
        } else {
            Err(DiscoveryError::DidResolutionFailed(format!(
                "no bootstrap contexts configured and fallback disabled for DID: {did}"
            )))
        }
    }
}

/// Errors produced when processing `.well-known/scp` data during bootstrap.
#[derive(Debug, thiserror::Error)]
pub enum WellKnownBootstrapError {
    /// The `.well-known/scp` document failed privacy or DID verification.
    #[error("well-known validation failed: {0}")]
    ValidationFailed(#[from] WellKnownValidationError),

    /// A discovery error occurred during bootstrap processing.
    #[error("discovery error: {0}")]
    Discovery(#[from] DiscoveryError),
}

impl From<BootstrapConfig> for BootstrapResolver {
    fn from(config: BootstrapConfig) -> Self {
        Self::new(config)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;

    fn entry(id: &str, did: &str) -> BootstrapContextEntry {
        BootstrapContextEntry {
            context_id: id.to_owned(),
            expected_creator_did: did.to_owned(),
        }
    }

    // -- BootstrapConfig defaults -----------------------------------------

    #[test]
    fn default_config_has_auto_query_enabled() {
        let config = BootstrapConfig::default();
        assert!(config.should_auto_query());
    }

    #[test]
    fn default_config_has_fallback_enabled() {
        let config = BootstrapConfig::default();
        assert!(config.should_fallback());
    }

    #[test]
    fn default_config_has_empty_context_lists() {
        let config = BootstrapConfig::default();
        assert!(config.default_contexts.is_empty());
        assert!(config.custom_contexts.is_empty());
    }

    #[test]
    fn default_config_all_context_ids_returns_empty() {
        let config = BootstrapConfig::default();
        assert!(config.all_context_ids().is_empty());
    }

    // -- BootstrapConfig construction -------------------------------------

    #[test]
    fn with_defaults_sets_default_contexts() {
        let entries = vec![
            entry("ctx-discovery-1", "did:dht:z6MkOp1"),
            entry("ctx-discovery-2", "did:dht:z6MkOp2"),
        ];
        let config = BootstrapConfig::with_defaults(entries.clone());

        assert_eq!(config.default_contexts, entries);
        assert!(config.custom_contexts.is_empty());
        assert!(config.should_auto_query());
        assert!(config.should_fallback());
    }

    // -- Adding custom contexts -------------------------------------------

    #[test]
    fn add_custom_context_appends_to_custom_list() {
        let mut config = BootstrapConfig::default();
        config.add_custom_context(entry("ctx-custom-1", "did:dht:z6MkC1"));
        config.add_custom_context(entry("ctx-custom-2", "did:dht:z6MkC2"));

        assert_eq!(config.custom_contexts.len(), 2);
        assert_eq!(config.custom_contexts[0].context_id, "ctx-custom-1");
        assert_eq!(config.custom_contexts[1].context_id, "ctx-custom-2");
    }

    // -- all_context_ids combines defaults and custom ---------------------

    #[test]
    fn all_context_ids_combines_defaults_and_custom() {
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-default-1", "did:dht:z6MkOp")]);
        config.add_custom_context(entry("ctx-custom-1", "did:dht:z6MkC"));

        let all_ids = config.all_context_ids();
        assert_eq!(all_ids.len(), 2);
        assert_eq!(all_ids[0], "ctx-default-1");
        assert_eq!(all_ids[1], "ctx-custom-1");
    }

    #[test]
    fn all_context_ids_defaults_come_before_custom() {
        let mut config = BootstrapConfig::with_defaults(vec![
            entry("ctx-d1", "did:dht:z6Mk1"),
            entry("ctx-d2", "did:dht:z6Mk2"),
        ]);
        config.add_custom_context(entry("ctx-c1", "did:dht:z6MkC"));

        let all_ids = config.all_context_ids();
        assert_eq!(all_ids.len(), 3);
        assert_eq!(*all_ids[0], "ctx-d1");
        assert_eq!(*all_ids[1], "ctx-d2");
        assert_eq!(*all_ids[2], "ctx-c1");
    }

    // -- all_entries ------------------------------------------------------

    #[test]
    fn all_entries_returns_entries_with_creator_dids() {
        let mut config = BootstrapConfig::with_defaults(vec![entry("ctx-d1", "did:dht:z6MkOp1")]);
        config.add_custom_context(entry("ctx-c1", "did:dht:z6MkOp2"));

        let entries = config.all_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].expected_creator_did, "did:dht:z6MkOp1");
        assert_eq!(entries[1].expected_creator_did, "did:dht:z6MkOp2");
    }

    // -- Opt-out of auto-query --------------------------------------------

    #[test]
    fn opt_out_of_auto_query() {
        let mut config = BootstrapConfig::default();
        config.auto_query_on_identity_creation = false;

        assert!(!config.should_auto_query());
    }

    #[test]
    fn opt_out_of_fallback() {
        let mut config = BootstrapConfig::default();
        config.fallback_to_did_resolution = false;

        assert!(!config.should_fallback());
    }

    // -- Serialization roundtrip ------------------------------------------

    #[test]
    fn bootstrap_config_serialization_roundtrip() {
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-discovery-1", "did:dht:z6MkOp1")]);
        config.add_custom_context(entry("ctx-custom-1", "did:dht:z6MkOp2"));
        config.auto_query_on_identity_creation = false;

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: BootstrapConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    #[test]
    fn bootstrap_config_backward_compat_deserialization() {
        // Old format without default_contexts/custom_contexts should still
        // deserialize (serde(default) on both fields).
        let json = r#"{"auto_query_on_identity_creation":true,"fallback_to_did_resolution":true}"#;
        let config: BootstrapConfig = serde_json::from_str(json).unwrap();
        assert!(config.default_contexts.is_empty());
        assert!(config.custom_contexts.is_empty());
    }

    // -- BootstrapResolver ------------------------------------------------

    #[test]
    fn resolver_returns_all_context_ids() {
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-default-1", "did:dht:z6MkOp")]);
        config.add_custom_context(entry("ctx-custom-1", "did:dht:z6MkC"));

        let resolver = BootstrapResolver::new(config);
        let contexts = resolver.resolve_contexts();

        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0], "ctx-default-1");
        assert_eq!(contexts[1], "ctx-custom-1");
    }

    #[test]
    fn resolver_deduplicates_context_ids() {
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-shared", "did:dht:z6MkOp")]);
        config.add_custom_context(entry("ctx-shared", "did:dht:z6MkOp"));
        config.add_custom_context(entry("ctx-unique", "did:dht:z6MkC"));

        let resolver = BootstrapResolver::new(config);
        let contexts = resolver.resolve_contexts();

        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0], "ctx-shared");
        assert_eq!(contexts[1], "ctx-unique");
    }

    #[test]
    fn resolver_empty_config_returns_empty() {
        let resolver = BootstrapResolver::new(BootstrapConfig::default());
        let contexts = resolver.resolve_contexts();
        assert!(contexts.is_empty());
    }

    #[test]
    fn resolver_config_accessor_returns_config() {
        let config = BootstrapConfig::with_defaults(vec![entry("ctx-1", "did:dht:z6MkOp")]);
        let resolver = BootstrapResolver::new(config.clone());
        assert_eq!(resolver.config(), &config);
    }

    #[test]
    fn resolver_from_config() {
        let config = BootstrapConfig::with_defaults(vec![entry("ctx-1", "did:dht:z6MkOp")]);
        let resolver: BootstrapResolver = config.into();
        assert_eq!(resolver.resolve_contexts(), vec!["ctx-1"]);
    }

    // -- resolve_with_fallback --------------------------------------------

    #[test]
    fn resolve_with_fallback_returns_contexts_when_available() {
        let config =
            BootstrapConfig::with_defaults(vec![entry("ctx-discovery-1", "did:dht:z6MkOp")]);
        let resolver = BootstrapResolver::new(config);

        let result = resolver.resolve_with_fallback("did:dht:zTestDid").unwrap();
        assert_eq!(result, vec!["ctx-discovery-1"]);
    }

    #[test]
    fn resolve_with_fallback_returns_empty_when_no_contexts_and_fallback_enabled() {
        let config = BootstrapConfig::default();
        assert!(config.should_fallback());

        let resolver = BootstrapResolver::new(config);
        let result = resolver.resolve_with_fallback("did:dht:zTestDid").unwrap();

        // Empty list signals caller should try direct DID resolution.
        assert!(result.is_empty());
    }

    #[test]
    fn resolve_with_fallback_errors_when_no_contexts_and_fallback_disabled() {
        let mut config = BootstrapConfig::default();
        config.fallback_to_did_resolution = false;

        let resolver = BootstrapResolver::new(config);
        let err = resolver
            .resolve_with_fallback("did:dht:zTestDid")
            .unwrap_err();

        assert!(matches!(err, DiscoveryError::DidResolutionFailed(_)));
        assert!(err.to_string().contains("did:dht:zTestDid"));
    }
}
