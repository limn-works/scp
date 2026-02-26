//! Discovery bootstrap and fallback configuration.
//!
//! Provides configurable default discovery context IDs (analogous to DNS root
//! servers) and a resolver that combines discovery context queries with
//! fallback to direct DID resolution.
//!
//! The SDK ships with configurable defaults that are auto-queried on first
//! identity creation (opt-out). Users can add custom discovery contexts and
//! configure fallback behavior.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`, acceptance criterion 8.

use serde::{Deserialize, Serialize};

use crate::identity::DidMethod;
use crate::well_known::{WellKnownScp, WellKnownValidationError};

use super::{ContextId, DiscoveryError};

// ---------------------------------------------------------------------------
// BootstrapConfig
// ---------------------------------------------------------------------------

/// Configuration for discovery bootstrap behavior.
///
/// Controls which discovery contexts the SDK queries on startup, whether
/// auto-query fires on first identity creation, and whether to fall back to
/// direct DID resolution when discovery contexts are unavailable.
///
/// Analogous to DNS root servers: the SDK ships with configurable default
/// discovery context IDs. Users can add custom discovery contexts. If
/// defaults are unreachable, direct DID resolution still works.
///
/// See ADR-020 acceptance criterion 8.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// Default discovery context IDs shipped with the SDK.
    ///
    /// These are queried automatically on first identity creation unless
    /// `auto_query_on_identity_creation` is set to `false`.
    pub default_context_ids: Vec<ContextId>,

    /// Whether to automatically query discovery contexts on first identity
    /// creation.
    ///
    /// Defaults to `true`. Set to `false` to opt out of automatic discovery
    /// queries.
    pub auto_query_on_identity_creation: bool,

    /// User-added custom discovery context IDs.
    ///
    /// These are queried alongside the defaults. Users can add contexts via
    /// [`BootstrapConfig::add_custom_context`].
    pub custom_context_ids: Vec<ContextId>,

    /// Whether to fall back to direct DID resolution when discovery contexts
    /// are unavailable or return no results.
    ///
    /// Defaults to `true`. When enabled, the resolver attempts DID document
    /// capability resolution as a last resort.
    pub fallback_to_did_resolution: bool,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            default_context_ids: Vec::new(),
            auto_query_on_identity_creation: true,
            custom_context_ids: Vec::new(),
            fallback_to_did_resolution: true,
        }
    }
}

impl BootstrapConfig {
    /// Creates a new `BootstrapConfig` with the given default discovery
    /// context IDs.
    ///
    /// All other fields are set to their defaults: auto-query enabled,
    /// fallback enabled, no custom contexts.
    ///
    /// # Arguments
    ///
    /// * `context_ids` -- Default discovery context IDs to query on bootstrap.
    #[must_use]
    pub fn with_defaults(context_ids: Vec<ContextId>) -> Self {
        Self {
            default_context_ids: context_ids,
            ..Self::default()
        }
    }

    /// Adds a custom discovery context ID.
    ///
    /// Custom contexts are queried alongside the defaults. Duplicate context
    /// IDs are not filtered here -- deduplication happens at query time in
    /// [`BootstrapResolver::resolve_contexts`].
    pub fn add_custom_context(&mut self, context_id: ContextId) {
        self.custom_context_ids.push(context_id);
    }

    /// Returns all context IDs (defaults + custom) as a combined list.
    ///
    /// The returned list contains references to the default context IDs
    /// followed by the custom context IDs.
    #[must_use]
    pub fn all_context_ids(&self) -> Vec<&ContextId> {
        self.default_context_ids
            .iter()
            .chain(self.custom_context_ids.iter())
            .collect()
    }

    /// Returns whether the SDK should auto-query discovery contexts on first
    /// identity creation.
    #[must_use]
    pub const fn should_auto_query(&self) -> bool {
        self.auto_query_on_identity_creation
    }

    /// Returns whether the resolver should fall back to direct DID resolution
    /// when discovery contexts are unavailable.
    #[must_use]
    pub const fn should_fallback(&self) -> bool {
        self.fallback_to_did_resolution
    }
}

// ---------------------------------------------------------------------------
// BootstrapResolver
// ---------------------------------------------------------------------------

/// Resolves discovery contexts and provides fallback to DID resolution.
///
/// Holds a [`BootstrapConfig`] and provides methods to retrieve all available
/// discovery context IDs and to attempt resolution with fallback behavior.
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

    /// Returns all available discovery context IDs (defaults + custom),
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

    /// Attempts to resolve discovery context IDs, falling back to DID
    /// resolution if configured and no contexts are available.
    ///
    /// Resolution strategy:
    /// 1. Collect all configured discovery context IDs (defaults + custom).
    /// 2. If contexts are found, return them.
    /// 3. If no contexts are found and fallback is enabled, attempt DID
    ///    document capability resolution by returning an empty list with a
    ///    note that the caller should try direct DID resolution.
    /// 4. If no contexts are found and fallback is disabled, return an error.
    ///
    /// # Arguments
    ///
    /// * `did` -- The DID to fall back to for direct resolution. Used only
    ///   when no discovery contexts are available and fallback is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::DidResolutionFailed`] if no discovery
    /// contexts are configured and fallback is disabled.
    pub fn resolve_with_fallback(&self, did: &str) -> Result<Vec<ContextId>, DiscoveryError> {
        let contexts = self.resolve_contexts();

        if !contexts.is_empty() {
            return Ok(contexts);
        }

        // No discovery contexts available -- check fallback policy.
        if self.config.should_fallback() {
            // Return an empty list to signal the caller should try direct DID
            // resolution for the given DID. The actual DID resolution is
            // performed by the caller using `did_capabilities::resolve_capabilities`.
            Ok(Vec::new())
        } else {
            Err(DiscoveryError::DidResolutionFailed(format!(
                "no discovery contexts configured and fallback disabled for DID: {did}"
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
        assert!(config.default_context_ids.is_empty());
        assert!(config.custom_context_ids.is_empty());
    }

    #[test]
    fn default_config_all_context_ids_returns_empty() {
        let config = BootstrapConfig::default();
        assert!(config.all_context_ids().is_empty());
    }

    // -- BootstrapConfig construction -------------------------------------

    #[test]
    fn with_defaults_sets_default_context_ids() {
        let ids = vec!["ctx-discovery-1".to_owned(), "ctx-discovery-2".to_owned()];
        let config = BootstrapConfig::with_defaults(ids.clone());

        assert_eq!(config.default_context_ids, ids);
        assert!(config.custom_context_ids.is_empty());
        assert!(config.should_auto_query());
        assert!(config.should_fallback());
    }

    // -- Adding custom contexts -------------------------------------------

    #[test]
    fn add_custom_context_appends_to_custom_list() {
        let mut config = BootstrapConfig::default();
        config.add_custom_context("ctx-custom-1".to_owned());
        config.add_custom_context("ctx-custom-2".to_owned());

        assert_eq!(config.custom_context_ids.len(), 2);
        assert_eq!(config.custom_context_ids[0], "ctx-custom-1");
        assert_eq!(config.custom_context_ids[1], "ctx-custom-2");
    }

    // -- all_context_ids combines defaults and custom ---------------------

    #[test]
    fn all_context_ids_combines_defaults_and_custom() {
        let mut config = BootstrapConfig::with_defaults(vec!["ctx-default-1".to_owned()]);
        config.add_custom_context("ctx-custom-1".to_owned());

        let all_ids = config.all_context_ids();
        assert_eq!(all_ids.len(), 2);
        assert_eq!(all_ids[0], "ctx-default-1");
        assert_eq!(all_ids[1], "ctx-custom-1");
    }

    #[test]
    fn all_context_ids_defaults_come_before_custom() {
        let mut config =
            BootstrapConfig::with_defaults(vec!["ctx-d1".to_owned(), "ctx-d2".to_owned()]);
        config.add_custom_context("ctx-c1".to_owned());

        let all_ids = config.all_context_ids();
        assert_eq!(all_ids.len(), 3);
        assert_eq!(*all_ids[0], "ctx-d1");
        assert_eq!(*all_ids[1], "ctx-d2");
        assert_eq!(*all_ids[2], "ctx-c1");
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
        let mut config = BootstrapConfig::with_defaults(vec!["ctx-discovery-1".to_owned()]);
        config.add_custom_context("ctx-custom-1".to_owned());
        config.auto_query_on_identity_creation = false;

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: BootstrapConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    // -- BootstrapResolver ------------------------------------------------

    #[test]
    fn resolver_returns_all_context_ids() {
        let mut config = BootstrapConfig::with_defaults(vec!["ctx-default-1".to_owned()]);
        config.add_custom_context("ctx-custom-1".to_owned());

        let resolver = BootstrapResolver::new(config);
        let contexts = resolver.resolve_contexts();

        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0], "ctx-default-1");
        assert_eq!(contexts[1], "ctx-custom-1");
    }

    #[test]
    fn resolver_deduplicates_context_ids() {
        let mut config = BootstrapConfig::with_defaults(vec!["ctx-shared".to_owned()]);
        config.add_custom_context("ctx-shared".to_owned());
        config.add_custom_context("ctx-unique".to_owned());

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
        let config = BootstrapConfig::with_defaults(vec!["ctx-1".to_owned()]);
        let resolver = BootstrapResolver::new(config.clone());
        assert_eq!(resolver.config(), &config);
    }

    #[test]
    fn resolver_from_config() {
        let config = BootstrapConfig::with_defaults(vec!["ctx-1".to_owned()]);
        let resolver: BootstrapResolver = config.into();
        assert_eq!(resolver.resolve_contexts(), vec!["ctx-1"]);
    }

    // -- resolve_with_fallback --------------------------------------------

    #[test]
    fn resolve_with_fallback_returns_contexts_when_available() {
        let config = BootstrapConfig::with_defaults(vec!["ctx-discovery-1".to_owned()]);
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
