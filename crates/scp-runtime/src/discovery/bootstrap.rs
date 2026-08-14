//! Discovery bootstrap and fallback configuration.
//!
//! Provides configurable default bootstrap context entries (analogous to DNS root
//! servers) and a resolver that combines context queries with
//! fallback to direct DID resolution.
//!
//! Each bootstrap context entry pairs a context ID with the expected creator DID,
//! enabling post-join verification that defends against context ID substitution
//! attacks (§22.13.2).
//!
//! The SDK ships with configurable defaults that are auto-queried on first
//! identity creation (opt-out). Users can add custom contexts with discovery outlets and
//! configure fallback behavior.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`, acceptance criterion 8.
//! See §22.13 for bootstrap context governance.

use scp_did::DID;
use serde::{Deserialize, Serialize};

use crate::well_known::{WellKnownScp, WellKnownValidationError};
use scp_identity::DidMethod;

use scp_protocol::discovery::{ContextId, DiscoveryError};

// ---------------------------------------------------------------------------
// BootstrapContextEntry
// ---------------------------------------------------------------------------

/// A bootstrap context with expected creator DID for post-join verification.
///
/// Pairs a `context_id` with an `expected_creator_did`. After the SDK joins a
/// bootstrap context via MLS group join, it MUST verify that the context's
/// creator DID matches the `expected_creator_did`. The creator DID is available
/// from the context's event log (the first event in any context is the creation
/// event, signed by the creator's DID). If the creator DID does not match, the
/// SDK MUST leave the context and treat the entry as failed — the context may
/// have been substituted by an attacker.
///
/// See §22.13.2 for the full verification protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapContextEntry {
    /// The bootstrap context's ID (hex-encoded).
    pub context_id: ContextId,
    /// The DID of the expected context creator. SDK MUST verify this matches the
    /// actual context creator after joining (§22.13.2).
    pub expected_creator_did: DID,
}

impl BootstrapContextEntry {
    /// Creates a new `BootstrapContextEntry`.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The bootstrap context's ID.
    /// * `expected_creator_did` -- The DID of the expected context creator.
    #[must_use]
    pub const fn new(context_id: ContextId, expected_creator_did: DID) -> Self {
        Self {
            context_id,
            expected_creator_did,
        }
    }
}

// ---------------------------------------------------------------------------
// BootstrapVerificationError
// ---------------------------------------------------------------------------

/// Errors produced when verifying a bootstrap context's creator DID.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapVerificationError {
    /// The actual creator DID does not match the expected creator DID from
    /// the bootstrap configuration.
    ///
    /// This indicates a potential context ID substitution attack (§22.13.2).
    /// The SDK MUST leave the context when this error is returned.
    #[error(
        "bootstrap context creator mismatch for {context_id}: expected {expected}, got {actual}"
    )]
    CreatorMismatch {
        /// The context ID that was verified.
        context_id: ContextId,
        /// The expected creator DID from the bootstrap configuration.
        expected: DID,
        /// The actual creator DID from the context's event log.
        actual: DID,
    },

    /// The custom contexts list has reached its maximum capacity.
    ///
    /// Prevents unbounded growth of the custom contexts list. The limit is
    /// [`MAX_CUSTOM_CONTEXTS`].
    #[error("custom contexts list has reached maximum capacity ({MAX_CUSTOM_CONTEXTS})")]
    TooManyCustomContexts,

    /// The default contexts list exceeds the maximum allowed size.
    ///
    /// Prevents unbounded growth of the default contexts list. The limit is
    /// [`MAX_DEFAULT_CONTEXTS`].
    #[error("default contexts list length {count} exceeds maximum of {MAX_DEFAULT_CONTEXTS}")]
    TooManyDefaultContexts {
        /// The number of entries that were provided.
        count: usize,
    },
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of default bootstrap context entries allowed in a [`BootstrapConfig`].
///
/// Prevents unbounded growth of the default contexts list. Callers passing
/// more entries to [`BootstrapConfig::with_defaults`] will receive a
/// [`BootstrapVerificationError::TooManyDefaultContexts`] error.
pub const MAX_DEFAULT_CONTEXTS: usize = 100;

/// Maximum number of custom context entries allowed in a [`BootstrapConfig`].
///
/// Prevents unbounded growth of the custom contexts list. Contexts beyond
/// this limit are rejected with [`BootstrapVerificationError::TooManyCustomContexts`].
pub const MAX_CUSTOM_CONTEXTS: usize = 100;

// ---------------------------------------------------------------------------
// BootstrapConfig
// ---------------------------------------------------------------------------

/// Configuration for discovery bootstrap behavior.
///
/// Controls which contexts with discovery outlets the SDK queries on startup, whether
/// auto-query fires on first identity creation, and whether to fall back to
/// direct DID resolution when contexts with discovery outlets are unavailable.
///
/// Analogous to DNS root servers: the SDK ships with configurable default
/// bootstrap context entries. Users can add custom contexts with discovery outlets.
/// If defaults are unreachable, direct DID resolution still works.
///
/// Each context entry includes the expected creator DID for post-join
/// verification (§22.13.2).
///
/// See ADR-020 acceptance criterion 8, §22.13.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// Default bootstrap context entries shipped with the SDK.
    ///
    /// These are queried automatically on first identity creation unless
    /// `auto_query_on_identity_creation` is set to `false`.
    #[serde(default)]
    pub default_contexts: Vec<BootstrapContextEntry>,

    /// Whether to automatically query contexts with discovery outlets on first identity
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

    /// Whether to fall back to direct DID resolution when contexts with discovery outlets
    /// are unavailable or return no results.
    ///
    /// Defaults to `true`. When enabled, the resolver attempts DID document
    /// capability resolution as a last resort.
    pub fallback_to_did_resolution: bool,
}

/// Raw deserialization target for [`BootstrapConfig`] that validates Vec lengths
/// on deserialization. Rejects payloads where `default_contexts` exceeds
/// [`MAX_DEFAULT_CONTEXTS`] or `custom_contexts` exceeds [`MAX_CUSTOM_CONTEXTS`].
#[derive(Deserialize)]
struct BootstrapConfigRaw {
    #[serde(default)]
    default_contexts: Vec<BootstrapContextEntry>,
    #[serde(default = "default_true")]
    auto_query_on_identity_creation: bool,
    #[serde(default)]
    custom_contexts: Vec<BootstrapContextEntry>,
    #[serde(default = "default_true")]
    fallback_to_did_resolution: bool,
}

const fn default_true() -> bool {
    true
}

impl<'de> Deserialize<'de> for BootstrapConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = BootstrapConfigRaw::deserialize(deserializer)?;
        if raw.default_contexts.len() > MAX_DEFAULT_CONTEXTS {
            return Err(serde::de::Error::custom(format!(
                "default_contexts length {} exceeds maximum of {MAX_DEFAULT_CONTEXTS}",
                raw.default_contexts.len()
            )));
        }
        if raw.custom_contexts.len() > MAX_CUSTOM_CONTEXTS {
            return Err(serde::de::Error::custom(format!(
                "custom_contexts length {} exceeds maximum of {MAX_CUSTOM_CONTEXTS}",
                raw.custom_contexts.len()
            )));
        }
        Ok(Self {
            default_contexts: raw.default_contexts,
            auto_query_on_identity_creation: raw.auto_query_on_identity_creation,
            custom_contexts: raw.custom_contexts,
            fallback_to_did_resolution: raw.fallback_to_did_resolution,
        })
    }
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
    /// Creates a new `BootstrapConfig` with the given default bootstrap context
    /// entries.
    ///
    /// All other fields are set to their defaults: auto-query enabled,
    /// fallback enabled, no custom contexts.
    ///
    /// # Arguments
    ///
    /// * `contexts` -- Default bootstrap context entries to query on bootstrap.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapVerificationError::TooManyDefaultContexts`] if
    /// `contexts.len()` exceeds [`MAX_DEFAULT_CONTEXTS`].
    pub fn with_defaults(
        contexts: Vec<BootstrapContextEntry>,
    ) -> Result<Self, BootstrapVerificationError> {
        if contexts.len() > MAX_DEFAULT_CONTEXTS {
            return Err(BootstrapVerificationError::TooManyDefaultContexts {
                count: contexts.len(),
            });
        }
        Ok(Self {
            default_contexts: contexts,
            ..Self::default()
        })
    }

    /// Adds a custom context entry.
    ///
    /// Custom contexts are queried alongside the defaults. Duplicate context
    /// IDs are not filtered here -- deduplication happens at query time in
    /// [`BootstrapResolver::resolve_contexts`].
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapVerificationError::TooManyCustomContexts`] if the
    /// custom contexts list has reached [`MAX_CUSTOM_CONTEXTS`].
    pub fn add_custom_context(
        &mut self,
        entry: BootstrapContextEntry,
    ) -> Result<(), BootstrapVerificationError> {
        if self.custom_contexts.len() >= MAX_CUSTOM_CONTEXTS {
            return Err(BootstrapVerificationError::TooManyCustomContexts);
        }
        self.custom_contexts.push(entry);
        Ok(())
    }

    /// Returns all context entries (defaults + custom) as a combined list.
    ///
    /// The returned list contains references to the default context entries
    /// followed by the custom context entries.
    #[must_use]
    pub fn all_contexts(&self) -> Vec<&BootstrapContextEntry> {
        self.default_contexts
            .iter()
            .chain(self.custom_contexts.iter())
            .collect()
    }

    /// Verifies that a context's actual creator DID matches the expected
    /// creator DID in the bootstrap configuration.
    ///
    /// This implements the post-join verification step from §22.13.2. After
    /// joining a bootstrap context, the SDK calls this method with the context
    /// ID and the creator DID extracted from the context's event log.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the context was found in the configuration and the
    ///   creator DID matches.
    /// - `Ok(false)` if the context is not in the bootstrap configuration
    ///   (not a bootstrap context, no verification needed).
    /// - `Err(CreatorMismatch)` if the context was found but the actual
    ///   creator DID does not match the expected one. The SDK MUST leave the
    ///   context in this case.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapVerificationError::CreatorMismatch`] when the context
    /// is found in the configuration but the creator DID does not match.
    pub fn verify_context_creator(
        &self,
        context_id: &ContextId,
        actual_creator_did: &DID,
    ) -> Result<bool, BootstrapVerificationError> {
        // Check custom_contexts first so user overrides take precedence
        // over stale default entries.
        let entry = self
            .custom_contexts
            .iter()
            .chain(self.default_contexts.iter())
            .find(|e| e.context_id == *context_id);

        entry.map_or(Ok(false), |e| {
            if e.expected_creator_did == *actual_creator_did {
                Ok(true)
            } else {
                Err(BootstrapVerificationError::CreatorMismatch {
                    context_id: context_id.clone(),
                    expected: e.expected_creator_did.clone(),
                    actual: actual_creator_did.clone(),
                })
            }
        })
    }

    /// Returns whether the SDK should auto-query contexts with discovery outlets on first
    /// identity creation.
    #[must_use]
    pub const fn should_auto_query(&self) -> bool {
        self.auto_query_on_identity_creation
    }

    /// Returns whether the resolver should fall back to direct DID resolution
    /// when contexts with discovery outlets are unavailable.
    #[must_use]
    pub const fn should_fallback(&self) -> bool {
        self.fallback_to_did_resolution
    }
}

// ---------------------------------------------------------------------------
// BootstrapResolver
// ---------------------------------------------------------------------------

/// Resolves contexts with discovery outlets and provides fallback to DID resolution.
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
    ///
    /// Extracts context IDs from [`BootstrapContextEntry`] entries.
    #[must_use]
    pub fn resolve_contexts(&self) -> Vec<ContextId> {
        let mut seen = std::collections::HashSet::new();
        self.config
            .all_contexts()
            .into_iter()
            .map(|entry| &entry.context_id)
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

        // No contexts with discovery outlets available -- check fallback policy.
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

    // -- Helper: create a BootstrapContextEntry ----------------------------

    fn entry(ctx_id: &str, creator: &str) -> BootstrapContextEntry {
        BootstrapContextEntry::new(ctx_id.to_owned(), DID::from(creator))
    }

    // -- BootstrapContextEntry --------------------------------------------

    #[test]
    fn bootstrap_context_entry_construction() {
        let e = BootstrapContextEntry::new(
            "ctx-discovery-1".to_owned(),
            DID::from("did:dht:zCreator1"),
        );
        assert_eq!(e.context_id, "ctx-discovery-1");
        assert_eq!(e.expected_creator_did, "did:dht:zCreator1");
    }

    #[test]
    fn bootstrap_context_entry_serde_roundtrip() {
        let e = entry("ctx-discovery-1", "did:dht:zCreator1");
        let json = serde_json::to_string(&e).unwrap();
        let deserialized: BootstrapContextEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, deserialized);
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
    fn default_config_all_contexts_returns_empty() {
        let config = BootstrapConfig::default();
        assert!(config.all_contexts().is_empty());
    }

    // -- BootstrapConfig construction -------------------------------------

    #[test]
    fn with_defaults_sets_default_contexts() {
        let entries = vec![
            entry("ctx-discovery-1", "did:dht:zCreator1"),
            entry("ctx-discovery-2", "did:dht:zCreator2"),
        ];
        let config = BootstrapConfig::with_defaults(entries.clone()).unwrap();

        assert_eq!(config.default_contexts, entries);
        assert!(config.custom_contexts.is_empty());
        assert!(config.should_auto_query());
        assert!(config.should_fallback());
    }

    // -- Adding custom contexts -------------------------------------------

    #[test]
    fn add_custom_context_appends_to_custom_list() {
        let mut config = BootstrapConfig::default();
        config
            .add_custom_context(entry("ctx-custom-1", "did:dht:zCustom1"))
            .unwrap();
        config
            .add_custom_context(entry("ctx-custom-2", "did:dht:zCustom2"))
            .unwrap();

        assert_eq!(config.custom_contexts.len(), 2);
        assert_eq!(config.custom_contexts[0].context_id, "ctx-custom-1");
        assert_eq!(config.custom_contexts[1].context_id, "ctx-custom-2");
    }

    // -- all_contexts combines defaults and custom ------------------------

    #[test]
    fn all_contexts_combines_defaults_and_custom() {
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-default-1", "did:dht:zD1")]).unwrap();
        config
            .add_custom_context(entry("ctx-custom-1", "did:dht:zC1"))
            .unwrap();

        let all = config.all_contexts();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].context_id, "ctx-default-1");
        assert_eq!(all[1].context_id, "ctx-custom-1");
    }

    #[test]
    fn all_contexts_defaults_come_before_custom() {
        let mut config = BootstrapConfig::with_defaults(vec![
            entry("ctx-d1", "did:dht:zD1"),
            entry("ctx-d2", "did:dht:zD2"),
        ])
        .unwrap();
        config
            .add_custom_context(entry("ctx-c1", "did:dht:zC1"))
            .unwrap();

        let all = config.all_contexts();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].context_id, "ctx-d1");
        assert_eq!(all[1].context_id, "ctx-d2");
        assert_eq!(all[2].context_id, "ctx-c1");
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
            BootstrapConfig::with_defaults(vec![entry("ctx-discovery-1", "did:dht:zCreator1")])
                .unwrap();
        config
            .add_custom_context(entry("ctx-custom-1", "did:dht:zCustom1"))
            .unwrap();
        config.auto_query_on_identity_creation = false;

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: BootstrapConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    // -- verify_context_creator -------------------------------------------

    #[test]
    fn verify_context_creator_success() {
        let config =
            BootstrapConfig::with_defaults(vec![entry("ctx-discovery-1", "did:dht:zCreator1")])
                .unwrap();

        let result = config
            .verify_context_creator(
                &"ctx-discovery-1".to_owned(),
                &DID::from("did:dht:zCreator1"),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn verify_context_creator_not_found() {
        let config =
            BootstrapConfig::with_defaults(vec![entry("ctx-discovery-1", "did:dht:zCreator1")])
                .unwrap();

        let result = config
            .verify_context_creator(&"ctx-unknown".to_owned(), &DID::from("did:dht:zCreator1"))
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_context_creator_mismatch() {
        let config =
            BootstrapConfig::with_defaults(vec![entry("ctx-discovery-1", "did:dht:zCreator1")])
                .unwrap();

        let err = config
            .verify_context_creator(
                &"ctx-discovery-1".to_owned(),
                &DID::from("did:dht:zAttacker"),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            BootstrapVerificationError::CreatorMismatch { .. }
        ));
        let msg = err.to_string();
        assert!(msg.contains("ctx-discovery-1"));
        assert!(msg.contains("did:dht:zCreator1"));
        assert!(msg.contains("did:dht:zAttacker"));
    }

    #[test]
    fn verify_context_creator_checks_custom_contexts() {
        let mut config = BootstrapConfig::default();
        config
            .add_custom_context(entry("ctx-custom-1", "did:dht:zCustomCreator"))
            .unwrap();

        let result = config
            .verify_context_creator(
                &"ctx-custom-1".to_owned(),
                &DID::from("did:dht:zCustomCreator"),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn verify_context_creator_custom_overrides_default() {
        // When the same context_id exists in both default and custom lists,
        // the custom entry's expected_creator_did should win.
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-shared", "did:dht:zDefaultCreator")])
                .unwrap();
        config
            .add_custom_context(entry("ctx-shared", "did:dht:zCustomCreator"))
            .unwrap();

        // The custom creator DID should verify successfully.
        let result = config
            .verify_context_creator(
                &"ctx-shared".to_owned(),
                &DID::from("did:dht:zCustomCreator"),
            )
            .unwrap();
        assert!(result);

        // The default creator DID should now fail (custom overrides it).
        let err = config
            .verify_context_creator(
                &"ctx-shared".to_owned(),
                &DID::from("did:dht:zDefaultCreator"),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            BootstrapVerificationError::CreatorMismatch { .. }
        ));
    }

    // -- BootstrapResolver ------------------------------------------------

    #[test]
    fn resolver_returns_all_context_ids() {
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-default-1", "did:dht:zD1")]).unwrap();
        config
            .add_custom_context(entry("ctx-custom-1", "did:dht:zC1"))
            .unwrap();

        let resolver = BootstrapResolver::new(config);
        let contexts = resolver.resolve_contexts();

        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0], "ctx-default-1");
        assert_eq!(contexts[1], "ctx-custom-1");
    }

    #[test]
    fn resolver_deduplicates_context_ids() {
        let mut config =
            BootstrapConfig::with_defaults(vec![entry("ctx-shared", "did:dht:zCreator")]).unwrap();
        config
            .add_custom_context(entry("ctx-shared", "did:dht:zCreator"))
            .unwrap();
        config
            .add_custom_context(entry("ctx-unique", "did:dht:zOther"))
            .unwrap();

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
        let config = BootstrapConfig::with_defaults(vec![entry("ctx-1", "did:dht:zC1")]).unwrap();
        let resolver = BootstrapResolver::new(config.clone());
        assert_eq!(resolver.config(), &config);
    }

    #[test]
    fn resolver_from_config() {
        let config = BootstrapConfig::with_defaults(vec![entry("ctx-1", "did:dht:zC1")]).unwrap();
        let resolver: BootstrapResolver = config.into();
        assert_eq!(resolver.resolve_contexts(), vec!["ctx-1"]);
    }

    // -- resolve_with_fallback --------------------------------------------

    #[test]
    fn resolve_with_fallback_returns_contexts_when_available() {
        let config =
            BootstrapConfig::with_defaults(vec![entry("ctx-discovery-1", "did:dht:zCreator1")])
                .unwrap();
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

    // -- with_defaults capacity limit -------------------------------------

    #[test]
    fn with_defaults_accepts_max_default_contexts() {
        let entries: Vec<_> = (0..MAX_DEFAULT_CONTEXTS)
            .map(|i| entry(&format!("ctx-{i}"), &format!("did:dht:zCreator{i}")))
            .collect();
        let config = BootstrapConfig::with_defaults(entries).unwrap();
        assert_eq!(config.default_contexts.len(), MAX_DEFAULT_CONTEXTS);
    }

    #[test]
    fn with_defaults_rejects_over_max_default_contexts() {
        let entries: Vec<_> = (0..=MAX_DEFAULT_CONTEXTS)
            .map(|i| entry(&format!("ctx-{i}"), &format!("did:dht:zCreator{i}")))
            .collect();
        let err = BootstrapConfig::with_defaults(entries).unwrap_err();
        assert!(
            matches!(
                err,
                BootstrapVerificationError::TooManyDefaultContexts { .. }
            ),
            "expected TooManyDefaultContexts, got: {err:?}"
        );
    }

    // -- add_custom_context capacity limit --------------------------------

    #[test]
    fn add_custom_context_rejects_at_capacity() {
        let mut config = BootstrapConfig::default();
        for i in 0..MAX_CUSTOM_CONTEXTS {
            config
                .add_custom_context(entry(&format!("ctx-{i}"), &format!("did:dht:zCreator{i}")))
                .unwrap();
        }
        assert_eq!(config.custom_contexts.len(), MAX_CUSTOM_CONTEXTS);

        // The next add must fail.
        let err = config
            .add_custom_context(entry("ctx-overflow", "did:dht:zOverflow"))
            .unwrap_err();
        assert!(
            matches!(err, BootstrapVerificationError::TooManyCustomContexts),
            "expected TooManyCustomContexts, got: {err:?}"
        );
        // Ensure the list did not grow.
        assert_eq!(config.custom_contexts.len(), MAX_CUSTOM_CONTEXTS);
    }
}
