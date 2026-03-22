//! Human-readable addressing types and unified resolution protocol.
//!
//! Implements §22 of the SCP specification: address format types, trust levels,
//! resolution paths, and the `AddressResolver` for multi-path resolution.
//!
//! Address format: `<local-part>@<scope>` with scope disambiguation by syntactic
//! inspection. Four addressing mechanisms are supported:
//!
//! - **Petnames** -- local, private, instant resolution (§22.4).
//! - **Context handles** -- SCP-native, DNS-free, community-governed (§22.3).
//! - **Attestation-backed handles** -- external identity bridge via reverse-lookup (§22.5).
//! - **Domain handles** -- optional web on-ramp via `.well-known/scp` (§22.6).
//!
//! See SCP-223 for the implementation story.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use scp_identity::DID;
use scp_primitives::Clock;

use super::ContextId;

// Import pure types from scp-protocol.
pub use scp_protocol::discovery::addressing::{
    AddressResolution, AddressingError, HandleTarget, MAX_LOCAL_PART_LENGTH, PetnameStore,
    ResolutionLayer, ResolutionPath, TrustLevel,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of the local-part of an address.

/// Default TTL for domain handle cache entries (1 hour per §22.8.4).
pub const DOMAIN_HANDLE_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Default TTL for context handle cache entries (15 minutes per §22.8.4).
pub const DISCOVERY_HANDLE_CACHE_TTL: Duration = Duration::from_secs(900);

/// TTL for petname cache entries (effectively indefinite: 1 year per §22.8.4).
/// Petnames are user-managed, so the cache is essentially permanent until the
/// user changes the petname.
pub const PETNAME_CACHE_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

/// Default TTL for attestation handle cache entries (1 day, matching renewal intervals per §22.8.4).
pub const ATTESTATION_HANDLE_CACHE_TTL: Duration = Duration::from_secs(86400);

// ---------------------------------------------------------------------------
// AddressType (§22.2)
// ---------------------------------------------------------------------------

/// The type of entity an address resolves to.
///
/// A single address (e.g., `recipes@cooking-community`) may resolve to an
/// identity, a context, or both. Resolution determines the type; the
/// `local-part` does not encode it.
///
/// See §22.2.1 Address Types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressType {
    /// The address resolves to a DID.
    Identity,
    /// The address resolves to a context ID with relay URLs.
    Context,
}

// HandleTarget, TrustLevel, ResolutionPath, ResolutionLayer, AddressResolution,
// AddressingError, PetnameStore — imported from scp_protocol::discovery::addressing.

// ---------------------------------------------------------------------------
// ParsedAddress (§22.2)
// ---------------------------------------------------------------------------

/// A parsed human-readable address with identified scope type.
///
/// Produced by `parse_address`. The scope kind determines which resolution
/// path to use.
///
/// See §22.2 Address Format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAddress {
    /// Scoped address with no `.` in scope -- context handle.
    /// Example: `alice@cooking-community`
    DiscoveryHandle {
        /// The local-part (handle name).
        local_part: String,
        /// The context scope name.
        scope: String,
    },
    /// Scoped address with `.` in scope -- domain handle (with attestation fallback).
    /// Example: `alice@example.com`
    DomainHandle {
        /// The local-part (handle name).
        local_part: String,
        /// The domain name.
        domain: String,
    },
    /// Leading `@` with no `@` separator -- attestation-backed handle.
    /// Example: `@alice_cooks` or `@alice_cooks:x`
    AttestationHandle {
        /// The platform handle (without leading `@`).
        handle: String,
        /// Platform qualifier, if present (e.g., `x`, `github`).
        platform: Option<String>,
    },
    /// Bare name with no scope -- unscoped, searches all layers.
    /// Example: `alice`
    Unscoped {
        /// The bare name.
        name: String,
    },
}

// ---------------------------------------------------------------------------
// AddressingError
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Address parsing (§22.2)
// ---------------------------------------------------------------------------

/// Validates the local-part of an address per §22.2 rules.
///
/// Rules:
/// - Lowercase ASCII letters, digits, hyphens, underscores, and periods only.
/// - Maximum 64 characters.
/// - No leading or trailing hyphens or periods.
/// - No consecutive periods.
fn validate_local_part(local_part: &str) -> Result<(), AddressingError> {
    if local_part.is_empty() {
        return Err(AddressingError::EmptyAddress);
    }
    if local_part.len() > MAX_LOCAL_PART_LENGTH {
        return Err(AddressingError::LocalPartTooLong);
    }
    if !local_part
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
    {
        return Err(AddressingError::InvalidLocalPartCharacters);
    }
    if local_part.starts_with('-')
        || local_part.ends_with('-')
        || local_part.starts_with('.')
        || local_part.ends_with('.')
    {
        return Err(AddressingError::InvalidLocalPartBoundary);
    }
    if local_part.contains("..") {
        return Err(AddressingError::ConsecutivePeriods);
    }
    Ok(())
}

/// Normalizes an address string per §22.2.2.
///
/// 1. Strips leading/trailing whitespace.
/// 2. Lowercases the entire string.
/// 3. Applies Unicode NFC normalization (approximated via lowercasing for ASCII).
#[must_use]
pub fn normalize_address(address: &str) -> String {
    address.trim().to_lowercase()
}

/// Parses a human-readable address string into a [`ParsedAddress`].
///
/// Applies normalization, validates the local-part, and determines the
/// resolution path based on scope disambiguation rules per §22.2.
///
/// # Errors
///
/// Returns [`AddressingError`] if the address is malformed (empty, invalid
/// characters, too long, etc.).
pub fn parse_address(address: &str) -> Result<ParsedAddress, AddressingError> {
    let normalized = normalize_address(address);
    if normalized.is_empty() {
        return Err(AddressingError::EmptyAddress);
    }

    // Attestation-backed handle: starts with `@`, no `@` separator after.
    if let Some(rest) = normalized.strip_prefix('@') {
        if rest.is_empty() {
            return Err(AddressingError::EmptyAddress);
        }
        // Check for platform qualifier: `@handle:platform`
        if let Some(colon_pos) = rest.find(':') {
            let handle = rest[..colon_pos].to_owned();
            let platform = rest[colon_pos + 1..].to_owned();
            if handle.is_empty() || platform.is_empty() {
                return Err(AddressingError::EmptyAddress);
            }
            return Ok(ParsedAddress::AttestationHandle {
                handle,
                platform: Some(platform),
            });
        }
        return Ok(ParsedAddress::AttestationHandle {
            handle: rest.to_owned(),
            platform: None,
        });
    }

    // Scoped address: contains `@`
    if let Some(at_pos) = normalized.find('@') {
        let local_part = &normalized[..at_pos];
        let scope = &normalized[at_pos + 1..];
        if scope.is_empty() {
            return Err(AddressingError::EmptyAddress);
        }
        validate_local_part(local_part)?;

        if scope.contains('.') {
            return Ok(ParsedAddress::DomainHandle {
                local_part: local_part.to_owned(),
                domain: scope.to_owned(),
            });
        }
        return Ok(ParsedAddress::DiscoveryHandle {
            local_part: local_part.to_owned(),
            scope: scope.to_owned(),
        });
    }

    // Bare name: unscoped
    Ok(ParsedAddress::Unscoped { name: normalized })
}

// ---------------------------------------------------------------------------
// ResolutionCache (§22.8.4)
// ---------------------------------------------------------------------------

/// A cached resolution result with expiry time.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached resolution results.
    results: Vec<AddressResolution>,
    /// When this entry expires.
    expires_at: Instant,
}

/// Local resolution cache to avoid redundant network calls.
///
/// Cache entries are keyed by normalized address string. Each entry has a TTL
/// determined by the resolution layer per §22.8.4:
/// - Petnames: indefinite (user-managed).
/// - Domain handles: ~1 hour.
/// - Context handles: ~15 minutes.
/// - Attestation handles: match attestation renewal intervals.
///
/// See §22.8.4 Resolution Caching.
#[derive(Debug)]
pub struct ResolutionCache {
    entries: lru::LruCache<String, CacheEntry>,
}

/// Default maximum capacity of the resolution cache.
const DEFAULT_CACHE_CAPACITY: usize = 10_000;

impl ResolutionCache {
    /// Creates a new empty resolution cache with default capacity (10,000).
    ///
    /// # Panics
    ///
    /// Panics if `DEFAULT_CACHE_CAPACITY` is zero (compile-time constant, always non-zero).
    #[must_use]
    // SAFETY: DEFAULT_CACHE_CAPACITY is a non-zero compile-time constant (128).
    #[allow(clippy::expect_used)]
    pub fn new() -> Self {
        Self {
            entries: lru::LruCache::new(
                std::num::NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).expect("constant is non-zero"),
            ),
        }
    }

    /// Looks up a cached result for the given normalized address.
    ///
    /// Returns `None` if no entry exists or the entry has expired.
    pub fn get(&mut self, address: &str) -> Option<&[AddressResolution]> {
        let entry = self.entries.get(address)?;
        if Instant::now() >= entry.expires_at {
            return None;
        }
        Some(&entry.results)
    }

    /// Inserts a resolution result into the cache with the given TTL.
    pub fn insert(&mut self, address: String, results: Vec<AddressResolution>, ttl: Duration) {
        self.entries.put(
            address,
            CacheEntry {
                results,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// Removes expired entries from the cache (defense-in-depth alongside LRU).
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.entries.pop(&key);
        }
    }

    /// Returns the number of entries in the cache (including expired).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ResolutionCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AddressResolver (§22.8)
// ---------------------------------------------------------------------------

/// SDK-level type implementing multi-path address resolution.
///
/// The `AddressResolver` orchestrates resolution across all four addressing
/// layers (petnames, context handles, attestation handles, domain
/// handles). It is not a wire-protocol component -- it is standardized SDK
/// behavior per §22.8.
///
/// Resolution results are ranked by trust level (higher `default_rank` first).
///
/// See §22.8 Unified Resolution Protocol.
#[derive(Debug)]
pub struct AddressResolver {
    /// Resolution cache for avoiding redundant network calls.
    pub cache: ResolutionCache,
}

impl AddressResolver {
    /// Creates a new `AddressResolver` with an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: ResolutionCache::new(),
        }
    }

    /// Resolves a human-readable address string.
    ///
    /// Parses the address, checks the cache, and dispatches to the appropriate
    /// resolution layer(s). Results are sorted by trust level (descending).
    ///
    /// For scoped addresses, only the relevant layer is queried. For unscoped
    /// addresses, all layers are searched per §22.8.2.
    ///
    /// # Arguments
    ///
    /// * `address` -- The human-readable address string to resolve.
    /// * `petname_store` -- Local petname store for instant lookup.
    /// * `handle_querier` -- Querier for context handle lookups.
    /// * `known_contexts` -- Known context scope names and their IDs.
    /// * `known_domains` -- Configured domains to check for domain handles during
    ///   unscoped resolution (§22.8.2 step 2a).
    ///
    /// # Errors
    ///
    /// Returns [`AddressingError`] if the address is malformed or resolution
    /// fails entirely.
    #[allow(clippy::future_not_send)] // async trait methods don't support Send bounds
    pub async fn resolve<P, H>(
        &mut self,
        address: &str,
        petname_store: &P,
        handle_querier: &H,
        known_contexts: &HashMap<String, ContextId>,
        known_domains: &[&str],
        clock: &dyn Clock,
    ) -> Result<Vec<AddressResolution>, AddressingError>
    where
        P: PetnameStore,
        H: HandleQuerier,
    {
        let normalized = normalize_address(address);

        // Check cache first.
        if let Some(cached) = self.cache.get(&normalized) {
            return Ok(cached.to_vec());
        }

        let parsed = parse_address(address)?;
        let mut results = Vec::new();

        match parsed {
            ParsedAddress::DiscoveryHandle { local_part, scope } => {
                if let Some(context_id) = known_contexts.get(&scope) {
                    let handle_results = handle_querier
                        .lookup_handle(context_id, &local_part, None)
                        .await;
                    results.extend(handle_results);
                }
            }
            ParsedAddress::DomainHandle { local_part, domain } => {
                let domain_results = handle_querier
                    .lookup_domain_handle(&domain, &local_part)
                    .await;
                results.extend(domain_results);

                if results.is_empty() {
                    let attestation_results = handle_querier
                        .lookup_attestation_handle(&local_part, Some(&domain))
                        .await;
                    results.extend(attestation_results);
                }
            }
            ParsedAddress::AttestationHandle { handle, platform } => {
                let attestation_results = handle_querier
                    .lookup_attestation_handle(&handle, platform.as_deref())
                    .await;
                results.extend(attestation_results);
            }
            ParsedAddress::Unscoped { name } => {
                // §22.8.2: Check petnames first (instant, no network).
                let petname_results = petname_store.resolve_petname(&name, clock);
                if !petname_results.is_empty() {
                    results.extend(petname_results);
                    self.cache
                        .insert(normalized, results.clone(), PETNAME_CACHE_TTL);
                    return Ok(results);
                }

                // Then check all contexts with discovery tools.
                for (scope, context_id) in known_contexts {
                    let handle_results =
                        handle_querier.lookup_handle(context_id, &name, None).await;
                    results.extend(handle_results);
                    let _ = scope;
                }

                // Then check domain handles for each configured domain (§22.8.2 step 2a).
                for domain in known_domains {
                    let domain_results = handle_querier.lookup_domain_handle(domain, &name).await;
                    results.extend(domain_results);
                }

                // Then check attestation.
                let attestation_results =
                    handle_querier.lookup_attestation_handle(&name, None).await;
                results.extend(attestation_results);
            }
        }

        if results.is_empty() {
            return Err(AddressingError::NotFound(address.to_owned()));
        }

        // Sort by trust level rank (descending).
        results.sort_by(|a, b| {
            b.trust_level()
                .default_rank()
                .cmp(&a.trust_level().default_rank())
        });

        // Deduplicate by DID: if multiple paths found the same DID, promote to
        // MultiLayerCorroborated per §22.8.2 step 4c.
        results = corroborate_results(results, clock);

        // Cache the results with the shortest applicable TTL.
        let ttl = shortest_ttl_for_results(&results);
        self.cache.insert(normalized, results.clone(), ttl);

        Ok(results)
    }
}

impl Default for AddressResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Traits for resolution layer abstraction
// ---------------------------------------------------------------------------

/// Trait for querying remote handle resolution layers.
///
/// Abstracts context handle lookup, attestation reverse-lookup,
/// and domain handle resolution.
#[allow(async_fn_in_trait)]
pub trait HandleQuerier {
    /// Looks up a handle in a context with discovery tools.
    ///
    /// Returns resolution results from the specified context.
    async fn lookup_handle(
        &self,
        context_id: &ContextId,
        handle: &str,
        type_filter: Option<AddressType>,
    ) -> Vec<AddressResolution>;

    /// Looks up a domain handle via `.well-known/scp`.
    ///
    /// Returns resolution results from the domain's handles map.
    async fn lookup_domain_handle(&self, domain: &str, handle: &str) -> Vec<AddressResolution>;

    /// Looks up an attestation-backed handle via reverse-lookup.
    ///
    /// Returns resolution results from attestation indexes in known
    /// contexts with discovery tools.
    async fn lookup_attestation_handle(
        &self,
        handle: &str,
        platform: Option<&str>,
    ) -> Vec<AddressResolution>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Detects when multiple resolution paths found the same DID and promotes
/// those results to `MultiLayerCorroborated` per §22.8.2 step 4c.
fn corroborate_results(
    results: Vec<AddressResolution>,
    clock: &dyn Clock,
) -> Vec<AddressResolution> {
    let mut by_did: HashMap<String, Vec<AddressResolution>> = HashMap::new();
    let mut non_identity: Vec<AddressResolution> = Vec::new();

    for result in results {
        match &result {
            AddressResolution::Identity { did, .. } => {
                by_did.entry(did.to_string()).or_default().push(result);
            }
            AddressResolution::Context { .. } => {
                non_identity.push(result);
            }
        }
    }

    let mut output: Vec<AddressResolution> = Vec::new();

    for (_, entries) in by_did {
        if entries.len() > 1 {
            // Multiple paths agree -- promote to MultiLayerCorroborated.
            let sources: Vec<ResolutionPath> = entries
                .iter()
                .map(|e| e.resolution_path().clone())
                .collect();
            if let Some(AddressResolution::Identity { did, .. }) = entries.into_iter().next() {
                let now = clock.now_secs();
                output.push(AddressResolution::Identity {
                    did,
                    trust_level: TrustLevel::MultiLayerCorroborated {
                        sources: sources.clone(),
                    },
                    resolution_path: ResolutionPath {
                        layer: ResolutionLayer::MultiLayerCorroborated,
                        source: "corroborated".to_owned(),
                        source_id: None,
                        resolved_at: now,
                    },
                });
            }
        } else {
            output.extend(entries);
        }
    }

    output.extend(non_identity);

    // Re-sort after corroboration.
    output.sort_by(|a, b| {
        b.trust_level()
            .default_rank()
            .cmp(&a.trust_level().default_rank())
    });

    output
}

/// Determines the shortest TTL to use for a set of resolution results.
///
/// Uses `Option<Duration>` to distinguish "no results seen" from "all results
/// are petname-only." The previous implementation initialized `min_ttl` to
/// `PETNAME_CACHE_TTL` then treated an unchanged value as "no real results,"
/// which incorrectly downgraded petname-only results from 365-day to 15-minute
/// cache TTL.
fn shortest_ttl_for_results(results: &[AddressResolution]) -> Duration {
    let mut min_ttl: Option<Duration> = None;

    for result in results {
        let ttl = match result.resolution_path().layer {
            ResolutionLayer::Petname => PETNAME_CACHE_TTL,
            ResolutionLayer::Domain => DOMAIN_HANDLE_CACHE_TTL,
            ResolutionLayer::HandleRegistry | ResolutionLayer::MultiLayerCorroborated => {
                DISCOVERY_HANDLE_CACHE_TTL
            }
            ResolutionLayer::Attestation => ATTESTATION_HANDLE_CACHE_TTL,
        };
        min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
    }

    min_ttl.unwrap_or(DISCOVERY_HANDLE_CACHE_TTL)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- Address parsing tests -----------------------------------------------

    #[test]
    fn parse_discovery_handle_no_dot_in_scope() {
        let parsed = parse_address("alice@cooking-community").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::DiscoveryHandle {
                local_part: "alice".to_owned(),
                scope: "cooking-community".to_owned(),
            }
        );
    }

    #[test]
    fn parse_domain_handle_dot_in_scope() {
        let parsed = parse_address("alice@example.com").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::DomainHandle {
                local_part: "alice".to_owned(),
                domain: "example.com".to_owned(),
            }
        );
    }

    #[test]
    fn parse_attestation_handle_no_platform() {
        let parsed = parse_address("@alice_cooks").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::AttestationHandle {
                handle: "alice_cooks".to_owned(),
                platform: None,
            }
        );
    }

    #[test]
    fn parse_attestation_handle_with_platform() {
        let parsed = parse_address("@alice_cooks:x").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::AttestationHandle {
                handle: "alice_cooks".to_owned(),
                platform: Some("x".to_owned()),
            }
        );
    }

    #[test]
    fn parse_unscoped_bare_name() {
        let parsed = parse_address("alice").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::Unscoped {
                name: "alice".to_owned(),
            }
        );
    }

    #[test]
    fn parse_address_normalizes_case() {
        let parsed = parse_address("  Alice@Cooking-Community  ").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::DiscoveryHandle {
                local_part: "alice".to_owned(),
                scope: "cooking-community".to_owned(),
            }
        );
    }

    #[test]
    fn parse_address_rejects_empty() {
        let result = parse_address("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_address_rejects_too_long_local_part() {
        let long_name = "a".repeat(65);
        let address = format!("{long_name}@scope");
        let result = parse_address(&address);
        assert!(matches!(result, Err(AddressingError::LocalPartTooLong)));
    }

    #[test]
    fn parse_address_rejects_invalid_characters() {
        let result = parse_address("al!ce@scope");
        assert!(matches!(
            result,
            Err(AddressingError::InvalidLocalPartCharacters)
        ));
    }

    #[test]
    fn parse_address_rejects_uppercase_in_local_part() {
        // Uppercase is normalized to lowercase, so this should succeed.
        let parsed = parse_address("Alice@scope").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::DiscoveryHandle {
                local_part: "alice".to_owned(),
                scope: "scope".to_owned(),
            }
        );
    }

    #[test]
    fn parse_address_rejects_leading_hyphen() {
        let result = parse_address("-alice@scope");
        assert!(matches!(
            result,
            Err(AddressingError::InvalidLocalPartBoundary)
        ));
    }

    #[test]
    fn parse_address_rejects_trailing_period() {
        let result = parse_address("alice.@scope");
        assert!(matches!(
            result,
            Err(AddressingError::InvalidLocalPartBoundary)
        ));
    }

    #[test]
    fn parse_address_rejects_consecutive_periods() {
        let result = parse_address("al..ice@scope");
        assert!(matches!(result, Err(AddressingError::ConsecutivePeriods)));
    }

    #[test]
    fn parse_address_allows_valid_special_characters() {
        let parsed = parse_address("alice.bob_charlie-dave@scope").unwrap();
        assert_eq!(
            parsed,
            ParsedAddress::DiscoveryHandle {
                local_part: "alice.bob_charlie-dave".to_owned(),
                scope: "scope".to_owned(),
            }
        );
    }

    // -- TrustLevel tests ----------------------------------------------------

    #[test]
    fn trust_level_default_rank_ordering() {
        assert!(
            TrustLevel::DirectExchange.default_rank() > TrustLevel::LocalPetname.default_rank()
        );
        assert!(
            TrustLevel::LocalPetname.default_rank()
                > TrustLevel::MultiLayerCorroborated { sources: vec![] }.default_rank()
        );
        assert!(
            TrustLevel::MultiLayerCorroborated { sources: vec![] }.default_rank()
                > TrustLevel::DomainVerified.default_rank()
        );
        assert!(
            TrustLevel::DomainVerified.default_rank()
                > TrustLevel::AttestationVerified.default_rank()
        );
        assert!(
            TrustLevel::AttestationVerified.default_rank()
                > TrustLevel::HandleRegistryVerified.default_rank()
        );
    }

    // -- ResolutionCache tests -----------------------------------------------

    #[test]
    fn cache_insert_and_get_returns_results() {
        let mut cache = ResolutionCache::new();
        let results = vec![AddressResolution::Identity {
            did: DID::from("did:dht:zAlice"),
            trust_level: TrustLevel::LocalPetname,
            resolution_path: ResolutionPath {
                layer: ResolutionLayer::Petname,
                source: "local".to_owned(),
                source_id: None,
                resolved_at: 1_700_000_000,
            },
        }];

        cache.insert("alice".to_owned(), results, Duration::from_secs(3600));

        let cached = cache.get("alice").unwrap();
        assert_eq!(cached.len(), 1);
    }

    #[test]
    fn cache_returns_none_for_missing_key() {
        let mut cache = ResolutionCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn cache_evict_expired_removes_old_entries() {
        let mut cache = ResolutionCache::new();
        cache.insert("expired".to_owned(), vec![], Duration::from_secs(0));
        cache.insert("alive".to_owned(), vec![], Duration::from_secs(3600));

        // The expired entry might or might not be stale yet (depends on timing).
        // Force eviction.
        std::thread::sleep(Duration::from_millis(10));
        cache.evict_expired();

        // The expired entry should be gone.
        assert!(cache.get("expired").is_none());
    }

    // -- AddressResolution tests ---------------------------------------------

    #[test]
    fn address_resolution_identity_accessors() {
        let resolution = AddressResolution::Identity {
            did: DID::from("did:dht:zAlice"),
            trust_level: TrustLevel::HandleRegistryVerified,
            resolution_path: ResolutionPath {
                layer: ResolutionLayer::HandleRegistry,
                source: "cooking-community".to_owned(),
                source_id: Some("ctx-001".to_owned()),
                resolved_at: 1_700_000_000,
            },
        };

        assert_eq!(
            *resolution.trust_level(),
            TrustLevel::HandleRegistryVerified
        );
        assert_eq!(
            resolution.resolution_path().layer,
            ResolutionLayer::HandleRegistry
        );
    }

    #[test]
    fn address_resolution_context_accessors() {
        let resolution = AddressResolution::Context {
            context_id: "a1b2c3".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            mode: Some("broadcast".to_owned()),
            trust_level: TrustLevel::DomainVerified,
            resolution_path: ResolutionPath {
                layer: ResolutionLayer::Domain,
                source: "example.com".to_owned(),
                source_id: None,
                resolved_at: 1_700_000_000,
            },
        };

        assert_eq!(*resolution.trust_level(), TrustLevel::DomainVerified);
        assert_eq!(resolution.resolution_path().layer, ResolutionLayer::Domain);
    }

    // -- Corroboration tests -------------------------------------------------

    #[test]
    fn corroborate_results_promotes_multi_path_same_did() {
        let results = vec![
            AddressResolution::Identity {
                did: DID::from("did:dht:zAlice"),
                trust_level: TrustLevel::HandleRegistryVerified,
                resolution_path: ResolutionPath {
                    layer: ResolutionLayer::HandleRegistry,
                    source: "cooking".to_owned(),
                    source_id: Some("ctx-1".to_owned()),
                    resolved_at: 1_700_000_000,
                },
            },
            AddressResolution::Identity {
                did: DID::from("did:dht:zAlice"),
                trust_level: TrustLevel::AttestationVerified,
                resolution_path: ResolutionPath {
                    layer: ResolutionLayer::Attestation,
                    source: "x".to_owned(),
                    source_id: None,
                    resolved_at: 1_700_000_000,
                },
            },
        ];

        let corroborated = corroborate_results(results, &scp_primitives::SystemClock);
        assert_eq!(corroborated.len(), 1);
        assert!(matches!(
            corroborated[0].trust_level(),
            TrustLevel::MultiLayerCorroborated { sources } if sources.len() == 2
        ));
        assert_eq!(
            corroborated[0].resolution_path().layer,
            ResolutionLayer::MultiLayerCorroborated
        );
    }

    #[test]
    fn corroborate_results_leaves_single_path_unchanged() {
        let results = vec![AddressResolution::Identity {
            did: DID::from("did:dht:zAlice"),
            trust_level: TrustLevel::HandleRegistryVerified,
            resolution_path: ResolutionPath {
                layer: ResolutionLayer::HandleRegistry,
                source: "cooking".to_owned(),
                source_id: Some("ctx-1".to_owned()),
                resolved_at: 1_700_000_000,
            },
        }];

        let corroborated = corroborate_results(results, &scp_primitives::SystemClock);
        assert_eq!(corroborated.len(), 1);
        assert_eq!(
            *corroborated[0].trust_level(),
            TrustLevel::HandleRegistryVerified
        );
    }

    // -- Unified resolution integration tests --------------------------------

    /// Test double: in-memory petname store.
    struct TestPetnameStore {
        petnames: HashMap<String, Vec<AddressResolution>>,
    }

    impl TestPetnameStore {
        fn new() -> Self {
            Self {
                petnames: HashMap::new(),
            }
        }

        fn add_petname(&mut self, name: &str, did: &str) {
            self.petnames
                .entry(name.to_owned())
                .or_default()
                .push(AddressResolution::Identity {
                    did: DID::from(did),
                    trust_level: TrustLevel::LocalPetname,
                    resolution_path: ResolutionPath {
                        layer: ResolutionLayer::Petname,
                        source: "local".to_owned(),
                        source_id: None,
                        resolved_at: 1_700_000_000,
                    },
                });
        }
    }

    impl PetnameStore for TestPetnameStore {
        fn resolve_petname(&self, name: &str, _clock: &dyn Clock) -> Vec<AddressResolution> {
            self.petnames.get(name).cloned().unwrap_or_default()
        }
    }

    /// Test double: in-memory handle querier.
    #[allow(clippy::struct_field_names)]
    struct TestHandleQuerier {
        discovery_handles: HashMap<(String, String), Vec<AddressResolution>>,
        domain_handles: HashMap<(String, String), Vec<AddressResolution>>,
        attestation_handles: HashMap<String, Vec<AddressResolution>>,
    }

    impl TestHandleQuerier {
        fn new() -> Self {
            Self {
                discovery_handles: HashMap::new(),
                domain_handles: HashMap::new(),
                attestation_handles: HashMap::new(),
            }
        }

        fn add_discovery_handle(
            &mut self,
            context_id: &str,
            handle: &str,
            did: &str,
            scope_name: &str,
        ) {
            self.discovery_handles
                .entry((context_id.to_owned(), handle.to_owned()))
                .or_default()
                .push(AddressResolution::Identity {
                    did: DID::from(did),
                    trust_level: TrustLevel::HandleRegistryVerified,
                    resolution_path: ResolutionPath {
                        layer: ResolutionLayer::HandleRegistry,
                        source: scope_name.to_owned(),
                        source_id: Some(context_id.to_owned()),
                        resolved_at: 1_700_000_000,
                    },
                });
        }

        fn add_domain_handle(&mut self, domain: &str, handle: &str, did: &str) {
            self.domain_handles
                .entry((domain.to_owned(), handle.to_owned()))
                .or_default()
                .push(AddressResolution::Identity {
                    did: DID::from(did),
                    trust_level: TrustLevel::DomainVerified,
                    resolution_path: ResolutionPath {
                        layer: ResolutionLayer::Domain,
                        source: domain.to_owned(),
                        source_id: None,
                        resolved_at: 1_700_000_000,
                    },
                });
        }

        fn add_attestation_handle(&mut self, handle: &str, did: &str) {
            self.attestation_handles
                .entry(handle.to_owned())
                .or_default()
                .push(AddressResolution::Identity {
                    did: DID::from(did),
                    trust_level: TrustLevel::AttestationVerified,
                    resolution_path: ResolutionPath {
                        layer: ResolutionLayer::Attestation,
                        source: "x".to_owned(),
                        source_id: None,
                        resolved_at: 1_700_000_000,
                    },
                });
        }
    }

    impl HandleQuerier for TestHandleQuerier {
        async fn lookup_handle(
            &self,
            context_id: &ContextId,
            handle: &str,
            _type_filter: Option<AddressType>,
        ) -> Vec<AddressResolution> {
            self.discovery_handles
                .get(&(context_id.clone(), handle.to_owned()))
                .cloned()
                .unwrap_or_default()
        }

        async fn lookup_domain_handle(&self, domain: &str, handle: &str) -> Vec<AddressResolution> {
            self.domain_handles
                .get(&(domain.to_owned(), handle.to_owned()))
                .cloned()
                .unwrap_or_default()
        }

        async fn lookup_attestation_handle(
            &self,
            handle: &str,
            _platform: Option<&str>,
        ) -> Vec<AddressResolution> {
            self.attestation_handles
                .get(handle)
                .cloned()
                .unwrap_or_default()
        }
    }

    #[tokio::test]
    async fn resolve_discovery_handle_returns_result() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle(
            "ctx-cooking",
            "alice",
            "did:dht:zAlice",
            "cooking-community",
        );

        let mut known = HashMap::new();
        known.insert("cooking-community".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "alice@cooking-community",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity { did, trust_level: TrustLevel::HandleRegistryVerified, .. }
            if did == "did:dht:zAlice"
        ));
    }

    #[tokio::test]
    async fn resolve_domain_handle_returns_result() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_domain_handle("example.com", "alice", "did:dht:zAlice");

        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "alice@example.com",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity { did, trust_level: TrustLevel::DomainVerified, .. }
            if did == "did:dht:zAlice"
        ));
    }

    #[tokio::test]
    async fn resolve_domain_handle_falls_back_to_attestation() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        // No domain handle, but attestation handle exists.
        querier.add_attestation_handle("alice", "did:dht:zAlice");

        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "alice@x.com",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity { did, trust_level: TrustLevel::AttestationVerified, .. }
            if did == "did:dht:zAlice"
        ));
    }

    #[tokio::test]
    async fn resolve_attestation_handle_returns_result() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_attestation_handle("alice_cooks", "did:dht:zAlice");

        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "@alice_cooks",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity { did, trust_level: TrustLevel::AttestationVerified, .. }
            if did == "did:dht:zAlice"
        ));
    }

    #[tokio::test]
    async fn resolve_unscoped_checks_petname_first() {
        let mut petnames = TestPetnameStore::new();
        petnames.add_petname("alice", "did:dht:zAlicePetname");

        let mut querier = TestHandleQuerier::new();
        querier.add_attestation_handle("alice", "did:dht:zAliceAttestation");

        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        // Petname should win -- returns immediately without checking other layers.
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity { did, trust_level: TrustLevel::LocalPetname, .. }
            if did == "did:dht:zAlicePetname"
        ));
    }

    #[tokio::test]
    async fn resolve_unscoped_multi_layer_corroboration() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle(
            "ctx-cooking",
            "alice",
            "did:dht:zAlice",
            "cooking-community",
        );
        querier.add_attestation_handle("alice", "did:dht:zAlice");

        let mut known = HashMap::new();
        known.insert("cooking-community".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        // Same DID from two paths should be corroborated.
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0].trust_level(),
            TrustLevel::MultiLayerCorroborated { sources } if sources.len() == 2
        ));
    }

    #[tokio::test]
    async fn resolve_unscoped_checks_domain_handles() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_domain_handle("example.com", "alice", "did:dht:zAlice");

        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &["example.com"],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity { did, trust_level: TrustLevel::DomainVerified, .. }
            if did == "did:dht:zAlice"
        ));
    }

    #[tokio::test]
    async fn resolve_not_found_returns_error() {
        let petnames = TestPetnameStore::new();
        let querier = TestHandleQuerier::new();
        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let result = resolver
            .resolve(
                "nonexistent@nowhere",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await;

        assert!(matches!(result, Err(AddressingError::NotFound(_))));
    }

    #[tokio::test]
    async fn resolve_caches_results() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle(
            "ctx-cooking",
            "alice",
            "did:dht:zAlice",
            "cooking-community",
        );

        let mut known = HashMap::new();
        known.insert("cooking-community".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();

        // First resolve populates cache.
        let results1 = resolver
            .resolve(
                "alice@cooking-community",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        // Second resolve should hit cache.
        let results2 = resolver
            .resolve(
                "alice@cooking-community",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_primitives::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(results1.len(), results2.len());
        assert!(!resolver.cache.is_empty());
    }

    // -- HandleTarget tests --------------------------------------------------

    #[test]
    fn handle_target_identity_serialization_roundtrip() {
        let target = HandleTarget::Identity {
            did: DID::from("did:dht:zAlice"),
        };
        let json = serde_json::to_string(&target).unwrap();
        let deserialized: HandleTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }

    #[test]
    fn handle_target_context_serialization_roundtrip() {
        let target = HandleTarget::Context {
            context_id: "a1b2c3".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
        };
        let json = serde_json::to_string(&target).unwrap();
        let deserialized: HandleTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }
}
