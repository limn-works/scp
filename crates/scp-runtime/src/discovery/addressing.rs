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

use scp_clock::Clock;

use scp_protocol::discovery::ContextId;

pub use scp_protocol::discovery::addressing::{
    AddressResolution, AddressResolutionOutcome, AddressingError, HandleTarget, LayerUnavailable,
    MAX_LOCAL_PART_LENGTH, PetnameStore, ResolutionLayer, ResolutionPath, TrustLevel,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default TTL for domain handle cache entries (1 hour per §22.8.4).
pub const DOMAIN_HANDLE_CACHE_TTL: Duration = Duration::from_hours(1);

/// Default TTL for context handle cache entries (15 minutes per §22.8.4).
pub const DISCOVERY_HANDLE_CACHE_TTL: Duration = Duration::from_mins(15);

/// TTL for petname cache entries (effectively indefinite: 1 year per §22.8.4).
/// Petnames are user-managed, so the cache is essentially permanent until the
/// user changes the petname.
pub const PETNAME_CACHE_TTL: Duration = Duration::from_hours(8760);

/// Default TTL for attestation handle cache entries (1 day, matching renewal intervals per §22.8.4).
pub const ATTESTATION_HANDLE_CACHE_TTL: Duration = Duration::from_hours(24);

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

/// A cached resolution outcome with expiry time.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached resolution outcome, carrying both the bindings resolution
    /// found and the layers that never answered. A cache hit replays both,
    /// because a hit that dropped the unavailable-layer list would tell a
    /// caller that every layer answered when no layer had.
    outcome: AddressResolutionOutcome,
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

    /// Looks up a cached outcome for the given normalized address.
    ///
    /// Returns `None` if no entry exists or the entry has expired.
    pub fn get(&mut self, address: &str) -> Option<&AddressResolutionOutcome> {
        let entry = self.entries.get(address)?;
        if Instant::now() >= entry.expires_at {
            return None;
        }
        Some(&entry.outcome)
    }

    /// Inserts a resolution outcome into the cache with the given TTL.
    pub fn insert(&mut self, address: String, outcome: AddressResolutionOutcome, ttl: Duration) {
        self.entries.put(
            address,
            CacheEntry {
                outcome,
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
    /// The returned [`AddressResolutionOutcome`] carries both the bindings
    /// resolution found and every layer nobody read — one that answered
    /// [`LayerUnavailable`] rather than a result vector, and one that
    /// `known_contexts` or `known_domains` named nothing to query for. A
    /// caller that acts on the top-ranked binding reads `unavailable_layers`
    /// to learn whether a higher-trust layer went unread, because §22.8.2
    /// ranks by trust and an unread higher-trust layer may hold a different
    /// binding.
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
    /// Returns [`AddressingError::EmptyAddress`] and its sibling parse
    /// variants when `address` is malformed. Returns
    /// [`AddressingError::NotFound`] when a read happened against every layer
    /// this address reaches and none held a binding. Returns
    /// [`AddressingError::LayersUnavailable`] when no layer held a binding and
    /// nobody read at least one layer — because `handle_querier` reaches no
    /// such layer, or because `known_contexts` or `known_domains` named
    /// nothing to query there — which tells a caller that a capability is
    /// missing rather than a binding.
    #[allow(clippy::future_not_send)] // async trait methods don't support Send bounds
    pub async fn resolve<P, H>(
        &mut self,
        address: &str,
        petname_store: &P,
        handle_querier: &H,
        known_contexts: &HashMap<String, ContextId>,
        known_domains: &[&str],
        clock: &dyn Clock,
    ) -> Result<AddressResolutionOutcome, AddressingError>
    where
        P: PetnameStore,
        H: HandleQuerier,
    {
        let normalized = normalize_address(address);

        // Check cache first.
        if let Some(cached) = self.cache.get(&normalized) {
            return Ok(cached.clone());
        }

        let parsed = parse_address(address)?;

        // §22.8.2 step 1 checks petnames first (instant, no network) and stops
        // at a hit, so no handle layer is queried and none reports
        // unavailability.
        if let ParsedAddress::Unscoped { name } = &parsed {
            let petname_results = petname_store.resolve_petname(name, clock);
            if !petname_results.is_empty() {
                let outcome = AddressResolutionOutcome {
                    resolutions: petname_results,
                    unavailable_layers: Vec::new(),
                };
                self.cache
                    .insert(normalized, outcome.clone(), PETNAME_CACHE_TTL);
                return Ok(outcome);
            }
        }

        let (mut results, unavailable) =
            query_handle_layers(&parsed, handle_querier, known_contexts, known_domains).await;

        if results.is_empty() {
            if unavailable.is_empty() {
                return Err(AddressingError::NotFound(address.to_owned()));
            }
            return Err(AddressingError::LayersUnavailable {
                address: address.to_owned(),
                layers: unavailable,
            });
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

        // Cache the outcome with the shortest applicable TTL.
        let ttl = shortest_ttl_for_results(&results);
        let outcome = AddressResolutionOutcome {
            resolutions: results,
            unavailable_layers: unavailable,
        };
        self.cache.insert(normalized, outcome.clone(), ttl);

        Ok(outcome)
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
///
/// Every method answers with a result vector, which may be empty when no
/// participant registered that handle, or with [`LayerUnavailable`], which
/// says this implementation reaches no such layer. An implementation that
/// cannot query a layer MUST return [`LayerUnavailable`] and MUST NOT return
/// an empty vector, because an empty vector claims that somebody looked.
/// [`AddressResolver::resolve`] carries every [`LayerUnavailable`] it collected
/// into [`AddressResolutionOutcome::unavailable_layers`], on a resolution that
/// found bindings as well as on one that found none.
#[allow(async_fn_in_trait)]
pub trait HandleQuerier {
    /// Looks up a handle in a context with discovery outlets.
    ///
    /// Returns resolution results from the specified context.
    ///
    /// # Errors
    ///
    /// Returns [`LayerUnavailable`] when this implementation reaches no
    /// context handle registry.
    async fn lookup_handle(
        &self,
        context_id: &ContextId,
        handle: &str,
        type_filter: Option<AddressType>,
    ) -> Result<Vec<AddressResolution>, LayerUnavailable>;

    /// Looks up a domain handle via `.well-known/scp`.
    ///
    /// Returns resolution results from the domain's handles map.
    ///
    /// # Errors
    ///
    /// Returns [`LayerUnavailable`] when this implementation performs no
    /// `.well-known/scp` fetch.
    async fn lookup_domain_handle(
        &self,
        domain: &str,
        handle: &str,
    ) -> Result<Vec<AddressResolution>, LayerUnavailable>;

    /// Looks up an attestation-backed handle via reverse-lookup.
    ///
    /// Returns resolution results from attestation indexes in known
    /// contexts with discovery outlets.
    ///
    /// # Errors
    ///
    /// Returns [`LayerUnavailable`] when this implementation invokes no
    /// `attestation_lookup` outlet (§22.5.1).
    async fn lookup_attestation_handle(
        &self,
        handle: &str,
        platform: Option<&str>,
    ) -> Result<Vec<AddressResolution>, LayerUnavailable>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Queries every handle layer that `parsed` reaches, per §22.8.2.
///
/// Returns the bindings those layers held, paired with every layer nobody
/// queried. A caller separates "this layer held no binding" from "nobody
/// queried this layer" by reading the second vector. Petname resolution
/// happens before this call, because §22.8.2 step 1 stops at a petname hit.
///
/// Two conditions put a layer in the second vector, and this function records
/// both, because both leave a caller in the same position: nobody read that
/// layer, so a binding may sit there unseen.
/// - `handle_querier` answered [`LayerUnavailable`], which says this
///   deployment reaches no such layer at all.
/// - `known_contexts` or `known_domains` named nothing for that layer, so this
///   function issued no query. `known_domains` is empty on all three FFI
///   bridges, so an unscoped resolution through a bridge always reports the
///   domain layer here.
#[allow(clippy::future_not_send)] // async trait methods don't support Send bounds
async fn query_handle_layers<H>(
    parsed: &ParsedAddress,
    handle_querier: &H,
    known_contexts: &HashMap<String, ContextId>,
    known_domains: &[&str],
) -> (Vec<AddressResolution>, Vec<LayerUnavailable>)
where
    H: HandleQuerier,
{
    let mut results = Vec::new();
    let mut unavailable: Vec<LayerUnavailable> = Vec::new();

    match parsed {
        ParsedAddress::DiscoveryHandle { local_part, scope } => {
            if let Some(context_id) = known_contexts.get(scope) {
                record_layer_answer(
                    handle_querier
                        .lookup_handle(context_id, local_part, None)
                        .await,
                    &mut results,
                    &mut unavailable,
                );
            } else {
                // The caller configured no context for this scope, so this
                // resolver queried no handle registry. Returning nothing here
                // would tell a caller that a registry answered and held no
                // entry for the handle.
                record_unavailable(
                    LayerUnavailable {
                        layer: ResolutionLayer::HandleRegistry,
                        reason: format!(
                            "no context is configured for scope '{scope}', so no handle registry was queried"
                        ),
                    },
                    &mut unavailable,
                );
            }
        }
        ParsedAddress::DomainHandle { local_part, domain } => {
            record_layer_answer(
                handle_querier
                    .lookup_domain_handle(domain, local_part)
                    .await,
                &mut results,
                &mut unavailable,
            );

            if results.is_empty() {
                record_layer_answer(
                    handle_querier
                        .lookup_attestation_handle(local_part, Some(domain))
                        .await,
                    &mut results,
                    &mut unavailable,
                );
            }
        }
        ParsedAddress::AttestationHandle { handle, platform } => {
            record_layer_answer(
                handle_querier
                    .lookup_attestation_handle(handle, platform.as_deref())
                    .await,
                &mut results,
                &mut unavailable,
            );
        }
        ParsedAddress::Unscoped { name } => {
            // Every context with discovery outlets (§22.8.2 step 2).
            if known_contexts.is_empty() {
                record_unavailable(
                    LayerUnavailable {
                        layer: ResolutionLayer::HandleRegistry,
                        reason: "no context with discovery outlets is configured, so no handle registry was queried".to_owned(),
                    },
                    &mut unavailable,
                );
            }
            for context_id in known_contexts.values() {
                record_layer_answer(
                    handle_querier.lookup_handle(context_id, name, None).await,
                    &mut results,
                    &mut unavailable,
                );
            }

            // Each configured domain (§22.8.2 step 2a).
            if known_domains.is_empty() {
                record_unavailable(
                    LayerUnavailable {
                        layer: ResolutionLayer::Domain,
                        reason:
                            "no domain is configured, so no .well-known/scp document was fetched"
                                .to_owned(),
                    },
                    &mut unavailable,
                );
            }
            for domain in known_domains {
                record_layer_answer(
                    handle_querier.lookup_domain_handle(domain, name).await,
                    &mut results,
                    &mut unavailable,
                );
            }

            // Attestation reverse-lookup (§22.8.2 step 3).
            record_layer_answer(
                handle_querier.lookup_attestation_handle(name, None).await,
                &mut results,
                &mut unavailable,
            );
        }
    }

    (results, unavailable)
}

/// Pushes one layer's answer onto `results`, or that layer's unavailability
/// onto `unavailable`.
fn record_layer_answer(
    answer: Result<Vec<AddressResolution>, LayerUnavailable>,
    results: &mut Vec<AddressResolution>,
    unavailable: &mut Vec<LayerUnavailable>,
) {
    match answer {
        Ok(found) => results.extend(found),
        Err(missing) => record_unavailable(missing, unavailable),
    }
}

/// Records one unqueried layer, skipping a duplicate of an entry already
/// recorded.
///
/// Two entries are duplicates when they carry the same layer AND the same
/// reason, which is how querying one layer once per configured domain still
/// produces one entry. Two queries against the same layer that fail for
/// different reasons — one context holds no registry while another holds one —
/// stay as two entries, because each names a different thing nobody queried.
fn record_unavailable(missing: LayerUnavailable, unavailable: &mut Vec<LayerUnavailable>) {
    if !unavailable.contains(&missing) {
        unavailable.push(missing);
    }
}

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
    use scp_did::DID;

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
        let outcome = AddressResolutionOutcome {
            resolutions: vec![AddressResolution::Identity {
                did: DID::from("did:dht:zAlice"),
                trust_level: TrustLevel::LocalPetname,
                resolution_path: ResolutionPath {
                    layer: ResolutionLayer::Petname,
                    source: "local".to_owned(),
                    source_id: None,
                    resolved_at: 1_700_000_000,
                },
            }],
            unavailable_layers: Vec::new(),
        };

        cache.insert("alice".to_owned(), outcome, Duration::from_hours(1));

        let cached = cache.get("alice").unwrap();
        assert_eq!(cached.resolutions.len(), 1);
    }

    #[test]
    fn cache_hit_replays_the_unavailable_layers_of_the_stored_outcome() {
        let mut cache = ResolutionCache::new();
        let outcome = AddressResolutionOutcome {
            resolutions: vec![AddressResolution::Identity {
                did: DID::from("did:dht:zAlice"),
                trust_level: TrustLevel::HandleRegistryVerified,
                resolution_path: ResolutionPath {
                    layer: ResolutionLayer::HandleRegistry,
                    source: "ctx-cooking".to_owned(),
                    source_id: None,
                    resolved_at: 1_700_000_000,
                },
            }],
            unavailable_layers: vec![LayerUnavailable {
                layer: ResolutionLayer::Attestation,
                reason: "no attestation_lookup outlet".to_owned(),
            }],
        };

        cache.insert("alice".to_owned(), outcome, Duration::from_hours(1));

        // A cache hit that dropped the unavailable-layer list would tell a
        // caller that every layer answered when the attestation layer had not.
        let cached = cache.get("alice").expect("entry was inserted, TTL is 1h");
        assert_eq!(cached.unavailable_layers.len(), 1);
        assert_eq!(
            cached.unavailable_layers[0].layer,
            ResolutionLayer::Attestation
        );
        assert!(!cached.every_layer_answered());
    }

    #[test]
    fn cache_returns_none_for_missing_key() {
        let mut cache = ResolutionCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn cache_evict_expired_removes_old_entries() {
        let mut cache = ResolutionCache::new();
        let empty = AddressResolutionOutcome {
            resolutions: Vec::new(),
            unavailable_layers: Vec::new(),
        };
        cache.insert("expired".to_owned(), empty.clone(), Duration::from_secs(0));
        cache.insert("alive".to_owned(), empty, Duration::from_hours(1));

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

        let corroborated = corroborate_results(results, &scp_clock::SystemClock);
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

        let corroborated = corroborate_results(results, &scp_clock::SystemClock);
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
        /// Layers this querier reports as unreachable, modelling a bridge that
        /// invokes no `attestation_lookup` outlet and fetches no
        /// `.well-known/scp` document.
        unavailable_layers: Vec<ResolutionLayer>,
        /// Contexts this querier holds no handle registry for, modelling
        /// `LocalHandleQuerier`, whose reason names the context it found no
        /// registry for.
        unavailable_context_registries: Vec<String>,
    }

    impl TestHandleQuerier {
        fn new() -> Self {
            Self {
                discovery_handles: HashMap::new(),
                domain_handles: HashMap::new(),
                attestation_handles: HashMap::new(),
                unavailable_layers: Vec::new(),
                unavailable_context_registries: Vec::new(),
            }
        }

        /// Marks `layer` unreachable, so every lookup against it answers with
        /// [`LayerUnavailable`].
        fn mark_unavailable(&mut self, layer: ResolutionLayer) {
            self.unavailable_layers.push(layer);
        }

        /// Marks one context's handle registry unreachable, so a lookup
        /// against that context answers with a [`LayerUnavailable`] whose
        /// reason names it. Two such contexts therefore produce two distinct
        /// entries under one layer.
        fn mark_context_registry_unavailable(&mut self, context_id: &str) {
            self.unavailable_context_registries
                .push(context_id.to_owned());
        }

        /// Answers with [`LayerUnavailable`] when a caller marked `layer`
        /// unreachable.
        fn availability(&self, layer: &ResolutionLayer) -> Result<(), LayerUnavailable> {
            if self.unavailable_layers.contains(layer) {
                return Err(LayerUnavailable {
                    layer: layer.clone(),
                    reason: "test double reaches no such layer".to_owned(),
                });
            }
            Ok(())
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
        ) -> Result<Vec<AddressResolution>, LayerUnavailable> {
            self.availability(&ResolutionLayer::HandleRegistry)?;
            if self.unavailable_context_registries.contains(context_id) {
                return Err(LayerUnavailable {
                    layer: ResolutionLayer::HandleRegistry,
                    reason: format!("no local handle registry for context {context_id}"),
                });
            }
            Ok(self
                .discovery_handles
                .get(&(context_id.clone(), handle.to_owned()))
                .cloned()
                .unwrap_or_default())
        }

        async fn lookup_domain_handle(
            &self,
            domain: &str,
            handle: &str,
        ) -> Result<Vec<AddressResolution>, LayerUnavailable> {
            self.availability(&ResolutionLayer::Domain)?;
            Ok(self
                .domain_handles
                .get(&(domain.to_owned(), handle.to_owned()))
                .cloned()
                .unwrap_or_default())
        }

        async fn lookup_attestation_handle(
            &self,
            handle: &str,
            _platform: Option<&str>,
        ) -> Result<Vec<AddressResolution>, LayerUnavailable> {
            self.availability(&ResolutionLayer::Attestation)?;
            Ok(self
                .attestation_handles
                .get(handle)
                .cloned()
                .unwrap_or_default())
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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

        // Same DID from two paths should be corroborated.
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0].trust_level(),
            TrustLevel::MultiLayerCorroborated { sources } if sources.len() == 2
        ));
    }

    #[tokio::test]
    async fn resolve_reports_two_unavailable_layers_alongside_a_found_binding() {
        // The handle registry holds a binding for `alice`, and neither the
        // attestation layer nor the domain layer answers. A caller that reads
        // only the resolution vector cannot tell this outcome from one where
        // all three layers answered and only the handle registry held a
        // binding, so `resolve` reports both unavailable layers.
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle(
            "ctx-cooking",
            "alice",
            "did:dht:zAlice",
            "cooking-community",
        );
        querier.mark_unavailable(ResolutionLayer::Attestation);
        querier.mark_unavailable(ResolutionLayer::Domain);

        let mut known = HashMap::new();
        known.insert("cooking-community".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();
        let outcome = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &["example.com"],
                &scp_clock::SystemClock,
            )
            .await
            .expect("the handle registry holds a binding for alice");

        assert_eq!(outcome.resolutions.len(), 1);
        assert!(
            !outcome.every_layer_answered(),
            "two layers answered LayerUnavailable, so not every layer answered"
        );
        let mut unavailable: Vec<ResolutionLayer> = outcome
            .unavailable_layers
            .iter()
            .map(|entry| entry.layer.clone())
            .collect();
        unavailable.sort_by_key(|layer| format!("{layer:?}"));
        assert_eq!(
            unavailable,
            vec![ResolutionLayer::Attestation, ResolutionLayer::Domain],
            "resolve must name both the attestation layer and the domain layer"
        );
    }

    #[tokio::test]
    async fn resolve_reports_no_unavailable_layer_when_every_layer_answers() {
        // The companion of the test above: with every layer answering, the
        // same top-ranked binding carries an empty unavailable-layer list, so
        // the two outcomes are distinguishable.
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
        let outcome = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &["example.com"],
                &scp_clock::SystemClock,
            )
            .await
            .expect("the handle registry holds a binding for alice");

        assert_eq!(outcome.resolutions.len(), 1);
        assert!(outcome.every_layer_answered());
        assert!(outcome.unavailable_layers.is_empty());
    }

    #[tokio::test]
    async fn resolve_cache_hit_repeats_the_unavailable_layers_of_the_first_answer() {
        // A second resolve of the same address reads the cache. Were the cache
        // to store only the resolution vector, that second answer would claim
        // that every layer answered.
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle(
            "ctx-cooking",
            "alice",
            "did:dht:zAlice",
            "cooking-community",
        );
        querier.mark_unavailable(ResolutionLayer::Attestation);

        let mut known = HashMap::new();
        known.insert("cooking-community".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();
        let first = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await
            .expect("the handle registry holds a binding for alice");
        let second = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await
            .expect("the cache holds the first answer");

        assert_eq!(first.unavailable_layers, second.unavailable_layers);
        // The querier reaches no attestation index, and this call configured
        // no domain, so both layers went unqueried on the first answer and the
        // cached second answer repeats both.
        assert_eq!(second.unavailable_layers.len(), 2);
        let layers: Vec<ResolutionLayer> = second
            .unavailable_layers
            .iter()
            .map(|entry| entry.layer.clone())
            .collect();
        assert!(layers.contains(&ResolutionLayer::Attestation));
        assert!(layers.contains(&ResolutionLayer::Domain));
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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity { did, trust_level: TrustLevel::DomainVerified, .. }
            if did == "did:dht:zAlice"
        ));
    }

    /// A scoped address whose scope IS configured, and whose handle registry
    /// answered and held no entry, reports [`AddressingError::NotFound`]: every
    /// layer this address reaches answered.
    #[tokio::test]
    async fn resolve_not_found_returns_error() {
        let petnames = TestPetnameStore::new();
        let querier = TestHandleQuerier::new();
        let mut known = HashMap::new();
        known.insert("nowhere".to_owned(), "ctx-nowhere".to_owned());

        let mut resolver = AddressResolver::new();
        let result = resolver
            .resolve(
                "nonexistent@nowhere",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await;

        assert!(
            matches!(result, Err(AddressingError::NotFound(_))),
            "expected NotFound, got {result:?}"
        );
    }

    /// A scoped address whose scope is configured NOWHERE reaches no handle
    /// registry, so resolution reports the handle-registry layer as unqueried
    /// rather than reporting that a registry answered and held no entry.
    #[tokio::test]
    async fn resolve_discovery_handle_reports_the_layer_when_its_scope_is_unconfigured() {
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
                &scp_clock::SystemClock,
            )
            .await;

        let Err(AddressingError::LayersUnavailable { address, layers }) = result else {
            panic!("expected LayersUnavailable, got {result:?}");
        };
        assert_eq!(address, "nonexistent@nowhere");
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].layer, ResolutionLayer::HandleRegistry);
        assert!(
            layers[0].reason.contains("nowhere"),
            "the reason names the scope nobody configured: {}",
            layers[0].reason
        );
    }

    /// An unscoped resolution with no configured domain fetched no
    /// `.well-known/scp` document, so it reports the domain layer even though
    /// its querier reaches that layer. All three FFI bridges pass an empty
    /// domain list, so this is what they report.
    #[tokio::test]
    async fn resolve_unscoped_reports_the_domain_layer_when_no_domain_is_configured() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle("ctx-cooking", "alice", "did:dht:zAlice", "cooking");
        querier.add_attestation_handle("alice", "did:dht:zAlice");

        let mut known = HashMap::new();
        known.insert("cooking".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();
        let outcome = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await
            .expect("the handle registry holds a binding for alice");

        assert_eq!(outcome.unavailable_layers.len(), 1);
        assert_eq!(outcome.unavailable_layers[0].layer, ResolutionLayer::Domain);
        assert!(
            outcome.unavailable_layers[0].reason.contains("no domain"),
            "the reason names the missing configuration: {}",
            outcome.unavailable_layers[0].reason
        );
    }

    /// An unscoped resolution that knows no context with discovery outlets
    /// queried no handle registry, and says so.
    #[tokio::test]
    async fn resolve_unscoped_reports_the_handle_registry_when_no_context_is_configured() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_domain_handle("example.com", "alice", "did:dht:zAlice");

        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let outcome = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &["example.com"],
                &scp_clock::SystemClock,
            )
            .await
            .expect("the domain handle map holds a binding for alice");

        let layers: Vec<ResolutionLayer> = outcome
            .unavailable_layers
            .iter()
            .map(|entry| entry.layer.clone())
            .collect();
        assert!(
            layers.contains(&ResolutionLayer::HandleRegistry),
            "expected the handle-registry layer, got {layers:?}"
        );
    }

    /// One layer produces one entry per distinct reason. Two contexts whose
    /// registries this deployment reaches for neither name two different
    /// things nobody queried, so collapsing them to one entry would drop the
    /// name of one context.
    #[tokio::test]
    async fn resolve_records_one_entry_per_distinct_reason_under_one_layer() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle("ctx-found", "alice", "did:dht:zAlice", "found");
        querier.mark_context_registry_unavailable("ctx-absent-a");
        querier.mark_context_registry_unavailable("ctx-absent-b");

        let mut known = HashMap::new();
        known.insert("found".to_owned(), "ctx-found".to_owned());
        known.insert("absent-a".to_owned(), "ctx-absent-a".to_owned());
        known.insert("absent-b".to_owned(), "ctx-absent-b".to_owned());

        let mut resolver = AddressResolver::new();
        let outcome = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &["example.com", "example.org"],
                &scp_clock::SystemClock,
            )
            .await
            .expect("ctx-found holds a binding for alice");

        let registry_reasons: Vec<&str> = outcome
            .unavailable_layers
            .iter()
            .filter(|entry| entry.layer == ResolutionLayer::HandleRegistry)
            .map(|entry| entry.reason.as_str())
            .collect();
        assert_eq!(
            registry_reasons.len(),
            2,
            "two unreachable registries name two things, got {registry_reasons:?}"
        );
        assert!(registry_reasons.iter().any(|r| r.contains("ctx-absent-a")));
        assert!(registry_reasons.iter().any(|r| r.contains("ctx-absent-b")));
    }

    /// Two configured domains against one unreachable domain layer produce one
    /// entry, because both queries went unmade for the same reason.
    #[tokio::test]
    async fn resolve_records_one_entry_for_two_domains_that_share_a_reason() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle("ctx-cooking", "alice", "did:dht:zAlice", "cooking");
        querier.mark_unavailable(ResolutionLayer::Domain);

        let mut known = HashMap::new();
        known.insert("cooking".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();
        let outcome = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &["example.com", "example.org"],
                &scp_clock::SystemClock,
            )
            .await
            .expect("the handle registry holds a binding for alice");

        let domain_entries = outcome
            .unavailable_layers
            .iter()
            .filter(|entry| entry.layer == ResolutionLayer::Domain)
            .count();
        assert_eq!(
            domain_entries, 1,
            "two domains sharing one reason collapse to one entry"
        );
    }

    /// A querier that reaches no attestation index reports
    /// [`AddressingError::LayersUnavailable`], never
    /// [`AddressingError::NotFound`], so a caller learns that this deployment
    /// invokes no `attestation_lookup` outlet (§22.5.1).
    #[tokio::test]
    async fn resolve_attestation_handle_reports_unavailable_layer() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.mark_unavailable(ResolutionLayer::Attestation);
        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let result = resolver
            .resolve(
                "@alice_cooks",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await;

        let Err(AddressingError::LayersUnavailable { address, layers }) = result else {
            panic!("expected LayersUnavailable, got {result:?}");
        };
        assert_eq!(address, "@alice_cooks");
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].layer, ResolutionLayer::Attestation);
    }

    /// A querier that reaches an attestation index holding no entry for this
    /// handle reports [`AddressingError::NotFound`]. Paired with
    /// `resolve_attestation_handle_reports_unavailable_layer`, this test pins
    /// one distinction a caller depends on: a missing binding and a missing
    /// capability produce different errors.
    #[tokio::test]
    async fn resolve_attestation_handle_absent_entry_returns_not_found() {
        let petnames = TestPetnameStore::new();
        let querier = TestHandleQuerier::new();
        let known = HashMap::new();

        let mut resolver = AddressResolver::new();
        let result = resolver
            .resolve(
                "@alice_cooks",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await;

        assert!(
            matches!(result, Err(AddressingError::NotFound(ref a)) if a == "@alice_cooks"),
            "expected NotFound, got {result:?}"
        );
    }

    /// An unavailable layer never suppresses a binding another layer found.
    #[tokio::test]
    async fn resolve_unscoped_returns_handle_result_despite_unavailable_attestation() {
        let petnames = TestPetnameStore::new();
        let mut querier = TestHandleQuerier::new();
        querier.add_discovery_handle("ctx-cooking", "alice", "did:dht:zAlice", "cooking");
        querier.mark_unavailable(ResolutionLayer::Attestation);

        let mut known = HashMap::new();
        known.insert("cooking".to_owned(), "ctx-cooking".to_owned());

        let mut resolver = AddressResolver::new();
        let results = resolver
            .resolve(
                "alice",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await
            .expect("handle registry holds a binding for alice")
            .resolutions;

        assert_eq!(results.len(), 1);
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
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

        // Second resolve should hit cache.
        let results2 = resolver
            .resolve(
                "alice@cooking-community",
                &petnames,
                &querier,
                &known,
                &[],
                &scp_clock::SystemClock,
            )
            .await
            .unwrap()
            .resolutions;

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
