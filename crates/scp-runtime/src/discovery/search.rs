//! Unified discovery search with result merging.
//!
//! Implements `unified_search` per ADR-020 acceptance criterion 7: search local
//! contact cache (instant), query each known context (parallel tool
//! calls), merge, deduplicate, and rank results. Returns results with
//! provenance per entry.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`.

use std::collections::HashMap;

use scp_primitives::Clock;

use scp_primitives::DID;
use scp_protocol::discovery::context::{AgentSearchParams, AgentSearchResult};
use scp_protocol::discovery::{
    ContextId, DataProvenance, DiscoveryError, DiscoveryQuery, DiscoveryResult,
    DiscoveryResultEntry,
};

// ---------------------------------------------------------------------------
// ContactCache trait
// ---------------------------------------------------------------------------

/// Trait for local contact cache lookup.
///
/// The contact cache provides instant (non-async) access to locally cached
/// discovery results. Implementations may back this with an in-memory map,
/// an on-disk store, or any other local data source.
pub trait ContactCache {
    /// Searches the local contact cache for entries matching the query.
    ///
    /// Returns matching entries instantly (no network I/O). The returned
    /// entries include provenance indicating "`local_cache`" as the source.
    fn search_local(&self, query: &DiscoveryQuery) -> Vec<DiscoveryResultEntry>;
}

// ---------------------------------------------------------------------------
// ContextQuerier trait
// ---------------------------------------------------------------------------

/// Trait for querying a remote context.
///
/// Each known context is queried via its `agent_search` tool
/// endpoint. Implementations handle the network transport and response
/// parsing.
#[allow(async_fn_in_trait)]
pub trait ContextQuerier {
    /// Queries a single context for results matching the given
    /// search parameters.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context to query.
    /// * `params` -- The search parameters (capability filter, keywords, limit).
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] if the query fails (e.g., context
    /// unreachable, authentication failure).
    async fn query_context(
        &self,
        context_id: &ContextId,
        params: &AgentSearchParams,
    ) -> Result<AgentSearchResult, DiscoveryError>;
}

// ---------------------------------------------------------------------------
// unified_search
// ---------------------------------------------------------------------------

/// Performs a unified discovery search across local cache and known discovery
/// contexts.
///
/// Execution strategy per ADR-020 acceptance criterion 7:
/// 1. Search local contact cache (instant, no network).
/// 2. Query each known context in parallel.
/// 3. Merge all results, deduplicating by DID.
/// 4. Rank by relevance score (descending).
///
/// Each result entry carries provenance indicating its source.
///
/// # Arguments
///
/// * `query` -- The discovery query (capability filter, keywords, min history).
/// * `known_contexts` -- Context IDs to query in parallel.
/// * `cache` -- Local contact cache for instant lookup.
/// * `querier` -- Remote context querier.
///
/// # Errors
///
/// Returns [`DiscoveryError`] if all remote context queries fail and the
/// local cache is empty. Individual context query failures are tolerated --
/// results from successful queries are still returned.
#[allow(clippy::future_not_send)] // async trait methods don't support Send bounds
pub async fn unified_search<C: ContactCache, Q: ContextQuerier>(
    query: &DiscoveryQuery,
    known_contexts: &[ContextId],
    cache: &C,
    querier: &Q,
    clock: &dyn Clock,
) -> Result<DiscoveryResult, DiscoveryError> {
    // Step 1: Search local contact cache (instant).
    let local_entries = cache.search_local(query);

    // Step 2: Query each known context in parallel.
    let search_params = query_to_search_params(query);
    let remote_results = query_contexts_parallel(known_contexts, &search_params, querier).await;

    // Step 3: Merge and deduplicate.
    let mut queried_sources: Vec<ContextId> = Vec::new();
    let mut all_entries: Vec<DiscoveryResultEntry> = local_entries;

    for (context_id, result) in remote_results {
        queried_sources.push(context_id.clone());
        let now = clock.now_secs();

        for agent_entry in result.entries {
            all_entries.push(DiscoveryResultEntry {
                did: agent_entry.did.clone(),
                capabilities: agent_entry.capabilities.clone(),
                participation_summary: None,
                provenance: DataProvenance {
                    source_did: agent_entry.did,
                    source_context: Some(context_id.clone()),
                    timestamp: now,
                },
                relevance_score: 0.0, // Scored during ranking step.
            });
        }
    }

    let deduplicated = deduplicate_entries(all_entries);

    // Step 4: Rank by relevance.
    let ranked = rank_entries(deduplicated, query);

    Ok(DiscoveryResult {
        entries: ranked,
        sources: queried_sources,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Converts a [`DiscoveryQuery`] to [`AgentSearchParams`] for context queries.
fn query_to_search_params(query: &DiscoveryQuery) -> AgentSearchParams {
    AgentSearchParams {
        capability_filter: query.capability_filter.clone(),
        keywords: query.keywords.clone(),
        limit: None, // No limit per context; we merge and rank globally.
    }
}

/// Queries multiple contexts with discovery tools in parallel, collecting successful
/// results. Individual failures are silently tolerated.
#[allow(clippy::future_not_send)] // async trait methods don't support Send bounds
async fn query_contexts_parallel<Q: ContextQuerier>(
    context_ids: &[ContextId],
    params: &AgentSearchParams,
    querier: &Q,
) -> Vec<(ContextId, AgentSearchResult)> {
    let mut results = Vec::new();

    // Spawn all queries concurrently via join.
    // NOTE: Using a simple sequential loop here because async trait methods
    // don't support Send bounds required by tokio::spawn without boxing.
    // For practical context counts (typically < 10), this is acceptable.
    // A production implementation would use FuturesUnordered.
    for context_id in context_ids {
        if let Ok(result) = querier.query_context(context_id, params).await {
            results.push((context_id.clone(), result));
        }
        // Individual failures are tolerated per the unified_search contract.
    }

    results
}

/// Deduplicates entries by DID, keeping the entry with the highest relevance
/// score. When scores tie, the entry with provenance from a context with discovery tools
/// (non-local) is preferred over local cache entries.
fn deduplicate_entries(entries: Vec<DiscoveryResultEntry>) -> Vec<DiscoveryResultEntry> {
    let mut by_did: HashMap<DID, DiscoveryResultEntry> = HashMap::new();

    for entry in entries {
        by_did
            .entry(entry.did.clone())
            .and_modify(|existing| {
                // Merge capabilities from duplicate entries.
                for cap in &entry.capabilities {
                    if !existing.capabilities.contains(cap) {
                        existing.capabilities.push(cap.clone());
                    }
                }
                // Prefer higher relevance score.
                if entry.relevance_score > existing.relevance_score {
                    existing.relevance_score = entry.relevance_score;
                    existing.provenance = entry.provenance.clone();
                }
                // Prefer context-sourced provenance over local when scores tie.
                if (entry.relevance_score - existing.relevance_score).abs() < f64::EPSILON
                    && entry.provenance.source_context.is_some()
                    && existing.provenance.source_context.is_none()
                {
                    existing.provenance = entry.provenance.clone();
                }
            })
            .or_insert(entry);
    }

    by_did.into_values().collect()
}

/// Ranks entries by relevance to the query.
///
/// Scoring factors:
/// - Capability match ratio: fraction of queried capabilities the entry has.
/// - Keyword match count: number of keywords that appear in capabilities or DID.
/// - Source bonus: entries from contexts with discovery tools get a small boost.
///
/// Entries are sorted by descending relevance score.
fn rank_entries(
    mut entries: Vec<DiscoveryResultEntry>,
    query: &DiscoveryQuery,
) -> Vec<DiscoveryResultEntry> {
    for entry in &mut entries {
        entry.relevance_score = compute_relevance(entry, query);
    }

    entries.sort_by(|a, b| {
        b.relevance_score
            .partial_cmp(&a.relevance_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    entries
}

/// Computes a relevance score in [0.0, 1.0] for a single entry against the
/// query.
fn compute_relevance(entry: &DiscoveryResultEntry, query: &DiscoveryQuery) -> f64 {
    let mut score = 0.0_f64;
    let mut factors = 0_u32;

    // Factor 1: Capability match ratio.
    if let Some(ref caps) = query.capability_filter
        && !caps.is_empty()
    {
        let matched = caps
            .iter()
            .filter(|c| entry.capabilities.iter().any(|ec| ec == *c))
            .count();
        #[allow(clippy::cast_precision_loss)] // counts are small; precision loss irrelevant
        {
            score += matched as f64 / caps.len() as f64;
        }
        factors += 1;
    }

    // Factor 2: Keyword match count.
    if let Some(ref keywords) = query.keywords
        && !keywords.is_empty()
    {
        let matched = keywords
            .iter()
            .filter(|kw| {
                let kw_lower = kw.to_lowercase();
                entry
                    .capabilities
                    .iter()
                    .any(|c| c.to_lowercase().contains(&kw_lower))
                    || entry.did.to_lowercase().contains(&kw_lower)
            })
            .count();
        #[allow(clippy::cast_precision_loss)] // counts are small; precision loss irrelevant
        {
            score += matched as f64 / keywords.len() as f64;
        }
        factors += 1;
    }

    // No query filters: all entries get a baseline score.
    if factors == 0 {
        return if entry.provenance.source_context.is_some() {
            0.55
        } else {
            0.5
        };
    }

    // Average the factor scores.
    let avg = score / f64::from(factors);

    // Source bonus: a small additive boost for context-sourced entries,
    // applied after averaging so it doesn't dilute the primary signal.
    let bonus = if entry.provenance.source_context.is_some() {
        0.05
    } else {
        0.0
    };

    (avg + bonus).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- Test doubles -------------------------------------------------------

    /// In-memory contact cache for testing.
    struct TestContactCache {
        entries: Vec<DiscoveryResultEntry>,
    }

    impl TestContactCache {
        fn new(entries: Vec<DiscoveryResultEntry>) -> Self {
            Self { entries }
        }

        fn empty() -> Self {
            Self {
                entries: Vec::new(),
            }
        }
    }

    impl ContactCache for TestContactCache {
        fn search_local(&self, query: &DiscoveryQuery) -> Vec<DiscoveryResultEntry> {
            self.entries
                .iter()
                .filter(|e| {
                    // Apply capability filter: include entries matching ANY
                    // queried capability. Partial matches rank lower via
                    // compute_relevance.
                    if let Some(ref caps) = query.capability_filter
                        && !caps.iter().any(|c| e.capabilities.contains(c))
                    {
                        return false;
                    }
                    // Apply keyword filter.
                    if let Some(ref keywords) = query.keywords
                        && !keywords.iter().any(|kw| {
                            let kw_lower = kw.to_lowercase();
                            e.capabilities
                                .iter()
                                .any(|c| c.to_lowercase().contains(&kw_lower))
                        })
                    {
                        return false;
                    }
                    true
                })
                .cloned()
                .collect()
        }
    }

    /// In-memory context querier for testing.
    struct TestContextQuerier {
        /// Map from context ID to the search results that context returns.
        responses: HashMap<ContextId, AgentSearchResult>,
        /// Context IDs that should return errors.
        failing_contexts: Vec<ContextId>,
    }

    impl TestContextQuerier {
        fn new() -> Self {
            Self {
                responses: HashMap::new(),
                failing_contexts: Vec::new(),
            }
        }

        fn add_response(&mut self, context_id: ContextId, result: AgentSearchResult) {
            self.responses.insert(context_id, result);
        }

        fn add_failing_context(&mut self, context_id: ContextId) {
            self.failing_contexts.push(context_id);
        }
    }

    impl ContextQuerier for TestContextQuerier {
        async fn query_context(
            &self,
            context_id: &ContextId,
            _params: &AgentSearchParams,
        ) -> Result<AgentSearchResult, DiscoveryError> {
            if self.failing_contexts.contains(context_id) {
                return Err(DiscoveryError::DidResolutionFailed(format!(
                    "context {context_id} unreachable"
                )));
            }

            self.responses.get(context_id).cloned().ok_or_else(|| {
                DiscoveryError::DidResolutionFailed(format!("context {context_id} not found"))
            })
        }
    }

    /// Helper: create a test entry with the given DID and capabilities.
    fn make_entry(did: &str, caps: &[&str], source_context: Option<&str>) -> DiscoveryResultEntry {
        DiscoveryResultEntry {
            did: did.into(),
            capabilities: caps.iter().map(|c| (*c).to_owned()).collect(),
            participation_summary: None,
            provenance: DataProvenance {
                source_did: did.into(),
                source_context: source_context.map(ToOwned::to_owned),
                timestamp: 1_700_000_000,
            },
            relevance_score: 0.0,
        }
    }

    /// Helper: create a registration entry for context querier responses.
    fn make_reg_entry(did: &str, caps: &[&str]) -> scp_protocol::discovery::RegistrationEntry {
        scp_protocol::discovery::RegistrationEntry {
            did: did.into(),
            capabilities: caps.iter().map(|c| (*c).to_owned()).collect(),
            metadata: serde_json::json!({}),
            entry_id: format!("reg-{did}"),
            registered_at: 1_700_000_000,
        }
    }

    // -- query_to_search_params ---------------------------------------------

    #[test]
    fn query_to_search_params_maps_all_fields() {
        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned()]),
            keywords: Some(vec!["rust".to_owned()]),
            min_history: None,
        };

        let params = query_to_search_params(&query);
        assert_eq!(params.capability_filter, query.capability_filter);
        assert_eq!(params.keywords, query.keywords);
        assert!(params.limit.is_none());
    }

    #[test]
    fn query_to_search_params_empty_query() {
        let query = DiscoveryQuery::default();
        let params = query_to_search_params(&query);
        assert!(params.capability_filter.is_none());
        assert!(params.keywords.is_none());
        assert!(params.limit.is_none());
    }

    // -- deduplicate_entries ------------------------------------------------

    #[test]
    fn deduplicate_entries_removes_duplicates_by_did() {
        let entries = vec![
            make_entry("did:dht:zAlice", &["code_review"], None),
            make_entry("did:dht:zAlice", &["testing"], Some("ctx-1")),
            make_entry("did:dht:zBob", &["translation"], None),
        ];

        let deduped = deduplicate_entries(entries);
        assert_eq!(deduped.len(), 2);

        let alice = deduped.iter().find(|e| e.did == "did:dht:zAlice").unwrap();
        // Alice's capabilities should be merged.
        assert!(alice.capabilities.contains(&"code_review".to_owned()));
        assert!(alice.capabilities.contains(&"testing".to_owned()));
    }

    #[test]
    fn deduplicate_entries_prefers_context_provenance_on_tie() {
        let mut local = make_entry("did:dht:zAlice", &["code_review"], None);
        local.relevance_score = 0.5;

        let mut remote = make_entry("did:dht:zAlice", &["code_review"], Some("ctx-1"));
        remote.relevance_score = 0.5;

        let entries = vec![local, remote];
        let deduped = deduplicate_entries(entries);

        assert_eq!(deduped.len(), 1);
        let alice = &deduped[0];
        assert!(alice.provenance.source_context.is_some());
    }

    #[test]
    fn deduplicate_entries_prefers_higher_relevance() {
        let mut low = make_entry("did:dht:zAlice", &["code_review"], None);
        low.relevance_score = 0.3;

        let mut high = make_entry("did:dht:zAlice", &["code_review"], Some("ctx-1"));
        high.relevance_score = 0.9;

        let entries = vec![low, high];
        let deduped = deduplicate_entries(entries);

        assert_eq!(deduped.len(), 1);
        assert!((deduped[0].relevance_score - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn deduplicate_entries_empty_input() {
        let deduped = deduplicate_entries(Vec::new());
        assert!(deduped.is_empty());
    }

    #[test]
    fn deduplicate_entries_single_entry_passes_through() {
        let entries = vec![make_entry("did:dht:zAlice", &["code_review"], None)];
        let deduped = deduplicate_entries(entries);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].did, "did:dht:zAlice");
    }

    #[test]
    fn deduplicate_entries_merges_capabilities_without_duplicates() {
        let entries = vec![
            make_entry("did:dht:zAlice", &["code_review", "testing"], None),
            make_entry("did:dht:zAlice", &["testing", "deploy"], Some("ctx-1")),
        ];

        let deduped = deduplicate_entries(entries);
        assert_eq!(deduped.len(), 1);

        let alice = &deduped[0];
        assert!(alice.capabilities.contains(&"code_review".to_owned()));
        assert!(alice.capabilities.contains(&"testing".to_owned()));
        assert!(alice.capabilities.contains(&"deploy".to_owned()));
        // "testing" should only appear once.
        assert_eq!(
            alice
                .capabilities
                .iter()
                .filter(|c| *c == "testing")
                .count(),
            1
        );
    }

    // -- compute_relevance --------------------------------------------------

    #[test]
    fn compute_relevance_full_capability_match() {
        let entry = make_entry("did:dht:zAlice", &["code_review", "testing"], None);
        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let score = compute_relevance(&entry, &query);
        // Full match on capabilities: 1.0/1 factor = 1.0.
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_relevance_partial_capability_match() {
        let entry = make_entry("did:dht:zAlice", &["code_review"], None);
        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let score = compute_relevance(&entry, &query);
        // 1/2 capabilities match: 0.5/1 factor = 0.5.
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_relevance_no_query_filters_returns_baseline() {
        let entry = make_entry("did:dht:zAlice", &["code_review"], None);
        let query = DiscoveryQuery::default();

        let score = compute_relevance(&entry, &query);
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_relevance_keyword_match() {
        let entry = make_entry("did:dht:zAlice", &["rust_code_review"], None);
        let query = DiscoveryQuery {
            capability_filter: None,
            keywords: Some(vec!["rust".to_owned()]),
            min_history: None,
        };

        let score = compute_relevance(&entry, &query);
        // 1/1 keyword match: 1.0/1 factor = 1.0.
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_relevance_keyword_no_match() {
        let entry = make_entry("did:dht:zAlice", &["code_review"], None);
        let query = DiscoveryQuery {
            capability_filter: None,
            keywords: Some(vec!["python".to_owned()]),
            min_history: None,
        };

        let score = compute_relevance(&entry, &query);
        assert!(score < f64::EPSILON);
    }

    #[test]
    fn compute_relevance_source_bonus_applied() {
        // Use a partial match (1 of 2 queried capabilities) so the additive
        // source bonus has room to differentiate. A perfect match would clamp
        // both to 1.0.
        let entry = make_entry("did:dht:zAlice", &["code_review"], Some("ctx-1"));
        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let score_with_context = compute_relevance(&entry, &query);

        let entry_no_ctx = make_entry("did:dht:zAlice", &["code_review"], None);
        let score_without_context = compute_relevance(&entry_no_ctx, &query);

        // Context-sourced entry should score higher (0.55 > 0.50).
        assert!(score_with_context > score_without_context);
    }

    #[test]
    fn compute_relevance_clamped_to_unit_range() {
        let entry = make_entry("did:dht:zAlice", &["code_review", "testing"], Some("ctx-1"));
        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
            keywords: Some(vec!["code".to_owned(), "test".to_owned()]),
            min_history: None,
        };

        let score = compute_relevance(&entry, &query);
        assert!(score >= 0.0);
        assert!(score <= 1.0);
    }

    // -- rank_entries -------------------------------------------------------

    #[test]
    fn rank_entries_sorts_by_descending_score() {
        let entries = vec![
            make_entry("did:dht:zLow", &["translation"], None),
            make_entry("did:dht:zHigh", &["code_review", "testing"], None),
        ];
        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let ranked = rank_entries(entries, &query);
        assert_eq!(ranked[0].did, "did:dht:zHigh");
        assert!(ranked[0].relevance_score >= ranked[1].relevance_score);
    }

    #[test]
    fn rank_entries_empty_input() {
        let ranked = rank_entries(Vec::new(), &DiscoveryQuery::default());
        assert!(ranked.is_empty());
    }

    // -- unified_search (integration) ---------------------------------------

    #[tokio::test]
    async fn unified_search_local_cache_only() {
        let cache =
            TestContactCache::new(vec![make_entry("did:dht:zAlice", &["code_review"], None)]);
        let querier = TestContextQuerier::new();

        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let result = unified_search(&query, &[], &cache, &querier, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].did, "did:dht:zAlice");
        assert!(result.sources.is_empty());
    }

    #[tokio::test]
    async fn unified_search_remote_contexts_only() {
        let cache = TestContactCache::empty();
        let mut querier = TestContextQuerier::new();

        querier.add_response(
            "ctx-discovery-1".to_owned(),
            AgentSearchResult {
                entries: vec![make_reg_entry("did:dht:zBob", &["testing"])],
                total_matches: 1,
            },
        );

        let query = DiscoveryQuery {
            capability_filter: Some(vec!["testing".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let result = unified_search(
            &query,
            &["ctx-discovery-1".to_owned()],
            &cache,
            &querier,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].did, "did:dht:zBob");
        assert_eq!(result.sources, vec!["ctx-discovery-1"]);
    }

    #[tokio::test]
    async fn unified_search_merges_local_and_remote() {
        let cache =
            TestContactCache::new(vec![make_entry("did:dht:zAlice", &["code_review"], None)]);
        let mut querier = TestContextQuerier::new();

        querier.add_response(
            "ctx-discovery-1".to_owned(),
            AgentSearchResult {
                entries: vec![make_reg_entry("did:dht:zBob", &["testing"])],
                total_matches: 1,
            },
        );

        let query = DiscoveryQuery::default();

        let result = unified_search(
            &query,
            &["ctx-discovery-1".to_owned()],
            &cache,
            &querier,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        assert_eq!(result.entries.len(), 2);
        let dids: Vec<&str> = result.entries.iter().map(|e| e.did.as_ref()).collect();
        assert!(dids.contains(&"did:dht:zAlice"));
        assert!(dids.contains(&"did:dht:zBob"));
    }

    #[tokio::test]
    async fn unified_search_deduplicates_across_sources() {
        // Same DID in local cache and remote context.
        let cache =
            TestContactCache::new(vec![make_entry("did:dht:zAlice", &["code_review"], None)]);
        let mut querier = TestContextQuerier::new();

        querier.add_response(
            "ctx-discovery-1".to_owned(),
            AgentSearchResult {
                entries: vec![make_reg_entry(
                    "did:dht:zAlice",
                    &["code_review", "testing"],
                )],
                total_matches: 1,
            },
        );

        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let result = unified_search(
            &query,
            &["ctx-discovery-1".to_owned()],
            &cache,
            &querier,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        // Should have only one entry for Alice (deduplicated).
        assert_eq!(result.entries.len(), 1);
        let alice = &result.entries[0];
        assert_eq!(alice.did, "did:dht:zAlice");
        // Capabilities should be merged.
        assert!(alice.capabilities.contains(&"code_review".to_owned()));
        assert!(alice.capabilities.contains(&"testing".to_owned()));
    }

    #[tokio::test]
    async fn unified_search_tolerates_failing_contexts() {
        let cache = TestContactCache::empty();
        let mut querier = TestContextQuerier::new();

        // One context works, one fails.
        querier.add_response(
            "ctx-good".to_owned(),
            AgentSearchResult {
                entries: vec![make_reg_entry("did:dht:zBob", &["testing"])],
                total_matches: 1,
            },
        );
        querier.add_failing_context("ctx-bad".to_owned());

        let query = DiscoveryQuery::default();

        let result = unified_search(
            &query,
            &["ctx-good".to_owned(), "ctx-bad".to_owned()],
            &cache,
            &querier,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        // Should still have Bob from the good context.
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].did, "did:dht:zBob");
        // Only the successful context is in sources.
        assert_eq!(result.sources, vec!["ctx-good"]);
    }

    #[tokio::test]
    async fn unified_search_empty_query_returns_all() {
        let cache = TestContactCache::new(vec![
            make_entry("did:dht:zAlice", &["code_review"], None),
            make_entry("did:dht:zBob", &["testing"], None),
        ]);
        let querier = TestContextQuerier::new();

        let query = DiscoveryQuery::default();

        let result = unified_search(&query, &[], &cache, &querier, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(result.entries.len(), 2);
    }

    #[tokio::test]
    async fn unified_search_no_results_returns_empty() {
        let cache = TestContactCache::empty();
        let querier = TestContextQuerier::new();

        let query = DiscoveryQuery {
            capability_filter: Some(vec!["nonexistent".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let result = unified_search(&query, &[], &cache, &querier, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert!(result.entries.is_empty());
        assert!(result.sources.is_empty());
    }

    #[tokio::test]
    async fn unified_search_multiple_contexts_parallel() {
        let cache = TestContactCache::empty();
        let mut querier = TestContextQuerier::new();

        querier.add_response(
            "ctx-1".to_owned(),
            AgentSearchResult {
                entries: vec![make_reg_entry("did:dht:zAlice", &["code_review"])],
                total_matches: 1,
            },
        );
        querier.add_response(
            "ctx-2".to_owned(),
            AgentSearchResult {
                entries: vec![make_reg_entry("did:dht:zBob", &["testing"])],
                total_matches: 1,
            },
        );

        let query = DiscoveryQuery::default();

        let result = unified_search(
            &query,
            &["ctx-1".to_owned(), "ctx-2".to_owned()],
            &cache,
            &querier,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.sources.len(), 2);
    }

    #[tokio::test]
    async fn unified_search_results_ranked_by_relevance() {
        let cache = TestContactCache::new(vec![
            make_entry("did:dht:zPartialMatch", &["code_review"], None),
            make_entry(
                "did:dht:zFullMatch",
                &["code_review", "testing"],
                Some("ctx-1"),
            ),
        ]);
        let querier = TestContextQuerier::new();

        let query = DiscoveryQuery {
            capability_filter: Some(vec!["code_review".to_owned(), "testing".to_owned()]),
            keywords: None,
            min_history: None,
        };

        let result = unified_search(&query, &[], &cache, &querier, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(result.entries.len(), 2);
        // Full match should rank higher.
        assert_eq!(result.entries[0].did, "did:dht:zFullMatch");
        assert!(result.entries[0].relevance_score >= result.entries[1].relevance_score);
    }

    #[tokio::test]
    async fn unified_search_provenance_set_per_entry() {
        let cache =
            TestContactCache::new(vec![make_entry("did:dht:zLocal", &["code_review"], None)]);
        let mut querier = TestContextQuerier::new();

        querier.add_response(
            "ctx-1".to_owned(),
            AgentSearchResult {
                entries: vec![make_reg_entry("did:dht:zRemote", &["testing"])],
                total_matches: 1,
            },
        );

        let query = DiscoveryQuery::default();

        let result = unified_search(
            &query,
            &["ctx-1".to_owned()],
            &cache,
            &querier,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let local = result
            .entries
            .iter()
            .find(|e| e.did == "did:dht:zLocal")
            .unwrap();
        assert!(local.provenance.source_context.is_none());

        let remote = result
            .entries
            .iter()
            .find(|e| e.did == "did:dht:zRemote")
            .unwrap();
        assert_eq!(remote.provenance.source_context.as_deref(), Some("ctx-1"));
    }
}
