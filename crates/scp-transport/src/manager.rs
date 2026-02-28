//! Multi-adapter transport manager.
//!
//! [`TransportManager`] holds one or more [`TransportAdapter`] instances and
//! provides a unified interface for sending, subscribing, querying, and
//! deleting envelopes across all registered adapters.
//!
//! **Phase 1:** single adapter support (SCP native relay).
//! **Phase 2:** multi-adapter routing with per-context relay set assignment,
//! suppression-resistant multi-relay publishing (3+ relays per context), and
//! deduplicated merged subscription streams.
//!
//! See ADR-005 in `.docs/adrs/phase-1.md` for the original transport manager
//! design and ADR-012 in `.docs/adrs/phase-2.md` for multi-transport routing.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt};
use lru::LruCache;
use scp_core::envelope::OuterEnvelope;

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::scoring::{
    self, DeliveryOutcome, ReliabilityScore, SuppressionTracker, SuppressionWarning,
};
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// Context identifier — a string alias matching the project-wide convention.
///
/// Each module in `scp-core` defines its own `ContextId = String` type alias.
/// We follow the same pattern here to avoid an inter-module coupling dependency
/// for what is fundamentally a `String`.
pub type ContextId = String;

/// Default deduplication cache capacity (number of entries).
const DEFAULT_DEDUP_CAPACITY: usize = 10_000;

/// Default deduplication cache entry TTL.
const DEFAULT_DEDUP_TTL: Duration = Duration::from_secs(3600);

/// Minimum number of relays required per context for suppression resistance.
///
/// Publishing to fewer than this many relays gives individual relays veto
/// power over message delivery (spec section 9.9.2).
const MIN_RELAYS_PER_CONTEXT: usize = 3;

/// Minimum number of successful relay deliveries required for a send to
/// succeed. If fewer than this many relays accept the envelope, the send
/// returns an error (insufficient redundancy).
const MIN_SUCCESSFUL_SENDS: usize = 2;

/// Multi-adapter transport manager.
///
/// Holds multiple [`TransportAdapter`] instances and routes operations
/// through them based on per-context relay set assignments. Each context is
/// assigned a set of at least 3 relays for suppression resistance.
///
/// # Phase 2 Features
///
/// - **Multi-relay publishing:** `send_to_context` sends envelopes to ALL
///   relays in a context's relay set concurrently. At least 2 must succeed.
/// - **Merged subscription streams:** `subscribe_context` merges streams
///   from all relays in a context's relay set, deduplicated by `BlobId`
///   using an LRU cache with configurable TTL.
/// - **Relay set assignment:** `assign_relay_set` distributes contexts
///   across relays with round-robin spread to minimize overlap.
/// - **Reliability scoring:** Per-relay delivery success tracking.
///
/// # Construction
///
/// Use [`TransportManager::new`] for Phase 1 single-adapter mode, or
/// [`TransportManager::with_config`] for full Phase 2 configuration.
///
/// See ADR-012 in `.docs/adrs/phase-2.md` for the full design.
pub struct TransportManager {
    /// Registered transport adapters, in insertion order.
    adapters: Vec<Box<dyn TransportAdapter>>,
    /// Per-context relay set assignments: context -> adapter indices.
    /// Wrapped in `RwLock` for interior mutability so that `send_to_context`
    /// and `assign_relay_set` can take `&self`, enabling concurrent sends.
    relay_assignments: RwLock<HashMap<ContextId, Vec<usize>>>,
    /// Per-relay reliability scores keyed by adapter index (as string).
    /// Shared with `MergedStream` so suppression downgrades apply immediately.
    reliability_scores: Arc<Mutex<HashMap<String, ReliabilityScore>>>,
    /// Deduplication cache: maps `BlobId` to the time it was first seen.
    dedup_cache: LruCache<BlobId, Instant>,
    /// TTL for deduplication cache entries.
    dedup_ttl: Duration,
    /// Round-robin counter for relay assignment spread.
    /// Atomic for interior mutability without locking.
    assignment_counter: AtomicUsize,
    /// Multi-relay suppression cross-check tracker (spec section 9.9.2).
    /// Shared with `MergedStream` for recording deliveries and checking
    /// suppressions during stream polling.
    suppression_tracker: Arc<Mutex<SuppressionTracker>>,
    /// Per-relay cost for cost-aware relay selection (section 19.8).
    ///
    /// Maps adapter index to per-publish cost (`Amount.value()`). Relays
    /// without an entry are treated as free (cost = 0). Cost is the third
    /// criterion in relay selection alongside reliability and latency.
    relay_costs: RwLock<HashMap<usize, u64>>,
}

/// Helper to create a `NonZeroUsize` for LRU capacity, falling back to 1.
fn nonzero_capacity(size: usize) -> std::num::NonZeroUsize {
    std::num::NonZeroUsize::new(size).unwrap_or(std::num::NonZeroUsize::MIN)
}

impl TransportManager {
    /// Creates a new `TransportManager` with a single adapter.
    ///
    /// This is the Phase 1 constructor. The provided adapter is used for
    /// all operations. For Phase 2 multi-adapter configuration, use
    /// [`TransportManager::with_config`].
    #[must_use]
    pub fn new(adapter: Box<dyn TransportAdapter>) -> Self {
        Self {
            adapters: vec![adapter],
            relay_assignments: RwLock::new(HashMap::new()),
            reliability_scores: Arc::new(Mutex::new(HashMap::new())),
            dedup_cache: LruCache::new(nonzero_capacity(DEFAULT_DEDUP_CAPACITY)),
            dedup_ttl: DEFAULT_DEDUP_TTL,
            assignment_counter: AtomicUsize::new(0),
            suppression_tracker: Arc::new(Mutex::new(SuppressionTracker::new())),
            relay_costs: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new `TransportManager` with no adapters.
    ///
    /// Use [`add_adapter`](TransportManager::add_adapter) to register
    /// adapters before performing any operations.
    #[must_use]
    pub fn builder() -> Self {
        Self {
            adapters: Vec::new(),
            relay_assignments: RwLock::new(HashMap::new()),
            reliability_scores: Arc::new(Mutex::new(HashMap::new())),
            dedup_cache: LruCache::new(nonzero_capacity(DEFAULT_DEDUP_CAPACITY)),
            dedup_ttl: DEFAULT_DEDUP_TTL,
            assignment_counter: AtomicUsize::new(0),
            suppression_tracker: Arc::new(Mutex::new(SuppressionTracker::new())),
            relay_costs: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new `TransportManager` with the given configuration.
    ///
    /// Uses the dedup cache size and TTL from the [`TransportConfig`].
    #[must_use]
    pub fn with_config(config: &TransportConfig) -> Self {
        Self {
            adapters: Vec::new(),
            relay_assignments: RwLock::new(HashMap::new()),
            reliability_scores: Arc::new(Mutex::new(HashMap::new())),
            dedup_cache: LruCache::new(nonzero_capacity(config.dedup_cache_size)),
            dedup_ttl: config.dedup_cache_ttl,
            assignment_counter: AtomicUsize::new(0),
            suppression_tracker: Arc::new(Mutex::new(SuppressionTracker::new())),
            relay_costs: RwLock::new(HashMap::new()),
        }
    }

    /// Registers an additional transport adapter.
    ///
    /// The adapter is appended to the end of the adapter list. Its index
    /// is used as the identifier for relay set assignments and reliability
    /// scoring.
    pub fn add_adapter(&mut self, adapter: Box<dyn TransportAdapter>) {
        let idx = self.adapters.len();
        if let Ok(mut scores) = self.reliability_scores.lock() {
            scores.insert(idx.to_string(), ReliabilityScore::new(idx.to_string()));
        }
        self.adapters.push(adapter);
    }

    /// Returns the number of registered adapters.
    #[must_use]
    pub fn adapter_count(&self) -> usize {
        self.adapters.len()
    }

    /// Send an outer envelope through the registered adapters.
    ///
    /// **Phase 1:** Routes through the first adapter only.
    /// **Phase 2+:** Use [`send_to_context`](TransportManager::send_to_context)
    /// for multi-relay fanout.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Propagates errors from the underlying adapter.
    pub async fn send(&self, envelope: &OuterEnvelope) -> Result<BlobId, TransportError> {
        let adapter = self.adapters.first().ok_or(TransportError::NotConnected)?;
        adapter.send(envelope).await
    }

    /// Send an envelope to all relays assigned to a context.
    ///
    /// Looks up the relay set for the given `context_id`, sends the envelope
    /// to ALL relays concurrently via [`FuturesUnordered`], and returns a
    /// `BlobId` per successful relay. If fewer than 2 relays succeed, returns
    /// an error indicating insufficient redundancy.
    ///
    /// Records delivery success/failure per relay for reliability scoring.
    ///
    /// See ADR-012 acceptance criterion 2.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered
    /// or no relay set is assigned to the context.
    /// Returns [`TransportError::SendFailed`] if fewer than 2 relays succeed.
    pub async fn send_to_context(
        &self,
        envelope: &OuterEnvelope,
        context_id: &ContextId,
    ) -> Result<Vec<BlobId>, TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let relay_indices = self
            .relay_assignments
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(context_id)
            .ok_or_else(|| {
                TransportError::SendFailed(format!(
                    "no relay set assigned for context {context_id}"
                ))
            })?
            .clone();

        // Send to all relays concurrently.
        let mut futures: FuturesUnordered<_> = relay_indices
            .iter()
            .filter_map(|&idx| {
                self.adapters
                    .get(idx)
                    .map(|adapter| async move { (idx, adapter.send(envelope).await) })
            })
            .collect();

        let mut successes: Vec<BlobId> = Vec::new();
        let mut outcomes: Vec<(usize, bool)> = Vec::new();

        while let Some((idx, result)) = futures.next().await {
            match result {
                Ok(blob_id) => {
                    successes.push(blob_id);
                    outcomes.push((idx, true));
                }
                Err(_) => {
                    outcomes.push((idx, false));
                }
            }
        }

        // Record delivery outcomes for reliability scoring via EMA.
        if let Ok(mut scores) = self.reliability_scores.lock() {
            for (idx, success) in outcomes {
                let key = idx.to_string();
                let outcome = if success {
                    DeliveryOutcome::Success { latency_ms: 0 }
                } else {
                    DeliveryOutcome::Failure
                };
                scoring::update_score(&mut scores, &key, outcome);
            }
        }

        if successes.len() < MIN_SUCCESSFUL_SENDS {
            return Err(TransportError::SendFailed(format!(
                "insufficient redundancy: only {} of {} relays accepted the envelope (minimum {})",
                successes.len(),
                relay_indices.len(),
                MIN_SUCCESSFUL_SENDS,
            )));
        }

        Ok(successes)
    }

    /// Subscribe to envelopes for a given routing ID across all adapters.
    ///
    /// Returns a merged stream that yields [`TransportEvent`]s from all
    /// registered adapters. Envelope events are deduplicated by [`BlobId`]
    /// using an LRU cache with configurable capacity and TTL.
    ///
    /// **Phase 1:** With a single adapter, the stream is passed through
    /// directly (no merging or deduplication needed).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Returns [`TransportError::SubscriptionFailed`] if any adapter's
    /// subscription fails.
    pub async fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<SubscriptionStream, TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        // Collect subscription streams from all adapters with their indices.
        let mut indexed_streams: Vec<(usize, SubscriptionStream)> =
            Vec::with_capacity(self.adapters.len());

        for (idx, adapter) in self.adapters.iter().enumerate() {
            let stream = adapter.subscribe(routing_id, since).await?;
            indexed_streams.push((idx, stream));
        }

        // Phase 1 optimization: single adapter, no merging needed.
        if indexed_streams.len() == 1
            && let Some((_idx, stream)) = indexed_streams.pop()
        {
            return Ok(stream);
        }

        // Phase 2: merge streams with LRU + TTL deduplication by BlobId.
        let total_relays = indexed_streams.len();
        let dedup_capacity = self.dedup_cache.cap();
        let merged = MergedStream::new(
            indexed_streams,
            dedup_capacity,
            self.dedup_ttl,
            Arc::clone(&self.suppression_tracker),
            Arc::clone(&self.reliability_scores),
            total_relays,
        );
        Ok(Box::pin(merged))
    }

    /// Subscribe to envelopes for a routing ID on all relays assigned to a
    /// context.
    ///
    /// Subscribes on all relays in the context's relay set, then merges the
    /// streams into a single deduplicated stream. Deduplication uses an LRU
    /// cache (10K capacity) with configurable TTL (default 1 hour).
    ///
    /// See ADR-012 acceptance criterion 3.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered
    /// or no relay set is assigned to the context.
    /// Returns [`TransportError::SubscriptionFailed`] if any adapter's
    /// subscription fails.
    pub async fn subscribe_context(
        &self,
        routing_id: &RoutingId,
        context_id: &ContextId,
        since: Option<u64>,
    ) -> Result<SubscriptionStream, TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let relay_indices = self
            .relay_assignments
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(context_id)
            .ok_or_else(|| {
                TransportError::SubscriptionFailed(format!(
                    "no relay set assigned for context {context_id}"
                ))
            })?
            .clone();

        let mut indexed_streams: Vec<(usize, SubscriptionStream)> =
            Vec::with_capacity(relay_indices.len());
        for &idx in &relay_indices {
            if let Some(adapter) = self.adapters.get(idx) {
                let stream = adapter.subscribe(routing_id, since).await?;
                indexed_streams.push((idx, stream));
            }
        }

        if indexed_streams.is_empty() {
            return Err(TransportError::NotConnected);
        }

        // Single relay optimization: no merging needed.
        if indexed_streams.len() == 1
            && let Some((_idx, stream)) = indexed_streams.pop()
        {
            return Ok(stream);
        }

        let total_relays = indexed_streams.len();
        let dedup_capacity = self.dedup_cache.cap();
        let merged = MergedStream::new(
            indexed_streams,
            dedup_capacity,
            self.dedup_ttl,
            Arc::clone(&self.suppression_tracker),
            Arc::clone(&self.reliability_scores),
            total_relays,
        );
        Ok(Box::pin(merged))
    }

    /// Unsubscribe from a routing ID across all adapters.
    ///
    /// Sends an unsubscribe request to every registered adapter. If any
    /// adapter fails, the first error is returned after attempting all
    /// adapters.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Returns the first error encountered from any adapter.
    pub async fn unsubscribe(&self, routing_id: &RoutingId) -> Result<(), TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let mut first_error: Option<TransportError> = None;
        for adapter in &self.adapters {
            if let Err(e) = adapter.unsubscribe(routing_id).await
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// One-shot query for stored envelopes across all adapters.
    ///
    /// **Phase 1:** Queries the first adapter only.
    /// **Phase 2+:** Queries all adapters and merges results with
    /// deduplication.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Propagates errors from the underlying adapter.
    pub async fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let adapter = self.adapters.first().ok_or(TransportError::NotConnected)?;
        adapter.query(routing_id, since).await
    }

    /// Request deletion of a blob across all adapters.
    ///
    /// Sends a delete request to every registered adapter. Best-effort:
    /// untrusted transports may ignore the request. If any adapter fails,
    /// the first error is returned after attempting all adapters.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Returns the first error encountered from any adapter.
    pub async fn delete(&self, blob_id: &BlobId) -> Result<(), TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let mut first_error: Option<TransportError> = None;
        for adapter in &self.adapters {
            if let Err(e) = adapter.delete(blob_id).await
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Assigns a relay set for a context.
    ///
    /// Selects at least [`MIN_RELAYS_PER_CONTEXT`] (3) adapters per context
    /// using round-robin spread to minimize overlap between contexts' relay
    /// sets. Prefers adapters with higher reliability scores.
    ///
    /// The assigned relay set is stored in `relay_assignments` and returned
    /// as a vector of adapter indices.
    ///
    /// See ADR-012 acceptance criterion 4.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    pub fn assign_relay_set(&self, context_id: &ContextId) -> Result<Vec<usize>, TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let adapter_count = self.adapters.len();
        let set_size = MIN_RELAYS_PER_CONTEXT.min(adapter_count);

        // Build a list of adapter indices sorted by:
        //   (overlap count ASC, reliability score DESC, cost ASC,
        //    round-robin offset ASC).
        // This prefers adapters least used by other contexts, with higher
        // reliability, and lower cost. Cost is the third criterion per
        // section 19.8: agents prefer cheaper relays, creating market
        // pressure.
        let scores = self
            .reliability_scores
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let assignments = self
            .relay_assignments
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let costs = self.relay_costs.read().unwrap_or_else(|e| e.into_inner());
        let mut candidates: Vec<(usize, usize, f64, u64)> = (0..adapter_count)
            .map(|idx| {
                let overlap = assignments
                    .values()
                    .filter(|set| set.contains(&idx))
                    .count();
                let reliability = scores
                    .get(&idx.to_string())
                    .map_or(1.0, ReliabilityScore::composite_score);
                let cost = costs.get(&idx).copied().unwrap_or(0);
                (idx, overlap, reliability, cost)
            })
            .collect();
        drop(scores);
        drop(assignments);
        drop(costs);

        let counter = self
            .assignment_counter
            .fetch_add(set_size, Ordering::Relaxed);
        candidates.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.3.cmp(&b.3))
                .then_with(|| {
                    // Round-robin offset for spread.
                    let a_off = (a.0 + adapter_count - counter % adapter_count) % adapter_count;
                    let b_off = (b.0 + adapter_count - counter % adapter_count) % adapter_count;
                    a_off.cmp(&b_off)
                })
        });

        let assigned: Vec<usize> = candidates
            .iter()
            .take(set_size)
            .map(|(idx, _, _, _)| *idx)
            .collect();

        self.relay_assignments
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(context_id.clone(), assigned.clone());

        Ok(assigned)
    }

    /// Returns the relay set currently assigned to a context, if any.
    #[must_use]
    pub fn get_relay_set(&self, context_id: &ContextId) -> Option<Vec<usize>> {
        self.relay_assignments
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(context_id)
            .cloned()
    }

    /// Returns the reliability score for an adapter by index.
    ///
    /// Returns a clone of the score to avoid holding the lock.
    #[must_use]
    pub fn get_reliability_score(&self, adapter_index: usize) -> Option<ReliabilityScore> {
        let scores = self
            .reliability_scores
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        scores.get(&adapter_index.to_string()).cloned()
    }

    /// Updates the reliability score for a relay after an operation.
    ///
    /// Delegates to [`scoring::update_score`] which applies exponential
    /// moving average (EMA) decay so that recent behavior weighs more than
    /// historical.
    ///
    /// See ADR-012 acceptance criterion 5.
    pub fn update_score(&self, relay_url: &str, outcome: DeliveryOutcome) {
        let mut scores = self
            .reliability_scores
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        scoring::update_score(&mut scores, relay_url, outcome);
    }

    /// Returns the current reliability score for a relay URL.
    ///
    /// Returns a clone of the score to avoid holding the lock.
    #[must_use]
    pub fn get_score(&self, relay_url: &str) -> Option<ReliabilityScore> {
        let scores = self
            .reliability_scores
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        scores.get(relay_url).cloned()
    }

    /// Returns a shared reference to the suppression tracker.
    #[must_use]
    pub fn suppression_tracker(&self) -> Arc<Mutex<SuppressionTracker>> {
        Arc::clone(&self.suppression_tracker)
    }

    /// Returns a shared reference to the reliability scores.
    #[must_use]
    pub fn reliability_scores(&self) -> Arc<Mutex<HashMap<String, ReliabilityScore>>> {
        Arc::clone(&self.reliability_scores)
    }

    /// Sets the per-publish cost for an adapter by index.
    ///
    /// The cost is used as the third criterion in relay selection
    /// (section 19.8): agents prefer cheaper relays, creating market
    /// pressure. Cost is specified as a raw `u64` value in the smallest
    /// currency unit (matching `Amount::value()`).
    ///
    /// A cost of 0 or absence of a cost entry means the relay is free.
    pub fn set_relay_cost(&self, adapter_index: usize, cost: u64) {
        let mut costs = self.relay_costs.write().unwrap_or_else(|e| e.into_inner());
        costs.insert(adapter_index, cost);
    }

    /// Returns the per-publish cost for an adapter by index.
    ///
    /// Returns `0` if no cost has been set (free relay).
    #[must_use]
    pub fn get_relay_cost(&self, adapter_index: usize) -> u64 {
        let costs = self.relay_costs.read().unwrap_or_else(|e| e.into_inner());
        costs.get(&adapter_index).copied().unwrap_or(0)
    }
}

/// Interval between periodic suppression cross-check calls during stream polling.
const SUPPRESSION_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// A merged stream that combines multiple adapter subscription streams with
/// deduplication by [`BlobId`] for [`TransportEvent::Envelope`] variants.
///
/// Uses an LRU cache with configurable capacity and TTL for deduplication.
/// Entries older than the TTL are treated as expired, allowing the same
/// `BlobId` to be delivered again if it arrives after the TTL window.
///
/// Records per-adapter deliveries in the shared [`SuppressionTracker`] and
/// periodically checks for suppression, emitting
/// [`TransportEvent::SuppressionDetected`] events and downgrading relay
/// reliability scores when suppression is detected.
///
/// Control events ([`BackfillComplete`](TransportEvent::BackfillComplete),
/// [`Reconnected`](TransportEvent::Reconnected),
/// [`Terminated`](TransportEvent::Terminated),
/// [`Error`](TransportEvent::Error)) are passed through per-adapter without
/// deduplication.
struct MergedStream {
    /// The underlying adapter streams being merged, paired with their adapter
    /// indices for suppression tracking.
    streams: Vec<(usize, SubscriptionStream)>,
    /// LRU cache of `BlobId`s already yielded, with timestamps for TTL expiry.
    seen: LruCache<BlobId, Instant>,
    /// TTL for deduplication cache entries.
    ttl: Duration,
    /// Shared suppression tracker for recording deliveries and checking
    /// suppressions across relays.
    suppression_tracker: Arc<Mutex<SuppressionTracker>>,
    /// Shared reliability scores for downgrading on suppression detection.
    reliability_scores: Arc<Mutex<HashMap<String, ReliabilityScore>>>,
    /// Total number of relays in this context's relay set.
    total_relays: usize,
    /// Timestamp of the last suppression cross-check.
    last_suppression_check: Instant,
    /// Pending suppression warnings to emit as events.
    pending_warnings: Vec<SuppressionWarning>,
}

impl MergedStream {
    /// Creates a new `MergedStream` from multiple adapter streams with
    /// suppression tracking.
    fn new(
        indexed_streams: Vec<(usize, SubscriptionStream)>,
        capacity: std::num::NonZeroUsize,
        ttl: Duration,
        suppression_tracker: Arc<Mutex<SuppressionTracker>>,
        reliability_scores: Arc<Mutex<HashMap<String, ReliabilityScore>>>,
        total_relays: usize,
    ) -> Self {
        Self {
            streams: indexed_streams,
            seen: LruCache::new(capacity),
            ttl,
            suppression_tracker,
            reliability_scores,
            total_relays,
            last_suppression_check: Instant::now(),
            pending_warnings: Vec::new(),
        }
    }

    /// Checks if a `BlobId` has been seen recently (within TTL).
    ///
    /// Returns `true` if the blob was already seen and the entry has not
    /// expired. Returns `false` if the blob is new or its entry has expired.
    /// Inserts or refreshes the entry on return of `false`.
    fn is_duplicate(&mut self, blob_id: &BlobId) -> bool {
        let now = Instant::now();
        if let Some(timestamp) = self.seen.get(blob_id)
            && now.duration_since(*timestamp) < self.ttl
        {
            return true;
        }
        self.seen.put(*blob_id, now);
        false
    }

    /// Runs a periodic suppression check if the interval has elapsed.
    /// Returns any new suppression warnings and downgrade the flagged relays.
    #[allow(clippy::cast_possible_truncation)]
    fn check_suppressions_if_due(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_suppression_check) < SUPPRESSION_CHECK_INTERVAL {
            return;
        }
        self.last_suppression_check = now;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let warnings = if let Ok(mut tracker) = self.suppression_tracker.lock() {
            tracker.check_suppressions(now_ms, self.total_relays)
        } else {
            return;
        };

        if warnings.is_empty() {
            return;
        }

        // Downgrade reliability scores for adapters that failed to deliver.
        if let Ok(mut scores) = self.reliability_scores.lock() {
            for warning in &warnings {
                let all_adapters: std::collections::HashSet<usize> =
                    (0..self.total_relays).collect();
                for &missing_adapter in all_adapters.difference(&warning.delivered_by) {
                    let key = missing_adapter.to_string();
                    scoring::update_score(&mut scores, &key, DeliveryOutcome::Failure);
                }
            }
        }

        self.pending_warnings.extend(warnings);
    }
}

impl Stream for MergedStream {
    type Item = TransportEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Emit any pending suppression warnings before polling streams.
        if let Some(warning) = this.pending_warnings.pop() {
            cx.waker().wake_by_ref();
            return Poll::Ready(Some(TransportEvent::SuppressionDetected(warning)));
        }

        // Check for suppressions periodically.
        this.check_suppressions_if_due();
        if let Some(warning) = this.pending_warnings.pop() {
            cx.waker().wake_by_ref();
            return Poll::Ready(Some(TransportEvent::SuppressionDetected(warning)));
        }

        // Round-robin poll across all streams. Return the first ready item
        // that passes deduplication. If all streams are pending, return
        // Pending. If all streams are exhausted, return None.
        let mut all_done = true;
        let mut any_pending = false;

        for i in 0..this.streams.len() {
            let (adapter_index, stream) = &mut this.streams[i];
            let adapter_idx = *adapter_index;
            match stream.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    match &event {
                        TransportEvent::Envelope(envelope) => {
                            let blob_id = BlobId::from_sha256(&envelope.encrypted_blob);

                            // Record this delivery for suppression tracking,
                            // regardless of whether it's a duplicate.
                            if let Ok(mut tracker) = this.suppression_tracker.lock() {
                                #[allow(clippy::cast_possible_truncation)]
                                let now_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0);
                                tracker.record_delivery(blob_id, adapter_idx, now_ms);
                            }

                            if !this.is_duplicate(&blob_id) {
                                return Poll::Ready(Some(event));
                            }
                            // Duplicate -- skip and wake so we poll again.
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        // Control events are always passed through.
                        TransportEvent::Error(_)
                        | TransportEvent::BackfillComplete
                        | TransportEvent::Reconnected
                        | TransportEvent::Terminated { .. }
                        | TransportEvent::SuppressionDetected(_) => {
                            return Poll::Ready(Some(event));
                        }
                    }
                }
                Poll::Ready(None) => {
                    // This stream is exhausted.
                }
                Poll::Pending => {
                    all_done = false;
                    any_pending = true;
                }
            }
        }

        if all_done {
            Poll::Ready(None)
        } else if any_pending {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use futures::stream;
    use scp_core::envelope::create_outer_envelope;

    use super::*;

    /// A mock transport adapter for testing.
    struct MockAdapter {
        /// Result returned by `send()`.
        send_result: Result<BlobId, TransportError>,
        /// Envelopes returned by `query()`.
        query_result: Result<Vec<OuterEnvelope>, TransportError>,
        /// Stream returned by `subscribe()`.
        subscribe_events: Arc<Vec<TransportEvent>>,
    }

    impl MockAdapter {
        fn succeeding() -> Self {
            Self {
                send_result: Ok(BlobId::new([0xAA; 32])),
                query_result: Ok(Vec::new()),
                subscribe_events: Arc::new(Vec::new()),
            }
        }

        fn failing(error: TransportError) -> Self {
            Self {
                send_result: Err(error.clone()),
                query_result: Err(error),
                subscribe_events: Arc::new(Vec::new()),
            }
        }

        fn with_blob_id(blob_id: BlobId) -> Self {
            Self {
                send_result: Ok(blob_id),
                query_result: Ok(Vec::new()),
                subscribe_events: Arc::new(Vec::new()),
            }
        }
    }

    impl TransportAdapter for MockAdapter {
        fn send(&self, _envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
            let result = self.send_result.clone();
            Box::pin(async move { result })
        }

        fn subscribe(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
            let events = self.subscribe_events.clone();
            Box::pin(async move {
                let items: Vec<TransportEvent> = events
                    .iter()
                    .map(|e| match e {
                        TransportEvent::Envelope(env) => TransportEvent::Envelope(env.clone()),
                        TransportEvent::Error(err) => TransportEvent::Error(err.clone()),
                        TransportEvent::BackfillComplete => TransportEvent::BackfillComplete,
                        TransportEvent::Reconnected => TransportEvent::Reconnected,
                        TransportEvent::Terminated { reason } => TransportEvent::Terminated {
                            reason: reason.clone(),
                        },
                        TransportEvent::SuppressionDetected(w) => {
                            TransportEvent::SuppressionDetected(w.clone())
                        }
                    })
                    .collect();
                let s: SubscriptionStream = Box::pin(stream::iter(items));
                Ok(s)
            })
        }

        fn unsubscribe(
            &self,
            _routing_id: &RoutingId,
        ) -> BoxFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn query(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
            let result = self.query_result.clone();
            Box::pin(async move { result })
        }

        fn delete(&self, _blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Convenience type alias for the boxed future used in trait methods.
    type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    fn test_envelope() -> OuterEnvelope {
        create_outer_envelope(&[0xAA; 32], None, 3600, vec![0x01, 0x02, 0x03]).unwrap()
    }

    fn test_envelope_with_blob(blob: Vec<u8>) -> OuterEnvelope {
        create_outer_envelope(&[0xAA; 32], None, 3600, blob).unwrap()
    }

    // -----------------------------------------------------------------------
    // Phase 1 backward-compatibility tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn manager_new_has_one_adapter() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        assert_eq!(manager.adapter_count(), 1);
    }

    #[tokio::test]
    async fn manager_builder_starts_empty() {
        let manager = TransportManager::builder();
        assert_eq!(manager.adapter_count(), 0);
    }

    #[tokio::test]
    async fn manager_add_adapter_increments_count() {
        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::succeeding()));
        assert_eq!(manager.adapter_count(), 1);
        manager.add_adapter(Box::new(MockAdapter::succeeding()));
        assert_eq!(manager.adapter_count(), 2);
    }

    #[tokio::test]
    async fn manager_send_returns_blob_id() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        let envelope = test_envelope();
        let blob_id = manager.send(&envelope).await.unwrap();
        assert_eq!(blob_id, BlobId::new([0xAA; 32]));
    }

    #[tokio::test]
    async fn manager_send_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let envelope = test_envelope();
        let result = manager.send(&envelope).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_send_propagates_adapter_error() {
        let manager = TransportManager::new(Box::new(MockAdapter::failing(
            TransportError::SendFailed("mock failure".to_string()),
        )));
        let envelope = test_envelope();
        let result = manager.send(&envelope).await;
        assert!(matches!(result, Err(TransportError::SendFailed(_))));
    }

    #[tokio::test]
    async fn manager_query_returns_envelopes() {
        let mut adapter = MockAdapter::succeeding();
        let env = test_envelope();
        adapter.query_result = Ok(vec![env]);

        let manager = TransportManager::new(Box::new(adapter));
        let routing_id = RoutingId::new([0xAA; 32]);
        let envelopes = manager.query(&routing_id, None).await.unwrap();
        assert_eq!(envelopes.len(), 1);
    }

    #[tokio::test]
    async fn manager_query_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.query(&routing_id, None).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_subscribe_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.subscribe(&routing_id, None).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_subscribe_single_adapter_yields_events() {
        let envelope = test_envelope();
        let adapter = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![
                TransportEvent::Envelope(envelope),
                TransportEvent::BackfillComplete,
            ]),
        };

        let manager = TransportManager::new(Box::new(adapter));
        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager.subscribe(&routing_id, Some(0)).await.unwrap();

        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::Envelope(_))));

        let second = stream.next().await;
        assert!(matches!(second, Some(TransportEvent::BackfillComplete)));

        let third = stream.next().await;
        assert!(third.is_none());
    }

    #[tokio::test]
    async fn manager_unsubscribe_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.unsubscribe(&routing_id).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_unsubscribe_single_adapter_succeeds() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.unsubscribe(&routing_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn manager_delete_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let blob_id = BlobId::new([0xAA; 32]);
        let result = manager.delete(&blob_id).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_delete_single_adapter_succeeds() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        let blob_id = BlobId::new([0xAA; 32]);
        let result = manager.delete(&blob_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn merged_stream_deduplicates_envelopes() {
        let envelope = test_envelope();
        let envelope_clone = envelope.clone();

        // Two adapters returning the same envelope.
        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope)]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope_clone)]),
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager.subscribe(&routing_id, None).await.unwrap();

        // Should get exactly one envelope (the duplicate is deduplicated).
        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::Envelope(_))));

        // The stream should end after the single envelope.
        let remaining = stream.next().await;
        assert!(remaining.is_none());
    }

    #[tokio::test]
    async fn merged_stream_passes_control_events_through() {
        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::BackfillComplete]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::BackfillComplete]),
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager.subscribe(&routing_id, Some(0)).await.unwrap();

        // Both BackfillComplete events should pass through (one per adapter).
        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::BackfillComplete)));

        let second = stream.next().await;
        assert!(matches!(second, Some(TransportEvent::BackfillComplete)));
    }

    // -----------------------------------------------------------------------
    // Phase 2 send fanout tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_to_context_fanout_returns_blob_ids_per_relay() {
        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x01; 32]))));
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x02; 32]))));
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x03; 32]))));

        let ctx = "ctx-1".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1, 2]);

        let envelope = test_envelope();
        let result = manager.send_to_context(&envelope, &ctx).await.unwrap();
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn send_to_context_error_when_fewer_than_two_succeed() {
        let mut manager = TransportManager::builder();
        // One succeeds, two fail => only 1 success < MIN_SUCCESSFUL_SENDS (2).
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x01; 32]))));
        manager.add_adapter(Box::new(MockAdapter::failing(TransportError::SendFailed(
            "fail1".to_string(),
        ))));
        manager.add_adapter(Box::new(MockAdapter::failing(TransportError::SendFailed(
            "fail2".to_string(),
        ))));

        let ctx = "ctx-fail".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1, 2]);

        let envelope = test_envelope();
        let result = manager.send_to_context(&envelope, &ctx).await;
        assert!(matches!(result, Err(TransportError::SendFailed(_))));
    }

    #[tokio::test]
    async fn send_to_context_succeeds_with_exactly_two_relays() {
        let mut manager = TransportManager::builder();
        // Two succeed, one fails => 2 successes >= MIN_SUCCESSFUL_SENDS.
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x01; 32]))));
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x02; 32]))));
        manager.add_adapter(Box::new(MockAdapter::failing(TransportError::SendFailed(
            "fail".to_string(),
        ))));

        let ctx = "ctx-partial".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1, 2]);

        let envelope = test_envelope();
        let result = manager.send_to_context(&envelope, &ctx).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn send_to_context_records_reliability_scores() {
        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x01; 32]))));
        manager.add_adapter(Box::new(MockAdapter::failing(TransportError::SendFailed(
            "fail".to_string(),
        ))));
        manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0x03; 32]))));

        let ctx = "ctx-score".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1, 2]);

        let envelope = test_envelope();
        let _ = manager.send_to_context(&envelope, &ctx).await;

        // Adapter 0 should have 1 success.
        let score0 = manager.get_reliability_score(0).unwrap();
        assert_eq!(score0.total_sends, 1);
        assert_eq!(score0.total_failures, 0);

        // Adapter 1 should have 1 failure.
        let score1 = manager.get_reliability_score(1).unwrap();
        assert_eq!(score1.total_sends, 1);
        assert_eq!(score1.total_failures, 1);

        // Adapter 2 should have 1 success.
        let score2 = manager.get_reliability_score(2).unwrap();
        assert_eq!(score2.total_sends, 1);
        assert_eq!(score2.total_failures, 0);
    }

    #[tokio::test]
    async fn send_to_context_no_assignment_returns_error() {
        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::succeeding()));

        let envelope = test_envelope();
        let result = manager
            .send_to_context(&envelope, &"unassigned".to_string())
            .await;
        assert!(matches!(result, Err(TransportError::SendFailed(_))));
    }

    // -----------------------------------------------------------------------
    // Phase 2 subscribe merge + dedup tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn subscribe_context_deduplicates_across_relays() {
        let envelope = test_envelope();
        let envelope_clone = envelope.clone();

        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope)]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope_clone)]),
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));

        let ctx = "ctx-dedup".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1]);

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager
            .subscribe_context(&routing_id, &ctx, None)
            .await
            .unwrap();

        // Only one envelope should come through (deduped).
        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::Envelope(_))));

        let second = stream.next().await;
        assert!(second.is_none());
    }

    #[tokio::test]
    async fn subscribe_context_delivers_distinct_envelopes() {
        let envelope1 = test_envelope_with_blob(vec![0x01, 0x02, 0x03]);
        let envelope2 = test_envelope_with_blob(vec![0x04, 0x05, 0x06]);

        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope1)]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope2)]),
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));

        let ctx = "ctx-distinct".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1]);

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager
            .subscribe_context(&routing_id, &ctx, None)
            .await
            .unwrap();

        // Both distinct envelopes should come through.
        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::Envelope(_))));

        let second = stream.next().await;
        assert!(matches!(second, Some(TransportEvent::Envelope(_))));

        let third = stream.next().await;
        assert!(third.is_none());
    }

    #[tokio::test]
    async fn subscribe_context_no_assignment_returns_error() {
        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::succeeding()));

        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager
            .subscribe_context(&routing_id, &"unassigned".to_string(), None)
            .await;
        assert!(matches!(result, Err(TransportError::SubscriptionFailed(_))));
    }

    // -----------------------------------------------------------------------
    // Phase 2 assign_relay_set tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn assign_relay_set_selects_min_three_relays() {
        let mut manager = TransportManager::builder();
        for _ in 0..5 {
            manager.add_adapter(Box::new(MockAdapter::succeeding()));
        }

        let ctx = "ctx-assign".to_string();
        let set = manager.assign_relay_set(&ctx).unwrap();
        assert!(set.len() >= 3);
    }

    #[tokio::test]
    async fn assign_relay_set_caps_at_adapter_count_when_fewer_than_three() {
        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::succeeding()));
        manager.add_adapter(Box::new(MockAdapter::succeeding()));

        let ctx = "ctx-small".to_string();
        let set = manager.assign_relay_set(&ctx).unwrap();
        // Only 2 adapters available, so the set is capped at 2.
        assert_eq!(set.len(), 2);
    }

    #[tokio::test]
    async fn assign_relay_set_minimizes_overlap() {
        let mut manager = TransportManager::builder();
        for _ in 0..6 {
            manager.add_adapter(Box::new(MockAdapter::succeeding()));
        }

        let set1 = manager.assign_relay_set(&"ctx-a".to_string()).unwrap();
        let set2 = manager.assign_relay_set(&"ctx-b".to_string()).unwrap();

        // With 6 adapters and 3 per set, optimal assignment should have
        // minimal overlap (ideally 0 shared relays).
        let overlap: usize = set1.iter().filter(|idx| set2.contains(idx)).count();
        assert!(
            overlap <= 1,
            "expected overlap <= 1, got {overlap} (set1={set1:?}, set2={set2:?})"
        );
    }

    #[tokio::test]
    async fn assign_relay_set_stores_assignment() {
        let mut manager = TransportManager::builder();
        for _ in 0..3 {
            manager.add_adapter(Box::new(MockAdapter::succeeding()));
        }

        let ctx = "ctx-stored".to_string();
        let set = manager.assign_relay_set(&ctx).unwrap();

        let retrieved = manager.get_relay_set(&ctx).unwrap();
        assert_eq!(set, retrieved);
    }

    #[tokio::test]
    async fn assign_relay_set_no_adapters_returns_error() {
        let manager = TransportManager::builder();
        let result = manager.assign_relay_set(&"ctx-empty".to_string());
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn assign_relay_set_prefers_higher_reliability() {
        let mut manager = TransportManager::builder();
        for _ in 0..5 {
            manager.add_adapter(Box::new(MockAdapter::succeeding()));
        }

        // Degrade reliability for adapters 0 and 1 using the scoring API.
        {
            let mut scores = manager.reliability_scores.lock().unwrap();
            for _ in 0..10 {
                scoring::update_score(&mut scores, "0", DeliveryOutcome::Failure);
                scoring::update_score(&mut scores, "1", DeliveryOutcome::Failure);
            }
        }

        let ctx = "ctx-reliable".to_string();
        let set = manager.assign_relay_set(&ctx).unwrap();

        // The set should prefer adapters 2, 3, 4 over 0 and 1 since they
        // have better reliability scores.
        assert!(set.len() >= 3);
        // At least 2 of the 3 selected should be from the reliable set.
        let reliable_count = set.iter().filter(|&&idx| idx >= 2).count();
        assert!(
            reliable_count >= 2,
            "expected at least 2 reliable adapters, got {reliable_count} (set={set:?})"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2 with_config tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn with_config_uses_custom_dedup_settings() {
        let config = TransportConfig {
            dedup_cache_size: 500,
            dedup_cache_ttl: Duration::from_secs(120),
            ..TransportConfig::default()
        };
        let manager = TransportManager::with_config(&config);
        assert_eq!(manager.dedup_ttl, Duration::from_secs(120));
        assert_eq!(
            manager.dedup_cache.cap(),
            std::num::NonZeroUsize::new(500).unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // ReliabilityScore tests
    // -----------------------------------------------------------------------

    #[test]
    fn reliability_score_new_starts_perfect() {
        let score = ReliabilityScore::new("relay-0".to_string());
        assert!((score.delivery_success_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(score.total_sends, 0);
        assert_eq!(score.total_failures, 0);
    }

    #[test]
    fn reliability_score_record_success_updates_rate() {
        let mut scores = HashMap::new();
        let relay = "relay-0";
        scoring::update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 10 },
        );
        scoring::update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 10 },
        );
        let score = scoring::get_score(&scores, relay).unwrap();
        // EMA with alpha=0.3: two successes on a 1.0 base stays 1.0.
        assert!((score.delivery_success_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(score.total_sends, 2);
        assert_eq!(score.total_failures, 0);
    }

    #[test]
    fn reliability_score_record_failure_updates_rate() {
        let mut scores = HashMap::new();
        let relay = "relay-0";
        scoring::update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 10 },
        );
        scoring::update_score(&mut scores, relay, DeliveryOutcome::Failure);
        let score = scoring::get_score(&scores, relay).unwrap();
        // EMA: start 1.0 → success keeps 1.0 → failure: 0.3*0.0 + 0.7*1.0 = 0.7
        assert!((score.delivery_success_rate - 0.7).abs() < 1e-10);
        assert_eq!(score.total_sends, 2);
        assert_eq!(score.total_failures, 1);
    }

    #[test]
    fn reliability_score_composite_equals_success_rate() {
        let mut scores = HashMap::new();
        let relay = "relay-0";
        scoring::update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 10 },
        );
        scoring::update_score(
            &mut scores,
            relay,
            DeliveryOutcome::Success { latency_ms: 10 },
        );
        scoring::update_score(&mut scores, relay, DeliveryOutcome::Failure);
        let score = scoring::get_score(&scores, relay).unwrap();
        // EMA: 1.0 → 1.0 → 0.3*0.0 + 0.7*1.0 = 0.7
        assert!((score.composite_score() - 0.7).abs() < 1e-10);
    }

    // -----------------------------------------------------------------------
    // Suppression tracker wiring tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn merged_stream_records_delivery_in_suppression_tracker() {
        // Two adapters deliver the same envelope. After consuming the stream,
        // the suppression tracker should show both adapters delivered the blob.
        let envelope = test_envelope();
        let envelope_clone = envelope.clone();
        let blob_id = BlobId::from_sha256(&envelope.encrypted_blob);

        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope)]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope_clone)]),
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));

        let ctx = "ctx-suppress-both".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1]);

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager
            .subscribe_context(&routing_id, &ctx, None)
            .await
            .unwrap();

        // Drain the stream.
        while stream.next().await.is_some() {}

        // Verify suppression tracker recorded deliveries from both adapters.
        let tracker = manager.suppression_tracker.lock().unwrap();
        assert!(
            !tracker.is_empty(),
            "suppression tracker should have recorded the blob"
        );
        // The tracker should have an entry for this blob with both adapter indices.
        // We can't peek directly into the LRU, but we can verify via check_suppressions:
        // 2 out of 2 relays delivered => no warning.
        drop(tracker);
        let mut tracker = manager.suppression_tracker.lock().unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 31_000; // simulate 31 seconds later
        let warnings = tracker.check_suppressions(now_ms, 2);
        assert!(
            warnings.is_empty(),
            "no suppression warning expected when both adapters delivered; got {warnings:?}"
        );
        let _ = blob_id; // used for clarity, suppression check validates internally
    }

    #[tokio::test]
    async fn merged_stream_records_delivery_for_single_adapter_envelope() {
        // Only one adapter out of four delivers a blob. After consuming, the
        // suppression tracker should show only that adapter delivered.
        // With 4 relays, threshold = ceil(4/2) = 2, so 1 delivery < 2 triggers
        // a suppression warning.
        let envelope1 = test_envelope_with_blob(vec![0x10, 0x20, 0x30]);

        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope1)]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(Vec::new()), // delivers nothing
        };
        let adapter3 = MockAdapter {
            send_result: Ok(BlobId::new([0xCC; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(Vec::new()), // delivers nothing
        };
        let adapter4 = MockAdapter {
            send_result: Ok(BlobId::new([0xDD; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(Vec::new()), // delivers nothing
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));
        manager.add_adapter(Box::new(adapter3));
        manager.add_adapter(Box::new(adapter4));

        let ctx = "ctx-suppress-one".to_string();
        manager
            .relay_assignments
            .write()
            .unwrap()
            .insert(ctx.clone(), vec![0, 1, 2, 3]);

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager
            .subscribe_context(&routing_id, &ctx, None)
            .await
            .unwrap();

        // Drain the stream.
        while stream.next().await.is_some() {}

        // The suppression tracker should have 1 delivery from adapter 0 only.
        // With 4 total relays, threshold = ceil(4/2) = 2. Only 1 delivered
        // => 1 < 2 => warning should be emitted.
        let mut tracker = manager.suppression_tracker.lock().unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 31_000;
        let warnings = tracker.check_suppressions(now_ms, 4);
        assert_eq!(
            warnings.len(),
            1,
            "expected 1 suppression warning when only 1 of 4 adapters delivered"
        );
        assert!(warnings[0].delivered_by.contains(&0));
        assert!(!warnings[0].delivered_by.contains(&1));
        assert!(!warnings[0].delivered_by.contains(&2));
        assert!(!warnings[0].delivered_by.contains(&3));
    }

    #[tokio::test]
    async fn suppression_warning_downgrades_reliability_score() {
        // Set up a scenario where suppression is detected and verify the
        // reliability score of the non-delivering adapter is downgraded.
        use crate::scoring::SuppressionWarning;
        use std::collections::HashSet;

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::succeeding()));
        manager.add_adapter(Box::new(MockAdapter::succeeding()));
        manager.add_adapter(Box::new(MockAdapter::succeeding()));

        // Manually simulate what MergedStream::check_suppressions_if_due does:
        // a warning where adapter 2 did not deliver.
        let mut delivered_by = HashSet::new();
        delivered_by.insert(0usize);
        delivered_by.insert(1usize);
        let warning = SuppressionWarning {
            blob_id: BlobId::new([0xFF; 32]),
            delivered_by,
            total_relays: 3,
        };

        // Apply the downgrade manually (same logic as MergedStream).
        {
            let mut scores = manager.reliability_scores.lock().unwrap();
            let all_adapters: HashSet<usize> = (0..3).collect();
            for &missing in all_adapters.difference(&warning.delivered_by) {
                scoring::update_score(&mut scores, &missing.to_string(), DeliveryOutcome::Failure);
            }
        }

        // Adapter 2 should have been downgraded (started at 1.0, one failure
        // => EMA: 0.3*0 + 0.7*1.0 = 0.7).
        let score2 = manager.get_reliability_score(2).unwrap();
        assert!(
            (score2.delivery_success_rate - 0.7).abs() < 1e-10,
            "expected adapter 2 to be downgraded to 0.7, got {}",
            score2.delivery_success_rate
        );
        assert_eq!(score2.total_failures, 1);

        // Adapters 0 and 1 should be unaffected.
        let score0 = manager.get_reliability_score(0).unwrap();
        assert!(
            (score0.delivery_success_rate - 1.0).abs() < f64::EPSILON,
            "adapter 0 should not be downgraded"
        );
        let score1 = manager.get_reliability_score(1).unwrap();
        assert!(
            (score1.delivery_success_rate - 1.0).abs() < f64::EPSILON,
            "adapter 1 should not be downgraded"
        );
    }

    // -----------------------------------------------------------------------
    // Concurrency tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn concurrent_sends_to_different_contexts_do_not_block() {
        // 10 tasks send to 10 different contexts through Arc<TransportManager>.
        // All sends should complete without deadlock.
        let mut manager = TransportManager::builder();
        for _ in 0..5 {
            manager.add_adapter(Box::new(MockAdapter::with_blob_id(BlobId::new([0xAA; 32]))));
        }

        // Assign relay sets for 10 contexts.
        for i in 0..10 {
            let ctx = format!("ctx-concurrent-{i}");
            manager.assign_relay_set(&ctx).unwrap();
        }

        let manager = Arc::new(manager);

        let mut handles = Vec::with_capacity(10);
        for i in 0..10 {
            let mgr = Arc::clone(&manager);
            let ctx = format!("ctx-concurrent-{i}");
            handles.push(tokio::spawn(async move {
                let envelope = test_envelope();
                mgr.send_to_context(&envelope, &ctx).await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(
                result.is_ok(),
                "send_to_context should succeed, got: {result:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Cost-aware relay selection tests (section 19.8)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn assign_relay_set_prefers_cheaper_relays() {
        let mut manager = TransportManager::builder();
        for _ in 0..5 {
            manager.add_adapter(Box::new(MockAdapter::succeeding()));
        }

        // Set high costs for adapters 0 and 1, leave 2, 3, 4 free.
        manager.set_relay_cost(0, 1000);
        manager.set_relay_cost(1, 500);

        let ctx = "ctx-cost-aware".to_string();
        let set = manager.assign_relay_set(&ctx).unwrap();

        assert_eq!(set.len(), 3);
        // The set should prefer adapters 2, 3, 4 (free) over 0, 1 (paid).
        let free_count = set.iter().filter(|&&idx| idx >= 2).count();
        assert!(
            free_count >= 2,
            "expected at least 2 free adapters, got {free_count} (set={set:?})"
        );
    }

    #[tokio::test]
    async fn set_relay_cost_and_get_relay_cost_roundtrip() {
        let manager = TransportManager::builder();

        // Default cost is 0.
        assert_eq!(manager.get_relay_cost(0), 0);

        manager.set_relay_cost(0, 42);
        assert_eq!(manager.get_relay_cost(0), 42);

        manager.set_relay_cost(0, 0);
        assert_eq!(manager.get_relay_cost(0), 0);
    }

    #[tokio::test]
    async fn assign_relay_set_cost_breaks_tie_between_equal_reliability() {
        let mut manager = TransportManager::builder();
        for _ in 0..4 {
            manager.add_adapter(Box::new(MockAdapter::succeeding()));
        }

        // All adapters have equal reliability (default 1.0).
        // Set different costs: adapter 0 = 100, adapter 1 = 50,
        // adapter 2 = 0, adapter 3 = 200.
        manager.set_relay_cost(0, 100);
        manager.set_relay_cost(1, 50);
        // adapter 2 is free (default 0)
        manager.set_relay_cost(3, 200);

        let ctx = "ctx-cost-tie".to_string();
        let set = manager.assign_relay_set(&ctx).unwrap();

        assert_eq!(set.len(), 3);
        // Adapter 2 (free) should always be selected.
        assert!(
            set.contains(&2),
            "free adapter 2 should be in the set (set={set:?})"
        );
        // Adapter 3 (most expensive) should NOT be selected when
        // 3 cheaper options exist.
        assert!(
            !set.contains(&3),
            "most expensive adapter 3 should not be in the set (set={set:?})"
        );
    }
}
