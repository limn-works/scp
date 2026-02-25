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
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt};
use lru::LruCache;
use scp_core::envelope::OuterEnvelope;

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::scoring::{self, DeliveryOutcome, ReliabilityScore, SuppressionTracker};
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
    relay_assignments: HashMap<ContextId, Vec<usize>>,
    /// Per-relay reliability scores keyed by adapter index (as string).
    reliability_scores: HashMap<String, ReliabilityScore>,
    /// Deduplication cache: maps `BlobId` to the time it was first seen.
    dedup_cache: LruCache<BlobId, Instant>,
    /// TTL for deduplication cache entries.
    dedup_ttl: Duration,
    /// Round-robin counter for relay assignment spread.
    assignment_counter: usize,
    /// Multi-relay suppression cross-check tracker (spec section 9.9.2).
    suppression_tracker: SuppressionTracker,
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
            relay_assignments: HashMap::new(),
            reliability_scores: HashMap::new(),
            dedup_cache: LruCache::new(nonzero_capacity(DEFAULT_DEDUP_CAPACITY)),
            dedup_ttl: DEFAULT_DEDUP_TTL,
            assignment_counter: 0,
            suppression_tracker: SuppressionTracker::new(),
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
            relay_assignments: HashMap::new(),
            reliability_scores: HashMap::new(),
            dedup_cache: LruCache::new(nonzero_capacity(DEFAULT_DEDUP_CAPACITY)),
            dedup_ttl: DEFAULT_DEDUP_TTL,
            assignment_counter: 0,
            suppression_tracker: SuppressionTracker::new(),
        }
    }

    /// Creates a new `TransportManager` with the given configuration.
    ///
    /// Uses the dedup cache size and TTL from the [`TransportConfig`].
    #[must_use]
    pub fn with_config(config: &TransportConfig) -> Self {
        Self {
            adapters: Vec::new(),
            relay_assignments: HashMap::new(),
            reliability_scores: HashMap::new(),
            dedup_cache: LruCache::new(nonzero_capacity(config.dedup_cache_size)),
            dedup_ttl: config.dedup_cache_ttl,
            assignment_counter: 0,
            suppression_tracker: SuppressionTracker::new(),
        }
    }

    /// Registers an additional transport adapter.
    ///
    /// The adapter is appended to the end of the adapter list. Its index
    /// is used as the identifier for relay set assignments and reliability
    /// scoring.
    pub fn add_adapter(&mut self, adapter: Box<dyn TransportAdapter>) {
        let idx = self.adapters.len();
        self.reliability_scores
            .insert(idx.to_string(), ReliabilityScore::new(idx.to_string()));
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
        &mut self,
        envelope: &OuterEnvelope,
        context_id: &ContextId,
    ) -> Result<Vec<BlobId>, TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let relay_indices = self
            .relay_assignments
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
        for (idx, success) in outcomes {
            let key = idx.to_string();
            let outcome = if success {
                DeliveryOutcome::Success { latency_ms: 0 }
            } else {
                DeliveryOutcome::Failure
            };
            scoring::update_score(&mut self.reliability_scores, &key, outcome);
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

        // Collect subscription streams from all adapters.
        let mut streams: Vec<SubscriptionStream> = Vec::with_capacity(self.adapters.len());

        for adapter in &self.adapters {
            let stream = adapter.subscribe(routing_id, since).await?;
            streams.push(stream);
        }

        // Phase 1 optimization: single adapter, no merging needed.
        if streams.len() == 1
            && let Some(stream) = streams.pop()
        {
            return Ok(stream);
        }

        // Phase 2: merge streams with LRU + TTL deduplication by BlobId.
        let dedup_capacity = self.dedup_cache.cap();
        let merged = MergedStream::new(streams, dedup_capacity, self.dedup_ttl);
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
            .get(context_id)
            .ok_or_else(|| {
                TransportError::SubscriptionFailed(format!(
                    "no relay set assigned for context {context_id}"
                ))
            })?
            .clone();

        let mut streams: Vec<SubscriptionStream> = Vec::with_capacity(relay_indices.len());
        for &idx in &relay_indices {
            if let Some(adapter) = self.adapters.get(idx) {
                let stream = adapter.subscribe(routing_id, since).await?;
                streams.push(stream);
            }
        }

        if streams.is_empty() {
            return Err(TransportError::NotConnected);
        }

        // Single relay optimization: no merging needed.
        if streams.len() == 1
            && let Some(stream) = streams.pop()
        {
            return Ok(stream);
        }

        let dedup_capacity = self.dedup_cache.cap();
        let merged = MergedStream::new(streams, dedup_capacity, self.dedup_ttl);
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
    pub fn assign_relay_set(
        &mut self,
        context_id: &ContextId,
    ) -> Result<Vec<usize>, TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let adapter_count = self.adapters.len();
        let set_size = MIN_RELAYS_PER_CONTEXT.min(adapter_count);

        // Build a list of adapter indices sorted by:
        //   (overlap count ASC, reliability score DESC, round-robin offset ASC).
        // This prefers adapters least used by other contexts and with higher
        // reliability.
        let mut candidates: Vec<(usize, usize, f64)> = (0..adapter_count)
            .map(|idx| {
                let overlap = self.overlap_count(idx);
                let reliability = self
                    .reliability_scores
                    .get(&idx.to_string())
                    .map_or(1.0, ReliabilityScore::composite_score);
                (idx, overlap, reliability)
            })
            .collect();

        let counter = self.assignment_counter;
        candidates.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
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
            .map(|(idx, _, _)| *idx)
            .collect();

        self.assignment_counter += set_size;
        self.relay_assignments
            .insert(context_id.clone(), assigned.clone());

        Ok(assigned)
    }

    /// Returns the relay set currently assigned to a context, if any.
    #[must_use]
    pub fn get_relay_set(&self, context_id: &ContextId) -> Option<&Vec<usize>> {
        self.relay_assignments.get(context_id)
    }

    /// Returns the reliability score for an adapter by index.
    #[must_use]
    pub fn get_reliability_score(&self, adapter_index: usize) -> Option<&ReliabilityScore> {
        self.reliability_scores.get(&adapter_index.to_string())
    }

    /// Updates the reliability score for a relay after an operation.
    ///
    /// Delegates to [`scoring::update_score`] which applies exponential
    /// moving average (EMA) decay so that recent behavior weighs more than
    /// historical.
    ///
    /// See ADR-012 acceptance criterion 5.
    pub fn update_score(&mut self, relay_url: &str, outcome: DeliveryOutcome) {
        scoring::update_score(&mut self.reliability_scores, relay_url, outcome);
    }

    /// Returns the current reliability score for a relay URL.
    ///
    /// Delegates to [`scoring::get_score`].
    #[must_use]
    pub fn get_score(&self, relay_url: &str) -> Option<&ReliabilityScore> {
        scoring::get_score(&self.reliability_scores, relay_url)
    }

    /// Returns a mutable reference to the suppression tracker.
    ///
    /// Used by the subscription layer to record per-blob deliveries and
    /// check for suppression across relays.
    pub fn suppression_tracker_mut(&mut self) -> &mut SuppressionTracker {
        &mut self.suppression_tracker
    }

    /// Returns a reference to the suppression tracker.
    #[must_use]
    pub fn suppression_tracker(&self) -> &SuppressionTracker {
        &self.suppression_tracker
    }

    /// Counts how many existing context relay sets include the given adapter
    /// index.
    fn overlap_count(&self, adapter_index: usize) -> usize {
        self.relay_assignments
            .values()
            .filter(|set| set.contains(&adapter_index))
            .count()
    }
}

/// A merged stream that combines multiple adapter subscription streams with
/// deduplication by [`BlobId`] for [`TransportEvent::Envelope`] variants.
///
/// Uses an LRU cache with configurable capacity and TTL for deduplication.
/// Entries older than the TTL are treated as expired, allowing the same
/// `BlobId` to be delivered again if it arrives after the TTL window.
///
/// Control events ([`BackfillComplete`](TransportEvent::BackfillComplete),
/// [`Reconnected`](TransportEvent::Reconnected),
/// [`Terminated`](TransportEvent::Terminated),
/// [`Error`](TransportEvent::Error)) are passed through per-adapter without
/// deduplication.
struct MergedStream {
    /// The underlying adapter streams being merged.
    streams: Vec<SubscriptionStream>,
    /// LRU cache of `BlobId`s already yielded, with timestamps for TTL expiry.
    seen: LruCache<BlobId, Instant>,
    /// TTL for deduplication cache entries.
    ttl: Duration,
}

impl MergedStream {
    /// Creates a new `MergedStream` from multiple adapter streams.
    fn new(
        streams: Vec<SubscriptionStream>,
        capacity: std::num::NonZeroUsize,
        ttl: Duration,
    ) -> Self {
        Self {
            streams,
            seen: LruCache::new(capacity),
            ttl,
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
}

impl Stream for MergedStream {
    type Item = TransportEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Round-robin poll across all streams. Return the first ready item
        // that passes deduplication. If all streams are pending, return
        // Pending. If all streams are exhausted, return None.
        let mut all_done = true;
        let mut any_pending = false;

        for stream in &mut this.streams {
            match stream.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    match &event {
                        TransportEvent::Envelope(envelope) => {
                            let blob_id = BlobId::from_sha256(&envelope.encrypted_blob);
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
                        | TransportEvent::Terminated { .. } => {
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
        manager.relay_assignments.insert(ctx.clone(), vec![0, 1, 2]);

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
        manager.relay_assignments.insert(ctx.clone(), vec![0, 1, 2]);

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
        manager.relay_assignments.insert(ctx.clone(), vec![0, 1, 2]);

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
        manager.relay_assignments.insert(ctx.clone(), vec![0, 1, 2]);

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
        manager.relay_assignments.insert(ctx.clone(), vec![0, 1]);

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
        manager.relay_assignments.insert(ctx.clone(), vec![0, 1]);

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
        assert_eq!(&set, retrieved);
    }

    #[tokio::test]
    async fn assign_relay_set_no_adapters_returns_error() {
        let mut manager = TransportManager::builder();
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
        for _ in 0..10 {
            scoring::update_score(
                &mut manager.reliability_scores,
                "0",
                DeliveryOutcome::Failure,
            );
            scoring::update_score(
                &mut manager.reliability_scores,
                "1",
                DeliveryOutcome::Failure,
            );
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
}
