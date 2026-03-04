//! Shared subscription registry used across all transport handlers.
//!
//! The subscription registry maps routing IDs to subscriber entries, allowing
//! any transport handler (WebSocket, QUIC, WebTransport) to deliver blobs to
//! subscribers regardless of which transport they connected through.
//!
//! See ADR-037 AC3 ("shared subscription registry") and spec §10.14.3.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand::Rng as _;
use tokio::sync::{RwLock, mpsc};

use crate::native::protocol::RelayMessage;
use crate::native::storage::StoredBlob;

// ---------------------------------------------------------------------------
// Global owner ID counter (cross-transport collision prevention)
// ---------------------------------------------------------------------------

/// Global connection/session ID counter shared across all transport handlers.
///
/// Each transport (WebSocket, QUIC, WebTransport) must allocate owner IDs from
/// this single counter. Without a shared counter, independent per-transport
/// counters starting at 1 can produce collisions: WebSocket connection 5 and
/// QUIC connection 5 would share the same `owner_id`, causing one transport's
/// disconnect to inadvertently remove the other's subscriptions.
static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

/// Returns the next globally unique owner ID for subscription registry entries.
///
/// All transport handlers (WebSocket, QUIC, WebTransport) must use this
/// function to allocate connection/session IDs, ensuring no cross-transport
/// collisions in the shared [`SubscriptionRegistry`].
pub fn next_owner_id() -> u64 {
    NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed)
}

/// An entry in the subscription registry.
///
/// Each entry represents a single subscriber (connection or session) that
/// wants to receive blobs published to a given routing ID.
pub struct SubscriberEntry {
    /// Unique ID for this connection/session (allows targeted removal on teardown).
    pub owner_id: u64,
    /// Channel for pushing relay messages to this subscriber.
    pub tx: mpsc::Sender<RelayMessage>,
}

/// The subscription registry: `routing_id -> Vec<SubscriberEntry>`.
///
/// Shared across WebSocket, QUIC, and WebTransport handlers so that a blob
/// published via any transport is delivered to all subscribers regardless of
/// their transport.
pub type SubscriptionRegistry = Arc<RwLock<HashMap<[u8; 32], Vec<SubscriberEntry>>>>;

/// Maximum total subscriptions across all routing IDs (SEC-006).
///
/// Prevents unbounded memory growth if a large number of unique routing IDs
/// accumulate subscriptions without cleanup. A relay serving 1000 connections
/// with 100 subscriptions each could approach this, so it is set generously.
pub const MAX_TOTAL_SUBSCRIPTIONS: usize = 100_000;

/// Maximum subscribers per routing ID (SEC-006).
///
/// Prevents a single routing ID from accumulating an excessive number of
/// subscribers (e.g., from a subscription-amplification attack).
pub const MAX_SUBSCRIBERS_PER_ROUTING_ID: usize = 1_000;

/// Creates a new empty subscription registry.
#[must_use]
pub fn new_registry() -> SubscriptionRegistry {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Registers a subscriber in the registry, enforcing global and per-routing-ID
/// limits (SEC-006).
///
/// Returns `Ok(())` if the subscriber was registered, or `Err(reason)` if
/// a capacity limit would be exceeded.
///
/// # Errors
///
/// Returns a descriptive error string if the global subscription limit
/// ([`MAX_TOTAL_SUBSCRIPTIONS`]) or per-routing-ID limit
/// ([`MAX_SUBSCRIBERS_PER_ROUTING_ID`]) would be exceeded.
pub async fn register_subscriber(
    registry: &SubscriptionRegistry,
    routing_id: [u8; 32],
    owner_id: u64,
    tx: mpsc::Sender<RelayMessage>,
) -> Result<(), String> {
    let mut reg = registry.write().await;
    register_subscriber_inner(&mut reg, routing_id, owner_id, tx)
}

/// Inner implementation: operates on an already-locked registry.
fn register_subscriber_inner(
    reg: &mut HashMap<[u8; 32], Vec<SubscriberEntry>>,
    routing_id: [u8; 32],
    owner_id: u64,
    tx: mpsc::Sender<RelayMessage>,
) -> Result<(), String> {
    // Check total subscription count across all routing IDs.
    let total: usize = reg.values().map(Vec::len).sum();
    if total >= MAX_TOTAL_SUBSCRIPTIONS {
        return Err(format!(
            "subscription registry full: {total}/{MAX_TOTAL_SUBSCRIPTIONS} total subscriptions"
        ));
    }

    let entries = reg.entry(routing_id).or_default();

    // Check per-routing-ID subscriber limit.
    if entries.len() >= MAX_SUBSCRIBERS_PER_ROUTING_ID {
        return Err(format!(
            "routing ID has too many subscribers: {}/{MAX_SUBSCRIBERS_PER_ROUTING_ID}",
            entries.len()
        ));
    }

    // Remove any existing subscription from this owner for this routing ID
    // (prevents duplicates on re-subscribe).
    entries.retain(|e| e.owner_id != owner_id);

    entries.push(SubscriberEntry { owner_id, tx });
    Ok(())
}

/// Delivers a stored blob to all subscribers of its routing ID.
///
/// When `jitter_ms > 0`, each subscriber's delivery is randomly delayed by
/// up to `jitter_ms` milliseconds to break timing correlation between
/// PUBLISH arrival and subscriber delivery (BLACK-001 mitigation).
///
/// Returns the number of failed deliveries (subscribers whose channel was
/// full or closed). A non-zero count indicates potential selective message
/// suppression if a relay artificially fills a target's buffer.
pub async fn deliver_to_subscribers(
    stored: &StoredBlob,
    subscriptions: &SubscriptionRegistry,
    jitter_ms: u64,
) -> u64 {
    // Snapshot entries and drop the read lock immediately to avoid holding it
    // during jittered delivery (which can take up to jitter_ms). Without this,
    // all subscription writes (new subs, unsubs, cleanup) would be blocked.
    let registry = subscriptions.read().await;
    let Some(entries) = registry.get(&stored.routing_id) else {
        return 0;
    };
    let entries_snapshot: Vec<(u64, mpsc::Sender<RelayMessage>)> =
        entries.iter().map(|e| (e.owner_id, e.tx.clone())).collect();
    drop(registry);

    let blob_msg = RelayMessage::Blob {
        routing_id: stored.routing_id,
        blob_id: stored.blob_id,
        recipient_hint: stored.recipient_hint,
        blob_ttl: stored.blob_ttl,
        stored_at: stored.stored_at,
        blob: stored.blob.clone(),
    };

    let total_subscribers = entries_snapshot.len();

    // When jitter is enabled, spawn parallel tasks so each subscriber's
    // random delay runs concurrently instead of cascading sequentially.
    // With N subscribers at J ms max jitter, worst-case drops from ~N*J/2
    // to ~J ms total wall time.
    let failed = if jitter_ms > 0 {
        let mut handles = Vec::with_capacity(total_subscribers);
        for (owner_id, tx) in &entries_snapshot {
            let msg = blob_msg.clone();
            let tx = tx.clone();
            let owner_id = *owner_id;
            let blob_id = stored.blob_id;

            handles.push(tokio::spawn(async move {
                // Per-subscriber delivery jitter (BLACK-001 mitigation).
                let delay_ms = rand::thread_rng().gen_range(0..jitter_ms);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                if let Err(e) = tx.try_send(msg) {
                    tracing::warn!(
                        owner_id,
                        blob_id = ?blob_id,
                        error = %e,
                        total_subscribers,
                        "failed to deliver blob to subscriber (channel full or closed) — \
                         possible selective suppression vector"
                    );
                    1u64
                } else {
                    0u64
                }
            }));
        }

        let mut total_failed = 0u64;
        for handle in handles {
            // Unwrap is safe: the spawned tasks do not panic.
            total_failed += handle.await.unwrap_or(1);
        }
        total_failed
    } else {
        // Zero-jitter fast path: deliver sequentially without spawn overhead.
        let mut total_failed = 0u64;
        for (owner_id, tx) in &entries_snapshot {
            if let Err(e) = tx.try_send(blob_msg.clone()) {
                total_failed += 1;
                tracing::warn!(
                    owner_id,
                    blob_id = ?stored.blob_id,
                    error = %e,
                    failed_count = total_failed,
                    total_subscribers,
                    "failed to deliver blob to subscriber (channel full or closed) — \
                     possible selective suppression vector"
                );
            }
        }
        total_failed
    };

    if failed > 0 {
        tracing::warn!(
            blob_id = ?stored.blob_id,
            routing_id = ?stored.routing_id,
            failed_deliveries = failed,
            total_subscribers,
            "blob delivery incomplete: {failed}/{total_subscribers} subscribers received the blob",
        );
    }

    failed
}
