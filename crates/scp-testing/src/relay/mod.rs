//! In-memory relay for testing, with fault injection support.
//!
//! Provides [`InMemoryRelay`] — a fully functional relay that stores blobs
//! in memory and delivers messages to subscribers. Supports configurable
//! fault injection via [`BehaviorMode`] for testing protocol resilience
//! against relay misbehavior (suppression, equivocation, replay, delay,
//! deletion non-compliance).

#![forbid(unsafe_code)]

pub mod behavior;
pub mod subscription;

pub use behavior::BehaviorMode;
pub use subscription::{RelayMessage, SubscriberId, SubscriptionRegistry};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use rand::Rng;
use sha2::{Digest, Sha256};

use behavior::{CommitSuppressionConfig, EquivocationConfig, ReplayConfig, SuppressionConfig};

/// A blob stored in the in-memory relay.
#[derive(Clone, Debug)]
pub struct StoredBlob {
    /// The routing ID this blob belongs to.
    pub routing_id: [u8; 32],
    /// The unique blob identifier (SHA-256 of data).
    pub blob_id: [u8; 32],
    /// The raw blob payload.
    pub data: Vec<u8>,
    /// Optional time-to-live in seconds from `stored_at`.
    pub ttl_secs: Option<u64>,
    /// Timestamp when the blob was stored (epoch seconds).
    pub stored_at: u64,
}

/// In-memory relay for testing. Stores blobs and delivers to subscribers.
///
/// Supports fault injection via [`BehaviorMode`] for testing relay misbehavior
/// scenarios (suppression, equivocation, replay, delay).
pub struct InMemoryRelay {
    behavior: BehaviorMode,
    subscriptions: SubscriptionRegistry,
    blobs: HashMap<[u8; 32], StoredBlob>,
    message_counter: AtomicU64,
}

impl InMemoryRelay {
    /// Creates a new relay with [`BehaviorMode::Normal`] (no fault injection).
    #[must_use]
    pub fn new() -> Self {
        Self {
            behavior: BehaviorMode::Normal,
            subscriptions: SubscriptionRegistry::new(),
            blobs: HashMap::new(),
            message_counter: AtomicU64::new(0),
        }
    }

    /// Creates a new relay with the specified behavior mode.
    #[must_use]
    pub fn with_behavior(behavior: BehaviorMode) -> Self {
        Self {
            behavior,
            subscriptions: SubscriptionRegistry::new(),
            blobs: HashMap::new(),
            message_counter: AtomicU64::new(0),
        }
    }

    /// Returns a reference to the current behavior mode.
    #[must_use]
    pub const fn behavior(&self) -> &BehaviorMode {
        &self.behavior
    }

    /// Replaces the current behavior mode.
    pub fn set_behavior(&mut self, behavior: BehaviorMode) {
        self.behavior = behavior;
    }

    /// Stores a blob and delivers it to subscribers according to the current
    /// behavior mode.
    ///
    /// Returns the blob ID (SHA-256 of `data`).
    pub fn store(
        &mut self,
        routing_id: [u8; 32],
        data: Vec<u8>,
        ttl_secs: Option<u64>,
        timestamp: u64,
    ) -> [u8; 32] {
        let blob_id = sha256_hash(&data);
        let blob = StoredBlob {
            routing_id,
            blob_id,
            data: data.clone(),
            ttl_secs,
            stored_at: timestamp,
        };
        self.blobs.insert(blob_id, blob);

        let msg_num = self.message_counter.fetch_add(1, Ordering::Relaxed) + 1;

        let base_message = RelayMessage {
            routing_id,
            blob_id,
            data,
            stored_at: timestamp,
        };

        self.apply_behavior(&self.behavior.clone(), &routing_id, &base_message, msg_num);

        blob_id
    }

    /// Retrieves a stored blob by its blob ID.
    #[must_use]
    pub fn get(&self, blob_id: &[u8; 32]) -> Option<&StoredBlob> {
        self.blobs.get(blob_id)
    }

    /// Returns all blobs stored under the given routing ID.
    #[must_use]
    pub fn query(&self, routing_id: &[u8; 32]) -> Vec<&StoredBlob> {
        self.blobs
            .values()
            .filter(|b| &b.routing_id == routing_id)
            .collect()
    }

    /// Deletes a blob by its blob ID.
    ///
    /// Returns `true` if the blob existed and was removed. Under
    /// [`BehaviorMode::DeletionNonCompliant`], deletion is a no-op and
    /// always returns `false`.
    pub fn delete(&mut self, blob_id: &[u8; 32]) -> bool {
        if Self::is_deletion_noncompliant(&self.behavior) {
            return false;
        }
        self.blobs.remove(blob_id).is_some()
    }

    /// Subscribes to messages for the given routing ID.
    ///
    /// Returns a `(SubscriberId, Receiver)` pair for receiving delivered
    /// messages.
    pub fn subscribe(
        &mut self,
        routing_id: [u8; 32],
    ) -> (
        SubscriberId,
        tokio::sync::mpsc::UnboundedReceiver<RelayMessage>,
    ) {
        self.subscriptions.subscribe(routing_id)
    }

    /// Removes a subscriber from a specific routing ID.
    ///
    /// Returns `true` if the subscriber was found and removed.
    pub fn unsubscribe(&mut self, routing_id: &[u8; 32], subscriber_id: SubscriberId) -> bool {
        self.subscriptions.unsubscribe(routing_id, subscriber_id)
    }

    /// Removes all blobs whose TTL has expired relative to `now`.
    ///
    /// Returns the number of blobs removed.
    pub fn expire_blobs(&mut self, now: u64) -> usize {
        let before = self.blobs.len();
        self.blobs.retain(|_, blob| {
            blob.ttl_secs
                .is_none_or(|ttl| now.saturating_sub(blob.stored_at) < ttl)
        });
        before - self.blobs.len()
    }

    /// Returns the number of stored blobs.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// Returns the total number of active subscriptions.
    #[must_use]
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.count()
    }

    /// Applies a behavior mode to a message delivery.
    fn apply_behavior(
        &mut self,
        mode: &BehaviorMode,
        routing_id: &[u8; 32],
        message: &RelayMessage,
        msg_num: u64,
    ) {
        match mode {
            BehaviorMode::Normal => {
                self.subscriptions.deliver(routing_id, message);
            }
            BehaviorMode::Suppressing(config) => {
                self.apply_suppression(routing_id, message, msg_num, config);
            }
            BehaviorMode::Equivocating(config) => {
                self.apply_equivocation(routing_id, message, msg_num, config);
            }
            BehaviorMode::Delayed(_) => {
                // Delay is simulated at a higher level (async sleep).
                // At this layer, deliver normally.
                self.subscriptions.deliver(routing_id, message);
            }
            BehaviorMode::Replaying(config) => {
                self.apply_replay(routing_id, message, config);
            }
            BehaviorMode::CommitSuppressing(config) => {
                self.apply_commit_suppression(routing_id, message, config);
            }
            BehaviorMode::DeletionNonCompliant => {
                // Delivery is normal; deletion is the affected operation.
                self.subscriptions.deliver(routing_id, message);
            }
            BehaviorMode::Composite(modes) => {
                // Apply all behaviors in order. Each one may deliver the
                // message in its own way.
                for sub_mode in modes {
                    self.apply_behavior(sub_mode, routing_id, message, msg_num);
                }
            }
        }
    }

    /// Suppression: skip delivery on every Nth message.
    fn apply_suppression(
        &mut self,
        routing_id: &[u8; 32],
        message: &RelayMessage,
        msg_num: u64,
        config: &SuppressionConfig,
    ) {
        if config.drop_nth > 0 && msg_num.is_multiple_of(u64::from(config.drop_nth)) {
            // Dropped — do not deliver.
            return;
        }
        self.subscriptions.deliver(routing_id, message);
    }

    /// Equivocation: after N messages, flip a byte in the data for odd-indexed
    /// subscribers so different subscribers see different content.
    fn apply_equivocation(
        &mut self,
        routing_id: &[u8; 32],
        message: &RelayMessage,
        msg_num: u64,
        config: &EquivocationConfig,
    ) {
        if msg_num <= u64::from(config.diverge_after) || message.data.is_empty() {
            // Before divergence threshold or empty payload — deliver faithfully.
            self.subscriptions.deliver(routing_id, message);
            return;
        }

        // Deliver to each subscriber individually, flipping a byte for
        // odd-indexed subscribers to create divergent views.
        if let Some(subs) = self.subscriptions.subscribers_for(routing_id) {
            let ids: Vec<(SubscriberId, usize)> = subs
                .iter()
                .enumerate()
                .map(|(i, (id, _))| (*id, i))
                .collect();
            for (sub_id, index) in ids {
                if index % 2 == 1 {
                    let mut divergent = message.clone();
                    // Flip the first byte.
                    divergent.data[0] ^= 0xFF;
                    self.subscriptions.deliver_to(sub_id, divergent);
                } else {
                    self.subscriptions.deliver_to(sub_id, message.clone());
                }
            }
        }
    }

    /// Replay: deliver the message N+1 times total.
    fn apply_replay(
        &mut self,
        routing_id: &[u8; 32],
        message: &RelayMessage,
        config: &ReplayConfig,
    ) {
        for _ in 0..=config.replay_count {
            self.subscriptions.deliver(routing_id, message);
        }
    }

    /// Commit suppression: probabilistically skip delivery of messages that
    /// look like MLS commits (heuristic: data starts with certain byte
    /// patterns, or simply apply probability to all messages).
    fn apply_commit_suppression(
        &mut self,
        routing_id: &[u8; 32],
        message: &RelayMessage,
        config: &CommitSuppressionConfig,
    ) {
        let mut rng = rand::thread_rng();
        let roll: f64 = rng.r#gen();
        if roll < config.suppress_probability {
            // Suppressed — do not deliver.
            return;
        }
        self.subscriptions.deliver(routing_id, message);
    }

    /// Checks whether the given behavior (or any nested composite) includes
    /// `DeletionNonCompliant`.
    fn is_deletion_noncompliant(mode: &BehaviorMode) -> bool {
        match mode {
            BehaviorMode::DeletionNonCompliant => true,
            BehaviorMode::Composite(modes) => modes.iter().any(Self::is_deletion_noncompliant),
            _ => false,
        }
    }
}

impl Default for InMemoryRelay {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the SHA-256 hash of the given data.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
