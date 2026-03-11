//! Subscription registry for in-memory relay message delivery.
//!
//! Manages subscriber channels keyed by routing ID, enabling fan-out delivery
//! of relay messages to all interested parties.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

/// Opaque identifier for a subscription channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubscriberId(pub u64);

/// A message delivered through the relay subscription system.
#[derive(Clone, Debug)]
pub struct RelayMessage {
    /// The routing ID this message belongs to.
    pub routing_id: [u8; 32],
    /// The unique blob identifier (SHA-256 of data).
    pub blob_id: [u8; 32],
    /// The raw message payload.
    pub data: Vec<u8>,
    /// Timestamp when the blob was stored (epoch seconds).
    pub stored_at: u64,
}

/// Fan-out registry that maps routing IDs to subscriber channels.
///
/// Each call to [`subscribe`](SubscriptionRegistry::subscribe) creates a new
/// unbounded MPSC channel and returns the receiving half. Messages delivered
/// via [`deliver`](SubscriptionRegistry::deliver) are cloned to every
/// subscriber registered for the target routing ID.
pub struct SubscriptionRegistry {
    /// Map from `routing_id` to list of (`subscriber_id`, sender) pairs.
    subscribers: HashMap<[u8; 32], Vec<(SubscriberId, mpsc::UnboundedSender<RelayMessage>)>>,
    /// Monotonic counter for generating unique subscriber IDs.
    next_id: AtomicU64,
}

impl SubscriptionRegistry {
    /// Creates an empty subscription registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
            next_id: AtomicU64::new(0),
        }
    }

    /// Subscribes to messages for the given routing ID.
    ///
    /// Returns a `(SubscriberId, Receiver)` pair. The receiver will yield
    /// every [`RelayMessage`] delivered to this routing ID until the
    /// subscription is removed or the registry is dropped.
    pub fn subscribe(
        &mut self,
        routing_id: [u8; 32],
    ) -> (SubscriberId, mpsc::UnboundedReceiver<RelayMessage>) {
        let id = SubscriberId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = mpsc::unbounded_channel();
        self.subscribers
            .entry(routing_id)
            .or_default()
            .push((id, tx));
        (id, rx)
    }

    /// Removes a specific subscriber from a routing ID.
    ///
    /// Returns `true` if the subscriber was found and removed.
    pub fn unsubscribe(&mut self, routing_id: &[u8; 32], subscriber_id: SubscriberId) -> bool {
        if let Some(subs) = self.subscribers.get_mut(routing_id) {
            let len_before = subs.len();
            subs.retain(|(id, _)| *id != subscriber_id);
            let removed = subs.len() < len_before;
            if subs.is_empty() {
                self.subscribers.remove(routing_id);
            }
            removed
        } else {
            false
        }
    }

    /// Delivers a message to all subscribers of the given routing ID.
    ///
    /// Subscribers whose channels have been closed are silently removed.
    /// Returns the number of subscribers that successfully received the message.
    pub fn deliver(&mut self, routing_id: &[u8; 32], message: &RelayMessage) -> usize {
        let Some(subs) = self.subscribers.get_mut(routing_id) else {
            return 0;
        };

        let mut delivered = 0usize;
        subs.retain(|(_, tx)| {
            if tx.send(message.clone()).is_ok() {
                delivered += 1;
                true
            } else {
                // Channel closed — remove dead subscriber.
                false
            }
        });

        if subs.is_empty() {
            self.subscribers.remove(routing_id);
        }

        delivered
    }

    /// Delivers a message to a specific subscriber, regardless of routing ID.
    ///
    /// Returns `true` if the subscriber was found and the message was sent
    /// successfully.
    pub fn deliver_to(&mut self, subscriber_id: SubscriberId, message: RelayMessage) -> bool {
        for subs in self.subscribers.values_mut() {
            for (id, tx) in subs.iter() {
                if *id == subscriber_id {
                    return tx.send(message).is_ok();
                }
            }
        }
        false
    }

    /// Removes a subscriber from all routing IDs.
    ///
    /// Returns the number of routing IDs the subscriber was removed from.
    pub fn disconnect(&mut self, subscriber_id: SubscriberId) -> usize {
        let mut removed_count = 0usize;
        self.subscribers.retain(|_, subs| {
            let len_before = subs.len();
            subs.retain(|(id, _)| *id != subscriber_id);
            if subs.len() < len_before {
                removed_count += 1;
            }
            !subs.is_empty()
        });
        removed_count
    }

    /// Returns the total number of active subscriptions across all routing IDs.
    #[must_use]
    pub fn count(&self) -> usize {
        self.subscribers.values().map(Vec::len).sum()
    }

    /// Returns the number of subscribers for a specific routing ID.
    #[must_use]
    pub fn count_for_routing_id(&self, routing_id: &[u8; 32]) -> usize {
        self.subscribers.get(routing_id).map_or(0, Vec::len)
    }

    /// Returns a reference to the subscriber list for a routing ID, if any.
    ///
    /// This is used internally by [`InMemoryRelay`](super::InMemoryRelay) for
    /// per-subscriber fault injection (e.g., equivocation).
    #[must_use]
    pub fn subscribers_for(
        &self,
        routing_id: &[u8; 32],
    ) -> Option<&Vec<(SubscriberId, mpsc::UnboundedSender<RelayMessage>)>> {
        self.subscribers.get(routing_id)
    }
}

impl Default for SubscriptionRegistry {
    fn default() -> Self {
        Self::new()
    }
}
