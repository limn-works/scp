//! Network simulator for orchestrating multi-relay, multi-identity test
//! scenarios.
//!
//! Combines [`SimulatedClock`],
//! [`InMemoryRelay`], [`SimulatedIdentity`], and
//! [`NetworkTopology`] into a single coordinator that can model partitions,
//! delays, fault injection, and time advancement.

#![forbid(unsafe_code)]

pub mod identity;
pub mod topology;

pub use identity::SimulatedIdentity;
pub use topology::{LinkConfig, NetworkTopology};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::clock::SimulatedClock;
use crate::relay::{BehaviorMode, InMemoryRelay};

/// Orchestrates simulated network scenarios with multiple relays, identities,
/// and configurable topology.
///
/// The simulator owns a shared clock, a set of named relays (behind `Mutex`
/// for interior mutability), a set of labeled identities, and a network
/// topology that tracks reachability between nodes.
pub struct NetworkSimulator {
    /// Shared simulated clock for deterministic time control.
    clock: Arc<SimulatedClock>,
    /// Named relays, each behind a `Mutex` for thread-safe mutation.
    relays: HashMap<String, Arc<Mutex<InMemoryRelay>>>,
    /// Labeled identities for test participants.
    identities: HashMap<String, SimulatedIdentity>,
    /// Network topology tracking reachability between nodes.
    topology: NetworkTopology,
}

impl NetworkSimulator {
    /// Creates a new simulator with the given clock and no relays, identities,
    /// or topology.
    #[must_use]
    pub fn new(clock: Arc<SimulatedClock>) -> Self {
        Self {
            clock,
            relays: HashMap::new(),
            identities: HashMap::new(),
            topology: NetworkTopology::new(),
        }
    }

    /// Adds a pre-constructed relay under the given name.
    pub fn add_relay(&mut self, name: impl Into<String>, relay: Arc<Mutex<InMemoryRelay>>) {
        self.relays.insert(name.into(), relay);
    }

    /// Creates a new [`InMemoryRelay`] with the given behavior and adds it
    /// under the given name.
    pub fn add_relay_with_behavior(&mut self, name: impl Into<String>, behavior: BehaviorMode) {
        let relay = Arc::new(Mutex::new(InMemoryRelay::with_behavior(behavior)));
        self.relays.insert(name.into(), relay);
    }

    /// Adds a simulated identity, keyed by its label.
    pub fn add_identity(&mut self, identity: SimulatedIdentity) {
        let label = identity.label().to_owned();
        self.identities.insert(label, identity);
    }

    /// Returns a reference to the shared clock.
    #[must_use]
    pub const fn clock(&self) -> &Arc<SimulatedClock> {
        &self.clock
    }

    /// Returns a reference to the relay with the given name, if it exists.
    #[must_use]
    pub fn relay(&self, name: &str) -> Option<&Arc<Mutex<InMemoryRelay>>> {
        self.relays.get(name)
    }

    /// Returns a reference to the identity with the given label, if it exists.
    #[must_use]
    pub fn identity(&self, label: &str) -> Option<&SimulatedIdentity> {
        self.identities.get(label)
    }

    /// Returns a mutable reference to the identity with the given label.
    #[must_use]
    pub fn identity_mut(&mut self, label: &str) -> Option<&mut SimulatedIdentity> {
        self.identities.get_mut(label)
    }

    /// Returns a reference to the network topology.
    #[must_use]
    pub const fn topology(&self) -> &NetworkTopology {
        &self.topology
    }

    /// Returns a mutable reference to the network topology.
    #[must_use]
    pub const fn topology_mut(&mut self) -> &mut NetworkTopology {
        &mut self.topology
    }

    /// Sets the behavior mode on the named relay.
    ///
    /// Returns `true` if the relay was found and updated, `false` if the name
    /// is not registered. Acquires the relay's mutex to apply the change.
    #[must_use]
    #[allow(clippy::significant_drop_tightening)]
    pub fn set_relay_behavior(&self, relay_name: &str, behavior: BehaviorMode) -> bool {
        self.relays
            .get(relay_name)
            .is_some_and(|relay_arc| match relay_arc.lock() {
                Ok(mut relay) => {
                    relay.set_behavior(behavior);
                    true
                }
                Err(poisoned) => {
                    poisoned.into_inner().set_behavior(behavior);
                    true
                }
            })
    }

    /// Advances the simulated clock by `delta_secs` seconds.
    pub fn advance_time(&self, delta_secs: u64) {
        self.clock.advance(delta_secs);
    }

    /// Returns the total number of blobs stored across all relays.
    #[must_use]
    #[allow(clippy::significant_drop_tightening)]
    pub fn total_blobs(&self) -> usize {
        self.relays
            .values()
            .map(|r| match r.lock() {
                Ok(relay) => relay.blob_count(),
                Err(poisoned) => poisoned.into_inner().blob_count(),
            })
            .sum()
    }

    /// Expires blobs across all relays using the given timestamp.
    ///
    /// Returns the total number of blobs expired.
    #[must_use]
    #[allow(clippy::significant_drop_tightening)]
    pub fn expire_all(&self, now: u64) -> usize {
        self.relays
            .values()
            .map(|r| match r.lock() {
                Ok(mut relay) => relay.expire_blobs(now),
                Err(poisoned) => poisoned.into_inner().expire_blobs(now),
            })
            .sum()
    }

    /// Returns the names of all registered relays.
    #[must_use]
    pub fn relay_names(&self) -> Vec<&str> {
        self.relays.keys().map(String::as_str).collect()
    }

    /// Returns the labels of all registered identities.
    #[must_use]
    pub fn identity_labels(&self) -> Vec<&str> {
        self.identities.keys().map(String::as_str).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::clock::Clock;
    use scp_did::DID;
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

    fn make_clock() -> Arc<SimulatedClock> {
        Arc::new(SimulatedClock::new(1_000_000))
    }

    #[test]
    fn new_simulator_is_empty() {
        let sim = NetworkSimulator::new(make_clock());
        assert!(sim.relay_names().is_empty());
        assert!(sim.identity_labels().is_empty());
        assert_eq!(sim.total_blobs(), 0);
    }

    #[test]
    fn add_relay_and_lookup() {
        let mut sim = NetworkSimulator::new(make_clock());
        sim.add_relay_with_behavior("relay-1", BehaviorMode::Normal);
        assert!(sim.relay("relay-1").is_some());
        assert!(sim.relay("nonexistent").is_none());
        assert_eq!(sim.relay_names().len(), 1);
    }

    #[test]
    fn add_identity_and_lookup() {
        let mut sim = NetworkSimulator::new(make_clock());
        let id = SimulatedIdentity::new(
            "alice",
            DID::from("did:test:alice"),
            Arc::new(InMemoryKeyCustody::new()),
            InMemoryStorage::new(),
        );
        sim.add_identity(id);
        assert!(sim.identity("alice").is_some());
        assert!(sim.identity("bob").is_none());
        assert_eq!(sim.identity_labels().len(), 1);
    }

    #[test]
    fn set_relay_behavior_returns_false_for_unknown() {
        let sim = NetworkSimulator::new(make_clock());
        assert!(!sim.set_relay_behavior("ghost", BehaviorMode::DeletionNonCompliant));
    }

    #[test]
    fn set_relay_behavior_succeeds() {
        let mut sim = NetworkSimulator::new(make_clock());
        sim.add_relay_with_behavior("r1", BehaviorMode::Normal);
        assert!(sim.set_relay_behavior("r1", BehaviorMode::DeletionNonCompliant));
    }

    #[test]
    fn advance_time_delegates_to_clock() {
        let clock = make_clock();
        let sim = NetworkSimulator::new(Arc::clone(&clock));
        let before = clock.now_secs();
        sim.advance_time(10);
        assert_eq!(clock.now_secs(), before + 10);
    }

    #[test]
    fn total_blobs_sums_across_relays() {
        let mut sim = NetworkSimulator::new(make_clock());
        sim.add_relay_with_behavior("r1", BehaviorMode::Normal);
        sim.add_relay_with_behavior("r2", BehaviorMode::Normal);

        // Store a blob in r1.
        if let Some(r) = sim.relay("r1") {
            let mut relay = r.lock().unwrap();
            relay.store([1; 32], vec![0xAB], None, 100);
        }
        assert_eq!(sim.total_blobs(), 1);
    }

    #[test]
    fn expire_all_across_relays() {
        let mut sim = NetworkSimulator::new(make_clock());
        sim.add_relay_with_behavior("r1", BehaviorMode::Normal);

        if let Some(r) = sim.relay("r1") {
            let mut relay = r.lock().unwrap();
            relay.store([1; 32], vec![0xAB], Some(10), 100);
        }
        assert_eq!(sim.total_blobs(), 1);

        // Expire at time 200 (TTL 10, stored at 100 => expired at 110).
        let expired = sim.expire_all(200);
        assert_eq!(expired, 1);
        assert_eq!(sim.total_blobs(), 0);
    }

    #[test]
    fn topology_mutation() {
        let mut sim = NetworkSimulator::new(make_clock());
        sim.topology_mut().connect("a", "b");
        assert!(sim.topology().can_reach("a", "b"));
    }
}
