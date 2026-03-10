//! Fluent builder for constructing [`NetworkSimulator`] instances.
//!
//! The [`ScenarioBuilder`] provides a declarative API for setting up test
//! scenarios with multiple relays, identities, and topology links. Call
//! [`build`](ScenarioBuilder::build) to finalize and obtain the simulator.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use scp_identity::DID;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

use crate::clock::SimulatedClock;
use crate::relay::{BehaviorMode, InMemoryRelay};
use crate::simulator::{NetworkSimulator, SimulatedIdentity};

/// Error type for scenario building failures.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// No relays were configured before building.
    #[error("no relays configured")]
    NoRelays,
    /// No identities were configured before building.
    #[error("no identities configured")]
    NoIdentities,
    /// Identity creation failed for the given reason.
    #[error("identity creation failed: {0}")]
    IdentityCreation(String),
    /// A duplicate label was detected.
    #[error("duplicate label: {0}")]
    DuplicateLabel(String),
}

/// Specification for a relay to be created at build time.
struct RelaySpec {
    name: String,
    behavior: BehaviorMode,
}

/// Specification for a topology link to be created at build time.
struct LinkSpec {
    a: String,
    b: String,
}

/// Fluent builder for constructing test scenarios.
///
/// # Example
///
/// ```rust,ignore
/// let sim = ScenarioBuilder::new()
///     .relay("relay-1")
///     .relay_with("relay-2", BehaviorMode::DeletionNonCompliant)
///     .identity("alice")
///     .identity("bob")
///     .connect("relay-1", "relay-2")
///     .build()?;
/// ```
pub struct ScenarioBuilder {
    /// Clock start time in seconds.
    clock_start_secs: u64,
    /// Relay specifications.
    relays: Vec<RelaySpec>,
    /// Identity labels.
    identity_labels: Vec<String>,
    /// Topology link specifications.
    links: Vec<LinkSpec>,
    /// Whether to create a full mesh at build time.
    full_mesh: bool,
}

impl ScenarioBuilder {
    /// Creates a new builder with a default clock starting at 1,000,000 seconds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clock_start_secs: 1_000_000,
            relays: Vec::new(),
            identity_labels: Vec::new(),
            links: Vec::new(),
            full_mesh: false,
        }
    }

    /// Sets the simulated clock start time in seconds.
    #[must_use]
    pub const fn clock_start(mut self, secs: u64) -> Self {
        self.clock_start_secs = secs;
        self
    }

    /// Adds a relay with [`BehaviorMode::Normal`].
    pub fn relay(&mut self, name: impl Into<String>) -> &mut Self {
        self.relays.push(RelaySpec {
            name: name.into(),
            behavior: BehaviorMode::Normal,
        });
        self
    }

    /// Adds a relay with the given behavior mode.
    pub fn relay_with(&mut self, name: impl Into<String>, behavior: BehaviorMode) -> &mut Self {
        self.relays.push(RelaySpec {
            name: name.into(),
            behavior,
        });
        self
    }

    /// Adds an identity label. The actual `SimulatedIdentity` is created at
    /// build time.
    pub fn identity(&mut self, label: impl Into<String>) -> &mut Self {
        self.identity_labels.push(label.into());
        self
    }

    /// Adds a topology link between two nodes.
    pub fn connect(&mut self, a: impl Into<String>, b: impl Into<String>) -> &mut Self {
        self.links.push(LinkSpec {
            a: a.into(),
            b: b.into(),
        });
        self
    }

    /// Marks the topology as full-mesh: all relay and identity nodes will be
    /// connected to each other at build time.
    pub const fn full_mesh(&mut self) -> &mut Self {
        self.full_mesh = true;
        self
    }

    /// Consumes the builder and produces a configured [`NetworkSimulator`].
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::NoRelays`] if no relays were configured.
    /// Returns [`BuilderError::NoIdentities`] if no identities were configured.
    /// Returns [`BuilderError::DuplicateLabel`] if any relay name or identity
    /// label appears more than once.
    pub fn build(&self) -> Result<NetworkSimulator, BuilderError> {
        if self.relays.is_empty() {
            return Err(BuilderError::NoRelays);
        }
        if self.identity_labels.is_empty() {
            return Err(BuilderError::NoIdentities);
        }

        // Check for duplicate relay names.
        let mut seen = HashSet::new();
        for spec in &self.relays {
            if !seen.insert(&spec.name) {
                return Err(BuilderError::DuplicateLabel(spec.name.clone()));
            }
        }

        // Check for duplicate identity labels.
        let mut seen = HashSet::new();
        for label in &self.identity_labels {
            if !seen.insert(label) {
                return Err(BuilderError::DuplicateLabel(label.clone()));
            }
        }

        // Create clock.
        let clock = Arc::new(SimulatedClock::new(self.clock_start_secs));

        // Create simulator.
        let mut sim = NetworkSimulator::new(clock);

        // Create relays.
        for spec in &self.relays {
            let relay = Arc::new(Mutex::new(InMemoryRelay::with_behavior(
                spec.behavior.clone(),
            )));
            sim.add_relay(spec.name.clone(), relay);
        }

        // Create identities.
        for label in &self.identity_labels {
            let did = DID::from(format!("did:test:{label}"));
            let custody = Arc::new(InMemoryKeyCustody::new());
            let storage = InMemoryStorage::new();
            let identity = SimulatedIdentity::new(label.clone(), did, custody, storage);
            sim.add_identity(identity);
        }

        // Set up topology links.
        for link in &self.links {
            sim.topology_mut().connect(link.a.clone(), link.b.clone());
        }

        // Full mesh: connect every node to every other node.
        if self.full_mesh {
            let mut all_nodes: Vec<String> = Vec::new();
            for spec in &self.relays {
                all_nodes.push(spec.name.clone());
            }
            for label in &self.identity_labels {
                all_nodes.push(label.clone());
            }
            for i in 0..all_nodes.len() {
                for j in (i + 1)..all_nodes.len() {
                    sim.topology_mut()
                        .connect(all_nodes[i].clone(), all_nodes[j].clone());
                }
            }
        }

        Ok(sim)
    }
}

impl Default for ScenarioBuilder {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn build_minimal_scenario() {
        let sim = ScenarioBuilder::new()
            .relay("relay-1")
            .identity("alice")
            .build()
            .unwrap();
        assert_eq!(sim.relay_names().len(), 1);
        assert_eq!(sim.identity_labels().len(), 1);
        assert!(sim.identity("alice").is_some());
        assert!(sim.relay("relay-1").is_some());
    }

    #[test]
    fn build_fails_without_relays() {
        let result = ScenarioBuilder::new().identity("alice").build();
        assert!(matches!(result, Err(BuilderError::NoRelays)));
    }

    #[test]
    fn build_fails_without_identities() {
        let result = ScenarioBuilder::new().relay("r1").build();
        assert!(matches!(result, Err(BuilderError::NoIdentities)));
    }

    #[test]
    fn build_fails_on_duplicate_relay() {
        let result = ScenarioBuilder::new()
            .relay("r1")
            .relay("r1")
            .identity("alice")
            .build();
        assert!(matches!(result, Err(BuilderError::DuplicateLabel(_))));
    }

    #[test]
    fn build_fails_on_duplicate_identity() {
        let result = ScenarioBuilder::new()
            .relay("r1")
            .identity("alice")
            .identity("alice")
            .build();
        assert!(matches!(result, Err(BuilderError::DuplicateLabel(_))));
    }

    #[test]
    fn build_with_custom_clock_start() {
        let sim = ScenarioBuilder::new()
            .clock_start(5000)
            .relay("r1")
            .identity("alice")
            .build()
            .unwrap();
        assert_eq!(sim.clock().now_secs(), 5000);
    }

    #[test]
    fn build_with_topology_links() {
        let sim = ScenarioBuilder::new()
            .relay("r1")
            .relay("r2")
            .identity("alice")
            .connect("r1", "r2")
            .build()
            .unwrap();
        assert!(sim.topology().can_reach("r1", "r2"));
        assert!(sim.topology().can_reach("r2", "r1"));
    }

    #[test]
    fn build_with_full_mesh() {
        let sim = ScenarioBuilder::new()
            .relay("r1")
            .relay("r2")
            .identity("alice")
            .identity("bob")
            .full_mesh()
            .build()
            .unwrap();
        assert!(sim.topology().can_reach("r1", "r2"));
        assert!(sim.topology().can_reach("r1", "alice"));
        assert!(sim.topology().can_reach("alice", "bob"));
        assert!(sim.topology().can_reach("r2", "bob"));
    }

    #[test]
    fn identity_has_correct_did() {
        let sim = ScenarioBuilder::new()
            .relay("r1")
            .identity("alice")
            .build()
            .unwrap();
        let alice = sim.identity("alice").unwrap();
        assert_eq!(alice.did().as_ref(), "did:test:alice");
        assert_eq!(alice.label(), "alice");
    }

    #[test]
    fn relay_with_custom_behavior() {
        let sim = ScenarioBuilder::new()
            .relay_with("r1", BehaviorMode::DeletionNonCompliant)
            .identity("alice")
            .build()
            .unwrap();
        let r = sim.relay("r1").unwrap();
        assert!(matches!(
            r.lock().unwrap().behavior(),
            BehaviorMode::DeletionNonCompliant
        ));
    }
}
