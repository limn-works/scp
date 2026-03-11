//! Network topology graph for simulated network scenarios.
//!
//! Tracks bidirectional reachability between named nodes and optional per-link
//! configuration (latency, packet loss). Used by [`super::NetworkSimulator`]
//! to model network partitions, healing, and isolation.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

/// Per-link network configuration.
#[derive(Clone, Debug)]
pub struct LinkConfig {
    /// Simulated latency in milliseconds.
    pub latency_ms: u64,
    /// Packet loss probability (0.0 = none, 1.0 = total).
    pub packet_loss: f64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            latency_ms: 0,
            packet_loss: 0.0,
        }
    }
}

/// Network topology graph tracking reachability between nodes.
///
/// Nodes are identified by string labels (e.g., relay names or DID strings).
/// The graph is directional -- `connect(a, b)` makes both reachable from each
/// other (bidirectional). Partitioning removes links in both directions.
///
/// Isolated nodes (via [`isolate`](Self::isolate)) have all links removed.
/// Healing restores links with default configuration.
pub struct NetworkTopology {
    /// Adjacency list: node -> set of directly reachable nodes.
    adjacency: HashMap<String, HashSet<String>>,
    /// Per-link configuration keyed by `(from, to)` pairs.
    link_configs: HashMap<(String, String), LinkConfig>,
    /// Snapshot of all links before any partitions, for `heal_all`.
    snapshot: Vec<(String, String, LinkConfig)>,
}

impl NetworkTopology {
    /// Creates a new empty topology with no nodes or links.
    #[must_use]
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            link_configs: HashMap::new(),
            snapshot: Vec::new(),
        }
    }

    /// Adds a bidirectional link between `a` and `b` with default configuration.
    pub fn connect(&mut self, a: impl Into<String>, b: impl Into<String>) {
        self.connect_with(a, b, LinkConfig::default());
    }

    /// Adds a bidirectional link between `a` and `b` with the given configuration.
    pub fn connect_with(&mut self, a: impl Into<String>, b: impl Into<String>, config: LinkConfig) {
        let a = a.into();
        let b = b.into();

        self.adjacency
            .entry(a.clone())
            .or_default()
            .insert(b.clone());
        self.adjacency
            .entry(b.clone())
            .or_default()
            .insert(a.clone());

        self.link_configs
            .insert((a.clone(), b.clone()), config.clone());
        self.link_configs
            .insert((b.clone(), a.clone()), config.clone());

        // Record in snapshot for heal_all.
        self.snapshot.push((a, b, config));
    }

    /// Removes the bidirectional link between `a` and `b`.
    pub fn partition(&mut self, a: &str, b: &str) {
        if let Some(neighbors) = self.adjacency.get_mut(a) {
            neighbors.remove(b);
        }
        if let Some(neighbors) = self.adjacency.get_mut(b) {
            neighbors.remove(a);
        }
        self.link_configs.remove(&(a.to_owned(), b.to_owned()));
        self.link_configs.remove(&(b.to_owned(), a.to_owned()));
    }

    /// Removes all links to and from the given node, isolating it completely.
    pub fn isolate(&mut self, node: &str) {
        // Collect neighbors first to avoid borrow issues.
        let neighbors: Vec<String> = self
            .adjacency
            .get(node)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        // Remove node from each neighbor's adjacency set.
        for neighbor in &neighbors {
            if let Some(set) = self.adjacency.get_mut(neighbor.as_str()) {
                set.remove(node);
            }
            self.link_configs
                .remove(&(neighbor.clone(), node.to_owned()));
        }

        // Clear node's own adjacency set.
        if let Some(set) = self.adjacency.get_mut(node) {
            set.clear();
        }

        // Remove outbound link configs.
        self.link_configs.retain(|key, _| key.0 != node);
    }

    /// Restores the bidirectional link between `a` and `b` with default
    /// configuration.
    pub fn heal(&mut self, a: &str, b: &str) {
        self.adjacency
            .entry(a.to_owned())
            .or_default()
            .insert(b.to_owned());
        self.adjacency
            .entry(b.to_owned())
            .or_default()
            .insert(a.to_owned());

        self.link_configs
            .insert((a.to_owned(), b.to_owned()), LinkConfig::default());
        self.link_configs
            .insert((b.to_owned(), a.to_owned()), LinkConfig::default());
    }

    /// Restores all links to their original state (as recorded at connect time).
    pub fn heal_all(&mut self) {
        // Clear current state.
        self.adjacency.clear();
        self.link_configs.clear();

        // Replay the snapshot.
        for (a, b, config) in &self.snapshot {
            self.adjacency
                .entry(a.clone())
                .or_default()
                .insert(b.clone());
            self.adjacency
                .entry(b.clone())
                .or_default()
                .insert(a.clone());
            self.link_configs
                .insert((a.clone(), b.clone()), config.clone());
            self.link_configs
                .insert((b.clone(), a.clone()), config.clone());
        }
    }

    /// Returns `true` if `to` is directly reachable from `from`.
    #[must_use]
    pub fn can_reach(&self, from: &str, to: &str) -> bool {
        self.adjacency
            .get(from)
            .is_some_and(|neighbors| neighbors.contains(to))
    }

    /// Returns all nodes directly reachable from `node`.
    #[must_use]
    pub fn reachable_from(&self, node: &str) -> Vec<&str> {
        self.adjacency
            .get(node)
            .map(|neighbors| neighbors.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Returns the link configuration for the `from -> to` direction, if the
    /// link exists.
    #[must_use]
    pub fn link_config(&self, from: &str, to: &str) -> Option<&LinkConfig> {
        self.link_configs.get(&(from.to_owned(), to.to_owned()))
    }

    /// Returns the total number of distinct nodes in the topology.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.adjacency.len()
    }
}

impl Default for NetworkTopology {
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

    #[test]
    fn connect_creates_bidirectional_link() {
        let mut topo = NetworkTopology::new();
        topo.connect("a", "b");
        assert!(topo.can_reach("a", "b"));
        assert!(topo.can_reach("b", "a"));
    }

    #[test]
    fn connect_with_stores_config() {
        let mut topo = NetworkTopology::new();
        topo.connect_with(
            "a",
            "b",
            LinkConfig {
                latency_ms: 50,
                packet_loss: 0.1,
            },
        );
        let cfg = topo.link_config("a", "b").unwrap();
        assert_eq!(cfg.latency_ms, 50);
        let cfg_rev = topo.link_config("b", "a").unwrap();
        assert_eq!(cfg_rev.latency_ms, 50);
    }

    #[test]
    fn partition_removes_bidirectional_link() {
        let mut topo = NetworkTopology::new();
        topo.connect("a", "b");
        topo.connect("a", "c");
        topo.partition("a", "b");
        assert!(!topo.can_reach("a", "b"));
        assert!(!topo.can_reach("b", "a"));
        // a-c should still be intact.
        assert!(topo.can_reach("a", "c"));
    }

    #[test]
    fn isolate_removes_all_links() {
        let mut topo = NetworkTopology::new();
        topo.connect("a", "b");
        topo.connect("a", "c");
        topo.connect("b", "c");
        topo.isolate("a");
        assert!(!topo.can_reach("a", "b"));
        assert!(!topo.can_reach("a", "c"));
        assert!(!topo.can_reach("b", "a"));
        assert!(!topo.can_reach("c", "a"));
        // b-c should still be intact.
        assert!(topo.can_reach("b", "c"));
    }

    #[test]
    fn heal_restores_link_with_defaults() {
        let mut topo = NetworkTopology::new();
        topo.connect_with(
            "a",
            "b",
            LinkConfig {
                latency_ms: 100,
                packet_loss: 0.5,
            },
        );
        topo.partition("a", "b");
        assert!(!topo.can_reach("a", "b"));
        topo.heal("a", "b");
        assert!(topo.can_reach("a", "b"));
        // Healed with defaults.
        let cfg = topo.link_config("a", "b").unwrap();
        assert_eq!(cfg.latency_ms, 0);
    }

    #[test]
    fn heal_all_restores_all_links() {
        let mut topo = NetworkTopology::new();
        topo.connect("a", "b");
        topo.connect("b", "c");
        topo.isolate("b");
        assert!(!topo.can_reach("a", "b"));
        assert!(!topo.can_reach("b", "c"));
        topo.heal_all();
        assert!(topo.can_reach("a", "b"));
        assert!(topo.can_reach("b", "c"));
    }

    #[test]
    fn reachable_from_returns_neighbors() {
        let mut topo = NetworkTopology::new();
        topo.connect("a", "b");
        topo.connect("a", "c");
        let mut reachable = topo.reachable_from("a");
        reachable.sort_unstable();
        assert_eq!(reachable, vec!["b", "c"]);
    }

    #[test]
    fn reachable_from_unknown_node_returns_empty() {
        let topo = NetworkTopology::new();
        assert!(topo.reachable_from("ghost").is_empty());
    }

    #[test]
    fn node_count_tracks_distinct_nodes() {
        let mut topo = NetworkTopology::new();
        assert_eq!(topo.node_count(), 0);
        topo.connect("a", "b");
        assert_eq!(topo.node_count(), 2);
        topo.connect("b", "c");
        assert_eq!(topo.node_count(), 3);
    }

    #[test]
    fn can_reach_unknown_node_returns_false() {
        let topo = NetworkTopology::new();
        assert!(!topo.can_reach("x", "y"));
    }

    #[test]
    fn link_config_returns_none_for_missing_link() {
        let topo = NetworkTopology::new();
        assert!(topo.link_config("x", "y").is_none());
    }
}
