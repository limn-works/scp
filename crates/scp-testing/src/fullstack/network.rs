//! Full-stack network factory.
//!
//! [`FullStackNetwork`] creates [`FullStackNode`]s that share a common
//! [`KeyExchange`] (for Welcome / access-key / sender-key bootstrap bytes) and
//! a node registry (so the creator side can reach a joiner's provider to mint
//! its real MLS key package during `add_member`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use scp_core::context::governance::KeyResolver;
use scp_did::DID;

use super::crypto::E2eCryptoProvider;
use super::exchange::KeyExchange;
use super::node::{FullStackNode, NodeRegistry};

/// Factory for creating `FullStackNode`s that share a `KeyExchange` and a node
/// registry.
///
/// All nodes created by the same `FullStackNetwork` can exchange Welcome /
/// access-key / sender-key bootstrap bytes through the shared `KeyExchange`,
/// and the creator side can reach a joiner's provider through the registry.
pub struct FullStackNetwork {
    /// Shared key-exchange side channel.
    exchange: Arc<Mutex<KeyExchange>>,
    /// Registry of every node's crypto helper, keyed by DID.
    registry: NodeRegistry,
}

impl FullStackNetwork {
    /// Creates a new full-stack network.
    #[must_use]
    pub fn new() -> Self {
        Self {
            exchange: Arc::new(Mutex::new(KeyExchange::new())),
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Creates a new node with the given DID.
    ///
    /// The node's [`E2eCryptoProvider`] shares the network's `KeyExchange`, and
    /// the node is registered so it can act as a joiner in later `add_member`
    /// calls.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID for this node.
    /// * `key_resolver` - Resolver for governance vote verification.
    #[must_use]
    pub fn create_node(&self, did: &str, key_resolver: KeyResolver) -> FullStackNode {
        let did_value = DID(did.to_owned());
        let crypto = Arc::new(E2eCryptoProvider::new(
            did_value.clone(),
            Arc::clone(&self.exchange),
        ));
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(did.to_owned(), Arc::clone(&crypto));
        FullStackNode::new(did_value, crypto, key_resolver, Arc::clone(&self.registry))
    }
}

impl Default for FullStackNetwork {
    fn default() -> Self {
        Self::new()
    }
}
