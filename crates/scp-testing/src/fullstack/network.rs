//! Full-stack network factory.
//!
//! [`FullStackNetwork`] creates [`FullStackNode`]s that share a common
//! [`KeyExchange`] for Welcome message and sender key coordination.

use std::sync::{Arc, Mutex};

use scp_core::context::governance::KeyResolver;
use scp_identity::DID;

use super::crypto::E2eCryptoProvider;
use super::exchange::KeyExchange;
use super::node::FullStackNode;

/// Factory for creating `FullStackNode`s that share a `KeyExchange`.
///
/// All nodes created by the same `FullStackNetwork` can exchange Welcome
/// messages and sender keys through the shared `KeyExchange`.
pub struct FullStackNetwork {
    /// Shared key exchange for Welcome messages and sender keys.
    exchange: Arc<Mutex<KeyExchange>>,
}

impl FullStackNetwork {
    /// Creates a new full-stack network.
    #[must_use]
    pub fn new() -> Self {
        Self {
            exchange: Arc::new(Mutex::new(KeyExchange::new())),
        }
    }

    /// Creates a new node with the given DID.
    ///
    /// The node's `E2eCryptoProvider` shares the network's `KeyExchange`.
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
        FullStackNode::new(did_value, crypto, key_resolver)
    }
}

impl Default for FullStackNetwork {
    fn default() -> Self {
        Self::new()
    }
}
