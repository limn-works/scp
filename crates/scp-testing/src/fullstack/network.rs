//! Full-stack network factory.
//!
//! [`FullStackNetwork`] creates [`FullStackNode`]s that share a common
//! [`KeyExchange`] (for sealed-invitation / access-key / sender-key bootstrap
//! bytes) and a node registry (so the creator side can reach a joiner's
//! supervisor to reserve its own MLS `KeyPackage` and publish its wrapping keypair
//! during `add_member`).
//!
//! Every node in one network resolves its `#active` verifying key through a
//! single deterministic [`KeyResolver`] the network owns: it maps each DID to
//! `SigningKey::from_bytes(did_to_seed(did)).verifying_key()` — exactly the key
//! each node signs with AND the key a joiner's #active custody imports, so
//! `Supervisor::invite_member` (which seals to the resolved invitee key) and
//! governance vote verification both work without any per-test resolver wiring.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use scp_core::context::governance::KeyResolver;
use scp_did::DID;

use super::crypto::E2eCryptoProvider;
use super::exchange::KeyExchange;
use super::node::{FullStackNode, NodeRegistry, NodeShared, did_to_seed};

/// Factory for creating `FullStackNode`s that share a `KeyExchange` and a node
/// registry.
///
/// All nodes created by the same `FullStackNetwork` can exchange sealed
/// invitation / access-key / sender-key bootstrap bytes through the shared
/// `KeyExchange`, and the creator side can reach a joiner's supervisor + crypto
/// helper through the registry.
pub struct FullStackNetwork {
    /// Shared key-exchange side channel.
    exchange: Arc<Mutex<KeyExchange>>,
    /// Registry of every node's shared handles, keyed by DID.
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

    /// The network's deterministic `#active` key resolver: maps every DID to
    /// `SigningKey::from_bytes(did_to_seed(did)).verifying_key()`. This is the
    /// same key each node signs with and the key a joiner's #active custody
    /// imports, so `invite_member` seals to a key the joiner can open and
    /// governance vote verification succeeds.
    #[must_use]
    fn resolver() -> KeyResolver {
        Arc::new(|did: &DID, _kid: scp_did::SigningKeyId| {
            Some(ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did)).verifying_key())
        })
    }

    /// Creates a new node with the given DID.
    ///
    /// The node's [`E2eCryptoProvider`] shares the network's `KeyExchange`, and
    /// the node's shared handles are registered so it can act as a joiner in
    /// later `add_member` calls. The node's `#active` resolver is the network's
    /// deterministic [`resolver`](Self::resolver) — no per-test resolver wiring.
    #[must_use]
    pub fn create_node(&self, did: &str) -> FullStackNode {
        let did_value = DID(did.to_owned());
        let crypto = Arc::new(E2eCryptoProvider::new(
            did_value.clone(),
            Arc::clone(&self.exchange),
        ));
        let node = FullStackNode::new(
            did_value,
            Arc::clone(&crypto),
            Self::resolver(),
            Arc::clone(&self.registry),
        );
        // Register the node's shared handles AFTER it is built (its `manager`
        // now exists) so the creator side can reserve this node's own
        // KeyPackage and publish its wrapping keypair when inviting it.
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                did.to_owned(),
                NodeShared {
                    manager: Arc::clone(&node.manager),
                    crypto,
                },
            );
        node
    }
}

impl Default for FullStackNetwork {
    fn default() -> Self {
        Self::new()
    }
}
