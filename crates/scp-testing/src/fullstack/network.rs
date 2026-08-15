//! Full-stack network factory.
//!
//! [`FullStackNetwork`] creates [`FullStackNode`]s that share a common
//! [`KeyExchange`] (for sealed-invitation / access-key / sender-key bootstrap
//! bytes) and a node registry (so the creator side can reach a joiner's
//! supervisor to reserve its own MLS `KeyPackage` and publish its wrapping keypair
//! during `add_member`).
//!
//! Every node in one network resolves its verifying keys through a single
//! deterministic, **persona-aware** [`KeyResolver`] the network owns (ADR-039):
//! `#active` maps to `SigningKey::from_bytes(did_to_seed(did))` — exactly the
//! key each node signs with AND the key a joiner's `#active` custody imports,
//! so `Supervisor::invite_member` (which seals to the resolved invitee key) and
//! governance vote verification both work without any per-test resolver wiring
//! — and `#agent` maps to a genuinely different key,
//! `SigningKey::from_bytes(did_to_agent_seed(did))`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use scp_core::context::governance::KeyResolver;
use scp_did::DID;

use super::crypto::E2eCryptoProvider;
use super::exchange::KeyExchange;
use super::node::{FullStackNode, NodeRegistry, NodeShared, did_to_agent_seed, did_to_seed};

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

    /// The network's deterministic **persona-aware** key resolver (ADR-039).
    ///
    /// Each DID resolves to a DIFFERENT verifying key per verification method:
    /// - `#active` → `SigningKey::from_bytes(did_to_seed(did))` — the key each
    ///   node signs with by default and the key a joiner's `#active` custody
    ///   imports, so `invite_member` seals to a key the joiner can open and
    ///   governance vote verification succeeds.
    /// - `#agent` → `SigningKey::from_bytes(did_to_agent_seed(did))` — the
    ///   node's autonomous-agent key.
    ///
    /// This resolver previously ignored the requested method (`|did, _kid|`)
    /// and answered the `#active` key for both. That made every declared-method
    /// assertion in this harness VACUOUS: an envelope stamped `#agent` but
    /// signed `#active` verified, and a judge resolving the wrong method still
    /// succeeded, so a test could not distinguish a correct implementation from
    /// one that dropped the declaration entirely. Two distinct keys restore the
    /// production property — the declared method must match the key that
    /// signed, or verification fails.
    #[must_use]
    fn resolver() -> KeyResolver {
        Arc::new(|did: &DID, kid: scp_did::SigningKeyId| {
            let seed = match kid {
                scp_did::SigningKeyId::Active => did_to_seed(did),
                scp_did::SigningKeyId::Agent => did_to_agent_seed(did),
            };
            Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
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
