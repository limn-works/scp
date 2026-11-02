//! The routing identifiers an identity's retained objects are stored under
//! (`09-security-model.md` §9.7.4.2 R13; §9.18.2's separator table).
//!
//! Each is `SHA-256(separator ‖ identifier_bytes)` over the identifier's 32
//! raw digest bytes. One function keyed by [`RoutingKind`] is the one
//! implementation of all four.

use scp_did::Identifier;
use sha2::{Digest, Sha256};

use crate::constants::{
    CONFLICT_STATEMENTS_ROUTING_SEPARATOR, COSIGNED_HEADS_ROUTING_SEPARATOR,
    KEY_EVENTS_ROUTING_SEPARATOR, NODE_LIST_ROUTING_SEPARATOR, SERVICE_RECORD_ROUTING_SEPARATOR,
};

/// The four retained object kinds an identity's routing identifiers address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutingKind {
    /// Key-event records, at `"scp:did:"`.
    KeyEvents,
    /// Witness-cosigned heads, at `"scp:wit:"`.
    CosignedHeads,
    /// Witness conflict statements, at `"scp:wcf:"`.
    ConflictStatements,
    /// The service record, at `"scp:svc:"`.
    ServiceRecord,
}

impl RoutingKind {
    /// The domain separator the kind's routing identifier is derived under.
    #[must_use]
    pub const fn separator(self) -> &'static [u8] {
        match self {
            Self::KeyEvents => KEY_EVENTS_ROUTING_SEPARATOR,
            Self::CosignedHeads => COSIGNED_HEADS_ROUTING_SEPARATOR,
            Self::ConflictStatements => CONFLICT_STATEMENTS_ROUTING_SEPARATOR,
            Self::ServiceRecord => SERVICE_RECORD_ROUTING_SEPARATOR,
        }
    }
}

/// `SHA-256(kind.separator() ‖ identifier_bytes)` (§9.7.4.2 R13).
#[must_use]
pub fn routing_id(kind: RoutingKind, identifier: &Identifier) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(kind.separator());
    hasher.update(identifier.as_bytes());
    hasher.finalize().into()
}

/// `SHA-256("scp:nls:" ‖ context_id)`, the routing identifier a node-list
/// context's records are published at (§9.6.3 "The fetch"; §9.10.12).
///
/// `context_id` is the node-list context's identifier string, hashed as its
/// UTF-8 bytes with no length prefix. A routing derivation hashes one
/// variable-length input after a fixed separator, so the input's end is the
/// preimage's end and no two inputs share a preimage. It is a separate
/// function from [`routing_id`] because its input is a context identifier
/// string, not an identity's 32-byte [`Identifier`].
#[must_use]
pub fn node_list_routing_id(context_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_LIST_ROUTING_SEPARATOR);
    hasher.update(context_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_list_routing_id_hashes_the_separator_and_the_context_id() {
        let mut hasher = Sha256::new();
        hasher.update(b"scp:nls:");
        hasher.update(b"ctx");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(node_list_routing_id("ctx"), expected);
        assert_ne!(node_list_routing_id("ctx"), node_list_routing_id("ctx2"));
    }
}
