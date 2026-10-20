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
    KEY_EVENTS_ROUTING_SEPARATOR, SERVICE_RECORD_ROUTING_SEPARATOR,
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
