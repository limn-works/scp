//! Which node record kind a blob is (`09-security-model.md` §9.10.12, the
//! per-kind table).
//!
//! A node tells a record kind from a blob under the shared TTL by two tests
//! together: the frame's version byte, and the routing derivation the kind
//! registers, computed over the frame's identifier field and compared with
//! the routing id the blob is published at (§9.7.4.2 R13, §9.6.3 for
//! `scp:nls:`, §9.7.4 for the `KeyPackage` set). §9.10.12: "It can execute all
//! three because it decodes the blob and confirms the routing id against the
//! derivation the kind registers".

use scp_did::Identifier;
use scp_kel::{RoutingKind, node_list_routing_id, routing_id};

use super::conflict::CONFLICT_FRAME_VERSION;
use super::frame::split_frame;
use super::key_events::KEY_EVENT_FRAME_VERSION;
use super::list::{NODE_LIST_FRAME_VERSION, decode_node_list_frame};
use super::service::SERVICE_RECORD_FRAME_VERSION;
use crate::crypto::envelope_seal::derive_key_package_routing_id;

/// The cosigned-head record's version byte (§9.10.12).
pub const COSIGNED_HEAD_FRAME_VERSION: u8 = 3;

/// The `KeyPackage` set frame's version byte (§9.10.12).
pub const KEY_PACKAGE_SET_FRAME_VERSION: u8 = 7;

/// The node record kinds of §9.10.12's table that a frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRecordKind {
    /// `0x02` at `scp:did:`.
    KeyEvents,
    /// `0x03` at `scp:wit:`.
    CosignedHeads,
    /// `0x04` at `scp:wcf:`.
    ConflictStatements,
    /// `0x05` at `scp:svc:`.
    ServiceRecord,
    /// `0x06` at `scp:nls:`.
    NodeList,
    /// `0x07` at the subject's `KeyPackage` routing id.
    KeyPackageSet,
}

impl NodeRecordKind {
    /// The kind a version byte names, before any routing check.
    #[must_use]
    pub const fn from_version(version: u8) -> Option<Self> {
        match version {
            KEY_EVENT_FRAME_VERSION => Some(Self::KeyEvents),
            COSIGNED_HEAD_FRAME_VERSION => Some(Self::CosignedHeads),
            CONFLICT_FRAME_VERSION => Some(Self::ConflictStatements),
            SERVICE_RECORD_FRAME_VERSION => Some(Self::ServiceRecord),
            NODE_LIST_FRAME_VERSION => Some(Self::NodeList),
            KEY_PACKAGE_SET_FRAME_VERSION => Some(Self::KeyPackageSet),
            _ => None,
        }
    }

    /// The kind's frame version byte.
    #[must_use]
    pub const fn version(self) -> u8 {
        match self {
            Self::KeyEvents => KEY_EVENT_FRAME_VERSION,
            Self::CosignedHeads => COSIGNED_HEAD_FRAME_VERSION,
            Self::ConflictStatements => CONFLICT_FRAME_VERSION,
            Self::ServiceRecord => SERVICE_RECORD_FRAME_VERSION,
            Self::NodeList => NODE_LIST_FRAME_VERSION,
            Self::KeyPackageSet => KEY_PACKAGE_SET_FRAME_VERSION,
        }
    }

    /// Whether the kind is one of the five a node retains with no TTL and a
    /// PUBLISH must flag `retain` (§9.10.12).
    #[must_use]
    pub const fn is_retained(self) -> bool {
        !matches!(self, Self::KeyPackageSet)
    }

    /// The routing id the kind's derivation yields for an identifier-keyed
    /// kind; `None` for [`NodeList`](Self::NodeList), whose derivation reads
    /// the `context_id` inside the record.
    #[must_use]
    pub fn routing_id_for(self, identifier: &Identifier) -> Option<[u8; 32]> {
        let kind = match self {
            Self::KeyEvents => RoutingKind::KeyEvents,
            Self::CosignedHeads => RoutingKind::CosignedHeads,
            Self::ConflictStatements => RoutingKind::ConflictStatements,
            Self::ServiceRecord => RoutingKind::ServiceRecord,
            Self::KeyPackageSet => {
                return Some(derive_key_package_routing_id(&identifier.to_string()));
            }
            Self::NodeList => return None,
        };
        Some(routing_id(kind, identifier))
    }
}

/// The kind whose version byte opens `blob` and whose routing derivation
/// over the frame yields `routing_id`; `None` for every other blob.
///
/// A `0x06` frame is decoded to read its `context_id`, which has no fixed
/// width and so takes no frame field (§9.10.12).
#[must_use]
pub fn classify_node_record(routing: &[u8; 32], blob: &[u8]) -> Option<NodeRecordKind> {
    let kind = NodeRecordKind::from_version(*blob.first()?)?;
    let routed = if kind == NodeRecordKind::NodeList {
        decode_node_list_frame(blob)
            .is_ok_and(|record| node_list_routing_id(&record.context_id) == *routing)
    } else {
        split_frame(blob, kind.version())
            .ok()
            .and_then(|(identifier, _)| kind.routing_id_for(&identifier))
            .is_some_and(|derived| derived == *routing)
    };
    routed.then_some(kind)
}

#[cfg(test)]
mod tests {
    use super::super::frame::join_frame;
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn each_identifier_kind_classifies_only_at_its_own_derivation() -> TestResult {
        let identifier = Identifier::from_bytes([5; 32]);
        let kinds = [
            NodeRecordKind::KeyEvents,
            NodeRecordKind::CosignedHeads,
            NodeRecordKind::ConflictStatements,
            NodeRecordKind::ServiceRecord,
            NodeRecordKind::KeyPackageSet,
        ];
        for kind in kinds {
            let blob = join_frame(kind.version(), &identifier, b"v");
            let own = kind
                .routing_id_for(&identifier)
                .ok_or_else(|| format!("{kind:?} has an identifier derivation"))?;
            assert_eq!(classify_node_record(&own, &blob), Some(kind));
            for other in kinds.iter().filter(|other| **other != kind) {
                let elsewhere = other
                    .routing_id_for(&identifier)
                    .ok_or_else(|| format!("{other:?} has an identifier derivation"))?;
                assert_eq!(
                    classify_node_record(&elsewhere, &blob),
                    None,
                    "{kind:?} at {other:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn a_blob_with_no_frame_version_is_unclassified() {
        assert_eq!(classify_node_record(&[0; 32], &[0x84, 1, 2]), None);
        assert_eq!(classify_node_record(&[0; 32], &[]), None);
        assert_eq!(classify_node_record(&[0; 32], &[2]), None);
    }

    #[test]
    fn only_the_key_package_set_is_unretained() -> TestResult {
        for version in 2..=7 {
            let kind = NodeRecordKind::from_version(version)
                .ok_or_else(|| format!("version {version} names a kind"))?;
            assert_eq!(kind.version(), version);
            assert_eq!(kind.is_retained(), version != 7);
        }
        assert_eq!(NodeRecordKind::from_version(1), None);
        assert_eq!(NodeRecordKind::from_version(8), None);
        Ok(())
    }
}
