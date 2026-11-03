//! Node wire types (`09-security-model.md` §9.6.3, §9.7.4.2 definitions,
//! §9.10.12, §9.18.2; spec 25 §25.27).
//!
//! - [`binding`]: the `NodeBinding` an operator and a node key both sign.
//! - [`frame`]: the 33-byte prefix every §9.10.12 record frame shares.
//! - [`key_events`]: the `0x02` key-event record frame at `scp:did:`.
//! - [`conflict`]: the witness conflict statement and its `0x04` frame at
//!   `scp:wcf:`.
//! - [`service`]: the service record and its `0x05` frame at `scp:svc:`.
//! - [`kind`]: which §9.10.12 record kind a blob is at its routing id.
//! - [`list`]: the governor-signed `NodeListRecord`, its entries, and the
//!   `0x06` frame it is published in at `scp:nls:`.
//! - [`proof`]: the node proof of control a node signs over a QUERY
//!   response.
//! - [`own_key`]: a node's own node key and the binding its operator
//!   installed, which sign possession and node proofs.
//!
//! These are pure types and codecs. Each verification returns a `Verified*`
//! type whose only constructor is that verification. A binding and a record
//! take the signer's validated key-event log and read the key the §9.7.1
//! class names from it: log-anchored for a binding and a record's
//! attribution, current-key for a record's standing. A proof takes the
//! verified binding of its node, the bound-node-key class.

pub mod binding;
pub mod conflict;
pub mod frame;
pub mod key_events;
pub mod kind;
pub mod list;
pub mod own_key;
pub mod proof;
pub mod service;

pub use binding::{
    NODE_BINDING_SEPARATOR, NODE_KEY_LEN, NodeBinding, NodeBindingError, VerifiedNodeBinding,
    node_url_hash,
};
pub use conflict::{
    CONFLICT_FRAME_VERSION, CONFLICT_STATEMENT_FIELDS_LEN, CONFLICT_STATEMENT_LEN,
    ConflictFrameError, ConflictStatement, WITNESS_CONFLICT_SEPARATOR, decode_conflict_frame,
    encode_conflict_frame,
};
pub use frame::{
    FramePrefixError, MAX_RECORD_FRAME_VALUE_LEN, RECORD_FRAME_PREFIX_LEN, join_frame, split_frame,
};
pub use key_events::{
    FrameEvent, KEY_EVENT_FRAME_VERSION, KeyEventFrame, KeyEventFrameError, decode_key_event_frame,
    encode_key_event_frame,
};
pub use kind::{
    COSIGNED_HEAD_FRAME_VERSION, KEY_PACKAGE_SET_FRAME_VERSION, NodeRecordKind,
    classify_node_record,
};
pub use list::{
    AdmittedNodeListEntry, AdmittedNodeListRecord, MAX_NODE_LIST_VALUE_LEN,
    NODE_LIST_FRAME_PREFIX_LEN, NODE_LIST_FRAME_VERSION, NODE_LIST_SEPARATOR, NodeListEntry,
    NodeListEntryError, NodeListError, NodeListFrameError, NodeListKeyClass, NodeListRecord,
    VerifiedNodeListEntry, VerifiedNodeListRecord, check_node_list_publish, decode_node_list_frame,
    encode_node_list_frame, entries_canonical_json,
};
pub use own_key::{BoundNodeKey, NodeBindingInstallError, NodeSigningKey, NodeSigningKeyError};
pub use proof::{
    NODE_PROOF_FIELDS_LEN, NODE_PROOF_LEN, NODE_PROOF_SEPARATOR, NodeProof, NodeProofError,
    response_value_digest,
};
pub use service::{
    IDENTITY_PRIVATE_STATE_TYPE, SERVICE_RECORD_FRAME_VERSION, SERVICE_RECORD_SEPARATOR,
    ServiceEntry, ServiceRecordFrame, ServiceRecordFrameError, decode_service_record_frame,
    encode_service_record_frame, service_record_fields, service_record_signing_digest,
};
