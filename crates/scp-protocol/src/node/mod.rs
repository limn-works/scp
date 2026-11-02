//! Node wire types (`09-security-model.md` §9.6.3, §9.7.4.2 definitions,
//! §9.10.12, §9.18.2; spec 25 §25.27).
//!
//! - [`binding`]: the `NodeBinding` an operator and a node key both sign.
//! - [`list`]: the governor-signed `NodeListRecord`, its entries, and the
//!   `0x06` frame it is published in at `scp:nls:`.
//! - [`proof`]: the node proof of control a node signs over a QUERY
//!   response.
//!
//! These are pure types and codecs. Every verification takes the key the
//! caller resolved, because the classes §9.7.1 assigns (log-anchored for a
//! binding and a record's attribution, current-key for a record's standing,
//! bound-node-key for a proof) read key state and list state this crate does
//! not hold.

pub mod binding;
pub mod list;
pub mod proof;

pub use binding::{
    NODE_BINDING_SEPARATOR, NODE_KEY_LEN, NodeBinding, NodeBindingError, node_url_hash,
};
pub use list::{
    MAX_NODE_LIST_VALUE_LEN, NODE_LIST_FRAME_PREFIX_LEN, NODE_LIST_FRAME_VERSION,
    NODE_LIST_SEPARATOR, NodeListEntry, NodeListError, NodeListFrameError, NodeListRecord,
    check_node_list_publish, decode_node_list_frame, encode_node_list_frame,
    entries_canonical_json,
};
pub use proof::{
    NODE_PROOF_FIELDS_LEN, NODE_PROOF_LEN, NODE_PROOF_SEPARATOR, NodeProof, NodeProofError,
    response_value_digest,
};
