//! How a node admits each retained kind (`09-security-model.md` §9.10.12,
//! "What a node admits, keeps and serves, per kind").
//!
//! Each `admit_*` function runs its kind's admission rule over the arriving
//! record and the records and chains the node holds, then computes the
//! kind's selection over the held records and the arriving one. It returns
//! that selection as a [`Selection`]; the caller stores the arriving record
//! only where the selection keeps it, and deletes every held record the
//! selection drops.

use std::collections::BTreeSet;

use scp_did::Identifier;
use scp_kel::{HoldOutcome, node_list_routing_id};
use scp_protocol::node::{
    NodeListRecord, check_node_list_publish, decode_conflict_frame, decode_key_event_frame,
    decode_node_list_frame, decode_service_record_frame,
};
use scp_relay_client::code;
use scp_transport::native::public_records::{PublicRecordRefusal, RetainedPublish};
use scp_transport::native::storage::{BlobStorage, StoredBlob};

use super::NodeListPin;
use super::selection::{
    HeldLog, HeldNodeList, LogCache, bound_witnesses, corrupt, decode_conflicts,
    decode_service_records, designated_service_keys, frame_refusal, held_log, held_log_from,
    held_node_lists, load_retained, next_admission, select_conflicts, select_key_events,
    select_node_lists, select_service_records, statement_admissible, verify_node_list,
};

/// What a kind's selection keeps at one routing id after a write.
pub(super) struct Selection {
    /// The retained records at the routing id before the write, in admission
    /// order.
    pub(super) held: Vec<StoredBlob>,
    /// The `blob_id`s the selection keeps, the arriving record's included
    /// where the selection keeps it.
    pub(super) kept: BTreeSet<[u8; 32]>,
}

/// `4040` with `msg`.
fn rejected(msg: impl Into<String>) -> PublicRecordRefusal {
    PublicRecordRefusal::new(code::DID_RECORD_REJECTED, msg)
}

/// `scp:did:` admission: §9.7.4.2 R10's frame admission (`4040`), then R3's
/// check order on every event of the frame against the chains the node
/// holds (`4044`), then R9's accepted-chain rule and suffix retention.
///
/// The frame is admitted onto the identity's held log once, incrementally:
/// [`held_log_from`] replays only the stored frames its cache lacks. The
/// returned [`HeldLog`] carries the arriving frame under the counter the
/// caller's commit gives it.
///
/// # Errors
///
/// `4040` for a frame the decoder or frame admission refuses or that the
/// retention bounds keep none of, `4044` for an illegal event, `5000` on a
/// storage failure.
pub(super) async fn admit_key_events(
    storage: &dyn BlobStorage,
    logs: &LogCache,
    publish: &RetainedPublish,
) -> Result<(Identifier, HeldLog, Selection), PublicRecordRefusal> {
    let frame = decode_key_event_frame(&publish.blob)
        .map_err(|e| rejected(format!("the key-event frame does not decode: {e}")))?;
    let identifier = frame.identifier();
    // `classify_node_record` confirmed `publish.routing_id` derives from the
    // frame's identifier, so the held frames are the records stored there.
    let stored = load_retained(storage, &publish.routing_id).await?;
    let mut held = held_log_from(logs, &identifier, &stored)?;
    let outcome = held
        .admit_frame(next_admission(&stored)?, publish.blob_id, &frame)
        .map_err(|e| frame_refusal(&e))?;
    if matches!(outcome, HoldOutcome::Refused { .. }) {
        return Err(rejected(
            "the retention bounds keep no chain the frame extends",
        ));
    }
    let kept = select_key_events(&held.retained(), held.frames());
    Ok((identifier, held, Selection { held: stored, kept }))
}

/// `scp:svc:` admission: the record verifies under the service key a chain
/// the node holds for the identity designates, and the node holds a log of
/// the identity.
///
/// # Errors
///
/// `4040` for a record that does not decode, an identity whose log the node
/// does not hold, a signature no designated key verifies, or a record the
/// selection would not keep; `5000` on a storage failure.
pub(super) async fn admit_service_record(
    storage: &dyn BlobStorage,
    logs: &LogCache,
    publish: &RetainedPublish,
) -> Result<Selection, PublicRecordRefusal> {
    let record = decode_service_record_frame(&publish.blob)
        .map_err(|e| rejected(format!("the service record does not decode: {e}")))?;
    let chains = held_log(storage, logs, &record.identifier())
        .await?
        .retained();
    if chains.is_empty() {
        return Err(rejected("this node holds no key-event log of the identity"));
    }
    let designated = designated_service_keys(&chains);
    if !designated.iter().any(|key| record.verify(key).is_ok()) {
        return Err(rejected(
            "the service record verifies under no service key a held chain designates",
        ));
    }
    let held = load_retained(storage, &publish.routing_id).await?;
    let mut records = decode_service_records(&held)?;
    records.push((publish.blob_id, record));
    let kept = select_service_records(&records, &designated);
    Ok(Selection { held, kept })
}

/// The selection at `identifier`'s service-record routing id `routing` over
/// what it holds, after the identity's held chains changed.
///
/// # Errors
///
/// `5000` on a storage failure or a stored record that does not decode.
pub(super) async fn reselect_service_records(
    storage: &dyn BlobStorage,
    logs: &LogCache,
    identifier: &Identifier,
    routing: &[u8; 32],
) -> Result<Selection, PublicRecordRefusal> {
    let held = load_retained(storage, routing).await?;
    if held.is_empty() {
        return Ok(Selection {
            held,
            kept: BTreeSet::new(),
        });
    }
    let chains = held_log(storage, logs, identifier).await?.retained();
    let kept = select_service_records(
        &decode_service_records(&held)?,
        &designated_service_keys(&chains),
    );
    Ok(Selection { held, kept })
}

/// `scp:nls:` admission: the record's (`context_id`, `governor`) pair is one
/// a pin of `pins` names, the routing id derives from its `context_id`, and
/// the record verifies under the governor's `#active` at
/// `signing_key_state_head` on a governor chain the node retains under R9, a
/// key no later governor event marks `Compromised` (§9.6.3, §9.10.12). The
/// governor key state is the store-held `RetainedChain` of `03-identity.md`
/// §3.10.10, never a resolution: admission is availability only.
///
/// # Errors
///
/// `4040` for a record the decoder refuses, a pair no pin names, a governor
/// whose key-event log the node does not hold, a record no retained governor
/// chain verifies (a head off every chain, another identity's key, a failed
/// signature), a compromised signing key, or a record the selection would
/// not keep; `5000` on a storage failure.
pub(super) async fn admit_node_list(
    storage: &dyn BlobStorage,
    logs: &LogCache,
    pins: &BTreeSet<NodeListPin>,
    publish: &RetainedPublish,
) -> Result<Selection, PublicRecordRefusal> {
    let record = check_node_list_publish(&publish.routing_id, &publish.blob)
        .map_err(|e| rejected(format!("the node-list record is refused: {e}")))?;
    if !pins
        .iter()
        .any(|pin| pin.context_id == record.context_id && pin.governor == record.governor)
    {
        return Err(rejected(
            "no node-list pointer this node is configured with names the record's context and \
             governor",
        ));
    }
    let governor = held_log(storage, logs, &record.governor).await?.retained();
    let signing = verify_node_list(&governor, &record)
        .map_err(|e| rejected(format!("the node-list record is refused: {e}")))?;
    if signing.compromised {
        return Err(rejected(
            "a later governor event marks the signing key Compromised",
        ));
    }
    let held = load_retained(storage, &publish.routing_id).await?;
    let mut records = held_node_lists(storage, logs, &held).await?;
    records.push(HeldNodeList {
        blob_id: publish.blob_id,
        record,
        signing: Some(signing),
    });
    let kept = select_node_lists(&records);
    Ok(Selection { held, kept })
}

/// The selection at the node-list routing id `routing` over what it holds,
/// after a governor's held chains changed.
///
/// # Errors
///
/// `5000` on a storage failure or a stored record that does not decode.
pub(super) async fn reselect_node_list(
    storage: &dyn BlobStorage,
    logs: &LogCache,
    routing: &[u8; 32],
) -> Result<Selection, PublicRecordRefusal> {
    let held = load_retained(storage, routing).await?;
    let kept = select_node_lists(&held_node_lists(storage, logs, &held).await?);
    Ok(Selection { held, kept })
}

/// The node-list records of every pinned (`context_id`, `governor`) pair,
/// whose bindings decide which node keys may sign a conflict statement.
async fn pinned_node_lists(
    storage: &dyn BlobStorage,
    pins: &BTreeSet<NodeListPin>,
) -> Result<Vec<NodeListRecord>, PublicRecordRefusal> {
    let mut records = Vec::new();
    for pin in pins {
        for blob in load_retained(storage, &node_list_routing_id(&pin.context_id)).await? {
            let record =
                decode_node_list_frame(&blob.blob).map_err(|e| corrupt("node-list", &e))?;
            if record.governor == pin.governor {
                records.push(record);
            }
        }
    }
    Ok(records)
}

/// `scp:wcf:` admission: every statement is signed by a bound node key that
/// the subject's key state names on either conflicting chain, with both
/// conflicting heads events of chains the node holds (§9.10.12).
///
/// A node with no node-list pin binds no node key, so it admits no conflict
/// statement.
///
/// # Errors
///
/// `4040` for a frame that does not decode, a statement that fails the rule,
/// or a frame the selection would not keep; `5000` on a storage failure.
pub(super) async fn admit_conflicts(
    storage: &dyn BlobStorage,
    logs: &LogCache,
    pins: &BTreeSet<NodeListPin>,
    publish: &RetainedPublish,
) -> Result<Selection, PublicRecordRefusal> {
    let (subject, statements) = decode_conflict_frame(&publish.blob)
        .map_err(|e| rejected(format!("the conflict frame does not decode: {e}")))?;
    let bound = bound_witnesses(storage, logs, &pinned_node_lists(storage, pins).await?).await?;
    let chains = held_log(storage, logs, &subject).await?.retained();
    if let Some(index) = statements
        .iter()
        .position(|statement| !statement_admissible(statement, &subject, &chains, &bound))
    {
        return Err(rejected(format!(
            "conflict statement {index} is not signed by a bound witness of the subject over \
             two heads this node holds"
        )));
    }
    let held = load_retained(storage, &publish.routing_id).await?;
    let mut frames = decode_conflicts(&held)?;
    frames.push((publish.blob_id, statements));
    let kept = select_conflicts(&frames, &subject, &chains, &bound);
    Ok(Selection { held, kept })
}

/// The selection at `subject`'s conflict routing id `routing` over what it
/// holds, after the subject's held chains changed.
///
/// # Errors
///
/// `5000` on a storage failure or a stored frame that does not decode.
pub(super) async fn reselect_conflicts(
    storage: &dyn BlobStorage,
    logs: &LogCache,
    pins: &BTreeSet<NodeListPin>,
    subject: &Identifier,
    routing: &[u8; 32],
) -> Result<Selection, PublicRecordRefusal> {
    let held = load_retained(storage, routing).await?;
    if held.is_empty() {
        return Ok(Selection {
            held,
            kept: BTreeSet::new(),
        });
    }
    let bound = bound_witnesses(storage, logs, &pinned_node_lists(storage, pins).await?).await?;
    let chains = held_log(storage, logs, subject).await?.retained();
    let kept = select_conflicts(&decode_conflicts(&held)?, subject, &chains, &bound);
    Ok(Selection { held, kept })
}
