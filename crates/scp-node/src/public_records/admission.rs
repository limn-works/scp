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

use scp_crypto::p256::P256PublicKey;
use scp_did::Identifier;
use scp_kel::{
    EntryVerdict, EventKind, RoutingKind, node_list_routing_id, routing_id, validate_entry,
};
use scp_protocol::node::{
    NodeListKeyClass, VerifiedNodeListRecord, check_node_list_publish, decode_conflict_frame,
    decode_key_event_frame, decode_node_list_frame, decode_service_record_frame,
};
use scp_relay_client::code;
use scp_transport::native::public_records::{PublicRecordRefusal, RetainedPublish};
use scp_transport::native::storage::{BlobStorage, StoredBlob};

use super::NodeListSource;
use super::selection::{
    HeldNodeList, bound_witnesses, decode_conflicts, decode_service_records,
    designated_service_keys, held_log, held_node_lists, hold_units, load_retained,
    node_list_signing_key, select_conflicts, select_key_events, select_node_lists,
    select_service_records, statement_admissible,
};

/// What a kind's selection keeps at one routing id after a write.
pub(super) struct Selection {
    /// The retained records at the routing id before the write.
    pub(super) held: Vec<StoredBlob>,
    /// The `blob_id`s the selection keeps, the arriving record's included
    /// where the selection keeps it.
    pub(super) kept: BTreeSet<[u8; 32]>,
}

/// `4040` with `msg`.
fn rejected(msg: impl Into<String>) -> PublicRecordRefusal {
    PublicRecordRefusal::new(code::DID_RECORD_REJECTED, msg)
}

/// `4044` with `msg`.
fn illegal(msg: impl Into<String>) -> PublicRecordRefusal {
    PublicRecordRefusal::new(code::KEY_EVENT_ILLEGAL, msg)
}

/// `scp:did:` admission: §9.7.4.2 R10's frame admission (`4040`), then R3's
/// check order on every event of the frame against the chains the node
/// holds (`4044`), then R9's accepted-chain rule and suffix retention.
///
/// # Errors
///
/// `4040` for a frame the decoder or frame admission refuses or that the
/// retention bounds keep none of, `4044` for an illegal event, `5000` on a
/// storage failure.
pub(super) async fn admit_key_events(
    storage: &dyn BlobStorage,
    publish: &RetainedPublish,
) -> Result<(Identifier, Selection), PublicRecordRefusal> {
    let frame = decode_key_event_frame(&publish.blob)
        .map_err(|e| rejected(format!("the key-event frame does not decode: {e}")))?;
    let identifier = frame.identifier();
    let mut log = held_log(storage, &identifier).await?;
    let held_digests = log.digests();
    let Some(first) = frame.first() else {
        return Err(rejected("the key-event frame carries no event"));
    };
    if held_digests.contains(&first.digest()) {
        return Err(rejected("the frame's first event is one this node holds"));
    }
    let admitted = if first.kind() == EventKind::Inception {
        first.recomputed_identifier() == identifier
    } else {
        held_digests.contains(first.predecessor())
    };
    if !admitted {
        return Err(rejected(
            "the frame's first event is neither the inception of this identifier nor an \
             event whose predecessor this node holds",
        ));
    }
    let held_count = log.units.len();
    let units: Vec<&[u8]> = log
        .units
        .iter()
        .map(Vec::as_slice)
        .chain(
            frame
                .events()
                .iter()
                .map(scp_protocol::node::FrameEvent::unit),
        )
        .collect();
    let validation = validate_entry(&identifier, &units);
    if let Some(discarded) = validation
        .discarded
        .iter()
        .find(|discarded| discarded.served_index() >= held_count)
    {
        return Err(illegal(format!(
            "event {} of the frame fails R3: {}",
            discarded.served_index() - held_count,
            discarded.defect(),
        )));
    }
    if !matches!(validation.verdict, EntryVerdict::Valid { .. }) {
        return Err(illegal(
            "the frame leaves the identifier with no valid chain",
        ));
    }
    hold_units(&mut log.holder, &identifier, &units)?;
    log.frames.push((
        publish.blob_id,
        frame
            .events()
            .iter()
            .map(scp_protocol::node::FrameEvent::digest)
            .collect(),
    ));
    let kept = select_key_events(&log.holder, &log.frames);
    let held = load_retained(storage, &publish.routing_id).await?;
    Ok((identifier, Selection { held, kept }))
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
    publish: &RetainedPublish,
) -> Result<Selection, PublicRecordRefusal> {
    let record = decode_service_record_frame(&publish.blob)
        .map_err(|e| rejected(format!("the service record does not decode: {e}")))?;
    let chains = held_log(storage, &record.identifier()).await?.chains();
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

/// The selection at a service-record routing id over what it holds, after
/// the identity's held chains changed.
///
/// # Errors
///
/// `5000` on a storage failure or a stored record that does not decode.
pub(super) async fn reselect_service_records(
    storage: &dyn BlobStorage,
    identifier: &Identifier,
) -> Result<([u8; 32], Selection), PublicRecordRefusal> {
    let routing = routing_id(RoutingKind::ServiceRecord, identifier);
    let chains = held_log(storage, identifier).await?.chains();
    let held = load_retained(storage, &routing).await?;
    let kept = select_service_records(
        &decode_service_records(&held)?,
        &designated_service_keys(&chains),
    );
    Ok((routing, Selection { held, kept }))
}

/// `scp:nls:` admission: the routing id derives from the record's
/// `context_id`, and the record verifies under the governor's `#active` at
/// `signing_key_state_head` in the governor key state the node holds, a key
/// no later governor event marks `Compromised` (§9.6.3, §9.10.12).
///
/// # Errors
///
/// `4040` for a record the decoder refuses, a governor log the node does not
/// hold at `signing_key_state_head`, a signature that fails, a compromised
/// signing key, or a record the selection would not keep; `5000` on a
/// storage failure.
pub(super) async fn admit_node_list(
    storage: &dyn BlobStorage,
    publish: &RetainedPublish,
) -> Result<Selection, PublicRecordRefusal> {
    let record = check_node_list_publish(&publish.routing_id, true, None, &publish.blob)
        .map_err(|e| rejected(format!("the node-list record is refused: {e}")))?;
    let governor_chains = held_log(storage, &record.governor).await?.chains();
    let Some(signing) = node_list_signing_key(&governor_chains, &record.signing_key_state_head)
    else {
        return Err(rejected(
            "this node holds no governor chain carrying the record's signing_key_state_head",
        ));
    };
    if signing.compromised {
        return Err(rejected(
            "a later governor event marks the signing key Compromised",
        ));
    }
    let key = P256PublicKey::from_sec1(&signing.key)
        .map_err(|e| rejected(format!("the governor's #active does not parse: {e}")))?;
    let record = VerifiedNodeListRecord::verify(record, NodeListKeyClass::Attribution, &key)
        .map_err(|e| rejected(format!("the node-list signature fails: {e}")))?
        .into_record();
    let mut records = held_node_lists(storage, &publish.routing_id).await?;
    let held = load_retained(storage, &publish.routing_id).await?;
    records.push(HeldNodeList {
        blob_id: publish.blob_id,
        record,
        signing: Some(signing),
    });
    let kept = select_node_lists(&records);
    Ok(Selection { held, kept })
}

/// The selection at the configured node-list routing id over what it holds,
/// after the governor's held chains changed; `None` where the node holds no
/// node-list context or `governor` is not its governor.
///
/// # Errors
///
/// `5000` on a storage failure or a stored record that does not decode.
pub(super) async fn reselect_node_list(
    storage: &dyn BlobStorage,
    source: &NodeListSource,
    governor: &Identifier,
) -> Result<Option<([u8; 32], Selection)>, PublicRecordRefusal> {
    let NodeListSource::Context {
        context_id,
        governor: configured,
    } = source
    else {
        return Ok(None);
    };
    if configured != governor {
        return Ok(None);
    }
    let routing = node_list_routing_id(context_id);
    let records = held_node_lists(storage, &routing).await?;
    let held = load_retained(storage, &routing).await?;
    let kept = select_node_lists(&records);
    Ok(Some((routing, Selection { held, kept })))
}

/// The node-list records of the node's configured context and governor,
/// whose bindings decide which node keys may sign a conflict statement.
async fn configured_node_lists(
    storage: &dyn BlobStorage,
    source: &NodeListSource,
) -> Result<Vec<scp_protocol::node::NodeListRecord>, PublicRecordRefusal> {
    let NodeListSource::Context {
        context_id,
        governor,
    } = source
    else {
        return Ok(Vec::new());
    };
    load_retained(storage, &node_list_routing_id(context_id))
        .await?
        .iter()
        .map(|blob| {
            decode_node_list_frame(&blob.blob)
                .map_err(|e| super::selection::corrupt("node-list", &e))
        })
        .filter(|record| {
            record
                .as_ref()
                .map_or(true, |record| record.governor == *governor)
        })
        .collect()
}

/// `scp:wcf:` admission: every statement is signed by a bound node key that
/// the subject's key state names on either conflicting chain, with both
/// conflicting heads events of chains the node holds (§9.10.12).
///
/// A node with no node-list context binds no node key, so it admits no
/// conflict statement.
///
/// # Errors
///
/// `4040` for a frame that does not decode, a statement that fails the rule,
/// or a frame the selection would not keep; `5000` on a storage failure.
pub(super) async fn admit_conflicts(
    storage: &dyn BlobStorage,
    source: &NodeListSource,
    publish: &RetainedPublish,
) -> Result<Selection, PublicRecordRefusal> {
    let (subject, statements) = decode_conflict_frame(&publish.blob)
        .map_err(|e| rejected(format!("the conflict frame does not decode: {e}")))?;
    let bound = bound_witnesses(storage, &configured_node_lists(storage, source).await?).await?;
    let chains = held_log(storage, &subject).await?.chains();
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

/// The selection at a conflict routing id over what it holds, after the
/// subject's held chains changed.
///
/// # Errors
///
/// `5000` on a storage failure or a stored frame that does not decode.
pub(super) async fn reselect_conflicts(
    storage: &dyn BlobStorage,
    source: &NodeListSource,
    subject: &Identifier,
) -> Result<([u8; 32], Selection), PublicRecordRefusal> {
    let routing = routing_id(RoutingKind::ConflictStatements, subject);
    let held = load_retained(storage, &routing).await?;
    if held.is_empty() {
        return Ok((
            routing,
            Selection {
                held,
                kept: BTreeSet::new(),
            },
        ));
    }
    let bound = bound_witnesses(storage, &configured_node_lists(storage, source).await?).await?;
    let chains = held_log(storage, subject).await?.chains();
    let kept = select_conflicts(&decode_conflicts(&held)?, subject, &chains, &bound);
    Ok((routing, Selection { held, kept }))
}
