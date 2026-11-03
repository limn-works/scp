//! What a node keeps of each retained kind (`09-security-model.md` §9.10.12,
//! "Selection: what the node keeps").
//!
//! Every selection is a function of the records stored at one routing id and
//! the key-event chains the node holds, so a node recomputes it from storage
//! on each write and keeps no index beside the blob store. Each `select_*`
//! function returns the `blob_id`s the selection keeps; the caller deletes
//! every other retained record at that routing id.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use scp_crypto::p256::P256PublicKey;
use scp_did::{Identifier, KeyCondition, NodeId};
use scp_kel::{
    AcceptedChainHolder, EntryVerdict, EventKind, RetainedChain, RoutingKind, ValidatedChain,
    key_state_at, replay, routing_id, validate_entry,
};
use scp_protocol::crypto::anchored_key::AnchoredKeyError;
use scp_protocol::node::{
    ConflictStatement, NodeListError, NodeListKeyClass, NodeListRecord, ServiceRecordFrame,
    VerifiedNodeListEntry, VerifiedNodeListRecord, decode_conflict_frame, decode_key_event_frame,
    decode_node_list_frame, decode_service_record_frame,
};
use scp_relay_client::code;
use scp_transport::native::public_records::PublicRecordRefusal;
use scp_transport::native::storage::{
    BlobLifetime, BlobStorage, QueryCursor, StorageError, StoredBlob,
};

/// One stored conflict frame: its `blob_id` and the statements it carries.
pub(super) type ConflictFrame = ([u8; 32], Vec<ConflictStatement>);

/// The page a load walks a routing id in.
const LOAD_PAGE: u32 = 256;

/// `5001` for a full backend and `5000` for every other storage failure,
/// naming the operation.
pub(super) fn storage_refusal(operation: &str, err: &StorageError) -> PublicRecordRefusal {
    PublicRecordRefusal::storage(operation, err)
}

/// `5000` for a stored retained record that no longer reads as its kind. The
/// node stores only records it admitted, so this is a corrupt store, and the
/// node refuses rather than serve or select around it.
pub(super) fn corrupt(kind: &str, err: &impl std::fmt::Display) -> PublicRecordRefusal {
    PublicRecordRefusal::new(
        code::INTERNAL_ERROR,
        format!("a stored {kind} record does not decode: {err}"),
    )
}

/// Every retained record at `routing_id`, in ascending (`stored_at`,
/// `blob_id`) order: the order the node stored them in, which every
/// selection's tie-break reads as "held earliest".
///
/// # Errors
///
/// `5000` on a storage failure.
pub(super) async fn load_retained(
    storage: &dyn BlobStorage,
    routing_id: &[u8; 32],
) -> Result<Vec<StoredBlob>, PublicRecordRefusal> {
    let mut held = Vec::new();
    let mut cursor = QueryCursor::All;
    loop {
        let page = storage
            .query(routing_id, cursor, LOAD_PAGE)
            .await
            .map_err(|e| storage_refusal("loading a routing id's records", &e))?;
        let Some(last) = page.last() else {
            break;
        };
        cursor = QueryCursor::After {
            since: last.stored_at,
            blob_id: last.blob_id,
        };
        let full = page.len() >= usize::try_from(LOAD_PAGE).unwrap_or(usize::MAX);
        held.extend(
            page.into_iter()
                .filter(|stored| stored.lifetime == BlobLifetime::Retained),
        );
        if !full {
            break;
        }
    }
    Ok(held)
}

/// How many TTL-bearing blobs `routing_id` holds, counted up to `stop_at`:
/// a caller comparing against a bound reads no further than one past it.
///
/// # Errors
///
/// `5000` on a storage failure.
pub(super) async fn count_ttl(
    storage: &dyn BlobStorage,
    routing_id: &[u8; 32],
    stop_at: usize,
) -> Result<usize, PublicRecordRefusal> {
    let mut counted = 0usize;
    let mut cursor = QueryCursor::All;
    while counted < stop_at {
        let page = storage
            .query(routing_id, cursor, LOAD_PAGE)
            .await
            .map_err(|e| storage_refusal("counting a routing id's TTL blobs", &e))?;
        let Some(last) = page.last() else {
            break;
        };
        cursor = QueryCursor::After {
            since: last.stored_at,
            blob_id: last.blob_id,
        };
        let full = page.len() >= usize::try_from(LOAD_PAGE).unwrap_or(usize::MAX);
        counted = counted.saturating_add(
            page.iter()
                .filter(|stored| matches!(stored.lifetime, BlobLifetime::Ttl(_)))
                .count(),
        );
        if !full {
            break;
        }
    }
    Ok(counted)
}

// ---------------------------------------------------------------------------
// scp:did:
// ---------------------------------------------------------------------------

/// The chains of one identifier the node holds, replayed from its stored
/// key-event frames (§9.7.4.2 R9).
pub(super) struct HeldLog {
    /// The holder after every stored frame, in the order the node stored them.
    pub(super) holder: AcceptedChainHolder,
    /// Each stored frame's `blob_id` and the event digests it carries.
    pub(super) frames: Vec<([u8; 32], Vec<[u8; 32]>)>,
    /// Every event unit the stored frames carry, in stored order.
    pub(super) units: Vec<Vec<u8>>,
}

impl HeldLog {
    /// Every event digest a stored frame carries.
    pub(super) fn digests(&self) -> BTreeSet<[u8; 32]> {
        self.frames
            .iter()
            .flat_map(|(_, digests)| digests.iter().copied())
            .collect()
    }

    /// Every chain the holder holds, accepted and retained suffixes.
    pub(super) fn chains(&self) -> Vec<ValidatedChain> {
        self.holder.held().cloned().collect()
    }

    /// Every chain the holder retains under R9, as the store-held key state
    /// admission and selection verify signatures under (`03-identity.md`
    /// §3.10.10, §9.10.12).
    pub(super) fn retained(&self) -> Vec<RetainedChain> {
        self.holder.retained()
    }
}

/// Holds every valid chain `units` carry under `identifier`.
///
/// # Errors
///
/// `5000` where `units` carry no valid chain, which units this node admitted
/// always do, or where the holder reaches an error, which valid chains of one
/// identifier never do.
pub(super) fn hold_units(
    holder: &mut AcceptedChainHolder,
    identifier: &Identifier,
    units: &[&[u8]],
) -> Result<(), PublicRecordRefusal> {
    let EntryVerdict::Valid { chains } = validate_entry(identifier, units).verdict else {
        return Err(PublicRecordRefusal::new(
            code::INTERNAL_ERROR,
            "the stored key-event log carries no valid chain",
        ));
    };
    for chain in chains.iter() {
        // The outcome is not read: every selection recomputes from `held()`.
        holder.hold(chain.clone()).map(drop).map_err(|e| {
            PublicRecordRefusal::new(
                code::INTERNAL_ERROR,
                format!("holding a validated chain: {e}"),
            )
        })?;
    }
    Ok(())
}

/// Replays the key-event frames stored for `identifier` into a holder, one
/// frame at a time, so the holder's "held earliest" moment of each chain is
/// the order the node admitted it in (§9.7.4.2 R9).
///
/// Stored order is (`stored_at`, `blob_id`), and `stored_at` has one-second
/// resolution, so two frames admitted in one second can come back with an
/// extension ahead of the frame holding its predecessor. Admission held each
/// frame's predecessor (or the frame is an inception), so the replay takes the
/// earliest stored frame whose first event is an inception or extends an event
/// already replayed: that order is the admission order up to same-second ties.
///
/// # Errors
///
/// `5000` on a storage failure, a stored frame that does not decode, or a
/// stored frame no replay order reaches.
pub(super) async fn held_log(
    storage: &dyn BlobStorage,
    identifier: &Identifier,
) -> Result<HeldLog, PublicRecordRefusal> {
    let stored = load_retained(storage, &routing_id(RoutingKind::KeyEvents, identifier)).await?;
    let mut log = HeldLog {
        holder: AcceptedChainHolder::new(),
        frames: Vec::with_capacity(stored.len()),
        units: Vec::new(),
    };
    let mut pending = stored
        .iter()
        .map(|blob| {
            decode_key_event_frame(&blob.blob)
                .map(|frame| (blob.blob_id, frame))
                .map_err(|e| corrupt("key-event", &e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut replayed = BTreeSet::new();
    while !pending.is_empty() {
        let next = pending.iter().position(|(_, frame)| {
            frame.first().is_some_and(|first| {
                first.kind() == EventKind::Inception || replayed.contains(first.predecessor())
            })
        });
        let Some(next) = next else {
            return Err(PublicRecordRefusal::new(
                code::INTERNAL_ERROR,
                "a stored key-event frame extends no event the node holds",
            ));
        };
        let (blob_id, frame) = pending.remove(next);
        let digests: Vec<[u8; 32]> = frame
            .events()
            .iter()
            .map(scp_protocol::node::FrameEvent::digest)
            .collect();
        replayed.extend(digests.iter().copied());
        log.frames.push((blob_id, digests));
        log.units
            .extend(frame.events().iter().map(|event| event.unit().to_vec()));
        let units: Vec<&[u8]> = log.units.iter().map(Vec::as_slice).collect();
        hold_units(&mut log.holder, identifier, &units)?;
    }
    Ok(log)
}

/// The key-event frames the did selection keeps: every frame carrying at
/// least one event of a chain the holder holds, accepted or suffix.
pub(super) fn select_key_events(
    holder: &AcceptedChainHolder,
    frames: &[([u8; 32], Vec<[u8; 32]>)],
) -> BTreeSet<[u8; 32]> {
    let kept: BTreeSet<[u8; 32]> = holder
        .held()
        .flat_map(ValidatedChain::event_digests)
        .collect();
    frames
        .iter()
        .filter(|(_, digests)| digests.iter().any(|digest| kept.contains(digest)))
        .map(|(blob_id, _)| *blob_id)
        .collect()
}

// ---------------------------------------------------------------------------
// scp:svc:
// ---------------------------------------------------------------------------

/// The service keys the held chains designate: on each chain, the key its
/// head key state lists `Current` in the service-record role (§9.10.12,
/// `03-identity.md` §3.10.13 "Who signs it").
pub(super) fn designated_service_keys(chains: &[ValidatedChain]) -> BTreeSet<[u8; 33]> {
    chains
        .iter()
        .flat_map(|chain| {
            let state = replay(chain);
            let role = state.key_state().service_key_role;
            state
                .key_state()
                .keys
                .iter()
                .filter(|entry| entry.role == role && entry.condition == KeyCondition::Current)
                .map(|entry| entry.key)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The service records the svc selection keeps: per designated key, the
/// record at the highest sequence, the one held earliest on a tie
/// (`03-identity.md` §3.10.13 "last writer wins on the record's own
/// sequence"). A record no held chain designates a key for is not kept.
///
/// `records` are in stored order.
pub(super) fn select_service_records(
    records: &[([u8; 32], ServiceRecordFrame)],
    designated: &BTreeSet<[u8; 33]>,
) -> BTreeSet<[u8; 32]> {
    let mut best: BTreeMap<[u8; 33], (u64, [u8; 32])> = BTreeMap::new();
    for (blob_id, record) in records {
        for key in designated {
            if record.verify(key).is_err() {
                continue;
            }
            let wins = best
                .get(key)
                .is_none_or(|(sequence, _)| record.sequence() > *sequence);
            if wins {
                best.insert(*key, (record.sequence(), *blob_id));
            }
        }
    }
    best.into_values().map(|(_, blob_id)| blob_id).collect()
}

/// Decodes every stored service record.
///
/// # Errors
///
/// `5000` for a stored record that does not decode.
pub(super) fn decode_service_records(
    stored: &[StoredBlob],
) -> Result<Vec<([u8; 32], ServiceRecordFrame)>, PublicRecordRefusal> {
    stored
        .iter()
        .map(|blob| {
            decode_service_record_frame(&blob.blob)
                .map(|record| (blob.blob_id, record))
                .map_err(|e| corrupt("service", &e))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// scp:nls:
// ---------------------------------------------------------------------------

/// The governor's `#active` a node-list record verified under, on a
/// governor chain the node retains, and whether a held chain carrying the
/// record's `signing_key_state_head` marks that key `Compromised` at its head
/// (§9.10.12, the `scp:nls:` row).
pub(super) struct SigningKey {
    /// The 33-byte key.
    pub(super) key: [u8; 33],
    /// A later governor event marks the key `Compromised`.
    pub(super) compromised: bool,
}

/// Why no governor chain the node retains verifies a node-list record.
#[derive(Debug, thiserror::Error)]
pub(super) enum NodeListUnverified {
    /// The node holds no key-event log of the record's governor.
    #[error("this node holds no key-event log of the governor")]
    NoGovernorLog,
    /// No retained governor chain verifies the record. The error is the
    /// first refusal other than a head off the chain, or a head off the
    /// chain where every chain refused that.
    #[error("no governor chain this node holds verifies the record: {0}")]
    Refused(NodeListError),
}

/// Verifies `record` under the log-anchored class on each governor chain the
/// node retains under R9, accepted or suffix, and returns the key of the
/// first chain that verifies it (§9.10.12: the node "holds every chain it
/// retains under R9, accepted or suffix, and selects per chain"; the
/// `scp:nls:` row). Every chain carrying the record's `signing_key_state_head`
/// shares the events up to it, so each reads the same key there.
///
/// `governor` is the store-held key state of `03-identity.md` §3.10.10: store
/// admission is availability only and grants no trust.
///
/// # Errors
///
/// [`NodeListUnverified`] where the node holds no governor log or no
/// retained chain verifies the record.
pub(super) fn verify_node_list(
    governor: &[RetainedChain],
    record: &NodeListRecord,
) -> Result<SigningKey, NodeListUnverified> {
    let head = &record.signing_key_state_head;
    let mut refusal: Option<NodeListError> = None;
    for chain in governor {
        match VerifiedNodeListRecord::verify(record.clone(), NodeListKeyClass::Attribution, chain) {
            Ok(verified) => {
                let key = verified.signing_key().to_compressed();
                let compromised = governor
                    .iter()
                    .filter(|held| held.key_state_at(head).is_ok())
                    .any(|held| {
                        held.key_state().keys.iter().any(|entry| {
                            entry.key == key && entry.condition == KeyCondition::Compromised
                        })
                    });
                return Ok(SigningKey { key, compromised });
            }
            Err(e) => {
                let off_chain = matches!(
                    e,
                    NodeListError::GovernorKey(AnchoredKeyError::HeadNotOnChain)
                );
                match &refusal {
                    None => refusal = Some(e),
                    Some(NodeListError::GovernorKey(AnchoredKeyError::HeadNotOnChain))
                        if !off_chain =>
                    {
                        refusal = Some(e);
                    }
                    Some(_) => {}
                }
            }
        }
    }
    Err(refusal.map_or(
        NodeListUnverified::NoGovernorLog,
        NodeListUnverified::Refused,
    ))
}

/// One stored node-list record and the key its signature verified under,
/// where that key still resolves.
pub(super) struct HeldNodeList {
    pub(super) blob_id: [u8; 32],
    pub(super) record: NodeListRecord,
    pub(super) signing: Option<SigningKey>,
}

/// The node-list records the nls selection keeps: per (governor, signing
/// key), the record at the highest sequence, the one held earliest on a tie.
/// A record whose signing key no held chain resolves, or that a later
/// governor event marks `Compromised`, is not kept.
pub(super) fn select_node_lists(records: &[HeldNodeList]) -> BTreeSet<[u8; 32]> {
    let mut best: BTreeMap<(Identifier, [u8; 33]), (u64, [u8; 32])> = BTreeMap::new();
    for held in records {
        let Some(signing) = held.signing.as_ref().filter(|signing| !signing.compromised) else {
            continue;
        };
        let slot = (held.record.governor, signing.key);
        let wins = best
            .get(&slot)
            .is_none_or(|(sequence, _)| held.record.sequence > *sequence);
        if wins {
            best.insert(slot, (held.record.sequence, held.blob_id));
        }
    }
    best.into_values().map(|(_, blob_id)| blob_id).collect()
}

/// Loads the node-list records at `routing_id` with each one's signing key
/// resolved from the governor chains the node holds.
///
/// # Errors
///
/// `5000` on a storage failure or a stored record that does not decode.
pub(super) async fn held_node_lists(
    storage: &dyn BlobStorage,
    routing_id: &[u8; 32],
) -> Result<Vec<HeldNodeList>, PublicRecordRefusal> {
    let stored = load_retained(storage, routing_id).await?;
    let mut chains: HashMap<Identifier, Vec<RetainedChain>> = HashMap::new();
    let mut held = Vec::with_capacity(stored.len());
    for blob in stored {
        let record = decode_node_list_frame(&blob.blob).map_err(|e| corrupt("node-list", &e))?;
        if let std::collections::hash_map::Entry::Vacant(e) = chains.entry(record.governor) {
            let log = held_log(storage, &record.governor).await?;
            e.insert(log.retained());
        }
        let signing = chains
            .get(&record.governor)
            .and_then(|chains| verify_node_list(chains, &record).ok());
        held.push(HeldNodeList {
            blob_id: blob.blob_id,
            record,
            signing,
        });
    }
    Ok(held)
}

// ---------------------------------------------------------------------------
// scp:wcf:
// ---------------------------------------------------------------------------

/// A witness the node list the node holds binds: its node key and operator.
pub(super) struct BoundWitness {
    pub(super) node_key: P256PublicKey,
    pub(super) operator: Identifier,
}

/// The witnesses the node-list records `records` bind, each binding
/// verified under its operator's `#active` at `key_state_head` on a held
/// operator chain (§9.6.3). A binding whose operator log the node does not
/// hold, or that does not verify, binds nothing.
///
/// # Errors
///
/// `5000` on a storage failure.
pub(super) async fn bound_witnesses(
    storage: &dyn BlobStorage,
    records: &[NodeListRecord],
) -> Result<HashMap<NodeId, BoundWitness>, PublicRecordRefusal> {
    let mut chains: HashMap<Identifier, Vec<RetainedChain>> = HashMap::new();
    let mut bound = HashMap::new();
    for entry in records.iter().flat_map(|record| record.entries.iter()) {
        let operator = entry.binding.operator;
        if let std::collections::hash_map::Entry::Vacant(e) = chains.entry(operator) {
            let log = held_log(storage, &operator).await?;
            e.insert(log.retained());
        }
        let verified = chains.get(&operator).and_then(|chains| {
            chains
                .iter()
                .find_map(|chain| VerifiedNodeListEntry::verify(entry.clone(), chain).ok())
        });
        if let Some(verified) = verified {
            bound.insert(
                *verified.binding().node_id(),
                BoundWitness {
                    node_key: *verified.binding().node_key(),
                    operator,
                },
            );
        }
    }
    Ok(bound)
}

/// Whether `statement` meets the `scp:wcf:` admission rule for `subject`:
/// signed by a bound node key whose operator the subject's key state names
/// among its witnesses on either conflicting chain, with both conflicting
/// heads events of chains the node holds for the subject at the sequences
/// the statement names (§9.10.12).
///
/// `KeyState.witnesses` lists operator identifiers (§9.7.4.2, the key
/// state's fields), so the operator the binding names is what the key state
/// is read for.
pub(super) fn statement_admissible(
    statement: &ConflictStatement,
    subject: &Identifier,
    subject_chains: &[ValidatedChain],
    bound: &HashMap<NodeId, BoundWitness>,
) -> bool {
    if statement.subject != *subject {
        return false;
    }
    let Some(witness) = bound.get(&statement.witness) else {
        return false;
    };
    if statement.verify(&witness.node_key).is_err() {
        return false;
    }
    let at = |digest: &[u8; 32], sequence: u64| {
        subject_chains.iter().find_map(|chain| {
            key_state_at(chain, digest)
                .ok()
                .filter(|state| state.head_sequence() == sequence)
        })
    };
    let (Some(held), Some(offered)) = (
        at(&statement.held_digest, statement.held_sequence),
        at(&statement.offered_digest, statement.offered_sequence),
    ) else {
        return false;
    };
    [held, offered]
        .iter()
        .any(|state| state.key_state().witnesses.contains(&witness.operator))
}

/// The conflict frames the wcf selection keeps: per (witness, offered head),
/// the admissible statement with the highest `observed_at`, the one held
/// earliest on a tie. A frame is kept while one of its statements wins.
///
/// `frames` are in stored order.
pub(super) fn select_conflicts(
    frames: &[ConflictFrame],
    subject: &Identifier,
    subject_chains: &[ValidatedChain],
    bound: &HashMap<NodeId, BoundWitness>,
) -> BTreeSet<[u8; 32]> {
    let mut best: BTreeMap<(NodeId, [u8; 32]), (u64, [u8; 32])> = BTreeMap::new();
    for (blob_id, statements) in frames {
        for statement in statements {
            if !statement_admissible(statement, subject, subject_chains, bound) {
                continue;
            }
            let slot = (statement.witness, statement.offered_digest);
            let wins = best
                .get(&slot)
                .is_none_or(|(observed_at, _)| statement.observed_at > *observed_at);
            if wins {
                best.insert(slot, (statement.observed_at, *blob_id));
            }
        }
    }
    best.into_values().map(|(_, blob_id)| blob_id).collect()
}

/// Decodes every stored conflict frame.
///
/// # Errors
///
/// `5000` for a stored frame that does not decode.
pub(super) fn decode_conflicts(
    stored: &[StoredBlob],
) -> Result<Vec<ConflictFrame>, PublicRecordRefusal> {
    stored
        .iter()
        .map(|blob| {
            decode_conflict_frame(&blob.blob)
                .map(|(_, statements)| (blob.blob_id, statements))
                .map_err(|e| corrupt("conflict", &e))
        })
        .collect()
}
