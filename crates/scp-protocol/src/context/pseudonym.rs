//! Per-context pseudonym-announcement wire types + the pure §9.10.4 / §9.10.4.1
//! validation core (ADR-057 T-1).
//!
//! This is the single, wasm-safe home for the per-context-pseudonym logic that
//! the relay/MLS routing layer uses to learn peers' routing IDs. It carries NO
//! async, NO transport, and NO platform dependency, so it compiles to
//! `wasm32-unknown-unknown` and both the native orchestrator (`scp-runtime`)
//! and the in-browser client (`scp-client`) call it verbatim (ADR-057 "share,
//! don't fork"). `pseudonym_cross_target_kat` exercises the cross-target
//! byte/decision parity under `wasm-pack test`.
//!
//! The module owns four things:
//! 1. the v1 [`PseudonymAnnouncement`] wire struct (§9.10.4) and the v2
//!    [`PseudonymAnnouncementV2`] rotation announcement (§9.10.4.1), with their
//!    tags [`PSEUDONYM_ANNOUNCEMENT_TAG`] and [`PSEUDONYM_ANNOUNCEMENT_V2_TAG`],
//! 2. the registry record [`PseudonymRecord`], one per peer DID: the routing ID
//!    and the epoch a v2 announcement carried (none for v1),
//! 3. the pure predicates [`is_pseudonym_announcement_payload`],
//!    [`is_reserved_pseudonym`], and [`pseudonym_collides_with_other_did`], and
//! 4. the pure decision core [`classify_pseudonym_announcement`], which runs the
//!    four §9.10.4 checks and then the §9.10.4.1 receipt-ordering rule, and
//!    returns one [`PseudonymAnnouncementDecision`] that each host maps to its
//!    own side effects.
//!
//! The reject-reason strings ([`REJECT_SENDER_MISMATCH`] et al.) are stable
//! `&'static str`s that are part of the committed cross-target known-answer
//! vectors (`.docs/specs/25-test-vectors.md` §25.19 Vectors 36 and 58) —
//! changing one is a wire-observable change, not a refactor.

use std::collections::{BTreeSet, HashMap};

use scp_did::DID;
use serde::{Deserialize, Serialize};

use super::{broadcast_routing_id, context_routing_id};

/// Wire format for pseudonym announcements sent as MLS application messages.
///
/// When a member joins or creates a context with a pre-derived pseudonym,
/// they announce it to other members via this structure serialized with
/// `MessagePack`. Recipients store the mapping in their pseudonym registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PseudonymAnnouncement {
    /// Magic prefix to distinguish from regular application messages.
    pub tag: String,
    /// The announcing member's DID.
    pub member_did: String,
    /// The 32-byte pseudonym routing ID.
    #[serde(with = "serde_bytes")]
    pub pseudonym: [u8; 32],
}

/// Magic tag used to identify pseudonym announcement messages in the MLS
/// application message stream.
///
/// Prefixed with `\0` to avoid collision with user-generated content (which is
/// always valid UTF-8 and will never start with a null byte when deserialized
/// from `MessagePack`).
pub const PSEUDONYM_ANNOUNCEMENT_TAG: &str = "\0scp:pseudonym-announce:v1";

/// The v2 rotation announcement (spec §9.10.4.1 "Announcement wire format
/// (v2)", §25.19 Vector 58).
///
/// A sender serializes it with `rmp_serde::to_vec_named`: a name-keyed map of
/// exactly these four fields in this order. `member_did` stays in the map so
/// the §9.10.4 sender binding applies to v2 unchanged. A map with a missing
/// key, an extra key, or a `routing_id` of any length other than 32 bytes is
/// not an announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PseudonymAnnouncementV2 {
    /// [`PSEUDONYM_ANNOUNCEMENT_V2_TAG`].
    pub tag: String,
    /// The announcing member's DID.
    pub member_did: String,
    /// The member's pseudonym rotation epoch (distinct from MLS epochs).
    pub pseudonym_epoch: u64,
    /// The 32-byte routing ID derived at `pseudonym_epoch`.
    #[serde(with = "serde_bytes")]
    pub routing_id: [u8; 32],
}

/// Tag of a [`PseudonymAnnouncementV2`] (spec §9.10.4.1).
pub const PSEUDONYM_ANNOUNCEMENT_V2_TAG: &str = "\0scp:pseudonym-announce:v2";

/// One peer's entry in a receiver's pseudonym registry (spec §9.10.4.1
/// "Receipt ordering").
///
/// The registry holds one record per DID, so deleting a DID's entry deletes
/// its routing ID and its epoch together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PseudonymRecord {
    /// The announced routing ID that senders fan application data out to.
    #[serde(with = "serde_bytes")]
    pub routing_id: [u8; 32],
    /// The announced epoch for a v2 announcement; `None` for a v1 one.
    #[serde(default)]
    pub epoch: Option<u64>,
}

/// Returns `true` when the first byte of `bytes` is a `MessagePack` map marker
/// (fixmap, map16 or map32).
///
/// The §9.10.4.1 decoding criterion names keys, and a derived `Deserialize`
/// also accepts a positional array of the same values, so the v2 decoder
/// requires a map before it decodes.
const fn starts_with_msgpack_map(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x80..=0x8f | 0xde | 0xdf))
}

/// Decodes a tagged v1 or v2 announcement into the announcer's claimed DID and
/// the record it asks the receiver to hold, or `None` for any other plaintext.
fn decode_announcement(plaintext: &[u8]) -> Option<(String, PseudonymRecord)> {
    if starts_with_msgpack_map(plaintext)
        && let Ok(v2) = rmp_serde::from_slice::<PseudonymAnnouncementV2>(plaintext)
    {
        return (v2.tag == PSEUDONYM_ANNOUNCEMENT_V2_TAG).then_some((
            v2.member_did,
            PseudonymRecord {
                routing_id: v2.routing_id,
                epoch: Some(v2.pseudonym_epoch),
            },
        ));
    }
    let v1 = rmp_serde::from_slice::<PseudonymAnnouncement>(plaintext).ok()?;
    (v1.tag == PSEUDONYM_ANNOUNCEMENT_TAG).then_some((
        v1.member_did,
        PseudonymRecord {
            routing_id: v1.pseudonym,
            epoch: None,
        },
    ))
}

/// Classifies a send-path payload as a pseudonym announcement, v1 or v2
/// (§9.10.4, §9.10.4.1).
///
/// Announcements are the ONLY payload class permitted to use the shared
/// `context_routing_id` as an addressee — they form the bootstrap channel
/// peers use to learn each other's pseudonyms before regular app data can fan
/// out on pseudonym-only paths. Returns `true` only when the payload decodes as
/// a well-formed v1 [`PseudonymAnnouncement`] or v2
/// [`PseudonymAnnouncementV2`] carrying its version's tag (`\0`-prefixed to
/// avoid collision with UTF-8 user content). False positives from adversarial
/// payloads cannot escalate: the worst outcome is a legitimate app message
/// routed to the shared RID, which is not a confidentiality issue (MLS still
/// gates content) and is detected as a non-announcement on the receive path.
#[must_use]
pub fn is_pseudonym_announcement_payload(payload: &[u8]) -> bool {
    decode_announcement(payload).is_some()
}

/// Returns `true` if `pseudonym` is a reserved routing ID a member is not
/// permitted to announce as their own (§9.10.4).
///
/// The pseudonym registry maps each member's DID to the routing ID honest
/// senders fan their app-data ciphertext out to. If a member could announce a
/// reserved value for their own DID, they could redirect every honest sender's
/// app-data:
///
/// - `[0u8; 32]` — the zero/degraded sentinel; maps to nothing meaningful.
/// - `context_routing_id(context_id)` — the shared bootstrap RID; announcing
///   it would push app-data ciphertext onto the shared channel, defeating
///   unlinkability.
/// - `broadcast_routing_id(context_id)` — the derivable `SHA-256(context_id)`
///   broadcast RID; same leak vector.
///
/// Honest pseudonyms are the raw 32-byte Ed25519 public key of the member's
/// per-context keypair (stored and routed on verbatim, NOT hashed). They
/// collide with these reserved values only with negligible probability, so
/// rejecting them costs nothing for legitimate members.
#[must_use]
pub fn is_reserved_pseudonym(pseudonym: &[u8; 32], context_id: &str) -> bool {
    *pseudonym == [0u8; 32]
        || *pseudonym == context_routing_id(context_id)
        || *pseudonym == broadcast_routing_id(context_id)
}

/// Returns `true` if `pseudonym` is already recorded under a DID OTHER than
/// `announcer_did` (§9.10.4 defense-in-depth).
///
/// The announcement path already enforces `announcement.member_did ==
/// sender_did`, so a member can only announce a routing ID for their own DID.
/// This guards the remaining vector: a member claiming a routing ID an
/// existing peer already legitimately uses, which would let two DIDs resolve
/// to one routing ID (a relay would then receive both members' fan-out at one
/// address, and honest senders addressing the colliding DID could misroute).
/// A member re-announcing a value for their OWN DID is NOT a collision; the
/// §9.10.4.1 ordering rule decides it.
///
/// Crate-internal: the sole caller is [`classify_pseudonym_announcement`] in
/// this module (plus this module's unit tests); the public entry point is the
/// classifier, not this predicate.
#[must_use]
pub(crate) fn pseudonym_collides_with_other_did(
    registry: &HashMap<DID, PseudonymRecord>,
    announcer_did: &DID,
    pseudonym: &[u8; 32],
) -> bool {
    registry
        .iter()
        .any(|(other_did, other)| other.routing_id == *pseudonym && other_did != announcer_did)
}

// ---------------------------------------------------------------------------
// Reject-reason strings (part of the cross-target KAT goldens — §25.19)
// ---------------------------------------------------------------------------

/// Reject reason: the announced `member_did` did not match the authenticated
/// sender (forged announcement).
///
/// This is the ONLY reason whose [`PseudonymAnnouncementDecision::Rejected`]
/// carries a `claimed_did`.
pub const REJECT_SENDER_MISMATCH: &str = "pseudonym announcement member_did does not match sender";

/// Reject reason: the announced pseudonym is a reserved routing ID
/// ([`is_reserved_pseudonym`]).
pub const REJECT_RESERVED: &str = "pseudonym announcement uses a reserved routing ID";

/// Reject reason: the announcement arrived on a broadcast context, which
/// carries no peer registry (registry `None`).
pub const REJECT_BROADCAST: &str = "pseudonym announcement received on broadcast context";

/// Reject reason: the announced routing ID is already recorded for a
/// DIFFERENT member ([`pseudonym_collides_with_other_did`]) or is one of the
/// receiver's own routing IDs.
pub const REJECT_COLLISION: &str =
    "pseudonym announcement collides with another member's routing ID";

/// Reject reason (§9.10.4.1 ordering criterion): a v2 announcement whose epoch
/// is lower than the recorded epoch, or equal to it with a different routing
/// ID.
pub const REJECT_EPOCH: &str = "pseudonym announcement epoch does not advance the recorded epoch";

/// Reject reason (§9.10.4.1 ordering criterion): a v1 announcement from a DID
/// whose record holds a v2 epoch.
pub const REJECT_V1_AFTER_V2: &str = "pseudonym v1 announcement follows a recorded v2 announcement";

/// Outcome of the pure §9.10.4 / §9.10.4.1 ingest classifier over a single
/// inbound plaintext.
///
/// The classifier makes the accept/reject DECISION; it performs no side
/// effects. Each host maps it to its own effects: a rejection metric and
/// `tracing` warn on `Rejected`, and a registry write plus a
/// `PseudonymAnnounced` event on `Accept`. Because both hosts share this one
/// decision function, they cannot diverge on which announcements are
/// accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudonymAnnouncementDecision {
    /// The plaintext is not a tagged announcement — the host should deliver it
    /// as a normal application message.
    NotAnnouncement,
    /// The plaintext was a tagged announcement that FAILED a security check
    /// or the ordering rule; the registry stays as it is. `reason` is one of
    /// the stable `REJECT_*` `&'static str`s; `claimed_did` is `Some` ONLY for
    /// the [`REJECT_SENDER_MISMATCH`] branch (it carries the forged DID so the
    /// host can reproduce the diagnostic).
    Rejected {
        /// The stable reject reason (one of the `REJECT_*` constants).
        reason: &'static str,
        /// The forged claimed DID — `Some` only on the sender-mismatch branch.
        claimed_did: Option<DID>,
    },
    /// A v2 announcement whose epoch and routing ID equal the announcer's
    /// record: an idempotent re-announcement, so the registry stays as it is.
    Unchanged,
    /// The plaintext was a well-formed announcement that passed every check.
    /// The host replaces `member_did`'s registry record with `record` and
    /// emits the routing-bootstrap signal when the routing ID changed.
    Accept {
        /// The authenticated announcer's DID (equals the sender).
        member_did: DID,
        /// The record to hold for `member_did`: the routing ID and the
        /// announced epoch (`None` for v1).
        record: PseudonymRecord,
    },
}

/// The pure §9.10.4 / §9.10.4.1 pseudonym-announcement decision core (ADR-057
/// T-1).
///
/// The single, shared, wasm-safe validator the native orchestrator and the
/// browser client both run, so their accept/reject behavior cannot drift.
///
/// Runs, over an inbound `plaintext`:
/// 1. decode ([`PseudonymAnnouncementDecision::NotAnnouncement`] unless the
///    plaintext is a tagged v2 or v1 announcement),
/// 2. `member_did == sender_did` (forged-announcement guard →
///    [`REJECT_SENDER_MISMATCH`], carrying the claimed DID),
/// 3. reserved-value rejection ([`is_reserved_pseudonym`] →
///    [`REJECT_RESERVED`]),
/// 4. broadcast-context reject (`registry == None` → [`REJECT_BROADCAST`]) then
///    collision ([`pseudonym_collides_with_other_did`], or a match with any of
///    `own_routing_ids` → [`REJECT_COLLISION`]),
/// 5. the §9.10.4.1 ordering rule against the announcer's record:
///    - v2 over no record, over a v1 record, or with an epoch strictly above
///      the recorded epoch → [`PseudonymAnnouncementDecision::Accept`];
///    - v2 with the recorded epoch and the recorded routing ID →
///      [`PseudonymAnnouncementDecision::Unchanged`];
///    - any other v2 (lower epoch, or equal epoch with another routing ID) →
///      [`REJECT_EPOCH`];
///    - v1 over a v2 record → [`REJECT_V1_AFTER_V2`];
///    - v1 over a v1 record or no record → `Accept` (§9.10.4 accepts a changed
///      value from the same DID).
///
/// `registry` is the caller's peer registry, or `None` for a broadcast context
/// (which carries no registry). `own_routing_ids` holds the RECEIVER's own
/// routing IDs in this context: its current routing ID and, while that value is
/// in its rotation grace, its previous one (empty when it has derived none).
/// The function performs NO side effects.
///
/// # Own-routing-ID collision guard (S1)
///
/// Step 4 rejects an announcement whose routing ID equals one of the
/// receiver's own. Without it a member M could announce `M → victim's routing
/// ID`: the sender binding passes, the value is not reserved, and the victim's
/// own routing ID is NOT in its PEER registry (which excludes self) — so the
/// victim would accept it and misroute every honest sender addressing M to the
/// victim's own address. The in-grace previous routing ID is still subscribed,
/// so it needs the same guard. This is sound because a member never
/// legitimately receives a peer announcement carrying its own routing ID — its
/// own announcements are self-echoes dropped at the MLS layer
/// (`CannotDecryptOwnMessage`) before reaching this classifier, and a distinct
/// member deriving the identical 32-byte value is negligible (and, were it to
/// happen, a genuine collision to reject).
// `registry` is ALWAYS the default-hasher peer registry the routing state owns;
// a `BuildHasher` type parameter would leak an unused generic into this shared
// cross-target decision API without real generality. Keep the concrete signature.
#[allow(clippy::implicit_hasher)]
#[must_use]
pub fn classify_pseudonym_announcement(
    plaintext: &[u8],
    sender_did: &str,
    context_id: &str,
    registry: Option<&HashMap<DID, PseudonymRecord>>,
    own_routing_ids: &[[u8; 32]],
) -> PseudonymAnnouncementDecision {
    // Step 1: decode. A non-announcement (or untagged payload) is ordinary
    // application data.
    let Some((claimed_did, announced)) = decode_announcement(plaintext) else {
        return PseudonymAnnouncementDecision::NotAnnouncement;
    };

    // Step 2: the announced DID must match the authenticated sender. A member
    // can only announce a routing ID for their OWN DID. Carry the claimed DID
    // so the host can reproduce the forged-announcement diagnostic.
    if claimed_did != sender_did {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_SENDER_MISMATCH,
            claimed_did: Some(DID(claimed_did)),
        };
    }

    let announced_did = DID(claimed_did);

    // Step 3: reject reserved routing-ID VALUES before touching the registry.
    // Announcing the zero sentinel, the shared bootstrap RID, or the broadcast
    // RID for one's own DID would redirect every honest sender's app-data
    // fan-out, defeating unlinkability or leaking ciphertext onto the shared
    // channel.
    if is_reserved_pseudonym(&announced.routing_id, context_id) {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_RESERVED,
            claimed_did: None,
        };
    }

    // Step 4: registry updates are meaningful only for encrypted contexts. A
    // broadcast context carries no peer registry — reject as a spec-level
    // violation. Otherwise reject a routing ID already recorded for a
    // DIFFERENT member, or one of the receiver's own (S1, see the doc comment).
    let Some(registry) = registry else {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_BROADCAST,
            claimed_did: None,
        };
    };
    if pseudonym_collides_with_other_did(registry, &announced_did, &announced.routing_id)
        || own_routing_ids.contains(&announced.routing_id)
    {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_COLLISION,
            claimed_did: None,
        };
    }

    // Step 5: the §9.10.4.1 ordering criterion against the announcer's record.
    let recorded = registry.get(&announced_did);
    match (announced.epoch, recorded.and_then(|r| r.epoch)) {
        (Some(epoch), Some(recorded_epoch)) if epoch > recorded_epoch => {}
        (Some(epoch), Some(recorded_epoch))
            if epoch == recorded_epoch
                && recorded.is_some_and(|r| r.routing_id == announced.routing_id) =>
        {
            return PseudonymAnnouncementDecision::Unchanged;
        }
        (Some(_), Some(_)) => {
            return PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_EPOCH,
                claimed_did: None,
            };
        }
        (None, Some(_)) => {
            return PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_V1_AFTER_V2,
                claimed_did: None,
            };
        }
        // v2 over a v1 record or no record, and v1 over a v1 record or no
        // record: the announcement replaces the record.
        (_, None) => {}
    }

    PseudonymAnnouncementDecision::Accept {
        member_did: announced_did,
        record: announced,
    }
}

// ---------------------------------------------------------------------------
// Membership-change criterion (§9.10.4.1)
// ---------------------------------------------------------------------------

/// The DID of every occupied MLS leaf before and after one Commit, one entry
/// per leaf, as the Commit's admission read the tree (spec 09 §9.10.4.1
/// "Membership-change criterion").
///
/// A DID appears once per leaf it holds, so a DID with two device leaves
/// appears twice. Order carries no meaning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitLeafDids {
    /// One DID per occupied leaf of the tree before the Commit.
    pub before: Vec<String>,
    /// One DID per occupied leaf of the tree after the Commit.
    pub after: Vec<String>,
}

/// The membership changes one Commit applies, counted by DID (spec 09
/// §9.10.4.1 "Membership-change criterion"), from
/// [`classify_commit_membership`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitMembershipChange {
    /// Each DID that held no leaf before the Commit and holds one after: one
    /// `AddMember` each. Sorted, without duplicates.
    pub added_dids: Vec<String>,
    /// Each DID that held a leaf before the Commit and holds none after: the
    /// Commit removed its last leaf, one `RemoveMember` each. Sorted, without
    /// duplicates.
    pub removed_dids: Vec<String>,
}

impl CommitMembershipChange {
    /// `true` when the Commit applies no `AddMember` and no `RemoveMember`, such
    /// as a key update or a device leaf added to or removed from a DID that
    /// holds another leaf before and after.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added_dids.is_empty() && self.removed_dids.is_empty()
    }
}

/// Classifies one Commit's membership changes by DID, not by MLS leaf (spec
/// 09 §9.10.4.1 "Membership-change criterion").
///
/// A Commit is an `AddMember` for each DID that held no leaf before it, and a
/// `RemoveMember` for each DID whose last leaf it removes. A device leaf added
/// to or removed from a DID that holds another leaf both before and after the
/// Commit (`26-conformance-suite.md` CONF-005) is neither, so it appears in
/// neither list.
#[must_use]
pub fn classify_commit_membership(leaf_dids: &CommitLeafDids) -> CommitMembershipChange {
    let before: BTreeSet<&str> = leaf_dids.before.iter().map(String::as_str).collect();
    let after: BTreeSet<&str> = leaf_dids.after.iter().map(String::as_str).collect();
    CommitMembershipChange {
        added_dids: after.difference(&before).map(|d| (*d).to_owned()).collect(),
        removed_dids: before.difference(&after).map(|d| (*d).to_owned()).collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        CommitLeafDids, PSEUDONYM_ANNOUNCEMENT_TAG, PSEUDONYM_ANNOUNCEMENT_V2_TAG,
        PseudonymAnnouncement, PseudonymAnnouncementDecision, PseudonymAnnouncementV2,
        PseudonymRecord, REJECT_BROADCAST, REJECT_COLLISION, REJECT_EPOCH, REJECT_RESERVED,
        REJECT_SENDER_MISMATCH, classify_commit_membership, classify_pseudonym_announcement,
        is_pseudonym_announcement_payload, is_reserved_pseudonym,
        pseudonym_collides_with_other_did,
    };
    use scp_did::DID;
    use std::collections::HashMap;

    const CTX: &str = "ctx-pseudonym-routing-tests";

    fn announcement_bytes(member_did: &str, pseudonym: [u8; 32]) -> Vec<u8> {
        let ann = PseudonymAnnouncement {
            tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: member_did.to_owned(),
            pseudonym,
        };
        rmp_serde::to_vec_named(&ann).expect("serialize announcement")
    }

    fn v2_bytes(member_did: &str, pseudonym_epoch: u64, routing_id: [u8; 32]) -> Vec<u8> {
        let ann = PseudonymAnnouncementV2 {
            tag: PSEUDONYM_ANNOUNCEMENT_V2_TAG.to_owned(),
            member_did: member_did.to_owned(),
            pseudonym_epoch,
            routing_id,
        };
        rmp_serde::to_vec_named(&ann).expect("serialize v2 announcement")
    }

    const fn v1_record(routing_id: [u8; 32]) -> PseudonymRecord {
        PseudonymRecord {
            routing_id,
            epoch: None,
        }
    }

    const fn v2_record(epoch: u64, routing_id: [u8; 32]) -> PseudonymRecord {
        PseudonymRecord {
            routing_id,
            epoch: Some(epoch),
        }
    }

    fn registry_of(entries: &[(&str, PseudonymRecord)]) -> HashMap<DID, PseudonymRecord> {
        entries
            .iter()
            .map(|(did, record)| (DID((*did).to_owned()), *record))
            .collect()
    }

    /// §9.10.4: the shared `context_routing_id` is a RESERVED value — a member
    /// must not be able to announce it as their own pseudonym, because honest
    /// senders fan app-data out to announced pseudonyms and the shared RID is
    /// relay-derivable. This is the type-level proof that the deleted
    /// `shared_rid` fallback cannot be reintroduced through an announcement.
    #[test]
    fn shared_context_routing_id_is_reserved() {
        let shared = super::context_routing_id(CTX);
        assert!(
            is_reserved_pseudonym(&shared, CTX),
            "shared context routing id must be rejected as a pseudonym value"
        );
    }

    #[test]
    fn zero_and_broadcast_routing_ids_are_reserved() {
        assert!(
            is_reserved_pseudonym(&[0u8; 32], CTX),
            "zero sentinel reserved"
        );
        let broadcast = super::broadcast_routing_id(CTX);
        assert!(
            is_reserved_pseudonym(&broadcast, CTX),
            "broadcast routing id reserved"
        );
    }

    #[test]
    fn honest_pseudonym_is_not_reserved() {
        // A raw Ed25519-public-key-shaped value (non-zero, not a derivable RID).
        let honest = [7u8; 32];
        assert!(
            !is_reserved_pseudonym(&honest, CTX),
            "an ordinary pseudonym must be accepted"
        );
    }

    #[test]
    fn cross_did_collision_detected_same_did_allowed() {
        let rid = [9u8; 32];
        let registry = registry_of(&[("did:key:alice", v1_record(rid))]);
        let alice = DID("did:key:alice".to_owned());
        let bob = DID("did:key:bob".to_owned());

        // Bob claiming Alice's routing ID is a cross-DID collision.
        assert!(
            pseudonym_collides_with_other_did(&registry, &bob, &rid),
            "a different DID claiming an existing routing ID is a collision"
        );
        // Alice re-announcing her OWN routing ID is not a collision.
        assert!(
            !pseudonym_collides_with_other_did(&registry, &alice, &rid),
            "same-DID re-announce is not a collision"
        );
    }

    #[test]
    fn announcement_classifier_matches_only_tagged_payloads() {
        assert!(
            is_pseudonym_announcement_payload(&announcement_bytes("did:key:alice", [3u8; 32])),
            "a well-formed tagged v1 announcement is classified as such"
        );
        assert!(
            is_pseudonym_announcement_payload(&v2_bytes("did:key:alice", 4, [3u8; 32])),
            "a well-formed tagged v2 announcement routes to the shared RID too"
        );
        // Arbitrary user content must NOT be classified as an announcement, so
        // it never gets routed to the shared bootstrap RID.
        assert!(
            !is_pseudonym_announcement_payload(b"hello world"),
            "ordinary app data is not an announcement"
        );
    }

    // -----------------------------------------------------------------------
    // classify_pseudonym_announcement — every branch, pinning the exact reject
    // reason strings (which are part of the §25.19 cross-target goldens).
    // -----------------------------------------------------------------------

    const ALICE: &str = "did:key:alice";
    const BOB: &str = "did:key:bob";

    #[test]
    fn classify_untagged_payload_is_not_announcement() {
        assert_eq!(
            classify_pseudonym_announcement(b"hello world", ALICE, CTX, Some(&HashMap::new()), &[]),
            PseudonymAnnouncementDecision::NotAnnouncement,
            "ordinary app data classifies as NotAnnouncement"
        );
    }

    #[test]
    fn classify_wrong_tag_is_not_announcement() {
        // A struct-shaped payload whose tag is not the magic tag decodes but is
        // not an announcement.
        let bytes = announcement_bytes(ALICE, [1u8; 32]);
        let mut ann: PseudonymAnnouncement = rmp_serde::from_slice(&bytes).expect("decode fixture");
        ann.tag = "not-the-tag".to_owned();
        let mistagged = rmp_serde::to_vec_named(&ann).expect("re-encode fixture");
        assert_eq!(
            classify_pseudonym_announcement(&mistagged, ALICE, CTX, Some(&HashMap::new()), &[]),
            PseudonymAnnouncementDecision::NotAnnouncement,
            "a non-magic tag classifies as NotAnnouncement"
        );
    }

    #[test]
    fn classify_v2_shape_with_v1_tag_and_v1_shape_with_v2_tag_are_not_announcements() {
        // Each version's tag binds its own shape: swapping them yields data.
        let mut v2 = PseudonymAnnouncementV2 {
            tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: ALICE.to_owned(),
            pseudonym_epoch: 1,
            routing_id: [5u8; 32],
        };
        let v2_with_v1_tag = rmp_serde::to_vec_named(&v2).expect("encode");
        let v1 = PseudonymAnnouncement {
            tag: PSEUDONYM_ANNOUNCEMENT_V2_TAG.to_owned(),
            member_did: ALICE.to_owned(),
            pseudonym: [5u8; 32],
        };
        let v1_with_v2_tag = rmp_serde::to_vec_named(&v1).expect("encode");
        for bytes in [v2_with_v1_tag, v1_with_v2_tag] {
            assert_eq!(
                classify_pseudonym_announcement(&bytes, ALICE, CTX, Some(&HashMap::new()), &[]),
                PseudonymAnnouncementDecision::NotAnnouncement,
            );
        }
        // A positional (array) encoding of the v2 fields names no keys, so the
        // §9.10.4.1 decoding criterion does not admit it.
        v2.tag = PSEUDONYM_ANNOUNCEMENT_V2_TAG.to_owned();
        let positional = rmp_serde::to_vec(&v2).expect("encode positional");
        assert_eq!(
            classify_pseudonym_announcement(&positional, ALICE, CTX, Some(&HashMap::new()), &[]),
            PseudonymAnnouncementDecision::NotAnnouncement,
        );
    }

    #[test]
    fn classify_sender_mismatch_is_rejected_with_claimed_did() {
        let forged = announcement_bytes(BOB, [0x42u8; 32]);
        assert_eq!(
            classify_pseudonym_announcement(&forged, ALICE, CTX, Some(&HashMap::new()), &[]),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_SENDER_MISMATCH,
                claimed_did: Some(DID(BOB.to_owned())),
            },
            "a forged-DID announcement is rejected and carries the claimed DID"
        );
    }

    #[test]
    fn classify_reserved_value_is_rejected() {
        for reserved in [
            [0u8; 32],
            super::context_routing_id(CTX),
            super::broadcast_routing_id(CTX),
        ] {
            let bytes = announcement_bytes(ALICE, reserved);
            assert_eq!(
                classify_pseudonym_announcement(&bytes, ALICE, CTX, Some(&HashMap::new()), &[]),
                PseudonymAnnouncementDecision::Rejected {
                    reason: REJECT_RESERVED,
                    claimed_did: None,
                },
                "a reserved routing ID is rejected"
            );
        }
    }

    #[test]
    fn classify_broadcast_context_is_rejected() {
        let bytes = announcement_bytes(ALICE, [0x42u8; 32]);
        assert_eq!(
            classify_pseudonym_announcement(&bytes, ALICE, CTX, None, &[]),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_BROADCAST,
                claimed_did: None,
            },
            "an announcement on a broadcast context (no registry) is rejected"
        );
    }

    #[test]
    fn classify_cross_did_collision_is_rejected() {
        let rid = [0x55u8; 32];
        let registry = registry_of(&[(ALICE, v1_record(rid))]);
        // BOB tries to claim ALICE's already-registered routing ID.
        let bytes = announcement_bytes(BOB, rid);
        assert_eq!(
            classify_pseudonym_announcement(&bytes, BOB, CTX, Some(&registry), &[]),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_COLLISION,
                claimed_did: None,
            },
            "a cross-DID routing-ID collision is rejected"
        );
    }

    #[test]
    fn classify_rejects_announcement_of_the_receivers_own_routing_ids() {
        // S1: BOB announces `BOB → victim routing ID`, where the value is one of
        // the RECEIVER's own. The sender binding passes, the value is not
        // reserved, and it is NOT in the peer registry (which excludes self) —
        // but the shared classifier, given the receiver's own routing IDs,
        // rejects it as a collision. The in-grace previous routing ID is
        // guarded the same way as the current one.
        let current = [0x77u8; 32];
        let previous = [0x78u8; 32];
        for claimed in [current, previous] {
            for bytes in [announcement_bytes(BOB, claimed), v2_bytes(BOB, 3, claimed)] {
                assert_eq!(
                    classify_pseudonym_announcement(
                        &bytes,
                        BOB,
                        CTX,
                        Some(&HashMap::new()),
                        &[current, previous],
                    ),
                    PseudonymAnnouncementDecision::Rejected {
                        reason: REJECT_COLLISION,
                        claimed_did: None,
                    },
                    "an announcement claiming one of the receiver's own routing IDs is rejected"
                );
            }
        }
        // A DIFFERENT value from BOB is still accepted with own routing IDs set.
        let other = announcement_bytes(BOB, [0x33u8; 32]);
        assert_eq!(
            classify_pseudonym_announcement(
                &other,
                BOB,
                CTX,
                Some(&HashMap::new()),
                &[current, previous],
            ),
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(BOB.to_owned()),
                record: v1_record([0x33u8; 32]),
            },
            "a non-colliding announcement is unaffected by the own-routing-ID guard"
        );
    }

    #[test]
    fn classify_legitimate_announcement_is_accepted() {
        let pseudonym = [0x42u8; 32];
        let bytes = announcement_bytes(ALICE, pseudonym);
        assert_eq!(
            classify_pseudonym_announcement(&bytes, ALICE, CTX, Some(&HashMap::new()), &[]),
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(ALICE.to_owned()),
                record: v1_record(pseudonym),
            },
            "a legitimate announcement is accepted with the announcer DID + pseudonym"
        );
    }

    #[test]
    fn classify_same_did_v1_reannounce_over_v1_record_is_accepted() {
        let registry = registry_of(&[(ALICE, v1_record([0x42u8; 32]))]);
        // §9.10.4 accepts a changed v1 value from the same DID.
        let bytes = announcement_bytes(ALICE, [0x43u8; 32]);
        assert_eq!(
            classify_pseudonym_announcement(&bytes, ALICE, CTX, Some(&registry), &[]),
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(ALICE.to_owned()),
                record: v1_record([0x43u8; 32]),
            },
        );
    }

    #[test]
    fn classify_v2_epoch_ordering_covers_max_epoch() {
        // An epoch at u64::MAX over u64::MAX - 1 advances; the same epoch with
        // the same value is idempotent; nothing above u64::MAX exists, so a
        // record at u64::MAX accepts only its own re-announcement.
        let registry = registry_of(&[(ALICE, v2_record(u64::MAX - 1, [0x44u8; 32]))]);
        assert_eq!(
            classify_pseudonym_announcement(
                &v2_bytes(ALICE, u64::MAX, [0x43u8; 32]),
                ALICE,
                CTX,
                Some(&registry),
                &[],
            ),
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(ALICE.to_owned()),
                record: v2_record(u64::MAX, [0x43u8; 32]),
            },
        );
        let at_max = registry_of(&[(ALICE, v2_record(u64::MAX, [0x43u8; 32]))]);
        assert_eq!(
            classify_pseudonym_announcement(
                &v2_bytes(ALICE, u64::MAX, [0x43u8; 32]),
                ALICE,
                CTX,
                Some(&at_max),
                &[],
            ),
            PseudonymAnnouncementDecision::Unchanged,
        );
        assert_eq!(
            classify_pseudonym_announcement(
                &v2_bytes(ALICE, u64::MAX, [0x45u8; 32]),
                ALICE,
                CTX,
                Some(&at_max),
                &[],
            ),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_EPOCH,
                claimed_did: None,
            },
        );
    }

    // -----------------------------------------------------------------------
    // §25.19 Vector 58 — the v2 wire bytes and every row of the decision table.
    // The cross-target copy of this assertion lives in
    // `crates/scp-client-wasm/tests/pseudonym_cross_target_kat.rs`.
    // -----------------------------------------------------------------------

    const MEMBER: &str = "scp:z5glr2inbuzd33xrfkdgpjejz4x7z4r2jxcsfvdxbwtgoi73xx2q";
    const OTHER: &str = "scp:ur5v4nca7x4lfagd2fojmjydguxwjwvfz2tur63s3x3k5vvqmppa";
    const KAT_CTX: &str = "ctx-adr057-pseudonym-kat";
    const V58_EPOCH_1_HEX: &str = "84a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7632aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271af70736575646f6e796d5f65706f636801aa726f7574696e675f6964c4204343434343434343434343434343434343434343434343434343434343434343";
    const V58_EPOCH_2_POW_32_HEX: &str = "84a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7632aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271af70736575646f6e796d5f65706f6368cf0000000100000000aa726f7574696e675f6964c4204343434343434343434343434343434343434343434343434343434343434343";
    const V36_GOLDEN_HEX: &str = "83a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7631aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271a970736575646f6e796dc4204242424242424242424242424242424242424242424242424242424242424242";

    #[test]
    fn vector_58_v2_wire_bytes_match_golden() {
        assert_eq!(
            hex::encode(v2_bytes(MEMBER, 1, [0x43u8; 32])),
            V58_EPOCH_1_HEX
        );
        assert_eq!(
            hex::encode(v2_bytes(MEMBER, 1 << 32, [0x43u8; 32])),
            V58_EPOCH_2_POW_32_HEX
        );
        // Vector 36's v1 golden is the input of the v1 rows below.
        assert_eq!(
            hex::encode(announcement_bytes(MEMBER, [0x42u8; 32])),
            V36_GOLDEN_HEX
        );
    }

    /// One Vector 58 decision-table row: case name, payload, receiver
    /// registry (`None` on a broadcast context), the receiver's own routing
    /// IDs, and the expected decision.
    type V58Row = (
        &'static str,
        Vec<u8>,
        Option<HashMap<DID, PseudonymRecord>>,
        Vec<[u8; 32]>,
        PseudonymAnnouncementDecision,
    );

    fn v58_accept() -> PseudonymAnnouncementDecision {
        PseudonymAnnouncementDecision::Accept {
            member_did: DID(MEMBER.to_owned()),
            record: v2_record(1, [0x43u8; 32]),
        }
    }

    const fn v58_rejected(reason: &'static str) -> PseudonymAnnouncementDecision {
        PseudonymAnnouncementDecision::Rejected {
            reason,
            claimed_did: None,
        }
    }

    /// The §9.10.4.1 receipt-ordering rows of Vector 58.
    fn v58_ordering_rows(golden: &[u8], golden_v1: &[u8]) -> Vec<V58Row> {
        vec![
            (
                "first v2, no record",
                golden.to_vec(),
                Some(HashMap::new()),
                vec![],
                v58_accept(),
            ),
            (
                "v2 over a v1 record",
                golden.to_vec(),
                Some(registry_of(&[(MEMBER, v1_record([0x42u8; 32]))])),
                vec![],
                v58_accept(),
            ),
            (
                "higher epoch",
                golden.to_vec(),
                Some(registry_of(&[(MEMBER, v2_record(0, [0x44u8; 32]))])),
                vec![],
                v58_accept(),
            ),
            (
                "same epoch, same value",
                golden.to_vec(),
                Some(registry_of(&[(MEMBER, v2_record(1, [0x43u8; 32]))])),
                vec![],
                PseudonymAnnouncementDecision::Unchanged,
            ),
            (
                "same epoch, other value",
                golden.to_vec(),
                Some(registry_of(&[(MEMBER, v2_record(1, [0x44u8; 32]))])),
                vec![],
                v58_rejected("pseudonym announcement epoch does not advance the recorded epoch"),
            ),
            (
                "lower epoch",
                golden.to_vec(),
                Some(registry_of(&[(MEMBER, v2_record(2, [0x44u8; 32]))])),
                vec![],
                v58_rejected("pseudonym announcement epoch does not advance the recorded epoch"),
            ),
            (
                "v1 after v2",
                golden_v1.to_vec(),
                Some(registry_of(&[(MEMBER, v2_record(1, [0x43u8; 32]))])),
                vec![],
                v58_rejected("pseudonym v1 announcement follows a recorded v2 announcement"),
            ),
            (
                "v1 over v1",
                golden_v1.to_vec(),
                Some(registry_of(&[(MEMBER, v1_record([0x44u8; 32]))])),
                vec![],
                PseudonymAnnouncementDecision::Accept {
                    member_did: DID(MEMBER.to_owned()),
                    record: v1_record([0x42u8; 32]),
                },
            ),
        ]
    }

    /// The §9.10.4 check rows (sender binding, reserved value, broadcast
    /// context, collision) and the decoding rows of Vector 58.
    fn v58_check_rows(golden: &[u8]) -> Vec<V58Row> {
        vec![
            (
                "sender mismatch",
                v2_bytes(OTHER, 1, [0x43u8; 32]),
                Some(HashMap::new()),
                vec![],
                PseudonymAnnouncementDecision::Rejected {
                    reason: "pseudonym announcement member_did does not match sender",
                    claimed_did: Some(DID(OTHER.to_owned())),
                },
            ),
            (
                "reserved value: zero",
                v2_bytes(MEMBER, 1, [0u8; 32]),
                Some(HashMap::new()),
                vec![],
                v58_rejected("pseudonym announcement uses a reserved routing ID"),
            ),
            (
                "reserved value: context routing ID",
                v2_bytes(MEMBER, 1, super::context_routing_id(KAT_CTX)),
                Some(HashMap::new()),
                vec![],
                v58_rejected("pseudonym announcement uses a reserved routing ID"),
            ),
            (
                "reserved value: broadcast routing ID",
                v2_bytes(MEMBER, 1, super::broadcast_routing_id(KAT_CTX)),
                Some(HashMap::new()),
                vec![],
                v58_rejected("pseudonym announcement uses a reserved routing ID"),
            ),
            (
                "broadcast context",
                golden.to_vec(),
                None,
                vec![],
                v58_rejected("pseudonym announcement received on broadcast context"),
            ),
            (
                "cross-DID collision",
                golden.to_vec(),
                Some(registry_of(&[(OTHER, v1_record([0x43u8; 32]))])),
                vec![],
                v58_rejected("pseudonym announcement collides with another member's routing ID"),
            ),
            (
                "receiver's current routing ID",
                golden.to_vec(),
                Some(HashMap::new()),
                vec![[0x43u8; 32]],
                v58_rejected("pseudonym announcement collides with another member's routing ID"),
            ),
            (
                "receiver's in-grace previous routing ID",
                golden.to_vec(),
                Some(HashMap::new()),
                vec![[0x45u8; 32], [0x43u8; 32]],
                v58_rejected("pseudonym announcement collides with another member's routing ID"),
            ),
            (
                "extra key",
                v58_with_extra_key(golden),
                Some(HashMap::new()),
                vec![],
                PseudonymAnnouncementDecision::NotAnnouncement,
            ),
            (
                "short routing_id",
                v58_with_short_routing_id(golden),
                Some(HashMap::new()),
                vec![],
                PseudonymAnnouncementDecision::NotAnnouncement,
            ),
        ]
    }

    #[test]
    fn vector_58_decision_table() {
        let golden = hex::decode(V58_EPOCH_1_HEX).expect("golden hex");
        let golden_v1 = hex::decode(V36_GOLDEN_HEX).expect("v1 golden hex");
        let rows = v58_ordering_rows(&golden, &golden_v1)
            .into_iter()
            .chain(v58_check_rows(&golden));
        for (case, payload, registry, own, expected) in rows {
            let before = registry.clone();
            let decision =
                classify_pseudonym_announcement(&payload, MEMBER, KAT_CTX, registry.as_ref(), &own);
            assert_eq!(decision, expected, "Vector 58 row: {case}");
            // The classifier is pure: every row leaves its input registry as is.
            assert_eq!(registry, before, "Vector 58 row: {case}");
        }
    }

    /// The golden v2 map with a fifth key appended: the fixmap header becomes
    /// `0x85` and `"x": 0` follows the four golden entries.
    fn v58_with_extra_key(golden: &[u8]) -> Vec<u8> {
        let mut bytes = golden.to_vec();
        bytes[0] = 0x85;
        bytes.extend_from_slice(&[0xa1, b'x', 0x00]);
        bytes
    }

    /// The golden v2 map with a 31-byte `routing_id`: the trailing `bin8`
    /// length becomes `0x1f` and one value byte is dropped.
    fn v58_with_short_routing_id(golden: &[u8]) -> Vec<u8> {
        let mut bytes = golden[..golden.len() - 1].to_vec();
        let len_at = bytes.len() - 31 - 1;
        assert_eq!(bytes[len_at], 0x20, "bin8 length byte of routing_id");
        bytes[len_at] = 0x1f;
        bytes
    }

    #[test]
    fn pseudonym_record_without_epoch_key_decodes_as_v1_record() {
        // `#[serde(default)]` on `epoch`: a record written without the key
        // reads back as a v1 record.
        let json = serde_json::json!({ "routing_id": vec![7u8; 32] });
        let record: PseudonymRecord = serde_json::from_value(json).expect("decode");
        assert_eq!(record, v1_record([7u8; 32]));
    }

    fn leaf_dids(before: &[&str], after: &[&str]) -> CommitLeafDids {
        CommitLeafDids {
            before: before.iter().map(|d| (*d).to_owned()).collect(),
            after: after.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    fn dids(list: &[&str]) -> Vec<String> {
        list.iter().map(|d| (*d).to_owned()).collect()
    }

    #[test]
    fn classify_commit_membership_counts_a_new_did_as_one_add() {
        let change = classify_commit_membership(&leaf_dids(&["a", "b"], &["a", "b", "c"]));
        assert_eq!(change.added_dids, dids(&["c"]));
        assert!(change.removed_dids.is_empty());
        assert!(!change.is_empty());
    }

    #[test]
    fn classify_commit_membership_counts_a_did_losing_its_last_leaf_as_one_remove() {
        let change = classify_commit_membership(&leaf_dids(&["a", "b", "c"], &["a", "b"]));
        assert!(change.added_dids.is_empty());
        assert_eq!(change.removed_dids, dids(&["c"]));
    }

    #[test]
    fn classify_commit_membership_ignores_a_device_leaf_added_to_a_held_did() {
        // CONF-005: c already holds a leaf, so a second device leaf adds no DID.
        let change =
            classify_commit_membership(&leaf_dids(&["a", "b", "c"], &["a", "b", "c", "c"]));
        assert!(change.is_empty(), "{change:?}");
    }

    #[test]
    fn classify_commit_membership_ignores_a_device_leaf_removed_from_a_did_keeping_one() {
        let change = classify_commit_membership(&leaf_dids(&["a", "c", "c"], &["a", "c"]));
        assert!(change.is_empty(), "{change:?}");
    }

    #[test]
    fn classify_commit_membership_counts_a_new_did_with_two_leaves_as_one_add() {
        let change = classify_commit_membership(&leaf_dids(&["a"], &["a", "c", "c"]));
        assert_eq!(change.added_dids, dids(&["c"]));
        assert!(change.removed_dids.is_empty());
    }

    #[test]
    fn classify_commit_membership_counts_a_did_losing_both_leaves_as_one_remove() {
        let change = classify_commit_membership(&leaf_dids(&["a", "c", "c"], &["a"]));
        assert!(change.added_dids.is_empty());
        assert_eq!(change.removed_dids, dids(&["c"]));
    }

    #[test]
    fn classify_commit_membership_reports_every_change_of_one_commit_sorted() {
        let change =
            classify_commit_membership(&leaf_dids(&["a", "e", "b"], &["a", "d", "c", "c"]));
        assert_eq!(change.added_dids, dids(&["c", "d"]));
        assert_eq!(change.removed_dids, dids(&["b", "e"]));
    }

    #[test]
    fn classify_commit_membership_finds_no_change_in_a_key_update() {
        let change = classify_commit_membership(&leaf_dids(&["a", "b"], &["b", "a"]));
        assert!(change.is_empty(), "{change:?}");
    }
}
