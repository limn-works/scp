//! Per-context pseudonym-announcement wire type + the pure §9.10.4 validation
//! core (ADR-057 T-1).
//!
//! This is the single, wasm-safe home for the §9.10.4 per-context-pseudonym
//! logic that the relay/MLS routing layer uses to learn peers' routing IDs. It
//! carries NO async, NO transport, and NO platform dependency, so it compiles
//! to `wasm32-unknown-unknown` and is READY to be consumed verbatim by the
//! in-browser client driver (ADR-057 "share, don't fork"). Today the native
//! orchestrator (`scp-runtime`) is the sole production consumer; the
//! cross-target byte/decision parity that a shared copy must hold is already
//! exercised by `pseudonym_cross_target_kat` under `wasm-pack test`, so a
//! future browser call site inherits one non-forked implementation.
//!
//! The module owns three things:
//! 1. the [`PseudonymAnnouncement`] wire struct + its [`PSEUDONYM_ANNOUNCEMENT_TAG`]
//!    magic tag (the `MessagePack` bootstrap payload members broadcast to teach
//!    peers their routing ID),
//! 2. the pure predicates [`is_pseudonym_announcement_payload`],
//!    [`is_reserved_pseudonym`], and [`pseudonym_collides_with_other_did`], and
//! 3. the pure decision core [`classify_pseudonym_announcement`], which folds the
//!    four-step ingest validation into a single [`PseudonymAnnouncementDecision`]
//!    the host maps to its own side effects (native `scp-runtime`: metric +
//!    `tracing` warn + registry insert + event emit; a future browser driver
//!    would run the equivalent hooks).
//!
//! The reject-reason strings ([`REJECT_SENDER_MISMATCH`] et al.) are stable
//! `&'static str`s that are part of the committed cross-target known-answer
//! vectors (`.docs/specs/25-test-vectors.md` §25.19) — changing one is a
//! wire-observable change, not a refactor.

use std::collections::HashMap;

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

/// Classifies a send-path payload as a `PseudonymAnnouncement` (§9.10.4).
///
/// Announcements are the ONLY payload class permitted to use the shared
/// `context_routing_id` as an addressee — they form the bootstrap channel
/// peers use to learn each other's pseudonyms before regular app data can fan
/// out on pseudonym-only paths. Returns `true` only when the payload
/// deserializes as a well-formed `PseudonymAnnouncement` AND carries the magic
/// tag (`PSEUDONYM_ANNOUNCEMENT_TAG`, `\0`-prefixed to avoid collision with
/// UTF-8 user content). False positives from adversarial payloads cannot
/// escalate: the worst outcome is a legitimate app message routed to the
/// shared RID, which is not a confidentiality issue (MLS still gates content)
/// and is detected as a non-announcement on the receive path.
#[must_use]
pub fn is_pseudonym_announcement_payload(payload: &[u8]) -> bool {
    rmp_serde::from_slice::<PseudonymAnnouncement>(payload)
        .is_ok_and(|a| a.tag == PSEUDONYM_ANNOUNCEMENT_TAG)
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

/// Returns `true` if `pseudonym` is already registered under a DID OTHER than
/// `announcer_did` (§9.10.4 defense-in-depth).
///
/// The announcement path already enforces `announcement.member_did ==
/// sender_did`, so a member can only announce a routing ID for their own DID.
/// This guards the remaining vector: a member claiming a routing ID an
/// existing peer already legitimately uses, which would let two DIDs resolve
/// to one routing ID (a relay would then receive both members' fan-out at one
/// address, and honest senders addressing the colliding DID could misroute).
/// A member re-announcing the SAME value for their OWN DID is legitimate (key
/// rotation re-broadcast) and is NOT a collision.
///
/// Crate-internal: the sole caller is [`classify_pseudonym_announcement`] in
/// this module (plus this module's unit tests); the public entry point is the
/// classifier, not this predicate.
#[must_use]
pub(crate) fn pseudonym_collides_with_other_did(
    registry: &HashMap<DID, [u8; 32]>,
    announcer_did: &DID,
    pseudonym: &[u8; 32],
) -> bool {
    registry.iter().any(|(other_did, other_pseudonym)| {
        other_pseudonym == pseudonym && other_did != announcer_did
    })
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

/// Reject reason: the announced pseudonym is already claimed by a DIFFERENT
/// member ([`pseudonym_collides_with_other_did`]).
pub const REJECT_COLLISION: &str =
    "pseudonym announcement collides with another member's routing ID";

/// Outcome of the pure §9.10.4 ingest classifier over a single inbound
/// plaintext.
///
/// The classifier makes the accept/reject DECISION; it performs no side
/// effects. The host maps this to its own effects: the native orchestrator
/// records a rejection metric + `tracing` warn on `Rejected`, and inserts the
/// registry entry + emits a `PseudonymAnnounced` event on `Accept` (a future
/// browser driver would run the equivalent hooks). Because any host shares this
/// one decision function, they cannot diverge on which announcements are
/// accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudonymAnnouncementDecision {
    /// The plaintext is not a tagged `PseudonymAnnouncement` — the host should
    /// deliver it as a normal application message.
    NotAnnouncement,
    /// The plaintext was a tagged announcement that FAILED a security check.
    /// `reason` is one of the stable `REJECT_*` `&'static str`s; `claimed_did`
    /// is `Some` ONLY for the [`REJECT_SENDER_MISMATCH`] branch (it carries the
    /// forged DID so the host can reproduce the diagnostic).
    Rejected {
        /// The stable reject reason (one of the `REJECT_*` constants).
        reason: &'static str,
        /// The forged claimed DID — `Some` only on the sender-mismatch branch.
        claimed_did: Option<DID>,
    },
    /// The plaintext was a well-formed announcement that passed every check.
    /// The host should insert `member_did -> pseudonym` into its peer registry
    /// and emit the routing-bootstrap signal.
    Accept {
        /// The authenticated announcer's DID (equals the sender).
        member_did: DID,
        /// The 32-byte routing ID to register for `member_did`.
        pseudonym: [u8; 32],
    },
}

/// The pure §9.10.4 pseudonym-announcement decision core (ADR-057 T-1).
///
/// This is the single, shared, wasm-safe validator the native orchestrator runs
/// today and a future browser driver can run verbatim, so their accept/reject
/// behavior cannot drift.
///
/// Runs the four-step validation core over an inbound `plaintext`:
/// 1. tag-decode ([`PseudonymAnnouncementDecision::NotAnnouncement`] if the
///    plaintext is not a tagged announcement),
/// 2. `member_did == sender_did` (forged-announcement guard →
///    [`REJECT_SENDER_MISMATCH`], carrying the claimed DID),
/// 3. reserved-value rejection ([`is_reserved_pseudonym`] →
///    [`REJECT_RESERVED`]),
/// 4. broadcast-context reject (`registry == None` → [`REJECT_BROADCAST`]) then
///    cross-DID collision ([`pseudonym_collides_with_other_did`] →
///    [`REJECT_COLLISION`]); otherwise [`PseudonymAnnouncementDecision::Accept`].
///
/// `registry` is the caller's immutable peer registry, or `None` for a
/// broadcast context (which carries no registry). `local_pseudonym` is the
/// RECEIVER's OWN per-context pseudonym (or `None` if it has not derived one) —
/// see the own-pseudonym collision guard below. The function performs NO side
/// effects: it neither mutates the registry nor logs — the host owns those.
///
/// # Own-pseudonym collision guard (S1)
///
/// The cross-DID collision check (step 4) also rejects an announcement whose
/// pseudonym equals the receiver's OWN `local_pseudonym`. Without it a member M
/// could announce `M → victim's_pseudonym`: the sender-mismatch guard passes (M
/// announces for its own DID), the value is not reserved, and the victim's own
/// pseudonym is NOT in its PEER registry (which excludes self) — so the victim
/// would accept it and misroute every honest sender addressing M to the victim's
/// own address. Rejecting any claim of the local pseudonym closes this for BOTH
/// hosts in one place (native + browser), and is sound because a member never
/// legitimately receives a peer announcement carrying its own pseudonym — its own
/// announcements are self-echoes dropped at the MLS layer
/// (`CannotDecryptOwnMessage`) before reaching this classifier, and a distinct
/// member deriving the identical 32-byte Ed25519 pseudonym is negligible (and,
/// were it to happen, a genuine collision to reject).
// `registry` is ALWAYS the default-hasher peer registry the routing state owns;
// a `BuildHasher` type parameter would leak an unused generic into this shared
// cross-target decision API without real generality. Keep the concrete signature.
#[allow(clippy::implicit_hasher)]
#[must_use]
pub fn classify_pseudonym_announcement(
    plaintext: &[u8],
    sender_did: &str,
    context_id: &str,
    registry: Option<&HashMap<DID, [u8; 32]>>,
    local_pseudonym: Option<[u8; 32]>,
) -> PseudonymAnnouncementDecision {
    // Step 1: tag-decode. A non-announcement (or untagged payload) is ordinary
    // application data.
    let Ok(announcement) = rmp_serde::from_slice::<PseudonymAnnouncement>(plaintext) else {
        return PseudonymAnnouncementDecision::NotAnnouncement;
    };
    if announcement.tag != PSEUDONYM_ANNOUNCEMENT_TAG {
        return PseudonymAnnouncementDecision::NotAnnouncement;
    }

    // Step 2: the announced DID must match the authenticated sender. A member
    // can only announce a routing ID for their OWN DID. Carry the claimed DID
    // so the host can reproduce the forged-announcement diagnostic.
    if announcement.member_did != sender_did {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_SENDER_MISMATCH,
            claimed_did: Some(DID(announcement.member_did)),
        };
    }

    let announced_did = DID(announcement.member_did);

    // Step 3: reject reserved pseudonym VALUES before touching the registry.
    // Announcing the zero sentinel, the shared bootstrap RID, or the broadcast
    // RID for one's own DID would redirect every honest sender's app-data
    // fan-out, defeating unlinkability or leaking ciphertext onto the shared
    // channel.
    if is_reserved_pseudonym(&announcement.pseudonym, context_id) {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_RESERVED,
            claimed_did: None,
        };
    }

    // Step 4: registry updates are meaningful only for encrypted contexts. A
    // broadcast context carries no peer registry — reject as a spec-level
    // violation. Otherwise reject a routing ID already claimed by a DIFFERENT
    // member (same-DID re-announce for key rotation stays allowed), then accept.
    let Some(registry) = registry else {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_BROADCAST,
            claimed_did: None,
        };
    };
    // Cross-DID collision against the PEER registry, OR a claim of the receiver's
    // OWN pseudonym (the S1 own-pseudonym guard — see the doc comment).
    if pseudonym_collides_with_other_did(registry, &announced_did, &announcement.pseudonym)
        || local_pseudonym == Some(announcement.pseudonym)
    {
        return PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_COLLISION,
            claimed_did: None,
        };
    }

    PseudonymAnnouncementDecision::Accept {
        member_did: announced_did,
        pseudonym: announcement.pseudonym,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement, PseudonymAnnouncementDecision,
        REJECT_BROADCAST, REJECT_COLLISION, REJECT_RESERVED, REJECT_SENDER_MISMATCH,
        classify_pseudonym_announcement, is_pseudonym_announcement_payload, is_reserved_pseudonym,
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
        let mut registry: HashMap<DID, [u8; 32]> = HashMap::new();
        let alice = DID("did:key:alice".to_owned());
        let bob = DID("did:key:bob".to_owned());
        let rid = [9u8; 32];
        registry.insert(alice.clone(), rid);

        // Bob claiming Alice's routing ID is a cross-DID collision.
        assert!(
            pseudonym_collides_with_other_did(&registry, &bob, &rid),
            "a different DID claiming an existing routing ID is a collision"
        );
        // Alice re-announcing her OWN routing ID (key rotation rebroadcast) is fine.
        assert!(
            !pseudonym_collides_with_other_did(&registry, &alice, &rid),
            "same-DID re-announce is not a collision"
        );
    }

    #[test]
    fn announcement_classifier_matches_only_tagged_payloads() {
        let tagged = announcement_bytes("did:key:alice", [3u8; 32]);
        assert!(
            is_pseudonym_announcement_payload(&tagged),
            "a well-formed tagged announcement is classified as such"
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
            classify_pseudonym_announcement(
                b"hello world",
                ALICE,
                CTX,
                Some(&HashMap::new()),
                None
            ),
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
            classify_pseudonym_announcement(&mistagged, ALICE, CTX, Some(&HashMap::new()), None),
            PseudonymAnnouncementDecision::NotAnnouncement,
            "a non-magic tag classifies as NotAnnouncement"
        );
    }

    #[test]
    fn classify_sender_mismatch_is_rejected_with_claimed_did() {
        let forged = announcement_bytes(BOB, [0x42u8; 32]);
        assert_eq!(
            classify_pseudonym_announcement(&forged, ALICE, CTX, Some(&HashMap::new()), None),
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
                classify_pseudonym_announcement(&bytes, ALICE, CTX, Some(&HashMap::new()), None),
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
            classify_pseudonym_announcement(&bytes, ALICE, CTX, None, None),
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
        let mut registry: HashMap<DID, [u8; 32]> = HashMap::new();
        registry.insert(DID(ALICE.to_owned()), rid);
        // BOB tries to claim ALICE's already-registered routing ID.
        let bytes = announcement_bytes(BOB, rid);
        assert_eq!(
            classify_pseudonym_announcement(&bytes, BOB, CTX, Some(&registry), None),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_COLLISION,
                claimed_did: None,
            },
            "a cross-DID routing-ID collision is rejected"
        );
    }

    #[test]
    fn classify_rejects_announcement_of_the_receivers_own_pseudonym() {
        // S1: BOB announces `BOB → victim_pseudonym`, where `victim_pseudonym` is
        // the RECEIVER's own pseudonym. The sender-mismatch guard passes (BOB
        // announces for BOB), the value is not reserved, and it is NOT in the peer
        // registry (which excludes self) — but the shared classifier, given the
        // receiver's own pseudonym, rejects it as a collision. Without this the
        // victim would misroute every honest sender addressing BOB to its own
        // address. Covers BOTH hosts (native + browser) in one place.
        let victim_pseudonym = [0x77u8; 32];
        let bytes = announcement_bytes(BOB, victim_pseudonym);
        assert_eq!(
            classify_pseudonym_announcement(
                &bytes,
                BOB,
                CTX,
                Some(&HashMap::new()),
                Some(victim_pseudonym),
            ),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_COLLISION,
                claimed_did: None,
            },
            "an announcement claiming the receiver's own pseudonym is rejected (S1)"
        );
        // A DIFFERENT pseudonym from BOB is still accepted with the local pseudonym set.
        let other = announcement_bytes(BOB, [0x33u8; 32]);
        assert_eq!(
            classify_pseudonym_announcement(
                &other,
                BOB,
                CTX,
                Some(&HashMap::new()),
                Some(victim_pseudonym),
            ),
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(BOB.to_owned()),
                pseudonym: [0x33u8; 32],
            },
            "a non-colliding announcement is unaffected by the own-pseudonym guard"
        );
    }

    #[test]
    fn classify_legitimate_announcement_is_accepted() {
        let pseudonym = [0x42u8; 32];
        let bytes = announcement_bytes(ALICE, pseudonym);
        assert_eq!(
            classify_pseudonym_announcement(&bytes, ALICE, CTX, Some(&HashMap::new()), None),
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(ALICE.to_owned()),
                pseudonym,
            },
            "a legitimate announcement is accepted with the announcer DID + pseudonym"
        );
    }

    #[test]
    fn classify_same_did_reannounce_is_accepted() {
        let first = [0x42u8; 32];
        let rotated = [0x43u8; 32];
        let mut registry: HashMap<DID, [u8; 32]> = HashMap::new();
        registry.insert(DID(ALICE.to_owned()), first);
        // ALICE re-announces a rotated routing ID — legitimate key rotation, not
        // a collision (the collision guard only fires for a DIFFERENT DID).
        let bytes = announcement_bytes(ALICE, rotated);
        assert_eq!(
            classify_pseudonym_announcement(&bytes, ALICE, CTX, Some(&registry), None),
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(ALICE.to_owned()),
                pseudonym: rotated,
            },
            "a same-DID re-announce is accepted (key rotation)"
        );
    }
}
