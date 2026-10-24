//! Cross-target byte-parity known-answer tests for the §9.10.4 per-context
//! pseudonym announcement (ADR-057 T-1, Prerequisite 5) and its §9.10.4.1 v2
//! rotation announcement (§25.19 Vector 58).
//!
//! The §9.10.4 pseudonym logic — the [`PseudonymAnnouncement`] and
//! [`PseudonymAnnouncementV2`] wire types and the pure
//! [`classify_pseudonym_announcement`] decision core — lives in the wasm-safe
//! `scp-protocol::context::pseudonym` module, which the native orchestrator
//! (`scp-runtime`) and the browser client (`scp-client`) both call. This file is
//! the guard that the shared code produces **byte-identical** output on both
//! native and `wasm32`:
//!
//! 1. **Wire encoding.** `rmp_serde::to_vec_named` of a FIXED v1 and v2
//!    announcement must equal the committed golden hex and round-trip,
//!    identically on both targets. Each struct is a `serde` name-keyed map with a
//!    `serde_bytes` 32-byte field — no `usize`, no float, no map iteration to
//!    order — so a fixed value re-encodes deterministically; a width/field-order
//!    divergence (wasm32 is 32-bit) would move it off the golden. The 2^32 epoch
//!    row pins the `uint64` encoding a 32-bit target would truncate.
//! 2. **Classifier decisions.** [`classify_pseudonym_announcement`] over a fixed
//!    input matrix, and over every row of Vector 58's decision table, must yield
//!    an identical [`PseudonymAnnouncementDecision`] — including the exact stable
//!    reject-reason strings — on both targets.
//! 3. **Reserved-value classification.** The zero-RID sentinel and BOTH derivable
//!    reserved routing IDs (`context_routing_id`, `broadcast_routing_id`) must
//!    classify as reserved on both targets.
//!
//! Every assertion lives in a helper called from BOTH a native `#[test]` and a
//! `#[wasm_bindgen_test]`. Because both targets assert against the SAME committed
//! constants, agreement is transitive: `native == golden` AND `wasm == golden`
//! implies `native == wasm`. The golden wire bytes are also spec-anchored in
//! `.docs/specs/25-test-vectors.md` §25.19 (Vectors 36 and 58).

// KATs assert on fixed vectors; `expect`/`unwrap`/`panic` keep failures legible.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use scp_did::DID;
use scp_protocol::context::pseudonym::{
    PSEUDONYM_ANNOUNCEMENT_TAG, PSEUDONYM_ANNOUNCEMENT_V2_TAG, PseudonymAnnouncement,
    PseudonymAnnouncementDecision, PseudonymAnnouncementV2, PseudonymRecord, REJECT_BROADCAST,
    REJECT_COLLISION, REJECT_RESERVED, REJECT_SENDER_MISMATCH, classify_pseudonym_announcement,
    is_reserved_pseudonym,
};
use scp_protocol::context::{broadcast_routing_id, context_routing_id};
use std::collections::HashMap;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

// ---------------------------------------------------------------------------
// Fixed inputs (identical on every target and every run)
// ---------------------------------------------------------------------------

/// The announcer identifier pinned into the golden wire blob and the
/// classifier matrix: §25.19 Vector 36's `SHA-256("SCP test vector identifier
/// announcing member")` in the `scp:` text form.
const KAT_MEMBER_DID: &str = "scp:z5glr2inbuzd33xrfkdgpjejz4x7z4r2jxcsfvdxbwtgoi73xx2q";
/// A second identifier for the sender-mismatch / cross-DID-collision matrix
/// rows: §25.19 Vector 36's "other member" fixture identifier.
const KAT_OTHER_DID: &str = "scp:ur5v4nca7x4lfagd2fojmjydguxwjwvfz2tur63s3x3k5vvqmppa";
/// The context id the classifier derives reserved routing IDs against.
const KAT_CONTEXT_ID: &str = "ctx-adr057-pseudonym-kat";
/// A fixed, honest (non-reserved) 32-byte routing ID.
const KAT_PSEUDONYM: [u8; 32] = [0x42u8; 32];
/// Vector 58's announced v2 routing ID.
const V58_ROUTING_ID: [u8; 32] = [0x43u8; 32];

// ---------------------------------------------------------------------------
// Golden constants (generated natively, asserted on BOTH targets)
// ---------------------------------------------------------------------------

/// GOLDEN: `rmp_serde::to_vec_named(&PseudonymAnnouncement { tag =
/// PSEUDONYM_ANNOUNCEMENT_TAG, member_did = KAT_MEMBER_DID, pseudonym =
/// KAT_PSEUDONYM })`, hex-encoded. A name-keyed `MessagePack` map with a
/// `serde_bytes` binary field — deterministic and target-independent. If this
/// moves, the wire format changed (a spec-observable event, §25.19), not a
/// refactor.
const GOLDEN_PSEUDONYM_ANNOUNCEMENT_HEX: &str = "83a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7631aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271a970736575646f6e796dc4204242424242424242424242424242424242424242424242424242424242424242";

/// GOLDEN (§25.19 Vector 58): the v2 announcement of `KAT_MEMBER_DID` at
/// `pseudonym_epoch = 1` with `routing_id = V58_ROUTING_ID`.
const GOLDEN_V58_EPOCH_1_HEX: &str = "84a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7632aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271af70736575646f6e796d5f65706f636801aa726f7574696e675f6964c4204343434343434343434343434343434343434343434343434343434343434343";

/// GOLDEN (§25.19 Vector 58): the same announcement at `pseudonym_epoch =
/// 2^32`, which pins the `uint64` epoch encoding.
const GOLDEN_V58_EPOCH_2_POW_32_HEX: &str = "84a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7632aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271af70736575646f6e796d5f65706f6368cf0000000100000000aa726f7574696e675f6964c4204343434343434343434343434343434343434343434343434343434343434343";

/// Vector 58's reject reasons, written out so a renamed constant cannot move
/// them silently.
const V58_REJECT_EPOCH: &str = "pseudonym announcement epoch does not advance the recorded epoch";
const V58_REJECT_V1_AFTER_V2: &str = "pseudonym v1 announcement follows a recorded v2 announcement";
const V58_REJECT_SENDER_MISMATCH: &str = "pseudonym announcement member_did does not match sender";
const V58_REJECT_RESERVED: &str = "pseudonym announcement uses a reserved routing ID";
const V58_REJECT_BROADCAST: &str = "pseudonym announcement received on broadcast context";
const V58_REJECT_COLLISION: &str =
    "pseudonym announcement collides with another member's routing ID";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Lowercase hex without external deps (the KAT must build for wasm32).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decodes lowercase hex without external deps.
fn from_hex(hex: &str) -> Vec<u8> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("non-hex character in golden constant"),
    };
    hex.as_bytes()
        .chunks(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn announcement_bytes(member_did: &str, pseudonym: [u8; 32]) -> Vec<u8> {
    let ann = PseudonymAnnouncement {
        tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
        member_did: member_did.to_owned(),
        pseudonym,
    };
    rmp_serde::to_vec_named(&ann).expect("serialize announcement")
}

fn v2_bytes(member_did: &str, pseudonym_epoch: u64, routing_id: [u8; 32]) -> Vec<u8> {
    rmp_serde::to_vec_named(&PseudonymAnnouncementV2 {
        tag: PSEUDONYM_ANNOUNCEMENT_V2_TAG.to_owned(),
        member_did: member_did.to_owned(),
        pseudonym_epoch,
        routing_id,
    })
    .expect("serialize v2 announcement")
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

// ---------------------------------------------------------------------------
// The golden-vector assertion bodies (called from BOTH targets)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // one cross-target decision matrix, read top-to-bottom
fn assert_pseudonym_cross_target_vectors() {
    // (1) Wire encoding of the fixed announcement matches the golden + round-trips.
    let bytes = announcement_bytes(KAT_MEMBER_DID, KAT_PSEUDONYM);
    assert_eq!(
        to_hex(&bytes),
        GOLDEN_PSEUDONYM_ANNOUNCEMENT_HEX,
        "PseudonymAnnouncement wire encoding diverged from the golden vector \
         (cross-target width/field-order change or a wire-format change)"
    );
    let decoded: PseudonymAnnouncement =
        rmp_serde::from_slice(&bytes).expect("golden announcement round-trips");
    assert_eq!(decoded.tag, PSEUDONYM_ANNOUNCEMENT_TAG);
    assert_eq!(decoded.member_did, KAT_MEMBER_DID);
    assert_eq!(decoded.pseudonym, KAT_PSEUDONYM);

    // (2) Classifier decision matrix — identical decisions + exact reason strings.
    let empty: HashMap<DID, PseudonymRecord> = HashMap::new();

    // The fifth arg is the receiver's OWN routing IDs for the S1 self-collision
    // guard; empty for every row that does not exercise it. The dedicated S1
    // row below passes it.

    // NotAnnouncement: ordinary app data.
    assert_eq!(
        classify_pseudonym_announcement(
            b"hello world",
            KAT_MEMBER_DID,
            KAT_CONTEXT_ID,
            Some(&empty),
            &[],
        ),
        PseudonymAnnouncementDecision::NotAnnouncement,
    );

    // Accept: legitimate announcement (sender == member, honest RID, no collision).
    assert_eq!(
        classify_pseudonym_announcement(&bytes, KAT_MEMBER_DID, KAT_CONTEXT_ID, Some(&empty), &[]),
        PseudonymAnnouncementDecision::Accept {
            member_did: DID(KAT_MEMBER_DID.to_owned()),
            record: v1_record(KAT_PSEUDONYM),
        },
    );

    // Rejected (sender mismatch): the payload claims KAT_OTHER_DID but the
    // authenticated sender is KAT_MEMBER_DID; carries the claimed DID.
    let forged = announcement_bytes(KAT_OTHER_DID, KAT_PSEUDONYM);
    assert_eq!(
        classify_pseudonym_announcement(&forged, KAT_MEMBER_DID, KAT_CONTEXT_ID, Some(&empty), &[]),
        PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_SENDER_MISMATCH,
            claimed_did: Some(DID(KAT_OTHER_DID.to_owned())),
        },
    );

    // Rejected (broadcast context): no registry.
    assert_eq!(
        classify_pseudonym_announcement(&bytes, KAT_MEMBER_DID, KAT_CONTEXT_ID, None, &[]),
        PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_BROADCAST,
            claimed_did: None,
        },
    );

    // Rejected (cross-DID collision): KAT_OTHER_DID already owns KAT_PSEUDONYM.
    let registry = registry_of(&[(KAT_OTHER_DID, v1_record(KAT_PSEUDONYM))]);
    assert_eq!(
        classify_pseudonym_announcement(
            &bytes,
            KAT_MEMBER_DID,
            KAT_CONTEXT_ID,
            Some(&registry),
            &[],
        ),
        PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_COLLISION,
            claimed_did: None,
        },
    );

    // Rejected (S1 self-collision): the announcement is otherwise honest (sender ==
    // member, non-reserved RID, empty peer registry) but announces the RECEIVER's
    // OWN pseudonym — a forged `member → our address` claim the local-pseudonym
    // guard rejects as a collision. Asserted cross-target so the S1 branch is
    // byte-identical on native and wasm32.
    assert_eq!(
        classify_pseudonym_announcement(
            &bytes,
            KAT_MEMBER_DID,
            KAT_CONTEXT_ID,
            Some(&empty),
            &[KAT_PSEUDONYM],
        ),
        PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_COLLISION,
            claimed_did: None,
        },
    );

    // (3) Reserved-value classification: the zero sentinel + both derivable
    // reserved routing IDs classify as reserved; via the classifier they reject
    // with REJECT_RESERVED. An honest RID is not reserved.
    assert!(is_reserved_pseudonym(&[0u8; 32], KAT_CONTEXT_ID));
    assert!(is_reserved_pseudonym(
        &context_routing_id(KAT_CONTEXT_ID),
        KAT_CONTEXT_ID
    ));
    assert!(is_reserved_pseudonym(
        &broadcast_routing_id(KAT_CONTEXT_ID),
        KAT_CONTEXT_ID
    ));
    assert!(!is_reserved_pseudonym(&KAT_PSEUDONYM, KAT_CONTEXT_ID));

    for reserved in [
        [0u8; 32],
        context_routing_id(KAT_CONTEXT_ID),
        broadcast_routing_id(KAT_CONTEXT_ID),
    ] {
        let reserved_bytes = announcement_bytes(KAT_MEMBER_DID, reserved);
        assert_eq!(
            classify_pseudonym_announcement(
                &reserved_bytes,
                KAT_MEMBER_DID,
                KAT_CONTEXT_ID,
                Some(&empty),
                &[],
            ),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_RESERVED,
                claimed_did: None,
            },
        );
    }
}

/// One Vector 58 decision-table row: the case name, the plaintext, the
/// receiver's registry (`None` for a broadcast context), the receiver's own
/// routing IDs, and the expected decision.
type V58Row = (
    &'static str,
    Vec<u8>,
    Option<HashMap<DID, PseudonymRecord>>,
    Vec<[u8; 32]>,
    PseudonymAnnouncementDecision,
);

#[allow(clippy::too_many_lines)] // one table, read top-to-bottom like §25.19
fn assert_vector_58() {
    // Wire bytes: both golden strings, and the epoch-1 bytes round-trip.
    let golden = v2_bytes(KAT_MEMBER_DID, 1, V58_ROUTING_ID);
    assert_eq!(to_hex(&golden), GOLDEN_V58_EPOCH_1_HEX);
    assert_eq!(
        to_hex(&v2_bytes(KAT_MEMBER_DID, 1 << 32, V58_ROUTING_ID)),
        GOLDEN_V58_EPOCH_2_POW_32_HEX
    );
    assert_eq!(golden, from_hex(GOLDEN_V58_EPOCH_1_HEX));
    let decoded: PseudonymAnnouncementV2 =
        rmp_serde::from_slice(&golden).expect("golden v2 announcement round-trips");
    assert_eq!(decoded.tag, PSEUDONYM_ANNOUNCEMENT_V2_TAG);
    assert_eq!(decoded.member_did, KAT_MEMBER_DID);
    assert_eq!(decoded.pseudonym_epoch, 1);
    assert_eq!(decoded.routing_id, V58_ROUTING_ID);

    let golden_v1 = from_hex(GOLDEN_PSEUDONYM_ANNOUNCEMENT_HEX);
    let accept_v2 = PseudonymAnnouncementDecision::Accept {
        member_did: DID(KAT_MEMBER_DID.to_owned()),
        record: v2_record(1, V58_ROUTING_ID),
    };
    let rejected = |reason| PseudonymAnnouncementDecision::Rejected {
        reason,
        claimed_did: None,
    };
    let empty: HashMap<DID, PseudonymRecord> = HashMap::new();
    let member = |record| Some(registry_of(&[(KAT_MEMBER_DID, record)]));

    // The fifth-key and short-routing-ID rows mutate the golden bytes: the
    // fixmap header becomes 0x85 with `"x": 0` appended, and the trailing bin8
    // length becomes 0x1f with one value byte dropped.
    let mut extra_key = golden.clone();
    extra_key[0] = 0x85;
    extra_key.extend_from_slice(&[0xa1, b'x', 0x00]);
    let mut short_routing_id = golden[..golden.len() - 1].to_vec();
    let len_at = short_routing_id.len() - 31 - 1;
    assert_eq!(
        short_routing_id[len_at], 0x20,
        "bin8 length byte of routing_id"
    );
    short_routing_id[len_at] = 0x1f;

    let rows: Vec<V58Row> = vec![
        (
            "first v2, no record",
            golden.clone(),
            Some(empty.clone()),
            vec![],
            accept_v2.clone(),
        ),
        (
            "v2 over a v1 record",
            golden.clone(),
            member(v1_record(KAT_PSEUDONYM)),
            vec![],
            accept_v2.clone(),
        ),
        (
            "higher epoch",
            golden.clone(),
            member(v2_record(0, [0x44u8; 32])),
            vec![],
            accept_v2,
        ),
        (
            "same epoch, same value",
            golden.clone(),
            member(v2_record(1, V58_ROUTING_ID)),
            vec![],
            PseudonymAnnouncementDecision::Unchanged,
        ),
        (
            "same epoch, other value",
            golden.clone(),
            member(v2_record(1, [0x44u8; 32])),
            vec![],
            rejected(V58_REJECT_EPOCH),
        ),
        (
            "lower epoch",
            golden.clone(),
            member(v2_record(2, [0x44u8; 32])),
            vec![],
            rejected(V58_REJECT_EPOCH),
        ),
        (
            "v1 after v2",
            golden_v1.clone(),
            member(v2_record(1, V58_ROUTING_ID)),
            vec![],
            rejected(V58_REJECT_V1_AFTER_V2),
        ),
        (
            "v1 over v1",
            golden_v1,
            member(v1_record([0x44u8; 32])),
            vec![],
            PseudonymAnnouncementDecision::Accept {
                member_did: DID(KAT_MEMBER_DID.to_owned()),
                record: v1_record(KAT_PSEUDONYM),
            },
        ),
        (
            "sender mismatch",
            v2_bytes(KAT_OTHER_DID, 1, V58_ROUTING_ID),
            Some(empty.clone()),
            vec![],
            PseudonymAnnouncementDecision::Rejected {
                reason: V58_REJECT_SENDER_MISMATCH,
                claimed_did: Some(DID(KAT_OTHER_DID.to_owned())),
            },
        ),
        (
            "reserved value: zero",
            v2_bytes(KAT_MEMBER_DID, 1, [0u8; 32]),
            Some(empty.clone()),
            vec![],
            rejected(V58_REJECT_RESERVED),
        ),
        (
            "reserved value: context routing ID",
            v2_bytes(KAT_MEMBER_DID, 1, context_routing_id(KAT_CONTEXT_ID)),
            Some(empty.clone()),
            vec![],
            rejected(V58_REJECT_RESERVED),
        ),
        (
            "reserved value: broadcast routing ID",
            v2_bytes(KAT_MEMBER_DID, 1, broadcast_routing_id(KAT_CONTEXT_ID)),
            Some(empty.clone()),
            vec![],
            rejected(V58_REJECT_RESERVED),
        ),
        (
            "broadcast context",
            golden.clone(),
            None,
            vec![],
            rejected(V58_REJECT_BROADCAST),
        ),
        (
            "cross-DID collision",
            golden.clone(),
            Some(registry_of(&[(KAT_OTHER_DID, v1_record(V58_ROUTING_ID))])),
            vec![],
            rejected(V58_REJECT_COLLISION),
        ),
        (
            "receiver's current routing ID",
            golden.clone(),
            Some(empty.clone()),
            vec![V58_ROUTING_ID],
            rejected(V58_REJECT_COLLISION),
        ),
        (
            "receiver's query-only routing ID",
            golden,
            Some(empty.clone()),
            vec![[0x45u8; 32], V58_ROUTING_ID],
            rejected(V58_REJECT_COLLISION),
        ),
        (
            "extra key",
            extra_key,
            Some(empty.clone()),
            vec![],
            PseudonymAnnouncementDecision::NotAnnouncement,
        ),
        (
            "short routing_id",
            short_routing_id,
            Some(empty),
            vec![],
            PseudonymAnnouncementDecision::NotAnnouncement,
        ),
    ];
    assert_eq!(rows.len(), 18, "Vector 58 has 18 decision-table rows");

    for (case, payload, registry, own, expected) in rows {
        let before = registry.clone();
        let decision = classify_pseudonym_announcement(
            &payload,
            KAT_MEMBER_DID,
            KAT_CONTEXT_ID,
            registry.as_ref(),
            &own,
        );
        assert_eq!(decision, expected, "Vector 58 row: {case}");
        assert_eq!(
            registry, before,
            "Vector 58 row leaves the registry as is: {case}"
        );
    }
}

// ---------------------------------------------------------------------------
// Native + wasm entry points
// ---------------------------------------------------------------------------

/// Pseudonym cross-target byte-parity KAT. Runs natively (proving determinism
/// vs. the committed vectors) and under `wasm-pack test --node` (proving
/// byte-equality across targets — ADR-057 T-1 / Prerequisite 5).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pseudonym_wire_and_classifier_match_golden_vectors() {
    assert_pseudonym_cross_target_vectors();
}

/// §25.19 Vector 58 (the v2 rotation announcement): both golden wire strings
/// and every decision-table row, natively and on wasm32.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn vector_58_v2_wire_and_decision_table_match_on_every_target() {
    assert_vector_58();
}
