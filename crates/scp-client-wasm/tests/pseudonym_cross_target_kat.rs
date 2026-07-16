//! Cross-target byte-parity known-answer tests for the §9.10.4 per-context
//! pseudonym announcement (ADR-057 T-1, Prerequisite 5).
//!
//! The §9.10.4 pseudonym logic — the [`PseudonymAnnouncement`] wire type and the
//! pure [`classify_pseudonym_announcement`] decision core — was extracted into
//! the wasm-safe `scp-protocol::context::pseudonym` module so it is READY to be
//! consumed verbatim by a future in-browser client driver without forking the
//! native orchestrator's (`scp-runtime`) copy. This file is the guard that the
//! shared code produces **byte-identical** output on both native and `wasm32`,
//! so that a future browser call site inherits one non-forked implementation:
//!
//! 1. **Wire encoding.** `rmp_serde::to_vec_named` of a FIXED
//!    [`PseudonymAnnouncement`] must equal a committed golden hex and round-trip,
//!    identically on both targets. The struct is a `serde` name-keyed map with a
//!    `serde_bytes` 32-byte field — no `usize`, no float, no map iteration to
//!    order — so a fixed value re-encodes deterministically; a width/field-order
//!    divergence (wasm32 is 32-bit) would move it off the golden.
//! 2. **Classifier decisions.** [`classify_pseudonym_announcement`] over a fixed
//!    input matrix must yield an identical [`PseudonymAnnouncementDecision`] —
//!    including the exact stable reject-reason `&'static str`s — on both targets.
//! 3. **Reserved-value classification.** The zero-RID sentinel and BOTH derivable
//!    reserved routing IDs (`context_routing_id`, `broadcast_routing_id`) must
//!    classify as reserved on both targets.
//!
//! Every assertion lives in a helper called from BOTH a native `#[test]` and a
//! `#[wasm_bindgen_test]`. Because both targets assert against the SAME committed
//! constants, agreement is transitive: `native == golden` AND `wasm == golden`
//! implies `native == wasm`. The golden wire bytes are also spec-anchored in
//! `.docs/specs/25-test-vectors.md` §25.19.

// KATs assert on fixed vectors; `expect`/`unwrap`/`panic` keep failures legible.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use scp_did::DID;
use scp_protocol::context::pseudonym::{
    PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement, PseudonymAnnouncementDecision,
    REJECT_BROADCAST, REJECT_COLLISION, REJECT_RESERVED, REJECT_SENDER_MISMATCH,
    classify_pseudonym_announcement, is_reserved_pseudonym,
};
use scp_protocol::context::{broadcast_routing_id, context_routing_id};
use std::collections::HashMap;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

// ---------------------------------------------------------------------------
// Fixed inputs (identical on every target and every run)
// ---------------------------------------------------------------------------

/// The announcer DID pinned into the golden wire blob and the classifier matrix.
const KAT_MEMBER_DID: &str = "did:dht:z6MkPseudonymKatFixtureMemberAAAAAAAAAAAAAA";
/// A second DID for the sender-mismatch / cross-DID-collision matrix rows.
const KAT_OTHER_DID: &str = "did:dht:z6MkPseudonymKatFixtureOtherBBBBBBBBBBBBBBB";
/// The context id the classifier derives reserved routing IDs against.
const KAT_CONTEXT_ID: &str = "ctx-adr057-pseudonym-kat";
/// A fixed, honest (non-reserved) 32-byte routing ID.
const KAT_PSEUDONYM: [u8; 32] = [0x42u8; 32];

// ---------------------------------------------------------------------------
// Golden constants (generated natively, asserted on BOTH targets)
// ---------------------------------------------------------------------------

/// GOLDEN: `rmp_serde::to_vec_named(&PseudonymAnnouncement { tag =
/// PSEUDONYM_ANNOUNCEMENT_TAG, member_did = KAT_MEMBER_DID, pseudonym =
/// KAT_PSEUDONYM })`, hex-encoded. A name-keyed `MessagePack` map with a
/// `serde_bytes` binary field — deterministic and target-independent. If this
/// moves, the wire format changed (a spec-observable event, §25.19), not a
/// refactor.
const GOLDEN_PSEUDONYM_ANNOUNCEMENT_HEX: &str = "83a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7631aa6d656d6265725f646964d9336469643a6468743a7a364d6b50736575646f6e796d4b6174466978747572654d656d6265724141414141414141414141414141a970736575646f6e796dc4204242424242424242424242424242424242424242424242424242424242424242";

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

fn announcement_bytes(member_did: &str, pseudonym: [u8; 32]) -> Vec<u8> {
    let ann = PseudonymAnnouncement {
        tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
        member_did: member_did.to_owned(),
        pseudonym,
    };
    rmp_serde::to_vec_named(&ann).expect("serialize announcement")
}

// ---------------------------------------------------------------------------
// The golden-vector assertion body (called from BOTH targets)
// ---------------------------------------------------------------------------

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
    let empty: HashMap<DID, [u8; 32]> = HashMap::new();

    // NotAnnouncement: ordinary app data.
    assert_eq!(
        classify_pseudonym_announcement(
            b"hello world",
            KAT_MEMBER_DID,
            KAT_CONTEXT_ID,
            Some(&empty)
        ),
        PseudonymAnnouncementDecision::NotAnnouncement,
    );

    // Accept: legitimate announcement (sender == member, honest RID, no collision).
    assert_eq!(
        classify_pseudonym_announcement(&bytes, KAT_MEMBER_DID, KAT_CONTEXT_ID, Some(&empty)),
        PseudonymAnnouncementDecision::Accept {
            member_did: DID(KAT_MEMBER_DID.to_owned()),
            pseudonym: KAT_PSEUDONYM,
        },
    );

    // Rejected (sender mismatch): the payload claims KAT_OTHER_DID but the
    // authenticated sender is KAT_MEMBER_DID; carries the claimed DID.
    let forged = announcement_bytes(KAT_OTHER_DID, KAT_PSEUDONYM);
    assert_eq!(
        classify_pseudonym_announcement(&forged, KAT_MEMBER_DID, KAT_CONTEXT_ID, Some(&empty)),
        PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_SENDER_MISMATCH,
            claimed_did: Some(DID(KAT_OTHER_DID.to_owned())),
        },
    );

    // Rejected (broadcast context): no registry.
    assert_eq!(
        classify_pseudonym_announcement(&bytes, KAT_MEMBER_DID, KAT_CONTEXT_ID, None),
        PseudonymAnnouncementDecision::Rejected {
            reason: REJECT_BROADCAST,
            claimed_did: None,
        },
    );

    // Rejected (cross-DID collision): KAT_OTHER_DID already owns KAT_PSEUDONYM.
    let mut registry: HashMap<DID, [u8; 32]> = HashMap::new();
    registry.insert(DID(KAT_OTHER_DID.to_owned()), KAT_PSEUDONYM);
    assert_eq!(
        classify_pseudonym_announcement(&bytes, KAT_MEMBER_DID, KAT_CONTEXT_ID, Some(&registry)),
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
                Some(&empty)
            ),
            PseudonymAnnouncementDecision::Rejected {
                reason: REJECT_RESERVED,
                claimed_did: None,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Native + wasm entry point
// ---------------------------------------------------------------------------

/// Pseudonym cross-target byte-parity KAT. Runs natively (proving determinism
/// vs. the committed vectors) and under `wasm-pack test --node` (proving
/// byte-equality across targets — ADR-057 T-1 / Prerequisite 5).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pseudonym_wire_and_classifier_match_golden_vectors() {
    assert_pseudonym_cross_target_vectors();
}
