//! Relay-side DID-record frame validation (OPTIONAL SCP-native-relay capability).
//!
//! A DID document is published to a relay inside a public, self-certifying
//! [`DidRecordV1`](scp_protocol::envelope::did_record::DidRecordV1) frame
//! (§9.10.12) at a deterministic DID-domain `routing_id =
//! SHA-256("scp:did:" || did_string)` (§3.10.2). Unlike an encrypted context
//! blob, a validating SCP-native relay MAY inspect this frame on PUBLISH to
//! keep a single highest-sequence slot per `routing_id` and make that address
//! slot-exclusive — the relay layer's anti-suppression measure (§3.10.8).
//!
//! This module is the **pure** part of that behavior: given a `routing_id` and
//! a candidate blob, [`classify_did_record_frame`] decides, **cheapest-first**,
//! whether the blob is a valid DID-record frame for that `routing_id`. It holds
//! no state and touches no storage — the stateful single-slot / slot-exclusivity
//! bookkeeping lives in [`DidSlotRegistry`](crate::native::did_slot::DidSlotRegistry).
//!
//! The check order mirrors, on the data plane, the exact check
//! [`verify_bridge_registration`](crate::relay::bridge::verify_bridge_registration)
//! already performs on the control plane (§10.12.4): an Ed25519 signature plus
//! the same `SHA-256("scp:did:" || did_string) == routing_id` binding. The
//! binding is a plain hash — **cheaper than an Ed25519 verify** — so it runs
//! *before* the signature step: a mis-addressed or non-frame blob never costs a
//! signature verification (§3.10.2 steps 2/3).
//!
//! # Not a trust dependency
//!
//! Relay-side validation is **defense-in-depth for availability, never a trust
//! input**. The resolver ALWAYS re-verifies every record's BEP44 signature
//! against the key it derives from the DID string itself (§9.6.1, §9.10.12
//! "Framing is outside the signed authority") and never trusts the relay's
//! acceptance or the frame-supplied `public_key`. A relay that skips, botches,
//! or lies about this validation degrades availability only, never integrity
//! (RELAYRES-002 client re-verification is the guarantee).

use scp_dht::verify_bep44_signature;
use scp_identity::did_record_routing_id;
use scp_protocol::envelope::did_record::DidRecordV1;

/// The reason a blob that decoded as a [`DidRecordV1`] frame was nonetheless
/// rejected as an invalid DID record for the `routing_id` it was published at.
///
/// The variants are ordered by the check that produced them, which is exactly
/// the cheapest-first order [`classify_did_record_frame`] applies. A test can
/// therefore assert the binding is checked *before* the signature by observing
/// that a frame with **both** a wrong binding and a bad signature is rejected
/// as [`BindingMismatch`](Self::BindingMismatch) (never [`SignatureInvalid`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidRecordRejection {
    /// `SHA-256("scp:did:" || did(public_key)) != routing_id` — the frame's
    /// embedded `public_key` does not hash to the `routing_id` it was published
    /// at (§3.10.2 step 2). Checked **before** the signature, so a frame
    /// rejected here never costs an Ed25519 verify.
    BindingMismatch,
    /// The BEP44 signature over `bencode(seq, value)` did not verify against the
    /// frame's `public_key` (§3.10.2 step 3). Only reachable for a frame whose
    /// binding already held.
    SignatureInvalid,
}

/// The outcome of classifying a candidate blob at a `routing_id` on a validating
/// relay (§3.10.2 "Relay-side validation").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidRecordClass {
    /// The blob decoded as a `DidRecordV1` frame, the `DID→routing_id` binding
    /// held, and the BEP44 signature verified. Carries the BEP44 `seq` the
    /// single-slot rule uses for supersession (§3.10.2 step 4). A candidate to
    /// establish or supersede the `routing_id`'s slot.
    Valid {
        /// The frame's BEP44 sequence number (§3.10.7).
        seq: u64,
    },
    /// The blob decoded as a `DidRecordV1` frame but is **not** a valid DID
    /// record for this `routing_id` (binding mismatch or bad signature). A
    /// validating relay rejects it — it never enters a slot and never displaces
    /// one (§3.10.8 "Junk frame … rejected at validation").
    Invalid(DidRecordRejection),
    /// The blob does **not** decode as a `DidRecordV1` frame — an opaque blob,
    /// not a candidate DID record. It is governed only by the slot-exclusivity
    /// rule (rejected iff the `routing_id`'s slot is already claimed; otherwise
    /// stored opaquely), never by frame validation (§3.10.2).
    NotAFrame,
}

/// Classifies a candidate PUBLISH blob at `routing_id` for a validating relay,
/// **cheapest-first** (§3.10.2 "Relay-side validation"):
///
/// 1. structural decode as a [`DidRecordV1`] frame — a blob that does not decode
///    is [`NotAFrame`](DidRecordClass::NotAFrame);
/// 2. `DID→routing_id` binding `SHA-256("scp:did:" || did(public_key)) ==
///    routing_id` — a plain hash, **checked before the signature**;
/// 3. BEP44 signature over `bencode(seq, value)` against the frame's
///    `public_key` — only reached once the binding holds.
///
/// Ordering the binding (a hash) ahead of the signature (an Ed25519 verify) is
/// deliberate: a **mis-addressed** or non-frame blob never costs an Ed25519
/// verify, so binding-first saves the signature work for junk that isn't even
/// aimed at the victim's `routing_id`. It does **not** make flooding free — a
/// *targeted* attacker who embeds the victim's real `public_key` and publishes
/// at the victim's `routing_id` satisfies the binding and DOES incur one Ed25519
/// verify per blob. Both cases are bounded by the per-IP PUBLISH rate limit
/// (ADR-004), which is the actual cost ceiling; binding-first is a constant-
/// factor saving on mis-addressed junk, not a flooding defense on its own.
///
/// Separately, the *first* binding-valid establish at a `routing_id` that was
/// pre-seeded with a flood pays a one-time O(N) eviction scan over the co-located
/// blobs (and, on a cold index, an O(N) classify scan to reconcile against
/// storage). N is bounded — only pre-seed junk accumulates at a DID address, and
/// the whole path sits behind the same per-IP rate limit — so the scan is cheap
/// and one-time (see [`DidSlotRegistry`](crate::native::did_slot::DidSlotRegistry)).
///
/// This function is pure: it neither reads nor writes storage and holds no
/// state. The single-slot and slot-exclusivity decisions that consume a
/// [`DidRecordClass::Valid`] live in
/// [`DidSlotRegistry`](crate::native::did_slot::DidSlotRegistry).
#[must_use]
pub fn classify_did_record_frame(routing_id: &[u8; 32], blob: &[u8]) -> DidRecordClass {
    // Step 1 — structural decode. A blob that is not a frame (e.g. an encrypted
    // `OuterEnvelope`, whose first byte is a MessagePack map marker, never
    // 0x01, §9.10.12) is not a candidate DID record.
    let Ok(frame) = DidRecordV1::decode(blob) else {
        return DidRecordClass::NotAFrame;
    };

    // Step 2 — DID→routing_id binding (a plain hash; runs BEFORE the signature).
    // Mirrors the control-plane BRIDGE_REGISTER check (§10.12.4).
    //
    // Derived through the shared `did_record_routing_id` (see its definition in
    // `scp_identity::resolution` for the agreement invariant this admission
    // check shares with the WRITE path). Unlike `classify_stored_frame`, the
    // compare here is REAL: `routing_id` is the caller-supplied WIRE address, so
    // a frame published at an address its key does not bind to is rejected.
    let derived_routing_id = did_record_routing_id(&frame);
    if &derived_routing_id != routing_id {
        return DidRecordClass::Invalid(DidRecordRejection::BindingMismatch);
    }

    // Step 3 — BEP44 signature over bencode(seq, value) against the frame's
    // public_key. Only reached once the binding holds, so a mis-addressed frame
    // never costs this Ed25519 verify.
    if verify_bep44_signature(
        frame.public_key(),
        frame.signature(),
        frame.value(),
        frame.seq(),
    )
    .is_err()
    {
        return DidRecordClass::Invalid(DidRecordRejection::SignatureInvalid);
    }

    DidRecordClass::Valid { seq: frame.seq() }
}

/// Maps a slot-publish failure to the relay wire error `(code, message)`.
///
/// Shared by every validating transport (WebSocket, QUIC, UDP/DTLS) — via
/// [`SlotPublishError`](crate::native::did_slot::SlotPublishError) — so the
/// PUBLISH-rejection code mapping never diverges across them:
///
/// - a non-superseding `seq` (or a genuine higher/equal frame adopted from
///   storage instead) → [`DID_RECORD_REJECTED`](scp_relay_client::code::DID_RECORD_REJECTED);
/// - a full backend → [`STORAGE_FULL`](scp_relay_client::code::STORAGE_FULL);
/// - any other backend failure → [`INTERNAL_ERROR`](scp_relay_client::code::INTERNAL_ERROR)
///   (an internal storage fault is not "storage full").
#[must_use]
pub fn slot_publish_error_response(
    err: &crate::native::did_slot::SlotPublishError,
) -> (u16, String) {
    use crate::native::did_slot::SlotPublishError;
    use crate::native::storage::StorageError;
    use scp_relay_client::code;

    match err {
        SlotPublishError::NonSuperseding {
            stored_seq,
            got_seq,
        } => (
            code::DID_RECORD_REJECTED,
            format!(
                "DID-record seq {got_seq} does not supersede the stored slot (seq {stored_seq})"
            ),
        ),
        SlotPublishError::Storage(StorageError::StorageFull) => {
            (code::STORAGE_FULL, err.to_string())
        }
        SlotPublishError::Storage(StorageError::Internal(_)) => {
            (code::INTERNAL_ERROR, err.to_string())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use scp_dht::bep44_signable;
    // Imported here, NOT via the production path: `routing_id_of_key` below is a
    // deliberate independent ORACLE. It recomposes the expected routing_id from a
    // raw verifying key (`did_from_ed25519_public_key` ∘ `did_routing_id`) rather
    // than calling the production `did_record_routing_id`, so a bug in that
    // helper's composition cannot make these tests vacuously pass by being wrong
    // on both sides.
    use scp_identity::{did_from_ed25519_public_key, did_routing_id};

    fn keypair(seed: u8) -> (VerifyingKey, SigningKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        (vk, sk)
    }

    /// Builds DID-record frame bytes. `frame_public_key` is what the frame
    /// carries (the relay checks against it); `signing_key` is what actually
    /// signs the BEP44 payload. Passing mismatched values lets a test forge the
    /// "valid triple but wrong embedded key" and "wrong binding" cases.
    fn frame_bytes(
        frame_public_key: [u8; 32],
        signing_key: &SigningKey,
        seq: u64,
        value: Vec<u8>,
    ) -> Vec<u8> {
        let payload = bep44_signable(&value, seq);
        let signature: ed25519_dalek::Signature = signing_key.sign(&payload);
        DidRecordV1::try_new(frame_public_key, seq, signature.to_bytes(), value)
            .unwrap()
            .encode()
    }

    fn routing_id_of_key(vk: &VerifyingKey) -> [u8; 32] {
        let did = did_from_ed25519_public_key(&vk.to_bytes());
        did_routing_id(&did)
    }

    #[test]
    fn valid_frame_at_correct_routing_id_classifies_valid() {
        let (vk, sk) = keypair(1);
        let rid = routing_id_of_key(&vk);
        let blob = frame_bytes(vk.to_bytes(), &sk, 7, b"did-document".to_vec());

        assert_eq!(
            classify_did_record_frame(&rid, &blob),
            DidRecordClass::Valid { seq: 7 }
        );
    }

    #[test]
    fn non_frame_blob_classifies_not_a_frame() {
        // Too short to be a frame, and does not start with 0x01.
        let rid = [0xAB; 32];
        assert_eq!(
            classify_did_record_frame(&rid, &[0x80, 0x01, 0x02, 0x03]),
            DidRecordClass::NotAFrame
        );
        // A long non-frame blob whose first byte is not the frame version.
        assert_eq!(
            classify_did_record_frame(&rid, &vec![0x99u8; 512]),
            DidRecordClass::NotAFrame
        );
    }

    #[test]
    fn wrong_binding_is_rejected_before_signature_is_verified() {
        // AC2 (cheapest-first ordering): a frame published at the WRONG
        // routing_id AND carrying a garbage signature must be rejected as a
        // BindingMismatch — proving the binding hash short-circuits before the
        // Ed25519 verify. If the order were reversed, the bad signature would
        // surface as SignatureInvalid instead.
        let (vk, _sk) = keypair(2);
        // A frame signed by a *different* key than the one it embeds, so the
        // signature is invalid against the embedded public_key; published at a
        // routing_id that does not match the embedded key either.
        let (_vk_other, sk_other) = keypair(3);
        let blob = frame_bytes(vk.to_bytes(), &sk_other, 1, b"x".to_vec());

        // Wrong routing_id (not the binding for vk).
        let wrong_rid = [0x00; 32];
        assert_eq!(
            classify_did_record_frame(&wrong_rid, &blob),
            DidRecordClass::Invalid(DidRecordRejection::BindingMismatch),
            "binding must be checked before signature; a wrong-binding frame \
             with a bad signature must reject as BindingMismatch, not \
             SignatureInvalid"
        );
    }

    #[test]
    fn correct_binding_but_bad_signature_is_signature_invalid() {
        // The complement of the ordering test: a frame published at the CORRECT
        // routing_id (binding holds) but whose signature does not verify against
        // the embedded key is rejected specifically as SignatureInvalid. This
        // is only reachable once the binding has passed.
        let (vk, _sk) = keypair(4);
        let (_vk_other, sk_other) = keypair(5);
        // Signed by sk_other but embeds vk and is published at vk's routing_id:
        // binding holds, signature fails against vk.
        let rid = routing_id_of_key(&vk);
        let blob = frame_bytes(vk.to_bytes(), &sk_other, 9, b"y".to_vec());

        assert_eq!(
            classify_did_record_frame(&rid, &blob),
            DidRecordClass::Invalid(DidRecordRejection::SignatureInvalid)
        );
    }

    #[test]
    fn valid_triple_at_wrong_routing_id_is_binding_mismatch() {
        // A perfectly valid, self-consistent frame (embedded key signs the
        // payload) published at the WRONG routing_id is rejected on the binding
        // — you cannot park a valid frame at someone else's DID address.
        let (vk, sk) = keypair(6);
        let blob = frame_bytes(vk.to_bytes(), &sk, 3, b"doc".to_vec());
        let (vk_victim, _sk_victim) = keypair(7);
        let victim_rid = routing_id_of_key(&vk_victim);

        assert_eq!(
            classify_did_record_frame(&victim_rid, &blob),
            DidRecordClass::Invalid(DidRecordRejection::BindingMismatch)
        );
    }
}
