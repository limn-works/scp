//! Items the broadcast domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::KeyRequestDecision;

/// Evaluates whether a subscriber's broadcast key request should be granted.
///
/// # Errors
///
/// Returns [`ContextError::PermissionDenied`] if `author_did` is not a locally
/// controlled DID, and [`ContextError::MembershipFailed`] if the actor is not a
/// broadcast context.
pub fn handle_broadcast_key_request(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    author_did: &DID,
    requester_did: &DID,
    wrapping_pubkey: &scp_protocol::crypto::hpke::p256::P256Point,
) -> Result<KeyRequestDecision, ContextError> {
    if !deps.local_dids.load().contains(author_did) {
        return Err(ContextError::PermissionDenied(format!(
            "author DID is not controlled by the local node: {author_did}"
        )));
    }

    let bc = cell
        .broadcast_context
        .as_ref()
        .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

    // Durable-ban serve-path gate (§5.14.8, #2088 / BLACK-303), fail-closed before
    // any grant. AUTHORITATIVE: the durable `banned_subscribers` record — the same
    // authority-only-clearable signal the subscribe-admission gate uses. This
    // catches a banned DID whom NEITHER other signal covers: a banned AUTHOR (the
    // context creator is always an author) is never on any block list (a
    // non-subscriber ban writes no block-list entry) and, once they self-leave,
    // is no longer in `read_exclusion_list`. `BroadcastContext::handle_key_request`
    // enforces this by construction for all callers; this early check keeps the
    // runtime serve path symmetric with subscribe. Uses the uniform reason
    // (non-leakage).
    if bc.is_banned(requester_did.as_ref()) {
        return Ok(KeyRequestDecision::Deny {
            reason: scp_protocol::context::broadcast::KEY_REQUEST_DENY_REASON.to_owned(),
        });
    }

    // Serve-path exclusion consult (defense-in-depth, §5.14.8 block-before-serve)
    // for a STILL-PRESENT read-revoked member: `read_exclusion_list` is written
    // fail-closed on `RevokeAccess{Read}` and consulted here before the per-author
    // block-list check. Unlike the durable ban above, this entry is CLEARED when
    // the subject self-leaves, so it is a defense-in-depth complement — NOT the
    // authoritative durable signal. Uses the SAME uniform deny reason (non-leakage).
    // Disjoint shared borrow of `cell.access` (a different field than
    // `broadcast_context`), so `bc` stays valid for the delegation below.
    if cell.access.read_exclusion_list.contains(requester_did) {
        return Ok(KeyRequestDecision::Deny {
            reason: scp_protocol::context::broadcast::KEY_REQUEST_DENY_REASON.to_owned(),
        });
    }

    Ok(bc.handle_key_request(author_did, requester_did, wrapping_pubkey))
}
