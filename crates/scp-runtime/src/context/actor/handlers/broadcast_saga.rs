// Read-only actor helpers still take `&mut PerContextState` so their
// handler futures capture `&mut T` (`T: Send`) rather than `&T`.
#![allow(clippy::needless_pass_by_ref_mut)]

//! Broadcast hosting-handshake saga phase handlers (spec §5.14.13).
//!
//! The supervisor FSM dispatches per-phase messages to a participant actor; this
//! module implements every phase, each running on a LOCAL actor:
//!
//! - **Prepare-A** ([`prepare_a`]) — on the HOST-context actor. Confirms the
//!   host context is Active and the requester (`subscriber_did`) holds
//!   `messages:read` for B, stages the forwarding-registry entry, and builds +
//!   signs the [`BroadcastHostingRequest`] with the requester's Active Signing
//!   Key (supplied per-call — the actor holds no key, ADR-049). Class-S
//!   fail-closed persist of the staged slot.
//!
//! - **Prepare-B** ([`prepare_b`]) — on the BROADCAST-context actor, the
//!   AUTHORITATIVE side. In order: validate the request signature is bound to
//!   `subscriber_did`; freshness (§9.14 skew + B's request-nonce dedup cache);
//!   block-list; gated-context `messages:read` UCAN re-bound to `subscriber_did`
//!   (B is authoritative — Prepare-A on the host cannot validate against B's
//!   UCAN/revocation store); clamp the config (incl. the `expires_at_ms`
//!   lifetime ceiling); aggregate cap. Then it captures `current_key_epoch`,
//!   `granted_at_ms`, the grant `nonce`/`timestamp_ms` at the SINGLE Prepare-B
//!   instant, signs the [`BroadcastHostingGrant`] (author key per-call), stages
//!   the typed prepared into `saga_pending`, records the request nonce in the
//!   dedup cache, and Class-S fail-closed persists.
//!
//! - **Commit-B** ([`commit_b`]) — on the BROADCAST-context actor. Persists the
//!   [`AcceptedHostSnapshotEntry`] on the §5.15.3 sync-persisted path together
//!   with the `MemberJoined{subscriber}` append (idempotently re-registering the
//!   host representative under its handshake `wrapping_pubkey`). **NO key is
//!   pushed** — the snapshot authorizes the host's later §5.14.2 HPKE pull.
//!   Returns the byte-identical author-signed grant bytes. Idempotent by
//!   `SagaId`.
//!
//! - **Commit-A** ([`commit_a`]) — on the HOST-context actor. Persists the
//!   author-signed grant as durable proof of relay authorization + does
//!   host-registration. Idempotent by `SagaId`.
//!
//! # Abort
//!
//! Abort is handled by the shared [`SagaPhaseMessage::Abort`](crate::context::actor::commands::SagaPhaseMessage::Abort)
//! arm (`handlers::saga::abort`): it clears the staged `saga_pending` slot, no
//! key, no snapshot, no append (§5.14.13 "Abort").
//!
//! # Error band
//!
//! Rejections surface as typed [`ContextError`]s carrying `SCP-SAGA-131xx`
//! codes (the broadcast-hosting sub-block of the saga band; the leaf types use
//! `13100-13102`, the runtime dispatch `13110-13199`).

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::hosting_handshake::{
    AcceptedHostSnapshotEntry, BroadcastHostConfig, BroadcastHostingGrant,
    BroadcastHostingGrantFields, BroadcastHostingRequest, BroadcastHostingRequestFields,
    ForwardingPolicy,
};
use scp_protocol::context::broadcast::{AggregateCapExceeded, BroadcastAdmission};
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::ucan::validate::{DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext};

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::{
    BroadcastCommitBReply, BroadcastPrepareAReply, BroadcastPrepareBReply,
    BroadcastPreparedAFields, BroadcastPreparedBFields, SagaPhaseMessage, SigningKeyBytes,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::{Outcome, outcome_error_sketch};
use crate::context::economy_logic::{ContextRevocationChecker, KeyResolverDidResolver};
use crate::context::state::{context_id_to_bytes, require_active};
use crate::context::supervisor::saga_journal::SagaId;
use crate::context::supervisor::saga_prepared_state::{
    BroadcastHostingHandshakePrepared, SagaPreparedState,
};

/// No-op nonce tracker for the gated-UCAN re-bind path. The cross-context
/// ENVELOPE / request replay is owned separately by B's request-nonce dedup
/// cache; the UCAN's OWN nonce is a long-lived delegation-proof concern that
/// must not falsely trip replay on re-validation. Mirrors the accepted
/// production `NoopNonceTracker` in `saga.rs` / `broadcast.rs`.
struct NoopNonceTracker;
impl scp_protocol::crypto::ucan::validate::NonceTracker for NoopNonceTracker {
    fn check_replay(
        &self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }
    fn record(
        &mut self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }
}

/// Dispatch a broadcast hosting-handshake [`SagaPhaseMessage`] against actor
/// state. Routed here from `handlers::saga::dispatch`'s broadcast partition.
pub(crate) async fn dispatch(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        SagaPhaseMessage::BroadcastPrepareA {
            saga_id,
            host_context_id,
            broadcast_context_id,
            subscriber_did,
            wrapping_pubkey,
            requested_config_bytes,
            ucan,
            nonce,
            timestamp_ms,
            requester_signing_key,
            reply,
        } => {
            let req = BroadcastPrepareARequest {
                saga_id,
                host_context_id,
                broadcast_context_id,
                subscriber_did,
                wrapping_pubkey,
                requested_config_bytes,
                ucan,
                nonce,
                timestamp_ms,
                requester_signing_key,
            };
            prepare_a(cell, deps, req, reply).await
        }
        SagaPhaseMessage::BroadcastPrepareB {
            saga_id,
            broadcast_context_id,
            request_bytes,
            author_signing_key,
            reply,
        } => {
            prepare_b(
                cell,
                deps,
                &saga_id,
                broadcast_context_id,
                &request_bytes,
                &author_signing_key,
                reply,
            )
            .await
        }
        SagaPhaseMessage::BroadcastCommitB { saga_id, reply } => {
            commit_b(cell, deps, &saga_id, reply).await
        }
        SagaPhaseMessage::BroadcastCommitA {
            saga_id,
            grant_bytes,
            reply,
        } => commit_a(cell, deps, &saga_id, &grant_bytes, reply).await,
        SagaPhaseMessage::BroadcastCommitAReack { saga_id, reply } => {
            // READ-ONLY crash-recovery witness check: report whether Commit-A's
            // durable grant proof for this SagaId is present.
            let present = cell.class_s.bcast_committed_grants.contains_key(&saga_id);
            let _ = reply.send(Ok(present));
            Outcome::ok(())
        }
        // The top-level `dispatch` router only forwards the four broadcast
        // phases here; any other variant reaching this point is a router
        // partition bug. Route it back through the xctx saga dispatcher (which
        // owns those variants' reply shapes) rather than panicking (ADR-049 §10).
        // Boxed because this is an indirect cycle back through `saga::dispatch`
        // (statically unreachable in practice; the box satisfies the recursive
        // async-fn requirement without a panic path).
        other => Box::pin(super::saga::dispatch(cell, deps, other)).await,
    }
}

/// Owned Prepare-A request fields (boxed payload destructure), so the dispatch
/// router stays within the per-function argument budget.
struct BroadcastPrepareARequest {
    saga_id: SagaId,
    host_context_id: [u8; 32],
    broadcast_context_id: [u8; 32],
    subscriber_did: DID,
    wrapping_pubkey: [u8; 32],
    requested_config_bytes: Vec<u8>,
    ucan: Option<String>,
    nonce: [u8; 16],
    timestamp_ms: u64,
    requester_signing_key: SigningKeyBytes,
}

// ---------------------------------------------------------------------------
// Prepare-A (host side)
// ---------------------------------------------------------------------------

/// Prepare-A (spec §5.14.13) — runs on the HOST-context actor. Confirms the host
/// context is Active and the requester holds `messages:read` for B, stages the
/// forwarding-registry entry, signs the request, and Class-S fail-closed
/// persists the staged slot.
async fn prepare_a(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    req: BroadcastPrepareARequest,
    reply: BroadcastPrepareAReply,
) -> Outcome<()> {
    // (1) Host context Active.
    if let Err(e) = require_active(&cell.handle) {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    // (2) The requester holds `messages:read` for B. The host representative is
    //     a §5.14.3 subscriber of B holding `messages:read`; on the host-context
    //     actor we confirm the requester is a known member of the host context
    //     (the channel-authenticated initiator the supervisor bound) before
    //     staging. The authoritative gated-UCAN / membership check against B
    //     itself runs at Prepare-B (B is authoritative — §5.14.13).
    let requester = req.subscriber_did.as_ref();
    let holds_read = cell
        .role_state
        .member_capabilities
        .get(requester)
        .is_some_and(|caps| {
            caps.contains(&Capability::MessagesRead) || caps.contains(&Capability::MessagesWrite)
        })
        || cell.membership.contains(requester);
    if !holds_read {
        let e = ContextError::PermissionDenied(format!(
            "SCP-SAGA-13110: broadcast hosting Prepare-A — requester '{requester}' is not a \
             member of the host context authorized to relay (messages:read required)"
        ));
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    // (3) Decode the requested config, build + sign the request with the
    //     requester's Active Signing Key (supplied per-call).
    let requested_config: BroadcastHostConfig =
        match serde_json::from_slice(&req.requested_config_bytes) {
            Ok(c) => c,
            Err(e) => {
                let err = ContextError::InvalidState(format!(
                    "SCP-SAGA-13111: broadcast hosting Prepare-A — requested_config is not a \
                     decodable BroadcastHostConfig: {e}"
                ));
                let sketch = outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                return Outcome::err(sketch);
            }
        };

    let signing_key = req.requester_signing_key.to_signing_key();
    let signed_request = match BroadcastHostingRequest::sign(
        &signing_key,
        BroadcastHostingRequestFields {
            host_context_id: req.host_context_id,
            broadcast_context_id: req.broadcast_context_id,
            subscriber_did: req.subscriber_did.0.clone(),
            wrapping_pubkey: req.wrapping_pubkey,
            requested_config,
            ucan: req.ucan.clone(),
            nonce: req.nonce,
            timestamp_ms: req.timestamp_ms,
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            let err = ContextError::CryptoFailed(format!(
                "SCP-SAGA-13112: broadcast hosting Prepare-A — request signing failed: {e}"
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        }
    };

    let request_bytes = match scp_protocol::jcs::to_vec(&signed_request) {
        Ok(b) => b,
        Err(e) => {
            let err = ContextError::CryptoFailed(format!(
                "SCP-SAGA-13113: broadcast hosting Prepare-A — request serialization failed: {e}"
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        }
    };

    // (4) Stage the host-side forwarding-registry entry into `saga_pending`
    //     (Class S — its loss before Commit must roll the saga back cleanly). On
    //     the host side the prepared records the public ids + the wrapping key;
    //     the granted-config / epoch fields are B-side and left as the request's
    //     for the host record (the host record is its own staged forwarding
    //     entry, not the authoritative grant snapshot).
    let prepared = BroadcastHostingHandshakePrepared {
        host_context_id: req.host_context_id,
        broadcast_context_id: req.broadcast_context_id,
        subscriber_did: req.subscriber_did.clone(),
        wrapping_pubkey: req.wrapping_pubkey,
        // The host stages no authoritative grant values; these are filled by B at
        // Prepare-B and delivered to the host as the signed grant at Commit-A.
        key_epoch_at_grant: 0,
        granted_at_ms: 0,
        grant_nonce: req.nonce,
        grant_timestamp_ms: req.timestamp_ms,
        broadcast_host_config_bytes: req.requested_config_bytes.clone(),
    };

    // Stage under a fail-closed Class-S persist that AUTO-RESTORES the Class-S
    // sub-struct (incl. `saga_pending`) on persist failure, so a host-side
    // Prepare-A whose persist did not land rolls the staged slot back cleanly
    // and a retry re-stages (no orphaned forwarding registration).
    let host_hex = hex::encode(req.host_context_id);
    let saga_id = req.saga_id.clone();
    if let Err(persist_err) = cell.commit_class_s_restore(deps, &host_hex, |mut view| {
        view.class_s_mut().saga_pending.insert(
            saga_id.clone(),
            SagaPreparedState::BroadcastHostingHandshake(prepared),
        );
        Ok::<(), ContextError>(())
    }) {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err(sketch);
    }

    let _ = reply.send(Ok(BroadcastPreparedAFields { request_bytes }));
    Outcome::ok_mutated(())
}

// ---------------------------------------------------------------------------
// Prepare-B (broadcast side, authoritative)
// ---------------------------------------------------------------------------

/// Prepare-B (spec §5.14.13) — runs on the BROADCAST-context actor.
async fn prepare_b(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    broadcast_context_id: [u8; 32],
    request_bytes: &[u8],
    author_signing_key: &SigningKeyBytes,
    reply: BroadcastPrepareBReply,
) -> Outcome<()> {
    match prepare_b_inner(
        cell,
        deps,
        saga_id,
        broadcast_context_id,
        request_bytes,
        author_signing_key,
    )
    .await
    {
        Ok((fields, mutated)) => {
            let _ = reply.send(Ok(fields));
            if mutated {
                Outcome::ok_mutated(())
            } else {
                Outcome::ok(())
            }
        }
        Err((e, mutated)) => {
            let sketch = outcome_error_sketch(&e);
            let _ = reply.send(Err(e));
            if mutated {
                Outcome::err_mutated(sketch)
            } else {
                Outcome::err(sketch)
            }
        }
    }
}

/// Prepare-B body. Returns `(fields, mutated)` on accept; `(error, mutated)` on
/// reject. `mutated` is `true` only once Class-S state has been touched.
#[allow(clippy::too_many_lines)] // the full ordered §5.14.13 Prepare-B gate set
async fn prepare_b_inner(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    broadcast_context_id: [u8; 32],
    request_bytes: &[u8],
    author_signing_key: &SigningKeyBytes,
) -> Result<(BroadcastPreparedBFields, bool), (ContextError, bool)> {
    let no_mut = |e: ContextError| (e, false);

    // (0) Context Active + decode the request.
    require_active(&cell.handle).map_err(no_mut)?;
    let request: BroadcastHostingRequest = serde_json::from_slice(request_bytes).map_err(|e| {
        no_mut(ContextError::InvalidState(format!(
            "SCP-SAGA-13120: broadcast hosting Prepare-B — request is not a decodable \
             BroadcastHostingRequest: {e}"
        )))
    })?;

    // Target-context binding: the request's broadcast_context_id MUST equal B's
    // own context (so a request for a different B cannot induce a side effect).
    if request.broadcast_context_id != broadcast_context_id {
        return Err(no_mut(ContextError::InvalidState(format!(
            "SCP-SAGA-13121: broadcast hosting Prepare-B — request broadcast_context_id does \
             not match this broadcast context '{}'",
            hex::encode(broadcast_context_id)
        ))));
    }

    // (1) Signature bound to subscriber_did. The Active Signing Key for
    //     subscriber_did is resolved via DID resolution; the request is valid
    //     only if signed by the DID it claims.
    let subscriber_did = DID(request.subscriber_did.clone());
    let subscriber_key = (deps.key_resolver)(
        &subscriber_did,
        scp_protocol::identity::SigningKeyId::Active,
    )
    .ok_or_else(|| {
        no_mut(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13122: broadcast hosting Prepare-B — cannot resolve the Active Signing \
             Key for requester '{subscriber_did}' (DID resolution failed)"
        )))
    })?;
    request.verify(&subscriber_key).map_err(|e| {
        no_mut(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13123: broadcast hosting Prepare-B — request signature does not verify \
             against the Active Signing Key of '{subscriber_did}': {e}"
        )))
    })?;

    // (2) Freshness: timestamp within §9.14 skew. (Read-only — the nonce-dedup
    //     check + record run together under the single fail-closed persist
    //     below so an accepted nonce is durably recorded.)
    let now_ms = deps.clock.now_millis();
    let now_secs = deps.clock.now_secs();
    let skew_ms = DEFAULT_CLOCK_SKEW_TOLERANCE_SECS.saturating_mul(1000);
    let within_skew = request.timestamp_ms <= now_ms.saturating_add(skew_ms)
        && request.timestamp_ms >= now_ms.saturating_sub(skew_ms);
    if !within_skew {
        return Err(no_mut(ContextError::PermissionDenied(format!(
            "SCP-SAGA-13124: broadcast hosting Prepare-B — request timestamp {} is outside the \
             clock-skew tolerance (now {now_ms} ms)",
            request.timestamp_ms
        ))));
    }
    // Nonce-dedup READ (the record happens under the persist below). A seen
    // nonce is a replay — reject before any side effect.
    if cell
        .class_s
        .bcast_request_nonce_dedup
        .is_replayed_read(&request.nonce, now_secs)
    {
        return Err(no_mut(ContextError::PermissionDenied(
            "SCP-SAGA-13125: broadcast hosting Prepare-B — request nonce already seen (replay)"
                .to_owned(),
        )));
    }

    // (3) Resolve B's sole local broadcast author (whose epoch / block list / key
    //     this grant rides) + (4) block-list + (5) gated-UCAN + (6) clamp +
    //     (7) aggregate cap. All read-only; performed before staging.
    let forwarding_policy_ok;
    let granted_config;
    let key_epoch_at_grant;
    {
        let bc = cell.broadcast_context.as_ref().ok_or_else(|| {
            no_mut(ContextError::MembershipFailed(
                "SCP-SAGA-13126: broadcast hosting Prepare-B — not a broadcast context".to_owned(),
            ))
        })?;

        // The locally-controlled broadcast author whose epoch is captured.
        let author_did = bc
            .author_dids()
            .find(|did| deps.local_dids.load().contains(&DID((*did).clone())))
            .cloned()
            .ok_or_else(|| {
                no_mut(ContextError::PermissionDenied(
                    "SCP-SAGA-13127: broadcast hosting Prepare-B — no locally-controlled \
                     broadcast author to authorize the grant"
                        .to_owned(),
                ))
            })?;

        // (4) Block-list: a blocked DID is refused.
        if bc.is_blocked(&author_did, subscriber_did.as_ref()) {
            return Err(no_mut(ContextError::PermissionDenied(format!(
                "SCP-SAGA-13128: broadcast hosting Prepare-B — requester '{subscriber_did}' is \
                 blocked by author '{author_did}'"
            ))));
        }

        // (5) Gated context: validate the request's `messages:read` UCAN re-bound
        //     to subscriber_did (B is authoritative — current, unrevoked check).
        if bc.admission() == BroadcastAdmission::Gated {
            let ucan_str = request.ucan.as_deref().ok_or_else(|| {
                no_mut(ContextError::PermissionDenied(
                    "SCP-SAGA-13129: broadcast hosting Prepare-B — gated broadcast requires a \
                     messages:read UCAN; none presented (Unauthorized)"
                        .to_owned(),
                ))
            })?;
            validate_gated_read_ucan(cell, deps, bc, ucan_str, &subscriber_did)?;
        }

        // (6) Clamp the requested config into B's permitted ranges → granted.
        //     The `expires_at_ms` lifetime ceiling (granted_at_ms +
        //     max_grant_lifetime_ms) is applied after capturing granted_at_ms.
        let mut clamped = BroadcastHostConfig::clamp(&request.requested_config);
        let cap = bc.aggregate_cap();
        // Lower bound: expires_at_ms MUST be strictly greater than granted_at_ms
        // (a born-expired grant is rejected, not clamped — §5.14.13).
        if clamped.expires_at_ms <= now_ms {
            return Err(no_mut(ContextError::PermissionDenied(format!(
                "SCP-SAGA-13130: broadcast hosting Prepare-B — requested expires_at_ms {} is \
                 not strictly after the Prepare-B clock {now_ms} (ConfigInvalid)",
                clamped.expires_at_ms
            ))));
        }
        // Upper bound: clamp down to granted_at_ms + max_grant_lifetime_ms.
        let lifetime_ceiling = now_ms.saturating_add(cap.max_grant_lifetime_ms);
        if clamped.expires_at_ms > lifetime_ceiling {
            clamped.expires_at_ms = lifetime_ceiling;
        }

        // (7) Aggregate cap — sum over OTHER live entries (excluding this pair).
        bc.check_aggregate_cap(
            &hex::encode(request.host_context_id),
            subscriber_did.as_ref(),
            clamped.max_subscribers,
            clamped.max_forward_rate_per_minute,
        )
        .map_err(|e| no_mut(aggregate_cap_error(&e)))?;

        // forwarding_policy: a routing-stripped policy must not break the signed
        // §5.14.5 envelope verification. Both ForwardingPolicy variants preserve
        // the inner signed envelope by construction (RoutingStripped touches only
        // outer-envelope routing hints), so any well-formed policy is admissible.
        forwarding_policy_ok = matches!(
            clamped.forwarding_policy,
            ForwardingPolicy::Verbatim | ForwardingPolicy::RoutingStripped
        );
        key_epoch_at_grant = bc.author_key_epoch(&author_did).unwrap_or(0);
        granted_config = clamped;
    }
    if !forwarding_policy_ok {
        return Err(no_mut(ContextError::InvalidState(
            "SCP-SAGA-13131: broadcast hosting Prepare-B — grant forwarding_policy would break \
             §5.14.5 envelope verification"
                .to_owned(),
        )));
    }

    // (8) Capture the replay-deterministic values at the SINGLE Prepare-B
    //     instant and sign the grant.
    let granted_at_ms = now_ms;
    let grant_nonce = request.nonce; // echoes the request's nonce (never freshly drawn)
    let grant_timestamp_ms = granted_at_ms;
    let author_sk = author_signing_key.to_signing_key();
    let grant = BroadcastHostingGrant::sign(
        &author_sk,
        BroadcastHostingGrantFields {
            host_context_id: request.host_context_id,
            broadcast_context_id: request.broadcast_context_id,
            subscriber_did: request.subscriber_did.clone(),
            wrapping_pubkey: request.wrapping_pubkey,
            granted_config: granted_config.clone(),
            current_key_epoch: key_epoch_at_grant,
            nonce: grant_nonce,
            timestamp_ms: grant_timestamp_ms,
        },
    )
    .map_err(|e| {
        no_mut(ContextError::CryptoFailed(format!(
            "SCP-SAGA-13132: broadcast hosting Prepare-B — grant signing failed: {e}"
        )))
    })?;
    let grant_bytes = scp_protocol::jcs::to_vec(&grant).map_err(|e| {
        no_mut(ContextError::CryptoFailed(format!(
            "SCP-SAGA-13133: broadcast hosting Prepare-B — grant serialization failed: {e}"
        )))
    })?;
    let granted_config_bytes = granted_config.to_jcs().map_err(|e| {
        no_mut(ContextError::CryptoFailed(format!(
            "SCP-SAGA-13134: broadcast hosting Prepare-B — granted_config JCS failed: {e}"
        )))
    })?;

    // (9) Stage the typed prepared + record the request nonce under ONE
    //     fail-closed Class-S persist with OPPOSITE rollback directions:
    //       (a) `bcast_request_nonce_dedup.record` — KEEP on persist failure
    //           (un-recording re-opens the §5.14.13 replay window).
    //       (b) `saga_pending.insert` — RESTORE on persist failure (a slot that
    //           did not durably land must be removed so a retry re-stages).
    let prepared = BroadcastHostingHandshakePrepared {
        host_context_id: request.host_context_id,
        broadcast_context_id: request.broadcast_context_id,
        subscriber_did,
        wrapping_pubkey: request.wrapping_pubkey,
        key_epoch_at_grant,
        granted_at_ms,
        grant_nonce,
        grant_timestamp_ms,
        broadcast_host_config_bytes: granted_config_bytes,
    };

    let broadcast_hex = hex::encode(broadcast_context_id);
    let nonce = request.nonce;
    let staged_saga_id = saga_id.clone();
    if let Err(persist_err) = cell.commit_class_s_keep_restore_split(
        deps,
        &broadcast_hex,
        |class_s| class_s.saga_pending.keys().cloned().collect::<Vec<_>>(),
        |mut view| {
            let class_s = view.class_s_mut();
            class_s.bcast_request_nonce_dedup.evict_expired(now_secs);
            class_s.bcast_request_nonce_dedup.record(nonce, now_secs);
            class_s.saga_pending.insert(
                staged_saga_id.clone(),
                SagaPreparedState::BroadcastHostingHandshake(prepared),
            );
            Ok::<(), ContextError>(())
        },
        |class_s, keys_before| {
            class_s.saga_pending.retain(|k, _| keys_before.contains(k));
        },
    ) {
        return Err((persist_err, true));
    }

    Ok((
        BroadcastPreparedBFields {
            grant_bytes,
            key_epoch_at_grant,
            granted_at_ms,
        },
        true,
    ))
}

/// Validate a gated-context `messages:read` UCAN re-bound to the presenting
/// subscriber, against THIS broadcast context (spec §5.14.13 / §5.14.4). Runs
/// the full ADR-016 pipeline (signature, delegation chain, **revocation**,
/// expiry, capability match), so a token revoked between subscribe and
/// handshake is refused here.
fn validate_gated_read_ucan(
    cell: &ClassSCell,
    deps: &ActorDeps,
    bc: &scp_protocol::context::broadcast::BroadcastContext,
    ucan_str: &str,
    subscriber_did: &DID,
) -> Result<(), (ContextError, bool)> {
    let token = scp_protocol::crypto::ucan::validate::parse_ucan(ucan_str).map_err(|e| {
        (
            ContextError::PermissionDenied(format!(
                "SCP-SAGA-13135: broadcast hosting Prepare-B — gated UCAN is not parseable: {e} \
                 (Unauthorized)"
            )),
            false,
        )
    })?;
    let ceiling = cell.role_state.ceiling().to_ucan_string_set();
    let creator_did = cell.role_state.creator_did.clone();
    let revoked = cell.governance.revoked_spending_ucan_cids.clone();
    let did_resolver = KeyResolverDidResolver::new(&deps.key_resolver);
    let revocation_checker = ContextRevocationChecker {
        revoked_cids: &revoked,
    };
    let mut nonce_tracker = NoopNonceTracker;
    let mut ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &revocation_checker,
        proof_resolver: &cell.xctx_ucan_proofs,
        ceiling: &ceiling,
        context_creator_did: &creator_did,
        // Re-bind to the requester: the token's audience MUST be subscriber_did.
        presenting_agent_did: subscriber_did.as_ref(),
        clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock: deps.clock.as_ref(),
    };
    bc.validate_messages_read_ucan_public(&token, &mut ctx)
        .map_err(|e| {
            (
                ContextError::PermissionDenied(format!(
                    "SCP-SAGA-13135: broadcast hosting Prepare-B — gated messages:read UCAN \
                     re-validation failed (re-bound to '{subscriber_did}'): {e} (Unauthorized)"
                )),
                false,
            )
        })
}

/// Map an [`AggregateCapExceeded`] to a typed `SCP-SAGA-13136` rejection.
fn aggregate_cap_error(e: &AggregateCapExceeded) -> ContextError {
    let detail = match e {
        AggregateCapExceeded::Subscribers {
            would_be_total,
            ceiling,
        } => format!("subscribers {would_be_total} > aggregate ceiling {ceiling}"),
        AggregateCapExceeded::ForwardRate {
            would_be_total,
            ceiling,
        } => format!("forward-rate {would_be_total} > aggregate ceiling {ceiling}"),
    };
    ContextError::PermissionDenied(format!(
        "SCP-SAGA-13136: broadcast hosting Prepare-B — aggregate cap exceeded ({detail}) \
         (AggregateCapExceeded)"
    ))
}

// ---------------------------------------------------------------------------
// Commit-B (broadcast side)
// ---------------------------------------------------------------------------

/// Commit-B (spec §5.14.13) — runs on the BROADCAST-context actor. Persists the
/// `AcceptedHostSnapshotEntry` + the `MemberJoined{subscriber}` append on the
/// sync-persisted path; returns the byte-identical author-signed grant bytes.
/// Idempotent by `SagaId`.
async fn commit_b(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    reply: BroadcastCommitBReply,
) -> Outcome<()> {
    match commit_b_inner(cell, deps, saga_id).await {
        Ok(grant_bytes) => {
            let _ = reply.send(Ok(grant_bytes));
            Outcome::ok_mutated(())
        }
        Err(e) => {
            let sketch = outcome_error_sketch(&e);
            let _ = reply.send(Err(e));
            Outcome::err(sketch)
        }
    }
}

async fn commit_b_inner(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
) -> Result<Vec<u8>, ContextError> {
    // Resolve the staged prepared (Class S). Absence ⇒ a replayed Commit whose
    // saga was already cleared, OR a Commit with no Prepare — fail fast.
    let prepared = match cell.class_s.saga_pending.get(saga_id) {
        Some(SagaPreparedState::BroadcastHostingHandshake(p)) => clone_prepared(p),
        Some(_) => {
            return Err(ContextError::InvalidState(format!(
                "SCP-SAGA-13140: broadcast hosting Commit-B — staged slot for saga '{}' is not a \
                 broadcast hosting handshake",
                saga_id.0
            )));
        }
        None => {
            return Err(ContextError::InvalidState(format!(
                "SCP-SAGA-13141: broadcast hosting Commit-B — no staged prepared for saga '{}' \
                 (Prepare-B did not land or was already committed)",
                saga_id.0
            )));
        }
    };

    let granted_config: BroadcastHostConfig =
        serde_json::from_slice(&prepared.broadcast_host_config_bytes).map_err(|e| {
            ContextError::InvalidState(format!(
                "SCP-SAGA-13142: broadcast hosting Commit-B — staged granted_config is not \
                 decodable: {e}"
            ))
        })?;

    let entry = AcceptedHostSnapshotEntry {
        host_context_id: prepared.host_context_id,
        subscriber_did: prepared.subscriber_did.0.clone(),
        wrapping_pubkey: prepared.wrapping_pubkey,
        granted_config,
        granted_at_ms: prepared.granted_at_ms,
        key_epoch_at_grant: prepared.key_epoch_at_grant,
        saga_id: saga_id.0.clone(),
    };

    // Re-sign the byte-identical grant from the staged replay-deterministic
    // values so Commit-B returns the SAME grant on a crash replay. The grant is
    // signed by the broadcast author; on a replay the author key is NOT
    // available to Commit-B (it rode Prepare-B), so the grant bytes must be
    // reconstructable from staged state WITHOUT re-signing. We therefore return
    // the grant the FSM already holds (from Prepare-B's reply) — Commit-B does
    // not re-sign. Instead Commit-B's reply is the grant bytes the FSM passes
    // back; the FSM is the byte-source. Commit-B persists the snapshot + append
    // and acks; the grant returned here is reconstructed from the snapshot for
    // the FSM's convenience, but the AUTHORITATIVE grant the host holds is the
    // one B signed at Prepare-B and the FSM forwards. We return the staged
    // grant config bytes so the FSM can confirm consistency. (Grant bytes are
    // carried by the FSM from Prepare-B; see the supervisor.)
    let context_id = cell.handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let subscriber_did = prepared.subscriber_did.clone();
    let granted_at_secs = prepared.granted_at_ms / 1000;

    // Persist the AcceptedHostSnapshotEntry (Class S — §5.15.3 sync path) +
    // idempotently register the host representative as a subscriber + clear the
    // staged slot, all under ONE fail-closed persist. The broadcast snapshot
    // (carrying accepted_hosts) is persisted fail-closed inside this closure.
    let staged_id = saga_id.clone();
    let entry_for_persist = entry.clone();
    let subscriber_for_persist = subscriber_did.clone();
    // Commit-B runs under the fail-closed Class-S combinator (the accepted-host
    // snapshot + MemberJoined append + slot clear are §5.15.3 sync-persisted).
    // The `ClassSMut` view's `rest_mut()` reaches the whole `&mut
    // PerContextState` (sound here precisely because the combinator persists
    // fail-closed), so the broadcast-context + membership Class-C mutations and
    // the Class-S slot clear all land atomically under ONE persist.
    cell.commit_class_s_keep(deps, &context_id, |mut view| {
        let granted_at_ms = entry_for_persist.granted_at_ms;
        let state = view.rest_mut();
        // (a) Upsert the accepted-host snapshot entry + idempotently register
        //     the host representative as a subscriber under its handshake
        //     wrapping_pubkey (an already-registered subscriber is an idempotent
        //     update, NOT a duplicate-membership error — §5.14.13).
        {
            let bc = state.broadcast_context.as_mut().ok_or_else(|| {
                ContextError::MembershipFailed(
                    "SCP-SAGA-13143: broadcast hosting Commit-B — not a broadcast context"
                        .to_owned(),
                )
            })?;
            bc.upsert_accepted_host(entry_for_persist.clone());
            bc.register_host_subscriber(subscriber_for_persist.as_ref(), granted_at_ms / 1000);
        }
        // (b) MemberJoined{subscriber} into the membership roster (idempotent —
        //     add_member overwrites an existing entry).
        state.membership.add_member(
            subscriber_for_persist.clone(),
            "subscriber".to_owned(),
            vec![],
        );
        // (c) Clear the staged slot (Commit consumed it).
        state.class_s.saga_pending.remove(&staged_id);
        Ok::<(), ContextError>(())
    })?;

    // Persist the broadcast snapshot fail-closed (the accepted_hosts registry is
    // sync-persisted per §5.15.3). A failure here means the snapshot did not
    // durably land — surface it so the FSM retries the idempotent Commit.
    if let Some(bc) = cell.broadcast_context.as_ref() {
        let snapshot = bc.to_snapshot();
        deps.persistence
            .persist_broadcast(&context_id, &snapshot)
            .map_err(|e| {
                ContextError::InvalidState(format!(
                    "SCP-SAGA-13144: broadcast hosting Commit-B — fail-closed broadcast snapshot \
                     persist failed: {e}"
                ))
            })?;
    }

    // MemberJoined event-log append (§5.14.3). Committer-assigned leaf timestamp
    // = the convergent granted_at instant (seconds), so honest members converge.
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberJoined,
        subscriber_did.as_ref(),
        granted_at_secs,
    )?;

    // Return the snapshot-derived grant bytes purely as a consistency echo; the
    // AUTHORITATIVE grant the host receives is the Prepare-B-signed grant the
    // FSM carries to Commit-A.
    scp_protocol::jcs::to_vec(&entry).map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13145: broadcast hosting Commit-B — snapshot echo serialization failed: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Commit-A (host side)
// ---------------------------------------------------------------------------

/// Commit-A (spec §5.14.13) — runs on the HOST-context actor. Persists the
/// author-signed grant as durable relay-authorization proof + clears the staged
/// host slot. Idempotent by `SagaId`.
async fn commit_a(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    grant_bytes: &[u8],
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Decode + sanity-check the grant (it is non-secret durable proof).
    if let Err(e) = serde_json::from_slice::<BroadcastHostingGrant>(grant_bytes) {
        let err = ContextError::InvalidState(format!(
            "SCP-SAGA-13150: broadcast hosting Commit-A — grant is not a decodable \
             BroadcastHostingGrant: {e}"
        ));
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err(sketch);
    }

    // Persist the grant as durable proof (the host's forwarding registry) +
    // clear the staged host slot. Idempotent by SagaId: a replay re-acks.
    let context_id = cell.handle.context_id().to_owned();
    let staged_id = saga_id.clone();
    let grant_owned = grant_bytes.to_vec();
    if let Err(persist_err) = cell.commit_class_s_keep(deps, &context_id, |mut view| {
        let class_s = view.class_s_mut();
        // Record the grant as durable relay-authorization proof keyed by SagaId.
        class_s
            .bcast_committed_grants
            .insert(staged_id.clone(), grant_owned.clone());
        class_s.saga_pending.remove(&staged_id);
        Ok::<(), ContextError>(())
    }) {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Clone a [`BroadcastHostingHandshakePrepared`] (the live type is non-`Clone`
/// because the wrapping enum carries the §9.4.3 non-derive barrier; this is a
/// field-wise copy of the public, non-bearer broadcast prepared).
fn clone_prepared(p: &BroadcastHostingHandshakePrepared) -> BroadcastHostingHandshakePrepared {
    BroadcastHostingHandshakePrepared {
        host_context_id: p.host_context_id,
        broadcast_context_id: p.broadcast_context_id,
        subscriber_did: p.subscriber_did.clone(),
        wrapping_pubkey: p.wrapping_pubkey,
        key_epoch_at_grant: p.key_epoch_at_grant,
        granted_at_ms: p.granted_at_ms,
        grant_nonce: p.grant_nonce,
        grant_timestamp_ms: p.grant_timestamp_ms,
        broadcast_host_config_bytes: p.broadcast_host_config_bytes.clone(),
    }
}
