//! Messaging handlers — hot-path send + deliver over per-context state.
//!
//! See [`MessagingCommand`](crate::context::actor::commands::MessagingCommand)
//! and plan §"Submodule organization" / row 8 of the commit ladder.
//!
//! # Phase 2A.7 — actor-shape dispatch
//!
//! The handler's sole entry point [`dispatch`] takes
//! `(&mut ClassSCell, &ActorDeps, MessagingCommand)` and routes every
//! variant through [`crate::context::messaging_helpers`] (the
//! actor-shape messaging helpers). The migration-window shim entry
//! point (`dispatch_from_shim`) and the `messaging_helpers_legacy`
//! module it routed through were deleted in Phase 2A finalization —
//! `Supervisor::dispatch_command` is mailbox-only, and a missing actor
//! surfaces a typed lookup-miss error.
//!
//! # Send-sequence tracker
//!
//! `state.send_tracker` is the actor-owned RAII rollback mechanism for
//! sequence reservations
//! ([`SequenceReservation`](crate::context::actor::SequenceReservation)).
//! The wire sequence is still driven by
//! `MembershipState::next_sequence_number` inside the helper body —
//! `send_tracker` runs in parallel and rolls back on early `?`
//! returns, transport timeouts, and crypto errors. A follow-on Phase 2
//! sub-chunk rewires the wire sequence onto `send_tracker`
//! exclusively.
//!
//! # Transport-timeout budget
//!
//! [`HANDLER_TIMEOUT`] is the handler-level budget. The predecessor
//! monolithic context methods did not carry their own deadline — this is
//! the new behaviour introduced by ADR-049 §7. 30 seconds matches the
//! plan's "every transport and storage call inside a handler wraps
//! `tokio::time::timeout(30s, ...)`" contract.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::ContextHandle;
use crate::context::actor::SendSequenceTracker;
use crate::context::actor::commands::MessagingCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::sequence::SequenceReservation;

/// Per-call transport budget for mutation handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`MessagingCommand`] against actor-owned state and deps.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::messaging::dispatch(state, deps, cmd).await`). Each
/// variant routes through [`crate::context::messaging_helpers`] (the
/// actor-shape messaging helpers). The send-sequence tracker
/// (`state.send_tracker`) is reserved internally inside
/// [`handle_send_message`].
// One arm per `MessagingCommand` variant — a flat match-dispatcher, not a
// complex body (mirrors the `#[allow]` on `handlers::lifecycle::dispatch`).
#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: MessagingCommand,
) -> Outcome<()> {
    match cmd {
        MessagingCommand::SendMessage { payload, reply } => {
            let p = *payload;
            // SendMessage reaches the spending-nonce leaf
            // (`enforce_send_economy`) via `send_message`, so it is threaded the
            // cell. The pure Class-C variants below (`ReportDegradedMode`,
            // `BuildLocalCheckpoint`, `CompareRemoteCheckpoint`, `DeliverIncoming`)
            // are threaded the cell too and reach their fields through the
            // non-persisting `class_c_view`: the entire receive cascade makes only
            // Class-C / structural mutations (sequence/reorder/receive buffers,
            // membership[read], role[read], routing, the ConsequenceStateSplit
            // Class-C fields), so no whole-state `state_mut()` is needed.
            handle_send_message(
                cell,
                deps,
                &p.context_id,
                p.params,
                &p.sender_did,
                &p.payload,
                p.signing_key.as_ref(),
                p.signing_key_id,
                p.source_provenance.as_ref(),
                p.spending_ucan.as_ref(),
                reply,
            )
            .await
        }
        MessagingCommand::DeliverIncoming {
            context_id,
            envelope_bytes,
            reply,
        } => handle_deliver_incoming(cell, deps, &context_id, &envelope_bytes, reply).await,
        MessagingCommand::DrainEvents { context_id, reply } => {
            handle_drain_events(cell, &context_id, reply).await
        }
        MessagingCommand::DrainEquivocationAlerts { context_id, reply } => {
            handle_drain_equivocation_alerts(cell, &context_id, reply).await
        }
        MessagingCommand::SendPseudonymAnnouncement { payload, reply } => {
            let p = *payload;
            handle_send_pseudonym_announcement(
                cell,
                deps,
                p.context_id,
                p.params,
                &p.sender_did,
                &p.signing_key,
                reply,
            )
            .await
        }
        #[cfg(feature = "testing")]
        MessagingCommand::SeedPeerPseudonym {
            context_id: _,
            member_did,
            pseudonym,
            reply,
        } => handle_seed_peer_pseudonym(cell, member_did, pseudonym, reply),
        #[cfg(feature = "testing")]
        MessagingCommand::TestInsertMember {
            context_id: _,
            member_did,
            role,
            reply,
        } => handle_test_insert_member(cell, deps, &member_did, &role, reply),
        #[cfg(feature = "outlet-capability-test-grant")]
        MessagingCommand::TestGrantMemberCapability {
            context_id,
            member_did,
            capability,
            reply,
        } => {
            handle_test_grant_member_capability(
                cell,
                deps,
                &context_id,
                &member_did,
                &capability,
                reply,
            )
            .await
        }
        #[cfg(feature = "testing")]
        MessagingCommand::TestInstallAccessKey {
            context_id,
            member_did,
            key,
            reply,
        } => handle_test_install_access_key(cell, &context_id, &member_did, key, reply),
        MessagingCommand::ReportDegradedMode {
            context_id,
            compat,
            unsupported_features,
            reply,
        } => handle_report_degraded_mode(
            cell,
            deps,
            &context_id,
            compat,
            unsupported_features,
            reply,
        ),
        MessagingCommand::BuildLocalCheckpoint {
            context_id,
            sender_did,
            signing_key,
            reply,
        } => {
            handle_build_local_checkpoint(cell, deps, &context_id, &sender_did, &signing_key, reply)
                .await
        }
        MessagingCommand::CompareRemoteCheckpoint {
            context_id,
            remote,
            reply,
        } => handle_compare_remote_checkpoint(cell, deps, &context_id, &remote, reply),
        MessagingCommand::SendHeartbeat {
            context_id,
            sender_did,
            signing_key,
            reply,
        } => handle_send_heartbeat(cell, deps, &context_id, &sender_did, &signing_key, reply).await,
        #[cfg(feature = "testing")]
        MessagingCommand::HandleSenderKeyRequest {
            context_id,
            request_bytes,
            requester_public_key,
            reply,
        } => {
            handle_handle_sender_key_request(
                cell,
                deps,
                &context_id,
                &request_bytes,
                &requester_public_key,
                reply,
            )
            .await
        }
        #[cfg(feature = "testing")]
        MessagingCommand::LandSenderKeyResponse {
            context_id,
            sender_did,
            sender_key,
            epoch,
            reply,
        } => {
            handle_land_sender_key_response(
                cell,
                deps,
                &context_id,
                &sender_did,
                sender_key,
                epoch,
                reply,
            )
            .await
        }
        #[cfg(feature = "testing")]
        MessagingCommand::InspectIncomingInner {
            context_id,
            envelope_bytes,
            reply,
        } => handle_inspect_incoming_inner(cell, deps, &context_id, &envelope_bytes, reply),
    }
}

/// Handle [`MessagingCommand::InspectIncomingInner`] (actor-shape, test-only).
///
/// ADR-049 PR-7 (SCP-CRYPTOMOVE-001) READ-ONLY inner-envelope inspection: the
/// actor twin of the deleted provider `open` inspection twin. Drives ONLY
/// [`ContextCryptoState::open`](crate::context::actor::state::ContextCryptoState::open)
/// on the actor's OWNED crypto state and returns the raw decrypted
/// [`InnerEnvelope`](scp_protocol::envelope::inner::InnerEnvelope) so the harness
/// can read the wire-level `message_type` / `sequence` (§9.9.2 heartbeat AC2/AC3).
///
/// # Non-mutating receive-state invariant (§9)
///
/// This is the whole point of the surface. `cs.open` performs a PURE decrypt and
/// surfaces `env.receive_floor`; it does NOT run the authoritative anti-replay
/// gate (`check_and_advance_recv_sequence`), touch the Class-M floor registry,
/// mutate `nonce_dedup`, or change the epoch — all of which live at the messaging
/// seam ([`decrypt_and_dispatch`](crate::context::messaging_helpers::decrypt_and_dispatch)),
/// which this inspection deliberately does NOT invoke. The ONLY state change is
/// the MLS decryption-ratchet advance intrinsic to decrypting a message (the
/// deleted provider inspection twin was non-mutating in exactly this same sense);
/// a successful open therefore reports `ok_mutated` so the coalesced Class-C
/// persist captures that ratchet advance. Control / Management results (which
/// carry no application inner header) and any decrypt failure return an error and
/// mutate nothing beyond that same intrinsic ratchet step, so they report
/// `ok_mutated` on a decoded-but-non-application open and `err` on a decrypt
/// failure.
///
/// # Caveat — inspect-then-deliver consumes the MLS receive ratchet
///
/// Because a successful open advances the MLS decryption ratchet, inspecting an
/// envelope and THEN delivering the same envelope through the real receive seam
/// would fail the second decrypt (the ratchet step for that message is already
/// spent). This surface is therefore test-only and one-shot per envelope: a
/// harness inspects OR delivers a given ciphertext, never both. Never wire it
/// ahead of the production receive path for a message you also intend to deliver.
#[cfg(feature = "testing")]
fn handle_inspect_incoming_inner(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    envelope_bytes: &[u8],
    reply: oneshot::Sender<Result<scp_protocol::envelope::inner::InnerEnvelope, ContextError>>,
) -> Outcome<()> {
    use scp_protocol::context::builder::OpenResult;

    let context_id_bytes = crate::context::state::context_id_to_bytes(context_id);

    let mut view = cell.class_c_view();
    // A `None` crypto state is a context with no MLS group (a broadcast context,
    // which never carries an MLS-wrapped inner envelope) — fail closed, matching
    // `decrypt_and_dispatch`'s "no MLS group" error.
    let Some(cs) = view.mode_mut().crypto_mut() else {
        let err = ContextError::CryptoFailed(
            "no MLS crypto state for inner-envelope inspection (context has no group)".to_string(),
        );
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err(sketch);
    };

    // PURE decrypt: `cs.open` decrypts (outer → MLS → sender-key → inner) and
    // surfaces `env.receive_floor`, but runs NONE of the receive-side anti-replay
    // enforcement (that is at the messaging seam, which this path skips). No floor
    // advance, no `nonce_dedup` mutation, no Class-M registry write, no epoch
    // change — only the intrinsic MLS decryption-ratchet advance.
    let (outcome, reply_result) =
        match cs.open(&*deps.clock, &context_id_bytes, context_id, envelope_bytes) {
            Ok(OpenResult::Application(env)) => (Outcome::ok_mutated(()), Ok(env.inner)),
            Ok(OpenResult::Control) => {
                let err = ContextError::CryptoFailed(
                    "open_inner_envelope: blob decoded to Control, not an application envelope"
                        .to_string(),
                );
                (Outcome::ok_mutated(()), Err(err))
            }
            Ok(OpenResult::Management { .. }) => {
                let err = ContextError::CryptoFailed(
                    "open_inner_envelope: blob decoded to Management, not an application envelope"
                        .to_string(),
                );
                (Outcome::ok_mutated(()), Err(err))
            }
            Err(e) => {
                let sketch = outcome_error_sketch(&e);
                let _ = reply.send(Err(e));
                return Outcome::err(sketch);
            }
        };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::HandleSenderKeyRequest`] (actor-shape, test-only).
///
/// ADR-049 PR-7 (SCP-CRYPTOMOVE-001) §9.16.2 ANSWER half reached by
/// `context_id`: drives the actor-owned
/// [`ContextCryptoState::handle_sender_key_request`](crate::context::actor::state::ContextCryptoState::handle_sender_key_request)
/// and returns the ephemeral-sealed `SenderKeyResponse` bytes straight back to
/// the caller (the full-stack harness, which drives the requester side with its
/// own custody — actor-loop request INITIATION is deferred #2049). Mirrors
/// [`super::broadcast::handle_handle_broadcast_key_request`]. The answer seals to
/// the requester's EPHEMERAL wrapping key, so it needs no signing key; only the
/// Class-C crypto replay cache (`nonce_dedup`) is mutated on a successful answer,
/// so a produced answer reports `ok_mutated` (an over-mark on the blocked
/// `Ok(None)` case is a harmless extra coalesced persist; an error mutates
/// nothing and reports `err`).
#[cfg(feature = "testing")]
async fn handle_handle_sender_key_request(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    request_bytes: &[u8],
    requester_public_key: &[u8; 32],
    reply: oneshot::Sender<Result<Option<Vec<u8>>, ContextError>>,
) -> Outcome<()> {
    let context_id_bytes = crate::context::state::context_id_to_bytes(context_id);
    let local_did = deps.crypto.local_did().to_owned();
    let now_secs = deps.clock.now_secs();
    // No per-context sender-key block list is resident on the actor (the
    // blocking-flow wiring into the actor answer path is a forward-only follow-up,
    // tracked in #2146); the §9.16.6 Mitigation-1 membership gate on the MLS group
    // tree is the live Sybil defense.
    let blocked = std::collections::HashSet::new();

    let mut view = cell.class_c_view();
    let answer_fut = async {
        // A `None` crypto state is a context with no MLS group (a broadcast
        // context, which never reaches the §9.16.2 sender-key pull path) — fail
        // closed, matching `decrypt_and_dispatch`'s "no MLS group" error.
        let cs = view.mode_mut().crypto_mut().ok_or_else(|| {
            ContextError::CryptoFailed(
                "no MLS crypto state for sender-key request (context has no group)".to_string(),
            )
        })?;
        cs.handle_sender_key_request(
            &context_id_bytes,
            &local_did,
            now_secs,
            request_bytes,
            requester_public_key,
            &blocked,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, answer_fut).await {
        Ok(Ok(opt)) => (Outcome::ok_mutated(()), Ok(opt)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "handle_sender_key_request exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::LandSenderKeyResponse`] (actor-shape, test-only).
///
/// ADR-049 PR-7 (SCP-CRYPTOMOVE-001) §9.16.2 install-onto-ACTOR
/// (GATE-BEFORE-INSTALL): GATES the authenticated `(sender_did, epoch)` against
/// the authoritative Class-M floor registry
/// (`check_and_advance_sender_epoch`, FAIL-CLOSED) and, only on success, installs
/// the key onto the actor-owned `cs.sender_key_store` (a Class-C coalesced
/// mutation). The gate runs before any cell borrow, so a regressing/poisoned
/// epoch is rejected with the key NEVER reaching the store. The requester
/// (harness) already HPKE-opened the ephemeral-sealed response with its own
/// wrapping secret; the provider store is empty on a taken context, so the
/// install MUST land on the actor.
#[cfg(feature = "testing")]
async fn handle_land_sender_key_response(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &str,
    sender_key: scp_protocol::crypto::sender_keys::SenderKey,
    epoch: u64,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_id_bytes = crate::context::state::context_id_to_bytes(context_id);

    // GATE first (FAIL-CLOSED, no cell borrow) — the Class-M registry enforces
    // epoch monotonicity + the poisoning ceiling and advances the authoritative
    // in-memory Class-M floor (durable at the next coalesced snapshot, coherently
    // with the Class-C install below) before we touch the store.
    if let Err(e) = deps.supervisor.check_and_advance_sender_epoch(
        &context_id_bytes,
        sender_did,
        epoch,
        scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
    ) {
        let e: ContextError = e.into();
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    // INSTALL onto the actor-owned store (Class-C coalesced).
    let ctx_id_hex = hex::encode(context_id_bytes);
    {
        let mut view = cell.class_c_view();
        // A `None` crypto state is a context with no MLS group (broadcast); the
        // §9.16.2 pull-response install never applies there — fail closed.
        let Some(cs) = view.mode_mut().crypto_mut() else {
            let err = ContextError::CryptoFailed(
                "no MLS crypto state for sender-key install (context has no group)".to_string(),
            );
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        };
        cs.sender_key_store
            .set_unchecked(&ctx_id_hex, sender_did, sender_key);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Handle [`MessagingCommand::SeedPeerPseudonym`] (actor-shape, test-only).
///
/// §9.10.4 test seam: records a peer pseudonym exactly as a delivered
/// `PseudonymAnnouncement` would. Broadcast contexts carry no peer registry —
/// rejects so a mis-targeted test fails loudly. Extracted from the dispatch
/// match so the dispatcher stays a flat one-line-per-arm router.
#[cfg(feature = "testing")]
fn handle_seed_peer_pseudonym(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    member_did: scp_did::DID,
    pseudonym: [u8; 32],
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Pure read via `Deref` on the cell (the error branch needs the context id).
    let context_id = cell.handle.context_id().to_owned();
    // Coalesced Class-C mutation (the run loop persists on `mutated`); route the
    // peer-registry insert through the non-persisting `class_c_view`.
    let mut view = cell.class_c_view();
    let result = view.routing_mut().peer_registry_mut().map_or(
        Err(ContextError::NotPseudonymousContext { context_id }),
        |reg| {
            reg.insert(member_did, pseudonym);
            Ok(())
        },
    );
    // ADR-049 §Decision 9 / finding N1: the peer-registry insert is a coalesced
    // Class-C mutation with NO co-located persist — its durability rides ENTIRELY
    // on the run loop marking itself dirty from this handler's `mutated` flag. A
    // successful insert therefore MUST report `ok_mutated`, else a ≤50 ms crash
    // silently loses the seeded pseudonym. The reject arm
    // (`NotPseudonymousContext`, a broadcast context with no peer registry) never
    // touched the view, so it reports `err` (unmutated).
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

/// Handle [`MessagingCommand::TestInsertMember`] (actor-shape, test-only).
///
/// Records a member directly into role state — `members` plus a role
/// `assignment` — exactly as an executed `AddMember` governance action would
/// for those two fields, but without the MLS Welcome / governance round-trip
/// (which a single-node test cannot drive: the bridge governance key resolver
/// only resolves DID-document-published identities). Used by tests that need a
/// multi-member context (e.g. exporter selection over a 2+ member membership
/// map). Rejects an inactive context so a mis-targeted test fails loudly.
#[cfg(feature = "testing")]
fn handle_test_insert_member(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    member_did: &scp_did::DID,
    role: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Coalesced Class-C structural mutation (the run loop persists on `mutated`):
    // the member roster insert, the system role assignment, and the membership
    // add all route through the non-persisting `class_c_view`. A member ADD is a
    // coalesce-window-rollback-acceptable structural change (ADR-049 §9), not a
    // downward-auth GROW, so it needs no fail-closed Class-S persist.
    // Pre-mutation gate: an inactive context rejects BEFORE any `class_c_view`
    // write, so nothing was mutated (`err`, mutated:false). Split OUT of the
    // closure below so this clean reject is distinguishable from a post-mutation
    // failure.
    if let Err(e) = crate::context::state::require_active(&cell.handle) {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }
    let result = (|| {
        let tokens = {
            let mut view = cell.class_c_view();
            let mut role_state = view.role_state_class_c_mut();
            role_state.members_mut().insert(member_did.to_string());
            role_state
                .system_assign_role(member_did.as_ref(), role, &*deps.clock)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?
        };
        cell.class_c_view().membership_class_c_mut().add_member(
            member_did.clone(),
            role.to_owned(),
            tokens,
        );
        Ok(())
    })();
    // ADR-049 §Decision 9 / finding N1: the roster insert, role assignment, and
    // membership add are coalesced Class-C mutations with NO co-located persist —
    // durability rides on this handler's `mutated` flag. A `mutated:false` here
    // silently lost the inserted member on a ≤50 ms crash. The `members_mut()`
    // insert lands BEFORE the only fallible step (`system_assign_role`), so ANY
    // error out of the closure is a PARTIAL mutation → `err_mutated` (persist the
    // partial state so the coalesced flush keeps the snapshot in sync); success →
    // `ok_mutated` so the member + role survive respawn.
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

/// Handle [`MessagingCommand::TestGrantMemberCapability`] (actor-shape,
/// test-only).
///
/// Inserts `capability` into the member's §7.2.2 Tier-2
/// `role_state.member_capabilities` cache — exactly as the runtime fixture
/// `authorizing_role_state` grants `Capability::OutletCallAll`, and as the
/// governance role-execution path does at `governance.rs` — but without the
/// round-trip. The insert is a Class-S authority GROW that DELIBERATELY
/// bypasses the capability ceiling (matching the fixture): the ceiling is
/// downward-auth Class-S with no structural-view `&mut`, so this seam reaches
/// `role_state.member_capabilities` through the whole-state
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep)
/// combinator (fail-closed persist; the grant is KEPT in memory even if the
/// durable write fails, and the run loop retries it). Rejects an inactive
/// context (pre-mutation gate → clean `err`, `mutated:false`) and an
/// unrecognized capability stem.
#[cfg(feature = "outlet-capability-test-grant")]
async fn handle_test_grant_member_capability(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &scp_did::DID,
    capability: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    use scp_protocol::context::roles::Capability;

    if let Err(e) = crate::context::state::require_active(&cell.handle) {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }
    // Parse the capability stem BEFORE any mutation so an unrecognized stem is a
    // clean `err`/`mutated:false` reject (nothing was written).
    let Some(cap) = Capability::new(capability) else {
        let err =
            ContextError::MembershipFailed(format!("unrecognized capability stem '{capability}'"));
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err(sketch);
    };
    let member = member_did.to_string();
    let commit = cell.commit_class_s_keep(deps, context_id, move |mut view| {
        view.rest_mut()
            .role_state
            .member_capabilities
            .entry(member)
            .or_default()
            .insert(cap);
        Ok(())
    });
    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, commit).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(err)) => {
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "test_grant_member_capability exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };
    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::TestInstallAccessKey`] (actor-shape, test-only).
///
/// Stores a member's access key into the context's access key store — exactly
/// as an executed `GenerateContextAccessKey` (or the deferred §9.17 production
/// pull-response ingest, #2050) would for that one entry — but with a key the
/// harness recovered through the REAL §9.17 pull round trip, not one minted
/// locally. Rejects an inactive context so a mis-targeted test fails loudly.
/// Routes the store through the non-persisting `class_c_view` (the run loop
/// persists on `mutated`), mirroring [`generate_context_access_key`](crate::context::queries_helpers::generate_context_access_key).
#[cfg(feature = "testing")]
fn handle_test_install_access_key(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    member_did: &str,
    key: scp_protocol::crypto::access_keys::AccessKey,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let result = (|| {
        crate::context::state::require_active(&cell.handle)?;
        cell.class_c_view()
            .access_mut()
            .access_key_store
            .set(context_id, member_did, key);
        Ok(())
    })();
    // Mirror the reference handler
    // [`handle_generate_context_access_key_actor`]: a successful install
    // mutated the persisted `access_key_store`, so mark the actor dirty
    // (`ok_mutated`) — otherwise a joiner restored from its spawn-time snapshot
    // would lose the pulled §9.17 keys. The only error path is `require_active`
    // failing BEFORE any write, so on error nothing was mutated (`err`).
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

/// Handle [`MessagingCommand::SendMessage`] (actor-shape): reserve a
/// sequence number via RAII on the actor-owned `send_tracker`,
/// delegate to
/// [`messaging_helpers::send_message`](crate::context::messaging_helpers::send_message)
/// under a 30s timeout, commit the reservation on success or let it
/// drop (RAII rollback) on any failure path.
///
/// The reservation is taken first against `state.send_tracker`, then
/// the helper is called with `state`. The reservation is moved
/// (consumed by `commit()` or dropped for rollback) before any other
/// borrow of `state.send_tracker` so the actor-owned RAII tracker
/// stays correct.
#[allow(clippy::too_many_arguments)]
async fn handle_send_message(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    params: scp_protocol::context::params::ContextParams,
    sender_did: &scp_did::DID,
    payload: &[u8],
    signing_key: Option<&crate::context::actor::commands::SigningKeyBytes>,
    signing_key_id: scp_did::SigningKeyId,
    source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // ADR-049 §9 Class-S cell seam: held so `send_message` (which reaches the
    // spending-nonce leaf) receives it. The send-tracker bookkeeping is a
    // COALESCED Class-C mutation (the run loop persists on `mutated`), so it
    // routes through the non-persisting `class_c_view` — its `&mut` borrow ends
    // before the cell-taking `send_message` call.
    let mut view = cell.class_c_view();
    // Step 1: reserve + commit a sequence number against the
    // actor-owned tracker. The wire sequence is still driven by
    // `MembershipState::next_sequence_number` inside the helper —
    // `send_tracker` is the actor-shape parallel that becomes
    // authoritative in a follow-on Phase 2 sub-chunk. We commit the
    // reservation BEFORE the helper call (not after) because the
    // helper takes `&mut state` which would conflict with an active
    // `&mut state.send_tracker` reservation guard. On failure we
    // manually decrement to mirror the RAII rollback semantics; the
    // helper does not read `send_tracker` so the early commit is
    // observationally identical.
    let high_water_before = view.send_tracker_mut().last_issued();
    {
        let reservation = SequenceReservation::reserve(view.send_tracker_mut());
        reservation.commit();
    }

    // Step 2: rebuild an ephemeral `ContextHandle` and transition it to
    // `Active` so the helper observes the same handle state every FFI
    // bridge passes today.
    let handle = ContextHandle::new(context_id.to_owned(), params);
    if let Err(e) = handle.transition_to(&scp_protocol::context::ContextState::Active) {
        // Manual rollback — restore the high-water mark prior to
        // reservation. `from_persisted` rebuilds the tracker at the
        // given last-issued value.
        *view.send_tracker_mut() = SendSequenceTracker::from_persisted(high_water_before);
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    // Step 3: delegate to the actor-shape helper, wrapped in the
    // per-call transport-timeout budget.
    let sk = signing_key.map(crate::context::actor::commands::SigningKeyBytes::to_signing_key);
    let sk_ref = sk.as_ref();
    // `send_message` is the spending-nonce-bearing path and takes the cell; the
    // `state` borrow above has ended (NLL) so `cell` is free here. The failure
    // arms re-derive the bare state for the send-tracker rollback.
    let send_fut = crate::context::messaging_helpers::send_message(
        cell,
        deps,
        &handle,
        sender_did,
        payload,
        sk_ref,
        signing_key_id,
        source_provenance,
        spending_ucan,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, send_fut).await {
        Ok(Ok(())) => {
            // Send succeeded — keep the committed high-water mark.
            (Outcome::ok_mutated(()), Ok(()))
        }
        Ok(Err(e)) => {
            // Rollback on failure (coalesced Class-C via `class_c_view`).
            *cell.class_c_view().send_tracker_mut() =
                SendSequenceTracker::from_persisted(high_water_before);
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            *cell.class_c_view().send_tracker_mut() =
                SendSequenceTracker::from_persisted(high_water_before);
            let err = ContextError::TransportTimeout(format!(
                "send_message exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::DeliverIncoming`] (actor-shape).
///
/// `deliver_incoming` is sync (no awaits in the actor body), so we
/// wrap it in `async {...}` to keep the per-call transport-timeout
/// budget. Precedent: `handlers::broadcast::handle_broadcast_*` wraps
/// sync helpers the same way.
async fn handle_deliver_incoming(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    envelope_bytes: &[u8],
    reply: crate::context::actor::commands::DeliverIncomingReply,
) -> Outcome<()> {
    // ADR-049 §9 (RED-CS3): a fail-closed-persist obligation populated when the
    // receive cascade performs a downward-auth mutation (a `suspended_capabilities`
    // GROW or an `AssignRole` `member_capabilities` replacement). Owned HERE as a
    // `&mut Option<ClassSCommitToken>` sink, at the cell boundary, so the obligation
    // is `commit`ted (a fail-closed, keep-direction persist) once the borrowing
    // `class_c_view` drops — it must not ride only the coalesced persist (a ≤50ms
    // crash would silently re-grant the member's removed authority). The token
    // carrier (vs. the prior `bool`) makes a populated-but-undischarged obligation a
    // Drop-guard PANIC in debug/CI, so a missed discharge cannot slip through.
    let mut downward_auth_obligation: Option<crate::context::actor::class_s::ClassSCommitToken> =
        None;
    // Coalesced Class-C mutation (the run loop persists on `mutated`); the receive
    // cascade reaches its Class-C fields through the non-persisting `class_c_view`
    // (sequence/reorder/receive buffers, membership[read], role[read], routing,
    // ConsequenceStateSplit Class-C only). The downward-auth mutations it can make
    // — a consequence-engine capability suspension or an `AssignRole` demotion —
    // populate `downward_auth_obligation` and are persisted fail-closed below, not
    // through the view.
    let (outcome, reply_result) = {
        let mut view = cell.class_c_view();
        let deliver_fut = async {
            crate::context::messaging_helpers::deliver_incoming(
                &mut view,
                deps,
                context_id,
                envelope_bytes,
                &mut downward_auth_obligation,
            )
            .await
        };

        match tokio::time::timeout(HANDLER_TIMEOUT, deliver_fut).await {
            Ok(Ok(opt)) => (Outcome::ok_mutated(()), Ok(opt)),
            Ok(Err(e)) => {
                let sketch = outcome_error_sketch(&e);
                (Outcome::err_mutated(sketch), Err(e))
            }
            Err(_elapsed) => {
                let err = ContextError::TransportTimeout(format!(
                    "deliver_incoming exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
                ));
                let sketch = outcome_error_sketch(&err);
                (Outcome::err_mutated(sketch), Err(err))
            }
        }
        // `view` drops here, releasing the `&mut cell` borrow.
    };

    // ADR-049 PR-7 §9.16.2 answer transmit: a PULL request handled inside
    // `decrypt_and_dispatch` enqueued its ephemeral-sealed answer on the actor's
    // `pending_distributions`. The deliver view has dropped; re-acquire the
    // Class-C crypto view and MLS-wrap + transport-send the queued answer(s)
    // through the existing drain path (reused verbatim from the join / rotate
    // transmit). A no-op when nothing was queued (the ordinary case). The drain
    // is best-effort by construction (per-recipient send failures are logged, the
    // requester recovers via a fresh request), so its `Result` — which cannot
    // actually error for the actor's in-memory `std::mem::take` drain — is not
    // allowed to fail the just-completed delivery ack.
    {
        let mut view = cell.class_c_view();
        let _ = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
            deps,
            view.mode_mut().crypto_mut(),
            context_id,
        )
        .await;
    }

    // Fail-closed persist of an applied downward-auth mutation (ADR-049 §9,
    // keep-direction): the mutation (suspension or `AssignRole` demotion) is
    // already in memory; committing the obligation's token makes it durable before
    // acking, closing the coalesce-window crash hole (RED-CS3). `take()` discharges
    // the Drop guard. On persist failure the mutation STAYS in memory (the token's
    // `commit` is keep-direction) and the §9 durability error is surfaced in place
    // of the original reply (durability is the security obligation). When the
    // deliver itself already errored (`Ok(Err(_))`), that original cause is
    // preserved in the surfaced message so it is not lost. Skipped (the obligation
    // stays `None`) when no downward-auth mutation occurred (the ordinary coalesced
    // persist via `mutated` is sufficient).
    let reply_result = if let Some(token) = downward_auth_obligation.take() {
        match token.commit(cell, deps, context_id).await {
            Ok(()) => reply_result,
            Err(persist_err) => Err(match reply_result {
                Ok(_) => persist_err,
                Err(deliver_err) => ContextError::PersistenceFailed(format!(
                    "{persist_err} (after a delivery error: {deliver_err})"
                )),
            }),
        }
    } else {
        reply_result
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::DrainEvents`] (actor-shape).
///
/// Drains the actor-owned receive buffer in place. Returns the drained
/// events on the reply channel; never propagates `ContextNotRegistered`
/// because the actor IS the registration.
async fn handle_drain_events(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    reply: crate::context::actor::commands::DrainEventsReply,
) -> Outcome<()> {
    // Coalesced Class-C mutation (the run loop persists on `mutated`); drain the
    // receive buffer through the non-persisting `class_c_view`.
    let mut view = cell.class_c_view();
    let drain_fut = async { view.receive_buffer_mut().drain() };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, drain_fut).await {
        Ok(events) => (Outcome::ok_mutated(()), Ok(events)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "drain_events exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::DrainEquivocationAlerts`] (actor-shape).
///
/// Extracts only the `EquivocationDetected` alerts from the actor-owned
/// receive buffer, leaving every other buffered event in place and in
/// order for the SDK's normal receive polling. This is the targeted
/// counterpart to [`handle_drain_events`]: the reconnection driver uses
/// it so catch-up does not destroy buffered application traffic
/// (messages, membership changes) that arrived during the sync.
async fn handle_drain_equivocation_alerts(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    reply: crate::context::actor::commands::DrainEventsReply,
) -> Outcome<()> {
    // Coalesced Class-C mutation (the run loop persists on `mutated`); drain the
    // equivocation alerts through the non-persisting `class_c_view`.
    let mut view = cell.class_c_view();
    let drain_fut = async { view.receive_buffer_mut().drain_equivocation_alerts() };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, drain_fut).await {
        Ok(events) => (Outcome::ok_mutated(()), Ok(events)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "drain_equivocation_alerts exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::SendPseudonymAnnouncement`] (actor-shape).
async fn handle_send_pseudonym_announcement(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    sender_did: &scp_did::DID,
    signing_key: &crate::context::actor::commands::SigningKeyBytes,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle.transition_to(&scp_protocol::context::ContextState::Active) {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let sk = signing_key.to_signing_key();
    let send_fut = crate::context::messaging_helpers::send_pseudonym_announcement(
        cell, deps, &handle, sender_did, &sk,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, send_fut).await {
        Ok(()) => (Outcome::ok_mutated(()), Ok(())),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "send_pseudonym_announcement exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::ReportDegradedMode`] (actor-shape).
///
/// Synchronous pure-emit handler: delegates to the actor-shape
/// [`queries_helpers::report_degraded_mode`](crate::context::queries_helpers::report_degraded_mode)
/// which writes a `DegradedMode` event into `state.receive_buffer` (and
/// the optional broadcast channel on `deps.event_tx`) only when the
/// supplied `compat` is the `DegradedMode` variant. All other
/// `VersionCompatibility` cases are silent no-ops. The handler never
/// awaits transport / storage so no `tokio::time::timeout` wrapper is
/// required. Always replies `Ok(())` and reports
/// [`Outcome::ok_mutated`] because the receive buffer may have grown by
/// one event.
fn handle_report_degraded_mode(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    compat: scp_protocol::envelope::VersionCompatibility,
    unsupported_features: Vec<String>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Coalesced Class-C mutation (the run loop persists on `mutated`); the
    // `DegradedMode` event lands in the receive buffer via the non-persisting
    // `class_c_view`. `report_degraded_mode` is field-narrowed to the single
    // `&mut ReceiveBuffer` it mutates.
    crate::context::queries_helpers::report_degraded_mode(
        cell.class_c_view().receive_buffer_mut(),
        deps,
        context_id,
        compat,
        unsupported_features,
    );
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Handle [`MessagingCommand::BuildLocalCheckpoint`] (actor-shape).
///
/// Forces a signed consistency checkpoint from the current event-log
/// state via
/// [`force_create_checkpoint_view`](crate::context::queries_helpers::force_create_checkpoint_view),
/// which reaches the three Class-C checkpoint fields through a
/// non-persisting [`class_c_view`](crate::context::actor::class_s::ClassSCell::class_c_view)
/// (the run loop coalesce-persists), then broadcasts it to peers via
/// [`send_checkpoint`](crate::context::messaging_helpers::send_checkpoint)
/// (best-effort — a transport failure is logged but does not fail the
/// command). The send happens inside the actor turn so the FFI-layer
/// reconnection driver never needs `send_checkpoint` (a `pub(crate)`
/// helper) across the crate boundary: Phase 3 (`event_log_sync`) is one
/// mailbox round-trip — build + broadcast — and the reply carries the
/// built checkpoint so the driver can record it.
///
/// Synchronous (the send body has no awaits); no
/// `tokio::time::timeout` wrapper required. Always replies
/// `Ok(checkpoint)`; reports [`Outcome::ok_mutated`] because the
/// checkpoint ring and counters changed.
async fn handle_build_local_checkpoint(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &scp_did::DID,
    signing_key: &crate::context::actor::commands::SigningKeyBytes,
    reply: crate::context::actor::commands::BuildLocalCheckpointReply,
) -> Outcome<()> {
    let sk = signing_key.to_signing_key();
    let now = deps.clock.now_secs();
    // Build + retain the checkpoint through the non-persisting Class-C view
    // (coalesced — the run loop persists on `mutated`). The `&mut view` borrow
    // ends before the shared-`&` `send_checkpoint` read below (NLL).
    let checkpoint = {
        let mut view = cell.class_c_view();
        let broadcast_context_is_none = view.broadcast_class_c_mut().is_none();
        let mls_epoch = view.epoch_mut().mls_epoch;
        crate::context::queries_helpers::force_create_checkpoint_view(
            &mut view,
            context_id,
            broadcast_context_is_none,
            mls_epoch,
            sender_did,
            &sk,
            now,
            &*deps.event_log,
        )
    };

    // Broadcast the freshly-built checkpoint to peers over the regular
    // encrypted inner-envelope pipeline (§9.9.3). Best-effort: a transport
    // failure is logged but never fails the build (the reconnection driver
    // still receives + records the local checkpoint). Mirrors the
    // periodic `create_and_broadcast_checkpoint_if_due` contract.
    // ADR-049 PR-7: `send_checkpoint` takes `&mut ClassSCell` (Send) and seals on
    // the actor crypto view; `cell` is free here (the checkpoint-build view borrow
    // above ended) and `checkpoint` is owned.
    if let Err(e) = crate::context::messaging_helpers::send_checkpoint(
        deps,
        cell,
        context_id,
        sender_did,
        &sk,
        &checkpoint,
    )
    .await
    {
        tracing::warn!(
            context_id,
            error = %e,
            "failed to broadcast forced consistency checkpoint to peers \
             (best-effort; build not rolled back) (§9.9.3)"
        );
    }

    let _ = reply.send(Ok(checkpoint));
    Outcome::ok_mutated(())
}

/// Handle [`MessagingCommand::CompareRemoteCheckpoint`] (actor-shape).
///
/// Compares a remote checkpoint against local event-log state via
/// [`compare_remote_checkpoint`](crate::context::queries_helpers::compare_remote_checkpoint),
/// which verifies membership + the checkpoint Ed25519 signature, compares
/// Merkle roots, and emits `ContextEvent::EquivocationDetected` on a
/// `Divergent` result (§9.9.3). Synchronous; forwards the typed
/// `Result<CheckpointComparison, ContextError>` verbatim so the caller
/// sees the `Behind` (consistency-proof catch-up seam, specified
/// separately) / `Ahead` / `Consistent` / `Divergent`
/// classification and any `MemberNotFound` / `CryptoFailed` error.
fn handle_compare_remote_checkpoint(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    reply: crate::context::actor::commands::CompareRemoteCheckpointReply,
) -> Outcome<()> {
    // Coalesced Class-C mutation (the run loop persists on `mutated`); the
    // equivocation dedup set + receive-buffer emit land through the non-persisting
    // `class_c_view`. `compare_remote_checkpoint` is narrowed to the Class-C view:
    // it reads membership and mutates `last_seen_remote_checkpoint` + `receive_buffer`.
    let result = crate::context::queries_helpers::compare_remote_checkpoint(
        &mut cell.class_c_view(),
        deps,
        context_id,
        remote,
    );
    let mutated = result.is_ok();
    let _ = reply.send(result);
    if mutated {
        Outcome::ok_mutated(())
    } else {
        Outcome::ok(())
    }
}

/// Handle [`MessagingCommand::SendHeartbeat`] (actor-shape).
///
/// Sends a suppression-detection heartbeat (§9.9.2) to context peers via
/// [`send_heartbeat`](crate::context::messaging_helpers::send_heartbeat),
/// which routes an EMPTY-payload [`MessageType::Heartbeat`](scp_protocol::envelope::inner::MessageType::Heartbeat)
/// envelope through the regular encrypt-and-send path. The caller (the
/// bridge/SDK subscribe-path scheduler) supplies `sender_did` + `signing_key`
/// per-call — the signing key is not actor-owned state. Routing the send
/// through the actor serializes it with the context's other sends.
///
/// Forwards the `send_heartbeat` result verbatim: `Ok(())` on success, or the
/// transport error if every fan-out send fails. Although a heartbeat does not
/// consume the application content SEQUENCE (it uses sequence `0`), sealing the
/// encrypted `Heartbeat` envelope advances the actor-owned MLS group's
/// send-ratchet GENERATION — per-context crypto state (Class-C, coalesced at the
/// next snapshot) that a `mutated: false` would silently drop on a ≤50ms crash.
/// This handler therefore reports [`Outcome::ok_mutated`] / [`Outcome::err_mutated`]
/// (the seal runs BEFORE the fan-out, so even an empty-routing no-op and a
/// post-seal transport failure have already advanced the generation), matching
/// [`handle_send_message`] and `handle_build_local_checkpoint`. See ADR-049 §9
/// (the MLS own-leaf send-generation residual, tracked in #2149).
// `needless_pass_by_ref_mut`: the `&mut ClassSCell` is only read (`&*cell`), but
// the `&mut` is load-bearing for Send — this async handler holds the cell borrow
// across the `send_heartbeat` await, and `&mut ClassSCell` is Send whereas
// `&PerContextState` (`!Sync`) would be `!Send` and break the spawned actor
// future. Same rationale as the module-level allow in the `*_helpers` modules.
#[allow(
    clippy::needless_pass_by_ref_mut,
    reason = "&mut ClassSCell held across await must be Send; &PerContextState is !Send (ADR-049 Decision 7)"
)]
async fn handle_send_heartbeat(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &scp_did::DID,
    signing_key: &crate::context::actor::commands::SigningKeyBytes,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Take `&mut ClassSCell` (Send) rather than `&PerContextState` (`!Sync`, so
    // `&PerContextState` is `!Send`): this async handler holds the borrow across
    // the `send_heartbeat` await, so the borrow must be `Send` for the spawned
    // actor future. `send_heartbeat` reads the shared `&*cell` in its sync
    // prelude (ADR-049 Decision 7).
    let sk = signing_key.to_signing_key();
    let result =
        crate::context::messaging_helpers::send_heartbeat(deps, cell, context_id, sender_did, &sk)
            .await;
    match result {
        Ok(()) => {
            let _ = reply.send(Ok(()));
            // The encrypted-context heartbeat SEALS an MLS `Heartbeat` envelope,
            // advancing the actor-owned MLS group's send-ratchet generation
            // (Class-C; coalesced with the next snapshot). Report `mutated` so the
            // actor coalesces that advance — the seal in `encrypt_and_send` runs
            // BEFORE the empty-routing no-op check, so even a peerless heartbeat
            // has already advanced the generation. (A broadcast-context heartbeat
            // seals nothing; over-marking `mutated` there is harmless — it only
            // triggers a redundant coalesced snapshot of unchanged state.)
            Outcome::ok_mutated(())
        }
        Err(e) => {
            // A fan-out transport failure can occur AFTER the seal already advanced
            // the generation, so report `mutated` on the error path too (the seal's
            // ratchet advance must still be coalesced) — same disposition as
            // `handle_send_message`'s `err_mutated` failure arm.
            let sketch = outcome_error_sketch(&e);
            let _ = reply.send(Err(e));
            Outcome::err_mutated(sketch)
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome sink helpers
// ---------------------------------------------------------------------------

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink given a borrowed error that cannot be
/// cloned. The outcome consumer only reads `mutated` (on the actor's
/// dispatch loop) — the `result` field carries a representative
/// variant (preserving the `TransportTimeout` / `TransportFailed` /
/// `CryptoFailed` classification when recoverable from the
/// `Display` string). This is a shim workaround; commit 12 deletes
/// the two-channel pattern by making `Outcome`'s `Err` consumption
/// the sole error path.
fn outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::TransportTimeout(msg) => ContextError::TransportTimeout(msg.clone()),
        ContextError::TransportFailed(msg) => ContextError::TransportFailed(msg.clone()),
        ContextError::CryptoFailed(msg) => ContextError::CryptoFailed(msg.clone()),
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::MemberNotFound(msg) => ContextError::MemberNotFound(msg.clone()),
        ContextError::ContextNotRegistered(msg) => ContextError::ContextNotRegistered(msg.clone()),
        ContextError::ContextNotActive => ContextError::ContextNotActive,
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}
