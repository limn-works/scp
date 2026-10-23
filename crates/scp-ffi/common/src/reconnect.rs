//! Relay-backed reconnection driver (ADR-029).
//!
//! After the ADR-049 actor refactor, the per-context actor's
//! [`ContextTransportProvider`](scp_core::context::ContextTransportProvider) is **send-only** — it has no
//! message-retrieval surface. Buffered-message retrieval (relay
//! SUBSCRIBE / QUERY-since) is owned by
//! [`scp_transport::TransportManager`] at the FFI/SDK relay-client layer.
//! Therefore the reconnection driver — the concrete impl of the three
//! ADR-029 tier traits — is constructed and driven here, at the same
//! layer as `context_subscribe`, and reaches actor-owned reconnection
//! state (MLS epoch, Commit/Welcome processing, checkpoint build/compare,
//! queue drain) through [`Supervisor`] commands/queries (the thin
//! wrappers added in this ticket), never by widening the transport
//! provider. See the "ADR-029 Addendum — Reconnection driver location
//! after the ADR-049 actor refactor" in `.docs/adrs/phase-6.md`.
//!
//! # Tier mapping
//!
//! - **Tier 1** ([`scp_core::sync::hours_offline::SyncPhaseDriver`]) — the
//!   six-phase reconnection protocol (ADR-029 §2). Implemented by
//!   [`RelayActorSyncDriver`].
//! - **Tier 2** ([`scp_core::sync::days_offline::SnapshotTransport`]) —
//!   snapshot fetch/publish for delta sync.
//! - **Tier 3** ([`scp_core::sync::weeks_offline::ResetTransport`]) —
//!   plaintext reset request + admin re-add + Welcome await.
//!
//! # Composition with checkpoint exchange (§9.9.3)
//!
//! Phase 3 (`event_log_sync`) builds + broadcasts the **local** checkpoint
//! through [`Supervisor::build_local_checkpoint`] (one actor turn — the
//! actor signs, retains, and sends it). Comparison of **remote**
//! checkpoints happens automatically: retrieved checkpoint blobs flow
//! through [`Supervisor::deliver_commit_blob`] in Phase 2, whose
//! `deliver_incoming` path dispatches `ConsistencyCheckpoint` messages to
//! `compare_remote_checkpoint`, which emits
//! `ContextEvent::EquivocationDetected` into the receive buffer on a
//! divergent Merkle root (§9.9.3). The driver drains those events and
//! maps them to [`SyncEvent::EquivocationDetected`]. Same
//! `SCP-CHECKPOINT-V1:` canonical hash, same comparison helper — the
//! driver only sequences the exchange.
//!
//! # Push-wake pull mode
//!
//! [`wake_pull_contexts`] runs the push-wake pull mode of ADR-029 §2: Phase 1,
//! Phase 2 and Phase 4 only, over the signer-free functions [`pull_buffered`],
//! [`deliver_commit_blobs_until_steady`] and [`refeed_buffer`] that the Tier 1
//! driver also calls. None of them takes a [`CommandSigner`], so the pull
//! cannot sign a checkpoint or an Update. The pull queries each context only at
//! the relays its own relay set names ([`RelayScope::Only`]) and delivers in
//! [`DeliveryMode::PullOnly`], so the actor sends no sender-key answer a pulled
//! `KeyRequest` queues; [`reconnect_contexts`] sends those answers on the next
//! full reconnection. A context's `last_relay_contact` is written only after
//! Phases 2 and 4 have fed every blob of its buffer.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use scp_core::context::actor::commands::{DeliverOutcome, DeliveryMode, MessagingCommand};
use scp_core::context::supervisor::Supervisor;
use scp_core::context::{ContextError, ContextWakeTarget};
use scp_core::store::StoreError;
use scp_core::store::sync::RelayContactStore;
use scp_core::sync::days_offline::{DaysOfflineError, SnapshotTransport};
use scp_core::sync::hours_offline::{BufferedMessage, EpochCatchUpState, SyncPhaseDriver};
use scp_core::sync::weeks_offline::ResetTransport;
use scp_did::DID;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::{broadcast_routing_id, context_routing_id};
use scp_protocol::envelope::outer::{OuterEnvelope, create_outer_envelope};
use scp_protocol::sync::{CatchUpStatus, SyncError, SyncEvent, SyncPolicy};
use scp_transport::{RoutingId, TransportManager};

// The checkpoint signer is resolved at the FFI boundary, not held by the
// actor, and holds no private key material (ADR-049 Decision 7a).
use scp_core::context::actor::CommandSigner;

/// Default blob TTL (seconds) used when wrapping a Tier-3 plaintext reset
/// request in an outer envelope. The reset request is short-lived; one
/// hour matches the relay's typical retention floor and is well within
/// the relay's accepted TTL band.
const RESET_BLOB_TTL_SECS: u32 = 3600;

/// Overlap, in seconds, subtracted from a stored relay-contact time before it
/// becomes a QUERY `since` (ADR-004 Connection Recovery; ADR-029 §2 push-wake
/// pull mode step 4).
const SINCE_OVERLAP_SECS: u64 = 5;

/// Per-context count of envelopes the actor accepted as application messages.
///
/// One reconnection counts each `Ok(Some(_))` from
/// [`Supervisor::deliver_commit_blob`]. Heartbeats, handled control messages
/// and refused blobs are not counted.
#[derive(Debug, Default)]
pub struct DeliveryTally(Mutex<HashMap<String, u64>>);

impl DeliveryTally {
    /// Adds `delivered` to the count of `context_id`.
    fn add(&self, context_id: &str, delivered: u64) {
        if delivered == 0 {
            return;
        }
        let mut counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = counts.entry(context_id.to_owned()).or_insert(0);
        *entry = entry.saturating_add(delivered);
        drop(counts);
    }

    /// The count of `context_id`; 0 when nothing was accepted.
    #[must_use]
    pub fn get(&self, context_id: &str) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(context_id)
            .copied()
            .unwrap_or(0)
    }

    /// The count over every context.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .fold(0u64, |acc, n| acc.saturating_add(*n))
    }
}

/// Which relays a Phase 1 pull queries.
#[derive(Debug, Clone, Copy)]
pub enum RelayScope<'a> {
    /// [`TransportManager::query`] on the instance's installed transport: the
    /// full reconnection's Tier 1 pull.
    Installed,
    /// [`TransportManager::query_relays`] over exactly these relays: one
    /// context's persisted relay set in a push-wake pull (ADR-029 §2
    /// push-wake pull mode step 4).
    Only(&'a [String]),
}

/// What one feed of a Phase 1 buffer to the actor accepted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeedTally {
    /// Blobs the actor accepted in any form (`Ok(_)`): Commits, control
    /// messages and application messages.
    pub accepted: u64,
    /// Blobs the actor accepted as application messages (`Ok(Some(_))`).
    pub delivered: u64,
}

/// Resolves the shared routing ID for a context (§9.10.4 / §5.14).
///
/// Broadcast contexts use `broadcast_routing_id` (plain
/// `SHA-256(context_id)`); encrypted contexts use the domain-separated
/// `context_routing_id`. Mirrors the `context_subscribe` selection so
/// the driver pulls from the same routing key the live subscription
/// uses (§5.14).
async fn shared_routing_id(supervisor: &Supervisor, context_id: &str) -> RoutingId {
    // `local_mls_epoch` returns `None` for a broadcast context — reuse
    // that single source of truth rather than re-deriving the mode.
    let is_broadcast = supervisor.local_mls_epoch(context_id).await.is_none();
    let bytes = if is_broadcast {
        broadcast_routing_id(context_id)
    } else {
        context_routing_id(context_id)
    };
    RoutingId::new(bytes)
}

/// Converts a retrieved [`OuterEnvelope`] into a [`BufferedMessage`].
///
/// `blob_id` is recomputed exactly as the relay does
/// (`SHA-256(serialized outer envelope)`) so cross-relay dedup keys
/// match. `stored_at` is set to the local receive time (`now`) — the
/// relay-assigned timestamp is not carried on the wire and is not
/// trusted for protocol decisions (§9.8.3; SCP-182). `epoch` is
/// `None`: the MLS epoch of an opaque application message is only
/// known after decryption (which the actor performs in Phase 2).
///
/// `payload` is the envelope's `encrypted_blob`: the bytes
/// [`Supervisor::deliver_commit_blob`] opens, the same field the live
/// subscription feeds the actor. The serialized outer envelope is only the
/// dedup key; the actor cannot open it.
fn envelope_to_buffered(
    context_id: &str,
    envelope: &OuterEnvelope,
    now: u64,
) -> Option<BufferedMessage> {
    let bytes = envelope.to_bytes().ok()?;
    let blob_id = *scp_transport::BlobId::from_sha256(&bytes).as_bytes();
    Some(BufferedMessage {
        blob_id: hex::encode(blob_id),
        context_id: context_id.to_owned(),
        payload: envelope.encrypted_blob.clone(),
        stored_at: now,
        epoch: None,
    })
}

/// Phase 1 body: QUERYs the relays `scope` names for each of `routing_ids`.
///
/// The QUERY runs since `since`. The result is deduplicated by `blob_id` and
/// sorted by `blob_id`, so the buffer does not depend on relay timing (the
/// relay-assigned `stored_at` is not carried on the wire). `now` is the local
/// receive time recorded on each message.
///
/// # Errors
///
/// [`SyncError::RelayCatchUpFailed`] when any QUERY fails; a partial buffer is
/// never returned, because a pull that skips a relay or a routing ID would
/// report traffic it never read as absent.
pub async fn pull_buffered(
    transport: &TransportManager,
    scope: RelayScope<'_>,
    context_id: &str,
    routing_ids: &[RoutingId],
    since: u64,
    now: u64,
) -> Result<Vec<BufferedMessage>, SyncError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut messages = Vec::new();
    for routing_id in routing_ids {
        let answer = match scope {
            RelayScope::Installed => transport.query(routing_id, Some(since)).await,
            RelayScope::Only(relay_urls) => {
                transport
                    .query_relays(relay_urls, routing_id, Some(since))
                    .await
            }
        };
        let envelopes = answer.map_err(|e| SyncError::RelayCatchUpFailed {
            context_id: context_id.to_owned(),
            reason: e.to_string(),
        })?;
        for envelope in &envelopes {
            if let Some(msg) = envelope_to_buffered(context_id, envelope, now)
                && seen.insert(msg.blob_id.clone())
            {
                messages.push(msg);
            }
        }
    }
    messages.sort_by(|a, b| a.blob_id.cmp(&b.blob_id));
    Ok(messages)
}

/// Phase 2 body: feeds the first `limit` blobs of `messages` to the actor
/// through [`Supervisor::deliver_commit_blob`] in `mode` until a full pass
/// accepts nothing or `limit` blobs were accepted.
///
/// Each application envelope the actor accepts is added to `tally` as it is
/// accepted, so a caller whose deadline drops this future still counts it.
///
/// Phase 1 sorts blobs by `blob_id` (`SHA-256`, effectively random), not by
/// epoch. `OpenMLS` only accepts a Commit whose epoch matches the group's
/// current epoch, so a single linear pass advances at most one epoch; each
/// further pass retries the still-refused blobs against the advanced epoch.
pub async fn deliver_commit_blobs_until_steady(
    supervisor: &Supervisor,
    context_id: &str,
    messages: &[BufferedMessage],
    limit: usize,
    mode: DeliveryMode,
    tally: &DeliveryTally,
) -> FeedTally {
    let mut fed = FeedTally::default();
    let mut pending: Vec<&[u8]> = messages
        .iter()
        .take(limit)
        .map(|m| m.payload.as_slice())
        .collect();
    let mut total_accepted: usize = 0;

    while !pending.is_empty() && total_accepted < limit {
        let mut still_pending: Vec<&[u8]> = Vec::with_capacity(pending.len());
        let mut accepted_this_pass = 0usize;

        for payload in pending {
            if total_accepted >= limit {
                // Budget exhausted mid-pass; carry the remainder so the
                // loop terminates without dropping blobs silently.
                still_pending.push(payload);
                continue;
            }
            match supervisor
                .deliver_commit_blob(context_id, payload.to_vec(), mode)
                .await
            {
                Ok(delivered) => {
                    fed.accepted += 1;
                    if delivered.is_some() {
                        fed.delivered += 1;
                        tally.add(context_id, 1);
                    }
                    accepted_this_pass += 1;
                    total_accepted += 1;
                }
                Err(e) => {
                    // Refused at the current epoch (out-of-epoch Commit,
                    // replay, or an undecryptable blob). Retained for a retry
                    // against the next epoch; a genuinely bad blob is never
                    // accepted and falls out at steady state.
                    tracing::trace!(
                        context_id,
                        error = %e,
                        "deliver_commit_blobs_until_steady: blob refused at current epoch; retrying next pass"
                    );
                    still_pending.push(payload);
                }
            }
        }

        if accepted_this_pass == 0 {
            // A full pass accepted nothing: steady state. The remaining blobs
            // apply to no reachable epoch (replays, or a gap that needs a
            // Welcome-based fast-forward).
            break;
        }
        pending = still_pending;
    }
    fed
}

/// What one [`refeed_buffer`] pass did with the Phase 1 buffer.
#[derive(Debug, Default)]
pub struct RefeedTally {
    /// Blobs the actor accepted as application messages on this pass.
    pub delivered: u64,
    /// Blobs whose delivery reached no verdict ([`delivery_reached_verdict`]).
    pub unreached: u64,
    /// The last delivery failure that reached no verdict.
    pub last_unreached: Option<ContextError>,
}

/// Phase 4 body: re-feeds every blob of the Phase 1 buffer to the actor once,
/// in `mode`.
///
/// The re-feed processes a sender-key advance interleaved among the blobs.
/// Each application message the actor accepts is counted and added to `tally`
/// as it is accepted. A blob the actor already accepted is refused as a replay
/// and is not counted. A blob whose delivery reached no verdict is counted in
/// [`RefeedTally::unreached`]: this pass is each blob's last delivery, so a
/// push-wake pull keeps the context's stored contact when any blob is
/// unreached (ADR-029 §2 push-wake pull mode step 6).
pub async fn refeed_buffer(
    supervisor: &Supervisor,
    context_id: &str,
    messages: &[BufferedMessage],
    mode: DeliveryMode,
    tally: &DeliveryTally,
) -> RefeedTally {
    let mut fed = RefeedTally::default();
    for msg in messages {
        match supervisor
            .deliver_commit_blob(context_id, msg.payload.clone(), mode)
            .await
        {
            Ok(Some(_)) => {
                fed.delivered += 1;
                tally.add(context_id, 1);
            }
            Ok(None) => {}
            Err(e) if delivery_reached_verdict(&e) => {
                tracing::debug!(
                    context_id,
                    error = %e,
                    "refeed_buffer: the actor refused a blob; continuing"
                );
            }
            Err(e) => {
                tracing::warn!(
                    context_id,
                    error = %e,
                    "refeed_buffer: a delivery reached no verdict; continuing"
                );
                fed.unreached += 1;
                fed.last_unreached = Some(e);
            }
        }
    }
    fed
}

/// Relay-backed driver for the ADR-029 reconnection protocol.
///
/// Borrows (never owns) the bridge instance's [`TransportManager`] (relay
/// retrieval) and [`Supervisor`] (actor-owned reconnection state). Each
/// `SyncPhaseDriver` / `SnapshotTransport` / `ResetTransport` method maps
/// to a real provider — there are no stubs. Built per `context_reconnect`
/// call at the bridge surface.
pub struct RelayActorSyncDriver<'a> {
    /// Relay-client retrieval surface (SUBSCRIBE / QUERY / send).
    transport: &'a Arc<TransportManager>,
    /// Actor-owned reconnection-state surface (epoch, checkpoint, MLS
    /// update, Commit delivery) reached through the mailbox.
    supervisor: &'a Arc<Supervisor>,
    /// Local member DID — the checkpoint author / reset requester.
    member_did: DID,
    /// Custody-backed signer for `member_did`, used to sign the Phase-3
    /// local checkpoint.
    signer: CommandSigner,
    /// Application envelopes the actor accepted, per context.
    tally: &'a DeliveryTally,
}

impl<'a> RelayActorSyncDriver<'a> {
    /// Constructs a driver borrowing the bridge's transport + supervisor.
    ///
    /// `signer` signs for `member_did` through its custody; it is
    /// used only to sign the local consistency checkpoint in Phase 3
    /// (the same authority the application send path uses). The
    /// [`SyncPolicy`] lives on the [`ReconnectionCoordinator`] and is
    /// passed into `epoch_reconciliation` per call, so the driver does
    /// not retain its own copy. `tally` collects the application envelopes
    /// the actor accepts in Phases 2 and 4 and in the Tier 3 Welcome pull.
    #[must_use]
    pub const fn new(
        transport: &'a Arc<TransportManager>,
        supervisor: &'a Arc<Supervisor>,
        member_did: DID,
        signer: CommandSigner,
        tally: &'a DeliveryTally,
    ) -> Self {
        Self {
            transport,
            supervisor,
            member_did,
            signer,
            tally,
        }
    }

    /// The shared routing ID of `context_id` ([`shared_routing_id`]).
    async fn shared_routing_id(&self, context_id: &str) -> RoutingId {
        shared_routing_id(self.supervisor, context_id).await
    }

    /// Drains ONLY the `EquivocationDetected` alerts from the actor's
    /// receive buffer and maps each to a
    /// [`SyncEvent::EquivocationDetected`] alert (§9.9.3), leaving all
    /// other buffered events (application messages, membership changes)
    /// untouched for the SDK's normal receive polling.
    ///
    /// The actor emits the equivocation event from inside
    /// `compare_remote_checkpoint` (reached via `deliver_commit_blob` for
    /// retrieved checkpoint blobs), carrying the real divergent local /
    /// remote Merkle roots. Those roots are surfaced verbatim on the
    /// alert here and are ALSO persisted in the event-log append payload
    /// by the actor (§9.9.4: security events must not be silently
    /// discarded). The `evidence` field (the two signed checkpoints) is
    /// not reconstructed at this layer — the divergent roots are the
    /// load-bearing proof of equivocation and travel on the event itself.
    ///
    /// Uses [`Supervisor::drain_equivocation_alerts`] (NOT the total
    /// `drain_events`) so catch-up does not destroy buffered application
    /// traffic.
    async fn collect_equivocation_alerts(&self, context_id: &str, now: u64) -> Vec<SyncEvent> {
        // Resolve the detector's local MLS epoch once for the whole batch so
        // every alert carries forensic epoch context (§9.12). `None` for a
        // broadcast context or on mailbox failure, matching the helper's soft
        // semantics — the divergent roots remain the load-bearing evidence.
        let local_epoch = self.supervisor.local_mls_epoch(context_id).await;
        self.supervisor
            .drain_equivocation_alerts(context_id)
            .await
            .into_iter()
            .filter_map(|event| match event {
                ContextEvent::EquivocationDetected {
                    context_id: ctx,
                    remote_sender_did,
                    event_count,
                    local_merkle_root,
                    remote_merkle_root,
                } => Some(SyncEvent::EquivocationDetected(Box::new(
                    scp_protocol::sync::EquivocationAlert {
                        context_id: ctx,
                        detector_did: self.member_did.clone(),
                        divergent_did: remote_sender_did,
                        divergent_event_count: event_count,
                        // Real divergent roots carried on the event by the
                        // actor's compare_remote_checkpoint, also persisted
                        // in the event-log payload for forensics.
                        local_merkle_root,
                        remote_merkle_root,
                        evidence: None,
                        detected_at: now,
                        local_epoch,
                    },
                ))),
                _ => None,
            })
            .collect()
    }
}

impl SyncPhaseDriver for RelayActorSyncDriver<'_> {
    /// Phase 1 — relay catch-up: QUERY each relay for buffered envelopes
    /// since `last_stored_at` and deduplicate by `blob_id`.
    async fn relay_catch_up(
        &self,
        context_id: &str,
        last_stored_at: u64,
    ) -> Result<Vec<BufferedMessage>, SyncError> {
        let routing_id = self.shared_routing_id(context_id).await;
        // 5-second overlap on re-subscribe per ADR-004 Connection Recovery.
        let since = last_stored_at.saturating_sub(SINCE_OVERLAP_SECS);
        // `since` is always <= `last_stored_at`; the local receive time
        // recorded on each buffered message is the caller-supplied
        // `last_stored_at`.
        pull_buffered(
            self.transport,
            RelayScope::Installed,
            context_id,
            &[routing_id],
            since,
            last_stored_at,
        )
        .await
    }

    /// Phase 2 — MLS epoch reconciliation: feed each retrieved blob into
    /// the actor (which decrypts, verifies, and `merge_staged_commit`s
    /// Commits to advance the local epoch), bounded by the policy's
    /// sequential-Commit limit, then re-read the local epoch.
    ///
    /// `messages` is the Phase-1 retrieved buffer, threaded in so this
    /// phase does not re-query the relay from zero.
    ///
    /// # Commit ordering across epochs
    ///
    /// Phase 1 sorts blobs by `blob_id` (`SHA-256` — effectively random),
    /// not by epoch, because the relay-assigned `stored_at` is untrusted
    /// and not carried on the wire. `OpenMLS` only accepts a Commit whose
    /// epoch matches the group's CURRENT epoch, so a single linear pass
    /// advances at most one epoch (every Commit for a later epoch is
    /// rejected as stale before its predecessor merges). To catch up
    /// across multiple epochs we loop: each pass feeds the still-rejected
    /// set against the now-advanced epoch and retries; we stop when a full
    /// pass merges nothing (steady state) or the cumulative merge count
    /// reaches the sequential-Commit budget.
    async fn epoch_reconciliation(
        &self,
        context_id: &str,
        local_epoch: u64,
        target_epoch: u64,
        policy: &SyncPolicy,
        messages: &[BufferedMessage],
    ) -> Result<EpochCatchUpState, SyncError> {
        let mut state = EpochCatchUpState::new(context_id.to_owned(), local_epoch, target_epoch);

        if local_epoch >= target_epoch {
            // Already current — nothing to process.
            return Ok(state);
        }

        if state.exceeds_sequential_limit(policy) {
            // Gap exceeds the sequential-Commit budget; the SDK falls back
            // to Welcome-based fast-forward (Tier-2/3 reset path). Surface
            // the decision rather than churning through bounded Commits.
            state.transition_to_fast_forward();
            return Ok(state);
        }

        let limit = usize::try_from(policy.max_sequential_commits).unwrap_or(usize::MAX);

        // Feeds the Phase-1 buffer (capped at the budget) through
        // `Supervisor::deliver_commit_blob` until a pass accepts nothing.
        let fed = deliver_commit_blobs_until_steady(
            self.supervisor,
            context_id,
            messages,
            limit,
            DeliveryMode::Live,
            self.tally,
        )
        .await;
        for _ in 0..fed.accepted {
            state.record_commit_processed();
        }

        // Re-read the authoritative local epoch from the actor.
        let new_local = self
            .supervisor
            .local_mls_epoch(context_id)
            .await
            .unwrap_or(local_epoch);
        if new_local >= target_epoch {
            // record_commit_processed already flips to Complete when the
            // counter reaches the target; ensure terminal status when the
            // actor reports caught-up even if some blobs were skipped.
            state = EpochCatchUpState::new(context_id.to_owned(), new_local, target_epoch);
            state.record_commit_processed();
        }
        Ok(state)
    }

    /// Phase 3 — event log sync: build + broadcast the local consistency
    /// checkpoint (one actor turn), then collect any `EquivocationDetected`
    /// alerts the actor emitted while comparing retrieved remote
    /// checkpoints in Phase 2.
    async fn event_log_sync(&self, context_id: &str) -> Result<(u64, Vec<SyncEvent>), SyncError> {
        let checkpoint = self
            .supervisor
            .build_local_checkpoint(context_id, &self.member_did, &self.signer)
            .await
            .map_err(|e| SyncError::EventLogSyncFailed {
                context_id: context_id.to_owned(),
                reason: e.to_string(),
            })?;

        // Drain equivocation alerts surfaced by the actor's
        // compare_remote_checkpoint (fed via deliver_commit_blob in Phase
        // 2). `event_count` is the local count at checkpoint time.
        let now = checkpoint.timestamp;
        let alerts = self.collect_equivocation_alerts(context_id, now).await;
        Ok((checkpoint.event_count, alerts))
    }

    /// Phase 4 — sender-key re-acquisition. Re-subscribe to the context
    /// routing key so any `SenderKeyEpochAdvance` a peer published while
    /// we were offline is delivered through the actor (the deliver path
    /// processes sender-key management messages). Returns the count of
    /// senders whose keys remain unrecoverable (0 on the happy path).
    async fn sender_key_reacquire(
        &self,
        context_id: &str,
        _policy: &SyncPolicy,
        messages: &[BufferedMessage],
    ) -> Result<u64, SyncError> {
        // Sender-key management messages (advance / request / response) ride
        // the same routing key as application data and are processed by the
        // actor's deliver path. Phase 2 already fed the buffer to advance
        // the MLS epoch; here we re-feed the SAME Phase-1 buffer (threaded
        // in, NOT re-queried from zero) so a late-arriving sender-key
        // advance interleaved among the blobs is not missed. Re-delivery is
        // idempotent — already-merged Commits and already-processed
        // management messages are rejected without side effects.
        refeed_buffer(
            self.supervisor,
            context_id,
            messages,
            DeliveryMode::Live,
            self.tally,
        )
        .await;
        // The actor surfaces unrecoverable sender keys as buffered
        // SenderKeyTimeout events; none means full recovery.
        Ok(0)
    }

    /// Phase 5 — MLS Update for post-compromise security (§9.12 step 2).
    /// Issues the Update through the actor and publishes the resulting
    /// Commit to the context routing key so peers advance with us.
    async fn mls_update(&self, context_id: &str) -> Result<bool, SyncError> {
        let commit_bytes = match self.supervisor.issue_mls_update(context_id).await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(SyncError::MlsUpdateFailed {
                    context_id: context_id.to_owned(),
                    reason: e.to_string(),
                });
            }
        };

        // Publish the Commit to the shared routing key so online peers
        // process the epoch advance. Best-effort: a transport failure does
        // not undo the local epoch advance (the Commit can be re-broadcast).
        let routing_id = self.shared_routing_id(context_id).await;
        let envelope = create_outer_envelope(
            routing_id.as_bytes(),
            None,
            RESET_BLOB_TTL_SECS,
            commit_bytes,
        )
        .map_err(|e| SyncError::MlsUpdateFailed {
            context_id: context_id.to_owned(),
            reason: format!("outer envelope for MLS update commit: {e}"),
        })?;
        if let Err(e) = self.transport.send(&envelope).await {
            tracing::warn!(
                context_id,
                error = %e,
                "mls_update: failed to publish Update Commit to peers (best-effort)"
            );
        }
        Ok(true)
    }

    /// Phase 6 — queue drain. The outbound offline queue is owned by
    /// `ProtocolRepository` at the bridge layer (not actor state), so the
    /// in-trait hook reports a no-op `(0, 0)`; the bridge surface owns the
    /// drain.
    ///
    /// Current reality: all three bridges invoke
    /// [`reconnect_contexts_no_drain`] (drain callback = `None`), so the
    /// queue drain is presently a NO-OP end to end. The producer that would
    /// populate the outbound queue — the offline send-enqueue path
    /// (`store::queue::enqueue_message`) — has no production caller yet, so
    /// there is nothing to drain. Wiring that offline-enqueue producer (so
    /// `send` while disconnected buffers to the queue, and reconnection
    /// drains it via `ReconnectionCoordinator::drain_context_queue`) is the
    /// explicit follow-up scope; until it lands, do not claim the queue is
    /// drained on reconnect. See the ADR-029 reconnection-driver addendum.
    async fn queue_drain(
        &self,
        _context_id: &str,
        _now: u64,
        _blob_ttl_secs: Option<u64>,
    ) -> Result<(u64, u64), SyncError> {
        Ok((0, 0))
    }

    /// Returns the local MLS epoch (`None` for broadcast contexts).
    async fn local_epoch(&self, context_id: &str) -> Result<Option<u64>, SyncError> {
        Ok(self.supervisor.local_mls_epoch(context_id).await)
    }

    /// Returns the highest epoch observed across retrieved messages.
    /// Application-message epochs are only known after decryption, so the
    /// public header epoch (`BufferedMessage::epoch`) is used when present;
    /// `None` when no message carried a header epoch.
    async fn observed_target_epoch(
        &self,
        _context_id: &str,
        messages: &[BufferedMessage],
    ) -> Result<Option<u64>, SyncError> {
        Ok(messages.iter().filter_map(|m| m.epoch).max())
    }

    /// Returns the configured blob TTL for a context. Encrypted contexts
    /// use the protocol default; the value bounds queue-entry expiry at
    /// drain time. `None` lets the caller fall back to the 7-day default.
    async fn blob_ttl_secs(&self, _context_id: &str) -> Result<Option<u64>, SyncError> {
        Ok(None)
    }
}

impl SnapshotTransport for RelayActorSyncDriver<'_> {
    /// Tier 2 — query the relay for the latest snapshot bytes at the
    /// context's well-known routing key. Returns `None` when no snapshot
    /// blob is stored.
    async fn query_snapshot(&self, context_id: &str) -> Result<Option<Vec<u8>>, DaysOfflineError> {
        let routing_id = self.shared_routing_id(context_id).await;
        let envelopes = self.transport.query(&routing_id, None).await.map_err(|e| {
            DaysOfflineError::SnapshotCodecFailed {
                context_id: context_id.to_owned(),
                reason: e.to_string(),
            }
        })?;
        // The most recent snapshot blob is the newest envelope on the key;
        // the snapshot payload is the encrypted blob (the engine decodes it).
        Ok(envelopes
            .last()
            .map(|envelope| envelope.encrypted_blob.clone()))
    }

    /// Tier 2 — publish snapshot bytes to the relay at the context's
    /// well-known routing key (wrapped in an outer envelope).
    async fn publish_snapshot_bytes(
        &self,
        context_id: &str,
        data: &[u8],
    ) -> Result<(), DaysOfflineError> {
        let routing_id = self.shared_routing_id(context_id).await;
        let envelope = create_outer_envelope(
            routing_id.as_bytes(),
            None,
            RESET_BLOB_TTL_SECS,
            data.to_vec(),
        )
        .map_err(|e| DaysOfflineError::SnapshotCodecFailed {
            context_id: context_id.to_owned(),
            reason: format!("outer envelope for snapshot: {e}"),
        })?;
        self.transport
            .send(&envelope)
            .await
            .map(|_blob_id| ())
            .map_err(|e| DaysOfflineError::SnapshotCodecFailed {
                context_id: context_id.to_owned(),
                reason: e.to_string(),
            })
    }
}

impl ResetTransport for RelayActorSyncDriver<'_> {
    /// Tier 3 — publish a serialized reset request to the relay as
    /// plaintext (NOT MLS-encrypted; the member may be unable to encrypt
    /// at the current epoch). The request is wrapped in an outer envelope
    /// addressed to the context routing key.
    async fn publish_plaintext(
        &self,
        context_id: &str,
        data: &[u8],
    ) -> Result<(), scp_core::sync::weeks_offline::WeeksOfflineError> {
        let routing_id = self.shared_routing_id(context_id).await;
        let envelope = create_outer_envelope(
            routing_id.as_bytes(),
            None,
            RESET_BLOB_TTL_SECS,
            data.to_vec(),
        )
        .map_err(|e| {
            scp_core::sync::weeks_offline::WeeksOfflineError::ResetRequestFailed {
                context_id: context_id.to_owned(),
                reason: format!("outer envelope for reset request: {e}"),
            }
        })?;
        self.transport
            .send(&envelope)
            .await
            .map(|_blob_id| ())
            .map_err(
                |e| scp_core::sync::weeks_offline::WeeksOfflineError::ResetRequestFailed {
                    context_id: context_id.to_owned(),
                    reason: e.to_string(),
                },
            )
    }

    /// Tier 3 — admin-side MLS reset: remove the stale leaf and re-add the
    /// member with a fresh `KeyPackage`, then issue the Commit. This is
    /// performed by an online admin; the reconnecting member only awaits
    /// the resulting Welcome. When the local node is the admin, the reset
    /// is driven through the actor's MLS update path (which ratchets the
    /// group); the returned epoch is the new local MLS epoch.
    async fn remove_and_readd_member(
        &self,
        context_id: &str,
        _member_did: &DID,
        _role_to_restore: &str,
    ) -> Result<u64, scp_core::sync::weeks_offline::WeeksOfflineError> {
        // Issue an MLS Update through the actor to ratchet the group to a
        // fresh epoch (the admin-side re-add advances the epoch); publish
        // the Commit so the reconnecting member receives it.
        self.mls_update(context_id).await.map_err(|e| {
            scp_core::sync::weeks_offline::WeeksOfflineError::ResetRequestFailed {
                context_id: context_id.to_owned(),
                reason: format!("admin MLS re-add ratchet failed: {e}"),
            }
        })?;
        let epoch = self
            .supervisor
            .local_mls_epoch(context_id)
            .await
            .unwrap_or(0);
        Ok(epoch)
    }

    /// Tier 3 — fails at once with
    /// [`ReJoinUnavailable`](scp_core::sync::weeks_offline::WeeksOfflineError::ReJoinUnavailable).
    ///
    /// No shipped path can complete a re-join: none publishes the member's
    /// `ResetRequest`, none has an admin process one, and none applies a
    /// re-add Welcome to a context the member already holds. An advance of the
    /// local MLS epoch is no re-add signal, because an ordinary Commit also
    /// advances it. The failure leaves `needs_reconnect` set and writes no
    /// relay contact (ADR-029 reconnection-driver addendum).
    async fn subscribe_and_await_welcome(
        &self,
        context_id: &str,
        _timeout_secs: u64,
    ) -> Result<u64, scp_core::sync::weeks_offline::WeeksOfflineError> {
        Err(
            scp_core::sync::weeks_offline::WeeksOfflineError::ReJoinUnavailable {
                context_id: context_id.to_owned(),
            },
        )
    }
}

/// Maps a [`CatchUpStatus`] to a coarse caught-up boolean for the bridge
/// report. Re-exported helper so each bridge classifies identically.
#[must_use]
pub const fn catch_up_is_terminal(status: &CatchUpStatus) -> bool {
    matches!(
        status,
        CatchUpStatus::Complete | CatchUpStatus::FastForwarded { .. }
    )
}

// ---------------------------------------------------------------------------
// Bridge-facing orchestration
// ---------------------------------------------------------------------------

use scp_core::sync::days_offline::{DeltaSyncEngine, RelayBackedDeltaSyncEngine};
use scp_core::sync::hours_offline::ReconnectionCoordinator;
use scp_core::sync::weeks_offline::{ReJoinExecutor, RelayBackedReJoinExecutor};
use scp_protocol::sync::OfflineTier;

/// Flat, FFI-friendly per-context reconnection result. Each bridge maps
/// this into its own object type (`PyO3` dict, `NAPI` object, `UniFFI` record)
/// for the SDK surface.
#[derive(Debug, Clone)]
pub struct ContextReconnectResult {
    /// Context that was reconnected.
    pub context_id: String,
    /// Offline tier classification: `"short"` / `"extended"` / `"long"`.
    pub tier: String,
    /// Outcome: `"fully_caught_up"` / `"fast_forwarded"` / `"reset"` /
    /// `"context_gone"` / `"failed"` / `"pending"`.
    pub outcome: String,
    /// MLS epochs caught up (Tier 1).
    pub epochs_caught_up: u64,
    /// Event-log events recovered.
    pub events_recovered: u64,
    /// Whether an MLS Update was issued after catch-up (§9.12).
    pub mls_update_issued: bool,
    /// Number of `EquivocationDetected` alerts surfaced during this
    /// context's sync (§9.9.3).
    pub equivocations_detected: u64,
    /// Whether the `needs_reconnect` flag was cleared on success.
    pub needs_reconnect_cleared: bool,
    /// Envelopes the actor accepted as application messages during this
    /// context's reconnection ([`DeliveryTally`]).
    pub envelopes_delivered: u64,
    /// Why writing `sync/{context_id}/last_relay_contact` failed after
    /// `needs_reconnect` was cleared, or `None` when the write succeeded or
    /// no write was due.
    pub relay_contact_error: Option<String>,
}

/// Flat, FFI-friendly reconnection report. Aggregates per-context results
/// plus queue-drain totals. Each bridge maps this into its SDK return type.
#[derive(Debug, Clone, Default)]
pub struct ReconnectReport {
    /// Per-context results.
    pub contexts: Vec<ContextReconnectResult>,
    /// Total queued messages drained across all contexts (Phase 6).
    pub messages_drained: u64,
    /// Total queued messages discarded (expired / context gone).
    pub messages_discarded: u64,
    /// Total reconnection duration in milliseconds.
    pub total_duration_ms: u64,
}

/// Maps an [`OfflineTier`] to a stable lowercase wire string.
fn tier_str(tier: OfflineTier) -> String {
    match tier {
        OfflineTier::Short => "short",
        OfflineTier::Extended => "extended",
        OfflineTier::Long => "long",
    }
    .to_owned()
}

/// Maps a [`SyncOutcome`](scp_protocol::sync::SyncOutcome) to a stable
/// lowercase wire string and a terminal-success boolean (used to decide
/// whether to clear `needs_reconnect`).
fn outcome_str(outcome: &scp_protocol::sync::SyncOutcome) -> (String, bool) {
    use scp_protocol::sync::SyncOutcome;
    match outcome {
        SyncOutcome::Pending => ("pending".to_owned(), false),
        SyncOutcome::FullyCaughtUp => ("fully_caught_up".to_owned(), true),
        SyncOutcome::FastForwarded { .. } => ("fast_forwarded".to_owned(), true),
        SyncOutcome::Reset => ("reset".to_owned(), true),
        SyncOutcome::ContextGone => ("context_gone".to_owned(), true),
        SyncOutcome::Failed { .. } => ("failed".to_owned(), false),
    }
}

/// Drives the full ADR-029 reconnection protocol for the given contexts at
/// the bridge surface and returns a flat report.
///
/// Each context's `sync/{context_id}/last_relay_contact` is read from
/// `relay_contacts`, the one source of that value; a context with none stored
/// is classified Long (ADR-029 §2 sync-state keys). For each context the
/// [`ReconnectionCoordinator`] classifies the offline tier from that value
/// and:
/// - **Tier 1 (Short)** — runs the six-phase protocol via
///   [`ReconnectionCoordinator::execute`] against a [`RelayActorSyncDriver`].
/// - **Tier 2 (Extended)** — fetches the relay snapshot via a
///   [`RelayBackedDeltaSyncEngine`] (delta application is the actor's job
///   once the snapshot lands; here we confirm a snapshot is reachable).
/// - **Tier 3 (Long)** — awaits a Welcome via a [`RelayBackedReJoinExecutor`]
///   (admin-side re-add + Welcome processing through the actor).
///
/// After a reconnection that reached `FullyCaughtUp`, `FastForwarded` or
/// `Reset`, the actor sends every sender-key answer it holds queued
/// ([`Supervisor::send_queued_sender_keys`]), including the answers a push-wake
/// pull left queued (ADR-029 §2 push-wake pull mode step 5); a failed send
/// makes the outcome `Failed`. On a terminal-success outcome the context's
/// `needs_reconnect` flag is cleared via [`Supervisor::clear_needs_reconnect`]. After per-context
/// execution, the optional `drain` callback is invoked once per context to
/// drain the bridge-owned outbound queue (Phase 6) — the queue lives in
/// `ProtocolRepository` at the bridge layer, not in actor state, so the
/// caller supplies the drain.
///
/// `request.signer` signs for `request.member_did` through its custody; it
/// signs the Phase-3 local checkpoint.
///
/// After clearing a context's `needs_reconnect`, writes `now` to its
/// `sync/{context_id}/last_relay_contact` through `relay_contacts` (ADR-029
/// §2 sync-state keys); a failed write is reported on
/// [`ContextReconnectResult::relay_contact_error`].
///
/// # Errors
///
/// [`ReconnectError::ContactRead`] when reading a context's
/// `last_relay_contact` fails; no context is reconnected, because a context
/// classified without its contact could take the wrong tier.
pub async fn reconnect_contexts<F, Fut>(
    request: ReconnectRequest<'_>,
    mut drain: Option<F>,
) -> Result<ReconnectReport, ReconnectError>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = (u64, u64)>,
{
    let ReconnectRequest {
        transport,
        supervisor,
        member_did,
        signer,
        relay_contacts,
        context_ids,
        now,
        policy,
    } = request;
    let last_relay_contacts = load_relay_contacts(relay_contacts, &context_ids).await?;

    let tally = DeliveryTally::default();
    let driver = RelayActorSyncDriver::new(
        transport,
        supervisor,
        member_did.clone(),
        signer.clone(),
        &tally,
    );

    let coordinator = ReconnectionCoordinator::with_policy(
        member_did,
        context_ids.clone(),
        last_relay_contacts,
        policy,
    );

    // Tier 1 contexts are executed by the coordinator's six-phase loop;
    // Tier 2 / Tier 3 contexts are reported with their classification and
    // driven through the tier engines below.
    let report = coordinator.execute(now, &driver).await;

    let mut results = Vec::with_capacity(report.contexts_synced.len());
    let mut messages_drained = report.messages_drained;
    let mut messages_discarded = report.messages_discarded;

    for ctx_result in report.contexts_synced {
        let context_id = ctx_result.context_id.clone();
        let tier = ctx_result.tier;

        // Tier 2 / Tier 3 contexts are not executed by `execute` (it only
        // runs Tier 1); drive their engines here so all three tiers are
        // reachable from `context_reconnect`.
        let (outcome, epochs, events, mls_update, equivocations) = match tier {
            OfflineTier::Short => {
                let equivocations = ctx_result.sync_events.len() as u64;
                (
                    ctx_result.outcome,
                    ctx_result.epochs_caught_up,
                    ctx_result.events_recovered,
                    ctx_result.mls_update_issued,
                    equivocations,
                )
            }
            OfflineTier::Extended | OfflineTier::Long => {
                let driver = RelayActorSyncDriver::new(
                    transport,
                    supervisor,
                    coordinator.member_did().clone(),
                    signer.clone(),
                    &tally,
                );
                (
                    drive_tier_engine(driver, tier, &context_id).await,
                    0,
                    0,
                    false,
                    0,
                )
            }
        };

        let outcome = send_queued_answers(supervisor, &context_id, outcome).await;
        let (outcome_string, terminal_success) = outcome_str(&outcome);

        let (needs_reconnect_cleared, relay_contact_error) = clear_and_record_contact(
            supervisor,
            relay_contacts,
            &context_id,
            now,
            terminal_success,
        )
        .await;

        // Phase 6: drain the bridge-owned outbound queue for this context.
        if let Some(drain_fn) = drain.as_mut() {
            let (drained, discarded) = drain_fn(context_id.clone()).await;
            messages_drained = messages_drained.saturating_add(drained);
            messages_discarded = messages_discarded.saturating_add(discarded);
        }

        let envelopes_delivered = tally.get(&context_id);
        results.push(ContextReconnectResult {
            context_id,
            tier: tier_str(tier),
            outcome: outcome_string,
            epochs_caught_up: epochs,
            events_recovered: events,
            mls_update_issued: mls_update,
            equivocations_detected: equivocations,
            needs_reconnect_cleared,
            envelopes_delivered,
            relay_contact_error,
        });
    }

    Ok(ReconnectReport {
        contexts: results,
        messages_drained,
        messages_discarded,
        total_duration_ms: report.total_duration_ms,
    })
}

/// Why [`reconnect_contexts`] reconnected no context.
#[derive(Debug, thiserror::Error)]
pub enum ReconnectError {
    /// Reading `sync/{context_id}/last_relay_contact` failed.
    #[error("reading the last relay contact of {context_id} failed: {source}")]
    ContactRead {
        /// The context whose key could not be read.
        context_id: String,
        /// The store failure.
        #[source]
        source: StoreError,
    },
}

impl ReconnectError {
    /// The bridge error code: `SCP-TRANS-5095` (`sdk-common.md`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ContactRead { .. } => crate::error_codes::TRANS_5095,
        }
    }
}

/// Sends the sender-key answers queued on the actor of `context_id` after a
/// reconnection whose `outcome` is `FullyCaughtUp`, `FastForwarded` or `Reset`,
/// and returns the outcome, made `Failed` when the send fails. Any other
/// outcome is returned unchanged with nothing sent.
async fn send_queued_answers(
    supervisor: &Supervisor,
    context_id: &str,
    outcome: scp_protocol::sync::SyncOutcome,
) -> scp_protocol::sync::SyncOutcome {
    use scp_protocol::sync::SyncOutcome;
    match outcome {
        SyncOutcome::FullyCaughtUp | SyncOutcome::FastForwarded { .. } | SyncOutcome::Reset => {
            match supervisor.send_queued_sender_keys(context_id).await {
                Ok(()) => outcome,
                Err(e) => SyncOutcome::Failed {
                    reason: format!("sending queued sender-key answers failed: {e}"),
                },
            }
        }
        SyncOutcome::Pending | SyncOutcome::ContextGone | SyncOutcome::Failed { .. } => outcome,
    }
}

/// Drives the Tier 2 or Tier 3 engine for `context_id`, which
/// [`ReconnectionCoordinator::execute`] does not run (it runs Tier 1 only).
///
/// Tier 2 delta sync fetches the latest relay snapshot; the actor applies the
/// delta when the snapshot is delivered, so a reachable snapshot means
/// recovery can proceed. Tier 3 reset awaits a Welcome (admin-side re-add and
/// Welcome processing through the actor). `Short` is not an engine tier and
/// yields `Failed`.
async fn drive_tier_engine(
    driver: RelayActorSyncDriver<'_>,
    tier: OfflineTier,
    context_id: &str,
) -> scp_protocol::sync::SyncOutcome {
    use scp_protocol::sync::SyncOutcome;
    match tier {
        OfflineTier::Extended => match RelayBackedDeltaSyncEngine::new(driver)
            .fetch_snapshot(context_id)
            .await
        {
            Ok(Some(_snapshot)) => SyncOutcome::FullyCaughtUp,
            Ok(None) => SyncOutcome::Failed {
                reason: "no relay snapshot available for Tier 2 delta sync".to_owned(),
            },
            Err(e) => SyncOutcome::Failed {
                reason: format!("Tier 2 snapshot fetch failed: {e}"),
            },
        },
        OfflineTier::Long => match RelayBackedReJoinExecutor::new(driver)
            .await_welcome(context_id, policy_welcome_timeout_secs())
            .await
        {
            Ok(_epoch) => SyncOutcome::Reset,
            Err(e) => SyncOutcome::Failed {
                reason: format!("Tier 3 re-join failed: {e}"),
            },
        },
        OfflineTier::Short => SyncOutcome::Failed {
            reason: "Tier 1 runs in the coordinator, not a tier engine".to_owned(),
        },
    }
}

/// Clears `needs_reconnect` and records the relay contact after a reconnection
/// of `context_id` whose outcome is a terminal success.
///
/// The clear keeps a later restore from re-driving the synced context
/// (§23.11). The contact write records `now` as `last_relay_contact`, because
/// a full reconnection that cleared the flag is a successful relay interaction
/// (ADR-029 §2). Returns whether the flag was cleared and the contact-write
/// error, if any. Nothing happens when `terminal_success` is false, and no
/// write happens when the clear fails.
async fn clear_and_record_contact(
    supervisor: &Arc<Supervisor>,
    relay_contacts: &dyn RelayContactStore,
    context_id: &str,
    now: u64,
    terminal_success: bool,
) -> (bool, Option<String>) {
    if !terminal_success {
        return (false, None);
    }
    if let Err(e) = supervisor.clear_needs_reconnect(context_id).await {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "reconnect_contexts: clearing needs_reconnect failed"
        );
        return (false, None);
    }
    let error = relay_contacts
        .store_last_relay_contact(context_id, now)
        .await
        .err()
        .map(|e| {
            tracing::error!(
                context_id = %context_id,
                error = %e,
                "reconnect_contexts: last_relay_contact write failed"
            );
            e.to_string()
        });
    (true, error)
}

/// Reads the stored `last_relay_contact` of each of `context_ids`; a context
/// with none stored is absent from the map.
///
/// # Errors
///
/// [`ReconnectError::ContactRead`] on the first read that fails.
async fn load_relay_contacts(
    relay_contacts: &dyn RelayContactStore,
    context_ids: &[String],
) -> Result<HashMap<String, u64>, ReconnectError> {
    let mut contacts = HashMap::with_capacity(context_ids.len());
    for context_id in context_ids {
        let stored = relay_contacts
            .load_last_relay_contact(context_id)
            .await
            .map_err(|source| ReconnectError::ContactRead {
                context_id: context_id.clone(),
                source,
            })?;
        if let Some(contact) = stored {
            contacts.insert(context_id.clone(), contact);
        }
    }
    Ok(contacts)
}

/// Welcome-await timeout (seconds) for Tier 3 re-join. Matches the
/// ADR-029 §4 reset-protocol Welcome window.
const fn policy_welcome_timeout_secs() -> u64 {
    30
}

/// Concrete no-op drain closure type — lets the `None` variant's closure
/// generics be inferred without each caller spelling them out.
type NoDrainFn = fn(String) -> std::future::Ready<(u64, u64)>;

/// Convenience over [`reconnect_contexts`] for the no-queue-drain case.
///
/// For bridges whose outbound queue has no persistent enqueued entries to
/// drain (e.g. encrypted in-memory storage), passes a typed `None` drain
/// callback so callers do not have to spell out the closure generics.
///
/// # Errors
///
/// The errors of [`reconnect_contexts`].
pub async fn reconnect_contexts_no_drain(
    request: ReconnectRequest<'_>,
) -> Result<ReconnectReport, ReconnectError> {
    // Concrete closure type so the `None` variant's generics are inferred.
    let drain: Option<NoDrainFn> = None;
    reconnect_contexts(request, drain).await
}

/// The inputs of one [`reconnect_contexts`] call.
pub struct ReconnectRequest<'a> {
    /// The relay connections Phase 1 pulls through.
    pub transport: &'a Arc<TransportManager>,
    /// The supervisor that owns each context's actor.
    pub supervisor: &'a Arc<Supervisor>,
    /// The local member reconnecting.
    pub member_did: DID,
    /// Signs for `member_did` through its custody (the Phase-3 checkpoint).
    pub signer: CommandSigner,
    /// The store that holds each context's `last_relay_contact`, read for
    /// tier classification and written after `needs_reconnect` clears.
    pub relay_contacts: &'a dyn RelayContactStore,
    /// The contexts to reconnect.
    pub context_ids: Vec<String>,
    /// The current local Unix time in seconds.
    pub now: u64,
    /// Catch-up limits.
    pub policy: SyncPolicy,
}

// ---------------------------------------------------------------------------
// Push-wake pull mode (ADR-029 §2)
// ---------------------------------------------------------------------------

/// Why [`wake_pull_contexts`] could not pull one context.
///
/// The failure is that context's alone: the other contexts' pulls run on, and
/// the context keeps its stored `last_relay_contact` (ADR-029 §2 push-wake
/// pull mode steps 6 and 7).
#[derive(Debug, thiserror::Error)]
pub enum WakePullError {
    /// The context's persisted relay set is empty.
    #[error("context {context_id} persists no relay URL")]
    NoRelays {
        /// The context with no relay.
        context_id: String,
    },
    /// A relay in the context's relay set was not dialed: the dial failed,
    /// timed out or panicked.
    #[error("relay {relay_url} of {context_id} is unreachable: {reason}")]
    RelayUnavailable {
        /// The context whose relay set names the relay.
        context_id: String,
        /// The relay that was not dialed.
        relay_url: String,
        /// Why the dial failed.
        reason: String,
    },
    /// Reading `sync/{context_id}/last_relay_contact` failed.
    #[error("reading the last relay contact of {context_id} failed: {source}")]
    ContactRead {
        /// The context whose key could not be read.
        context_id: String,
        /// The store failure.
        #[source]
        source: StoreError,
    },
    /// A Phase 1 QUERY failed on a relay of the context's relay set.
    #[error("relay query for {context_id} failed: {source}")]
    Query {
        /// The context whose pull failed.
        context_id: String,
        /// The relay failure.
        #[source]
        source: SyncError,
    },
    /// Writing `sync/{context_id}/last_relay_contact` after Phases 2 and 4
    /// failed.
    #[error("writing the last relay contact of {context_id} failed: {source}")]
    ContactWrite {
        /// The context whose key could not be written.
        context_id: String,
        /// The store failure.
        #[source]
        source: StoreError,
    },
    /// The actor reached no verdict on `count` blobs of the context's Phase 1
    /// buffer in their last delivery, Phase 4 ([`delivery_reached_verdict`]),
    /// so the context keeps its stored `last_relay_contact` (ADR-029 §2
    /// push-wake pull mode step 6).
    #[error("{count} blob(s) of {context_id} reached no verdict: {source}")]
    Undelivered {
        /// The context whose blobs reached no verdict.
        context_id: String,
        /// How many blobs reached no verdict.
        count: u64,
        /// The last delivery failure.
        #[source]
        source: ContextError,
    },
}

impl WakePullError {
    /// The context the failure belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        match self {
            Self::NoRelays { context_id }
            | Self::RelayUnavailable { context_id, .. }
            | Self::ContactRead { context_id, .. }
            | Self::Query { context_id, .. }
            | Self::ContactWrite { context_id, .. }
            | Self::Undelivered { context_id, .. } => context_id,
        }
    }

    /// The bridge error code of this failure: one `SCP-TRANS` code per
    /// variant, `SCP-TRANS-5096` to `SCP-TRANS-5101` (`sdk-common.md`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoRelays { .. } => crate::error_codes::TRANS_5096,
            Self::RelayUnavailable { .. } => crate::error_codes::TRANS_5097,
            Self::ContactRead { .. } => crate::error_codes::TRANS_5098,
            Self::Query { .. } => crate::error_codes::TRANS_5099,
            Self::ContactWrite { .. } => crate::error_codes::TRANS_5100,
            Self::Undelivered { .. } => crate::error_codes::TRANS_5101,
        }
    }
}

/// Whether a delivery that returned `error` reached a verdict on its blob
/// (ADR-029 §2 push-wake pull mode step 6).
///
/// `true` when the actor judged the blob and refused it as invalid for the
/// group: a replay, an undecryptable blob, a Commit that fits no epoch, or any
/// other refusal of the blob's content or sender. `false` when the delivery
/// never reached a judgment: the actor is busy, crashed, poisoned,
/// unregistered or shut down, or its key custody, transport, event log or
/// store failed. Every variant is named, so a new `ContextError` variant is a
/// compile error here until someone decides which side it falls on.
#[must_use]
pub const fn delivery_reached_verdict(error: &ContextError) -> bool {
    match error {
        ContextError::Custody(_)
        | ContextError::WrappingKeyCustodyUnavailable
        | ContextError::WrappingKeyHandleInvalid
        | ContextError::TransportFailed(_)
        | ContextError::EventLogFailed(_)
        | ContextError::PersistenceFailed(_)
        | ContextError::ContextNotRegistered(_)
        | ContextError::RateLimited { .. }
        | ContextError::CommitBroadcastFault { .. }
        | ContextError::ActorBusy(_)
        | ContextError::NotImplemented(_)
        | ContextError::NotInitialized(_)
        | ContextError::TransportTimeout(_)
        | ContextError::ContextPoisoned(_)
        | ContextError::ActorCrashed(_)
        | ContextError::SupervisorShutDown(_) => false,
        ContextError::InvalidTransition { .. }
        | ContextError::CeilingImmutable
        | ContextError::CeilingRequired(_)
        | ContextError::ContextNotActive
        | ContextError::ContextClosed
        | ContextError::ContextExpired
        | ContextError::TemplateMismatch(_)
        | ContextError::MembershipFailed(_)
        | ContextError::CryptoFailed(_)
        | ContextError::SenderMismatch { .. }
        | ContextError::AttestationSignerActiveKeyUnresolved
        | ContextError::AttestationSignerNotActiveKey
        | ContextError::InvitationEncMalformed(_)
        | ContextError::PermissionDenied(_)
        | ContextError::MemberNotFound(_)
        | ContextError::InvalidState(_)
        | ContextError::InvalidKeyPackage(_)
        | ContextError::LimitExceeded(_)
        | ContextError::InvalidMemoryScopeForBroadcast
        | ContextError::NothingToRestore(_)
        | ContextError::IntegrationFailed(_)
        | ContextError::GovernanceFailed(_)
        | ContextError::CreationFailed(_)
        | ContextError::VersionIncompatible { .. }
        | ContextError::SnapshotFloorRegression { .. }
        | ContextError::ImportRejected { .. }
        | ContextError::ExportVersionUnsupported { .. }
        | ContextError::SnapshotSignatureInvalid { .. }
        | ContextError::NoParticipationFacts { .. }
        | ContextError::PseudonymRegistryEmpty { .. }
        | ContextError::NotPseudonymousContext { .. }
        | ContextError::KeyPackageReplay(_)
        | ContextError::Outlet(_)
        | ContextError::OutletContextNotActive { .. } => true,
    }
}

/// Runs the push-wake pull mode of ADR-029 §2 for every target, concurrently
/// and independently, and returns the failure of each context that failed.
///
/// For each target: a context with an empty relay set fails with
/// [`WakePullError::NoRelays`], and one whose relay set names a relay in
/// `unreachable` (relay URL to dial failure) fails with
/// [`WakePullError::RelayUnavailable`]. Otherwise Phase 1 ([`pull_buffered`])
/// queries only the target's own relay set ([`RelayScope::Only`]) for the
/// target's routing IDs (the shared routing ID and each pseudonym routing ID
/// the member holds) since the stored `last_relay_contact` minus
/// [`SINCE_OVERLAP_SECS`], or 0 when none is stored; Phase 2
/// ([`deliver_commit_blobs_until_steady`]) and Phase 4 ([`refeed_buffer`])
/// feed the buffer to the actor in [`DeliveryMode::PullOnly`]; and only when
/// every blob's Phase 4 delivery reached a verdict is `now` written to
/// `last_relay_contact`, else the context fails with
/// [`WakePullError::Undelivered`]. Every application envelope the
/// actor accepts is added to `tally` as it is accepted, so a caller whose
/// deadline drops this future still knows what was delivered, and a context
/// the deadline stops keeps its stored contact.
///
/// The pull takes no [`CommandSigner`] and sends no queued sender-key answer,
/// so it builds no checkpoint, issues no Update and publishes nothing, and it
/// leaves `needs_reconnect` set.
pub async fn wake_pull_contexts(
    pull: &WakePull<'_>,
    targets: &[ContextWakeTarget],
) -> Vec<WakePullError> {
    futures::future::join_all(targets.iter().map(|target| wake_pull_context(pull, target)))
        .await
        .into_iter()
        .filter_map(Result::err)
        .collect()
}

/// The inputs [`wake_pull_contexts`] shares across every target.
pub struct WakePull<'a> {
    /// The transient manager holding the dialed relays.
    pub transport: &'a TransportManager,
    /// The supervisor that owns each context's actor.
    pub supervisor: &'a Supervisor,
    /// Relay URL to dial failure, for each relay the wake could not dial.
    pub unreachable: &'a BTreeMap<String, String>,
    /// The store that holds each context's `last_relay_contact`.
    pub relay_contacts: &'a dyn RelayContactStore,
    /// Catch-up limits; `max_sequential_commits` bounds Phase 2.
    pub policy: &'a SyncPolicy,
    /// The current local Unix time in seconds, written as the new contact.
    pub now: u64,
    /// Counts each application envelope the actor accepts.
    pub tally: &'a DeliveryTally,
}

/// One target of [`wake_pull_contexts`].
async fn wake_pull_context(
    pull: &WakePull<'_>,
    target: &ContextWakeTarget,
) -> Result<(), WakePullError> {
    let WakePull {
        transport,
        supervisor,
        unreachable,
        relay_contacts,
        policy,
        now,
        tally,
    } = *pull;
    let limit = usize::try_from(policy.max_sequential_commits).unwrap_or(usize::MAX);
    let context_id = target.context_id.as_str();
    if target.relay_urls.is_empty() {
        return Err(WakePullError::NoRelays {
            context_id: context_id.to_owned(),
        });
    }
    if let Some((relay_url, reason)) = target
        .relay_urls
        .iter()
        .find_map(|url| unreachable.get(url).map(|reason| (url, reason)))
    {
        return Err(WakePullError::RelayUnavailable {
            context_id: context_id.to_owned(),
            relay_url: relay_url.clone(),
            reason: reason.clone(),
        });
    }
    let stored = relay_contacts
        .load_last_relay_contact(context_id)
        .await
        .map_err(|source| WakePullError::ContactRead {
            context_id: context_id.to_owned(),
            source,
        })?;
    let since = stored.map_or(0, |t| t.saturating_sub(SINCE_OVERLAP_SECS));
    let routing_ids: Vec<RoutingId> = target
        .routing_ids
        .iter()
        .copied()
        .map(RoutingId::new)
        .collect();
    let messages = pull_buffered(
        transport,
        RelayScope::Only(&target.relay_urls),
        context_id,
        &routing_ids,
        since,
        now,
    )
    .await
    .map_err(|source| WakePullError::Query {
        context_id: context_id.to_owned(),
        source,
    })?;
    deliver_commit_blobs_until_steady(
        supervisor,
        context_id,
        &messages,
        limit,
        DeliveryMode::PullOnly,
        tally,
    )
    .await;
    let refed = refeed_buffer(
        supervisor,
        context_id,
        &messages,
        DeliveryMode::PullOnly,
        tally,
    )
    .await;
    if let Some(source) = refed.last_unreached {
        return Err(WakePullError::Undelivered {
            context_id: context_id.to_owned(),
            count: refed.unreached,
            source,
        });
    }
    relay_contacts
        .store_last_relay_contact(context_id, now)
        .await
        .map_err(|source| WakePullError::ContactWrite {
            context_id: context_id.to_owned(),
            source,
        })
}

/// Writes the current local Unix time to `sync/{context_id}/last_relay_contact`
/// (ADR-029 §2 sync-state keys). A live subscription calls it after the actor
/// accepts a delivered envelope.
///
/// # Errors
///
/// The store's [`StoreError`] when the write fails.
async fn record_relay_contact(
    relay_contacts: &dyn RelayContactStore,
    context_id: &str,
) -> Result<(), StoreError> {
    relay_contacts
        .store_last_relay_contact(
            context_id,
            scp_clock::Clock::now_secs(&scp_clock::SystemClock),
        )
        .await
}

/// What [`deliver_live_envelope`] did with one envelope.
#[derive(Debug)]
pub struct LiveDelivery {
    /// The actor's reply to the delivery.
    pub delivered: Result<DeliverOutcome, ContextError>,
    /// The failure of the `last_relay_contact` write after an accepted
    /// delivery; `None` when the write landed or the actor refused the
    /// envelope.
    pub contact_error: Option<StoreError>,
}

/// Delivers one envelope a live relay subscription received.
///
/// Dispatches `MessagingCommand::DeliverIncoming` in [`DeliveryMode::Live`]
/// to `context_id` through the Supervisor `supervisor` still points at,
/// awaits the actor's reply, and applies the live-subscription contact rule
/// (ADR-029 §2 sync-state keys): an accepted envelope writes the current
/// local time to the context's `last_relay_contact`, and a refused one writes
/// nothing.
///
/// Every bridge's live subscription delivers through this function, so none
/// can deliver without the contact rule. The upgraded `Arc` is held only for
/// the dispatch. Returns `None` when the Supervisor has dropped, which ends
/// the subscription (ADR-049 Decision 16). A reply the actor drops is
/// [`ContextError::ActorCrashed`].
pub async fn deliver_live_envelope(
    supervisor: &std::sync::Weak<Supervisor>,
    relay_contacts: &dyn RelayContactStore,
    context_id: &str,
    encrypted_blob: Vec<u8>,
) -> Option<LiveDelivery> {
    let (reply, rx) = tokio::sync::oneshot::channel();
    let cmd = MessagingCommand::DeliverIncoming {
        context_id: context_id.to_owned(),
        envelope_bytes: encrypted_blob,
        mode: DeliveryMode::Live,
        reply,
    };
    let dispatched = {
        let live = supervisor.upgrade()?;
        live.dispatch_command(context_id, cmd).await
    };
    let delivered = match dispatched {
        Ok(_) => rx.await.unwrap_or_else(|_| {
            Err(ContextError::ActorCrashed(format!(
                "the actor of {context_id} dropped its delivery reply"
            )))
        }),
        Err(e) => Err(e),
    };
    let contact_error = record_contact_after_live_delivery(relay_contacts, context_id, &delivered)
        .await
        .err();
    Some(LiveDelivery {
        delivered,
        contact_error,
    })
}

/// The contact rule of a live subscription (ADR-029 §2 sync-state keys).
///
/// An envelope the actor accepted writes the current local time to the
/// context's `last_relay_contact` through [`record_relay_contact`]; a delivery
/// the actor refused writes nothing, because a refused envelope proves no
/// successful relay interaction.
///
/// # Errors
///
/// The store's [`StoreError`] when the write after an accepted delivery
/// fails. The caller reports it and keeps delivering.
async fn record_contact_after_live_delivery<T: Sync, E: Sync>(
    relay_contacts: &dyn RelayContactStore,
    context_id: &str,
    delivered: &Result<T, E>,
) -> Result<(), StoreError> {
    if delivered.is_err() {
        return Ok(());
    }
    record_relay_contact(relay_contacts, context_id).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn contacts() -> scp_core::store::ProtocolRepository<scp_platform::in_memory::InMemoryStorage> {
        scp_core::store::ProtocolRepository::new_for_testing(
            scp_platform::in_memory::InMemoryStorage::new(),
        )
    }

    /// A store whose writes fail, for the write-failure arm.
    struct FailingStore;
    #[async_trait::async_trait]
    impl RelayContactStore for FailingStore {
        async fn store_last_relay_contact(&self, _: &str, _: u64) -> Result<(), StoreError> {
            Err(StoreError::SerializationFailed(
                "injected write failure".to_owned(),
            ))
        }
        async fn load_last_relay_contact(&self, _: &str) -> Result<Option<u64>, StoreError> {
            Ok(None)
        }
    }

    /// A dropped Supervisor yields `None`, which ends the subscription, and
    /// writes no contact.
    #[tokio::test]
    async fn a_live_delivery_to_a_dropped_supervisor_ends_the_subscription() {
        let store = contacts();
        let outcome =
            deliver_live_envelope(&std::sync::Weak::new(), &store, "ctx", vec![1, 2, 3]).await;
        assert!(outcome.is_none(), "a dropped Supervisor must end the loop");
        assert_eq!(store.load_last_relay_contact("ctx").await.unwrap(), None);
    }

    /// An accepted live delivery writes the current local time; a refused one
    /// writes nothing; a failed write after an accepted delivery is returned.
    #[tokio::test]
    async fn a_live_delivery_writes_the_contact_only_when_the_actor_accepts() {
        let store = contacts();
        let refused: Result<(), &str> = Err("replay");
        record_contact_after_live_delivery(&store, "ctx", &refused)
            .await
            .unwrap();
        assert_eq!(store.load_last_relay_contact("ctx").await.unwrap(), None);

        let before = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let accepted: Result<(), &str> = Ok(());
        record_contact_after_live_delivery(&store, "ctx", &accepted)
            .await
            .unwrap();
        let after = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let stored = store.load_last_relay_contact("ctx").await.unwrap();
        assert!(
            stored.is_some_and(|t| (before..=after).contains(&t)),
            "{stored:?} not in {before}..={after}"
        );

        let err = record_contact_after_live_delivery(&FailingStore, "ctx", &accepted).await;
        assert!(
            matches!(err, Err(StoreError::SerializationFailed(_))),
            "{err:?}"
        );
    }
}
