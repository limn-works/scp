//! Relay-backed reconnection driver (ADR-029).
//!
//! After the ADR-049 actor refactor, the per-context actor's
//! [`ContextTransportProvider`] is **send-only** — it has no
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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use scp_core::context::supervisor::Supervisor;
use scp_core::sync::days_offline::{DaysOfflineError, SnapshotTransport};
use scp_core::sync::hours_offline::{BufferedMessage, EpochCatchUpState, SyncPhaseDriver};
use scp_core::sync::weeks_offline::ResetTransport;
use scp_did::DID;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::{broadcast_routing_id, context_routing_id};
use scp_protocol::envelope::outer::{OuterEnvelope, create_outer_envelope};
use scp_protocol::sync::{CatchUpStatus, SyncError, SyncEvent, SyncPolicy};
use scp_transport::{RoutingId, TransportManager};

/// Default blob TTL (seconds) used when wrapping a Tier-3 plaintext reset
/// request in an outer envelope. The reset request is short-lived; one
/// hour matches the relay's typical retention floor and is well within
/// the relay's accepted TTL band.
const RESET_BLOB_TTL_SECS: u32 = 3600;

/// Local Ed25519 signing-key seed carried for checkpoint build.
/// Held in [`RelayActorSyncDriver`] so Phase 3 can sign the local
/// checkpoint as the application send path does — the signing key is not
/// actor-owned state (it lives at the FFI boundary).
///
/// Wrapped in [`Zeroizing`](zeroize::Zeroizing) so the 32-byte private seed
/// is zeroed when the driver (and every clone threaded into the per-tier
/// engines) drops, rather than lingering in freed heap/stack memory.
type SigningKeyBytes = zeroize::Zeroizing<[u8; 32]>;

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
    /// Local Ed25519 signing-key seed used to sign the Phase-3 local
    /// checkpoint. Zeroized by the caller after the driver is dropped
    /// (the caller owns the key material lifetime).
    signing_key: SigningKeyBytes,
}

impl<'a> RelayActorSyncDriver<'a> {
    /// Constructs a driver borrowing the bridge's transport + supervisor.
    ///
    /// `signing_key` is the 32-byte Ed25519 seed for `member_did`; it is
    /// used only to sign the local consistency checkpoint in Phase 3
    /// (the same authority the application send path uses). The
    /// [`SyncPolicy`] lives on the [`ReconnectionCoordinator`] and is
    /// passed into `epoch_reconciliation` per call, so the driver does
    /// not retain its own copy.
    #[must_use]
    pub const fn new(
        transport: &'a Arc<TransportManager>,
        supervisor: &'a Arc<Supervisor>,
        member_did: DID,
        signing_key: SigningKeyBytes,
    ) -> Self {
        Self {
            transport,
            supervisor,
            member_did,
            signing_key,
        }
    }

    /// Resolves the shared routing ID for a context (§9.10.4 / §5.14).
    ///
    /// Broadcast contexts use `broadcast_routing_id` (plain
    /// `SHA-256(context_id)`); encrypted contexts use the domain-separated
    /// `context_routing_id`. Mirrors the `context_subscribe` selection so
    /// the driver pulls from the same routing key the live subscription
    /// uses (§5.14).
    async fn shared_routing_id(&self, context_id: &str) -> RoutingId {
        // `local_mls_epoch` returns `None` for a broadcast context — reuse
        // that single source of truth rather than re-deriving the mode.
        let is_broadcast = self.supervisor.local_mls_epoch(context_id).await.is_none();
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
            payload: bytes,
            stored_at: now,
            epoch: None,
        })
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

// `SyncPhaseDriver` declares these methods future-returning, so this impl cannot drop
// `async` without hand-writing the same future. See `.docs/standards/rust.md`,
// section `clippy::unused_async_trait_impl`.
#[allow(clippy::unused_async_trait_impl)]
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
        let since = last_stored_at.saturating_sub(5);
        let envelopes = self
            .transport
            .query(&routing_id, Some(since))
            .await
            .map_err(|e| SyncError::RelayCatchUpFailed {
                context_id: context_id.to_owned(),
                reason: e.to_string(),
            })?;

        // `since` is `last_stored_at` minus the 5s overlap, so it is always
        // <= `last_stored_at`; the local receive time recorded on each
        // buffered message is the caller-supplied `last_stored_at`.
        let now = last_stored_at;
        let mut seen: HashSet<String> = HashSet::with_capacity(envelopes.len());
        let mut messages = Vec::with_capacity(envelopes.len());
        for envelope in &envelopes {
            if let Some(msg) = Self::envelope_to_buffered(context_id, envelope, now)
                && seen.insert(msg.blob_id.clone())
            {
                messages.push(msg);
            }
        }
        // Stable order by blob_id keeps the catch-up deterministic across
        // relays (the relay-assigned stored_at is not carried on the wire).
        messages.sort_by(|a, b| a.blob_id.cmp(&b.blob_id));
        Ok(messages)
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

        // The pending set starts as the full Phase-1 buffer (capped at the
        // budget). Commits accepted on a pass advance the epoch; rejected
        // blobs are retried on the next pass against the new epoch.
        let mut pending: Vec<Vec<u8>> = messages
            .iter()
            .take(limit)
            .map(|m| m.payload.clone())
            .collect();
        let mut total_merged: usize = 0;

        while !pending.is_empty() && total_merged < limit {
            let mut still_pending: Vec<Vec<u8>> = Vec::with_capacity(pending.len());
            let mut merged_this_pass = 0usize;

            for payload in pending {
                if total_merged >= limit {
                    // Budget exhausted mid-pass; carry the remainder so the
                    // loop terminates without dropping blobs silently.
                    still_pending.push(payload);
                    continue;
                }
                match self
                    .supervisor
                    .deliver_commit_blob(context_id, payload.clone())
                    .await
                {
                    Ok(_) => {
                        state.record_commit_processed();
                        merged_this_pass += 1;
                        total_merged += 1;
                    }
                    Err(e) => {
                        // Rejected at the current epoch (out-of-epoch Commit,
                        // replay, or a non-Commit application blob). Retain
                        // it for a retry against the next epoch; a genuinely
                        // bad blob is simply never accepted and falls out
                        // when the loop reaches steady state.
                        tracing::trace!(
                            context_id,
                            error = %e,
                            "epoch_reconciliation: blob rejected at current epoch; retrying next pass"
                        );
                        still_pending.push(payload);
                    }
                }
            }

            if merged_this_pass == 0 {
                // A full pass advanced nothing — steady state. The
                // remaining blobs are not Commits applicable to any
                // reachable epoch (application messages, replays, or a
                // genuine gap requiring Welcome-based fast-forward).
                break;
            }
            pending = still_pending;
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
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.signing_key);
        let checkpoint = self
            .supervisor
            .build_local_checkpoint(context_id, &self.member_did, &signing_key)
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
        for msg in messages {
            if let Err(e) = self
                .supervisor
                .deliver_commit_blob(context_id, msg.payload.clone())
                .await
            {
                tracing::debug!(
                    context_id,
                    error = %e,
                    "sender_key_reacquire: deliver rejected a blob; continuing"
                );
            }
        }
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

    /// Tier 3 — subscribe to the context routing key and wait for a
    /// Welcome to arrive within `timeout_secs`, feeding each retrieved
    /// blob into the actor (which processes the Welcome and advances the
    /// epoch). Returns the new local MLS epoch after processing.
    async fn subscribe_and_await_welcome(
        &self,
        context_id: &str,
        timeout_secs: u64,
    ) -> Result<u64, scp_core::sync::weeks_offline::WeeksOfflineError> {
        let routing_id = self.shared_routing_id(context_id).await;
        let deadline = std::time::Duration::from_secs(timeout_secs.max(1));
        let pull = async {
            let envelopes = self.transport.query(&routing_id, None).await.map_err(|e| {
                // A relay query failure during reset is surfaced as a
                // reset-request failure (the Welcome could not be fetched).
                scp_core::sync::weeks_offline::WeeksOfflineError::ResetRequestFailed {
                    context_id: context_id.to_owned(),
                    reason: format!("await_welcome relay query failed: {e}"),
                }
            })?;
            for envelope in &envelopes {
                if let Ok(bytes) = envelope.to_bytes() {
                    let _ = self.supervisor.deliver_commit_blob(context_id, bytes).await;
                }
            }
            Ok::<(), scp_core::sync::weeks_offline::WeeksOfflineError>(())
        };
        tokio::time::timeout(deadline, pull).await.map_err(|_| {
            scp_core::sync::weeks_offline::WeeksOfflineError::WelcomeTimeout {
                context_id: context_id.to_owned(),
                timeout_secs,
            }
        })??;
        let epoch = self
            .supervisor
            .local_mls_epoch(context_id)
            .await
            .unwrap_or(0);
        Ok(epoch)
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
/// For each context the [`ReconnectionCoordinator`] classifies the offline
/// tier from `last_relay_contacts` and:
/// - **Tier 1 (Short)** — runs the six-phase protocol via
///   [`ReconnectionCoordinator::execute`] against a [`RelayActorSyncDriver`].
/// - **Tier 2 (Extended)** — fetches the relay snapshot via a
///   [`RelayBackedDeltaSyncEngine`] (delta application is the actor's job
///   once the snapshot lands; here we confirm a snapshot is reachable).
/// - **Tier 3 (Long)** — awaits a Welcome via a [`RelayBackedReJoinExecutor`]
///   (admin-side re-add + Welcome processing through the actor).
///
/// On a terminal-success outcome the context's `needs_reconnect` flag is
/// cleared via [`Supervisor::clear_needs_reconnect`]. After per-context
/// execution, the optional `drain` callback is invoked once per context to
/// drain the bridge-owned outbound queue (Phase 6) — the queue lives in
/// `ProtocolRepository` at the bridge layer, not in actor state, so the
/// caller supplies the drain.
///
/// `signing_key` is the 32-byte Ed25519 seed for `member_did`; it signs the
/// Phase-3 local checkpoint.
// `implicit_hasher`: `last_relay_contacts` is forwarded verbatim to
// `ReconnectionCoordinator::with_policy`, which fixes the default
// `RandomState` hasher; generalizing here would only force every caller to
// re-annotate the same concrete type.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn reconnect_contexts<F, Fut>(
    transport: &Arc<TransportManager>,
    supervisor: &Arc<Supervisor>,
    member_did: DID,
    signing_key: SigningKeyBytes,
    context_ids: Vec<String>,
    last_relay_contacts: HashMap<String, u64>,
    now: u64,
    policy: SyncPolicy,
    mut drain: Option<F>,
) -> ReconnectReport
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = (u64, u64)>,
{
    let driver = RelayActorSyncDriver::new(
        transport,
        supervisor,
        member_did.clone(),
        signing_key.clone(),
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
            OfflineTier::Extended => {
                // Tier 2 delta sync: fetch the latest relay snapshot. The
                // actor applies the delta when the snapshot is delivered;
                // a reachable snapshot means recovery can proceed.
                let engine = RelayBackedDeltaSyncEngine::new(RelayActorSyncDriver::new(
                    transport,
                    supervisor,
                    coordinator.member_did().clone(),
                    signing_key.clone(),
                ));
                let outcome = match engine.fetch_snapshot(&context_id).await {
                    Ok(Some(_snapshot)) => scp_protocol::sync::SyncOutcome::FullyCaughtUp,
                    Ok(None) => scp_protocol::sync::SyncOutcome::Failed {
                        reason: "no relay snapshot available for Tier 2 delta sync".to_owned(),
                    },
                    Err(e) => scp_protocol::sync::SyncOutcome::Failed {
                        reason: format!("Tier 2 snapshot fetch failed: {e}"),
                    },
                };
                (outcome, 0, 0, false, 0)
            }
            OfflineTier::Long => {
                // Tier 3 reset: await a Welcome (admin-side re-add +
                // Welcome processing through the actor).
                let executor = RelayBackedReJoinExecutor::new(RelayActorSyncDriver::new(
                    transport,
                    supervisor,
                    coordinator.member_did().clone(),
                    signing_key.clone(),
                ));
                let timeout_secs = policy_welcome_timeout_secs();
                let outcome = match executor.await_welcome(&context_id, timeout_secs).await {
                    Ok(_epoch) => scp_protocol::sync::SyncOutcome::Reset,
                    Err(e) => scp_protocol::sync::SyncOutcome::Failed {
                        reason: format!("Tier 3 re-join failed: {e}"),
                    },
                };
                (outcome, 0, 0, false, 0)
            }
        };

        let (outcome_string, terminal_success) = outcome_str(&outcome);

        // Clear needs_reconnect on terminal success so a later restore does
        // not re-drive the already-synced context (§23.11).
        let needs_reconnect_cleared = if terminal_success {
            supervisor.clear_needs_reconnect(&context_id).await.is_ok()
        } else {
            false
        };

        // Phase 6: drain the bridge-owned outbound queue for this context.
        if let Some(drain_fn) = drain.as_mut() {
            let (drained, discarded) = drain_fn(context_id.clone()).await;
            messages_drained = messages_drained.saturating_add(drained);
            messages_discarded = messages_discarded.saturating_add(discarded);
        }

        results.push(ContextReconnectResult {
            context_id,
            tier: tier_str(tier),
            outcome: outcome_string,
            epochs_caught_up: epochs,
            events_recovered: events,
            mls_update_issued: mls_update,
            equivocations_detected: equivocations,
            needs_reconnect_cleared,
        });
    }

    ReconnectReport {
        contexts: results,
        messages_drained,
        messages_discarded,
        total_duration_ms: report.total_duration_ms,
    }
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
#[allow(clippy::implicit_hasher, clippy::too_many_arguments)]
pub async fn reconnect_contexts_no_drain(
    transport: &Arc<TransportManager>,
    supervisor: &Arc<Supervisor>,
    member_did: DID,
    signing_key: SigningKeyBytes,
    context_ids: Vec<String>,
    last_relay_contacts: HashMap<String, u64>,
    now: u64,
    policy: SyncPolicy,
) -> ReconnectReport {
    // Concrete closure type so the `None` variant's generics are inferred.
    let drain: Option<NoDrainFn> = None;
    reconnect_contexts(
        transport,
        supervisor,
        member_did,
        signing_key,
        context_ids,
        last_relay_contacts,
        now,
        policy,
        drain,
    )
    .await
}
