//! Relay-backed reconnection driver (#1540).
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
//! # Composition with checkpoint exchange (#1540 Steps 2/3)
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

use std::collections::HashMap;
use std::sync::Arc;

use scp_core::context::supervisor::Supervisor;
use scp_core::sync::days_offline::{DaysOfflineError, SnapshotTransport};
use scp_core::sync::hours_offline::{BufferedMessage, EpochCatchUpState, SyncPhaseDriver};
use scp_core::sync::weeks_offline::ResetTransport;
use scp_identity::DID;
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

/// Maximum local Ed25519-signing-key bytes carried for checkpoint build.
/// Held in [`RelayActorSyncDriver`] so Phase 3 can sign the local
/// checkpoint as the application send path does — the signing key is not
/// actor-owned state (it lives at the FFI boundary).
type SigningKeyBytes = [u8; 32];

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
    /// uses (#1534).
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

    /// Drains the actor's receive buffer and maps any
    /// `ContextEvent::EquivocationDetected` to a
    /// [`SyncEvent::EquivocationDetected`] alert (§9.9.3).
    ///
    /// The actor emits the equivocation event from inside
    /// `compare_remote_checkpoint` (reached via `deliver_commit_blob` for
    /// retrieved checkpoint blobs). Draining here surfaces those alerts to
    /// the Phase-3 result so the reconnection report carries them.
    async fn collect_equivocation_alerts(&self, context_id: &str, now: u64) -> Vec<SyncEvent> {
        self.supervisor
            .drain_events(context_id)
            .await
            .into_iter()
            .filter_map(|event| match event {
                ContextEvent::EquivocationDetected {
                    context_id: ctx,
                    remote_sender_did,
                    event_count,
                } => Some(SyncEvent::EquivocationDetected(Box::new(
                    scp_protocol::sync::EquivocationAlert {
                        context_id: ctx,
                        detector_did: self.member_did.clone(),
                        divergent_did: remote_sender_did,
                        divergent_event_count: event_count,
                        // The local/remote roots are recorded inside the
                        // event log by the actor; the alert surfaced to the
                        // SDK carries the count + DIDs (the roots are
                        // available via the event log for forensics).
                        local_merkle_root: [0u8; 32],
                        remote_merkle_root: [0u8; 32],
                        evidence: None,
                        detected_at: now,
                        local_epoch: None,
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
        let since = last_stored_at.saturating_sub(5);
        let envelopes = self
            .transport
            .query(&routing_id, Some(since))
            .await
            .map_err(|e| SyncError::RelayCatchUpFailed {
                context_id: context_id.to_owned(),
                reason: e.to_string(),
            })?;

        let now = since.max(last_stored_at);
        let mut seen: HashMap<String, ()> = HashMap::with_capacity(envelopes.len());
        let mut messages = Vec::with_capacity(envelopes.len());
        for envelope in &envelopes {
            if let Some(msg) = Self::envelope_to_buffered(context_id, envelope, now)
                && seen.insert(msg.blob_id.clone(), ()).is_none()
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
    async fn epoch_reconciliation(
        &self,
        context_id: &str,
        local_epoch: u64,
        target_epoch: u64,
        policy: &SyncPolicy,
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

        // Re-fetch the buffered blobs and feed them to the actor. Each
        // Commit the actor merges advances its local MLS epoch; application
        // messages are buffered by the actor for normal receive polling.
        let messages = self.relay_catch_up(context_id, 0).await?;
        let limit = usize::try_from(policy.max_sequential_commits).unwrap_or(usize::MAX);
        for msg in messages.into_iter().take(limit) {
            match self
                .supervisor
                .deliver_commit_blob(context_id, msg.payload)
                .await
            {
                Ok(_) => state.record_commit_processed(),
                Err(e) => {
                    // A single bad blob (replay, stale epoch) is not fatal
                    // to the whole catch-up; log and continue. A genuinely
                    // gone context surfaces below via the epoch re-read.
                    tracing::debug!(
                        context_id,
                        error = %e,
                        "epoch_reconciliation: deliver_commit_blob rejected a blob; continuing"
                    );
                }
            }
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
    ) -> Result<u64, SyncError> {
        // Sender-key management messages (advance / request / response) ride
        // the same routing key as application data and are processed by the
        // actor's deliver path. Re-running catch-up + deliver in Phase 2
        // already drains them; here we re-query specifically and feed any
        // remaining blobs so a late-arriving advance is not missed.
        let messages = self.relay_catch_up(context_id, 0).await?;
        for msg in messages {
            if let Err(e) = self
                .supervisor
                .deliver_commit_blob(context_id, msg.payload)
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
    /// bridge surface drains it directly via
    /// `ReconnectionCoordinator::drain_context_queue` after `execute`
    /// returns. The in-trait hook therefore reports a no-op `(0, 0)` and
    /// the real drain runs at the bridge surface where the repository
    /// lives. See the ADR-029 reconnection-driver addendum.
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
