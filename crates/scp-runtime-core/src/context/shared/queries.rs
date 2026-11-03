//! Items the queries domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::actor::class_s::ClassCMut;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::signer::CommandSigner;
use crate::context::builder::ContextEventLogProvider;
use crate::context::state;
use crate::context::state::EpochState;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::membership::ReceiveBuffer;
use scp_protocol::context::roles::Capability;

/// Maximum number of checkpoints retained per context. Older checkpoints
/// are drained when this limit is exceeded to prevent unbounded growth.
pub const MAX_RETAINED_CHECKPOINTS: usize = 100;

/// Clears the context's `EpochState.needs_reconnect` flag (spec §23.11).
///
/// Mutating — called by the reconnection driver after a context completes
/// the six-phase protocol successfully so a later restore does not
/// re-drive the already-synced context.
///
/// Field-narrowed (ADR-049 §9) to `&mut EpochState` so a cell-holder calls it
/// with `cell.class_c_view().epoch_mut()` (no whole-state `state_mut()`), while
/// a bare-`&mut PerContextState` holder passes `&mut state.epoch`. The
/// `needs_reconnect` flag is Class-C reconnection liveness state, not a
/// fail-closed Class-S witness.
pub const fn clear_needs_reconnect(epoch: &mut EpochState) {
    epoch.needs_reconnect = false;
}

/// Reports that a received envelope triggered degraded mode (§13.6).
///
/// Emits a `DegradedMode` event into the receive buffer (and the
/// optional event broadcast channel from `deps.event_tx`).
pub fn report_degraded_mode(
    receive_buffer: &mut ReceiveBuffer,
    deps: &ActorDeps,
    context_id: &str,
    compat: scp_protocol::envelope::VersionCompatibility,
    unsupported_features: Vec<String>,
) {
    if let scp_protocol::envelope::VersionCompatibility::DegradedMode {
        local_minor,
        remote_minor,
    } = compat
    {
        let local_major =
            scp_protocol::envelope::version_major(scp_protocol::envelope::SCP_PROTOCOL_VERSION);
        let remote_major = local_major; // same major guaranteed by VersionCompatibility
        let event = ContextEvent::DegradedMode {
            context_id: context_id.to_owned(),
            local_version: (local_major, local_minor),
            remote_version: (remote_major, remote_minor),
            unsupported_features,
        };
        state::emit_event_into(receive_buffer, event, context_id, deps.event_tx.as_ref());
    }
}

/// Generates and stores a per-member access key.
///
/// # Errors
///
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member.
pub fn generate_context_access_key(
    view: &mut ClassCMut,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !view
        .role_state_class_c_mut()
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !view.membership_class_c_mut().contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    view.access_mut()
        .access_key_store
        .set(context_id, member_did, key);
    Ok(())
}

/// Revokes (removes) a member's access key from the access key store.
///
/// # Errors
///
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if no access key exists for
///   `member_did`.
pub fn revoke_context_access_key(
    view: &mut ClassCMut,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !view
        .role_state_class_c_mut()
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    view.access_mut()
        .access_key_store
        .remove(context_id, member_did)
        .ok_or_else(|| {
            ContextError::MemberNotFound(format!("no access key found for member: {member_did}"))
        })?;
    Ok(())
}

/// Restores a member's access key by generating a new key at epoch 0.
///
/// # Errors
///
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member.
pub fn restore_context_access_key(
    view: &mut ClassCMut,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !view
        .role_state_class_c_mut()
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !view.membership_class_c_mut().contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    view.access_mut()
        .access_key_store
        .set(context_id, member_did, key);
    Ok(())
}

/// Records an already-signed consistency checkpoint (from
/// [`build_checkpoint`]) as the context's newest, regardless of whether the
/// event/time thresholds have been reached.
///
/// Takes per-field references so callers may pass disjoint sub-borrows of the
/// unified [`PerContextState`] (ADR-049 §Decision 1).
///
/// The checkpoint is built and signed before this call because signing awaits
/// custody (ADR-049 Decision 7a) and the close path records it inside a
/// synchronous Class-S combinator closure.
pub fn force_create_checkpoint_fields(
    context_id: &str,
    checkpoint_events_since: &mut u64,
    checkpoint_last_time_secs: &mut u64,
    checkpoints: &mut Vec<scp_event_log::checkpoint::ConsistencyCheckpoint>,
    cp: scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
    let now = cp.timestamp;
    *checkpoint_events_since = 0;
    *checkpoint_last_time_secs = now;
    checkpoints.push(cp.clone());

    if checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
        checkpoints.drain(..checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
    }

    tracing::info!(
        context_id,
        event_count = cp.event_count,
        "forced final checkpoint on context close (§9.9.3)"
    );

    cp
}

/// Unconditionally creates a consistency checkpoint via a [`ClassCMut`] view,
/// the actor-shape sibling of [`force_create_checkpoint_fields`].
///
/// Identical semantics, but reaches the three Class-C checkpoint fields
/// (`checkpoint_events_since`, `checkpoint_last_time_secs`, `checkpoints`)
/// through the view's field-granular accessors — touched in SEPARATE
/// statements so each `&mut` borrow ends before the next, which is what lets
/// the actor handler drive this with no whole `&mut PerContextState`.
/// `broadcast_context_is_none` and `mls_epoch` are read by the caller from the
/// view (their borrows released) before this call. Returns the built checkpoint.
///
/// The checkpoint is signed through `signer` (ADR-049 Decision 7a) before any
/// checkpoint field is touched, so a failed sign leaves the view unchanged.
///
/// # Errors
///
/// Any error [`build_checkpoint`] returns.
#[allow(clippy::too_many_arguments)]
pub async fn force_create_checkpoint_view(
    view: &mut ClassCMut<'_>,
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    sender_did: &DID,
    signer: &CommandSigner,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError> {
    let cp = build_checkpoint(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        sender_did,
        signer,
        now,
        event_log,
    )
    .await?;

    // Sequential per-field view accessors: each `&mut` borrow ends before the
    // next, so no whole `&mut PerContextState` (nor a 3-field simultaneous
    // borrow) is needed.
    *view.checkpoint_events_since_mut() = 0;
    *view.checkpoint_last_time_secs_mut() = now;
    {
        let checkpoints = view.checkpoints_mut();
        checkpoints.push(cp.clone());
        if checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
            checkpoints.drain(..checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
        }
    }

    tracing::info!(
        context_id,
        event_count = cp.event_count,
        "forced final checkpoint on context close (§9.9.3)"
    );

    Ok(cp)
}

/// Creates a consistency checkpoint when due (§9.9.3 thresholds) via a
/// [`ClassCMut`] view — the actor-shape checkpoint entry for the send path.
///
/// Same §9.9.3 gating (50-event / 600-second thresholds) and semantics as the
/// unconditional [`force_create_checkpoint_view`], but reaches the three Class-C
/// checkpoint
/// fields (`checkpoint_events_since`, `checkpoint_last_time_secs`,
/// `checkpoints`) through the view's field-granular accessors, touched in
/// SEPARATE statements so each `&mut` borrow ends before the next — which is
/// what lets the send path drive this with no whole `&mut PerContextState` (nor
/// a 3-field simultaneous borrow). `broadcast_context_is_none` and `mls_epoch`
/// are read by the caller from the view (their borrows released) before this
/// call. Returns the built checkpoint when one was due, else `None`.
///
/// The checkpoint is signed through `signer` (ADR-049 Decision 7a) before any
/// checkpoint field is touched, so a failed sign leaves the thresholds armed
/// and the next send retries.
///
/// # Errors
///
/// Any error [`build_checkpoint`] returns.
#[allow(clippy::too_many_arguments)]
pub async fn create_checkpoint_if_due_view(
    view: &mut ClassCMut<'_>,
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    sender_did: &DID,
    signer: &CommandSigner,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> Result<Option<scp_event_log::checkpoint::ConsistencyCheckpoint>, ContextError> {
    let events_since = *view.checkpoint_events_since_mut();
    let last_time = *view.checkpoint_last_time_secs_mut();
    let events_due = events_since >= 50;
    // Time-based checkpoints require at least one event — creating a checkpoint
    // for zero events is wasteful and indistinguishable from the previous one.
    let time_due = events_since > 0 && now.saturating_sub(last_time) >= 600;

    if !events_due && !time_due {
        return Ok(None);
    }

    let cp = build_checkpoint(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        sender_did,
        signer,
        now,
        event_log,
    )
    .await?;

    // Sequential per-field view accessors: each `&mut` borrow ends before the
    // next, so no whole `&mut PerContextState` (nor a 3-field simultaneous
    // borrow) is needed.
    *view.checkpoint_events_since_mut() = 0;
    *view.checkpoint_last_time_secs_mut() = now;
    {
        let checkpoints = view.checkpoints_mut();
        checkpoints.push(cp.clone());
        if checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
            checkpoints.drain(..checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
        }
    }

    tracing::debug!(
        context_id,
        event_count = cp.event_count,
        "consistency checkpoint created (§9.9.3)"
    );

    Ok(Some(cp))
}

/// Builds a signed checkpoint from the current event log over the field slice
/// the §9.9.3 canonical-hash inputs require.
///
/// The `SCP-CHECKPOINT-V1:` canonical hash is computed first, then signed
/// through `signer` within the custody budget (ADR-049 Decision 7a).
///
/// # Errors
///
/// - The event log's error when its count and root cannot be read; no
///   checkpoint is signed over a log the node could not read.
/// - [`ContextError::Custody`] when custody refuses the sign or does not
///   answer within the budget (`TimedOut`, `SCP-CRYPTO-4062`).
/// - [`ContextError::CryptoFailed`] when the canonical hash is not 32 bytes.
pub async fn build_checkpoint(
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    sender_did: &DID,
    signer: &CommandSigner,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError> {
    // One read of the log state for both values, propagated: a failed read
    // never becomes a signed claim of an empty log.
    let (count, merkle_root) =
        event_log.event_log_summary(&state::context_id_to_bytes(context_id))?;
    let event_count = count as u64;

    // Encrypted contexts (no broadcast_context) use MLS epochs; broadcast
    // contexts do not use MLS and have no meaningful epoch.
    let epoch = if broadcast_context_is_none {
        Some(mls_epoch)
    } else {
        None
    };

    let canonical_hash = scp_event_log::checkpoint::compute_checkpoint_canonical_hash(
        context_id,
        sender_did.as_ref(),
        event_count,
        &merkle_root,
        epoch,
        now,
    );

    let digest = <[u8; 32]>::try_from(canonical_hash.as_slice()).map_err(|_| {
        ContextError::CryptoFailed(format!(
            "checkpoint canonical hash is {} bytes, expected 32",
            canonical_hash.len()
        ))
    })?;
    let signature = signer.sign_bounded_ed25519(&digest).await?;

    Ok(scp_event_log::checkpoint::ConsistencyCheckpoint {
        context_id: context_id.to_owned(),
        sender_did: sender_did.clone(),
        event_count,
        merkle_root,
        epoch,
        timestamp: now,
        signature: signature.to_vec(),
    })
}

/// Registers a DID as controlled by the local node/SDK.
///
/// Supervisor-scoped — mutates `supervisor.local_dids` under the
/// supervisor's write lock. No per-context actor-shape twin exists
/// because the actor model serializes per-context, not supervisor-wide.
pub async fn register_local_did(supervisor: &crate::context::supervisor::Supervisor, did: DID) {
    // ArcSwap+write_lock pattern (ADR-049 §Decision 12). Reads are
    // lock-free; writes serialize on the supervisor write_lock to
    // avoid lost updates against the cloned snapshot.
    let _guard = supervisor.write_lock.lock().await;
    let snapshot = supervisor.local_dids_ref().load_full();
    let mut updated: std::collections::HashSet<DID> = (*snapshot).clone();
    updated.insert(did);
    supervisor
        .local_dids_ref()
        .store(std::sync::Arc::new(updated));
}

/// Returns `true` if the given DID is registered as locally controlled.
///
/// Supervisor-scoped read. No actor-shape twin.
///
/// `async` is preserved (despite no `await` after the §12 lock-free
/// read migration) to keep the signature symmetric with
/// [`register_local_did`] and the legacy method, matching the call
/// shape the FFI bridges + `Supervisor::is_local_did` passthrough
/// expect.
#[allow(clippy::unused_async)]
pub async fn is_local_did(supervisor: &crate::context::supervisor::Supervisor, did: &DID) -> bool {
    // Lock-free read (ADR-049 §Decision 12).
    supervisor.local_dids_ref().load().contains(did)
}
