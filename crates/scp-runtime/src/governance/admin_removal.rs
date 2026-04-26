#![allow(
    clippy::too_many_lines,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_overindented_list_items
)]

//! Admin-removal salt-rotation handler — atomic
//! `RemoveMember`+`InterfaceSaltRotated` emission per §6.2.0.1 round-6
//! (SCP-OUT-042c).
//!
//! # Construction overview
//!
//! When governance approves a `RemoveMember` action whose target holds
//! the admin role, this module's [`emit_admin_removal_with_rotations`]
//! routine:
//!
//! 1. Enumerates the local context's active outlet interfaces.
//! 2. Validates `induced_rotations` against the active set via
//!    [`crate::context::interface::validate_remove_member_induced_rotations`]
//!    (closes the OUT-042d governance gate).
//! 3. For each active interface, derives a fresh `new_ikm_local` via
//!    the §6.2.0.1 step-1 peer-suffixed MLS exporter at the local
//!    context's CURRENT epoch, signs the
//!    `SCP-OUTLET-IKM-ROTATE-V1:` preimage under the remaining admin's
//!    `#active` key, and assembles an [`InterfaceSaltRotated`] entry
//!    citing the upcoming `RemoveMember` event id.
//! 4. Returns an [`AdminRemovalBatch`] containing the populated
//!    `RemoveMember` action + the per-interface rotation events. The
//!    caller MUST atomically append these to the same MLS commit batch
//!    (§6.2.0.1 "Atomic removal+rotation — local-side semantics").
//!
//! # `hop_salt` state machine
//!
//! Per active interface, the state transitions on this code path are:
//!
//! ```text
//! PreRotation  --(RemoveMember proposal)-->  Frozen
//! Frozen       --(commit-batch lands)----->  PostRotation
//! ```
//!
//! While `Frozen`, [`OutboundOutletErrorQueue::buffer_or_emit`]
//! buffers any new `OutletError` envelope on the affected interface;
//! on `Frozen → PostRotation` the queue is drained and emits each
//! envelope under the new `hop_salt` (§6.2.0.1 "Outbound queue
//! discipline"). Envelopes whose buffered age exceeds
//! `outlet_error_buffer_max_secs` are dropped with the
//! `governance.remove-member-buffer-overflow` audit-log slug and the
//! removal-timeout escalates.
//!
//! # Verifier rule
//!
//! [`verify_rotation`] implements the §6.2.0.1 round-6 verifier
//! rejection rule. A rotation is rejected with
//! `authorization.salt-rotation-unjustified` (`SCP-TOOL-6115`) when
//! ANY of:
//!
//! 1. `new_ikm_local_sig` fails verification under the signing admin's
//!    `#active` key against the `SCP-OUTLET-IKM-ROTATE-V1:` preimage.
//! 2. `removal_event_id` does not reference a prior admin-removal
//!    event in the same local event log whose target DID equals
//!    `trigger_removal_did` and whose epoch equals or is one less
//!    than `epoch_local`.
//! 3. The same `removal_event_id` has already been cited by a prior
//!    `InterfaceSaltRotated` on the same `interface_id`.
//!
//! # Peer-side semantics
//!
//! [`build_peer_reciprocal_rotation`] mirrors the construction for
//! the peer side: same preimage, same domain separator, but uses the
//! peer's local `AdminRemovalMirror` event id and the peer's own
//! fresh IKM signed by the peer's remaining admin. Per §6.2.0.1
//! "Atomic removal+rotation — peer-side semantics" the peer enters
//! `Frozen` on shared-member-bridged receipt and exits when its own
//! reciprocal rotation commits.

use std::collections::{HashMap, VecDeque};

use ed25519_dalek::{SigningKey, VerifyingKey};
use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::GovernanceAction;
use scp_protocol::context::outlets::error_codes::{
    CODE_AUTHORIZATION_SALT_ROTATION, SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED,
};
use scp_protocol::context::outlets::interface::{
    ContextId, InterfaceSaltRotated, RotationVerifyError, sign_interface_rotation,
    verify_interface_rotation,
};

use crate::context::interface::ikm_commitment::IKM_EXPORTER_LABEL_PREFIX;
use crate::context::interface::ikm_commitment::MlsExporter;
use crate::context::interface::validate_remove_member_induced_rotations;

/// `OutletErrorClass::Authorization` slug emitted when a
/// `InterfaceSaltRotated` event fails the §6.2.0.1 round-6 verifier
/// rule. Pinned to the [`SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED`]
/// constant from `scp_protocol::context::outlets::error_codes` so the
/// bridge layer reads the exact same string.
pub const SALT_ROTATION_UNJUSTIFIED_SLUG: &str = SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED;

/// `SCP-TOOL-NNNN` code attached to the §6.2.0.1 round-6 verifier
/// rejection. Pinned to [`CODE_AUTHORIZATION_SALT_ROTATION`].
pub const SALT_ROTATION_UNJUSTIFIED_CODE: &str = CODE_AUTHORIZATION_SALT_ROTATION;

/// Audit-log slug emitted when a `Frozen`-window-buffered envelope
/// exceeds `ContextParams::outlet_error_buffer_max_secs` and is
/// dropped. The governance-removal timeout escalates per §6.2.0.1
/// "Outbound queue discipline".
pub const BUFFER_OVERFLOW_AUDIT_SLUG: &str = "governance.remove-member-buffer-overflow";

// ---------------------------------------------------------------------------
// hop_salt state machine
// ---------------------------------------------------------------------------

/// Per-interface `hop_salt` state per §6.2.0.1 round-6 atomic
/// removal+rotation invariant.
///
/// ```text
/// PreRotation  --(RemoveMember proposed)-->  Frozen
/// Frozen       --(commit-batch lands)----->  PostRotation
/// ```
///
/// While `Frozen`, no envelopes emit on the affected interface.
/// Buffered envelopes flush on `Frozen → PostRotation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopSaltState {
    /// Pre-rotation steady state. Envelopes emit under the
    /// `InterfaceEstablished`-derived `hop_salt`.
    PreRotation,
    /// Atomic-rotation transient state. Set on `RemoveMember` proposal;
    /// cleared when the commit batch (including every
    /// `InterfaceSaltRotated`) lands. No envelopes emit while
    /// `Frozen`.
    Frozen,
    /// Post-rotation steady state. Envelopes emit under the new
    /// `hop_salt` derived from the rotated IKMs.
    PostRotation,
}

/// Failure modes when a state-machine transition is attempted out of
/// order — e.g. `Frozen → Frozen` or `PostRotation → Frozen` (peer
/// receives a second rotation before its first reciprocal commits).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HopSaltStateError {
    /// Attempted to enter `Frozen` while the interface was already in
    /// a transient state. Indicates concurrent rotation triggers — the
    /// caller MUST sequence them serially.
    #[error("hop_salt state {from:?} cannot transition to Frozen (already mid-rotation)")]
    InvalidFreeze {
        /// State the interface was in when freeze was attempted.
        from: HopSaltState,
    },
    /// Attempted to exit `Frozen → PostRotation` from a non-`Frozen`
    /// state. Indicates the caller skipped the freeze step.
    #[error("hop_salt state {from:?} cannot transition to PostRotation (must come through Frozen)")]
    InvalidUnfreeze {
        /// State the interface was in when unfreeze was attempted.
        from: HopSaltState,
    },
}

impl HopSaltState {
    /// Transitions `PreRotation` (or `PostRotation` after a prior
    /// rotation cycle) into `Frozen`. Concurrent freeze attempts on
    /// the same interface fail loud.
    ///
    /// # Errors
    ///
    /// Returns [`HopSaltStateError::InvalidFreeze`] when called on a
    /// `Frozen` state — the caller must wait for the prior commit batch
    /// to land first.
    pub const fn freeze(self) -> Result<Self, HopSaltStateError> {
        match self {
            Self::PreRotation | Self::PostRotation => Ok(Self::Frozen),
            Self::Frozen => Err(HopSaltStateError::InvalidFreeze { from: self }),
        }
    }

    /// Transitions `Frozen → PostRotation` after the atomic commit
    /// batch lands.
    ///
    /// # Errors
    ///
    /// Returns [`HopSaltStateError::InvalidUnfreeze`] when called on a
    /// non-`Frozen` state — that signals a wiring bug (the caller
    /// skipped the freeze step).
    pub const fn unfreeze(self) -> Result<Self, HopSaltStateError> {
        match self {
            Self::Frozen => Ok(Self::PostRotation),
            Self::PreRotation | Self::PostRotation => {
                Err(HopSaltStateError::InvalidUnfreeze { from: self })
            }
        }
    }

    /// `true` if the state forbids `OutletError` emission. Only the
    /// `Frozen` state buffers; `PreRotation` and `PostRotation` permit
    /// emission under their respective hop-salts.
    #[must_use]
    pub const fn forbids_outlet_error_emission(self) -> bool {
        matches!(self, Self::Frozen)
    }
}

// ---------------------------------------------------------------------------
// Outbound OutletError queue (Frozen-window discipline)
// ---------------------------------------------------------------------------

/// One pending `OutletError` envelope buffered during the `Frozen`
/// window per §6.2.0.1 "Outbound queue discipline". The opaque payload
/// preserves the envelope bytes verbatim — the runtime emits them
/// unchanged once the new `hop_salt` is in effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedOutletError {
    /// Interface id this envelope targets. Used to associate the
    /// buffered envelope with the affected interface's state machine.
    pub interface_id: [u8; 32],
    /// Wall-clock unix-millis at which the envelope was buffered.
    /// Compared against the current time at flush to enforce the
    /// `outlet_error_buffer_max_secs` upper bound.
    pub buffered_at_ms: u64,
    /// Opaque envelope bytes — emitted verbatim on flush. Caller-owned.
    pub envelope_bytes: Vec<u8>,
}

/// Outcome from [`OutboundOutletErrorQueue::buffer_or_emit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferOutcome {
    /// State permits emission — the envelope was passed through and
    /// the queue did NOT buffer it.
    PassThrough,
    /// State is `Frozen` — the envelope was buffered. Returned the new
    /// queue depth for diagnostic surfacing.
    Buffered {
        /// Queue depth (including this envelope) for diagnostics.
        queue_depth: usize,
    },
}

/// Outcome from [`OutboundOutletErrorQueue::flush`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushOutcome {
    /// Envelopes emitted under the new `hop_salt`. Order preserved.
    pub emitted: Vec<BufferedOutletError>,
    /// Envelopes whose buffered-age exceeded
    /// `outlet_error_buffer_max_secs` and were dropped with the
    /// `governance.remove-member-buffer-overflow` audit slug.
    pub dropped: Vec<BufferedOutletError>,
}

/// `Frozen`-window outbound queue for `OutletError` envelopes
/// (§6.2.0.1 round-6 "Outbound queue discipline"). The runtime owns
/// one of these per affected interface.
#[derive(Debug, Default)]
pub struct OutboundOutletErrorQueue {
    pending: HashMap<[u8; 32], VecDeque<BufferedOutletError>>,
}

impl OutboundOutletErrorQueue {
    /// New empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// If `state` is `Frozen`, buffers `envelope` for later emission;
    /// otherwise reports pass-through to the caller.
    pub fn buffer_or_emit(
        &mut self,
        state: HopSaltState,
        envelope: BufferedOutletError,
    ) -> BufferOutcome {
        if state.forbids_outlet_error_emission() {
            let q = self.pending.entry(envelope.interface_id).or_default();
            q.push_back(envelope);
            BufferOutcome::Buffered {
                queue_depth: q.len(),
            }
        } else {
            BufferOutcome::PassThrough
        }
    }

    /// Drains the queue for `interface_id`, partitioning entries into
    /// emitted (within `max_buffer_secs`) vs dropped (older than the
    /// upper bound). Called on `Frozen → PostRotation` transition.
    ///
    /// `max_buffer_secs` is `ContextParams::outlet_error_buffer_max_secs`
    /// per §9.18.B (default 30 s, range [5, 300]).
    pub fn flush(
        &mut self,
        interface_id: &[u8; 32],
        now_ms: u64,
        max_buffer_secs: u32,
    ) -> FlushOutcome {
        let mut emitted = Vec::new();
        let mut dropped = Vec::new();
        let max_age_ms = u64::from(max_buffer_secs).saturating_mul(1_000);
        if let Some(q) = self.pending.remove(interface_id) {
            for env in q {
                let age = now_ms.saturating_sub(env.buffered_at_ms);
                if age > max_age_ms {
                    dropped.push(env);
                } else {
                    emitted.push(env);
                }
            }
        }
        FlushOutcome { emitted, dropped }
    }

    /// Returns the depth of the queue for `interface_id` (0 if no
    /// queue exists). Useful for tests.
    #[must_use]
    pub fn depth(&self, interface_id: &[u8; 32]) -> usize {
        self.pending
            .get(interface_id)
            .map_or(0, std::collections::VecDeque::len)
    }
}

// ---------------------------------------------------------------------------
// Active-interface descriptor for rotation emission
// ---------------------------------------------------------------------------

/// Per-active-interface input to [`emit_admin_removal_with_rotations`].
/// Mirrors the §6.2.0.1 "Active interface state" the runtime tracks for
/// each established interface that needs to be rotated when an admin is
/// removed.
#[derive(Debug, Clone)]
pub struct ActiveInterfaceDescriptor {
    /// The interface/offer identifier.
    pub interface_id: [u8; 32],
    /// Local context's MLS group id (the 32-byte canonical id used by
    /// `ContextCryptoProvider::export_secret_for_context`).
    pub local_context_id_bytes: [u8; 32],
    /// Local human-readable context id (string form, used in the
    /// rotation preimage).
    pub local_context_id: ContextId,
    /// Peer human-readable context id (string form, used in the
    /// rotation preimage AND as the §6.2.0.1 step-1 exporter label
    /// suffix `"scp-context-hop-salt-v1:" || peer_id`).
    pub peer_context_id: ContextId,
}

// ---------------------------------------------------------------------------
// AdminRemovalBatch — atomic commit unit
// ---------------------------------------------------------------------------

/// The atomic commit batch produced by
/// [`emit_admin_removal_with_rotations`] — `RemoveMember` action
/// populated with `induced_rotations`, the `removal_event_id` (the
/// id the caller will assign to the `RemoveMember` event), and the
/// list of per-interface rotation events.
///
/// The caller MUST append these to the SAME MLS commit batch so the
/// rotations cite the `RemoveMember`'s assigned `event_id` and share
/// the commit's MLS epoch counter (§6.2.0.1 "Commit atomicity").
#[derive(Debug, Clone)]
pub struct AdminRemovalBatch {
    /// `GovernanceAction::RemoveMember` with `induced_rotations`
    /// populated. Sibling commit-batch entries follow.
    pub action: GovernanceAction,
    /// Per-interface rotations to be appended as sibling commit-batch
    /// entries citing this commit's MLS epoch counter and the
    /// `RemoveMember`'s `removal_event_id`.
    pub rotations: Vec<InterfaceSaltRotated>,
    /// The `removal_event_id` assigned to the `RemoveMember` event in
    /// this commit batch — caller-supplied so the rotations can cite
    /// it byte-for-byte. The runtime computes the id deterministically
    /// from the proposal id + epoch counter (§6.2.0.1 step 4).
    pub removal_event_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for [`emit_admin_removal_with_rotations`].
#[derive(Debug, thiserror::Error)]
pub enum AdminRemovalError {
    /// Local-side MLS exporter call failed for an interface (typically
    /// because the local MLS group is missing or destroyed).
    #[error("MLS exporter failed for interface {interface_hex}: {source}")]
    ExporterFailed {
        /// Hex-encoded `interface_id` for diagnostics.
        interface_hex: String,
        /// Underlying provider error.
        #[source]
        source: ContextError,
    },
    /// The MLS exporter returned a non-32-byte payload — should not
    /// happen when invoked with `length = 32`, but defensively checked.
    #[error("MLS exporter returned {actual} bytes, expected 32 for hop-salt IKM")]
    UnexpectedExporterLength {
        /// The actual byte count returned by the provider.
        actual: usize,
    },
    /// `induced_rotations` validation failed — empty rotations against
    /// active interfaces, count mismatch, coverage mismatch, or
    /// spurious rotations.
    #[error("induced_rotations validation failed: {0}")]
    InducedRotationsInvalid(
        #[from] crate::context::interface::cluster_detection::InducedRotationsError,
    ),
    /// The signing admin's self-verify failed — defense-in-depth check
    /// that trips only if the runtime supplies a mismatched key pair.
    #[error("rotation self-verify failed: {0}")]
    SelfVerifyFailed(#[source] RotationVerifyError),
}

// ---------------------------------------------------------------------------
// emit_admin_removal_with_rotations
// ---------------------------------------------------------------------------

/// Builds the atomic `RemoveMember` + `InterfaceSaltRotated` batch for
/// an admin-removal governance action per §6.2.0.1 round-6.
///
/// # Steps
///
/// 1. Validates the supplied `active_interfaces` slice covers exactly
///    the interfaces the runtime tracks as active (caller filters).
/// 2. For each active interface:
///    a. Calls `MLS_EXPORTER("scp-context-hop-salt-v1:" || peer_id,
///       b"", 32)` to derive `new_ikm_local`.
///    b. Computes the §6.2.0.1 round-6 rotation-signature preimage
///       (`SCP-OUTLET-IKM-ROTATE-V1:` separator + length-prefixed
///       fields) and signs it under `signing_admin_key`.
///    c. Defensively self-verifies the signature.
///    d. Assembles the `InterfaceSaltRotated` entry.
/// 3. Validates `induced_rotations` against the active set via
///    [`validate_remove_member_induced_rotations`] (closes the OUT-042d
///    governance gate).
/// 4. Returns the populated `RemoveMember` action + the rotation
///    events. The caller appends them as sibling MLS commit-batch
///    entries.
///
/// # Errors
///
/// See [`AdminRemovalError`] for the failure modes. Each variant is
/// fail-closed: NO partial commit is produced.
///
/// # Cryptographic invariants
///
/// - Domain separation: `SCP-OUTLET-IKM-ROTATE-V1:` (registered in
///   §9.18.2). DISTINCT from the accept-time
///   `SCP-OUTLET-IKM-COMMITMENT-V1:` separator — a signature under one
///   cannot be replayed as a signature under the other.
/// - Length-prefixed variable-length fields prevent concatenation
///   ambiguity.
/// - Each rotation binds the (`interface_id`, `context_local_id`,
///   `context_peer_id`, `epoch_local`, `new_ikm_local`,
///   `trigger_removal_did`, `removal_event_id`) tuple — none of these
///   can be swapped without invalidating the signature.
#[allow(clippy::too_many_arguments)]
pub fn emit_admin_removal_with_rotations<E: MlsExporter + ?Sized>(
    mls: &E,
    signing_admin_key: &SigningKey,
    target_did: DID,
    reason: Option<String>,
    epoch_local: u64,
    removal_event_id: [u8; 32],
    active_interfaces: &[ActiveInterfaceDescriptor],
) -> Result<AdminRemovalBatch, AdminRemovalError> {
    let mut rotations = Vec::with_capacity(active_interfaces.len());
    for active in active_interfaces {
        // -- Step a: derive fresh IKM for this interface at the
        //    local-side MLS exporter under the §6.2.0.1 step-1 label.
        let mut label =
            Vec::with_capacity(IKM_EXPORTER_LABEL_PREFIX.len() + active.peer_context_id.len());
        label.extend_from_slice(IKM_EXPORTER_LABEL_PREFIX);
        label.extend_from_slice(active.peer_context_id.as_bytes());
        let exported = mls
            .export_secret(&active.local_context_id_bytes, &label, b"", 32)
            .map_err(|source| AdminRemovalError::ExporterFailed {
                interface_hex: hex::encode(active.interface_id),
                source,
            })?;
        if exported.len() != 32 {
            return Err(AdminRemovalError::UnexpectedExporterLength {
                actual: exported.len(),
            });
        }
        let mut new_ikm_local = [0u8; 32];
        new_ikm_local.copy_from_slice(&exported[..]);

        // -- Step b: sign the rotation preimage.
        let sig = sign_interface_rotation(
            signing_admin_key,
            &active.interface_id,
            &active.local_context_id,
            &active.peer_context_id,
            epoch_local,
            &new_ikm_local,
            &target_did,
            &removal_event_id,
        );

        // -- Step c: defensive self-verify. Trips only on
        //    mismatched-keypair runtime bugs, but exercising the same
        //    verifier as event-log append-time keeps the construction
        //    consistent end-to-end.
        let vk = signing_admin_key.verifying_key();
        verify_interface_rotation(
            &vk,
            &sig,
            &active.interface_id,
            &active.local_context_id,
            &active.peer_context_id,
            epoch_local,
            &new_ikm_local,
            &target_did,
            &removal_event_id,
        )
        .map_err(AdminRemovalError::SelfVerifyFailed)?;

        // -- Step d: assemble the rotation event.
        rotations.push(InterfaceSaltRotated {
            interface_id: active.interface_id,
            new_ikm_local,
            new_ikm_local_sig: sig,
            epoch_local,
            trigger_removal_did: target_did.clone(),
            removal_event_id,
        });
    }

    // -- Step 3: validate induced_rotations covers the active set
    //    exactly. The validator is the OUT-042d governance gate; we
    //    invoke it here so any caller-side mismatch is caught before
    //    the commit batch is constructed.
    let active_ids: Vec<[u8; 32]> = active_interfaces.iter().map(|a| a.interface_id).collect();
    let rotation_ids: Vec<[u8; 32]> = rotations.iter().map(|r| r.interface_id).collect();
    validate_remove_member_induced_rotations(&rotation_ids, &active_ids)?;

    // -- Step 4: assemble the populated RemoveMember action.
    let action = GovernanceAction::RemoveMember {
        did: target_did,
        reason,
        induced_rotations: rotations.clone(),
    };

    Ok(AdminRemovalBatch {
        action,
        rotations,
        removal_event_id,
    })
}

// ---------------------------------------------------------------------------
// Peer-side reciprocal rotation
// ---------------------------------------------------------------------------

/// Builds the peer-side reciprocal `InterfaceSaltRotated` per §6.2.0.1
/// "Atomic removal+rotation — peer-side semantics".
///
/// The peer enters `Frozen` on shared-member-bridged receipt of the
/// original rotation, derives its OWN fresh IKM at its local epoch,
/// signs the SAME `SCP-OUTLET-IKM-ROTATE-V1:` preimage with
/// `(local, peer)` swapped to its own perspective, and cites the
/// peer-local `AdminRemovalMirror` event id as `removal_event_id`. On
/// commit, the peer transitions `Frozen → PostRotation`.
///
/// # Errors
///
/// Returns [`AdminRemovalError`] when the MLS exporter call fails or
/// the deterministic self-verify trips. See
/// [`emit_admin_removal_with_rotations`] for the underlying failure
/// modes — this wrapper invokes that function with a single-element
/// descriptor.
#[allow(clippy::too_many_arguments)]
pub fn build_peer_reciprocal_rotation<E: MlsExporter + ?Sized>(
    mls: &E,
    signing_admin_key: &SigningKey,
    interface_id: [u8; 32],
    local_context_id_bytes: [u8; 32],
    local_context_id: ContextId,
    peer_context_id: ContextId,
    local_epoch: u64,
    trigger_removal_did: DID,
    admin_removal_mirror_event_id: [u8; 32],
) -> Result<InterfaceSaltRotated, AdminRemovalError> {
    let descriptor = ActiveInterfaceDescriptor {
        interface_id,
        local_context_id_bytes,
        local_context_id,
        peer_context_id,
    };
    let batch = emit_admin_removal_with_rotations(
        mls,
        signing_admin_key,
        trigger_removal_did,
        Some("peer-bridged admin removal".to_owned()),
        local_epoch,
        admin_removal_mirror_event_id,
        std::slice::from_ref(&descriptor),
    )?;
    // Single-rotation batch — extract the one rotation we built.
    batch
        .rotations
        .into_iter()
        .next()
        .ok_or(AdminRemovalError::UnexpectedExporterLength { actual: 0 })
}

// ---------------------------------------------------------------------------
// Verifier rule (§6.2.0.1 round-6)
// ---------------------------------------------------------------------------

/// Reference to a prior admin-removal event surfaced from the local
/// event log for [`verify_rotation`]'s removal-binding check.
///
/// The event log adapter resolves an `event_id` into this struct so
/// the verifier can confirm the (i) target DID, (ii) epoch, and (iii)
/// admin-removal nature of the cited event without taking a dependency
/// on the runtime's event-log type system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRemovalEvent {
    /// The event id that `removal_event_id` refers to (echoed back so
    /// the verifier can guard against id-confusion bugs in the
    /// resolver).
    pub event_id: [u8; 32],
    /// `true` if the event's body is a `RemoveMember` with admin role,
    /// or any §14 governance-action-catalog admin-removal-equivalent.
    pub is_admin_removal: bool,
    /// The DID the cited admin-removal action targets.
    pub target_did: DID,
    /// The MLS epoch counter at which the cited event was committed.
    pub epoch: u64,
}

/// Failure modes for [`verify_rotation`] — every variant maps to the
/// `authorization.salt-rotation-unjustified` (`SCP-TOOL-6115`) wire
/// rejection slug.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RotationVerifierError {
    /// `new_ikm_local_sig` failed the §6.2.0.1 round-6 cryptographic
    /// check under the signing admin's `#active` key.
    #[error(
        "rotation signature invalid (slug={SALT_ROTATION_UNJUSTIFIED_SLUG}, code={SALT_ROTATION_UNJUSTIFIED_CODE}): {0}"
    )]
    SignatureInvalid(#[source] RotationVerifyError),
    /// `removal_event_id` did not resolve to any prior event in the
    /// local event log.
    #[error(
        "rotation cites unknown removal_event_id (slug={SALT_ROTATION_UNJUSTIFIED_SLUG}, code={SALT_ROTATION_UNJUSTIFIED_CODE})"
    )]
    UnknownRemovalEvent,
    /// The cited event exists but is not an admin-removal action.
    #[error(
        "rotation cites non-admin-removal event (slug={SALT_ROTATION_UNJUSTIFIED_SLUG}, code={SALT_ROTATION_UNJUSTIFIED_CODE})"
    )]
    CitedEventNotAdminRemoval,
    /// The cited event's target DID does not match
    /// `trigger_removal_did`.
    #[error(
        "rotation cites event targeting {got} but trigger_removal_did is {expected} (slug={SALT_ROTATION_UNJUSTIFIED_SLUG}, code={SALT_ROTATION_UNJUSTIFIED_CODE})"
    )]
    CitedEventTargetMismatch {
        /// DID listed in the rotation's `trigger_removal_did`.
        expected: DID,
        /// DID found in the cited event's body.
        got: DID,
    },
    /// The cited event's epoch is neither equal to nor exactly one
    /// less than `epoch_local`.
    #[error(
        "rotation epoch_local={rotation_epoch} but cited event's epoch={cited_epoch} (must be == or exactly one less) (slug={SALT_ROTATION_UNJUSTIFIED_SLUG}, code={SALT_ROTATION_UNJUSTIFIED_CODE})"
    )]
    EpochOutOfRange {
        /// Rotation's `epoch_local`.
        rotation_epoch: u64,
        /// Cited event's epoch.
        cited_epoch: u64,
    },
    /// The same `removal_event_id` has already been cited by a prior
    /// `InterfaceSaltRotated` on the same `interface_id` — replay
    /// rejection.
    #[error(
        "rotation replays removal_event_id already cited on this interface (slug={SALT_ROTATION_UNJUSTIFIED_SLUG}, code={SALT_ROTATION_UNJUSTIFIED_CODE})"
    )]
    RemovalEventReplay,
}

/// Verifier rule for `InterfaceSaltRotated` events at event-log
/// append time per §6.2.0.1 round-6.
///
/// # Inputs
///
/// - `rotation` — the candidate event being appended.
/// - `signing_admin_vk` — the admin's `#active` verifying key resolved
///   against the role registry at `epoch_local`.
/// - `local_context_id`, `peer_context_id` — the canonical
///   per-interface ordered pair (matches the rotation's preimage).
/// - `cited_removal` — the event-log resolver's response when looking
///   up `rotation.removal_event_id`. `None` indicates the id did not
///   resolve.
/// - `prior_citations_for_interface` — `removal_event_id`s already
///   cited by prior `InterfaceSaltRotated` events on the same
///   `interface_id`. The slice is short — one entry per prior
///   admin-removal cycle.
///
/// # Errors
///
/// See [`RotationVerifierError`]. Every variant maps to the
/// `authorization.salt-rotation-unjustified` (`SCP-TOOL-6115`) wire
/// slug.
pub fn verify_rotation(
    rotation: &InterfaceSaltRotated,
    signing_admin_vk: &VerifyingKey,
    local_context_id: &ContextId,
    peer_context_id: &ContextId,
    cited_removal: Option<&ResolvedRemovalEvent>,
    prior_citations_for_interface: &[[u8; 32]],
) -> Result<(), RotationVerifierError> {
    // (i) signature verification under the rotation preimage.
    verify_interface_rotation(
        signing_admin_vk,
        &rotation.new_ikm_local_sig,
        &rotation.interface_id,
        local_context_id,
        peer_context_id,
        rotation.epoch_local,
        &rotation.new_ikm_local,
        &rotation.trigger_removal_did,
        &rotation.removal_event_id,
    )
    .map_err(RotationVerifierError::SignatureInvalid)?;

    // (ii) removal-event binding.
    let cited = cited_removal.ok_or(RotationVerifierError::UnknownRemovalEvent)?;
    if cited.event_id != rotation.removal_event_id {
        // Defensive: the resolver echoed a different id back. Treat as
        // "unknown" because the binding cannot be honoured.
        return Err(RotationVerifierError::UnknownRemovalEvent);
    }
    if !cited.is_admin_removal {
        return Err(RotationVerifierError::CitedEventNotAdminRemoval);
    }
    if cited.target_did != rotation.trigger_removal_did {
        return Err(RotationVerifierError::CitedEventTargetMismatch {
            expected: rotation.trigger_removal_did.clone(),
            got: cited.target_did.clone(),
        });
    }
    // Epoch must be == epoch_local OR == epoch_local - 1 per
    // §6.2.0.1 round-6.
    let allowed_low = rotation.epoch_local.saturating_sub(1);
    if cited.epoch != rotation.epoch_local && cited.epoch != allowed_low {
        return Err(RotationVerifierError::EpochOutOfRange {
            rotation_epoch: rotation.epoch_local,
            cited_epoch: cited.epoch,
        });
    }

    // (iii) replay check — same removal_event_id on same interface.
    if prior_citations_for_interface.contains(&rotation.removal_event_id) {
        return Err(RotationVerifierError::RemovalEventReplay);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use super::*;
    use crate::context::interface::derive_hop_salt_from_committed_ikms;
    use hmac::{Hmac, Mac};
    use scp_protocol::context::outlets::interface::Ed25519Signature;
    use std::collections::HashMap;
    use std::sync::Mutex;

    type HmacSha256 = Hmac<sha2::Sha256>;

    // ----- Test fixtures --------------------------------------------------

    /// In-memory MLS exporter fixture seeded with deterministic
    /// label→IKM mappings so the test does not need a real MLS group.
    #[derive(Default)]
    struct FixtureExporter {
        responses: Mutex<HashMap<(Vec<u8>, Vec<u8>, Vec<u8>), Vec<u8>>>,
    }

    impl FixtureExporter {
        fn insert(&self, ctx_id: &[u8; 32], label: &[u8], context: &[u8], value: Vec<u8>) {
            let mut g = self.responses.lock().unwrap();
            g.insert((ctx_id.to_vec(), label.to_vec(), context.to_vec()), value);
        }
    }

    impl MlsExporter for FixtureExporter {
        fn export_secret(
            &self,
            context_id: &[u8; 32],
            label: &[u8],
            context: &[u8],
            length: usize,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, ContextError> {
            let g = self.responses.lock().unwrap();
            match g.get(&(context_id.to_vec(), label.to_vec(), context.to_vec())) {
                Some(v) if v.len() == length => Ok(zeroize::Zeroizing::new(v.clone())),
                _ => Err(ContextError::CryptoFailed("missing fixture".into())),
            }
        }
    }

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did(s: &str) -> DID {
        DID::from(s.to_owned())
    }

    /// Builds a fixture for `n` active interfaces. Returns the
    /// fixture, a vector of descriptors, and the IKM the exporter
    /// will return for each.
    fn fixture_for_n_interfaces(
        n: u8,
        local_id_bytes: [u8; 32],
        local_id: &str,
        peer_ids: &[&str],
    ) -> (
        FixtureExporter,
        Vec<ActiveInterfaceDescriptor>,
        Vec<[u8; 32]>,
    ) {
        let exporter = FixtureExporter::default();
        let mut descriptors = Vec::new();
        let mut ikms = Vec::new();
        for i in 0..n {
            let peer_id = peer_ids[usize::from(i)].to_owned();
            let mut label = IKM_EXPORTER_LABEL_PREFIX.to_vec();
            label.extend_from_slice(peer_id.as_bytes());
            let ikm = [0xA0_u8.wrapping_add(i); 32];
            exporter.insert(&local_id_bytes, &label, b"", ikm.to_vec());
            descriptors.push(ActiveInterfaceDescriptor {
                interface_id: [0x10_u8.wrapping_add(i); 32],
                local_context_id_bytes: local_id_bytes,
                local_context_id: local_id.to_owned(),
                peer_context_id: peer_id,
            });
            ikms.push(ikm);
        }
        (exporter, descriptors, ikms)
    }

    // ----- AC: 3 interfaces emit simultaneously ---------------------------

    /// Admin removal triggers `InterfaceSaltRotated` on 3 active
    /// interfaces; all events share the same `removal_event_id` and
    /// target DID; the new IKMs differ from any prior pre-rotation
    /// IKM; HMAC-style derivation under the new IKM pair produces a
    /// `hop_salt` that does NOT match the pre-rotation `hop_salt`.
    #[test]
    fn admin_removal_emits_rotation_for_three_interfaces_atomically() {
        let local_id_bytes = [0xCC; 32];
        let (exporter, descriptors, ikms) = fixture_for_n_interfaces(
            3,
            local_id_bytes,
            "ctx-local",
            &["ctx-peer-1", "ctx-peer-2", "ctx-peer-3"],
        );
        let admin = signer(0xAB);
        let removed = did("did:dht:zEVICT");
        let removal_event_id = [0xEE; 32];
        let epoch = 42;

        let batch = emit_admin_removal_with_rotations(
            &exporter,
            &admin,
            removed.clone(),
            None,
            epoch,
            removal_event_id,
            &descriptors,
        )
        .expect("3-interface batch must succeed");

        // All 3 rotations present, each citing the same removal_event_id.
        assert_eq!(batch.rotations.len(), 3);
        for (i, r) in batch.rotations.iter().enumerate() {
            assert_eq!(r.removal_event_id, removal_event_id);
            assert_eq!(r.trigger_removal_did, removed);
            assert_eq!(r.epoch_local, epoch);
            assert_eq!(r.interface_id, descriptors[i].interface_id);
            assert_eq!(r.new_ikm_local, ikms[i]);
            assert_eq!(r.new_ikm_local_sig.len(), 64);
        }

        // Action carries induced_rotations populated.
        match &batch.action {
            GovernanceAction::RemoveMember {
                did: d,
                induced_rotations,
                ..
            } => {
                assert_eq!(d, &removed);
                assert_eq!(induced_rotations.len(), 3);
            }
            _ => panic!("unexpected action variant"),
        }

        // hop_salt under the new IKM pair (we only have local-side
        // IKM here; in production the peer publishes its own
        // reciprocal rotation IKM) does NOT collide with a salt
        // computed from a pre-rotation IKM pair.
        let pre_rotation_ikm_local = [0x11; 32];
        let pre_rotation_ikm_peer = [0x22; 32];
        let pre_salt = derive_hop_salt_from_committed_ikms(
            &pre_rotation_ikm_local,
            &pre_rotation_ikm_peer,
            &"ctx-local".to_owned(),
            &"ctx-peer-1".to_owned(),
        );
        // Synthesise a "post" peer-side IKM and derive new salt.
        let post_peer = [0x33; 32];
        let post_salt = derive_hop_salt_from_committed_ikms(
            &batch.rotations[0].new_ikm_local,
            &post_peer,
            &"ctx-local".to_owned(),
            &"ctx-peer-1".to_owned(),
        );
        assert_ne!(
            pre_salt, post_salt,
            "post-rotation salt must differ from pre-rotation salt"
        );

        // HMAC-old-salt computation against a wire pseudonym derived
        // under post-rotation hop_salt does NOT match. Encoded as: a
        // random 32-byte "pseudonym" derived from the post salt is
        // not equal to the pre salt under the same input.
        let raw_context_id = b"ctx-target-XYZ";
        let mut pre_mac = HmacSha256::new_from_slice(&pre_salt).expect("salt bytes always valid");
        pre_mac.update(raw_context_id);
        let pre_pseud = pre_mac.finalize().into_bytes();
        let mut post_mac = HmacSha256::new_from_slice(&post_salt).expect("salt bytes always valid");
        post_mac.update(raw_context_id);
        let post_pseud = post_mac.finalize().into_bytes();
        assert_ne!(pre_pseud, post_pseud);
    }

    // ----- AC: trigger_removal_did + removal_event_id binding -------------

    /// Both `trigger_removal_did` and `removal_event_id` reference
    /// the removed admin — the rotation trail is doubly verifiable.
    #[test]
    fn rotation_trail_is_doubly_verifiable() {
        let local_id_bytes = [0x55; 32];
        let (exporter, descriptors, _ikms) =
            fixture_for_n_interfaces(1, local_id_bytes, "L", &["P"]);
        let admin = signer(0x33);
        let removed = did("did:dht:zREM");
        let removal_event_id = [0xBE; 32];
        let batch = emit_admin_removal_with_rotations(
            &exporter,
            &admin,
            removed.clone(),
            None,
            7,
            removal_event_id,
            &descriptors,
        )
        .unwrap();

        // First witness: trigger_removal_did equals removed admin.
        assert_eq!(batch.rotations[0].trigger_removal_did, removed);
        // Second witness: removal_event_id is set verbatim.
        assert_eq!(batch.rotations[0].removal_event_id, removal_event_id);
    }

    // ----- AC: missing removal_event_id reference -------------------------

    /// A rotation whose `removal_event_id` does NOT reference any
    /// prior `RemoveMember` event is rejected with
    /// `authorization.salt-rotation-unjustified`.
    #[test]
    fn rotation_without_removal_event_reference_rejected() {
        let admin = signer(0x44);
        let admin_vk = admin.verifying_key();
        let interface_id = [0x77; 32];
        let new_ikm = [0x88; 32];
        let trigger = did("did:dht:zEVICTED");
        let removal_event_id = [0x99; 32];
        let local = "ctx-local".to_owned();
        let peer = "ctx-peer".to_owned();

        let sig: Ed25519Signature = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            5,
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 5,
            trigger_removal_did: trigger,
            removal_event_id,
        };

        // Resolver returns None for the cited event id.
        let err = verify_rotation(&rotation, &admin_vk, &local, &peer, None, &[])
            .expect_err("unresolved removal must reject");
        assert_eq!(err, RotationVerifierError::UnknownRemovalEvent);
    }

    // ----- AC: replay rejection -------------------------------------------

    /// Replaying the same `removal_event_id` on a second
    /// `InterfaceSaltRotated` against the same interface is rejected
    /// with `authorization.salt-rotation-unjustified`.
    #[test]
    fn replayed_removal_event_id_on_same_interface_rejected() {
        let admin = signer(0x66);
        let admin_vk = admin.verifying_key();
        let interface_id = [0xAB; 32];
        let new_ikm = [0xBA; 32];
        let trigger = did("did:dht:zVICTIM");
        let removal_event_id = [0xCD; 32];
        let local = "L".to_owned();
        let peer = "P".to_owned();
        let sig = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            10,
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 10,
            trigger_removal_did: trigger.clone(),
            removal_event_id,
        };
        let resolved = ResolvedRemovalEvent {
            event_id: removal_event_id,
            is_admin_removal: true,
            target_did: trigger,
            epoch: 10,
        };

        // First citation succeeds.
        verify_rotation(&rotation, &admin_vk, &local, &peer, Some(&resolved), &[])
            .expect("first citation valid");
        // Second citation replays — rejected.
        let err = verify_rotation(
            &rotation,
            &admin_vk,
            &local,
            &peer,
            Some(&resolved),
            &[removal_event_id],
        )
        .expect_err("replay must reject");
        assert_eq!(err, RotationVerifierError::RemovalEventReplay);
    }

    // ----- AC: TOCTOU closure — Frozen window buffers -------------------

    /// Between proposal and commit, no `OutletError` is emitted on
    /// affected interfaces — the test wedges the commit by leaving
    /// state at `Frozen` and observes that the queue buffers each
    /// envelope. After unfreeze, the queue flushes under the new
    /// `hop_salt`.
    #[test]
    fn frozen_window_buffers_and_flushes_on_unfreeze() {
        let mut queue = OutboundOutletErrorQueue::new();
        let interface_id = [0xDE; 32];

        // PreRotation — pass-through.
        let env_pre = BufferedOutletError {
            interface_id,
            buffered_at_ms: 1_000,
            envelope_bytes: b"pre".to_vec(),
        };
        let outcome = queue.buffer_or_emit(HopSaltState::PreRotation, env_pre);
        assert_eq!(outcome, BufferOutcome::PassThrough);

        // Frozen — buffer.
        let env_a = BufferedOutletError {
            interface_id,
            buffered_at_ms: 2_000,
            envelope_bytes: b"a".to_vec(),
        };
        let env_b = BufferedOutletError {
            interface_id,
            buffered_at_ms: 2_500,
            envelope_bytes: b"b".to_vec(),
        };
        assert_eq!(
            queue.buffer_or_emit(HopSaltState::Frozen, env_a),
            BufferOutcome::Buffered { queue_depth: 1 }
        );
        assert_eq!(
            queue.buffer_or_emit(HopSaltState::Frozen, env_b),
            BufferOutcome::Buffered { queue_depth: 2 }
        );
        assert_eq!(queue.depth(&interface_id), 2);

        // Flush at now=3_000 with max_buffer_secs=30 — both envelopes
        // are within the window → both emit.
        let flushed = queue.flush(&interface_id, 3_000, 30);
        assert_eq!(flushed.emitted.len(), 2);
        assert!(flushed.dropped.is_empty());
        assert_eq!(queue.depth(&interface_id), 0);

        // State machine: PreRotation → Frozen → PostRotation.
        let s0 = HopSaltState::PreRotation;
        let s1 = s0.freeze().unwrap();
        assert_eq!(s1, HopSaltState::Frozen);
        let s2 = s1.unfreeze().unwrap();
        assert_eq!(s2, HopSaltState::PostRotation);

        // Frozen → Frozen rejects.
        assert!(s1.freeze().is_err());
        // PreRotation → PostRotation rejects (must come through Frozen).
        assert!(s0.unfreeze().is_err());
    }

    /// Buffered envelopes older than `outlet_error_buffer_max_secs`
    /// are dropped with the audit slug; the queue does not retain them.
    #[test]
    fn buffer_overflow_drops_with_audit_slug() {
        let mut queue = OutboundOutletErrorQueue::new();
        let interface_id = [0xFF; 32];
        let stale = BufferedOutletError {
            interface_id,
            buffered_at_ms: 1_000,
            envelope_bytes: b"old".to_vec(),
        };
        let fresh = BufferedOutletError {
            interface_id,
            buffered_at_ms: 60_000,
            envelope_bytes: b"new".to_vec(),
        };
        queue.buffer_or_emit(HopSaltState::Frozen, stale);
        queue.buffer_or_emit(HopSaltState::Frozen, fresh);

        // now=70_000, max=30s. stale aged 69s → drop. fresh aged 10s → emit.
        let flushed = queue.flush(&interface_id, 70_000, 30);
        assert_eq!(flushed.emitted.len(), 1);
        assert_eq!(flushed.emitted[0].envelope_bytes, b"new");
        assert_eq!(flushed.dropped.len(), 1);
        assert_eq!(flushed.dropped[0].envelope_bytes, b"old");

        // Audit slug constant is the canonical wire string.
        assert_eq!(
            BUFFER_OVERFLOW_AUDIT_SLUG,
            "governance.remove-member-buffer-overflow"
        );
    }

    // ----- Verifier — happy path + epoch boundary -----------------------

    /// Verifier accepts a rotation whose cited removal event has
    /// `epoch == epoch_local`.
    #[test]
    fn verifier_accepts_same_epoch_rotation() {
        let admin = signer(0xC1);
        let admin_vk = admin.verifying_key();
        let interface_id = [0x42; 32];
        let new_ikm = [0x43; 32];
        let trigger = did("did:dht:zT");
        let removal_event_id = [0x44; 32];
        let local = "L".to_owned();
        let peer = "P".to_owned();
        let sig = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            5,
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 5,
            trigger_removal_did: trigger.clone(),
            removal_event_id,
        };
        let resolved = ResolvedRemovalEvent {
            event_id: removal_event_id,
            is_admin_removal: true,
            target_did: trigger,
            epoch: 5,
        };
        verify_rotation(&rotation, &admin_vk, &local, &peer, Some(&resolved), &[])
            .expect("same-epoch rotation must accept");
    }

    /// Verifier accepts a rotation whose cited removal event has
    /// `epoch == epoch_local - 1` (peer-bridged response after the
    /// peer's local epoch advanced).
    #[test]
    fn verifier_accepts_prior_epoch_rotation() {
        let admin = signer(0xC2);
        let admin_vk = admin.verifying_key();
        let interface_id = [0x52; 32];
        let new_ikm = [0x53; 32];
        let trigger = did("did:dht:zT2");
        let removal_event_id = [0x54; 32];
        let local = "L".to_owned();
        let peer = "P".to_owned();
        let sig = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            8, // epoch_local
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 8,
            trigger_removal_did: trigger.clone(),
            removal_event_id,
        };
        let resolved = ResolvedRemovalEvent {
            event_id: removal_event_id,
            is_admin_removal: true,
            target_did: trigger,
            epoch: 7, // exactly one less
        };
        verify_rotation(&rotation, &admin_vk, &local, &peer, Some(&resolved), &[])
            .expect("prior-epoch rotation must accept");
    }

    /// Verifier rejects a rotation whose cited event's epoch is two
    /// less than `epoch_local` — outside the spec window.
    #[test]
    fn verifier_rejects_too_old_epoch() {
        let admin = signer(0xC3);
        let admin_vk = admin.verifying_key();
        let interface_id = [0x62; 32];
        let new_ikm = [0x63; 32];
        let trigger = did("did:dht:zT3");
        let removal_event_id = [0x64; 32];
        let local = "L".to_owned();
        let peer = "P".to_owned();
        let sig = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            10,
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 10,
            trigger_removal_did: trigger.clone(),
            removal_event_id,
        };
        let resolved = ResolvedRemovalEvent {
            event_id: removal_event_id,
            is_admin_removal: true,
            target_did: trigger,
            epoch: 8, // 2 less — out of [9, 10] window
        };
        let err = verify_rotation(&rotation, &admin_vk, &local, &peer, Some(&resolved), &[])
            .expect_err("epoch out of range must reject");
        match err {
            RotationVerifierError::EpochOutOfRange {
                rotation_epoch: 10,
                cited_epoch: 8,
            } => {}
            other => panic!("unexpected error {other:?}"),
        }
    }

    /// Verifier rejects a tampered signature.
    #[test]
    fn verifier_rejects_tampered_signature() {
        let admin = signer(0xC4);
        let admin_vk = admin.verifying_key();
        let interface_id = [0x71; 32];
        let new_ikm = [0x72; 32];
        let trigger = did("did:dht:zT4");
        let removal_event_id = [0x73; 32];
        let local = "L".to_owned();
        let peer = "P".to_owned();
        let mut sig = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            5,
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        *sig.last_mut().unwrap() ^= 0x01;
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 5,
            trigger_removal_did: trigger.clone(),
            removal_event_id,
        };
        let resolved = ResolvedRemovalEvent {
            event_id: removal_event_id,
            is_admin_removal: true,
            target_did: trigger,
            epoch: 5,
        };
        let err = verify_rotation(&rotation, &admin_vk, &local, &peer, Some(&resolved), &[])
            .expect_err("tampered sig must reject");
        match err {
            RotationVerifierError::SignatureInvalid(_) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// Verifier rejects when the cited event is not an admin-removal.
    #[test]
    fn verifier_rejects_non_admin_removal_citation() {
        let admin = signer(0xC5);
        let admin_vk = admin.verifying_key();
        let interface_id = [0x81; 32];
        let new_ikm = [0x82; 32];
        let trigger = did("did:dht:zT5");
        let removal_event_id = [0x83; 32];
        let local = "L".to_owned();
        let peer = "P".to_owned();
        let sig = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            5,
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 5,
            trigger_removal_did: trigger.clone(),
            removal_event_id,
        };
        let resolved = ResolvedRemovalEvent {
            event_id: removal_event_id,
            is_admin_removal: false, // wrong kind of event
            target_did: trigger,
            epoch: 5,
        };
        let err = verify_rotation(&rotation, &admin_vk, &local, &peer, Some(&resolved), &[])
            .expect_err("non-admin-removal citation must reject");
        assert_eq!(err, RotationVerifierError::CitedEventNotAdminRemoval);
    }

    /// Verifier rejects when the cited event's target DID does not
    /// match `trigger_removal_did`.
    #[test]
    fn verifier_rejects_target_did_mismatch() {
        let admin = signer(0xC6);
        let admin_vk = admin.verifying_key();
        let interface_id = [0x91; 32];
        let new_ikm = [0x92; 32];
        let trigger = did("did:dht:zCorrect");
        let removal_event_id = [0x93; 32];
        let local = "L".to_owned();
        let peer = "P".to_owned();
        let sig = sign_interface_rotation(
            &admin,
            &interface_id,
            &local,
            &peer,
            5,
            &new_ikm,
            &trigger,
            &removal_event_id,
        );
        let rotation = InterfaceSaltRotated {
            interface_id,
            new_ikm_local: new_ikm,
            new_ikm_local_sig: sig,
            epoch_local: 5,
            trigger_removal_did: trigger,
            removal_event_id,
        };
        let resolved = ResolvedRemovalEvent {
            event_id: removal_event_id,
            is_admin_removal: true,
            target_did: did("did:dht:zWrong"),
            epoch: 5,
        };
        let err = verify_rotation(&rotation, &admin_vk, &local, &peer, Some(&resolved), &[])
            .expect_err("target mismatch must reject");
        match err {
            RotationVerifierError::CitedEventTargetMismatch { .. } => {}
            other => panic!("expected CitedEventTargetMismatch, got {other:?}"),
        }
    }

    // ----- Empty-active-interfaces invariant ------------------------------

    /// Empty active interfaces produces an empty rotation batch — no
    /// rotations needed when no interfaces are active. The
    /// `induced_rotations` validator accepts this case.
    #[test]
    fn no_active_interfaces_produces_empty_batch() {
        let exporter = FixtureExporter::default();
        let admin = signer(0xC7);
        let batch = emit_admin_removal_with_rotations(
            &exporter,
            &admin,
            did("did:dht:zNoOp"),
            None,
            1,
            [0u8; 32],
            &[],
        )
        .expect("no-active-interfaces case must succeed");
        assert!(batch.rotations.is_empty());
        match batch.action {
            GovernanceAction::RemoveMember {
                induced_rotations, ..
            } => {
                assert!(induced_rotations.is_empty());
            }
            _ => panic!("unexpected variant"),
        }
    }

    // ----- Peer-side reciprocal rotation ----------------------------------

    /// On peer-side receipt of an admin-removal mirror, the peer
    /// derives its own fresh IKM at its local epoch, signs the SAME
    /// preimage with `(local, peer)` swapped to its own perspective,
    /// and cites the peer-local mirror event id.
    #[test]
    fn peer_reciprocal_rotation_uses_peer_perspective() {
        let local_id_bytes = [0x77; 32];
        let admin = signer(0xC8);
        // Peer's local exporter — labeled with the OTHER side's id
        // (which is what was the original local context).
        let exporter = FixtureExporter::default();
        let mut label = IKM_EXPORTER_LABEL_PREFIX.to_vec();
        label.extend_from_slice(b"peer-of-original");
        exporter.insert(&local_id_bytes, &label, b"", vec![0xCC; 32]);

        let mirror_event_id = [0xDD; 32];
        let r = build_peer_reciprocal_rotation(
            &exporter,
            &admin,
            [0x88; 32],
            local_id_bytes,
            "ctx-peer".to_owned(),         // peer's local id (this side)
            "peer-of-original".to_owned(), // other side
            12,
            did("did:dht:zEvictedAdmin"),
            mirror_event_id,
        )
        .expect("peer reciprocal rotation must succeed");

        assert_eq!(r.removal_event_id, mirror_event_id);
        assert_eq!(r.epoch_local, 12);
        assert_eq!(r.new_ikm_local, [0xCC; 32]);
        assert_eq!(r.new_ikm_local_sig.len(), 64);

        // Verifier accepts the peer's reciprocal rotation against its
        // own perspective.
        let admin_vk = admin.verifying_key();
        let resolved = ResolvedRemovalEvent {
            event_id: mirror_event_id,
            is_admin_removal: true,
            target_did: did("did:dht:zEvictedAdmin"),
            epoch: 12,
        };
        verify_rotation(
            &r,
            &admin_vk,
            &"ctx-peer".to_owned(),
            &"peer-of-original".to_owned(),
            Some(&resolved),
            &[],
        )
        .expect("peer reciprocal must verify under peer's perspective");
    }

    /// Slug + code constants are pinned to the canonical
    /// `scp_protocol::context::outlets::error_codes` constants — no
    /// drift across bridges.
    #[test]
    fn slug_and_code_pinned_to_protocol_constants() {
        assert_eq!(
            SALT_ROTATION_UNJUSTIFIED_SLUG,
            "authorization.salt-rotation-unjustified"
        );
        assert_eq!(SALT_ROTATION_UNJUSTIFIED_CODE, "SCP-TOOL-6115");
        assert_eq!(
            SALT_ROTATION_UNJUSTIFIED_SLUG,
            SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED
        );
        assert_eq!(
            SALT_ROTATION_UNJUSTIFIED_CODE,
            CODE_AUTHORIZATION_SALT_ROTATION
        );
    }

    /// Sanity: the rotation domain separator is distinct from the
    /// commitment separator, so a signature under one cannot replay
    /// against the other.
    #[test]
    fn rotation_separator_distinct_from_commitment_separator() {
        use crate::context::interface::ikm_commitment::IKM_COMMITMENT_DOMAIN_SEPARATOR;
        use scp_protocol::context::outlets::interface::IKM_ROTATE_DOMAIN_SEPARATOR;
        assert_ne!(IKM_ROTATE_DOMAIN_SEPARATOR, IKM_COMMITMENT_DOMAIN_SEPARATOR);
        assert_eq!(IKM_ROTATE_DOMAIN_SEPARATOR, b"SCP-OUTLET-IKM-ROTATE-V1:");
    }

    /// Validator integration — empty rotations against active
    /// interfaces is rejected (gates the proposal at the §6.2.0.1
    /// "Rotation is unconditional" boundary).
    #[test]
    fn empty_rotations_against_active_interfaces_rejected() {
        // Direct call to the validator with an empty rotation list and
        // a non-empty active list — emits the OUT-042d error variant.
        let active = vec![[0x10; 32], [0x11; 32]];
        let err = validate_remove_member_induced_rotations(&[], &active)
            .expect_err("empty rotations + active interfaces must reject");
        // The validator surfaces MissingForActiveInterfaces; this is
        // the OUT-042d gate referenced by §6.2.0.1 round-6.
        match err {
            crate::context::interface::cluster_detection::InducedRotationsError::MissingForActiveInterfaces { active_interface_count } => {
                assert_eq!(active_interface_count, 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
