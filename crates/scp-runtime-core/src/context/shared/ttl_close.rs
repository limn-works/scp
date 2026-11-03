//! Items the `ttl_close` domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::ContextHandle;
use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::builder::AppendMode;
use crate::context::state::context_id_to_bytes;
use crate::context::supervisor::handle::ConvergentDeadline;
use crate::context::ttl;
use scp_protocol::context::ContextError;
use scp_protocol::context::MemoryScope;
use scp_protocol::context::memory_scope::KeyDestructionAttestation;
use scp_protocol::context::memory_scope::KeyDestructionLevel;

/// Outcome of an actor-owned TTL expiry attempt (SEC-1 rework, ADR-049 §9
/// amendment).
///
/// Carries BOTH the [`TtlExpiryResult`](crate::context::ttl::TtlExpiryResult)
/// (which cleanup steps completed — the bitmask the actor stores as
/// `ttl_expiry_completed` and feeds back as `prior_completed` on a retry) AND
/// the fail-closed persist result of the terminal `Expired` state. The actor
/// treats the expiry as terminal (despawns) ONLY when `result.is_complete()`
/// AND `persist_result.is_ok()` (the terminal `Expired` state is durable);
/// otherwise it keeps the actor alive and re-arms a bounded retry.
pub struct TtlExpiryOutcome {
    /// Which cleanup steps completed (state transition, key destruction, event
    /// leaf), carried forward across on-actor retries.
    pub result: crate::context::ttl::TtlExpiryResult,
    /// Result of the FAIL-CLOSED persist of the terminal `Expired` state.
    /// `Err` means the terminal transition did not durably land (keep-direction:
    /// the in-memory FSM is NOT rolled back to `Active`) — the actor stays alive
    /// and retries so a crash cannot resurrect the context as `Active` against a
    /// stale `Active` snapshot (SEC-1i).
    pub persist_result: Result<(), ContextError>,
}

/// Distinguishes the two TTL-extension activation paths.
///
/// Both share the `scp_runtime_ttl_close::helpers::extend_ttl_deadline_and_record` leaf-atomic combinator
/// (B3), and each has its own convergent `proposal_id` + leaf-`timestamp`
/// convention.
pub enum ExtensionLeaf {
    /// Governance `ExtendTtl`: the approved proposal id and the committer-assigned
    /// convergent leaf timestamp (`proposal.created_at`, identical for every
    /// member that processes the signed proposal; §7.3.1 / §9.9.3).
    Governance {
        /// The approved governance proposal id recorded on the leaf.
        proposal_id: [u8; 32],
        /// The convergent committer-assigned leaf timestamp.
        committer_timestamp_secs: u64,
        /// The DIDs whose approvals carried the proposal (leaf `consenting_members`).
        consenting_members: Vec<String>,
    },
    /// Bilateral propose/reset activation: no signed governance proposal, so the
    /// leaf's `proposal_id` is content-derived from `(context, old, new)` and its
    /// `timestamp` is the convergent PRE-extension deadline (`old`) — a value
    /// every consenting member holds identically, keeping the leaf byte-identical
    /// across members. (The deadline derivation in [`convergent_ttl_deadline`]
    /// reads the payload's `new_deadline_unix`, never this timestamp, so the
    /// choice is convergence-only, not a semantic deadline input.)
    Reset {
        /// The pending consent tally's members (sorted, leaf `consenting_members`).
        consenting_members: Vec<String>,
    },
}

impl ExtensionLeaf {
    /// Where the leaf sits relative to its extension's irreversible step
    /// (spec section 17.3, "Event log write failures"). A governance extension
    /// is already committed, so its leaf follows the side effect. The
    /// bilateral reset's leaf comes first: the reset moves the deadline and
    /// clears the consent tally only after the leaf is stored.
    #[must_use]
    pub const fn append_mode(&self) -> AppendMode {
        match self {
            Self::Governance { .. } => AppendMode::AfterSideEffect,
            Self::Reset { .. } => AppendMode::FailClosed,
        }
    }
}

/// Computes the CONVERGENT initial-TTL expiry deadline (Unix seconds) for a
/// context: `creation_timestamp_secs + params.ttl`.
///
/// Both inputs are convergent across members — `creation_timestamp_secs` is the
/// creator-assigned `ContextCreated` value copied onto every member's state,
/// and `ttl_secs` is the TTL in the context params (legible to every member) —
/// so every member computes the IDENTICAL absolute deadline regardless of when
/// (or with what local clock) it armed its timer. This is the value recorded on
/// `ContextExpired`/`ContextClosed` leaves, making them convergent-by-
/// construction (§7.3.1, §9.9.3).
///
/// Returns `None` when the context has no finite TTL.
#[must_use]
pub const fn convergent_ttl_deadline_secs(
    creation_timestamp_secs: u64,
    ttl_secs: Option<u64>,
) -> Option<ConvergentDeadline> {
    match ttl_secs {
        Some(ttl) => Some(ConvergentDeadline(
            creation_timestamp_secs.saturating_add(ttl),
        )),
        None => None,
    }
}

/// Derives the SINGLE authoritative convergent TTL deadline for a context.
///
/// The derivation is PARTITIONED by failure direction between the
/// prune-immune snapshot and the prunable event log (§5.10, §5.10.1, §7.3.1 /
/// §9.9.3, ADR-049 §9).
///
/// # The partitioned invariant
///
/// The convergent deadline has two inputs, split by which way losing them fails:
///
/// - **Fail-DANGEROUS ⇒ prune-immune SNAPSHOT.** The create BASE is
///   `creation_timestamp_secs + params_ttl`, and PROMOTION is `params_ttl ==
///   None` (spec §5.10 — promotion removes the TTL). Both come from the
///   persisted `ContextSnapshot` (`creation_timestamp_secs` + `context_params`),
///   NOT the prunable log: losing the base would never-expire a finite context
///   (keys never destroyed) and losing the promotion signal would destroy a
///   permanent one — the dangerous directions, so neither may depend on a leaf a
///   pruning policy can delete.
/// - **Fail-SAFE ⇒ prunable LOG.** Every EXTENSION is a `TtlExtended` leaf's
///   `new_deadline_unix` (governance `execute_extend_ttl` AND bilateral
///   `reset_ttl_timer` both record one). Extensions only LENGTHEN; pruning one
///   shortens the derived deadline — the fail-safe direction (the context
///   expires no later than its convergent TTL).
///
/// The deadline is the create base RAISED to the highest recorded extension. It
/// is `None` (no arm) IFF `params_ttl == None` — a context that never had a TTL,
/// or one whose TTL promotion removed.
///
/// # Prune-safe by construction (closes the pass-4d #2102 pruning HIGH)
///
/// Pass-4d sourced the base from the genesis `ContextCreated` LEAF timestamp and
/// read promotion from the `ContextPromoted` LEAF — both prunable. Pruning the
/// genesis leaf voided the base (fail-OPEN: a finite context outlived its TTL);
/// a pruned/forged promotion leaf could re-arm a permanent context. Sourcing
/// both from the prune-immune snapshot dissolves that: an empty / pruned log
/// still yields the base (it is in the snapshot), and promotion is the snapshot's
/// `params_ttl == None`. The log is read ONLY for the fail-safe extension term.
///
/// # The `ContextPromoted` leaf is NOT read for the arm decision
///
/// `params_ttl` is the sole promotion authority (prune-immune). The
/// `ContextPromoted` leaf remains in the log as the event RECORD of promotion,
/// but reading it here would reintroduce a fail-DANGEROUS dependency on the
/// prunable log — a forged or pruned promotion leaf must never flip a finite
/// context's arm.
///
/// Every reader (restore/import re-arm, the terminal-leaf timestamp, the
/// extension primitive) derives the deadline through THIS function instead of
/// trusting an independent persisted scalar, a `memory_scope` heuristic, or
/// params alone — collapsing the competing sources that produced the H1/M1/M3
/// deadline bugs into one.
///
/// # Returns
///
/// - `None` iff `params_ttl == None` (no TTL, or promotion removed it) — no arm,
///   regardless of any (stale) `TtlExtended` leaf.
/// - otherwise `Some(max(creation_timestamp_secs + params_ttl, highest
///   TtlExtended.new_deadline_unix))`.
#[must_use]
pub fn convergent_ttl_deadline(
    entries: &[scp_event_log::Event],
    creation_timestamp_secs: u64,
    params_ttl: Option<u64>,
) -> Option<ConvergentDeadline> {
    use scp_event_log::EventType;

    // Fail-dangerous BASE + PROMOTION from the prune-immune snapshot. `None`
    // `params_ttl` (never had a TTL, or promotion removed it per §5.10) ⇒ no arm,
    // returned BEFORE any log read so a stale / forged extension leaf can never
    // arm a promoted or never-finite context ("None iff params_ttl == None").
    let base = convergent_ttl_deadline_secs(creation_timestamp_secs, params_ttl)?;

    // Fail-safe EXTENSION term from the prunable log: the highest recorded
    // `TtlExtended` leaf's `new_deadline_unix` (§5.10.1 step 5).
    // `extend_ttl_deadline_and_record` records the running post-extension
    // deadline, so the max is the current extended deadline every member
    // re-derives identically. Pruning a leaf only SHORTENS the result (fail-safe).
    // A leaf whose payload cannot be decoded is DROPPED with a warning (not
    // silently) so a corrupt leaf that shortens the derived deadline is
    // observable rather than an invisible security regression.
    let ext =
        entries
            .iter()
            .filter(|e| e.event_type == EventType::TtlExtended)
            .filter_map(|e| {
                match scp_event_log::payload::decode_payload::<
                    scp_event_log::payload::TtlExtendedPayload,
                >(&e.payload)
                {
                    Ok(p) => Some(p.new_deadline_unix),
                    Err(err) => {
                        tracing::warn!(
                            sequence = e.sequence,
                            error = %err,
                            "convergent_ttl_deadline: dropping an undecodable TtlExtended leaf; \
                             the derived deadline may be SHORTER than the recorded extension \
                             (single-source invariant — visible, not silent)"
                        );
                        None
                    }
                }
            })
            .max();

    // Raise the prune-immune base to the highest fail-safe extension.
    Some(match ext {
        Some(ext) if ext > base.as_secs() => ConvergentDeadline(ext),
        _ => base,
    })
}

/// Completes context closure on actor-owned state.
///
/// Destroys MLS group state and sender keys, issues relay deletion
/// requests for ephemeral/summary scopes, transitions from `Closing` to
/// `Closed`, and appends the final `ContextClosed` event.
///
/// Persisted snapshot is deleted on success (best-effort) so a later
/// restore does not resurrect the closed context.
///
/// The lifecycle transition runs through `handle.transition_to`; the
/// `ContextClosed` leaf is stamped with the ACTUAL close instant
/// (`deps.clock.now_secs()`) — see the body for why the TTL deadline is NOT the
/// right quantity for this (explicit-only) path.
///
/// # Returns — the truthful key-destruction attestation (#2199 / F2)
///
/// On a successful Ephemeral/Summary close where actor-owned crypto was present
/// and disposed, returns `Ok(Some(attestation))` — the TRUTHFUL
/// [`KeyDestructionAttestation`] built HERE from the OBSERVED
/// [`DisposalOutcome`](crate::context::actor::state::DisposalOutcome) (the sole
/// canonical build site since the dead orchestrators were deleted in #2199).
/// Returns `Ok(None)` for Full scope (crypto retained), a Broadcast context (no
/// crypto), or the destruction-required-but-crypto-absent anomaly. The
/// attestation is returned to the LOCAL caller (`handle_finalize_close` in
/// `scp_runtime_ttl_close::handler`) for
/// logging; this is a pure in-process Rust value — it is NOT surfaced across the
/// FFI reply (the oneshot stays `Result<(), ContextError>`), and recording it
/// into the event log / `ContextClosed` leaf is a separate DOA wire-format
/// decision tracked by #2215.
///
/// # Errors
///
/// The error of the `Closing → Closed` transition and its terminal leaf;
/// nothing is disposed then.
pub async fn finalize_close(
    // #2148 (ADR-049 birth-into-actor): the actor-owned crypto lives here — for
    // an Ephemeral/Summary explicit close it is disposed through the cell after
    // the FSM transition lands (the provider holds no per-context state).
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
) -> Result<Option<KeyDestructionAttestation>, ContextError> {
    let context_id = handle.context_id().to_owned();

    // `ContextClosed` leaf timestamp = the ACTUAL close instant (F4). This helper
    // is reached ONLY from the FFI `context_finalize_close` explicit Closing→Closed
    // path (`handle_finalize_close`); the TTL-EXPIRY path (`handle_ttl_expiry`)
    // stamps its own `ContextExpired` leaf off the convergent deadline and never
    // reaches here. For an explicit close the convergent TTL deadline is the WRONG
    // quantity: a context with a live finite `params.ttl = Some` closed BEFORE it
    // expires has `convergent_ttl_deadline == Some(creation + ttl)`, a FUTURE
    // instant unrelated to when the close actually happened — stamping it would
    // record a future close time. The actual close time is `now`. (This also
    // unifies the two former branches: the prior `params.ttl == None` path already
    // fell back to `now`, so both explicit-close shapes now stamp `now`
    // consistently.) Cross-member convergence of an EXPLICIT governance close is
    // anchored by the prior `ContextClosing` leaf (stamped with the governance
    // committer's convergent close-commit time in `execute_close_context`), NOT by
    // the exact instant of this local terminal finalization — each member
    // finalizes after processing its own notification window, so the terminal
    // leaf's instant is legitimately a local `now`.
    let close_ts = deps.clock.now_secs();

    // FSM transition (`Closing → Closed`) + terminal leaf + best-effort relay
    // ciphertext delete. Returns Ok only if the transition landed.
    ttl::finalize_close(
        handle,
        deps.transport.as_ref(),
        deps.event_log.as_ref(),
        close_ts,
    )
    .await?;

    // #2148 (ADR-049 birth-into-actor): now that the close transition has landed,
    // dispose the ACTOR-owned MLS crypto for Ephemeral/Summary scope (the provider
    // holds none). Each `ScpMlsGroup` owns its own in-memory `InMemoryMlsProvider`,
    // freed when `PerContextState` drops — but a closed actor STAYS registered (its
    // `state` is NOT dropped here), so without an explicit dispose the crypto would
    // linger live. `dispose_secrets` runs OpenMLS `destroy_group`, which eagerly
    // frees the group NOW; the Ed25519 signer zeroizes on drop
    // (`SignatureKeyPair` holds its private key in `SecretVLBytes`) — same as a
    // bare drop, just eager; the sender key zeroizes on its own drop (security
    // model spec §9.15 lists the copies no wipe reaches). Full scope retains keys
    // (readable after close), so it is
    // skipped. A broadcast context carries no `ContextCryptoState`
    // (`crypto_mut() == None`), a clean no-op there.
    // #2199 (F2): the TRUTHFUL `KeyDestructionAttestation`, built below from the
    // OBSERVED disposal outcome and RETURNED to the local caller (which logs it).
    // `None` for Full scope / Broadcast / the crypto-absent anomaly.
    let mut attestation: Option<KeyDestructionAttestation> = None;
    let memory_scope = handle.params().memory_scope;
    if memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary {
        let mut view = cell.class_c_view();
        if let Some(crypto) = view.mode_mut().crypto_mut() {
            // #2199: capture the OBSERVED disposal outcome and build the TRUTHFUL
            // `KeyDestructionAttestation` HERE — at the seam where the actor-owned
            // crypto is actually torn down (post-disposal), from the REAL context
            // params (`memory_scope` above, read from `handle.params()`) + the
            // observed outcome + the actual close instant. The destroyed-flags are
            // the disposal's OBSERVED result read through the `DisposalOutcome`
            // accessors, never a fabricated `true` (a lying provenance record is
            // worse than honest absence — ADR-018). This is the SOLE canonical
            // attestation build site since #2199 deleted the dead orchestrators
            // (which minted a hardcoded `true` off a fake default `ContextParams`
            // BEFORE any disposal and discarded it). The built attestation is
            // RETURNED to `handle_finalize_close` for logging; recording it into
            // the event log / `ContextClosed` leaf is a separate DOA wire-format
            // decision tracked by #2215 — deliberately NOT done here.
            let disposal = crypto.dispose_secrets();
            attestation = Some(KeyDestructionAttestation {
                context_id: context_id.clone(),
                // `dispose_secrets` zeroizes the sender key (`ZeroizeOnDrop`) and
                // frees the MLS group in software; no hardware attestation is wired
                // on this path, so `SoftwareOnly` is the honest level.
                level: KeyDestructionLevel::SoftwareOnly,
                attested_at: close_ts,
                mls_group_destroyed: disposal.mls_group_destroyed(),
                sender_keys_destroyed: disposal.sender_keys_destroyed(),
            });
        } else {
            // Destruction-required scope with no `ContextCryptoState` — Broadcast is
            // Full-scope, so this is unreachable in practice. No disposal was
            // observed, so there is no truthful attestation to build; surface the
            // anomaly rather than fabricating one (#2199 honest-absent).
            tracing::warn!(
                context_id = %context_id,
                ?memory_scope,
                "finalize_close: destruction-required scope has no crypto state to \
                 dispose — no disposal observed, no attestation built (#2199 \
                 honest-absent)"
            );
        }
    }

    // Delete persisted state after finalize (best-effort). Mirrors
    // the legacy path which only ran the delete when a persistence
    // provider was attached; ContextPersistence is always present on
    // ActorDeps so we always issue the delete.
    let _ = deps.persistence.delete_context(&context_id).await;

    // Prune the authoritative Class-M floor registry entry (ADR-049):
    // an explicit close is a PERMANENT teardown. While this closed actor stays
    // REGISTERED, Precheck A (live-actor) blocks any resurrection of this id; the
    // durable Class-S snapshot is deleted just below (Ephemeral/Summary are
    // non-durable by design). There is therefore no terminal on-disk marker to
    // refuse against once the snapshot is gone — if this closed actor later
    // despawns/crashes the id becomes free to re-create, which is acceptable
    // here (a locally-driven, non-durable close, not a remote exploit). So the
    // registry floors are moot and must be dropped, mirroring the per-context
    // floor teardown inside `dispose_secrets`/`destroy_group` (which
    // `ttl::finalize_close` ran above for Ephemeral/Summary scope) and
    // co-located with the snapshot delete. Pruned
    // regardless of memory scope: a `Closed` context accepts no further inbound,
    // so the floors serve no purpose even when Full-scope crypto is retained.
    // See `Supervisor::remove_context_floors` for the permanent-vs-transient
    // safety argument.
    let ctx_id_bytes = context_id_to_bytes(&context_id);
    deps.supervisor.remove_context_floors(&ctx_id_bytes);
    // Streaming twin of the floor-registry prune (spec §5.4.5): an explicit
    // close is a permanent teardown (`Closed` context accepts no further
    // stream opens), so drop its per-context admission-tracker registry
    // entry. An in-flight pump holding its own Arc keeps the tracker alive.
    deps.supervisor.reap_stream_admission(&context_id);

    // #2199 (F2): hand the truthful attestation back to the local caller (which
    // logs it). Pure in-process value — not surfaced across the FFI reply.
    Ok(attestation)
}
