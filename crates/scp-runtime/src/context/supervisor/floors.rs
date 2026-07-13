//! Supervisor-owned Class-M floor registry (ADR-049 PR-6, epoch + recv side).
//!
//! This module holds the [`ContextFloors`] registry on the [`Supervisor`] plus
//! the TOCTOU-safe advance primitives and the §23.17.2 validating merge that
//! mutate it. The merge/validation path (`validate_and_merge_*`) is now
//! **authoritative-CAPABLE**: it implements the full §23.17.2 fail-closed
//! Inv-2/Inv-3/Inv-4 + epoch-poisoning-overshoot validating merge (no longer the
//! unconditional monotone-max PR-4 follower). It is implemented and unit-tested
//! in isolation.
//!
//! The **LIVE receive/enforcement gate still reads the provider's authoritative
//! homes** — the supervisor-owned `MlsCryptoProvider` (`crypto/mls/provider.rs` —
//! `SenderKeyStore.epochs` and `recv_sequence_tracker`). Read-authority is NOT
//! flipped onto this registry yet: production still routes the authoritative
//! restore / import result through the provider (the follower seed's `Result` is
//! non-fatal, log-and-dropped), and no production code READS `Supervisor.floors`
//! for any enforcement, capture, or merge decision. The atomic read-authority
//! switch (a later ADR-049 PR-6 slice) flips the gate onto the registry; see
//! `actor/deps.rs` §"`MlsCryptoProvider` dissolution", ADR-049 Decision 9.
//!
//! Why it must live on the `Supervisor` (an `Arc<Supervisor>`, not on the actor
//! `PerContextState`): these are **Class-M** floors that MUST survive an actor
//! task unwind. A `PerContextState`-owned floor would die with the crashing
//! actor, re-opening the §23.17 Invariant-2 / Invariant-4 replay window on the
//! respawn. The provider carries them today for exactly this reason; PR-4 stands
//! up the supervisor-owned successor store as a follower so PR-7's key-move
//! (`take_crypto_state`) has a Class-M home already in place before the
//! provider's floor maps are deleted (PR-6). This ordering — PR-4 → PR-6 → PR-7
//! — is the only sound one.

use std::collections::HashMap;

use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ReceiveFloor;
use scp_protocol::crypto::sender_keys::{MAX_EPOCH_ADVANCE, MergePolicy};

use super::supervisor::Supervisor;

/// Per-context Class-M floor bundle held by the supervisor registry.
///
/// Bundled (rather than two separate maps) because the receive-side overshoot
/// ceiling in [`Supervisor::check_and_advance_recv_sequence`] reads the sender
/// epoch floor from the SAME entry — one `DashMap` entry guard covers both,
/// keeping every gate a single acquire (ADR-049 Decision 13).
///
/// No `Zeroize`: these are non-secret monotonic counters (epoch high-water and
/// `(epoch, sequence)` anti-replay marks), not key material.
#[derive(Debug, Default)]
pub(in crate::context::supervisor) struct ContextFloors {
    /// `sender_did` → highest sender-key epoch observed for that sender.
    /// Mirrors `SenderKeyStore.epochs` for this context (the authoritative
    /// copy in PR-4).
    ///
    /// INVARIANT (black-hat F-3): this one map holds BOTH the REMOTE per-sender
    /// distributed-epoch high-water (keyed by each remote sender DID) AND — via
    /// the local-rotation mirror-forward — the LOCAL `sender_key_epoch` scalar
    /// keyed by `local_did`. This coexistence is safe today ONLY because
    /// `local_did` never appears as a remote sender in its own recv path, so the
    /// receive-side overshoot ceiling (which reads `sender_epochs[remote_did]`)
    /// never reads the local scalar. This coincidence is LOAD-BEARING: PR-6 / PR-7
    /// must preserve it (or split the two counters into separate maps) before the
    /// gate becomes read-authoritative.
    pub(in crate::context::supervisor) sender_epochs: HashMap<String, u64>,
    /// `sender_did` → highest [`ReceiveFloor`] (`epoch`, `sequence`) accepted
    /// from that sender — the intra-epoch anti-replay floor (spec §23.17.3).
    /// LEXICOGRAPHIC (epoch-major) order. Mirrors the provider's
    /// `recv_sequence_tracker`.
    pub(in crate::context::supervisor) recv_sequence: HashMap<String, ReceiveFloor>,
}

/// Rejection reason from a floor-advance gate.
///
/// Non-fatal in PR-4: the follower mirror-forward seams log-and-drop these
/// because the provider remains authoritative. PR-6's atomic read-authority
/// switch flips these to fail-closed (see PR-6 scope note).
// `pub` (not `pub(crate)`) because this enum lives in the PRIVATE `floors`
// module: `pub` here is still crate-internal (the private module ceiling caps
// visibility), and `pub(crate)` would trip clippy::redundant_pub_crate.
// `handle.rs` reaches it via `super::floors::FloorAdvanceError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorAdvanceError {
    /// A sender-key epoch that did not strictly exceed the recorded floor
    /// (rollback / replay attempt — #1608 monotonicity).
    SenderEpochNotMonotonic {
        /// The sender whose floor was consulted.
        did: String,
        /// The floor currently recorded (absent floor read as `0`).
        current: u64,
        /// The rejected proposed epoch.
        proposed: u64,
    },
    /// A sender-key epoch beyond `current + max_advance` (epoch-poisoning
    /// ceiling — a crafted `epoch = u64::MAX` would otherwise wedge the store).
    SenderEpochOvershoot {
        /// The sender whose floor was consulted.
        did: String,
        /// The enforced `current + max_advance` ceiling.
        ceiling: u64,
        /// The rejected proposed epoch.
        proposed: u64,
    },
    /// A receive-side `(epoch, sequence)` that did not strictly exceed the
    /// recorded floor (replay / reorder — spec §23.17.3).
    RecvSequenceNotMonotonic {
        /// The sender whose floor was consulted.
        did: String,
        /// The floor currently recorded.
        current: ReceiveFloor,
        /// The rejected proposed [`ReceiveFloor`] (`epoch`, `sequence`).
        proposed: ReceiveFloor,
    },
    /// A receive-side epoch beyond the sender's epoch floor `+ max_advance`
    /// (the follower's analogue of the provider's H9 receive-side epoch ceiling
    /// in `open()` — but the ceiling reads THIS follower's own, possibly-lagging
    /// `sender_epochs` mirror, not the provider's authoritative epoch, so it is
    /// NOT exact provider-parity; exact parity is a PR-6 concern once the gate
    /// is fail-closed and read-authoritative).
    RecvSequenceOvershoot {
        /// The sender whose floor was consulted.
        did: String,
        /// The enforced `sender_epoch_floor + max_advance` ceiling.
        ceiling: u64,
        /// The rejected proposed epoch.
        proposed: u64,
    },
}

impl std::fmt::Display for FloorAdvanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SenderEpochNotMonotonic {
                did,
                current,
                proposed,
            } => write!(
                f,
                "sender-epoch floor for {did} is non-monotonic: proposed {proposed} <= current {current}"
            ),
            Self::SenderEpochOvershoot {
                did,
                ceiling,
                proposed,
            } => write!(
                f,
                "sender-epoch floor for {did} overshoots: proposed {proposed} > ceiling {ceiling}"
            ),
            Self::RecvSequenceNotMonotonic {
                did,
                current,
                proposed,
            } => write!(
                f,
                "recv-sequence floor for {did} is non-monotonic: proposed {proposed:?} <= current {current:?}"
            ),
            Self::RecvSequenceOvershoot {
                did,
                ceiling,
                proposed,
            } => write!(
                f,
                "recv-sequence floor for {did} overshoots: proposed epoch {proposed} > ceiling {ceiling}"
            ),
        }
    }
}

impl std::error::Error for FloorAdvanceError {}

/// Live receive-gating rejection → context error, for the PR-6 fail-closed
/// seams (`open()` + the three receive helper seams, landing in later PR-6
/// slices) that will call `check_and_advance_*(..)?` and must surface a
/// [`ContextError`]. Additive here: no caller wires it in this slice.
///
/// ALL FOUR variants map uniformly to [`ContextError::CryptoFailed`]. This is a
/// deliberate, reviewed choice — not a convenience default:
///
/// - `FloorAdvanceError` is the **live receive-gating** rejection type: a
///   received sender-key epoch or recv `(epoch, sequence)` that fails the
///   monotonicity / overshoot floor at the crypto-open seam. `CryptoFailed` is
///   exactly what the live crypto path (`open()`, MLS decrypt) already returns,
///   so mapping here preserves the existing FFI/SDK-bridged crypto-failure
///   taxonomy — no new canonical code, no bridge-translator change. Concretely,
///   the authoritative live `open()` path already maps the sender-key
///   rollback/replay case (`SenderKeyError::EpochNotMonotonic`, surfaced by the
///   provider's epoch check) to `ContextError::CryptoFailed`; mapping this
///   follower-mirror analogue to anything else would make the follower seam
///   MORE granular than the authoritative seam it mirrors.
/// - It deliberately does **not** map to
///   [`ContextError::SnapshotFloorRegression`]. That variant is
///   *import-specific* (canonical code `SCP-CTX-2091`): it aggregates EVERY
///   regressing sender into `per_sender_deltas: Vec<(String, u64, u64)>` and
///   carries a `resource` class string. It is constructed directly by the
///   snapshot import/merge path (`validate_and_merge_*`), which holds the full
///   delta set. A per-variant `From` sees only ONE sender and no resource
///   class, so producing `SnapshotFloorRegression` from it would fabricate a
///   bogus single-element aggregate and misrepresent a live replay rejection as
///   a snapshot-import regression.
/// - `err.to_string()` preserves the [`Display`](std::fmt::Display) message
///   (which sender, current vs proposed floor, ceiling) into `CryptoFailed`'s
///   `String` payload, so the human-readable reason survives the conversion.
impl From<FloorAdvanceError> for ContextError {
    fn from(err: FloorAdvanceError) -> Self {
        Self::CryptoFailed(err.to_string())
    }
}

impl Supervisor {
    /// Atomically check-and-advance the per-sender **epoch** floor for `ctx`.
    ///
    /// The whole read-current → reject-if-`<=` → reject-if-overshoot → write
    /// sequence runs under **exactly ONE** `self.floors.entry(*ctx).or_default()`
    /// guard (ADR-049 Decision 13 — one acquire per gate). It NEVER does a
    /// `get()`-then-`insert()`, which would open a TOCTOU window.
    ///
    /// # Single-writer / security separation (inquisitor-sharpened, verbatim)
    ///
    /// SECURITY — "never accept a key below the floor" — is STRUCTURAL and
    /// caller-topology-independent: the single-`entry()`-guard body (atomic read
    /// → reject-`<=` → reject-overshoot → write, all under one guard) plus the
    /// fail-safe gate-then-key-insert ordering make key-below-floor impossible no
    /// matter who calls. The per-context single-writer actor (`ContextActor::run()`
    /// serializes gate-then-insert) preserves only LIVENESS (avoids spurious
    /// rejects). If `check_and_advance` were ever called for a LIVE context from
    /// OUTSIDE its owning actor, the gate→insert window would open but stays
    /// FAIL-SAFE — it degrades liveness (a spurious reject / retry), NEVER
    /// fail-open. Do NOT read this as "security depends on single-writer";
    /// security is the structural gate, single-writer is a liveness convention.
    /// (PR-6 re-evaluates whether a structural guard is warranted once the gate
    /// RESULT becomes security-enforced.)
    ///
    /// # Errors
    ///
    /// [`FloorAdvanceError::SenderEpochNotMonotonic`] if `epoch <=` the recorded
    /// floor (absent floor read as `0`, matching `SenderKeyStore::set_checked`);
    /// [`FloorAdvanceError::SenderEpochOvershoot`] if `epoch` exceeds
    /// `current + max_advance`.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span read-reject-write for the TOCTOU-atomic monotone floor advance (ADR-049 PR-4); early-dropping it breaks the invariant"
    )]
    pub(in crate::context) fn check_and_advance_sender_epoch(
        &self,
        ctx: &[u8; 32],
        did: &str,
        epoch: u64,
        max_advance: u64,
    ) -> Result<(), FloorAdvanceError> {
        // THE single guard. Everything below runs under it — no second acquire.
        let mut entry = self.floors.entry(*ctx).or_default();
        let floors = entry.value_mut();

        // Read-current UNDER the guard (absent read as 0, matching set_checked).
        let current = floors.sender_epochs.get(did).copied().unwrap_or(0);
        // reject-if-<= (monotonicity, #1608).
        if epoch <= current {
            return Err(FloorAdvanceError::SenderEpochNotMonotonic {
                did: did.to_owned(),
                current,
                proposed: epoch,
            });
        }
        // reject-if-overshoot (epoch-poisoning ceiling).
        let ceiling = current.saturating_add(max_advance);
        if epoch > ceiling {
            return Err(FloorAdvanceError::SenderEpochOvershoot {
                did: did.to_owned(),
                ceiling,
                proposed: epoch,
            });
        }
        // write UNDER the same guard.
        floors.sender_epochs.insert(did.to_owned(), epoch);
        Ok(())
    }

    /// Atomically check-and-advance the per-sender **receive-sequence** floor for
    /// `ctx`. Receive-side twin of [`Self::check_and_advance_sender_epoch`].
    ///
    /// `next` is compared LEXICOGRAPHICALLY on `(epoch, sequence)`. The overshoot
    /// ceiling reads the sender epoch floor from the SAME entry — the follower's
    /// analogue of the provider's H9 receive-side epoch ceiling in `open()`, but
    /// against THIS follower's own, possibly-lagging `sender_epochs` mirror (which
    /// only catches up when the Management-arm mirror-forward runs), NOT the
    /// provider's authoritative epoch. It is therefore NOT exact provider-parity;
    /// exact parity is a PR-6 concern once the gate becomes fail-closed and
    /// read-authoritative. Both floors live under one `entry()` guard (ADR-049
    /// Decision 13). Same TOCTOU-safety and the same
    /// single-writer / security separation as the epoch twin above apply here
    /// verbatim: security is the structural single-guard gate; single-writer is
    /// only a liveness convention.
    ///
    /// # Errors
    ///
    /// [`FloorAdvanceError::RecvSequenceNotMonotonic`] if `next <=` a recorded
    /// floor (absent floor accepts the first observation, matching `open()`'s
    /// `Some`-guarded replay check); [`FloorAdvanceError::RecvSequenceOvershoot`]
    /// if `next.0` exceeds `sender_epoch_floor + max_advance`.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span read-reject-write for the TOCTOU-atomic monotone floor advance (ADR-049 PR-4); early-dropping it breaks the invariant"
    )]
    pub(in crate::context) fn check_and_advance_recv_sequence(
        &self,
        ctx: &[u8; 32],
        did: &str,
        next: ReceiveFloor,
        max_advance: u64,
    ) -> Result<(), FloorAdvanceError> {
        // THE single guard. Everything below runs under it — no second acquire.
        let mut entry = self.floors.entry(*ctx).or_default();
        let floors = entry.value_mut();

        // reject-if-<= — but ONLY when a floor is already present, matching
        // `open()` which applies the replay check under `if let Some(..)` and
        // accepts the first observation for an absent sender.
        if let Some(current) = floors.recv_sequence.get(did).copied()
            && next <= current
        {
            return Err(FloorAdvanceError::RecvSequenceNotMonotonic {
                did: did.to_owned(),
                current,
                proposed: next,
            });
        }
        // reject-if-overshoot: the receive-side epoch ceiling reads the sender
        // epoch floor from THIS SAME entry (absent read as 0).
        let epoch_floor = floors.sender_epochs.get(did).copied().unwrap_or(0);
        let ceiling = epoch_floor.saturating_add(max_advance);
        if next.epoch > ceiling {
            return Err(FloorAdvanceError::RecvSequenceOvershoot {
                did: did.to_owned(),
                ceiling,
                proposed: next.epoch,
            });
        }
        // write UNDER the same guard.
        floors.recv_sequence.insert(did.to_owned(), next);
        Ok(())
    }

    /// Read the registry's per-sender epoch floors for `ctx` as a
    /// `(sender_did, epoch)` list (empty if no entry). Registry twin of the
    /// provider's `export_sender_key_epochs`; PR-6 retargets callers here.
    ///
    /// PR-4 has no PRODUCTION caller (the authoritative capture stays on the
    /// provider); this is the forward-declared read surface the PR-6
    /// read-authority switch retargets onto. Fully exercised by the registry
    /// unit tests + the respawn coalesce-lag follower-tracks-provider assertion.
    #[must_use]
    #[allow(
        dead_code,
        reason = "ADR-049 PR-4 forward-declared registry read API; production callers land in PR-6 (read-authority switch). Test-exercised today."
    )]
    pub(in crate::context) fn export_sender_key_epochs(
        &self,
        ctx: &[u8; 32],
    ) -> Vec<(String, u64)> {
        self.floors.get(ctx).map_or_else(Vec::new, |entry| {
            entry
                .value()
                .sender_epochs
                .iter()
                .map(|(did, epoch)| (did.clone(), *epoch))
                .collect()
        })
    }

    /// Read the registry's per-sender receive-sequence floors for `ctx` as a
    /// `(sender_did, (epoch, sequence))` list (empty if no entry). Registry twin
    /// of the provider's `export_recv_sequence_floors`.
    ///
    /// PR-4 has no PRODUCTION caller (forward-declared for the PR-6
    /// read-authority switch); fully exercised by the registry unit tests.
    #[must_use]
    #[allow(
        dead_code,
        reason = "ADR-049 PR-4 forward-declared registry read API; production callers land in PR-6 (read-authority switch). Test-exercised today."
    )]
    pub(in crate::context) fn export_recv_sequence_floors(
        &self,
        ctx: &[u8; 32],
    ) -> Vec<(String, ReceiveFloor)> {
        self.floors.get(ctx).map_or_else(Vec::new, |entry| {
            entry
                .value()
                .recv_sequence
                .iter()
                .map(|(did, floor)| (did.clone(), *floor))
                .collect()
        })
    }

    /// Merge `incoming` per-sender epoch floors into the registry for `ctx`
    /// under the spec §23.17.2 fail-closed validating-merge semantics.
    ///
    /// This path is **authoritative-CAPABLE** — it implements the full §23.17.2
    /// merge, NOT the PR-4 unconditional monotone-max follower. `policy` selects
    /// the lower-bound rule:
    ///
    /// - [`MergePolicy::RejectRegression`] (**Inv-3**, UNTRUSTED import): reject
    ///   the WHOLE merge if ANY incoming floor is strictly below its local floor
    ///   (a snapshot-mediated downgrade is a replay vector).
    /// - [`MergePolicy::MaxMergeTrustedLocal`] (**Inv-2**, TRUSTED-LOCAL restore):
    ///   NEVER reject a regression — a snapshot floor lagging the live floor is
    ///   the expected ≤50ms coalesce-lag case (ADR-049 §9), silently dominated by
    ///   the live floor in the max-merge apply.
    ///
    /// BOTH policies enforce the epoch-poisoning overshoot ceiling
    /// (`local + max_advance`, saturating; the ADR-049 guard keyed off
    /// `MAX_EPOCH_ADVANCE = 1000`) and the **Inv-4** append-only max-merge apply.
    /// The validation pass returns on the FIRST failure BEFORE any mutation, so a
    /// rejected merge leaves the registry UNTOUCHED (atomic — no partial apply).
    /// The whole two-pass merge runs under one `entry()` guard.
    ///
    /// # Errors
    ///
    /// Returns the single-sender [`FloorAdvanceError`] for the FIRST failing
    /// sender in `incoming` order:
    /// [`FloorAdvanceError::SenderEpochNotMonotonic`] on an Inv-3 regression, or
    /// [`FloorAdvanceError::SenderEpochOvershoot`] on an overshoot. (The provider
    /// twin aggregates every failure into `ContextError::SnapshotFloorRegression`;
    /// the `From<FloorAdvanceError>` impl reconciles this single-sender registry
    /// error to `ContextError` at the atomic-core seam. Atomicity holds
    /// regardless of single-vs-batch reporting.)
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span the whole validating two-pass merge (ADR-049 §23.17.2); early-dropping it breaks the TOCTOU-atomic single-guard invariant"
    )]
    pub(in crate::context) fn validate_and_merge_epoch_floors(
        &self,
        ctx: &[u8; 32],
        incoming: Vec<(String, u64)>,
        max_advance: u64,
        policy: MergePolicy,
    ) -> Result<(), FloorAdvanceError> {
        // Cold-restart no-op (§23.17.2 / ADR-049 §9): nothing to merge or regress
        // against.
        if incoming.is_empty() {
            return Ok(());
        }
        // THE single guard. Both passes run under it — no second acquire.
        let mut entry = self.floors.entry(*ctx).or_default();
        let floors = entry.value_mut();

        // Validation pass (NO mutation): returning on the FIRST failure — BEFORE
        // any apply below — IS the "reject the whole merge, no partial apply"
        // atomicity guarantee.
        for (did, incoming_epoch) in &incoming {
            let local = floors.sender_epochs.get(did).copied().unwrap_or(0);
            // Inv-3 lower-bound (RejectRegression only): a strictly-lower incoming
            // floor is a replay/downgrade. MaxMergeTrustedLocal (Inv-2) tolerates
            // it — the live floor dominates in the apply pass.
            if policy == MergePolicy::RejectRegression && *incoming_epoch < local {
                return Err(FloorAdvanceError::SenderEpochNotMonotonic {
                    did: did.clone(),
                    current: local,
                    proposed: *incoming_epoch,
                });
            }
            // Epoch-poisoning overshoot ceiling (BOTH policies): reject a floor
            // beyond `local + max_advance` so a corrupt snapshot cannot wedge the
            // sender's monotonicity guard at `epoch = u64::MAX`.
            let ceiling = local.saturating_add(max_advance);
            if *incoming_epoch > ceiling {
                return Err(FloorAdvanceError::SenderEpochOvershoot {
                    did: did.clone(),
                    ceiling,
                    proposed: *incoming_epoch,
                });
            }
        }

        // Apply pass (Inv-4 append-only max-merge): only reached when validation
        // found no failure. Senders present locally but absent from `incoming`
        // are untouched (local-only retention).
        for (did, incoming_epoch) in incoming {
            floors
                .sender_epochs
                .entry(did)
                .and_modify(|cur| *cur = (*cur).max(incoming_epoch))
                .or_insert(incoming_epoch);
        }
        Ok(())
    }

    /// Merge `incoming` per-sender receive-sequence floors into the registry for
    /// `ctx` under the spec §23.17.2 / §23.17.3 fail-closed validating-merge
    /// semantics. Receive-side twin of
    /// [`Self::validate_and_merge_epoch_floors`].
    ///
    /// `policy` selects the lower-bound rule exactly as the epoch twin:
    /// [`MergePolicy::RejectRegression`] (**Inv-3**) rejects the WHOLE merge if
    /// ANY incoming [`ReceiveFloor`] is lexicographically (epoch-major) below its
    /// local floor; [`MergePolicy::MaxMergeTrustedLocal`] (**Inv-2**) tolerates a
    /// lagging floor. The **Inv-4** apply pass max-merges lexicographically. An
    /// absent local floor accepts the first observation.
    ///
    /// The epoch-poisoning overshoot ceiling bounds ONLY the EPOCH axis: an
    /// incoming floor whose `epoch` exceeds the sender's epoch floor
    /// (`sender_epochs[did] + MAX_EPOCH_ADVANCE`, saturating, read from the SAME
    /// entry) is rejected under BOTH policies. The SEQUENCE axis is DELIBERATELY
    /// UNBOUNDED: there is no sound `MAX_SEQUENCE_ADVANCE` oracle (no per-`(sender,
    /// epoch)` sequence high-water to bound against, unlike `sender_epochs` for
    /// the epoch axis), and §23.17.2 Inv-3 mandates accepting a floor `>= local`
    /// via max-merge. The residual is reachable by ANY untrusted peer whose
    /// imported snapshot passes validation — not only a signed/trusted exporter:
    /// under `RejectRegression` an incoming `(current_epoch, u64::MAX)` is
    /// `>= local` AND within the epoch ceiling, so it is accepted and silences
    /// that sender for the current epoch. It stays LOW-severity because it is
    /// (a) fail-SAFE — it can only OVER-reject that sender's legitimate messages
    /// (a self-inflicted liveness dent), NEVER admit a replay or a floor below the
    /// live one; and (b) self-healing — the next sender-key rotation advances the
    /// sender to `epoch + 1`, and `(epoch + 1, 0) > (epoch, u64::MAX)` epoch-major,
    /// so a legitimate `(epoch + 1, *)` floor immediately clears the poisoned mark.
    /// It is a bounded `DoS`, NOT a replay hole.
    ///
    /// # Precondition (F-2 / same-entry epoch read)
    ///
    /// The epoch-axis ceiling reads `sender_epochs[did]` from the SAME entry, so
    /// the caller MUST run [`Self::validate_and_merge_epoch_floors`] BEFORE this
    /// recv merge (the existing follower-seed caller order already does). This is
    /// the F-3 co-mingling invariant: the ceiling reads
    /// `sender_epochs[remote_did]`, and `local_did` never appears as a remote
    /// sender on its own recv path, so the ceiling never reads the local scalar.
    ///
    /// # Errors
    ///
    /// Returns the single-sender [`FloorAdvanceError`] for the FIRST failing
    /// sender in `incoming` order:
    /// [`FloorAdvanceError::RecvSequenceNotMonotonic`] on an Inv-3 regression, or
    /// [`FloorAdvanceError::RecvSequenceOvershoot`] on an epoch overshoot.
    /// Reconciled to `ContextError::SnapshotFloorRegression` via the
    /// `From<FloorAdvanceError>` impl at the atomic-core seam; atomicity holds
    /// regardless of single-vs-batch reporting.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span the whole validating two-pass merge (ADR-049 §23.17.2); early-dropping it breaks the TOCTOU-atomic single-guard invariant"
    )]
    pub(in crate::context) fn validate_and_merge_recv_sequence_floors(
        &self,
        ctx: &[u8; 32],
        incoming: Vec<(String, ReceiveFloor)>,
        policy: MergePolicy,
    ) -> Result<(), FloorAdvanceError> {
        // Cold-restart no-op (§23.17.2 / ADR-049 §9): nothing to merge or regress
        // against.
        if incoming.is_empty() {
            return Ok(());
        }
        // THE single guard. Both passes run under it — no second acquire.
        let mut entry = self.floors.entry(*ctx).or_default();
        let floors = entry.value_mut();

        // Validation pass (NO mutation): returning on the FIRST failure BEFORE any
        // apply IS the "reject the whole merge, no partial apply" atomicity
        // guarantee.
        for (did, incoming_floor) in &incoming {
            // Inv-3 lower-bound (RejectRegression only), lexicographic epoch-major
            // via ReceiveFloor's derived Ord. An absent local floor accepts the
            // first observation (matching the live gate's Some-guarded check).
            if policy == MergePolicy::RejectRegression
                && let Some(current) = floors.recv_sequence.get(did).copied()
                && *incoming_floor < current
            {
                return Err(FloorAdvanceError::RecvSequenceNotMonotonic {
                    did: did.clone(),
                    current,
                    proposed: *incoming_floor,
                });
            }
            // Epoch-poisoning overshoot ceiling (BOTH policies), EPOCH axis only.
            // Reads the sender epoch floor from THIS SAME entry (absent read as
            // 0). The sequence axis is intentionally unbounded (see fn docs).
            let epoch_floor = floors.sender_epochs.get(did).copied().unwrap_or(0);
            let ceiling = epoch_floor.saturating_add(MAX_EPOCH_ADVANCE);
            if incoming_floor.epoch > ceiling {
                return Err(FloorAdvanceError::RecvSequenceOvershoot {
                    did: did.clone(),
                    ceiling,
                    proposed: incoming_floor.epoch,
                });
            }
        }

        // Apply pass (Inv-4 append-only max-merge), lexicographic. Senders present
        // locally but absent from `incoming` are untouched (local-only retention).
        for (did, incoming_floor) in incoming {
            floors
                .recv_sequence
                .entry(did)
                .and_modify(|cur| *cur = (*cur).max(incoming_floor))
                .or_insert(incoming_floor);
        }
        Ok(())
    }

    /// Create-seed: ensure a default-empty floor entry exists for `ctx`.
    ///
    /// ADR-049 PR-4 §5 — called on the context-creation path so the registry
    /// entry exists from creation (it then grows via mirror-forward).
    /// **INSERT-IF-ABSENT only** (`entry().or_default()`), NEVER an
    /// unconditional `insert`: a late / racing create-seed must never reset an
    /// already-advanced follower entry. Harmless in PR-4 (the registry is
    /// unread) but forward-safe for the PR-6 read-authority switch.
    /// [cryptographer hardening]
    pub(in crate::context) fn seed_context_floors(&self, ctx: &[u8; 32]) {
        // Insert-if-absent; the returned guard is dropped immediately. Does NOT
        // overwrite an existing (possibly already-advanced) entry.
        self.floors.entry(*ctx).or_default();
    }

    /// Permanent-teardown prune: drop the whole [`ContextFloors`] entry for
    /// `ctx` (ADR-049 PR-4).
    ///
    /// The provider prunes its AUTHORITATIVE per-context floor maps inside
    /// `destroy_mls_group` (`self.contexts.remove` in `crypto/mls/provider.rs`);
    /// the follower registry has no such prune, so without this every
    /// permanently-torn-down context would leak a `ContextFloors` entry (and its
    /// unbounded per-sender maps). This is the follower twin of that prune,
    /// called from EVERY genuine permanent-teardown site (explicit
    /// close → `Closed`, TTL expiry → `Expired`, welcome-join rollback, process
    /// shutdown) — mirroring exactly where the provider drops its crypto state
    /// and where `crash_windows` is reaped.
    ///
    /// # Safety (why pruning is sound only on PERMANENT teardown)
    ///
    /// A later re-create of the SAME deterministic id is a NEW MLS group with
    /// fresh keys, so the discarded `(epoch, sequence)` / epoch floors are
    /// cryptographically moot — an old floor cannot gate (or be replayed
    /// against) the new group's keys. It is therefore CORRECT here but WOULD BE
    /// UNSOUND on a TRANSIENT destroy where the SAME keys resume (a warm
    /// respawn / restore, where `restore_crypto_state_with_floor_guard`
    /// deliberately captures + re-merges the live floors instead of dropping
    /// them). Callers must only invoke this when the context is permanently gone
    /// or is being replaced by a fresh group. Idempotent: remove-on-absent is a
    /// no-op, so a bounded TTL-expiry retry re-entering here is harmless.
    pub(in crate::context) fn remove_context_floors(&self, ctx: &[u8; 32]) {
        self.floors.remove(ctx);
    }

    /// Member-granular floor prune: remove `did` from BOTH the `sender_epochs`
    /// and `recv_sequence` maps of `ctx`'s [`ContextFloors`] entry, WITHOUT
    /// dropping the whole entry (sibling senders and the local `sender_key_epoch`
    /// scalar remain).
    ///
    /// The member-granular twin of [`Self::remove_context_floors`]: that prunes
    /// the entire per-context bundle on permanent teardown; this prunes a single
    /// departed member's floors while the context lives on. Both maps are cleared
    /// under ONE `get_mut` guard so a member is never left half-removed.
    ///
    /// Idempotent: an absent member — or an absent `ctx` — is a no-op.
    ///
    /// No membership-set sweep here: the registry carries no membership set at
    /// this layer (that is an atomic-core caller concern). Production callers
    /// (a member leaving / being removed pruning its floors) arrive with the
    /// atomic read-authority switch; definition-only in this slice.
    #[allow(
        dead_code,
        reason = "ADR-049 PR-6 forward-declared member-granular floor prune; production callers land in the atomic read-authority switch. Test-exercised today."
    )]
    pub(in crate::context) fn remove_member_floors(&self, ctx: &[u8; 32], did: &str) {
        if let Some(mut entry) = self.floors.get_mut(ctx) {
            let floors = entry.value_mut();
            floors.sender_epochs.remove(did);
            floors.recv_sequence.remove(did);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use scp_protocol::crypto::sender_keys::{MAX_EPOCH_ADVANCE, MergePolicy};

    use super::{ContextError, FloorAdvanceError, ReceiveFloor, Supervisor};
    use crate::context::supervisor::handle::SupervisorHandle;

    const CTX: [u8; 32] = [0xA5u8; 32];
    const DID: &str = "did:dht:z6MkFloorSenderFloorSenderFloorSenderAA";

    /// Terse [`ReceiveFloor`] constructor for the recv-sequence tests.
    const fn rf(epoch: u64, sequence: u64) -> ReceiveFloor {
        ReceiveFloor { epoch, sequence }
    }

    fn sup() -> Arc<Supervisor> {
        // The registry needs no providers, so the provider-free query shim is
        // the right lightweight constructor for these unit tests.
        Arc::new(Supervisor::for_query_shim())
    }

    // -- sender-epoch monotonicity + overshoot ----------------------------------

    #[test]
    fn sender_epoch_advances_monotonically() {
        let s = sup();
        // First observation must be > 0 (matches SenderKeyStore::set_checked).
        assert_eq!(
            s.check_and_advance_sender_epoch(&CTX, DID, 0, MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::SenderEpochNotMonotonic {
                did: DID.to_owned(),
                current: 0,
                proposed: 0,
            })
        );
        assert!(
            s.check_and_advance_sender_epoch(&CTX, DID, 1, MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        assert!(
            s.check_and_advance_sender_epoch(&CTX, DID, 5, MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // Equal or lower is rejected (rollback / replay).
        assert!(matches!(
            s.check_and_advance_sender_epoch(&CTX, DID, 5, MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::SenderEpochNotMonotonic { .. })
        ));
        assert!(matches!(
            s.check_and_advance_sender_epoch(&CTX, DID, 4, MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::SenderEpochNotMonotonic { .. })
        ));
        assert_eq!(s.export_sender_key_epochs(&CTX), vec![(DID.to_owned(), 5)]);
    }

    #[test]
    fn sender_epoch_rejects_overshoot() {
        let s = sup();
        // From an absent floor (0), the ceiling is 0 + MAX_EPOCH_ADVANCE.
        assert_eq!(
            s.check_and_advance_sender_epoch(&CTX, DID, MAX_EPOCH_ADVANCE + 1, MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::SenderEpochOvershoot {
                did: DID.to_owned(),
                ceiling: MAX_EPOCH_ADVANCE,
                proposed: MAX_EPOCH_ADVANCE + 1,
            })
        );
        // Exactly at the ceiling is accepted.
        assert!(
            s.check_and_advance_sender_epoch(&CTX, DID, MAX_EPOCH_ADVANCE, MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // A rejected overshoot leaves no floor written.
        assert_eq!(
            s.export_sender_key_epochs(&CTX),
            vec![(DID.to_owned(), MAX_EPOCH_ADVANCE)]
        );
    }

    // -- recv-sequence monotonicity + overshoot ---------------------------------

    #[test]
    fn recv_sequence_advances_lexicographically() {
        let s = sup();
        // First observation for an absent sender is accepted (matches open()'s
        // Some-guarded replay check).
        assert!(
            s.check_and_advance_recv_sequence(&CTX, DID, rf(0, 3), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // Same (epoch, seq) is a replay — rejected.
        assert!(matches!(
            s.check_and_advance_recv_sequence(&CTX, DID, rf(0, 3), MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
        ));
        // Lower sequence at the same epoch — rejected.
        assert!(matches!(
            s.check_and_advance_recv_sequence(&CTX, DID, rf(0, 2), MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
        ));
        // Higher sequence at the same epoch — accepted.
        assert!(
            s.check_and_advance_recv_sequence(&CTX, DID, rf(0, 4), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // Advance to a higher epoch — accepted (epoch 1 is within the ceiling
        // `sender_epoch_floor(0) + MAX_EPOCH_ADVANCE`).
        assert!(
            s.check_and_advance_recv_sequence(&CTX, DID, rf(1, 0), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // Lower epoch, even with a much higher seq — rejected (lexicographic on
        // the `(epoch, seq)` pair: `(0, 99) < (1, 0)`).
        assert!(matches!(
            s.check_and_advance_recv_sequence(&CTX, DID, rf(0, 99), MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
        ));
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![(DID.to_owned(), rf(1, 0))]
        );
    }

    #[test]
    fn recv_sequence_overshoot_reads_epoch_floor_from_same_entry() {
        let s = sup();
        // Advance the sender epoch floor to 5 in the SAME entry.
        s.check_and_advance_sender_epoch(&CTX, DID, 5, MAX_EPOCH_ADVANCE)
            .unwrap();
        // A recv epoch beyond epoch_floor(5) + MAX_EPOCH_ADVANCE is rejected.
        assert_eq!(
            s.check_and_advance_recv_sequence(
                &CTX,
                DID,
                rf(5 + MAX_EPOCH_ADVANCE + 1, 0),
                MAX_EPOCH_ADVANCE
            ),
            Err(FloorAdvanceError::RecvSequenceOvershoot {
                did: DID.to_owned(),
                ceiling: 5 + MAX_EPOCH_ADVANCE,
                proposed: 5 + MAX_EPOCH_ADVANCE + 1,
            })
        );
        // At the ceiling — accepted.
        assert!(
            s.check_and_advance_recv_sequence(
                &CTX,
                DID,
                rf(5 + MAX_EPOCH_ADVANCE, 0),
                MAX_EPOCH_ADVANCE
            )
            .is_ok()
        );
    }

    // -- FloorAdvanceError → ContextError conversion (PR-6 seam) ----------------

    #[test]
    fn floor_advance_error_converts_to_crypto_failed_preserving_message() {
        // Every FloorAdvanceError variant is a LIVE receive-gating rejection and
        // MUST land as ContextError::CryptoFailed (never SnapshotFloorRegression),
        // carrying the Display message so the human-readable reason survives.
        let cases = [
            FloorAdvanceError::SenderEpochNotMonotonic {
                did: DID.to_owned(),
                current: 7,
                proposed: 4,
            },
            FloorAdvanceError::SenderEpochOvershoot {
                did: DID.to_owned(),
                ceiling: 10,
                proposed: 99,
            },
            FloorAdvanceError::RecvSequenceNotMonotonic {
                did: DID.to_owned(),
                current: rf(3, 8),
                proposed: rf(3, 2),
            },
            FloorAdvanceError::RecvSequenceOvershoot {
                did: DID.to_owned(),
                ceiling: 12,
                proposed: 40,
            },
        ];

        for err in cases {
            let expected_message = err.to_string();

            // Convert via the `From` impl (the shape the `?`-seams will use).
            let ctx_err = ContextError::from(err.clone());
            assert!(
                matches!(ctx_err, ContextError::CryptoFailed(_)),
                "expected CryptoFailed for {err:?}, got {ctx_err:?}"
            );

            // The Display message must be preserved verbatim in the payload —
            // including the sender DID and the numeric floor facts.
            let ContextError::CryptoFailed(payload) = &ctx_err else {
                unreachable!("matched CryptoFailed above");
            };
            assert_eq!(
                payload, &expected_message,
                "CryptoFailed payload must be the FloorAdvanceError Display message"
            );
            assert!(
                payload.contains(DID),
                "payload must name the sender DID: {payload}"
            );

            // `.into()` at a `?`-style seam yields the same CryptoFailed.
            let via_into: ContextError = err.into();
            assert!(matches!(via_into, ContextError::CryptoFailed(_)));
        }

        // Spot-check that the specific numeric facts of a NotMonotonic rejection
        // (proposed <= current) reach the payload, not just the DID.
        let mono = FloorAdvanceError::SenderEpochNotMonotonic {
            did: DID.to_owned(),
            current: 7,
            proposed: 4,
        };
        let ContextError::CryptoFailed(payload) = ContextError::from(mono) else {
            unreachable!("SenderEpochNotMonotonic maps to CryptoFailed");
        };
        assert!(
            payload.contains('7') && payload.contains('4'),
            "proposed/current numbers must survive into the payload: {payload}"
        );
    }

    // -- merge / seed / export --------------------------------------------------

    #[test]
    fn merge_is_monotone_max_and_seed_is_insert_if_absent() {
        let s = sup();
        // seed creates a default-empty entry (insert-if-absent).
        s.seed_context_floors(&CTX);
        assert!(s.export_sender_key_epochs(&CTX).is_empty());

        // Advance one sender, then merge a mix of lower + higher + new.
        s.check_and_advance_sender_epoch(&CTX, DID, 10, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.validate_and_merge_epoch_floors(
            &CTX,
            vec![
                (DID.to_owned(), 4),              // lower — must NOT regress
                (DID.to_owned(), 12),             // higher — wins via max
                ("did:dht:zOther".to_owned(), 7), // new sender
            ],
            MAX_EPOCH_ADVANCE,
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();
        let mut got = s.export_sender_key_epochs(&CTX);
        got.sort();
        assert_eq!(
            got,
            vec![(DID.to_owned(), 12), ("did:dht:zOther".to_owned(), 7)]
        );

        // seed after advance must NOT reset the entry.
        s.seed_context_floors(&CTX);
        let mut after = s.export_sender_key_epochs(&CTX);
        after.sort();
        assert_eq!(after, got);

        // recv merge twin — monotone max, lexicographic.
        s.validate_and_merge_recv_sequence_floors(
            &CTX,
            vec![(DID.to_owned(), rf(2, 9)), (DID.to_owned(), rf(1, 0))],
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![(DID.to_owned(), rf(2, 9))]
        );
        // empty merge is a no-op that does not error.
        assert!(
            s.validate_and_merge_epoch_floors(
                &CTX,
                vec![],
                MAX_EPOCH_ADVANCE,
                MergePolicy::RejectRegression
            )
            .is_ok()
        );
    }

    // -- §23.17.2 validating epoch merge (Inv-2/Inv-3/Inv-4 + overshoot) --------

    #[test]
    fn epoch_merge_max_merges_accepted_monotonic() {
        let s = sup();
        s.check_and_advance_sender_epoch(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.check_and_advance_sender_epoch(&CTX, "B", 10, MAX_EPOCH_ADVANCE)
            .unwrap();
        // Inv-2 (MaxMergeTrustedLocal): B:3 lags — tolerated, live 10 dominates;
        // A:8 wins via max; C:2 is a new sender (insert-if-absent).
        s.validate_and_merge_epoch_floors(
            &CTX,
            vec![
                ("A".to_owned(), 8),
                ("B".to_owned(), 3),
                ("C".to_owned(), 2),
            ],
            MAX_EPOCH_ADVANCE,
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();
        let mut got = s.export_sender_key_epochs(&CTX);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("A".to_owned(), 8),
                ("B".to_owned(), 10),
                ("C".to_owned(), 2)
            ]
        );
    }

    #[test]
    fn epoch_merge_rejects_regression_atomically() {
        let s = sup();
        s.check_and_advance_sender_epoch(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.check_and_advance_sender_epoch(&CTX, "B", 10, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.check_and_advance_sender_epoch(&CTX, "C", 1, MAX_EPOCH_ADVANCE)
            .unwrap();
        let before = {
            let mut v = s.export_sender_key_epochs(&CTX);
            v.sort();
            v
        };
        // Inv-3 (RejectRegression): A:9 validates OK first, then B:3 < 10 fails.
        // The FIRST failure is returned (single-sender FloorAdvanceError).
        assert_eq!(
            s.validate_and_merge_epoch_floors(
                &CTX,
                vec![("A".to_owned(), 9), ("B".to_owned(), 3)],
                MAX_EPOCH_ADVANCE,
                MergePolicy::RejectRegression,
            ),
            Err(FloorAdvanceError::SenderEpochNotMonotonic {
                did: "B".to_owned(),
                current: 10,
                proposed: 3,
            })
        );
        // Atomicity: A was NOT advanced despite validating OK — no partial apply.
        let after = {
            let mut v = s.export_sender_key_epochs(&CTX);
            v.sort();
            v
        };
        assert_eq!(after, before, "rejected merge leaves the map unchanged");
    }

    #[test]
    fn epoch_merge_rejects_overshoot_atomically_both_policies() {
        for policy in [
            MergePolicy::MaxMergeTrustedLocal,
            MergePolicy::RejectRegression,
        ] {
            let s = sup();
            s.check_and_advance_sender_epoch(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
                .unwrap();
            // Overshoot ceiling `local(5) + MAX_EPOCH_ADVANCE` — enforced under
            // BOTH policies.
            assert_eq!(
                s.validate_and_merge_epoch_floors(
                    &CTX,
                    vec![("A".to_owned(), 5 + MAX_EPOCH_ADVANCE + 1)],
                    MAX_EPOCH_ADVANCE,
                    policy,
                ),
                Err(FloorAdvanceError::SenderEpochOvershoot {
                    did: "A".to_owned(),
                    ceiling: 5 + MAX_EPOCH_ADVANCE,
                    proposed: 5 + MAX_EPOCH_ADVANCE + 1,
                })
            );
            // Rejected atomically — floor unchanged at 5.
            assert_eq!(s.export_sender_key_epochs(&CTX), vec![("A".to_owned(), 5)]);
            // Exactly at the ceiling is accepted.
            s.validate_and_merge_epoch_floors(
                &CTX,
                vec![("A".to_owned(), 5 + MAX_EPOCH_ADVANCE)],
                MAX_EPOCH_ADVANCE,
                policy,
            )
            .unwrap();
            assert_eq!(
                s.export_sender_key_epochs(&CTX),
                vec![("A".to_owned(), 5 + MAX_EPOCH_ADVANCE)]
            );
        }
    }

    #[test]
    fn epoch_merge_trusted_local_tolerates_vs_untrusted_rejects() {
        let regressing = vec![("A".to_owned(), 3)];
        // Inv-2 (trusted-local): the lagging floor is tolerated; live 10 dominates.
        let trusted = sup();
        trusted
            .check_and_advance_sender_epoch(&CTX, "A", 10, MAX_EPOCH_ADVANCE)
            .unwrap();
        trusted
            .validate_and_merge_epoch_floors(
                &CTX,
                regressing.clone(),
                MAX_EPOCH_ADVANCE,
                MergePolicy::MaxMergeTrustedLocal,
            )
            .unwrap();
        assert_eq!(
            trusted.export_sender_key_epochs(&CTX),
            vec![("A".to_owned(), 10)]
        );
        // Inv-3 (untrusted): the SAME regression is rejected.
        let untrusted = sup();
        untrusted
            .check_and_advance_sender_epoch(&CTX, "A", 10, MAX_EPOCH_ADVANCE)
            .unwrap();
        assert!(matches!(
            untrusted.validate_and_merge_epoch_floors(
                &CTX,
                regressing,
                MAX_EPOCH_ADVANCE,
                MergePolicy::RejectRegression,
            ),
            Err(FloorAdvanceError::SenderEpochNotMonotonic { .. })
        ));
        assert_eq!(
            untrusted.export_sender_key_epochs(&CTX),
            vec![("A".to_owned(), 10)]
        );
    }

    #[test]
    fn epoch_merge_empty_is_noop() {
        for policy in [
            MergePolicy::MaxMergeTrustedLocal,
            MergePolicy::RejectRegression,
        ] {
            let s = sup();
            s.check_and_advance_sender_epoch(&CTX, "A", 7, MAX_EPOCH_ADVANCE)
                .unwrap();
            s.validate_and_merge_epoch_floors(&CTX, vec![], MAX_EPOCH_ADVANCE, policy)
                .unwrap();
            assert_eq!(s.export_sender_key_epochs(&CTX), vec![("A".to_owned(), 7)]);
        }
    }

    // -- §23.17.2/.3 validating recv-sequence merge -----------------------------

    #[test]
    fn recv_merge_max_merges_lexicographic() {
        let s = sup();
        s.check_and_advance_recv_sequence(&CTX, "A", rf(2, 5), MAX_EPOCH_ADVANCE)
            .unwrap();
        // Inv-4 max-merge, epoch-major: rf(2,9) dominates; rf(1,99) is below
        // (lower epoch beats higher sequence).
        s.validate_and_merge_recv_sequence_floors(
            &CTX,
            vec![("A".to_owned(), rf(2, 9)), ("A".to_owned(), rf(1, 99))],
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![("A".to_owned(), rf(2, 9))]
        );
    }

    #[test]
    fn recv_merge_rejects_regression_atomically() {
        let s = sup();
        s.check_and_advance_recv_sequence(&CTX, "A", rf(3, 0), MAX_EPOCH_ADVANCE)
            .unwrap();
        s.check_and_advance_recv_sequence(&CTX, "B", rf(1, 4), MAX_EPOCH_ADVANCE)
            .unwrap();
        // Inv-3: rf(2,9) < rf(3,0) lexicographically (lower epoch) — rejected.
        assert_eq!(
            s.validate_and_merge_recv_sequence_floors(
                &CTX,
                vec![("A".to_owned(), rf(2, 9))],
                MergePolicy::RejectRegression,
            ),
            Err(FloorAdvanceError::RecvSequenceNotMonotonic {
                did: "A".to_owned(),
                current: rf(3, 0),
                proposed: rf(2, 9),
            })
        );
        // Atomicity: A keeps rf(3,0); sibling B is untouched.
        let mut got = s.export_recv_sequence_floors(&CTX);
        got.sort();
        assert_eq!(
            got,
            vec![("A".to_owned(), rf(3, 0)), ("B".to_owned(), rf(1, 4))]
        );
    }

    #[test]
    fn recv_merge_rejects_epoch_overshoot() {
        let s = sup();
        // Advance the sender epoch floor to 5 in the SAME entry.
        s.check_and_advance_sender_epoch(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
            .unwrap();
        // The recv overshoot ceiling reads `sender_epochs[A]`(5) + MAX_EPOCH_ADVANCE
        // from the SAME entry (F-3): a recv epoch beyond it is rejected.
        assert_eq!(
            s.validate_and_merge_recv_sequence_floors(
                &CTX,
                vec![("A".to_owned(), rf(5 + MAX_EPOCH_ADVANCE + 1, 0))],
                MergePolicy::RejectRegression,
            ),
            Err(FloorAdvanceError::RecvSequenceOvershoot {
                did: "A".to_owned(),
                ceiling: 5 + MAX_EPOCH_ADVANCE,
                proposed: 5 + MAX_EPOCH_ADVANCE + 1,
            })
        );
        // Rejected atomically — no recv floor written for A.
        assert!(s.export_recv_sequence_floors(&CTX).is_empty());
    }

    #[test]
    fn recv_merge_trusted_local_tolerates_regression() {
        let s = sup();
        s.check_and_advance_recv_sequence(&CTX, "A", rf(3, 0), MAX_EPOCH_ADVANCE)
            .unwrap();
        // Inv-2: a lagging restored recv floor is tolerated; live rf(3,0) dominates.
        s.validate_and_merge_recv_sequence_floors(
            &CTX,
            vec![("A".to_owned(), rf(2, 9))],
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![("A".to_owned(), rf(3, 0))]
        );
    }

    #[test]
    fn recv_merge_empty_is_noop() {
        for policy in [
            MergePolicy::MaxMergeTrustedLocal,
            MergePolicy::RejectRegression,
        ] {
            let s = sup();
            s.check_and_advance_recv_sequence(&CTX, "A", rf(1, 1), MAX_EPOCH_ADVANCE)
                .unwrap();
            s.validate_and_merge_recv_sequence_floors(&CTX, vec![], policy)
                .unwrap();
            assert_eq!(
                s.export_recv_sequence_floors(&CTX),
                vec![("A".to_owned(), rf(1, 1))]
            );
        }
    }

    // -- member-granular floor prune --------------------------------------------

    #[test]
    fn remove_member_floors_drops_member_keeps_siblings() {
        const OTHER_CTX: [u8; 32] = [0x11u8; 32];
        let s = sup();
        // Populate BOTH maps for two members.
        s.check_and_advance_sender_epoch(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.check_and_advance_sender_epoch(&CTX, "B", 7, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.check_and_advance_recv_sequence(&CTX, "A", rf(1, 2), MAX_EPOCH_ADVANCE)
            .unwrap();
        s.check_and_advance_recv_sequence(&CTX, "B", rf(3, 4), MAX_EPOCH_ADVANCE)
            .unwrap();

        s.remove_member_floors(&CTX, "A");

        // A is gone from BOTH maps; B is intact in BOTH; the ctx entry survives.
        assert_eq!(s.export_sender_key_epochs(&CTX), vec![("B".to_owned(), 7)]);
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![("B".to_owned(), rf(3, 4))]
        );
        assert_eq!(s.floors.len(), 1, "ctx entry kept — only the member pruned");

        // Idempotent: removing the now-absent member again is a no-op.
        s.remove_member_floors(&CTX, "A");
        assert_eq!(s.export_sender_key_epochs(&CTX), vec![("B".to_owned(), 7)]);
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![("B".to_owned(), rf(3, 4))]
        );

        // Absent ctx is a no-op — it does not create an entry.
        s.remove_member_floors(&OTHER_CTX, "A");
        assert!(s.export_sender_key_epochs(&OTHER_CTX).is_empty());
        assert_eq!(s.floors.len(), 1, "absent-ctx prune created no entry");
    }

    // -- Decision-13: exactly ONE registry entry per gate (single-guard body) ---

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "test read: the DashMap entry guard is held only across the immediate assertions verifying the single-entry invariant"
    )]
    fn gate_uses_single_entry_no_double_insert() {
        let s = sup();
        assert_eq!(s.floors.len(), 0);
        s.check_and_advance_sender_epoch(&CTX, DID, 1, MAX_EPOCH_ADVANCE)
            .unwrap();
        // One gate → exactly one context entry created.
        assert_eq!(s.floors.len(), 1, "one entry() per gate (Decision-13)");
        // A recv gate on the same ctx reuses the SAME entry — no second insert.
        s.check_and_advance_recv_sequence(&CTX, DID, rf(1, 1), MAX_EPOCH_ADVANCE)
            .unwrap();
        assert_eq!(s.floors.len(), 1, "recv gate reuses the same ctx entry");
        // Both floors live under that single entry.
        let entry = s.floors.get(&CTX).expect("ctx entry");
        assert_eq!(entry.sender_epochs.get(DID).copied(), Some(1));
        assert_eq!(entry.recv_sequence.get(DID).copied(), Some(rf(1, 1)));
    }

    // -- Decision-14: gate work is O(1) — independent of sender count -----------

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "test read: the DashMap entry guard is held only across the immediate assertions verifying O(1) per-sender isolation"
    )]
    fn gate_is_o1_independent_of_sender_count() {
        let s = sup();
        // Pre-load the registry entry with many senders.
        for i in 0..5_000u64 {
            let did = format!("did:dht:zBulk{i}");
            s.check_and_advance_sender_epoch(&CTX, &did, 1, MAX_EPOCH_ADVANCE)
                .unwrap();
        }
        // A single-sender advance in a large registry touches ONLY that sender:
        // no O(senders) scan/clone (the property the Decision-14 <15% budget
        // rests on — the mirror-forward reads the value from `open()`/getters in
        // O(1), never via an O(senders) export re-read).
        s.check_and_advance_sender_epoch(&CTX, DID, 42, MAX_EPOCH_ADVANCE)
            .unwrap();
        let entry = s.floors.get(&CTX).expect("ctx entry");
        assert_eq!(entry.sender_epochs.get(DID).copied(), Some(42));
        // Every pre-loaded sender is untouched (still 1) — the gate did not
        // rewrite or iterate them.
        assert_eq!(entry.sender_epochs.get("did:dht:zBulk0").copied(), Some(1));
        assert_eq!(
            entry.sender_epochs.get("did:dht:zBulk4999").copied(),
            Some(1)
        );
        assert_eq!(entry.sender_epochs.len(), 5_001);
    }

    // -- shuttle-style strict-monotonicity concurrency test ---------------------
    //
    // NOTE: this lives inline (crate-internal) rather than in
    // `tests/shuttle_actor.rs` because the registry gate is capability-reduced
    // (`pub(in crate::context)`) and is NOT reachable from the external test
    // crate without violating Invariant 3 / the cross-layer gate. It exercises
    // the same "strict-monotonicity under concurrent writers" invariant with
    // real OS threads, exactly like the sibling `context_handle_cas_stress`
    // stress test in `tests/shuttle_actor.rs`.

    #[test]
    fn concurrent_advances_are_strictly_monotone_no_lost_update() {
        const LADDER: u64 = 2_000;
        let s = sup();

        // Two threads race the SAME (ctx, did) ladder 1..=LADDER. Each epoch in
        // the ladder can be accepted by AT MOST ONE thread (the single-`entry()`
        // guard serializes gate-then-write); a slower thread re-loads the fresh
        // higher floor and is rejected. Under ANY interleaving the invariants are:
        //  (a) strict monotonicity — no accepted epoch is ever <= a prior floor;
        //  (b) no lost update — every epoch 1..=LADDER is accepted EXACTLY once,
        //      so the two threads' success counts sum to exactly LADDER;
        //  (c) the final floor is exactly the ladder top.
        let worker = |s: Arc<Supervisor>| {
            move || {
                let mut accepted = 0u64;
                for epoch in 1..=LADDER {
                    // max_advance = LADDER guarantees +1 steps never overshoot.
                    if s.check_and_advance_sender_epoch(&CTX, DID, epoch, LADDER)
                        .is_ok()
                    {
                        accepted += 1;
                    }
                }
                accepted
            }
        };
        let a = thread::spawn(worker(Arc::clone(&s)));
        let b = thread::spawn(worker(Arc::clone(&s)));
        let count_a = a.join().expect("thread a");
        let count_b = b.join().expect("thread b");

        // (b) no lost update, no double-accept.
        assert_eq!(
            count_a + count_b,
            LADDER,
            "each epoch must be accepted exactly once across both racers"
        );
        // (a)/(c) the floor landed exactly on the ladder top, strictly monotone.
        assert_eq!(
            s.export_sender_key_epochs(&CTX),
            vec![(DID.to_owned(), LADDER)]
        );
    }

    // -- SupervisorHandle fan-out accessors forward to the registry -------------

    #[test]
    fn handle_accessors_forward_to_registry() {
        let s = sup();
        let h = SupervisorHandle::wrap(Arc::clone(&s));

        h.seed_context_floors(&CTX);
        assert!(
            h.check_and_advance_sender_epoch(&CTX, DID, 3, MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        assert!(
            h.check_and_advance_recv_sequence(&CTX, DID, rf(3, 1), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        h.validate_and_merge_epoch_floors(
            &CTX,
            vec![(DID.to_owned(), 8)],
            MAX_EPOCH_ADVANCE,
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();
        h.validate_and_merge_recv_sequence_floors(
            &CTX,
            vec![(DID.to_owned(), rf(8, 2))],
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();

        // The handle reads must agree with the direct Supervisor reads.
        assert_eq!(
            h.export_sender_key_epochs(&CTX),
            s.export_sender_key_epochs(&CTX)
        );
        assert_eq!(
            h.export_recv_sequence_floors(&CTX),
            s.export_recv_sequence_floors(&CTX)
        );
        assert_eq!(h.export_sender_key_epochs(&CTX), vec![(DID.to_owned(), 8)]);
        assert_eq!(
            h.export_recv_sequence_floors(&CTX),
            vec![(DID.to_owned(), rf(8, 2))]
        );

        // The remove_member_floors fan-out reaches the registry: pruning DID via
        // the handle drops it from BOTH maps of the direct Supervisor view.
        h.remove_member_floors(&CTX, DID);
        assert!(s.export_sender_key_epochs(&CTX).is_empty());
        assert!(s.export_recv_sequence_floors(&CTX).is_empty());
    }
}
