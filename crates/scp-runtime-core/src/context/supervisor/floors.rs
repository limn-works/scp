//! Supervisor-owned Class-M floor registry (ADR-049 PR-6, epoch + recv side).
//!
//! This module holds the [`ContextFloors`] registry on the [`Supervisor`] plus
//! the TOCTOU-safe advance primitives and the §23.17.2 validating merge that
//! mutate it. The merge/validation path (`validate_and_merge_*`) implements the
//! full §23.17.2 fail-closed Inv-2/Inv-3/Inv-4 + epoch-poisoning-overshoot
//! validating merge.
//!
//! **This registry is the AUTHORITATIVE Class-M home** for the sender-key epoch
//! high-water floors and the receive-side `(epoch, sequence)` anti-replay floors
//! (ADR-049 PR-6 read-authority switch). The provider's former mirrors —
//! `NodeMlsFactory`'s `recv_sequence_tracker` field and its `export_*` /
//! `validate_and_merge_*` twins — are **DELETED**. Production now:
//!
//! - GATES fail-closed on this registry at the live receive seams
//!   (`deliver_incoming`'s recv floor, after the inner envelope verifies,
//!   `decrypt_and_dispatch`'s remote-epoch arm, and the local-rotation
//!   `mirror_forward_local_sender_epoch`), each `check_and_advance_*(..)?`;
//! - SOURCES the durable-blob floors FROM this registry (`export_*`) at every
//!   `export_crypto_state` caller; and
//! - RESTORES the snapshot floors INTO this registry (`validate_and_merge_*`)
//!   via `restore_crypto_state_with_floor_guard`.
//!
//! The node `SenderKeyStore.epochs` map is present-but-unread on the node
//! (retained only for the shared scp-protocol API the browser scp-client still
//! uses, ADR-057).
//!
//! Why it must live on the `Supervisor` (an `Arc<Supervisor>`, not on the actor
//! `PerContextState`): these are **Class-M** floors that MUST survive an actor
//! task unwind. A `PerContextState`-owned floor would die with the crashing
//! actor, re-opening the §23.17 Invariant-2 / Invariant-4 replay window on the
//! respawn. The provider carried them until this switch for exactly this reason;
//! PR-4 stood up this supervisor-owned successor store so PR-7's key-move
//! (`take_crypto_state`) has a Class-M home already in place. This ordering —
//! PR-4 → PR-6 → PR-7 — is the only sound one.

use std::collections::HashMap;

use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ReceiveFloor;
use scp_protocol::crypto::sender_keys::{MAX_EPOCH_ADVANCE, MergePolicy};

use super::supervisor::Supervisor;

scp_runtime_types::pub_under_testing! {
    /// Per-context Class-M floor bundle held by the supervisor registry.
    ///
    /// Bundled (rather than two separate maps) because the receive-side overshoot
    /// ceiling in `Supervisor::check_and_advance_recv_sequence` reads the sender
    /// epoch floor from the SAME entry — one `DashMap` entry guard covers both,
    /// keeping every gate a single acquire (ADR-049 Decision 13).
    ///
    /// No `Zeroize`: these are non-secret monotonic counters (epoch high-water and
    /// `(epoch, sequence)` anti-replay marks), not key material.
    ///
    /// Core-internal; `pub` under `testing` for the runtime crates' tests (ADR-070 §5).
    #[derive(Debug, Default)]
    pub(crate) struct ContextFloors {
        /// `sender_did` → highest sender-key epoch observed for that sender. The
        /// AUTHORITATIVE per-sender epoch high-water for this context (ADR-049 PR-6;
        /// the provider's `SenderKeyStore.epochs` mirror is no longer read on the
        /// node).
        ///
        /// INVARIANT (black-hat F-3): this one map holds BOTH the REMOTE per-sender
        /// distributed-epoch high-water (keyed by each remote sender DID) AND — via
        /// the local-rotation mirror-forward — the LOCAL `sender_key_epoch` scalar
        /// keyed by `local_did`. This coexistence is safe ONLY because `local_did`
        /// never appears as a remote sender in its own recv path, so the receive-side
        /// overshoot ceiling (which reads `sender_epochs[remote_did]`) never reads the
        /// local scalar. This is LOAD-BEARING and enforced at the recv seam:
        /// `decrypt_and_dispatch` rejects an application message whose MLS sender is
        /// `local_did`. A
        /// violation is fail-safe on the SECURITY axis: co-mingling the (typically
        /// higher) local scalar into `sender_epochs[local_did]` would only RAISE the
        /// receive-side epoch CEILING for the local DID — an over-PERMIT on the
        /// ceiling axis, which is harmless because you cannot decrypt at an
        /// un-installed epoch — and NEVER lowers the monotonic anti-replay floor, so
        /// it can never admit a replay or a floor below the live one. The alternative
        /// — splitting the two counters into separate maps — was rejected as
        /// over-engineering (it ripples through merge/export/blob format).
        pub(in crate::context::supervisor) sender_epochs: HashMap<String, u64>,
        /// `sender_did` → highest [`ReceiveFloor`] (`epoch`, `sequence`) accepted
        /// from that sender — the intra-epoch anti-replay floor (spec §23.17.3). The
        /// AUTHORITATIVE receive-side floor (ADR-049 PR-6; the provider's
        /// `recv_sequence_tracker` mirror is deleted). LEXICOGRAPHIC (epoch-major)
        /// order.
        pub(in crate::context::supervisor) recv_sequence: HashMap<String, ReceiveFloor>,
    }
}

/// Rejection reason from a floor-advance gate.
///
/// Fail-closed at the authoritative seams (ADR-049 PR-6): the live receive seams
/// (`deliver_incoming`, `decrypt_and_dispatch`) and the restore/import guard surface these via
/// `check_and_advance_*(..)?` / `validate_and_merge_*(..)` and map them to
/// [`ContextError::CryptoFailed`] through the `From` impl below — a rejection
/// aborts the operation, it is never logged-and-dropped.
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
    /// A receive-side epoch beyond the sender's epoch floor `+ max_advance` —
    /// the authoritative receive-side epoch ceiling (successor to the provider's
    /// deleted H9 `open()` ceiling), reading `sender_epochs[did]` from the SAME
    /// registry entry that the key-distribution seam advances. Because both the
    /// epoch advance and this recv ceiling now read/write the ONE authoritative
    /// registry map, they cannot diverge (ADR-049 PR-6).
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

/// Live receive-gating rejection → context error, WIRED at the ADR-049 PR-6
/// fail-closed seams: `deliver_incoming`'s recv floor, `decrypt_and_dispatch`'s
/// remote-epoch arm, and the
/// local-rotation `mirror_forward_local_sender_epoch` call `check_and_advance_*(..)?`,
/// and the restore/import guard calls `validate_and_merge_all_floors(..)`, all
/// surfacing a [`ContextError`] through this `From`.
///
/// ALL FOUR variants map uniformly to [`ContextError::CryptoFailed`]. This is a
/// deliberate, reviewed choice — not a convenience default:
///
/// - `FloorAdvanceError` is the **live receive-gating** rejection type: a
///   received sender-key epoch or recv `(epoch, sequence)` that fails the
///   monotonicity / overshoot floor at the receive seam. `CryptoFailed` is
///   exactly what the live crypto path (`open()`, MLS decrypt) already returns,
///   so mapping here preserves the existing FFI/SDK-bridged crypto-failure
///   taxonomy — no new canonical code, no bridge-translator change. Concretely,
///   the sender-key rollback/replay case already mapped
///   (`SenderKeyError::EpochNotMonotonic`) to `ContextError::CryptoFailed`;
///   mapping this authoritative registry-gate rejection to anything else would
///   make the seam MORE granular than the crypto-failure taxonomy it joins.
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
        super::admit_sender_epoch(did, current, epoch, max_advance)?;
        // write UNDER the same guard.
        floors.sender_epochs.insert(did.to_owned(), epoch);
        Ok(())
    }

    /// Reads the per-sender **sender-key epoch** floor for `ctx` without
    /// creating an entry; an absent floor reads as `0`, the value
    /// [`Self::check_and_advance_sender_epoch`] reads.
    ///
    /// The `KeyResponse` receive path checks the response's public epoch
    /// against this floor with [`admit_sender_epoch`](super::admit_sender_epoch)
    /// before any custody call, then advances the floor with [`Self::check_and_advance_sender_epoch`]
    /// after the open. The read and the advance are separate, so a floor that
    /// moves between them is caught by the advance, which re-checks under the
    /// entry guard.
    pub(in crate::context) fn sender_epoch_floor(&self, ctx: &[u8; 32], did: &str) -> u64 {
        self.floors
            .get(ctx)
            .and_then(|entry| entry.sender_epochs.get(did).copied())
            .unwrap_or(0)
    }

    /// Atomically check-and-advance the per-sender **receive-sequence** floor for
    /// `ctx`. Receive-side twin of [`Self::check_and_advance_sender_epoch`].
    ///
    /// `next` is compared LEXICOGRAPHICALLY on `(epoch, sequence)`. The overshoot
    /// ceiling reads the sender epoch floor from the SAME entry — the authoritative
    /// receive-side epoch ceiling (successor to the provider's deleted H9 `open()`
    /// ceiling). ADR-049 PR-6: this registry IS the authoritative home, so the
    /// ceiling reads the SAME `sender_epochs` map the key-distribution seam
    /// advances — no provider mirror, no lag, exact by construction.
    ///
    /// # F-2 ordering invariant (key-dist-before-recv)
    ///
    /// A recv at epoch N decrypts only if the epoch-N sender key is installed; the
    /// install happens AFTER that seam's `check_and_advance_sender_epoch` has
    /// advanced `sender_epochs[did]` to N (gate-before-install at
    /// `decrypt_and_dispatch`'s remote-epoch arm). So when this recv ceiling reads
    /// the floor for a decryptable message, the floor is already `>= N` — never
    /// stale, so a legitimate recv is never spuriously rejected by the ceiling.
    ///
    /// Both floors live under one `entry()` guard (ADR-049 Decision 13). Same
    /// TOCTOU-safety and single-writer / security separation as the epoch twin
    /// above apply verbatim: security is the structural single-guard gate,
    /// single-writer is only a liveness convention.
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
    /// ADR-049 PR-6 (read-authority switch): now the AUTHORITATIVE read surface
    /// for the durable-blob export path — the 6 production `export_crypto_state`
    /// callers source the per-sender epoch floors here.
    #[must_use]
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
    /// ADR-049 PR-6 (read-authority switch): now the AUTHORITATIVE read surface
    /// for the durable-blob export path — the 6 production `export_crypto_state`
    /// callers source the per-sender recv-sequence floors here.
    #[must_use]
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
    /// merge — the full §23.17.2 fail-closed validating merge. `policy` selects
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
    /// The epoch-poisoning overshoot ceiling (`local + max_advance`, saturating;
    /// `MAX_EPOCH_ADVANCE = 1000`) is enforced ONLY under
    /// [`MergePolicy::RejectRegression`] (untrusted import). Under
    /// [`MergePolicy::MaxMergeTrustedLocal`] (the node's OWN at-rest snapshot on a
    /// process restart / cold restore) the accumulated high-water loads VERBATIM —
    /// there is no ceiling — because the blob is trusted exactly as much as every
    /// other snapshot field and ADR-049:239 mandates "cold restart loads floors
    /// verbatim" (a context whose true high-water legitimately exceeds
    /// `MAX_EPOCH_ADVANCE` must remain restorable). The ceiling stays the
    /// poisoning guard on the untrusted-import path, and the LIVE per-message gate
    /// [`Self::check_and_advance_sender_epoch`] ALWAYS keeps its ceiling. The
    /// **Inv-4** append-only max-merge apply and the validate-before-apply
    /// atomicity (returning on the FIRST failure BEFORE any mutation) hold under
    /// both policies; the whole two-pass merge runs under one `entry()` guard.
    ///
    /// # Errors
    ///
    /// Returns the single-sender [`FloorAdvanceError`] for the FIRST failing
    /// sender in `incoming` order:
    /// [`FloorAdvanceError::SenderEpochNotMonotonic`] on an Inv-3 regression, or
    /// [`FloorAdvanceError::SenderEpochOvershoot`] on an overshoot (`RejectRegression`
    /// only). Reconciled to `ContextError::CryptoFailed` via the
    /// `From<FloorAdvanceError>` impl at the restore/import seam.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span the whole validating two-pass merge (ADR-049 §23.17.2); early-dropping it breaks the TOCTOU-atomic single-guard invariant"
    )]
    #[allow(
        dead_code,
        reason = "ADR-049 §23.17.2 single-axis validating-merge primitive, unit-tested in isolation; the production restore/import path uses the combined validate_and_merge_all_floors under one guard"
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
            // Epoch-poisoning overshoot ceiling — UNTRUSTED import only. A
            // trusted-local self-snapshot loads its accumulated high-water
            // verbatim (ADR-049:239); the ceiling would otherwise make any
            // context past `MAX_EPOCH_ADVANCE` permanently unrestorable.
            if policy == MergePolicy::RejectRegression {
                let ceiling = local.saturating_add(max_advance);
                if *incoming_epoch > ceiling {
                    return Err(FloorAdvanceError::SenderEpochOvershoot {
                        did: did.clone(),
                        ceiling,
                        proposed: *incoming_epoch,
                    });
                }
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
    /// The epoch-poisoning overshoot ceiling bounds ONLY the EPOCH axis, and ONLY
    /// under [`MergePolicy::RejectRegression`] (untrusted import): an incoming
    /// floor whose `epoch` exceeds the sender's epoch floor
    /// (`sender_epochs[did] + MAX_EPOCH_ADVANCE`, saturating, read from the SAME
    /// entry) is rejected. Under [`MergePolicy::MaxMergeTrustedLocal`] (trusted
    /// self-snapshot / cold restore) the recv floor loads verbatim — no epoch
    /// ceiling — matching the epoch twin and ADR-049:239. The SEQUENCE axis is
    /// DELIBERATELY
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
    /// the epoch floors must be applied BEFORE this recv merge validates. The
    /// production sink [`Self::validate_and_merge_all_floors`] does exactly this
    /// under one guard (it validates recv against the PROJECTED post-apply epoch);
    /// the standalone twin is unit-test only. This is the F-3 co-mingling
    /// invariant: the ceiling reads
    /// `sender_epochs[remote_did]`, and `local_did` never appears as a remote
    /// sender on its own recv path, so the ceiling never reads the local scalar.
    ///
    /// # Errors
    ///
    /// Returns the single-sender [`FloorAdvanceError`] for the FIRST failing
    /// sender in `incoming` order:
    /// [`FloorAdvanceError::RecvSequenceNotMonotonic`] on an Inv-3 regression, or
    /// [`FloorAdvanceError::RecvSequenceOvershoot`] on an epoch overshoot.
    /// Reconciled to `ContextError::CryptoFailed` via the `From<FloorAdvanceError>`
    /// impl at the restore/import seam (NOT `SnapshotFloorRegression` — see the
    /// design note on that impl for why); atomicity holds regardless of
    /// single-vs-batch reporting.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span the whole validating two-pass merge (ADR-049 §23.17.2); early-dropping it breaks the TOCTOU-atomic single-guard invariant"
    )]
    #[allow(
        dead_code,
        reason = "ADR-049 §23.17.2 single-axis validating-merge primitive, unit-tested in isolation; the production restore/import path uses the combined validate_and_merge_all_floors under one guard"
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
            // Epoch-poisoning overshoot ceiling — UNTRUSTED import only, EPOCH axis
            // only. Reads the sender epoch floor from THIS SAME entry (absent read
            // as 0). Skipped under MaxMergeTrustedLocal so a trusted self-snapshot
            // loads verbatim (ADR-049:239). The sequence axis is intentionally
            // unbounded (see fn docs).
            if policy == MergePolicy::RejectRegression {
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

    /// Atomically validate + merge BOTH the per-sender epoch floors AND the
    /// receive-sequence floors for `ctx` under ONE `entry()` guard — the
    /// production restore/import sink.
    ///
    /// Fixes the cross-axis atomicity gap of calling
    /// [`Self::validate_and_merge_epoch_floors`] then
    /// [`Self::validate_and_merge_recv_sequence_floors`] SEQUENTIALLY: each is
    /// internally atomic, but the PAIR is not — if the epoch merge applied and the
    /// recv merge then rejected, the epoch floors would be committed with no
    /// rollback. Here BOTH sets are validated with NO mutation; only if BOTH pass
    /// are BOTH applied. A rejection leaves the WHOLE registry entry UNTOUCHED
    /// (atomic across axes).
    ///
    /// `policy` and the overshoot-ceiling semantics are exactly the two twins':
    /// [`MergePolicy::RejectRegression`] rejects regressions + enforces the
    /// epoch-poisoning ceiling; [`MergePolicy::MaxMergeTrustedLocal`] loads the
    /// trusted self-snapshot VERBATIM (no ceiling, no regression reject —
    /// ADR-049:239, so a context past `MAX_EPOCH_ADVANCE` stays restorable). The
    /// recv floor's epoch-axis ceiling (`RejectRegression` only) reads the PROJECTED
    /// post-apply sender-epoch baseline (`max(local, incoming epoch)`), matching
    /// the sequential twins' epoch-merge-before-recv order, WITHOUT mutating before
    /// both axes validate.
    ///
    /// Empty-guard is on the INCOMING sets, never the live registry, so a COLD
    /// restart (empty live registry + non-empty blob) still RUNS the merge and
    /// populates the registry (D2).
    ///
    /// # Errors
    ///
    /// The FIRST failing [`FloorAdvanceError`] — the epoch set is checked before
    /// the recv set. Reconciled to `ContextError::CryptoFailed` at the seam.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span the whole cross-axis validating merge (ADR-049 §23.17.2); early-dropping it breaks the TOCTOU-atomic single-guard invariant"
    )]
    pub(in crate::context) fn validate_and_merge_all_floors(
        &self,
        ctx: &[u8; 32],
        epochs: Vec<(String, u64)>,
        recv: Vec<(String, ReceiveFloor)>,
        max_advance: u64,
        policy: MergePolicy,
    ) -> Result<(), FloorAdvanceError> {
        // Cold-restart / nothing-to-merge no-op — guarded on the INCOMING sets.
        if epochs.is_empty() && recv.is_empty() {
            return Ok(());
        }

        // Projected post-apply epoch baseline (max-merge of the incoming epochs
        // per did), so the recv epoch-axis ceiling reads the epoch the merge is
        // ABOUT to apply — parity with the sequential epoch-then-recv order —
        // without mutating before both axes validate. Owned keys so it does not
        // borrow `epochs` across the apply-pass move.
        let mut incoming_epoch_max: HashMap<String, u64> = HashMap::new();
        for (did, epoch) in &epochs {
            incoming_epoch_max
                .entry(did.clone())
                .and_modify(|cur| *cur = (*cur).max(*epoch))
                .or_insert(*epoch);
        }

        // THE single guard. All validation + apply runs under it.
        let mut entry = self.floors.entry(*ctx).or_default();
        let floors = entry.value_mut();

        // Pass 1: validate the EPOCH set (no mutation).
        for (did, incoming_epoch) in &epochs {
            let local = floors.sender_epochs.get(did).copied().unwrap_or(0);
            if policy == MergePolicy::RejectRegression && *incoming_epoch < local {
                return Err(FloorAdvanceError::SenderEpochNotMonotonic {
                    did: did.clone(),
                    current: local,
                    proposed: *incoming_epoch,
                });
            }
            if policy == MergePolicy::RejectRegression {
                let ceiling = local.saturating_add(max_advance);
                if *incoming_epoch > ceiling {
                    return Err(FloorAdvanceError::SenderEpochOvershoot {
                        did: did.clone(),
                        ceiling,
                        proposed: *incoming_epoch,
                    });
                }
            }
        }

        // Pass 2: validate the RECV set (no mutation) against the PROJECTED epoch.
        for (did, incoming_floor) in &recv {
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
            if policy == MergePolicy::RejectRegression {
                let local_epoch = floors.sender_epochs.get(did).copied().unwrap_or(0);
                let projected_epoch =
                    local_epoch.max(incoming_epoch_max.get(did).copied().unwrap_or(0));
                let ceiling = projected_epoch.saturating_add(MAX_EPOCH_ADVANCE);
                if incoming_floor.epoch > ceiling {
                    return Err(FloorAdvanceError::RecvSequenceOvershoot {
                        did: did.clone(),
                        ceiling,
                        proposed: incoming_floor.epoch,
                    });
                }
            }
        }

        // Both axes validated — apply BOTH (Inv-4 append-only max-merge).
        for (did, incoming_epoch) in epochs {
            floors
                .sender_epochs
                .entry(did)
                .and_modify(|cur| *cur = (*cur).max(incoming_epoch))
                .or_insert(incoming_epoch);
        }
        for (did, incoming_floor) in recv {
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
    /// ADR-049 §5 — called on the context-creation path so the registry entry
    /// exists from creation (it then grows via the fail-closed advance seams).
    /// **INSERT-IF-ABSENT only** (`entry().or_default()`), NEVER an unconditional
    /// `insert`: because this registry is AUTHORITATIVE, a late / racing
    /// create-seed must never reset an already-advanced entry (that would rewind
    /// a live anti-replay floor). [cryptographer hardening]
    pub(in crate::context) fn seed_context_floors(&self, ctx: &[u8; 32]) {
        // Insert-if-absent; the returned guard is dropped immediately. Does NOT
        // overwrite an existing (possibly already-advanced) entry.
        self.floors.entry(*ctx).or_default();
    }

    /// Permanent-teardown prune: drop the whole [`ContextFloors`] entry for
    /// `ctx` (ADR-049).
    ///
    /// The provider drops its per-context crypto state inside `destroy_mls_group`
    /// (`self.contexts.remove` in `crypto/mls/provider.rs`); this AUTHORITATIVE
    /// registry needs its own prune, so without this every permanently-torn-down
    /// context would leak a `ContextFloors` entry (and its unbounded per-sender
    /// maps). Called from EVERY genuine permanent-teardown site (explicit
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
    /// respawn / restore, where `restore_crypto_state_with_floor_guard` leaves
    /// THIS registry untouched and merges the snapshot blob back into it instead
    /// of dropping it). Callers must only invoke this when the context is
    /// permanently gone
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
    /// # Deliberate divergence from the provider's D3 whole-membership sweep
    ///
    /// The deleted provider `remove_member_sender_key` performed, in addition to
    /// the member-granular prune, a DEFENSIVE whole-membership sweep — it
    /// `retain`ed only recv-tracker entries whose DID was still in
    /// `member_wrapping_keys`, catching floors re-populated by an in-flight
    /// message from an already-removed member. This registry has NO membership
    /// equivalent and deliberately does NOT reconstruct one (orchestrator
    /// decision, ADR-049 PR-6): (a) the divergence is FAIL-SAFE — a lingering
    /// floor for a member removed out-of-band can only OVER-reject that DID's
    /// traffic (a liveness dent), NEVER admit a replay or a floor below the live
    /// one; (b) reconstructing a membership sweep would re-couple the Class-M
    /// registry to the membership set, violating the isolation that is the whole
    /// point of the read-authority switch. The member-granular prune below is
    /// the exact, sufficient replacement, driven from every removal seam.
    pub(in crate::context) fn remove_member_floors(&self, ctx: &[u8; 32], did: &str) {
        if let Some(mut entry) = self.floors.get_mut(ctx) {
            let floors = entry.value_mut();
            floors.sender_epochs.remove(did);
            floors.recv_sequence.remove(did);
        }
    }
}

/// Test-only reach into fields that stay private to this crate. Compiled only
/// under `testing`, so no production or bridge build reaches them (ADR-070 §4).
#[cfg(any(test, feature = "testing"))]
impl ContextFloors {
    /// The registry's per-sender epoch floors.
    #[must_use]
    pub const fn sender_epochs_for_test(&self) -> &HashMap<String, u64> {
        &self.sender_epochs
    }

    /// The registry's per-sender receive floors.
    #[must_use]
    pub const fn recv_sequence_for_test(&self) -> &HashMap<String, ReceiveFloor> {
        &self.recv_sequence
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {

    use super::{ContextError, FloorAdvanceError, ReceiveFloor};

    const DID: &str = "did:dht:z6MkFloorSenderFloorSenderFloorSenderAA";

    /// Terse [`ReceiveFloor`] constructor for the recv-sequence tests.
    const fn rf(epoch: u64, sequence: u64) -> ReceiveFloor {
        ReceiveFloor { epoch, sequence }
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
}
