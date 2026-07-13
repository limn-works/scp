//! Supervisor-owned Class-M floor registry (ADR-049 PR-4, epoch side).
//!
//! This module adds the [`ContextFloors`] registry to the [`Supervisor`] and
//! the TOCTOU-safe advance primitives that mutate it. In PR-4 the registry is a
//! **NON-AUTHORITATIVE FOLLOWER**: the authoritative homes for the per-sender
//! epoch high-water and the receive-side `(epoch, sequence)` anti-replay floor
//! remain the supervisor-owned `MlsCryptoProvider` (`crypto/mls/provider.rs` —
//! `SenderKeyStore.epochs` and `recv_sequence_tracker`). Enforcement, capture,
//! and merge all still run there. Nothing in PR-4 READS `Supervisor.floors` for
//! any enforcement, capture, or merge decision; the registry is **write-only**
//! until PR-6 flips read-authority onto it (see `.claude/plans` PR-6 scope /
//! `actor/deps.rs` §"`MlsCryptoProvider` dissolution", ADR-049 Decision 9).
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
    /// `sender_did` → highest `(epoch, sequence)` accepted from that sender —
    /// the intra-epoch anti-replay floor (spec §23.17.3). LEXICOGRAPHIC order.
    /// Mirrors the provider's `recv_sequence_tracker`.
    pub(in crate::context::supervisor) recv_sequence: HashMap<String, (u64, u64)>,
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
        current: (u64, u64),
        /// The rejected proposed `(epoch, sequence)`.
        proposed: (u64, u64),
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
        next: (u64, u64),
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
        if next.0 > ceiling {
            return Err(FloorAdvanceError::RecvSequenceOvershoot {
                did: did.to_owned(),
                ceiling,
                proposed: next.0,
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
    ) -> Vec<(String, (u64, u64))> {
        self.floors.get(ctx).map_or_else(Vec::new, |entry| {
            entry
                .value()
                .recv_sequence
                .iter()
                .map(|(did, floor)| (did.clone(), *floor))
                .collect()
        })
    }

    /// Merge `incoming` per-sender epoch floors into the registry for `ctx`.
    ///
    /// PR-4 **follower** semantics: a monotone max-merge — for each incoming
    /// `(did, floor)`, the registry keeps `max(existing, floor)` (insert-if-
    /// absent). It never regresses a registry floor and never rejects, because
    /// the AUTHORITATIVE regression / overshoot validation runs on the provider
    /// in PR-4 (this seed only mirrors the provider's already-validated result).
    /// `max_advance` and `trusted_local` are plumbed through for the PR-6
    /// read-authority switch, which makes this the authoritative, fail-closed
    /// merge (see PR-6 scope note); they are intentionally unused in the PR-4
    /// follower body. The whole merge runs under one `entry()` guard.
    ///
    /// # Errors
    ///
    /// Infallible in PR-4 (returns `Ok`); the `Result` matches the provider twin
    /// so PR-6 can retarget callers without a PARAM-LIST change. Parity is only
    /// PARTIAL, though: the provider twin returns `Result<(), ContextError>`
    /// while this returns `Result<(), FloorAdvanceError>`, so the PR-6 retarget
    /// is param-list-churn-free but MUST still reconcile the error type (unify
    /// `FloorAdvanceError` / `ContextError`).
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span the whole monotone max-merge (ADR-049 PR-4); early-dropping it breaks the single-guard invariant"
    )]
    #[allow(
        clippy::unnecessary_wraps,
        unused_variables,
        reason = "signature parity with provider::validate_and_merge_epoch_floors — max_advance/trusted_local + the fallible Result are exercised by the PR-6 fail-closed validating merge; the PR-4 follower is infallible monotone-max"
    )]
    pub(in crate::context) fn validate_and_merge_epoch_floors(
        &self,
        ctx: &[u8; 32],
        incoming: Vec<(String, u64)>,
        max_advance: u64,
        trusted_local: bool,
    ) -> Result<(), FloorAdvanceError> {
        // PR-4 follower: `max_advance` / `trusted_local` are reserved for the
        // PR-6 fail-closed switch.
        if incoming.is_empty() {
            return Ok(());
        }
        let mut entry = self.floors.entry(*ctx).or_default();
        let floors = entry.value_mut();
        for (did, floor) in incoming {
            floors
                .sender_epochs
                .entry(did)
                .and_modify(|cur| *cur = (*cur).max(floor))
                .or_insert(floor);
        }
        Ok(())
    }

    /// Merge `incoming` per-sender receive-sequence floors into the registry for
    /// `ctx`. Receive-side twin of [`Self::validate_and_merge_epoch_floors`] with
    /// the same PR-4 follower (monotone max-merge, lexicographic on
    /// `(epoch, sequence)`) semantics and the same PR-6 deferral.
    ///
    /// # Errors
    ///
    /// Infallible in PR-4 (returns `Ok`); the `Result` matches the provider twin
    /// in PARAM-LIST only — same PARTIAL parity as
    /// [`Self::validate_and_merge_epoch_floors`]: the provider twin returns
    /// `Result<(), ContextError>` while this returns `Result<(), FloorAdvanceError>`,
    /// so PR-6's retarget must still reconcile the error type.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the single DashMap entry guard MUST span the whole monotone max-merge (ADR-049 PR-4); early-dropping it breaks the single-guard invariant"
    )]
    #[allow(
        clippy::unnecessary_wraps,
        unused_variables,
        reason = "signature parity with provider::validate_and_merge_recv_sequence_floors — trusted_local + the fallible Result are exercised by the PR-6 fail-closed validating merge; the PR-4 follower is infallible monotone-max"
    )]
    pub(in crate::context) fn validate_and_merge_recv_sequence_floors(
        &self,
        ctx: &[u8; 32],
        incoming: Vec<(String, (u64, u64))>,
        trusted_local: bool,
    ) -> Result<(), FloorAdvanceError> {
        // PR-4 follower: `trusted_local` is reserved for the PR-6 fail-closed
        // switch.
        if incoming.is_empty() {
            return Ok(());
        }
        let mut entry = self.floors.entry(*ctx).or_default();
        let floors = entry.value_mut();
        for (did, floor) in incoming {
            floors
                .recv_sequence
                .entry(did)
                .and_modify(|cur| *cur = (*cur).max(floor))
                .or_insert(floor);
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE;

    use super::{FloorAdvanceError, Supervisor};
    use crate::context::supervisor::handle::SupervisorHandle;

    const CTX: [u8; 32] = [0xA5u8; 32];
    const DID: &str = "did:dht:z6MkFloorSenderFloorSenderFloorSenderAA";

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
            s.check_and_advance_recv_sequence(&CTX, DID, (0, 3), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // Same (epoch, seq) is a replay — rejected.
        assert!(matches!(
            s.check_and_advance_recv_sequence(&CTX, DID, (0, 3), MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
        ));
        // Lower sequence at the same epoch — rejected.
        assert!(matches!(
            s.check_and_advance_recv_sequence(&CTX, DID, (0, 2), MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
        ));
        // Higher sequence at the same epoch — accepted.
        assert!(
            s.check_and_advance_recv_sequence(&CTX, DID, (0, 4), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // Advance to a higher epoch — accepted (epoch 1 is within the ceiling
        // `sender_epoch_floor(0) + MAX_EPOCH_ADVANCE`).
        assert!(
            s.check_and_advance_recv_sequence(&CTX, DID, (1, 0), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        // Lower epoch, even with a much higher seq — rejected (lexicographic on
        // the `(epoch, seq)` pair: `(0, 99) < (1, 0)`).
        assert!(matches!(
            s.check_and_advance_recv_sequence(&CTX, DID, (0, 99), MAX_EPOCH_ADVANCE),
            Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
        ));
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![(DID.to_owned(), (1, 0))]
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
                (5 + MAX_EPOCH_ADVANCE + 1, 0),
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
                (5 + MAX_EPOCH_ADVANCE, 0),
                MAX_EPOCH_ADVANCE
            )
            .is_ok()
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
            true,
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
            vec![(DID.to_owned(), (2, 9)), (DID.to_owned(), (1, 0))],
            true,
        )
        .unwrap();
        assert_eq!(
            s.export_recv_sequence_floors(&CTX),
            vec![(DID.to_owned(), (2, 9))]
        );
        // empty merge is a no-op that does not error.
        assert!(
            s.validate_and_merge_epoch_floors(&CTX, vec![], MAX_EPOCH_ADVANCE, false)
                .is_ok()
        );
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
        s.check_and_advance_recv_sequence(&CTX, DID, (1, 1), MAX_EPOCH_ADVANCE)
            .unwrap();
        assert_eq!(s.floors.len(), 1, "recv gate reuses the same ctx entry");
        // Both floors live under that single entry.
        let entry = s.floors.get(&CTX).expect("ctx entry");
        assert_eq!(entry.sender_epochs.get(DID).copied(), Some(1));
        assert_eq!(entry.recv_sequence.get(DID).copied(), Some((1, 1)));
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
            h.check_and_advance_recv_sequence(&CTX, DID, (3, 1), MAX_EPOCH_ADVANCE)
                .is_ok()
        );
        h.validate_and_merge_epoch_floors(&CTX, vec![(DID.to_owned(), 8)], MAX_EPOCH_ADVANCE, true)
            .unwrap();
        h.validate_and_merge_recv_sequence_floors(&CTX, vec![(DID.to_owned(), (8, 2))], true)
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
            vec![(DID.to_owned(), (8, 2))]
        );
    }
}
