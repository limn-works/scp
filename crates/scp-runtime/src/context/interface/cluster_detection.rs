//! Cluster-detection rolling window + population-weighted quadratic
//! interface-spam fee.
//!
//! Spec §6.2.0.1 round 6, ADR-049 round-6 §"Cluster detection 4th
//! predicate + population-weighted floor", SCP-OUT-042d.
//!
//! # Spec mapping
//!
//! Outlet-interface establishment is an economic action with an
//! anonymity-set interaction: every additional active A↔X interface that
//! Context A holds narrows the anonymity set under which `hop_salt`
//! pseudonyms from A appear. To deter interface-spam as an
//! anonymity-set-reduction attack, the cost a context pays to establish
//! its `n`-th active interface scales **quadratically** in the count of
//! active prior interfaces within a 24-hour rolling window — and the
//! count itself is computed against four cluster-detection predicates
//! that resist creator/admin/capability-holder DID rotation evasions.
//!
//! ```text
//! interface_cost = max(base_cost, interface_base_cost_floor(ctx)) × (k + 1)²
//!
//! interface_base_cost_floor(ctx) =
//!     max(
//!         currency_atomic_unit(ctx.currency),
//!         ceil(log2(ctx.member_count + 1)) × ContextParams::base_cost_scale,
//!     )
//! ```
//!
//! where `k` is the cluster-match count over the rolling window. A prior
//! `InterfaceEstablished` event contributes to `k` whenever ANY of these
//! four predicates holds between the prior peer `P_i` and the candidate
//! peer `B`:
//!
//! 1. **Context-id match.** `P_i.context_id == B.context_id`. Direct
//!    re-negotiation with the same peer.
//! 2. **Creator-DID match.** `P_i.creator_did == B.creator_did`.
//!    `creator_did` is fixed at peer-context creation and cannot be
//!    rotated out — closes the "rotate admin to spin up disjoint contexts"
//!    evasion.
//! 3. **Admin-set intersection.** `P_i.admin_set ∩ B.admin_set ≠ ∅`. Closes
//!    the "new DID creates a context and invites the same admin cluster"
//!    evasion.
//! 4. **Capability-holder-set intersection.** `P_i.capability_holder_set ∩
//!    B.capability_holder_set ≠ ∅`. Closes the round-6 "rotate creator
//!    AND admin DIDs but keep a stable cross-context invoker DID"
//!    evasion (the natural attack profile, since the attacker IS the
//!    cross-context invoker).
//!
//! See `.docs/specs/06-cross-context-communication.md` §6.2.0.1
//! "Interface-spam deterrent (quadratic cost, cluster-aware)" for the
//! full text and `.docs/specs/09-security-model.md` §9.18.B for the
//! `ContextParams::base_cost_scale` registration.

use std::collections::HashSet;

use scp_identity::DID;
use scp_protocol::context::outlets::interface::{ContextId, InterfaceEstablished};
use scp_protocol::context::roles::Capability;
use scp_protocol::economy::{Amount, CurrencyCode, currency_atomic_unit};

// ---------------------------------------------------------------------------
// Rolling window constant
// ---------------------------------------------------------------------------

/// Width of the §6.2.0.1 cluster-detection rolling window: 24 hours in
/// milliseconds.
///
/// Callers pass `now` and `event.established_at` (both unix-millis) and
/// filter the window before invoking [`compute_cluster_match_count`].
pub const CLUSTER_DETECTION_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;

// ---------------------------------------------------------------------------
// InterfaceCandidate
// ---------------------------------------------------------------------------

/// A peer context evaluated as a candidate for an interface acceptance,
/// carrying the four cluster-detection inputs read by §6.2.0.1's
/// rolling-window predicates.
///
/// Compared against every `InterfaceEstablished` event in the local
/// 24-hour rolling window. See [`compute_cluster_match_count`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCandidate {
    /// Candidate peer context's id (predicate 1 input).
    pub context_id: ContextId,
    /// Candidate peer context's `creator_did` (predicate 2 input). Fixed
    /// at peer creation per §5.4 lifecycle.
    pub creator_did: DID,
    /// Candidate peer context's admin set at the proposed
    /// interface-acceptance time (predicate 3 input).
    pub admin_set: Vec<DID>,
    /// Candidate peer context's capability-holder set at the proposed
    /// interface-acceptance time (predicate 4 input). Includes every DID
    /// holding ANY of `outlet:offer:*` (i.e., [`Capability::OutletInterface`]),
    /// `outlet:query:*` (parameterised or `OutletQueryAll`), or
    /// `outlet:call:*` (parameterised or `OutletCallAll`).
    pub capability_holder_set: Vec<DID>,
}

// ---------------------------------------------------------------------------
// compute_cluster_match_count
// ---------------------------------------------------------------------------

/// Counts §6.2.0.1 round-6 cluster matches between `candidate` and every
/// prior interface in `rolling_window_events`.
///
/// `rolling_window_events` MUST be pre-filtered to the 24-hour rolling
/// window (`now - established_at <= CLUSTER_DETECTION_WINDOW_MS`). The
/// caller does the filtering because rolling-window state is held by the
/// runtime's event-log adapter, not by this pure function.
///
/// Returns the cluster-match count `k` saturated at `u32::MAX` — a
/// realistic context cannot accumulate >`u32::MAX` interfaces in a
/// 24-hour window, but the saturation makes overflow impossible.
///
/// # Algorithm
///
/// For each prior `P_i`, increments `k` by 1 if ANY of the four
/// predicates holds (predicate union — never double-counts a single
/// prior even when multiple predicates match).
#[must_use]
pub fn compute_cluster_match_count(
    rolling_window_events: &[InterfaceEstablished],
    candidate: &InterfaceCandidate,
) -> u32 {
    // The candidate's admin / capability-holder sets are converted to
    // hash sets once so the O(N×M) per-prior intersection check
    // collapses to O(N + M_total) overall — N priors, M_total summed
    // peer-DID counts. Cloning here is cheap (DID is a thin String
    // wrapper) and avoids re-hashing per prior.
    let candidate_admin: HashSet<&DID> = candidate.admin_set.iter().collect();
    let candidate_caps: HashSet<&DID> = candidate.capability_holder_set.iter().collect();

    let mut k: u32 = 0;
    for prior in rolling_window_events {
        if matches_any_predicate(prior, candidate, &candidate_admin, &candidate_caps) {
            // Saturate at u32::MAX so degenerate test inputs cannot
            // overflow the counter.
            k = k.saturating_add(1);
        }
    }
    k
}

/// Predicate-union check for a single prior interface. Returns `true`
/// when ANY of the four §6.2.0.1 round-6 predicates matches.
fn matches_any_predicate(
    prior: &InterfaceEstablished,
    candidate: &InterfaceCandidate,
    candidate_admin: &HashSet<&DID>,
    candidate_caps: &HashSet<&DID>,
) -> bool {
    // Predicate 1 — context-id match. The prior's peer is its source
    // context (the offerer); the local side is always the target. We
    // therefore compare the prior's `source_context` against the
    // candidate's `context_id`.
    if prior.source_context == candidate.context_id {
        return true;
    }
    // Predicate 2 — creator-DID match.
    if prior.creator_did == candidate.creator_did {
        return true;
    }
    // Predicate 3 — admin-set intersection. Walk the smaller side.
    // `prior.admin_set` is typically small (single-digit admin counts),
    // so iterate it against the pre-built candidate hash set.
    if prior.admin_set.iter().any(|d| candidate_admin.contains(d)) {
        return true;
    }
    // Predicate 4 — capability-holder-set intersection. Same shape as
    // predicate 3.
    if prior
        .capability_holder_set
        .iter()
        .any(|d| candidate_caps.contains(d))
    {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// interface_base_cost_floor
// ---------------------------------------------------------------------------

/// Computes the §6.2.0.1 round-6 population-weighted interface-spam
/// floor for a context with the given currency, member count, and
/// `ContextParams::base_cost_scale`.
///
/// ```text
/// interface_base_cost_floor =
///     max(currency_atomic_unit(currency),
///         ceil(log2(member_count + 1)) × base_cost_scale)
/// ```
///
/// Larger contexts pay a proportionally larger floor on their first
/// same-cluster interface, closing the round-6 MAJOR-5
/// cluster-detection bypass residual-risk where a small-N sybil could
/// pay only the constant currency-atomic-unit fee.
///
/// # Floor semantics
///
/// - `member_count == 0` is treated as `member_count == 1` for the
///   logarithm so the floor stays at `1 × base_cost_scale` (a freshly
///   created single-admin context). The `ceil(log2(2)) = 1` lower bound
///   still applies.
/// - When `base_cost_scale == 0` (the operator-declared scale fell below
///   the atomic unit), the floor degenerates to
///   `currency_atomic_unit(currency)` — strictly `> 0`. This closes the
///   "trivial `base_cost = 0` bypass" disclosed in §6.2.0.1.
/// - Multiplication overflow saturates to `Amount(u64::MAX)` so an
///   arithmetic edge case can never silently zero-out the floor.
///
/// The saturation sentinel is `Amount(u64::MAX)` — see [`Amount`].
#[must_use]
pub fn interface_base_cost_floor(
    currency: CurrencyCode,
    member_count: u32,
    base_cost_scale: Amount,
) -> Amount {
    let atomic = currency_atomic_unit(currency);

    // ceil(log2(member_count + 1)). 32 - leading_zeros gives ceil(log2)
    // for n >= 1 because we evaluate it on (member_count + 1). We
    // saturate the +1 step at u32::MAX so a hypothetical
    // member_count == u32::MAX still produces a finite log.
    let n_plus_one = member_count.saturating_add(1).max(2); // floor at 2 → log >= 1
    let log_ceil: u32 = 32 - (n_plus_one - 1).leading_zeros();

    // Population-weighted contribution: log_ceil × base_cost_scale.
    // Saturating multiplication means a degenerate log_ceil × scale
    // overflow can only land at the maximum representable amount —
    // never zero — so the floor never silently collapses.
    let weighted = base_cost_scale
        .checked_mul(u64::from(log_ceil))
        .unwrap_or(AMOUNT_MAX);

    // Outer max — the absolute atomic-unit lower bound dominates when
    // operator-supplied base_cost_scale falls below it.
    if atomic.value() > weighted.value() {
        atomic
    } else {
        weighted
    }
}

// ---------------------------------------------------------------------------
// compute_interface_fee
// ---------------------------------------------------------------------------

/// Computes the §6.2.0.1 round-6 quadratic interface-spam fee:
///
/// ```text
/// fee = max(base_cost, interface_base_cost_floor(ctx)) × (k + 1)²
/// ```
///
/// Inputs:
///
/// - `base_cost` — the context's economic-policy `base_cost` (§19.3).
/// - `currency`, `member_count`, `base_cost_scale` — feed
///   [`interface_base_cost_floor`].
/// - `k` — cluster-match count from [`compute_cluster_match_count`].
///
/// Multiplication overflow saturates to `Amount(u64::MAX)`: at `k = 0` the
/// fee is `1²` (no escalation), at `k = 4` it is `25 ×`, at `k = 9` it
/// is `100 ×`, etc. The escalator quickly dominates any finite
/// `base_cost`, so spam is economically irrational long before overflow
/// becomes relevant.
#[must_use]
pub fn compute_interface_fee(
    base_cost: Amount,
    currency: CurrencyCode,
    member_count: u32,
    base_cost_scale: Amount,
    k: u32,
) -> Amount {
    let floor = interface_base_cost_floor(currency, member_count, base_cost_scale);
    let unit_cost = if base_cost.value() > floor.value() {
        base_cost
    } else {
        floor
    };

    // (k + 1)² as a u64. `k` is u32, so `k + 1` fits in u64 trivially;
    // squaring stays within u64 for any k <= 2^32 - 1, but we still
    // saturate-multiply to be defensive against the edge.
    let k_plus_one: u64 = u64::from(k).saturating_add(1);
    let factor: u64 = k_plus_one.saturating_mul(k_plus_one);

    unit_cost.checked_mul(factor).unwrap_or(AMOUNT_MAX)
}

// ---------------------------------------------------------------------------
// Capability-holder enumeration
// ---------------------------------------------------------------------------

/// Returns `true` when `cap` is one of the §6.2.0.1 round-6 cluster
/// predicate-4 capabilities.
///
/// A capability matches when, held by a DID in the peer context at
/// interface-acceptance time, it places that DID into the
/// `capability_holder_set`. The spec text lists
/// `{outlet:offer:*, outlet:query:*, outlet:call:*}`. In the protocol's
/// `Capability` taxonomy these correspond to:
///
/// - `outlet:offer:*` — [`Capability::OutletInterface`] (the
///   cross-context outlet exposure capability — see §6.2.0.1 step 1
///   "validates that `outlet:interface` is in its ceiling").
/// - `outlet:query:*` — [`Capability::OutletQueryAll`] OR any
///   parameterised `Capability::OutletQuery(_)`.
/// - `outlet:call:*` — [`Capability::OutletCallAll`] OR any
///   parameterised `Capability::OutletCall(_)`.
#[must_use]
pub const fn is_outlet_interface_capability(cap: &Capability) -> bool {
    matches!(
        cap,
        Capability::OutletInterface
            | Capability::OutletQueryAll
            | Capability::OutletQuery(_)
            | Capability::OutletCallAll
            | Capability::OutletCall(_)
    )
}

/// Enumerates DIDs holding ANY of the §6.2.0.1 round-6 predicate-4
/// capabilities.
///
/// Returns a deterministic lexicographically-sorted vector ready for
/// placement into [`InterfaceEstablished::capability_holder_set`]. The
/// lexicographic sort closes the `MessagePack`/`serde_json` round-trip
/// determinism invariant declared on the `capability_holder_set` field.
#[must_use]
pub fn enumerate_capability_holders<'a, I>(did_to_caps: I) -> Vec<DID>
where
    I: IntoIterator<Item = (&'a DID, &'a HashSet<Capability>)>,
{
    let mut holders: Vec<DID> = did_to_caps
        .into_iter()
        .filter_map(|(did, caps)| {
            if caps.iter().any(is_outlet_interface_capability) {
                Some(did.clone())
            } else {
                None
            }
        })
        .collect();
    // Sort by DID string for deterministic on-wire bytes.
    holders.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    holders.dedup();
    holders
}

// ---------------------------------------------------------------------------
// Induced-rotations validator (RemoveMember-admin governance gate)
// ---------------------------------------------------------------------------

/// Validates the §6.2.0.1 atomic-removal+rotation invariant on a
/// proposed `RemoveMember`-admin governance action.
///
/// When active interfaces exist, the action MUST carry a non-empty
/// `induced_rotations` vector. Empty rotations + active interfaces is a
/// governance-action validation failure (ADR-049 round-6 §"Admin-removal
/// rotation TOCTOU closure", spec §6.2.0.1 "Rotation is unconditional").
///
/// The state-machine that emits the rotations lives in OUT-042c — but
/// the validator check belongs in this story for cohesion with the
/// quadratic-fee validator (both run in the interface-governance path).
///
/// # Errors
///
/// Returns [`InducedRotationsError::MissingForActiveInterfaces`] when the
/// rotation vector is empty AND `active_interface_ids` is non-empty.
///
/// Returns [`InducedRotationsError::CountMismatch`] when the rotation
/// vector size does not equal the active-interface count — a
/// `RemoveMember`-admin commit MUST cover every active interface
/// exactly once (no coverage gaps, no duplicates) per §6.2.0.1
/// "Atomic removal+rotation — local-side semantics".
pub fn validate_remove_member_induced_rotations(
    induced_rotation_interface_ids: &[[u8; 32]],
    active_interface_ids: &[[u8; 32]],
) -> Result<(), InducedRotationsError> {
    if active_interface_ids.is_empty() {
        // No active interfaces — nothing to rotate. An empty
        // `induced_rotations` is the only valid value here.
        if !induced_rotation_interface_ids.is_empty() {
            return Err(InducedRotationsError::SpuriousRotation {
                rotation_count: induced_rotation_interface_ids.len(),
            });
        }
        return Ok(());
    }

    if induced_rotation_interface_ids.is_empty() {
        return Err(InducedRotationsError::MissingForActiveInterfaces {
            active_interface_count: active_interface_ids.len(),
        });
    }

    if induced_rotation_interface_ids.len() != active_interface_ids.len() {
        return Err(InducedRotationsError::CountMismatch {
            expected: active_interface_ids.len(),
            got: induced_rotation_interface_ids.len(),
        });
    }

    // Same length — verify the sets are exactly equal. Sort copies and
    // compare. The local active-interface list is held in the
    // governance state and is small (single-digit to low-double-digit),
    // so the O(N log N) sort-and-compare is trivial.
    let mut sorted_rot = induced_rotation_interface_ids.to_vec();
    sorted_rot.sort_unstable();
    let mut sorted_active = active_interface_ids.to_vec();
    sorted_active.sort_unstable();
    if sorted_rot != sorted_active {
        return Err(InducedRotationsError::CoverageMismatch);
    }

    Ok(())
}

/// Failure modes for [`validate_remove_member_induced_rotations`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InducedRotationsError {
    /// An admin-removing `RemoveMember` lacked any `InterfaceSaltRotated`
    /// entries when active interfaces exist. Governance-action
    /// validation failure per §6.2.0.1 "Rotation is unconditional".
    #[error(
        "RemoveMember-admin missing induced rotations: {active_interface_count} active interfaces require rotations"
    )]
    MissingForActiveInterfaces {
        /// Number of active interfaces that needed coverage.
        active_interface_count: usize,
    },
    /// Rotation count does not equal active-interface count.
    #[error("RemoveMember-admin induced-rotation count mismatch: expected {expected}, got {got}")]
    CountMismatch {
        /// Expected rotation count (= active interface count).
        expected: usize,
        /// Actual rotation count supplied.
        got: usize,
    },
    /// Same count but the rotation set does not exactly cover the
    /// active-interface set.
    #[error("RemoveMember-admin induced rotations cover the wrong interface set")]
    CoverageMismatch,
    /// Rotations supplied with no active interfaces — would be a covert
    /// rotation channel per §6.2.0.1 "Verifier rule — signature, trigger, and epoch".
    #[error(
        "RemoveMember-admin supplied {rotation_count} rotation(s) but no interfaces are active"
    )]
    SpuriousRotation {
        /// Rotation count supplied.
        rotation_count: usize,
    },
}

// ---------------------------------------------------------------------------
// AMOUNT_MAX — saturation sentinel
// ---------------------------------------------------------------------------

/// All-ones [`Amount`] (`u64::MAX`), used as the saturation sentinel for
/// the §6.2.0.1 fee-arithmetic overflow paths.
///
/// Kept module-private so the `Amount` API surface in `scp-protocol`
/// does not need to widen for this one consumer.
const AMOUNT_MAX: Amount = Amount(u64::MAX);

// ---------------------------------------------------------------------------
// Tests — adversarial coverage for SCP-OUT-042d ACs
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
    clippy::type_complexity,
    clippy::cast_possible_truncation
)]
mod tests {
    use std::collections::HashSet;

    use scp_protocol::context::outlets::OutletId;

    use super::*;

    // ----- Helpers ---------------------------------------------------------

    fn did(s: &str) -> DID {
        DID::from(s.to_owned())
    }

    fn ctx(s: &str) -> ContextId {
        s.to_owned()
    }

    fn outlet_id(s: &str) -> OutletId {
        s.to_owned()
    }

    fn usd() -> CurrencyCode {
        CurrencyCode::from("USD")
    }

    /// Builds an `InterfaceEstablished` populated only with the
    /// cluster-detection inputs the tests exercise. Other fields take
    /// deterministic dummy values; signatures and IKMs are zeroed
    /// because no signature verification runs in this test scope —
    /// `compute_cluster_match_count` reads only the four cluster
    /// fields plus `source_context`.
    fn established(
        idx: u8,
        source_context: &str,
        creator: &str,
        admin_set: &[&str],
        cap_set: &[&str],
    ) -> InterfaceEstablished {
        InterfaceEstablished {
            interface_id: [idx; 32],
            source_context: ctx(source_context),
            target_context: ctx("ctx-local"),
            outlet_id: outlet_id("outlet-x"),
            established_at: 1_700_000_000_000,
            epoch_a: 1,
            epoch_b: 1,
            ikm_a: [0u8; 32],
            ikm_a_sig: vec![0u8; 64],
            ikm_b: [0u8; 32],
            ikm_b_sig: vec![0u8; 64],
            creator_did: did(creator),
            admin_set: admin_set.iter().map(|s| did(s)).collect(),
            capability_holder_set: cap_set.iter().map(|s| did(s)).collect(),
        }
    }

    fn candidate(
        context_id: &str,
        creator: &str,
        admin_set: &[&str],
        cap_set: &[&str],
    ) -> InterfaceCandidate {
        InterfaceCandidate {
            context_id: ctx(context_id),
            creator_did: did(creator),
            admin_set: admin_set.iter().map(|s| did(s)).collect(),
            capability_holder_set: cap_set.iter().map(|s| did(s)).collect(),
        }
    }

    // ----- AC 6 — quadratic factor at k=0 and k=4 --------------------------

    /// AC 6 — 0 priors yields fee = max(base, floor) × 1²; 4 priors
    /// matching ANY predicate yields fee = max(base, floor) × 5² = 25×.
    #[test]
    fn fee_at_zero_and_four_priors() {
        let scale = Amount::new(100); // currency-meaningful for USD-cents
        let base_cost = Amount::new(50); // below floor → floor wins
        let cur = usd();
        let members = 1u32; // 1-member context → log_ceil = 1

        let cand = candidate(
            "ctx-B",
            "did:peer-creator",
            &["did:admin-1"],
            &["did:cap-1"],
        );

        // 0 priors → fee = floor × 1
        let k0 = compute_cluster_match_count(&[], &cand);
        assert_eq!(k0, 0);
        let fee0 = compute_interface_fee(base_cost, cur, members, scale, k0);
        let floor = interface_base_cost_floor(cur, members, scale);
        assert_eq!(fee0, floor); // base 50 < floor 100 → floor wins; (0+1)² = 1

        // 4 priors → all match by context_id → k = 4 → fee = floor × 25
        let priors = vec![
            established(1, "ctx-B", "x1", &["other-admin"], &["other-cap"]),
            established(2, "ctx-B", "x2", &["other-admin"], &["other-cap"]),
            established(3, "ctx-B", "x3", &["other-admin"], &["other-cap"]),
            established(4, "ctx-B", "x4", &["other-admin"], &["other-cap"]),
        ];
        let k4 = compute_cluster_match_count(&priors, &cand);
        assert_eq!(k4, 4);
        let fee4 = compute_interface_fee(base_cost, cur, members, scale, k4);
        assert_eq!(fee4, Amount::new(floor.value() * 25));
    }

    // ----- AC 7 — predicate 4 (capability-holder) closure ------------------

    /// AC 7 — attacker rotates `creator_did` AND `admin_set` per peer
    /// context but reuses a stable long-lived non-admin DID holding
    /// `outlet:offer:*` — predicate 4 catches this for every prior.
    #[test]
    fn predicate_four_catches_capability_holder_evasion() {
        // Attacker reuses `did:invoker-stable` across all 5 peer contexts
        // even though every other field rotates.
        let priors = vec![
            established(
                1,
                "ctx-peer-1",
                "did:creator-1",
                &["did:admin-r1"],
                &["did:invoker-stable", "did:other-1"],
            ),
            established(
                2,
                "ctx-peer-2",
                "did:creator-2",
                &["did:admin-r2"],
                &["did:invoker-stable", "did:other-2"],
            ),
            established(
                3,
                "ctx-peer-3",
                "did:creator-3",
                &["did:admin-r3"],
                &["did:invoker-stable", "did:other-3"],
            ),
            established(
                4,
                "ctx-peer-4",
                "did:creator-4",
                &["did:admin-r4"],
                &["did:invoker-stable", "did:other-4"],
            ),
            established(
                5,
                "ctx-peer-5",
                "did:creator-5",
                &["did:admin-r5"],
                &["did:invoker-stable", "did:other-5"],
            ),
        ];

        // Candidate context — fresh in every dimension EXCEPT it still
        // contains `did:invoker-stable` in its capability holder set.
        let cand = candidate(
            "ctx-peer-6",
            "did:creator-6",
            &["did:admin-r6"],
            &["did:invoker-stable", "did:other-6"],
        );

        let k = compute_cluster_match_count(&priors, &cand);
        assert_eq!(
            k, 5,
            "predicate 4 must catch every prior whose cap-holder set shares did:invoker-stable"
        );
    }

    // ----- AC 8 — population-weighted floor --------------------------------

    /// AC 8 — population scaling. Member counts of 1 / 10 / 100 / 500
    /// produce log_ceil values of 1 / 4 / 7 / 9.
    #[test]
    fn population_weighted_floor_scales_logarithmically() {
        let scale = Amount::new(1_000); // 10 USD-cents per log step
        let cur = usd();

        // 1 member  → ceil(log2(2))   = 1 → 1 × scale
        let f1 = interface_base_cost_floor(cur, 1, scale);
        assert_eq!(f1, Amount::new(1_000));

        // 10 members → ceil(log2(11))  = 4 → 4 × scale
        let f10 = interface_base_cost_floor(cur, 10, scale);
        assert_eq!(f10, Amount::new(4_000));

        // 100 members → ceil(log2(101)) = 7 → 7 × scale
        let f100 = interface_base_cost_floor(cur, 100, scale);
        assert_eq!(f100, Amount::new(7_000));

        // 500 members → ceil(log2(501)) = 9 → 9 × scale
        let f500 = interface_base_cost_floor(cur, 500, scale);
        assert_eq!(f500, Amount::new(9_000));
    }

    // ----- AC 9 — currency_atomic_unit lower bound -------------------------

    /// AC 9 — `base_cost_scale = 0` falls back to
    /// `currency_atomic_unit`, NOT zero. Closes the trivial
    /// `base_cost = 0` bypass.
    #[test]
    fn currency_atomic_unit_lower_bound_when_scale_is_zero() {
        let cur = usd();
        let f = interface_base_cost_floor(cur, 100, Amount::new(0));
        assert_eq!(f, currency_atomic_unit(cur));
        assert_eq!(f, Amount::new(1));

        // And the fee at k=0 with base_cost=0 STILL produces a non-zero
        // amount — the (k+1)² escalator multiplied against the floor.
        let fee = compute_interface_fee(Amount::new(0), cur, 100, Amount::new(0), 0);
        assert_eq!(fee, Amount::new(1));
        assert!(fee.value() > 0, "atomic unit must keep fee > 0");
    }

    // ----- AC 10 — predicate 2 (creator_did) closure -----------------------

    /// AC 10 — peer with matching `creator_did` counts toward k even
    /// when admin_set differs.
    #[test]
    fn creator_did_predicate_catches_admin_rotation() {
        let priors = vec![
            // Different context_id, different admin_set, but matching creator.
            established(
                1,
                "ctx-old-peer",
                "did:shared-creator",
                &["did:admin-old"],
                &["did:cap-old"],
            ),
        ];

        let cand = candidate(
            "ctx-fresh-peer",     // different
            "did:shared-creator", // same creator
            &["did:admin-fresh"], // different admin
            &["did:cap-fresh"],   // different cap holder
        );

        let k = compute_cluster_match_count(&priors, &cand);
        assert_eq!(k, 1, "predicate 2 must catch matching creator_did");
    }

    // ----- AC 11 — 10 disjoint contexts share 1 admin DID ------------------

    /// AC 11 — 10 disjoint peer contexts share a single admin DID with
    /// A's prior peer; predicate 3 must count all 10 → k = 10 → fee
    /// = floor × 11² = 121 × floor.
    #[test]
    fn ten_disjoint_contexts_sharing_admin_count_via_predicate_three() {
        let mut priors = Vec::with_capacity(10);
        for i in 0u8..10 {
            priors.push(established(
                i + 1,
                &format!("ctx-prior-{}", i),
                &format!("did:creator-prior-{}", i),
                &["did:shared-admin", &format!("did:other-{}", i)],
                &[&format!("did:cap-{}", i)],
            ));
        }

        // Candidate context — totally fresh in every other dimension
        // EXCEPT it contains `did:shared-admin`.
        let cand = candidate(
            "ctx-cand",
            "did:creator-cand",
            &["did:shared-admin", "did:other-cand"],
            &["did:cap-cand"],
        );

        let k = compute_cluster_match_count(&priors, &cand);
        assert_eq!(
            k, 10,
            "predicate 3 must catch every disjoint peer sharing a single admin DID"
        );

        // Fee = max(base, floor) × (10+1)² = floor × 121
        let scale = Amount::new(100);
        let cur = usd();
        let members = 5u32;
        let floor = interface_base_cost_floor(cur, members, scale);
        let fee = compute_interface_fee(Amount::new(0), cur, members, scale, k);
        assert_eq!(fee, Amount::new(floor.value() * 121));
    }

    // ----- AC 13 — capability-holder enumeration determinism ---------------

    /// AC 13 — `enumerate_capability_holders` returns a sorted vector
    /// of DIDs holding ANY of the round-6 predicate-4 capabilities.
    #[test]
    fn enumerate_capability_holders_sorts_and_filters() {
        let mut by_did: Vec<(DID, HashSet<Capability>)> = vec![
            // Holds OutletInterface = "outlet:offer:*"
            (
                did("did:zeta"),
                HashSet::from([Capability::OutletInterface]),
            ),
            // Holds OutletQueryAll = "outlet:query:*"
            (
                did("did:alpha"),
                HashSet::from([Capability::OutletQueryAll]),
            ),
            // Holds parameterised OutletCall = "outlet:call:foo"
            (
                did("did:mike"),
                HashSet::from([Capability::OutletCall(outlet_id("foo"))]),
            ),
            // Holds NEITHER predicate-4 capability — must be filtered out
            (
                did("did:no-relevant"),
                HashSet::from([Capability::MessagesRead]),
            ),
        ];
        // Mutate one entry in place to confirm we don't depend on sort order
        by_did.sort_by(|a, b| b.0.as_ref().cmp(a.0.as_ref()));

        let holders = enumerate_capability_holders(by_did.iter().map(|(d, c)| (d, c)));
        assert_eq!(
            holders,
            vec![did("did:alpha"), did("did:mike"), did("did:zeta")]
        );
    }

    /// `is_outlet_interface_capability` covers every relevant variant.
    #[test]
    fn predicate_four_capability_match_is_complete() {
        assert!(is_outlet_interface_capability(&Capability::OutletInterface));
        assert!(is_outlet_interface_capability(&Capability::OutletQueryAll));
        assert!(is_outlet_interface_capability(&Capability::OutletQuery(
            outlet_id("x")
        )));
        assert!(is_outlet_interface_capability(&Capability::OutletCallAll));
        assert!(is_outlet_interface_capability(&Capability::OutletCall(
            outlet_id("x")
        )));

        // Counterexamples — none of these belong to predicate 4.
        assert!(!is_outlet_interface_capability(&Capability::MessagesRead));
        assert!(!is_outlet_interface_capability(&Capability::OutletRegister));
        assert!(!is_outlet_interface_capability(&Capability::MemberInvite));
    }

    // ----- AC 14 — RemoveMember-admin induced-rotations validator ---------

    /// AC 14 — empty `induced_rotations` with active interfaces must
    /// fail validation. The validator lives here for cohesion with the
    /// quadratic-fee path.
    #[test]
    fn remove_member_with_active_interfaces_requires_rotations() {
        let active = vec![[0xAA; 32], [0xBB; 32]];
        let err = validate_remove_member_induced_rotations(&[], &active)
            .expect_err("empty rotations + active interfaces must reject");
        match err {
            InducedRotationsError::MissingForActiveInterfaces {
                active_interface_count,
            } => {
                assert_eq!(active_interface_count, 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// Validator accepts non-empty rotations whose ids exactly match
    /// the active-interface set.
    #[test]
    fn remove_member_with_matching_rotations_is_valid() {
        let active = vec![[0xAA; 32], [0xBB; 32]];
        let rotations = vec![[0xBB; 32], [0xAA; 32]]; // any order
        validate_remove_member_induced_rotations(&rotations, &active)
            .expect("matching-set rotations must validate");
    }

    /// Validator rejects coverage-mismatch (same length, wrong set).
    #[test]
    fn remove_member_rejects_coverage_mismatch() {
        let active = vec![[0xAA; 32], [0xBB; 32]];
        let rotations = vec![[0xAA; 32], [0xCC; 32]]; // CC isn't active
        let err = validate_remove_member_induced_rotations(&rotations, &active)
            .expect_err("coverage mismatch must reject");
        assert_eq!(err, InducedRotationsError::CoverageMismatch);
    }

    /// Validator rejects spurious rotations when no interfaces are
    /// active — closes the covert-rotation-channel surface.
    #[test]
    fn remove_member_rejects_spurious_rotation() {
        let err = validate_remove_member_induced_rotations(&[[0xAA; 32]], &[])
            .expect_err("spurious rotation must reject");
        assert_eq!(
            err,
            InducedRotationsError::SpuriousRotation { rotation_count: 1 }
        );
    }

    /// Validator accepts no-rotations + no-active-interfaces.
    #[test]
    fn remove_member_with_no_active_and_no_rotations_is_valid() {
        validate_remove_member_induced_rotations(&[], &[]).expect("trivially valid");
    }

    /// Validator surfaces count mismatch when rotation count != active
    /// count.
    #[test]
    fn remove_member_rejects_count_mismatch() {
        let active = vec![[0xAA; 32], [0xBB; 32]];
        let rotations = vec![[0xAA; 32]];
        let err = validate_remove_member_induced_rotations(&rotations, &active)
            .expect_err("count mismatch must reject");
        assert_eq!(
            err,
            InducedRotationsError::CountMismatch {
                expected: 2,
                got: 1,
            }
        );
    }

    // ----- Round-trip / overflow regression --------------------------------

    /// Population scaling at the upper MLS bound (`u32::MAX`) does not
    /// overflow.
    #[test]
    fn population_floor_at_u32_max_does_not_overflow() {
        let f = interface_base_cost_floor(usd(), u32::MAX, Amount::new(1));
        // ceil(log2(u32::MAX + 1, saturated)) = 32
        assert_eq!(f, Amount::new(32));
    }

    /// Quadratic factor at the upper saturating-edge does not silently
    /// zero.
    #[test]
    fn fee_saturates_to_amount_max_on_overflow() {
        let huge_base = Amount::new(u64::MAX / 4);
        let fee = compute_interface_fee(huge_base, usd(), 1, Amount::new(1), 1_000);
        // (1000+1)² × (u64::MAX/4) overflows; saturate to u64::MAX.
        assert_eq!(fee, AMOUNT_MAX);
    }

    /// Multiple predicates matching the same prior contribute exactly
    /// 1 to k (predicate union, not predicate sum).
    #[test]
    fn predicate_union_does_not_double_count() {
        // This prior matches predicates 1, 2, AND 3 simultaneously.
        let priors = vec![established(
            1,
            "ctx-cand", // match predicate 1
            "did:c",    // match predicate 2
            &["did:a"], // match predicate 3
            &["did:cap-novel"],
        )];

        let cand = candidate(
            "ctx-cand",
            "did:c",
            &["did:a", "did:other-admin"],
            &["did:cap-cand"],
        );

        let k = compute_cluster_match_count(&priors, &cand);
        assert_eq!(k, 1, "single prior must contribute 1, not 3");
    }
}
