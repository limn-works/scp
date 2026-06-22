//! `ClassSCell` — the fail-closed-persist combinator wrapper around
//! [`PerContextState`] (ADR-049 §9 Class S).
//!
//! # Why this exists
//!
//! ADR-049 §9 defines a **Class-S persistence invariant**: a Class-S field of
//! [`PerContextState`] (spending-nonce consume, executed-proposals,
//! downward-authorization transitions, saga reservation slots) must be persisted
//! **fail-closed** after any mutation — a mutation is NEVER acknowledged to a
//! caller unless it is durable, because a coalesced (best-effort) acknowledgment
//! would let an actor crash roll the mutation back and re-open a replay /
//! re-spend / re-grant window the caller already observed as closed.
//!
//! Today that invariant is enforced by a source-text scanner
//! (`scripts/check-class-s-fail-closed.sh`) which pattern-matches handler bodies
//! for "mutate then persist_fail_closed." A source-text scanner is structurally
//! non-convergent: every new way to alias a `&mut PerContextState`
//! (extern-fn, `&mut`-alias, ref-mut-destructure, autoref-method) is a fresh
//! evasion, and the gate must grow a new pattern to catch each one. The goal of
//! the refactor this file is part of is to make the invariant a **compile error**
//! to violate, retiring the scanner.
//!
//! # The mechanism
//!
//! [`ClassSCell`] owns the [`PerContextState`] and exposes:
//!
//! - **Reads** via [`Deref`] — `&*cell` / `cell.<field>` yields `&PerContextState`.
//!   There is deliberately **no [`DerefMut`]**: you cannot obtain a
//!   `&mut PerContextState` by writing `&mut cell.<field>` or `*cell = …`. That is
//!   the compile-time hook — a future migration step privatizes the fields so the
//!   ONLY way to mutate Class-S state is through the combinators below, each of
//!   which performs the fail-closed persist by construction.
//! - **Mutation through a combinator** — every combinator hands `f` a *view*
//!   ([`ClassSMut`] for the Class-S-capable combinators, [`ClassCMut`] for the
//!   Class-C best-effort combinator) rather than the bare `&mut PerContextState`.
//!   The view chooses which slice of the state `f` can reach `&mut`. The
//!   Class-S-capable combinators ([`commit_class_s_keep`](ClassSCell::commit_class_s_keep),
//!   [`commit_class_s_restore`](ClassSCell::commit_class_s_restore),
//!   [`commit_class_s_compensating`](ClassSCell::commit_class_s_compensating),
//!   [`commit_class_s_keep_compensating`](ClassSCell::commit_class_s_keep_compensating),
//!   [`commit_class_s_then_append`](ClassSCell::commit_class_s_then_append))
//!   perform the fail-closed persist;
//!   [`commit_class_c_best_effort`](ClassSCell::commit_class_c_best_effort)
//!   performs the best-effort persist (Class C).
//!
//! # View-typed combinators (this PR)
//!
//! The combinators no longer take a caller-supplied `R: FnOnce(&mut …)` rollback
//! closure. Instead the rollback strategy is encoded in the combinator NAME and
//! implemented against the PR2a [`ClassSState`] / [`GovernanceClassS`] mirror
//! (their `snapshot` / `restore` methods) — so the combinator, not the caller,
//! owns the (correct, total) undo of the Class-S sub-structs. This removes the
//! foot-gun where a caller could write a rollback that undoes the wrong field.
//!
//! - `*_keep` — persist fail-closed; on persist failure the in-memory mutation
//!   STAYS (fail-closed direction: e.g. recording an accepted replay nonce that
//!   must not be un-recorded).
//! - `*_restore` — snapshot the Class-S sub-structs before `f`; on persist
//!   failure restore them (rolling the mutation back), then return the error.
//! - `*_compensating` — like `*_restore`, but after the in-state restore it runs
//!   an async compensation for an EXTERNAL effect the mutation produced
//!   (e.g. void an escrow).
//! - `*_keep_compensating` — KEEP-direction for Class-S (like `*_keep`, the
//!   Class-S mutation is NOT restored on persist failure), but run an async
//!   `on_persist_failure` to undo the Class-C / external effects the failed
//!   persist did not make durable. For sites that consume a security-critical
//!   replay nonce (keep-S) while charging an in-memory Class-C reservation that
//!   must be reversed when the reservation does not durably land. The undo is
//!   the CALLER's hook (the combinator's snapshot covers only Class-S, which is
//!   intentionally NOT restored here), and it receives a [`ClassCMut`] so it
//!   cannot re-touch Class-S.
//!
//! ## The [`ClassCMut`] view is airtight BY CONSTRUCTION
//!
//! The best-effort combinator and the compensation closures run with NO
//! subsequent fail-closed persist, so a Class-S mutation made through their view
//! would escape the §9 invariant. [`ClassCMut`] (and its governance sub-view
//! [`GovernanceClassCMut`]) close this by exposing NO `&mut` to any
//! Class-S-CONTAINING struct — no `&mut PerContextState`, `&mut GovernanceState`,
//! `&mut ClassSState`, or `&mut GovernanceClassS`. Every `&mut` accessor returns
//! a specifically-Class-C field; governance is reached only field-granularly.
//! With no `&mut` PATH to Class-S, a Class-S mutation on the
//! best-effort/compensation path is a COMPILE error. This does NOT rely on field
//! privatization — and could not: the combinator module and the handler modules
//! are co-descendants of `context::actor`, so no `pub(in PATH)` visibility
//! separates them (a handler could always name `class_s` through a whole-struct
//! `&mut` if one were handed out). Field privatization (a later step) concerns
//! only the [`ClassSCell::state_mut`] escape hatch and [`ClassSMut`]'s
//! `pub(crate)` reach, NOT this view, which is already airtight.
//! - `*_then_append` — persist fail-closed AFTER `f`, then run an async `after`
//!   step that appends a derived record to an EXTERNAL durable sink (the event
//!   log adapter on [`ActorDeps`]); if `after` fails, restore the snapshot and
//!   RE-PERSIST, returning [`AppendOutcomeError`] so the caller learns whether
//!   durable state may diverge from the returned in-memory state. `after`
//!   receives a READ-ONLY `&PerContextState` (it reads the just-persisted state
//!   to build the record) and CANNOT mutate Class-S — see the method docs.
//!
//! # Combinator coverage & migration scope
//!
//! These six combinators are deliberately the set for the **common** Class-S
//! persist/rollback shapes, not an exhaustive cover of every call site. The
//! Class-S-capable five span the *keep / restore* × *no-Class-C-undo /
//! Class-C-(or-external)-undo* grid — `*_keep` (keep, no undo), `*_restore`
//! (restore, no undo), `*_keep_compensating` (keep, undo C/external),
//! `*_compensating` (restore, undo C/external) — plus `*_then_append` for the
//! one extra shape of a fail-closed persist FOLLOWED BY an external durable
//! append (event-log) that can itself fail; `commit_class_c_best_effort` covers
//! the Class-C best-effort path. They are chosen because they are the shapes
//! that recur; they are NOT proof that every site fits one of them.
//!
//! A site whose shape falls OUTSIDE this set is handled when **that site
//! migrates** (during the handler migration, where its exact crash/atomicity
//! semantics are known), not pre-covered speculatively here. Two known
//! outliers, recorded so a future migrator does not mistake the gap for an
//! oversight:
//!
//! - **Intra-Class-S keep-one-field / restore-another split.** A single site
//!   can KEEP one Class-S field while RESTORING another on persist failure
//!   (e.g. `prepare_b` records the `xctx_nonce_dedup` entry — keep-direction,
//!   un-recording re-opens the replay window — while staging `saga_pending`,
//!   which must roll back if the persist does not land). The combinators'
//!   snapshot/restore is all-or-nothing over the Class-S sub-structs, so no
//!   single combinator expresses this. It is migrated by DECOMPOSING the site
//!   into a sequential `commit_class_s_keep` then `commit_class_s_restore` (two
//!   fail-closed persists — the migration must verify the intermediate-crash
//!   state between them is recoverable), or by introducing a site-specific
//!   field-granular combinator if decomposition is not sound for that site.
//! - **Append-then-persist of UNCHANGED state.** A site that appends a record
//!   to an external sink and then persists *without mutating Class-S* (e.g.
//!   `emit_divergence_marker`) is not a Class-S mutation site at all and needs
//!   no combinator — it routes through the ordinary persist path.
//!
//! The [`ClassSCell::state_mut`] escape hatch is what bridges every site that
//! has not yet migrated: a site still on `state_mut` is EXPECTED during the
//! migration, not a defect. `state_mut` is deleted in the terminal migration
//! step, once every Class-S mutation routes through a combinator (or a
//! site-specific one added along the way); at that point — with the Class-S
//! fields privatized and no `DerefMut` — the compiler, not this prose,
//! enforces that every Class-S mutation is fail-closed-persisted.
//!
//! # Behaviour-neutral scaffolding
//!
//! No handler is migrated to these combinators yet (handlers still mutate through
//! the temporary [`ClassSCell::state_mut`] escape hatch + nested field paths), so
//! the combinators are `#[allow(dead_code)]` and exercised only by this module's
//! unit tests. The source-text gate is UNCHANGED and still passes — the view
//! `*_mut()` accessors return `&mut` to the sub-structs and carry no Class-S
//! mutation MARKER tokens, and the combinators take closures (any marker appears
//! in the caller's closure, where the later migration will route it through the
//! persist-on-commit boundary). The escape hatch and these allows are removed in
//! the final migration step.

use std::collections::{HashMap, HashSet};
use std::ops::Deref;

use super::deps::ActorDeps;
use super::state::{ClassSState, PerContextState};
use crate::context::messaging_helpers::{persist_state_best_effort, persist_state_fail_closed};
use crate::context::state::{GovernanceClassS, GovernanceState};
use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::membership::{MembershipState, ReceiveBuffer};
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::economy::budget::MemberBudgetTracker;
use scp_protocol::economy::types::EconomicPolicy;

/// Mutable view over a [`PerContextState`] that EXPOSES the Class-S sub-structs.
///
/// Handed to the Class-S-capable combinators
/// ([`ClassSCell::commit_class_s_keep`] / `_restore` / `_compensating` /
/// `_then_append`). Through it `f` can reach `&mut` to the actor's Class-S
/// sub-structs ([`ClassSState`] via [`Self::class_s_mut`],
/// [`GovernanceClassS`] via [`Self::governance_class_s_mut`]) as well as the
/// rest of [`PerContextState`] (reads via [`Deref`], targeted `&mut` via the
/// explicit accessors). The combinator that hands out the view owns the
/// fail-closed persist, so any Class-S mutation `f` makes through this view is
/// persisted (or rolled back) by construction.
///
/// # Token extension point (PR3)
///
/// A later PR threads a `ClassSCommitToken` through this view (issued by the
/// combinator, consumed by the privatized Class-S mutators) so that the ONLY way
/// to call a Class-S mutator is from inside a combinator that performs the
/// persist. The token field is intentionally NOT added yet — this view keeps the
/// same shape so the migration is additive. See the module docs.
pub(crate) struct ClassSMut<'a> {
    /// The borrowed actor state. Private so the only mutable reach into Class-S
    /// is through [`Self::class_s_mut`] / [`Self::governance_class_s_mut`].
    state: &'a mut PerContextState,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: the view accessors (`class_s_mut`, `governance_class_s_mut`, `rest_mut`) get their first PRODUCTION callers when handlers migrate onto the combinators. Exercised by this module's unit tests now."
)]
impl<'a> ClassSMut<'a> {
    /// Wrap a borrowed [`PerContextState`]. Crate-internal: only the combinators
    /// construct a view.
    const fn new(state: &'a mut PerContextState) -> Self {
        Self { state }
    }

    /// `&mut` access to the actor's Class-S sub-struct ([`ClassSState`]):
    /// `saga_pending`, the B-owned `xctx_nonce_dedup`, and the three
    /// committed/reservation witnesses (ADR-049 §9). Mutating these is the
    /// fail-closed-persisted Class-S transition the owning combinator guards.
    pub(crate) const fn class_s_mut(&mut self) -> &mut ClassSState {
        &mut self.state.class_s
    }

    /// `&mut` access to the governance Class-S sub-struct ([`GovernanceClassS`]):
    /// `executed_proposals`, `threshold_signers`, `threshold_value`, and the
    /// `spending_nonce_tracker` (ADR-049 §9). Reached through the `governance`
    /// field; the owning combinator persists fail-closed.
    pub(crate) const fn governance_class_s_mut(&mut self) -> &mut GovernanceClassS {
        &mut self.state.governance.class_s
    }

    /// `&mut` access to the rest of [`PerContextState`] (the NON-Class-S
    /// portion). The Class-S sub-structs are still reachable through this bare
    /// `&mut` while their fields stay `pub(crate)` this PR — the field-privatizing
    /// PR is what makes [`Self::class_s_mut`] / [`Self::governance_class_s_mut`]
    /// the *only* path. Until then this accessor exists so a migrated handler can
    /// mutate the structural / Class-C portion of the state from inside a Class-S
    /// combinator without a second borrow.
    ///
    /// # Naming note — why `rest_mut` exists HERE but NOT on [`ClassCMut`]
    ///
    /// This (Class-S-capable) view may hand out a whole `&mut PerContextState`
    /// because its bound combinator persists **fail-closed**: any Class-S field
    /// reachable through that `&mut` (e.g. `state.class_s`, `state.governance.class_s`)
    /// is covered by the fail-closed persist the combinator performs, so the §9
    /// invariant holds even though the `&mut` can in principle reach Class-S.
    ///
    /// [`ClassCMut`] — handed to the BEST-EFFORT combinator and to the
    /// compensation closures, which run with NO subsequent fail-closed persist —
    /// **may NOT** hand out such a `&mut`, and therefore has NO `rest_mut` (and no
    /// `governance_mut`) at all. It is field-granular: every accessor returns a
    /// `&mut` to a specifically-Class-C field (or a [`GovernanceClassCMut`]
    /// sub-view), so there is no `&mut` PATH from it to any Class-S-containing
    /// struct — a Class-S mutation on the best-effort/compensation path is a
    /// COMPILE error by construction, independent of any future field
    /// privatization. The asymmetry is the whole point: the view that persists
    /// fail-closed may reach Class-S; the view that does not, structurally cannot.
    pub(crate) const fn rest_mut(&mut self) -> &mut PerContextState {
        self.state
    }
}

impl Deref for ClassSMut<'_> {
    type Target = PerContextState;

    /// Immutable reads of the whole state.
    fn deref(&self) -> &PerContextState {
        self.state
    }
}

/// RESTRICTED mutable view over a [`PerContextState`] that exposes ONLY the
/// Class-C / structural portion — there is **no** `class_s_mut` /
/// `governance_class_s_mut`, and (deliberately) **no** `rest_mut` /
/// `governance_mut` either.
///
/// Handed to [`ClassSCell::commit_class_c_best_effort`] (Class-C, best-effort
/// persist) and to the async compensation closures of
/// [`ClassSCell::commit_class_s_compensating`] /
/// [`ClassSCell::commit_class_s_keep_compensating`] — all of which run with NO
/// subsequent fail-closed persist (best-effort, or the persist-FAILURE arm). So
/// a Class-S mutation made through this view would NOT be fail-closed-persisted,
/// re-opening the replay / re-spend / re-grant window the §9 invariant closes.
///
/// # Airtight BY CONSTRUCTION (not by field privatization)
///
/// The combinator module (`context::actor::class_s`) and the handler modules
/// (`context::actor::handlers::*`) are co-descendants of `context::actor`; no
/// `pub(in PATH)` visibility separates them, so field privatization CANNOT make
/// the Class-S fields unnameable from a handler — a handler could always write
/// `view.rest_mut().class_s…` or `view.governance_mut().class_s…` if those
/// accessors existed. Therefore this view exposes NO `&mut` to any
/// Class-S-CONTAINING struct: not `&mut PerContextState`, not
/// `&mut GovernanceState`, not `&mut ClassSState`, not `&mut GovernanceClassS`.
/// Every `&mut` accessor returns a specifically-Class-C field, and governance is
/// reached only through the field-granular [`GovernanceClassCMut`] sub-view
/// (which likewise exposes no `&mut self.gov` whole and no `class_s` accessor).
/// With no `&mut` PATH to a Class-S-containing struct, a Class-S mutation from
/// this view is a COMPILE error — independent of any future field privatization
/// (which concerns only the `state_mut` escape hatch and [`ClassSMut`]'s
/// `pub(crate)` reach, NOT this view). Reads via [`Deref`] are still whole-state
/// (reads don't mutate, so they cannot violate the invariant).
///
/// # Disjoint-borrow support (`ConsequenceStateSplit`)
///
/// [`crate::context::governance_logic::ConsequenceStateSplit`] needs FIVE
/// simultaneous disjoint borrows of distinct [`PerContextState`] fields
/// (`governance`, `&mut role_state`, `&membership`, `&mut receive_buffer`,
/// `&mut checkpoint_events_since`). A single `&mut PerContextState` cannot be
/// reborrowed five ways through method calls (each `&mut self` method borrows the
/// WHOLE state), so [`Self::split_class_c`] destructures the underlying `&mut`
/// ONCE into independent field references the borrow checker accepts in parallel
/// (with the governance reference wrapped in a [`GovernanceClassCMut`] so it,
/// too, cannot reach Class-S).
pub(crate) struct ClassCMut<'a> {
    /// The borrowed actor state. Private; mutated only through the field-granular
    /// accessors / [`Self::split_class_c`], none of which reach Class-S.
    state: &'a mut PerContextState,
}

/// RESTRICTED mutable view over a [`GovernanceState`] that exposes ONLY its
/// Class-C governance fields — there is **no** accessor returning
/// `&mut GovernanceState` (the whole bucket) and **no** accessor reaching
/// `governance.class_s` ([`GovernanceClassS`]).
///
/// Produced by [`ClassCMut::governance_class_c_mut`] and held by the
/// `governance` field of [`ClassCSplit`]. It is the governance counterpart of
/// [`ClassCMut`]'s airtightness: because the best-effort / compensation paths do
/// not persist fail-closed, they must not reach any Class-S-containing struct,
/// and `GovernanceState` CONTAINS one (`governance.class_s`). Handing out
/// `&mut GovernanceState` would let a handler write `gov.class_s.threshold_value
/// = …` with no fail-closed persist; this view never does. Reads of the whole
/// governance bucket go through [`Deref`] (reads cannot violate §9); the only
/// `&mut` it grants is to individual Class-C governance fields.
#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: the Class-C governance field accessors (`velocity_tracker_mut`, `budget_tracker_mut`, `cooldown_until_mut`, `economic_policy_mut`) get their first PRODUCTION callers at the `ConsequenceStateSplit` / economy-compensation migration. Exercised by this module's unit tests now."
)]
pub(crate) struct GovernanceClassCMut<'a> {
    /// The borrowed governance bucket. Private so the ONLY mutable reach is
    /// through the field-granular Class-C accessors — never a whole
    /// `&mut self.gov` and never `&mut self.gov.class_s`.
    gov: &'a mut GovernanceState,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: the Class-C governance field accessors (`velocity_tracker_mut`, `budget_tracker_mut`, `cooldown_until_mut`, `economic_policy_mut`) get their first PRODUCTION callers at the `ConsequenceStateSplit` / economy-compensation migration. Exercised by this module's unit tests now."
)]
impl<'a> GovernanceClassCMut<'a> {
    /// Wrap a borrowed [`GovernanceState`]. Crate-internal: constructed only by
    /// [`ClassCMut`] (directly or via [`ClassCMut::split_class_c`]).
    const fn new(gov: &'a mut GovernanceState) -> Self {
        Self { gov }
    }

    /// `&mut` access to the per-sender velocity tracker (§19.7 anti-spam /
    /// consequence evaluation). Class-C: a coalesce-window rollback of a velocity
    /// tick is acceptable.
    pub(crate) const fn velocity_tracker_mut(
        &mut self,
    ) -> &mut scp_protocol::economy::antispam::SenderVelocityTracker {
        &mut self.gov.velocity_tracker
    }

    /// `&mut` access to the per-member cumulative budget tracker (§19.5). Class-C:
    /// the consequence/economy reservation it records is reversed by the
    /// compensation hook when a persist does not land.
    pub(crate) const fn budget_tracker_mut(&mut self) -> &mut MemberBudgetTracker {
        &mut self.gov.budget_tracker
    }

    /// `&mut` access to the consequence-rule cooldown map (`rule_index` → Unix
    /// seconds until re-fire is allowed). Class-C structural liveness state.
    pub(crate) const fn cooldown_until_mut(&mut self) -> &mut HashMap<usize, u64> {
        &mut self.gov.cooldown_until
    }

    /// `&mut` access to the mutable economic policy (§19.3). Class-C governance
    /// configuration.
    pub(crate) const fn economic_policy_mut(&mut self) -> &mut Option<EconomicPolicy> {
        &mut self.gov.economic_policy
    }
}

impl Deref for GovernanceClassCMut<'_> {
    type Target = GovernanceState;

    /// Immutable reads of the whole governance bucket (reads cannot violate the
    /// §9 fail-closed invariant).
    fn deref(&self) -> &GovernanceState {
        self.gov
    }
}

/// Independent disjoint `&mut`/`&` borrows of the Class-C / structural fields of
/// a [`PerContextState`], produced by [`ClassCMut::split_class_c`].
///
/// Each field is borrowed from a DISTINCT field of the underlying state, so the
/// borrow checker accepts holding all of them at once — this is exactly the
/// shape [`crate::context::governance_logic::ConsequenceStateSplit`] needs. The
/// migration of `ConsequenceStateSplit` onto this is a LATER PR; this struct
/// only makes the view CAPABLE of producing the borrows.
#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: constructed by `ClassCMut::split_class_c`, whose first PRODUCTION caller is the `ConsequenceStateSplit` migration. Exercised by this module's unit test now."
)]
pub(crate) struct ClassCSplit<'a> {
    /// Field-granular Class-C governance view. NOT a `&mut GovernanceState`:
    /// `GovernanceState` contains the Class-S sub-struct `class_s`, and the
    /// consequence/best-effort path does not persist fail-closed, so it must have
    /// no `&mut` path to it. [`GovernanceClassCMut`] exposes only the Class-C
    /// governance fields and reads via [`Deref`] — airtight by construction.
    pub(crate) governance: GovernanceClassCMut<'a>,
    /// `&mut` role / ceiling / assignment state.
    pub(crate) role_state: &'a mut ContextRoleState,
    /// `&` membership (read-only in the consequence path).
    pub(crate) membership: &'a MembershipState,
    /// `&mut` receive buffer (consequence events are emitted here).
    pub(crate) receive_buffer: &'a mut ReceiveBuffer,
    /// `&mut` checkpoint counter (bumped by consequence enforcement).
    pub(crate) checkpoint_events_since: &'a mut u64,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: the field-granular Class-C view accessors (`governance_class_c_mut`, `members_mut`, `receive_buffer_mut`, `role_state_mut`, `split_class_c`) get their first PRODUCTION callers when the best-effort handlers + `ConsequenceStateSplit` migrate onto the combinators. Exercised by this module's unit tests now."
)]
impl<'a> ClassCMut<'a> {
    /// Wrap a borrowed [`PerContextState`]. Crate-internal: only the combinators
    /// construct a view.
    const fn new(state: &'a mut PerContextState) -> Self {
        Self { state }
    }

    /// Field-granular `&mut` access to the governance bucket via a
    /// [`GovernanceClassCMut`] sub-view, which exposes only the Class-C
    /// governance fields and CANNOT reach `governance.class_s`. This is the ONLY
    /// governance reach on this view — there is deliberately no `governance_mut`
    /// returning `&mut GovernanceState`, because that whole-bucket `&mut` would be
    /// a `&mut` path to a Class-S-containing struct (see the type doc).
    pub(crate) const fn governance_class_c_mut(&mut self) -> GovernanceClassCMut<'_> {
        GovernanceClassCMut::new(&mut self.state.governance)
    }

    /// `&mut` access to the active-member DID set (Class-C / structural). Safe to
    /// hand out directly: `HashSet<DID>` contains no Class-S sub-struct.
    pub(crate) const fn members_mut(&mut self) -> &mut HashSet<DID> {
        &mut self.state.members
    }

    /// `&mut` access to the receive event buffer (Class-C / structural). Safe to
    /// hand out directly: it contains no Class-S sub-struct.
    pub(crate) const fn receive_buffer_mut(&mut self) -> &mut ReceiveBuffer {
        &mut self.state.receive_buffer
    }

    /// `&mut` access to the role / ceiling / assignment state (Class-C /
    /// structural). Safe to hand out directly: it contains no Class-S sub-struct.
    pub(crate) const fn role_state_mut(&mut self) -> &mut ContextRoleState {
        &mut self.state.role_state
    }

    // NOTE: This view intentionally has NO `rest_mut` / `governance_mut`
    // (whole-`&mut PerContextState` / whole-`&mut GovernanceState`). Both would be
    // `&mut` paths to a Class-S-containing struct, which the best-effort /
    // compensation paths must not have (see the `ClassCMut` type doc). More
    // field-granular SAFE accessors (for other Class-C / structural
    // `PerContextState` fields — never `class_s` or `governance`) are added here
    // as handlers migrate onto the best-effort combinator; each one returns a
    // `&mut` to a field that provably contains no Class-S sub-struct.

    /// Destructure into independent disjoint borrows of the Class-C structural
    /// fields, for the [`crate::context::governance_logic::ConsequenceStateSplit`]
    /// pattern. Borrows five DISTINCT fields of the underlying state so all five
    /// references are live simultaneously (a single `&mut self` reborrow cannot
    /// do this). None of the borrowed fields is Class-S: governance is wrapped in
    /// a [`GovernanceClassCMut`] so even it cannot reach `governance.class_s`.
    pub(crate) const fn split_class_c(&mut self) -> ClassCSplit<'_> {
        ClassCSplit {
            governance: GovernanceClassCMut::new(&mut self.state.governance),
            role_state: &mut self.state.role_state,
            membership: &self.state.membership,
            receive_buffer: &mut self.state.receive_buffer,
            checkpoint_events_since: &mut self.state.checkpoint_events_since,
        }
    }
}

impl Deref for ClassCMut<'_> {
    type Target = PerContextState;

    /// Immutable reads of the whole state.
    fn deref(&self) -> &PerContextState {
        self.state
    }
}

/// Outcome of a [`ClassSCell::commit_class_s_then_append`] that did not complete
/// cleanly (the post-persist `after` step failed, or a persist failed).
///
/// `mutated` is a DURABILITY-DIVERGENCE flag, NOT an "in-memory changed relative
/// to pre-`f`" flag. It answers the only question the caller needs: *could the
/// durable (persisted) state disagree with the in-memory state this call
/// returns?* See the field doc for the exact contract.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "ADR-049 §9: returned only by `commit_class_s_then_append`, which has no production caller until the handler-migration PR. Exercised by this module's unit tests."
)]
pub(crate) struct AppendOutcomeError {
    /// Whether DURABLE state may diverge from the in-memory state this call
    /// leaves behind — a hard fault the caller must surface.
    ///
    /// `true` when the on-disk and in-memory views are NOT known to agree:
    /// - initial-persist-fail — `f`'s mutation is in memory but did not durably
    ///   land (no later persist made it durable); and
    /// - re-persist-fail — `after` failed, the in-memory rollback ran, but the
    ///   RE-PERSIST that would make that rollback durable itself failed, so disk
    ///   still holds `f`'s mutation while memory holds the rollback.
    ///
    /// `false` when durable and in-memory are known to agree:
    /// - `f` rejected before any persist (nothing changed durably or in memory);
    ///   and
    /// - `after` failed but the rollback's RE-PERSIST succeeded (disk and memory
    ///   both hold the pre-`f` value).
    ///
    /// This is deliberately NOT framed as "in-memory mutated relative to the
    /// pre-`f` snapshot": on the re-persist-fail arm the in-memory state HAS been
    /// rolled back to pre-`f`, yet `mutated` is `true` because durability
    /// diverged. Durability-divergence is the meaning the caller acts on.
    pub(crate) mutated: bool,
    /// The error that terminated the operation (the `after` error, or the
    /// re-persist error if the rollback could not be made durable).
    pub(crate) err: ContextError,
}

/// Owns one [`PerContextState`] and gates every mutation behind a
/// persistence combinator (ADR-049 §9 Class S).
///
/// Reads go through [`Deref`]; there is intentionally no [`DerefMut`] (see the
/// module docs). Mutations go through the view-typed combinators
/// ([`Self::commit_class_s_keep`] / `_restore` / `_compensating` /
/// `_keep_compensating` / `_then_append` for fail-closed persist,
/// [`Self::commit_class_c_best_effort`] for best-effort).
pub(crate) struct ClassSCell {
    /// The wrapped state. Private — the only mutable access is through the
    /// combinators (or the PR1-temporary [`Self::state_mut`] escape hatch).
    state: PerContextState,
}

impl Deref for ClassSCell {
    type Target = PerContextState;

    /// Immutable access to the wrapped state. This is the *only* `Deref`
    /// direction: there is no `DerefMut`, so `&mut cell.<field>` does not
    /// compile (that is the compile-time enforcement hook).
    fn deref(&self) -> &PerContextState {
        &self.state
    }
}

impl ClassSCell {
    /// Wrap an owned [`PerContextState`].
    pub(crate) const fn new(state: PerContextState) -> Self {
        Self { state }
    }

    /// Unwrap, returning the owned [`PerContextState`]. Used at ownership
    /// hand-off boundaries (e.g. draining state out of the actor on shutdown /
    /// replace).
    ///
    /// `dead_code` allow: pure scaffolding — the first production caller is the
    /// migration step that routes a state hand-off through the cell. The method
    /// is exercised by this module's unit tests today.
    #[allow(dead_code)]
    pub(crate) fn into_inner(self) -> PerContextState {
        self.state
    }

    /// **TEMPORARY — removed in the final migration step.**
    ///
    /// Hands out the bare `&mut PerContextState` so existing handlers keep
    /// working byte-for-byte unchanged while the combinators are introduced.
    /// Once every handler routes its mutations through the combinators and the
    /// [`PerContextState`] Class-S fields are privatized, this method is deleted —
    /// at which point the only path to a `&mut PerContextState` is through the
    /// persist-on-commit combinators, making the Class-S fail-closed invariant a
    /// compile error to violate.
    pub(in crate::context) const fn state_mut(&mut self) -> &mut PerContextState {
        &mut self.state
    }

    /// Mutate Class-S state through a [`ClassSMut`] view and persist
    /// **fail-closed**, KEEPING the mutation even if the persist fails
    /// (ADR-049 §9).
    ///
    /// **Decision criterion (keep-on-persist-failure):** choose this variant —
    /// over [`Self::commit_class_s_restore`] — for a mutation that MUST survive a
    /// persist failure because un-doing it would be the unsafe direction. The
    /// canonical case is recording an accepted replay nonce: un-recording it
    /// re-opens the replay window the dedup cache exists to close, so even when
    /// the persist does not land the in-memory record is RETAINED (and the
    /// durable-divergence is reported by propagating the persist error). If
    /// instead the mutation must be ROLLED BACK when the persist fails (the caller
    /// must never observe success for an undurable mutation), use
    /// [`Self::commit_class_s_restore`].
    ///
    /// Sequence:
    /// 1. Run `f(view)`. If `f` returns `Err(e)`, return `Err(e)` immediately —
    ///    no persist runs (a rejected operation that staged no durable-relevant
    ///    mutation must not trigger a Class-S write).
    /// 2. On `Ok(value)`, call [`persist_state_fail_closed`]. On success return
    ///    `Ok(value)`; on failure return the persist error WITHOUT undoing the
    ///    mutation.
    ///
    /// # Errors
    ///
    /// Returns `f`'s error, or [`ContextError::PersistenceFailed`].
    ///
    /// `dead_code` allow: scaffolding — no handler is migrated yet. Exercised by
    /// this module's unit tests.
    #[allow(dead_code)]
    pub(crate) fn commit_class_s_keep<T>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<T, ContextError>,
    ) -> Result<T, ContextError> {
        let value = f(ClassSMut::new(&mut self.state))?;
        persist_state_fail_closed(&self.state, deps, context_id).map(|()| value)
    }

    /// Pure-Class-S rollback on persist failure (snapshot covers ONLY the
    /// Class-S sub-structs; mixed Class-S+Class-C sites MUST use
    /// [`Self::commit_class_s_compensating`]).
    ///
    /// Mutate Class-S state through a [`ClassSMut`] view and persist
    /// **fail-closed**, RESTORING the Class-S sub-structs on persist failure
    /// (ADR-049 §9).
    ///
    /// For mutations that must be ROLLED BACK when the persist does not land —
    /// the caller must never observe success for an undurable mutation, and the
    /// in-memory state must match what a respawn would load. The rollback is the
    /// combinator's own snapshot/restore of the Class-S sub-structs (via
    /// [`ClassSState::snapshot`]/[`ClassSState::restore`] +
    /// [`GovernanceClassS::snapshot`]/[`GovernanceClassS::restore`]) — there is no
    /// caller-supplied rollback closure to get wrong.
    ///
    /// # Snapshot SCOPE contract — Class-S sub-structs ONLY
    ///
    /// The snapshot covers EXACTLY the two Class-S sub-structs —
    /// [`ClassSState`] (`state.class_s`) and [`GovernanceClassS`]
    /// (`state.governance.class_s`). It does NOT capture any other
    /// [`PerContextState`] field. If `f` mutates Class-C / structural state (a
    /// governance velocity/budget counter, membership, the receive buffer, …) or
    /// produces an external effect, the on-persist-failure restore here rolls back
    /// ONLY the Class-S portion and leaves that Class-C / external mutation in
    /// place — a PARTIAL rollback. Therefore:
    ///
    /// - `f` mutates Class-S ONLY ⇒ use this combinator; the rollback is total.
    /// - `f` mutates Class-S AND Class-C / external state and BOTH must roll back
    ///   ⇒ use [`Self::commit_class_s_compensating`], whose `compensate` receives
    ///   a [`ClassCMut`] and is the CALLER's hook to undo the in-state Class-C and
    ///   external effects the Class-S snapshot does not cover.
    ///
    /// Sequence:
    /// 1. SNAPSHOT both Class-S sub-structs.
    /// 2. Run `f(view)`. If `f` errs, return the error (the snapshot is dropped;
    ///    `f` is responsible for not leaving a partial mutation it cares about —
    ///    same contract as the legacy "reject before mutate" handlers; no persist
    ///    runs).
    /// 3. On `Ok(value)`, persist fail-closed. On success return `Ok(value)`; on
    ///    failure RESTORE both sub-structs from the snapshot, then return the
    ///    persist error.
    ///
    /// # Errors
    ///
    /// Returns `f`'s error, or [`ContextError::PersistenceFailed`] (after
    /// restoring the snapshot).
    ///
    /// `dead_code` allow: scaffolding — see [`Self::commit_class_s_keep`].
    #[allow(dead_code)]
    pub(crate) fn commit_class_s_restore<T>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<T, ContextError>,
    ) -> Result<T, ContextError> {
        let class_s_snap = self.state.class_s.snapshot();
        let gov_snap = self.state.governance.class_s.snapshot();
        let value = f(ClassSMut::new(&mut self.state))?;
        match persist_state_fail_closed(&self.state, deps, context_id) {
            Ok(()) => Ok(value),
            Err(persist_err) => {
                self.restore_class_s(class_s_snap, gov_snap, deps);
                Err(persist_err)
            }
        }
    }

    /// Class-S rollback + caller Class-C/external compensation on persist failure.
    ///
    /// Mutate Class-S state through a [`ClassSMut`] view, persist **fail-closed**,
    /// and on persist failure RESTORE the Class-S sub-structs AND run an async
    /// `compensate` to undo an EXTERNAL effect the mutation produced
    /// (ADR-049 §9).
    ///
    /// Like [`Self::commit_class_s_restore`] but for a mutation that also
    /// produced an out-of-band side effect (e.g. an escrow authorization) that an
    /// in-state restore alone cannot reverse. `f` returns `(value, external)`,
    /// where `external` (`X`) is the handle the async `compensate` needs to undo
    /// the effect. `compensate` receives a [`ClassCMut`] (NOT a `ClassSMut`): the
    /// Class-S in-state restore has already run, so the compensation must not
    /// re-touch Class-S state.
    ///
    /// # Snapshot SCOPE contract — Class-S sub-structs ONLY
    ///
    /// As with [`Self::commit_class_s_restore`], the combinator's snapshot covers
    /// EXACTLY the two Class-S sub-structs ([`ClassSState`] and
    /// [`GovernanceClassS`]) — no other [`PerContextState`] field. The difference
    /// is that THIS combinator hands the caller a place to roll back everything
    /// the snapshot does not: `compensate` gets a [`ClassCMut`] and so can undo
    /// (a) the in-state Class-C / structural mutations `f` made and (b) the
    /// external effect carried in `external`. So when `f` mutates Class-S AND
    /// Class-C / external state and ALL of it must roll back on persist failure,
    /// this is the combinator to pick (pure-Class-S rollback ⇒
    /// [`Self::commit_class_s_restore`]).
    ///
    /// Sequence:
    /// 1. SNAPSHOT both Class-S sub-structs.
    /// 2. Run `f(view)`. If `f` errs, return the error (no persist, no
    ///    compensation — nothing durable or external happened that `f` did not
    ///    itself unwind).
    /// 3. On `Ok((value, external))`, persist fail-closed. On success return
    ///    `Ok(value)`. On failure: RESTORE both Class-S sub-structs in memory,
    ///    THEN run `compensate(external, ClassCMut, deps).await` to undo the
    ///    external effect, then return the persist error.
    ///
    /// # Errors
    ///
    /// Returns `f`'s error, or [`ContextError::PersistenceFailed`] (after the
    /// in-state restore + async compensation).
    ///
    /// `dead_code` allow: scaffolding — see [`Self::commit_class_s_keep`].
    #[allow(dead_code)]
    pub(crate) async fn commit_class_s_compensating<T, X>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<(T, X), ContextError>,
        // An `AsyncFnOnce` (edition-2024 async closure) — written `async |..|`
        // at the call site — so the returned future may BORROW the `ClassCMut`
        // view and `&ActorDeps` for the call's lifetime. A named `Fut: Future`
        // generic cannot express that (the future would outlive a borrow created
        // in this body); a regular `FnOnce -> impl Future` closure also can't
        // (its async block's future is not tied to the borrowed args). The view
        // borrows `&mut self.state`, so the future is held only across the
        // immediate `.await` below.
        compensate: impl AsyncFnOnce(X, ClassCMut<'_>, &ActorDeps),
    ) -> Result<T, ContextError> {
        let class_s_snap = self.state.class_s.snapshot();
        let gov_snap = self.state.governance.class_s.snapshot();
        let (value, external) = f(ClassSMut::new(&mut self.state))?;
        match persist_state_fail_closed(&self.state, deps, context_id) {
            Ok(()) => Ok(value),
            Err(persist_err) => {
                self.restore_class_s(class_s_snap, gov_snap, deps);
                compensate(external, ClassCMut::new(&mut self.state), deps).await;
                Err(persist_err)
            }
        }
    }

    /// KEEP Class-S on persist failure + caller Class-C/external compensation
    /// (for keep-direction sites like a consumed replay nonce).
    ///
    /// Keep the Class-S mutation on persist failure (like
    /// [`Self::commit_class_s_keep`]), but run `on_persist_failure` to undo
    /// Class-C / external effects that the failed persist did not make durable.
    /// The Class-S sub-structs are NOT restored. Returns the persist error after
    /// compensation (ADR-049 §9).
    ///
    /// # Decision criterion (keep-S, compensate-C-on-persist-failure)
    ///
    /// Choose this combinator — over [`Self::commit_class_s_keep`] (which keeps
    /// the Class-C mutation too) and over [`Self::commit_class_s_compensating`]
    /// (which RESTORES Class-S) — when a single mutation BOTH:
    ///
    /// - consumes security-critical Class-S state that must STAY consumed on
    ///   persist failure (un-consuming it re-opens a replay / re-spend window —
    ///   the fail-closed direction), AND
    /// - charges an in-memory Class-C / external reservation that DID NOT
    ///   durably land and so must be reversed.
    ///
    /// This is the shape of `reserve_tool_economy`: it consumes a spending-UCAN
    /// nonce (Class-S — kept) while charging the `budget_tracker` /
    /// `velocity_tracker` / `hard_rate_limit` (Class-C — reversed on persist
    /// failure, because the reservation the caller is being charged for did not
    /// become durable). The Class-C reversal is CONDITIONAL on the persist
    /// result, so it cannot be folded into `f` (which runs before the persist):
    /// `f` returns the handles the reversal needs as `external` (`X`), and the
    /// reversal runs only on the persist-failure arm.
    ///
    /// `on_persist_failure` receives a [`ClassCMut`] (NOT a [`ClassSMut`]): the
    /// Class-S sub-structs are intentionally left as `f` mutated them, so the
    /// compensation must not — and structurally CANNOT — re-touch Class-S.
    ///
    /// # Snapshot SCOPE contract — keep-direction for Class-S
    ///
    /// Unlike [`Self::commit_class_s_restore`] / [`Self::commit_class_s_compensating`]
    /// this combinator takes NO snapshot of the Class-S sub-structs: keep-direction
    /// means there is nothing to restore. The ONLY undo on persist failure is the
    /// caller-supplied `on_persist_failure` over Class-C / external effects.
    ///
    /// Sequence:
    /// 1. Run `f(view)` → `(value, external)`. If `f` errs, return the error (no
    ///    persist, no compensation — nothing durable or external to unwind that
    ///    `f` did not itself unwind).
    /// 2. On `Ok((value, external))`, persist fail-closed.
    ///    - On persist SUCCESS return `Ok(value)` — the external effect committed,
    ///      nothing to compensate.
    ///    - On persist FAILURE run
    ///      `on_persist_failure(external, ClassCMut, deps).await` to undo the
    ///      Class-C / external effect (the Class-S mutation is KEPT — NOT
    ///      restored), then return the persist error.
    ///
    /// # Errors
    ///
    /// Returns `f`'s error, or [`ContextError::PersistenceFailed`] (after running
    /// `on_persist_failure`, with the Class-S mutation retained).
    ///
    /// `dead_code` allow: scaffolding — see [`Self::commit_class_s_keep`].
    #[allow(dead_code)]
    pub(crate) async fn commit_class_s_keep_compensating<T, X>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<(T, X), ContextError>,
        // An `AsyncFnOnce` (see `commit_class_s_compensating`) — written
        // `async |..|` at the call site — so the returned future may BORROW the
        // `ClassCMut` view and `&ActorDeps` for the call's lifetime. The view
        // borrows `&mut self.state`, so the future is held only across the
        // immediate `.await` below.
        on_persist_failure: impl AsyncFnOnce(X, ClassCMut<'_>, &ActorDeps),
    ) -> Result<T, ContextError> {
        // No Class-S snapshot: keep-direction leaves the Class-S mutation in
        // place on persist failure, so there is nothing to restore.
        let (value, external) = f(ClassSMut::new(&mut self.state))?;
        match persist_state_fail_closed(&self.state, deps, context_id) {
            Ok(()) => Ok(value),
            Err(persist_err) => {
                on_persist_failure(external, ClassCMut::new(&mut self.state), deps).await;
                Err(persist_err)
            }
        }
    }

    /// Mutate Class-S state through a [`ClassSMut`] view, persist **fail-closed**,
    /// THEN run an async `after` step that appends a derived record to an
    /// EXTERNAL durable sink; if `after` fails, RESTORE the snapshot + RE-PERSIST
    /// and report the outcome (ADR-049 §9).
    ///
    /// For a Class-S mutation that must be paired with a follow-on durable append
    /// which can itself fail. This is the shape of the cross-context tool-invoke
    /// "Commit" path (spec §6.2.4): `f` captures the committed output into Class-S
    /// (`xctx_committed_outputs`) and persists it; `after` then appends a
    /// `ToolInvoked` record to the EVENT LOG. That append targets the event-log
    /// adapter on [`ActorDeps`] (`deps.event_log`) — an EXTERNAL durable sink. It
    /// is NOT an in-state [`PerContextState`] mutation: the live persist snapshot
    /// (`build_snapshot_from_state`) hard-codes `event_log_merkle_root` to zero
    /// and the `event_log` / `merkle_tree` fields are rebuilt from their own
    /// provider on restore — they are never serialized into `ContextSnapshot`. So
    /// `after` re-persisting nothing on the Ok path loses no durable state.
    ///
    /// Because the append is external and `after` must NOT make a fresh Class-S
    /// transition (that would be an un-persisted Class-S mutation escaping this
    /// combinator's guarantee), `after` receives a READ-ONLY `&PerContextState`
    /// (to read the just-persisted state when building the record) and
    /// `&ActorDeps` (to perform the external append). The `&PerContextState`
    /// view exposes no `&mut`, so `after` provably cannot name `class_s_mut` /
    /// `governance_class_s_mut` — it is a compile error to mutate Class-S from
    /// `after`.
    ///
    /// If `after` errs, the combinator rolls the Class-S mutation back from the
    /// snapshot and RE-PERSISTS so durable state matches the rollback.
    ///
    /// Sequence:
    /// 1. SNAPSHOT both Class-S sub-structs.
    /// 2. Run `f(view)` → `(value, append_input)`. If `f` errs, return
    ///    `AppendOutcomeError { mutated: false, err }` (no persist ran).
    /// 3. Persist fail-closed. On failure return
    ///    `AppendOutcomeError { mutated: true, err }` — `f`'s mutation is in
    ///    memory but did not durably land (the restore is the caller's call; this
    ///    matches `*_keep`'s "report divergence, keep mutation" and signals
    ///    `mutated`).
    /// 4. Run `after(&append_input, &state, deps).await` (external append). On
    ///    `Ok` return `Ok(value)` — no re-persist, since the append wrote to an
    ///    external sink, not to `ContextSnapshot`-backed in-state. On
    ///    `Err(after_err)`: RESTORE both sub-structs, RE-PERSIST.
    ///    - re-persist OK → `AppendOutcomeError { mutated: false, err: after_err }`
    ///      (durable and in-memory both hold the pre-`f` value).
    ///    - re-persist Err → `AppendOutcomeError { mutated: true, err: <re-persist
    ///      err> }` (could not make the rollback durable — durable/in-memory
    ///      divergence the caller must surface).
    ///
    /// # Errors
    ///
    /// Returns [`AppendOutcomeError`] carrying `f`'s error, the persist error, the
    /// `after` error, or the re-persist error — with `mutated` set per the rules
    /// above.
    ///
    /// `dead_code` allow: scaffolding — see [`Self::commit_class_s_keep`].
    #[allow(dead_code)]
    pub(crate) async fn commit_class_s_then_append<T, A>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<(T, A), ContextError>,
        // An `AsyncFnOnce` (see `commit_class_s_compensating`) — written
        // `async |..|` at the call site — so the returned future may borrow the
        // `&A`, `&PerContextState`, and `&ActorDeps` arguments. `after` gets a
        // READ-ONLY `&PerContextState`: the external append it performs must not
        // make a fresh (un-persisted) Class-S transition, and a `&` view has no
        // `class_s_mut` to name — enforced by the type, not by the source-text
        // gate.
        after: impl AsyncFnOnce(&A, &PerContextState, &ActorDeps) -> Result<(), ContextError>,
    ) -> Result<T, AppendOutcomeError> {
        let class_s_snap = self.state.class_s.snapshot();
        let gov_snap = self.state.governance.class_s.snapshot();
        let (value, append_input) =
            f(ClassSMut::new(&mut self.state)).map_err(|err| AppendOutcomeError {
                mutated: false,
                err,
            })?;
        persist_state_fail_closed(&self.state, deps, context_id).map_err(|err| {
            AppendOutcomeError {
                // `f`'s mutation is in memory but did not durably land.
                mutated: true,
                err,
            }
        })?;
        match after(&append_input, &self.state, deps).await {
            // `after` appended to an external sink (e.g. the event log); the
            // Class-S mutation is already durable from the persist above and
            // `after` made no in-state mutation — nothing to re-persist.
            Ok(()) => Ok(value),
            Err(after_err) => {
                self.restore_class_s(class_s_snap, gov_snap, deps);
                match persist_state_fail_closed(&self.state, deps, context_id) {
                    // Rollback made durable: in-memory matches the pre-`f` value.
                    Ok(()) => Err(AppendOutcomeError {
                        mutated: false,
                        err: after_err,
                    }),
                    // Could not make the rollback durable: hard divergence.
                    Err(repersist_err) => Err(AppendOutcomeError {
                        mutated: true,
                        err: repersist_err,
                    }),
                }
            }
        }
    }

    /// Class-C best-effort persist (the Class-C path — no Class-S mutator on the
    /// view, persist failure is not surfaced).
    ///
    /// Mutate Class-C state through a [`ClassCMut`] view and persist
    /// **best-effort** (ADR-049 §9). Runs `f`, then [`persist_state_best_effort`] —
    /// a persist failure is logged + metered but not surfaced (the ≤50 ms
    /// coalesce-window rollback is acceptable for liveness / structural state).
    /// The [`ClassCMut`] view exposes no Class-S mutator, so a best-effort `f`
    /// cannot stage a Class-S transition.
    ///
    /// `dead_code` allow: scaffolding — see [`Self::commit_class_s_keep`].
    #[allow(dead_code)]
    pub(crate) fn commit_class_c_best_effort(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassCMut),
    ) {
        f(ClassCMut::new(&mut self.state));
        persist_state_best_effort(&self.state, deps, context_id);
    }

    /// Restore both Class-S sub-structs from their snapshots. The governance
    /// restore needs the clock from `deps` to rebuild the `spending_nonce_tracker`.
    fn restore_class_s(
        &mut self,
        class_s_snap: super::state::ClassSStateSnapshot,
        gov_snap: crate::context::state::GovernanceClassSSnapshot,
        deps: &ActorDeps,
    ) {
        self.state.class_s.restore(class_s_snap);
        self.state.governance.class_s.restore(gov_snap, &deps.clock);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::persistence::ContextPersistence;
    use scp_identity::DID;
    use scp_platform::testing::InMemoryStorage;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Minimal event log provider — accepts every call (the combinator paths do
    /// not touch the event log).
    struct TestEventLog;
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Persistence that accepts every write (success path).
    struct OkPersistence;
    /// Persistence whose `persist_context` ALWAYS fails (fail-closed path).
    struct FailPersistence;
    /// Persistence SPY: accepts every write but counts `persist_context` calls,
    /// so a test can assert a combinator actually performed its persist.
    struct SpyPersistence {
        persist_calls: Arc<AtomicUsize>,
    }

    macro_rules! impl_persistence {
        ($ty:ty, $persist_result:expr) => {
            impl ContextPersistence for $ty {
                fn persist_context(
                    &self,
                    _: &str,
                    _: &crate::context::state::ContextSnapshot,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    $persist_result
                }
                fn load_context(
                    &self,
                    _: &str,
                ) -> Result<
                    Option<crate::context::state::ContextSnapshot>,
                    Box<dyn std::error::Error + Send + Sync>,
                > {
                    Ok(None)
                }
                fn persist_broadcast(
                    &self,
                    _: &str,
                    _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    Ok(())
                }
                fn load_broadcast(
                    &self,
                    _: &str,
                ) -> Result<
                    Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
                    Box<dyn std::error::Error + Send + Sync>,
                > {
                    Ok(None)
                }
                fn delete_context(
                    &self,
                    _: &str,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    Ok(())
                }
                fn list_persisted_contexts(
                    &self,
                ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
                    Ok(Vec::new())
                }
            }
        };
    }

    impl_persistence!(OkPersistence, Ok(()));
    impl_persistence!(FailPersistence, Err("induced persist failure".into()));

    impl ContextPersistence for SpyPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.persist_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn persist_broadcast(
            &self,
            _: &str,
            _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _: &str,
        ) -> Result<
            Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Persistence that SUCCEEDS the first `persist_context` call then FAILS
    /// every subsequent one — lets `then_append` exercise "post-f persist OK,
    /// rollback re-persist FAILS" (the hard-divergence `mutated == true` path).
    struct SucceedThenFail {
        calls: Arc<AtomicUsize>,
    }
    impl ContextPersistence for SucceedThenFail {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Ok(())
            } else {
                Err("re-persist failure".into())
            }
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn persist_broadcast(
            &self,
            _: &str,
            _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _: &str,
        ) -> Result<
            Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Assemble an `ActorDeps` with the supplied persistence backend.
    async fn build_deps(persistence: Box<dyn ContextPersistence>) -> ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestClassSCell".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(persistence),
            None,
            None,
            None,
            mls_storage,
        );
        supervisor
            .build_actor_deps(&DID("did:example:class-s-cell-test".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// A fresh encrypted test state.
    fn fresh_state(ctx_byte: u8) -> PerContextState {
        PerContextState::new_for_test_encrypted(
            [ctx_byte; 32],
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        )
    }

    fn ctx_hex(byte: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..32 {
            use std::fmt::Write;
            let _ = write!(s, "{byte:02x}");
        }
        s
    }

    fn saga(id: &str) -> crate::context::supervisor::saga_journal::SagaId {
        crate::context::supervisor::saga_journal::SagaId(id.to_owned())
    }

    /// Build a `CrossContextToolInvocation` prepared-state for `saga_pending`.
    fn prepared_invocation() -> crate::context::supervisor::saga_prepared_state::SagaPreparedState {
        use crate::context::supervisor::saga_prepared_state::{
            CrossContextToolInvocationPrepared, SagaPreparedState,
        };
        SagaPreparedState::CrossContextToolInvocation(CrossContextToolInvocationPrepared {
            caller_context_id: [0x1Au8; 32],
            target_context_id: [0x2Bu8; 32],
            caller_did: DID("did:example:caller".to_owned()),
            tool_registration_id: "tool-v1".to_owned(),
            ucan_proof_id: "ucan-1".to_owned(),
            recorded_timestamp_ms: 1_700_000_000_123,
            recorded_nonce: [0x3Cu8; 16],
            recorded_chain_depth: 1,
        })
    }

    // ------------------------------------------------------------------
    // commit_class_s_keep
    // ------------------------------------------------------------------

    /// `*_keep` persists fail-closed and returns `Ok(value)` on persist success,
    /// retaining the mutation.
    #[tokio::test]
    async fn keep_persists_and_returns_ok_on_success() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x11));
        let ctx = ctx_hex(0x11);

        let returned = cell
            .commit_class_s_keep(&deps, &ctx, |mut view| {
                view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
                Ok("kept")
            })
            .expect("persist succeeds ⇒ Ok");

        assert_eq!(returned, "kept");
        assert!(
            cell.class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&[0x3Cu8; 16]),
            "mutation retained on persist success"
        );
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            1,
            "exactly one persist"
        );
    }

    /// `*_keep` KEEPS the mutation on persist failure (fail-closed direction) and
    /// surfaces the persist error.
    #[tokio::test]
    async fn keep_retains_mutation_on_persist_failure() {
        let deps = build_deps(Box::new(FailPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x12));
        let ctx = ctx_hex(0x12);

        let result = cell.commit_class_s_keep(&deps, &ctx, |mut view| {
            view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
            Ok(())
        });

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "persist failure surfaces; got {result:?}"
        );
        assert!(
            cell.class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&[0x3Cu8; 16]),
            "keep variant retains the recorded nonce even on persist failure"
        );
    }

    /// `*_keep` returns `f`'s error without persisting when `f` rejects.
    #[tokio::test]
    async fn keep_returns_f_error_without_persisting() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x13));
        let ctx = ctx_hex(0x13);

        let result: Result<(), ContextError> = cell.commit_class_s_keep(&deps, &ctx, |_view| {
            Err(ContextError::PermissionDenied("rejected".to_owned()))
        });

        assert!(
            matches!(result, Err(ContextError::PermissionDenied(_))),
            "f's error propagates unchanged; got {result:?}"
        );
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            0,
            "no Class-S persist runs when f rejects"
        );
    }

    // ------------------------------------------------------------------
    // commit_class_s_restore
    // ------------------------------------------------------------------

    /// `*_restore` persists fail-closed and returns `Ok` on success, retaining
    /// the mutation.
    #[tokio::test]
    async fn restore_persists_and_returns_ok_on_success() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x21));
        let ctx = ctx_hex(0x21);
        let saga_a = saga("saga-restore-ok");

        let value = cell
            .commit_class_s_restore(&deps, &ctx, |mut view| {
                view.class_s_mut()
                    .saga_pending
                    .insert(saga_a.clone(), prepared_invocation());
                Ok(99u32)
            })
            .expect("persist succeeds ⇒ Ok");

        assert_eq!(value, 99);
        assert!(
            cell.class_s.saga_pending.contains_key(&saga_a),
            "mutation retained on persist success"
        );
    }

    /// (key behaviour) `*_restore` ROLLS BACK the Class-S sub-structs on persist
    /// failure — asserted via the mirror across BOTH `saga_pending` and the
    /// nonce dedup cache, plus the governance Class-S sub-struct.
    #[tokio::test]
    async fn restore_rolls_back_class_s_on_persist_failure() {
        let deps = build_deps(Box::new(FailPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x22));
        let ctx = ctx_hex(0x22);
        let saga_a = saga("saga-restore-rollback");

        let result = cell.commit_class_s_restore(&deps, &ctx, |mut view| {
            // Mutate Class-S: saga_pending + nonce dedup …
            let cs = view.class_s_mut();
            cs.saga_pending
                .insert(saga_a.clone(), prepared_invocation());
            cs.xctx_nonce_dedup.record([0x3Cu8; 16], 1_700_000_000);
            // … and governance Class-S (threshold).
            view.governance_class_s_mut().threshold_value = 7;
            Ok(())
        });

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "persist failure surfaces; got {result:?}"
        );
        assert!(
            cell.class_s.saga_pending.is_empty(),
            "saga_pending rolled back via the mirror"
        );
        assert!(
            !cell
                .class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&[0x3Cu8; 16]),
            "recorded nonce rolled back via the mirror"
        );
        assert_eq!(
            cell.governance.class_s.threshold_value, 0,
            "governance threshold rolled back via the mirror"
        );
    }

    /// `*_restore` returns `f`'s error without persisting when `f` rejects.
    #[tokio::test]
    async fn restore_returns_f_error_without_persisting() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x23));
        let ctx = ctx_hex(0x23);

        let result: Result<(), ContextError> = cell.commit_class_s_restore(&deps, &ctx, |_view| {
            Err(ContextError::PermissionDenied("rejected".to_owned()))
        });

        assert!(matches!(result, Err(ContextError::PermissionDenied(_))));
        assert_eq!(persist_calls.load(Ordering::SeqCst), 0);
    }

    // ------------------------------------------------------------------
    // commit_class_s_compensating
    // ------------------------------------------------------------------

    /// `*_compensating` on persist success returns `Ok` and does NOT run the
    /// async compensation.
    #[tokio::test]
    async fn compensating_does_not_compensate_on_persist_success() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x31));
        let ctx = ctx_hex(0x31);
        let compensated = Arc::new(AtomicUsize::new(0));
        let comp_for_closure = Arc::clone(&compensated);

        let value = cell
            .commit_class_s_compensating(
                &deps,
                &ctx,
                |mut view| {
                    view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
                    Ok((5u32, "escrow-handle"))
                },
                async move |_external, _classc: ClassCMut<'_>, _deps: &ActorDeps| {
                    comp_for_closure.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await
            .expect("persist succeeds ⇒ Ok");

        assert_eq!(value, 5);
        assert_eq!(
            compensated.load(Ordering::SeqCst),
            0,
            "compensation does not run on persist success"
        );
        assert!(
            cell.class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&[0x3Cu8; 16]),
            "mutation retained on success"
        );
    }

    /// (key behaviour) `*_compensating` on persist FAILURE restores Class-S
    /// IN-STATE first, then runs the async compensation exactly once.
    #[tokio::test]
    async fn compensating_restores_then_compensates_on_persist_failure() {
        let deps = build_deps(Box::new(FailPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x32));
        let ctx = ctx_hex(0x32);
        let saga_a = saga("saga-compensate");
        // Compensation observes the post-restore Class-S state: it records
        // whether saga_pending was already empty (i.e. restore ran BEFORE it).
        let saw_empty_after_restore = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let comp_flag = Arc::clone(&saw_empty_after_restore);

        let result = cell
            .commit_class_s_compensating(
                &deps,
                &ctx,
                |mut view| {
                    view.class_s_mut()
                        .saga_pending
                        .insert(saga_a.clone(), prepared_invocation());
                    Ok(((), "escrow-handle"))
                },
                async move |external, classc: ClassCMut<'_>, _deps: &ActorDeps| {
                    assert_eq!(external, "escrow-handle");
                    // The Class-S in-state restore has already run, so the
                    // ClassCMut view reads an empty saga_pending.
                    comp_flag.store(classc.saga_pending().is_empty(), Ordering::SeqCst);
                },
            )
            .await;

        assert!(matches!(result, Err(ContextError::PersistenceFailed(_))));
        assert!(
            saw_empty_after_restore.load(Ordering::SeqCst),
            "compensation runs AFTER the in-state restore (saga_pending already empty)"
        );
        assert!(
            cell.class_s.saga_pending.is_empty(),
            "Class-S restored on persist failure"
        );
    }

    // ------------------------------------------------------------------
    // commit_class_s_keep_compensating
    // ------------------------------------------------------------------

    /// `*_keep_compensating` on persist SUCCESS returns `Ok(value)`, runs NO
    /// compensation, and retains the Class-S mutation. (The Class-C effect `f`
    /// staged also stands — nothing to compensate when the persist landed.)
    #[tokio::test]
    async fn keep_compensating_does_not_compensate_on_persist_success() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x36));
        let ctx = ctx_hex(0x36);
        let compensated = Arc::new(AtomicUsize::new(0));
        let comp_for_closure = Arc::clone(&compensated);
        let member = DID("did:example:keep-comp-success".to_owned());
        let member_for_f = member.clone();

        let value = cell
            .commit_class_s_keep_compensating(
                &deps,
                &ctx,
                move |mut view| {
                    // Class-S: consume a replay nonce (kept).
                    view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
                    // Class-C: stage an in-memory reservation (a member here).
                    view.rest_mut().members.insert(member_for_f);
                    Ok((5u32, "reservation-handle"))
                },
                async move |_external, _classc: ClassCMut<'_>, _deps: &ActorDeps| {
                    comp_for_closure.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await
            .expect("persist succeeds ⇒ Ok");

        assert_eq!(value, 5);
        assert_eq!(
            compensated.load(Ordering::SeqCst),
            0,
            "no compensation on persist success"
        );
        assert!(
            cell.class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&[0x3Cu8; 16]),
            "Class-S nonce kept on success"
        );
        assert!(
            cell.members.contains(&member),
            "Class-C reservation stands on success"
        );
    }

    /// (key behaviour) `*_keep_compensating` on persist FAILURE runs
    /// `on_persist_failure` (which undoes the Class-C effect), KEEPS the Class-S
    /// mutation (NOT restored — fail-closed direction), and returns the persist
    /// error.
    #[tokio::test]
    async fn keep_compensating_keeps_class_s_and_compensates_class_c_on_persist_failure() {
        let deps = build_deps(Box::new(FailPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x37));
        let ctx = ctx_hex(0x37);
        let member = DID("did:example:keep-comp-failure".to_owned());
        let member_for_f = member.clone();
        let external_for_undo = member.clone();
        // The compensation observes that the Class-S nonce was NOT restored
        // (still present) at the time it runs.
        let saw_nonce_kept = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kept_flag = Arc::clone(&saw_nonce_kept);

        let result = cell
            .commit_class_s_keep_compensating(
                &deps,
                &ctx,
                move |mut view| {
                    view.class_s_mut().xctx_nonce_dedup.record([0x3Cu8; 16], 0);
                    view.rest_mut().members.insert(member_for_f);
                    Ok(((), external_for_undo))
                },
                async move |external: DID, mut classc: ClassCMut<'_>, _deps: &ActorDeps| {
                    // Class-S kept: the nonce is still recorded when we compensate
                    // (read via Deref to `&PerContextState`; the restricted
                    // `ClassCMut` view exposes no Class-S *mutator*).
                    kept_flag.store(
                        classc
                            .class_s
                            .xctx_nonce_dedup
                            .entries()
                            .contains_key(&[0x3Cu8; 16]),
                        Ordering::SeqCst,
                    );
                    // Undo the Class-C reservation the failed persist did not make
                    // durable.
                    classc.members_mut().remove(&external);
                },
            )
            .await;

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "persist failure surfaces; got {result:?}"
        );
        assert!(
            saw_nonce_kept.load(Ordering::SeqCst),
            "Class-S nonce is KEPT (not restored) when on_persist_failure runs"
        );
        assert!(
            cell.class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&[0x3Cu8; 16]),
            "Class-S nonce retained on persist failure (fail-closed direction)"
        );
        assert!(
            !cell.members.contains(&member),
            "Class-C reservation undone by on_persist_failure"
        );
    }

    /// `*_keep_compensating` returns `f`'s error without persisting or
    /// compensating when `f` rejects.
    #[tokio::test]
    async fn keep_compensating_returns_f_error_without_persisting() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x38));
        let ctx = ctx_hex(0x38);
        let compensated = Arc::new(AtomicUsize::new(0));
        let comp_for_closure = Arc::clone(&compensated);

        let result: Result<(), ContextError> = cell
            .commit_class_s_keep_compensating(
                &deps,
                &ctx,
                |_view| Err(ContextError::PermissionDenied("rejected".to_owned())),
                async move |_external: (), _classc: ClassCMut<'_>, _deps: &ActorDeps| {
                    comp_for_closure.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;

        assert!(
            matches!(result, Err(ContextError::PermissionDenied(_))),
            "f's error propagates unchanged; got {result:?}"
        );
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            0,
            "no persist runs when f rejects"
        );
        assert_eq!(
            compensated.load(Ordering::SeqCst),
            0,
            "no compensation runs when f rejects"
        );
    }

    // ------------------------------------------------------------------
    // commit_class_s_then_append
    // ------------------------------------------------------------------

    /// `*_then_append` on persist-OK + after-OK returns `Ok(value)` and retains
    /// both the mutation and whatever `after` did.
    #[tokio::test]
    async fn then_append_ok_when_persist_and_after_succeed() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x41));
        let ctx = ctx_hex(0x41);
        let saga_a = saga("saga-append-ok");

        let value = cell
            .commit_class_s_then_append(
                &deps,
                &ctx,
                |mut view| {
                    view.class_s_mut()
                        .saga_pending
                        .insert(saga_a.clone(), prepared_invocation());
                    Ok((11u32, "append-input"))
                },
                async |input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                    assert_eq!(*input, "append-input");
                    Ok(())
                },
            )
            .await
            .expect("persist + after succeed ⇒ Ok");

        assert_eq!(value, 11);
        assert!(cell.class_s.saga_pending.contains_key(&saga_a));
    }

    /// (new contract — FIX 1) `*_then_append`'s `after` receives a READ-ONLY
    /// `&PerContextState` reflecting the JUST-PERSISTED state, and performs only
    /// an EXTERNAL append. On `after`-Ok there is NO re-persist (the append wrote
    /// to an external sink, not to `ContextSnapshot`-backed in-state), so exactly
    /// ONE persist runs — the post-`f` fail-closed persist.
    ///
    /// The `&PerContextState` view (no `&mut`) provably CANNOT name `class_s_mut`
    /// / `governance_class_s_mut`: that is enforced by the type, not by this test.
    /// Were `after` to take a `ClassSMut`, an un-persisted Class-S mutation could
    /// escape the combinator's guarantee; the read-only view makes that a compile
    /// error. This test confirms the view TYPE and the single-persist behaviour.
    #[tokio::test]
    async fn then_append_after_reads_just_persisted_state_and_does_not_repersist() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x46));
        let ctx = ctx_hex(0x46);
        let saga_a = saga("saga-append-reads-state");
        // `after` records whether the read-only state it was handed already
        // reflects `f`'s Class-S mutation (i.e. it observes the just-persisted
        // state, not a pre-`f` view).
        let saw_mutation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_flag = Arc::clone(&saw_mutation);
        let saga_for_after = saga_a.clone();

        let value = cell
            .commit_class_s_then_append(
                &deps,
                &ctx,
                |mut view| {
                    view.class_s_mut()
                        .saga_pending
                        .insert(saga_a.clone(), prepared_invocation());
                    Ok((7u32, "append-input"))
                },
                // `state: &PerContextState` — a read-only view. There is no
                // `state.class_s_mut()` to call; mutating Class-S here would not
                // compile. `after` reads the just-persisted state, then performs
                // its (here, no-op stand-in for an external) append.
                async move |input: &&str, state: &PerContextState, _deps: &ActorDeps| {
                    assert_eq!(*input, "append-input");
                    saw_flag.store(
                        state.class_s.saga_pending.contains_key(&saga_for_after),
                        Ordering::SeqCst,
                    );
                    Ok(())
                },
            )
            .await
            .expect("persist + after succeed ⇒ Ok");

        assert_eq!(value, 7);
        assert!(
            saw_mutation.load(Ordering::SeqCst),
            "after reads the JUST-PERSISTED state (f's mutation is visible)"
        );
        assert!(cell.class_s.saga_pending.contains_key(&saga_a));
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            1,
            "after-Ok does NOT re-persist: exactly one (post-f) persist runs"
        );
    }

    /// (key behaviour) `*_then_append` when `after` fails RESTORES + RE-PERSISTS
    /// the snapshot and reports `mutated == false` (rollback made durable).
    #[tokio::test]
    async fn then_append_restores_and_repersists_on_after_failure() {
        // Persistence succeeds for the initial persist AND the re-persist.
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x42));
        let ctx = ctx_hex(0x42);
        let saga_a = saga("saga-append-fail");

        let result = cell
            .commit_class_s_then_append(
                &deps,
                &ctx,
                |mut view| {
                    view.class_s_mut()
                        .saga_pending
                        .insert(saga_a.clone(), prepared_invocation());
                    Ok(((), "append-input"))
                },
                async |_input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                    Err(ContextError::EventLogFailed("append failed".to_owned()))
                },
            )
            .await;

        match result {
            Err(AppendOutcomeError { mutated, err }) => {
                assert!(!mutated, "rollback re-persisted ⇒ mutated is false");
                assert!(
                    matches!(err, ContextError::EventLogFailed(_)),
                    "carries the after error; got {err:?}"
                );
            }
            Ok(()) => panic!("expected AppendOutcomeError"),
        }
        assert!(
            cell.class_s.saga_pending.is_empty(),
            "saga_pending rolled back after the after-failure"
        );
        // Two persists: the post-f fail-closed persist + the rollback re-persist.
        assert_eq!(persist_calls.load(Ordering::SeqCst), 2);
    }

    /// `*_then_append` reports `mutated == true` when the post-`f` persist itself
    /// fails (the mutation is in memory but did not durably land).
    #[tokio::test]
    async fn then_append_reports_mutated_on_initial_persist_failure() {
        let deps = build_deps(Box::new(FailPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x43));
        let ctx = ctx_hex(0x43);
        let saga_a = saga("saga-append-persistfail");
        let after_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let after_flag = Arc::clone(&after_ran);

        let result = cell
            .commit_class_s_then_append(
                &deps,
                &ctx,
                |mut view| {
                    view.class_s_mut()
                        .saga_pending
                        .insert(saga_a.clone(), prepared_invocation());
                    Ok(((), "append-input"))
                },
                async move |_input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                    after_flag.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await;

        match result {
            Err(AppendOutcomeError { mutated, err }) => {
                assert!(mutated, "initial persist failed ⇒ mutated is true");
                assert!(matches!(err, ContextError::PersistenceFailed(_)));
            }
            Ok(()) => panic!("expected AppendOutcomeError"),
        }
        assert!(
            !after_ran.load(Ordering::SeqCst),
            "after never runs when the initial fail-closed persist fails"
        );
    }

    /// `*_then_append` when `after` fails AND the rollback re-persist also fails:
    /// reports `mutated == true` (could not make the rollback durable).
    #[tokio::test]
    async fn then_append_reports_mutated_when_repersist_fails() {
        // Fail ONLY the second persist (the re-persist): succeed the first
        // post-f persist, fail the rollback re-persist (see `SucceedThenFail`).
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SucceedThenFail {
            calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x44));
        let ctx = ctx_hex(0x44);
        let saga_a = saga("saga-append-repersistfail");

        let result = cell
            .commit_class_s_then_append(
                &deps,
                &ctx,
                |mut view| {
                    view.class_s_mut()
                        .saga_pending
                        .insert(saga_a.clone(), prepared_invocation());
                    Ok(((), "x"))
                },
                async |_input: &&str, _state: &PerContextState, _deps: &ActorDeps| {
                    Err(ContextError::EventLogFailed("append failed".to_owned()))
                },
            )
            .await;

        match result {
            Err(AppendOutcomeError { mutated, err }) => {
                assert!(mutated, "re-persist failed ⇒ mutated is true");
                assert!(
                    matches!(err, ContextError::PersistenceFailed(_)),
                    "carries the re-persist error; got {err:?}"
                );
            }
            Ok(()) => panic!("expected AppendOutcomeError"),
        }
        assert_eq!(persist_calls.load(Ordering::SeqCst), 2);
    }

    /// `*_then_append` returns `AppendOutcomeError { mutated: false }` when `f`
    /// itself rejects (no persist ran).
    #[tokio::test]
    async fn then_append_reports_not_mutated_when_f_rejects() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x45));
        let ctx = ctx_hex(0x45);

        let result: Result<(), AppendOutcomeError> = cell
            .commit_class_s_then_append(
                &deps,
                &ctx,
                |_view| Err(ContextError::PermissionDenied("rejected".to_owned())),
                async |_input: &(), _state: &PerContextState, _deps: &ActorDeps| Ok(()),
            )
            .await;

        match result {
            Err(AppendOutcomeError { mutated, err }) => {
                assert!(!mutated);
                assert!(matches!(err, ContextError::PermissionDenied(_)));
            }
            Ok(()) => panic!("expected AppendOutcomeError"),
        }
        assert_eq!(persist_calls.load(Ordering::SeqCst), 0);
    }

    // ------------------------------------------------------------------
    // commit_class_c_best_effort
    // ------------------------------------------------------------------

    /// `commit_class_c_best_effort` runs the Class-C mutation and issues exactly one
    /// best-effort persist.
    #[tokio::test]
    async fn best_effort_runs_mutation_and_persists() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x51));
        let ctx = ctx_hex(0x51);
        let member = DID("did:example:best-effort-member".to_owned());
        let member_for_closure = member.clone();

        cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
            view.members_mut().insert(member_for_closure);
        });

        assert!(
            cell.members.contains(&member),
            "best-effort mutation is applied"
        );
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            1,
            "commit_class_c_best_effort issues exactly one persist"
        );
    }

    /// `ClassCMut::split_class_c` yields the five disjoint borrows the
    /// `ConsequenceStateSplit` pattern needs, simultaneously.
    #[tokio::test]
    async fn best_effort_split_yields_disjoint_class_c_borrows() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x52));
        let ctx = ctx_hex(0x52);

        cell.commit_class_c_best_effort(&deps, &ctx, |mut view| {
            let mut split = view.split_class_c();
            // Hold all five borrows live at once; mutate two of them to prove
            // they are independent mutable references.
            *split.checkpoint_events_since += 3;
            // Exercise the GovernanceClassCMut field-granular accessor (a Class-C
            // field) AND a whole-bucket read via its Deref — neither can reach
            // `governance.class_s`.
            split
                .governance
                .cooldown_until_mut()
                .insert(7usize, 1_700_000_999);
            let _ = split.governance.next_proposal_seq;
            let _ = &split.role_state;
            let _ = split.membership.count();
            let _ = split.receive_buffer.len();
        });

        assert_eq!(
            cell.checkpoint_events_since, 3,
            "the disjoint &mut checkpoint counter was mutated through the split"
        );
        assert_eq!(
            cell.governance.cooldown_until.get(&7usize),
            Some(&1_700_000_999),
            "the GovernanceClassCMut Class-C accessor mutated cooldown_until through the split"
        );
    }

    /// `ClassCMut::governance_class_c_mut` yields a `GovernanceClassCMut` whose
    /// field-granular accessors mutate a Class-C governance field, and whose
    /// `Deref` reads the whole governance bucket — with no `&mut` path to
    /// `governance.class_s`.
    #[tokio::test]
    async fn best_effort_governance_class_c_mut_mutates_class_c_field() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x53));
        let ctx = ctx_hex(0x53);

        cell.commit_class_c_best_effort(&deps, &ctx, |mut view| {
            let mut gov = view.governance_class_c_mut();
            // Mutate a Class-C governance field through the field-granular
            // accessor.
            gov.cooldown_until_mut().insert(3usize, 1_700_000_500);
            // Read the whole governance bucket via Deref (reads cannot violate the
            // fail-closed invariant). There is no `&mut self.gov` / `class_s`
            // accessor to reach Class-S.
            let _ = gov.next_proposal_seq;
        });

        assert_eq!(
            cell.governance.cooldown_until.get(&3usize),
            Some(&1_700_000_500),
            "Class-C governance field mutated through governance_class_c_mut"
        );
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            1,
            "best-effort issues exactly one persist"
        );
    }

    /// `GovernanceClassCMut::velocity_tracker_mut` hands out a `&mut` to the
    /// per-sender velocity tracker; a recorded message is observable on the
    /// underlying `cell.governance.velocity_tracker`.
    #[tokio::test]
    async fn best_effort_velocity_tracker_mut_records_through_view() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x54));
        let ctx = ctx_hex(0x54);
        let sender = DID("did:example:velocity-sender".to_owned());
        let sender_for_closure = sender.clone();

        cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
            let mut gov = view.governance_class_c_mut();
            let vt = gov.velocity_tracker_mut();
            vt.record_message(&sender_for_closure, 1_700_000_000);
        });

        assert_eq!(
            cell.governance
                .velocity_tracker
                .get_velocity(&sender, 1_700_000_000),
            1,
            "velocity message recorded through velocity_tracker_mut"
        );
    }

    /// `GovernanceClassCMut::budget_tracker_mut` hands out a `&mut` to the
    /// per-member budget tracker; a grant is observable on the underlying
    /// `cell.governance.budget_tracker`.
    #[tokio::test]
    async fn best_effort_budget_tracker_mut_grants_through_view() {
        use scp_protocol::economy::types::Amount;

        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x55));
        let ctx = ctx_hex(0x55);
        let member = DID("did:example:budget-member".to_owned());
        let member_for_closure = member.clone();

        cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
            view.governance_class_c_mut()
                .budget_tracker_mut()
                .grant(&member_for_closure, Amount(500));
        });

        assert_eq!(
            cell.governance.budget_tracker.remaining(&member),
            Amount(500),
            "budget grant landed through budget_tracker_mut"
        );
    }

    /// `GovernanceClassCMut::economic_policy_mut` hands out a `&mut Option<…>`;
    /// setting it to `Some(policy)` is observable on the underlying
    /// `cell.governance.economic_policy`.
    #[tokio::test]
    async fn best_effort_economic_policy_mut_sets_through_view() {
        use scp_protocol::economy::types::{CostSchedule, CurrencyCode};

        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x56));
        let ctx = ctx_hex(0x56);

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID("did:example:payee".to_owned()),
        };
        let expected = policy.clone();

        cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
            *view.governance_class_c_mut().economic_policy_mut() = Some(policy);
        });

        assert_eq!(
            cell.governance.economic_policy,
            Some(expected),
            "economic policy set through economic_policy_mut"
        );
    }

    /// `ClassCMut::receive_buffer_mut` hands out a `&mut ReceiveBuffer`; a pushed
    /// event is observable on the underlying `cell.receive_buffer`.
    #[tokio::test]
    async fn best_effort_receive_buffer_mut_pushes_through_view() {
        use scp_protocol::context::membership::ContextEvent;

        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x57));
        let ctx = ctx_hex(0x57);

        let before = cell.receive_buffer.len();

        cell.commit_class_c_best_effort(&deps, &ctx, |mut view| {
            view.receive_buffer_mut().push(ContextEvent::MemberLeft {
                member_did: DID("did:example:left".to_owned()),
            });
        });

        assert_eq!(
            cell.receive_buffer.len(),
            before + 1,
            "event pushed through receive_buffer_mut"
        );
    }

    /// `ClassCMut::role_state_mut` hands out a `&mut ContextRoleState`; a member
    /// inserted into its `members` set is observable on the underlying
    /// `cell.role_state`.
    #[tokio::test]
    async fn best_effort_role_state_mut_mutates_through_view() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x58));
        let ctx = ctx_hex(0x58);
        let member_did = "did:example:role-member".to_owned();
        let member_for_assert = member_did.clone();

        cell.commit_class_c_best_effort(&deps, &ctx, move |mut view| {
            view.role_state_mut().members.insert(member_did);
        });

        assert!(
            cell.role_state.members.contains(&member_for_assert),
            "member inserted through role_state_mut"
        );
    }

    // ------------------------------------------------------------------
    // new / into_inner
    // ------------------------------------------------------------------

    /// `into_inner` returns the wrapped state with mutations intact, and `Deref`
    /// reads see the same state.
    #[tokio::test]
    async fn into_inner_returns_wrapped_state() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x61));
        let ctx = ctx_hex(0x61);
        let saga_a = saga("saga-unwrap");

        cell.commit_class_s_keep(&deps, &ctx, |mut view| {
            view.class_s_mut()
                .saga_pending
                .insert(saga_a.clone(), prepared_invocation());
            Ok(())
        })
        .expect("persist succeeds");
        // Read through Deref before unwrap.
        assert!(cell.saga_pending().contains_key(&saga_a));

        let state = cell.into_inner();
        assert!(
            state.saga_pending().contains_key(&saga_a),
            "into_inner preserves the committed mutation"
        );
    }
}
