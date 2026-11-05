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
//! This invariant is now enforced **by the type system** for the THREE privatized
//! Class-S fields (`PerContextState.class_s`, `GovernanceState.class_s`,
//! `GovernanceState.revoked_spending_ucan_cids`). The original enforcement was a
//! source-text scanner (`scripts/check-class-s-fail-closed.sh`) which
//! pattern-matched handler bodies for "mutate then persist_fail_closed." A
//! source-text scanner is structurally non-convergent: every new way to alias a
//! `&mut PerContextState` (extern-fn, `&mut`-alias, ref-mut-destructure,
//! autoref-method) was a fresh evasion, and the gate had to grow a new pattern to
//! catch each one. That scanner has been **RETIRED**: this file's `ClassSCell`
//! (no `DerefMut`, no `state_mut` escape hatch) plus the privatized Class-S fields
//! make a mutation of those three fields outside a fail-closed-persisting
//! combinator a **compile error**, and a bounded positive-allowlist tripwire test
//! (`class_s_no_persist_mutator_whitelist_is_bounded`, this module's test
//! submodule) guards the one sanctioned no-persist Class-S method against a NEW
//! no-persist mutator being added later. For those three fields the compile-time
//! guard + the whitelist together cover what the scanner covered, soundly and
//! convergently. The scanner ALSO had markers for the dual-use
//! `ContextRoleState.ceiling` / `suspended_capabilities` downward-auth pair and
//! for `MembershipState::remove_member`; member removal IS now behind the boundary
//! (the best-effort views withhold `remove_member` and removal routes through a
//! fail-closed combinator). The `ceiling` / `suspended_capabilities` pair is now
//! CLOSED on both axes: the BEHAVIORAL §9 hole is persisted fail-closed by the
//! cell-holding caller (RED-CS3), AND the STRUCTURAL residual is gone — the
//! whole-`&mut` `role_state_mut` accessor is deleted, the fields are privatized to
//! `pub(crate)` (cross-crate seam: `ContextRoleState::class_c_parts`), and the
//! FIELD-GRANULAR best-effort role view (`RoleStateClassCMut`) exposes no
//! downward-auth GROW accessor (`suspend_capabilities` / `suspend_all`) — so a GROW
//! through THAT view is a compile error. (The GROW direction is not gone: it is
//! reachable via the consequence-only view and the inherent `pub`
//! `ContextRoleState::suspend_*` behind a whole `&mut`, each persisted fail-closed
//! by its combinator/caller — see the dedicated section below.)
//!
//! # The mechanism
//!
//! [`ClassSCell`] owns the [`PerContextState`] and exposes:
//!
//! - **Reads** via [`Deref`] — `&*cell` / `cell.<field>` yields `&PerContextState`.
//!   There is deliberately **no [`DerefMut`](std::ops::DerefMut)**: you cannot obtain a
//!   `&mut PerContextState` by writing `&mut cell.<field>` or `*cell = …`. That is
//!   the compile-time hook, and it is now in force for the THREE privatized
//!   Class-S fields (`PerContextState.class_s`, `GovernanceState.class_s`, and
//!   `GovernanceState.revoked_spending_ucan_cids` are `pub(in crate::context)`):
//!   with no `state_mut` escape hatch, the only way to mutate THOSE THREE FIELDS
//!   is through the combinators below, each of which performs the fail-closed
//!   persist by construction. (The dual-use `ContextRoleState.ceiling` /
//!   `suspended_capabilities` Class-S pair is now privatized to `pub(crate)` and
//!   GROW-confined to the consequence-only view — see the dedicated section below.)
//! - **Mutation through a combinator** — every combinator hands `f` a *view*
//!   (`ClassSMut` for the Class-S-capable combinators, `ClassCMut` for the
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
//! [`GovernanceClassCMut`]) close this by holding ONLY FIELD-GRANULAR
//! references — never a whole `&mut PerContextState` or `&mut GovernanceState`.
//! On construction each view destructures the `&mut` it is built from into a
//! `&mut` per writable Class-C / structural field plus a shared `&` to the
//! Class-S sub-structs (and `membership`). Because no whole-bucket `&mut` is
//! held anywhere, there is NOTHING of type `&mut PerContextState` /
//! `&mut GovernanceState` / `&mut ClassSState` / `&mut GovernanceClassS` for any
//! accessor to return — a future "convenience" accessor like
//! `fn rest_mut(&mut self) -> &mut PerContextState` simply cannot be written, so
//! a Class-S mutation on the best-effort / compensation path is a COMPILE error.
//! This is STRUCTURAL, not a convention to be followed: it does not rely on
//! field privatization — and could not, because the combinator module and the
//! handler modules are co-descendants of `context::actor`, so no `pub(in PATH)`
//! visibility separates them (a handler could always name `class_s` through a
//! whole-struct `&mut` if one were ever handed out — but none is). Field
//! privatization (`PerContextState.class_s` / `GovernanceState.class_s` are now
//! `pub(in crate::context)`) closes the LAST whole-`&mut` reach that DID exist —
//! the deleted `ClassSCell::state_mut` escape hatch and `ClassSMut`'s
//! `pub(crate)` reach — NOT this view, which was already airtight.
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
//! These combinators are deliberately the set for the **common** Class-S
//! persist/rollback shapes, not an exhaustive cover of every call site. The
//! Class-S-capable ones span the *keep / restore* × *no-Class-C-undo /
//! Class-C-(or-external)-undo* grid — `*_keep` (keep, no undo), `*_restore`
//! (restore, no undo), `*_keep_compensating` (keep, undo C/external),
//! `*_compensating` (restore, undo C/external) — plus `*_then_append` for the
//! one extra shape of a fail-closed persist FOLLOWED BY an external durable
//! append (event-log) that can itself fail, and `*_keep_restore_split` for a
//! single fail-closed persist that KEEPs one Class-S field while RESTOREing
//! another (the `prepare_b` decomposition shape). `commit_class_c_best_effort`
//! covers the Class-C best-effort path. They are chosen because they are the
//! shapes that recur; they are NOT proof that every site fits one of them.
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
//! For the three PRIVATIZED Class-S fields — `PerContextState.class_s`,
//! `GovernanceState.class_s`, and `GovernanceState.revoked_spending_ucan_cids` —
//! the boundary is now in force: every mutation of them routes through a
//! combinator (or the single sanctioned no-persist
//! [`ClassSCell::clear_committed_reservation_idempotent`]). The temporary
//! `state_mut` escape hatch has been DELETED, those fields are privatized, and
//! there is no `DerefMut` — so the compiler, not this prose, enforces that every
//! mutation of them is fail-closed-persisted. The text scanner
//! (`scripts/check-class-s-fail-closed.sh`) is retired in favour of this
//! compile-time guarantee plus the bounded whitelist tripwire described below.
//!
//! # The dual-use `ContextRoleState` downward-auth fields — CLOSED
//!
//! ADR-049 §9 also classifies the **downward-authorization** fields
//! `ContextRoleState.ceiling` and `ContextRoleState.suspended_capabilities` as
//! Class-S (a coalesce-window rollback of a ceiling tightening or a capability
//! suspension re-widens authority the caller observed as narrowed). Both the
//! BEHAVIORAL hole AND the prior STRUCTURAL residual are now **CLOSED**:
//!
//! - **Behavioral (RED-CS3):** when consequence enforcement applies a downward-auth
//!   mutation (a `suspended_capabilities` GROW or an `AssignRole`
//!   `member_capabilities` demotion),
//!   `scp_runtime_governance::logic::enforce_triggered_consequences` returns a
//!   downward-auth flag and the cell-holding caller persists the already-applied
//!   mutation **fail-closed** (keep-direction) before acking, in every production
//!   consequence site (send / receive / outlet-settle / periodic sweep; governance
//!   execution was already fail-closed via its `ClassSCommitToken`). Consequence
//!   EVALUATION stays best-effort / coalesced — only the rare downward-auth OUTCOME
//!   is fail-closed.
//! - **Structural (BLACK-CS-03):** the whole-`&mut` `ClassCMut::role_state_mut`
//!   accessor is **DELETED**. The best-effort surface now hands out only the
//!   field-granular [`RoleStateClassCMut`] (via [`ClassCMut::role_state_class_c_mut`]
//!   and [`ClassCSplit::role_state`]), which exposes `ceiling` READ-ONLY, the
//!   suspension map through a SHARED read + the SHRINK-only
//!   `prune_suspensions_to_role_grants`, structural `&mut`, and a
//!   `system_assign_role` that mints over its own fields — **NO** downward-auth
//!   GROW accessor (`suspend_capabilities` / `suspend_all`). So a caller holding a
//!   `RoleStateClassCMut` (or a [`ClassCSplit`]) cannot perform a downward-auth
//!   GROW — the GROW method does not exist on THAT type. The load-bearing barrier
//!   is the PRIVATE Class-S fields + `!DerefMut` (no external `&mut` to the
//!   downward-auth maps), NOT a compile-witness over method resolution; a
//!   maintainer adding a new `&mut self` GROW method to this impl in-file is an
//!   in-file-insider residual, a code-review responsibility (see the honest §9
//!   structural account in the test submodule).
//!
//!   This is a STRUCTURAL property of the field-granular role view, NOT a global
//!   claim that "a GROW lives nowhere else." There are TWO real GROW paths, each
//!   §9-safe by the OBLIGATION of the combinator/caller that reaches it (NOT by
//!   impossibility):
//!   - **(A) the consequence-only view.** [`ClassCMut::consequence_split`] (itself
//!     reachable from the best-effort `ClassSCell::class_c_view`) yields a
//!     [`ConsequenceRoleStateMut`], the role view that DOES expose
//!     `suspend_capabilities` / `suspend_all`. A `ClassCMut` holder CAN therefore
//!     reach a GROW — and the §9 guarantee is that the consequence caller persists
//!     the applied GROW FAIL-CLOSED (RED-CS3), not that the GROW is unreachable.
//!   - **(B) the inherent `pub` GROW.** `ContextRoleState::suspend_capabilities` /
//!     `suspend_all` are inherent `pub` methods reachable through ANY whole
//!     `&mut ContextRoleState` — e.g. `ClassSMut::rest_mut`, used by the
//!     governance helpers. That whole-`&mut` is handed out only by a
//!     fail-closed-PERSISTING combinator, so the GROW it can reach is persisted
//!     fail-closed by construction.
//!
//!   The structural part is narrower-and-exact: the FIELD-GRANULAR best-effort role
//!   view has no GROW accessor (a real compile-time guarantee). It is NOT that a
//!   GROW exists nowhere — paths (A) and (B) exist and are made safe by the
//!   persist obligation of the combinator/consequence caller that reaches them.
//!
//! The `ContextRoleState.ceiling` / `suspended_capabilities` fields (and
//! `CapabilityCeiling.capabilities`) are now **privatized** to `pub(crate)` in
//! `scp-protocol`; the cross-crate seam is [`scp_protocol::context::roles::ContextRoleState::class_c_parts`],
//! which hands `scp-runtime`'s field-granular views the disjoint refs (ceiling
//! shared `&`) without naming the private fields. The whole-ceiling WRITE is the
//! named [`scp_protocol::context::roles::ContextRoleState::set_ceiling`] mutator,
//! reachable only behind a whole `&mut ContextRoleState` — which, post-deletion of
//! `role_state_mut`, exists in production only inside a fail-closed-persisting
//! combinator (the single ceiling-modification site routes through
//! `commit_class_s_keep`).
//!
//! REMAINING structural-field surface (consciously deferred, NOT claimed closed):
//! `ContextRoleState.assignments` / `members` / `member_capabilities` /
//! `role_definitions` stay `pub` (Class-C structural, not the downward-auth
//! residual); privatizing them too is a larger follow-up.
//!
//! # Final enforcement model
//!
//! Most combinators now have production callers. Only two —
//! [`ClassSCell::commit_class_s_compensating`] and
//! [`ClassSCell::commit_class_s_then_append`] — have no production caller yet and
//! retain `#[allow(dead_code)]`; they are exercised by this module's unit tests
//! and wired when a site with their exact crash/atomicity shape migrates. The
//! compile-time guarantee does NOT depend on any handler being migrated — it is a
//! property of `ClassSCell`'s shape (no `DerefMut`, no `state_mut`, private
//! Class-S fields): a caller can obtain `&mut` to one of the three PRIVATIZED
//! Class-S fields only through the view a combinator constructs, and the
//! best-effort views hold no `&mut` to them, so the only `&mut` to those fields
//! originates inside a persisting `ClassSCell` method. (The dual-use
//! `ContextRoleState.ceiling` / `suspended_capabilities` downward-auth fields are
//! now privatized per the section above; the whole-`&mut` `role_state_mut` accessor
//! is deleted, so the FIELD-GRANULAR best-effort role view can no longer name a
//! downward-auth GROW — a GROW through that view is a compile error. The GROW
//! direction is not eliminated: it remains reachable via the consequence-only view
//! and the inherent `pub` `ContextRoleState::suspend_*` behind a whole `&mut`, each
//! persisted fail-closed by its combinator/caller.)
//!
//! The ONE remaining `&mut self` method on `ClassSCell` that mutates Class-S
//! WITHOUT a fail-closed persist is
//! [`ClassSCell::clear_committed_reservation_idempotent`] (a single named,
//! idempotent straggler cleanup whose §9 safety argument is on the method). A
//! bounded positive-allowlist test —
//! `class_s_no_persist_mutator_whitelist_is_bounded` — asserts the set of such
//! methods is EXACTLY the known-safe set, so a NEW no-persist Class-S mutator
//! added later trips it. This replaces the retired text scanner: it is a closed
//! whitelist (not an ever-growing denylist), so it is sound and convergent.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::Deref;

use super::deps::ActorDeps;
use super::state::{
    ClassSState, ContextEventLog, ContextLifecycleState, ContextModeState, ContextRouting,
    PerContextState, RecvSequenceTracker, WelcomeProcessing,
};
use crate::context::ContextHandle;
use scp_runtime_types::context::actor::sequence::SendSequenceTracker;
use scp_runtime_types::context::governance::timeout::DeadlockDetectionState;

use crate::context::snapshot::persist_state_best_effort;
use crate::context::snapshot::persist_state_fail_closed;
use crate::context::state::{
    AccessControlState, CommitFaultMarker, EpochState, GovernanceClassS, GovernanceState,
    MigrationState, PendingCeilingModification, PendingCommit, PendingEconomicPolicyChange,
    TtlState,
};
use scp_did::DID;
use scp_event_log::checkpoint::ConsistencyCheckpoint;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::{
    BroadcastContext as ProtocolBroadcastContext, BroadcastContextClassCParts,
    BroadcastPublishMetadata, BroadcastPublishReservation, ReservedPublishApply,
    SubscriptionResult, UnblockResult, UnsubscribeResult,
};
use scp_protocol::context::governance::{
    GovernanceEngine, GovernanceProposal, ProposalId, PruningPolicy,
};
use scp_protocol::context::membership::{MemberInfo, MembershipState, ReceiveBuffer};
use scp_protocol::context::outlets::interface::OutletInterface;
use scp_protocol::context::params::OutletRegistration;
use scp_protocol::context::roles::{
    Capability, CapabilityCeiling, ContextRoleClassCParts, ContextRoleState, RoleAssignment,
    RoleDefinition, RoleError, UcanToken,
};
use scp_protocol::crypto::ucan::validate::InMemoryProofResolver;
use scp_protocol::economy::antispam::{
    ContextMessagePricingConfig, SenderVelocityTracker, TokenBucketLimiter,
};
use scp_protocol::economy::budget::MemberBudgetTracker;
use scp_protocol::economy::types::EconomicPolicy;
use scp_protocol::envelope::{ReorderBuffer, SequenceTracker};
use scp_protocol::trust::consequence::ConsequenceRule;
use scp_protocol::trust::participation::ParticipationRecord;
use scp_runtime_types::economy::adapter::PaymentReceipt;

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
pub struct ClassSMut<'a> {
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
    pub const fn class_s_mut(&mut self) -> &mut ClassSState {
        &mut self.state.class_s
    }

    /// `&mut` access to the governance Class-S sub-struct ([`GovernanceClassS`]):
    /// `executed_proposals`, `threshold_signers`, `threshold_value`, and the
    /// `spending_nonce_tracker` (ADR-049 §9). Reached through the `governance`
    /// field; the owning combinator persists fail-closed.
    pub const fn governance_class_s_mut(&mut self) -> &mut GovernanceClassS {
        &mut self.state.governance.class_s
    }

    /// `&mut` access to the rest of [`PerContextState`] (and, in principle, the
    /// Class-S sub-structs, which this whole-`&mut` can also reach). This accessor
    /// exists so a handler can mutate the structural / Class-C portion of the
    /// state from inside a Class-S combinator without a second borrow. It is sound
    /// even though it can reach Class-S because the combinator that hands out this
    /// (Class-S-capable) view persists **fail-closed** — see the naming note
    /// below. The Class-S fields are now privatized to `pub(in crate::context)`, so
    /// this `ClassSMut` view (and the persisting combinators it belongs to) is the
    /// sanctioned mutation path; the airtight best-effort [`ClassCMut`] view holds
    /// no `&mut` to Class-S at all.
    ///
    /// # This whole-`&mut` reaches the inherent downward-auth GROW (path B)
    ///
    /// The returned `&mut PerContextState` includes a whole `&mut ContextRoleState`
    /// (`state.role_state`), through which the INHERENT `pub`
    /// [`scp_protocol::context::roles::ContextRoleState::suspend_capabilities`] /
    /// [`suspend_all`](scp_protocol::context::roles::ContextRoleState::suspend_all)
    /// downward-auth GROW are reachable (this is the "path B" the module docs
    /// describe; the governance helpers use it). That is §9-safe HERE for the same
    /// reason the rest of this `&mut` is: the combinator that hands out this
    /// `ClassSMut` view persists **fail-closed**, so any downward-auth GROW applied
    /// through it is durable before the operation acks. It is NOT structurally
    /// confined away — the confinement is the field-granular best-effort
    /// [`RoleStateClassCMut`] view (which exposes no GROW accessor); a whole
    /// `&mut ContextRoleState` deliberately CAN reach the inherent GROW, and is only
    /// ever handed out inside a fail-closed-persisting combinator (NEVER on the
    /// best-effort / coalesced path).
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
    /// **may NOT** hand out such a `&mut`, and CANNOT have a `rest_mut` (or a
    /// `governance_mut`): it holds no whole `&mut PerContextState` /
    /// `&mut GovernanceState`, only field-granular references (a `&mut` per
    /// Class-C field, a shared `&` to Class-S). There is therefore no value of
    /// that type for such an accessor to return — a Class-S mutation on the
    /// best-effort / compensation path is a COMPILE error by construction,
    /// independent of any future field privatization. The asymmetry is the whole
    /// point: the view that persists fail-closed holds the whole `&mut` and may
    /// reach Class-S; the view that does not persist fail-closed holds no whole
    /// `&mut` and so structurally cannot.
    pub const fn rest_mut(&mut self) -> &mut PerContextState {
        self.state
    }

    /// The three disjoint Class-C `&mut` fields the MLS-Commit broadcast-failure
    /// apply (`scp_runtime_governance::helpers::apply_broadcast_failure`)
    /// mutates, bundled so a caller can pass all three at once. The MIRROR of
    /// [`ClassCMut::commit_broadcast_borrows`], but supplied from this
    /// Class-S-capable view so the apply rides the owning combinator's
    /// **fail-closed** persist: the safety-gated commit-broadcast sites
    /// (`scp_runtime_governance::helpers::keep_broadcast_failure`) build the
    /// borrows HERE — inside a `commit_class_s_keep` closure — rather than through
    /// the coalesced `ClassCMut` view, so the `commit_fault` safety gate and the
    /// `pending_commits` retry entry survive a crash before the ≤50 ms persist
    /// tick. Each is a distinct field of the underlying `PerContextState`, so the
    /// simultaneous `&mut` is sound by construction.
    pub const fn commit_broadcast_borrows(&mut self) -> CommitBroadcastBorrows<'_> {
        CommitBroadcastBorrows {
            pending_commits: &mut self.state.pending_commits,
            commit_fault: &mut self.state.commit_fault,
            receive_buffer: &mut self.state.receive_buffer,
        }
    }
}

impl Deref for ClassSMut<'_> {
    type Target = PerContextState;

    /// Immutable reads of the whole state.
    fn deref(&self) -> &PerContextState {
        self.state
    }
}

/// SHARED, READ-ONLY wrapper around a `&ClassSState` (ADR-049 §9 / BLACK-CS-01).
///
/// Holds the actor's Class-S sub-struct as a PRIVATE shared reference. It exposes
/// ONLY [`Self::get`] (a `&ClassSState` read) — there is NO `&mut` accessor and
/// NO [`DerefMut`](std::ops::DerefMut). [`ClassCMut`] stores its Class-S reach as a `SharedClassS`
/// rather than a bare `&'a ClassSState` so that re-arming a `&mut` to Class-S on
/// the best-effort view requires THREE conspicuous central edits — the
/// `ClassCMut.class_s` field type, this wrapper's private field, AND
/// [`Self::new`]'s parameter — not a single-token flip of one binding. Each is a
/// load-bearing central edit a reviewer sees; the structural shape (private field,
/// no `&mut`/`DerefMut`) is the actual guarantee, backstopped by the crate-root
/// `#![forbid(unsafe_code)]` (no `*const _ as *mut _` escape).
///
/// This is the structural answer to BLACK-CS-01 (the old `compile_fail` doctest
/// was a decoupled mirror that did NOT track a real-field flip). The companion
/// `assert_not_impl_any!(SharedClassS<'static>: DerefMut)` (this module's test
/// submodule) is the compile-time witness.
pub(crate) struct SharedClassS<'a>(&'a ClassSState);

impl<'a> SharedClassS<'a> {
    /// Wrap a shared `&ClassSState` (the ONLY constructor; takes a shared `&`, so
    /// no `&mut` to Class-S can enter the wrapper here).
    pub(crate) const fn new(class_s: &'a ClassSState) -> Self {
        Self(class_s)
    }

    /// The ONLY accessor — a shared `&ClassSState` read. There is deliberately no
    /// `&mut` counterpart, so a Class-S mutation through this wrapper is a COMPILE
    /// error by construction.
    pub(crate) const fn get(&self) -> &ClassSState {
        self.0
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
/// # Airtight BY CONSTRUCTION — no whole `&mut PerContextState` to return
///
/// The combinator module (`context::actor::class_s`) and the handler modules
/// (`context::actor::handlers::*`) are co-descendants of `context::actor`; no
/// `pub(in PATH)` visibility separates them, so field privatization could NOT
/// make the Class-S fields unnameable from a handler — a handler could always
/// write `view.rest_mut().class_s…` or `view.governance_mut().class_s…` if those
/// accessors existed and returned a whole `&mut`. This view closes that
/// STRUCTURALLY rather than by convention: it does not hold a whole
/// `&mut PerContextState` at all. On construction it destructures the underlying
/// `&mut PerContextState` ONCE into disjoint field references — a `&mut` to each
/// writable Class-C / structural field (including the `membership` roster, whose
/// only mutable reach is the restricted [`MembershipClassCMut`] sub-view — no
/// `remove_member`, the downward-auth Class-S removal), a `&` (shared,
/// read-only) to the Class-S [`ClassSState`], and a [`GovernanceClassCMut`]
/// sub-view for the Class-C governance fields. There is therefore NO whole
/// `&mut PerContextState`, no `&mut GovernanceState`, no `&mut ClassSState`, and
/// no `&mut GovernanceClassS` held anywhere — so a future "convenience"
/// accessor like `fn rest_mut(&mut self) -> &mut PerContextState` CANNOT be
/// written (there is nothing of that type to return), and a Class-S mutation
/// from this view is a COMPILE error by construction. Reads of `class_s` go
/// through the field-granular `&`-returning read accessor [`Self::class_s`]
/// (there is no whole-state [`Deref`]); reads don't mutate, so a shared `&` to
/// Class-S cannot violate the invariant.
///
/// # The Class-S reach is the read-only `SharedClassS` wrapper (BLACK-CS-01)
///
/// `ClassCMut.class_s` is a `SharedClassS` — a wrapper holding a PRIVATE
/// `&ClassSState`, with NO `&mut` accessor and NO [`DerefMut`](std::ops::DerefMut). So the only Class-S
/// reach on this best-effort view is the shared read [`Self::class_s`]
/// (`self.class_s.get()`); there is no `&mut` to the actor's `ClassSState`
/// anywhere, and a Class-S mutation from this view is a COMPILE error by
/// construction.
///
/// Re-arming a `&mut` here is NOT a one-token flip: it requires editing the
/// `class_s` field TYPE here, AND `SharedClassS`'s private field, AND
/// `SharedClassS::new`'s parameter — three conspicuous central edits a reviewer
/// sees. The load-bearing guarantee is that structural shape (private field, no
/// `&mut`/`DerefMut`), witnessed at compile time by
/// `assert_not_impl_any!(SharedClassS<'static>: DerefMut)` in this module's test
/// submodule. (Per `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`,
/// the structural wrapper + assert is the guarantee; an illustrative doctest is a
/// demoted, accurate signpost — NOT a decoupled mirror that can drift from a real
/// field flip, which is the BLACK-CS-01 defect this replaces.)
///
/// # Disjoint-borrow support (`ConsequenceStateSplit`)
///
/// [`crate::context::actor::class_s::ConsequenceStateSplit`] needs FIVE
/// simultaneous disjoint borrows of distinct [`PerContextState`] fields
/// (`governance`, `&mut role_state`, `&membership`, `&mut receive_buffer`,
/// `&mut checkpoint_events_since`). The view ALREADY holds these as disjoint
/// field references (the construction destructured them apart), so
/// [`Self::split_class_c`] simply reborrows them into a [`ClassCSplit`] — all
/// five live simultaneously (with the governance reference wrapped in a
/// [`GovernanceClassCMut`] so it, too, cannot reach Class-S).
pub struct ClassCMut<'a> {
    /// `&mut` to the active-member DID set (Class-C / structural).
    members: &'a mut HashSet<DID>,
    /// `&mut` to the receive event buffer (Class-C / structural).
    receive_buffer: &'a mut ReceiveBuffer,
    /// `&mut` to the role / ceiling / assignment state (Class-C / structural).
    role_state: &'a mut ContextRoleState,
    /// `&mut` to the checkpoint counter (Class-C / structural).
    checkpoint_events_since: &'a mut u64,
    /// `&mut` to the monotonic generation counter (Class-C / structural).
    generation: &'a mut u64,
    /// `&mut` to the full-fat context handle (Class-C / structural).
    handle: &'a mut ContextHandle,
    /// `&mut` to the optional Merkle event log (Class-C / structural).
    event_log: &'a mut Option<ContextEventLog>,
    /// `&mut` to the bounded payment-receipt ring buffer (Class-C / §19.11).
    payment_receipts: &'a mut VecDeque<PaymentReceipt>,
    /// `&mut` to the optional broadcast-mode metadata (Class-C / §5.14).
    broadcast_context: &'a mut Option<ProtocolBroadcastContext>,
    /// `&mut` to the optional active migration state (Class-C / §5.11A).
    migration_state: &'a mut Option<MigrationState>,
    /// `&mut` to the MLS epoch + reconnection state (Class-C / §5.9, §23.11).
    epoch: &'a mut EpochState,
    /// `&mut` to the access-control / CEK-wrapping exclusion state (Class-C).
    access: &'a mut AccessControlState,
    /// `&mut` to the TTL timer + extension state (Class-C / SCP-021).
    ttl: &'a mut TtlState,
    /// `&mut` to the per-context routing strategy (Class-C / §9.10.4, §5.14).
    routing: &'a mut ContextRouting,
    /// `&mut` to the per-sender anti-replay sequence tracker (Class-C / §9.8.2).
    sequence_tracker: &'a mut SequenceTracker,
    /// `&mut` to the per-sender reorder buffer (Class-C / §9.8.5).
    reorder_buffer: &'a mut ReorderBuffer,
    /// `&mut` to the MLS Commit retry queue (Class-C / §9.9.3).
    pending_commits: &'a mut VecDeque<PendingCommit>,
    /// `&mut` to the commit-fault fail-close marker (Class-C / structural).
    commit_fault: &'a mut Option<CommitFaultMarker>,
    /// `&mut` to the last-checkpoint timestamp (Class-C / §9.9.3).
    checkpoint_last_time_secs: &'a mut u64,
    /// `&mut` to the locally generated consistency checkpoints (Class-C / §9.9.3).
    checkpoints: &'a mut Vec<ConsistencyCheckpoint>,
    /// `&mut` to the per-sender remote-checkpoint divergence dedup set (Class-C /
    /// §9.9.3). Receiver-minted equivocation evidence, NOT a sender-authenticated
    /// replay witness — coalesce-window rollback re-emits at most one bounded
    /// duplicate alert, so best-effort is acceptable.
    last_seen_remote_checkpoint: &'a mut HashMap<DID, HashSet<(u64, [u8; 32])>>,
    /// `&mut` to the send-sequence counter with RAII rollback (Class-C).
    send_tracker: &'a mut SendSequenceTracker,
    /// `&mut` to the per-sender receive-sequence high-water marks (Class-C).
    recv_tracker: &'a mut RecvSequenceTracker,
    /// `&mut` to the reconstructable cross-context UCAN proof store (Class-C /
    /// §6.2.4). Interface state repopulated when the outlet interface is
    /// re-established — explicitly NOT the Class-S freshness/replay witness.
    xctx_ucan_proofs: &'a mut InMemoryProofResolver,
    /// `&mut` to the multi-step Welcome scratchpad (Class-C / structural).
    welcome_scratchpad: &'a mut Option<WelcomeProcessing>,
    /// `&mut` to the actor-internal lifecycle state (Class-C / structural).
    lifecycle_state: &'a mut ContextLifecycleState,
    /// `&mut` to the mode-specific state (Class-C / structural).
    mode: &'a mut ContextModeState,
    /// `&mut` to the authoritative membership roster (Class-C / structural).
    /// `MembershipState` contains NO Class-S sub-struct — member REMOVAL is a
    /// downward-auth Class-S *operation*, not a Class-S *field* — so a `&mut` to
    /// the roster is safe to hold HERE PROVIDED the only mutable reach exposed
    /// is the restricted [`MembershipClassCMut`] sub-view (no `remove_member`,
    /// no whole `&mut`); see [`Self::membership_class_c_mut`]. The consequence /
    /// `split_class_c` path reborrows it SHARED (`&*`), so its read-only use is
    /// unchanged.
    membership: &'a mut MembershipState,
    /// Shared, read-only Class-S [`ClassSState`] reach — wrapped in
    /// [`SharedClassS`] (a private-field wrapper with NO `&mut` accessor, NO
    /// `DerefMut`), so reads work without a whole-state `Deref` and a Class-S
    /// MUTATION is structurally impossible (BLACK-CS-01). Re-arming a `&mut` here
    /// requires editing the field type AND `SharedClassS`'s field AND
    /// `SharedClassS::new` — three conspicuous central edits, not a one-token flip.
    class_s: SharedClassS<'a>,
    /// Field-granular Class-C governance sub-view (holds no whole
    /// `&mut GovernanceState`, no `class_s` reach).
    governance: GovernanceClassCMut<'a>,
}

/// FIELD-GRANULAR best-effort view over a [`ProtocolBroadcastContext`]'s Class-C
/// publish / roster surface (ADR-049 §9, §5.14.8 mutation-surface confinement).
///
/// Produced by [`ClassCMut::broadcast_class_c_mut`]. Mirrors [`RoleStateClassCMut`]:
/// it holds the [`BroadcastContextClassCParts`] DISJOINT field refs (NOT a whole
/// `&mut BroadcastContext`) and forwards ONLY the benign publish-path / roster
/// methods. The downward-authorization security mutators (`block_subscriber`,
/// `block_author`, `governance_ban_subscriber`, `rotate_all_author_keys`) are
/// inherent `&mut self` on `BroadcastContext` and are deliberately NOT forwarded
/// here — they are reachable only through a whole `&mut BroadcastContext` a
/// fail-closed combinator hands out via [`ClassSMut::rest_mut`]. Because this view
/// holds no whole `&mut`, a future "convenience" accessor returning one CANNOT be
/// written; the load-bearing guarantee is the PRIVATE [`AuthorState`] security
/// fields plus `ClassSCell: !DerefMut`.
///
/// Precision: "benign" here means SAFE-DIRECTION, NOT "never touches the security
/// fields". Two forwarded methods DO write them: `unsubscribe(rotate_keys = true)`
/// advances `epoch` and installs a fresh `broadcast_key` (forward-only rotation; a
/// coalesce-window rollback returns to "subscriber present under the old key",
/// never a re-grant), and `unblock_subscriber` clears an entry from `block_list`
/// (UPWARD re-grant; a rollback re-instates the block). Both are persisted
/// BEST-EFFORT and are safe precisely because a lost write only leaves authority
/// NARROWER than the caller observed. The fail-closed, must-survive-crash
/// guarantee (via the `n` keep-direction combinator) covers only the
/// REVOCATION-direction mutators (`block_subscriber` / `block_author` /
/// `governance_ban_subscriber` / `rotate_all_author_keys`), which are NOT
/// forwarded here. What this view structurally prevents is a *direct* private-
/// field write (the `#[F.2]` compile-fail witness) and any reach to that
/// revocation surface.
///
/// [`AuthorState`]: scp_protocol::context::broadcast::AuthorState
#[allow(
    dead_code,
    reason = "ADR-049 §9 / §5.14.8: the benign publish-path / roster forwards (`subscribe`, `unsubscribe`, `unblock_subscriber`, `reserve_publish`, `apply_reserved_publish`, `rollback_reserved_publish`, `publish`, `publish_metadata`, `context_id`) are exercised by the broadcast publish/roster helpers and this module's unit tests; the remainder gain callers as the broadcast handlers migrate fully onto the field-granular view."
)]
pub struct BroadcastContextClassCMut<'a> {
    /// The disjoint Class-C parts. PRIVATE: no accessor hands out `&mut authors`
    /// / `&mut subscribers` (either would re-open the `block_author` /
    /// registry-clear surface), so the only reach is the benign forwards below.
    parts: BroadcastContextClassCParts<'a>,
}

impl<'a> BroadcastContextClassCMut<'a> {
    /// Build the field-granular view by destructuring a `&mut BroadcastContext`
    /// through [`BroadcastContext::class_c_parts`](ProtocolBroadcastContext::class_c_parts).
    fn new(bc: &'a mut ProtocolBroadcastContext) -> Self {
        Self {
            parts: bc.class_c_parts(),
        }
    }

    /// Context identifier (structural identity).
    #[must_use]
    pub const fn context_id(&self) -> &str {
        self.parts.context_id()
    }

    /// Benign roster ADD. Forwards to [`BroadcastContextClassCParts::subscribe`].
    ///
    /// # Errors
    ///
    /// See [`BroadcastContextClassCParts::subscribe`].
    pub fn subscribe<D, N, R, P, S>(
        &mut self,
        subscriber_did: &str,
        ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        timestamp: u64,
        validation_ctx: Option<
            &mut scp_protocol::crypto::ucan::validate::ValidationContext<'_, D, N, R, P, S>,
        >,
    ) -> Result<SubscriptionResult, ContextError>
    where
        D: scp_protocol::crypto::ucan::validate::DidResolver,
        N: scp_protocol::crypto::ucan::validate::NonceTracker,
        R: scp_protocol::crypto::ucan::validate::RevocationChecker,
        P: scp_protocol::crypto::ucan::validate::ProofResolver,
        S: std::hash::BuildHasher,
    {
        self.parts
            .subscribe(subscriber_did, ucan, timestamp, validation_ctx)
    }

    /// Benign roster REMOVE (+ optional forward-secrecy rotation). Forwards to
    /// [`BroadcastContextClassCParts::unsubscribe`].
    ///
    /// # Errors
    ///
    /// See [`BroadcastContextClassCParts::unsubscribe`].
    pub fn unsubscribe(
        &mut self,
        subscriber_did: &str,
        rotate_keys: bool,
    ) -> Result<UnsubscribeResult, ContextError> {
        self.parts.unsubscribe(subscriber_did, rotate_keys)
    }

    /// UPWARD (re-grant) unblock — best-effort by design. Forwards to
    /// [`BroadcastContextClassCParts::unblock_subscriber`].
    ///
    /// # Errors
    ///
    /// See [`BroadcastContextClassCParts::unblock_subscriber`].
    pub fn unblock_subscriber(
        &mut self,
        author_did: &str,
        unblocked_did: &str,
    ) -> Result<UnblockResult, ContextError> {
        self.parts.unblock_subscriber(author_did, unblocked_did)
    }

    /// Benign publish signing metadata. Forwards to
    /// [`BroadcastContextClassCParts::publish_metadata`].
    ///
    /// # Errors
    ///
    /// See [`BroadcastContextClassCParts::publish_metadata`].
    pub fn publish_metadata(
        &self,
        author_did: &str,
    ) -> Result<BroadcastPublishMetadata<'_>, ContextError> {
        self.parts.publish_metadata(author_did)
    }

    /// Benign single-phase publish. Forwards to
    /// [`BroadcastContextClassCParts::publish`].
    ///
    /// # Errors
    ///
    /// See [`BroadcastContextClassCParts::publish`].
    pub fn publish(
        &mut self,
        author_did: &str,
        payload: &[u8],
        timestamp: u64,
        signature: ed25519_dalek::Signature,
        nonce: &[u8; 12],
        provenance: Option<scp_protocol::provenance::DataProvenance>,
    ) -> Result<scp_protocol::crypto::sender_keys::BroadcastEnvelope, ContextError> {
        self.parts
            .publish(author_did, payload, timestamp, signature, nonce, provenance)
    }

    /// Benign phase-1 reservation. Forwards to
    /// [`BroadcastContextClassCParts::reserve_publish`].
    ///
    /// # Errors
    ///
    /// See [`BroadcastContextClassCParts::reserve_publish`].
    pub fn reserve_publish(
        &mut self,
        author_did: &str,
    ) -> Result<BroadcastPublishReservation, ContextError> {
        self.parts.reserve_publish(author_did)
    }

    /// Benign phase-2 seal. Forwards to
    /// [`BroadcastContextClassCParts::apply_reserved_publish`].
    ///
    /// # Errors
    ///
    /// See [`BroadcastContextClassCParts::apply_reserved_publish`].
    pub fn apply_reserved_publish(
        &mut self,
        author_did: &str,
        payload: &[u8],
        nonce: &[u8; 12],
        apply: ReservedPublishApply,
    ) -> Result<scp_protocol::crypto::sender_keys::BroadcastEnvelope, ContextError> {
        self.parts
            .apply_reserved_publish(author_did, payload, nonce, apply)
    }

    /// Benign reservation rollback. Forwards to
    /// [`BroadcastContextClassCParts::rollback_reserved_publish`].
    pub fn rollback_reserved_publish(&mut self, author_did: &str, reserved_sequence: u64) {
        self.parts
            .rollback_reserved_publish(author_did, reserved_sequence);
    }
}

/// Simultaneously-held borrows for the §19 economy pre-check.
///
/// The §19 message economy pre-check needs a `&mut` to the per-member
/// `budget_tracker` (to debit) held AT THE SAME TIME as shared reads of the
/// `velocity_tracker`, `economic_policy`, `consequence_rules`, and
/// `message_pricing`. Returning these as one struct (rather than a sequence of
/// accessor calls) lets the caller hold the single `&mut` and the four `&`
/// reads concurrently without re-borrowing the view between them — every field
/// here is a DISJOINT borrow of a distinct [`GovernanceClassCMut`] field, so
/// the aliasing is sound by construction.
///
/// All fields are Class-C / structural: the `budget_tracker` debit it enables
/// is reversed by the economy-compensation hook when a persist does not land,
/// and the four reads are configuration / liveness state. This struct holds NO
/// reference into any Class-S sub-struct — it names only the Class-C fields the
/// [`GovernanceClassCMut`] already exposes individually.
#[allow(
    dead_code,
    reason = "ADR-049 §9 foundation: the simultaneous §19 economy pre-check borrows get their first PRODUCTION reader when the message-economy pre-check migrates onto `economy_pre_check_borrows`. Exercised by this module's unit tests now."
)]
pub struct EconomyPreCheckBorrows<'a> {
    /// `&mut` to the per-member cumulative budget tracker (§19.5) — the debit
    /// target of the pre-check.
    pub budget_tracker: &'a mut MemberBudgetTracker,
    /// Shared read of the per-sender velocity tracker (§19.7 anti-spam).
    pub velocity_tracker: &'a SenderVelocityTracker,
    /// Shared read of the mutable economic policy (§19.3).
    pub economic_policy: &'a Option<EconomicPolicy>,
    /// Shared read of the consequence rules declared at creation (ADR-017).
    pub consequence_rules: &'a [ConsequenceRule],
    /// Shared read of the per-DID escalating-cost message pricing config (§19.7).
    pub message_pricing: &'a Option<ContextMessagePricingConfig>,
}

/// RESTRICTED mutable view over the Class-C governance fields of a
/// [`GovernanceState`]. It holds those fields as SEPARATE field-granular
/// references — it does **not** hold a whole `&mut GovernanceState`, so there is
/// no whole-bucket `&mut` for any accessor to return and no way to reach
/// `governance.class_s` ([`GovernanceClassS`]).
///
/// Produced by [`ClassCMut::governance_class_c_mut`] and held by the
/// `governance` field of [`ClassCSplit`]. It is the governance counterpart of
/// [`ClassCMut`]'s airtightness: because the best-effort / compensation paths do
/// not persist fail-closed, they must not reach any Class-S-containing struct,
/// and `GovernanceState` CONTAINS one (`governance.class_s`). A whole
/// `&mut GovernanceState` would let a handler write `gov.class_s.threshold_value
/// = …` with no fail-closed persist; this view holds no such reference, so that
/// is a COMPILE error BY CONSTRUCTION, not merely a documented prohibition.
///
/// # Airtight BY CONSTRUCTION — no whole `&mut` to return
///
/// The struct destructures the `&mut GovernanceState` it is built from into
/// disjoint references the moment it is constructed: a `&mut` to each of the
/// four writable Class-C fields, plus a shared `&` to the `next_proposal_seq`
/// counter that callers read. There is therefore no whole-bucket `&mut`
/// anywhere in the view, and no `class_s` reference at all — so a future
/// "convenience" accessor like `fn gov_mut(&mut self) -> &mut GovernanceState`
/// CANNOT be written (there is nothing of that type to return). Reads of
/// Class-C fields go through the field-granular `&`-returning read accessors
/// ([`Self::next_proposal_seq`]); there is no [`Deref`] to the whole bucket.
///
/// This safe-Rust guarantee is backstopped by the crate-root
/// `#![forbid(unsafe_code)]` (`scp-runtime/src/lib.rs`): the only type-system
/// escape — a `*const _ as *mut _` cast on the shared `class_s` read reference —
/// requires an `unsafe` block, which `forbid` rejects crate-wide and cannot be
/// locally re-enabled. Weakening that attribute would re-open this vector.
///
/// # `governance.class_s` is unreachable from this view (structural)
///
/// `GovernanceClassCMut::new` destructures the `&mut GovernanceState` and leaves
/// `class_s` (the [`GovernanceClassS`] Class-S sub-struct) and
/// `revoked_spending_ucan_cids` in the `..` rest — so this view holds NO reference
/// (mut or shared) to either. A "convenience" accessor returning a
/// `&mut GovernanceClassS` CANNOT be written, because no field of that type exists
/// on the view (illustrative, NOT a decoupled `compile_fail` mirror that could
/// drift): the load-bearing guarantee is this struct's field list itself. The
/// regression to guard against — binding `class_s` by name in `new` so a `&mut`
/// survives — is caught by the SAFETY-INVARIANT contract on `Self::new`'s
/// destructure (the `..` rest) plus the type having no `class_s` field; it does
/// NOT rely on an example. (Per
/// `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`, prefer
/// the structural shape over a source-text/doctest signpost.)
pub struct GovernanceClassCMut<'a> {
    /// `&mut` to the per-sender velocity tracker (§19.7).
    velocity_tracker: &'a mut SenderVelocityTracker,
    /// `&mut` to the per-member cumulative budget tracker (§19.5).
    budget_tracker: &'a mut MemberBudgetTracker,
    /// `&mut` to the consequence-rule cooldown map.
    cooldown_until: &'a mut HashMap<usize, u64>,
    /// `&mut` to the mutable economic policy (§19.3).
    economic_policy: &'a mut Option<EconomicPolicy>,
    /// `&mut` to the governance engine (ADR-031).
    engine: &'a mut Box<dyn GovernanceEngine>,
    /// `&mut` to the approved-proposals conflict-tracking map (ADR-031 §7).
    approved_proposals: &'a mut HashMap<ProposalId, (GovernanceProposal, u64, u64)>,
    /// `&mut` to the monotonic proposal sequence counter (H10, ADR-031 §7).
    next_proposal_seq: &'a mut u64,
    /// `&mut` to the governance freeze state (ADR-031 §7).
    freeze: &'a mut Option<(ProposalId, ProposalId, u64)>,
    /// `&mut` to the per-context deadlock detection state (ADR-031 §10).
    deadlock: &'a mut DeadlockDetectionState,
    /// `&mut` to the pending ceiling modification (M7, §5.3.2).
    pending_ceiling_modification: &'a mut Option<PendingCeilingModification>,
    /// `&mut` to the pending economic policy change (§19.3).
    pending_economic_policy_change: &'a mut Option<PendingEconomicPolicyChange>,
    /// `&mut` to the dynamically registered outlets list (§5.9).
    registered_outlets: &'a mut Vec<OutletRegistration>,
    /// `&mut` to the cross-context outlet interfaces list (§6.2).
    outlet_interfaces: &'a mut Vec<OutletInterface>,
    /// `&mut` to the pruning policy override (ADR-030 §6).
    pruning_policy: &'a mut Option<PruningPolicy>,
    /// `&mut` to the last-known-member set for departure detection.
    last_known_members: &'a mut HashSet<DID>,
    /// `&mut` to the pending governance-triggered epoch resets (ADR-029 Tier 3).
    pending_epoch_resets: &'a mut Vec<DID>,
    /// `&mut` to the consequence rules declared at creation (ADR-017).
    consequence_rules: &'a mut Vec<ConsequenceRule>,
    /// `&mut` to the per-member participation record cache (#1530 proposer eligibility).
    participation_cache: &'a mut HashMap<String, ParticipationRecord>,
    /// `&mut` to the per-DID escalating-cost message pricing config (§19.7).
    message_pricing: &'a mut Option<ContextMessagePricingConfig>,
    /// `&mut` to the defense-in-depth Matrix-style hard rate limiter (§19.7).
    hard_rate_limit: &'a mut TokenBucketLimiter,
    /// `&mut` to the per-member governance proposal timestamps (§9.3).
    proposal_timestamps: &'a mut HashMap<String, Vec<u64>>,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: the field-granular Class-C governance accessors (`velocity_tracker_mut`, `budget_tracker_mut`, `cooldown_until_mut`, `economic_policy_mut`, `next_proposal_seq`, `next_proposal_seq_mut`, `engine_mut`, `approved_proposals_mut`, `freeze_mut`, `deadlock_mut`, `pending_ceiling_modification_mut`, `pending_economic_policy_change_mut`, `registered_outlets_mut`, `outlet_interfaces_mut`, `pruning_policy_mut`, `last_known_members_mut`, `pending_epoch_resets_mut`, `consequence_rules_mut`, `participation_cache_mut`, `message_pricing_mut`, `hard_rate_limit_mut`, `proposal_timestamps_mut`, `evict_stale_entries`, `detection_borrows`) get their first PRODUCTION callers when the best-effort handlers + `ConsequenceStateSplit` / economy-compensation paths migrate onto the combinators. Exercised by this module's unit tests now."
)]
impl<'a> GovernanceClassCMut<'a> {
    /// Wrap a borrowed [`GovernanceState`] by DESTRUCTURING it into the
    /// disjoint field references this view holds. Crate-internal: constructed
    /// only by [`ClassCMut`] (directly or via [`ClassCMut::split_class_c`]).
    ///
    /// The single destructuring `let` is what makes the airtightness structural:
    /// the whole `&mut GovernanceState` is consumed here and only field-granular
    /// references survive, so the view never holds a whole-bucket `&mut`.
    const fn new(gov: &'a mut GovernanceState) -> Self {
        // SAFETY INVARIANT (ADR-049 §9 — rationale in this type's doc above). When
        // adding a field here: any field that is, or transitively contains, a
        // Class-S sub-struct (`GovernanceClassS`), OR is itself a Class-S
        // downward-authorization field (ADR-049 §9 lists the **spending-UCAN
        // revocation set** `revoked_spending_ucan_cids` as Class S — a
        // coalesce-window rollback of a revocation re-admits a spending UCAN the
        // caller observed as revoked), MUST be left to the `..` rest — NEVER bound
        // `&mut`, and never bound by name (match ergonomics on the
        // `&mut GovernanceState` would make the binding `&mut`). Today the fields
        // left to `..` for this reason are `class_s: GovernanceClassS` and
        // `revoked_spending_ucan_cids: HashSet<String>`, so no `&mut` to either is
        // ever produced from this best-effort view. Every field named below is a
        // Class-C / structural `&mut`.
        let GovernanceState {
            velocity_tracker,
            budget_tracker,
            cooldown_until,
            economic_policy,
            engine,
            approved_proposals,
            next_proposal_seq,
            freeze,
            deadlock,
            pending_ceiling_modification,
            pending_economic_policy_change,
            registered_outlets,
            outlet_interfaces,
            pruning_policy,
            last_known_members,
            pending_epoch_resets,
            consequence_rules,
            participation_cache,
            message_pricing,
            hard_rate_limit,
            proposal_timestamps,
            // `class_s: GovernanceClassS` (the Class-S sub-struct) and
            // `revoked_spending_ucan_cids` (the Class-S spending-UCAN revocation
            // set, ADR-049 §9) are left to `..` so NO reference (mut or shared) to
            // either is taken here — a revocation is fail-closed governance, never
            // a best-effort mutation through this view.
            ..
        } = gov;
        Self {
            velocity_tracker,
            budget_tracker,
            cooldown_until,
            economic_policy,
            engine,
            approved_proposals,
            next_proposal_seq,
            freeze,
            deadlock,
            pending_ceiling_modification,
            pending_economic_policy_change,
            registered_outlets,
            outlet_interfaces,
            pruning_policy,
            last_known_members,
            pending_epoch_resets,
            consequence_rules,
            participation_cache,
            message_pricing,
            hard_rate_limit,
            proposal_timestamps,
        }
    }

    /// `&mut` access to the per-sender velocity tracker (§19.7 anti-spam /
    /// consequence evaluation). Class-C: a coalesce-window rollback of a velocity
    /// tick is acceptable.
    pub const fn velocity_tracker_mut(&mut self) -> &mut SenderVelocityTracker {
        self.velocity_tracker
    }

    /// `&mut` access to the per-member cumulative budget tracker (§19.5). Class-C:
    /// the consequence/economy reservation it records is reversed by the
    /// compensation hook when a persist does not land.
    pub const fn budget_tracker_mut(&mut self) -> &mut MemberBudgetTracker {
        self.budget_tracker
    }

    /// `&mut` access to the consequence-rule cooldown map (`rule_index` → Unix
    /// seconds until re-fire is allowed). Class-C structural liveness state.
    pub const fn cooldown_until_mut(&mut self) -> &mut HashMap<usize, u64> {
        self.cooldown_until
    }

    /// `&mut` access to the mutable economic policy (§19.3). Class-C governance
    /// configuration.
    pub const fn economic_policy_mut(&mut self) -> &mut Option<EconomicPolicy> {
        self.economic_policy
    }

    /// Read accessor for the monotonic proposal sequence counter
    /// ([`GovernanceState::next_proposal_seq`]). Field-granular `&`-read of the
    /// held `&mut`, replacing the removed whole-bucket [`Deref`] read. Callers
    /// that only inspect the counter use this; the `&mut` write path is
    /// [`Self::next_proposal_seq_mut`].
    #[must_use]
    pub const fn next_proposal_seq(&self) -> u64 {
        *self.next_proposal_seq
    }

    /// `&mut` access to the monotonic proposal sequence counter (H10, ADR-031 §7).
    /// Class-C: the conflict-ordering counter is structural governance state, not
    /// a Class-S replay/authorization witness.
    pub const fn next_proposal_seq_mut(&mut self) -> &mut u64 {
        self.next_proposal_seq
    }

    /// `&mut` access to the governance engine (ADR-031, §5.9). Class-C: the
    /// engine's mutable bookkeeping is best-effort-rollback acceptable.
    pub const fn engine_mut(&mut self) -> &mut Box<dyn GovernanceEngine> {
        self.engine
    }

    /// `&mut` access to the approved-proposals conflict-tracking map (ADR-031 §7).
    /// Class-C: a coalesce-window rollback re-derives from the durable proposal
    /// flow; it is not a replay/authorization witness.
    pub const fn approved_proposals_mut(
        &mut self,
    ) -> &mut HashMap<ProposalId, (GovernanceProposal, u64, u64)> {
        self.approved_proposals
    }

    /// `&mut` access to the governance freeze state (ADR-031 §7). Class-C
    /// structural liveness state.
    pub const fn freeze_mut(&mut self) -> &mut Option<(ProposalId, ProposalId, u64)> {
        self.freeze
    }

    /// `&mut` access to the per-context deadlock detection state (ADR-031 §10).
    /// Class-C structural liveness state.
    pub const fn deadlock_mut(&mut self) -> &mut DeadlockDetectionState {
        self.deadlock
    }

    /// `&mut` access to the pending ceiling modification (M7, §5.3.2). Class-C
    /// governance configuration awaiting its notification period.
    pub(crate) const fn pending_ceiling_modification_mut(
        &mut self,
    ) -> &mut Option<PendingCeilingModification> {
        self.pending_ceiling_modification
    }

    /// `&mut` access to the pending economic policy change (§19.3). Class-C
    /// governance configuration awaiting its notification period.
    pub const fn pending_economic_policy_change_mut(
        &mut self,
    ) -> &mut Option<PendingEconomicPolicyChange> {
        self.pending_economic_policy_change
    }

    /// `&mut` access to the dynamically registered outlets list (§5.9). Class-C
    /// structural governance configuration.
    pub const fn registered_outlets_mut(&mut self) -> &mut Vec<OutletRegistration> {
        self.registered_outlets
    }

    /// `&mut` access to the cross-context outlet interfaces list (§6.2). Class-C
    /// structural governance configuration.
    pub const fn outlet_interfaces_mut(&mut self) -> &mut Vec<OutletInterface> {
        self.outlet_interfaces
    }

    /// `&mut` access to the pruning policy override (ADR-030 §6). Class-C
    /// governance configuration.
    pub const fn pruning_policy_mut(&mut self) -> &mut Option<PruningPolicy> {
        self.pruning_policy
    }

    /// `&mut` access to the last-known-member set used for departure detection.
    /// Class-C: a per-tick liveness cache, best-effort-rollback acceptable.
    pub const fn last_known_members_mut(&mut self) -> &mut HashSet<DID> {
        self.last_known_members
    }

    /// `&mut` access to the pending governance-triggered epoch resets (ADR-029
    /// Tier 3). Class-C: a per-tick drain queue, not durable authorization state.
    pub const fn pending_epoch_resets_mut(&mut self) -> &mut Vec<DID> {
        self.pending_epoch_resets
    }

    /// `&mut` access to the consequence rules declared at creation (ADR-017).
    /// Class-C structural governance configuration.
    pub const fn consequence_rules_mut(&mut self) -> &mut Vec<ConsequenceRule> {
        self.consequence_rules
    }

    /// `&mut` access to the per-member participation record cache (#1530 proposer
    /// eligibility). Class-C: a derived cache, best-effort-rollback acceptable.
    pub const fn participation_cache_mut(&mut self) -> &mut HashMap<String, ParticipationRecord> {
        self.participation_cache
    }

    /// `&mut` access to the per-DID escalating-cost message pricing config (§19.7).
    /// Class-C governance configuration.
    pub(crate) const fn message_pricing_mut(&mut self) -> &mut Option<ContextMessagePricingConfig> {
        self.message_pricing
    }

    /// `&mut` access to the defense-in-depth Matrix-style hard rate limiter
    /// (§19.7). Class-C: a token-bucket whose coalesce-window rollback is
    /// acceptable (defense-in-depth, layered atop §19.7 economic escalation).
    pub const fn hard_rate_limit_mut(&mut self) -> &mut TokenBucketLimiter {
        self.hard_rate_limit
    }

    /// `&mut` access to the per-member governance proposal timestamps (§9.3
    /// earned-capacity rate limiting). Class-C structural rate-limit state.
    pub const fn proposal_timestamps_mut(&mut self) -> &mut HashMap<String, Vec<u64>> {
        self.proposal_timestamps
    }

    /// Borrows for the §19 economy pre-check: a `&mut` to the `budget_tracker`
    /// (the debit target) held simultaneously with shared `&` reads of
    /// `velocity_tracker`, `economic_policy`, `consequence_rules`, and
    /// `message_pricing`.
    ///
    /// These five borrows are disjoint fields of this view, so the borrow
    /// checker permits the single `&mut` alongside the four `&` reads. The
    /// caller can therefore run the whole pre-check (debit + the four reads)
    /// without re-borrowing the view between steps. Every field is Class-C; no
    /// reference into any Class-S sub-struct is produced.
    pub fn economy_pre_check_borrows(&mut self) -> EconomyPreCheckBorrows<'_> {
        EconomyPreCheckBorrows {
            budget_tracker: self.budget_tracker,
            velocity_tracker: self.velocity_tracker,
            economic_policy: self.economic_policy,
            consequence_rules: self.consequence_rules,
            message_pricing: self.message_pricing,
        }
    }

    /// Evict stale governance liveness entries (participation cache, cooldowns,
    /// proposal timestamps) keyed off the last-known-member set. Class-C
    /// liveness cleanup — field-granular over this view's own fields: a
    /// coalesce-window rollback of an eviction tick is acceptable (the caches
    /// re-derive from the durable membership / proposal flow). The `&*` reborrow
    /// narrows `last_known_members` to a shared `&` so it can be read inside the
    /// `retain` closures while `participation_cache` / `proposal_timestamps` are
    /// borrowed `&mut` — disjoint fields, no whole-bucket `&mut`.
    pub fn evict_stale_entries(&mut self, now: u64) {
        // M25: O(1) membership check per entry via HashSet::contains.
        // last_known_members is HashSet<DID> which implements Borrow<str>,
        // so we can look up &str keys directly.
        let last_known_members = &*self.last_known_members;
        self.participation_cache
            .retain(|did, _| last_known_members.contains(did.as_str()));
        // Evict expired cooldown entries.
        self.cooldown_until.retain(|_, expiry| now < *expiry);
        // Evict departed members from proposal timestamps.
        self.proposal_timestamps
            .retain(|did, _| last_known_members.contains(did.as_str()));
    }

    /// Disjoint borrows for the governance deadlock-detection update: a `&mut`
    /// to the [`DeadlockDetectionState`] held simultaneously with a shared `&`
    /// read of the governance [`GovernanceEngine`]. Both are distinct fields of
    /// this view, so the borrow checker permits the single `&mut` alongside the
    /// `&` read; the caller (`update_detection_state`) needs both at once.
    ///
    /// Both fields are Class-C / structural — the deadlock-detection bookkeeping
    /// is per-tick liveness state whose coalesce-window rollback is acceptable,
    /// and the engine read is configuration. No reference into any Class-S
    /// sub-struct is produced.
    pub fn detection_borrows(&mut self) -> (&mut DeadlockDetectionState, &dyn GovernanceEngine) {
        (self.deadlock, self.engine.as_ref())
    }

    /// Reborrow this view into a shorter-lived [`GovernanceClassCMut`] over the
    /// same fields. Used by [`ClassCMut::split_class_c`] to hand an OWNED
    /// sub-view (not a reference) into a [`ClassCSplit`] without giving up the
    /// `ClassCMut`'s own borrow. Each held `&mut` is reborrowed (`&mut **`); the
    /// shared `&` is copied.
    const fn reborrow(&mut self) -> GovernanceClassCMut<'_> {
        GovernanceClassCMut {
            velocity_tracker: &mut *self.velocity_tracker,
            budget_tracker: &mut *self.budget_tracker,
            cooldown_until: &mut *self.cooldown_until,
            economic_policy: &mut *self.economic_policy,
            engine: &mut *self.engine,
            approved_proposals: &mut *self.approved_proposals,
            next_proposal_seq: &mut *self.next_proposal_seq,
            freeze: &mut *self.freeze,
            deadlock: &mut *self.deadlock,
            pending_ceiling_modification: &mut *self.pending_ceiling_modification,
            pending_economic_policy_change: &mut *self.pending_economic_policy_change,
            registered_outlets: &mut *self.registered_outlets,
            outlet_interfaces: &mut *self.outlet_interfaces,
            pruning_policy: &mut *self.pruning_policy,
            last_known_members: &mut *self.last_known_members,
            pending_epoch_resets: &mut *self.pending_epoch_resets,
            consequence_rules: &mut *self.consequence_rules,
            participation_cache: &mut *self.participation_cache,
            message_pricing: &mut *self.message_pricing,
            hard_rate_limit: &mut *self.hard_rate_limit,
            proposal_timestamps: &mut *self.proposal_timestamps,
        }
    }
}

/// RESTRICTED mutable view over the Class-C / structural fields of a
/// [`ContextRoleState`]. It holds those fields as SEPARATE field-granular
/// references — it does **not** hold a whole `&mut ContextRoleState`, so there
/// is no whole-bucket `&mut` for any accessor to return and no `&mut` path to
/// the **downward-authorization** fields (`ceiling`, `suspended_capabilities`).
///
/// # Why `ContextRoleState` is dual-use, and what this view closes
///
/// [`ContextRoleState`] is DUAL-USE (ADR-049 §9): it carries Class-C structural
/// state (role definitions, assignments, the member set, derived capabilities)
/// AND Class-S downward-authorization state that MUST be mutated only through a
/// fail-closed-persisting combinator:
///
/// - `ceiling` — the immutable capability ceiling. A ceiling MODIFICATION is a
///   downward-authorization governance leaf (`PendingCeilingModification`,
///   §5.3.2) that must be fail-closed: a coalesce-window rollback of a ceiling
///   tightening would silently re-widen the authorization envelope a caller
///   already observed as narrowed. Exposed READ-ONLY here.
/// - `suspended_capabilities` — the per-member capability suspension / blocklist
///   set. A suspension is a downward-authorization leaf (the application-level
///   block enforced by `member_has_capability`): rolling a suspension back
///   re-grants a capability the caller observed as denied. Exposed READ-ONLY
///   here.
///
/// A whole `&mut ContextRoleState` would let the best-effort / compensation path
/// mutate `ceiling` / `suspended_capabilities` with NO fail-closed persist — a §9
/// bypass. This view is the replacement (there is no longer any whole-`&mut`
/// accessor): it closes that the same way [`GovernanceClassCMut`] closes the
/// `governance.class_s` bypass — it holds no whole `&mut ContextRoleState`, only a
/// `&mut` per Class-C field plus a shared
/// `&` to the two downward-auth fields.
///
/// # Airtight BY CONSTRUCTION — no whole `&mut` to return
///
/// On construction it destructures (via [`ContextRoleState::class_c_parts`]) into
/// disjoint references — a `&mut` to each writable Class-C field, a shared `&` to
/// `ceiling`, a `&mut` to `suspended_capabilities` exposed ONLY through the
/// SHRINK-only prune + a shared read, and (stable structural identity) shared `&`
/// reads of `context_id` / `creator_did`. There is therefore NO whole
/// `&mut ContextRoleState`, so a future "convenience" accessor returning one
/// CANNOT be written, and there is no downward-auth GROW path. Reads go through
/// the `&`-returning read accessors; reads cannot violate the invariant.
///
/// # Downward-auth confinement (structural, BLACK-CS-03)
///
/// `ceiling` is bound a SHARED `&` (read-only — there is no `ceiling_mut`).
/// `suspended_capabilities` is held `&mut` BUT exposed ONLY through the
/// SHRINK-only `Self::prune_suspensions_to_role_grants` + a shared READ
/// ([`Self::suspended_capabilities`]) — there is deliberately NO GROW ACCESSOR
/// (`suspend_capabilities` / `suspend_all`) on this view. So a caller holding THIS
/// view (a `RoleStateClassCMut`) cannot perform a downward-auth GROW — the GROW
/// method does not exist on this type.
///
/// The LOAD-BEARING structural guarantee is the PRIVATE Class-S fields
/// (`suspended_capabilities` / `member_capabilities`, private to their defining
/// modules) plus `ClassSCell: !DerefMut` / `SharedClassS: !DerefMut` (asserted in
/// the test submodule): no code OUTSIDE this crate's view layer can reach a `&mut`
/// to the downward-auth maps. This is NOT enforced by a coupled compile-witness
/// over method resolution — the two such witnesses that used to live here were
/// shape-fragile (they missed the realistic `&mut self` inherent GROW) and were
/// deleted; see the honest §9 structural account in the test submodule. Per
/// `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`.
///
/// SCOPE: this is NOT a claim that a GROW lives nowhere else. The consequence-only
/// [`ConsequenceRoleStateMut`] exposes the GROW (reachable from a best-effort
/// `ClassCMut` via [`ClassCMut::consequence_split`]) — §9-safe because those GROW
/// methods STRUCTURALLY REQUIRE an obligation sink and the consequence caller
/// persists fail-closed (RED-CS3) — and the inherent `pub`
/// `ContextRoleState::suspend_*` is reachable through any whole
/// `&mut ContextRoleState` (e.g. [`ClassSMut::rest_mut`]) — §9-safe because that
/// `&mut` is handed out only inside a fail-closed-persisting combinator. The
/// RESIDUAL the type system does NOT prevent — a maintainer editing THIS impl
/// in-file to add a new `&mut self` GROW over its private maps — is an
/// in-file-insider action, a code-review responsibility (the deleted witnesses did
/// not defend it either).
pub struct RoleStateClassCMut<'a> {
    /// Shared `&` to the context's identifier (structural identity, stable).
    context_id: &'a str,
    /// Shared `&` to the creator DID (structural identity, stable).
    creator_did: &'a str,
    /// Shared `&` to the immutable capability ceiling — DOWNWARD-AUTH Class-S,
    /// read-only here (modifications are fail-closed governance, §5.3.2).
    ceiling: &'a CapabilityCeiling,
    /// `&mut` to all role definitions (Class-C / structural governance config).
    role_definitions: &'a mut HashMap<String, RoleDefinition>,
    /// `&mut` to the current role assignments (Class-C / structural).
    assignments: &'a mut HashMap<String, RoleAssignment>,
    /// `&mut` to the member DID set (Class-C / structural).
    members: &'a mut HashSet<String>,
    /// `&mut` to the per-member GRANTED capability sets. These ARE an
    /// authorization input — [`Self::member_has_capability`] reads them directly
    /// (`member_has_capability` = `member_capabilities` − `suspended_capabilities`),
    /// so a non-persisted downward SHRINK of this map is a §9 downward-auth hazard
    /// in its own right. The `&mut` is held ONLY so this view's
    /// [`Self::system_assign_role`] can REPLACE a member's set on a structural
    /// member ADD / JOIN (best-effort by design — a coalesce-window rollback of a
    /// JOIN re-derives from the durable membership flow; the consequence-engine
    /// DEMOTION path uses the consequence-only [`ConsequenceRoleStateMut`], whose
    /// caller persists fail-closed). There is deliberately NO standalone
    /// whole-`&mut` `member_capabilities_mut()` accessor on this best-effort view
    /// (it was the F2 shrink hole — a future `member_capabilities` mutation must
    /// route through a fail-closed combinator, the consequence view, or
    /// `system_assign_role`); reads go through [`Self::member_capabilities`].
    member_capabilities: &'a mut HashMap<String, HashSet<Capability>>,
    /// `&mut` to the per-member capability SUSPENSION set — DOWNWARD-AUTH
    /// Class-S. The `&mut` is held ONLY so this view can run the SHRINK-only
    /// [`Self::prune_suspensions_to_role_grants`] (a coalesce-window rollback of a
    /// prune can only RE-SUSPEND — re-narrow authority — never re-grant). There is
    /// deliberately NO GROW accessor on THIS view (`suspend_capabilities` /
    /// `suspend_all` are NOT exposed here — they live on the consequence-only
    /// [`ConsequenceRoleStateMut`] and as the inherent `pub`
    /// `ContextRoleState::suspend_*`, each persisted fail-closed by its
    /// combinator/caller; see the type doc SCOPE note), and the READ accessor
    /// [`Self::suspended_capabilities`] hands out a shared `&` reborrow.
    suspended_capabilities: &'a mut HashMap<String, HashSet<Capability>>,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9: the field-granular Class-C role-state accessors (`context_id`, `creator_did`, `ceiling`, `role_definitions_mut`, `assignments_mut`, `members_mut`, `member_capabilities` (read-only — the F2 whole-`&mut` shrink accessor is deleted), `suspended_capabilities`, `prune_suspensions_to_role_grants`, `system_assign_role`, `reborrow`) are partially exercised by this module's unit tests; the remainder gain production callers across the structural / membership role-state mutation sites."
)]
impl<'a> RoleStateClassCMut<'a> {
    /// Build from the cross-crate [`ContextRoleClassCParts`] destructure of a
    /// `&mut ContextRoleState` (ADR-049 §9). Crate-internal: constructed only by
    /// [`ClassCMut::role_state_class_c_mut`] and the split paths.
    ///
    /// The downward-auth `ceiling` arrives a SHARED `&` from `class_c_parts`
    /// (read-only here, no `&mut`); `suspended_capabilities` arrives `&mut` but is
    /// exposed ONLY through the SHRINK-only prune + a shared read; the structural
    /// fields are `&mut`. No whole `&mut ContextRoleState` is held, so no accessor
    /// can return one, and there is no GROW path to `suspended_capabilities`.
    const fn from_parts(parts: ContextRoleClassCParts<'a>) -> Self {
        let ContextRoleClassCParts {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
            suspended_capabilities,
        } = parts;
        Self {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
            suspended_capabilities,
        }
    }

    /// Build directly from a `&mut ContextRoleState` by routing through
    /// [`ContextRoleState::class_c_parts`] (the cross-crate disjoint destructure).
    fn new(role_state: &'a mut ContextRoleState) -> Self {
        Self::from_parts(role_state.class_c_parts())
    }

    /// Reborrow this view into a shorter-lived [`RoleStateClassCMut`] over the
    /// same fields (mirrors [`GovernanceClassCMut::reborrow`]). Used by the split
    /// paths to hand an OWNED sub-view into a [`ClassCSplit`] without giving up
    /// the parent borrow. Each held `&mut` is reborrowed; the shared `&` is copied.
    const fn reborrow(&mut self) -> RoleStateClassCMut<'_> {
        RoleStateClassCMut {
            context_id: self.context_id,
            creator_did: self.creator_did,
            ceiling: self.ceiling,
            role_definitions: &mut *self.role_definitions,
            assignments: &mut *self.assignments,
            members: &mut *self.members,
            member_capabilities: &mut *self.member_capabilities,
            suspended_capabilities: &mut *self.suspended_capabilities,
        }
    }

    /// Test-only reach into [`Self::context_id`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn context_id_for_test(&self) -> &str {
        Self::context_id(self)
    }

    /// Read the context identifier (structural identity).
    #[must_use]
    pub(crate) const fn context_id(&self) -> &str {
        self.context_id
    }

    /// Read the creator DID (structural identity).
    #[must_use]
    pub const fn creator_did(&self) -> &str {
        self.creator_did
    }

    /// Test-only reach into [`Self::ceiling`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn ceiling_for_test(&self) -> &CapabilityCeiling {
        Self::ceiling(self)
    }

    /// READ-ONLY access to the immutable capability ceiling. DOWNWARD-AUTH
    /// Class-S: ceiling modifications are fail-closed governance (§5.3.2), so
    /// there is deliberately no `&mut` counterpart on this view.
    #[must_use]
    pub(crate) const fn ceiling(&self) -> &CapabilityCeiling {
        self.ceiling
    }

    /// Test-only reach into [`Self::role_definitions_mut`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub const fn role_definitions_mut_for_test(&mut self) -> &mut HashMap<String, RoleDefinition> {
        Self::role_definitions_mut(self)
    }

    /// `&mut` access to the role definitions map (Class-C / structural
    /// governance configuration).
    pub(crate) const fn role_definitions_mut(&mut self) -> &mut HashMap<String, RoleDefinition> {
        self.role_definitions
    }

    /// Test-only reach into [`Self::assignments_mut`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub const fn assignments_mut_for_test(&mut self) -> &mut HashMap<String, RoleAssignment> {
        Self::assignments_mut(self)
    }

    /// `&mut` access to the current role assignments (Class-C / structural).
    pub(crate) const fn assignments_mut(&mut self) -> &mut HashMap<String, RoleAssignment> {
        self.assignments
    }

    /// `&mut` access to the member DID set (Class-C / structural). NOT a
    /// downward-auth witness: a coalesce-window rollback of a structural member
    /// add re-derives from the durable membership flow.
    pub const fn members_mut(&mut self) -> &mut HashSet<String> {
        self.members
    }

    /// Test-only reach into [`Self::member_capabilities`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn member_capabilities_for_test(&self) -> &HashMap<String, HashSet<Capability>> {
        Self::member_capabilities(self)
    }

    /// READ-ONLY access to the per-member GRANTED capability sets (ADR-049 §9 /
    /// F2). These are an authorization input — [`Self::member_has_capability`]
    /// reads them — so a non-persisted downward SHRINK is a §9 hazard. This
    /// best-effort view therefore exposes NO standalone whole-`&mut`
    /// `member_capabilities_mut()` (the former F2 shrink hole is DELETED): the only
    /// `member_capabilities` write this view permits is the
    /// [`Self::system_assign_role`] REPLACEMENT on a structural member ADD / JOIN
    /// (best-effort by design). A `member_capabilities` DEMOTION must route through
    /// the consequence-only [`ConsequenceRoleStateMut`] (whose caller persists
    /// fail-closed) or another fail-closed combinator.
    #[must_use]
    pub(crate) const fn member_capabilities(&self) -> &HashMap<String, HashSet<Capability>> {
        self.member_capabilities
    }

    /// READ-ONLY access to the per-member capability suspension / blocklist set.
    /// DOWNWARD-AUTH Class-S: there is NO GROW accessor (`suspend_capabilities` /
    /// `suspend_all`) on THIS field-granular view — it exposes only this read and
    /// the SHRINK-only prune. The GROW direction is reachable elsewhere (the
    /// consequence-only [`ConsequenceRoleStateMut`], and the inherent `pub`
    /// `ContextRoleState::suspend_*` behind a whole `&mut`), each persisted
    /// fail-closed by its combinator/caller — see the type doc's SCOPE note.
    #[must_use]
    pub const fn suspended_capabilities(&self) -> &HashMap<String, HashSet<Capability>> {
        self.suspended_capabilities
    }

    /// SHRINK-only prune of a member's suspensions to the capabilities the
    /// `new_role_capabilities` set still grants (ADR-049 §9). The ONLY mutation of
    /// `suspended_capabilities` this general-purpose view exposes: it can only
    /// REMOVE entries, never GROW the denied set. A best-effort prune is §9-safe in
    /// the directional sense that matters — a coalesce-window rollback can only
    /// RE-SUSPEND a dropped entry (re-narrow authority), never re-grant a removed
    /// capability — and it rolls back in lockstep with the same-persist
    /// `member_capabilities` replacement.
    pub(crate) fn prune_suspensions_to_role_grants(
        &mut self,
        member_did: &str,
        new_role_capabilities: &HashSet<Capability>,
    ) {
        if let Some(suspended) = self.suspended_capabilities.get_mut(member_did) {
            suspended.retain(|cap| new_role_capabilities.contains(cap));
            if suspended.is_empty() {
                self.suspended_capabilities.remove(member_did);
            }
        }
    }

    /// Mint + structurally apply a system-level role assignment over THIS view's
    /// disjoint fields (ADR-049 §9). Inserts/replaces `assignments` /
    /// `member_capabilities` and runs the SHRINK-only suspension prune, all over
    /// the view's own `&mut` fields — reading `context_id` / `creator_did` /
    /// `role_definitions` shared, writing the structural fields. No whole
    /// `&mut ContextRoleState` is needed, so the structural / membership callers no
    /// longer reach for the deleted whole-`&mut` accessor.
    ///
    /// Mirrors [`ContextRoleState::system_assign_role`] field-for-field (it cannot
    /// delegate to it without a whole `&mut`, which the view deliberately does not
    /// hold). The `member_capabilities` REPLACEMENT is a downward-auth shrink on a
    /// demotion; at the structural / membership call sites it is best-effort by
    /// design (member ADD / JOIN is coalesce-window-rollback acceptable, ADR-049
    /// §9), and the consequence-engine demotion path uses the consequence-only
    /// view, whose caller persists fail-closed.
    ///
    /// # Errors
    ///
    /// [`RoleError::MemberNotInContext`] if the member is absent;
    /// [`RoleError::RoleNotFound`] if the role is undefined.
    pub fn system_assign_role(
        &mut self,
        member_did: &str,
        role_name: &str,
        clock: &dyn scp_clock::Clock,
    ) -> Result<Vec<UcanToken>, RoleError> {
        // Build a transient `ContextRoleClassCParts` from REBORROWS of this view's
        // own disjoint fields and delegate to the protocol seam (which owns the
        // private `mint_role_tokens`). `ceiling` is reborrowed shared `&` (unused
        // by the mint, read-only regardless).
        let mut parts = ContextRoleClassCParts {
            context_id: self.context_id,
            creator_did: self.creator_did,
            ceiling: self.ceiling,
            role_definitions: &mut *self.role_definitions,
            assignments: &mut *self.assignments,
            members: &mut *self.members,
            member_capabilities: &mut *self.member_capabilities,
            suspended_capabilities: &mut *self.suspended_capabilities,
        };
        parts.system_assign_role(member_did, role_name, clock)
    }

    /// Whether `member_did` currently holds `capability` (read). Mirrors
    /// [`ContextRoleState::member_has_capability`] over the two fields this view
    /// already holds: a suspension (DOWNWARD-AUTH Class-S, read here) masks an
    /// otherwise-granted derived capability (Class-C). Pure read — no mutation,
    /// so it neither reaches a Class-S `&mut` nor needs a fail-closed persist.
    #[must_use]
    pub fn member_has_capability(&self, member_did: &str, capability: &Capability) -> bool {
        if self
            .suspended_capabilities
            .get(member_did)
            .is_some_and(|suspended| suspended.contains(capability))
        {
            return false;
        }
        self.member_capabilities
            .get(member_did)
            .is_some_and(|caps| caps.contains(capability))
    }
}

/// CONSEQUENCE-ONLY mutable view over a [`ContextRoleState`]'s downward-auth +
/// structural fields (ADR-049 §9, RED-CS3 / R1).
///
/// This is the DISTINCT role-state VIEW the consequence engine holds — the only
/// field-granular role view that exposes the downward-authorization GROW mutators
/// ([`Self::suspend_capabilities`], [`Self::suspend_all`]) and the demotion
/// ([`Self::system_assign_role`]). It is carried ONLY by [`ConsequenceStateSplit`],
/// whose cell-holding caller persists the applied downward-auth mutation
/// FAIL-CLOSED (keep-direction) before acking. The general-purpose
/// [`RoleStateClassCMut`] (carried by [`ClassCSplit`] and handed to best-effort /
/// structural callers) deliberately exposes NO GROW ACCESSOR: a caller holding a
/// `RoleStateClassCMut` (or a [`ClassCSplit`]) CANNOT call
/// `suspend_capabilities` / `suspend_all` because the method does not exist on
/// THAT type. That is the structural confinement that CLOSES BLACK-CS-03 (a future
/// best-effort GROW-suspend through the FIELD-GRANULAR view would be a coalesce-loss
/// §9 violation) rather than relocating it.
///
/// SCOPE (not a global "GROW exists nowhere else"): the GROW direction ALSO exists
/// as the INHERENT `pub` [`scp_protocol::context::roles::ContextRoleState::suspend_capabilities`]
/// / [`suspend_all`](scp_protocol::context::roles::ContextRoleState::suspend_all),
/// reachable through ANY whole `&mut ContextRoleState` (e.g. [`ClassSMut::rest_mut`],
/// used by the governance helpers). That path is §9-safe because the combinator
/// handing out the whole `&mut` persists fail-closed — by OBLIGATION, not because a
/// GROW is impossible there. What is structurally enforced is narrower-and-exact:
/// the FIELD-GRANULAR best-effort role view exposes no GROW accessor.
///
/// # Airtight BY CONSTRUCTION — no whole `&mut`, no `ceiling` write
///
/// Built from the cross-crate [`ContextRoleClassCParts`] destructure, it holds a
/// `&mut` per writable field plus a shared `&` to `ceiling` (a ceiling
/// modification is its OWN fail-closed governance leaf, §5.3.2, never written on
/// the consequence path). It holds NO whole `&mut ContextRoleState`, so no
/// accessor can return one, and `ceiling` is unreachable for mutation.
#[allow(
    dead_code,
    reason = "ADR-049 §9 / RED-CS3: the consequence-only GROW role view. `member_capabilities`/`role_definitions`/`assignments`/`members` mut accessors back the consequence-test setup + future structural needs; the GROW + demotion methods are the live consequence-engine path."
)]
pub struct ConsequenceRoleStateMut<'a> {
    /// Shared `&` to the context identifier (structural identity, stable).
    context_id: &'a str,
    /// Shared `&` to the creator DID (structural identity, stable).
    creator_did: &'a str,
    /// Shared `&` to the immutable capability ceiling — DOWNWARD-AUTH Class-S,
    /// read-only even on the consequence path (ceiling changes are their own
    /// fail-closed governance leaf, §5.3.2).
    ceiling: &'a CapabilityCeiling,
    /// `&mut` to all role definitions (Class-C / structural).
    role_definitions: &'a mut HashMap<String, RoleDefinition>,
    /// `&mut` to the current role assignments (Class-C / structural).
    assignments: &'a mut HashMap<String, RoleAssignment>,
    /// `&mut` to the member DID set (Class-C / structural).
    members: &'a mut HashSet<String>,
    /// `&mut` to the per-member derived capability sets (Class-C / structural —
    /// REPLACED by a demotion, a downward-auth shrink the caller persists
    /// fail-closed).
    member_capabilities: &'a mut HashMap<String, HashSet<Capability>>,
    /// `&mut` to the per-member capability SUSPENSION set — DOWNWARD-AUTH Class-S.
    /// The GROW direction (`suspend_capabilities` / `suspend_all`) is exposed HERE
    /// and ONLY here; the caller persists the GROW fail-closed.
    suspended_capabilities: &'a mut HashMap<String, HashSet<Capability>>,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 / RED-CS3: consequence-only GROW role-view accessors; the GROW + demotion methods are the live consequence path, the structural mut accessors + reads back the consequence tests."
)]
impl<'a> ConsequenceRoleStateMut<'a> {
    /// Build from the cross-crate [`ContextRoleClassCParts`] destructure.
    const fn from_parts(parts: ContextRoleClassCParts<'a>) -> Self {
        let ContextRoleClassCParts {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
            suspended_capabilities,
        } = parts;
        Self {
            context_id,
            creator_did,
            ceiling,
            role_definitions,
            assignments,
            members,
            member_capabilities,
            suspended_capabilities,
        }
    }

    /// Reborrow into a shorter-lived consequence view over the same fields (used
    /// by the split paths to hand an OWNED sub-view into a [`ConsequenceStateSplit`]
    /// without giving up the parent borrow).
    const fn reborrow(&mut self) -> ConsequenceRoleStateMut<'_> {
        ConsequenceRoleStateMut {
            context_id: self.context_id,
            creator_did: self.creator_did,
            ceiling: self.ceiling,
            role_definitions: &mut *self.role_definitions,
            assignments: &mut *self.assignments,
            members: &mut *self.members,
            member_capabilities: &mut *self.member_capabilities,
            suspended_capabilities: &mut *self.suspended_capabilities,
        }
    }

    /// READ-ONLY access to the immutable capability ceiling.
    pub(crate) const fn ceiling(&self) -> &CapabilityCeiling {
        self.ceiling
    }

    /// Whether `member_did` is currently a member (read).
    pub(crate) fn contains_member(&self, member_did: &str) -> bool {
        self.members.contains(member_did)
    }

    /// DOWNWARD-AUTH GROW: suspend specific capabilities for a member (ADR-049 §9).
    ///
    /// The `obligation` sink is a REQUIRED parameter, not a courtesy: arming the
    /// fail-closed-persist obligation is part of the GROW's signature so it is
    /// IMPOSSIBLE to apply this GROW without arming the owed persist. Whenever the
    /// GROW actually mutates `suspended_capabilities` (a non-empty `capabilities`),
    /// the sink is armed with a [`ClassSCommitToken`] via
    /// [`ClassSCommitToken::note_downward_auth`] (idempotent — one owed persist per
    /// cascade); an empty iterator is a no-op that leaves the sink untouched (the
    /// hot path stays coalesced). The cell-holding caller discharges the populated
    /// sink fail-closed after the view drops. There is NO separate hand-written
    /// arming call to forget (GAP-A closed): the mutation and its obligation are one
    /// operation.
    pub fn suspend_capabilities(
        &mut self,
        member_did: &str,
        capabilities: impl IntoIterator<Item = Capability>,
        obligation: &mut Option<ClassSCommitToken>,
        context_id: &str,
    ) {
        let entry = self
            .suspended_capabilities
            .entry(member_did.to_owned())
            .or_default();
        let before = entry.len();
        entry.extend(capabilities);
        // Arm the fail-closed obligation IFF a capability was actually added — an
        // empty / fully-redundant suspend is not a downward-auth transition and
        // owes no fail-closed persist (the coalesced persist suffices). The token
        // is minted against the AUTHORITATIVE `context_id` the cell-holding caller
        // will commit against (the dispatch ctx), NOT the role state's own
        // `context_id` (which may be unset on a test/seed state).
        let did_grow = entry.len() != before;
        ClassSCommitToken::note_downward_auth(obligation, did_grow, context_id);
    }

    /// DOWNWARD-AUTH GROW: suspend ALL of a member's current capabilities (the H10
    /// `SuspendAll` escalation / `SuspendAccess`).
    ///
    /// As with [`Self::suspend_capabilities`], the `obligation` sink is a REQUIRED
    /// parameter so arming the fail-closed-persist obligation cannot be forgotten
    /// (GAP-A): the sink is armed via [`ClassSCommitToken::note_downward_auth`]
    /// whenever the GROW actually inserts a suspension. The cell-holding caller
    /// discharges the populated sink fail-closed after the view drops.
    pub fn suspend_all(
        &mut self,
        member_did: &str,
        obligation: &mut Option<ClassSCommitToken>,
        context_id: &str,
    ) {
        if let Some(caps) = self.member_capabilities.get(member_did) {
            let all_caps: HashSet<Capability> = caps.clone();
            self.suspended_capabilities
                .insert(member_did.to_owned(), all_caps);
        }
        // `suspend_all` is an explicit downward-auth SUSPEND-ACCESS / H10-escalation
        // command, so it ALWAYS arms the fail-closed obligation — unconditionally,
        // matching the dispatch's `downward_auth: true` contract for SuspendAccess.
        // (Over-persisting when the member currently holds no capabilities is the
        // safe direction; under-arming would be the §9 violation.) Minted against
        // the authoritative dispatch `context_id` (see `suspend_capabilities`), not
        // the role state's own (possibly unset) one.
        ClassSCommitToken::note_downward_auth(obligation, true, context_id);
    }

    /// Demotion / system-level role assignment (a `member_capabilities`
    /// REPLACEMENT — downward-auth on a demotion). Delegates to the protocol seam
    /// over reborrows of this view's disjoint fields.
    ///
    /// The `obligation` sink is a REQUIRED parameter (GAP-A): a consequence-path
    /// `system_assign_role` is a demotion — a `member_capabilities` REPLACEMENT that
    /// shrinks the member's effective authority — so it owes a fail-closed persist,
    /// and arming that obligation is part of the signature so it cannot be
    /// forgotten. On a successful assignment the sink is armed via
    /// [`ClassSCommitToken::note_downward_auth`] (idempotent); a failed assignment
    /// (member/role not found) mutates nothing and leaves the sink untouched. We do
    /// NOT diff capability sets to distinguish demotion from promotion: arming
    /// unconditionally on success is sound and simpler — over-persisting a promotion
    /// is harmless (a coalesce-loss of a promotion is the safe upward direction).
    ///
    /// # Errors
    ///
    /// [`RoleError::MemberNotInContext`] / [`RoleError::RoleNotFound`].
    pub fn system_assign_role(
        &mut self,
        member_did: &str,
        role_name: &str,
        clock: &dyn scp_clock::Clock,
        obligation: &mut Option<ClassSCommitToken>,
        context_id: &str,
    ) -> Result<Vec<UcanToken>, RoleError> {
        let mut parts = ContextRoleClassCParts {
            context_id: self.context_id,
            creator_did: self.creator_did,
            ceiling: self.ceiling,
            role_definitions: &mut *self.role_definitions,
            assignments: &mut *self.assignments,
            members: &mut *self.members,
            member_capabilities: &mut *self.member_capabilities,
            suspended_capabilities: &mut *self.suspended_capabilities,
        };
        let result = parts.system_assign_role(member_did, role_name, clock);
        // Arm the fail-closed obligation IFF the replacement actually landed,
        // against the authoritative dispatch `context_id` (the cell-holding caller
        // commits against it), not the role state's own (possibly unset) one.
        ClassSCommitToken::note_downward_auth(obligation, result.is_ok(), context_id);
        result
    }

    /// `&mut` to the role definitions map (Class-C / structural) — backs the
    /// consequence-test role-table setup.
    pub(crate) const fn role_definitions_mut(&mut self) -> &mut HashMap<String, RoleDefinition> {
        self.role_definitions
    }

    /// `&mut` to the current role assignments (Class-C / structural).
    pub(crate) const fn assignments_mut(&mut self) -> &mut HashMap<String, RoleAssignment> {
        self.assignments
    }

    /// `&mut` to the member DID set (Class-C / structural).
    pub(crate) const fn members_mut(&mut self) -> &mut HashSet<String> {
        self.members
    }

    // NO raw `member_capabilities_mut()` accessor (ADR-049 §9, BLACK-1c): handing
    // out a whole `&mut HashMap` to the per-member derived capability sets would let
    // a caller SHRINK a member's `member_capabilities` (a downward-auth demotion)
    // with no obligation sink, re-opening GAP-A on the consequence view. The only
    // sanctioned `member_capabilities` REPLACEMENT is the obligation-coupled
    // `system_assign_role` above (which arms the fail-closed persist on success).
}

/// RESTRICTED mutable view over the Class-C / structural mutation surface of a
/// [`MembershipState`]. It holds a `&mut MembershipState` but exposes ONLY the
/// structural mutators (member ADD, per-member sequence bookkeeping) — it does
/// **not** expose a `remove_member`-equivalent or any whole-`&mut` accessor.
///
/// # Why `MembershipState` is dual-use, and what this view closes
///
/// [`MembershipState`] is DUAL-USE (ADR-049 §9): member ADD and the per-member
/// sequence-number bookkeeping (`next_sequence_number` /
/// `rollback_sequence_number`) are Class-C structural mutations whose
/// coalesce-window rollback is acceptable, but member REMOVAL is a
/// downward-authorization Class-S transition — removing a member from the
/// authoritative roster must be fail-closed (a coalesce-window rollback would
/// silently re-admit a member the caller observed as removed). The plain
/// `ClassCMut::members_mut()` (the `HashSet<DID>` active set) is a DIFFERENT
/// structure; this view governs the authoritative [`MembershipState`] roster,
/// whose `remove_member` is the downward-auth leaf.
///
/// Unlike [`RoleStateClassCMut`] / [`GovernanceClassCMut`], this view CANNOT be
/// made airtight by field-destructuring: [`MembershipState`]'s single `members`
/// field is PRIVATE to its defining module, so it cannot be named (and the
/// whole removal/add/sequence logic lives behind methods). The airtightness is
/// therefore method-granular instead of field-granular: the view holds the
/// `&mut MembershipState` but FORWARDS only the structural-mutation methods and
/// the read methods — it never exposes `remove_member`, and (because the held
/// `&mut` is private and never returned) no accessor can hand out a whole
/// `&mut MembershipState` for a caller to call `remove_member` through. A future
/// "convenience" `fn inner_mut(&mut self) -> &mut MembershipState` would
/// re-open the bypass and MUST NOT be added — the closed method surface is the
/// contract.
pub struct MembershipClassCMut<'a> {
    /// The borrowed roster. Private — the only mutable reach is through the
    /// forwarded STRUCTURAL methods below (never `remove_member`, never a whole
    /// `&mut`).
    membership: &'a mut MembershipState,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: the structural membership accessors (`add_member`, `next_sequence_number`, `rollback_sequence_number`, `get_mut`, `count`, `contains`, `get`, `remove_subscriber`) get their first PRODUCTION callers when the structural membership-mutation handlers migrate off the whole-`&mut` `members_mut`. Exercised by this module's unit tests now."
)]
impl<'a> MembershipClassCMut<'a> {
    /// Wrap a borrowed [`MembershipState`]. Crate-internal: constructed only by
    /// [`ClassCMut::membership_class_c_mut`].
    const fn new(membership: &'a mut MembershipState) -> Self {
        Self { membership }
    }

    /// Add a member with the given role and tokens (Class-C / structural). A
    /// coalesce-window rollback of an add re-derives from the durable membership
    /// flow — best-effort acceptable. Forwards [`MembershipState::add_member`].
    pub fn add_member(&mut self, did: DID, role_name: String, tokens: Vec<UcanToken>) {
        self.membership.add_member(did, role_name, tokens);
    }

    /// Increment and return the next per-sender sequence number (Class-C /
    /// §9.8.5). Forwards [`MembershipState::next_sequence_number`].
    pub fn next_sequence_number(&mut self, sender_did: &str) -> Option<u64> {
        self.membership.next_sequence_number(sender_did)
    }

    /// Roll back the last per-sender sequence increment (Class-C / §9.8.5).
    /// Forwards [`MembershipState::rollback_sequence_number`].
    pub fn rollback_sequence_number(&mut self, sender_did: &str) {
        self.membership.rollback_sequence_number(sender_did);
    }

    /// Test-only reach into [`Self::get_mut`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub fn get_mut_for_test(&mut self, did: &str) -> Option<&mut MemberInfo> {
        Self::get_mut(self, did)
    }

    /// `&mut` access to a specific member's metadata, if present (Class-C /
    /// structural per-member bookkeeping). Forwards
    /// [`MembershipState::get_mut`]. NOTE: this cannot remove a member (it
    /// returns `Option<&mut MemberInfo>`, not the roster), so it is not a
    /// downward-auth removal path.
    pub(crate) fn get_mut(&mut self, did: &str) -> Option<&mut MemberInfo> {
        self.membership.get_mut(did)
    }

    /// Number of members (read). Forwards [`MembershipState::count`].
    #[must_use]
    pub fn count(&self) -> usize {
        self.membership.count()
    }

    /// Whether the given DID is a member (read). Forwards
    /// [`MembershipState::contains`].
    #[must_use]
    pub fn contains(&self, did: &str) -> bool {
        self.membership.contains(did)
    }

    /// Test-only reach into [`Self::get`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn get_for_test(&self, did: &str) -> Option<&MemberInfo> {
        Self::get(self, did)
    }

    /// Read a specific member's metadata, if present. Forwards
    /// [`MembershipState::get`].
    #[must_use]
    pub(crate) fn get(&self, did: &str) -> Option<&MemberInfo> {
        self.membership.get(did)
    }

    /// Iterate the member DIDs (read). Forwards
    /// [`MembershipState::member_dids`].
    pub fn member_dids(&self) -> impl Iterator<Item = &DID> {
        self.membership.member_dids()
    }

    /// Remove a BROADCAST SUBSCRIBER from the roster (Class-C / best-effort).
    /// Returns `true` if the subscriber was present. Forwards
    /// [`MembershipState::remove_member`].
    ///
    /// # Why a removal is exposed here when the general one is NOT
    ///
    /// This view deliberately withholds a general `remove_member`: removing a
    /// regular member is a downward-authorization op gated by an MLS Commit, and
    /// a coalesce-window rollback of such a removal would silently re-admit a
    /// member the caller already observed as removed — so it MUST be fail-closed
    /// (ADR-049 §9), not best-effort through this Class-C view.
    ///
    /// A broadcast UNSUBSCRIBE is different: a broadcast context's subscriber
    /// roster carries NO key secrecy — content is public, per-author broadcast
    /// keys (not MLS group keys) protect publication, and the unsubscribe is not
    /// an MLS-gated authorization boundary. A coalesce-window rollback of a
    /// subscriber removal at most re-lists a public-content subscriber for the
    /// window, with no membership-secrecy consequence — so best-effort removal
    /// is acceptable HERE and only here. This method is therefore scoped, by
    /// name and contract, to the broadcast subscription roster; it is NOT a
    /// general member-removal escape, and a general `remove_member` MUST NOT be
    /// added to this view.
    pub fn remove_subscriber(&mut self, did: &DID) -> bool {
        self.membership.remove_member(did)
    }
}

/// Independent disjoint `&mut`/`&` borrows of the Class-C / structural fields of
/// a [`PerContextState`], produced by [`ClassCMut::split_class_c`].
///
/// Each field is borrowed from a DISTINCT field of the underlying state, so the
/// borrow checker accepts holding all of them at once — this is exactly the
/// shape [`crate::context::actor::class_s::ConsequenceStateSplit`] needs. The
/// migration of `ConsequenceStateSplit` onto this is a LATER PR; this struct
/// only makes the view CAPABLE of producing the borrows.
#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: constructed by `ClassCMut::split_class_c`, whose first PRODUCTION caller is the `ConsequenceStateSplit` migration. Exercised by this module's unit test now."
)]
pub struct ClassCSplit<'a> {
    /// Field-granular Class-C governance view. NOT a `&mut GovernanceState`:
    /// `GovernanceState` contains the Class-S sub-struct `class_s`, and the
    /// consequence/best-effort path does not persist fail-closed, so it must have
    /// no `&mut` path to it. [`GovernanceClassCMut`] exposes only the Class-C
    /// governance fields and reads via field-granular `&`-accessors (e.g.
    /// [`GovernanceClassCMut::next_proposal_seq`]); it holds no whole
    /// `&mut GovernanceState` — airtight by that field-granular construction.
    pub governance: GovernanceClassCMut<'a>,
    /// Field-granular role view (ADR-049 §9). NOT a whole `&mut ContextRoleState`:
    /// [`RoleStateClassCMut`] exposes `&mut` only for the Class-C structural fields
    /// (role definitions / assignments / members), a SHRINK-only suspension prune, a
    /// `system_assign_role` REPLACEMENT, and SHARED `&` reads of the granted
    /// capabilities and the downward-auth `ceiling` / `suspended_capabilities`. It
    /// exposes NO GROW ACCESSOR (`suspend_capabilities` / `suspend_all`). So a
    /// best-effort caller holding a `ClassCSplit` structurally CANNOT perform a
    /// downward-auth GROW through THIS role view — the GROW method does not exist on
    /// `RoleStateClassCMut` (a COMPILE error). (The GROW direction itself is not
    /// gone: it lives on the consequence-only [`ConsequenceRoleStateMut`] carried by
    /// [`crate::context::actor::class_s::ConsequenceStateSplit`], and as the
    /// inherent `pub` `ContextRoleState::suspend_*` behind a whole `&mut` — each
    /// persisted fail-closed by its combinator/caller; see the `RoleStateClassCMut`
    /// type doc SCOPE note.) The structural BLACK-CS-03 confinement of the
    /// field-granular view is CLOSED by construction, not merely documented.
    pub role_state: RoleStateClassCMut<'a>,
    /// `&` membership (read-only in the consequence path).
    /// `pub` under `testing`, so `scp-runtime`'s Class-S tests can read it.
    #[cfg(any(test, feature = "testing"))]
    pub membership: &'a MembershipState,
    /// `&` membership (read-only in the consequence path).
    #[cfg(not(any(test, feature = "testing")))]
    pub(crate) membership: &'a MembershipState,
    /// `&mut` receive buffer (consequence events are emitted here).
    pub receive_buffer: &'a mut ReceiveBuffer,
    /// `&mut` checkpoint counter (bumped by consequence enforcement).
    /// `pub` under `testing`, so `scp-runtime`'s Class-S tests can read it.
    #[cfg(any(test, feature = "testing"))]
    pub checkpoint_events_since: &'a mut u64,
    /// `&mut` checkpoint counter (bumped by consequence enforcement).
    #[cfg(not(any(test, feature = "testing")))]
    pub(crate) checkpoint_events_since: &'a mut u64,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: `ClassCSplit::from_state` gets its first PRODUCTION caller when `ConsequenceStateSplit` reshapes onto `ClassCSplit` (it is the cell-free bridge used by the non-actor construction sites). Exercised by this module's unit test now."
)]
impl<'a> ClassCSplit<'a> {
    /// Build a [`ClassCSplit`] DIRECTLY from a `&mut PerContextState`, with NO
    /// owning [`ClassSCell`] / [`ClassCMut`] in scope.
    ///
    /// This is the cell-free bridge that lets
    /// [`crate::context::actor::class_s::ConsequenceStateSplit`] reshape onto
    /// the [`ClassCSplit`] field shape while keeping its
    /// `from_state(&mut PerContextState)` signature — every existing
    /// (non-cell) consequence construction site stays compiling unchanged. A
    /// cell holder reaches the SAME `ClassCSplit` shape via
    /// `cell.class_c_view().split_class_c()`, so this commit makes the
    /// consequence type cell-COMPATIBLE without itself dropping any `state_mut`
    /// call (that is the later cell-threading pass).
    ///
    /// # Airtight BY CONSTRUCTION — parity with [`ClassCMut::split_class_c`]
    ///
    /// This performs the EXACT SAME safe destructure that
    /// [`ClassCMut::new`] + [`ClassCMut::split_class_c`] already perform — it
    /// just exposes it without the [`ClassCMut`] wrapper. It holds NO whole
    /// `&mut PerContextState`, NO whole `&mut GovernanceState`, and NO `&mut` to
    /// any Class-S-containing struct:
    ///
    /// - `governance` is wrapped in a [`GovernanceClassCMut`], whose `new`
    ///   destructures the `&mut GovernanceState` and leaves `governance.class_s`
    ///   ([`GovernanceClassS`]) in its `..` rest — so NO reference (mut or
    ///   shared) to it is taken, and a `governance.class_s` mutation is a COMPILE
    ///   error by construction (there is no whole `&mut GovernanceState` to reach
    ///   it through).
    /// - `class_s` ([`ClassSState`], the actor's own Class-S sub-struct) is left
    ///   in the destructure's `..` rest — NO reference to it is taken AT ALL.
    /// - `membership` is bound a SHARED `&` (read-only on the consequence path),
    ///   matching [`ClassCMut::split_class_c`]'s `&*self.membership` narrowing.
    /// - `role_state` is wrapped in the field-granular [`RoleStateClassCMut`] (NOT
    ///   a whole `&mut ContextRoleState`, BLACK-CS-03): it exposes `ceiling`
    ///   READ-ONLY, the suspension map through a shared read + the SHRINK-only
    ///   prune, structural `&mut`, and a `system_assign_role` — but NO downward-auth
    ///   GROW ACCESSOR (`suspend_capabilities` / `suspend_all`). So a caller holding
    ///   THIS general split CANNOT perform a downward-auth GROW through its role view
    ///   — the method does not exist on `RoleStateClassCMut`. (The GROW direction is
    ///   reachable elsewhere — the consequence-only [`ConsequenceStateSplit`] /
    ///   [`ConsequenceRoleStateMut`], and the inherent `pub`
    ///   `ContextRoleState::suspend_*` behind a whole `&mut` — each persisted
    ///   fail-closed by its combinator/caller; this split simply does not expose it.)
    ///
    /// No whole `&mut PerContextState` / `&mut GovernanceState` / `&mut ClassSState`
    /// / `&mut GovernanceClassS` / `&mut ContextRoleState` is held, so a mutation of
    /// the privatized Class-S fields (or a downward-auth GROW) through this view is a
    /// compile error by construction.
    pub(crate) fn from_state(state: &'a mut PerContextState) -> Self {
        // SAFETY INVARIANT (ADR-049 §9 — rationale in this method's doc above):
        // mirror the disjoint destructure of `ClassCMut::new`. The Class-S
        // sub-structs `class_s` (actor) and `governance.class_s` (via
        // `GovernanceClassCMut`'s own `..`) are NEVER bound `&mut` — they fall into
        // the `..` rest here and inside `GovernanceClassCMut::new`. `role_state` is
        // wrapped in the field-granular `RoleStateClassCMut` (downward-auth
        // `ceiling` / `suspended_capabilities` exposed read-only / shrink-only, NO
        // GROW); `membership` is narrowed to a shared `&`.
        let PerContextState {
            governance,
            role_state,
            membership,
            receive_buffer,
            checkpoint_events_since,
            ..
        } = state;
        Self {
            governance: GovernanceClassCMut::new(governance),
            role_state: RoleStateClassCMut::new(role_state),
            membership: &*membership,
            receive_buffer,
            checkpoint_events_since,
        }
    }
}

/// The CONSEQUENCE-ENGINE split (ADR-049 §9 / RED-CS3 / R1).
///
/// Identical to [`ClassCSplit`] EXCEPT its `role_state` is the consequence-only
/// [`ConsequenceRoleStateMut`], which exposes the downward-authorization GROW
/// mutators (`suspend_capabilities` / `suspend_all`) and the demotion
/// (`system_assign_role`). This is the ONLY split that can apply a downward-auth
/// GROW — and its cell-holding caller persists that GROW FAIL-CLOSED before
/// acking (RED-CS3: `scp_runtime_governance::logic::enforce_triggered_consequences`
/// returns a downward-auth flag the caller acts on).
///
/// Un-ALIASED from [`ClassCSplit`] (R1): a type alias would hand the GROW view to
/// every best-effort caller of [`ClassCMut::split_class_c`], re-opening the §9
/// hole this PR closes. As a distinct struct, the GROW reach is confined to the
/// consequence path (built via [`ClassCMut::consequence_split`] or the cell-free
/// [`Self::from_state`]); best-effort callers get [`ClassCSplit`] with no GROW.
#[allow(
    dead_code,
    reason = "ADR-049 §9 / RED-CS3: the consequence-engine split; its `role_state` (GROW) is the live consequence path, the other fields drive event emission / cooldown. Some accessors are exercised by tests; the rest are production consequence callers."
)]
pub struct ConsequenceStateSplit<'a> {
    /// Field-granular Class-C governance view (no whole `&mut GovernanceState`,
    /// no `class_s` reach) — same as [`ClassCSplit::governance`].
    pub governance: GovernanceClassCMut<'a>,
    /// CONSEQUENCE-ONLY role view exposing the downward-auth GROW mutators. The
    /// cell-holding caller persists any applied GROW / demotion fail-closed.
    pub role_state: ConsequenceRoleStateMut<'a>,
    /// `&` membership (read-only in the consequence path).
    pub membership: &'a MembershipState,
    /// `&mut` receive buffer (consequence events are emitted here).
    pub(crate) receive_buffer: &'a mut ReceiveBuffer,
    /// `&mut` checkpoint counter (bumped by consequence enforcement).
    pub checkpoint_events_since: &'a mut u64,
}

impl ConsequenceStateSplit<'_> {
    /// Pushes `event` into this context's receive buffer and fans it out on
    /// `event_tx`. A split comes only from core's combinators or from a
    /// `&mut PerContextState` core lent, so only such code can call it
    /// (ADR-070 §4).
    pub fn emit_event(
        &mut self,
        event: scp_protocol::context::membership::ContextEvent,
        context_id: &str,
        event_tx: Option<
            &tokio::sync::broadcast::Sender<(
                String,
                scp_protocol::context::membership::ContextEvent,
            )>,
        >,
    ) {
        crate::context::state::emit_event_into(self.receive_buffer, event, context_id, event_tx);
    }
}

impl<'a> ConsequenceStateSplit<'a> {
    /// Build a [`ConsequenceStateSplit`] DIRECTLY from a `&mut PerContextState`,
    /// with NO owning [`ClassSCell`] / [`ClassCMut`] in scope (the cell-free
    /// governance-helper consequence sites). Mirrors `ClassCSplit::from_state`'s
    /// disjoint destructure, but wraps `role_state` in the GROW-capable
    /// [`ConsequenceRoleStateMut`]. The Class-S sub-structs `class_s` (actor) and
    /// `governance.class_s` are never bound `&mut` (left to the `..` rest / the
    /// `GovernanceClassCMut` `..`); `membership` is narrowed to shared `&`.
    pub fn from_state(state: &'a mut PerContextState) -> Self {
        let PerContextState {
            governance,
            role_state,
            membership,
            receive_buffer,
            checkpoint_events_since,
            ..
        } = state;
        Self {
            governance: GovernanceClassCMut::new(governance),
            role_state: ConsequenceRoleStateMut::from_parts(role_state.class_c_parts()),
            membership: &*membership,
            receive_buffer,
            checkpoint_events_since,
        }
    }
}

/// Operations a domain crate runs on this view's own fields. A `ClassCMut` comes
/// only from a `ClassSCell` combinator, so these are callable only by code that
/// core lent a cell (ADR-070 §4).
impl ClassCMut<'_> {
    /// Runs the synchronous terminal phase of a TTL expiry on this context: the
    /// `Expired` transition of its handle and the scope-driven destruction of
    /// its actor-owned keys (spec §5.4.5). `prior_completed` is the
    /// completed-step bitmask of an earlier attempt, so a retry re-runs only
    /// the failed step.
    #[must_use]
    pub fn apply_ttl_terminal_transition(
        &mut self,
        prior_completed: u8,
    ) -> crate::context::ttl::TtlExpiryResult {
        crate::context::ttl::apply_ttl_terminal_transition(
            self.handle,
            self.mode.crypto_mut(),
            prior_completed,
        )
    }
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 scaffolding: the field-granular Class-C view accessors (`governance_class_c_mut`, `members_mut`, `receive_buffer_mut`, `emit_event`, `role_state_class_c_mut`, `membership_class_c_mut`, `checkpoint_events_since_mut`, `generation_mut`, `handle_mut`, `event_log_mut`, `payment_receipts_mut`, `broadcast_class_c_mut`, `migration_state_mut`, `epoch_mut`, `access_mut`, `ttl_mut`, `routing_mut`, `sequence_tracker_mut`, `reorder_buffer_mut`, `pending_commits_mut`, `commit_fault_mut`, `checkpoint_last_time_secs_mut`, `checkpoints_mut`, `last_seen_remote_checkpoint_mut`, `send_tracker_mut`, `recv_tracker_mut`, `xctx_ucan_proofs_mut`, `welcome_scratchpad_mut`, `lifecycle_state_mut`, `mode_mut`, `class_s`, `split_class_c`, `consequence_split`) get their first PRODUCTION callers when the best-effort handlers + `ConsequenceStateSplit` migrate onto the combinators. Exercised by this module's unit tests now."
)]
impl<'a> ClassCMut<'a> {
    /// Wrap a borrowed [`PerContextState`] by DESTRUCTURING it into the disjoint
    /// field references this view holds. Crate-internal: only the combinators
    /// construct a view.
    ///
    /// The single destructuring `let` is what makes the airtightness structural:
    /// the whole `&mut PerContextState` is consumed here and only field-granular
    /// references survive (a `&mut` per writable Class-C / structural field, a
    /// shared `&` to Class-S and membership, and a [`GovernanceClassCMut`] over
    /// the governance bucket). The view never holds a whole-state `&mut`, so no
    /// accessor can return one.
    const fn new(state: &'a mut PerContextState) -> Self {
        // SAFETY INVARIANT (ADR-049 §9 — rationale in this type's doc above). When
        // adding a field here: any field that is, or transitively contains, a
        // Class-S sub-struct (`ClassSState` / `GovernanceClassS`) MUST be bound a
        // shared `&` (coerced at the `Self { .. }` init), or wrapped in a sub-view
        // — NEVER handed out `&mut`. Today: `class_s` is bound and stored as a
        // shared `&` (the `Self` field is `&'a …`, so the `&mut` ergonomic
        // binding reborrows down to `&`); `membership` is kept `&mut` BUT
        // `MembershipState` contains NO Class-S sub-struct (member REMOVAL is a
        // Class-S *operation*, exposed nowhere on this view — `membership_class_c_mut`
        // hands out a restricted `MembershipClassCMut` with no `remove_member`
        // and no whole `&mut`); and `governance` is wrapped in
        // `GovernanceClassCMut` (its own `class_s` falls into that sub-view's `..`
        // rest). Every other field is a Class-C / structural `&mut`.
        let PerContextState {
            members,
            receive_buffer,
            role_state,
            checkpoint_events_since,
            generation,
            handle,
            event_log,
            payment_receipts,
            broadcast_context,
            migration_state,
            epoch,
            access,
            ttl,
            routing,
            sequence_tracker,
            reorder_buffer,
            pending_commits,
            commit_fault,
            checkpoint_last_time_secs,
            checkpoints,
            last_seen_remote_checkpoint,
            send_tracker,
            recv_tracker,
            xctx_ucan_proofs,
            welcome_scratchpad,
            lifecycle_state,
            mode,
            membership,
            class_s,
            governance,
            ..
        } = state;
        Self {
            members,
            receive_buffer,
            role_state,
            checkpoint_events_since,
            generation,
            handle,
            event_log,
            payment_receipts,
            broadcast_context,
            migration_state,
            epoch,
            access,
            ttl,
            routing,
            sequence_tracker,
            reorder_buffer,
            pending_commits,
            commit_fault,
            checkpoint_last_time_secs,
            checkpoints,
            last_seen_remote_checkpoint,
            send_tracker,
            recv_tracker,
            xctx_ucan_proofs,
            welcome_scratchpad,
            lifecycle_state,
            mode,
            membership,
            // BLACK-CS-01: wrap the shared Class-S reach in `SharedClassS` (no
            // `&mut` accessor, no `DerefMut`) — re-arming `&mut` now requires three
            // central edits, not a one-token flip of this binding.
            class_s: SharedClassS::new(class_s),
            governance: GovernanceClassCMut::new(governance),
        }
    }

    /// Test-only reach into [`Self::from_state`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub const fn from_state_for_test(state: &'a mut PerContextState) -> Self {
        Self::from_state(state)
    }

    /// Build a [`ClassCMut`] DIRECTLY from a `&mut PerContextState`, with NO
    /// owning [`ClassSCell`] in scope.
    ///
    /// This is the cell-free bridge — the [`ClassCMut`] counterpart of
    /// `ClassCSplit::from_state` — for the receive-cascade sites that hold a
    /// bare `&mut PerContextState` (the `deliver_message_and_drain_buffered` unit
    /// tests exercise `deliver_incoming` with a bare `&mut PerContextState`, with
    /// no cell to call [`ClassSCell::class_c_view`] through). A cell holder
    /// reaches the SAME view via `cell.class_c_view()`; this exposes it without a
    /// cell.
    ///
    /// # Airtight BY CONSTRUCTION — identical to [`ClassSCell::class_c_view`]
    ///
    /// This delegates to `Self::new`, which performs the SINGLE disjoint
    /// destructure that is the airtightness guarantee: the whole
    /// `&mut PerContextState` is consumed and only field-granular references
    /// survive. It holds NO whole `&mut PerContextState`, NO whole
    /// `&mut GovernanceState` (the `governance` bucket is wrapped in a
    /// [`GovernanceClassCMut`], leaving `governance.class_s` in its `..` rest),
    /// and NO `&mut` to [`ClassSState`] (the actor's `class_s` is bound a shared
    /// `&`). A Class-S mutation through this view is therefore a COMPILE error by
    /// construction — exactly as through the cell path — so the absence of a
    /// fail-closed persist here is safe: every mutation it exposes is Class-C /
    /// structural (coalesce-window rollback acceptable).
    pub(crate) const fn from_state(state: &'a mut PerContextState) -> Self {
        Self::new(state)
    }

    /// Field-granular `&mut` access to the governance bucket via a
    /// [`GovernanceClassCMut`] sub-view, which exposes only the Class-C
    /// governance fields and CANNOT reach `governance.class_s`. This is the ONLY
    /// governance reach on this view — there is deliberately no `governance_mut`
    /// returning `&mut GovernanceState`, because that whole-bucket `&mut` would be
    /// a `&mut` path to a Class-S-containing struct (see the type doc). Returns a
    /// `&mut` to the held [`GovernanceClassCMut`] sub-view.
    pub const fn governance_class_c_mut(&mut self) -> &mut GovernanceClassCMut<'a> {
        &mut self.governance
    }

    /// Test-only reach into [`Self::members_mut`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub const fn members_mut_for_test(&mut self) -> &mut HashSet<DID> {
        Self::members_mut(self)
    }

    /// `&mut` access to the active-member DID set (Class-C / structural). Safe to
    /// hand out directly: `HashSet<DID>` contains no Class-S sub-struct.
    pub(crate) const fn members_mut(&mut self) -> &mut HashSet<DID> {
        self.members
    }

    /// `&mut` access to the receive event buffer (Class-C / structural). Safe to
    /// hand out directly: it contains no Class-S sub-struct.
    pub const fn receive_buffer_mut(&mut self) -> &mut ReceiveBuffer {
        self.receive_buffer
    }

    /// Emit a [`scp_protocol::context::membership::ContextEvent`] into the
    /// receive buffer (and, for non-secret variants, a sanitized copy onto the
    /// broadcast channel). Class-C / structural — field-granular over
    /// `receive_buffer` ONLY, delegating to
    /// [`crate::context::state::emit_event_into`] (the same security invariants:
    /// `WelcomeGenerated` never broadcasts, message payloads are stripped before
    /// broadcast). The buffered event is best-effort / coalesce-window-rollback
    /// acceptable. Domain crates call it on a view core lent them (ADR-070 §4).
    pub fn emit_event(
        &mut self,
        event: scp_protocol::context::membership::ContextEvent,
        context_id: &str,
        tx: Option<
            &tokio::sync::broadcast::Sender<(
                String,
                scp_protocol::context::membership::ContextEvent,
            )>,
        >,
    ) {
        crate::context::state::emit_event_into(self.receive_buffer, event, context_id, tx);
    }

    /// RESTRICTED Class-C view over the dual-use [`ContextRoleState`]: a
    /// [`RoleStateClassCMut`] that exposes `&mut` ONLY for the structural /
    /// Class-C fields (role definitions, assignments, the member set, derived
    /// capabilities), the SHRINK-only suspension prune, and a `system_assign_role`
    /// that mints over those fields — plus shared `&` READS for the
    /// downward-authorization Class-S fields (`ceiling`, `suspended_capabilities`).
    /// There is deliberately NO whole-`&mut` `role_state_mut` accessor and NO GROW
    /// (`suspend_capabilities` / `suspend_all`) on this view (the GROW path lives
    /// ONLY on the consequence-only [`ConsequenceRoleStateMut`] carried by
    /// [`Self::consequence_split`]). Use this for best-effort / compensation /
    /// structural mutations of the role state, so a §9 downward-auth GROW bypass is
    /// a compile error by construction.
    pub fn role_state_class_c_mut(&mut self) -> RoleStateClassCMut<'_> {
        RoleStateClassCMut::new(self.role_state)
    }

    /// SHARED (read-only) access to the whole [`ContextRoleState`]. Safe to hand
    /// out a `&ContextRoleState` from the best-effort surface: a read cannot
    /// mutate the dual-use downward-auth Class-S fields (`ceiling` /
    /// `suspended_capabilities`), so it raises no §9 fail-closed obligation. Use
    /// this for read-only needs (capability checks, snapshotting/cloning the role
    /// state); structural mutations use [`Self::role_state_class_c_mut`] (there is
    /// no whole-`&mut` accessor).
    #[must_use]
    pub const fn role_state(&self) -> &ContextRoleState {
        self.role_state
    }

    /// RESTRICTED Class-C view over the dual-use [`MembershipState`] roster: a
    /// [`MembershipClassCMut`] that forwards ONLY the structural mutators (member
    /// ADD, per-member sequence bookkeeping) and the reads — it exposes NO
    /// `remove_member` (member REMOVAL is a downward-auth Class-S transition that
    /// must be fail-closed) and no whole `&mut MembershipState`. Use this for
    /// best-effort / compensation structural mutations of the roster.
    pub const fn membership_class_c_mut(&mut self) -> MembershipClassCMut<'_> {
        MembershipClassCMut::new(self.membership)
    }

    /// `&mut` access to the events-since-last-checkpoint counter (Class-C /
    /// §9.9.3). Bumped by consequence/checkpoint enforcement; best-effort
    /// rollback acceptable.
    pub const fn checkpoint_events_since_mut(&mut self) -> &mut u64 {
        self.checkpoint_events_since
    }

    /// `&mut` access to the monotonic generation counter (Class-C / structural).
    /// Best-effort rollback acceptable.
    pub(crate) const fn generation_mut(&mut self) -> &mut u64 {
        self.generation
    }

    /// `&mut` access to the full-fat context handle (creation params + lifecycle
    /// FSM) (Class-C / structural). Best-effort rollback acceptable.
    pub const fn handle_mut(&mut self) -> &mut ContextHandle {
        self.handle
    }

    /// `&mut` access to the optional RFC-6962 Merkle event log (Class-C /
    /// structural). Best-effort rollback acceptable; the durable leaf sequence is
    /// the event-log adapter's own concern.
    pub(crate) const fn event_log_mut(&mut self) -> &mut Option<ContextEventLog> {
        self.event_log
    }

    /// `&mut` access to the bounded payment-receipt ring buffer (Class-C /
    /// §19.11). A per-member in-memory sliding window, not the durable ledger —
    /// best-effort rollback acceptable.
    pub const fn payment_receipts_mut(&mut self) -> &mut VecDeque<PaymentReceipt> {
        self.payment_receipts
    }

    /// FIELD-GRANULAR best-effort broadcast view (ADR-049 §9, §5.14.8
    /// mutation-surface confinement). Returns [`None`] for a non-broadcast
    /// context. Exposes ONLY the benign publish-path / roster methods
    /// (`subscribe` / `unsubscribe` / `unblock_subscriber` / `reserve_publish` /
    /// `apply_reserved_publish` / `rollback_reserved_publish` / `publish` /
    /// `publish_metadata`). It holds the [`BroadcastContextClassCParts`] disjoint
    /// refs — NOT a whole `&mut BroadcastContext` — so the downward-authorization
    /// security mutators (`block_subscriber`, `block_author`,
    /// `governance_ban_subscriber`, `rotate_all_author_keys`) are UNREACHABLE
    /// through this view: they are inherent `&mut self` on `BroadcastContext`,
    /// reachable only through a whole `&mut BroadcastContext` a fail-closed
    /// combinator hands out via [`ClassSMut::rest_mut`]. Mirrors
    /// [`ClassCMut::role_state_class_c_mut`] → [`RoleStateClassCMut`].
    pub fn broadcast_class_c_mut(&mut self) -> Option<BroadcastContextClassCMut<'_>> {
        self.broadcast_context
            .as_mut()
            .map(BroadcastContextClassCMut::new)
    }

    /// `&mut` access to the optional active migration state (Class-C / §5.11A).
    /// Best-effort rollback acceptable.
    pub const fn migration_state_mut(&mut self) -> &mut Option<MigrationState> {
        self.migration_state
    }

    /// `&mut` access to the MLS epoch + reconnection state (Class-C / §5.9,
    /// §23.11). Best-effort rollback acceptable.
    pub const fn epoch_mut(&mut self) -> &mut EpochState {
        self.epoch
    }

    /// `&mut` access to the access-control / CEK-wrapping exclusion state
    /// (Class-C / ADR-038, §9.17). Best-effort rollback acceptable.
    pub const fn access_mut(&mut self) -> &mut AccessControlState {
        self.access
    }

    /// `&mut` access to the TTL timer + extension state (Class-C / SCP-021).
    /// Best-effort rollback acceptable.
    pub const fn ttl_mut(&mut self) -> &mut TtlState {
        self.ttl
    }

    /// `&mut` access to the per-context routing strategy (Class-C / §9.10.4,
    /// §5.14). Best-effort rollback acceptable.
    pub const fn routing_mut(&mut self) -> &mut ContextRouting {
        self.routing
    }

    /// `&mut` access to the per-sender anti-replay sequence tracker (Class-C /
    /// §9.8.2). The Class-S replay witnesses live in `class_s` /
    /// `governance.class_s`; this structural high-water tracker is best-effort.
    pub const fn sequence_tracker_mut(&mut self) -> &mut SequenceTracker {
        self.sequence_tracker
    }

    /// `&mut` access to the per-sender reorder buffer (Class-C / §9.8.5).
    /// Best-effort rollback acceptable.
    pub const fn reorder_buffer_mut(&mut self) -> &mut ReorderBuffer {
        self.reorder_buffer
    }

    /// Drain timed-out reorder-buffer gaps (Class-C / §9.8.5). Bundles the
    /// simultaneous `&mut reorder_buffer` + `&sequence_tracker` borrow that
    /// [`ReorderBuffer::drain_timed_out`] needs — both are distinct fields of
    /// this view, so the aliasing is sound by construction, and keeping it behind
    /// one method spares callers a borrow bundle. Best-effort: a coalesce-window
    /// rollback of a drained gap is acceptable.
    pub fn drain_timed_out_gaps(
        &mut self,
        now_ms: u64,
    ) -> Vec<(
        scp_protocol::envelope::validation::GapInfo,
        Vec<scp_protocol::envelope::validation::BufferedMessage>,
    )> {
        self.reorder_buffer
            .drain_timed_out(now_ms, self.sequence_tracker)
    }

    /// `&mut` access to the MLS Commit retry queue (Class-C / §9.9.3).
    /// Best-effort rollback acceptable.
    pub const fn pending_commits_mut(&mut self) -> &mut VecDeque<PendingCommit> {
        self.pending_commits
    }

    /// `&mut` access to the commit-fault fail-close marker (Class-C / structural).
    /// Best-effort rollback acceptable.
    pub const fn commit_fault_mut(&mut self) -> &mut Option<CommitFaultMarker> {
        self.commit_fault
    }

    /// The three disjoint Class-C `&mut` fields the MLS-Commit broadcast-failure
    /// apply (`scp_runtime_governance::helpers::apply_broadcast_failure`)
    /// mutates, bundled so a cell holder can pass all three at once. Each is a
    /// distinct field of this view, so the simultaneous `&mut` is sound by
    /// construction. This view supplies them COALESCED (best-effort); the
    /// safety-gated sites instead supply them from a `commit_class_s_keep`
    /// `rest_mut()` view for a fail-closed persist.
    pub const fn commit_broadcast_borrows(&mut self) -> CommitBroadcastBorrows<'_> {
        CommitBroadcastBorrows {
            pending_commits: self.pending_commits,
            commit_fault: self.commit_fault,
            receive_buffer: self.receive_buffer,
        }
    }

    /// `&mut` access to the last-checkpoint timestamp (Class-C / §9.9.3).
    /// Best-effort rollback acceptable.
    pub(crate) const fn checkpoint_last_time_secs_mut(&mut self) -> &mut u64 {
        self.checkpoint_last_time_secs
    }

    /// Test-only reach into [`Self::checkpoints_mut`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub const fn checkpoints_mut_for_test(&mut self) -> &mut Vec<ConsistencyCheckpoint> {
        Self::checkpoints_mut(self)
    }

    /// `&mut` access to the locally generated consistency checkpoints (Class-C /
    /// §9.9.3). Best-effort rollback acceptable.
    pub(crate) const fn checkpoints_mut(&mut self) -> &mut Vec<ConsistencyCheckpoint> {
        self.checkpoints
    }

    /// `&mut` access to the per-sender remote-checkpoint divergence dedup set
    /// (Class-C / §9.9.3). Receiver-minted equivocation evidence, not a
    /// sender-authenticated replay witness — best-effort (at most one bounded
    /// duplicate alert on coalesce-window rollback).
    pub const fn last_seen_remote_checkpoint_mut(
        &mut self,
    ) -> &mut HashMap<DID, HashSet<(u64, [u8; 32])>> {
        self.last_seen_remote_checkpoint
    }

    /// `&mut` access to the send-sequence counter with RAII rollback (Class-C).
    /// Best-effort rollback acceptable.
    pub const fn send_tracker_mut(&mut self) -> &mut SendSequenceTracker {
        self.send_tracker
    }

    /// `&mut` access to the per-sender receive-sequence high-water marks
    /// (Class-C). Best-effort rollback acceptable.
    pub(crate) const fn recv_tracker_mut(&mut self) -> &mut RecvSequenceTracker {
        self.recv_tracker
    }

    /// `&mut` access to the reconstructable cross-context UCAN proof store
    /// (Class-C / §6.2.4). Interface state repopulated when the outlet interface is
    /// re-established — explicitly NOT the Class-S freshness/replay witness
    /// (`class_s.xctx_nonce_dedup`), so best-effort rollback is acceptable.
    pub(crate) const fn xctx_ucan_proofs_mut(&mut self) -> &mut InMemoryProofResolver {
        self.xctx_ucan_proofs
    }

    /// `&mut` access to the multi-step Welcome scratchpad (Class-C / structural).
    /// Best-effort rollback acceptable.
    pub(crate) const fn welcome_scratchpad_mut(&mut self) -> &mut Option<WelcomeProcessing> {
        self.welcome_scratchpad
    }

    /// `&mut` access to the actor-internal lifecycle state (Class-C / structural).
    /// Best-effort rollback acceptable.
    pub const fn lifecycle_state_mut(&mut self) -> &mut ContextLifecycleState {
        self.lifecycle_state
    }

    /// `&mut` access to the mode-specific state (Class-C / structural). Best-effort
    /// rollback acceptable.
    pub const fn mode_mut(&mut self) -> &mut ContextModeState {
        self.mode
    }

    /// READ-ONLY access to the Class-S [`ClassSState`] sub-struct. Field-granular
    /// `&`-read, replacing the removed whole-state [`Deref`] read of `class_s`.
    /// There is NO `&mut` counterpart on this view — a mutation of the actor's
    /// `ClassSState` from the best-effort / compensation path is a compile error by
    /// construction. (This is one of the three privatized Class-S fields; the
    /// dual-use `ContextRoleState.ceiling` / `suspended_capabilities` pair is now
    /// covered by a complementary structural guarantee — privatized + GROW-confined
    /// to the consequence-only view, see the module section above.)
    #[must_use]
    pub const fn class_s(&self) -> &ClassSState {
        self.class_s.get()
    }

    // NOTE: This view intentionally holds NO whole `&mut PerContextState` /
    // `&mut GovernanceState` and NO `&mut` to any Class-S-containing struct, so
    // it CANNOT grow a `rest_mut` / `governance_mut` whole-bucket accessor (there
    // is no value of that type to return). More field-granular SAFE accessors
    // (for other Class-C / structural `PerContextState` fields — never `class_s`
    // or whole `governance`) are added here as handlers migrate onto the
    // best-effort combinator; each takes a field reference already destructured
    // apart in `new`.

    /// Reborrow the held disjoint Class-C structural fields into a
    /// [`ClassCSplit`], for the
    /// [`crate::context::actor::class_s::ConsequenceStateSplit`] pattern. The
    /// view ALREADY holds five distinct field references (destructured apart in
    /// `Self::new`), so all five borrows are live simultaneously. None is
    /// Class-S: governance is the field-granular [`GovernanceClassCMut`] (which
    /// cannot reach `governance.class_s`), and `class_s` itself is not handed out
    /// here (the split is for the structural consequence path).
    pub fn split_class_c(&mut self) -> ClassCSplit<'_> {
        ClassCSplit {
            governance: self.governance.reborrow(),
            // Field-granular role view (ADR-049 §9): NO whole `&mut`, NO GROW path.
            role_state: RoleStateClassCMut::new(&mut *self.role_state),
            // SHARED reborrow: the consequence/split path reads membership only,
            // so the held `&mut` is narrowed to `&` here (unchanged behaviour).
            membership: &*self.membership,
            receive_buffer: &mut *self.receive_buffer,
            checkpoint_events_since: &mut *self.checkpoint_events_since,
        }
    }

    /// Produce the CONSEQUENCE-ENGINE split (ADR-049 §9 / RED-CS3 / R1): identical
    /// disjoint borrows to [`Self::split_class_c`], but `role_state` is the
    /// GROW-capable [`ConsequenceRoleStateMut`]. Used by the consequence sites
    /// (receive / send / outlet-settle / periodic sweep), whose cell-holding caller
    /// persists any applied downward-auth GROW / demotion FAIL-CLOSED.
    ///
    /// NOTE — this method, like [`Self::split_class_c`], is on the best-effort
    /// [`ClassCMut`] (reachable from [`ClassSCell::class_c_view`]). So the GROW is
    /// NOT structurally unreachable from a `ClassCMut` holder: choosing
    /// `consequence_split` (GROW-capable) vs `split_class_c` (no GROW accessor) is
    /// CALLER DISCIPLINE. The §9 guarantee for the GROW path is the cell-holding
    /// caller's fail-closed persist (RED-CS3), NOT impossibility. What IS structural
    /// is that a caller who took `split_class_c` cannot then GROW (its
    /// `RoleStateClassCMut` has no GROW accessor — a compile error).
    pub fn consequence_split(&mut self) -> ConsequenceStateSplit<'_> {
        ConsequenceStateSplit {
            governance: self.governance.reborrow(),
            role_state: ConsequenceRoleStateMut::from_parts(self.role_state.class_c_parts()),
            membership: &*self.membership,
            receive_buffer: &mut *self.receive_buffer,
            checkpoint_events_since: &mut *self.checkpoint_events_since,
        }
    }

    /// Test seam: registers `author_did` as a broadcast author with an initial
    /// epoch, mirroring the author-publish/add path. Bypasses the governance
    /// round-trip.
    ///
    /// Mirrors the rationale of
    /// [`MessagingCommand::SeedPeerPseudonym`](crate::context::actor::commands::MessagingCommand::SeedPeerPseudonym):
    /// single-node integration tests cannot drive genuine governance to produce
    /// a second broadcast author; this seam populates the author registry so
    /// multi-author KEA-leaf and counter tests can exercise the real code path.
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MembershipFailed`] if not a broadcast context,
    /// or [`ContextError::PermissionDenied`] if the author is already
    /// registered (matches
    /// [`BroadcastContext::add_author`](scp_protocol::context::BroadcastContext::add_author)).
    #[cfg(feature = "testing")]
    pub fn seed_broadcast_author(
        &mut self,
        author_did: &scp_did::DID,
    ) -> Result<(), scp_protocol::context::ContextError> {
        self.broadcast_context
            .as_mut()
            .ok_or_else(|| {
                scp_protocol::context::ContextError::MembershipFailed(
                    "seed_broadcast_author: not a broadcast context".into(),
                )
            })?
            .add_author(author_did.as_ref())
            .map(|_| ())
    }
}

scp_runtime_types::pub_under_testing! {
    /// Outcome of a [`ClassSCell::commit_class_s_then_append`] that did not complete
    /// cleanly (the post-persist `after` step failed, or a persist failed).
    ///
    /// `durability_diverged` is a DURABILITY-DIVERGENCE flag, NOT an "in-memory
    /// changed relative to pre-`f`" flag. It answers the only question the caller
    /// needs: *could the durable (persisted) state disagree with the in-memory state
    /// this call returns?* See the field doc for the exact contract.
    ///
    /// Core-internal; `pub` under `testing` for the runtime crates' tests (ADR-070 §5).
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
        /// rolled back to pre-`f`, yet `durability_diverged` is `true` because
        /// durability diverged. Durability-divergence is the meaning the caller acts
        /// on.
        pub(crate) durability_diverged: bool,
        /// The error that terminated the operation (the `after` error, or the
        /// re-persist error if the rollback could not be made durable).
        pub(crate) err: ContextError,
    }
}

/// Test-only reach into an [`AppendOutcomeError`]'s fields. Compiled only
/// under `testing`, so no production or bridge build reaches it (ADR-070 §4).
#[cfg(any(test, feature = "testing"))]
impl AppendOutcomeError {
    /// `(durability_diverged, err)`.
    #[must_use]
    pub fn into_parts_for_test(self) -> (bool, ContextError) {
        (self.durability_diverged, self.err)
    }
}

/// Owns one [`PerContextState`] and gates every mutation behind a
/// persistence combinator (ADR-049 §9 Class S).
///
/// Reads go through [`Deref`]; there is intentionally no [`DerefMut`](std::ops::DerefMut) (see the
/// module docs). Mutations go through the view-typed combinators
/// ([`Self::commit_class_s_keep`] / `_restore` / `_compensating` /
/// `_keep_compensating` / `_then_append` for fail-closed persist,
/// [`Self::commit_class_c_best_effort`] for best-effort).
pub struct ClassSCell {
    /// The wrapped state. Private — the only mutable access is through the
    /// persist-on-commit combinators (or the single sanctioned no-persist
    /// [`Self::clear_committed_reservation_idempotent`]). There is no `state_mut`
    /// escape hatch and no `DerefMut`.
    state: PerContextState,
    /// Number of mutable views this cell has handed out over `state` since
    /// construction (ADR-049 §9). Every combinator, token discharge, and view
    /// accessor that constructs a [`ClassSMut`] or [`ClassCMut`] over `state`
    /// advances it at the point where a mutation can have been applied, so a
    /// caller that reads [`Self::mutation_epoch`] before a fallible sequence and
    /// compares after it learns whether that sequence can have touched the
    /// state. `execute_governance_action` reads it to decide what a dispatch
    /// error means: an unchanged epoch proves the helper applied no effect, so
    /// the proposal's replay marker can be dropped and the proposal retried; a
    /// changed epoch means a retry would re-apply an effect, so the marker
    /// stays. In-memory only: never persisted, never part of a snapshot, and
    /// reset to zero on every respawn.
    mutation_epoch: u64,
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
    /// Test-only reach into [`Self::new`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub const fn new_for_test(state: PerContextState) -> Self {
        Self::new(state)
    }

    /// Wrap an owned [`PerContextState`].
    pub(crate) const fn new(state: PerContextState) -> Self {
        Self {
            state,
            mutation_epoch: 0,
        }
    }

    /// The count of mutable views handed out over the wrapped state so far.
    /// Two reads that return the same value prove that no [`ClassSMut`] and no
    /// [`ClassCMut`] was constructed between them, so no mutation can have
    /// been applied to the state in that interval. See the field doc.
    pub const fn mutation_epoch(&self) -> u64 {
        self.mutation_epoch
    }

    /// Unwrap, returning the owned [`PerContextState`]. Used at ownership
    /// hand-off boundaries (e.g. draining state out of the actor on shutdown /
    /// replace).
    ///
    /// `dead_code` allow: the current callers are `#[cfg(test)]` (the supervisor /
    /// lifecycle hand-off tests); its first non-test caller is the shutdown/replace
    /// drain migration. Exercised by this module's unit tests today.
    #[allow(dead_code)]
    pub(crate) fn into_inner(self) -> PerContextState {
        self.state
    }

    /// Idempotent straggler cleanup of a committed cross-context reservation
    /// (ADR-049 §9). NO fail-closed persist — DELIBERATELY. Safe because: the
    /// committed terminal is already durably witnessed by `xctx_committed_invocations`
    /// (the only caller checks `contains(&saga_id)` first); a removal here is the rare
    /// re-ack straggler, idempotent, and rebuilt-irrelevant on respawn. Adding a persist
    /// would turn an idempotent `Ok` re-ack into a fallible write. This is a single named
    /// operation, NOT a general no-persist escape — it can never widen to a closure form.
    /// Production caller: `commit_a`'s committed-terminal replay arm. It is the ONE
    /// no-persist Class-S mutator on the allowlist enforced by
    /// `class_s_no_persist_mutator_whitelist_is_bounded`.
    pub fn clear_committed_reservation_idempotent(
        &mut self,
        saga_id: &scp_runtime_types::context::supervisor::saga_journal::SagaId,
    ) -> bool {
        let removed = self
            .state
            .class_s
            .xctx_caller_reservations
            .remove(saga_id)
            .is_some();
        if removed {
            self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        }
        removed
    }

    /// Set the monotonic generation counter directly (test fixtures only).
    ///
    /// Parity with [`ClassSCommitToken::new_for_test`]: `generation` is a
    /// Class-C / structural field, so a test may seed it without routing through
    /// a persist combinator. Test-only — gated behind `#[cfg(any(test, feature = "testing"))]`.
    #[cfg(any(test, feature = "testing"))]
    pub const fn set_generation_for_test(&mut self, g: u64) {
        self.state.generation = g;
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
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
    pub async fn commit_class_s_keep<T>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<T, ContextError>,
    ) -> Result<T, ContextError> {
        let value = f(ClassSMut::new(&mut self.state))?;
        // Keep-direction: the mutation stays in memory whether or not the
        // persist lands, so it counts from here.
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        persist_state_fail_closed(&self.state, deps, context_id)
            .await
            .map(|()| value)
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
    /// `GovernanceClassS::snapshot`/`GovernanceClassS::restore`) — there is no
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
    pub async fn commit_class_s_restore<T>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<T, ContextError>,
    ) -> Result<T, ContextError> {
        let class_s_snap = self.state.class_s.snapshot();
        let gov_snap = self.state.governance.class_s.snapshot();
        let value = f(ClassSMut::new(&mut self.state))?;
        match persist_state_fail_closed(&self.state, deps, context_id).await {
            Ok(()) => {
                // Restore-direction: only a persisted mutation survives, so
                // only the persisted arm counts.
                self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
                Ok(value)
            }
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
    pub async fn commit_class_s_compensating<T, X>(
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
        match persist_state_fail_closed(&self.state, deps, context_id).await {
            Ok(()) => {
                // Restore-direction: only the persisted arm counts (the failure
                // arm restores the Class-S state and compensates the external
                // effect, so nothing of `f` survives it).
                self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
                Ok(value)
            }
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
    /// This is the shape of `reserve_outlet_economy`: it consumes a spending-UCAN
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
    pub async fn commit_class_s_keep_compensating<T, X>(
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
        // Keep-direction: the Class-S mutation stays in memory on either arm.
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        match persist_state_fail_closed(&self.state, deps, context_id).await {
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
    /// which can itself fail. This is the shape of the cross-context outlet-invoke
    /// "Commit" path (spec §6.2.4): `f` captures the committed output into Class-S
    /// (`xctx_committed_outputs`) and persists it; `after` then appends a
    /// `OutletInvoked` record to the EVENT LOG. That append targets the event-log
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
    ///    `AppendOutcomeError { durability_diverged: false, err }` (no persist
    ///    ran).
    /// 3. Persist fail-closed. On failure return
    ///    `AppendOutcomeError { durability_diverged: true, err }` — `f`'s mutation
    ///    is in memory but did not durably land (the restore is the caller's call;
    ///    this matches `*_keep`'s "report divergence, keep mutation" and signals
    ///    `durability_diverged`).
    /// 4. Run `after(&append_input, &state, deps).await` (external append). On
    ///    `Ok` return `Ok(value)` — no re-persist, since the append wrote to an
    ///    external sink, not to `ContextSnapshot`-backed in-state. On
    ///    `Err(after_err)`: RESTORE both sub-structs, RE-PERSIST.
    ///    - re-persist OK → `AppendOutcomeError { durability_diverged: false,
    ///      err: after_err }` (durable and in-memory both hold the pre-`f` value).
    ///    - re-persist Err → `AppendOutcomeError { durability_diverged: true,
    ///      err: <re-persist err> }` (could not make the rollback durable —
    ///      durable/in-memory divergence the caller must surface).
    ///
    /// # Errors
    ///
    /// Returns [`AppendOutcomeError`] carrying `f`'s error, the persist error, the
    /// `after` error, or the re-persist error — with `durability_diverged` set per
    /// the rules above.
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
                durability_diverged: false,
                err,
            })?;
        // `f` mutated the state; the restore arm below re-persists a rolled-back
        // state, but the interval still handed out a mutable view, so it counts.
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        persist_state_fail_closed(&self.state, deps, context_id)
            .await
            .map_err(|err| {
                AppendOutcomeError {
                    // `f`'s mutation is in memory but did not durably land.
                    durability_diverged: true,
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
                match persist_state_fail_closed(&self.state, deps, context_id).await {
                    // Rollback made durable: in-memory matches the pre-`f` value.
                    Ok(()) => Err(AppendOutcomeError {
                        durability_diverged: false,
                        err: after_err,
                    }),
                    // Could not make the rollback durable: hard divergence.
                    Err(repersist_err) => Err(AppendOutcomeError {
                        durability_diverged: true,
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
    pub async fn commit_class_c_best_effort(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassCMut),
    ) {
        f(ClassCMut::new(&mut self.state));
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        persist_state_best_effort(&self.state, deps, context_id).await;
    }

    /// NON-PERSISTING Class-C view (ADR-049 §9): construct a [`ClassCMut`]
    /// directly — the same restricted, airtight view
    /// [`Self::commit_class_c_best_effort`] hands to its closure — but perform
    /// NO persist.
    ///
    /// # When to use this vs [`Self::commit_class_c_best_effort`]
    ///
    /// Most actor dispatch-arm Class-C mutations rely on the run-loop's
    /// COALESCED persist, NOT a per-site persist: the run loop (`mod.rs`) tracks
    /// a `dirty` flag (set from the handler's `Outcome.mutated`) and flushes a
    /// single `persist_snapshot` after a ≤50 ms `COALESCE_INTERVAL`. Those sites
    /// must mutate Class-C state WITHOUT injecting a persist of their own —
    /// routing them through [`Self::commit_class_c_best_effort`] would add a
    /// per-site best-effort persist they do not have today, a behaviour change
    /// (an extra durable write per mutation).
    ///
    /// - Use `class_c_view` when the run loop will coalesce-persist the mutation
    ///   (the handler reports `mutated`, the loop flushes). NO persist happens
    ///   here; the view is the ONLY thing returned.
    /// - Use [`Self::commit_class_c_best_effort`] when the site must persist
    ///   immediately, best-effort, AT the mutation (e.g. a site with no
    ///   coalescing run-loop behind it).
    ///
    /// # Airtight — same view, same guarantee
    ///
    /// The returned [`ClassCMut`] is structurally identical to the one
    /// [`Self::commit_class_c_best_effort`] hands out: it holds NO whole
    /// `&mut PerContextState`, only field-granular references with a shared `&`
    /// read of Class-S — so it CANNOT mutate Class-S. The absence of a persist
    /// here is therefore safe: a Class-C mutation through this view is exactly
    /// the kind whose coalesce-window rollback is acceptable, and a Class-S
    /// mutation is a COMPILE error by construction (the view exposes no Class-S
    /// mutator), so no fail-closed-requiring transition can escape unpersisted.
    ///
    pub const fn class_c_view(&mut self) -> ClassCMut<'_> {
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        ClassCMut::new(&mut self.state)
    }

    /// Mutate Class-S state through a [`ClassSMut`] view and persist
    /// **fail-closed** ONCE, KEEPING one part of the Class-S mutation while
    /// RESTORING another on persist failure (ADR-049 §9, keep-one / restore-one
    /// split).
    ///
    /// # Decision criterion vs the other combinators
    ///
    /// The all-or-nothing combinators take a single rollback DIRECTION over the
    /// whole Class-S snapshot: [`Self::commit_class_s_keep`] keeps everything,
    /// [`Self::commit_class_s_restore`] restores everything. Some single sites
    /// stage TWO Class-S fields with OPPOSITE directions under ONE persist — a
    /// shape no all-or-nothing combinator expresses. This combinator is for
    /// exactly that: it snapshots ONLY the to-be-RESTORED portion before `f`,
    /// runs `f` (which mutates BOTH the kept and the restored field), persists
    /// fail-closed, and on persist FAILURE restores JUST the snapshotted portion
    /// (rolling that field back) while LEAVING the kept field as `f` mutated it,
    /// then returns the persist error.
    ///
    /// This is the shape of the cross-context `prepare_b` staging site
    /// (§6.2.4): under one fail-closed persist it
    /// - RECORDS an accepted replay nonce in `xctx_nonce_dedup` — KEEP direction
    ///   (un-recording it re-opens the replay window the dedup cache closes), and
    /// - STAGES the prepared projection into `saga_pending` — RESTORE direction
    ///   (a staged slot that did not durably land must be removed so a retry
    ///   re-stages cleanly).
    ///
    /// The caller supplies `snapshot_restore_field` (capture the restore-targeted
    /// portion BEFORE `f`) and `restore_on_failure` (apply that capture back on
    /// persist failure), so the split is expressed at the call site over the
    /// EXACT fields the site keeps vs restores. The combinator owns the
    /// fail-closed persist and the reject-vs-persist-failure distinction.
    ///
    /// # `f`-reject vs persist-failure (CRITICAL)
    ///
    /// An `f` REJECT (`Err`) returns immediately and runs NEITHER the persist NOR
    /// `restore_on_failure` — a rejected operation staged no durable-relevant
    /// mutation, so there is nothing to persist and nothing to roll back. ONLY a
    /// persist FAILURE (after a successful `f`) runs `restore_on_failure`. This
    /// matches `prepare_b`: a check reject must surface as a clean error with no
    /// `saga_pending` remove, distinct from a persist failure that staged the
    /// slot and must then roll it back.
    ///
    /// Sequence:
    /// 1. Capture the restore portion: `snap = snapshot_restore_field(&state)`.
    /// 2. Run `f(view)`. If `f` returns `Err(e)`, return `Err(e)` immediately —
    ///    NO persist, NO `restore_on_failure`.
    /// 3. On `Ok(value)`, persist fail-closed.
    ///    - On persist SUCCESS return `Ok(value)` — both fields are durable.
    ///    - On persist FAILURE run `restore_on_failure(&mut state.class_s, snap)`
    ///      (rolling back ONLY the restore-targeted field; the kept field stays
    ///      as `f` left it), then return the persist error.
    ///
    /// # Errors
    ///
    /// Returns `f`'s error, or [`ContextError::PersistenceFailed`] (after running
    /// `restore_on_failure`, with the KEPT field retained).
    ///
    pub async fn commit_class_s_keep_restore_split<T, S>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        snapshot_restore_field: impl FnOnce(&ClassSState) -> S,
        f: impl FnOnce(ClassSMut) -> Result<T, ContextError>,
        restore_on_failure: impl FnOnce(&mut ClassSState, S),
    ) -> Result<T, ContextError> {
        // Capture ONLY the restore-targeted portion BEFORE f (the kept portion is
        // deliberately NOT snapshotted — keep-direction has nothing to restore).
        let restore_snap = snapshot_restore_field(&self.state.class_s);
        let value = f(ClassSMut::new(&mut self.state))?;
        // Keep-direction for the kept field: it stays in memory on either arm.
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        match persist_state_fail_closed(&self.state, deps, context_id).await {
            Ok(()) => Ok(value),
            Err(persist_err) => {
                // Roll back JUST the restore-targeted field; the kept field stays
                // as f mutated it (fail-closed direction).
                restore_on_failure(&mut self.state.class_s, restore_snap);
                Err(persist_err)
            }
        }
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

    /// Run an EARLY Class-S mutation through a [`ClassSMut`] view and DEFER the
    /// fail-closed persist, returning the mutation's value paired with a linear
    /// [`ClassSCommitToken`] the caller MUST later [`commit`](ClassSCommitToken::commit)
    /// (ADR-049 §9, keep-direction).
    ///
    /// # Why this combinator exists (deferred-persist Class-S sites)
    ///
    /// The persist-on-return combinators ([`Self::commit_class_s_keep`] etc.)
    /// persist *immediately* when `f` returns. Some Class-S sites cannot do
    /// that: they consume the security-critical state EARLY (e.g. a spending-UCAN
    /// nonce burned in the economy-enforcement phase) but only learn whether the
    /// whole operation will be acknowledged MUCH LATER, after intervening async
    /// work (escrow authorization, MLS membership mutation, transport fan-out).
    /// Persisting at `f`-return would durably commit the consume before those
    /// steps could still abort and unwind it; deferring lets the SINGLE final
    /// persist cover the consume regardless of which terminal path runs.
    ///
    /// `begin_class_s` performs the EARLY mutation now (through the same
    /// fail-closed-capable [`ClassSMut`] view the persist-on-return combinators
    /// use) but does NOT persist. Instead it hands back a [`ClassSCommitToken`]:
    /// a `#[must_use]` linear handle whose [`commit`](ClassSCommitToken::commit)
    /// performs the deferred [`persist_state_fail_closed`]. Every terminal path
    /// the operation can take after `begin_class_s` MUST `commit` the token —
    /// keep-direction: the burned nonce / executed marker must become durable on
    /// EVERY exit, success or abort (un-persisting it would re-open the replay /
    /// re-spend / re-execute window). There is deliberately NO `discard`/abort
    /// helper.
    ///
    /// The `#[must_use]` attribute + the token's `Drop` guard (which
    /// `debug_assert!`s + `tracing::error!`s on an un-`commit`-ed drop, exactly
    /// mirroring [`crate::context::shared::economy::EconomyTicket`]) are the
    /// backstop: a path that forgets to `commit` fails CI loudly rather than
    /// silently acknowledging an unpersisted Class-S consume.
    ///
    /// Sequence:
    /// 1. Run `f(view)`. If `f` returns `Err(e)`, return `Err(e)` immediately and
    ///    issue NO token — a rejected operation staged no consume to discharge.
    /// 2. On `Ok(value)`, return `(value, token)` WITHOUT persisting. The caller
    ///    owns the deferred persist via [`ClassSCommitToken::commit`].
    ///
    /// # Errors
    ///
    /// Returns `f`'s error (no token issued).
    pub fn begin_class_s<T>(
        &mut self,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<T, ContextError>,
    ) -> Result<(T, ClassSCommitToken), ContextError> {
        let value = f(ClassSMut::new(&mut self.state))?;
        self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        Ok((value, ClassSCommitToken::new(context_id)))
    }

    /// Like [`Self::begin_class_s`], but the early mutation is CONDITIONAL: `f`
    /// reports (via the `bool` of its `Ok((value, did_mutate))`) whether a
    /// Class-S mutation actually happened, and a [`ClassSCommitToken`] is issued
    /// ONLY when it did (ADR-049 §9, keep-direction).
    ///
    /// The deferred-persist economy sites are conditional by nature: the
    /// enforcement helper consumes a spending-UCAN nonce only on the PAID branch
    /// (a non-zero cost AND a spending UCAN present); a FREE / best-effort send or
    /// join burns no nonce. Returning `Ok((value, false))` from `f` on the free
    /// branch yields `(value, None)` so that path stays token-free and keeps its
    /// existing best-effort persist — only the paid branch (`Ok((value, true))`)
    /// produces a token whose [`commit`](ClassSCommitToken::commit) must
    /// fail-close.
    ///
    /// Sequence:
    /// 1. Run `f(view)` → `Ok((value, did_mutate))` or `Err(e)`. On `Err`, return
    ///    it and issue NO token.
    /// 2. On `Ok((value, true))`, return `(value, Some(token))` (deferred persist
    ///    is the caller's obligation). On `Ok((value, false))`, return
    ///    `(value, None)` — no Class-S transition occurred, nothing to persist
    ///    fail-closed.
    ///
    /// # Errors
    ///
    /// Returns `f`'s error (no token issued).
    pub fn begin_class_s_conditional<T>(
        &mut self,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<(T, bool), ContextError>,
    ) -> Result<(T, Option<ClassSCommitToken>), ContextError> {
        let (value, did_mutate) = f(ClassSMut::new(&mut self.state))?;
        if did_mutate {
            self.mutation_epoch = self.mutation_epoch.wrapping_add(1);
        }
        let token = if did_mutate {
            Some(ClassSCommitToken::new(context_id))
        } else {
            None
        };
        Ok((value, token))
    }
}

/// A `#[must_use]` linear handle for a DEFERRED Class-S fail-closed persist
/// (ADR-049 §9, keep-direction).
///
/// Issued by [`ClassSCell::begin_class_s`] /
/// [`ClassSCell::begin_class_s_conditional`] AFTER an early Class-S mutation
/// (e.g. a burned spending-UCAN nonce, an inserted `executed_proposals` marker)
/// has been applied IN MEMORY but NOT yet persisted. The holder MUST eventually
/// call [`Self::commit`] on EVERY terminal path the operation can take —
/// success or abort — so the mutation becomes durable before the operation is
/// acknowledged.
///
/// # Why keep-direction, and why no `discard`
///
/// The deferred mutation is security-critical monotonic state whose un-recording
/// is the UNSAFE direction: un-burning a consumed nonce re-opens a replay /
/// double-spend window; un-marking an executed proposal re-opens a re-execute
/// window. So there is no `discard`/abort variant — every path that reached
/// `begin_*` commits, persisting the consume fail-closed even when the
/// surrounding operation is aborting for an UNRELATED reason. On a persist
/// failure the [`Self::commit`] does NOT roll the Class-S mutation back; it
/// propagates the error so the CALLER runs its existing Class-C / external
/// reversal (escrow void, economy-ticket rollback, sequence rollback) while the
/// consume stays consumed.
///
/// # The `#[must_use]` + `Drop` backstop is parity with [`EconomyTicket`](crate::context::shared::economy::EconomyTicket)
///
/// Like [`crate::context::shared::economy::EconomyTicket`], this handle carries a
/// `consumed` flag set true by [`Self::commit`], and a [`Drop`] guard that
/// `debug_assert!`s + `tracing::error!`s if it is dropped un-`commit`-ed. The
/// `#[must_use]` makes a dropped-without-commit path a compile-time warning and
/// the `Drop` guard makes it a loud CI failure — the same belt-and-braces
/// guarantee `EconomyTicket` uses so a forgotten discharge cannot silently
/// acknowledge an unpersisted Class-S consume. It carries NO snapshot
/// (keep-direction has nothing to restore).
///
/// ACCEPTED RESIDUAL (ADR-049 §9): `std::mem::forget(token)` suppresses the `Drop`
/// guard, so a deliberately-forgotten token would silently drop its owed
/// fail-closed persist. This is the UNIVERSAL Rust escape on EVERY linear handle
/// (it applies identically to [`EconomyTicket`](crate::context::shared::economy::EconomyTicket)
/// and any `#[must_use]` + `Drop` type) and is NOT defendable at the type level —
/// `mem::forget` is safe, stable, and intrinsic. It is an in-file-insider action in
/// the same threat class as editing any enforcement, and is a code-review
/// responsibility, not a structural guarantee. The legitimate "discharge without a
/// second persist" need (a redundant obligation covered by a sibling token) is
/// served by the explicit, audited [`Self::subsume`] — NOT by `mem::forget`.
#[must_use = "ClassSCommitToken must be committed — dropping leaves a Class-S consume (e.g. a burned spending nonce) unpersisted, re-opening a replay/re-spend window on crash"]
pub struct ClassSCommitToken {
    /// The context whose state the deferred persist targets. Checked against the
    /// `context_id` passed to [`Self::commit`] via `debug_assert_eq!` so a token
    /// cannot be committed against the wrong context's state.
    context_id: String,
    /// Set `true` by [`Self::commit`] BEFORE the persist runs, so the `Drop`
    /// guard treats the obligation as discharged even when the persist itself
    /// returns `Err` (keep-direction: the consume stays in memory and the error
    /// propagates to the caller's reversal).
    consumed: bool,
}

impl ClassSCommitToken {
    /// Construct an un-consumed token for `context_id`. Crate-internal: only the
    /// `begin_*` combinators and the downward-auth sink mint one.
    fn new(context_id: &str) -> Self {
        Self {
            context_id: context_id.to_owned(),
            consumed: false,
        }
    }

    /// Mint a downward-authorization fail-closed-persist obligation for the
    /// consequence-engine GROW path (ADR-049 §9, RED-CS3).
    ///
    /// The consequence-cascade sites thread a `&mut Option<ClassSCommitToken>`
    /// *sink* (owned at the cell boundary) rather than the bare `bool` they used
    /// to: when `scp_runtime_governance::logic::enforce_triggered_consequences`
    /// applies a downward-auth GROW (a `suspended_capabilities` suspension or an
    /// `AssignRole` `member_capabilities` demotion), the site populates the sink
    /// with a token via this constructor (idempotently — multiple GROWs in one
    /// cascade reuse the single owed persist), and the cell-holding caller
    /// [`commit`](Self::commit)s it AFTER the borrowing view drops. The
    /// `#[must_use]` + [`Drop`] guard then make a populated-but-undischarged sink
    /// a debug/CI PANIC (a metered counter in release) instead of the old
    /// silently-dropped `bool` — a consequence GROW that is applied but never
    /// fail-closed-persisted can no longer slip through unnoticed.
    ///
    /// This is the SAME linear handle the deferred spending-nonce sites use (it
    /// carries the same keep-direction, exactly-once persist obligation); only the
    /// *origin* of the obligation differs (a downward-auth GROW rather than a
    /// burned nonce). Minting goes through [`Self::new`] so the bounded
    /// whitelist tripwire's `ClassSCommitToken::new` persist-marker still witnesses
    /// every producer.
    pub(crate) fn for_downward_auth(context_id: &str) -> Self {
        Self::new(context_id)
    }

    /// Test-only reach into [`Self::note_downward_auth`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    #[cfg(any(test, feature = "testing"))]
    pub fn note_downward_auth_for_test(sink: &mut Option<Self>, did_grow: bool, context_id: &str) {
        Self::note_downward_auth(sink, did_grow, context_id);
    }

    /// Populate a downward-auth sink with a fresh obligation if one is not already
    /// owed (ADR-049 §9, RED-CS3). Idempotent: a cascade that applies more than one
    /// downward-auth GROW still owes EXACTLY ONE fail-closed persist (the single
    /// cell-boundary [`commit`](Self::commit) covers every mutation already in
    /// memory), so a second GROW reuses the token already in the sink rather than
    /// minting a duplicate. A no-op when `did_grow` is `false` (no downward-auth
    /// transition occurred — the caller's ordinary coalesced persist suffices).
    pub(crate) fn note_downward_auth(sink: &mut Option<Self>, did_grow: bool, context_id: &str) {
        if did_grow && sink.is_none() {
            *sink = Some(Self::for_downward_auth(context_id));
        }
    }

    /// Discharge the deferred obligation: persist the actor state **fail-closed**
    /// (ADR-049 §9), KEEPING the Class-S mutation even if the persist fails.
    ///
    /// Takes `state: &PerContextState` rather than being a method on
    /// [`ClassSCell`] DELIBERATELY: a deferred-persist site reads the actor's
    /// state (through the cell's `Deref`) at the commit point after intervening
    /// async work, so the commit point persists the `&PerContextState` it is
    /// handed rather than re-borrowing the cell. (The earlier-mutation half of
    /// the deferral is performed inside [`ClassSCell::begin_class_s`] through a
    /// [`ClassSMut`] view; this token only owns the deferred PERSIST.)
    ///
    /// Sequence:
    /// 1. `debug_assert_eq!` the token's `context_id` against the caller's, so a
    ///    token cannot be committed against another context's state.
    /// 2. Set `self.consumed = true` BEFORE persisting — so even if the persist
    ///    returns `Err`, the `Drop` guard sees the obligation as discharged (the
    ///    error is the caller's to surface; the consume is intentionally KEPT).
    /// 3. [`persist_state_fail_closed`]. On failure the Class-S mutation is NOT
    ///    rolled back (keep-direction); the error propagates so the caller runs
    ///    its existing Class-C reversal.
    ///
    /// # When to use this vs [`Self::discharge_with`]
    ///
    /// Use `commit` when the deferred persist has NO further state mutation to
    /// run at the terminal — it takes a `&PerContextState` (read-only) and simply
    /// persists the state the cell already holds. Use [`Self::discharge_with`]
    /// when ONE final Class-S mutation must land under this SAME (still-owed)
    /// persist: it takes a `&mut ClassSCell` + a closure, runs the closure through
    /// a [`ClassSMut`] view, then performs the single deferred persist. Both are
    /// keep-direction and perform EXACTLY ONE [`persist_state_fail_closed`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] when the durable write fails
    /// (the in-memory Class-S mutation is retained — keep-direction).
    ///
    /// # Not `async fn` — `Send` discipline (ADR-049 Decision 7)
    ///
    /// This is a SYNC fn that returns a future, NOT an `async fn`. It delegates to
    /// the shared [`persist_state_fail_closed`], whose synchronous prelude consumes
    /// the `&PerContextState` (building the owned snapshot) so it is NOT captured by
    /// the returned future — which holds only the owned snapshot plus
    /// `deps` / `context_id`.
    /// An `async fn` would keep the `&PerContextState` parameter in the future's
    /// captured state across the `.await`; `PerContextState` is `!Sync` (it
    /// holds a `dyn FnMut` sink), so that would make the actor's `run()` future
    /// `!Send` and fail `tokio::spawn`. `ClassSCell` intentionally has no
    /// `DerefMut`, so the `&mut`-capture escape hatch the combinators use is not
    /// available here — hence the sync-prelude shape. `use<'d, 'c>` precisely
    /// captures only the `deps` / `context_id` lifetimes (edition 2024), not the
    /// `state` borrow.
    pub fn commit<'d, 'c>(
        mut self,
        state: &PerContextState,
        deps: &'d ActorDeps,
        context_id: &'c str,
    ) -> impl std::future::Future<Output = Result<(), ContextError>> + Send + use<'d, 'c> {
        debug_assert_eq!(
            self.context_id, context_id,
            "ClassSCommitToken committed against the wrong context",
        );
        // Discharge the Drop obligation BEFORE the persist so a persist Err still
        // counts as committed (keep-direction: the consume stays, the error
        // propagates to the caller's reversal).
        self.consumed = true;
        // Delegate the single deferred fail-closed persist to the shared
        // [`persist_state_fail_closed`] helper — the canonical sync-prelude form
        // (its prelude builds the owned snapshot and drops the `&PerContextState`
        // borrow before the returned future, which then captures only the owned
        // snapshot + `deps`/`context_id`, keeping it `Send`). Sharing the one
        // helper keeps the keep-direction/fail-closed core identical across this
        // terminal and the deferred terminals `discharge_with` / `commit_fail_closed`.
        persist_state_fail_closed(state, deps, context_id)
    }

    /// Discharge the deferred obligation, running ONE final (possibly fallible)
    /// state mutation through a [`ClassSMut`] view immediately BEFORE the single
    /// fail-closed persist this token already owed (ADR-049 §9, keep-direction).
    ///
    /// This is the deferred-persist analogue of [`ClassSCell::commit_class_s_keep`]:
    /// a site that deferred its Class-S persist via [`ClassSCell::begin_class_s`]
    /// sometimes learns, at a terminal, that ONE more state mutation must land
    /// under the SAME (still-owed) persist. Two governance terminals use it:
    /// - the `execute_governance_action` dispatch-failure arm un-marks the
    ///   `executed_proposals` replay marker it staged (via
    ///   `ClassSMut::governance_class_s_mut`), and that removal must be the
    ///   state the deferred persist makes durable;
    /// - the success / finalize-failure terminal runs `finalize_governance_action`
    ///   (a Class-C body, reached via [`ClassSMut::rest_mut`]) and then performs
    ///   the token's owed persist over the finalized state.
    ///
    /// Rather than reach a whole-state `&mut` to mutate, then call
    /// [`Self::commit`] (two reaches), this runs the mutation through the same
    /// fail-closed-capable [`ClassSMut`] view the combinators use and performs the
    /// token's single deferred persist over the resulting state — EXACTLY ONE
    /// persist, KEEP-direction.
    ///
    /// `f` may itself fail. Keep-direction means the persist runs REGARDLESS of
    /// `f`'s result (the partial mutations `f` made before erroring stay and are
    /// made durable — un-doing them is the unsafe direction). The returned
    /// `Result` surfaces `f`'s error FIRST when `f` failed (after persisting),
    /// else the persist error, else `f`'s value — matching the prior
    /// "mutate (maybe-Err), then `token.commit`, then return that error/value"
    /// hand-written terminals.
    ///
    /// Takes `&mut ClassSCell` (not the bare `&PerContextState` [`Self::commit`]
    /// takes) because building the [`ClassSMut`] view needs `&mut` to the owned
    /// state; the cell is the owner.
    ///
    /// # When to use this vs [`Self::commit`]
    ///
    /// Use `discharge_with` when ONE final Class-S mutation must land under the
    /// token's still-owed persist (it needs the `&mut ClassSCell` to build the
    /// [`ClassSMut`] view for that mutation). Use the read-only [`Self::commit`]
    /// when the terminal has nothing left to mutate and only owes the persist of
    /// the state the cell already holds. Both perform EXACTLY ONE
    /// [`persist_state_fail_closed`], keep-direction.
    ///
    /// # Errors
    ///
    /// Returns `f`'s error (after the keep-direction persist still ran), or
    /// [`ContextError::PersistenceFailed`] when the durable write fails (the
    /// in-memory mutation `f` made is retained — keep-direction).
    pub async fn discharge_with<T>(
        mut self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<T, ContextError>,
    ) -> Result<T, ContextError> {
        debug_assert_eq!(
            self.context_id, context_id,
            "ClassSCommitToken discharged against the wrong context",
        );
        // Run the final mutation through the view. Discharge the Drop obligation
        // BEFORE the persist (so a persist Err still counts as committed —
        // keep-direction) and perform the single deferred persist REGARDLESS of
        // `f`'s result (keep-direction: a partial mutation `f` left must be made
        // durable; un-doing it is the unsafe direction).
        let f_result = f(ClassSMut::new(&mut cell.state));
        cell.mutation_epoch = cell.mutation_epoch.wrapping_add(1);
        self.consumed = true;
        // The SINGLE deferred fail-closed persist, routed through the shared
        // [`persist_state_fail_closed`] helper so the keep-direction/fail-closed
        // core stays identical to `ClassSDischargeGuard::commit_fail_closed`, the
        // read-only `commit`, and the combinators. Its sync prelude builds the
        // owned snapshot and drops the `&cell.state` borrow off the await point —
        // keeps the actor future `Send` (`PerContextState` is `!Sync`; ADR-049
        // Decision 7).
        let persist_result = persist_state_fail_closed(&cell.state, deps, context_id).await;
        match (f_result, persist_result) {
            // `f` failed: the persist still ran (keep); surface `f`'s error.
            (Err(f_err), _) => Err(f_err),
            // `f` succeeded but the persist failed: surface the persist error.
            (Ok(_), Err(persist_err)) => Err(persist_err),
            // Both succeeded.
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    /// Begin an `async`-body deferred discharge (ADR-049 Decision 7).
    ///
    /// RAII counterpart to [`Self::discharge_with`] for a finalize body that must
    /// `.await` while holding the `&mut PerContextState` view — e.g.
    /// `finalize_governance_action`, which appends to the async
    /// `EventLogPersistence`-backed Merkle event log AND mutates the state,
    /// interleaved, so it cannot be expressed as a synchronous `discharge_with`
    /// closure. A closure returning a borrowing future would need an
    /// `for<'a> Fn(..) -> BoxFuture<'a>` bound that (via the boxed trait-object
    /// lifetime) demands `'static` captures — hence this guard shape, which keeps
    /// a single ordinary borrow lifetime.
    ///
    /// The returned [`ClassSDischargeGuard`] hands out the `ClassSMut` view via
    /// [`ClassSDischargeGuard::view`] (held across the finalize awaits — a
    /// `&mut PerContextState` across an await is `Send`), then performs the SINGLE
    /// deferred fail-closed persist via
    /// [`ClassSDischargeGuard::commit_fail_closed`]. Semantics match
    /// `discharge_with` exactly: the `Drop` obligation is discharged BEFORE the
    /// persist, and the persist runs REGARDLESS of the finalize result
    /// (keep-direction). If the guard is dropped WITHOUT `commit_fail_closed`
    /// (e.g. the finalize body panics), the owned token's `Drop` obligation fires,
    /// exactly as an un-committed `ClassSCommitToken` would.
    pub const fn begin_discharge(self, cell: &mut ClassSCell) -> ClassSDischargeGuard<'_> {
        cell.mutation_epoch = cell.mutation_epoch.wrapping_add(1);
        ClassSDischargeGuard {
            token: self,
            state: &mut cell.state,
        }
    }

    /// Discharge this obligation because ANOTHER in-flight [`ClassSCommitToken`]
    /// already owes the SAME fail-closed persist (ADR-049 §9, keep-direction).
    ///
    /// # `subsume` PERFORMS ZERO PERSIST — sibling-commit precondition
    ///
    /// This is a DISCARD primitive: it consumes the token and defuses the `Drop`
    /// guard WITHOUT writing anything. It is sound ONLY when a SIBLING token
    /// commits the SAME whole-`cell.state` fail-closed persist. A single
    /// [`persist_state_fail_closed`] makes the WHOLE in-memory Class-S state
    /// durable, so when two obligations are owed for mutations that will both be
    /// made durable by one other token's `commit` (the canonical case: the send
    /// path's deferred spending-nonce token AND a consequence GROW armed during the
    /// same send — see `finalize_send`), only ONE persist must actually run. The
    /// covering token performs it; this redundant token is SUBSUMED — consumed
    /// WITHOUT a second persist. This is NOT a silent drop (which would trip the
    /// `Drop` guard) and NOT a `mem::forget` (which would suppress the guard
    /// universally): it is an explicit, audited discharge whose precondition is that
    /// a sibling token covers the identical persist.
    ///
    /// **Calling `subsume` WITHOUT a guaranteed sibling commit silently discards
    /// the owed fail-closed persist, re-opening the ≤50ms coalesce-window re-grant
    /// hazard.** The set of sanctioned callers is therefore bounded by the
    /// `subsume_callers_equal_the_allowlist` tripwire (`crates/scp-testing/tests/subsume_caller_allowlist.rs`): a NEW
    /// `.subsume(` caller trips CI and must be reviewed for its sibling commit. The
    /// two sanctioned production sites and their siblings are:
    ///
    /// - `crates/scp-runtime-messaging/src/helpers.rs` (paid-send reconcile) — sibling: the nonce
    ///   `ClassSCommitToken` committed in `persist_finalized_send`.
    /// - `crates/scp-runtime-governance/src/helpers.rs` (governance finalize) — sibling: the ambient
    ///   `execute_governance_action` `discharge_with` token.
    ///
    /// The `context_id` is debug-asserted against the token's own, mirroring
    /// [`Self::commit`], so a token cannot be subsumed against the wrong context.
    pub fn subsume(mut self, context_id: &str) {
        // Mark consumed BEFORE the assert so that, even on the wrong-context
        // debug-assert path, the `Drop` guard does not ALSO fire (a second panic
        // during unwinding aborts the process and masks the real assertion).
        self.consumed = true;
        debug_assert_eq!(
            self.context_id, context_id,
            "ClassSCommitToken subsumed against the wrong context",
        );
    }

    /// Mint a pre-consumed-context token for tests that drive a deferred-persist
    /// site's commit point directly (e.g. the `finalize_send` unit tests).
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_test(context_id: &str) -> Self {
        Self::new(context_id)
    }

    /// Defuse the Drop obligation WITHOUT persisting — for unit tests that
    /// exercise the obligation-arming logic (a GROW arms the sink) against a
    /// `PerContextState` with no persistence backend wired, where driving a real
    /// fail-closed `commit` would require a full `ActorDeps`. This is a test-only
    /// escape hatch: production code MUST discharge via [`Self::commit`] /
    /// [`Self::discharge_with`] (the persist is the whole point of the obligation).
    #[cfg(any(test, feature = "testing"))]
    pub fn defuse_for_test(mut self) {
        self.consumed = true;
    }
}

impl Drop for ClassSCommitToken {
    fn drop(&mut self) {
        if !self.consumed {
            // Error-level log so a leaked obligation is visible in production,
            // a metered counter so it is OBSERVABLE in release builds (where the
            // `debug_assert!` below is a no-op and `#[must_use]` is silenced by an
            // `_`-binding), and a debug-assert so CI fails loudly — parity with
            // EconomyTicket plus the release-build metric backstop (ADR-049 §9).
            tracing::error!(
                context_id = %self.context_id,
                "ClassSCommitToken dropped without commit — a Class-S consume \
                 (e.g. a burned spending nonce) may be unpersisted (ADR-049 §9)"
            );
            scp_runtime_types::metrics::record_class_s_token_dropped_uncommitted();
            debug_assert!(
                false,
                "ClassSCommitToken dropped without commit for context {}",
                self.context_id
            );
        }
    }
}

/// RAII discharge guard for an `async`-body deferred Class-S persist (ADR-049
/// Decision 7). Minted by [`ClassSCommitToken::begin_discharge`].
///
/// Holds the owed [`ClassSCommitToken`] AND the `&mut PerContextState` view for
/// the finalize body's duration, so the finalize can `.await` (its interleaved
/// async Merkle-event-log appends) while mutating the state. The SINGLE deferred
/// fail-closed persist is performed by [`Self::commit_fail_closed`]; dropping the
/// guard without committing lets the owned token's `Drop` obligation fire — so a
/// panicking finalize does not silently skip the owed persist.
pub struct ClassSDischargeGuard<'a> {
    token: ClassSCommitToken,
    state: &'a mut PerContextState,
}

impl ClassSDischargeGuard<'_> {
    /// The `ClassSMut` view over the guarded state. Called for the finalize body
    /// (via `view().rest_mut()`); the returned view may be held across the
    /// finalize awaits — a `&mut PerContextState` across an await is `Send`.
    pub const fn view(&mut self) -> ClassSMut<'_> {
        ClassSMut::new(&mut *self.state)
    }

    /// Perform the SINGLE deferred fail-closed persist and discharge the token.
    ///
    /// Mirrors [`ClassSCommitToken::discharge_with`]: the `Drop` obligation is
    /// marked discharged BEFORE the persist (so a persist `Err` still counts as
    /// committed — keep-direction), and the owned snapshot is built off the await
    /// point. Consumes the guard.
    ///
    /// # Errors
    ///
    /// The persist error. The token counts as discharged even then.
    pub async fn commit_fail_closed(
        mut self,
        deps: &ActorDeps,
        context_id: &str,
    ) -> Result<(), ContextError> {
        debug_assert_eq!(
            self.token.context_id, context_id,
            "ClassSDischargeGuard committed against the wrong context",
        );
        self.token.consumed = true;
        // Single deferred fail-closed persist via the shared
        // [`persist_state_fail_closed`] helper — identical keep-direction core to
        // `ClassSCommitToken::discharge_with`. Its sync prelude builds the owned
        // snapshot off the await point, keeping the actor future `Send`.
        persist_state_fail_closed(self.state, deps, context_id).await
    }
}

/// The three disjoint Class-C `&mut` fields `scp_runtime_governance::helpers::apply_broadcast_failure` mutates,
/// threaded as ONE struct so the caller holds all three at once (they are
/// distinct fields of [`PerContextState`], so the borrow checker accepts the
/// simultaneous `&mut`).
///
/// Replaces the prior whole `&mut PerContextState` parameter: the broadcast-
/// failure apply touches ONLY the MLS Commit retry queue (`pending_commits`), the
/// queue-full fail-close marker (`commit_fault`), and the local receive buffer
/// (`receive_buffer`). The borrow is field-granular and reaches no Class-S
/// sub-struct; the DURABILITY class is the caller's choice — the safety-gated
/// sites supply these from a `commit_class_s_keep` `rest_mut()` view (fail-closed
/// persist of `pending_commits`/`commit_fault`), the best-effort sites from a
/// coalesced `ClassCMut` view (see `scp_runtime_governance::helpers::apply_broadcast_failure`).
pub struct CommitBroadcastBorrows<'a> {
    /// `&mut` to the MLS Commit retry queue (Class-C / §9.9.3).
    pub pending_commits: &'a mut std::collections::VecDeque<PendingCommit>,
    /// `&mut` to the queue-full fail-close marker (Class-C / structural).
    pub commit_fault: &'a mut Option<CommitFaultMarker>,
    /// `&mut` to the local receive buffer (Class-C / structural).
    pub receive_buffer: &'a mut ReceiveBuffer,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use scp_did::DID;

    // Compile-time airtightness guard (ADR-049 §9): [`ClassSCell`] MUST NOT
    // implement `DerefMut`. The cell `Deref`s to `&PerContextState` (reads), and
    // that single read direction is load-bearing — a `DerefMut` would hand out a
    // `&mut PerContextState` outside any persist combinator, re-opening every
    // Class-S bypass the combinator boundary closes. If anyone ever adds
    // `impl DerefMut for ClassSCell`, this assertion fails to compile.
    //
    // The best-effort / compensation views (`ClassCMut`, `GovernanceClassCMut`)
    // need no `DerefMut` guard: they no longer `Deref` at all (the whole-bucket
    // `Deref` was removed). They hold field-granular references — a `&mut` per
    // writable Class-C field plus shared `&` to Class-S / membership — so there is
    // no whole `&mut PerContextState` / `&mut GovernanceState` for any accessor (or
    // `DerefMut`) to return. (NOTE: `ClassCMut` DOES hold a whole
    // `&mut ContextRoleState` in its `role_state` field — `ContextRoleState` carries
    // no Class-S SUB-STRUCT, and the view exposes that field only through the
    // field-granular `RoleStateClassCMut` / read accessors, NEVER a whole-`&mut`
    // `rest_mut` / `role_state_mut`; the inherent `pub` downward-auth GROW reachable
    // through such a whole `&mut` is the "path B" the module docs describe. The
    // best-effort view's lack of any whole-`&mut` accessor is a code-review property,
    // NOT a compile-witness — see the honest §9 structural account in this submodule
    // for why the prior coupled witness was shape-fragile and was deleted.)
    // Only `ClassSCell`'s no-`DerefMut` remains a `DerefMut`-guarded invariant.
    static_assertions::assert_not_impl_any!(ClassSCell: core::ops::DerefMut);

    // BLACK-CS-01 (ADR-049 §9): the Class-S reach on the best-effort `ClassCMut`
    // view is a `SharedClassS` (private `&ClassSState`, no `&mut` accessor). It
    // MUST NOT implement `DerefMut` — a `DerefMut` would hand out a
    // `&mut ClassSState` outside any persist combinator. If anyone ever adds
    // `impl DerefMut for SharedClassS`, this assertion fails to compile. (Re-arming
    // a `&mut` would also require editing the `ClassCMut.class_s` field type AND
    // `SharedClassS`'s private field AND `SharedClassS::new` — three central edits,
    // not a one-token flip — so the wrapper, not a doctest, is the guarantee.)
    static_assertions::assert_not_impl_any!(SharedClassS<'static>: core::ops::DerefMut);

    // ------------------------------------------------------------------
    // ADR-049 §9 — what actually confines the downward-auth GROW (honest
    // structural account; NOT a coupled compile-witness over method resolution)
    // ------------------------------------------------------------------
    //
    // Two shape-fragile compile-witnesses used to live here
    // (`role_view_grow_resolves_to_trait` and
    // `best_effort_view_has_no_whole_mut_accessor`). They coupled a zero-arg,
    // `&self`, trait-shim call against the real view and relied on "an inherent
    // method shadows a trait method" to turn an ADDED inherent GROW into a compile
    // error. They were DELETED because they gave FALSE structural confidence: the
    // realistic shape a maintainer would add is `fn suspend_all(&mut self, did, …)`
    // — an `&mut self`, multi-arg inherent method. At the witnesses' NON-`mut`,
    // zero-arg call site that inherent method is simply non-viable, so resolution
    // falls through to the `&self` trait shim and the witness stays GREEN. (Proven:
    // an injected `fn suspend_all(&mut self, did)` on `RoleStateClassCMut` compiled
    // with all witnesses passing.) A coupled witness over method RESOLUTION is
    // fragile to receiver mutability, arity, generics, and macros; per
    // `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` and
    // the project's "a gate adds ~zero marginal security vs an insider who can edit
    // it — prefer real type-system enforcement" philosophy, false confidence is
    // worse than none.
    //
    // What ACTUALLY confines the downward-auth GROW (the real, type-system
    // guarantees, still witnessed by the `!DerefMut` assertions above):
    //
    //   (i)  NO external `&mut` to the downward-auth maps. `ClassSCell` has no
    //        `DerefMut` (asserted above) and the Class-S fields
    //        (`suspended_capabilities`, `member_capabilities`) are PRIVATE to their
    //        defining modules. No code outside this crate's view layer can name or
    //        reach a `&mut` to them. `SharedClassS` (the best-effort view's Class-S
    //        reach) is `!DerefMut` (asserted above) and holds only a `&` — no `&mut`
    //        path exists through the best-effort view at all.
    //
    //   (ii) The ONLY whole `&mut ContextRoleState` (which reaches the inherent
    //        `pub` `ContextRoleState::suspend_*` — "path B") is handed out via
    //        `ClassSMut::rest_mut()`, and `ClassSMut` is constructed ONLY inside the
    //        fail-closed-persisting combinators (`commit_class_s_keep` /
    //        `begin_class_s`). A path-B GROW therefore always rides a fail-closed
    //        persist. The best-effort `ClassCMut` exposes NO `rest_mut` /
    //        `role_state_mut` (it has no whole-`&mut` accessor), so it cannot reach
    //        path B.
    //
    //   (iii) The consequence-only `ConsequenceRoleStateMut` GROW methods
    //        (`suspend_capabilities` / `suspend_all` / the demoting
    //        `system_assign_role`) STRUCTURALLY REQUIRE an obligation sink: each
    //        takes `&mut Option<ClassSCommitToken>` as a non-defaultable parameter
    //        and arms it on a real mutation. A consequence GROW therefore CANNOT be
    //        applied without arming the fail-closed persist (GAP-A closed) — and a
    //        populated-but-undischarged sink is a Drop-guard PANIC in debug/CI.
    //
    //   (iv) The RESIDUAL the type system does NOT prevent: a maintainer EDITING the
    //        best-effort `RoleStateClassCMut` impl in THIS file to add a new
    //        `&mut self` method that inserts into its private `suspended_capabilities`
    //        / `member_capabilities` `&mut`. That is an in-file-insider action in the
    //        SAME threat class as editing any enforcement file (the private field is
    //        the real barrier — only in-module code can name it), and is NOT defended
    //        by a compile-witness (the deleted witnesses did not defend it either —
    //        that was the false confidence). It is a CODE-REVIEW responsibility, and
    //        intentionally so: per the project's enforcement philosophy a CI/AST gate
    //        adds ~zero marginal security against an insider who can edit the gate.
    //
    // The positive confirmation that the GROW direction is CONFINED (exists on the
    // consequence view, not lost) is the live `consequence_*` fail-closed tests in
    // the actor handler submodules — they call the consequence GROW with its real
    // signature (obligation sink included) and assert the fail-closed persist.

    // Defense-in-depth (ADR-049 §9): the linear deferred-persist obligation MUST
    // be un-duplicable. `ClassSCommitToken` must NOT implement `Clone` (nor
    // `Copy`) — cloning the token would let a caller commit one copy and silently
    // drop the other, OR (worse) hold two tokens for ONE deferred persist and
    // double-discharge / mis-attribute it. The keep-direction obligation is
    // exactly-once: one mutation, one owed persist, one consuming `commit` /
    // `discharge_with`. If anyone ever derives/implements `Clone` (or `Copy`) on
    // the token, this assertion fails to compile.
    static_assertions::assert_not_impl_any!(ClassSCommitToken: Clone, Copy);

    /// Return `src` with the CONTENT of comments and string / char literals
    /// blanked out (delimiters, braces, code tokens, and newlines preserved), so
    /// downstream `.find` / `.contains` / brace-depth scans see ONLY code. This is
    /// the single source-aware lexer the tripwire uses; [`brace_bounded_body`]
    /// runs brace-matching over its output and [`class_s_no_persist_methods`]
    /// runs the persist-marker scan over it.
    ///
    /// It is `char`-based (never `byte as char`, which would corrupt multi-byte
    /// UTF-8 like `§ … × →` that appear in this file's doc comments) and handles
    /// the literal forms that actually occur in Rust source: `//` line comments,
    /// `/* … */` block comments (nesting), regular and **raw** strings
    /// (`"…"`, `r"…"`, `r#"…"#`, with any `#` count), **byte** strings
    /// (`b"…"`, `br#"…"#`), `\\`-escapes inside regular strings, and `'…'` char /
    /// byte-char literals vs lifetimes. A marker inside ANY of these is therefore
    /// dropped before classification, closing the comment/string spoof vector.
    ///
    /// CONSCIOUS CHOICE (not inherited by momentum): this is a small hand-rolled
    /// lexer rather than a `syn` dev-dependency parse. A `syn` parse would be
    /// strictly sounder and a few lines shorter, but it pulls a heavy proc-macro
    /// parsing crate into `scp-runtime`'s `dev-dependencies` for a single
    /// `#[cfg(test)]` honest-contributor speed-bump — disproportionate to the
    /// marginal benefit, given the compile-time boundary (not this test) is the
    /// real guarantee. The lexer's scope is bounded to the constructs this one
    /// file uses; the fail-LOUD macro / block-comment / count guards cover the
    /// shapes it deliberately does not parse. If this file ever grows constructs
    /// the lexer doesn't handle, prefer the `syn` parse over extending the lexer.
    fn code_only(src: &str) -> String {
        let chars: Vec<char> = src.chars().collect();
        let len = chars.len();
        let at = |idx: usize| chars.get(idx).copied().unwrap_or('\0');
        let mut out = String::with_capacity(src.len());
        let mut pos = 0;
        while pos < len {
            let cur = chars[pos];
            // Line comment: drop to end of line (the `\n` is emitted next loop).
            if cur == '/' && at(pos + 1) == '/' {
                while pos < len && chars[pos] != '\n' {
                    pos += 1;
                }
                continue;
            }
            // Block comment (nesting): drop content, keep newlines.
            if cur == '/' && at(pos + 1) == '*' {
                pos = skip_block_comment(&chars, pos + 2, &mut out);
                continue;
            }
            // Raw string: r"…", r#"…"#, br##"…"## (any `#` count, optional `b`).
            let raw_hash_at = if cur == 'r' {
                Some(pos + 1)
            } else if cur == 'b' && at(pos + 1) == 'r' {
                Some(pos + 2)
            } else {
                None
            };
            if let Some(next) =
                raw_hash_at.and_then(|after| skip_raw_string(&chars, after, &mut out))
            {
                pos = next;
                continue;
            }
            // Regular / byte string: "…" or b"…" with `\\`-escapes.
            if cur == '"' || (cur == 'b' && at(pos + 1) == '"') {
                let quote = if cur == 'b' { pos + 1 } else { pos };
                pos = skip_quoted_string(&chars, quote, &mut out);
                continue;
            }
            // Char / byte-char literal (`'a'`, `b'{'`, `'\n'`) vs lifetime (`'a`).
            if cur == '\'' {
                let esc = at(pos + 1) == '\\';
                let close_at = if esc { pos + 3 } else { pos + 2 };
                if close_at < len && chars[close_at] == '\'' {
                    out.push_str("''"); // placeholder, content dropped
                    pos = close_at + 1;
                    continue;
                }
                out.push('\''); // a lifetime: let the ident flow as code
                pos += 1;
                continue;
            }
            out.push(cur);
            pos += 1;
        }
        out
    }

    /// Skip a `/* … */` block comment (already past the opening `/*`), keeping
    /// only newlines in `out`; returns the index just past the closing `*/`.
    fn skip_block_comment(chars: &[char], mut pos: usize, out: &mut String) -> usize {
        let len = chars.len();
        let at = |idx: usize| chars.get(idx).copied().unwrap_or('\0');
        let mut depth = 1usize;
        while pos < len && depth > 0 {
            if chars[pos] == '/' && at(pos + 1) == '*' {
                depth += 1;
                pos += 2;
            } else if chars[pos] == '*' && at(pos + 1) == '/' {
                depth -= 1;
                pos += 2;
            } else {
                if chars[pos] == '\n' {
                    out.push('\n');
                }
                pos += 1;
            }
        }
        pos
    }

    /// If `hash_at` begins a raw-string opener (`#* "`), drop its content and emit
    /// placeholder quotes + newlines into `out`, returning the index past the
    /// closing `"#*`. Returns `None` if it is not actually a raw string.
    fn skip_raw_string(chars: &[char], hash_at: usize, out: &mut String) -> Option<usize> {
        let len = chars.len();
        let mut pos = hash_at;
        let mut hashes = 0usize;
        while pos < len && chars[pos] == '#' {
            hashes += 1;
            pos += 1;
        }
        if pos >= len || chars[pos] != '"' {
            return None;
        }
        out.push('"');
        pos += 1;
        while pos < len {
            if chars[pos] == '"' {
                let mut end = pos + 1;
                let mut got = 0;
                while end < len && got < hashes && chars[end] == '#' {
                    got += 1;
                    end += 1;
                }
                if got == hashes {
                    out.push('"');
                    return Some(end);
                }
            }
            if chars[pos] == '\n' {
                out.push('\n');
            }
            pos += 1;
        }
        Some(pos)
    }

    /// Skip a regular/byte string starting at the opening `"` (`quote`), dropping
    /// content (honoring `\\`-escapes) and emitting placeholder quotes + newlines
    /// into `out`; returns the index just past the closing `"`.
    fn skip_quoted_string(chars: &[char], quote: usize, out: &mut String) -> usize {
        let len = chars.len();
        out.push('"');
        let mut pos = quote + 1;
        while pos < len {
            if chars[pos] == '\\' {
                pos += 2; // skip the escaped char (incl. `\"` and `\\`)
                continue;
            }
            if chars[pos] == '"' {
                out.push('"');
                return pos + 1;
            }
            if chars[pos] == '\n' {
                out.push('\n');
            }
            pos += 1;
        }
        pos
    }

    /// Find every INHERENT `impl <type_name> { … }` block in `code` (which MUST be
    /// [`code_only`]-stripped) and return each block's code-only body (header
    /// through its matching closing `}`), brace-depth bounded (BLACK-CS-02).
    ///
    /// Matches `impl` + whitespace + `type_name` (word-bounded — the next char must
    /// not be an identifier char, so `ClassSCell` does not match `ClassSCellFoo`) +
    /// optional whitespace/newline + `{`. This handles the inline (`impl T{…}`),
    /// multi-space, and newline-before-brace spellings a brittle literal
    /// `"\nimpl T {\n"` scan would miss — closing the BLACK-CS-02 evasion where an
    /// inline `impl ClassSCell{ … }` block hid a no-persist mutator. A trait impl
    /// (`impl Trait for T`) is excluded because the token immediately after the
    /// `impl`-whitespace is the trait name, not `type_name` (and an `impl T for …`
    /// would have `for` where the `{` is expected, so it is rejected by the
    /// brace-follows check).
    fn find_inherent_impl_blocks(code: &str, type_name: &str) -> Vec<String> {
        let bytes = code.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let mut blocks = Vec::new();
        let mut search = 0usize;
        while let Some(rel) = code[search..].find("impl") {
            let impl_at = search + rel;
            search = impl_at + 4;
            // `impl` must be a standalone keyword (word-bounded both sides).
            if impl_at > 0 && is_ident(bytes[impl_at - 1]) {
                continue;
            }
            let mut pos = impl_at + 4;
            if pos >= bytes.len() || !bytes[pos].is_ascii_whitespace() {
                continue;
            }
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            // The token here must be exactly `type_name`, word-bounded.
            if !code[pos..].starts_with(type_name) {
                continue;
            }
            let after_name = pos + type_name.len();
            if after_name < bytes.len() && is_ident(bytes[after_name]) {
                continue;
            }
            // Optional whitespace/newline, then the opening `{` (inherent impl).
            let mut brace = after_name;
            while brace < bytes.len() && bytes[brace].is_ascii_whitespace() {
                brace += 1;
            }
            if brace >= bytes.len() || bytes[brace] != b'{' {
                // e.g. `impl ClassSCell where …` or `impl Trait for ClassSCell` —
                // not an inherent `impl T {` header. Skip.
                continue;
            }
            // Brace-depth bound the block (braces in comments/strings already gone).
            let mut depth = 0i32;
            let mut end = brace;
            for (idx, ch) in code[brace..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = brace + idx + ch.len_utf8();
                            break;
                        }
                    }
                    _ => {}
                }
            }
            blocks.push(code[impl_at..end].to_owned());
            search = end;
        }
        blocks
    }

    /// Detect a `type <Ident> = ClassSCell;` alias declaration in `code` (which
    /// MUST be [`code_only`]-stripped), returning the FIRST aliasing line if any
    /// (ADR-049 §9 — cheap alias-reject, F3).
    ///
    /// An alias lets `impl <Alias> { fn evil(&mut self){ self.state.class_s… } }`
    /// reach the privatized Class-S fields through an `impl` block the
    /// `find_inherent_impl_blocks("…","ClassSCell")` scan does NOT match (it keys on
    /// the literal `ClassSCell` type name after `impl`). This is the canonical /
    /// accidental evasion shape; rejecting the alias DECLARATION (rather than
    /// chasing every alias-impl spelling) keeps the guard CHEAP and CONVERGENT — it
    /// is NOT an attempt to out-spell a determined adversary (the compile boundary
    /// is the real guarantee; see this test's doc). Matches `type` + ws + an
    /// identifier + ws? + `=` + ws? + a type-path whose FINAL `::`-separated segment
    /// is `ClassSCell` word-bounded (so the bare `type X = ClassSCell;` AND the
    /// path-qualified `type X = crate::context::actor::class_s::ClassSCell;` both
    /// trip, while `ClassSCellFoo` does not), tolerating any `=`/whitespace spacing
    /// and an optional leading `::` (absolute path).
    ///
    /// ACCEPTED RESIDUAL (ADR-049 §9): this catches the `type … = ClassSCell;` alias
    /// form (bare OR path-qualified) but NOT a `use …::ClassSCell as Alias;` import
    /// rename (nor a generic-parameter binding), which would also let `impl Alias { … }`
    /// evade the literal-`ClassSCell` impl-block scan. That is deliberately UN-chased:
    /// the path-qualified RHS is the one convergent extra spelling an HONEST
    /// contributor would reach for; out-spelling import renames or generic bindings
    /// would be a non-convergent denylist. The real
    /// barrier is that `ClassSCell.state` is a PRIVATE field, so ANY aliased `impl`
    /// — under any spelling — only compiles IN THIS MODULE, i.e. the attacker is
    /// already editing this file (an in-file-insider, the same threat class as
    /// editing any enforcement). The tripwire is a cheap, convergent speed-bump for
    /// HONEST contributors against the accidental `type`-alias shape; the private
    /// field + module boundary is the guarantee. Out-spelling every alias form would
    /// be a non-convergent denylist for ~zero marginal security.
    fn class_s_cell_alias(code: &str) -> Option<String> {
        let bytes = code.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let mut search = 0usize;
        while let Some(rel) = code[search..].find("type") {
            let kw_at = search + rel;
            search = kw_at + 4;
            // `type` must be a standalone keyword (word-bounded both sides).
            if kw_at > 0 && is_ident(bytes[kw_at - 1]) {
                continue;
            }
            let mut pos = kw_at + 4;
            if pos >= bytes.len() || !bytes[pos].is_ascii_whitespace() {
                continue;
            }
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            // The alias NAME: a run of identifier chars (skipped — any name).
            let name_start = pos;
            while pos < bytes.len() && is_ident(bytes[pos]) {
                pos += 1;
            }
            if pos == name_start {
                continue; // no alias identifier (e.g. `type` in some other context)
            }
            // Optional generics on the alias (`type Foo<T> = …`) — skip a balanced
            // `<…>` so the `=` after it is still found.
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos < bytes.len() && bytes[pos] == b'<' {
                let mut depth = 0i32;
                while pos < bytes.len() {
                    match bytes[pos] {
                        b'<' => depth += 1,
                        b'>' => {
                            depth -= 1;
                            if depth == 0 {
                                pos += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    pos += 1;
                }
                while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
            }
            // Require the `=`.
            if pos >= bytes.len() || bytes[pos] != b'=' {
                continue;
            }
            pos += 1;
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            // The aliased type's FINAL path segment must be exactly `ClassSCell`,
            // word-bounded. Walk a `seg (:: seg)*` path so a PATH-QUALIFIED RHS
            // (`type Evil = crate::context::actor::class_s::ClassSCell;`) is caught
            // as well as the bare `type Evil = ClassSCell;` — both let an
            // `impl <Alias>` block reach the privatized Class-S fields through a
            // header the literal-`ClassSCell` impl-block scan can't see. An optional
            // leading `::` (absolute path) is tolerated. This stays a CHEAP,
            // CONVERGENT honest-contributor speed-bump for the path-qualified case
            // ONLY — it does NOT chase `use … as Alias;` import renames or generic
            // bindings (the private `ClassSCell.state` field + the module boundary is
            // the real barrier; see this fn's doc).
            if code[pos..].starts_with("::") {
                pos += 2;
                while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
            }
            // Walk path segments, tracking the byte span of the LAST one.
            let mut last_seg_start = pos;
            let mut last_seg_end = pos;
            loop {
                let seg_start = pos;
                while pos < bytes.len() && is_ident(bytes[pos]) {
                    pos += 1;
                }
                if pos == seg_start {
                    // No identifier where a path segment was required — not a
                    // type-path RHS (e.g. `type Bytes = [u8; 32];`).
                    break;
                }
                last_seg_start = seg_start;
                last_seg_end = pos;
                // Look past whitespace for a `::` path separator.
                let mut peek = pos;
                while peek < bytes.len() && bytes[peek].is_ascii_whitespace() {
                    peek += 1;
                }
                if code[peek..].starts_with("::") {
                    pos = peek + 2;
                    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                        pos += 1;
                    }
                    continue;
                }
                break;
            }
            // The final segment must be exactly `ClassSCell` (word-bounded by the
            // ident-run scan above — `ClassSCellFoo` is a single longer segment that
            // will not equal `ClassSCell`).
            if &code[last_seg_start..last_seg_end] != "ClassSCell" {
                continue;
            }
            let after = last_seg_end;
            // Report the whole logical line for the failure message.
            let line_start = code[..kw_at].rfind('\n').map_or(0, |i| i + 1);
            let line_end = code[after..].find('\n').map_or(code.len(), |i| after + i);
            return Some(code[line_start..line_end].trim().to_owned());
        }
        None
    }

    /// Whether `header_line` (a 4-space-indented line) is a method header —
    /// STRUCTURALLY, not by a fixed prefix list. Strips an optional `pub` / `pub(…)`
    /// visibility (any restriction, incl. `pub(in crate::context)` and future
    /// spellings), then any `const` / `async` / `unsafe` / `extern` fn-qualifier
    /// keywords in any order, and asks whether what remains starts with `fn `. A
    /// new method spelling (bare `async fn`, `pub fn`, `pub(super) fn`, …) is
    /// therefore recognized — closed by construction, so it cannot silently drop a
    /// method from the whitelist scan.
    fn is_method_header(header_line: &str) -> bool {
        let mut t = header_line.trim_start();
        if let Some(rest) = t.strip_prefix("pub") {
            t = rest.trim_start();
            if let Some(after) = t.strip_prefix('(') {
                let Some(close) = after.find(')') else {
                    return false;
                };
                t = after[close + 1..].trim_start();
            }
        }
        while let Some(rest) = ["const ", "async ", "unsafe ", "extern "]
            .iter()
            .find_map(|kw| t.strip_prefix(kw))
        {
            t = rest.trim_start();
            // `extern` may carry an ABI string: `extern "C" fn …`. Drop it.
            if let Some(close) = t
                .strip_prefix('"')
                .and_then(|q| q.find('"').map(|c| (q, c)))
            {
                let (after_quote, close_idx) = close;
                t = after_quote[close_idx + 1..].trim_start();
            }
        }
        t.starts_with("fn ")
    }

    /// Bound a method's body to its own braces over the COMMENT/STRING-stripped
    /// ([`code_only`]) text of `slice`, returning the code-only text from the
    /// method header through its closing `}`. Because braces inside comments and
    /// string / char literals are already gone, a plain depth counter is exact
    /// (no `format!`-style `"{…}"` can desync it). The returned `String` is
    /// code-only, so the caller's name parse, receiver check, AND persist-marker
    /// scan all run over code — a marker in a comment/string cannot bleed in from
    /// this method's body OR from the NEXT method's leading doc/attributes.
    fn brace_bounded_body(slice: &str) -> String {
        let code = code_only(slice);
        let Some(body_open) = code.find('{') else {
            return code;
        };
        let mut depth = 0i32;
        for (idx, ch) in code[body_open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let end = body_open + idx + ch.len_utf8();
                        return code[..end].to_owned();
                    }
                }
                _ => {}
            }
        }
        code
    }

    /// Whether a brace-bounded method `body` declares a `self` receiver. Finds the
    /// param-list `(` — the first `(` AFTER the `fn name` AND after any balanced
    /// `<…>` generic list (so a `(` inside a `Fn(…)` / `FnOnce(…)` generic bound is
    /// not mistaken for the param list) — then checks the FIRST parameter is a
    /// `self` receiver, matched as a TOKEN (`self` / `&self` / `&mut self` /
    /// `&'a self` / `self:`), not a substring (so a param merely NAMED `self_id`
    /// is not a false positive). The signature can span several physical lines.
    fn body_has_self_receiver(body: &str) -> bool {
        let Some(fn_kw) = body.find("fn ") else {
            return false;
        };
        let after_fn = &body[fn_kw + 3..];
        let trimmed = after_fn.trim_start();
        let Some(name_end_rel) = trimmed.find(['(', '<', ' ']) else {
            return false;
        };
        let name_end = (after_fn.len() - trimmed.len()) + name_end_rel;
        // Skip a balanced `<…>` generic list if one immediately follows the name,
        // so a `(` inside a `Fn(…)` bound is not taken as the param list.
        let rest_after_name = &after_fn[name_end..];
        let search_from = if rest_after_name.trim_start().starts_with('<') {
            let mut depth = 0i32;
            let mut end = rest_after_name.len();
            for (k, ch) in rest_after_name.char_indices() {
                match ch {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            end = k + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            name_end + end
        } else {
            name_end
        };
        let Some(param_open_rel) = after_fn[search_from..].find('(').map(|r| search_from + r)
        else {
            return false;
        };
        let first_param = after_fn[param_open_rel + 1..]
            .split([',', ')'])
            .next()
            .unwrap_or("")
            .trim();
        // Normalize a reference receiver: strip a leading `&`, an optional `'a`
        // lifetime token, and an optional `mut`; the remainder must be exactly
        // `self` (or `self:` for an explicit-type receiver). Rejects `self_id`,
        // `myself`, etc. while accepting every real receiver form.
        let mut r = first_param;
        if let Some(after_amp) = r.strip_prefix('&') {
            r = after_amp.trim_start();
            if r.starts_with('\'') {
                // Drop the lifetime token up to the next whitespace.
                r = r
                    .split_once(char::is_whitespace)
                    .map_or("", |(_, rest)| rest);
                r = r.trim_start();
            }
        }
        let r = r.strip_prefix("mut ").map_or(r, str::trim_start);
        r == "self" || r.starts_with("self:") || r.starts_with("self ")
    }

    /// Enumerate the `self`-receiver methods of an `impl ClassSCell` block (given
    /// as its source text `impl_block`) and return the NAMES of those whose body
    /// performs NONE of `persist_markers`, plus the total recognized-method count
    /// (for a parser-drift cross-check). Splits the impl into per-method slices at
    /// each method-level (4-space-indented) `fn`, and bounds each body to its own
    /// braces via [`brace_bounded_body`] — whose output is code-only (comment /
    /// string contents stripped), so the persist-marker scan cannot be spoofed by
    /// a marker named in a comment or string literal.
    fn class_s_no_persist_methods(
        impl_block: &str,
        persist_markers: &[&str],
    ) -> (Vec<String>, usize) {
        let fn_starts: Vec<usize> = impl_block
            .match_indices("\n    ")
            .filter(|(i, _)| {
                let line = impl_block[i + 1..].lines().next().unwrap_or("");
                // Exactly 4-space indent (method level, not a deeper body line),
                // and structurally a method header (any valid qualifier soup).
                line.starts_with("    ") && !line.starts_with("     ") && is_method_header(line)
            })
            .map(|(i, _)| i + 1)
            .collect();

        assert!(
            !fn_starts.is_empty(),
            "must find method `fn`s in impl ClassSCell — parser drift if empty"
        );

        let recognized = fn_starts.len();
        let mut out: Vec<String> = Vec::new();
        for (idx, &start) in fn_starts.iter().enumerate() {
            let slice_end = fn_starts.get(idx + 1).copied().unwrap_or(impl_block.len());
            // `body` is COMMENT/STRING-stripped (code-only): the name parse, the
            // receiver check, and the persist-marker scan below all run over code,
            // so a marker named in a comment/string cannot spoof classification.
            let body = brace_bounded_body(&impl_block[start..slice_end]);
            let header = body.lines().next().unwrap_or("");

            let name = header
                .split("fn ")
                .nth(1)
                .and_then(|s| s.split(['(', '<', ' ']).next())
                .unwrap_or("")
                .to_owned();
            assert!(
                !name.is_empty(),
                "could not parse method name from: {header}"
            );

            // Only methods with a `self` receiver can mutate the owned state;
            // `new(state: PerContextState)` has no `self` receiver — skip it.
            if !body_has_self_receiver(&body) {
                continue;
            }
            if !persist_markers.iter().any(|m| body.contains(m)) {
                out.push(name);
            }
        }
        (out, recognized)
    }

    /// ADR-049 §9 — **bounded positive-allowlist tripwire** replacing the retired
    /// source-text scanner `scripts/check-class-s-fail-closed.sh`.
    ///
    /// # What this guards, and why a whitelist (not a denylist)
    ///
    /// The compile-time guarantee is layered, and it — NOT this test — is the
    /// adversarial boundary. `ClassSCell` hands out NO whole `&mut PerContextState`
    /// (no `DerefMut`, no `state_mut`), so a caller can only obtain `&mut` to one
    /// of the three PRIVATIZED Class-S fields (`class_s`, `governance.class_s`,
    /// `revoked_spending_ucan_cids`) through the *view* a combinator constructs —
    /// and the best-effort views (`ClassCMut` / `GovernanceClassCMut`) hold no
    /// `&mut` to them at all (field-granular refs + a shared `&` to `class_s`), so
    /// the only `&mut` to those fields originates inside a `ClassSCell` method (the
    /// combinators + token paths, which persist). (The dual-use
    /// `ContextRoleState.ceiling` / `suspended_capabilities` downward-auth fields
    /// are now privatized to `pub(crate)` in `scp-protocol` and the whole-`&mut`
    /// `role_state_mut` accessor is deleted — the downward-auth GROW is confined to
    /// the consequence-only view; see the module section above.) Field privatization
    /// to
    /// `pub(in crate::context)` is the OUTER, defense-in-depth ring: it stops code
    /// *outside* `crate::context` from naming the fields, but does NOT (and cannot)
    /// stop a sibling module under `crate::context` from naming them — so the
    /// inner, load-bearing guarantee is the cell's no-whole-`&mut` shape, not the
    /// visibility. That shape (plus crate-wide `#![forbid(unsafe_code)]`) is what
    /// resists a *deliberate* adversary.
    ///
    /// This test is a narrower thing: a review **speed-bump** that catches the
    /// NAIVE / ACCIDENTAL case of a method ADDED to `impl ClassSCell` (which can
    /// reach `self.state.class_s` directly) that mutates Class-S but forgets to
    /// persist. It is NOT an adversarial gate and deliberately does not try to be
    /// one: it lives `#[cfg(test)]` in the SAME FILE as `impl ClassSCell`, so
    /// anyone who can add a no-persist mutator can equally edit `KNOWN_SAFE` or
    /// delete the test — chasing source-text reachability/macro-expansion to defeat
    /// a determined evader would be the non-convergent denylist this PR retired.
    /// What it DOES guarantee, soundly and convergently, is fail-LOUD behaviour for
    /// the honest contributor: a straightforwardly-added no-persist `&mut self`
    /// Class-S mutator trips it, and a parser blind-spot (an unrecognized header,
    /// or a method-producing macro invocation) trips the count / macro
    /// cross-checks rather than silently passing. The honest author is then steered
    /// to persist — directly (`persist_state_fail_closed`), via the explicitly-
    /// Class-C best-effort combinator (`persist_state_best_effort`), or by deferring
    /// the fail-closed persist to a `ClassSCommitToken` (minted via
    /// `ClassSCommitToken::new`).
    ///
    /// It ALSO rejects a `type … = ClassSCell;` alias (the canonical/accidental
    /// shape where `impl <Alias> { … }` would reach the privatized fields through a
    /// header the `ClassSCell`-keyed `impl`-block scan cannot see). That is the
    /// SAME class of honest/accidental coverage — `find_inherent_impl_blocks` keys
    /// on the literal `ClassSCell` name, so an alias-impl is invisible to it; the
    /// alias-DECLARATION reject closes that without growing the impl scan. It is
    /// deliberately a single cheap declaration check, NOT a chase of every
    /// alias-impl spelling — extending it that way would be the non-convergent
    /// denylist this PR retired. As with the rest of this test, a determined
    /// adversary who can add the alias can equally edit the test; the alias-reject
    /// is for the honest contributor, and the COMPILE boundary remains the real
    /// guarantee.
    ///
    /// The retired scanner was a DENYLIST: it chased "one more spelling" of a
    /// mutate-without-persist and had to grow a pattern per evasion. This test is
    /// the convergent inverse — a CLOSED POSITIVE ALLOWLIST. It enumerates the
    /// `self`-receiver methods of `impl ClassSCell` from the source text and
    /// asserts that the set which performs NO persist of any kind is EXACTLY the
    /// known-safe set. Adding a NEW `&mut self` method that mutates Class-S
    /// without a persist mechanism (the exact §9 hazard) makes the no-persist set
    /// grow beyond the allowlist and TRIPS this test — forcing a reviewer to
    /// either route it through a combinator/token or consciously, reviewably add
    /// it to `KNOWN_SAFE` with a §9 safety argument. The allowlist is bounded by
    /// construction: it does not grow to chase spellings, only to admit a new
    /// deliberately-sanctioned no-persist method.
    ///
    /// # The known-safe set (each justified)
    ///
    /// - `new` / `into_inner` — ownership in/out; `new` takes `state` by value (no
    ///   `self` receiver, so it is not even enumerated), `into_inner` unwraps by
    ///   value. Neither mutates Class-S behind a caller ack.
    /// - `class_c_view` / `commit_class_c_best_effort` — Class-C: the [`ClassCMut`]
    ///   view they hand out, by construction, holds NO `&mut` to any Class-S field
    ///   (shared `&` to `class_s`), so they cannot perform a Class-S mutation at
    ///   all. (`commit_class_c_best_effort` performs a *best-effort* persist, which
    ///   is deliberately NOT a Class-S persist marker — a Class-S mutator that only
    ///   best-effort-persists must TRIP, so it is whitelisted by NAME here on the
    ///   grounds that it cannot reach Class-S, not on the grounds that it persists.)
    /// - `clear_committed_reservation_idempotent` — the SINGLE sanctioned
    ///   no-persist Class-S mutator; its §9 safety argument (the committed
    ///   terminal is already durably witnessed; the removal is an idempotent
    ///   straggler cleanup) is on the method.
    /// - `set_generation_for_test` — `#[cfg(test)]`, seeds the Class-C generation
    ///   counter only; never compiled into production.
    /// - `restore_class_s` — the PRIVATE combinator-internal restore arm: reached
    ///   ONLY from inside `commit_class_s_restore` / `_compensating` (whose own
    ///   bodies own the fail-closed persist), to roll a Class-S sub-struct back to a
    ///   pre-`f` snapshot when that persist FAILED — by construction always wrapped
    ///   by a persisting combinator, never a standalone Class-S mutation entry.
    ///
    /// # Known limitations (honest scope)
    ///
    /// The persist check is a presence test — does the method body NAME a
    /// fail-closed persist mechanism — NOT a reachability/dominance analysis. It
    /// therefore does NOT catch a method that mutates Class-S and then takes an
    /// early-return path that SKIPS the persist, nor one that names the marker on
    /// an unreachable branch, nor one that shadows the marker's spelling with an
    /// unrelated local item. Building source-text control-flow analysis to close
    /// these would be the non-convergent denylist this PR retired; instead they are
    /// left to ordinary code review (the compile-time shape still forces the
    /// mutation through a persisting `ClassSCell` method — it does not force
    /// *correct persist placement* within that method, which review must verify).
    #[test]
    fn class_s_no_persist_mutator_whitelist_is_bounded() {
        const SRC: &str = include_str!("class_s.rs");

        // "Performs a FAIL-CLOSED persist" = the body names one of the two
        // mechanisms that satisfy §9 for a Class-S mutation: the synchronous
        // fail-closed persist, or minting a deferred-persist `ClassSCommitToken`
        // (whose `commit` / `discharge_with` perform the fail-closed persist).
        //
        // `persist_state_best_effort` is DELIBERATELY NOT a marker: best-effort
        // (coalesced) persistence does NOT satisfy §9 for Class-S — a crash in the
        // ≤50ms coalesce window rolls the mutation back behind a caller who already
        // saw success. A method that mutates Class-S and only best-effort-persists
        // is exactly the §9 hazard and MUST trip. The sole best-effort combinator,
        // `commit_class_c_best_effort`, is Class-C (its `ClassCMut` view cannot
        // reach Class-S) and is therefore on `KNOWN_SAFE`, not cleared by a marker.
        const PERSIST_MARKERS: [&str; 2] = ["persist_state_fail_closed", "ClassSCommitToken::new"];

        // The closed allowlist of self-receiver methods that legitimately perform
        // NO fail-closed persist of a Class-S mutation. A NEW no-persist mutator
        // NOT in this set trips the assert.
        // - `class_c_view` / `commit_class_c_best_effort` — Class-C: the `ClassCMut`
        //   view they hand out holds NO `&mut` to any Class-S field (it cannot name
        //   one), so they cannot perform a Class-S mutation at all; no fail-closed
        //   persist is required of them.
        // - `restore_class_s` — the PRIVATE combinator-internal restore arm: reached
        //   ONLY from inside `commit_class_s_restore` / `_compensating` (whose own
        //   bodies own the fail-closed persist), to roll a Class-S sub-struct back to
        //   a pre-`f` snapshot when that persist FAILED — by construction always
        //   wrapped by a persisting combinator, never a standalone mutation entry.
        // - `mutation_epoch` — a `&self` reader of the view hand-out counter; it
        //   holds no `&mut` at all, so it can perform no mutation of any class.
        const KNOWN_SAFE: [&str; 7] = [
            "into_inner",
            "mutation_epoch",
            "class_c_view",
            "commit_class_c_best_effort",
            "clear_committed_reservation_idempotent",
            "set_generation_for_test",
            "restore_class_s",
        ];

        // Exactly-ONE-block guard, BRACE-DEPTH-AWARE (BLACK-CS-02): isolate EVERY
        // inherent `impl ClassSCell { … }` block over the COMMENT/STRING-stripped
        // source via `find_inherent_impl_blocks`, which matches `impl` + ws +
        // `ClassSCell` + ws + `{` (handling the inline `impl ClassSCell{…}`,
        // multi-space, and newline-before-brace spellings a literal
        // `"\nimpl ClassSCell {\n"` scan missed — the exact spelling that let a
        // hostile inline no-persist mutator hide) and brace-bounds each body. The
        // prior whitespace-literal count was the BLACK-CS-02 hole. Assert there is
        // EXACTLY ONE such block so the single-block scan is exhaustive.
        let src_code = code_only(SRC);

        // Alias-reject (ADR-049 §9, F3): a `type <Ident> = ClassSCell;` alias would
        // let an `impl <Alias> { fn evil(&mut self){ self.state.class_s… } }` block
        // reach the privatized Class-S fields through an `impl` header the
        // `ClassSCell`-keyed scan below does NOT match. Forbid the alias DECLARATION
        // outright (there are none today; the cell is named directly everywhere) so
        // an alias-impl cannot hide a no-persist mutator. This is a CHEAP, CONVERGENT
        // guard for the canonical/accidental shape — NOT an adversarial gate (the
        // compile boundary is the real guarantee; a determined evader who can add the
        // alias can equally edit this test). We deliberately do NOT chase further
        // alias spellings beyond this declaration reject.
        let alias = class_s_cell_alias(&src_code);
        assert!(
            alias.is_none(),
            "ADR-049 §9 (F3): a `type … = ClassSCell;` alias ({alias:?}) lets an \
             `impl <Alias>` block reach the privatized Class-S fields through a header \
             the `ClassSCell`-keyed tripwire scan cannot see — hiding a no-persist \
             Class-S mutator. Name `ClassSCell` directly (remove the alias)."
        );

        let cell_blocks = find_inherent_impl_blocks(&src_code, "ClassSCell");
        assert_eq!(
            cell_blocks.len(),
            1,
            "ADR-049 §9 (BLACK-CS-02): expected EXACTLY ONE inherent `impl ClassSCell` \
             block, found {}. The whitelist tripwire scans the block(s) this finds; a \
             2nd block (in ANY brace/whitespace spelling) could hide a no-persist \
             Class-S mutator. Merge the blocks into one.",
            cell_blocks.len()
        );

        // The isolated `impl ClassSCell { … }` block — code-only, brace-bounded.
        // The downstream method enumeration / persist-marker scan run over THIS
        // block only.
        let impl_block = cell_blocks
            .into_iter()
            .next()
            .expect("one ClassSCell block");
        let impl_block = impl_block.as_str();

        // Enumerate `self`-receiver methods and classify each by whether its body
        // performs ANY persist mechanism. A method with NO persist mechanism that
        // mutates Class-S behind a caller ack is the §9 hazard — those must equal
        // the known-safe allowlist exactly.
        //
        // The enumeration + classification is in `class_s_no_persist_methods`.
        let (mut no_persist_methods, recognized) =
            class_s_no_persist_methods(impl_block, &PERSIST_MARKERS);
        no_persist_methods.sort();
        let mut expected: Vec<String> = KNOWN_SAFE.iter().map(|s| (*s).to_owned()).collect();
        expected.sort();

        // Parser-drift cross-check: the count of recognized method headers must
        // equal the count of `fn ` keyword occurrences at method (4-space) indent
        // in the impl block. If a header spelling slips past `is_method_header`,
        // these diverge and the test fails LOUDLY (parser drift) rather than
        // silently dropping a method from the scan. Run over the COMMENT/STRING-
        // stripped block so a `fn ` inside a comment or string does not skew it.
        let impl_code = code_only(impl_block);
        let total_method_fns = impl_code
            .lines()
            .filter(|l| {
                l.starts_with("    ") && !l.starts_with("     ") && l.trim_start().contains("fn ")
            })
            .count();
        assert_eq!(
            recognized, total_method_fns,
            "ADR-049 §9 parser drift: `is_method_header` recognized {recognized} method \
             headers but {total_method_fns} 4-space-indented `fn ` lines exist in \
             `impl ClassSCell`. A header spelling slipped past the recognizer — a new \
             method could be silently dropped from the no-persist scan. Fix \
             `is_method_header` to recognize it."
        );

        // Macro fail-LOUD guard: a method-producing macro INVOCATION at method
        // (4-space) indent (`    foo!(…)` / `    foo! {…}`) expands to methods the
        // source-text scan cannot see — silently bypassing the whitelist. The
        // source-text approach is fundamentally blind to macro expansion, so we
        // forbid such invocations inside `impl ClassSCell` outright: there are none
        // today, and any addition must be a `fn` the scan CAN read (or the author
        // must replace this guard with expansion-aware enforcement). This converts
        // a fail-SILENT blind spot into a fail-LOUD assertion.
        let macro_invocation = impl_code.lines().find(|l| {
            if !l.starts_with("    ") || l.starts_with("     ") {
                return false;
            }
            let t = l.trim_start();
            // `ident!(` / `ident !(` / `ident! {` — a leading identifier, then `!`
            // (tolerating whitespace either side so it does not depend on `cargo
            // fmt` having run), then a delimiter. (Negative `!expr` and `!=` start
            // with `!`, not an ident, so they are excluded.)
            let Some(bang) = t.find('!') else {
                return false;
            };
            let before = t[..bang].trim_end();
            let ident: String = before
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            !ident.is_empty()
                && ident == before
                && t[bang + 1..].trim_start().starts_with(['(', '{', '['])
        });
        assert!(
            macro_invocation.is_none(),
            "ADR-049 §9: a method-producing macro invocation at method indent in \
             `impl ClassSCell` ({macro_invocation:?}) is invisible to the source-text \
             whitelist scan — it could add a no-persist Class-S mutator silently. \
             Either remove it or replace this tripwire with expansion-aware \
             enforcement."
        );

        // Block-comment fail-LOUD guard: a `/* … */` block comment on a method-
        // indent line shifts the surviving indentation (the comment body is
        // dropped), which can move a `fn` header off the exact 4-space prefix that
        // BOTH the enumeration and the count cross-check key on — letting a method
        // slip BOTH silently. There are no block comments in this impl today (it
        // uses `//` / `///`), so forbid them at method indent rather than special-
        // case the indent shift. Scanned on the RAW block (pre-strip) so the `/*`
        // is still visible.
        let block_comment = impl_block.lines().find(|l| {
            l.starts_with("    ") && !l.starts_with("     ") && l.trim_start().contains("/*")
        });
        assert!(
            block_comment.is_none(),
            "ADR-049 §9: a `/* … */` block comment at method indent in `impl ClassSCell` \
             ({block_comment:?}) can shift a `fn` header off the 4-space prefix the \
             whitelist scan keys on, hiding a method from BOTH the enumeration and the \
             count cross-check. Use `//` line comments instead."
        );

        assert_eq!(
            no_persist_methods, expected,
            "ADR-049 §9: the set of `ClassSCell` self-receiver methods that perform \
             NO persist must be EXACTLY the known-safe allowlist. A NEW method here \
             means a Class-S mutation may be acknowledged without a fail-closed \
             persist (a §9 replay/re-spend/re-grant hole). Route it through a \
             combinator / `ClassSCommitToken`, or — if it is genuinely safe — add \
             it to KNOWN_SAFE with a §9 safety argument on the method. \
             Found: {no_persist_methods:?}, expected: {expected:?}"
        );
    }

    /// ADR-049 §9 — table-driven UNIT tests for the tripwire's hand-rolled lexer
    /// (`code_only` / `skip_block_comment` / `skip_raw_string`). These helpers are
    /// the tripwire's trust root; the whitelist test above feeds them only the REAL
    /// file, so a silent lexer bug (a marker leaking out of a comment/string, a
    /// multi-byte-UTF-8 desync) would go unnoticed until it let a real evasion
    /// through. This test feeds CRAFTED synthetic inputs so such a bug is a LOUD
    /// test failure, not a silent gap. (The header / receiver / brace-bounding /
    /// no-persist-method helpers are exercised by
    /// `tripwire_lexer_classifies_headers_and_no_persist_methods`.)
    #[test]
    fn tripwire_lexer_blanks_comments_and_strings() {
        // --- code_only: comment / string content is blanked, code survives ---
        // A persist marker that appears ONLY inside a `//` line comment, a
        // `/* … */` block comment, and a raw string must NOT survive into the
        // code-only output (so a marker-in-comment cannot spoof "persisted").
        let line_comment = "let x = 1; // persist_state_fail_closed here\n let y = 2;";
        assert!(
            !code_only(line_comment).contains("persist_state_fail_closed"),
            "a marker inside a `//` comment must be blanked by code_only"
        );
        let block_comment = "a(); /* persist_state_fail_closed */ b();";
        let bc_out = code_only(block_comment);
        assert!(
            !bc_out.contains("persist_state_fail_closed"),
            "a marker inside a `/* … */` block comment must be blanked"
        );
        assert!(
            bc_out.contains("a()") && bc_out.contains("b()"),
            "code outside the block comment must survive: {bc_out:?}"
        );
        // Nested block comments: the inner `*/` must not close the outer comment.
        let nested = "p(); /* outer /* inner persist_state_fail_closed */ still */ q();";
        let nested_out = code_only(nested);
        assert!(
            !nested_out.contains("persist_state_fail_closed") && !nested_out.contains("still"),
            "nested block comment must be fully blanked: {nested_out:?}"
        );
        assert!(
            nested_out.contains("p()") && nested_out.contains("q()"),
            "code around a nested block comment must survive: {nested_out:?}"
        );

        // --- skip_raw_string: a raw-string-spoofed marker is dropped ---
        // `r#"…"#` content (with any `#` count) is blanked; an embedded `"#` that
        // does not match the opener's hash count does NOT close the raw string.
        let raw_spoof = r##"let s = r#"persist_state_fail_closed and a "quote" inside"#; tail()"##;
        let raw_out = code_only(raw_spoof);
        assert!(
            !raw_out.contains("persist_state_fail_closed"),
            "a marker inside a raw string must be blanked: {raw_out:?}"
        );
        assert!(
            raw_out.contains("tail()"),
            "code after a raw string must survive: {raw_out:?}"
        );
        // Byte raw string `br#"…"#` is handled the same way.
        let byte_raw = r##"x(); let b = br#"persist_state_fail_closed"#; y();"##;
        let byte_raw_out = code_only(byte_raw);
        assert!(
            !byte_raw_out.contains("persist_state_fail_closed")
                && byte_raw_out.contains("x()")
                && byte_raw_out.contains("y()"),
            "byte raw string must be blanked, surrounding code kept: {byte_raw_out:?}"
        );

        // --- code_only: multi-byte UTF-8 (`§ × →`) must not corrupt offsets ---
        // The lexer is char-based; a multi-byte body must round-trip its CODE
        // tokens intact and still blank a comment that follows.
        let utf8 = "fn f() { let _ = \"§ × →\"; do_it(); } // §persist_state_fail_closed";
        let utf8_out = code_only(utf8);
        assert!(
            utf8_out.contains("do_it()") && utf8_out.contains("fn f()"),
            "multi-byte UTF-8 body code must survive intact: {utf8_out:?}"
        );
        assert!(
            !utf8_out.contains("persist_state_fail_closed"),
            "the trailing comment (after a multi-byte body) must still be blanked"
        );

        // --- skip_block_comment / skip_raw_string newline preservation ---
        // (so the count cross-check's line indexing stays aligned).
        let multiline_block = "a();\n/* line1\nline2 persist_state_fail_closed\nline3 */\nb();";
        let ml_out = code_only(multiline_block);
        assert_eq!(
            ml_out.matches('\n').count(),
            multiline_block.matches('\n').count(),
            "code_only must preserve every newline (block-comment newlines kept) so \
             line-indexed cross-checks stay aligned: {ml_out:?}"
        );
        assert!(!ml_out.contains("persist_state_fail_closed"));
    }

    /// ADR-049 §9 — table-driven UNIT tests for the tripwire's header / receiver /
    /// brace-bounding / no-persist-method helpers (`is_method_header` /
    /// `body_has_self_receiver` / `brace_bounded_body` /
    /// `class_s_no_persist_methods`). Companion to
    /// `tripwire_lexer_blanks_comments_and_strings`.
    #[test]
    fn tripwire_lexer_classifies_headers_and_no_persist_methods() {
        // --- is_method_header: structural qualifier-soup recognition ---
        for ok in [
            "    fn plain(&mut self) {",
            "    pub fn p(&self) {",
            "    pub(crate) fn pc(&mut self) {",
            "    pub(in crate::context) fn restricted(&self) {",
            "    pub(super) const fn cs(&self) {",
            "    async fn af(&mut self) {",
            "    pub(crate) const async unsafe fn soup(&mut self) {",
            "    extern \"C\" fn ext() {",
        ] {
            assert!(is_method_header(ok), "must recognize method header: {ok:?}");
        }
        for not in [
            "    let x = 1;",
            "    // fn commented(&self) {",
            "    self.field = 2;",
            "    struct NotAFn;",
        ] {
            assert!(
                !is_method_header(not),
                "must NOT treat as a method header: {not:?}"
            );
        }

        // --- body_has_self_receiver: token match, not substring ---
        assert!(body_has_self_receiver("fn m(&mut self) { }"));
        assert!(body_has_self_receiver("fn m(&self) { }"));
        assert!(body_has_self_receiver("fn m(self) { }"));
        assert!(body_has_self_receiver("fn m(&'a self) { }"));
        assert!(body_has_self_receiver("fn m(self: Box<Self>) { }"));
        // A generic `<…>` list with a `Fn(…)` bound before the param list must not
        // confuse the param-list finder.
        assert!(body_has_self_receiver(
            "fn m<T: Fn(u8) -> u8>(&mut self, t: T) { }"
        ));
        // A param merely NAMED `self_id` is NOT a self receiver (false-positive
        // guard) — nor is a free function whose first param is some other type.
        assert!(
            !body_has_self_receiver("fn m(self_id: u8) { }"),
            "`self_id` must not be mistaken for a `self` receiver"
        );
        assert!(
            !body_has_self_receiver("fn m(myself: u8) { }"),
            "`myself` must not be mistaken for a `self` receiver"
        );
        assert!(
            !body_has_self_receiver("fn new(state: PerContextState) { }"),
            "a constructor with no self receiver must be skipped"
        );

        // --- brace_bounded_body: a `format!`-style `\"{…}\"` brace cannot desync ---
        // Braces inside a string literal must not be counted (code_only blanks the
        // string content first), so the body bounds at its REAL closing brace.
        let with_str_brace = "fn m(&self) { let s = \"{ not a brace }\"; inner(); } fn next() {";
        let bounded = brace_bounded_body(with_str_brace);
        assert!(
            bounded.contains("inner()") && !bounded.contains("fn next"),
            "brace_bounded_body must stop at the real closing brace, not a \
             string-literal brace, and not bleed into the next method: {bounded:?}"
        );

        // --- class_s_no_persist_methods: end-to-end over a crafted impl block ---
        // A rogue `&mut self` no-persist mutator must be FOUND; a method that names
        // the marker only inside a comment must ALSO be found (the comment marker
        // does not count as a persist); a method that genuinely names the marker in
        // CODE must NOT be found; a `self_id`-param free-ish method and a no-self
        // constructor must be skipped.
        let crafted_impl = "\
impl ClassSCell {
    fn rogue_no_persist(&mut self) {
        self.state.class_s.x = 1;
    }

    fn marker_only_in_comment(&mut self) {
        // persist_state_fail_closed (this is a comment, must NOT count)
        self.state.class_s.y = 2;
    }

    fn genuinely_persists(&mut self) {
        self.state.class_s.z = 3;
        persist_state_fail_closed(&self.state, deps, ctx);
    }

    fn not_a_receiver(self_id: u8) {
        let _ = self_id;
    }

    fn ctor(state: PerContextState) -> Self {
        Self { state }
    }
}
";
        let (mut found, recognized) =
            class_s_no_persist_methods(crafted_impl, &["persist_state_fail_closed"]);
        found.sort();
        assert_eq!(
            found,
            vec![
                "marker_only_in_comment".to_owned(),
                "rogue_no_persist".to_owned(),
            ],
            "the no-persist SELF-receiver methods must be exactly the rogue mutator \
             and the comment-only-marker method; the genuinely-persisting method, \
             the `self_id` non-receiver, and the no-self constructor are excluded"
        );
        // Five `fn` headers, all recognized (the count cross-check the tripwire
        // relies on).
        assert_eq!(
            recognized, 5,
            "is_method_header must recognize all five crafted `fn` headers"
        );
    }

    /// ADR-049 §9 (BLACK-CS-02) — `find_inherent_impl_blocks` is brace-depth-aware,
    /// so an INLINE / multi-space / newline-brace second `impl ClassSCell` block is
    /// detected (the prior literal `"\nimpl ClassSCell {\n"` count missed all three
    /// spellings, letting a hostile no-persist mutator hide in an un-scanned block).
    #[test]
    fn tripwire_counts_inline_and_spaced_impl_blocks() {
        // One canonical block + an INLINE hostile block (no space before `{`, body
        // on one line) + a multi-space + a newline-before-brace block. A brittle
        // `"\nimpl ClassSCell {\n"` scan would count only the canonical one.
        let src = "\
impl ClassSCell {
    fn ok(&mut self) { persist_state_fail_closed(); }
}
impl ClassSCell{ fn evil(&mut self){ self.state.class_s.saga_pending.clear(); } }
impl  ClassSCell   {
    fn spaced(&self) {}
}
impl ClassSCell
{
    fn newline_brace(&self) {}
}
";
        let code = code_only(src);
        let blocks = find_inherent_impl_blocks(&code, "ClassSCell");
        assert_eq!(
            blocks.len(),
            4,
            "brace-aware scan must find ALL FOUR `impl ClassSCell` blocks \
             (canonical + inline + multi-space + newline-brace); found {}: {:?}",
            blocks.len(),
            blocks
        );
        // The inline hostile block's body must be isolated intact (so its
        // no-persist `evil` mutator would be classified, not hidden).
        assert!(
            blocks.iter().any(|b| b.contains("fn evil")),
            "the inline hostile block must be isolated so its mutator is scannable"
        );
        // Word-boundary: `ClassSCellFoo` is NOT `ClassSCell`.
        let not = code_only("impl ClassSCellFoo { fn x(&self) {} }");
        assert!(
            find_inherent_impl_blocks(&not, "ClassSCell").is_empty(),
            "the type-name match must be word-bounded (no `ClassSCellFoo` match)"
        );
        // A trait impl `impl Trait for ClassSCell { … }` is NOT an inherent block.
        let trait_impl = code_only("impl Deref for ClassSCell { fn deref(&self) {} }");
        assert!(
            find_inherent_impl_blocks(&trait_impl, "ClassSCell").is_empty(),
            "a trait impl (`impl Trait for ClassSCell`) must not be counted as an \
             inherent `impl ClassSCell` block"
        );
    }

    /// ADR-049 §9 (F3) — `class_s_cell_alias` rejects a `type … = ClassSCell;`
    /// alias (the canonical evasion that would let an `impl <Alias>` block reach the
    /// privatized Class-S fields through a header the `ClassSCell`-keyed scan can't
    /// see), and does NOT false-positive on non-alias `type` items or a `ClassSCellFoo`
    /// prefix collision.
    #[test]
    fn tripwire_rejects_class_s_cell_alias() {
        // Canonical hostile alias + an alias-impl with a no-persist mutator: the
        // DECLARATION is what trips (the impl-block scan would miss `impl Evil`).
        let hostile = code_only(
            "type Evil = ClassSCell;\n\
             impl Evil { fn sneak(&mut self){ self.state.class_s.saga_pending.clear(); } }",
        );
        assert!(
            class_s_cell_alias(&hostile).is_some(),
            "a `type Evil = ClassSCell;` alias must be detected (F3)"
        );

        // Spacing variants (no spaces around `=`, extra spaces) still trip.
        assert!(class_s_cell_alias(&code_only("type A=ClassSCell;")).is_some());
        assert!(class_s_cell_alias(&code_only("type   B   =   ClassSCell ;")).is_some());

        // A generic alias `type C<T> = ClassSCell;` (degenerate but parse-safe).
        assert!(class_s_cell_alias(&code_only("type C<T> = ClassSCell;")).is_some());

        // A PATH-QUALIFIED RHS whose final segment is `ClassSCell` also trips — the
        // canonical honest-contributor spelling the bare-name match alone would miss
        // (the `impl <Alias>` it enables would equally evade the literal-`ClassSCell`
        // impl-block scan).
        assert!(
            class_s_cell_alias(&code_only(
                "type Evil = crate::context::actor::class_s::ClassSCell;"
            ))
            .is_some(),
            "a path-qualified alias of `ClassSCell` must be detected (F3)"
        );
        // An absolute-path (`::`-prefixed) qualification trips too.
        assert!(
            class_s_cell_alias(&code_only(
                "type Evil = ::crate::actor::class_s::ClassSCell;"
            ))
            .is_some(),
            "a leading-`::` path-qualified alias must be detected"
        );

        // NOT an alias of ClassSCell: a different aliased type, a prefix collision,
        // and an unrelated `type` item must all be ignored (no false positive).
        assert!(class_s_cell_alias(&code_only("type Other = PerContextState;")).is_none());
        // A path-qualified RHS whose final segment is an UNRELATED type must NOT trip
        // — the match keys on the final segment, not on any `ClassSCell` in the path.
        assert!(
            class_s_cell_alias(&code_only("type Ok = crate::foo::PerContextState;")).is_none(),
            "a path-qualified alias of an unrelated type must not false-positive"
        );
        // A path-qualified RHS whose final segment is a `ClassSCell` PREFIX collision
        // stays word-bounded (the final segment is `ClassSCellFoo`, not `ClassSCell`).
        assert!(
            class_s_cell_alias(&code_only("type Foo = crate::class_s::ClassSCellFoo;")).is_none(),
            "the final-segment match must be word-bounded even when path-qualified"
        );
        assert!(
            class_s_cell_alias(&code_only("type Foo = ClassSCellFoo;")).is_none(),
            "the aliased-type match must be word-bounded (no `ClassSCellFoo` match)"
        );
        assert!(class_s_cell_alias(&code_only("type Bytes = [u8; 32];")).is_none());
        // A `ClassSCell` mention that is NOT a type alias (e.g. inside an impl
        // header) must not be mistaken for one.
        assert!(class_s_cell_alias(&code_only("impl ClassSCell { fn x(&self) {} }")).is_none());

        // The real source file declares NO such alias (the production invariant).
        assert!(
            class_s_cell_alias(&code_only(include_str!("class_s.rs"))).is_none(),
            "class_s.rs must not declare a `type … = ClassSCell;` alias"
        );
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

    /// A token dropped without `commit` trips the `Drop` `debug_assert!`
    /// (keep-direction backstop, parity with `EconomyTicket`). Ignored without
    /// `debug_assertions`: a release build compiles the assert out, so the
    /// expected panic never fires there. The body still compiles in release.
    #[cfg_attr(
        not(debug_assertions),
        ignore = "the debug_assert! this test expects is compiled out without debug_assertions"
    )]
    #[test]
    #[should_panic(expected = "dropped without commit")]
    fn token_dropped_without_commit_panics_in_debug() {
        let token = ClassSCommitToken::new_for_test(&ctx_hex(0x65));
        drop(token);
    }

    /// `subsume` discharges the Drop obligation WITHOUT a second persist — the
    /// audited path for a redundant obligation already covered by a sibling token
    /// (ADR-049 §9). The token does NOT trip the Drop guard after `subsume`. This is
    /// the reconciliation the send-finalize PAID branch and the governance-finalize
    /// `discharge_with` path use when a consequence GROW armed a sink whose persist
    /// is already owed by another in-flight token.
    #[test]
    fn subsume_discharges_without_panicking() {
        let ctx = ctx_hex(0x66);
        let token = ClassSCommitToken::new_for_test(&ctx);
        // Subsuming consumes the token (sets `consumed`), so its `Drop` is silent —
        // no `dropped without commit` panic. (If `subsume` left the token un-consumed
        // this test would abort in the destructor.)
        token.subsume(&ctx);
    }

    /// `subsume` debug-asserts the token's context against the caller's, mirroring
    /// `commit` — a token cannot be subsumed against the wrong context. Ignored
    /// without `debug_assertions`: a release build compiles the `debug_assert_eq!`
    /// out, so the expected panic never fires there. The body still compiles in
    /// release.
    #[cfg_attr(
        not(debug_assertions),
        ignore = "the debug_assert_eq! this test expects is compiled out without debug_assertions"
    )]
    #[test]
    #[should_panic(expected = "subsumed against the wrong context")]
    fn subsume_wrong_context_panics_in_debug() {
        let token = ClassSCommitToken::new_for_test(&ctx_hex(0x67));
        token.subsume(&ctx_hex(0x68));
    }

    // ------------------------------------------------------------------
    // set_generation_for_test (foundation #5 — test-only Class-C setter)
    // ------------------------------------------------------------------

    /// `set_generation_for_test` seeds the Class-C generation counter directly,
    /// observable through the read `Deref`.
    #[test]
    fn set_generation_for_test_seeds_generation() {
        let mut cell = ClassSCell::new(fresh_state(0x93));
        assert_eq!(cell.generation, 0, "fresh state starts at generation 0");
        cell.set_generation_for_test(7);
        assert_eq!(
            cell.generation, 7,
            "generation seeded through set_generation_for_test"
        );
    }

    // -----------------------------------------------------------------------
    // `mutation_epoch` — the view hand-out counter `execute_governance_action`
    // reads to tell a pre-effect dispatch error from a post-effect one.
    // -----------------------------------------------------------------------

    /// A fresh cell starts at zero, and `Deref` reads advance nothing: two
    /// equal reads must prove that no mutable view was constructed between them.
    #[test]
    fn mutation_epoch_starts_at_zero_and_reads_hold_it() {
        let cell = ClassSCell::new(fresh_state(0x90));
        assert_eq!(cell.mutation_epoch(), 0, "fresh cell starts at epoch 0");
        let _ = cell.members.len();
        let _ = cell.governance.class_s.threshold_value;
        assert_eq!(
            cell.mutation_epoch(),
            0,
            "immutable reads through `Deref` construct no view and advance nothing"
        );
    }

    /// `class_c_view` hands out a mutable view, so it advances the epoch once
    /// per hand-out — the counter cannot see which field the view touched, so
    /// the hand-out itself is the event.
    #[test]
    fn mutation_epoch_advances_once_per_class_c_view() {
        let mut cell = ClassSCell::new(fresh_state(0x91));
        {
            let mut view = cell.class_c_view();
            view.members_mut()
                .insert(DID("did:example:epoch-member".to_owned()));
        }
        assert_eq!(cell.mutation_epoch(), 1, "one hand-out, one advance");
        *cell.class_c_view().checkpoint_events_since_mut() += 1;
        assert_eq!(
            cell.mutation_epoch(),
            2,
            "a leaf credit through the view is a hand-out too: a landed leaf that \
             a helper credits advances the epoch"
        );
    }
}
