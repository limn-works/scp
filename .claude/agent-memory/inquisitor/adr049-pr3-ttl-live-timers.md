---
name: adr049-pr3-ttl-live-timers
description: ADR-049 PR-3 live-timers TTL review — H1 memory_scope==Full gate is an unsound proxy for promotion-status (created-Full+ttl contexts lose TTL on restore); P1 import clamp and P3 bounded backoff are sound.
metadata:
  type: project
---

ADR-049 PR-3 (`feat/adr049-pr3-live-timers`, TTL live timers). Interrogated pass-4 fixes.

**PASS-5 WHOLE-BRANCH REASSESSMENT (HEAD ae3bcc7b1): VERDICT = PATCH via ROOT-CAUSE
pass-4c, NOT redo, NOT symptom-patch.** Core overturn (A3 actor-owned reconcile_timers
arms; absolute ttl_deadline_secs; §9 Class-S fail-closed terminal persist; is_terminal;
create-terminal precheck) is SOUND and orthogonal — ~4000 of 4538 lines. REDO would
destroy sound expensive work to fix a ~600-line subsystem (inverse sunk-cost). ROOT CAUSE
of the recurring round-2 pattern = **no single source of truth for the convergent
deadline.** Four representations kept in sync only by convention: (1) runtime
`state.ttl.timer.deadline_unix_secs`, (2) persisted `ContextSnapshot.ttl_deadline_secs`,
(3) event-log `max TtlExtended.new_deadline_unix`, (4) `creation+params.ttl`. Each branch
fix picked a DIFFERENT authority → patching one exposed the next:
- **Two extension paths, divergent logging.** `execute_extend_ttl` (governance ExtendTtl,
  gov_helpers.rs:1871) emits a TtlExtended leaf. `reset_ttl_timer` (ttl_close_helpers:329,
  reached by LIVE FFI `context_reset_ttl_timer` on all 4 bridges + propose/unanimous flow)
  mutates the deadline with NO leaf. Spec §5.10.1 step 5 REQUIRES the TtlExtended leaf on
  every activation → reset_ttl_timer VIOLATES spec. M1 terminal leaf
  (convergent_expiry_leaf_deadline, ttl_close_helpers:454) and M3 import clamp
  (derive_extension_bound, export_import:519) both derive from the log (#3) → a
  reset-extended context gets an UN-extended terminal leaf and its import deadline clamped
  DOWN, re-breaking D2 (the exact extension-loss the branch set out to fix). M3-clamp
  DIRECTLY CONTRADICTS the 150bfccd5 restore-verbatim decision unless every extension logs.
- **Promotion diverges from spec (H1 root).** Spec §5.10 "on promotion: TTL is removed."
  execute_promote_context (gov_helpers:2703) clears runtime deadline + sets memory_scope
  Full + emits ContextPromoted, but does NOT clear params.ttl (the source restore reads).
  So persisted deadline=None is ambiguous {no-ttl | promoted | legacy}. Restore/import
  re-derive from params.ttl via `.or_else(convergent_ttl_deadline_secs)` → re-arm promoted
  contexts. Pass-4a proxied with `memory_scope != Full` (lifecycle_helpers:2470 import,
  :3071 restore) — wrong: created-Full+ttl (every broadcast context, :3591 "broadcast only
  Full") goes immortal after restart. THE AUTHORITATIVE SIGNAL ALREADY EXISTS AND IS
  DURABLE — the ContextPromoted leaf — and the re-arm logic ignores it for a proxy.
Coherent target: **event log = single authoritative convergent deadline.** One derive fn:
ContextPromoted-after-Created ⇒ None; else max(creation+params.ttl, max TtlExtended). Every
mutation emits a leaf (creation✓, extension: unify reset into execute_extend_ttl / delete
bare context_reset_ttl_timer as phantom-provenance, promotion✓). Restore/import/retry/re-arm
all DERIVE from the log; persisted scalar #2 becomes a reconcilable cache; M3 "clamp"
becomes "derive" (import already Merkle-validates the whole log → adversarial-inflation
vanishes, history_complete predicate concern dissolves); memory_scope gate DELETED. pass-4c
MUST be scoped as this root fix — a symptom pass-4c (fix the 3 round-2 findings) is
non-convergent and spawns round 3. Redo becomes preferable ONLY if the team won't commit to
root scoping. Tests encoding buggy behavior (restore_promoted memory_scope gate 14168; H2
reset-no-leaf 14555) must be rewritten under the coherent design (a redo would owe the same).

**H1 gate is MIS-IMPLEMENTED (root-cause finding).** The re-arm gate at
`lifecycle_helpers.rs:2470` (import) and `:3071` (restore) is
`params.ttl.is_some() && memory_scope != MemoryScope::Full`. It uses
`memory_scope==Full` as a proxy for "was promoted / has no live TTL." That proxy
is UNSOUND: `memory_scope` is a data-retention policy (Ephemeral/Summary/Full =
what happens to keys on close), NOT a lifecycle fact.
- **Why:** `validate_params` (builder.rs:775) permits `Full` + finite `ttl`
  (only checks broadcast). Tests construct it (params.rs:1087, 1565).
  `reconcile_timers` (actor/mod.rs:721) arms TTL at creation with NO scope gate.
  Spec §5.10 line 488 ("When TTL expires, key destruction follows the memory
  scope") explicitly contemplates Full+TTL: close at TTL, retain data.
- **Consequence:** a context CREATED with Full+ttl honors its TTL while the node
  runs but SILENTLY becomes immortal after restart/import — the gate skips
  `dispatch_start_ttl_timer` and the restored actor's `TtlTimer::with_clock`
  starts `deadline_unix_secs=None`, so `reconcile_timers` arms nothing.
- **Three sites disagree** (internal incoherence / drift): H1 assumes Full⇒no-TTL;
  creation/reconcile assume Full+TTL is live; validate_params is silent.
- **Clean fix exists** (so it's MIS-IMPLEMENTED, not an unavoidable dilemma):
  promotion clears the persisted `deadline_unix_secs` but a created-Full+ttl
  context persists it as `Some`. So for Full scope, arm iff persisted
  `ttl_deadline_secs` is `Some` (do NOT re-derive creation+ttl for Full). That
  keeps promotion-safety (None→skip) AND created-Full+ttl correctness (Some→arm).
  Alternatively use the `ContextPromoted` event as the signal. Per artifact-flow:
  resolve the spec question first (is Full+ttl a valid live-TTL state? §5.10 says
  yes), then either enforce Full⇒no-ttl in validate_params OR fix the predicate.

**P1 import clamp (M3) HOLDS.** `derive_extension_bound` (export_import.rs:519)
clamps imported `ttl_deadline_secs` to `max(creation+ttl, max logged
TtlExtended.new_deadline_unix)` when `history_complete` (log begins with
ContextCreated genesis), else verbatim. The pruned-log "hole" is closed by the
import Merkle-completeness replay (export_import.rs:672-689): a prefix-pruned
(genesis-dropped) log is REJECTED outright — the non-genesis first entry's
sequence/prev_hash fails replay, so the recomputed root ≠ signed root. So on the
sole caller (import), `history_complete` is always true post-validation; the
"else verbatim" branch is near-unreachable defense-in-depth. Clamp-not-reject is
correct (preserves valid extensions). Minor: comment frames verbatim branch as
handling "pruned logs" the import path never actually admits.

**P3 bounded backoff (M2) HOLDS.** `ttl_expiry_retry_backoff` (actor/mod.rs:116):
base 5s, exp 2^(n-1), capped 5min, overflow-safe. Retry COUNT is intentionally
infinite (fail-closed SEC-1: never despawn with undurable terminal state), with
operator-visible rate-limited `error!` at `TTL_EXPIRY_STUCK_THRESHOLD=12` and
every 12 thereafter. "Bounded backoff" now accurately describes the CADENCE;
comment corrected and honest ("keeps retrying; operator intervention required").

**is_terminal() (N5) HOLDS.** `ContextState::is_terminal()`
(scp-protocol/context/mod.rs:236) = {Expired,Closed,Tombstoned}, exhaustive
match (new variant = compile error). Correctly EXCLUDES Poisoned (recoverable
via operator respawn), Closing/MigratingOut (transient). Matches spec terminal
definition; both uses (despawn gate, B8 precheck) want permanent-terminal.
Good closed-by-construction centralization.
