---
name: adr049-2g-placeholder-delete-destale
description: ADR-049 Phase 2G review — delete dead Placeholder mailbox variants + corpus-wide doc de-stale; FINAL @9b19a8974 SOUND+COHERENT, prior two residual misses now fixed
metadata:
  type: project
---

**FINAL re-review @9b19a8974 (was 7d449f9dd): SOUND + COHERENT.** Both prior residual
de-stale MISSES are now RESOLVED:
- deps.rs module-doc (miss #1) rewritten: "read directly by the handler bodies — e.g.
  `deps.event_tx` in governance, `deps.payment_adapter` in saga, `deps.local_dids` in
  queries. The former `view.manager().foo` indirection and the legacy manager it reached
  through are gone." No stale "commit 12"/"do not yet read". Fixed.
- mod.rs field-level vestigial allows (miss #2) on state/deps/ttl_timer/governance_timeout/
  last_persisted_at/dirty REMOVED. Only 3 allows remain, all honest: `context_id` (future-dead
  "when watchdog lands"), `new` (names real prod caller spawn_actor_with_state), `new_skeleton`
  (honestly "no production caller... pending removal of skeleton apparatus").
NEW at this HEAD: struct-level `#[allow(dead_code)]` on `PerContextState` REMOVED. VERIFIED
SOUND (no hidden dead field): all 4 private-type fields read on prod path — governance
(governance.rs cell.governance.engine/state.governance.timeout_task, lifecycle.rs:607,
saga.rs:1143), epoch (governance.rs:1172 cell.epoch.mls_epoch, trust_recovery.rs), ttl
(lifecycle.rs:606 state.ttl.timer.cancel, ttl_close.rs), access (via `access_mut()` accessor
called from governance_helpers.rs:1198 / messaging_helpers.rs:1105,1149 / queries_helpers.rs /
lifecycle_helpers.rs). Verified by call-graph tracing, not full clippy compile.
Actor-dispatch axis CLEAN: `dispatch_from_shim` has NO def + NO caller (fully deleted); all 4
surviving mentions correctly past-tense ("was/has been deleted at Phase 2A finalization"). All
ContextManager mentions past/deleted-framing. `dispatch_standing_direct`(4717)/`dispatch_economy_direct`
(3169) are real permanent Supervisor supervisor-scoped methods, NOT laundered shims. messaging.rs
send_tracker prose correctly re-attributed Phase-2A-finalization→follow-on sub-chunk while
PRESERVING pending truth (not laundered pending→done). skeleton_dispatch family honestly
test-only/pending-removal, "sole surviving NotImplemented producer" holds (standing/broadcast/
trust_recovery NotImplemented arms are passthrough clones, not producers). Placeholder = ZERO in
commands.rs. OUT OF SCOPE (tracked #125): state.rs:1158-62 access/access_key_store dual-storage
"12d removes the unused one" field-consolidation cluster — different axis, correctly not blocked.

---
Original review (HEAD 7d449f9dd, ADR-049 Phase 2G):
deletes 8 dead actor-mailbox `Placeholder` command variants, migrates their tests onto
real commands, de-stales deleted-`ContextManager`/`MutationStateView`/`dispatch_from_shim`
present-tense docs → past-tense.

**Sound decisions (verified against code + spec):**
- Placeholder deletions: no-op handshake targets, no load-bearing scaffold. Replaced by real
  commands / typed `ContextNotRegistered` errors. `tools_command_context_id` correctly
  narrowed `Option<&str>`→`&str` (all 4 ToolsCommand variants carry context_id; Placeholder
  was sole None-source) — principled simplification driven by the deletion.
- Test substitutions stronger: state-owning test now asserts a *concrete* MemberCount answer
  instead of a NotImplemented ack.
- Spec-citation fix §5.12.4→§5.12.6 (contact graph) verified correct against 05-contexts.md.
- DEFERRED-commit-11 ADR rewrite grounded in spec §5.15.8 "standing-pair creation path is not
  yet wired"; reframes exit-criterion-2 away from deleted Placeholder's `reply_not_implemented`
  to the actual unwired full-creation protocol; NO false "done" claim. `standing_context`
  get-or-create path exists (calls create_context) but add_member/Welcome/consent unwired —
  matches ADR + spec.
- skeleton actor / `spawn_actor` / `new_skeleton` honestly labeled dead-code/test-only pending
  removal (verified: zero production callers, only `#[cfg(test)]`). Not laundered into a
  permanent design category.
- Prior-review seams RESOLVED: state.rs `# Construction` now says production goes through
  `Supervisor::spawn_actor_with_state`; state-field "does not yet consume" doc corrected.

**Residual de-stale MISSES (corpus-wide-per-file gap — the recurring failure mode):**
1. `actor/deps.rs:84-88` — module-doc paragraph left un-destaled. Says "until the legacy
   manager is deleted in commit 12" (already deleted), "Handler bodies do not yet read the new
   fields" (FALSE — governance.rs/saga.rs/queries.rs read deps.event_tx/payment_adapter/
   local_dids), "12b+ performs the migration from `view.manager().foo`→`deps.foo`"
   (view.manager()/MutationStateView deleted). Contradicts same-file de-staled prose + code.
   (line 80 "migrates ... in commit 12b/c" same class.) This is the real finding.
2. `actor/mod.rs` fields state/deps/ttl_timer/governance_timeout/last_persisted_at/dirty keep
   `#[allow(dead_code)]` but the PR rewrote each comment to present-tense "read by the run-loop's
   X arm". Fields ARE read on the production run/dispatch path (already so on main), so the
   attribute is a vestigial no-op self-contradicting its own comment. `context_id` field's allow
   (line 112, future-tense "when the watchdog lands") is legitimately dead — leave it. Coherence
   nit; recommend deleting the 6 vestigial allows.

Verdict: overwhelmingly sound + coherent; two de-stale misses to fix to honor the PR's own
"corpus-wide de-stale" claim. Supersedes prior partial-de-stale note.
