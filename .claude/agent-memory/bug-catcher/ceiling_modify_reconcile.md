---
name: ceiling-modify-reconcile
description: Review of fix/ceiling-modify-reconcile (3afb1ae06) — ContextRoleState::set_ceiling eager shrink reconcile + FFI role-state re-sync. Clean; one LOW doc-precision note.
metadata:
  type: project
---

# fix/ceiling-modify-reconcile review (HEAD 3afb1ae06, 2026-06-26)

The change: `ContextRoleState::set_ceiling` now calls new private `reconcile_to_ceiling`
(shrink-only `retain` prune of role_definitions[*].capabilities, member_capabilities[*],
suspended_capabilities[*] to `ceiling.contains(c)`). FFI deferred-apply paths (PyO3
scp-ffi/src/context.rs, NAPI scp-ffi/napi/src/context.rs, UniFFI scp-ffi/uniffi/src/bridge.rs)
re-sync role_state from supervisor after ApplyPendingCeilingModification. WASM doc-only.

**Verdict: CLEAN.** Verified end-to-end:
- Borrow soundness: split-borrow via local `let ceiling = &self.ceiling;` and
  `let member_capabilities = &self.member_capabilities;` before each retain — disjoint
  fields, no whole-self conflict. Order: member_capabilities pruned BEFORE suspensions read it.
- No resurrection: suspension prune only drops a suspension when cap is out-of-ceiling OR
  no longer granted; a still-granted+in-ceiling suspended cap is RETAINED. Dropping a
  suspension for a non-granted cap can't resurrect (member_has_capability=false either way).
- Wildcard: `contains(ToolInvoke(id))` true only if ToolInvokeAll in ceiling → dropping
  ToolInvokeAll prunes concrete ToolInvoke(id). Correct.
- Widen never grants: reconcile is pure shrink; grants only from assign_role.
- FFI: `applied: bool` correctly threaded; UniFFI `??` (JoinError then inner Result);
  context_id cloned into closure, post-sync uses handle.context_id — no use-after-move;
  sync errors logged-not-propagated (graceful). sync_role_state_from_manager copies
  authoritative supervisor role_state verbatim — idempotent, "sync regardless of applied" safe.
- Runtime apply (governance_helpers.rs:489) routes through set_ceiling inside actor → reconcile
  fires before FFI re-reads. WASM dispatch_modify_ceiling also calls shared set_ceiling.
- Tests genuinely fail-before/pass-after: removed reconcile() call in throwaway worktree →
  5 of 7 new protocol tests + the class_s e2e test FAIL. (widen_does_not_grant +
  reconcile_idempotent pass either way — trivially; the other 5 carry regression weight.)
  All pass on the branch: `cargo test -p scp-protocol context::roles` (138 ok),
  `cargo test -p scp-runtime context::actor::class_s` (e2e ok).

**LOW (doc-precision only, NOT a defect):** roles.rs reconcile/set_ceiling docs say
reconcile is "a no-op on a WIDEN". Edge: a member assigned an empty-cap custom role
(RoleDefinition::new accepts empty set) has an empty member_capabilities entry; the first
set_ceiling (even a widen) removes that empty entry (`caps.retain` no-op then
`!caps.is_empty()` → false → removed), so a widen is not literally byte-identical when a
pre-existing empty member entry exists. HARMLESS: empty==absent at member_has_capability;
assignments map (source of truth) + retained role_definition fully reconstruct it; native +
WASM both route through shared set_ceiling → converge; idempotence (the digest-load-bearing
property, §23.16.8/ADR-050) holds on same-ceiling re-apply. Pure wording nit.

reconcile does NOT touch `assignments` (correct — assignment is source of truth, cache is derived).
