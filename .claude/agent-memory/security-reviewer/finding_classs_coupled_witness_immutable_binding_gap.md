---
name: finding-classs-coupled-witness-immutable-binding-gap
description: Class-S §9 coupled-negative compile witnesses (role_view_grow_resolves_to_trait, best_effort_view_has_no_whole_mut_accessor) only catch a &self inherent accessor; the realistic &mut self bypass shape is NOT caught because the test binds the view immutably
metadata:
  type: project
---

## Finding (commit b23509123, branch classs-fin-trunk, scp-runtime)

The two "coupled negative" compile witnesses in `crates/scp-runtime/src/context/actor/class_s.rs` are NOT real guards against the realistic bypass shape — they only catch a `&self` inherent method, not the `&mut self` one that any real GROW / whole-mut accessor would actually have.

- `role_view_grow_resolves_to_trait` (~line 3447): binds `let role_view = view.role_state_class_c_mut();` (IMMUTABLE), then calls `role_view.suspend_all()` / `.suspend_capabilities()` zero-arg, expecting them to resolve to the `NoInherentGrow` `&self` trait shims returning `NoGrowWitness`.
- `best_effort_view_has_no_whole_mut_accessor` (~line 3500): binds `let view = ClassCMut::from_state(...)` (IMMUTABLE), then `view.rest_mut()` / `.role_state_mut()` zero-arg, expecting the `NoWholeMutAccessor` `&self` trait shims.

**The flaw:** the real `ConsequenceRoleStateMut::suspend_all` is `fn suspend_all(&mut self, member_did: &str)` and the real `ClassSMut::rest_mut` is `fn rest_mut(&mut self) -> &mut PerContextState`. When a `&mut self` inherent method with that shape is ADDED to the named type, Rust method resolution CANNOT autoref `&mut` on an immutably-bound receiver, so it silently FALLS THROUGH to the `&self` trait shim — the witness STILL COMPILES and stays green. The "ADDING an inherent GROW breaks it / a COMPILE ERROR" claim (commit msg pt4 + the type-doc SCOPE notes + the test comments) is FALSE for the realistic case.

**Empirically verified** (probes added then reverted, file restored clean):
- inherent `fn suspend_all(&self, _:&str)->bool` on RoleStateClassCMut → witness BREAKS (E0061 arity + E0308 return) ✓ caught
- inherent `fn suspend_all(&mut self, _:&str)` (the REAL shape) on RoleStateClassCMut → COMPILES CLEAN, witness silent ✗ NOT caught
- inherent `fn rest_mut(&mut self)->&mut PerContextState` on ClassCMut → COMPILES CLEAN, witness silent ✗ NOT caught

**Fix:** bind the receiver `let mut role_view` / `let mut view` so a `&mut self` inherent candidate is preferred during resolution and its mismatched signature breaks the zero-arg `*Witness`-typed call. (With a `mut` binding, both `&self` and `&mut self` inherent shapes are caught.)

**Severity: MEDIUM** — defense-in-depth witness, not the primary guarantee (the field-granular type privacy + no-DerefMut wrappers are the real structural boundary, and those are sound). But the witness is advertised as the load-bearing coupled compile check for BLACK-CS-03 / path-B asymmetry, and it does not deliver that for the realistic mutator shape — so a future GROW/whole-mut accessor would land silently. Honest fix is a one-line `mut` per witness.

## Reusable lesson
Coupled-negative compile witnesses (trait `&self` shim + zero-arg call, relying on inherent-over-trait resolution preference) MUST bind the receiver `mut`. An immutably-bound receiver makes `&mut self` inherent candidates non-viable, so resolution falls through to the `&self` shim and the witness fails to catch the most common mutator shape. Always probe BOTH `&self` and `&mut self` inherent shapes when validating such a witness.

## What WAS sound in this commit (verified)
- ClassSCommitToken sink machinery: `consumed=true` set BEFORE persist (keep-direction), Drop-guard panic in debug + metric in release, `!Clone/!Copy` asserted, no mem::forget/ManuallyDrop/swap escape, producers confined to new/for_downward_auth/new_for_test, note_downward_auth idempotent (sink.is_none()).
- All 5 production sites discharge fail-closed before ack with correct error precedence (durability over original cause):
  - receive handler handle_deliver_incoming: take()+commit after view drops, all 3 timeout arms reach it
  - send finalize_send/persist_finalized_send: free branch mints token; paid branch rides nonce token's commit (debug_assert no double obligation) — EXACTLY ONE owed persist per branch
  - tool-settle settle_tool_economy: token in CALLER's Option survives callee's `?` early-return; take()+commit on BOTH Ok/Err arms BEFORE `capture_result?` — sound `?`-survival
  - periodic sweep handle_evaluate_periodic_consequences_actor: take().map_or(Ok, commit), reports mutated so run loop coalesce-persists too
  - governance action: unchanged (already discharge_with token-based)
- F2 member_capabilities_mut shrink hole CLOSED: deleted from best-effort RoleStateClassCMut (now read-only member_capabilities()); the remaining member_capabilities_mut at ~1575 is on the GROW-capable ConsequenceRoleStateMut (fail-closed by caller) — correct.
- roles.rs change is DOC-ONLY (no visibility/code change, no new GROW reach).
- class_s_cell_alias tripwire (F3) honestly scoped (honest-contributor convergent guard, compile boundary is the real guarantee).
- All 1916 scp-runtime lib tests pass.
