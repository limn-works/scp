# fix/ceiling-modify-reconcile (HEAD abdc11d80) — CLEAN review (Jun 2026)

ModifyCeiling deferred-apply now reconciles cached auth state down to a lowered ceiling.

## What changed
- `roles.rs::set_ceiling` now calls new private `reconcile_to_ceiling()` after storing the ceiling.
- `reconcile_to_ceiling`: shrink-only prune of `role_definitions[*].capabilities`, `member_capabilities[*]`, `suspended_capabilities[*]` to `ceiling.contains(c)`. Empty `member_capabilities`/`suspended_capabilities` entries removed; empty role definitions RETAINED (name may back assignments/membership).
- FFI sync after deferred apply (`apply_pending_ceiling_modification`) in PyO3/NAPI/UniFFI: re-read role_state via `sync_role_state_from_manager[_async]`, syncs regardless of `applied` bool, logs on failure (non-fatal). PyO3 correctly uses the `_async` variant (nested block_on would panic). UniFFI `??` correct (JoinError then ScpError); `bi` moved into spawn, sync uses `self.inner` — sound.
- WASM: comment-only (shared set_ceiling already inherits reconcile).
- runtime class_s.rs: genuine e2e test.

## Verification done
- Borrow split sound: `let ceiling=&self.ceiling` + per-field `retain` on disjoint named fields.
- Wildcard prune correct: dropping ToolInvokeAll → `contains(ToolInvoke(id))` false → stale concrete pruned.
- Widen = no-op (no grant): `widen_does_not_grant`/`idempotent` PASS even with reconcile disabled.
- No resurrection: suspended-prune predicate keeps a still-granted+in-ceiling cap suspended (fails both drop conditions).
- Gate uses `member_capabilities.get().is_some_and()` → removing empty entry == empty set. members/assignments untouched (membership ≠ cap cache); no dangling ref at gate.
- Idempotence = logical Eq (HashMap order-independent); digest uses serde_sorted_set so order irrelevant.
- Deferred apply (governance_helpers.rs:489) calls set_ceiling inside commit_class_s_keep fail-closed.
- Other production set_ceiling sites = test/initial-ceiling; reconcile pure-shrink can only remove already-unauthorized caps → harmless everywhere.
- FAIL-BEFORE PROBE: disabled `self.reconcile_to_ceiling();` → 5 protocol prune tests + runtime e2e FAIL; widen/idempotent still PASS. Restored. Genuine tests, no tautology.
- `cargo test -p scp-protocol context::roles` 138 pass; `-p scp-runtime --lib apply_pending_ceiling_modification_prunes` 1 pass.

## No bugs found. No panics/unwraps in new non-test code (retain closures total).
