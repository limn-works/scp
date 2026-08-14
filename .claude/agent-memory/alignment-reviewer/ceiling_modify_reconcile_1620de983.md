---
name: ceiling-modify-reconcile-1620de983
description: ALIGNED review of fix/ceiling-modify-reconcile (eager ceiling-change cache reconciliation; §5.3.2 step5 + §7.2.2 spec edits + roles.rs reconcile_to_ceiling + UniFFI honesty comment)
metadata:
  type: project
---

# fix/ceiling-modify-reconcile @ 1620de983 (2026-06-26) — ALIGNED, 0 blocking

Spec-first correction. Old §5.3.2 step 5 ("Retroactive UCAN validation … SDK MUST re-validate all cached UCANs on the next action attempt" = LAZY) contradicted §7.2.2's "no window where stale capabilities are served". Branch replaces lazy with EAGER reconciliation at activation.

**Why:** prior tension was real — lazy revalidation leaves out-of-ceiling caps in the Tier-2 `member_capabilities` cache until next action; §7.2.2 simultaneously promised no-stale-window. Eager prune at `set_ceiling` closes it permanently (no DOA — pure narrowing, idempotent).

**How to apply:** treat as the canonical example of a legitimate code→spec correction done RIGHT (fixed spec first, then downstream §7.2.2 bullet, then code). All claims independently verified:
- `validate_role_definition` guard (i): called at roles.rs 2264 (free assign_role) BEFORE member_capabilities.insert 2283; also 1998/2184/2310. TRUE.
- `set_ceiling` → `reconcile_to_ceiling` guard (ii): added at roles.rs ~1871; SHRINK-only + idempotent (test `set_ceiling_reconcile_idempotent` pins §23.16.8/ADR-050 digest stability). TRUE.
- import path (iii) "signature-bound not construction-closed": lifecycle_helpers.rs:2074 `role_state: export.snapshot.role_state` installs verbatim, NOT via set_ceiling. Honest. Inert because creator IS ceiling authority + cross-node re-validated at §7.2.1 step 8 (step 8 exists, confirmed).
- WASM `dispatch_modify_ceiling` (manager.rs:3731) routes through set_ceiling → inherits reconcile. Native `apply_pending_ceiling_modification` (governance_helpers.rs) routes set_ceiling inside commit_class_s_keep. Both converge on shared chokepoint. TRUE.
- UniFFI honesty comment (bridge.rs ~10037): `sync_role_state_from_manager` (uniffi/runtime.rs:933) binds `let _role_state` and DISCARDS — read-only liveness/log, NO write-back. PyO3 (src/runtime.rs:1683 `st.role_state = new_role_state`) + NAPI ARE the load-bearing write-backs (they hold FFI-local FfiBridgeState.role_state copy; UniFFI reads live from Supervisor). Asymmetry comment exactly accurate.
- `Ok(applied)` preserves prior bool return; sync is non-fatal warn-only side effect (correct: apply already succeeded).

No stale lazy/"retroactive UCAN"/"next action attempt" text remains anywhere in .docs/ (grep clean; remaining "retroactive" hits are content/access-key revocation + shadow-claim, unrelated). 09-security-model.md had NO diff vs main on this branch (working-tree M was unrelated).

7 new unit tests in roles.rs (prune member_caps, prune role_defs, widen-no-grant, idempotent, suspended-stays-denied, tool-invoke-wildcard-prune, member_has_capability-false-after-lowering). Doc-comments protocol-level, not over-specified — the authoritative invariant block is load-bearing (explains why read-time gate skips ceiling re-intersection).
