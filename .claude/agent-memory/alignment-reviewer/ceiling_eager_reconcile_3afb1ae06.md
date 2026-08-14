---
name: ceiling-eager-reconcile-3afb1ae06
description: ALIGNED review of fix/ceiling-modify-reconcile — eager ceiling reconciliation replacing lazy UCAN revalidation (§5.3.2 step 5 / §7.2.2)
metadata:
  type: project
---

# Eager Ceiling Reconciliation — branch `fix/ceiling-modify-reconcile` HEAD `3afb1ae06` (2026-06-26) — ALIGNED

Spec-first fix for the real §7.2.2-vs-§5.3.2 tension: §7.2.2 claimed "no window where stale capabilities are served" but §5.3.2 step 5 said LAZY "re-validate cached UCANs on next action attempt" (which DOES leave a stale-serving window at the Tier-2 local gate). Replaced with EAGER reconciliation at ceiling-change activation.

**Why:** the lazy text contradicted the cache's stated invariant and left a real window; the convergence/equivocation work (§9.9.3 Relay Consistency) depends on the no-stale-window property being true.

**How to apply (verified facts for future ceiling/cache reviews):**
- `ContextRoleState::set_ceiling` (roles.rs ~1843) is the SINGLE whole-ceiling write chokepoint; it calls `reconcile_to_ceiling()` immediately after storing. Both apply paths inherit reconcile: native `apply_pending_ceiling_modification` (governance_helpers.rs:489) + WASM `dispatch_modify_ceiling` (manager.rs:3730). Verify any NEW ceiling write routes through `set_ceiling`.
- `reconcile_to_ceiling` prunes THREE caches via `CapabilityCeiling::contains` (honors `ToolInvokeAll`→concrete `ToolInvoke(id)` wildcard): role_definitions[*].capabilities (empty roles RETAINED — names back assignments), member_capabilities[*] (empty entries dropped), suspended_capabilities[*] (dead-weight pruned). Pure SHRINK + idempotent → digest-stable (§23.16.8/ADR-050).
- Import path is the deliberate exception: `lifecycle_helpers` installs `export.snapshot.role_state` VERBATIM (line ~2074), NOT via set_ceiling. `validate_export_for_import` (export_import.rs:553) binds ORIGIN (version + exporter==creator + Ed25519 sig + Merkle root) NOT well-formedness — confirmed no cap-subset check. A self-inconsistent signed snapshot WOULD install an out-of-ceiling grant at the local gate but is INERT: (a) creator is the ceiling authority, (b) cross-node re-presentation re-validated against signed ceiling (§7.2.1 step 8). roles.rs doc-comment correctly declines to call this "construction-closed" and correctly refuses to add a redundant import-time re-check (tenet-aligned).
- Write-time guard (i) = `validate_role_definition` (roles.rs:2177) at assign time; guard (ii) = reconcile at ceiling-lower.

**Verification pattern that worked:** for spec↔code "describes the code" claims, grep `.docs/specs .docs/adrs` for the OLD behavior (here: "lazy", "Retroactive UCAN", "re-validate all cached UCAN", "on the next action attempt") — clean here, only unrelated storage-§17.10 `lazy` + Kotlin `by lazy` hits. Then confirm each doc-comment symbol exists (set_ceiling callers, apply fn, wasm dispatch fn, validate_export_for_import) and that named apply paths actually call set_ceiling. 0 blocking/material findings; 2 INFO (clean grep, §5.3.1.1 consistent).
