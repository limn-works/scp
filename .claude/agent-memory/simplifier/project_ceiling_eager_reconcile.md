---
name: ceiling-eager-reconcile
description: ContextRoleState::set_ceiling eager shrink-only reconcile is the chosen design; member_has_capability deliberately has NO read-time ceiling re-check (write-time invariant covers all writers)
metadata:
  type: project
---

`ContextRoleState::set_ceiling` (crates/scp-protocol/src/context/roles.rs) eagerly calls `reconcile_to_ceiling()` — a SHRINK-ONLY, idempotent intersection of `role_definitions[*].capabilities`, `member_capabilities[*]`, and `suspended_capabilities[*]` against the new ceiling. Branch fix/ceiling-modify-reconcile.

**Why:** A governed `ModifyCeiling` that LOWERS the ceiling must not leave stale out-of-ceiling grants in the Tier-2 cache (`member_has_capability` reads `member_capabilities` minus suspended, with NO ceiling re-check). Putting reconcile in `set_ceiling` — the single whole-ceiling write chokepoint — means BOTH native (`apply_pending_ceiling_modification`) and WASM (`dispatch_modify_ceiling`) inherit it identically.

**The omitted read-time re-check is correct, not under-engineering.** Verified the full write set to `member_capabilities`/`role_definitions[*].capabilities`: `new` (ceiling-bounded), `assign_role`/`system_assign_role` (copy from ceiling-bounded role defs), the Ed25519-signed import path, and the `set_ceiling` reconcile. The only other runtime writer (governance_helpers.rs signer-removal `retain`) is a SHRINK. All other hits are test seeds. So the write-time invariant genuinely closes — a read-time `self.ceiling.contains(...)` in `member_has_capability` would be a redundant use-time re-check of a write-time-enforced property (CLAUDE.md negative-value rule).

**Import path = guard (iii), deliberately NOT closed at the local gate.** export/import installs `role_state` VERBATIM via `lifecycle_helpers.rs` (~line 2074, `export.snapshot.role_state`), bypassing `set_ceiling`. `validate_export_for_import` binds ORIGIN (Ed25519 sig) not well-formedness. Argued inert: creator IS the ceiling authority, and cross-node re-presentation is independently re-validated against the signed ceiling at spec §7.2.1 step 8 (verified real, `07-trust-validation-and-capabilities.md:81`). An import-time cap-subset-of-ceiling re-check would be a redundant re-check of a signature-bound inert property — do NOT recommend adding it. The authoritative invariant doc on `ContextRoleState` is consolidated to ONE block (guards i/ii/iii) with one-line pointers elsewhere. If a future revision adds a "guard (iv)" lazy/import re-check, THAT is the over-engineering risk to flag.

**How to apply:** If reviewing future mutations of `member_capabilities` or role-def capabilities, the new writer MUST stay ceiling-bounded or route through `set_ceiling`. Do NOT recommend adding a lazy ceiling check to `member_has_capability` — that was deliberately rejected. `reconcile_to_ceiling` mirrors the existing `prune_suspensions_to_role_grants` retain+empty-cleanup idiom. FFI sync after this op reuses the existing `sync_role_state_from_manager` helper (the standing post-governance pattern in crates/scp-ffi/CLAUDE.md).
