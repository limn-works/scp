---
name: classs-cell-field-granular-view
description: ADR-049 §9 ClassSCell view design — field-granular Class-C view (ClassCMut/GovernanceClassCMut) airtightness comes from accessor shape, not field privatization, because combinator+handler modules are co-descendants
metadata:
  type: project
---

`crates/scp-runtime/src/context/actor/class_s.rs` — ClassSCell (ADR-049 §9) gates Class-S state mutation behind persist combinators. Each combinator hands its closure a *view*: `ClassSMut` (fail-closed persist, may reach Class-S) or `ClassCMut` (best-effort / compensation, NO fail-closed persist, must NOT reach Class-S).

Reviewed commit 398a89c66 (branch refactor/classs-type-guard, 2026-06-21): made `ClassCMut` field-granular — deleted `rest_mut`/`governance_mut`; added `governance_class_c_mut -> GovernanceClassCMut` sub-view + `members_mut`/`receive_buffer_mut`/`role_state_mut`. `ClassCSplit.governance` retyped to `GovernanceClassCMut`. Verdict: APPROVED, merge-ready.

**Key reusable design lesson:**
- Airtightness of `ClassCMut` (no `&mut` path to any Class-S-containing struct) CANNOT come from field privatization, because the combinator module (`context::actor::class_s`) and handler modules (`context::actor::handlers::*`) are co-descendants of `context::actor` — no `pub(in PATH)` visibility separates them, so a handler could always name a `class_s` field through any whole-struct `&mut` handed out. Airtightness MUST come from the accessor SHAPE: every `&mut` accessor returns a specifically-Class-C field (or a Class-C sub-view); reads stay whole-state via `Deref` (reads can't violate the invariant).
- Asymmetry (`ClassSMut` keeps whole-`&mut` `rest_mut`, `ClassCMut` is field-granular) is correct and justified on the right axis: the fail-closed-persisting view may reach Class-S because its combinator covers it; the non-persisting view structurally cannot.

**Why:** A prior revision of these docs falsely claimed a later field-privatization PR would make `ClassCMut` airtight; this commit retracts that. The honest scoping: field-privatization concerns only the `state_mut` escape hatch and `ClassSMut`'s reach, NOT `ClassCMut`.

**How to apply:** When reviewing further ClassSCell migration PRs: (1) `class_s` is the ONLY Class-S field in both `PerContextState` (state.rs:1015) and `GovernanceState` (state.rs:1044) — direct `&mut` accessors to any other field are sound. (2) The field-granular set is intentionally a partial scaffold that grows as handlers migrate; only ~3 of ~16 PerContextState and ~4 of ~22 GovernanceState Class-C fields are exposed. Adding accessors is additive, not a design flaw. (3) Watch the `ConsequenceStateSplit` migration — it's the named first consumer of `split_class_c` and may need GovernanceClassCMut accessors beyond the current 4 (velocity_tracker/budget_tracker/cooldown_until/economic_policy) — e.g. hard_rate_limit, participation_cache, message_pricing. (4) Verify no `DerefMut` on any view (the compile-time hook).
