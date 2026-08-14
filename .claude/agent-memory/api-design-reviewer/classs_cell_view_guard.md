---
name: classs-cell-view-guard
description: ClassSCell / ClassSMut / ClassCMut field-granular view family (ADR-049 §9) — fail-closed-vs-best-effort persist guard; APPROVED, the airtightness pattern + watch-items
metadata:
  type: project
---

# ClassSCell mutation-view guard (ADR-049 §9, `crates/scp-runtime/src/context/actor/class_s.rs`)

Reviewed branch `refactor/classs-type-guard` @ `d8207cde2` (2026-06-21). Verdict: APPROVED as a `pub(crate)` internal boundary.

**What it is.** `ClassSCell` owns `PerContextState`, `Deref` only (no `DerefMut`), and gates every Class-S mutation behind named combinators (`commit_class_s_keep/_restore/_compensating/_keep_compensating/_then_append` fail-closed; `commit_class_c_best_effort` best-effort). Goal: make the §9 fail-closed-persist invariant a COMPILE error to violate, retiring `scripts/check-class-s-fail-closed.sh` (a non-convergent source-text scanner).

**The key pattern (worth recalling for similar boundaries).** Two view types with deliberate asymmetry:
- `ClassSMut` — fail-closed path — MAY hold a whole `&mut PerContextState` (via `rest_mut`); safe because its combinator persists fail-closed so any Class-S field reached through that `&mut` is covered.
- `ClassCMut` / `GovernanceClassCMut` — best-effort/compensation path (NO subsequent fail-closed persist) — hold ONLY field-granular references (a `&mut` per Class-C field + shared `&` to Class-S). Because no whole-bucket `&mut` survives the construction destructure, a "convenience" `rest_mut`/`governance_mut` accessor is literally unwriteable (no value of that type to return) → a Class-S mutation on the non-fail-closed path is uncompilable BY CONSTRUCTION, not by convention. This does NOT rely on field privatization (combinator + handler modules are co-descendants of `context::actor`, so no `pub(in PATH)` separates them).
- Backstopped by crate-root `#![forbid(unsafe_code)]` (lib.rs:21) — the only type-system escape (`*const _ as *mut _`) needs `unsafe`.

**Verified accurate against source (all load-bearing doc claims true):** GovernanceState (state.rs:1044) has exactly ONE Class-S field `class_s: GovernanceClassS` (→ `..` rest); PerContextState (actor/state.rs:1015) has exactly TWO (`class_s` → shared `&`, `governance` → wrapped). The new (d8207cde2) SAFETY INVARIANT comments at the two destructure sites (class_s.rs:394-402, 518-527) correctly state the rule "Class-S-containing field must be `..`-rest or shared-`&`, NEVER `&mut`" and name current field disposition concretely.

**Watch-item (non-blocking, NOT a defect).** The airtightness argument is restated ~4× (module doc 73-95, ClassCMut type doc 280-301, GovernanceClassCMut doc 349-365, test comment 1128-1146). Approaching the redundancy the worktree's own over-engineering guidance flags. If a future PR touches the file, consolidate canonical argument into module doc + cross-ref. Doc weight overall IS proportionate for a security-invariant boundary retiring a scanner.

See [[pr1744_pseudonym_routing_rehome]] for prior strong-private-field-enum pattern in same codebase.
