---
name: classs-type-guard-review
description: Review of refactor/classs-type-guard (class_s.rs field-granular ClassCMut/GovernanceClassCMut views) — CLEAN
metadata:
  type: project
---

# class_s.rs field-granular view refactor — CLEAN (2026-06-22)

Branch `refactor/classs-type-guard` @ec108ea5f. Reviewed `crates/scp-runtime/src/context/actor/class_s.rs` (2404 lines).

**Why:** ClassCMut/GovernanceClassCMut converted from whole-`&mut` to FIELD-GRANULAR refs (per-field `&mut` Class-C + shared `&` to class_s/membership/next_proposal_seq). Airtightness claim: no whole `&mut PerContextState`/`&mut GovernanceState`/`&mut ClassSState`/`&mut GovernanceClassS` held anywhere on best-effort/compensation views, so a Class-S mutation there is a COMPILE error.

**How to apply:** No defects found. Verified:
- Both destructure constructors (`ClassCMut::new`, `GovernanceClassCMut::new`) bind right field→type; `class_s`/`governance.class_s` correctly fall to `..` or shared `&`. SAFETY INVARIANT comments factually accurate.
- `next_proposal_seq` shared-`&` trick: destructuring `&mut GovernanceState` binds `&mut u64`, coerces to `&'a u64` at field-init (mut→shared ref coercion). Disjoint from the four `&mut` (distinct struct fields). Compiles clean.
- `split_class_c` 5 simultaneous disjoint borrows (governance reborrow + 4 distinct fields) — sound.
- `*_restore` snapshot is TOTAL: ClassSState has exactly 6 fields, all in ClassSStateSnapshot; GovernanceClassS 4 fields all in GovernanceClassSSnapshot; restores write all back via literal/assignment.
- ClassCMut/GovernanceClassCMut expose NO whole-bucket `*_mut`; only `class_s()` read-only `&`. class_s_mut/governance_class_s_mut/rest_mut exist ONLY on ClassSMut (fail-closed view).
- Exposed Class-C types (ReceiveBuffer, ContextRoleState, MembershipState) carry no ClassSState/GovernanceClassS transitively.
- async-borrow soundness: `external` (X) owned local, held across `&mut self` restore then passed to compensate — fine.
- `durability_diverged` 4 arms correct.
- 28 tests pass; gate self-test + scan PASS (exit 0); clippy clean; build clean.

CLAUDE.md crate-root `#![forbid(unsafe_code)]` backstops the only type-system escape (ptr cast on shared class_s ref).
