---
name: review-classcmut-field-granular-398a89c66
description: CLEAN security review of commit 398a89c66 (branch refactor/classs-type-guard) — ClassCMut made field-granular to close best-effort Class-S &mut bypass (ADR-049 §9)
metadata:
  type: project
---

# ClassCMut field-granular — close best-effort Class-S bypass (398a89c66) — CLEAN

Worktree `.claude/worktrees/classs-guard`, branch `refactor/classs-type-guard`, HEAD `398a89c66`. Commit touches EXACTLY ONE file: `crates/scp-runtime/src/context/actor/class_s.rs` (+241/-68). `state.rs` (where bearer types live) UNCHANGED by this commit (verified `git show ~1:state.rs` vs `:state.rs` byte-diff empty).

**What changed:** The best-effort/compensation view `ClassCMut` (which runs with NO subsequent fail-closed persist) previously handed out `rest_mut()→&mut PerContextState` and `governance_mut()→&mut GovernanceState` — both `&mut` PATHS reaching a Class-S-containing struct (`state.class_s`, `state.governance.class_s`). A handler could mutate Class-S there with no fail-closed persist, re-opening a replay/re-spend/re-grant window. Field privatization CANNOT close this (combinator module `context::actor::class_s` and handler modules `context::actor::handlers::*` are co-descendants of `context::actor`; no `pub(in PATH)` separates them). Fix: replace bare-`&mut` accessors with field-granular Class-C accessors + new `GovernanceClassCMut` sub-view, so no `&mut` path to any Class-S-containing struct exists from `ClassCMut` — a Class-S mutation there is now a COMPILE error by construction.

**Why CLEAN (all checks pass):**
- `ClassCMut` `&mut` accessors return ONLY: `members_mut→&mut HashSet<DID>`, `receive_buffer_mut→&mut ReceiveBuffer`, `role_state_mut→&mut ContextRoleState`, `governance_class_c_mut→GovernanceClassCMut`. VERIFIED against `PerContextState` def (actor/state.rs:1015): the ONLY Class-S-containing fields are `class_s`(:1260 ClassSState) and `governance`(:1115). None of the four returned types is/contains them. `ReceiveBuffer`/`ContextRoleState`/`MembershipState` are scp-protocol types — cannot contain scp-runtime Class-S structs (no dep cycle).
- `GovernanceClassCMut` `&mut` accessors return ONLY: `velocity_tracker`, `budget_tracker`, `cooldown_until`(HashMap<usize,u64>), `economic_policy`(Option<EconomicPolicy>). VERIFIED against `GovernanceState` def (state.rs:1044): the ONLY Class-S field is `class_s`(:1156 GovernanceClassS). None of the four is it.
- `split_class_c→ClassCSplit`: governance wrapped in GovernanceClassCMut (was `&mut GovernanceState`); other fields role_state/membership(&)/receive_buffer/checkpoint_events_since(&mut u64) all non-Class-S.
- Both `Deref` impls (ClassCMut→&PerContextState, GovernanceClassCMut→&GovernanceState) are READ-ONLY (reads can't violate §9). No DerefMut anywhere (only doc mentions).
- `ClassSMut` side sound: all 5 `ClassSMut::new` sites (617/679/751/836/919) each followed by `persist_state_fail_closed`. The two `ClassCMut::new` compensation sites (756/840) are in the persist-FAILURE `Err` arm (compensation only).
- Behaviour-neutral: all new combinators `#[allow(dead_code)]`, no production callers; crate builds clean; NO panic/unwrap/expect added on production path (only in `mod tests`). 21 module unit tests pass.
- Gate `scripts/check-class-s-fail-closed.sh` BYTE-IDENTICAL to origin/main (`git diff origin/main` empty); self-test exit 0; real scan exit 0 ("PASSED").
- §9.4.3 bearer barrier intact: no Clone/Serialize/Debug derive added in diff; bearer types live in state.rs which this commit does not touch.

NOTE: `git diff origin/main..398a89c66 --stat` shows a HUGE unrelated delta (184 files) — branch base predates many merges (stale-base, the known two-dot-diff artifact). The commit ITSELF is single-file; per-commit and gate-script diffs are authoritative and clean.

NO findings (any severity). Zero actionable.
