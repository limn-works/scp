---
name: classs-compiletime-guard-governance-hole
description: Class-S fail-closed-persist compile-time guard (ClassSCell/ClassSMut/ClassCMut) end-state analysis — governance.class_s field-privatization is a CLASS-A residual due to module topology
metadata:
  type: project
---

# Class-S compile-time guard (class_s.rs) — end-state adversarial verdict

File: `crates/scp-runtime/src/context/actor/class_s.rs` (ADR-049 §9). `ClassSCell` Deref-no-DerefMut; mutation only via `commit_class_s_*` (fail-closed) / `commit_best_effort` (Class-C, best-effort). Views: `ClassSMut` (exposes `class_s_mut`/`governance_class_s_mut`), `ClassCMut` (no Class-S mutator; `rest_mut`/`governance_mut`/`split_class_c`).

## Module topology (the crux)
- `PerContextState { class_s: ClassSState, governance: GovernanceState }` — in `crate::context::actor::state`
- `GovernanceState { class_s: GovernanceClassS }` — in `crate::context::state` (DIFFERENT subtree)
- Views (`ClassSMut`/`ClassCMut`) — in `crate::context::actor::class_s`
- Helper handlers (`governance_helpers`, `tools_helpers`, `lifecycle_logic`, `broadcast_helpers`, `manager_methods`, `trust_recovery_helpers`, `supervisor`) — siblings under `crate::context`

## rustc-verified results (probes in /tmp, end-state = private parent .class_s field)
1. `ClassCMut::rest_mut()->&mut PerContextState` and `governance_mut()->&mut GovernanceState`: once parent `.class_s` is private, a handler in another module CANNOT name `p.class_s` / `g.class_s` (E0616). `&mut` reborrow does NOT defeat field privacy. BLOCKED.
2. `ClassSMut::rest_mut()` same — can't reach `class_s` without `class_s_mut` (no bypass). BLOCKED.
3. **ASYMMETRY (the finding):**
   - `PerContextState.class_s` CAN be scoped `pub(in crate::context::actor)` → views reach it, sibling helpers under `context` (lifecycle_helpers etc.) BLOCKED. SOUND.
   - `GovernanceState.class_s` is in `context::state`; `pub(in X)` requires X to be an ANCESTOR of `context::state`. The tightest ancestor that also covers the views' subtree `context::actor::class_s` is `crate::context` itself. `pub(in crate::context)` LEAKS to EVERY helper module under context — including `governance_helpers.rs` which TODAY does raw `state.governance.class_s.threshold_signers.push(...)` with no combinator. **Field privatization does NOT make a raw governance Class-S mutation a compile error.** CLASS-A residual.
4. Inner-field privatization (make `GovernanceClassS.threshold_value` etc. private to `context::state`) DOES block sibling helpers — but ALSO breaks legit handler closures (`view.governance_class_s_mut().threshold_value = 7`, real at class_s.rs:1026). Requires adding typed mutator methods on GovernanceClassS/ClassSState. Larger change than "just privatize fields."

## Verdict
- Actor-state Class-S field (`PerContextState.class_s`): soundly gated in end state.
- Governance Class-S field (`GovernanceState.class_s`): NOT soundly gated by field privatization alone — module split means tightest viable visibility (`pub(in crate::context)`) still admits all sibling helper modules. FIX = move GovernanceState/GovernanceClassS (or just class_s) into the `actor` subtree, OR privatize INNER fields + add typed mutators, OR wrap in a privatizing newtype whose mutators are the only write path.
- PR1-era expected residuals (NOT class-A): `state_mut` escape hatch, `into_inner` detach (deferred to PR6).
- AsyncFnOnce combinators (`*_compensating`, `*_then_append`): views borrow `&mut self.state`, future held only across immediate `.await`; no escape-the-borrow soundness issue. compensate gets ClassCMut (post-restore, can't re-touch Class-S). Sound.
