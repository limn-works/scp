---
name: ADR-049 commit 12 — helpers vs logic split rule
description: Project context for the ADR-049 actor-per-context refactor (commit 12) module-naming convention
type: project
---

After ADR-049 commit 12 (HEAD `7c3137565` on `refactor/actor-per-context`), the `crates/scp-runtime/src/context/manager/` directory was deleted and its bodies hoisted into split modules:

- `*_helpers.rs` — free functions taking `supervisor: &Supervisor` (the previous inherent-method receivers).
- `*_logic.rs` — pure free functions on `&PerContextState` / values, no `Supervisor` dependency.

**Why:** `*_logic.rs` files were created in commit `7a36df265` to host wasm-portable / dependency-light pieces of the legacy manager. The split is principled: `_logic` has zero `Supervisor` references; `_helpers` is the supervisor-bound surface. Three logic files exist: `economy_logic.rs`, `governance_logic.rs`, `lifecycle_logic.rs`.

**How to apply:** When adding to this layer, route Supervisor-touching functions to `*_helpers.rs` and pure value-shape functions to `*_logic.rs`. Note that `*_helpers.rs` *also* contains some `&PerContextState` helpers (governance_helpers in particular has 5 of them), so the split isn't perfectly clean — when in doubt, prefer `*_helpers.rs` since it's the bigger module.
