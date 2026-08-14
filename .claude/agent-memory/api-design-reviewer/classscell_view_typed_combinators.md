---
name: classscell-view-typed-combinators
description: ADR-049 §9 ClassSCell internal API — view-typed persistence combinators, ClassSMut/ClassCMut asymmetry, durability_diverged rename rationale
metadata:
  type: project
---

`crates/scp-runtime/src/context/actor/class_s.rs` — `ClassSCell` is the ADR-049 §9 Class-S
mutation boundary (`pub(crate)`). Owns `PerContextState`, `Deref` but deliberately NO `DerefMut`.
Mutation only via six combinators that persist-on-commit.

**The asymmetry (intentional, documented, load-bearing):**
- `ClassSMut` (fail-closed combinators) KEEPS `rest_mut` → whole `&mut PerContextState`. Justified
  because the bound combinator persists fail-closed, so any Class-S field reachable through it is
  covered.
- `ClassCMut` (best-effort + compensation closures — NO subsequent fail-closed persist) is
  field-granular: NO `rest_mut`/`governance_mut`; only `members_mut`/`receive_buffer_mut`/
  `role_state_mut`/`split_class_c` + `governance_class_c_mut -> GovernanceClassCMut`. A Class-S
  mutation from it is a COMPILE error by construction. Does NOT rely on field privatization (can't —
  handler + combinator modules are co-descendants of `context::actor`, no `pub(in PATH)` separates
  them). Growth path: add per-field Class-C accessors as handlers migrate (positive whitelist, bounded).

**Combinator set (six, NOT exhaustive by design):** `_keep`/`_restore`/`_compensating`/
`_keep_compensating`/`_then_append` (fail-closed) + `commit_class_c_best_effort`. Two recorded
outlier shapes handled at migration time (intra-Class-S keep-one/restore-another split; append-then-
persist of unchanged state). `state_mut` is a TEMPORARY escape hatch deleted in the terminal step.

**durability_diverged rename (commit 467f20222):** `AppendOutcomeError.mutated` → `durability_diverged`.
**Why:** the SAME `context::actor` module has `Outcome.mutated: bool` (outcome.rs) meaning "handler
changed in-memory state" (drives dirty/persist). `AppendOutcomeError.mutated` meant something DIFFERENT
— "durable may diverge from returned in-memory" — true even on the re-persist-fail arm where memory
WAS rolled back. Two sibling `mutated` fields, near-opposite meaning. Rename resolves the collision +
self-documents. Verdict: APPROVED, merge-ready (rename complete — `durability_diverged` only in class_s.rs).

**How to apply:** when reviewing later steps of this migration (field privatization, token threading
`ClassSCommitToken` per PR3, deleting `state_mut`, handlers migrating off `state_mut`), the asymmetry
and the field-granular whitelist are the invariants to preserve. New `ClassCMut` accessors must
provably contain no Class-S sub-struct.
