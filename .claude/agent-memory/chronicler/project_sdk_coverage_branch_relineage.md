---
name: project-sdk-coverage-branch-relineage
description: fix/sdk-coverage-fail-closed-and-parity was RE-DONE on a fresh lineage; an earlier abandoned HEAD's 5 lessons never merged but their knowledge was re-applied
metadata:
  type: project
---

The SDK-coverage fail-closed + parity work exists in TWO lineages.

**Fact:** Prior session HEAD `8c0713499` created five `.docs/lessons/` files
(fail-closed-gate-escape-hatch-must-be-verified, suffix-matcher-becomes-bypass-when-gate-fails-closed,
mock-test-must-not-invert-real-bridge-behavior, fromhandle-must-surface-all-protocol-significant-fields,
cross-sdk-method-naming-matches-canonical-sdk). That commit is NOT an ancestor of the
shipped branch HEAD `fa4730e04` and is NOT on origin/main — it was abandoned. Those five
lesson FILES do not exist on the shipped lineage.

**Why it doesn't matter for correctness:** the underlying knowledge was re-applied in code
on the new lineage even though it wasn't re-documented as five separate lessons —
identity-lifecycle.test.ts now asserts `migrated.did).not.toBe(identity.did)` (the inverted-mock
bug is fixed); rotationEventJson is surfaced in TS Identity + all 4 Rust FFI bridges; PERM-3030
re-raise has Python/TS parity with cross-ref comments; discover→discoverContexts naming resolved.
The shipped branch consolidates into TWO lessons instead: `coverage-gates-must-fail-closed.md`
and `identity-migration-cite-9.12-not-3.2.1.md`.

**How to apply:** When a branch's prior lessons can't be found, check whether the recorded prior
HEAD is actually an ancestor (`git merge-base --is-ancestor`). A re-done lineage abandons the old
lesson files; verify the KNOWLEDGE survived in code rather than assuming the lessons regressed.
The two consolidated lessons are accurate but coarser-grained than the abandoned five — the
mock-inversion and fromHandle-field-dropping learnings are now only implicit in code, not
documented as standalone evergreen lessons. See [project_branch_sdk_coverage_fail_closed.md].
