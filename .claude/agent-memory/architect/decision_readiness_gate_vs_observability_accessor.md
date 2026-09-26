---
name: decision-readiness-gate-vs-observability-accessor
description: A late-bound resource's COUNT accessor and the GATE that reads it are separable — delete the gate, keep the read-only count; the fix for an unsatisfiable readiness sample is unconditional scheduling + fail-closed + backoff, never re-sampling.
metadata:
  type: project
---

When a background arm depends on a resource that is bound LATER (a relay client, a
socket, any late-bound handle), do NOT gate the arm on a readiness sample. Schedule
it unconditionally, make the operation fail closed with a typed error while the
resource is absent, and let exponential backoff absorb the empty window. A later
bind then self-heals the arm with no reconstruction and no re-drive.

Both readiness-gate variants are REJECTED for SCP's relay republish arm
(SCP-RELAYRES-004 `details.rejected_design`):

- **One-shot latch** — sample at construction, `disable_relay()` if zero. Unfixable
  by construction: the sample necessarily runs before any client can exist, so the
  arm can never be true and, being latched, can never be woken.
- **Per-tick re-evaluation** — re-sample the count every tick. Also rejected: it
  retains a readiness gate the arm does not need. An interim PRD revision proposed
  this as "the root-cause fix"; it is not.

**The accessor and the gate are separable.** Deleting the latch does not mean
deleting the count. A read-only `bound_relay_count()` is legitimate observability
and downstream stories need it to write `== 1` / `== 3` bind assertions. Keep it,
document it as observability-only, and pin the constraint mechanically with a
bounded grep over the files that own scheduling — not an open-ended denylist.

**Why:** 36358fc17 deleted the latch; the PRD that governed it (rewritten in
4f6c247d3, one commit earlier) still specified it, so per the one-way artifact flow
a later agent executing the story would have regressed the fix. The reviewer who
said "delete the accessor too" and the one who said "006/007 need the count" were
both right about different things.

**How to apply:** When a review says "delete X" about a symbol used by both a
defective gate and legitimate observability, split the finding before acting. When
a story's AC asserts an ordering invariant ("bind precedes start"), check whether
the invariant still exists — an ordering requirement that only mattered because of
a removed gate is scar tissue. Record rejected variants in the story `details` so
the next agent does not reinvent the one that was already tried.

Related: [[finding-prd-code-desync-after-story-rewrite]],
[[finding_phantom_provenance_issue_number_is_the_prd]]
