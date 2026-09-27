---
name: decision-readiness-gate-vs-observability-accessor
description: A late-bound resource's count accessor and the gate that reads it are separable — delete the gate, keep the read-only count; schedule unconditionally, fail closed, and back off instead of sampling readiness.
metadata:
  type: project
---

When a background arm depends on a resource that is bound later (a relay client, a socket,
any late-bound handle), do not gate the arm on a readiness sample. Schedule it
unconditionally, make the operation fail closed with a typed error while the resource is
absent, and let exponential backoff absorb the empty window. A later bind then heals the arm
with no reconstruction.

Both readiness-gate variants were rejected for the relay republish arm
(SCP-RELAYRES-004 `details.rejected_design`):

- **One-shot latch** — sample at construction and disable the arm if the count is zero. The
  sample runs before any client can exist, so the arm never activates and, being latched,
  never wakes.
- **Per-tick re-evaluation** — re-sample every tick. It keeps a readiness gate the arm does
  not need.

**The accessor and the gate are separable.** A read-only `bound_relay_count()` is legitimate
observability that downstream stories use in bind assertions. Keep it and document it as
observability-only.

**How to apply:** when a review says "delete X" about a symbol that both a defective gate and
legitimate observability use, split the finding before acting. When a story's acceptance
criterion asserts an ordering invariant ("bind precedes start"), check whether the invariant
mattered only because of a removed gate. Record rejected variants in the story's `details` so
the next agent does not retry them.
