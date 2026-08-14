---
name: class-s-gate-selftest-redundancy
description: How fixture redundancy works in scripts/check-class-s-fail-closed.sh self-test; the fail-closed exemption is marker-source-agnostic
metadata:
  type: project
---

In `scripts/check-class-s-fail-closed.sh`, the self-test fixtures fall into two
kinds: HIT fixtures (a Class-S mutation that persists best-effort → MUST be
flagged) and fail-closed (FC) control fixtures (a mutation that persists
fail-closed → MUST NOT be flagged).

**Key fact for redundancy analysis:** the satisfaction logic
(`satisfied = fn_failclosed || (fn_name in helper) || (fn_name in classc)`) is
**marker-source-agnostic** — once any marker sets `fn_mutates=1`, the
fail-closed exemption applies identically regardless of *which* marker fired.

**Why:** a new FC control fixture that pairs a *specific* marker (e.g. a
`&mut.<field>` borrow companion) with a fail-closed persist is REDUNDANT iff
both already exist: (a) a HIT-side fixture using the same alias shape (proves
the marker fires), and (b) any pre-existing FC control (proves the exemption
honours `persist_state_fail_closed`). No regression uniquely trips the new
fixture. Verified empirically: breaking the FC exemption tripped 8 fixtures;
removing the borrow markers tripped only the HIT-side ones.

**How to apply:** when reviewing added self-test fixtures to this gate, a
mutate+fail-closed "control" is only non-vacuous if it exercises a code path
the marker-agnostic exemption logic does NOT already cover. Read-vs-write
precision controls (shared `&` borrow MUST NOT collapse) ARE non-vacuous —
they guard against `normalize_borrow` over-collapsing, a distinct regression.
See [[outcome_error_sketch divergent clones]] for the field-name
second-source-of-truth pattern (MUTATORS marker list vs normalize_borrow gsub
field set duplicate the six field names; consolidation blocked by POSIX awk
lacking variable-built gsub regexes).
