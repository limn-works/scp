---
name: pr2209-outlet-6132-split
description: Alignment review of PR #2209 splitting SCP-OUTLET-6132 (stream-cap-exhausted) off overloaded 6131 — split sound, one stale spec count word
metadata:
  type: project
---

# PR #2209 fix/outlet-2209-6131-overload @ 8797f0bb0 (stacked on #2196 tip e7507d936) — ALIGNED except one spec-count defect

Delta = 5 files: 05-contexts.md, 25-test-vectors.md, error_codes.rs, scp-protocol/lib.rs, dispatch.rs. Closes #2209 (pre-existing taxonomy collision flagged by inquisitor during SCP-OUT-048 review): `SCP-OUTLET-6131` was assigned to TWO conditions — `execution.stream-gap` (receiver gap) AND `execution.stream-cap-exhausted` (node-level concurrent-pump ceiling rejection at OPEN).

**SPLIT JUSTIFIED (not over-engineering).** The retry policy is keyed on CODE (`error_code_to_retry_policy(code)`, no slug-keyed variant exists), so two slugs sharing a code MUST share a retry policy. stream-cap-exhausted needs `WithBackoff` (node saturated → immediate retry busy-spins), but the other two 6131 slugs need `Immediate`. Genuine, forced mismatch — the code-keyed design makes it impossible to fix with a slug alone. Splitting EXACTLY ONE slug is the minimal correct fix: credit-exhausted (framework refreshes credits) + stream-gap (cancel-and-rerun) both = Immediate and correctly stay co-located on 6131, slug-distinguished — exactly what the compact-code taxonomy (§5.4.4) intends. WithBackoff 1s..30s matches sibling back-pressure bands credit-stall 6133 + transport 6160. Emitter fully consistent: dispatch.rs StreamCapExhausted → code 6132 + slug unchanged.

**ARTIFACT-FLOW CORRECT.** Not code-informing-spec. #2209 (tracked issue) authorizes the taxonomy correction; spec §5.4.4 table + §5.4.5 prose updated to define 6132, code follows. 6132 was a reserved gap now allocated; reserved-gap example refs updated 6132→6134 in all 4 sites (spec, error_codes doc x2, test). ALL_CODES 14→15, reserved test drops 6132. 6132 does NOT foreclose #2197 (lazy-open orphan/double-reserve — proposes no specific code numbers; reserved tail 6134/6136-6139/6180-6199 remain). §25 vectors: sequence_gap stays 6131 (correct, unaffected); no KAT pins stream-cap (it's an open-time rejection, not in the 7-vector streaming set).

**FINDING (spec-internal + spec-vs-code count divergence, LOW/MEDIUM, non-blocking design but should fix per completeness norms):** `.docs/specs/05-contexts.md:314` still reads "Only **fourteen** codes are allocated across the 6100..6199 sub-block" — but the PR added a 15th code (6132) to the very table below it (now 15 rows), and the code was updated (error_codes.rs:12 "roughly **fifteen**", `ALL_CODES: [&str; 15]`, doc "allocates (15)"). The spec prose count word was missed. Fix: §5.4.4:314 "fourteen" → "fifteen". Both remain within the compact target [12,18], so no design impact — purely a stale enumerated count that an auditor cross-checking spec-count-vs-code would flag.
