---
name: pr2209-6132-stream-cap-split
description: PR #2209 split SCP-OUTLET-6132 (stream-cap-exhausted, WithBackoff) off 6131 — code wiring COMPLETE, one stale scp-testing doc-comment gap
metadata:
  type: project
---

PR #2209 (branch fix/outlet-2209-6131-overload @8797f0bb0, stacked on #2196 tip e7507d936). Split `execution.stream-cap-exhausted` (node-level concurrent-pump ceiling) off shared `CODE_EXECUTION_CREDIT` (6131, Immediate) into its own `CODE_EXECUTION_STREAM_CAP` = SCP-OUTLET-6132 with WithBackoff{1s..30s}, because retry policy is keyed on the CODE and a saturated node must back off not busy-spin.

Verdict: functionally COMPLETE. All wiring verified end-to-end: error_codes.rs const+rustdoc, ALL_CODES[15], error_code_to_class(Execution), error_code_to_default_slug, error_code_to_retry_policy(WithBackoff), reserved-list (6132 removed, 6134/6136-6139 still free), new pinning test `stream_cap_exhausted_is_split_with_backoff_retry` real+passing (18/18); lib.rs re-export; dispatch.rs sole emitter `OpenStreamRejection::StreamCapExhausted::error_code()`→6132 (grep confirms no other emitter still on 6131); credit-exhausted+stream-gap correctly STILL share 6131/Immediate (dispatch.rs:4589 unchanged); spec §5.4.4 table+gaps+retry-guidance, §5.4.5 ceiling clause, §25.21 two-traps note all corrected. check-error-codes.sh PASS (4081 occ), cargo test error_codes 18/18.

**Sole gap (artifact divergence, non-functional):** `crates/scp-testing/tests/integration/outlet_stream_vectors_common.rs:72-76` rustdoc on `CODE_STREAM_GAP` still claims, citing §25.21 "two error-code traps", that 6131 is "SHARED by execution.stream-gap, execution.credit-exhausted, AND execution.stream-cap-exhausted" — that third slug is now 6132. The constant `CODE_STREAM_GAP = CODE_EXECUTION_CREDIT` is still correct (stream-gap path). Only the comment is phantom provenance now (contradicts the §25.21 text this same PR rewrote). File was NOT in the #2209 diff. Sweep it in the same PR.

LESSON: when a PR corrects a spec note (§25.21) that has a code-comment MIRROR elsewhere, grep the exact claim across all crates — scp-testing had a duplicate of the same three-way-share sentence.
