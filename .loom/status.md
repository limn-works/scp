# Loom Status

## Failing Tests
None — full workspace test suite green (2841+ tests pass, 0 failures).

## Uncommitted Changes
None — all changes committed.

## Fixed This Iteration
N/A — no prior failures.

## Tests Added / Updated
- Lane A added 7 wire format compliance tests (serde rename verification)
- Lane A updated dedup TTL test for 24hr window
- Sender key tests updated: all 26 `serde_json::from_slice` sites migrated to `rmp_serde::from_slice`
- Legacy serde defaults test rewritten to use helper struct approach (MessagePack binary incompatible with serde_json::Value)

## Work Summary

### Phase 0: COMPLETE — 8 spec fix lanes
All 8 spec lanes merged to `feat/achieve-production-readiness`:

| Lane | Issue(s) | Status | Commit |
|------|----------|--------|--------|
| S-B | #380 (UCAN nonce format) | Done | aa92b92 |
| S-C | #378 (Protocol versioning §13) | Done | 23c4b32 |
| S-E | #372 (Identity private state) | Done | f8bbc6e |
| S-F | CRYPTO-03/04/18 (HPKE + nonce) | Done | e6ecaa3 |
| S-G | #381 (Sync anti-replay) | Done | 8c7ae18 |
| S-H | #374 (Context nesting eligibility) | Done | 5c79ab7 |
| S-I | #379 (§15 erasure clarification) | Done | aeaf5f9 |
| S-A, S-D | Pre-existing | Already done before this iteration |

### Phase 1: PARTIAL — 8 of ~15 issues resolved
Code fixes committed directly to `feat/achieve-production-readiness`:

| Issue | Description | Status | Commit |
|-------|------------|--------|--------|
| #345 | serde rename (ref_id→ref, event_type→type) | Done | af4192c |
| #313 | Dedup cache TTL 1hr→24hr | Done | 2444c9a |
| #348 | ProtocolStore positional→named MessagePack | Done | d174211 |
| #354 | Missing conflict detection pairs | Done | 38fe1cf |
| #351 | deny_unknown_fields on InnerEnvelope | Done | 26e2222 |
| #312 | HPKE domain separator alignment | Done | 53ed083 |
| #346 | Sender key JSON→MessagePack (4 sites) + future timestamp | Partial (2 of 4 findings) | 7f341b8 |

### Phase 1: REMAINING

| Issue | Description | Blocked By |
|-------|------------|------------|
| #346 findings 2-3 | BlockNotification signing_key_id, nonce serde_bytes | — |
| #290 | Signaling message type binding | — |
| #353 | block_subscriber per-author scope | — |
| #352 | BroadcastEnvelope missing 5 fields | — |
| #355 | UCAN parse optimization in projection | — |
| #291 | Stub comment format compliance | — |
| #350 | Replace stub RoleDefinition/ToolRegistration | — |
| #301 | Wire real metrics to dev API | — |

### Phases 2-12: NOT STARTED
See `.docs/prod-readiness-exec-plan.md` for the full 12-phase plan.

## Review Outcomes
Review skipped — no subagent-produced production code exceeded 50 lines in this iteration. Lane A subagent completed but was a standalone merge. All other work was done directly by the orchestrator.
