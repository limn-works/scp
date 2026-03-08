# Loom Status

## Failing Tests
<<<<<<< HEAD
None. All 3423+ tests pass (excluding pre-existing scp-ffi-napi linker error).
=======
None — full workspace test suite green (5228 tests, 0 failures). Clippy clean. NAPI linkage pre-existing (needs Node.js napi symbols).
>>>>>>> feat/spec-code-alignment

## Uncommitted Changes
None on the main worktree.

## Fixed This Iteration
<<<<<<< HEAD
- 36+ compilation errors from SCP-272/273 subagent merge (trait methods outside block, KeyResolver calling convention, signature serialization, missing ContextSnapshot fields)
- 6 checkpoint cosignature test failures (fake signatures replaced with real Ed25519 signatures, mock_resolver extended)
- Conflict detection wiring into vote submission path (was in subagent working copy but not properly merged)
- sha2::Sha256 import and GovernanceError-to-String conversion in cherry-picked code

## Tests Added / Updated
- 49 governance integration tests (SCP-274) — governance_integration.rs
- 15 content access governance tests (SCP-CAC-007) — manager.rs
- 6 broadcast wiring tests (SCP-CAC-008) — manager.rs
- Fixed 6 checkpoint cosignature tests with real signatures

## Work Summary

### Wave 1: SCP-CAC-007 + SCP-274 (parallel)
- **SCP-CAC-007** (content access governance actions) — subagent completed, committed d2163551, merged ddb5bbae
- **SCP-274** (governance integration tests) — subagent completed, committed d0e0cf69, merged 796ba7a8

### Wave 2: SCP-CAC-009 + SCP-CAC-010 (parallel)
Both subagents hit usage limits before starting implementation.
- **SCP-CAC-009** (content access integration test) — failed, needs re-dispatch
- **SCP-CAC-010** (governance content access integration test) — failed, needs re-dispatch

### Compilation Fix Commits
- c23f0601 — fix(governance): resolve compilation errors from SCP-272/273 merge (27 files, 551 insertions)
- c5a3165f — feat(governance): wire conflict detection into vote submission path
- 09b058cf — re-applied conflict detection wiring after revert/merge cycle

### Merge Strategy Notes
SCP-CAC-007 had 28 merge conflicts in manager.rs due to overlapping changes with SCP-272 conflict detection wiring. Resolved by:
1. Reverting the conflict detection wiring commit
2. Accepting CAC-007's version (which included the most comprehensive changes)
3. Cherry-picking the conflict detection wiring back on top
4. Resolving the single remaining conflict (keeping both presence-only check and freeze check)

## Review Outcomes
Review deferred — Phase 6 not yet complete (CAC-009, CAC-010 remaining).

## Phase Status Summary
- **Phases 0-5**: COMPLETE
- **Phase 6**: SCP-CAC-001–008 COMPLETE. Remaining: SCP-CAC-009, SCP-CAC-010
- **Phase 7**: SCP-267–274 COMPLETE
- **Phase 8**: Lanes C, E done. Lanes A, B, D remaining.
- **Issue #398**: NOT STARTED

## Next Iteration

**Re-dispatch (all dependencies met):**
- SCP-CAC-009 (Phase 6 — content access integration test)
- SCP-CAC-010 (Phase 6 — governance content access integration test)

**After Phase 6 completes:**
- Run review cycle on Phase 6 + Phase 7 combined
- Begin Phase 8: SCP-227 (Lane A), #334 (Lane B), #316/#323 (Lane D)

**After Phase 8:**
- Issue #398 (envelope version field)
=======
- #395: HPKE sender key wrapping missing context binding — added context_id/sender_did/epoch to info + AAD
- #396: BroadcastEnvelope missing top-level nonce and expanded AAD — added nonce field, expanded AAD with context_id + sequence
- Formatting: cargo fmt applied across workspace (21 files)
- scp-node too_many_lines clippy error from cargo fmt expansion — reverted to HEAD (original formatting was within limit)

## Tests Added / Updated
- **#395**: 3 new tests (hpke_rejects_wrong_context_id, hpke_rejects_wrong_sender_did, hpke_rejects_wrong_epoch) + updated 2 existing call sites
- **#396**: 2 new tests (open_with_tampered_context_id_fails, open_with_tampered_sequence_fails) + nonce separation tests

## Work Summary

### Issues Completed (from prior subagent runs, merged this iteration)

| Issue | Description | Commit | Tests |
|-------|-------------|--------|-------|
| #395 | HPKE sender key wrapping context binding (info + AAD) | 1fe28a47 | 3 new + 2 updated |
| #396 | BroadcastEnvelope top-level nonce + expanded AAD | b4b9161c | 2 new |
| #397 | ResetRequest nonce + anti-replay validation | d6146a16 (prior iteration) | existing |

### Spec-Code Alignment Status
- **#395**: COMPLETE
- **#396**: COMPLETE
- **#397**: COMPLETE (merged prior iteration)
- **#398**: NOT STARTED (envelope version field — assigned to different loom)

## Next Iteration
Spec-Code Alignment scope (#395, #396, #397) is COMPLETE. No further work in this worktree.
>>>>>>> feat/spec-code-alignment
