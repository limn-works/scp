# Loom Status

## Failing Tests
None — full workspace test suite green (5228 tests, 0 failures). Clippy clean. NAPI linkage pre-existing (needs Node.js napi symbols).

## Uncommitted Changes
None — all changes committed. Working tree clean (except .loom/).

## Fixed This Iteration
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
