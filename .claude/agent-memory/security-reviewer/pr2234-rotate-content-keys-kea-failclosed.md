---
name: pr2234-rotate-content-keys-kea-failclosed
description: PR#2234 KeyEpochAdvance best-effort→fail-closed conversion + Class-C counter inline-bump correctness (ADR-011 convergent-trigger classification)
metadata:
  type: project
---

# PR#2234 fix/rotate-content-keys-review-followup — final sweep PASS (2026-08-03)

Final double-zero confirmation (pass 6). ZERO findings. Reviewed diff origin/main...origin/fix/rotate-content-keys-review-followup.

**Core semantic change — ADR-011 convergent-trigger classification governs KEA leaf failure mode:**
- CONVERGENT governance triggers (execute_revoke governance-ban, execute_rotate_content_keys) → KeyEpochAdvance leaves are FAIL-CLOSED. On main these were best-effort (warn+continue, kea_success_count). Now each KEA append uses `?`/map_err(EventLogFailed) → error propagates. Rationale: all members process the same commit; best-effort would diverge Merkle roots. governance_helpers.rs execute_revoke ~979, execute_rotate_content_keys ~3171.
- NON-CONVERGENT single-origin triggers (per-author unilateral block in block_broadcast_subscriber, voluntary unsubscribe) → KEA leaf remains BEST-EFFORT (warn on fail). MemberBlocked leaf itself IS fail-closed (uses `?`). broadcast_helpers.rs ~725.

**Class-C counter (`checkpoint_events_since`) inline-bump pattern (§9.9.3 determinism):**
- Counter is `&mut u64` borrowed into actor-owned in-memory state (class_s.rs:2014/2127); mutated in place, NO transactional rollback. On fail-closed Err path the counter reflects exactly the leaves durably appended before the error. Correct by construction.
- Converted from coalesced `+= 1 + kea_success_count` to inline `+= 1` per durable leaf (mirrors execute_reconfigure_governance).
- BUGFIX: execute_reconfigure_governance on main under-counted — appended 2 leaves (GovernanceReconfigured + GovernanceDeadlockRecovery) but bumped only +1. Now +1 after each = +2. Fixed.

**Test seam seed_broadcast_author — fully gated `#[cfg(feature="testing")]` at ALL layers:** supervisor pub method (~14492), BroadcastCommand::SeedBroadcastAuthor variant (commands.rs:1901), handler handle_seed_broadcast_author (handlers/broadcast.rs:645) + dispatch arm (142), class_s seed_broadcast_author (2666), both dispatch match arms (supervisor 5793, 15298). Never reachable from production/FFI.

**Comment accuracy verified:** BroadcastKeyEpochAdvance.timestamp comment corrected to "Currently unconsumed" — verified: only `advance.timestamp` reads are in tests; messaging_helpers.rs:3131 `inner.timestamp` is a different struct. Spec §5.14.8/§5.14.10 references real; spec 05-contexts.md §2028 gained fail-closed RotateContentKeys clause consistent with code.

**Determinism fix:** rotated_authors/key_rotations now sort_unstable_by author_did before returning (broadcast/mod.rs ~846, ~1655) — HashMap iteration was randomized per-process → divergent Merkle roots. Tests assert sort WITHOUT re-sorting.
