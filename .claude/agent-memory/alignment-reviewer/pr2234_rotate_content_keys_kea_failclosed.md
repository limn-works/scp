---
name: pr2234-rotate-content-keys-kea-failclosed
description: PR #2234 final double-zero (pass 6) — ADR-011 convergent-leaf fail-closed for governance KEA leaves; ALIGNED
metadata:
  type: project
---

# PR #2234 `fix/rotate-content-keys-review-followup` — pass-6 double-zero confirm (2026-08-03) — PASS / ALIGNED

Reviewed diff `origin/main...origin/fix/rotate-content-keys-review-followup` (10 files, +959/-101). Working tree was detached HEAD (NOT the branch) — inspected branch via `git show origin/<branch>:<file>`, not the working copy. Pass 5 (chronicler/completionist/bug-catcher) was clean; this pass confirms alignment. 0 CRITICAL/HIGH/MEDIUM.

**Core alignment thesis (verified against ADR-011 amendment in phase-2.md:900-996 + §9.9.3 in 09-security-model.md:793):** ADR-011 rule = "a derived record is automatic *and* convergent iff its trigger input is convergent." §9.9.3 equivocation detection = Merkle-root equality at equal event count.
- Governance ban (`execute_revoke`) + `RotateContentKeys` (`execute_rotate_content_keys`) are MLS-commit-ordered convergent triggers → their per-author KEA leaves converted best-effort → **fail-closed** (`.map_err(EventLogFailed)?`). Correct: best-effort would let one member append + another drop → divergent root.
- Per-author unilateral block (`block_broadcast_subscriber`) is single-origin NON-convergent → KEA leaf correctly KEPT best-effort, with explicit ADR-011 rationale comment. MemberBlocked itself stays fail-closed (confidentiality).

**Sort (§9.9.3 Merkle determinism):** all THREE fan-out KEA sources sort `author_did` before returning: broadcast/mod.rs:852 (unsubscribe key_rotations), :1663 (governance_ban rotated_authors), :1742 (rotate_all_author_keys advances, unconditional pre-return). Block path emits 1 KEA (no sort needed). HashMap iter is per-process random — sort eliminates divergence.

**Counter (§9.9.3 checkpoint-position; invariant at governance_logic.rs:156 "counter = true durable-leaf count"):** inline `+=1` per durable leaf replaces coalesced `+=1+kea_success_count`. Fail-closed `?` short-circuits so counter only counts durable leaves even on mid-loop failure. Bug-2 fix: block path OLD code bumped only +1 total while appending up-to-2 leaves (under-count) → now +1 MemberBlocked +1 KEA-if-durable. Verified NO double-count: execute_reconfigure_governance has exactly 2 bumps (lines 89,126) for 2 leaves, test asserts delta==2.

**Spec §5.14.8 additions accurate + consistent:** new RotateContentKeys paragraph ("KEA leaves after durable ContentKeysRotated leaf") matches code order; ban-path + step-4 gained "fail-closed per ADR-011"; per-author block steps 1-4 correctly LEFT without fail-closed (mirrors non-convergent code). Artifact-flow correct (ADR→spec→code).

**`BroadcastKeyEpochAdvance.timestamp` doc "currently unconsumed" = FACTUALLY VERIFIED:** grep shows field read only in tests; struct NOT embedded in any transport/relay message enum; the earlier "relay-message consumer on block path" attribution was genuinely phantom. Field still populated + serde-round-trip-tested (wire contract locked). Honest correction.

**Test seam `seed_broadcast_author`:** `#[cfg(feature="testing")]` at every layer (ClassCMut, BroadcastCommand, handler, Supervisor); mirrors `seed_peer_pseudonym`; supervisor non-actor arm returns ContextNotRegistered; unreachable from FFI. Legitimate — lets single-node tests build multi-author broadcast ctx (bridge key-resolver only sees one actor's custody).

**LOW observations (NOT introduced by PR, out of scope):** spec §5.14.8 step-2 "Publishes KeyEpochAdvance notification (relay message)" has no distinct wire-message impl — epoch bump surfaced via pull-based key-request model; pre-existing. #2243/#2244/#2245 are external tracking issues, NOT in-code stubs/TODOs (no `// Stub` markers in diff) — no in-scope gap.

GOTCHA for next pass: working tree is detached HEAD with unrelated dirty files — always `git show origin/<branch>:<file>`, never read working copy.
