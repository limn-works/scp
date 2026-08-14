---
name: pr2234-kea-sort-determinism
description: PR#2234 governance KeyEpochAdvance Merkle-determinism sort + fail-closed KEA + inline counter; crypto SOUND across 3 review passes
metadata:
  type: project
---

# PR#2234 fix/rotate-content-keys-review-followup (grew to 7 commits; tip 2fd43bee9)

## ROUND-3 (final pass, tip 2fd43bee9) — VERDICT SOUND, no blocker
Branch evolved past round-1 single-commit. Key delta: the two CONVERGENT-governance KEA paths (execute_revoke ban, execute_rotate_content_keys) converted best-effort→FAIL-CLOSED (map_err→? propagation) per ADR-011 — this RESOLVES the round-1 LOW PRESENCE-axis gap for governance triggers. Counter reworked best-effort-coalesced→INLINE +=1 per durable leaf (mirrors execute_reconfigure_governance).
- Fail-closed coherence PROVEN: handler returns `Outcome::err_mutated` (outcome.rs:81, mutated:true) on Err ⇒ actor PERSISTS the inline-bumped Class-C counter even when surfacing the error ⇒ counter == durable-leaf-count on BOTH success and error paths (no §9.9.3 drift). Inline bump is NECESSARY now: a post-loop coalesced bump would be skipped entirely by an early `?` mid-loop, under-counting durable leaves.
- Bump placement: each `+=1` is strictly AFTER a successful durable append; a failing append/encode `?`-returns BEFORE its bump ⇒ never counts a non-durable leaf. Verified execute_revoke (985/1013), execute_rotate_content_keys (3177/3211), reconfigure (3315/3352 = +=2 for 2 leaves, fixes old-main single-+=1 UNDER-count).
- No replay / no epoch-skip: epochs monotonic (author.epoch += 1, new_epoch≥1), leaf payload (old,new) unique per advance, retries advance further (N+2) ⇒ distinct leaves, no collision, never decrease.
- Residual (LOW, pre-existing ADR-049 Decision-7): epoch persist (fail-closed Class-S closure) is NON-ATOMIC with leaf append (async, after closure). On leaf failure a replica ends: advanced-epoch durable + partial leaves + SURFACED error + coherent counter. Fail-closed does NOT achieve absolute cross-replica leaf convergence — it converts SILENT divergence into an observable error (best achievable given async-append constraint). ADR-011 "convergent leaf" is thus approximated, not absolutely guaranteed.
- Fail-closed line is PRINCIPLED: drawn at convergent GOVERNANCE triggers only. block_broadcast_subscriber (per-author UNILATERAL block, §5.14.8) + unsubscribe_broadcast (VOLUNTARY, §5.14.8 auth-upward-safe) stay best-effort by design — matches prior deferred PRESENCE-axis TODO, documented in-code.
- Test seam seed_broadcast_author: #[cfg(feature="testing")] on ALL layers (class_s, commands, handlers/broadcast, supervisor), gated, never in prod/FFI. Enables real multi-author fan-out counter test.
- Sort invariants ENFORCED not asserted: rotate_all_author_keys sorts internally (mod.rs:~1739 sort_unstable_by author_did) + pre-validate checked_add all-or-nothing +1; governance_ban_subscriber + unsubscribe both sort before return. author_did = unique HashMap key ⇒ no ties ⇒ sort_unstable fully deterministic. Tests assert WITHOUT re-sorting.

## ROUND-1 (commit 39a19e90c) — historical
VERDICT: crypto core SOUND, no blocker. All findings LOW/INFO.

Two-dot-diff trap: `git diff main...branch` against LOCAL main = enormous (stale merge-base). Use `git log origin/main..origin/branch` → single commit; read files via `git show 39a19e90c:path` (working tree was on a different stale branch).

## What the PR does (§5.14.8/§5.14.10, #1847)
- Bug1 (HIGH): `governance_ban_subscriber` now `sort_unstable_by(a.author_did.cmp(b.author_did))` on `rotated_authors` — mirrors sort already in `rotate_all_author_keys` (#2218). Fixes Merkle leaf-ordering non-determinism (HashMap iter order randomized per-process → divergent root on replay, §9.9.3).
- Bug2 (MEDIUM): `execute_reconfigure_governance` split checkpoint_events_since bump into two `+=1`, one after EACH durable leaf append (GovernanceReconfigured, GovernanceDeadlockRecovery). Prior single end-bump under-counted by 1 if 2nd append fails. Aligns in-mem counter to durable-leaf count.
- Doc: BroadcastKeyEpochAdvance.timestamp rustdoc "relay-path only, dead on governance path"; TODO(spec) at both KEA sites.

## Soundness confirmed (independent trace)
- SORT: author_did = HashMap keys ⇒ unique, no ties ⇒ sort_unstable fully determined; String::cmp total byte-lexicographic platform/locale-independent. Runtime CONSUMES sorted output: execute_revoke rotated_authors=r.rotated_authors (gov_helpers:934); execute_rotate_content_keys key_advances from sorted advances (gov_helpers:3104). KEA leaves appended in loop-iteration order ⇒ leaf order == sort. Leaves distinct per author because author_did bound as leaf actor_did (payload = {old_epoch,new_epoch} only).
- old_epoch=new_epoch.saturating_sub(1): SOUND by construction. BOTH rotate paths increment epoch by EXACTLY 1 under pre-validate `checked_add(1)` over ALL authors (all-or-nothing, fail-closed CryptoFailed). new_epoch≥1 post-inc ⇒ saturating_sub exact, floor unreachable.
- Overflow guard: pre-validate ALL before mutate ANY; test proves no partial mutation.
- ms `timestamp` field: NEVER in any hash. KeyEpochAdvancePayload (scp-event-log/payload.rs:177) = old/new epoch only; leaf timestamp = timestamp_secs (committer-assigned, deterministic). rotate_all_author_keys(timestamp_secs.saturating_mul(1000)) embeds ms but gov path ignores it. Crypto-neutral.
- execute_add_member KP validate (#2218, lifecycle_helpers.rs:840): single validate_key_package(bytes, hardened clock) → credential_did from SAME authenticated leaf → `member_did != validated.credential_did` reject, BEFORE any state mutation. No TOCTOU. SOUND.

## Findings (all LOW/INFO)
- LOW: best-effort KEA leaf emission (gov_helpers:988 ban, :3206 rotate) = residual Merkle-convergence gap on PRESENCE axis. Sort fixes ordering non-determinism (flagged HIGH) but a failed append is warn+skip+excluded from kea_success_count ⇒ different leaf SET across replicas ⇒ same divergence class. Pre-existing, explicitly flagged `TODO(spec): §2033 vs §5.14.10/ADR-011 tension`. Correctly deferred upward (spec decision, artifact-flow). Kept LOW: local durable writes non-adversarial, per-node counter/log internally consistent, epoch advance itself fail-closed in snapshot (only audit leaf best-effort). Internal tension worth naming: same reasoning that made the sort HIGH applies to best-effort skip.
- LOW: broadcast.rs:132 rustdoc overstates ms field "consumed on per-author block relay path" — rotate_broadcast_key has NO non-test production caller (scp-node/projection.rs + scp-testing tests only, all discard `_advance`). Field is future-carrier, dead everywhere in prod now.
- LOW: new integration test rotate_content_keys_broadcast_kea_governance_integration is SINGLE-author ⇒ doesn't exercise sort. Ordering guaranteed only by 2 unit tests in broadcast/mod.rs (3 authors reverse-inserted, assert sorted no-resort) — genuine but catch regression only PROBABILISTICALLY (HashMap randomization).
- INFO: spec §5.14.8 new clause "mandatory…MUST advance" conflates epoch-advance (fail-closed, done) with leaf emission (best-effort) = the TODO tension.
