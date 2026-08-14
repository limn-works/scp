---
name: eventlog-phase2-pr1850
description: Black-hat review of PR #1850 (event-log Phase-2 substrate swap) — convergent timestamps, TTL deadlines, WASM/native parity, import re-pin, saga appends, MessageSent. No new exploitable defects found.
metadata:
  type: project
---

# PR #1850 event-log Phase-2 substrate swap — black-hat review (clean)

Diff range `4cad781e5..HEAD` (HEAD 12e6bd180). Reviewed read-only in worktree.

**Verdict: no NEW exploitable defect introduced by this diff.** Attack surfaces probed:

## Notification-window backdating (§19) — RESISTS
- `is_effective(cur) = cur >= effective_at.max(observed_at + PERIOD)` (state.rs:279,352).
- `effective_at` is proposer-controlled (backdatable) but only LOWERS first term;
  floor `observed_at + PERIOD` survives. `observed_at` = local commit clock.
- Untrusted IMPORT path re-pins `observed_at = now` (lifecycle_helpers.rs:1762,1770).
  Trusted RESTORE keeps verbatim (self-respawn = own local storage, different trust boundary).
  Cannot route a malicious snapshot through RESTORE (reads own persisted state).

## Convergent committer-assigned saga timestamps — RESISTS
- Caller `CrossContextToolInvoked` leaf uses `receipt.timestamp_ms/1000` (saga.rs:1645,1501).
- Receipt VERIFIED before commit_a via `verify_commit_b_receipt` (supervisor.rs:6584,6603)
  against target's Active Signing Key the FSM holds.
- Co-resident SDK seam: A and B same node; "malicious B" = node compromise (no new boundary).
- All three leaves (caller ToolInvoked, target ToolInvoked, divergence marker) draw the
  single B-staged `recorded_timestamp_ms` → convergent by construction.

## divergence_marker_plan asserted_timestamp_ms fallback (supervisor.rs:7125) — DEAD, not exploitable
- `ctx.prepared_b.map_or(ctx.asserted_timestamp_ms, |b| b.recorded_timestamp_ms)`.
- Fallback to caller-asserted ts is UNREACHABLE: plan requires `committed_b_tool_invoked_event_id`
  (=Some only after Commit-B), which implies Prepare-B ran → prepared_b populated.
  Recovery NeedsRepair arm uses `recover_needs_repair_entry` (cache rehydrate), not this plan.

## WASM↔native leaf byte-parity — RESISTS
- Governance proposal/vote leaves now EMPTY payload both sides (WASM manager.rs b"";
  native append_context_event → EventPayload::default()). proposal_id moved to buffer-only ContextEvent.
- Tags 76/77 distinct, injective; tag 59 retired (tree.rs). Conformance bijection test updated.
- consequence.rs sequence numbering fix (idx→buffer_events_accepted) is evidence-only metadata,
  behavior-preserving, FIXES a cross-impl gap divergence.

## MessageSent — NOT changed by this diff
- MessageSent durable-leaf exclusion (M12) PREDATES base 4cad781e5. This diff only touches
  a "75→77" test comment + snapshot builders. No repudiation surface introduced here.

## Class-S saga persistence (crash-recovery) — sound
- All snapshot builders route saga fields through shared helpers (messaging_helpers.rs).
  ContextSnapshot fields non-Option → compiler enforces completeness.
- import/create start fresh; same-node RESTORE rehydrates; cross-node import DROPS
  (foreign saga state has no authority — documented).
- xctx_nonce_dedup rehydrated with SAGA_NONCE_DEDUP_TTL_SECS on restore (BLACK-XCTX-01 addressed).
  Empty on import → replay bounded by freshness skew-tolerance ts check (validate_freshness saga.rs:1170).
  Forward obligation for untrusted cross-node transport documented (not shipped).
- velocity rollback_one_at (antispam.rs) token-independent, keyed by record.actor_did+recorded_at_secs,
  bounded by single consumed CallerReservationRecord per saga. No over-refund/velocity-suppression vector.

## serde_util — sound
- serde_nonce_16 rejects non-16-byte; bounded_bytes 512KiB cap; canonical_hash uses
  RawBytes(fixed)+VarBytes(len-prefixed) → no splice ambiguity.
