---
name: eventlog-convergence-slices
description: Adversarial review of the 3 event-log §9.9.3 convergence slices (#1857/#1858/#1859) — clamp removal, consequence window anchor, commit-broadcast demotion
metadata:
  type: project
---

# Event-log convergence slices (PRs #1857 slice1, #1858 slice2, #1859 slice3)

Base commit 1f1ea7cd2 (Phase-2 event-log substrate swap onto scp_event_log RFC-6962).
All three close §9.9.3 equivocation false-positives (honest members diverging at equal event count).

## Slice 1 (#1857) — demote CommitBroadcasted* off canonical Merkle log — SOUND
- `try_broadcast_commit_or_enqueue` made infallible; removed durable appends of
  CommitBroadcasted/Pending/Succeeded/Failed + their checkpoint_events_since increments.
- Root: per-committer transport-retry outcomes are non-convergent (receiver has no record of sender's retries) → permanent exclusion, not interim.
- Verified: no durable consumer reads them; checkpoint_events_since invariant (== durable-leaf count) preserved in lockstep; all 5 callers updated; pruning.rs classification table entries are harmless dead config (closed EventType set kept intentionally). Real convergence test + negative control in eventlog_convergence.rs.

## Slice 2 (#1858) — WASM consumes creation_timestamp_secs verbatim (clamp removed) — SOUND
- WASM manager.rs:5942 dropped `.min(now_secs())` clamp; now matches native verbatim consumption.
- Signature verified BEFORE struct build: deserialize_and_verify_envelope → verify_snapshot_signature (verify_strict, exporter_did==creator_did binding). Field is inside signed JCS preimage.
- Sole consumer = TTL upper bound (creation+ttl). Future-dating grants creator nothing (they already sign ttl; max_ttl policy caps the DURATION not the absolute deadline, and is on the invitation auto-accept path, not import). No new vector opened.
- handle_ttl_expiry guards creation!=0 (empty→now fallback). Native convergent_ttl_deadline_secs does NOT guard creation==0 → native(0+ttl=1970 immediate) vs WASM(now+ttl) divergence for a deliberately creator-zeroed signed snapshot in mixed membership. Minor convergence asymmetry, not forgery (pre-release, creator self-harm).
- STALE COMMENT (defect, not vuln): lifecycle_helpers.rs:1751 says observed_at re-pin "mirrors the creation_timestamp_secs re-pin above" — creation_timestamp_secs is NO LONGER re-pinned on import (consumed verbatim at 1807). Comment is now factually wrong.

## Slice 3 (#1859) — convergent consequence evidence-window anchor — MOSTLY SOUND, disclosure INCOMPLETE
- evaluate_consequence_rules gains convergent_now param; window anchors on convergent_now (max Source-1 log ts) for convergent triggers (WarningCount/Custom), local `now` for non-convergent (MessageVelocity/ToolRateExceeded). Wired through all call sites native+WASM identically.
- Empty-log `now` fallback is SOUND: Source-2 buffer contributes ONLY MessageSent (governance types fall to _=>continue in merge_consequence_events), so zero convergent evidence can match the fallback window. Disclosure claim accurate.
- is_convergent_trigger gates durable leaf (enforce_one_triggered). Sound.
- **FINDING (disclosure incompleteness):** SECURITY doc-comment in governance_logic.rs documents the false-POSITIVE direction (malicious quorum future-dates governance action to WIDEN window + mint ConsequenceTriggered against victim) but OMITS the false-NEGATIVE/SUPPRESSION direction: future-dating a single governance leaf pushes convergent_now=max(ts) forward, sliding window_start=convergent_now-window past genuine older evidence → EVADES a deserved consequence against the attacker. Same root (unbounded committer-assigned timestamps + max-anchored window), same admin/quorum gate, opposite effect. finalize_governance_action emits the action to durable log BEFORE reading convergent_now, so the attacker's own future-dated action shifts the very evaluation. Disclosure should enumerate both directions.
