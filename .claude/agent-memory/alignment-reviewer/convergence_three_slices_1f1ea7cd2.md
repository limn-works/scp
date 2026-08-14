---
name: convergence-three-slices-1f1ea7cd2
description: Review of 3 §9.9.3 convergence-fix slices (#1857 commit-broadcast off log, #1858 convergent ContextSnapshot creation-time, #1859 convergent consequence window) off base 1f1ea7cd2
metadata:
  type: project
---

Three convergence-fix branches off slices-base `1f1ea7cd2` (worktrees under `.claude/worktrees/sliceN-*`), reviewed 2026-06-21. All three close a real §9.9.3 false-positive-equivocation source (equal event_count + different Merkle root = forged history; every leaf field MUST be convergent). All ALIGNED.

**Why:** these implement the ADR-011-amendment convergence rule "a derived record is automatic AND convergent iff its trigger input is convergent." Slice 1 writes the amendment; Slices 2/3 consume contracts (`is_convergent_trigger`, signed-snapshot preimage) it/base already define.

**How to apply:** if re-reviewing or merging these, note the cross-slice overlap on 5 files (governance.rs, governance_helpers.rs, lifecycle_helpers.rs, messaging_helpers.rs, state.rs) — disjoint edit regions, merge sequentially not in parallel.

## Slice 1 #1857 (HEAD 6687ecaae) — ALIGNED, 0 findings
phase-2.md adds exclusion sub-category 3 (per-committer broadcast-retry: CommitBroadcasted/Pending/Succeeded/Failed). Correctly traces §9.9.3 (committer-appends/receiver-doesn't), distinguishes from category-2 (NO convergent order even under ADR-051 — transport-send has no cross-member referent → PERMANENT not interim). Closed-set preserved: CommitBroadcasted stays tag 57, total EventType = **77** unchanged. Code matches prose: all append_context_event(CommitBroadcast*) removed; try_broadcast_commit_or_enqueue now infallible + dropped unused actor_did (all 5 callers updated); first-attempt success genuinely not surfaced (Ok(())=>{}). eventlog_convergence.rs adds positive + non-vacuous negative control.

## Slice 2 #1858 (HEAD 18d8d5a49) — ALIGNED, 2 stale doc-comments (non-blocking)
Adds creation_timestamp_secs to ContextSnapshot; create path binds ONE deps.clock.now_secs() for both ContextCreated leaf + state (lifecycle_helpers.rs:1159/1167/1212); import/restore now arm CONVERGENT TTL (anchor_deadline_to_creation=true). Security verified: field is inside signed JCS preimage SHA-256(domain||scope-tag||JCS(snapshot)); validate_export_for_import enforces exporter_did==creator_did + verify_strict BEFORE consumption → native verbatim (no clamp) sound; upper-bound creation+ttl fail-safe reasoning correct. WASM honest: keeps .min(now()) clamp, labels DTO NOT byte-parity, has convergence+fallback tests.
STALE COMMENTS (fix inline): ttl_close_helpers.rs:249-250 (start_ttl_timer deadline_override doc still cites restore/import as the None/local-clock example) + supervisor/handle.rs:654-656 (dispatch_start_ttl_timer says "false for restore/import — arm relative to local clock" — both now pass true). These describe the exact PRE-FIX behavior removed. NOT stale: lifecycle_helpers.rs:1150-1158/349/863 + governance_helpers.rs:3964/4273 "forward step under ADR-051" — those are about cross-member LEAF REPLICATION (receive-side append dormant), genuinely future, and explicitly carve out that TTL-deadline use is already convergent.

## Slice 3 #1859 (HEAD edfa17e57) — ALIGNED, 0 findings
evaluate_consequence_rules gains convergent_now param: convergent triggers (WarningCount/Custom) anchor window on convergent_now, non-convergent (MessageVelocity/ToolRateExceeded) on local now. is_convergent_trigger is PRE-EXISTING at base 1f1ea7cd2 (categorization matches amendment word-for-word) — slice CONSUMES, doesn't redefine → artifact flow intact. Anchor = max(Source-1 log ts) BEFORE buffer merge w/ now-fallback (never from merged set w/ Source-2 local-clock estimates), computed in event_log_entries_for_consequences (now returns (events, convergent_now)). ALL eval call sites thread real convergent_now (governance sweep, finalize proposer+target, tool reserve/settle, messaging send/recv); participation-only paths discard via _convergent_now. WASM mirrors anchor exactly (byte-parity). TriggeredConsequence +PartialEq/Eq for convergence assert. Positive + non-vacuity control tests.

LESSON: for a "convergent annotation" fix, the load-bearing checks are (1) the convergent value is inside the SIGNED preimage before verbatim consumption, (2) the anchor derives from Source-1-only NOT the merged buffer set, (3) every caller threads the real value not local now(), (4) WASM either byte-parity-converges OR honestly documents its clamp+non-parity. All four held. Doc-staleness is the recurring residue — grep the OLD behavior description ("arm relative to local clock", "does not yet carry") crate-wide after flipping a bool.
