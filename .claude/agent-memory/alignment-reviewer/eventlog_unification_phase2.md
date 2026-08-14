---
name: eventlog-unification-phase2
description: ADR-011 event-log unification Phase 2 substrate (scp-runtime onto scp_event_log::EventLog) round-2/3/4 fidelity reviews — APPROVED
metadata:
  type: project
---

# Event-Log Unification Phase 2 — substrate migration (ADR-011 amendment + ADR-050 + §9.9.3/§23.16.8)

Branch `feat/eventlog-unification-phase2-substrate`. Diff base `1c0ccbc7d`. Migrates scp-runtime ContextManager event log from the legacy hash-CHAIN (export-snapshot `SCP-EXPORT-ENTRY:` format, ~18 untyped string event names) onto the protocol's RFC 6962 `scp_event_log::EventLog` (tree::root, typed `EventType` leaves). See [[finding_runtime_eventlog_not_rfc6962]] equivalent in root project memory.

**Why:** unblocks #1540 native↔WASM equivocation fixtures + #1535 catch-up consistency-proof; Alec chose FULL unification (2026-06-17).

## Round 3 @ HEAD `526c50eb4` (2026-06-18) — APPROVE, 0 findings
Verified the two round-2 minor findings FIXED + complete:
- (a) export_import.rs:628-648 truncation comment rewritten (commit `7a5d6c425`) to RFC 6962 tree::root-over-ALL-entries / truncation-CLOSED (not merely detected). Comment now matches code: `verify_merkle_chain` (export_import.rs:471) replays every entry through `scp_event_log::tree::append_unsigned_event` (validates per-leaf sequence + prev_hash chain link) then `tree::root`; constant-time `ct_eq` vs SIGNED `snapshot.event_log_merkle_root` (step 5) + envelope defense-in-depth (step 6). Backed by named tests `verify_merkle_chain_rejects_{prefix,suffix}_truncated_log`.
- (b) `#710` issue-refs stripped from `crates/scp-runtime/src` (commit `63b45c114`) — `git grep "#710" crates/scp-runtime/src` EMPTY. Also corrected stale "event name"→"event type" prose (deliver_plaintext_or_announcement now returns `Option<scp_event_log::EventType>`, not String).

Fidelity confirmed:
- **typed-only**: EventType enum (crates/scp-event-log/src/lib.rs) has NO `Other(`/`Custom(`/`Unknown(` string escape hatch; deliver_plaintext_or_announcement returns `Option<EventType>`.
- **two exclusions**: MessageReceived + EquivocationDetected emitted ONLY as in-memory `ContextEvent` bus alerts (receive-buffer/SDK observation), return `None` → NO Merkle leaf. messaging_helpers.rs:358-388 has the canonical exclusion w/ correct §9.9.3 equivocation rationale (receiver-minted sender-unauthenticated leaf would diverge honest receivers' roots).
- **tree::root export binding**: signed root is RFC 6962 tree::root over all entries (ADR-050); importer cannot suppress consequences by truncating (full signed leaf set is the only set that verifies).
- **no upstream artifact wrongly modified**: `git diff --stat 1c0ccbc7d..HEAD -- .docs` EMPTY.
- **no new issue-refs on added lines**: the only `+#636` lines are residue of stripping `#710` from pre-existing `"#636, #710"` lines (#636 pre-existed at diff base on those exact lines). `#710` survivors in `.docs/specs/17-persistence-and-storage.md:147,227` + `CHANGELOG.md:305` are PRE-EXISTING (Phase 1, not on this PR's added lines) and LEGITIMATE — no-issue-refs rule ([[feedback_no_issue_refs_in_code]]) is scoped to source/comments/test-names, NOT specs/CHANGELOG.

NOTE (pre-existing, out-of-scope): scp-runtime/src is saturated w/ pre-existing #NNNN refs (#636 #1606 #1530 #363 #1474 #645 etc.) violating the no-issue-refs rule crate-wide. Far outside this PR; this PR stripped the one it was asked to (#710) and added none.

HEAD test commits both sound/non-weakening: `2e409a734` adds `buffered_drain_call_site_runs_governance_for_application_message` regression locking the REAL drain call-site (prevents reintroduction of `if let Some(event_name)` gate bug; asserts ConsequenceTriggered appended + NO MessageSent leaf per §9.9.3); `526c50eb4` de-flakes 3 KeyPackage supervisor poison tests (current-thread→2-worker multi-thread; logic unchanged). Protocol-crate dead-branch removal `234017ed8` drops legacy null-terminated-UTF8 + custom_key JSON decode fallbacks w/ zero producers/tests under typed substrate (runtime emits exactly 2 encodings: positional MessagePack target_did-first + JSON target_did).

Orchestrator ran gates GREEN. Verdict APPROVE.

## Round 4 @ HEAD `526c50eb4` (2026-06-18) — APPROVE, 0 findings (independent re-confirm; HEAD unchanged from round 3)
Fresh independent pass against all 6 confirmation criteria — all TRUE, same HEAD as round 3 (no new commits). Re-verified: (1) `EventLogEntry` struct fully DELETED repo-wide (no definition, no src ref, no test ref); FFI common `event_type_label()` keeps filter+surfaced string in lock-step. (2) the two exclusion append sites gone; residual refs are ContextEvent variants/docs only. (3) export-root=tree::root w/ prefix-trunc(seq-check)+suffix-trunc(root-mismatch) rejected, legit-prune accepted; §23.16.8 spec text matches impl verbatim. (4) §7.3.7 matcher decodes target_did from positional-rmp + JSON; 4 Consequence* variants typed-emitted; recursive-blindspot preserved; dead legacy branches removed (pre-release OK). (5) `signature: Vec::new()` deferral matches WASM unsigned-event model + lesson `unsigned-event-mcp-bridge.md`; signed-snapshot-root is the real §23.16.8 boundary. (6) zero `.docs/` in diff; only `+#636` lines are #710-stripped reworded pre-existing lines (net reduction); #303 on unmodified line out of scope.
ONE latent finding for team follow-up (NOT this PR's regression, NOT blocking): `crates/scp-runtime/tests/test_vectors.rs:1200` still lists `"SCP-EXPORT-ENTRY:"` in `domain_separators_are_all_unique()` — last touched `e1c4f666e` (unrelated), not in this diff; the separator is now likely dead post-unification. Worth a future uniqueness-list prune. Verdict APPROVE.
