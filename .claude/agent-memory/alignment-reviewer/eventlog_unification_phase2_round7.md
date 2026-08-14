---
name: eventlog-unification-phase2-round7
description: Round-7 fidelity review of event-log unification Phase 2 at 82f8eaf74 — comment-only stale-comment sweep, APPROVE
metadata:
  type: project
---

Round-7 review of `feat/eventlog-unification-phase2-substrate` at HEAD `82f8eaf74` (base `1c0ccbc7d`). Verdict APPROVE, 0 findings.

Commit `82f8eaf74` ("docs(event-log): correct comments falsified by the substrate swap") is a comment-only sweep across 5 files: commands.rs, governance_logic.rs, queries_helpers.rs, state.rs, reconnect_sync.rs (integration test). +52/-72.

**Why:** Phase-2 substrate swap renamed `EventLogEntry`→`scp_event_log::Event` (string event-names→typed EventType) and REMOVED the durable `MessageReceived`/`EquivocationDetected` Merkle appends. Several comments still described the old hash-chain model.

**How to apply:** This closed BOTH round-6 informational findings: (1) the commands.rs:406-408 `CompareRemoteCheckpoint` doc falsely claiming a durable EquivocationDetected append, AND (2) the state.rs `event_log_merkle_root` stale-comment sibling (was "hash-chain head / pruning-tolerant / front-truncation not neutral"; now "RFC 6962 tree::root over ALL entries / prefix-truncation rejected outright").

Verified each rewritten claim against live code:
- `record_equivocation_if_fresh` (queries_helpers.rs:868-929) does exactly one `emit_event_into(receive_buffer,...)`, NO durable append; per-sender `(count, root)` set is the SOLE dedup (count-advance backstop gone).
- `verify_merkle_chain` (export_import.rs:471-507) replays via `append_unsigned_event` (validates sequence vs running count + prev_hash vs prior leaf/genesis); `tree::root` over full sequence. Tests `verify_merkle_chain_rejects_prefix_truncated_log` (hard error) + `verify_merkle_chain_rejects_suffix_truncated_log` (different root caught by signed-root constant-time compare) back the comment.
- governance_logic.rs `event_log_entries_for_consequences` (642-704) typed-EventType→coarse-bucket projection: governance/consequence variants→GovernanceAction, Tool*→ToolInvoked, payload pass-through. Matches rewritten doc.

Hard checks (all pass): every added line is comment/doc/blank (grep -vE comment patterns → none); zero issue-refs `#NNNN` on added lines; zero `.docs/` artifacts modified across whole branch range (artifact-flow invariant holds — substrate consumed ADR-011-amendment/ADR-050/§9.9.3/§23.16.8 without mutating them).

KNOWN/OUT-OF-SCOPE confirmed not raised: pre-existing `#1594`/`#636` refs in unchanged context lines; dead app_sandbox AppBound formatters.

Reusable pattern: when a substrate swap removes a durable side-effect (the EquivocationDetected append) AND that side-effect was load-bearing in a test's RATIONALE ("suppression via count-advance"), the test ASSERTION stays valid (exactly-once) but its EXPLANATORY COMMENT goes stale — verify the comment's mechanism (dedup set vs count-advance) against the post-swap code, not just that the assert still passes.
