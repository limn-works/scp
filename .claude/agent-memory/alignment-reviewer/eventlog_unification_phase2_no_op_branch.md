---
name: eventlog-unification-phase2-no-op-branch
description: Phase-2 event-log unification review where branch HEAD was an ANCESTOR of origin/main (no unique commits) — 3-dot diff masked an empty 2-dot delta; the claimed runtime cutover never landed
metadata:
  type: project
---

Review of `feat/eventlog-unification-phase2-substrate` @ HEAD `964f186519` (2026-06-18). Orchestrator claimed: runtime cut over to RFC 6962 `tree::root` + typed `EventType`, two ADR exclusions (MessageReceived, EquivocationDetected) removed, export-root chain-head→tree::root migration; clippy clean + nextest 9412/9412; review `git diff origin/main...HEAD`.

**Finding: the branch contained NO unique work.** `git log origin/main..HEAD` was EMPTY; `git merge-base --is-ancestor HEAD origin/main` = YES. HEAD = origin/main MINUS one commit (`f55ff949e` test-gating). The 2-dot `git diff origin/main HEAD` was ONLY the reverse of that one commit (3 test files: supervisor.rs, crypto/mls/provider.rs, scpid.rs gaining `#[cfg(feature="testing")]`). Nothing event-log related.

**Why the task looked plausible:** orchestrator specified the THREE-DOT diff `origin/main...HEAD` (vs merge-base `b321248e`). That surfaced ~46 files / 1600 LOC of event-log unification — but those were commits already on **main** (`e6493a2c8` ADR-011 amendment, `1c0ccbc7d` EventType 76-variant expansion, `bba12a3a3` payload structs), NOT this branch's contribution. 3-dot diff attributes merge-base→HEAD delta, which includes everything that landed on main since the (stale) merge base.

**Runtime cutover did NOT happen** on HEAD OR main: `git grep -c "SCP-EXPORT-ENTRY|compute_entry_hash|EventLogEntry" <ref> -- crates/scp-runtime/src` = **98 on BOTH**. The canonical `scp_event_log::EventType` taxonomy + payload encoder landed (#1827/#1825), but the runtime `MerkleEventLogProvider` still uses free-form string events + `SCP-EXPORT-ENTRY:` hash-CHAIN + chain-head-as-merkle_root. Req #1 grep (must be empty) returns 98.

**Only real WIP:** ONE uncommitted line in working tree (`lifecycle_helpers.rs` test fixture `"MemberJoined"`→`EventType::MemberJoined`) — not committed, not in reviewed diff. Suggests the cutover was about to start but no substrate was actually written/committed.

Verdict: CHANGES-NEEDED (nothing to review; reviewed the wrong diff).

REUSABLE LESSON: When a task cites `git diff A...B` (three-dot) on a feature branch, ALWAYS cross-check `git log A..B` (unique commits) and `git diff A B` (two-dot). A stale merge base makes three-dot diffs attribute already-merged upstream work to the branch. If `git merge-base --is-ancestor HEAD origin/main` is YES, the branch has ZERO net-new content regardless of how large the 3-dot diff looks. This is the same class as the existing CRITICAL-rule "always verify two-dot diff before merge."
