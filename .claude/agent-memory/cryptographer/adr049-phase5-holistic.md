---
name: adr049-phase5-holistic
description: ADR-049 Phase 5 FINAL holistic crypto re-review @f2d4e7d0f (origin/main, complete actor-per-context refactor) — four fail-closed sites verified exhaustive; #2060 issue_mls_update sharpened to HIGH silent-PCS-desync
metadata:
  type: project
---

Worktree scp-wt-phase5 = origin/main @ f2d4e7d0f (Phase 4 docs tip; D7 PR-1..3 merged: 78814ba92, b9ea04f72, 96f9fa49d). Read-only holistic pass. All per-branch findings from [[adr049-d7-commit-fault-failclosed]] CONFIRMED in MERGED code (not just the review branch).

**CLEAN on probes 1,2,4,5.** ONE HIGH cross-cutting finding = #2060.

**Probe 1 — four-site set EXHAUSTIVE (verified by enumerating ALL commit producers).** Universe of epoch-advancing MLS-Commit producers:
- FAIL-CLOSED in-runtime (try_broadcast_commit→keep_broadcast_failure): execute_remove_member (gov_helpers:1442), leave_context (lifecycle_helpers:382), execute_rotate_content_keys (gov_helpers:2858), recovery_advance_epoch (trust_recovery_helpers:252). keep_broadcast_failure (gov_helpers:5589) = commit_class_s_keep + apply_broadcast_failure(commit_broadcast_borrows). GATES: check_commit_fault on SEND (messaging_helpers:913 via check_commit_fault_marker), GOVERNANCE (gov_helpers:5220), LIFECYCLE/leave (lifecycle_helpers:244), retry-drain (handlers/governance.rs:1097). Recovery re-entry does NOT gate on commit_fault → fail-close cannot deadlock recovery.
- BEST-EFFORT in-runtime BY DESIGN (coalesced, upward/neutral-auth, §9.9.4 heals): execute_add_member (gov_helpers:1268), execute_reset_member (gov_helpers:2490/2503). Correct — not gaps. gov_helpers:4386 + lifecycle_helpers:1267 are RedactedBytes result/WelcomeGenerated surfacing of the same add commit, not extra broadcasts.
- OUT-OF-LAYER best-effort = **#2060 issue_mls_update — the ONLY hole.**

**Probe 4 — sender-key/AAD/HPKE/zeroize UNCHANGED.** `git diff --name-only 78814ba92~1..f2d4e7d0f` touched ZERO files under crypto/sender/hpke/mls. Model stays as prior SOUND assessments: HPKE info+AAD bind (context_id, sender_did, epoch) (key_protocol.rs:360-361, build_hpke_info/build_hpke_aad); Zeroizing on DH secret / plaintext / key bytes (key_protocol.rs:348/363/375); ENCRYPTION-AUTHORITATIVE epoch = sender_key_store.epoch(ctx,did) high-water (provider.rs:1648/1707/2086), NOT the coalesced bookkeeping mls_epoch counter — so the coalesced counter bumps in recovery_advance_epoch step-4 and issue_mls_update CANNOT cause a crypto-layer epoch/sender-key desync. No regression possible from D7.

**Probe 5 — RecoveryBackend `#[async_trait(?Send)]` SOUND.** CompromiseRecoveryOrchestrator::execute_recovery (recovery.rs:492) is a single async fn, sequential `for` loop, awaits backend.mls_update inline — NO tokio::spawn, no concurrency, trait object never moved to another task. Actual crypto state lives actor-owned behind dispatch_trust_recovery mailbox (serialized). No unsound shared crypto state. recovery_advance_epoch PersistenceFailed surfaces as step-2 Err → context marked failed, steps 3/4 skipped (fail-loud, coherent).

**HIGH / #2060 — issue_mls_update silent post-compromise desync (SHARPENED from prior INFO).**
TWO distinct §9.12-step-2 (post-compromise MLS Update self-Commit) PRODUCTION paths exist; D7 PR-3 hardened ONE, left the other:
- Path A (orchestrator): ProductionRecoveryBackend::mls_update (recovery.rs:893) → TrustRecoveryCommand::RecoveryAdvanceEpoch → recovery_advance_epoch → FAIL-CLOSED. ✓
- Path B (reconnect driver, ADR-029 Phase 5, prophylactic PCS on EVERY reconnect): scp-ffi/common/src/reconnect.rs:439 mls_update → Supervisor::issue_mls_update (supervisor.rs:9550) → handle_issue_mls_update_actor (handlers/lifecycle.rs:681) → deps.crypto.advance_epoch() advances LOCAL MLS+sender-key epoch to N+1 UNCONDITIONALLY, returns commit_bytes out-of-layer. reconnect.rs:464 publishes commit BEST-EFFORT: transport.send fail → `tracing::warn!` + returns `Ok(true)` (mls_update_issued=true, state.mls_updated=true). NO pending_commits, NO commit_fault gate, NO retry. commit_bytes dropped at fn end. Comment says "can be re-broadcast" but NOTHING re-broadcasts the specific N→N+1 commit; a later reconnect produces a fresh N+1→N+2 commit peers-at-N cannot process.
FAILURE SCENARIO: transport blip during reconnect → local node at N+1 (fresh leaf, encrypts on new sender-key epoch), peers stranded at N, recovery reported SUCCESS. Peers keep using epoch N → compromised offline-window key retains group read access (PCS DEFEATED). Permanent desync; if any peer commits on N, MLS single-committer rule → group FORK/partition (local's N→N+1 incompatible with peer's N→N+1'). Same harm class D7 PR-3 fixed for Path A. Silent, no caller obligation.
Matches #2060 scope, BUT severity should be HIGH (silent PCS-defeat on the security-critical recovery path), not the "by-design caller-distributes / tracked separately" INFO framing. Recommend #2060 escalation. Fix NOT proposed here (per Phase-5 scope). Bounded to: reconnect-driver Phase 5 + a transport send failure at that instant.
