---
name: eventlog-1847-best-effort-audit
description: PR #1847 (fix/eventtype-audit-1847) adds audit leaves but ships secondary ones best-effort — audit-erasure + Merkle-root divergence risk
metadata:
  type: project
---

# Issue #1847 event-log audit leaves shipped best-effort

Branch `fix/eventtype-audit-1847` adds missing EventType audit leaves but makes the
secondary/companion append best-effort (warn-and-suppress) while the primary is fail-closed.

**Why:** stated goal is audit completeness (auditors verify state changes from the Merkle
log). Best-effort undermines that goal AND risks §9.9.3 convergence (member whose append
hits transient IO error derives a different event_log_merkle_root than one whose append
succeeded).

**How to apply:** when reviewing #1847-style audit-leaf additions, a best-effort append to a
convergent Merkle log is a correctness hazard, not just audit hygiene. Flag it.

Confirmed sites (HEAD ~737206f84):
- `recovery.rs::revoke_ucans` (commit 34e07e64e): TokenRevoked appended best-effort BEFORE
  the revocation notification dispatch (seq 1); step Ok/Err decided only by dispatch →
  revocation takes effect while TokenRevoked leaf silently absent. HIGH.
- `broadcast_helpers.rs::block_broadcast_subscriber` (commit 2eace6675): MemberBlocked
  fail-closed (.await?) but companion KeyEpochAdvance best-effort → forward-secrecy proof droppable.
- `governance_helpers.rs::execute_reconfigure_governance` (working-tree diff / helper
  `append_deadlock_recovery_event_best_effort` @2930): GovernanceReconfigured fail-closed
  (empty payload) but the removed-signer DIDs + justification ride ONLY the best-effort
  GovernanceDeadlockRecovery payload → who-was-removed/why is droppable. MEDIUM.

Controls that HOLD: `execute_remove_member` emits MemberLeft fail-closed; leaves are
Ed25519-signed + verified in tree::append (epoch counters non-secret → no replay/forge).
