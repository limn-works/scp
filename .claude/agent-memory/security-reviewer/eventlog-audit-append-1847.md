---
name: eventlog-audit-append-1847
description: Event-log append security model for issue #1847 (MemberBlocked/KeyEpochAdvance/TokenRevoked/GovernanceDeadlockRecovery/MediaSession) — event log is audit anchor not enforcement gate
metadata:
  type: project
---

# Event-log audit-append security model (issue #1847, branch fix/eventtype-audit-1847)

Reviewed 5 commits + uncommitted governance_helpers.rs change 2026-07-16. Verdict: SOUND, no CRIT/HIGH/MEDIUM; 3 LOW + 1 obs.

**Load-bearing invariant (VERIFIED):** Every security-relevant state mutation is made durable BEFORE any event-log leaf append. The event log is an AUDIT ANCHOR, NOT an enforcement gate → it is NOT a SPOF for any access-control decision.
- Block path (broadcast_helpers.rs block_broadcast_subscriber): epoch advance + block-list insert committed via `commit_class_s_keep(...).await?` FIRST; then MemberBlocked leaf (fail-closed `.await?`), then KeyEpochAdvance leaf (best-effort warn). block_subscriber (broadcast/mod.rs:1351) mutates author.epoch inside the durable closure.
- Revocation path (recovery.rs revoke_ucans): RevocationList::revoke() local FIRST; TokenRevoked leaf BEST-EFFORT (NOT fail-closed — task premise was wrong); effectiveness comes from dispatch_recovery_send_notification which IS fail-closed. Event log not the SPOF; distribution is, and it's fail-closed.
- GovernanceDeadlockRecovery: GovernanceReconfigured durable first; recovery leaf changed to best-effort to avoid retry-duplicating the primary leaf.
- MediaSession (napi/uniffi media.rs): best-effort, actor_did = participants.first().map_or("", ...).

**Reusable review pattern:** For "is the event-log a SPOF / can attacker suppress a security action via log failures?" — TRACE ORDER. If the primary mutation is durably committed before the append, log failure can't undo enforcement; worst case is a missing/duplicate AUDIT leaf. The real SPOF is whatever path actually distributes/enforces (here: commit_class_s_keep and dispatch_recovery_send_notification), and those were fail-closed.

**Findings (all LOW):**
- A: MemberBlocked fail-closed + non-idempotent epoch advance → transient log failure → caller retry re-advances epoch (churn) + duplicate MemberBlocked leaves. Same failure mode the GovernanceDeadlockRecovery commit went best-effort to avoid. Recommend block leaf go best-effort too (block already durable → fail-closed buys nothing).
- B: "always co-located"/"verifiers can correlate" comments over-promise: primary fail-closed + companion best-effort means companion CAN be absent. Given "absence of provenance is a signal" tenet, verifier may false-positive tampering. Fix: atomic multi-leaf append OR soften comment.
- C: recovery_cid = format!("recovery:{}:scopes={}:before={}", context_id, scopes,...) unescaped delimiter concat of a revocation MATCHER; pre-existing (diff only added .clone()); trusted inputs today; collision/forge risk if context_id/scope ever carries :/, . Defense-in-depth: length-prefixed/hashed encoding.
- Obs: MediaSession empty-string actor_did fallback when participants empty.

Positive: durable-before-append ordering + the broadcast_helpers.rs:631-645 crash-window comment (re-grant of revoked key access) are exemplary.
