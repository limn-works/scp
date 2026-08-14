---
name: convergence-slices-1857-1858-1859
description: Adversarial review of three convergence-fix branches off main 1f1ea7cd2 — Slice1 CommitBroadcast off-canonical (CLEAN), Slice2 verbatim creation_timestamp_secs import (HIGH native/WASM clamp asymmetry diverges TTL leaf), Slice3 convergent_now anchor (MED future-dated evidence now counts for an admin-forgeable consequence)
metadata:
  type: project
---

Reviewed 2026-06-21. Base = worktree slices-base @ 1f1ea7cd2.

## Slice 1 (#1857, slice1-commitbroadcast @ 6687ecaae) — CLEAN
Removes durable append of CommitBroadcasted/Pending/Succeeded/Failed; demoted to local ContextEvent.
- No durable reader exists: only consumers are pruning.rs classify-as-non-retained (dead-but-harmless) + tree.rs tag table (KAT stability, never invoked). CommitFault* family is UNRELATED state (commit_fault marker), untouched.
- §9.9.4 (selective commit suppression) mitigation = epoch-divergence detection + re-request recovery, NOT a durable CommitBroadcasted leaf. So no accountability/auditability relied on the durable record. Cannot be abused to hide a commit-broadcast.
- checkpoint_events_since increment removed alongside append → IMPROVES convergence (these were per-committer only; receivers never appended/incremented). try_broadcast_commit_or_enqueue made infallible — callers all drop the old Result safely (transport failure already absorbed into retry queue / commit_fault).

## Slice 2 (#1858, slice2-snapshot-creation @ 18d8d5a49) — HIGH (native/WASM divergence)
Adds ContextSnapshot.creation_timestamp_secs, consumed VERBATIM on native import; sole semantic consumer = convergent_ttl_deadline_secs = creation+ttl, used ONLY as the recorded ContextExpired/ContextClosed leaf timestamp (deadline_unix_secs). Timer FIRE time = tokio sleep(duration=ttl_remaining_secs), NOT creation_timestamp_secs.
- (b) future-dated deadline delaying mandatory close: NOT exploitable — close fires on ttl_remaining_secs (separate field); creation only mis-stamps the leaf.
- Third-party forgery: blocked — field is inside creator-signed JCS snapshot; validate_export_for_import verifies Ed25519 + exporter_did==creator_did BEFORE the builder consumes it.
- REAL FINDING: native import consumes verbatim (lifecycle_helpers.rs:~1796), but WASM import CLAMPS to min(snap.creation_timestamp_secs, now) (manager.rs:~5934). For a mixed native+WASM context where creation_timestamp_secs > wasm_importer_now (legit clock skew up to DEFAULT_CLOCK_SKEW_TOLERANCE 5min, OR creator stamped slightly-future), native computes creation+ttl, WASM computes wasm_now+ttl → ContextExpired/ContextClosed leaf timestamps DIVERGE → §9.9.3 equal-count/different-root false-positive equivocation — the very thing the slice exists to eliminate. The asymmetry self-defeats for mixed deployments. Honest same-clock case fine.

## Slice 3 (#1859, slice3-consequence-window @ edfa17e57) — MED (admin-forgeable, directional expansion)
convergent_now = max(Source-1 durable timestamps), captured before buffer merge; convergent-trigger rules (WarningCount/Custom) window = [convergent_now - window, convergent_now] instead of local [now-window, now]. Non-convergent (MessageVelocity/ToolRateExceeded) keep local now.
- Honest convergence SOUND: GovernanceAction evidence sourced ONLY from Source-1 (buffer match falls through _=>continue); empty-log unwrap_or(now) fallback benign (no convergent evidence to anchor).
- ATTACK: proposal.created_at is proposer-chosen + unbounded (code explicitly admits this at governance_helpers.rs:1403-1405 and 3961-3967 — added observed_at floor ONLY for the ceiling-notification window, NOT for consequence eval). Governance leaf timestamp = created_at. So a malicious admin (SingleAdmin) or colluding quorum can mint N WarningCount-evidence governance actions targeting a victim with future-dated created_at AND set the anchor there → crosses threshold → fabricates a convergent durable ConsequenceTriggered (e.g. AssignRole demote / SuspendCapability) against the victim, agreed by all members.
- NEW vs old: old local-now ceiling (event.timestamp <= now) REJECTED future-dated evidence; new convergent_now ceiling ADMITS it. So future-dating evidence now counts where it previously couldn't. ConsequenceTriggered leaf ts = convergent_consequence_timestamp = highest-seq evidence ts (already proposer-controlled pre-slice; slice changes the COUNT/threshold-crossing).
- Privilege note: a SingleAdmin can already suspend/demote directly, so for that actor it's not escalation; the concern is the consequence engine being a supposedly-objective enforcement path that is now admin-forgeable while looking convergent/legitimate. Recommend: clamp convergent_now (and convergent-trigger evidence ts) to NOT exceed a locally-observed bound, mirroring the observed_at defense already applied to the ceiling-notification window.
