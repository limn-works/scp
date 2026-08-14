---
name: black301-import-window-repin-verified
description: BLACK-301 notification-window import backdating is CLOSED by f234988bc; re-attack of import-boundary time fields found nothing new (merge-gating confirmation)
metadata:
  type: project
---

# BLACK-301 verification (commit f234988bc) — CLOSED, no new findings

**Why:** Prior pass found the §19/§5.3.2 notification window collapsible on the
untrusted IMPORT path (exporter backdated `observed_at` installed verbatim).
f234988bc claims to fix via re-pin. Asked to verify + re-attack for merge gating.

**How to apply:** If re-reviewing context export/import time fields, this is the
baseline — these vectors are already closed; do not re-report.

## Verdict: BLACK-301 genuinely closed; nothing new found.

### Fix is sound (item 1)
- `crates/scp-runtime/src/context/lifecycle_helpers.rs` import_context re-pins
  `pending_ceiling_modification.observed_at` and
  `pending_economic_policy_change.observed_at` to `now_for_validation` (local
  import clock) at lines ~1743-1752, assigned at ~1815-1816.
- `is_effective` (state.rs:279/352) gates on `current >= effective_at.max(observed_at + PERIOD)`.
  With observed_at = import_time, floor = import_time + PERIOD. A backdated
  `effective_at` is DOMINATED by the floor (max), so it cannot collapse the
  window. A FUTURE effective_at only delays application (self-harm). `effective_at`
  ALONE cannot defeat the window.
- RESTORE path (lifecycle_helpers.rs:2259-2260) keeps observed_at VERBATIM — correct:
  it's trusted self-respawn from local storage; re-pinning would let a crash-loop
  re-arm the window forever. Comment reasoning is correct.
- Only two snapshot->state construction sites exist: import (re-pinned) and restore
  (verbatim/trusted). All other pending_* writes are snapshot-CREATION (live->snapshot).
  No missed import entry point.
- WASM bridge (manager.rs:5863) does NOT track pending notification-window state at
  all (apply_pending_ceiling_modification always returns Ok(false); no economic-policy
  apply). No field to backdate there — attack surface absent, not a bypass. Pre-existing
  ADR-034 constraint, out of scope.

### No OTHER member-local-time field crosses import verbatim into a time-gate (item 2)
Import is conservative. Sanitized/wiped/fresh:
- cooldown_until: sanitize_cooldown_until (clamped)
- hard_rate_limit_state / velocity_tracker: validate_and_sanitize_snapshot (rejects future ts)
- spending_nonce_tracker: FRESH (new)
- proposal_timestamps: WIPED (C3) — earned-capacity rate limit reset to empty (= fresh member)
- participation_cache: WIPED
- pending_commits / commit_fault: empty/None
- checkpoint_events_since / checkpoint_last_time_secs: fresh local
- grace_store: FRESH; migration_state: None
- TTL: armed relative to LOCAL clock (anchor_deadline_to_creation=false)
- executed_proposals: timestamped with local `now`
- creation_timestamp_secs: local now
Carried verbatim but NOT exploitable:
- governance_freeze.freeze_start: verbatim, but freeze is a SAFETY block; auto-expiry
  via check_and_resolve_expired_freezes just removes already-wiped approved_proposals +
  clears freeze. Backdated freeze_start = self-DoS at worst ("you chose to import this").
- pending_*.effective_at: verbatim — REQUIRED for cross-member convergence (anchored on
  proposal.created_at). Dominated by re-pinned floor for window enforcement. When the
  change applies, the durable CeilingModified/EconomicPolicyApplied leaf is stamped with
  effective_at (governance_helpers.rs:463/509). A malicious exporter's divergent
  effective_at would diverge the IMPORTER's leaf vs honest members — but this is a
  PRE-EXISTING property of carrying effective_at verbatim (NOT introduced by the fix; the
  fix only touched observed_at) and only self-incriminates the importer in §9.9.3. Event
  log enforces NO timestamp monotonicity, so a backdated leaf ts is not a log-integrity
  violation. Not a new attack.
- notified_at: informational only, never read by a gate.

### New code in f234988bc is inert security-wise (item 3)
- WASM empty-payload change (GovernanceProposalCreated/VoteCast/VoteWithdrawn leaves:
  proposal_id.as_bytes() -> b""): MATCHES native append_context_event (empty payload,
  governance_helpers.rs:404). Convergence fix, not a regression. proposal_id rides only in
  buffer-only ContextEvent. Merkle tree distinguishes leaves by sequence/prev_hash, not
  payload — no equivocation introduced.
- dedup / dense-sequence in merge_consequence_events (consequence.rs:891): keys Event.sequence
  on buffer_events_accepted instead of idx. `Event.sequence` is NEVER read in trust eval
  (grep confirms zero reads in trust/). Cap MAX_BUFFER_EVENTS_FOR_EVAL still gates inflation.
  Behavior-preserving cosmetic densification.
- Added supervisor test import_repins_observed_at_so_backdated_pending_change_is_not_effective:
  drives REAL import_context -> dispatch_governance_command -> apply path with real Ed25519
  signed export; asserts not-effective at import+1 AND effective at import+PERIOD+1. Non-gameable.
