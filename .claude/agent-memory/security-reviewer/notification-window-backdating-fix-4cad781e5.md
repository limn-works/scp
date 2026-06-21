# Notification-Window Backdating Fix (4cad781e5) -- 2026-06-20

Verifies the prior HIGH (econ-policy/ceiling deferred window used proposer-backdatable
`effective_at = created_at + PERIOD`, collapsible to zero).

## Verdict: HIGH genuinely RESOLVED, no new security regression. CLEAN.
## DOUBLE-ZERO CONFIRMED (2026-06-20 independent re-verify of HEAD 4cad781e5)
- observed_at = deps.clock.now_secs() at commit (gov_helpers 1410 ceiling / 2520 econ) — applying
  member's own clock, NOT proposer data. is_effective max(effective_at, observed_at+PERIOD).
- Apply paths (gov_helpers 443/492) gate on is_effective; durable leaf STILL pending.effective_at
  (convergent) at 463 CeilingModified / 509 EconomicPolicyApplied. Convergent root preserved.
- Export seam (export_import 555-648): version-pin -> exporter==creator binding -> verify_strict over
  canonical digest -> recompute_event_log_root (RFC6962) -> ct_eq vs SIGNED event_log_merkle_root.
  Unsigned merkle_root mirror gone; signed field sole authority. Prefix-trunc rejected by seq/prev_hash.
- merge_consequence_events (protocol consequence.rs 739): convergent events (membership/gov/conseq)
  ONLY from Source1 (signed log); buffer (Source2) contributes ONLY MessageSent/MessageReceived
  (per-author velocity, non-durable). is_convergent_trigger exhaustive (velocity/rate=false,
  warncount/custom=true). trigger_kind_str stable Custom:{key} (not Debug). WASM consequence.rs 119
  calls the SAME shared fns — byte-identical leaves, no reimpl drift. EventType 76->75 (PseudonymAnnounced
  removed, zero remaining EventType:: refs). No authz/audit consumer broken. MERGE-GATING: GREEN.

## Fix shape
- `PendingCeilingModification` / `PendingEconomicPolicyChange` gain per-member `observed_at`
  = `deps.clock.now_secs()` captured at commit-processing (governance_helpers.rs ~1414, ~2526).
- `is_effective` (state.rs ~271/~336) changed const fn -> fn:
  `current >= effective_at.max(observed_at + PERIOD)` (saturating_add floor).
- Applied leaf STILL uses `pending.effective_at` (convergent), NOT observed_at
  (governance_helpers.rs:463 CeilingModified, :509 EconomicPolicyApplied). Verified.

## Why backdating is closed
- Floor `observed_at + PERIOD` and apply-tick `current_timestamp` are the SAME member's
  wall clock (now_secs = Unix epoch). Interval is clock-offset-invariant. A proposer
  backdating `created_at` only lowers `effective_at`; the floor is proposer-independent,
  so window >= PERIOD of locally-observed time always. Regression test real (uses
  `observed - PERIOD` backdated created_at; asserts not-effective at commit & floor-1,
  effective exactly at floor). notification_window_backdating_tests in state.rs.

## Convergence/signature: observed_at does NOT poison signed/convergent bytes
- Cross-member convergent value = `event_log_merkle_root` (effective_at leaves), NOT observed_at.
- Full-scope (3/4) signed ContextSnapshot DOES serialize pending_* (Serialize derived) incl
  observed_at AND create_export Full signs snapshot as-is (export_import.rs:843-845). BUT this
  is SELF-ATTESTATION: validate_export_for_import enforces exporter_did==creator_did (line 579)
  and verifies the creator's OWN sig over the received bytes (line 592-595). No cross-member
  byte-identity requirement on Full snapshot; observed_at never compared cross-member nor folded
  into a Merkle root. Public scope zeros pending_* (strip_snapshot_for_public 747-748). Not a regression.

## Freeze residual (accepted, sound)
- governance_helpers.rs ~609 freeze_start = max(created_at_a,b), still backdatable; left with
  `// SECURITY (residual, accepted)` comment. check_and_resolve_expired_freezes REMOVES BOTH
  conflicting proposals on expiry (lines 659-660) -- opposite of granting capability. Backdating
  only ends a self-created two-signer deadlock earlier. No authz bypass. Correctly not floored.

## Clock-skew edge cases: none
- Floor interval is offset-invariant (both endpoints same wall clock). Late joiner imports with
  pending_*=None (export zeros them) so never inherits a stale floor. No under/over-block.
