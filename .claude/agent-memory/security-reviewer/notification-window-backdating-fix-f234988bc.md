---
name: notification-window-backdating-fix-f234988bc
description: Verification of the import observed_at re-pin fix closing the notification-window backdating bypass (HIGH from prior 16a2cd42b review)
metadata:
  type: project
---

# observed_at import re-pin (f234988bc) — VERIFIED, bypass CLOSED, no new regression

Follow-on to the eventlog-phase2 HIGH and the prior fix at 4cad781e5. This commit
(f234988bc) is the canonical re-pin fix for the §19.3/§5.3.2 notification-window
backdating bypass on the UNTRUSTED import path.

**Why:** A malicious context creator can sign a Full export with both `effective_at`
(proposer-controlled via proposal.created_at) AND `observed_at` (the local
non-backdatable floor) backdated. Signature verification does NOT defend — the
creator IS the signer; that is the threat model. Installed verbatim, the gate
`current >= max(effective_at, observed_at + PERIOD)` collapses to zero and a
ceiling/econ-policy change applies on the first apply tick.

**Fix (lifecycle_helpers.rs import_context, ~L1742-1750):** re-pins `observed_at`
to `now_for_validation = deps.clock.now_secs()` (importing member's local clock,
same source as the `creation_timestamp_secs` re-pin and `cooldown_until`
sanitization) for BOTH `pending_ceiling_modification` and
`pending_economic_policy_change`. Floor becomes `import_time + PERIOD`.

**Verified:**
1. Bypass closed — `is_effective` (state.rs L279/L352) only consults
   `effective_at` + `observed_at` (notified_at is informational, never gating).
   Re-pin → floor = import_time+PERIOD regardless of attacker effective_at.
2. RESTORE path (restore_context, L2258-2259) keeps pending_* VERBATIM — correct:
   self-respawn, re-pinning would let a crash-loop re-arm the window forever.
3. Test `import_repins_observed_at_so_backdated_pending_change_is_not_effective`
   (supervisor.rs L9135): backdates BOTH fields by 10*PERIOD, builds REAL signed
   Full export (passes sig + Merkle), asserts NOT effective at import+1 AND
   effective at import+PERIOD+1 (proves window restarts, not destroyed — no
   over-protection breaking legit function).
4. Import is the ONLY untrusted observed_at install site. Other assignments
   (governance_helpers.rs L1414/L2526) are in-process from local clock.
5. validate_export_for_import runs FIRST (L1499) before re-pin.

**Other f234988bc changes — CLEAN:**
- WASM governance leaf payloads (manager.rs): proposal_id → b"" for
  GovernanceProposalCreated/VoteCast/VoteWithdrawn to match native's
  append_context_event (empty payload). Closes a Merkle-root divergence that
  false-positives §9.9.3 equivocation. Native uses append_context_event (empty),
  WASM now matches. proposal_id rides only in buffer-only ContextEvent.
- consequence.rs dedup: sequence keyed on buffer_events_accepted (contiguous)
  not raw idx (gappy). Sequence is evidence-only metadata, matches_trigger never
  reads it — behavior-preserving, improves native↔WASM convergence.
- convergent_consequence_timestamp moved governance_logic.rs → consequence.rs
  (scp-protocol) for shared native/WASM use. Body byte-identical.

VERDICT: MERGE-GATING CONFIRMATION — bypass closed, no new regression.
