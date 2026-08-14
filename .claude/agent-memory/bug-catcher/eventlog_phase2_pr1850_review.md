# PR #1850 — event-log Phase-2 substrate swap + #1852 merge (HEAD 44f2ebeda)

Reviewed 2026-06-21. Verdict: CLEAN — no blocking defects found.

## Scope reviewed
- scp-event-log core: EventType 76→77 (CrossContextToolInvoked=76, CrossContextDivergenceMarker=77;
  PseudonymAnnounced removed, tag 59 retired as a deliberate gap), EventPayload Default, tree::leaf_hash
  exposed, consequence_event_payload shared JSON producer.
- Append API reshape: append_event/append_context_event[_with_payload] now take typed EventType +
  EventPayload + explicit timestamp_secs (committer-assigned). All call sites updated.
- saga.rs convergent committer-assigned leaves: ToolInvoked (B), CrossContextToolInvoked (A),
  CrossContextDivergenceMarker all derive seconds from B's signed recorded_timestamp_ms/1000
  (verified: build_signed_receipt sets receipt.timestamp_ms = prepared.recorded_timestamp_ms; all 3
  leaves use the SAME integer /1000 → identical second, no off-by-one, no ms/secs mixing).
- Consequence native↔WASM parity: native process_one_triggered_consequence (governance_logic.rs) vs
  shared enforce_triggered (scp-protocol consequence.rs, used by WASM dispatcher). Both emit identical
  leaf EventType order + payloads (consequence_event_payload) + convergent_consequence_timestamp.
  Failure-escalation path matches: ConsequenceEnforcementFailed(action_type) then
  ConsequenceEscalatedToSuspendAll("SuspendAll"). RevokeAccess/RemoveMember → false → escalate on both.
- divergence_marker_plan: NEW guard `let prepared_b = ctx.prepared_b.as_ref()?` refuses to mint a marker
  from caller-ASSERTED nonce/timestamp; sources nonce+timestamp only from B's verified provenance.
  Verified prepared_b is always Some when committed_b_tool_invoked_event_id is Some (FSM ordering:
  Prepare-B sets prepared_b before Commit-B sets the event id) — guard is defense-in-depth, no live
  behavior change. Guard regression test added.
- economy: PaymentReceipt.anchored bool added — UNSIGNED wire field (outside signing preimage),
  always constructed false, doc warns consumers must derive anchoring locally. payment_history rewritten
  to read per-context payment_receipts ring buffer (bounded, oldest-evicted) instead of scanning event
  log (PaymentReceived is per-payee non-convergent, excluded from Merkle log). New PaymentHistory query
  routes through actor mailbox. complete_paid_action populates the buffer on capture.
- ContextEvent::PaymentReceived new variant — PyO3 convert_context_event has catch-all `other => Debug`
  arm so it's surfaced (not dropped), same tier as pre-existing PaymentCaptureFailed.
- TTL convergence: anchor_deadline_to_creation bool on TtlTimerPayload. Create path = true (anchors
  ContextExpired/Closed leaf to creation_timestamp_secs + ttl, convergent). Join/import/restore = false
  (local-clock arm) because snapshot doesn't yet carry convergent creation time — HONESTLY documented as
  forward step under ADR-051 (task #200). convergent_ttl_deadline_secs uses saturating_add.
- import re-pins observed_at (pending_ceiling_modification + pending_economic_policy_change) to local
  clock on UNTRUSTED import path (security: prevents backdated window collapse); restore keeps verbatim
  (trusted self-respawn). Security test covers it. Correct asymmetry.

## Dispositioned (per task brief, not re-raised)
- caller-leaf nonce-equality invariant (documented at supervisor.rs ~6873)
- dormant cross-member replication (foundation)
- #[test] hardcoded-crypto fixtures
- convergent creation-time on join/import/restore = forward step (tasks #200), not a bug

## Note (pre-existing, not this diff)
- payment_history returns RECENT buffered receipts (bounded ring, lost on respawn), NOT complete ledger.
  Full persisted history is separate not-yet-wired work. Documented honestly in receipt.rs doc.
