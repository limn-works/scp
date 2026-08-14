---
name: eventlog-convergence-b3d354279
description: Security review of event-log convergence change (Wave A/B, b3d354279 + 3e667ef48) — per-author/per-payee leaf removal for §9.9.3
metadata:
  type: project
---

# Event-log convergence review (commits 217d14ac6 Wave A, b3d354279 Wave B-core, 3e667ef48 WASM/SDK) — 2026-06-19

Change: per-author app events (MessageSent, ToolInvoked, PaymentReceived) + velocity/rate consequence leaves no longer mint durable Merkle leaves, so two honest members converge on event_log_merkle_root (§9.9.3 equivocation detection). PaymentReceived receipts moved to local `PerContextState.payment_receipts` Vec. Two `anchored` bools added (PaymentReceipt.anchored UNSIGNED; ParticipationProfile.tool_invocation_count_anchored SIGNED into SCP-PARTICIPATION-V1 preimage as 1 byte after tool_invocation_count).

## Security verdict: clean on the four stated focus areas, with 2 findings.

- **Convergence direction is CORRECT**: per-author events have no global order, so keeping them WOULD break the detector. Removing them is the right move. Velocity/rate keyed on `is_convergent_trigger` enum gate (fail-safe: missing rule => non-durable).
- **payment_history query**: context-scoped (per-context actor reads only its own state.payment_receipts), soft-default empty Vec on unknown context. No cross-context leak. BUT no caller-side authz — any caller of Supervisor::payment_history(context_id, filter) gets all receipts for that context (payer+payee visible). Acceptable per spec §19.11 (host-app SDK surface) but note absence.
- **anchored trust semantics**: NO production consumer branches on `anchored` to grant access/skip a check (only a test helper `requires_merkle_proven`). tool_invocation_count_anchored correctly bound into signed preimage (tests prove flip invalidates sig). PaymentReceipt.anchored unsigned + crosses wire, always false today — latent footgun for when ADR-051 lands, no current exploit.
- **velocity routing**: matches_trigger keys on subject_did==actor_did; WASM MessageReceived arm maps actor=sender_did → can't inflate another member's count. Self-DoS only.
- **Receive buffer (consequence Source 2) is bounded**: ring buffer, default 1k, max 10k, evicts oldest. WASM mirrors native bounds (MAX_BUFFER_EVENTS_FOR_EVAL=100, AGE=3600s, FUTURE=5s).

## FINDINGS
1. **MEDIUM — unbounded `payment_receipts` Vec (new structure, no eviction/cap/persist-clear).** Only writer: complete_paid_action (escrow capture, verified receipt). Reached on EVERY paid message-send + paid join. A member sending high-frequency paid micro-messages grows the PAYEE node's in-memory Vec one entry/send, unbounded for actor lifetime. Volume gated by real funded payments (not free), so remote-triggerable but not free; severity MEDIUM. The OLD path stored in durable event log which has checkpoint/export/truncation; this new parallel Vec has none. Recommend cap + eviction (or back by ProtocolRepository store::economy which already has list_payment_receipts).

2. **HIGH (alignment/provenance, security-adjacent) — phantom provenance + removed durable accountability.** Commits cite "ADR-051 §6" — ADR-051 DOES NOT EXIST in repo. Current spec phase-2.md ADR-011 amendment §2 (line ~872) says MessageReceived + EquivocationDetected are "the **only** two exclusions"; spec §19.6.1 says PaymentReceived "carries the same Merkle-tree inclusion guarantees as other event types"; §174/§541 keep MessageSent/ToolInvoked as durable leaves. The code removes all three — DIRECTLY CONTRADICTS current spec. Per artifact-flow invariant, spec must change FIRST. Security dimension: durable accountability records (tenet "Behavioral records are durable") that dispute/violation flows rely on are silently gone; `anchored=false` is the only honest signal. Either land ADR-051 + spec amendment first, or this is phantom provenance.
