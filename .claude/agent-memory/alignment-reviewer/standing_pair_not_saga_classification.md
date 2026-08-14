---
name: standing-pair-not-saga-classification
description: Standing-pair creation is SETTLED as single-context async (NOT a saga); only §6.2.4 + §5.14.13 are sagas — saga count is 2
metadata:
  type: project
---

Standing-pair creation reclassified from a cross-context saga to **single-context async creation** (settled 2026-06-18, spec branch `spec/standing-pair-not-a-saga-v2`).

**Why:** A standing pair is ONE MLS group with two members (both parties derive the identical `derived_context_id`), not two distinct contexts. Replica sync is MLS (epoch-ordered Commits + bootstrapping Welcome) + the event-log RFC-6962 consistency layer — the same machinery every single context uses. A saga only coordinates atomicity across 2+ *distinct* contexts sharing no sync protocol; that never described a standing pair. Original (PR #1793) two-phase-commit / Prepare-A/Prepare-B / `CreationReceipt` / reserve-not-consume framing was a miscategorization.

**The two genuine cross-context sagas are exactly:** §6.2.4 cross-context tool invocation, §5.14.13 broadcast-hosting handshake. Saga count is **2**, not 3. ADR-049 Decision-3/3a numbers retained as stable anchors.

**How to apply:** In any future review touching sagas, ADR-049, or standing pairs: standing-pair creation has NO `start_*_saga` FFI export — it's reached via the `standing_context` get-or-create entrypoint. `SagaInput::StandingPairCreate` / `StandingPairCreatePrepared` variants + `creation_receipt.rs` scaffolding are slated for removal in a separate code-correctness PR. New normative machinery (consent gate on Welcome receipt by the joining peer; did_lo-survives concurrent-creation collision resolution keyed on group authorship + creator-credential confirmation; orphaned single-member-replica reaper; transparent re-drive via deterministic id) is all per-node local actor logic — no supervisor saga, no cross-context await. Reject any reintroduction of saga/two-phase framing for standing pairs.

Known limitation (matches ADR-049 Follow-up #1): creator→peer direction works today; joiner-originated SEND is gated on the Phase-2E spawn-from-Welcome actor entrypoint (part of the Welcome-Delivery effort).
