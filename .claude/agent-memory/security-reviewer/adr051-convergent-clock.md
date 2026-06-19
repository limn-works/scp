# ADR-051 Convergent Clock / Causal-DAG (re-review 2026-06-19)

REVISED ADR (C01-C05 fixes): node-vantage DROPPED, max()-clamp DROPPED. Verdict: APPROVE, prior MEDIUM CLOSED.

## Prior MEDIUM (anchored prose-only) — CLOSED
- §7.3.2 ParticipationProfile gains real field `tool_invocation_count_anchored: bool` (specs/07 L39),
  covered by existing signature over all fields. event_log_root comment now notes the caveat.
- §19 PaymentReceipt gains real field `anchored: bool` (specs/19 L186), inside the signed struct.
- Both carry "consumers MUST NOT treat as Merkle-proven" inline. ADR §6 req#6 mandates field (not comment).

## Residual NIT (NOT blocking; ADR is model-only, impl is forward program)
- §25 test-vectors.md does NOT yet have the anchored=false consumer-rejection KAT vector that
  ADR §6 req#6 + req#5(f) mandate. Correctly deferred to impl step 2 (the field — the load-bearing
  surfacing mechanism — IS present now, which is what closed the MEDIUM). Track: vector lands WITH
  consumers, not after. §25 diff this changeset was only the 76->75 EventType count edit.

## C01 preimage binding — SUFFICIENT (Q2)
- {context_id, epoch, leaf_hash, receiver_did, receive_time_ms} receiver-signed. context_id+epoch+
  leaf_hash kills cross-context/cross-epoch replay; receiver_did pins attester (one signature-bound
  vote/member). No replay or cross-context forgery.

## C02 fix (receiver-median-IS-value, sender/relay early-floor-only) — SOUND, no new gap (Q3)
- Upward lever removed: median MUST be >= max(sender, relay-ingest) but floors NEVER raise value above
  receiver median. Colluding sender+relay stamping late cannot push canonical time forward to dodge a
  rate window. Below-floor median => inconsistency => no durable consequence (throttle fallback).
- Soft posture honest: residual = receiver-Sybil-LATE-majority (one-directional, can't frame honest
  member as fast), raised by §9.3 admission cost (deterrent), backstopped by local throttle that NEVER
  consumes this clock — so every clock-biasing attack degrades only the durable record, not live defense.

## C05 relay delay-not-forge — ACCEPTED, security-acceptable (Q4)
- Relay withholds a member's checkpoint -> cut won't close -> denies DURABLE record (-> throttle),
  indistinguishable from offline, invisible to §9.9.3 (catches forged not withheld; cf §9.9.4).
  Cannot fabricate a suspension. Live spam defense unaffected. Acceptable: durable record is soft.

## No new gap from simplification (Q5)
- node-stamp (sender-capturable duplicate, no opposing incentive) + max()-clamp (the upward lever)
  both REJECTED correctly. C03: no small-context floor (spread=latency not N) + quorum-size confidence
  annotation (2-receiver median not weighted like 200). Determinism: u64 ms, lower-of-two even-quorum
  median, KAT-pinned. Closure observation-order-independent (all anchoring-epoch members / convergent log).
- §9.9.3 preserved: equal-frontierRoot/equal-root (frontier is a SET, not derivable from scalar count),
  frontierRoot in SCP-CHECKPOINT-V2 signed preimage. Vantage stamps signed by role key (forge-proof).

## Scope notes
- ADR-049 + phase-2 diffs in SAME changeset = SEPARATE concerns. ADR-049: OwnedIdentityDid switched
  from compiler-only to a CI-gate (check-owned-identity-did.py, closed allowlist) + tree-sitter dev-dep
  reinstated — NOT this clock's surface. phase-2: ADR-011 exclusion taxonomy §2 (per-author app
  activity) is the prerequisite this ADR consumes.
