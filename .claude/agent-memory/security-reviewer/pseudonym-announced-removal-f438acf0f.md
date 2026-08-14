---
name: pseudonym-announced-removal-f438acf0f
description: Security review of EventType::PseudonymAnnounced removal from durable Merkle taxonomy (commits 96f46eeeb + f438acf0f) — APPROVED, no findings
metadata:
  type: project
---

# EventType::PseudonymAnnounced Removal — APPROVE (2026-06-18)

Commits 96f46eeeb (ADR-011 amendment doc) + f438acf0f (code) removed
`EventType::PseudonymAnnounced` from the closed durable Merkle taxonomy (76->75).

**Why:** Receive-path durable append was non-convergent — minted per-receiver in
per-receiver arrival order; late joiners miss earlier announcements; WASM context
manager (`decrypt_message`) NEVER appends on receive. Divergent `tree::root` would
false-positive §9.9.3 equivocation detection. Same class as `MessageReceived` and
`EquivocationDetected` (both already correctly ContextEvent-only). These are now the
ONLY three Merkle-log exclusions.

**How to apply / verified facts:**
- Validation FULLY PRESERVED in `ingest_pseudonym_announcement` (messaging_helpers.rs):
  tag-decode, sender-DID-match (anti-forgery), reserved-value rejection
  (zero/shared-bootstrap/broadcast RID via is_reserved_pseudonym), broadcast-context
  rejection, cross-DID collision rejection (same-DID rotation allowed). None touched.
- `ContextEvent::PseudonymAnnounced` buffer signal RETAINED (membership.rs:797) —
  registry insert + SDK observation. The announcement's entire function is carried.
- ZERO durable consumers: no `EventType::PseudonymAnnounced` refs remain anywhere;
  no checkpoint/export/proof/pruning read it. Tag 59 RETIRED as a deliberate gap
  (no renumbering) so KAT vectors 32/33 root 39e50b87... stay byte-stable (verified).
- Receive-path durable-append surface now EMPTY: `deliver_plaintext_or_announcement`
  always returns None for received traffic; the `Some` channel kept for future
  sender-authenticated received events. Remaining appends (MessageSent line 1677,
  PaymentCaptureFailed line 1635) are send/local-action authored, legit.
- New regression test `received_announcement_updates_registry_without_durable_append`
  proves registry update WITHOUT any Merkle leaf (any_append flag).
- All 18 pseudonym_routing_tests pass; 200 event-log tests pass WITH --features testing.

**GOTCHA:** `cargo test -p scp-event-log` shows 116 FAILURES without `--features testing`
— all are `checkpoint::tests` "unsupported DID format: did:key:<hex>" (the did:key hex
format is gated behind the testing feature, issue #128). NOT a regression. Always run
event-log/runtime tests with `--features testing`.
