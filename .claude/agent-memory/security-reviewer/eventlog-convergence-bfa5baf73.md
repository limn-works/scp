# Event-Log Convergence Review (bfa5baf73 / origin/main...HEAD) -- 2026-06-19

CLEAN security review. ADR-051/ADR-011-amendment convergent event log. No HIGH/CRITICAL.

## What changed
- Native `MerkleEventLogProvider` rewritten to use canonical `scp_event_log` substrate
  (typed `EventType`, `tree::append_unsigned_event`, `tree::root`) instead of a side
  SHA-256 hash-CHAIN of `EventLogEntry` (free-form event-name strings). Now byte-identical
  to WASM (`SHA-256(0x00 ‖ rmp_serde(Event))`). Eliminates native↔WASM root divergence
  (was latent §9.9.3 false-positive source). Removed `EventLogEntry`, `compute_entry_hash`
  (`SCP-EXPORT-ENTRY:` chain), `verify_chain`, `is_structural_event_name` (string matcher
  that could drift from typed `pruning::is_structural_event`).
- `append_event` trait now takes typed `EventType` + `EventPayload` (not string + Option<Value>).
  Can no longer append an off-taxonomy event name. STRONG improvement.
- PseudonymAnnounced removed from EventType (76->75 variants), tag 59 RETIRED (gap left so
  other tags + §25 KAT preimages stay byte-stable). It's a per-receiver routing-bootstrap
  ContextEvent, not a durable leaf.

## EL01 fix (commit 564222c48) -- the load-bearing one
- Durable consequence leaves (ConsequenceTriggered/Enforced/Failed/EscalatedToSuspendAll)
  must derive from CONVERGENT source only. Bug: `event_log_entries_for_consequences` (native)
  + `merged_consequence_events` (WASM) merged durable log (Source 1) with member-local
  receive buffer (Source 2); Source 2 also yielded MemberJoined/MemberLeft/GovActionExecuted
  which are ALSO in Source 1. Buffer-length-keyed dedup double-counted on quiet members ->
  divergent WarningCount -> divergent durable leaf -> false-positive equivocation.
- FIX: Source 2 now contributes ONLY MessageSent (per-author, excluded from durable log,
  buffer is its sole source; velocity triggers need it; never feeds a durable leaf).
  Convergent events come exclusively from Source 1. Mirrored in WASM identically.

## Durability gate (the other load-bearing one)
- `is_convergent_trigger(trigger)` in scp-protocol/trust/consequence.rs (compiles wasm32):
  WarningCount/Custom => durable leaf; MessageVelocity/ToolRateExceeded => buffer-only,
  NO durable leaf (a rate needs a clock the protocol lacks; per-receiver leaf would diverge).
  Missing/unresolvable rule => non-durable (fail-safe). Keyed on ENUM not string.
- `checkpoint_events_since` bumped ONLY when a durable leaf is actually appended -> no
  §9.9.3 checkpoint-position drift.
- Shared label producers in scp-protocol (`trigger_kind_str`, `consequence_action_type`)
  + shared payload bytes (`scp_event_log::payload::consequence_event_payload`, sorted-key
  JSON, no preserve_order) => native + WASM emit byte-identical leaf preimages. Cross-impl
  byte-parity tests with pinned known-answer fixtures (gov-action, token-revoked, consequence).

## anchored fields
- `PaymentReceipt.anchored`: UNSIGNED (outside signing preimage, §19.6 scope ends at timestamp),
  crosses wire. Doc explicitly says "do not trust deserialized value, derive from local state."
  Always constructed false. grep confirms NO production consumer branches on it (only Debug +
  tests). Safe.
- `ParticipationProfile.tool_invocation_count_anchored`: SIGNED (1 byte in signable_bytes after
  tool_invocation_count). Test `signature_binds_tool_invocation_count_anchored` proves flipping
  it invalidates sig -> cannot be stripped/downgraded. SDK parity: Python + TS fields added.

## payment_receipts VecDeque ring
- Cap = DEFAULT_BUFFER_CAPACITY, enforced on EVERY push (economy_helpers.rs:242 `>= cap` then
  pop_front then push_back). No unbounded path. Holds payee's OWN captured receipts (per
  §19.6.1); no cross-member write path -> no history-truncation attack on a victim. Doc states
  it's a sliding window, NOT the authoritative ledger (store-backed history separate, not wired).
  Query context-scoped (per-actor state.payment_receipts), no cross-context leak.

## EquivocationDetected dedup (state.rs last_seen_remote_checkpoint)
- Changed from "durable-append-backed primary + in-memory secondary" to "in-memory SOLE dedup."
  Correct: an equivocation record is receiver-minted, NOT sender-authenticated, so appending it
  to the durable log would itself diverge honest receivers' roots (defeats the very detection).
  Bounded consequence: ONE duplicate alert after respawn. Acceptable. Insertion cap-gated at
  MAX_SEQUENTIAL_COMMITS per sender; emission always-on (never silently drops a §9.9.4 event).

## Minor (Observations, not findings)
- `consequence_event_payload` uses `serde_json::to_vec(&value).unwrap_or_default()`. Inputs are
  all &str/usize (always serializable) so unreachable; AND it's the single SHARED producer so
  both platforms would fail identically -> no divergence even in the impossible failure case.
- `unwrap_or_default()` on SystemTime timestamp in provider append (returns 0 on clock error) --
  recurring systemic pattern, pre-existing, bounded.
