# Cross-context saga × Phase-2 typed event log (commit e068a70d4) — APPROVE, SOUND

Integrates #1849 cross-context tool-call saga onto Phase-2 convergent typed EventType log.
Adds tags 76 (CrossContextToolInvoked, operational) + 77 (CrossContextDivergenceMarker, structural).

## Taxonomy byte-stability: VERIFIED
- Leaf preimage uses `event_type_tag()` NUMERIC u16 tag (tree.rs:387), NOT serde name.
  (lib.rs comment "serializes by name" is about serde distinctness test, not the leaf hash.)
- Tags 0-35 unchanged, 36-75 unchanged, 59 still retired, 76/77 new next-free. No existing leaf shifts.
- KAT 32/33 (don't use new variants) pass byte-unchanged — ran `cargo test -p scp-event-log` 200+10 green.
- 3 distinctness tests updated to 77 (tree all_event_type_tags_are_distinct, lib taxonomy_closed_at_77, wasm_conformance bijection) — all pass.

## Saga leaf convergence: SOUND — the crux
Leaf preimage (tree.rs:362) = SHA-256("SCP-EVENT-V1:" || tag || len(actor_did)||actor_did || timestamp_BE || seq_BE || len(payload)||payload || prev_hash). So timestamp + actor_did + payload are ALL load-bearing for convergence.

Single convergent instant = B's `recorded_timestamp_ms`, captured ONCE at Prepare-B (saga.rs:818 `deps.clock.now_millis()`), staged into saga_pending + Class-S persisted + replicated to supervisor via PreparedBFields. Replay-deterministic.

1. ToolInvoked (target, commit_b_first_settle saga.rs:1497): ts=`receipt.timestamp_ms/1000`; receipt.timestamp_ms=`prepared.recorded_timestamp_ms` (saga.rs:1571). actor_did=`prepared.caller_did` (convergent). Payload all convergent (saga_id, event_id=`ToolInvoked:{saga_id}` derived, caller_ctx, tool_reg_id, receipt.chain_depth, receipt.timestamp_ms). CONVERGENT.
2. CrossContextToolInvoked (caller, commit_a saga.rs:1759 via cross_context_invoked_leaf): ts re-parsed from forwarded signed receipt.timestamp_ms/1000 — SAME signed instant as #1. actor_did=req.caller_did. Payload: saga_id, target_ctx, nonce, output_hash, receipt_len — all committed. CONVERGENT.
3. CrossContextDivergenceMarker (both sides, emit_divergence_marker saga.rs:2110): ts=`committed_timestamp_secs` threaded from supervisor (supervisor.rs:7119 = `prepared_b.recorded_timestamp_ms/1000`, computed ONCE outside the 2-side loop @6995, same u64 to both sends). actor_did="" (trivially convergent). Payload=serialized signed marker. CONVERGENT per-context.

## Receipt signature covers timestamp: VERIFIED
CrossContextToolReceipt::signing_preimage (cross_context_saga.rs:218-233) includes CanonicalField::U64(timestamp_ms) @231, domain XCTX_RECEIPT_DOMAIN, length-prefixed varfields. verify_strict. So a relay/peer cannot vary timestamp_ms per-recipient.

## Divergence-marker NUANCE (sound, not a finding)
Marker's OWN signing_preimage (cross_context_saga.rs:375) does NOT cover a timestamp (only saga_id,nonce,committed_side,committed_event_id). The marker LEAF timestamp rides outside the signed marker, sourced from supervisor's single `committed_timestamp_secs`. Convergence holds because supervisor computes it once and threads the identical value to both context actors; trait docstring (builder.rs:150) pins "never a per-member local clock." committed_event_id IS signed and = `ToolInvoked:{saga_id}` derived (committed-side convergent). No per-member field enters either the signed preimage or the leaf.

## Compensation paths
All 3 appends gated behind witness/capture + Class-S persist; malformed-receipt/serialize failures in commit_a roll witness back + re-persist (fail-closed). ToolInvoked exactly-once across retries (CountingEventLog test). No orphan leaves.

Tests: 74 lib saga + emit_divergence_marker_appends_verifiable_marker + xctx_needs_repair_emits_dual_signed_divergence_markers + dual-record (xctx ToolInvoked/CrossContextToolInvoked share leaf ts) + bijection all green.
