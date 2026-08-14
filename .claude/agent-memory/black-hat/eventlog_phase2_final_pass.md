---
name: eventlog-phase2-final-pass
description: Final merge-gating black-hat pass on event-log Phase-2 substrate swap (HEAD 3d96058f5) — clean, no new findings
metadata:
  type: project
---

# Event-Log Phase-2 Substrate Swap — Final Black-Hat Pass (HEAD 3d96058f5)

Final pre-merge adversarial pass. NO NEW FINDINGS. Double-zero confirmation.

**Why:** last look before merge of the ADR-011/ADR-051 native↔WASM event-log unification + non-backdatable notification-window security fix.

**How to apply:** these surfaces are now verified-clean; don't re-litigate them on the same HEAD. Re-examine only if the relevant files change.

## Surfaces probed and cleared

- **`now_ms` cfg-gating (wasm/src/time.rs):** native `SystemTime` fallback is `#[cfg(not(target_arch="wasm32"))]`. Crate is `crate-type=["cdylib"]`, ships only via `wasm-pack build --target` (wasm32-unknown-unknown). Native variant is structurally absent from any deployed .wasm — cannot weaken the hardened captured-`Date.now` clock in production. Exists only so native-host `cargo test` can drive WASM logic without a JS runtime.
- **Test helpers `test_insert_context`/`test_set_governance`** (+ test_append_log_event_at, test_event_log_root, make_bare_per_context_state, test_insert_member, etc.): ALL `#[cfg(test)]`-gated. Compiled out of production builds. No state-injection surface.
- **Non-backdatable notification window (state.rs is_effective):** `max(effective_at, observed_at + PERIOD)`. `effective_at` proposer-controlled (backdatable via proposal.created_at); `observed_at = deps.clock.now_secs()` (local, non-backdatable). Floor dominates backdated effective_at. Correct.
- **Export/import observed_at re-pin (lifecycle_helpers.rs import_context):** untrusted import re-pins `observed_at` to local import time → window restarts from import. Trusted RESTORE path (restore_context, loads from local persistence only — NOT network-reachable) keeps verbatim to avoid crash-loop re-arm. Trust boundary correct. Regression test in supervisor.rs proves backdated signed export NOT effective at import+1, IS at import+PERIOD.
- **Governance freeze backdating:** honestly documented as accepted residual — liveness-only (never grants capability), requires TWO colluding signers, not unilateral. Local-floor intentionally not applied.
- **WASM proposal/vote leaf parity (#1846 class):** WASM was stamping proposal_id into leaf; native used empty payload → would false-positive equivocation. Fixed to `b""` both. Regression detector test proves stamped vs empty roots diverge.
- **Convergent timestamp dedup (merge_consequence_events):** Source-1 dense `events.len()` numbering + Source-2 `next_seq + buffer_events_accepted` (was `idx`, left gaps). sequence is evidence-only, matches_trigger never reads it. Behavior-preserving, byte-identical native↔WASM merged sets.
- **leaf_hash extraction (tree.rs):** pure refactor, same `SHA-256(0x00 ‖ rmp_serde(event))`.
- **Tag 59 retirement (PseudonymAnnounced removed):** gap preserved, no renumbering → §25 KAT preimages byte-stable, all 75 remaining tags distinct.
- **Shared leaf producers genuinely called by BOTH paths (verified, not hollow):**
  - `consequence_event_payload`: WASM manager.rs:677 + native governance_logic.rs:320/362/400/544/560
  - `token_revoked_payload`: WASM manager.rs:2720 + native FFI resolvers.rs:677
  - No divergent local reimplementations.
- **serde_json sorted-key convergence:** NO `preserve_order` anywhere in workspace → json! uses BTreeMap (sorted). usize serialized as decimal text (width-agnostic). Native↔WASM identical.
- **payload_target_did decode order:** rmp-array-first then JSON. JSON `{` (0x7B) decodes as MessagePack positive fixint not array → falls through to JSON correctly. No encoding confusion.
- **tool_invocation_count_anchored / PaymentReceived.anchored / leaf anchoring:** truth-in-advertising `anchored:false` flags in signed preimage (signable_bytes), bound by signature. PaymentReceived is local-only ContextEvent (no Merkle leaf).

ALREADY TRACKED (not re-reported): #1845 dormant cross-member replication, #1846 WASM ~40-leaf gap, BLACK-301 (import notification-window — FIXED+confirmed).
