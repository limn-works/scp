---
name: eventtype-audit-1847
description: EventType orphan-producer audit PR (fix/eventtype-audit-1847) — INCOMPLETE; media append wired only for TS, AppBound/AppUnbound orphans missed, KeyEpochAdvance on 1-of-4 epoch paths
metadata:
  type: project
---

# fix/eventtype-audit-1847 review (2nd pass) @6553bb2b8

PR charter: "add durable event-log appends for EventType variants that previously had no producer" + correct payload schemas + PyO3 media parity. Diff touches ONLY crates/ (no bindings/ — this is the crux of the wiring gaps).

**VERDICT: INCOMPLETE.** Findings:

1. **AppBound/AppUnbound = orphan EventTypes the audit MISSED.** Both have payload structs (payload.rs) + wire tags 74/75 + pruning retain=true + canonical test vector (spec §25:373) but ZERO producers (grep `EventType::AppBound` = only enum-def/serde/pruning/test, no append). §8 spec (08-products-and-apps.md:130) MANDATES "App binding and unbinding events are visible in the event log — silent app attachment is not possible." FFI declaration-validation path (context.rs:1829 py_validate_capability_declaration) validates but appends no leaf. Exactly the PR's target class, not addressed.

2. **Media event-log append wired ONLY for TypeScript** (3 of 4 SDKs unwired):
   - TS/NAPI ✓: napi instance method `mediaActivateSession` (scp.rs:3998, PRE-EXISTED, →`media_activate_session_on`) already called by TS `this.#native.mediaActivateSession`; PR added log to `_on` body → flows for free. napi has NO free-fn variant.
   - Python/PyO3 ✗: PR added SEPARATE `PyScp::media_activate_session_with_log` but Python SDK media.py:106 calls `bridge.media_activate_session` = module FREE fn (media.rs:297, no append). `_bridge()` returns `_scp_core` module. `_with_log` method has zero SDK callers = dead.
   - Swift+Kotlin/UniFFI ✗: PR added per-instance `Scp::media_activate_session` (bridge.rs:17490, in `#[uniffi::export] impl Scp`) but Swift SDK calls `fn_func_media_activate_session` = FREE fn (bridge.rs:7160, no append); Kotlin same. Generated bindings NOT regenerated (no `checksum_method_scp_media_activate` in ScpBindings.swift). Even if regen'd, SDK wrapper (Media.kt) calls free fn.
   - Commit msg claims PyO3 `_with_log` "Mirrors NAPI and UniFFI" = PHANTOM parity: method exists, SDK never calls it.

3. **KeyEpochAdvance leaf emitted on only 1 of ~4 epoch-advance paths.** Present: block_broadcast_subscriber (broadcast_helpers.rs:681). MISSING on: governance_ban_subscriber (governance_helpers.rs:932 rotated_authors), rotate_all_author_keys (:2840), unsubscribe_broadcast(rotate_keys=true) (broadcast_helpers.rs:205 — `UnsubscribeResult.key_rotations` doc SAYS "Callers use this to emit MemberLeft + KeyEpochAdvance" but field IGNORED = phantom-provenance doc), crypto.rotate_sender_key write-revoke/MLS-reset (:988/:2539). ADR-049 §191: "block_subscriber, governance_ban_subscriber, AND rotate_all_author_keys all ADVANCE the epoch." Single-pair `KeyEpochAdvancePayload{old,new}` also doesn't fit multi-author ban/unsubscribe (needs 1 leaf/author). Strict ≥1-producer bar met; semantic "record every epoch advance" bar NOT.

4. **Dead `revocation_cid.clone()`** (recovery.rs:989). TokenRevoked append (added 34e07e64e) removed by 64c1d28a3 (CORRECT — avoids dual-schema conflict w/ canonical JSON producer resolvers.rs:871/revoke.rs); clone left orphaned (revocation_cid now used only at :989).

5. Test gaps: NO test asserts `EventType::KeyEpochAdvance` durable leaf lands (all KeyEpochAdvance-named tests cover wire msg SenderKeyEpochAdvance/BroadcastKeyEpochAdvance). Media appends have only BRIDGE-level tests (call `_on`/`_with_log` directly → false confidence); no SDK-level test → unwired Py/Swift/Kotlin uncaught.

**CORRECT parts:** GovernanceDeadlockRecovery fully wired + genuine integration test (governance_integration.rs, field+ordering asserts). Payload schema fixes (KeyEpochAdvancedPayload→KeyEpochAdvance rename, missed_windows u32→Vec<(String,u32)>, Provenance doc JSON→MsgPack). session.rs serde aliases (lowercase bridge JSON round-trip). block-path old=new.saturating_sub(1) semantics.

## LESSON
When a PR adds an event-log append inside a "with_log"/`_on` bridge method, VERIFY THE SDK CALLS THAT EXACT METHOD. Failure mode: PyO3/UniFFI SDKs call a module-level FREE FUNCTION (`py_media_activate_session`/`fn_func_*`), so a new PER-INSTANCE `_with_log` method is dead. NAPI differs — its instance method pre-existed and TS already called it. Bridge-level tests (call the method directly) PASS while the SDK path records nothing. Grep the SDK wrapper's actual call target (`_bridge()` module vs instance; `fn_func_` vs `method_` in generated UniFFI bindings) before trusting "mirrors other bridges." Also: a "coverage audit" PR should enumerate ALL payload-struct-without-producer orphans — grep every `*Payload` struct → producer; AppBound/AppUnbound were missed.
