---
name: pr2235-app-bind-audit
description: PR #2235 (§8.4 AppBound/AppUnbound durable appends) review-pass-1 findings — bridge ceiling-source divergence, vacuous pipeline gate, non-atomic bind.
metadata:
  type: project
---

# PR #2235 — app_bind/app_unbind durable event-log appends (review pass 1)

Head `60ad49aac`, base `origin/main` `0179284d7`. Already-filed: #2230 (actor
routing), #2231 (persist declaration), #2232 (write-only bound_apps registry).

## Top findings (not covered by #2230/#2231/#2232)

1. **UniFFI reads the WRONG ceiling source.** `Scp::app_bind` derives the
   ceiling from `handle.ceiling_strings` (`crates/scp-ffi/uniffi/src/bridge.rs`
   ~15831). That field is a create-time snapshot and is **empty when the
   caller passes `ceiling: []`** — which the UniFFI `ContextParams` doc calls
   "no ceiling restriction" and which `build_ucan_context_state`
   (`uniffi/src/runtime.rs:1137`) and `ucan_mint` (`bridge.rs:5529`, #1419)
   both substitute with `default_ceiling()`. Result: every `appBind` on a
   default-ceiling Swift/Kotlin context fails `CeilingExceeded`. The correct
   source is `ucan_state.ceiling_strings` (used at bridge.rs 4373/4973/15458)
   or `QueriesCommand::ContextParams`.
2. **Stale ceiling everywhere.** No bridge re-syncs its cached ceiling on
   `ModifyCeiling` apply (`apply_pending_ceiling_modification` only dispatches
   to the actor). Bind can grant above the current, lowered ceiling.
3. **Role-cap source diverges.** UniFFI queries `QueriesCommand::GetRoleState`
   (authoritative); PyO3/NAPI read cached `st.role_state`, which is only
   re-synced by local governance ops — remote role changes are invisible.
4. **`unbind_app` has zero authorization.** Any caller, any `actor_did`.

## Recurring-pattern notes

- **Vacuous enforcement assertion inflating a ratchet.** New pipeline test
  `build_event_log_provider_absent_from_all_bridges` asserts a symbol that has
  **0 occurrences at base** in all three scanned files. The real anti-pattern
  is `event_log_provider_from_existing_repo` (napi/src/**runtime**.rs) and
  `bi.protocol_repository.event_log_provider()` (uniffi) — neither is checked,
  and runtime.rs is not in the scanned `*_SRC` set. It still counted toward
  MIN_ACTIVE_PIPELINE_ASSERTIONS 55→59. Always verify a new "absence"
  assertion could ever have failed on the pre-fix code.
- **Non-atomic durable-write-then-registry-mutate.** bind appends AppBound,
  THEN inserts into the in-memory registry; a concurrent close between the two
  makes the log claim a binding that no registry holds (and vice versa on
  unbind). Same shape as the earlier "registry mutated but log append failed"
  class.
- **Bridge JSON-casing change without updating the TS public interface.** NAPI
  `validate_capability_declaration_on` switched camelCase→snake_case for
  parity with PyO3/UniFFI, but `DeclarationValidationResult` in
  `bindings/typescript/src/context.ts:366` still declares
  `grantedCapabilities`/`appDid` → silent `undefined` for TS consumers.
- **API-shape divergence dodging the handle-affinity gate.** PyO3/NAPI take
  `context_id: String`; UniFFI takes `Arc<ContextHandle>`.
  `scripts/check-handle-affinity.sh` only fires on handle-typed params, so a
  raw-string context op is invisible to it by construction.
