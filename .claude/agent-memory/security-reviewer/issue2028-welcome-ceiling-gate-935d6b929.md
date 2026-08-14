---
name: issue2028-welcome-ceiling-gate-935d6b929
description: Security review of #2028 F5 (fail-closed Welcome seam on stale genesis ceiling) — gate is sound, but the ceiling lowering has NO authorization effect anywhere else
metadata:
  type: project
---

# #2028 F5 — `check_genesis_ceiling_covered_by_live` (935d6b929, branch `fix/2028-f5-welcome-join-ceiling`)

## What the fix does
`crates/scp-runtime/src/context/state.rs:2117` adds `check_genesis_ceiling_covered_by_live(genesis: &[Capability], live: &CapabilityCeiling, site)`.
Called from two places:
- `PerContextState::add_member` (`actor/state.rs:2561`) — first statement, ahead of the MLS add and ahead of the `cfg!(test/testing)` no-crypto return. Reject-before-mutate.
- `Supervisor::invite_member` step 1b (`supervisor/supervisor.rs:13099`) — reads live role state via `get_role_state` (None ⇒ fail-closed `InvalidState`).
`relabel_add_member_error` (`governance_helpers.rs:1245`) passes `InvalidState` through; everything else still flattens to `MembershipFailed`. `add_member`'s only other error is `CryptoFailed`, so the relabel is precise.

## Verified sound
- Chokepoint holds in `scp-runtime`: every Welcome comes from `PerContextState::add_member_from_bytes`; the three callers (`execute_add_member`, `join_context` lifecycle_helpers:1025, `execute_reset_member`) all route through the gated `add_member`.
- No false positive on normal paths: create (`lifecycle_helpers:1616`), Welcome-joiner (`supervisor.rs:14170`), import + restore (`lifecycle_helpers:2370/3266/3530`) all pair role_state ceiling with the SAME params ceiling. `strip_snapshot_for_public` (export_import.rs:695) DOES pair `default_ceiling()` with genesis params — but `import_context` rejects non-`Full` scope, so it is unreachable.
- Predicate is never laxer than the authorization check: `CapabilityCeiling::contains` covers `OutletQueryAll ⊇ OutletQuery(id)`, `OutletCallAll ⊇ OutletCall(id)`; it is exact-match for `Custom`, i.e. STRICTER than `CapabilityUri::is_within_ceiling` (capability.rs:214-220), which honors `{resource}:*`.
- Not a nullifier: it returns a typed `Err`, does not log-and-continue.

## The residual that matters (bigger than the fix)
- `ModifyCeiling` NEVER propagates. `classify_action` ⇒ `MlsImpact::NoMlsChange` (`mls_integration.rs:99`), no transport send, `decrypt_and_dispatch` has no governance arm, `CeilingModified` Merkle leaf has ZERO consumers. Only production `set_ceiling` writer is `governance_helpers.rs:489`.
- `apply_pending_ceiling_modification` is host-app-driven with a CALLER-SUPPLIED `current_timestamp` — the §5.3.2 72h window is caller-controlled.
- The FFI `ceiling_strings` cache (the ceiling UCAN mint/delegate/outlet-invoke actually authorize against — `scp-ffi/src/outlets.rs:370`, `napi/src/ucan.rs:315/425`) is written ONLY at create (`runtime.rs:1559`) and join (`sync_ceiling_from_params`, `runtime.rs:1792`), both from GENESIS params. No bridge `apply_pending_ceiling_modification` re-syncs it — violating `crates/scp-ffi/CLAUDE.md` §Gotchas "Role state sync after governance" which names ModifyCeiling explicitly.
⇒ After a governed lowering the revoked capability is still fully usable by every existing member INCLUDING the lowering node. The fix seals new joins only.

## Root-cause fix that exists but wasn't taken
The joiner cross-checks the bundle ceiling against the MLS-committed `0xFF02` `ceiling_hash` (`lifecycle_helpers.rs:2063` → `group_context_extension.rs:429`), so sealing the LIVE ceiling into the bundle is genuinely blocked. But openmls 0.8 supports a GroupContextExtensions commit; re-committing `0xFF02` on ModifyCeiling apply would propagate the lowering cryptographically to all members AND rebind the hash. `scp-mls/src/context_extension.rs:52-55` records a deliberate choice to avoid that machinery.

## Test gap
All three new tests (`spawn_from_welcome_tests.rs:3387/3544/3625`) drive `invite_member`, which refuses at the front door first. Deleting the in-actor `add_member` gate leaves all three GREEN. The paths only that gate covers (SDK `propose_governance_action(AddMember)` on a voting-governed context, `join_context`, `execute_reset_member`) are untested.

## Adjacent in-flight branch
`fix/ceiling-modify-reconcile` (abdc11d80/3afb1ae06/1620de983) rewrites `apply_pending_ceiling_modification` to reconcile role/member capabilities. NOT an ancestor of this branch. The F5 test fixture rationale ("role definitions are not reconciled when set_ceiling lowers") is premised on the pre-reconcile behavior.
