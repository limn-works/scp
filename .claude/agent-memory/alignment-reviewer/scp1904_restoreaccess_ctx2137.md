---
name: scp1904-restoreaccess-ctx2137
description: SCP-1904 WASM RestoreAccess NothingToRestore guard + shared CTX-2137 — ALIGNED guard, but cross-bridge parity INCOMPLETE (UniFFI+NAPI still CTX-2001)
metadata:
  type: project
---

# SCP-1904 RestoreAccess NothingToRestore guard @ `e4374df28` (2026-06-27, part of #1877 native↔WASM convergence)

Commit `e4374df28` (+238/-0, 3 files): WASM `RestoreAccess` gains native's NothingToRestore guard; new shared `SCP-CTX-2137`.

**Guard parity: byte-identical, ALIGNED.** WASM handler (manager.rs:4216-4238) mirrors native `execute_restore_access` (governance_helpers.rs:1054-1070): same `nothing_suspended_for_request = suspended_for(did).is_none_or(|set| !caps.iter().any(|c| set.contains(c)))`, same `read_excluded`/`read_requested` carve-out `!(read_requested && read_excluded)`, same point (BEFORE mutation), same CTX_2137. Both sides operate on the SAME shared type `scp_protocol::context::roles::ContextRoleState` (`suspended_for`/`restore_capabilities`) — genuine parity, not reimplementation. Spec §5.9 (05-contexts.md:424) grounds it: "Restoring access for a member who was never revoked returns NothingToRestore." 3 production-path tests (reject / real-suspension clear / read-excluded carve-out).

**Native PyO3 code change: safe.** error.rs:450 adds `CE::NothingToRestore(_) => CTX_2137`; previously fell to `_ => CTX_2001` catch-all. NO pre-existing test/consumer asserted the old CTX_2001 for NothingToRestore (grep clean) — no break. New unit test error.rs:925.

**Why: convergence directive #1877 (native↔WASM); WASM previously cleared read-exclusion/re-minted with NO guard, diverging from native which rejected.**
**How to apply:** the guard itself is fully aligned. THE finding below is the only material gap.

## FINDING (material, cross-bridge parity incomplete)
Commit claims "dedicated SCP-CTX-2137 used by BOTH bridges." True for PyO3+WASM. But UniFFI (`uniffi/src/bridge.rs` ContextError match, ~1090-1180) AND NAPI (`napi/src/error.rs` ~205-285) BOTH route governance through the runtime `dispatch_governance_command` → `execute_restore_access` → produce `ContextError::NothingToRestore`, and BOTH lack a `CE::NothingToRestore` arm → still fall to `_ => CTX_2001`. So Swift/Kotlin/Node-TS still surface the generic CTX_2001 for the exact error PyO3+WASM now surface as CTX_2137. The convergence is 2-of-4 bridges. To fully close #1877's intent: add `CE::NothingToRestore(_) => CTX_2137` to uniffi/src/bridge.rs and napi/src/error.rs (+ a unit test each, mirroring the PyO3 `nothing_to_restore_surfaces_ctx_2137` and the sibling CTX_2134/2135/2136 arms already present in both files).

## Clean
- CTX_2137 in valid 2000-2999 CTX range; no collision (check-error-codes.sh phase-2); placement after 2001 catch-all / before 2100 block matches existing 2134/2135/2136 convention.
- `is_none_or` MSRV fine (used across scp-runtime/scp-protocol).
- Scope tight: only WASM bridge handler + shared error code + PyO3 mapping. No governance-engine / unrelated changes.
- No new #NNNN issue-refs in source.
