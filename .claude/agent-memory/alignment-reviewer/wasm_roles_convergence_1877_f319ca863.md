---
name: wasm-roles-convergence-1877-f319ca863
description: ALIGNED review of WASM context-export role-state convergence (#1877 slice1-roles, commit f319ca863) — embeds shared ContextRoleState verbatim, closes BLACK-CEIL-01; next-slice = MembershipState sidecar
metadata:
  type: project
---

# WASM role-state convergence @ `f319ca863` (branch slice1-roles) — ALIGNED, 0 blocking

Part of #1877 native↔WASM convergence program. Owner directive (verbatim): "WASM should ONLY reimplement things that depend on async/tokio — when it MUST. Share everything we can... even if it means doing away with recent work."

**What it does (WASM-only, 1 file, +420/-239):** `crates/scp-ffi/wasm/src/manager.rs` export/import. Replaced a lossy FLAT role-state snapshot projection (`creator_did`+`ceiling_strings`+`members:Vec<WasmExportMember>`+`suspended_capabilities`) + a `system_assign_role` RECOMPUTE-on-import with the shared typed `scp_protocol::context::roles::ContextRoleState` carried in the snapshot and restored VERBATIM (`let role_state = snap.role_state.clone();`). Deleted `WasmExportMember`, `validate_imported_ceiling_strings`, the 3 flat array sorts in `canonicalize_snapshot_sets`.

**BLACK-CEIL-01:** old recompute re-ran `system_assign_role` per member vs the imported ceiling → re-granted a SuspendAccess'd-then-ceiling-widened member the widened cap (`member_has_capability` false→true across round-trip). Verbatim restore fixes it. Load-bearing regression `import_does_not_un_suspend_capability_widened_after_suspension` (mutation-verified RED with old loop).

**Native parity verified (this is the alignment crux):**
- native `lifecycle_helpers::import_context` (crates/scp-runtime/src/context/lifecycle_helpers.rs) does `role_state: export.snapshot.role_state` at :2074 — verbatim, no recompute. WASM now matches.
- §5.3.1.1 ceiling-grammar belt: native calls `role_state.ceiling().validate_entries()` at lifecycle_helpers.rs:1786-1793 with CTX-2032 envelope + "signature authenticates origin not well-formedness" rationale. WASM now mirrors exactly.
- shared `ContextRoleState` (crates/scp-protocol/src/context/roles.rs:1372) self-canonicalizes the signed digest via `serde_sorted_set`/`serde_sorted_set_map` codecs (inner sets sorted, outer maps JCS-keyed) + `#[serde(try_from="CapabilityCeilingRaw")]` rejects malformed ceiling at deserialize (roles.rs:478,632). So dropping WASM's explicit sorts is sound.
- Correctly DECLINED to add member_capabilities∩ceiling intersection on import (native does none; adding = NEW divergence).

**Direction is correct under ADR-034:** REMOVES a WASM reimplementation (good); WASM may only reimplement what async/tokio forces.

**Next-slice misalignment (LOW/informational, anticipated, NOT a defect):** native's signed `ContextSnapshot` (crates/scp-runtime/src/context/state.rs:600-603) carries TWO shared typed fields restored verbatim — `role_state: ContextRoleState` AND `membership: MembershipState`. Per-member MLS sequence counter is `MemberInfo.sequence_number` (crates/scp-protocol/src/context/membership.rs:116), a first-class field of shared `MembershipState`. WASM still keeps these in a FLAT `member_sequence_numbers: HashMap<String,u64>` sidecar. So after this commit role-state half is converged, membership/sequence half is not. Convergent end-state = WASM carries shared `MembershipState` verbatim, kill the sidecar. Recommended as #1877 slice 2. Correctly out-of-scope here; correctly NOT forced into ContextRoleState (no home for seq there).

**LESSON (reusable for the rest of #1877 slices):** the canonical convergence shape = carry the shared scp-protocol type in the WASM snapshot, restore verbatim, keep ONLY genuinely-async/WASM-local orchestration state as a thin sidecar. To assess a slice: (1) find the native snapshot field(s) for that domain in state.rs `ContextSnapshot`; (2) confirm native restores them verbatim in lifecycle_helpers import; (3) confirm WASM now carries the SAME shared type, not a flat projection; (4) check the shared type's serde codecs handle digest canonicalization so WASM's `canonicalize_snapshot_sets` sorts can be dropped; (5) the leftover flat sidecars name the NEXT slice. See sibling [[standing_pair_not_a_saga_v3_5a5f7f275]] for the docs-side of native/WASM convergence framing.
