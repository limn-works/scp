---
name: wasm-1877-role-state-double-validation
description: WASM ceiling import validation across two designs — #1877 string-wire (string check load-bearing) vs f319ca863 typed-enum-wire (string check correctly DELETED, no longer load-bearing)
metadata:
  type: project
---

WASM Slice 1 (`crates/scp-ffi/wasm/src/manager.rs`) adopts shared `scp_protocol::context::roles::ContextRoleState`, deleting the flat `MemberEntry`/`ceiling_strings`/`suspended_capabilities`/`creator_did` reimplementation.

**The wire representation determines whether a string-level import check is load-bearing — this flipped between two designs:**

DESIGN A (#1877, earlier): import carried `ceiling_strings: Vec<String>` and rebuilt the ceiling via `ucan_string_to_capability` == `Capability::new`, which is LOSSY: it maps BOTH `"tool:invoke:*"` (colon) and `"tool_invoke:*"` (UCAN) to the SAME `ToolInvokeAll` variant. After that parse a non-canonical colon-form built-in is indistinguishable from canonical UCAN form, so ONLY a STRING-level check BEFORE the parse (`validate_imported_ceiling_strings`) could reject it (BLACK-005). Under Design A the string check was load-bearing and must NOT be dropped.

DESIGN B (commit f319ca863, "restore ContextRoleState verbatim on import", BLACK-CEIL-01): import now carries the typed `ContextRoleState` → `CapabilityCeiling` → `HashSet<Capability>` over the wire using the DEFAULT serde enum repr (built-ins as `"ToolInvokeAll"`, data variants as `{"Custom":"..."}`). `Capability::new`/`ucan_string_to_capability` is NO LONGER on the import path. A malicious peer's only colon-smuggle avenue is `{"Custom":"tool:invoke:*"}`, which deserializes to `Capability::Custom("tool:invoke:*")` — a DISTINCT variant from `ToolInvokeAll`; gate checks match the enum variant, so it grants nothing (no aliasing). So under Design B the `validate_imported_ceiling_strings` string check is CORRECTLY DELETED — the lossy-parse aliasing it guarded against cannot occur. Grammar is enforced two ways: (1) `#[serde(try_from = "CapabilityCeilingRaw")]` runs `validate_entries()` at deserialize time; (2) an explicit `role_state.ceiling().validate_entries()` belt in `import_context`.

**The `validate_entries()` belt is NATIVE PARITY, not redundancy to cut:** `crates/scp-runtime/src/context/lifecycle_helpers.rs` import_context (~line 1769) runs the IDENTICAL `role_state.ceiling().validate_entries()` belt on the already-deserialize-validated snapshot. Native also consumes `role_state: export.snapshot.role_state` verbatim (line 2074). WASM converged to native exactly. Keep the belt: matching native's defense-in-depth across bridges is the higher-order invariant, and the cost is ~8 lines.

**How to apply:** Do NOT cite the old #1877 "string check is load-bearing" conclusion against Design-B code — it was true ONLY for the string-wire format. Under the typed-enum wire, deleting the string check is correct. If a future change reverts the wire to carry UCAN strings + `Capability::new`-parse on import, the load-bearing string check must come back.

**Two more facts from the same slice (manager.rs HEAD 4babda7ba):**

1. `member_sequence_numbers: HashMap<String,u64>` is an INTENTIONAL sidecar, NOT over-engineering. It's MLS encryption state (next outgoing message seq per sender), not role state, so it has no home in `ContextRoleState`. Documented interim until WASM adopts shared `MembershipState`/`MemberInfo.sequence_number` (deferred convergence follow-up). It's the minimal flat representation — nothing to cut.

2. KNOWN behavioral divergence (NOT a simplifier-lane fix, flag for bug-catcher/alignment): WASM `leave_context` (manager.rs ~1962-1968) clears the leaving member's suspended set via `restore_capabilities`; native (`lifecycle_helpers.rs:306-311`, `governance_helpers.rs:1045-1047`) does NOT — leaves a dangling `suspended_capabilities` entry (phantom suspension on same-DID re-admit). There is NO shared `ContextRoleState::remove_member` helper; BOTH native and WASM hand-roll the multi-field removal (members/assignments/member_capabilities ± suspended). The convergent fix is a shared `remove_member` helper both call — that would also delete the pre-existing native/WASM duplication. WASM is arguably the *more correct* of the two here.

The `validate_ceiling_capabilities` boundary call on the **ModifyCeiling governance path** (manager.rs ~3676) takes already-TYPED `Capability` enums (from deserialized `GovernanceAction`), and `set_ceiling` re-validates the same input — but `Capability::Custom(String)` deserializes WITHOUT grammar enforcement, so this is NOT a redundant re-check of a type-system guarantee; its marginal value is canonical `SCP-VALID-7000` error-surface parity (acceptable belt, not BLOCKER class).
