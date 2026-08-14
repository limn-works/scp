---
name: ceiling-grammar-pr1884
description: PR #1884 ceiling-wellformedness invariant — BLACK-001..004 closed; BLACK-005 (WASM import path) still bypasses grammar validation, the native↔WASM asymmetry the PR's own native fix calls out.
metadata:
  type: project
---

# PR #1884 ceiling well-formedness construction invariant

Branch `fix/ceiling-wellformed-custom-enforcement`. Goal: "a malformed CapabilityCeiling can never be stored" on EVERY path. `ContextRoleState::set_ceiling` made fallible (validates whole replacement via `CapabilityCeiling::validate_entries` → per-entry `Capability::validate_as_ceiling_entry`, fail-closed leaves prior unchanged).

## Re-attack verdict (HEAD 8caf7fb62)

- **BLACK-001 (native ModifyCeiling)**: CLOSED. `execute_modify_ceiling` validates each proposed entry (`validate_as_ceiling_entry`) at propose/stage time (governance_helpers.rs ~1552); apply (`apply_pending_ceiling_modification`) goes through `set_ceiling`. Propose-form == apply-form (both `validate_as_ceiling_entry`), so no propose/apply divergence. FFI boundary also covered by common `validate_governance_action_strings` ModifyCeiling arm.
- **BLACK-002 (WASM ModifyCeiling + divergence)**: CLOSED for the governed-modify path. `dispatch_modify_ceiling` validates each entry before store; stored form `capability_to_ucan_format(name())` == native `ucan_capability_name()` for valid single-colon customs.
- **BLACK-003 (validate vs enforce mismatch)**: CLOSED. All 4 native bridge create-paths + WASM create-path validate the PARSED enum `Capability::new(raw).validate_as_ceiling_entry()` (strips `custom:` prefix), so `custom:payments` → `Custom("payments")` is rejected consistently.
- **BLACK-004 (native import/restore)**: CLOSED. `import_context` (lifecycle_helpers.rs ~1766) and `restore_context` (~2388) re-validate `role_state.ceiling().validate_entries()` after deserialize; reject with ImportRejected / PersistenceFailed. Rationale in-code: "a valid signature authenticates ORIGIN, not WELL-FORMEDNESS."

## BLACK-005 — NEW BYPASS (still open). Severity HIGH.

WASM `WasmContextManager::import_context` (crates/scp-ffi/wasm/src/manager.rs ~6211) copies `ceiling_strings: snap.ceiling_strings.iter().cloned().collect()` (line ~6346) from a deserialized, signed-but-untrusted peer snapshot into stored `PerContextState.ceiling_strings` with NO grammar validation. The import body validates context_id, DIDs, member roles, state, protocol version, anti-replay — NOT ceiling entries. Only `validate_as_ceiling_entry` calls in the WASM manager are create_context (~1465) and dispatch_modify_ceiling — import was missed.

Exported live as `#[wasm_bindgen] context_import` (context.rs ~1856 → manager import_context). Envelope verify requires `exporter_did == creator_did` + valid Ed25519 sig over JCS snapshot — i.e. attacker need only be the legitimate CREATOR of their own context (trivial). This is the EXACT untrusted-peer threat the PR's native import fix calls out, NOT mirrored to the WASM reimplementation (ADR-034 separate manager).

Impact: native importer REJECTS a malformed-ceiling export; WASM importer ACCEPTS + registers it → native↔WASM split-brain on context existence + authorization envelope (the cross-impl convergence invariant the whole PR exists to protect). WASM `in_ceiling` (manager.rs ~562) does exact-string + `{resource}:*` wildcard match, so the stored malformed strings also feed authorization checks divergently.

Fix: add per-entry `Capability::new(s).validate_as_ceiling_entry()` over `snap.ceiling_strings` in WASM import_context before building PerContextState, returning Validation/Context error — mirroring native lifecycle_helpers import guard + the WASM create-path check.

## Key structural note for future re-attacks
`set_ceiling` is the only PRODUCTION whole-ceiling write on native (field `ContextRoleState.ceiling` is `pub(crate)`; `ceiling_mut` is test-only-gated). BUT serde `Deserialize` is a second write path that bypasses `set_ceiling` — so EVERY deserialize-then-store site (native import/restore, WASM import) must re-validate. Native covers all 3; WASM import is the gap. `BroadcastContextSnapshot` carries no ceiling (not a write path).
