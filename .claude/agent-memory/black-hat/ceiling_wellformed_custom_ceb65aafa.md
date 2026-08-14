---
name: ceiling-wellformed-custom-ceb65aafa
description: Black-hat creative-angle re-attack of CapabilityCeiling well-formedness on fix/ceiling-wellformed-custom-enforcement at HEAD ceb65aafa — rehydration/replication, snapshot consumers, nesting, divergence, transmute/serde-skip all CLEAN. INVARIANT HOLDS.
metadata:
  type: project
---

# Ceiling well-formedness FINAL creative re-attack (ceb65aafa) — INVARIANT HOLDS, NO BYPASS

HEAD delta over prior-clean c2503b59a = ONE commit (ceb65aafa), WASM-only, refactor:
extracts `ValidatedCeilingStrings::validation_error(e)` assoc-fn shared by all 3 ctors
(from_colon_entries/from_capabilities/from_ucan_strings). Behavior-identical: same
SCP-VALID-7000, same e.to_string(), same insert order. Plus doc reword on the newtype
(native stores Capability enums per ADR-034; convergent property = ucan_capability_name
string projection, not in-memory repr). ZERO new surface. Prior c2503b59a verdict carries.

## Five creative angles hunted (beyond orchestrator's mechanics check) — ALL CLEAN

1. REHYDRATION/REPLICATION/RESTORE: native export/import = rmp_serde::from_slice into
   StoredValue<ContextExport> → ContextSnapshot → ContextRoleState → typed `ceiling:
   CapabilityCeiling` → serde try_from → validate_entries. Malformed ceiling can't
   deserialize. No raw Vec<String>/HashSet<String>/Raw-struct rehydration into native
   live state. WASM restore_context/restore_all_contexts HARD-ERROR (ADR-034 ephemeral,
   manager.rs:6733/6749) — no localStorage rehydrate path.

2. SNAPSHOT ROUND-TRIP (WASM raw Vec<String>): export snapshot WasmContextExportSnapshot
   .ceiling_strings is raw Vec<String> (manager.rs:6950). Deserialized EXACTLY ONCE from
   untrusted bytes (serde_json::from_slice @6128 in deserialize_and_verify_envelope). The
   ONLY consumer turning it live = import_context @6453 `from_ucan_strings(&snap
   .ceiling_strings)?` fail-closed, assigned @6461. No alternate write. ContextMetadata
   .ceiling (6769) is export-only read. Closes BLACK-005 (old raw copy).

3. nesting.rs new() WITHOUT validate_entries: compute_ceiling_intersection @nesting.rs:625
   uses CapabilityCeiling::new(intersection) NO validate — SOUND: intersection ⊆ already-
   validated parent ceilings, validity closed under subset. ContextNesting::new @414 stores
   child_ceiling directly NO validate — SOUND: type-guaranteed validated at construction
   (pub(crate) inner set ⇒ a CapabilityCeiling only obtainable via validating path). ParentRef
   .ceiling is `pub CapabilityCeiling` but inner capabilities pub(crate) ⇒ can't cross-crate-forge.

4. NATIVE↔WASM DIVERGENCE (PROBED, ran): native custom:payments:approve → Custom("payments:
   approve") → ucan_name "payments:approve"; WASM import validate_ucan_ceiling_string
   ("payments:approve")=ok ⇒ CONVERGENT. bridging → native ucan_name "bridging:*";
   import validate("bridging:*")=ok, validate("bridging")=false (no honest exporter emits
   bare bridging) ⇒ convergent, no DoS. INFO footgun UNCHANGED & CONVERGENT: deserialize
   Custom("tool:invoke:*") passes try_from + projects to privileged tool_invoke:* (NOT
   == ToolInvokeAll enum, but same ucan string ⇒ same gate authority); custom:tool:invoke:*
   via new() strips custom: → Custom("tool:invoke:*") → tool_invoke:* identically. This is
   creator-self-authored max-authority bound, by-design, present on BOTH native+WASM.

5. unsafe/transmute/serde-skip/manual-Deserialize: NONE. CapabilityCeiling = #[serde(
   try_from="CapabilityCeilingRaw")] (TRY_from, NOT from); Raw is private Deserialize-only
   waypoint, no code constructs/stores it. Capability enum = plain derive Deserialize, inner
   strings (Custom/ToolInvoke) carried VERBATIM (no normalization laundering) → reach
   validate_entries→validate_as_ceiling_entry. capabilities_mut/ceiling_mut/test_insert all
   cfg(test|testing)-gated out of prod.

## Probe (added cz4_probe test, ran, REVERTED — worktree pristine)
serde_json deserialize Custom("*:*")/Custom("payments")=Err (try_from rejects); existing
ceiling_deserialize_rejects_malformed_entry{,_msgpack} cover JSON+msgpack array+named.
2 passed. Reverted via git checkout; git status clean.

## VERDICT: malformed CapabilityCeiling (native) / malformed live ceiling_strings (WASM)
is UNREPRESENTABLE by construction. Type-level invariant genuinely holds. No CRIT/HIGH/MED/LOW.
