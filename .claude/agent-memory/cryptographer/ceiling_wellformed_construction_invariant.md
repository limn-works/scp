---
name: ceiling-wellformed-construction-invariant
description: Review of fix/ceiling-wellformed-custom-enforcement (8caf7fb62→c2503b59a) — malformed CapabilityCeiling made unrepresentable; SOUND/APPROVE
metadata:
  type: project
---

# Ceiling well-formedness as a construction+deserialization invariant (§5.3.1.1)

Branch fix/ceiling-wellformed-custom-enforcement, delta 8caf7fb62→c2503b59a (HEAD c2503b59a). VERDICT: SOUND, APPROVE, no blocking findings. Builds on [[ceiling_entry_grammar]] (PR #1884).

**Why:** closes the residual from the prior ceiling-grammar work where ModifyCeiling/import/deserialize paths could still materialize a malformed/over-broad ceiling. Now malformed is unrepresentable by the TYPE.

**Native (scp-protocol/src/context/roles.rs):**
- `CapabilityCeiling` gets `#[serde(try_from = "CapabilityCeilingRaw")]`. Raw mirror (private, Deserialize-only, same `serde_sorted_set` field attr → decode parity) → `TryFrom` runs `validate_entries()` → rejects malformed at deserialize. Original field's `#[serde(with)]` now drives serialize only (try_from overrides decode); serialize unchanged → signed-export digest byte-stable.
- Propagates through every embedder: `ContextRoleState.ceiling: CapabilityCeiling` (the validating type) → any serde_json/rmp_serde decode of a ContextRoleState / signed export snapshot routes through TryFrom. Native by-bytes path CLOSED by construction.
- Write paths intact: `ContextRoleState::new` (validate_entries), `set_ceiling` (validate_entries before store), `TryFrom` (validate_entries). `CapabilityCeiling::new` deliberately UNCHECKED (its output must still cross a write/deserialize boundary). No raw `.ceiling =` assignment exists outside new/set_ceiling.
- `validate_ceiling_entry_charset` EXTRACTED: byte-identical to prior head of validate_ceiling_entry (len-cap MAX_CEILING_ENTRY_LENGTH + is_control + is_whitespace + HTML-special `< > & " '`). `validate_custom_ceiling_entry` EXTRACTED: byte-identical to prior tail (exactly-one-colon, kebab resource, action kebab|`*`). Both verified via git show base vs HEAD. NO weakening, NO divergence.
- New `validate_ucan_ceiling_string` (UCAN/import form): charset prelude FIRST (shared), then exactly-one-of: (1) BUILTIN_CAPABILITIES exact ucan_capability_name match (18 non-parameterized built-ins, exhaustive-match test pins the list), (2) `tool_invoke:{tool_id}` non-`*` token, (3) `validate_custom_ceiling_entry` (a valid custom is single-colon so colon-form==UCAN-form byte-identical). Rule 3 calls custom core DIRECTLY (not validate_ceiling_entry) → deliberately REJECTS colon-form built-ins (`tool:invoke:*`, `context:child:create`) on import so stored vocab stays strictly canonical UCAN form. SOUND.

**WASM (scp-ffi/wasm/src/manager.rs, ADR-034 — stores UCAN strings not Capability enums, no native ceiling type):**
- New `ValidatedCeilingStrings(HashSet<String>)` newtype. Private inner; Deref→&HashSet<String> (read-only, no DerefMut); only 3 validating constructors + `#[cfg(test)] test_insert`. No production `.0` mutation, no direct `.insert` on ceiling_strings (grep-verified: only hit is line 385 inside cfg(test) test_insert). `ceiling_strings_pub`/reads drop-in via Deref.
- create → `from_colon_entries` (Capability::new parse → validate_as_ceiling_entry → ucan_capability_name format). modify(ModifyCeiling) → `from_capabilities` (validate_as_ceiling_entry → ucan_capability_name), validates WHOLE replacement BEFORE mutation (fail-closed, prior ceiling unchanged on bad entry). import → `from_ucan_strings` (validate_ucan_ceiling_string, store verbatim). WASM snapshot field is `Vec<String>` (no native validating Deserialize on WASM) so import re-validation is the SOLE WASM enforcement — correctly wired (closes BLACK-005).
- Canonical convergence confirmed end-to-end: `custom:payments:approve` → Capability::new strips `custom:` → Custom("payments:approve") → ucan_resource_action rsplit_once(':')→("payments","approve"), resource.replace(':','_') no-op → ucan_capability_name = `payments:approve` on BOTH native and WASM. Old build_ceiling_strings raw-string bug (`custom_payments:approve`) DELETED. 3 convergence/parity tests assert create==modify==import==native.

**Tests:** native — exhaustive built-in list, ucan-validator accept/reject (incl colon-form-builtin reject), JSON deserialize accept-roundtrip + reject-malformed, rmp_serde reject in BOTH to_vec(array)+to_vec_named(named) + good roundtrip, ContextRoleState embedder propagation. WASM — create canonical parity, import accept/reject, 3-constructor convergence. Property 3 (validating Deserialize fires for JSON+msgpack array+named) HOLDS and is correctly tested.

**Residual (NON-blocking, pre-existing, noted by [[ceiling_entry_grammar]]):** native ModifyCeiling execute/apply enforcement-consistency gap is a separate concern; this change is about representability, not the governance apply path. No new path to materialize malformed/over-broad ceiling found (native construct/deserialize/embedded; WASM create/modify/import/Deref).
