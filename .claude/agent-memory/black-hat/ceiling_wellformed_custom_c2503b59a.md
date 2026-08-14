---
name: ceiling-wellformed-custom-c2503b59a
description: Black-hat re-review of CapabilityCeiling well-formedness on fix/ceiling-wellformed-custom-enforcement at c2503b59a — delta over 8caf7fb62 is shared-helper extraction + msgpack-reject pin. NO BYPASS.
metadata:
  type: project
---

# Ceiling well-formedness re-review (c2503b59a, delta over 8caf7fb62) — NO BYPASS FOUND

Two commits on top of prior-clean 8caf7fb62:
- 8bd7499bb fix: enforce ceiling well-formedness by type, not caller-audit (already covered by 8caf7fb62 memory; native `#[serde(try_from)]` + WASM newtype).
- c2503b59a refactor: dedupe ceiling-validator charset prelude; pin msgpack reject.

## Verdict: invariant HOLDS. No CRIT/HIGH/MED/LOW. Refactor is behavior-preserving.

## What changed (native roles.rs)
- Extracted `validate_ceiling_entry_charset` (shared length-cap + control/whitespace/HTML-special prelude). Moved code is CHARACTER-IDENTICAL to the old inline block in `validate_ceiling_entry`. Probed: 256 accepted / 257 rejected for BOTH validators (shared prelude fires identically).
- Extracted `validate_custom_ceiling_entry` (single-colon, kebab resource, action=kebab|`*`). Identical to prior inline custom core. Colon-form path ordering preserved: charset → BUILTIN_CEILING_CATEGORIES exact → `tool:invoke:` prefix → custom core.
- NEW `pub fn validate_ucan_ceiling_string` (UCAN-form import validator) backed by `BUILTIN_CAPABILITIES` (18 enum variants). Rule 1 = exact match vs each variant's `ucan_capability_name()`; rule 2 = `tool_invoke:{id}` token; rule 3 = shared custom core (rejects underscore-resource customs since `_` not in kebab charset).
- `builtin_capabilities_list_is_exhaustive` test = exhaustive match → new enum variant is a compile error unless listed. Sound, bounded (positive whitelist).

## What changed (WASM manager.rs)
- `ceiling_strings` field type `HashSet<String>` → `ValidatedCeilingStrings` newtype (private `.0`, Deref-only NO DerefMut, 3 validating ctors + Default(empty) + cfg(test) test_insert).
- All 4 prod write sites route through ctors: 1612 create=from_colon_entries, 3455 modify=from_capabilities, 6458 import=from_ucan_strings, 1433/default=Default(empty). Export (5969) reads via Deref. NO `.0`/insert/remove/iter_mut/extend on `ceiling_strings` anywhere outside the impl. Type contained to manager.rs (grep -rln = only manager.rs).
- Lines 3676/3716 `capability_to_ucan_format` + `.insert/.remove` write to `suspended_capabilities` (DIFFERENT field), NOT ceiling — legitimately still used; not a ceiling bypass.
- Dead `build_ceiling_strings` deleted.

## Equivocation analysis (PROBED standalone via scp-protocol public validators)
- Colon-form vs UCAN-form built-ins are MUTUALLY EXCLUSIVE by spelling and that's BY DESIGN: `tool:invoke:*` colon-only, `tool_invoke:*` UCAN-only; `context:child:create` colon vs `context_child:create` UCAN. Import calls ONLY validate_ucan_ceiling_string → REJECTS colon-form built-ins (`tool:invoke:*`, `context:child:create`) so a non-canonical spelling the gate-check wouldn't match can't be stored. Correct.
- `bridging`: Capability::new("bridging")→Bridging→ucan_name "bridging:*" (explicit new() arm). WASM create stores bridging:* = native. bare `bridging` UCAN-validate=false but no honest exporter emits it. No DoS.
- underscore customs (`member_ban:x`, `custom_payments:approve`) rejected by BOTH (kebab forbids `_`) — closes prior WASM-create bug spelling.
- `a:b:c` → new() makes `a_b:c` BUT validate rejects `a:b:c` (multi-colon) on both paths before storage → `a_b:c` unreachable as stored entry.
- `messages:*` accepted by both (custom wildcard) → gate `in_ceiling` wildcard-widens to grant messages:read/write. This is CREATOR SELF-AUTHORITY (ceiling = creator's own max-authority bound), accepted identically on create+import. Pre-existing semantic, not introduced.
- INFO footgun UNCHANGED from 8caf7fb62: `custom:tool:invoke:*` → Capability::new strips custom: → Custom("tool:invoke:*") → validate_as_ceiling_entry(name "tool:invoke:*")=Ok → stored as privileged `tool_invoke:*`. Same on native+WASM create (convergent). Creator-self-authored, by-design.

## Gate-check (WASM in_ceiling @713): `contains(cap) || contains("{resource}:*")`. Literal+wildcard match on stored set; no parse ambiguity. Stored string == validated string.

## msgpack pin
- Native `#[serde(try_from)]` fires for rmp_serde array AND named (`to_vec`/`to_vec_named`) — new test `ceiling_deserialize_rejects_malformed_entry_msgpack` + embedded `ContextRoleState` reject test both pass.

## Tests run (all green)
- `cargo test -p scp-protocol --lib context::roles` = 118 passed (incl all new ceiling tests).
- `cargo test -p scp-runtime --test wasm_conformance --features testing` = 55 passed.
- `cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown --lib` = clean.

## lifecycle_helpers.rs delta = DOC-COMMENT ONLY (verified). Explicit `.ceiling().validate_entries()` re-validation calls in import_context + restore_context REMAIN — genuine guards for in-memory entry points (Supervisor::import_context / in-memory ContextPersistence providers hand back already-typed values not crossing serde). NOT redundant.

## Default safety: derive(Default) → empty inner set = trivially well-formed. from_ucan_strings(empty)→empty (over-restrictive/fail-safe, never over-broad).
