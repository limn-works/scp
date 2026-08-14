# Ceiling well-formedness construction+deserialize invariant (8caf7fb62) — CLEAN, ZERO findings

worktree /private/tmp/scp-ceiling, branch fix/ceiling-wellformed-custom-enforcement, HEAD 8caf7fb62
(atop c4660606f grammar-enforce + 0a87e4ac2 docs #1882). Spec §5.3.1.1. 3 files: roles.rs (+392), wasm manager.rs (+431), lifecycle_helpers.rs (+37 COMMENT-ONLY).

## What the fix does
Makes a malformed CapabilityCeiling UNREPRESENTABLE on every from-bytes path.
- NATIVE: `CapabilityCeiling` gains `#[serde(try_from = "CapabilityCeilingRaw")]`. Private `CapabilityCeilingRaw` mirror (no validation) is the only serde waypoint; `TryFrom` runs `validate_entries()` and rejects whole deser on first malformed entry. Propagates through ANY embedding struct (ContextRoleState → signed export snapshot decoded by `rmp_serde::from_slice` in `deserialize_export`). `CapabilityCeiling::new()` still does NOT validate (validation at write/deser boundary); whole-ceiling writers ContextRoleState::new/set_ceiling validate.
- WASM (ADR-034, stores UCAN strings not enums): new `ValidatedCeilingStrings(HashSet<String>)` newtype, private inner, Deref→&HashSet (read-only, no DerefMut). 3 validating ctors: from_colon_entries (create), from_capabilities (modify), from_ucan_strings (import). `build_ceiling_strings` DELETED.

## New grammar fn: `validate_ucan_ceiling_string` (roles.rs)
UCAN-form (`tool_invoke:*`, `context_child:create`) counterpart to colon-form `validate_ceiling_entry`. Same sanitization (len/control/whitespace/HTML). Accepts iff EXACTLY ONE of: (1) exact match a BUILTIN_CAPABILITIES `.ucan_capability_name()`; (2) `tool_invoke:{id}` w/ is_tool_id_token; (3) custom via shared `validate_custom_ceiling_entry` (extracted core, single colon, kebab resource, action=kebab|literal `*`). Rule 3 calls custom core DIRECTLY not validate_ceiling_entry → colon-form built-ins (`tool:invoke:*`) REJECTED on import (forces canonical UCAN stored vocabulary; rejecting non-canonical = NARROWER/fail-closed not broader). BUILTIN_CAPABILITIES exhaustiveness pinned by compile-match test (18 variants).

## All 6 audit concerns — VERIFIED CLEAN
1. Untrusted from-bytes paths fail-closed: native rmp_serde/serde_json deser CANNOT materialize malformed ceiling (try_from). WASM import (`snap.ceiling_strings: Vec<String>` plain unvalidated from serde_json::from_slice) routed through from_ucan_strings BEFORE the single PerContextState build (manager.rs:6450→6458). Runtime explicit validate_entries() at lifecycle_helpers.rs:1788 (import, ImportRejected) + 2410 (restore, PersistenceFailed) are GENUINE belt-suspenders for the IN-MEMORY boundary: Supervisor::import_context (supervisor.rs:7966) takes a `ContextExport` VALUE (no serde) — a programmatic export w/ Custom("payments") in the set bypasses try_from; 1788 catches it. NOT redundant, NOT false security.
2. from_ucan_strings rejects malformed AND non-canonical colon-form (test: payments/*:*/a:b:c/custom_payments:approve/tool:invoke:*/context:child:create all Err VALID_7000). Closes BLACK-005 (import previously raw-copied ceiling_strings).
3. WASM ModifyCeiling fail-closed ordering CORRECT: from_capabilities(new_ceiling)? FIRST (no ctx touch), then require_active_context_mut, then policy check, THEN ctx.ceiling_strings=validated. Any Err short-circuits before mutation → prior ceiling unchanged. No TOCTOU introduced (validation is stateless).
4. Error msgs echo only capability name + grammar reason. Ceiling entries are PUBLIC opt-in contract (§5.7), not secrets. control/HTML sanitization prevents log-injection via echoed entry. OK.
5. Type-level guarantee SOUND: enumerated ALL ceiling_strings write sites — 1433 default, 1612 from_colon_entries, 3455 from_capabilities, 6458 from_ucan_strings; .0.insert only in cfg(test) test_insert. Private inner + Deref-only. No prod bypass.
6. Native try_from is colon-form-consistent: Capability derives serde-enum (Custom("payments") → {"Custom":"payments"}); validate_entries→validate_as_ceiling_entry→validate_ceiling_entry(self.name()) where Custom name() = raw (no custom: prefix) → custom grammar rejects no-colon. Consistent w/ construction-time grammar.

## Cross-bridge consistency
Native export = to_ucan_string_set() = ucan_capability_name() per entry = exact form from_ucan_strings accepts. WASM export now always-canonical (all 3 ctors). WASM create custom:payments:approve → Custom("payments:approve") → payments:approve (NOT old raw custom_payments:approve), matches native. 3 ctors converge (test_wasm_ceiling_constructors_converge_on_canonical_form).

## Tests
scp-protocol roles: 117 pass (new builtin_exhaustive, ucan_string accept/reject, deser accept-roundtrip, deser reject-malformed, ContextRoleState embed-reject). scp-ffi-wasm: 16 ceiling tests pass.

ZERO findings, all 4 categories.
