# Slice1 #1877 — undisclosed §5.3.1.1 ceiling-validation removal (CRITICAL)

Branch `wasm/1877-slice1-adopt-context-role-state` (HEAD 3495c2062, parent c65552c9e).

Commit msg claims "pure state-representation refactor (no leaf/Merkle/event-count changes)"
for WASM adopting shared ContextRoleState. BUT the diff also DELETES the entire spec §5.3.1.1
ceiling-entry grammar validation subsystem from scp-protocol + all enforcement points —
undisclosed, out-of-scope, spec-violating.

## CRITICAL — ceiling well-formedness enforcement removed at every layer
Removed from roles.rs: validate_ceiling_entry / validate_as_ceiling_entry /
validate_ucan_ceiling_string / CeilingEntryError / CapabilityCeilingRaw (the `#[serde(try_from)]`
from-bytes invariant) / CapabilityCeiling::validate_entries / BUILTIN_CAPABILITIES list.
`set_ceiling` went from `Result<(),CeilingEntryError>` → infallible. `ContextRoleState::new`
no longer validates. Removed enforcement call sites:
- common/src/validate.rs validate_governance_action_strings ModifyCeiling arm (FFI boundary)
- lifecycle_helpers.rs create_context, import_context (ImportRejected — untrusted peer!),
  restore_context (on-disk corruption defense)
- builder.rs ContextCreationError::InvalidCeilingCategory, roles.rs RoleError::InvalidCeilingCategory
- Deleted regression tests: restore_rejects_malformed_ceiling_entry,
  governance_action_modify_ceiling_rejects_malformed_entry, the whole §5.3.1.1 test block.
Result: malformed ceiling entry (e.g. Custom("payments") no colon) flows through unchecked.

## CRITICAL — silent wildcard widening reintroduced
roles.rs Capability::ucan_resource_action no-colon Custom fallback reverted from concrete
`(name, name)` BACK to `(name, "*")`. Spec §5.3.1.1: "MUST NOT be silently interpreted as
`payments:*`... silent widening would defeat the legibility tenet." So Custom("payments") now
mints `scp:ctx:{id}/payments:*` (can:"*") — privilege widening. This is the exact bug PR #1884 /
ceiling-wellformed-custom-enforcement fixed; cleanly regressed here (diff base origin/main has
the validation). Spec §5.3.1.1 verified present in .docs/specs/05-contexts.md.

## HIGH — WASM ucan_string_to_capability missing `bridging:*` reverse mapping
manager.rs ucan_string_to_capability handles tool_invoke:* / tool_invoke:<id> /
context_child:create then defers to Capability::new. Capability::new on this branch NO LONGER
recognizes UCAN spellings (`"bridging:*"` arm deleted, was `"bridging" | "bridging:*"`).
Bridging.ucan_capability_name() == "bridging:*". Export emits to_ucan_string_set()="bridging:*";
import_context (line 6504) reverses via ucan_string_to_capability("bridging:*") → Custom("bridging:*")
NOT Capability::Bridging. CapabilityCeiling::contains is plain HashSet eq (only ToolInvoke/All
special-cased) → typed Bridging != Custom("bridging:*"). Any context with Bridging in ceiling:
export→import silently mutates Bridging → Custom("bridging:*"). String identity preserved (so
metadata/most string-path checks pass) but typed identity lost → a §12 bridge gate constructing
Capability::Bridging + check_ceiling fails. NEW to this slice (old WASM was string-only, no variant
identity). default_ceiling() has no Bridging so commit's "byte-equal default" claim holds — but
Bridging is a valid built-in.

## CLEAN (verified, no action)
- send_message write gate (~1904) + publish_broadcast gate (~5256): correct positive
  messages:write grant, suspension-aware, membership-first, is_author interplay fine, seq via
  entry().or_insert(0).
- FIX 5 apply_suspend_all → suspend_all_pub (replace semantics): suspend_all only inserts when
  member_capabilities has entry; empty → no-op, returns false; test is_none_or(is_empty) correct.
- FIX 2 import context_id inline: ContextRoleState::new(context_id.clone(),...), creator-admin
  tokens discarded via members/assignments/member_capabilities.clear() then rebuild from snapshot.
- cfg(test) helpers (member_has_capability_pub, suspended_capabilities_insert) — no non-test callers.
- scp-protocol compiles clean.
