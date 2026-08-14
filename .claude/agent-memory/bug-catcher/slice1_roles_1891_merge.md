---
name: slice1-roles-1891-merge
description: CLEAN review — #1877 WASM role-state slice rebase over #1891; typed Capability suspension supersedes string-canonicalization fix by construction
metadata:
  type: project
---

# slice1-roles (#1877) rebase over #1891 — CLEAN (HEAD 97d3095b6)

WASM bridge replaced FLAT string suspended-capability storage with shared typed `ContextRoleState`
(suspensions = `HashSet<Capability>`). Verified the rebase preserves #1891's correctness:

**Why typed supersedes #1891's string fix (by construction):**
- `Capability` derives `Hash, PartialEq, Eq` (roles.rs:70). `Capability::new` canonicalizes divergent
  display forms: `"bridging"|"bridging:*"` → `Bridging`; `"tool:invoke:*"|"tool_invoke:*"` → `ToolInvokeAll`.
- Suspend path: consequence `EnforcementSeverity::SuspendCapability{ capabilities: Vec<Capability> }` is typed
  end-to-end (no string round-trip) → `apply_suspend` → `suspend_capabilities_typed` → `ContextRoleState.suspended_capabilities` (typed set).
- Lookup path: `member_has_capability(did, &ucan_string_to_capability(s))` where `ucan_string_to_capability = Capability::new`.
  `ContextRoleState::member_has_capability` does `suspended.contains(capability)` on typed `Eq` values (roles.rs:1544).
- Send gate (manager.rs:2056) uses `member_has_capability(sender, &Capability::MessagesWrite)` — typed, suspension-aware.
- **No string-spelling mismatch possible.** The #1891 bug class cannot reappear.

**Remnant sweep — clean:** `capability_to_ucan_format` GONE from whole tree. No flat `suspended_capabilities:`
field on PerContextState (only `role_state: ContextRoleState`). No conflict markers. No dup `apply_suspend`/`member_has_capability`.
No `1891` issue ref in source.

**3 ported tests non-vacuous + exercise ENFORCEMENT (not just storage):**
- `apply_suspend_enforces_capabilities_with_divergent_display_form` (consequence.rs:860) — asserts `member_has_capability_pub` DENIES Bridging+ToolInvokeAll post-suspend. The exact #1891 bug, proven via enforcement.
- `governance_suspend_restore_uses_canonical_form_for_all_shapes` (manager.rs:9810) — real dispatch_governance_action SuspendCapability/RestoreAccess over Bridging/ToolInvokeAll/Custom("custom:foo")/Custom("bridging"); canonical store + full clear.
- `ceiling_string_conversion_matches_native_for_all_builtin_variants` (manager.rs:9885) — exhaustive built-in loop + explicit pins old buggy spellings (`bridging`,`tool:invoke:*`) GONE, canonical (`bridging:*`,`tool_invoke:*`) present.

Governance arms (manager.rs:4180 SuspendCapability/SuspendAccess/RestoreAccess, dispatch_revoke:4293) all typed via shared ContextRoleState. Import/export carries role_state verbatim (derived PartialEq); flat-string seeding is test-only via validating set_ceiling/suspend_capabilities.

VERDICT: merge clean, #1891 correctness preserved. No bug found.
