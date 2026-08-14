---
name: pr1877-slice1-ceiling-recon
description: PR #1877 slice 1 (WASM adopts shared ContextRoleState) rebased on #1884 ceiling-grammar — final probe, CLEAN, one benign custom: prefix non-idempotency noted
metadata:
  type: project
---

# PR #1877 Slice 1 — WASM ContextRoleState rebase on #1884 (HEAD 848557957)

Probed: crates/scp-ffi/wasm/src/manager.rs + consequence.rs. Core grammar lives in
scp-protocol/src/context/roles.rs (validate_ceiling_entry colon-form,
validate_ucan_ceiling_string UCAN-form, validate_custom_ceiling_entry shared core).

## VERDICT: CLEAN — no exploitable authorization gap from the rebase.

Verified:
- §5.3.1.1 ceiling grammar enforced on ALL 3 WASM write paths:
  - create_context: validate_ceiling_capabilities on PARSED enums (validate_as_ceiling_entry). Rejects no-colon/`*:*`/`*:read`/multi-colon/uppercase/underscore-resource/non-canonical colon built-in.
  - ModifyCeiling (dispatch_modify_ceiling): validate_ceiling_capabilities BEFORE mutation + set_ceiling re-validates (defense in depth), fail-closed.
  - import_context: validate_imported_ceiling_strings (validate_ucan_ceiling_string) runs on RAW strings BEFORE lossy parse — BLACK-005 ordering correct. Rejects colon-form built-ins on import (vocabulary is strictly UCAN form).
- set_ceiling fail-closed: validate_entries()? returns before `self.ceiling = ceiling`. set_ceiling_and_refresh: set_ceiling first, role-def rebuild + member-cap refresh are infallible-by-construction after success. NO partial mutation.
- send/publish write gate: positive Capability::MessagesWrite via member_has_capability (suspension-aware). Read-only role rejected, suspended writer rejected. publish_broadcast mirrors send_message.
- #1886: system_assign_role rejects RoleNotFound + CapabilityOutsideCeiling; import propagates the error → undefined/out-of-ceiling role rejected. WASM snapshot carries NO role_definitions (re-derived as builtins∩ceiling), so a member's role string must be a builtin.
- compound built-in round-trip on import: bridging:* → Bridging, context_child:create → ChildContextCreate, tool_invoke:* → ToolInvokeAll. Export uses ucan_capability_name/to_ucan_string_set (canonical UCAN). Typed identity preserved.
- governance exec auth: execute_governance_action requires require_proposal_approved + resolves action from TRACKED proposal (no action substitution). No direct-execute quorum bypass.
- consequence suspend_all rebase: OLD iterated ceiling-caps-member-has; NEW = ContextRoleState::suspend_all (REPLACE with member_capabilities). Matches native byte-for-byte. REPLACE only ever drops suspensions for caps the member can't exercise anyway → never weakens enforcement.

## BENIGN NOTE (not a vuln): `custom:` prefix non-idempotency
- validate_ucan_ceiling_string("custom:foo") ACCEPTS it (resource=custom, action=foo, both kebab).
- Capability::new("custom:foo") treats `custom:` as a SIGIL → Custom("foo") → stored "foo:foo".
- So import gate (string) and create gate (parsed enum: validate_as_ceiling_entry(name()="foo")=FALSE) DISAGREE: import accepts custom:foo, create rejects it.
- Across one export/import cycle the enum identity shifts Custom("foo") → Custom("foo:foo") (both export as "foo:foo"; fixpoint after 1 cycle).
- NOT exploitable: no widening (concrete single cap, no wildcard, no builtin reachable); only triggers on a hand-crafted/non-conformant signed snapshot (conformant exporter emits foo:foo, never custom:foo); a snapshot signer can already set any in-grammar ceiling directly. Self-consistent within each generation because member_has_capability parses queries with the same Capability::new.
- If hygiene desired: validate_ucan_ceiling_string could reject the literal `custom:` prefix (UCAN form never carries it), aligning import with create. Cosmetic only.
