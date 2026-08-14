---
name: slice1-f8b6e11-ceiling-validator-deletion
description: WASM @f8b6e11c1 dropped redundant per-cap ceiling validator (create+modify) relying on shared ContextRoleState::new/set_ceiling validate_entries; 5 deserialize/grammar probes + full slice ALL CLEAN
metadata:
  type: project
---

# WASM ceiling-validator deletion sweep — commit f8b6e11c1 (CLEAN)

Worktree `/tmp/scp-s1-bh14`. Commit deletes WASM-side `validate_ceiling_capabilities`/`ValidatedCeilingStrings` per-cap validator on create + modify-ceiling paths, AND migrates `PerContextState` from flat `members:HashMap<MemberEntry>`/`ceiling_strings:HashSet<String>`/`suspended_capabilities:HashMap<String,HashSet<String>>` to the shared `role_state: ContextRoleState`. Consequence path adopted shared `ContextRoleState` too. Claim: behavior-preserving, same SCP-VALID-7000.

## Verdict: SOUND. No break after genuine effort.

### Enforcement is a closed positive whitelist (scp-protocol roles.rs)
- `validate_ceiling_entry` (§5.3.1.1) = built-in exact-match table OR `tool:invoke:{id}` (tool_id charset `[a-z0-9_-]`) OR custom `{resource}:{action}` (resource kebab `[a-z0-9-]`, action kebab-or-single-`*`). Plus charset guard (len<=256, no control/whitespace/HTML). Everything else rejected.
- CREATE path: `ContextRoleState::new` → `ceiling.validate_entries()` (roles.rs:1456) BEFORE any store. WASM `create_context` builds ceiling via `Capability::new(str)` then hands to `new`.
- MODIFY path: `dispatch_modify_ceiling` → `role_state.set_ceiling(...)` (fail-closed: validate WHOLE replacement, then assign; receiver UNCHANGED on error, roles.rs:1687).
- DESERIALIZE (import): `CapabilityCeiling` has `#[serde(try_from="CapabilityCeilingRaw")]` → `validate_entries()` at deserialize. Import ALSO re-runs explicit `validate_entries()` belt after.

### Probes run through prod enforcement points (5 throwaway tests, all pass, reverted)
- `payments`(no-colon), `*:*`, `*:read`, `a:b:c`, `payments:read:write`, `payments_v2:read`(underscore-resource), `pay*ments:read`, `payments:wr*`, `Payments:read`(upper), `:read`, `payments:`, ``, whitespace, `<script>:x` → ALL rejected on CREATE (ContextRoleState::new) and MODIFY (set_ceiling).
- MODIFY fail-closed: every rejected `set_ceiling` leaves prior ceiling byte-unchanged (verified set-equality before/after each).
- `Capability::new` roundtrip: every malformed vector → `Custom(verbatim)` (name() byte-equal), so validate sees the malformed string (no silent normalization).
- FORGED serialized ceiling (externally-tagged enum bypasses Capability::new string parse): `{"Custom":"a:b:c"}`, `{"Custom":"payments"}`, `{"Custom":"*:*"}`, `{"Custom":"tool_invoke:*"}`, `{"Custom":"messages_:write"}` → ALL rejected at serde try_from. `{"ToolInvoke":"a:b"}`(colon id) rejected. 

### Laundering analyses (benign, NOT escalation)
- `custom:messages:write` → strips `custom:` → `Custom("messages:write")`, name()="messages:write", validates as well-formed custom. `to_ucan_string_set()`={"messages:write"} BYTE-EQUAL to built-in. BUT typed `ceiling.contains(&Capability::MessagesWrite)`=FALSE (distinct enum variants). NOT escalation: messages:write is a legit built-in a creator may grant directly. NB: WASM UCAN ceiling gate IS string-based (`ucan_context_state` returns `to_ucan_string_set()`), so the Custom would authorize a messages:write UCAN — still no escalation past grammar.
- `tool_invoke:*`→ToolInvokeAll, `context_child:create`→ChildContextCreate: LEGIT built-in aliases in Capability::new table (lines 164/172). Forged `ToolInvoke("*")` (name()=`tool:invoke:*`) accepted, projects tool_invoke:* = legit ToolInvokeAll spelling.
- KEY invariant: any custom whose UCAN projection would COLLIDE with a multi-segment built-in needs `_` in resource → kebab check rejects it before storage. So a stored custom only ever string-projects to its validated colon-form.

### Rest of slice (unchanged-but-verified)
- Suspension typed end-to-end: send gate (manager.rs:2053) + publish gate (5627) call shared `member_has_capability(did, &Capability::MessagesWrite)` (suspension-aware, typed). `SuspendCapability`.capabilities is `Vec<Capability>` (serde-typed) → `suspend_capabilities(typed)` — no string round-trip. `ucan_string_to_capability`=`Capability::new` only used on test-only insert + restore-from-suspended (typed source).
- RemoveMember: strips members+assignments+member_capabilities together (4026/4045-46) after MLS evict; no split-brain. AddMember/subscribe_broadcast: conditional rollback (only undo what THIS call inserted) — no gone-from-members-but-retains-caps. subscribe_broadcast assigns ceiling-filtered `subscriber` role (read-only) → can't publish (no messages:write).
- Import: exporter==creator binding (key from creator_did NOT envelope, 6662), empty-sig reject, verify_strict #active→#agent, import-over-existing reject, role_state restored VERBATIM (no recompute → BLACK-CEIL-01 stays fixed), grammar belt after.

### Suites green
scp-ffi-wasm lib 413/413; scp-runtime wasm_conformance 57 pass / 1 ignored (per-action-EventType-leaf-parity deferral, documented `wasm_native_full_governance_eventtype_parity_pending`).
