# fix/ceiling-modify-reconcile (capability-security review, 3afb1ae06)

ModifyCeiling LOWER now eagerly reconciles cached authz state. Verdict: SOUND. One MEDIUM doc-accuracy finding (UniFFI), no security holes.

## Construction
- `ContextRoleState::set_ceiling` (scp-protocol/src/context/roles.rs:1863) validates entries, stores ceiling, then calls new private `reconcile_to_ceiling()` (roles.rs:1901).
- reconcile = pure SHRINK via `CapabilityCeiling::contains` (wildcard-aware: ToolInvoke(id) under ToolInvokeAll is the ONLY wildcard; all else exact). Prunes role_definitions[*].capabilities (retain empty role NAMES — avoids dangling assignment refs), member_capabilities[*] (drop emptied entries), suspended_capabilities[*] (drop dead-weight: ceiling.contains(cap) && member still granted).
- Borrow-splitting correct: per-field `&self.ceiling` immut + one field mut; suspension pass binds already-pruned `&self.member_capabilities` immut while `suspended_capabilities` mut. Ordering: member_caps pruned BEFORE suspension pass, so granted.is_some_and sees pruned grants. If member entry fully removed → granted=None → all their suspensions dropped. No orphan entries, no borrow bug.
- Idempotent + no-op-on-widen → §23.16.8/ADR-050 export digest stable. WIDEN never grants (cache only narrows; grants only ever from explicit assignment).

## Write-time invariant (lazy member_has_capability re-check correctly OMITTED)
Every member_capabilities writer is ceiling-bounded at write:
- new (roles.rs:1592): validate_entries + per-custom-role ceiling.contains + admin derived from ceiling.
- assign_role (2227), free system_assign_role (2307→inherent), inherent system_assign_role (1972), view system_assign_role (2164): ALL call validate_role_definition(&role_def,&ceiling) BEFORE the member_capabilities.insert.
- set_ceiling reconcile (guard ii) closes the lowering window.
So member_has_capability (1705) trusting member_capabilities − suspended verbatim is sound. No read-time re-intersection needed.

## Import path (claim iii) — ACCURATE
lifecycle_helpers.rs:1788 / 2074 consume `export.snapshot.role_state` VERBATIM (NOT via set_ceiling). Import validates ONLY ceiling well-formedness (1787 validate_entries), NOT member_capabilities ⊆ ceiling. Doc-comment correctly states: signature binds ORIGIN not well-formedness; a creator-self-inconsistent snapshot WOULD install an out-of-ceiling grant servable by local gate — NOT construction-closed. Inert because: (a) creator is the ceiling authority (self-grant beyond own ceiling buys nothing vs just declaring higher ceiling); (b) cross-node re-presentation re-validated against signed ceiling per spec §7.2.1 step 8 (07-trust...md:81 — entire `att` set checked, any out-of-ceiling attestation rejected). Adding import-time subset re-check = redundant per CLAUDE.md over-engineering guard. Correct call.

## Apply seam
governance_helpers.rs:455 apply_pending_ceiling_modification routes set_ceiling inside commit_class_s_keep (fail-closed KEEP direction: lowered ceiling stays on persist failure). Early-return-before-mutation when not effective. Reconcile persists atomically with lowering. Tier-2 enforcement (send/invoke/gov/close) runs in scp-runtime against actor's reconciled role_state — the real gate; FFI-local copies are secondary.

## FFI re-sync — PyO3/NAPI correct; UniFFI doc MISLEADING (MEDIUM)
- PyO3 (scp-ffi/src/runtime.rs:1683 sync + 1713 async): pulls sup.get_role_state, writes st.role_state. context.rs path uses _async variant (avoids nested block_on panic). CORRECT.
- NAPI (napi/src/runtime.rs:1667): QueriesCommand::GetRoleState, writes st.role_state (with_context). NAPI DOES keep FFI-local copy (tests 5013/5027). Load-bearing + correct.
- UniFFI (uniffi/src/runtime.rs:933): queries get_role_state but `let _role_state = ...` DISCARDS it — no write-back. CORRECT outcome because UniFFI keeps NO FFI-local role_state cache; every read (bridge.rs:4213/4352/4572 agent_role/member list) goes LIVE to supervisor via block_in_place. So actor reconcile is auto-visible; nothing to sync. BUT the call-site doc (bridge.rs:~10046) claims it prevents "stale role state" / "local Tier-2 gate would serve out-of-ceiling capabilities" — FALSE for UniFFI (no local copy, always live). Helper is effectively a liveness-probe + debug log. Recommend: correct the comment (UniFFI reads live; no local cache to resync) OR drop the no-op call. Not a security hole.

## Tests
- 138 scp-protocol context::roles pass (7 new reconcile tests).
- scp-runtime class_s apply_pending_ceiling_modification_prunes_out_of_ceiling_member_capability passes (production seam, not unit mutator).
- My probe (custom role name retained + orphan suspension dropped + emptied member entry removed + gate denies): PASS.
