---
name: eventlog-governance-executor-convergence-501a44f6a
description: ALIGNED review of native↔WASM governance executor-stamping + WASM auth-model convergence (§9.9.3) at slice45-actor-did 501a44f6a
metadata:
  type: project
---

# Native↔WASM Governance Convergence @ `501a44f6a` (2026-06-22) — ALIGNED

Branch `fix/leaf-actor-did-convergence`, worktree `slice45-actor-did`. Range `b5b0eb02c..501a44f6a` (11 commits, +1974/-143, 11 files). b5b0eb02c IS ancestor — clean two-dot.

**GOTCHA (critical):** agent shell CWD reset lands in the MAIN checkout (`feat/actor-2c-xctx-tool-saga` @ b321248e1), NOT the slice45 worktree. `git log -3` showed wrong HEAD; Read tool read wrong file (656 vs 1609 lines). MUST use `git -C <worktree-path>` for every command and `git show 501a44f6a:<file>` to read. `git worktree list` confirms the real checkout. The "STOP if not 501a44f6a" precheck false-tripped because of this.

**Verdict: ALIGNED. 0 blocking, 0 material, 1 LOW doc-drift.**

Scope: GovernanceActionExecuted executor stamping (proposer→executor), convergent ContextClosed deadline, shared system-actor consts, WASM governance auth-model convergence.

Verified all-correct:
- Native `execute_governance_action` (governance_helpers.rs:4477) has NO per-member capability check — gates ONLY status==Approved + context-id + check_commit_fault + replay. WASM removing its per-member execute check now matches.
- Spec model confirms: ADR-031 phase-6.md §2326-2394 — propose needs GovernancePropose (line 2337), vote needs GovernanceVote (2346), execution is automatic on quorum (try_resolve 2383). NO spec requirement that executor individually hold the action capability. Group authorizes via quorum; ceiling bounds action. Removed WASM check diverged from BOTH native AND spec.
- Executor = committing member: quorum path = quorum-crossing voter; auto-execute/SingleAdmin = proposer; direct-FFI (context_execute_governance) = proposal.proposer_did (via proposal_proposer_did), matching native handle_execute_governance_action_actor. ADR-031 §8 step 4 (phase-6.md:2749): "records ... executor DID".
- Consequence SUBJECT unchanged = proposal.proposer_did (governance_helpers.rs:4342+ block; comment at 4232-4234 documents the distinction). Executor change does NOT touch consequence semantics. (Task #205 = separate consequence-subject convergence, NOT this slice.)
- Native per-action ceiling gates = EXACTLY: {SuspendCapability execute_suspend_member:734, SuspendAccess inline:4008, RevokeAccess execute_revoke:798, RestoreAccess execute_restore_access:943}→MemberBan; RegisterTool:1294→ToolRegister; CreateChildContext:1689→ChildContextCreate; EstablishToolInterface:1977→ToolInterface. execute_remove_member/change_role/close_context have NO ceiling gate → WASM returns None. WASM dispatch_ceiling_capability is an EXHAUSTIVE no-wildcard match (closed-by-construction) mapping exactly these 7 variants + None for all others.
- UCAN ceiling strings exact: roles.rs ucan_resource_action — ChildContextCreate=context_child:create, ToolInterface=tool:interface, MemberBan=member:ban, ToolRegister=tool:register. WASM matches these against ceiling_strings (underscore UCAN form, populated via capability_to_ucan_format). Correct.
- Convergent ContextClosed: WASM finalize_close (manager.rs:6396) close_leaf_secs = Some(ttl)=>creation+ttl else now_secs. Native ttl_close_helpers::finalize_close derives deadline_unix_secs.unwrap_or_else(now_secs) (=creation+ttl per convergent_ttl_deadline:274) → ttl::finalize_close. Byte-identical. Only ONE ContextClosed append (close_context appends ContextClosing only, committer-stamped — correct).
- System-actor consts (scp-event-log/system_actors.rs): SYSTEM_TIMER_ACTOR=system:timer, SYSTEM_CLOSE_ACTOR=system:close, SYSTEM_SAGA_ACTOR=system:saga, SYSTEM_CONSEQUENCE_ACTOR=system. scp-event-log on ADR-034 permitted shared-dep list → convergence by construction. Saga divergence marker native changed ""→"system:saga" (native-only leaf today; pre-release so no migration concern).
- WASM_PROPOSAL_TTL_MS bumped 24h→14d to mirror native EXECUTED_PROPOSALS_TTL_SECS — closes a replay-window divergence (security-positive).
- Tests: consequence.rs +821 ALL #[cfg(test)] cross-impl parity. cross_impl_nonadmin_voter_crosses_quorum_mints_one_leaf_wasm is the linchpin: voter has governance:vote but role:assign SUSPENDED → old check minted 0, fix mints 1 stamped voter. Symmetric native integration tests (governance_integration.rs:492 stamps_executor_not_proposer with non-vacuity proposer!=executor; :579 voter_without_action_capability_mints_one_leaf; out-of-ceiling reject for RevokeAccess + CreateChildContext + EstablishToolInterface).
- No #NNNN issue refs in added source. Saturating ExtendTtl add (overflow safety + native parity). Encode-payload-before-buffer-push (fail-closed, symmetric side effects).

**LOW finding (doc drift):** manager.rs:2864 dispatch_ceiling_capability outer doc says "Native gates precisely these five:" + lists only 5 member:ban/tool:register bullets + "(`member:ban`, `tool:register`)" — but final commit 501a44f6a added CreateChildContext→context_child:create and EstablishToolInterface→tool:interface to the match body. Impl gates SEVEN variants / FOUR capabilities. Match body + inner comment (cite execute_create_child_context/execute_establish_tool_interface) are CORRECT; only the outer doc summary under-describes. Cite-back drift when the final commit extended the gate set but missed the function's own doc header.
