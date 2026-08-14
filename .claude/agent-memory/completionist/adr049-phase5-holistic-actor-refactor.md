---
name: adr049-phase5-holistic-actor-refactor
description: ADR-049 Phase 5 FINAL holistic completeness review of the complete actor-per-context refactor — cross-layer wiring @f2d4e7d0f
metadata:
  type: project
---

# ADR-049 Phase 5 — holistic actor-refactor completeness review @ f2d4e7d0f (origin/main, pinned worktree scp-wt-phase5)

Verdict: COMPLETE code, INCOMPLETE artifacts. The actor refactor is fully wired end-to-end; the only findings are stale ADR/doc-comment provenance + one dark test file + documented cross-binding asymmetries.

**Why:** Final review after the whole ContextManager→Supervisor+per-context-actor refactor landed. ContextManager is deleted (only comment residue in persistence.rs). 12 command sub-enums (Messaging/Lifecycle/Governance/Broadcast/Economy/TrustRecovery/Standing/TtlClose/Tools/Queries/SagaPhase/LifecycleControl); Supervisor (supervisor.rs, 23.8k lines) is the ContextManager-equivalent that dispatches typed commands to actors.

**How to apply:** on a "N live saga arms" premise VERIFY the count against ADR corrections first — premises go stale.

## HEADLINE FINDING (artifact divergence / phantom provenance — MEDIUM, actionable=docs)
The §6.2.4 cross-context tool-invocation saga FFI surface **LANDED** (commit 050b05ba7 "PR-6b #1950", 2026-06-29, ancestor of HEAD) — fully wired: PyO3 `tool_invoke_cross_context_saga` (tools.rs:1945, prod, not test-gated), NAPI `toolInvokeCrossContextSaga`, UniFFI `tool_invoke_cross_context_saga`, all 4 SDK wrappers (py/ts/sw/kt), capability-matrix entry `invoke_cross_context_saga` (line 597), pipeline_wiring assertions (41→44), and `enforce_caller_principal_binding` (tools.rs:1051) genuinely discharges the §3a forward obligation (identity_registry_contains = channel-auth principal + is_member). Yet the system-of-record ADR-049 — last edited 2026-07-07 (8 days AFTER the saga shipped, at HEAD) — STILL says it's deferred:
- ADR-049 line 66: "no production caller yet, because its FFI export is deferred (per §3a)" + "recovery ... inert in production today" — STALE.
- §3a lines 82/95: frames export as "MUST NOT ship until per-set gating" (gating LANDED: try_reserve_context_set) + "obligation lands with the wiring PR, not before" (wiring LANDED).
- supervisor.rs:5542 doc on start_cross_context_tool_invocation_saga: "This saga has NO production caller yet" — STALE (3 bridges call it).
- INTERNAL ADR contradiction: §428(b) says the py/ts reverse-tripwire flip "remains" deferred while §430 (same doc) says it's "been flipped."
Direction per one-way flow: CODE+matrix+pipeline are TRUTHFUL; the ADR prose + supervisor doc are stale and must be updated to record landed status (T1 "landed in this change set" precedent). NOT enforcement theater.

## Saga premise correction
Task said "2 live saga arms (CrossContextToolInvocation, BroadcastHostingHandshake)". FALSE at HEAD: BroadcastHostingHandshake was **RESOLVED-AS-WITHDRAWN 2026-06-25** as a category error (§5.11A.6 phantom topology). Deletion is COMPLETE+clean: zero residue of hosting_handshake.rs / SagaInput::BroadcastHostingHandshake / SCP-SAGA-13100..13102 / spec §5.14.13 / InitiateBroadcastHostingHandshake. **Sole live saga = cross-context tool invocation.** SagaInput enum = {CrossContextToolInvocation (prod, sealed by CrossContextSagaSeal), TestForceNeedsRepair (cfg test/testing)}. Sole saga has REAL behavioral tests (19 integration incl actor_saga_coordinator/concurrent/crash_recovery + 86 inline async in saga.rs) driving prepare/commit/abort/crash-recovery — not name refs.

## Enforcement files — REAL, not theater (compiled+run: pipeline 48/48, ffi_conformance 89/89, check_ready_coverage 2/2, 0 ignored)
- pipeline_wiring.rs: fn_body_contains scans PRODUCTION source (include_str! + brace-matching lexer stripping comments/strings, 12 evasion-defeat tests) so a name can't match itself; no `let _=fn` fraud (sole repo `let _=` is a parser test fixture string); `no_stale_ignores` catch-all rejects ANY #[ignore]; ratchet floor MIN_ACTIVE_PIPELINE_ASSERTIONS=55.
- ffi_conformance.rs: syn AST collects actually-@-decorated exports, excludes cfg(test), bidirectional parity vs bridge-aliases.json (shared w/ check-bridge-symmetry.sh), rejects undecorated pub fn.
- check_ready_coverage.rs: syn Visit counts .check_handle(x.instance_id()) ≥ handle-param count per #[uniffi::export] method.

## issue_mls_update (#2060 probe) — COMPLETE, wired (NOT a void)
supervisor.rs:9550 → LifecycleCommand::IssueMlsUpdate → handle_issue_mls_update_actor (lifecycle.rs:681) advances epoch; consumed by reconnect driver Phase 5 mls_update (reconnect.rs:439/621) which PUBLISHES the Commit to peers via transport.send on the shared routing key; reconnect_contexts is the FFI-common public entry, exposed via SDK `reconnect` all 4 SDKs. Real test reconnect_sync.rs:289. Minor: no dedicated pipeline assertion BY NAME (covered obliquely inside pinned driver src + advance_epoch/propose_update branch).

## REAL GAP — UniFFI tool_verify fabricates a passing result (DRIFT, actionable, HIGH-for-correctness)
UniFFI `tool_verify` (bridge.rs:12886-12912) does check_handle → lock state → assert ContextState::Active (else TOOL_6007) → then hardcodes `Ok(ToolVerificationResult { tool_id, passed: true, failures: Vec::new() })`. It NEVER calls scp_core::context::tools::verify_tool. Both peer bridges DO: PyO3 tool_verify_impl (tools.rs:585-628) calls verify_tool(&rt.tool_registry, tool_id, identity-executor) → `passed: result.integrity_ok`, real `failures` from vector_results; NAPI tool_verify_on (tools.rs:452) identical. Effect: EVERY Swift/Kotlin caller gets passed:true/failures:[] for ANY tool, including tools whose test_vectors would fail — false-positive verification. Fix: mirror PyO3/NAPI, call verify_tool against the in-scope registry. Likely pre-existing (not actor-refactor-introduced) but a live cross-bridge parity + correctness defect. Verified directly, not subagent-trusted.

## Other findings (secondary)
- **NAPI MCP placeholder ContextProvider (pre-existing, out-of-actor-scope):** McpNapiBridgeProvider (napi/src/mcp.rs:338-403) holds only agent_did+context_ids; agent_role→None, context_tools→[], validate_capability→Err("not implemented"), invoke_tool→Err. Constructor mcp_server_create_on gets the bridge instance but never threads it. PyO3 (FfiBridgeProvider Weak→instance, ADR-016 UCAN validation) + UniFFI (dispatch_query GetRoleState) wire it fully. NAPI MCP server exposes tools with no role resolution / no capability enforcement. warn_once discloses. Track for reference-bridge parity.
- **Recovery mock backend fakes success (borderline, documented):** FfiRecoveryBackend (identity.rs:2341-2377) + NapiRecoveryBackend (napi/scp.rs:1173-1211) return Ok/true for every step so identity_execute_recovery reports success without MLS/UCAN work at this layer, while sibling NotConfiguredMigrationBackend fails closed. Documented ("real backends injected at SDK layer"), consistent PyO3+NAPI. The fake-success-vs-fail-closed asymmetry merits a deliberate decision.
- **§9.10.4.A step-4 pseudonym-privacy migration incomplete (cross-bridge, honest TODO):** napi/context.rs:2017 — after pseudonym exchange the bridge should unsubscribe the shared routing ID but "shared subscription is permanent (migration never completes)"; no unsubscribe in PyO3/UniFFI either. Out of actor scope.

- **network_simulation.rs dark test (LOOSE END, actionable):** entire file `#![cfg(any())]`-gated (line 10); its 2 #[ignore] reasons cite "tracked alongside commit-12 deletion of ContextManager" — but ContextManager IS deleted, so the stated unblock condition is MET yet the whole network-simulation integration suite stays dark. Rewire to MlsCryptoProvider::with_backends or re-track.
- **§9.9.2 heartbeat sender NAPI-only (cross-binding gap, partially disclosed):** run_heartbeat_scheduler co-spawned ONLY in NAPI context.rs:2363; UniFFI context_subscribe (bridge.rs:10560) omits it; Python uses pull context_receive. So Swift/Kotlin/Python nodes emit no §9.9.2 heartbeats → appear suppressed to peers' monitors. Disclosed as a NAPI-only NOTE on the `subscribe` matrix entry (line 477) but NO per-binding exemption citing spec/ADR/issue for the others.
- **clear_poison/clear_kp_poison orphaned (disclosed for clear_poison only):** both are SupervisorHandle recovery primitives with zero non-test callers (no FFI/SDK). ADR §232 discloses clear_poison ("recovery = restart until an operator surface lands") but does NOT mention the sibling clear_kp_poison — extend the disclosure.
- **Typed governance fields None across ALL bridges (confirmed-tracked #2027/#2029):** CommonContextParams.governance_threshold/signers/voters (context_params.rs:61) set None by every bridge (PyO3 context.rs:1461 "string-only governance for now"); parse_governance silently falls back to SingleAdmin when signers empty. Consistent with governed-context-not-yet-implemented deferral (ADR §428(2), invite_member returns Err(InvalidState) for governed). Observation: the SILENT degrade (ask multisig → get SingleAdmin, no error) is worth a hard error.
- **spending_ucan_jwt FALSE POSITIVE:** a subagent claimed NAPI/UniFFI hardcode join spending_ucan=None — WRONG. Both thread spending_ucan_jwt: Option<String> (napi context.rs:880/962, uniffi bridge.rs:9985/10094). Cited lines were misattributed (napi:606=consequenceRules, uniffi:2931=Drop doc). Verify subagent None-claims against actual code.

## Clean
- Zero todo!()/unimplemented!() in prod actor/supervisor; "not yet implemented" hits = documented fail-closed governed-invite deferrals only.
- start_saga (generic) test-only-substrate by design (can't drive cross-context Commit w/o executor+keys); real path = start_cross_context_tool_invocation_saga. Documented in SagaInput doc.
- spawn_actor_from_welcome wired to prod FFI export context_join_from_welcome (2J slice landed); reserve_key_package + join all-4-SDK wired.
