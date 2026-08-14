---
name: project-saga-gate2-reads-caller-context
description: §6.2.4 cross-context tool saga gate-2 (has_established_tool_interface) reads the CALLER/source context's actor state, not the target's; how to drive it to Committed from PyO3
metadata:
  type: project
---

§6.2.4 cross-context tool-invocation saga (`Supervisor::start_cross_context_tool_invocation_saga`, crates/scp-runtime/src/context/supervisor/supervisor.rs:5478): gate 2 (`has_established_tool_interface`) is queried against the **CALLER (source) context A's** actor governance state — NOT the target B's.

**Why:** supervisor.rs:9481 sets the `HasEstablishedToolInterface` command's routing `context_id = source_context_hex`; the actor handler (queries.rs:164) reads the routed actor's `state`; predicate (queries_helpers.rs:298) matches `approved_by_source && approved_by_target && source_context==caller_hex && target_context==target_hex && tool_id==reg_id`. A widely-circulated assumption (and one Explore-agent summary) says "target actor state" — that is WRONG; the code routes to the source/caller actor. Verify by reading line 9481 + queries.rs:164, not prose.

**How to apply:** To drive this saga to a real **Committed** from the PyO3 bridge (e.g. e2e Committed coverage):
- Establish the `ToolInterface` in CALLER context A's state (not B) via `scp.governance_propose(handle_A, owner, action_json)` with a `GovernanceAction::EstablishToolInterface` whose interface has `approved_by_source:true, approved_by_target:true, source_context=A_hex, target_context=B_hex, tool_id=reg_id`. JSON is default externally-tagged: `{"EstablishToolInterface":{"interface":{...snake_case fields, null for None...}}}`.
- Context A must be created (`scp.context_create`, which mints a real 64-hex id) with a ceiling including `"governance:propose"` AND `"tool:interface"` — the built-in admin role grants all ceiling caps (roles.rs:1206-1212); single_admin auto-executes. `execute_establish_tool_interface` (governance_helpers.rs:2230) requires `Capability::ToolInterface` in the ceiling.
- Register the tool in TARGET B (`scp.tool_register`) + a handler in B via `crate::runtime::register_tool_handler(bi, ctx_b, reg_id, Arc<Fn>)`; the saga executor snapshots B's `tool_handlers.get(reg_id)` (tools.rs:1182) and runs it once at Commit-B. Handler output MUST satisfy B's registered output schema (e.g. build_tool_reg wants numeric `sum`+`ok`).
- caller_did must be hosted (identity registry) + member of A — both true if A's creator (`enforce_caller_principal_binding`, tools.rs:1062). Then `scp.tool_invoke_cross_context_saga(ctx_a, ctx_b, owner, reg_id, input, nonce_hex, ts_ms, chain_depth, None)` returns `PySagaResult{saga_id, receipt:Some, output:Some}` on Commit.

**THREE more non-obvious Prepare/commit preconditions (each cost a saga-abort to discover, verified):**
1. **Tool lives in TWO registries.** Saga Prepare-B reads the tool from B's **actor** `state.governance.registered_tools` (saga.rs:1223, SCP-SAGA-13016 if absent) — NOT the FFI-side `tool_registry` that `scp.tool_register` writes. So register the tool into B's actor state via a `RegisterTool` GovernanceAction AND via FFI `tool_register` (latter only because `register_tool_handler` requires an FFI-registry entry; executor reads the *handler* from `rt.tool_handlers`). Same deterministic `tool-<name>` id keys all three: B-actor registered_tools, A's interface gate-2, FFI handler.
2. **Governance sig verify needs a RESOLVABLE proposer DID.** Even single_admin auto-execute resolves the proposer pubkey via the instance resolver (governance/mod.rs:1211 "unknown voter"). Registry-only `create_test_identity` does NOT publish a DID doc → fails. Use bridge `scp.identity_create(py,"in_memory",None)` (publishes) and run it BEFORE `init_context_manager_for_test` — `build_supervisor` snapshots `bi.did_resolver()` at build time (else always-None key resolver).
3. **Timestamp skew.** Prepare-B enforces §9.14 ±5min (SCP-SAGA-13018); pass `SystemTime::now()` ms, not a fixed historical constant.

**Gate gotcha:** the e2e_bridge test target REQUIRES BOTH `allow_in_memory_custody` AND `testing` to build. Clippy without `testing` silently skips the test target (false-clean). Always `--features "allow_in_memory_custody testing"`.

Related: [[project-pr105-xctx-saga-ffi]] (#105/#116 FFI export of this saga). As of 2026-06-29 no scp-runtime test drove a true Committed (only executor-less misuse aborts + journal replay); the PyO3 e2e_bridge test on branch feat/116-ffi-saga-export is the first end-to-end Committed coverage.
