---
name: project-1866-direct-execute-by-id
description: SEC-1866 governance direct-execute quorum-bypass fix — by-id resolution, KAT reachability facts, bridge governance resolver gap
metadata:
  type: project
---

SEC-1866 (branch fix/1866-direct-execute-trust, commit c9db30486): direct-execute governance now resolves the proposal from the actor's OWN engine via `engine.get_proposal(proposal_id)` and rejects untracked/unapproved ids. Bridge surface is `(handle, identity_did, proposal_id_hex)` on all 4 bridges; WASM resolves the action from its tracked proposal (no `action_json`). Core fix was pre-done; this session did tests/SDK wrappers/enforcement/verify.

**Why:** caller could hand the runtime a fabricated `status=Approved` proposal+action → quorum bypass + action substitution.

**How to apply (load-bearing reachability facts for future governance tests):**
- Quorum-crossing vote AUTO-EXECUTES inline (`vote_on_proposal_inner` calls `execute_governance_action` when status flips to Approved, unless `in_freeze`). So after quorum the proposal is BOTH Approved AND in `executed_proposals`.
- Therefore a *separate* FFI execute-by-id of a quorum-approved proposal is ALWAYS replay-rejected ("already been executed") — there is NO propose/vote/conflict flow that yields an Approved-but-unexecuted proposal the FFI path can successfully run. The freeze path keeps the 2nd proposal Pending; conflict-resolve marks the loser executed and leaves the winner Approved-unexecuted only via a complex path. The genuine "first execute succeeds" is only reachable by directly seeding engine/manager state (WASM has `test_insert_resolved_proposal`).
- KAT design that IS reachable everywhere: FORGERY (untracked id → rejected + no state change) is the core security test. GENUINE = propose→vote-to-quorum (auto-exec once) → execute-by-id replay-rejected. WASM genuine-success uses `test_insert_resolved_proposal` seam.
- WASM forgery rejection message is "not approved (status: None)" (status precondition checked first), NOT "not tracked" — assert on either.

**Bridge governance resolver gap (pre-existing, NOT a #1866 bug):** the genuine propose flow through PyO3/UniFFI/NAPI/WASM bridges FAILS with "unknown voter: cannot resolve public key for DID" for in-memory test identities. Root cause: `document_vm_key_resolver` resolves DID docs from `InMemoryDhtClient` which `identity_create` never publishes (for in_memory custody). So per-bridge KATs use the FORGERY shape only. The native runtime (`governance_integration.rs`, fullstack) uses `mock_key_resolver`/`permissive_key_resolver`-style maps that DO resolve, so genuine quorum flows work there.

**fullstack harness gotcha:** the full-MLS `add_member`/join path re-homes the context actor so a follow-up `dispatch_governance_command` returns ContextNotRegistered (while `is_member` still works via the legacy DashMap direct fallback in `dispatch_query`). Cross-bridge genuine KAT uses a single-member Majority[creator] context (1/1 = quorum) to avoid add_member. Added node helpers propose_governance/approve_governance/execute_governance_by_id + verifying_key() to scp-testing fullstack/node.rs.

**New test seam:** `Supervisor::test_insert_member` (testing-gated) + MessagingCommand::TestInsertMember + handler — inserts into role_state.members+assignments without MLS/governance, mirrors WASM test_insert_member. Used to un-ignore `multi_member_context_export_round_trips_as_creator` (the coder had #[ignore]'d it; export reads role_state.creator_did NOT membership iteration, so the .next() bug it guarded is gone — seam preserves the 2-member precondition).

**Verify gotcha:** TS `bun test` real-napi/integration tests need the addon BUILT WITH allow_in_memory_custody. The published `node_modules/@limn-works/scp-ts-napi-darwin-arm64/index.node` lacks it → 196 SCP-IDENT-1008 failures. Rebuild: `cargo build -p scp-ffi-napi --release --features allow_in_memory_custody` then cp `target/release/libscp_ffi_napi.dylib` over that index.node → 618 pass / 0 fail. Without rebuild, addon tests run but fail on identity_create("in_memory") setup (graceful-skip only triggers when addon is ENTIRELY absent).

Enforcement: `pipeline_wiring.rs` new `native_execute_governance_action_resolves_proposal_by_id_from_engine` + `wasm_execute_governance_action_resolves_action_from_tracked_proposal` (added `extract_fn_signature` helper). sdk-capability-matrix.json execute_action row: added `notes` describing by-id shape, all 4 SDKs stay true (the python/typescript execute_action AST-mismatch warnings are PRE-EXISTING). Swift ScpBindings.swift regenerated via uniffi-bindgen (only governance_execute sig + checksum 38425→14006 changed). Kotlin generated bindings are gitignored (CI regenerates).
