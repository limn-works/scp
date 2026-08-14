---
name: adr049-624-saga-slice5
description: ADR-049 §6.2.4 cross-context tool-invocation saga slice 5 — supervisor FSM dispatch over two local actors + supervisor-side executor
metadata:
  type: project
---

§6.2.4 saga slice 5 ("keystone") wires the supervisor FSM to drive a cross-context tool-invocation saga end-to-end over TWO co-resident context actors. Built on branch `feat/actor-2c-6.2.4-xctx-saga` (parent SHA 694410b7a = slice 4).

**Why:** Slices 3b/4 already landed the actor-side handlers (`handlers/saga.rs`: prepare_a/prepare_b/commit_b_reserve/commit_b_settle/commit_a/abort/emit_divergence_marker — all complete with SCP-SAGA-13xxx error band). Slice 5 makes them RUN: `run_saga_fsm` previously threaded NO per-phase data and all production arms returned NotImplemented.

**How to apply / key facts:**
- The actor-side handlers are the system of record for validation — the FSM only sequences messages + holds per-phase data (PreparedAFields → PreparedBFields → executor output/receipt). It carries NO signing key.
- Receipt/divergence-marker signing keys are SUPPLIED BY THE CALLER (FFI/SDK boundary) — the runtime holds no custody key (mirrors send_heartbeat/build_local_checkpoint which take `signing_key: &ed25519_dalek::SigningKey`). See [[lesson_actor_boundary_no_key_no_retrieval]].
- The tool EXECUTOR closure is ALSO caller-supplied (`FnOnce(serde_json::Value) -> Fut`), exactly like `invoke_tool_with_economy`. It runs supervisor-side BETWEEN CommitBReserve and CommitBSettle (non-Send, can't cross mailbox per ADR-049 §3). The OUTLET streaming bridge replaces this executor at slice 7.
- `ContextActorHandle::send<T,F>(|reply| ContextCommand::SagaPhase(SagaPhaseMessage::X{..,reply}))` is the AWAITING send helper (creates oneshot, embeds via factory, sends w/ timeout, awaits reply). `dispatch_via_mailbox` is fire-and-forget — NOT for the FSM.
- `lookup(&hex(ctx_id))` resolves a co-resident actor handle; `None` ⇒ typed error (co-resident scope only; child-bridge cross-node is future work).
- `SagaInput::CrossContextToolInvocation` was UNDER-specified (only caller/target ctx ids + caller_did + tool_reg_id). PrepareB needs ucan_proof_id/input/asserted chain_depth+nonce+ts; PrepareA needs declared_cost — all wired through (no None stubs).
- Co-resident-scope decision: both caller+target are locally-controlled actors in ONE supervisor.
- Authorize-before-reserve: verify initiator is a member of caller_context_id (Supervisor::is_member) BEFORE try_reserve_context_set (the forward-obligation documented at supervisor.rs ~4464).
- StandingPairCreate + BroadcastHostingHandshake stay NotImplemented (concurrency-gating tests in actor_saga_concurrent.rs use them + TestForceNeedsRepair).
- `actor_saga_concurrent.rs` cross_context() sagas previously asserted NotImplemented; slice 5 makes them real → with no registered actors the FSM aborts on lookup-miss (typed co-resident error), still non-ActorBusy + releases reservation. Those assertions were retargeted.
- GATE: check-handler-no-panic.sh brace-depth mis-scopes ~8 pre-existing `panic!()` in `#[tokio::test]` fns in supervisor.rs whenever supervisor.rs is in a diff. Sanctioned fix = convert those test-assertion panics to `assert!(matches!(...))`. Do NOT edit the gate script.
- GATE: check-saga-gating-granularity.sh P4 structurally requires `try_reserve_context_set(` to be called LITERALLY inside `fn start_saga`'s body (not in a shared helper). When adding a second saga entry point (start_cross_context_tool_invocation_saga), reserve in EACH entry point and pass the `SagaSetReservation` guard into the shared `run_saga` driver — don't move the reserve into the shared helper or the gate fails.
- DONE 2026-06-18, committed 8abd02cbc on feat/actor-2c-6.2.4-xctx-saga (parent 694410b7a). Lib 1788/0, 4 new E2E tests pass (xctx_saga_happy_path_commits_and_executes_once, _prepare_b_confused_deputy_aborts_no_execution, _overlapping_set_is_saga_busy, _commit_replay_reemits_without_reinvoke). All 4 gates exit 0. Full-workspace CI clippy clean.
- GOTCHA: ToolEconomyTicket has a `Drop` debug_assert that PANICS if dropped un-consumed. The FSM must never let a held `PreparedAFields` reservation drop unbalanced — settle via Commit-A, roll back via the actor's Abort handler, or (actor unreachable / residual NeedsRepair) call `ticket.void_external_and_consume(payment_adapter_ref())`. The `run_saga` tail drains any residual `prepared_a` and voids it.
- GOTCHA: the boxed saga executor + its future MUST be `Send` (`Box<dyn FnOnce -> Pin<Box<dyn Future + Send>> + Send>`), else start_saga's future is !Send and can't be spawned. "Executor can't cross the mailbox" (ADR-049 §3) means not embedded in a ContextCommand, NOT non-Send.
- E2E test lives IN supervisor.rs `mod tests` (not tests/) because it needs `pub(in crate::context) spawn_actor_with_state`. `is_member` reads `state.membership` (add via `membership.add_member`), the Prepare-A outbound gate reads `role_state`.
