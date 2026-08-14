# #1911 saga FSM structural SCP-SAGA codes (Jun 30 2026, worktree saga-1911-bh @35be7185f)

**CLEAN — no defects.** §6.2.4 xctx-tool saga now carries SCP-SAGA codes STRUCTURALLY (SagaReject{code:Option<u16>, error}) instead of parsing them from message strings. `saga_code_from_message` DELETED; `lift_run_saga_error` reads `saga_code.unwrap_or(13067)`.

Traced full chain leaf→reply→run_saga_fsm→RunSagaError→lift:
- **From over-capture: SAFE.** All 20 Prepare-axis coded sites (13010-13027, 13051-13053) build via `saga_reject!` macro and propagate as `Result<_,SagaReject>` (via `?` on matching type, or direct `match outcome{Rejected(r)=>Err(r)}`). NONE route through `From<ContextError>` (which sets code:None). Only genuine infra `?`/`.into()` hit From: append_journal, abort_saga-failure, resolve_committed, commit-exhaustion, phase-timeout → all correctly codeless→13067 (or NeedsRepair).
- **Codeless aborts: correct.** TransportTimeout→None→13067; token-bucket ECON RateLimited→None→13067 with reason=RateLimited{retry_after_ms} (reason derived from error VARIANT in lift, independent of code, so retry_after_ms survives); journal InvalidState→None→13067.
- **needs_repair precedence: correct.** `if needs_repair{return NeedsRepair}` (13065) BEFORE code resolution. commit-exhaustion sets needs_repair=true + code None.
- **Macro single-source: correct.** code literal Some($code) + `concat!("SCP-SAGA-{}: ",$fmt)` prefix both from $code — cannot diverge. RateLimited arm preserves $rms (retry_after_ms).
- **large_enum_variant allow: no bug.** Prepared(PreparedAFields w/ ToolEconomyReservation drop-guard) moves by value; reject path constructs no carrier; prepared path delivers to FSM or recovers+balances in lost-receiver `if let Err(returned)=reply.send(..) && let Ok(Prepared{reservation})=returned` branch (void_external_and_consume). No balance leak.
- **dispatch exhaustive:** dispatch_xctx_prepare_a/b match Prepared|Rejected; mod.rs skeleton acks not-impl.
- **13030/13063/13064** (Commit-phase raw ContextError, NOT macro): flow commit_with_retry→exhaustion→NeedsRepair(13065); lift needs_repair short-circuit ignores code. Never surfaced as Aborted.code even pre-PR (only reach lift via needs_repair). NOT a regression.
- **13050/13062** pre-reserve gates: built directly as SagaError::Aborted{code} in public entry, unchanged by PR.

Tests: 82 saga tests pass. MUTATION-PROVEN: (1) routing 13010 through `From` → code None → test `prepare_a_rejects_caller_without_tool_interface` fails (None vs Some(13010)). (2) flip call-site literal 13011→13099 → `prepare_a_rejects_caller_not_in_allowed_callers` fails (Some(13099) vs Some(13011)). Per-site `assert_eq!(reject.code, Some(N))` asserts have teeth. Build does NOT deadlock against main WIP in this worktree.
