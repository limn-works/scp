# SCP-SAGA-13068 MailboxSaturated lift (commit 693d94a1c, #121) — CLEAN

`lift_run_saga_error` now resolves (reason,code) by structural match on &ContextError:
ActorBusy(_) => (MailboxSaturated{None}, 13068) [code HARDCODED, ignores saga_code];
RateLimited{..} => (RateLimited, saga_code.unwrap_or(13067)); _ => (Rejected, unwrap_or(13067)).

VERIFIED no defects:
- Scoping sound: ActorBusy can only reach the match with needs_repair=false from a Prepare-phase
  send (dispatch_xctx_prepare_a/b `actor.send().await?` → closed/full mailbox → ContextError::ActorBusy
  via handle.rs:136/139; From<ContextError> for SagaReject sets code=None). Commit path:
  commit_with_retry ALWAYS returns Ok or exhausts all 3 BACKOFFS → Err, and run_saga_fsm sets
  reached_needs_repair=true BEFORE the fallible NeedsRepair append → needs_repair=true short-circuits
  to NeedsRepair above the (reason,code) match. resolve_committed_or_needs_repair only returns
  InvalidState (not ActorBusy) and also sets reached_needs_repair. So NO commit-phase ActorBusy
  reaches the match with needs_repair=false.
- No coded reject uses ActorBusy: all saga_reject! invocations (saga.rs + supervisor.rs) use
  PermissionDenied / RateLimited / InvalidState / ContextNotRegistered — never ActorBusy. So the
  hardcoded 13068 (ignoring saga_code) never clobbers a real structural code. §3a overlap ActorBusy
  is mapped to SagaError::Busy in start_cross_context_tool_invocation_saga BEFORE run_saga — never
  reaches lift. lift is called from exactly ONE site (5652).
- Patterns correct vs ContextError def (scp-protocol/src/context/mod.rs:377/516):
  RateLimited{resource,message,retry_after_ms} matched as `{retry_after_ms, ..}`; ActorBusy(String) as `(_)`.
- FFI fold (saga_errors.rs:114-118) exhaustive over 3 SagaAbortReason variants; RateLimited|MailboxSaturated
  => retry_after_ms, Rejected => None; code formatted separately as SCP-SAGA-{code}. No field/code swallowed.
- Integration test deterministic: spawn_xctx_pair registers caller+target at their hex; test overwrites
  ONLY target_hex with from_sender(tx)+drop(rx). lookup(target_hex)=Some (no 13053); send to dropped-receiver
  mpsc returns Err immediately (closed-channel arm), no 30s hang. Any target-routed gate OR Prepare-B yields
  ActorBusy → MailboxSaturated/13068; assertion is outcome-based so robust even if first failing send isn't
  literally Prepare-B. Keystone + every-terminal tests pin the pre-fix mutation (assert_ne Rejected / 13067;
  SagaAbortReason derives PartialEq,Eq). Display `#[error("SCP-SAGA-{code}: ...")]` satisfies contains check.

Minor (NOT a bug): ActorBusy + saga_code:Some(X) is unreachable in production and untested; hardcoding 13068
is the intended semantics regardless.
