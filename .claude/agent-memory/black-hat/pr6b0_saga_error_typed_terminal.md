---
name: pr6b0-saga-error-typed-terminal
description: PR 408c3079b SagaError typed-terminal review — escrow fix verified complete; one residual mark_resolved-misclassification finding
metadata:
  type: project
---

# PR 408c3079b — typed SagaError terminal (§6.2.4), 3rd-defect escrow fix

Commit 408c3079b on /tmp/scp-pr6b0-review. base e406c15c5.

## Escrow fix (3rd defect) — VERIFIED COMPLETE & CORRECT
- supervisor.rs run_saga_fsm Err(err) arm (~6818): `ctx.reached_needs_repair = true`
  set at 6835-6837 BEFORE `append_journal(NeedsRepair).await?` (6838). Flag is the FIRST
  op in the Err arm — NO `?`/await between arm-entry and flag-set. So a journal-durability
  failure on the NeedsRepair append no longer downgrades a diverged saga to clean Aborted,
  and run_saga tail (5682-5709) leaves escrow HELD via hold_external_for_repair (5690).
- Flag NOT set too early: only reachable inside Err arm of `commit_result` = commit_with_retry
  exhausted (3x). commit_with_retry only returns Err after BACKOFFS loop exhausts (7055).
- Even a "clean" NeedsRepair (Commit-B never landed, no divergence marker, 6864-6869) still
  holds escrow — correct conservative posture (never auto-refund a possibly-charged saga).
- commit_a_settle does `prepared_a.take()` (7379) so on success prepared_a=None → tail void
  block (5697) is a no-op → no double-void, no leak.

## RESIDUAL FINDING (MEDIUM, NOT fixed by this commit): mark_resolved(Committed)-fail → Aborted
- run_saga_fsm Ok(()) arm (6805-6816): after a FULLY successful dual-commit (Commit-B settled,
  Commit-A settled+escrow consumed, ctx.committed set), `mark_resolved(Committed).await
  .map_err(InvalidState)?` (6806-6815) is a REAL fallible I/O op (saga_journal.rs:658 real impl
  does list_keys/store → JournalError::Io on disk-full/backend failure).
- On that failure: reached_needs_repair=false (we're in Ok arm) → RunSagaError{needs_repair:false}
  → lift_run_saga_error → message "saga journal mark_resolved: {e}" has NO SCP-SAGA- prefix →
  saga_code_from_message=None → unwrap_or(13067) → SagaError::Aborted{reason:Rejected,code:13067}.
- But the SagaError::Aborted doc CONTRACT asserts "Aborted ⇒ neither side committed". Here BOTH
  sides committed. Caller seeing Aborted may re-issue the saga (NEW SagaId ⇒ different idempotency
  key ⇒ genuine DOUBLE tool execution + double charge). Economic/correctness misclassification.
- MITIGATED durably: crash-recovery recover_committing_entry (6294) re-resolves a Committing-last
  saga whose both sides committed back to Committed (6303). So durable truth is recoverable; only
  the SYNCHRONOUS caller return value lies.
- Root cause: sdk-common.md:117 registers 13067 as "journal I/O failure" generically — conflates
  pre-commit journal failures (genuinely Aborted) with the post-commit mark_resolved failure
  (committed-but-unresolved). Correct fix: Ok-arm should set reached_needs_repair=true (or a
  dedicated Committed-unresolved terminal) so it lifts to NeedsRepair, not Aborted.
- NO test covers mark_resolved-fail-after-commit.

## Prior fixes RE-VERIFIED intact
- retry_after_ms: sliding windows Some(secs*1000) (saga.rs:704/720/814); token-bucket hard
  limits None (tools_helpers:545, lifecycle:734, messaging:951). outcome.rs:120-127 exhaustive
  match preserves *retry_after_ms. No Some(0) coercion anywhere.
- 13067 generic fallback truthful (registry 13067 = generic, 13065=NeedsRepair, 13066=Busy added).
- 13050/13062 now via TYPED explicit code (not message-parsed). saga_code_from_message only on
  FSM-error lift; genuine messages put SCP-SAGA- at position 0 → find() FIRST-occurrence wins,
  attacker DID/tool_id after prefix can't override. No crafted-message code-forcing.
- Clone/PartialEq/Eq on SagaError: no secret material in any variant (SagaId=UUIDv4, no key);
  no security-decision uses PartialEq. No adversarial exposure.
- saga_id integrity: minted once at start path (5594 SagaId::new()), same id flows to Ok
  SagaOutput.saga_id AND NeedsRepair{saga_id}. run_saga no longer mints internally.
