---
name: pr1911-saga-reject-ok-channel
description: #1911 §6.2.4 saga Prepare-A/B mailbox reply moves POLICY rejects to Ok(Rejected(SagaReject)) success channel; ADR-049 architecture review APPROVED
metadata:
  type: project
---

# #1911 saga Prepare reply: policy reject → Ok(Rejected) success channel

Branch saga-code-1911 @ 35be7185f. 4 files, scp-runtime only (actor/commands.rs, actor/handlers/saga.rs, actor/mod.rs, supervisor/supervisor.rs). ARCHITECTURALLY SOUND — approved.

**The change.** `SagaPhaseMessage::PrepareA`/`PrepareB` mailbox reply goes `Result<PreparedAFields, ContextError>` → `Result<PrepareAOutcome, ContextError>` (and B). New `PrepareAOutcome { Prepared(PreparedAFields) | Rejected(SagaReject) }`. `SagaReject { code: Option<u16>, error: ContextError }`. §6.2.4 POLICY rejects (capability/caller/rate/schema/freshness/replay/chain-depth — 20 sites) now ride `Ok(Rejected)` on the SUCCESS channel carrying a STRUCTURAL `SCP-SAGA-13xxx` code; only mailbox/transport/Class-S-persist failures stay `Err(ContextError)`.

**Why it's sound (not muddying the contract).**
- handle.rs `send` returns `Result<T, ContextError>` where Err = mailbox/transport infra (dropped receiver, actor gone). The reply PAYLOAD `T` carrying the app-level decision (Prepared vs policy-denial) is the textbook actor split: transport-Result ≠ application-Result. A policy denial is a *successfully computed decision*, not an infra failure → `Ok(Rejected)` is the correct semantics. This IMPROVES on the old shape where reject + dropped-receiver both came back `Err(ContextError)` disambiguated only by string-prefix parse.
- NOT a new precedent: Commit-B phases ALREADY use `CommitBReserveOutcome`/`CommitBSettleOutcome` enums on the success channel. This CONVERGES Prepare onto the existing pattern. `SagaReject`/`saga_reject!` are reusable for any future saga axis (§6.2.4 is the sole live saga).

**Class-S / RAII balance — no risk.** Two distinct "Outcome" types (naming collision, the only maintainability nit): `outcome::Outcome<()>` drives Class-S persistence accounting (`Outcome::err`/`err_mutated`/`ok_mutated`); `PrepareAOutcome` is the mailbox reply. Handler does BOTH (send reply + return Outcome) exactly as before — only the reply payload shape changed; the `Outcome::err`/`err_mutated` returns are byte-identical to pre-change, so the commit-token/RAII machinery (keyed off Outcome, not reply) is untouched. `#[must_use]` `ToolEconomyReservation` carrier moves by value through `Prepared`; lost-receiver recovery destructure updated correctly; `Rejected` arm carries no reservation.

**The real win.** DELETED `saga_code_from_message` string parser — the code is now carried structurally end-to-end (FSM `saga_reject!` → mailbox `SagaReject.code` → `RunSagaError.saga_code` → `lift_run_saga_error` reads `saga_code.unwrap_or(13067)`). Removes a source-text re-derivation of a property the type system now carries soundly (the CLAUDE.md "don't re-check in weaker string form" guard). Non-vacuity test `lift_reads_saga_code_structurally_not_from_message` embeds a DELIBERATELY-WRONG token in the message + asserts structural code wins.

**Completeness (compiler-enforced).** FSM→mailbox→supervisor lift→FFI all wired. Generic `start_saga` correctly discards extras via `.map_err(|e| e.error)`. Skeleton actor mod.rs = comment-only. FFI `decompose_saga_error` (scp-ffi/common/src/saga_errors.rs) UNTOUCHED — already reads `SagaError::Aborted { code, .. }` structurally; this change just populates that field structurally instead of by parse. Every early-return in prepare_a/b sends a reply (no drop-receiver-without-reply); the 2 `reply.send(Err(persist_err))` paths intentionally stay infra-channel → 13067. `saga_reject!` macro = closed 4-variant set (PermissionDenied/InvalidState/ContextNotRegistered/RateLimited), fails-compile on unsupported variant — bounded, sound. No DOA.
