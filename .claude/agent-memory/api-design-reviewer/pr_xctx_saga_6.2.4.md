---
name: pr-xctx-saga-6-2-4
description: §6.2.4 cross-context tool-invocation saga API review — named-field request/keys structs eliminate same-typed transposition; SCP-SAGA code sub-ranges; receipt signer-authorization
metadata:
  type: project
---

Branch `feat/actor-2c-6.2.4-xctx-saga`. Reviewed the §6.2.4 saga public API surface (read-only, findings-only).

**Verdict: APPROVED.** Strongest transposition-resistance work I've seen in this codebase.

Key surfaces:
- `Supervisor::start_cross_context_tool_invocation_saga(request: CrossContextToolInvocationRequest, signing_keys: SagaSigningKeys<'_>, executor)` — all same-typed positional params eliminated. Two adjacent `[u8;32]` ids + 3 String fields now named in `CrossContextToolInvocationRequest`; two adjacent `&SigningKey` now named-by-role in `SagaSigningKeys{target,caller}`. Keys/executor kept OUT of the request struct (capabilities vs envelope data) — correct separation.
- `CrossContextToolReceipt::sign(&SigningKey, CrossContextToolReceiptFields)` — same pattern; signing key stays separate param. `verify(&VerifyingKey)` requires caller-resolved authorizing key (signer-authorization is an INPUT, never receipt-named). Excellent misuse-resistance: a forged receipt naming its own key can't self-authorize.
- `CommittedSide` enum (not bool) for divergence marker; `tag()` stable 0/1 discriminator bound into preimage.
- Two-step Commit-B split: `CommitBReserve`→`CommitBSettle` with `CommitBReserveOutcome{ReadyToExecute, AlreadyCommitted{...}}` driving exactly-once executor. Idempotency surfaced in the type, not docs.
- `SCP-SAGA-13000-13999` partitioned: 13000-13009 protocol, 13010-13049 handler, 13050-13099 supervisor, 13100+ reserved. Registry table in sdk-common.md. Codes verified unique-per-condition (duplicate grep hits are tests/doc-refs to one def).
- `SagaPhaseMessage` is `#[non_exhaustive]` + exhaustive dispatch match (adding a phase = compile error). Good.

Minor observations only (non-blocking):
- `CrossContextDivergenceMarker::sign(key, saga_id, nonce, committed_side, event_id)` still POSITIONAL — `saga_id`/`committed_event_id` are two adjacent `String` params, transposable. Inconsistent with the Fields-struct pattern applied to receipt/request. Lower-stakes (both feed same preimage, swap changes signed bytes detectably) but breaks the convention.
- `SagaOutput.receipt`/`.output` are `Option<Vec<u8>>` (None for standing-pair/broadcast). Stringly/bytes-typed; a committed xctx saga always has Some. Consider an enum over saga-family outputs long-term, but acceptable given one wired variant.
- `caller_did` is typed `DID` end-to-end; narrows to `String` (`.0`) only at the protocol receipt struct boundary which requires String. Acceptable.
