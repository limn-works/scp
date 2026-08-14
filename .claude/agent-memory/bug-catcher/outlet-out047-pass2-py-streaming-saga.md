---
name: outlet-out047-pass2-py-streaming-saga
description: SCP-OUT-047 pass-2 Python SDK StreamingSagaHandle + 2 SCP methods (f48e071c2) — substantially CLEAN, 2 LOW
metadata:
  type: project
---

# SCP-OUT-047 pass 2 Python SDK streaming-saga wrapper (branch feat/outlet-xctx-047-streaming-saga-ffi @f48e071c2)

**Substantially CLEAN.** `StreamingSagaHandle` async-iterator + `outlet_invoke_cross_context_streaming_saga` (sync, lazy) + `recover_streaming_saga_truncated_close` (async). Faithful mirror of `InvocationHandle` minus the (correctly absent) live control plane.

Verified sound:
- Terminal chunk is YIELDED before StopAsyncIteration (return chunk after capture; next call StopAsyncIteration on `_closed`). None-poll (abnormal sender-drop) distinct from normal terminal (StopAsyncIteration; aggregate→ProtocolError). No hang introduced by SDK (poll_next blocks in FFI; ceiling bounds count).
- `_ensure_open` idempotent + guarded by asyncio.Lock (double-check `_saga_id is None`); open-error leaves `_saga_id=None` (reusable/receiver-never-handed-out); `_draining` reentrancy guard held ACROSS the `to_thread` await (raised BEFORE `_draining=True` so second driver doesn't reset owner's flag).
- **Param order EXACT** vs FFI `outlet_streaming_saga_open` (outlet_stream.rs:1793): 13 positional args caller_context_id,target_context_id,caller_did,outlet_registration_id,input,asserted_nonce_hex,timestamp_ms,chain_depth,ucan_token,proof_tokens,ucan_proof_id,timeout_ms,estimated_chunk_count — matches; test test_open_forwards_full_param_set_in_ffi_order locks it.
- Gap path: no receiver-cancel (correct — no xctx cancel plane §6.2.5); `_error=StreamGap` re-raised idempotently by aggregate.
- chain_depth 0..255 + timestamp_ms>=0 validation rejects bool+float, identical to unary sibling; runs BEFORE param capture (no open attempted on reject).
- `_saga_terminal_from_bridge` reads code from args[1], datum args[2] structurally; SagaAborted/NeedsRepair/Busy codes preserved.

**LOW #1 (systemic, NOT newly introduced): recover perm-gate `.code` collapses.** Bridge raises `ContextError` w/ SCP-PERM-3001 for hosted-but-non-invoker. `_translate_bridge_error` does `sdk_cls(str(exc))` with code=None → ContextError defaults to SCP-CTX-2000. So `.code` == "SCP-CTX-2000", NOT "SCP-PERM-3001"; only the *message string* contains SCP-PERM-3001. Caller cannot programmatically distinguish "not hosted/unknown saga" from "non-invoker" via `.code` on a money-moving op. Test only asserts substring in str() so passes despite wrong `.code`. Docstring promise ("rejected with SCP-PERM-3001") is misleading. Mirrors same-context grant/cancel behavior — systemic `_translate_bridge_error` limitation (memory: ContextError(code=None)→SCP-CTX-2000).

**LOW #2 (pre-existing #2098, not this PR): `_resolve_bridge` (outlets.py:62) dead code.** Genuinely unused across all of bindings/python (whole module uses `self._native` from construction). Pyright "not accessed" is CORRECT. Harmless.

**Pyright outlets.py:753 "unreachable" = FALSE POSITIVE.** grant_credit's `if not isinstance(grant, Credit)` runtime defense for dynamically-typed callers; unreachable only under the static `grant: Credit` annotation. Intentional, keep.

Non-issue: timestamp_ms has no SDK upper bound → >u64::MAX becomes ContextError (OverflowError→not-saga-terminal→_translate_bridge_error) at lazy open. Fails closed; identical to unary sibling.
