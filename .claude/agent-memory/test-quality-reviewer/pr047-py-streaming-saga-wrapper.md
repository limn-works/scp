---
name: pr047-py-streaming-saga-wrapper
description: SCP-OUT-047 pass-2 Python StreamingSagaHandle mock-driven wrapper tests (test_outlets_streaming_saga.py) — SHIP w/ strengtheners
metadata:
  type: project
---

# SCP-OUT-047 Python streaming-saga SDK wrapper tests

Branch feat/outlet-xctx-047-streaming-saga-ffi @ f48e071c2, worktree /Users/alec/Developer/limn/scp-wt-047.
File: bindings/python/tests/test_outlets_streaming_saga.py (18 tests). SDK under test:
outlets.py StreamingSagaHandle (lines 950-1154) + scp.py outlet_invoke_cross_context_streaming_saga
(2583) / recover_streaming_saga_truncated_close (2680).

VERDICT: SHIP. Mock-driven at the REAL `self._native` seam (methods invoked unbound with
`scp._native = native`), so mocks exercise real wrapper drain/translation/forwarding — NOT vacuous.
Matches the identical convention as sibling test_outlets_streaming.py (`_FakeNative` scripted
`_native`, class-name-driven bridge excs). Coder's "100% existing outlet/saga tests mock `_native`"
corroborated.

**Why:** flat mock injection at `_native` is genuine because outlets.py reads self._native directly
(1043/1085) and scp.py passes self._native (2678). Layer boundary honestly drawn: FFI-behavioral
claims (runtime non-blocking-open FSM, billed_count, exec-once) delegated to VERIFIED-PRESENT Rust
tests — supervisor.rs:31482 xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6, :31732 _truncated_close_ac7,
e2e_bridge.rs:1824-2008 five xctx_streaming_saga_* rejection tests. FFI recover returns () → billed_count
unobservable in Python by construction (docstring accurate, not a dodge).

**How to apply / key findings:**
- AC6 strong test = test_consumes_chunks_before_gated_terminal: `_GatedTerminalSagaNative` parks the
  TERMINAL poll on a threading.Event; because __anext__ polls once per call and drain runs in
  asyncio.to_thread, consumer gets all data chunks while terminal gated. A block-until-terminal
  (buffering) impl would DEADLOCK at first __anext__ and trip the 5s guard. Genuinely distinguishes
  progressive vs blocking — not a call count. GOOD PATTERN to replicate for progressive-drain proof.
- Structural error translation: `_bridge_exc` builds `type(name,(Exception,),{})(*args)` so class NAME
  drives _saga_terminal_from_bridge / BRIDGE_ERROR_MAP dispatch, reading (msg,code,datum) tuple
  positionally — mirrors real ScpPyError→PyO3 conversion. .code / .saga_id asserts load-bearing.
- test_second_concurrent_driver: single `await asyncio.sleep(0)` IS sufficient — __anext__ sets
  _draining=True synchronously before first await, second __anext__ raises before any await. Deterministic.
- NON-BLOCKING flakiness residuals to add (mock-coverable, all low-cost):
  (1) aggregate() idempotency after full async-for — assert poll_calls unchanged on cached re-return (UNTESTED real logic);
  (2) test_sequence_gap_raises_stream_gap_without_cancel UNDER-ASSERTS its name — only checks raises(StreamGap),
      never asserts NO bridge cancel (saga handle must NOT cancel on gap unlike same-context; outlets.py:1095-1107).
      Add a cancel-counter negative assert;
  (3) poll_next-receives-minted-saga_id unverified (_FakeSagaNative ignores its arg → wrong-id mutation survives);
  (4) non-saga open rejection fall-through (_translate_saga_open_error → BRIDGE_ERROR_MAP branch) untested — only saga-terminal branch (AC5) covered;
  (5) cached-error re-raise on 2nd await untested.
- Minor: uses MagicMock (child-mock on typo'd attr) vs sibling SimpleNamespace (AttributeError fail-fast). Harmless, sibling stronger.

LESSON: a "without_X" test name is a claim the test must ASSERT (absence of X), not merely a fact the
production code happens to guarantee structurally. Grep the test body for a negative assert matching the name.
