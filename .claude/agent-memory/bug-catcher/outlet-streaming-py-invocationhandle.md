# outlet-streaming Python InvocationHandle (C11a, SCP-OUT-038, commit 3de014f40)

Reviewed `bindings/python/scp_sdk/outlets.py` InvocationHandle state machine (awaitable + async-iterable, shared drain over `outlet_stream_poll_next` via `asyncio.to_thread`). Branch `feat/outlet-streaming-ffi`.

## MEDIUM — data-plane bridge errors NOT translated (mirrored x4)
`_ensure_open` (calls `outlet_stream_open`) and `__anext__` (calls `outlet_stream_poll_next`) do NOT wrap the FFI call in `_translate_bridge_error`, unlike `grant_credit`/`cancel` in the SAME file (outlets.py:682/709) and every other SDK module (trust.py, scp.py). So raw `_scp_core` bridge exceptions leak from `await handle` / `async for`. Bridge raises typed errors here: open → `ScpPyError::ucan` (UCAN denial), `validate::*` ValidationError (input-schema), `ScpPyError::context`; poll_next → `no_active_stream_err`=`ScpPyError::context` (unknown handle). These are a DIFFERENT class hierarchy than `scp_sdk.errors.*` — and `UcanError`→`UcanPermissionError` even differs by name in BRIDGE_ERROR_MAP — so caller `except OutletError`/`except UcanPermissionError`/`except ValidationError` around the data plane SILENTLY MISSES. Fix: wrap open + poll_next to_thread in try/except → `_translate_bridge_error` (like grant/cancel). Untested (mock never raises from open/poll).

## Verified SOUND (sequential single-consumer state machine)
- iterate-partway→await: aggregate() drains rest, End.aggregate is full server-computed aggregate (not partial). OK.
- double-await / iterate-to-end-then-await: idempotent cached `_aggregate`. OK.
- terminal paths ALL set `_closed`: End, terminal Error, poll None. OK.
- no-End close (poll None) → ProtocolError; terminal Error → captured `_error` raised on await, yielded as chunk on iterate. OK.
- to_thread never mutates shared state (cursor is server-side; `_closed`/`_aggregate`/`_error`/`_handle_id` mutated only on event-loop thread). No data race. OK.
- grant/cancel `_closed` guard TOCTOU is NOT reachable: `_ensure_open` returns synchronously (no await/yield) when already open, so no task can flip `_closed` between the guard and the dispatch. First-open case can't be terminal yet. OK.
- `bytes(raw)` normalizes both mock `bytes` and live PyO3 `Vec<u8>`→`list[int]`. OK.

## LOW
- Multi-consumer undefined: two concurrent `async for`, or concurrent await+iterate, both call `__anext__`→concurrent poll_next → chunk-stealing between consumers (aggregate still correct since End sets `_aggregate` for whoever polls it). Contract implies single shared sequential drain; no guard/assert against concurrent iterators. Consider a re-entrancy guard.
- Mock faithfulness (point 6): mock poll_next returns `bytes`; live bridge returns `list[int]`. `bytes(raw)` covers both but the list[int] shape is never exercised by the 31 contract tests.
