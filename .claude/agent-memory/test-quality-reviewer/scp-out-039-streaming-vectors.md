---
name: scp-out-039-streaming-vectors
description: SCP-OUT-039 outlet-streaming conformance vector tests (5 tiers) — flakiness/robustness/behavior review on feat/outlet-streaming-ffi
metadata:
  type: project
---

# SCP-OUT-039 streaming conformance vectors (branch feat/outlet-streaming-ffi)

Reviewed 5 test tiers replaying `tests/conformance/vectors/outlet_stream_vectors.json`
(7 vectors, 29 total chunk descriptors: non_streaming=2, multi_chunk=11, cancellation=4,
error_terminal=2, error_recoverable=5, sequence_gap=3, credit_exhaustion=2).

**Verdict: SHIP with minor revises.** Runtime tiers are HIGH ROI; bridge tiers reasonable.

Key structural facts:
- `poll_next` (crates/scp-ffi/src/outlet_stream.rs:686) BLOCKS on `recv().await` (no per-poll
  timeout). So bridge live-drain `for _ in 0..16` caps bound ITERATIONS not wall-time — a hung
  pump HANGS the test instead of failing fast. Runtime tiers correctly wrap recv in
  `tokio::time::timeout(10s)`. Bridge tiers (pyo3/napi/uniffi live) do NOT → inconsistency.
- Timers are REAL wall-clock, NOT paused: credit_stall_secs=1, cancel_ack_secs=1, outer
  timeout 10s (10x margin). credit_exhaustion + cancellation runtime tests wait ~1 real sec.
  Acceptable margin; not virtual-time-deterministic.
- credit_exhaustion runtime test is GENUINELY strong: build_script special-cases err=="6133"
  string → emits credit_window+1 Data, Block; real stall timer fires 6133 terminal; asserts
  chunk0 Data=={"n":0} + terminal Error 6133. String-coupling to "SCP-OUTLET-6133" is
  load-bearing but self-consistent (fails loud if vector code renamed).

Biggest ROI caveat (all 5 gap tests): the "receiver MUST cancel on gap" rule is implemented by
the TEST's `ReceiverSequenceTracker`, NOT production code. `code=="SCP-OUTLET-6131"` compares a
test-hardcoded constant; only the gap POSITION (fired_at==Some(2)/cancelled_at==Some(3)) and the
`vector["expected_error_code"]==6131` cross-check are non-tautological. Real production coverage
in gap tests = sign_chunk/verify_chunk_signature wire integrity only. DOCUMENTED as slice-3
transport deferral, honest, but test NAME (`..receiver_tracker_cancels_with_6131`) can mislead.

Weakest assertion: pyo3 `cancellation_control_plane_and_terminal` final assert
`chunks.last().is_some_and(terminal) || chunks.is_empty()` — is_empty() escape hatch makes it
near-tautological. napi/uniffi live equivalents use `assert!(saw_terminal)` (stronger, no escape).

Duplication: the two scp-testing runtime files (outlet_stream_conformance.rs /
outlet_stream_vectors_through_open_path.rs) are SEPARATE [[test]] binaries (Cargo.toml:100-106)
but ~90% verbatim-identical (schema, VectorPayload, ScriptedExecutor, ReceiverSequenceTracker,
build_script, apply_grant, assert_transcript_matches, assert_terminal_status). Only drive_vector's
open call differs (raw open_stream_session vs Supervisor::open_outlet_stream). Could be a shared
`#[path] mod`. Cross-crate copies (napi/uniffi/wasm/pyo3) more justified (ADR-034 wasm can't dep
tokio; napi/uniffi need pub(crate) seams). Minor divergence: runtime tracker returns constant
`CODE_EXECUTION_CREDIT`; others hardcode string "SCP-OUTLET-6131" (same value 6131).

Magic 29: USEFUL tripwire (independent of loop; catches a dropped/truncated vector). Only wasm
has the per-vector breakdown comment; napi/uniffi copies lack it. Naming smell: CODE_EXECUTION_CREDIT
(6131) is shared by execution.credit-exhausted AND execution.stream-gap AND stream-cap-exhausted;
credit-STALL is the distinct 6133.
