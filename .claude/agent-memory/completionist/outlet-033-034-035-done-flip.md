---
name: outlet-033-034-035-done-flip
description: SCP-OUT-033/034/035 done-flip audit @f96079706 — runtime ACs genuinely met+tested; 2 real cross-layer gaps (unwired verified-appender, FFI sink=None)
metadata:
  type: project
---

# SCP-OUT-033/034/035 done-flip audit (@f96079706, feat/outlet-xctx-streaming-saga)

Verdict: RUNTIME-scoped ACs GENUINELY MET with real non-gamed tests (done-flip honest for the runtime deliverables). Two real completeness gaps at the runtime↔FFI boundary that the COMMIT MESSAGE overstates.

Real tests confirmed (all drive the actual pump / real Ed25519, not string-search stubs):
- 033 timeout: invoke.rs:5687 invoke_outlet_streaming_timeout_..._033_ac10_034_ac7 drives streaming pump via invoke_outlet, 50ms timeout, asserts terminal Error code=CODE_EXECUTION_FAULT(6130)+terminal+msg "timed out". 033 panic: invoke.rs:5567.
- 034 billing: dispatch.rs:5021 ten_data→billed 10 refund 0; :5330 pump_midstream_cancel_truncates_billing (cancel@5 after 8 Data → billed_count=5, chunks_billed=5, refund=3, Cancelled status) — the §5.4.5:530(3) over-bill-by-one fix; :5251 credit_stall_after_three→billed 3 refund 7 (6133); :5196 cancel_then_silence→6135; :5073 hundred_chunks with REAL sign_credit_grant window32→billed 100.
- 034 grant sig: scp-protocol stream.rs:1802/1818/1830/1852 replay/bad-sig/identity-mismatch/cross-epoch all real Ed25519.
- 034 AC32 monotonic crash-safety: scp-ffi/src/outlet_stream.rs:1305 sdk_restart_midstream uses SqliteStorage, 3 grants(0,1,2), close, REOPEN fresh handle same DB, resumed=3>prior_max. Durable cursor scp-ffi/common/outlet_stream_credit.rs next_grant_monotonic_seq persist-before-return, key context/{id}/stream_credit_counter/{rid}. Wired 3 native bridges (PyO3 direct :836; napi :832/uniffi :824 via ProtocolRepoVariant::next_stream_credit_seq bridge_runtime.rs:444).
- 035: invoke.rs:5762 single-event chunk_count=5; :5836 one-shot 2-chunk; :5904 failed→Error(code); :5980 replay recomputes compute_chunk_manifest_root byte-identical. RFC-6962 INDEPENDENT KATs scp-protocol stream.rs:3106/3128 use recursive split-at-largest-pow2 MTH + hardcoded golden hashes (leaf0/root2/root4).
- G4: spec 05-contexts.md:521 6100→6101 landed; error_codes.rs:96 CODE_PROTOCOL_SESSION=6101 family includes protocol.context-closed-mid-stream; stream.rs:988 ContextClosedMidStream→CODE_PROTOCOL_SESSION. Consistent.
- G5 cost:None SOUND+spec-cited (invoke.rs:3843 §5.4.5:570-579 event shape omits cost; amount lives in PaymentReceipt §19.15.5). Not hardcoded-None-where-data-exists.
- cancel_ack_seq: lifecycle.rs:321 #[serde(default, skip_serializing_if=Option::is_none)] byte-identical wire; 2 MCP struct-literal sites (mcp.rs:1064, uniffi bridge.rs:4863) set None (legit synchronous non-streaming). Build passes ⇒ no uncompiled sites. verify_outlet_invoked_event_local backstop KEPT (event_log.rs:771, stream.rs:1560). No #[ignore] added.

TWO REAL GAPS (commit-message overclaim, not gaming of tests):
1. append_outlet_invoked_verified (event_log.rs:266) is TEST-ONLY — exactly 3 callers, all in 2 test fns (:1142/:1206). Commit msg claims it's the log-insert wire-rejection "for one-shot/xctx/import" — FALSE (grep repo-wide = 0 prod callers). Pump uses verify_outlet_invoked_event_manifest(Frontier) INLINE (dispatch.rs:3292), a DIFFERENT fn. So AC23's STRONG manifest-derived rejection (chunks_billed != chunks_billed_ref) at the real prod log-insert boundary (append_event) does NOT run — append_event only does the WEAK <=count backstop. Honest pump self-protects via frontier; residual exposure = OTHER writers (import/xctx/replay) get only <=count. AC22/23 verified by real test but tested guarantee not on a live insert path.
2. invoked_event_sink=None in ALL 3 FFI bridges (PyO3 outlet_stream.rs:577, napi:610, uniffi:610). Only Some(sink) caller is the internal pump guard. So OutletInvokedEvent (035's "ONE event per stream at close") is NEVER persisted to durable event log in any shipping FFI streaming path — only tests supply a sink. settlement_sink IS wired (money moves + PaymentReceipt) but does NOT append the audit event. PRE-EXISTING from 037/038/039 (#2125). 035 files[] cites nonexistent manager/outlets.rs (stale post-ADR-049-actor path).

LOW: slug not durably recorded — timeout/panic/non-det all collapse to Error(6130); ChunkPayload::Error{code,message,terminal} has NO slug field; finer slug only in tracing. Intentional §5.4.4 code grouping. Test-name AC numbers scrambled vs PRD (±1) but content covers.
