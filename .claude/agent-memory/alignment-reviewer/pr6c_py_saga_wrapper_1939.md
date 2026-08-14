---
name: pr6c-py-saga-wrapper-1939
description: PR-6c slice PY (#1939) — Python SDK wrapper SCP.tool_invoke_cross_context_saga over PyO3 §6.2.4 bridge export; ALIGNED 0 findings @ 561da74a3
metadata:
  type: project
---

# PR-6c slice PY (#1939) Python SDK wrapper for §6.2.4 saga @ `561da74a3` — ALIGNED, ship, 0 findings, 2 OBS

Follows PR-6b (#1950) which landed the 3 native bridge exports. This slice = Python SDK wrapper ONLY.
Scope CLEAN: 8 files, all `bindings/python/scp_sdk/*` + matrix + `scripts/check-sdk-coverage.py` alias. No Rust, no other SDK.

**Why ALIGNED:**
- Faithful bridge wrap. SDK `SCP.tool_invoke_cross_context_saga` (scp.py:2042) forwards 9 params in EXACT order/names to PyO3 export (tools.rs:1942, verified `#[pyo3(signature=...)]`): caller_context_id, target_context_id, caller_did, tool_registration_id, input, asserted_nonce_hex, timestamp_ms, chain_depth, ucan_proof_id=None. `SagaResult` dataclass (tools.py) = 1:1 pass-through of `PySagaResult` (saga_id:str, receipt:Option<Vec<u8>>->bytes|None, output->bytes|None) — None never synthesized.
- SagaId output-only. Not a caller param; minted supervisor-side; SDK reads `native_result.saga_id` OUT. Caller-principal binding is bridge's (enforce_caller_principal_binding) — SDK just forwards.
- Typed terminals read STRUCTURALLY. `_saga_terminal_from_bridge` (errors.py) dispatches on bridge exc class NAME + reads datum POSITIONALLY off `exc.args` (args[0]=msg, args[1]=code, args[2]=datum) — never message-parse. Matches bridge raise sites EXACTLY (error.rs:366/368/374 `new_err((formatted, code, datum))`). 3 SDK subclasses of ToolError: SagaAbortedError(retry_after_ms), SagaNeedsRepairError(saga_id), SagaBusyError(contended_context).
- Default codes sound. SagaAborted `_default_code=SCP-SAGA-13067` (generic), NeedsRepair=13065, Busy=13066 — MATCH registry sdk-common.md:115/116/117. Default is class FALLBACK only (used iff args[1] missing); bridge always passes specific code (test proves 13050 caller-membership reject preserved verbatim, not overwritten by 13067).
- retry None-never-0. `datum if isinstance(int) and not isinstance(bool) else None` -> None preserved as None (tested). 0-never-emitted is the BRIDGE's invariant (typed SagaError RateLimited{Option<u64>}, None-never-Some(0)); SDK faithfully forwards rather than re-enforcing = correct layering.
- Matrix flip HONEST. python false->true; ts/kotlin/swift STAY false+exempt; python exemption REMOVED; notes updated "Python SDK wrapper is live (PR-6c slice PY); remaining per-SDK tracked by #1939" — does NOT falsely claim #1939 done. coverage alias `(Tools,invoke_cross_context_saga)` added; method exists in scp.py -> check passes.
- No issue-# leak in source. `#1939` lives ONLY in matrix JSON (.docs) = allowed. All `#NNNN` grep hits in scp_sdk/*.py are PRE-EXISTING lines, none in this diff. Test names zero #NNNN.
- Tests behavioral (test_tools.py +324L): committed->faithful SagaResult + null pass-through; positional-forward assert; ucan forward; abort None/int/generic-default; needs-repair saga_id+13065; busy contended_context+13066; non-saga exc re-raised `is sentinel` (translate returns None -> bare `raise`); chain_depth/timestamp fail-fast `assert_not_called`.

OBS-1 (non-blocking): coverage alias adds ts/kotlin/swift names while those cells remain false — inert (aliases only consulted when cell true) + mirrors sibling sync `invoke_cross_context` entry. Forward-looking, harmless, honest.
OBS-2 (non-blocking): SDK relies on bridge None-never-0 invariant rather than coercing 0->None — correct layering (coercing would mask a bridge bug); SDK's own duty (don't turn None into 0) IS met + tested.

LESSON: per-slice SDK-wrapper PR over an already-landed bridge export -> verify (1) wrapper forwards params in EXACT bridge signature order (read `#[pyo3(signature)]`); (2) result type 1:1 field pass-through, None not synthesized; (3) typed-error translator reads datum STRUCTURALLY off args by class-name dispatch, matching bridge `new_err` tuple positions; (4) default codes are class FALLBACKS matching registry + bridge's specific code wins when present (test it); (5) per-slice matrix flip touches ONLY this language's cell, removes ONLY this language's exemption, notes say "live (slice X); rest tracked by #N" not "#N done"; (6) #NNNN OK in .docs matrix JSON, finding in .py/.rs.
