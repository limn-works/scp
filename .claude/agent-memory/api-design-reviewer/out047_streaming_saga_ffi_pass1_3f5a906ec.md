---
name: out047-streaming-saga-ffi-pass1
description: SCP-OUT-047 streaming-saga FFI (open/poll_next/recover) — pass-1 findings + pass-3a NAPI/UniFFI shape-consistency resolution
metadata:
  type: project
---

SCP-OUT-047 cross-context streaming-saga FFI: open / poll_next / recover_truncated_close. Bridge trio + Python SDK.

## Pass-3a @fd33fadf2 (branch feat/outlet-xctx-047-streaming-saga-ffi) — APPROVED (shape-consistency)

NAPI + UniFFI streaming-saga exports mirror the PyO3 reference. Reviewed the string-vs-handle split (the KEY question). VERDICT: house-consistent, NOT a new divergence; pass-3b must mirror each SDK's own idiom, NOT normalize handle↔id away.

**The string/handle split is the ESTABLISHED per-bridge convention — verified across BOTH sibling families:**
- PyO3 (reference) is STRING-based (`caller_context_id`/`target_context_id: &str`) across: same-context `outlet_stream_open` (context_id:1615), unary `outlet_invoke_cross_context_saga_impl` (outlets.rs:1254-55), AND streaming saga (outlet_stream.rs:1162-63). Internally uniform.
- NAPI is HANDLE-based (`source_handle`/`target_handle: &NapiContextHandle`) across all three (same-ctx open scp.rs:2923; unary saga scp.rs:3286-87; streaming scp.rs:3087-88). Uniform.
- UniFFI is HANDLE-based (`Arc<ContextHandle>`) across all three (same-ctx open outlet_stream.rs:1576; unary saga bridge.rs:13644-45; streaming outlet_stream.rs:1781-82). Uniform.
- So streaming saga follows each bridge's OWN precedent exactly. Coder's claim TRUE + verified.

**Why the split is legitimate (not arbitrary):** NAPI/UniFFI ContextHandle is instance-affine — `check_handle` enforces SCP-PERM-3030 cross-instance rejection + carries context_id/creator_did. PyO3 PyScp addresses per-context state by id-string. Intrinsic per-bridge architecture, not style. Handle bridges derive caller_context_id/target_context_id INTERNALLY from the handles (napi 1173-74 / uniffi 1175-76) — same arity (13 params all 3), 1:1 at positions 1-2.

**Shape identity (positions 3-13 BYTE-IDENTICAL across all 3 bridges):** caller_did, outlet_registration_id, input(_json), asserted_nonce_hex, timestamp_ms, chain_depth, ucan_token, proof_tokens, ucan_proof_id, timeout_ms, estimated_chunk_count. All return bare `String` saga_id. poll_next(saga_id)->Option<bytes>; recover(saga_id, caller_did)->(). poll/recover take a BARE saga_id string even on handle bridges — house-consistent: saga_id is a runtime-minted durable id (like same-context stream's handle_id:String for poll/control), NOT a context reference; only CONTEXTS use handles.

**Developer-facing (Python SDK pass-2 confirms):** `outlet_invoke_cross_context_streaming_saga(caller_context_id: str, target_context_id: str, ...)` (scp.py:2583) mirrors its own unary `outlet_invoke_cross_context_saga(...:str)` (scp.py:2503) — id strings. Pass-3b TS/Swift/Kotlin wrap NAPI/UniFFI → will take Context handle objects, mirroring their OWN unary-saga wrappers. This Python-ids-vs-others-handles divergence is PRE-EXISTING + intrinsic (already true for unary saga + same-ctx stream across the SDK family). "Identical shape across bindings" tenet is operatively "identical ORDER/NAMING/RETURN/ERROR modulo each SDK's fixed context-ref idiom." Pass-3b MUST NOT force ids onto handle SDKs or vice-versa (would break each SDK's own outlet-family consistency).

**Pass-1 findings ALL resolved:**
- F1 (caller_did positional swap): FIXED — caller_did now at position 3 in BOTH PyO3 unary + streaming (leading 6 identical: caller_ctx, target_ctx, caller_did, outlet_reg_id, input, nonce).
- F2 (asserted_ freshness-field prefix): RESOLVED AT SURFACE — exported pyo3 kwargs are `timestamp_ms`/`chain_depth` (plain) on BOTH saga pymethods (outlets.rs:2088-89 signature; outlet_stream.rs:1788-89) + match NAPI/UniFFI. The `asserted_timestamp_ms`/`asserted_chain_depth` prefix survives ONLY in the PyO3 unary IMPL-internal param names (outlets.rs:1260-61) — never crosses FFI, invisible to Python. Purely cosmetic internal drift, out of API scope.
- F3 (inert spending_ucan footgun): FIXED — streaming saga does NOT accept spending_ucan (documented NOTE outlet_stream.rs:1182-89 / napi 1187-90). Carries ucan_token (validated once at open §5.4.5 UCAN-check-locus) + ucan_proof_id (target-side spend gate). Clean tri-modal justification.

**No misuse-resistance regression from handles** — strictly stronger than strings (SCP-PERM-3030 affinity). Only residual: two leading SAME-TYPED args (both ContextHandle / both str) positionally swappable — family-wide + pre-existing (unary saga identical). Pass-3b nit: use labeled/named args (Swift labels, Kotlin named); TS positional → consider options-object or doc.

Enforcement change direction CORRECT: removed 6 pass-1 bridge-alias exemptions + filled uniffi/napi alias arrays + MIN_PARITY_OPERATIONS 106→109 (stricter = legitimate).
