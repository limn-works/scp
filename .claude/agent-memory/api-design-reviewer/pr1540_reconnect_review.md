---
name: pr1540-reconnect-review
description: API review of #1540 context_reconnect/reconnect() + ReconnectReport across 4 bridges + 4 SDKs; verdict APPROVE-WITH-NITS
metadata:
  type: project
---

PR #1540 (feat/1540-checkpoint-equivocation-sync) added `context_reconnect` bridge fn (PyO3/NAPI/UniFFI, WASM exempt) + `reconnect()` SDK wrapper (Py/TS/Swift/Kotlin) + `ReconnectReport` return type. ADR-029 six-phase reconnection driver.

**Why:** API-surface review request, focus on cross-SDK consistency, EquivocationDetected actionability, WASM gap honesty, matrix/aliases.

**How to apply / findings (verdict APPROVE-WITH-NITS):**
- `ReconnectReport`/`ContextReconnectResult` shape is IDENTICAL across all 3 bridges — single `scp_ffi_common::reconnect::ReconnectReport` source mirrored into PyReconnectReport (#[pyclass], real class not dict), NapiReconnectReport (#[napi(object)], f64 counts), UniFFI ReconnectReport (uniffi::Record). Good.
- BLOCKING-ish #1: first param diverges — Py/TS take `identity_did`/`identityDid: string`; Swift/Kotlin take `identity: Identity`. MATCHES local house style (contextJoin/Leave/Send already split same way), so likely intended. BUT behavior differs: Py/TS resolve signing key from registry BY DID; UniFFI resolves from passed Identity handle's custody. Note in docs.
- NIT #2: `tier` (3 vals short/extended/long from OfflineTier) and `outcome` (6 vals from SyncOutcome) are bare `String` end-to-end. Should be string-literal unions (TS) / uniffi::Enum (Swift/Kotlin) / Literal/Enum (Py). Values already in doc comments — promote to types. RECURRING pattern (context state/custody stringly-typed at accessors, per prior reviews).
- `EquivocationDetected`: report only carries COUNT `equivocations_detected`. Structured EquivocationAlert (divergent_did, event_count, roots) emitted as ContextEvent::EquivocationDetected into receive buffer (queries_helpers.rs:833) + event log — recoverable via contextDrainEvents/event log. Reasonable (flat report, forensics in log) but docs don't tell caller where to look when count>0. Suggest doc line.
- `outcome=="failed"` discards SyncOutcome::Failed{reason} — no failure_reason field on result. Follow-up suggestion.
- WASM gap: HONEST + consistent across sdk-capability-matrix.json (notes.wasm) + bridge-aliases.json (wasm_required:false, empty wasm:[], matching exemption block). typescript:true qualified as NAPI-satisfied (browser throws SCP-VALID-7005). Reasoning sound (no Supervisor/actor, no in-core relay QUERY per ADR-034).
- Precondition "transportConnect first" ENFORCED (typed TRANS_5010) in all 3 bridges, not just documented. Good fail-closed.
- last_relay_contacts defaulted in all SDKs (None/undefined/emptyMap/[:]); absent ctx → most conservative tier.
