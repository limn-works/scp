---
name: pr2144-r2-error-code-reconcile
description: Round-2 re-review of #2144 browser participant (scp-client-wasm) error-code reconciliation — CLEAN
metadata:
  type: project
---

# #2144 Round-2 (branch fix/2144-error-code-reconcile @457487275) — CLEAN, 0 defects

Cross-surface-free renumber of scp-client-wasm error codes. Verdict CLEAN.

Verified:
- All 17 `ClientError` arms in `crates/scp-client-wasm/src/error.rs::error_code` match the sdk-common.md ledger; no swap/double-assign. New codes: UnknownContext=CTX-2082, ContextAlreadyExists=CTX-2083 (NOT native 2003, which is off-native overloaded), UnsupportedMembershipChange=CTX-2084, Driver=CTX-2085, NoPendingJoinMaterial=CTX-2086, PseudonymRegistryEmpty=CTX-2095 (ONLY intentional cross-surface reuse), Codec=VALID-7028, ChannelContentMismatch=VALID-7029, Transport=TRANS-5005, Mls(convergent)=CRYPTO-4040, Mls(_)=CRYPTO-4041, SenderKey=4020, EventLog=4030, Storage 8010-8013 (unchanged).
- New `pub(crate) const WASM_INPUT_VALIDATION_CODE="SCP-VALID-7028"` (inquisitor R1 fix): all 9 lib.rs free-fn validators (lines 825,874,879,885,890,915,924,935,944) route through it via `format!("[{WASM_INPUT_VALIDATION_CODE}]...")`; ZERO bare `[SCP-VALID-7010]` emitters remain. `lib_rs_input_validation_code_is_pinned` test pins const value (typo fails).
- Exhaustive no-wildcard allowlist test (`reconciled_code` + `every_variant_representative` probe match) + 9 native tests PASS. Compiles clean post-rebase against current enum.
- TS-wasm tests/docs updated to new codes. mapBridgeError (bindings/typescript/src/errors.ts:321 ERROR_PREFIX_MAP) dispatches by category prefix only — every renumber stayed within prefix, classification unaffected.
- No stale old browser codes anywhere in crates/scp-client-wasm or bindings/typescript-wasm.

Known-accepted (R1) design limit, NOT a defect: error_code + reconciled_code are hand-maintained duplicates in the same file; ledger (sdk-common.md prose) is not machine-checked from Rust, so an identical-but-wrong renumber of both + ledger could pass. Documented in module doc.
