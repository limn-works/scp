---
name: pr1867-final-65eba404b
description: PR#1867 fix/sdk-coverage-fail-closed-and-parity final API review @65eba404b — prior blockers resolved; remaining = evaluateTrust export asymmetry (TS exports, Python doesn't)
metadata:
  type: project
---

PR #1867 `fix/sdk-coverage-fail-closed-and-parity` final API review at HEAD `65eba404b` (commits: 205966ced revert multi-att→att[0]; b9a528e42 wasm doc; 65eba404b stale-ref+errors.ts doc fix).

**Why:** verify prior-round blockers closed. **How to apply:** these are RESOLVED — do not re-raise:
- Multi-att AND-intersection divergence (62bbf8e41) REVERTED. Both TS `evaluateLayer1` and Python `evaluate_trust` are att[0]-only again. No `intersect` code remains; only one Python comment mentions "every att[i]" as future-work. Consistent.
- TS error-surface exemption (d34097078): RESOLVED. `ucanValidate` AND `eventLogQuery` on SCP class both route through `mapBridgeError` now (scp.ts:2362ff, 2452ff). So `evaluateTrust`'s regex-on-`.message` classification works on typed UcanError/ContextError (mapBridgeError preserves `.message` verbatim).
- `__extractCapabilityUri` parity (5e1bf40d2): RESOLVED. TS `__extractCoreError` ↔ Python `_extract_core_error` 1:1; `__extractAllCapabilityUris` ↔ `_extract_all_capability_uris` 1:1.
- WASM PERM code (205966ced): wasm/src/ucan.rs now emits `[SCP-PERM-3001] permission error:` matching NAPI/PyO3/UniFFI; errors.ts mapBridgeError doc comment updated to say both bridges use `[{code}] {category} error: {message}` — accurate.
- `PermissionError` TS alias: now fully REMOVED (errors.ts:85-90 deleted). Class is `UcanPermissionError`. Matches Python convention.

**Remaining finding (MED, parity/discoverability):** four-layer `evaluateTrust` is exported from TS package index (`index.ts:88 export { evaluateTrust } from "./trust"`) but the four-layer `evaluate_trust` from `scp_sdk.trust` is NOT in Python `__init__.py` `__all__` (only `bridge_evaluate_trust` is, :267). Asymmetric top-level discoverability for the SAME canonical op (sketch.md:793 `SCP.Trust.evaluate`). Python users must `from scp_sdk.trust import evaluate_trust`; TS users get it from the root. Add `evaluate_trust` to Python `__init__.py`.

**Naming notes (not blocking):**
- `validateOneCapUri` (trust.ts:452, PRIVATE non-exported helper). "One" is fine — it validates one URI per call. Renaming to `validateFirstCapUri` would over-specify; att[0]-only is an `evaluateLayer1` policy, surfaced in that fn's JSDoc, not the helper's job. Leave it.
- `evaluateLayer1` att[0]-only limitation is documented at the right level (its own JSDoc + `__extractAllCapabilityUris` JSDoc + `evaluateTrust` JSDoc). Good.

**ADR-053 PreRotationCustodyProvider:** DOC-ONLY in this PR (Status: Proposed). No code implements it (grep confirms zero impls in bindings/crates). Canonical table §"Canonical method names" is internally correct: concept `import_seed_bytes` → NAPI `importSeedBytes`, Swift/Kotlin `importSeedBytes()`, Rust/UniFFI/PyO3 `import_seed_bytes`. The review's "importSeedBytes" matches NAPI/Swift/Kotlin casing. `consume`/`generate`/`public_key`→`publicKey` all consistent. Handle single-use lifecycle invariant well-specified (adapter-enforced invalidation).

**economyVerifyPaymentReceipts:** TS sync vs Python async = acceptable per-SDK idiom (NAPI sync, PyO3 to_thread). Receipt wire shape correct both: top-level `allValid`/`all_valid`+`results`; per-entry `ok` (=adapter-responded NOT valid), `valid`, `receiptId`/`receipt_id`, `result`, `error`. NO top-level `ok`. Casing per-SDK convention.
