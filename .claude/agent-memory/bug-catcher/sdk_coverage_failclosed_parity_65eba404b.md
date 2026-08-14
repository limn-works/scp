# PR #1867 (65eba404b) — sdk-coverage fail-closed + trust att[0] parity

Reviewed 6 prompted areas. CLEAN except one LOW (stale comments).

- **evaluateLayer1 (trust.ts):** `__extractAllCapabilityUris(token)?.[0] ?? null` — extractor returns `string[]|null` (null when empty, guaranteed non-empty when array via `uris.length>0?uris:null`), so `[0]` is always defined → capUri is `string|null`, never `undefined`. CLEAN.
- **validateOneCapUri:** `error instanceof Error ? error.message : String(error)` + regex on string is safe for non-Error throws. Closed allowlist absorbs ONLY `[SCP-PERM-3001]`, rethrows PERM-3000/3030/future. CLEAN.
- **Python evaluate_trust:** `_extract_all_capability_uris` returns None on empty (`return uris if uris else None`), so `cap_uris[0]` can't IndexError (None→break). base64 padding `4 - len%4` then `*(padding%4)` correct, invalid b64 → except → None fail-closed. PERM-3030 reraised inside UcanError handler. CLEAN.
- **mapBridgeError (errors.ts):** Error.message typed string; String(error) for non-Error. Diff only removed deprecated `PermissionError` alias + comment fix. CLEAN.
- **check-sdk-coverage.py total_ops==0 floor guard (line 1646):** total_ops increments per-op BEFORE value check (1518), so all-false matrix has total_ops>0 → guard correctly does NOT fire (only catches empty/missing capabilities). Fixes prior 614f0eb17 empty-matrix fail-open. CLEAN.
- **WASM run_validate_ucan:** now `Result<(),UcanError>`, all `?`/map_err propagate UcanError, no unwrap/expect. `ucan_error_code` is exhaustive const-fn match (no `_=>`, no panic), all variants→PERM_3001. CLEAN.

LOW: tools.rs:515-519, 628-630, 737-area — three "fall back to PERM_3000 for non-parse failures (validation pipeline, state lookup)" comments are now STALE. validate_tool_ucan_wasm's final run_validate_ucan map_err now returns `Some(code)` (was None), so `code.unwrap_or(PERM_3000)` is structurally unreachable. Behavior change is INTENTIONAL+CORRECT (parity: PERM_3001 everywhere). Only the comments misdescribe. Pattern: behavior tightened to always-Some but unwrap_or fallback + its explanatory comment left behind.
