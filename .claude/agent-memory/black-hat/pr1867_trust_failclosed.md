---
name: pr1867-trust-failclosed
description: PR #1867 trust.ts/Python Layer-1 UCAN classification — fail-closed analysis, prefix-forgery via capability URI in error string
metadata:
  type: project
---

# PR #1867 (fix/sdk-coverage-fail-closed-and-parity) — Layer-1 UCAN trust classification

Reviewed @8909092eb. TS `bindings/typescript/src/trust.ts`, Python `bindings/python/scp_sdk/trust.py`, WASM `crates/scp-ffi/wasm/src/ucan.rs`.

## Architecture (sound)
- Layer-1 starts all-true optimistic, AND-intersects per-URI then per-token verdicts. False wins. Malformed token / no-att → all-false (fail-closed, bridge not called). Empty/undefined token list → all-false.
- `intersectCapabilityValidation` covers ALL 6 CapabilityValidation fields explicitly (no missing field, no default-true leak). Q1 = clean.
- `validateOneCapUri` absorbs ONLY `/^\[SCP-PERM-3001\]/` (closed allowlist). PERM_3000 (WASM mgr), PERM_3030 (handle affinity), VALID-*, CTX-* all re-throw. Q3 = correct.
- All UcanError variants → PERM_3001 via `scp_ffi_common::ucan_errors::ucan_error_code` (exhaustive match, compile-error on new variant). NAPI Display = `[{code}] permission error: {message}`; prefix at pos 0. WASM `ucan_validate` routes EVERY failure path (parse, cap-uri parse, run_validate_ucan) through `ucan_error_code` → PERM_3001. ucan_mint/ucan_delegate keep PERM_3000 (correct — those are not validation). Q4 = clean.
- Code prefix `[SCP-PERM-3001]` cannot be forged at pos 0 by attacker URI content: URI is always DOWNSTREAM of the bridge-prepended prefix. Q5 absorption decision = safe.

## REAL FINDING (LOW/MEDIUM) — classification (not absorption) is attacker-influenceable
- Capability URI = attacker-controlled `att[i].with`. Validator (`validate_capability_uri`) blocks only control chars + `< > & " '`. Em-dash U+2014, `]`, and literal text `permission error:` are ALL permitted.
- URI is embedded in UcanError Display: `capability outside ceiling: {uri}` / `capability not granted: {uri}` → full msg `[SCP-PERM-3001] permission error: capability not granted: scp:ctx:.../X — advice`.
- `__extractCoreError`: indexOf(`] permission error: `) first-occ (safe, before URI) THEN indexOf(` — `) first-occ to strip advice. Attacker URI containing ` — ` truncates `core` EARLY → could drop the real prefix from `core`, flipping classification to `unknown` (PASSED_BEFORE=∅ → all-false). all-false is MORE restrictive, so NOT exploitable toward false-positive.
- Worse direction: attacker can't make a FAILING token classify into a LATER stage to gain spurious true fields, because verdict only ever sets true the fields BEFORE the classified stage, and an attacker who controls the URI text still triggered a real failure. Mis-classification only shuffles WHICH earlier fields show true — but a genuine ceiling failure (stage=ceiling) already grants tokensValid+signaturesValid=true legitimately. To gain `nonceValid`/`notRevoked`=true spuriously the attacker would need core to startWith a nonce/revoked/expiry prefix; URI content sits AFTER `capability not granted: ` so cannot control `core.startsWith`. CONCLUSION: not a privilege-gain bug; the string-classification design is brittle but fail-closed-biased.
- Recommendation (hardening, not blocker): classify on a structured error code/discriminant, not Display-string prefix. Display strings with embedded attacker data are an anti-pattern for control-flow.

## Q6 test-guard — solid
- `assertTestEnvironment` reads process.env ONCE at module load (frozen const), `Object.hasOwn` (proto-pollution safe), fail-closed (false in browser/no-process/prod). Test hooks (`__setBridgeForTests`, `__constructScpWithNativeForTests`) also dead-code-eliminated by tsup + not re-exported + exports-map blocks deep import. Defense-in-depth is layered. No bypass found.
- Residual: NODE_ENV=development also unlocks hooks in a deployed dev build — acceptable per documented intent.
