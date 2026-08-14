---
name: pr1867-valid-absorption-3ea854ff3
description: PR#1867 fix/sdk-coverage-fail-closed-and-parity HEAD 3ea854ff3 — VALID-* absorption arm + WASM Option-drop re-attack; CLEAN, no CRIT/HIGH/MED
metadata:
  type: project
---

# PR #1867 @ 3ea854ff3 — VALID-* boundary absorption + validate_tool_ucan_wasm Option drop

Two new commits over prior-reviewed 1861c3691:
- 785aaf560: validate_tool_ucan_wasm `Result<(),(String,Option<&str>)>` → `Result<(),(String,&'static str)>`; 3 callers in tools.rs drop `unwrap_or(PERM_3000)`.
- 3ea854ff3: validateOneCapUri (trust.ts) + py evaluate_trust gain a `[SCP-VALID-` arm → absorb as ALL_LAYER1_FIELDS_FALSE (fail-closed).

VERDICT: CLEAN. No CRIT/HIGH/MED. The prior LOW (TS threw on VALID-* vs null-path all-false) is now RESOLVED — both SDKs absorb VALID-* as all-false consistently.

## Why each attack fails (Q1-Q6)
- Q1 (genuine auth absorbed by VALID arm / forge `[SCP-VALID-` prefix): NO. ucan_validate_on (napi) ordering: napi_check_handle(PERM-3030)→validate_ucan_token(VALID)→validate_capability_uri(VALID)→ensure_registered(CTX)→parse_ucan(PERM-3001)→capability.parse::<CapabilityUri>() EXPLICIT PERM-3001 (error.rs l.217)→validate_ucan(UcanError→PERM-3001 via From, ALWAYS Permission never Validation, error.rs l.402-413). So EVERY cryptographic/authz pipeline failure = PERM-3001 (classified), VALID arm is STRICTLY boundary-shape rejection (control/HTML chars in token or capUri) = correctly fail-closed. Prefix unforgeable: `[{code}] validation error: ` is bridge-written at pos0; attacker capUri text lands AFTER prefix; `^` anchor defeats injecting `[SCP-VALID-7003]` into URI body. Brackets+`SCP-VALID-7003` text PASS validate_capability_uri (not in HTML_SPECIAL_CHARS=`<>&"'`, not control) but then fail capability.parse → PERM-3001, NOT VALID.
- Q2 (py except ordering / PERM-3030 absorbed as VALID): NO. `except bridge.UcanError` BEFORE `except Exception`. PyO3 hierarchy (error.rs create_exception): UcanError & ValidationError both rooted at ScpError = SIBLINGS, neither subclass of other. PERM-3030→ScpPyError::UcanError (HandleAffinityError From, error.rs l.737)→_scp_core.UcanError→caught by FIRST handler→startswith("[SCP-PERM-3030]")→raise. Boundary VALID→_scp_core.ValidationError→NOT caught by first→falls to except Exception→startswith("[SCP-VALID-")→all-false. PERM-3030 can NEVER reach VALID arm.
- Q3 (WASM Option drop / None-producing site): NO. ucan_error_code is `const fn` exhaustive match over ALL UcanError variants (no `_=>`, compile-breaks on new variant), returns `&'static str`=PERM_3001. unwrap_or was genuinely dead. Exactly 3 callers (tools.rs 513/622/731), all use `code.to_owned()` directly. No site constructs None.
- Q4 (__extractFirstCapabilityUri skip att[0]→att[1]): NO. Reads `att[0]` strictly (trust.ts l.328 `att[0]`); missing/non-string/empty `.with` → uri="" → null → evaluateLayer1 all-false. No fall-through to att[1] anywhere.
- Q5 (coverage gate forge): NO CHANGE in 1861c3691..HEAD to check-sdk-coverage.py / sdk-capability-matrix.json. Gate unchanged since prior-clean review (closed allowlist, total_ops==0 floor, all-exempted guard, substring/suffix removed).
- Q6 (injection via VALID-* msg to classifier): NO. mapBridgeError does super(message) verbatim; trust classifies on `^\[SCP-VALID-` / `^\[SCP-PERM-3001\]` anchored at pos0; URI text always downstream of bridge prefix.

## Cross-platform parity confirmed
WASM ucan_validate (ucan.rs l.408) calls validate_capability_uri at l.418 BEFORE pipeline → ScpWasmError::Validation `[SCP-VALID-7xxx] validation error:` (pos0) → TS regex matches under WASM too. Pipeline → Permission PERM-3001. Same fail-closed shape as napi.

## Latent (NOT exploitable, note only)
- WASM ScpWasmError::Trust variant uses code `SCP-VALID-7070` (error.rs l.123-128 doc) so a WASM trust error would ALSO match `^\[SCP-VALID-` and be absorbed. UNREACHABLE from ucan_validate (only Validation+Permission produced there). Even if reachable = fail-closed (safe). Cosmetic parity wrinkle.
- WASM ucan_validate proof_tokens_json malformed → VALID_7000 (l.446). Trust layer never passes proofTokens (validateOneCapUri calls scp.ucanValidate(handle,token,capUri) only) so unreachable.

Tests non-vacuous: trust.test.ts l.605/627 (VALID→all-false), l.655 (CTX propagates), l.676 (PERM-3030 re-throw via mapBridgeError). Drive real validateOneCapUri via __stub, bridge-shaped Display strings.
