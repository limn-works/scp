---
name: pr2141-sdk-trust-coverage-r25
description: Black-hat review of PR #2141 (fix/sdk-coverage-fail-closed-and-parity) — Layer-1 UCAN trust, coverage-gate ALIASES, mapBridgeError, WASM CTX routing, ADR-053
round6_note: "@14501c98b (unchanged since R5) — 2nd clean pass, NO ATTACK VECTOR. Two prior R25 concerns now CLOSED on this branch: (1) R25-2 Python coverage extractor NOW excludes underscore-prefixed symbols (check-sdk-coverage.py:1029/1054/1084 startswith('_') skip) → mis-pointed ALIAS to private helper now FAILS the gate (fail-closed tightening, legit 'add coverage' mod). (2) SCP-302 is now a REAL story in .docs/prds/main.json (id/title/AC/sources, status pending) — the att[0]-only within_ceiling over-report comments (R25-3/BLACK-053 OBS-1) no longer phantom-provenance. Re-verified: classification NOT attacker-inflatable (core=text after bridge-fixed '] permission error: ' via split maxsplit=1, startswith on bridge-fixed UcanError leading literal; attacker token content lands AFTER the literal, em-dash truncation only demotes→unknown fail-closed); all-True Layer-1 requires EVERY token full-bridge-pass; closed allowlist PERM-3001-only, CTX-2023/PERM-3030/VALID-* propagate; WASM WasmValidateError Ucan→PERM-3001 vs Context→CTX-2023 restores NAPI parity so ctx-state faults in Layer-1 THROW not absorb; ucan_errors.rs exhaustive match no _=>. within_ceiling att[0]-only persists (advisory, no authz consumer, now SCP-302-tracked)."
metadata:
  type: project
---

# PR #2141 black-hat pass (branch fix/sdk-coverage-fail-closed-and-parity)

## R3-batch2 re-attack @96ac8c942 — CLEAN, all 3 focus areas resist
- New Rust test `all_variants_route_to_perm_3001` (ucan_errors.rs:136): corrected docstring ACCURATE — array NOT compiler-checked (runtime spot-list); real exhaustiveness = `match` in `ucan_error_code`, no `_=>`. VERIFIED `UcanError` (scp-protocol mod.rs:65) NOT `#[non_exhaustive]` → cross-crate exhaustive match holds. No false security.
- New surface since R2B3: `de0077f13` py `re.match`+`$`→`fullmatch` (closes `\n`-before-EOS bypass; fail-CLOSED even if bypassed: absorbed→all-false=untrusted); `bba5b5d23` TS anchored-regex→`startsWith(PIPELINE_ABSORBED_CODE_PREFIX)` (equivalent; absorption only narrows toward false, fully-true needs null/real-crypto); `adfe9c710` coverage-gate filters `_`-prefixed symbols as ALIAS targets = CLOSES prior BLACK-R25-2 (tightens). NO new vector.
- att[0]-only withinCeiling = SAME MED-latent over-report (BLACK-053 OBS-1 / R25-3), NOT escalation. Core mint/delegate `verify_attestation_ceiling_compliance` (mint.rs:81-96) iterates ALL attenuations → out-of-ceiling att can't exist in validly-signed token; NO non-test consumer gates access-ctrl on Layer-1 fields (grep: only Swift/TS struct defs); action-time per-uri gate re-checks. Py+TS PARITY att[0]-only, sketch.md:807-813 honest. Missing PRD story for multi-att bridge op = provenance/completeness gap, NOT a security vector.


Trust classification is SOUND: validate.rs (crates/scp-protocol/src/crypto/ucan/validate.rs:512) pipeline order
parse→sig(2)→chain(3)→issuer(4)→aud(5)→keyscope→cap(6)→catA→atten(7)→ceiling(8)→nonce(9)→revoke(10)→expiry(11)
matches _PASSED_BEFORE EXACTLY. Sig before expiry → forged-sig token can't reach late stage → no field-forge. startsWith
classification robust: all UcanError Display variants have FIXED prefix, attacker data always interpolated as SUFFIX.
all-true only if real crypto passes att[0]. ucan_error_code (crates/scp-ffi/common/src/ucan_errors.rs:48) exhaustive
match, every variant → PERM_3001 today.

FINDINGS:
- **BLACK-R25-1 (MEDIUM latent)**: Closed-allowlist `startsWith("[SCP-PERM-3001]")` in trust.py:874 / trust.ts:514
  couples to "all UcanError→PERM_3001" invariant. ucan_errors.rs:11,64,85 DOCUMENTS a planned split (TokenExpired→PERM_3007,
  TokenRevoked→PERM_3008). When it lands, expired/revoked trust eval THROWS across ALL 4 bridges instead of graceful
  narrowed verdict. _PASSED_BEFORE["expiry"]/["revoked"] + _EXPIRY/_REVOCATION_PREFIXES become present-but-unreachable.
  No mechanical link across the 3 files; only prose "held back pending test_trust.py update". A dev doing the split
  following only ucan_errors.rs comment will likely miss the trust.py/ts gate expansion.
- **BLACK-R25-2 (MEDIUM design)**: check-sdk-coverage.py ALIASES = name-existence whitelist (docstring:88 honest).
  _extract_python_symbols (:1054) includes PRIVATE symbols (no __all__/underscore filter) — TS extractor DOES require
  `export`. So a Python ALIAS can point at an unrelated private helper and pass. + all-exempted guard only needs ONE
  statically-"verified" SDK → a single mis-pointed ALIAS + 3 prose coverage_exemptions masks a real gap. Insider/PR-gated.
- **BLACK-R25-3 (MEDIUM design, persistent)**: within_ceiling att[0]-only over-report (reverted to att[0] @205966ced).
  Layer-1 within_ceiling=true does NOT mean all requested caps in ceiling; att[1..n] unchecked. Advisory only (real
  enforcement = per-op scp.ucanValidate at bridge), heavily documented. Same as prior BLACK-053 OBS-1.
- **BLACK-R25-4 (LOW)**: multi-token fail-fast — aggregate verdict reflects only FIRST failing token; [expired, revoked]
  reports notRevoked=true (stops at expiry). Diagnostic fidelity, not bypass.
- **BLACK-R25-5 (LOW)**: py/ts VALID parity — Python absorbs [SCP-VALID-*] only via generic `except Exception` (:887);
  if bridge ever raised VALID as UcanError type it'd re-raise vs TS all-false. Currently unreachable (VALID=ValidationError,
  not _scp_core.UcanError). Both fail-closed.
- **BLACK-R25-6 (LOW)**: test-guard.ts treats NODE_ENV=development as test env → enables test-only bridge-swap hooks;
  env frozen at module load (pre-import pollution still wins, but needs code-exec). Good hardening (Object.hasOwn vs
  proto-pollution; fail-closed in browser).

RESISTANT: vector1 field-forge (sequential pipeline verified); vector4 mapBridgeError (^-anchored, pos-0 uncontrollable —
CLOSES prior minor issue); vector5 WASM CTX-2023 DoS (NAPI parity, precondition-only, throw doesn't leak optimistic-true);
vector7 ADR-053 (PR CORRECTS prior overclaim — now honestly says type-sep does NOT enforce substrate isolation, foreign
impl can back both providers w/ same Keychain/biometric; migration-reveal transits seed thru shared mem; ADR Proposed,
code not built, reference InMemoryPreRotationCustody honestly flagged not-isolated).

uri.rs & provider.rs changes = doc/refactor only, no behavior change.
