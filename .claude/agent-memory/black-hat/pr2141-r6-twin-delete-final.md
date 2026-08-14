---
name: pr2141-r6-twin-delete-final
description: PR#2141 Round 6 FINAL — Swift+Kotlin insecure participation-verifier twin deletions; all 4 bridges route to sound scp-protocol core; NO ATTACK VECTOR
metadata:
  type: project
---

# PR #2141 Round 6 (FINAL) — participation-verifier twin deletion, /tmp/scp-review-r25

HEAD advanced past task's stated `7097938f5` to **`58f6f06b5`** (3rd commit: chore removes accidentally-committed `scratch_trust_old.py`, 1784 lines — caught & cleaned, not shipped/imported).

**Verdict: NO ATTACK VECTOR FOUND.**

Delta = deletion of two pure-language insecure twins that did bare threshold math (no sig / freshness / subject-binding / min_contexts):
- Swift: `verifyParticipationRequirements(requirement:profile:)` + `ParticipationFact`/`ParticipationThreshold`/`RequireParticipation` deleted from Trust.swift (23779139f, -90).
- Kotlin: entire `Participation.kt` (free fn + 4 data classes + `checkThreshold`) deleted (7097938f5, -127).

**All four bridges now route to the identical sound core** `scp_protocol::trust::participation::verify_participation_requirements` (participation.rs:715) — pure-sync, compiles wasm32, does: `verify_strict` Ed25519 on every statement up-front, freshness (`max_age_secs` → RecordTooStale), distinct-signer HashSet vs `min_contexts` (InsufficientContexts), threshold (ThresholdNotMet), subject-binding via `signable_bytes()`:
- Swift → generated free func `Internal/ScpBindings.swift:15097` → `uniffi_scp_ffi_uniffi_fn_func_verify_participation_requirements` (checksum 3043). Scp.swift only has a comment now.
- Kotlin → `Scp.kt:1714` wrapper → `uniffi.scp.verifyParticipationRequirements` (build-generated).
- Python → `trust.py:1087` → PyO3 `bridge.verify_participation_requirements(json,json)` (data classes only serialize `_to_bridge_dict`, no local verify).
- TS → `scp.ts:2812` → NAPI `#native.verifyParticipationRequirements`.
- WASM → `wasm/src/trust.rs:301` → `protocol_verify` = the SAME `scp_protocol` core (import line 263); NOT a local reimplementation. (wasm aggregate_trust_input still throws VALID-7072 by design.)
- UniFFI bridge:6025 passes `current_time` → core (freshness live).

**Coverage gate** (`check-sdk-coverage.py:587`): `("Trust","verify_participation_requirements")` name-resolves per SDK against `Sources/SCP/**/*.swift` (incl. generated `Internal/`) and `scp-kt/src/main/**/*.kt`. With twins deleted, the ONLY callable `verifyParticipationRequirements` in each scanned tree is the secure Rust-backed symbol → gate now unambiguously load-bearing on the secure path.

Checks: zero dangling refs to deleted Swift/Kotlin types (grep clean both langs); zero enforcement files touched; no test refs to twins; scratch file un-tracked/removed at HEAD.

ucan_errors.rs / wasm/ucan.rs untouched by these commits (prior-round scope, already sound per [[pr2141-sdk-trust-coverage-r25]]).

## Round 7 @5d118e1a2 — single regex fix, NO ATTACK VECTOR
Delta = 1 line: `_CODES_RETURN_RE` in test_ucan_conformance.py `codes::(\w+)` → `=>\s*\{?\s*codes::(\w+)` (anchor on match-arm `=>`). Fixes a real HARD-FAIL: old regex matched doc-comment `codes::PERM_3009` (ucan_errors.rs:114, illustrative "raw-literal drift" example) → PERM_3009 is NOT a real const (3007/3008 ARE, held-back-unemitted; 3009 isn't) → `assert value is not None` blew up. New regex extracts exactly {PERM_3001} (empirically verified). Excludes doc/test/`_ =>`/alias mentions.
Direction proven FAIL-CLOSED: `test_every_emitted_code_is_absorbed` enforces emitted⊆absorbed; trust.py:935 `if not absorbed: raise`. Regex UNDER-match (miss a real emitted code) → test under-requires → runtime hits unabsorbed code → RE-RAISE → no verdict granted → fail-closed. Absorption NEVER sets Layer-1 all-true (bounded by _PASSED_BEFORE, excludes failed stage+after); no path to fail-open from over- OR under-absorption. Only un-caught future pattern = block-body arm with statement BEFORE `codes::` (`=> { log(); codes::X }`) → still fail-closed (re-raise) AND independently caught by Rust `all_variants_route_to_perm_3001` (hardcodes every variant==PERM_3001) + compile-time exhaustive match (no `_ =>`). Triple-layered. Inline + simple block-body future splits (PERM_3007/3008) ARE caught → BLACK-R25-1 guard intact.

## Round 8 (double-zero pass 2) @5d118e1a2 — NO ATTACK VECTOR, EMPIRICALLY re-confirmed
Zero code delta since Round 7 (same HEAD). Independently re-ran both regexes on real ucan_errors.rs: OLD `codes::(\w+)` = {PERM_3001, PERM_3009} (3009 = doc-only line 114, no backing const → old hard-fail CONFIRMED); NEW `=>\s*\{?\s*codes::(\w+)` = {PERM_3001} exactly. error_codes.rs:448 PERM_3001="SCP-PERM-3001" → bracket [SCP-PERM-3001] ∈ _PIPELINE_ABSORBED_CODES (trust.py:470 frozenset, single element). No `_ =>` catch-all anywhere (only comment mentions @ ucan_errors 32/45/112). WASM ucan.rs routes ALL 5 UcanError sites (448/475/495/602/613/625) thru shared ucan_error_code→PERM_3001-absorbed; Context→CTX_2023 propagates (not in closed allowlist). Absorb→all-false=deny direction. Fail-closed in over- AND under-match. Confirmed double-zero.
