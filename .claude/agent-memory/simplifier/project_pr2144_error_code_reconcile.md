---
name: pr2144-error-code-reconcile
description: #2144 wasm error-code reconciliation review — CLEAN, minimal renumber + prose ledger + one bounded exhaustive positive test; the sanctioned shape, NOT a BLOCKER.
metadata:
  type: project
---

#2144 reconciled `crates/scp-client-wasm/src/error.rs` codes that collided (same number, different meaning) with the native FFI-common registry in the single TS `ScpError` hierarchy (prefix+number `.code` is the public contract).

Verdict: CLEAN / ship. No over-engineering, no non-convergence.

**Why (what made it minimal + sound):**
- Renumber browser codes off the collisions into browser-owned bands (2077-2080, 4020/4030/4040/4041, 5005, 7018/7019); keep exactly TWO intentional shared-meaning reuses (`SCP-CTX-2003` already-exists, `SCP-CTX-2095` pseudonym-registry-empty) — both verified byte-identical in meaning against `crates/scp-ffi/common/src/error_codes.rs`.
- Restraint confirmed: did NOT touch `error_codes.rs`, `errors.ts` dispatch logic, or `scripts/check-error-codes.sh`. Only renumber + prose ledger in sdk-common.md + doc/test repoints.
- The ONE new enforcement is the [[sanctioned-bounded-tripwire-shape]]: an exhaustive NO-wildcard `reconciled_code()` match + a wildcard-free `every_variant_representative()` enumeration, asserted equal to `error_code()`. Closed-by-construction (new `ClientError` variant fails to compile until an arm is added), value-pinning, NOT a denylist, NOT a redundant cross-file source-text gate. Complements the prose ledger (which is not machine-checked), doesn't duplicate it.
- Collapsing all wasm free-fn input validators onto one `SCP-VALID-7018` is GOOD not lossy — same granularity as before (message string carries the specific cause), just renumbered off the native UCAN-validation 7010 collision.
- Bonus registering pre-existing TS-wrapper `SCP-VALID-7025/7026` = proportionate ledger-completion (both real, in client.ts), not scope creep.
- Bare-number comment citations ("native registry's CRYPTO-4010", no `SCP-` prefix) = clean convention: keeps a grep for *emitters* of the old code at 0 in this crate. Phase-2 skips comments anyway, so it's grep hygiene for humans/tools, not a hack.

**How to apply:** error-code-band reconciliation reviews recur (see [[project_pr2141_sdk_error_mapping]]). The right shape is renumber + prose ledger + ONE exhaustive positive test — do not demand a new cross-file gate, and do not flag the single positive test as redundant with the ledger. Only mild note available: `codes_match_the_reconciled_allowlist` subsumes the prefix-space + convergent-ordering tests, and the trailing `INTENTIONAL_NATIVE_REUSES` `.starts_with("SCP-CTX-")` loop is tautological — optional trims, not findings.
