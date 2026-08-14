---
name: trust-ucan-error-classifier-not-a-gate
description: The UCAN error-prefix lists in trust.ts/trust.py are a fail-closed verdict REFINER, not a security gate — don't flag their denylist shape as non-convergent
metadata:
  type: project
---

The per-stage UCAN error-message prefix lists in `bindings/typescript/src/trust.ts` and `bindings/python/scp_sdk/trust.py` (`SIGNATURE_CHAIN_PREFIXES`, `CAPABILITY_CEILING_PREFIXES`, `NONCE_PREFIXES`, `REVOCATION_PREFIXES`, `EXPIRY_PREFIXES`, `TOKEN_PARSE_PREFIXES` / `_*_PREFIXES`) are denylist-SHAPED but are NOT a security gate.

They only refine an already-failed UCAN verdict into finer-grained `CapabilityValidation` boolean fields (which pipeline stage failed → which earlier fields are known to have passed, via `__PASSED_BEFORE` / `_PASSED_BEFORE`). Any error that matches no prefix falls to category `unknown` → all-false → fail-closed. So unmatched/new prefixes degrade SAFELY.

**Why:** This is exactly the artifact a simplifier review would normally suspect of non-convergent denylist growth. It is not. The real enforcement is the Rust `validate_ucan` pipeline; this is presentation-layer classification of its already-binary failure. New error spellings cannot create a false PASS — worst case they make the field breakdown coarser while the overall verdict stays correctly failed.

**How to apply:** When reviewing changes that add prefixes to these lists, do NOT raise a BLOCKER for non-convergent enforcement. Verify only that (a) the `unknown`/fail-closed fallback is intact and (b) TS and Python lists stay in parity. The genuine convergence-sensitive gates in this repo are the capability-type AST/allowlist gates (OwnedIdentityDid) and `check-sdk-coverage.py` — those use positive closed allowlists by design.

Related: [[ts-python-trust-parity-docstring-drift]]
