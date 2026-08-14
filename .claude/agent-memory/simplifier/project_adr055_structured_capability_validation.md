---
name: adr055-structured-capability-validation
description: ADR-055 + spec §7.2.4 retire SDK prose-parsing of UCAN errors in favor of a closed structured CapabilityValidation record + single [SCP-CAT-NNNN] mapping chokepoint; simplifier judged it appropriately minimal (it IS the anti-over-engineering instrument)
metadata:
  type: project
---

ADR-055 ("Structured Capability/Trust Validation Across the FFI") on branch `docs/adr-structured-capability-validation-ffi` (commit 48908917d) is a docs-only change: +62 lines in `.docs/adrs/phase-2.md`, +25 lines in `.docs/specs/07-trust-validation-and-capabilities.md` §7.2.4.

**Verdict (2026-06-26 review): appropriately minimal. Zero over-engineering findings. This ADR is itself an anti-over-engineering instrument** — it records the decision to DELETE a non-convergent prose denylist and replace it with a closed structured record.

Verified against code on the branch:
- `crates/scp-protocol/src/crypto/ucan/validate.rs`: `validate_ucan` (gate, records nonce via `check_and_record` ~L611) and `evaluate_ucan` (diagnostic, read-only `check_replay` ~L827) both exist; six-field `CapabilityValidation` struct (tokens_valid/signatures_valid/within_ceiling/nonce_valid/not_revoked/time_bounds_valid) exists. Gate-vs-diagnostic side-effect distinction is REAL in code, not invented by the ADR.
- `scripts/check-error-codes.sh`: `[SCP-CAT-NNNN]` taxonomy is a genuinely CLOSED, range-allocated category set (IDENT 1000-1999, PERM 3000-3999, etc.) — so "map on the code" is a bounded positive set, NOT a denylist.
- `bindings/python/scp_sdk/trust.py`: the prose-parsing antipattern the ADR retires genuinely exists — multiple "Error message prefixes" lists + `_classify_ucan_error` doing `core.startswith(prefix)`. This IS the open-ended denylist; ADR is correct to kill it.

**Why the two-op (gate vs diagnostic) design is NOT duplicate complexity:** they differ in side effects, not just return type. Gate records the nonce (fail-closed, presentation-boundary, consumes nonce). Diagnostic probes read-only (safe to call repeatedly, never burns nonce). Collapsing to one op forces either non-throwing gate (loses fail-closed) or side-effecting diagnostic (nonce-burn DoS). The distinction is a security property. ADR §Rejected-Alt-2 argues this correctly.

**Why it converges the SDK surface rather than adding to it:** net DELETION of the trust.py prose parser; SDK error typing routed through ONE [SCP-CAT-NNNN] chokepoint (closed) instead of N per-call try/catch ladders (rejected as Alt-3). Per-SDK idiom preserved (§5 / Dep on per-sdk-idiom lesson) so it does not over-constrain wrapper shape.

Downstream "C3c SDK rebuild" is the code PR governed by this ADR (separate). See root MEMORY index entry project_pr1867_audit_split_rebuild (PR-B = ADR-055 spec, PR-C = Goal #2 rebuild).
