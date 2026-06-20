---
name: sdk-coverage-failclosed-parity-review
description: Alignment review of fix/sdk-coverage-fail-closed-and-parity (27d82895e) — spec/ADR anchors for four-layer trust, identity migration, coverage gate
metadata:
  type: project
---

Alignment review of branch `fix/sdk-coverage-fail-closed-and-parity` @ `27d82895e` (2026-06-20). Two commits, each "address 9 review findings"; cumulative diff `0c8f0b065..HEAD`.

**Verdict: ALIGNED** (one LOW provenance nit).

**Why:** SDK cross-language parity + mechanical-gate hardening, all anchored to real spec/ADR text.

**Key spec anchors verified (reusable):**
- Identity migration → **NEW DID**: spec `03-identity.md` §3.2.1 line 28 — "creates a new DID — identity continuity via `alsoKnownAs` + `DidRotationEvent` sent to all active contexts." TS `identityMigrate` doc + `rotationEventJson` field match exactly.
- Four-layer trust model = spec `07-trust-validation-and-capabilities.md`: §7.2 Layer1 Protocol Enforcement, §7.3 Layer2 Participation, §7.4 Layer3 Attestation Authenticity, §7.5 Layer4 Trust Evaluation. Citation `§7.2–7.5` is CORRECT. `§9.3` = Sybil Resistance (WRONG section for trust — that was the miscitation being fixed).
- TS `evaluateTrust` faithfully mirrors Python `bindings/python/scp_sdk/trust.py` (`_PASSED_BEFORE` ordering, UcanError/ContextError catch semantics, `__extractCoreError` em-dash strip).
- TS `bridgeEvaluateTrust` disambiguation name mirrors existing Python `__init__.py:50` `evaluate_trust as bridge_evaluate_trust` — cross-SDK precedent, not ad-hoc.

**LOW finding:** `bindings/typescript/src/types.ts:785` — leftover comment where trust types were moved still cites `(spec §9.3, ADR-017)` for the "four-layer TrustEvaluation model." This is the EXACT miscitation commit 27d82895e claimed to fix (fixed in trust.ts, missed in types.ts). Should be §7.2–7.5. Internal inconsistency; contradicts the change's own stated intent.

**Pre-existing (not this diff, noted):** types.ts:49/69 carry `#1531` issue refs in source comments — violates "no issue numbers in source code" rule, but predate this change.

**ADR-051** (`.docs/adrs/ADR-051-...md`, Status: Proposed): pre-rotation custody substrate isolation. Closes §9.7.4.1 §3 gap (in-memory pre-rotation custody on callback path shares process substrate w/ operational key). Separate `PreRotationCustodyProvider` interface (not new methods on KeyCustodyProvider) correctly enforces §3's "MUST NOT be same custody provider." Aligns w/ ADR-003 (two-substrate split), ADR-025 (sibling), in-memory-is-dev-only stance. Sound, well-grounded.

**Coverage gate** `scripts/check-sdk-coverage.py`: fail-open→fail-closed (WARNING+exit0 → ERROR+exit1 on unmatched true cell, unless coverage_exemptions reason). Removed evadable `endswith` substring matcher (~23 fabricated names could pass) → positive ALIASES whitelist (matches lesson_security_gate_closed_allowlist). Added all-exempted guard (≥1 SDK must be statically verified). Runs clean: 221 ops, 0 errors, 1 legit exemption (Kotlin add_relay_url, untracked UniFFI-generated binding). CLAUDE.md adds the script to enforcement-files list (protects ALIASES trust root). Directly serves "Enforce mechanically" tenet.
