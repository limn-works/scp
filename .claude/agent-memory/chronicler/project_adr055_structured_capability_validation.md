---
name: adr055-structured-capability-validation
description: ADR-055 / spec §7.2.4 / SCP-302 — structured CapabilityValidation crosses FFI; SDKs consume typed result not prose; doc-integrity review notes
metadata:
  type: project
---

ADR-055 "Structured Capability/Trust Validation Across the FFI" (branch c3c-ts, PR pending). Capability validation crosses FFI as `CapabilityValidation` (six per-stage bools: tokens_valid, signatures_valid, within_ceiling, nonce_valid, not_revoked, time_bounds_valid). SDKs consume the typed record; prose-string parsing is forbidden.

**Why:** First-principles audit found Python `trust.py` reverse-engineering which check failed by string-matching `[SCP-PERM-3001]…` error prose — brittle, and it MASKED a multi-attestation nonce bug (mocks emitted prose without modeling nonce state).

**Key design points (durably captured in ADR-055 Decision 1-5 + §7.2.4):**
- Two distinct ops: `ucan_validate` = enforcement GATE (throws, fail-closed, RECORDS nonce via NonceTracker::check_and_record). `ucan_evaluate` = read-only DIAGNOSTIC (never throws, probes nonce read-only via check_replay, records NOTHING).
- Diagnostic's `required_capability` is OPTIONAL (Option<&CapabilityUri>); gate's stays MANDATORY. None = intrinsic-validity mode, skips step-6 grant-match. Bare `*` sentinel rejected (malformed URI); absence = omit the capability.
- `signatures_valid` EXCLUDES grant-match in intrinsic mode (footnote in §7.2.4 table; doc-comments in both SDKs correctly state this).
- All 4 bridges coerce empty/whitespace cap to no-challenge: `capability.filter(|c| !c.trim().is_empty())`.
- SDK error TYPING via single mapping chokepoint keyed on `[SCP-CAT-NNNN]` codes, not per-call string classification.

**ADR provenance convention learned:** UCAN nonce/replay defense is cited project-wide as "spec section 9.5" (ADR-009 lines 9/20, ADR-016 lines 7/19 all do this) even though §9.5 today is titled "Cryptographic Primitive Specification" and the dedup-cache detail lives in §9.8.2. This is a pre-existing repo convention, NOT introduced by this PR. ADR-009 (titled "Role Assignment and Capability Ceiling Enforcement") is also the FOUNDATION where NonceTracker is first specced (lines 137-148); ADR-016 (phase-3.md:666) is the normative 11-step pipeline. So ADR-055's "ADR-009 (nonce/replay defense)" label is loose-but-defensible.

**Review verdict (2026-06-27):** docs internally consistent + consistent with code (verified evaluate_ucan signature, all 4 bridge coercions, Python parser symbols all grep-0, TS evaluateTrust intrinsic-mode null challenge). validate-prd green (371 stories). Lessons are flat files — no index to update.
