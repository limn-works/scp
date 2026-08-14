---
name: pr2141-r27-lessons-and-clippy-22ac39777
description: PR #2141 Round-27 delta review at 22ac39777 — 2 lesson files + clippy CI fix on top of Round-26 (ae3a4238f); all accurate, ALIGNED
metadata:
  type: project
---

# PR #2141 Round 27 delta @ 22ac39777 (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-15) — ALIGNED

Delta over Round-26 ([[adr053_substrate_isolation_and_trust_parity_ae3a4238f]]) = 3 commits: 2 lesson docs + 1 clippy fix. Round-26 already validated ADR-053 correction + trust parity; those unchanged.

**Why:** wrapping up the 95-commit branch for merge; CI-green + lesson-capture.

**How to apply:** treat the substance (ADR-053 + trust parity) as settled per Round-26. New material verified accurate:

- `custody-substrate-isolation-holds-at-rest-not-in-transit.md` (new lesson) — ACCURATE. Cross-checked all three referenced facts: (1) bridge.rs:686-692 "Type-level isolation is satisfied... Substrate isolation is NOT yet satisfied" comment EXISTS verbatim; (2) migration-reveal transit (consume→import_ed25519_signing_key transits 32-byte seed through shared process memory, Zeroizing narrows-not-closes) matches ADR-053:101; (3) type-distinctness≠substrate-distinctness matches ADR-053:99 "structurally encouraged... foreign-implementation obligation... conformance test primary observable enforcement." `hash-commitment-preimage-lifetime.md:38` overclaim ("type system enforces §9.7.4.1 §3 at compile time") CORRECTED to "structurally encourages" — resolves the stale claim the lesson itself flagged.
- ucan lesson revocation-narrowing section (e02cf5e99) — ACCURATE. REVOCATION_PREFIXES = exactly `("token revoked:",)` in BOTH trust.py:145 and trust.ts:288 (lockstep, re-confirmed). Operational prefixes ("revocation unauthorized:"/"revocation failed:") correctly EXCLUDED → classify unknown → fail-closed. Referenced gate `test_operational_errors_classify_as_unknown` EXISTS at bindings/python/tests/test_ucan_conformance.py:434 and asserts exactly that (operational msgs → stage=="unknown").
- clippy fix (22ac39777) — 3 behavior-preserving refactors, all VERIFIED equivalent: uri.rs if-let-else-return-None→`?`; tools.rs `and_then(|v| if v.is_none(){None}else{Some(v)})`→`.filter(|v| !v.is_none())`; fullstack.rs drop redundant `&`. Touches ZERO enforcement files.

**LOW/OBS (non-blocking):** clippy commit titled "pre-existing lint errors blocking CI" bundles 3 unrelated non-SDK files (uri/tools/fullstack) into an SDK-coverage+parity PR — technically violates atomic-commit tenet, but justified+honest (mergeability requires green CI; CLAUDE.md mandates fixing CI failures regardless of origin). Not a blocker.

**VERDICT: ALIGNED.** Zero misalignments between stated intent and implementation in the delta.
