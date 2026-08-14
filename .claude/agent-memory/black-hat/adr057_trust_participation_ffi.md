---
name: adr057-trust-participation-ffi
description: Adversarial review of ADR-057 structured-trust FFI (verify_participation_requirements void+throw + subject binding), branch c9c956739 — no exploitable findings
metadata:
  type: project
---

# ADR-057 trust/participation FFI review (HEAD c9c956739)

Reviewed `verify_participation_requirements` (core + PyO3/NAPI/UniFFI + Py/TS/Swift/Kotlin SDKs),
`check_capability_requirements`, `verify_challenge_verification`, aggregate verify-on-ingest.

**Verdict: no exploitable vulnerabilities in the change set. Well-hardened.**

Key confirmations:
- Subject binding CRYPTOGRAPHIC: `ParticipationProfile::signable_bytes` includes length-prefixed
  `subject_did` in signed preimage (participation.rs:785). Step-0 plaintext filter + Step-1 sig verify.
  A tampered plaintext subject fails signature check. `verify_challenge_verification` (challenge.rs:868)
  binds subject+context+expiry over signed canonical bytes, signature-FIRST.
- Empty-subject rejected in BOTH core fns (EmptyExpectedSubject / EmptySubjectDid) AND at all 3 bridges via validate_did.
- Void+throw contract clean across all 4 SDKs; old `bool` return was vestigially always-true, no caller relied on it.
- Arg-order change: OLD PyO3 was `(profile_json, requirements_json)`; NEW is `(expected_subject, requirements_json, profile_json)` — the two JSON args SWAPPED relative order. Every call site updated correctly (SDK wrappers named/positional-correct, core uses distinct types = compile-safe). No transposed caller found.
- Aggregate read path (aggregate.rs:530) re-verifies challenge results with correct subject+context, fail-closed `.is_ok()`, with documented resolver-totality caveat.
- store/trust.rs uses sanitize_key_component + subject-scoped keys (test rejects_traversal_in_subject_did).
- Enforcement-file changes (bridge-aliases.json, check-sdk-coverage.py) additive-only.

Informational (not defects):
1. Self-certifying signer/verifier = min_contexts gives NO Sybil resistance (subject can mint N profiles
   from N keys it controls for its own subject_did). Correctly documented in core, deferred to spec §7.4.
   BUT Python SDK docstring (trust.py:1046) omits the "establish signer legitimacy separately" caveat —
   agent-author could mistake this for a complete Sybil-resistant gate. Recommend surfacing in all 4 SDK docs.
2. Core fns check is_empty() but not DID well-formedness; FFI compensates via validate_did. A future direct
   core/runtime caller could pass whitespace subject. Not exploitable (still binds to exact string). Low.
3. check_capability_requirements re-exported at scp-core (lib.rs:128) but has NO FFI/SDK/runtime caller —
   hardened-but-unwired. Completeness note, not security.
