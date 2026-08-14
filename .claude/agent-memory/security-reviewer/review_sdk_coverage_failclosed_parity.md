---
name: review-sdk-coverage-failclosed-parity
description: Security review of branch fix/sdk-coverage-fail-closed-and-parity (HEAD 8c0713499) — SDK parity additions + coverage gate fail-closed + ADR-051
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity — CLEAN (no security findings)

HEAD 8c0713499, base 0c8f0b065. Reviewed for trust-boundary, capability-escalation,
auth-bypass, error-message-parsing injection, info-disclosure, gate-bypass, ADR-051 gap.

**Verdict: no CRITICAL/HIGH/MED/LOW security findings.** All new code is thin forwarders
or faithful ports of already-shipped Python behavior.

KEY POINTS:
- TS `evaluateTrust` (trust.ts) is a byte-faithful port of bindings/python/scp_sdk/trust.py
  (pre-existing). Optimistic-then-falsify Layer-1 pattern; `__PASSED_BEFORE.unknown = empty set`
  => unknown UCAN error classifies fail-CLOSED (all fields false). break-on-first-failure.
- Error-string parsing (`__extractCoreError`/`__classifyUcanError`) only drives an INFORMATIONAL
  CapabilityValidation struct; it performs NO authorization. Real auth is `scp.ucanValidate` in
  Rust core. A misclassification cannot grant access — worst case mislabels a diagnostic field.
- `instanceof UcanPermissionError` filter sound: code-prefix map SCP-PERM- => UcanPermissionError;
  non-UCAN errors propagate (not swallowed). Rust napi From<UcanError> format confirmed:
  "[SCP-PERM-3001] permission error: <Display> — advice" (em-dash U+2014). Parser matches.
- ucanValidate(handle, token, "*") wildcard cap — same as Python; within_ceiling semantics are
  informational only, not an enforcement decision.
- New identity-lifecycle methods (identityRotateKey/Migrate/AddAgentKey/RotateAgentKey/RemoveAgentKey)
  route via getBridge(this) — per-SCP WeakMap (_nativeBridgeForScp), instance isolation preserved
  (ADR-048). Bridge iface methods pre-existing. No SDK-layer auth (correct; thin forwarder).
- Coverage gate (check-sdk-coverage.py): WARN→ERROR is strictly TIGHTENING (fail-closed). Escape
  hatch = coverage_exemptions JSON requiring reasoned per-SDK entry, same pattern as exemptions.
  _EXTRA_ALIASES are matrix-coverage mappings only — no runtime effect; verified send/join spending-
  UCAN aliases point at methods that actually accept the param. Kotlin recursive extractor OVER-
  captures (safe failure mode for fail-closed gate). One coverage_exemptions added (add_relay_url/
  kotlin) for UniFFI-generated backtick methods tree-sitter can't parse.
- ADR-051 documents a PRE-EXISTING gap (pre-rotation key shares process-memory substrate on callback-
  custody path, violates §9.7.4.1 §3). This PR does NOT introduce/weaken anything — it makes a known,
  already-source-commented, already-fail-closing (migration import_ed25519_signing_key Unsupported)
  limitation legible with a remediation plan. Net-positive for posture.
- Test-only __-prefixed exports NOT re-exported from index.ts; pure classifiers, no secrets.
- Python economy_verify_payment_receipts correctly documents ok vs valid/all_valid footgun.
