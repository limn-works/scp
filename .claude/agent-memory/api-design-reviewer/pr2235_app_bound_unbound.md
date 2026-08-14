---
name: pr2235-app-bound-unbound
description: PR #2235 §8.4 AppBound/AppUnbound event-log API review — cross-binding parity defects in context-id vs handle param, invalid-JSON error code, JSON-string return type, Python coded-error gap
metadata:
  type: project
---

# PR #2235 feat/app-bound-unbound-event-log — API review (2026-08-03)

§8.4 durable AppBound/AppUnbound appends (tags 74/75), codes CTX_2056–2059, across PyO3/NAPI/UniFFI bridges + Python/TS/Swift/Kotlin SDKs. Core fns `bind_app`/`unbind_app` in scp-runtime/context/app_sandbox.rs.

**Why:** Recurring cross-SDK shape-parity concern (see [[cross-sdk-shape-parity]]). This PR reproduced several.

**How to apply — findings to re-verify on next revision:**
- Context-identity param TYPE diverges: PyO3/NAPI/TS take `context_id: string`; UniFFI/Swift/Kotlin take `handle: ContextHandle`. Param ORDER is consistent across all (ctx, decl/app_did, actor_did, timestamp_secs). Within PyO3 this also diverges from sibling context_send(handle,...).
- Invalid-declaration-JSON parse error: UniFFI codes it `VALID_7070`; PyO3/NAPI raise bare PyValueError/NapiError with NO code prefix. Error-code parity gap.
- Return type is a raw JSON string `{"app_did","granted_capabilities":[...]}` — all 4 SDKs return the unparsed string (vs economy_verify_payment_receipts which returns typed dict/PaymentReceiptVerificationResult). Agent-first ergonomics: prefer a typed AppBinding result.
- Python `context_app_bind`/`context_app_unbind` wrappers OMIT the `_coded_bridge_error` translation that the SAME PR added to context_send/governance_propose/etc. TS/Swift/Kotlin do map. Python-only coded-error gap.
- CapabilityDeclaration wire format (8.4.1): `resource` URI category→Capability mapping in CapabilityEntry::to_capabilities silently maps UNKNOWN categories to Capability::Custom (typo "messages" vs "messaging" won't error). Valid actions/categories only in doc comments; declaration passed as opaque signed JSON string — no SDK build+sign helper, caller must do JCS+Ed25519 themselves. min_role/actions stringly-typed.
- Good: was-bound check (CTX_2059) present in all 3 bridges; app_did trimmed consistently; SDK wrapper names contextAppBind/context_app_bind parity across all 4.
