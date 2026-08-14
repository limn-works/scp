---
name: pr2235-app-bound-event-log
description: Defensive facts from PR #2235 app-bound/unbound event-log review (validate_did whitespace, version parse fail-open, CTX code classification)
metadata:
  type: project
---

# PR #2235 feat/app-bound-unbound-event-log (2nd-pass, commit 54dd06ee8)

**Why:** verified the 5 defensive fixes. **How to apply:** reuse these invariant facts for context/app-sandbox work.

## Reusable facts
- `scp_ffi_common::validate::validate_did` (crates/scp-ffi/common/src/validate.rs:278) does NOT reject leading/trailing whitespace — space (0x20) is not a control char, and only method/prefix/length/control are checked. So any `.trim()` around a validated DID is genuinely load-bearing, not dead code.
- CTX error codes render as `SCP-CTX-NNNN` (error_codes.rs). Python `_coded_bridge_error` (errors.py) anchors `^\s*\[(SCP-[A-Z]+-\d+)\]`, prefix `SCP-CTX`→ContextError. CTX_2056/2057/2058/2059 all classify correctly.
- app_bind/unbind live in: PyO3 crates/scp-ffi/src/context.rs (~6147), NAPI crates/scp-ffi/napi/src/context.rs (~5055/5165), UniFFI crates/scp-ffi/uniffi/src/bridge.rs (~15724/15891). All 3 use `supervisor.event_log_provider_arc()` (None→CTX-2057 typed error, fail-closed) and trim app_did for store(bind)/lookup(unbind).
- `bind_app`→`validate_declaration` (app_sandbox.rs:802) calls `validate_structure`. Caps: app_name 128B+non-empty, app_version 64B, capabilities 1..=64, actions 1..=32/entry, min_role non-empty. CURRENT_SCP_VERSION="1.0" (current_minor=0).

## Finding (WARNING, not a blocker)
- validate_structure minor-version parse is FAIL-OPEN: `decl_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0)`. Malformed ("1.bad") or u64-overflow ("1.99999999999999999999") minor coerces to 0 → `0 > current_minor(0)` false → ACCEPTED, evading the future-minor rejection. Major is string-compared so garbage major IS rejected; "" rejected via major mismatch; legit "1.5" rejected. Blast radius low: version gate is compatibility-only, capabilities still bounded by ceiling. Fix: reject unparseable minor instead of unwrap_or(0).

## INFO
- Core AppBound payload records UNtrimmed `scoped.app_did()` while registry key is trimmed; unreachable-in-practice since whitespace app_id fails sig-verify at bind.
- app_bind serde JSON-parse failure raises PyValueError "invalid declaration JSON" with NO code prefix → `_coded_bridge_error` falls back to base ScpError (class "ValueError" not in BRIDGE_ERROR_MAP), not ValidationError.
- SignatureVerificationFailed folded into CTX_2056 with CeilingExceeded/InvalidDeclaration — loses crypto distinction but fail-closed (arguably intentional non-leak).
- Do NOT re-flag architectural issues #2256-#2262 (already filed).
