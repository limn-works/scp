---
name: finding-permissionerror-rename-incomplete
description: PR #1867 renamed SDK PermissionError→UcanPermissionError but missed phase-3.md (Python blueprint, 4 refs) and scaffold/typescript.md (TS blueprint, 1 ref)
metadata:
  type: project
---

PR #1867 (`fix/sdk-coverage-fail-closed-and-parity`, HEAD c0bee8d22) renamed the SDK error class `PermissionError` → `UcanPermissionError` and fixed doc drift in `phase-4.md`, `sdk-common.md`, `prds/main.json`. Both shipped SDKs (TS `errors.ts`, Python `errors.py`) have ONLY `UcanPermissionError`, no `PermissionError`.

**Missed stale references** (same class of drift, ungreped files):
- `.docs/adrs/phase-3.md:379,682,946,977` — Python SDK error-hierarchy blueprint + examples (`class PermissionError(ScpError)`, `scp_sdk.PermissionError`, `except scp.PermissionError`, "fails with PermissionError"). Refers to the renamed Python class.
- `.docs/scaffold/typescript.md:177` — TS SDK error-class blueprint (`export class PermissionError extends ScpError`). Contradicts actual SDK.

**Correctly left alone** (different language idiom, not the SCP SDK class):
- `.docs/scaffold/go.md:231,238` — Go SDK; `PermissionError` is Go-idiomatic, Go SDK not in scope.
- `bindings/python/tests/test_types.py:114` — `assert not isinstance(err, PermissionError)` tests the shadowing-avoidance against `builtins.PermissionError`; correct as-is.

**Why:** rename PRs need a full-repo grep, not a file-by-file pass. The author greped the files they remembered.
**How to apply:** when reviewing any SDK-symbol rename, run `git grep -n "<oldname>"` across all of `.docs/` + `docs/` + `bindings/` and classify each hit (SCP SDK class = fix; other-language idiom or builtin-shadow test = leave).

Cross-ref: ADR-053 §51 "Canonical migration flow" method-name conflation (operational `import_seed_bytes` vs `import_ed25519_signing_key`) that I previously flagged was FIXED in this PR — line 51 now correctly reads `KeyCustody::import_ed25519_signing_key(seed)`; line 48 keeps `import_seed_bytes` as the distinct pre-rotation-provider method.
