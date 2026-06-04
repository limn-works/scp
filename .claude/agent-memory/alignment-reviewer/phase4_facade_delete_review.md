---
name: Phase 4 PR 4 Façade Deletion Review
description: 2026-04-19 review of refactor/phase4-facade-delete branch — method-migration landed, demolition slice missing, branch name mismatches plan intent
type: project
---

Branch `refactor/phase4-facade-delete` reviewed 2026-04-19 against master plan `/Users/alec/.claude/plans/cozy-fluttering-rose.md` §618/§700/§870-905 (re-scoped 2026-04-19: no deprecation window, builder tenet "no deferral").

**Why:** Branch commit footers say `#1549 PR 4` and name implies demolition, but landed work is only the method-addition half.

**How to apply:** When reviewing "Phase 4 PR 4" or `#1549` work: verify demolition (delete _deprecation.py, _deprecation.ts, SCP.default(), DEFAULT_BRIDGE_INSTANCE, check-no-default-in-tests.sh, all SCP-DEFAULT-INSTANCE-OK tags, all @Deprecated annotations, all free-function façade exports) has actually landed. Counts to verify:
- PyO3 free `#[pyfunction]`s should be near 0 (only pure helpers)
- NAPI free `#[napi]` exports should be near 0
- UniFFI `#[uniffi::export]` free fns should be near 0
- `grep -rn "SCP-DEFAULT-INSTANCE-OK" bindings/` should be 0
- `grep -rn "DEFAULT_BRIDGE_INSTANCE" crates/scp-ffi/` should be 0
- `_deprecation.py` and `internal/deprecation.ts` should not exist
- `SCP.default()` / `SCP.default_instance()` should not exist in any of 4 SDKs

Key paths for the demolition:
- `bindings/python/scp_sdk/_deprecation.py` (delete)
- `bindings/typescript/src/internal/deprecation.ts` (delete)
- `bindings/swift/Sources/SCP/SCP.swift` (remove default()/deprecated annotations)
- `bindings/kotlin/scp-sdk-kotlin/` (no SCP.kt found — may need creation)
- `scripts/check-no-default-in-tests.sh` (delete)
- `crates/scp-ffi/src/lib.rs` (scp_suspend/scp_resume still free)

The Python SDK pattern to watch: `from scp_sdk._deprecation import resolve_scp` + `resolve_scp(scp)` → falls back to SCP.default_instance(). This is the façade in a different shape; plan requires SDK methods to REQUIRE an explicit SCP instance, not fall back.

## Landed work assessment (method-migration half)

- 22 commits, well-sequenced sub-slices A-G across PyO3/NAPI/UniFFI
- PyO3: 192 &self method sigs on PyScp; NAPI: 163 NapiScp methods; UniFFI: corresponding
- SDK wrappers for Python (`scp.py`), TS, Swift, Kotlin added
- All 4 SDK index/__init__ files export `SCP` class
- Commit messages reference `#1549 PR 4` and follow conventional commits

## Review patterns (reusable)

1. When plan says "4 PRs all atomic," verify the branch implements ALL parts, not just the easier additive half.
2. Branch naming can mislead — always verify against plan text, not branch name.
3. Free-function counts on the branch are a direct signal of demolition progress:
   - `grep -rn "^#\[pyfunction\]" crates/scp-ffi/src/ | wc -l`
   - `grep -rn "^#\[napi\]" crates/scp-ffi/napi/src/ | wc -l`
   - `grep -rn "^#\[uniffi::export\]" crates/scp-ffi/uniffi/src/ | wc -l`
4. SDK delegation path reveals façade vs method-only:
   - If SDK imports `resolve_scp` or similar fallback helper → façade still present
   - If SDK methods require explicit `scp: SCP` param (no optional/None default) → method-only
5. The 533 `SCP-DEFAULT-INSTANCE-OK` count is a direct readout of test migration progress — plan requires 0.
