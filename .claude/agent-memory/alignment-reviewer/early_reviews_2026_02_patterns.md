---
name: early-reviews-2026-02-patterns
description: Archived 2026-02/03 review verdicts (SDK standards, ADR-022/025, PR #86, Gate 1, SCP-161, Gate 3, PR #118) plus the reusable review patterns they produced
metadata:
  type: project
---

Archive of the earliest alignment reviews. **Verdicts are historical — do NOT cite as current state.** Kept for the reusable patterns.

## Verdicts (historical)
- **SDK Standards Round 2 (2026-02-22)** — NEEDS REVISION. 3 material: API surface missing `ucan_delegate`/`role_assign`/`tool_update`/cross-context tool ops/MCP ops; Python `run_sync[T]` PEP 695 needs 3.12 but min was 3.10; security-scanning CI only in Rust/Go (missing Python/TS/Swift/Kotlin/C#/Java).
- **ADR-022 TS dual-target (SCP-060, 2026-02-26)** — PASS, 8/8 AC. Minor: shared.md package name drift; `Context.join()` static while siblings are instance.
- **ADR-025 Apple adapters (SCP-082, 2026-02-26)** — FAIL→all 3 fixed in PR #86 (StrongBox rationale moved to ADR-027, force-try replaced, DeviceAttestationProvider added to ADR-021 UDL).
- **PR #86 (2026-02-26)** — ALIGNED. ADRs 022/025/026/027/028/029/030/031. 3 minor doc issues.
- **Gate 1 / Phase-1 crypto proof (2026-02-27)** — all 17 stories (SCP-001..017) VERIFIED, 2630+ tests green, 0 material.
- **SCP-161 paid context templates (2026-02-27)** — ALIGNED, 14/14 AC. 2 non-blocking: serde(rename) inconsistency across TemplateId variants; ToolInterface variant missing from the enum.
- **Gate 3 / Phase-3 Python SDK + MCP (2026-02-27)** — INCOMPLETE. 6 of 23 "done" stories blocked on bridge stubs (`tools.rs`/`ucan.rs`/`event_log.rs` returning `Err("not implemented")`), 9 missing `py_mcp_*` bridge fns, and a MagicMock-based "integration" test.
- **PR #118 Android adapters + Kotlin bridge (2026-02-28)** — NEEDS REVISION. Blocking: `PlatformAdapter.kt` factory missing (ADR-027 specifies 5 files, 4 delivered).

## Reusable patterns
- Check the ADR's original stub ("What This ADR Will Decide" / "Expected Decisions") against its final content.
- Cross-reference `scaffold/`, `standards/`, and `sdk-common.md` for naming consistency; package names in shared.md Distribution Channels drift from ADR decisions.
- Wrapper file layouts listed without matching acceptance criteria = coverage gap.
- Cross-ADR references drift: verify callback interfaces, trait names, type names between dependent ADRs.
- ADR code samples diverge from implementation (method names, dependency versions, artifact IDs). Verify actual code, never the pseudocode.
- Test counts in result fields drift; run `cargo test` for real numbers.
- PRD `files` paths are often systematically wrong — glob for the actual location.
- Bridge layers need function-by-function verification: stub signatures look correct but return errors. Python wrappers calling non-existent bridge fns compile fine (dynamic dispatch) — cross-reference against bridge `lib.rs` module registration.
- Mock-based integration tests give false confidence — verify what the mock replaces.
- Platform adapters vs Rust traits: compare method-by-method including return types.
- For template "extends" relationships: verify the child is a valid specialization (ceiling narrows, not just matches).
- Force-try / force-unwrap keeps reappearing in Swift examples despite the builder tenets — always flag.
