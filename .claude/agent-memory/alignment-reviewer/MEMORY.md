# Alignment Reviewer Memory

## Phase 4 PR 4 Façade Deletion Review (2026-04-19)
See [phase4_facade_delete_review.md](phase4_facade_delete_review.md) — branch `refactor/phase4-facade-delete` landed method-migration half of PR 4 but NOT the demolition (delete _deprecation.py/ts, SCP.default(), DEFAULT_BRIDGE_INSTANCE, opt-in-tag gate). Verdict MISALIGNED. Pattern: branch names can mislead; verify free-fn counts (`#[pyfunction]`, `#[napi]`, `#[uniffi::export]`), `SCP-DEFAULT-INSTANCE-OK` tag count (533 on branch, plan requires 0), and whether SDKs require explicit SCP instance (not `resolve_scp` fallback).

## SDK Standards Review Round 2 (2026-02-22)
Second pass after ~38 findings were addressed. 6 of 7 originally tracked issues fixed.
Remaining issue: security scanning CI jobs only in Rust/Go, missing from Python/TS/Swift/Kotlin/C#/Java.
New findings: 13 issues (3 material, 10 minor). Verdict: NEEDS REVISION (3 material findings).

### Material findings:
1. API surface missing `ucan_delegate`, `role_assign`, `tool_update`, cross-context tool ops, MCP ops
2. Python `run_sync[T]` uses PEP 695 syntax (requires 3.12) but minimum version is 3.10
3. Security scanning CI absent from 5 of 7 language pipelines despite sdk-common.md mandate

### Previous findings status:
- Maven coordinate collision: FIXED (kotlin/java now have distinct artifact IDs)
- Python PermissionError shadow: FIXED (now UcanPermissionError)
- Swift force unwraps in examples: FIXED (all examples use proper error handling)
- Missing block/trust operations: FIXED (context_block, context_mute, trust_evaluate, trust_attest added)
- Missing sender key conformance tests: FIXED (dedicated category added)
- TypeScript TS 6.0 reference: FIXED (now 5.7+)
- Security scanning in CI: PARTIALLY FIXED (Rust and Go only)

### Notes:
- `.docs/specs/` is empty (only .gitkeep) -- no product spec files to cross-reference
- Trust operations (evaluate, attest) are forward-looking; not in any current ADR but don't contradict
- Rust streams return OuterEnvelope while other SDKs return Message -- naming table inconsistency

## ADR-022 Review (SCP-060) (2026-02-26)
ADR-022 (TypeScript SDK Dual-Target Architecture) reviewed and PASSED.
- All 8 acceptance criteria satisfied.
- 3 minor issues found: shared.md lists `@limn-works/scp-ts-node` but ADR-022 uses per-platform `@limn-works/scp-ts-napi-{platform}` (shared.md needs update); trust.ts and mcp.ts listed in wrapper layout but no acceptance criteria; Context.join() is static while other methods are instance (inconsistent surface).
- 4 non-blocking suggestions: receive() generator needs cleanup on break; asyncDispose should guard on state; CI commands should match standards file exactly; private field access across classes in sketched code.

### ADR review patterns (reusable):
- Always check the original stub ("What This ADR Will Decide" + "Expected Decisions") against final content
- Cross-reference scaffold/, standards/, and sdk-common.md for naming/convention consistency
- Verify package names in shared.md Distribution Channels match actual ADR decisions
- Check that wrapper file layouts match acceptance criteria coverage (modules listed but not tested = gap)
- Cross-ADR references can drift: verify callback interfaces, trait names, and type names match between dependent ADRs
- Force-try/force-unwrap keeps appearing in Swift examples despite builder tenets -- always flag

## ADR-025 Apple Platform Adapter Review (SCP-082) (2026-02-26)
Initial review: FAIL (2 major, 1 minor). All 3 findings FIXED in PR #86.
- StrongBox rationale moved to ADR-027 where it belongs
- Force-try replaced with proper `throws` in `make()`
- DeviceAttestationProvider now present in ADR-021 UDL (5 callback interfaces total)
Remaining: ADR-025 example code (line 419) still has `.data(using: .utf8)!` force-unwrap, but implementation avoids it.

## PR #86 Full Review (2026-02-26)
Verdict: ALIGNED. ADRs 022, 025, 026, 027, 028, 029, 030, 031 all reviewed.
3 minor doc issues: ADR-025 example force-unwrap, ADR-022 generator cleanup on break, ADR-028 ucanMint accessing private handle.
All previous major findings resolved. Implementation code matches ADR specs.
Phase 6 ADRs (029-031) are "Decided" but not yet implemented; no roadmap conflicts.
Weighted voting deferral in ADR-031 is justified (requires unbuilt token/stake mechanism).

## Gate 1 Verification (Phase 1: Crypto Proof) (2026-02-27)
Deep verification of SCP-001 through SCP-017. All 17 stories VERIFIED.
- All files exist at expected paths
- All acceptance criteria met (spot-checked every story)
- 2,630+ tests across scp-platform (45), scp-core (2,370), scp-transport (215), scp-testing (2 integration)
- All tests pass green
- No unwrap()/expect() in library code (only in #[cfg(test)] blocks)
- #![forbid(unsafe_code)] present in all crate roots
- Proptests for all required crypto operations
- Feature gating correct: testing adapters behind `software_platform` feature
- 0 material findings, 2 minor observations

### Gate 1 verification patterns (reusable):
- Test count from result fields can drift; always run `cargo test` to get actual counts
- Feature flag naming: `software_platform` not `testing` -- the lib.rs aliases `testing` as `software`
- The scp-core crate has 2,370 tests because it includes context, economy, bridge, etc. beyond Phase 1

## SCP-161 Review: Paid Context Templates (2026-02-27)
Verdict: ALIGNED. All 14 acceptance criteria PASS. 71 tests pass.
2 non-blocking actions:
1. serde(rename) inconsistency: PaidService/PaidBroadcast have scp:template/ URIs but older variants (BilateralEphemeral etc.) don't -- mixed serialization conventions.
2. ToolInterface template variant missing from TemplateId enum despite being defined in spec 05-contexts.md:247. PaidService "extends" it conceptually but no structural enforcement.

### Template review patterns (reusable):
- For "extends" relationships: verify the child's properties are a valid specialization of the parent (ceiling can narrow, not just match)
- For caller-supplied fields (like economic_policy): validation should be a separate function, not part of the generic field-comparison loop
- Check serde(rename) consistency across all enum variants -- partial adoption creates wire-format inconsistencies
- Template inheritance is conceptual in this codebase -- no formal extends mechanism, only comments and matching properties

## Gate 3 Verification (Phase 3: Python SDK + MCP) (2026-02-27)
Deep verification of SCP-036 through SCP-058. 23 stories, all marked "done". Verdict: **INCOMPLETE**.
- 23/23 stories have code at correct locations
- 17/23 stories have real, functional implementations
- 6 stories have bridge stubs blocking end-to-end functionality
- Rust MCP crate: 158 tests pass. UCAN crate: 273 tests pass. All green.

### 3 Material findings:
1. **Bridge stubs:** `tools.rs`, `ucan.rs`, `event_log.rs` in `crates/scp-ffi/src/` are stubs returning `Err("not implemented")`. Blocks SCP-040 (tools), SCP-041 (UCAN bridge), SCP-039 (event log).
2. **Missing MCP bridge functions:** `mcp.py` calls 9 bridge functions (`py_mcp_serve`, `py_mcp_client_connect_stdio`, etc.) that do not exist in the `scp-ffi` bridge layer. Blocks SCP-046 (MCP Python wrapper).
3. **Mock-based integration test:** `phase3_integration_test.py` uses `MagicMock` for the bridge -- validates Python SDK logic but not actual Rust integration. Only 3 of 16 test methods attempt real bridge calls. Blocks SCP-058 (integration test story).

### 4 Minor findings:
1. PRD `files` paths systematically wrong (missing `src/` segment) -- `crates/scp-ffi/pyo3/` should be `crates/scp-ffi/src/`
2. Conflicting pyproject.toml: `crates/scp-ffi/pyproject.toml` says Python >=3.9, `bindings/python/pyproject.toml` says >=3.10
3. `ToolError` in `errors.py` is unreachable -- `tools.rs` bridge raises generic `ScpError`, not `ToolError`
4. Async pattern deviation: `context.py` uses `asyncio.to_thread()` instead of `py.allow_threads(|| rt.block_on(...))` pattern from other modules

### What's solid:
- Rust MCP crate (`scp-mcp`): protocol.rs, namespace.rs, server.rs, client.rs, stdio.rs, sse.rs -- all real, tested, comprehensive
- Rust UCAN crate: 11-step validation pipeline, capability matching, nonce tracking, revocation, minting -- all real, 273 tests
- Python SDK wrappers: identity.py, context.py, sync.py, types.py, errors.py, trust.py -- well-structured, correct patterns
- PyO3 bridge: identity.rs, context.rs, error.rs -- real implementations calling scp-core

### Gate 3 verification patterns (reusable):
- PRD file paths can be systematically wrong; always glob to find actual locations
- Bridge layers need function-by-function verification -- stub signatures look correct but return errors
- Python wrappers that call non-existent bridge functions compile fine (dynamic dispatch) -- must cross-reference against bridge lib.rs module registration
- Mock-based integration tests provide false confidence -- verify what the mocks are replacing

## PR #118 Review: Android Platform Adapters + Kotlin Bridge (2026-02-28)
Verdict: NEEDS REVISION (1 blocking finding).
8 stories: SCP-110, SCP-111, SCP-112, SCP-113, SCP-115, SCP-211, SCP-212, SCP-213.

### Blocking:
- **PlatformAdapter.kt missing**: ADR-027 specifies 5 files, only 4 delivered. The factory `AndroidPlatformAdapter.make(context)` that wires adapters into `Scp.create()` does not exist.

### Non-blocking:
- `assertRequest()` vs ADR-027 spec `assert()` -- correct name per UniFFI, ADR needs update
- `verify()` and `custodyType()` listed in ADR-027 scope but absent from Kotlin interface -- Rust trait also omits verify, custodyType redundant with KeyHandle.custodyType field
- `softwareKeys` is `internal` not `private` -- exposes private key material within module
- SQLCipher dependency uses `sqlcipher-android:4.6.1` not `android-database-sqlcipher:4.5.4` (different artifact)
- `py_mcp_load_contexts` ignores `relay_url` param (prefixed with `_`)

### Patterns (reusable):
- ADR code samples diverge from implementation: method names, dependency versions, artifact IDs. Always verify actual code against ADR pseudocode.
- When checking platform adapters against Rust traits, compare method-by-method including return types -- Kotlin interfaces may simplify (e.g. returning DestructionAttestation instead of `()`)
- Android JVM unit tests cannot exercise hardware paths (Keystore, Play Integrity). Tests correctly scope to software/deterministic paths.
- `internal` visibility in Kotlin leaks key material within module -- prefer `private` with API-only test assertions
- PlatformAdapter factory is the critical glue between platform adapters and SDK entry point -- always verify it exists
