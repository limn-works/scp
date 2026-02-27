# Alignment Reviewer Memory

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
- 3 minor issues found: shared.md lists `@scp/sdk-node` but ADR-022 uses per-platform `@scp/sdk-napi-{platform}` (shared.md needs update); trust.ts and mcp.ts listed in wrapper layout but no acceptance criteria; Context.join() is static while other methods are instance (inconsistent surface).
- 4 non-blocking suggestions: receive() generator needs cleanup on break; asyncDispose should guard on state; CI commands should match standards file exactly; private field access across classes in sketched code.

### ADR review patterns (reusable):
- Always check the original stub ("What This ADR Will Decide" + "Expected Decisions") against final content
- Cross-reference scaffold/, standards/, and sdk-common.md for naming/convention consistency
- Verify package names in shared.md Distribution Channels match actual ADR decisions
- Check that wrapper file layouts match acceptance criteria coverage (modules listed but not tested = gap)
- Cross-ADR references can drift: verify callback interfaces, trait names, and type names match between dependent ADRs
- Force-try/force-unwrap keeps appearing in Swift examples despite builder tenets -- always flag

## ADR-025 Apple Platform Adapter Review (SCP-082) (2026-02-26)
Verdict: FAIL (2 major, 1 minor).
- **StrongBox is Android, not Apple** (major): Rationale "Why reject StrongBox" is factually wrong
- **Force-try contradicts error handling claim** (major): `try!` in make() vs stated PlatformError return
- **DeviceAttestationProvider missing from ADR-021** (minor): ADR-025 claims 4 callback interfaces but ADR-021 UDL only defines 3
