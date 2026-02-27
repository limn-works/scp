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
