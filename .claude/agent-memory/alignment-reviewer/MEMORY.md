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
