# Loom Status

## Failing Tests
None. All ~2,163 workspace tests pass (1,639 scp-core + 158 scp-mcp + 64 scp-node + 31 scp-media + 44 scp-platform + 215 scp-transport + doctests).

## Uncommitted Changes
None. All changes committed.

## Fixed This Iteration
No previously-failing tests.

## Tests Added / Updated
- **scp-core UCAN spending**: 53 new tests for SpendingCapability, AND-composition, attenuation validation, 24h expiry, budget tracking, mint/validate functions.
- **scp-core bridge claiming**: Tests for shadow claiming with identity attestation, handle mismatch, already-claimed rejection, one-way irreversibility.
- **scp-core context nesting**: Tests for ceiling intersection, lifecycle coupling, eligibility enforcement, multi-parent governance approval.
- **scp-transport relay economics**: Tests for RelayEconomicConfig serialize/deserialize, .well-known/scp parsing with/without economic field, cost-aware relay selection, free relay bootstrap validation.
- **Python SDK MCP**: Tests for serve_mcp(), McpClient, CLI entry point.

## Tool-Gated Stories
None.

## Subagent Outcomes
Five subagents launched in parallel with worktree isolation.

1. **SCP-051** (MCP Python wrapper) — **DONE**. Created `bindings/python/scp_sdk/mcp.py` with `serve_mcp()` async function, `McpClient` class with `connect()`, `list_tools()`, `invoke()` methods, and CLI entry point. Follows existing Python SDK patterns (lazy bridge imports, async-first, error handling).

2. **SCP-088** (Shadow claiming) — **DONE**. Created `crates/scp-core/src/bridge/claiming.rs` with ClaimRequest, ClaimResult, ClaimError types. `claim_shadow()` verifies attestation, retires shadow, retroattributes historical actions. One-way irreversible claiming enforced.

3. **SCP-153** (SpendingCapability UCAN) — **DONE**. Created `crates/scp-core/src/crypto/ucan/spending.rs` with SpendingCapability struct, AND-composition check, attenuation validation, 24h expiry, BudgetTracker with rolling window, mint_spending_ucan_payload and validate_spending_ucan functions. 53 tests. Merged from worktree branch.

4. **SCP-158** (Relay economic config) — **DONE**. Created RelayEconomicConfig in scp-transport, extended .well-known/scp parsing with optional economic field, added cost-aware relay selection to TransportManager, implemented free relay bootstrap validation.

5. **SCP-134** (Context nesting) — **DONE**. Created `crates/scp-core/src/context/nesting.rs` with ParentGovernanceConfig, OnSeverPolicy, ContextNesting struct. Ceiling intersection validation, continuous eligibility enforcement, lifecycle coupling, multi-parent governance approval, MLS group_context extension helper.

## Remaining Stories
Next unblocked stories after this iteration:
- **SCP-135** (Auto-accept policy persistence) — blockers SCP-018, SCP-030 done → UNBLOCKED
- **SCP-138** (Standing channels) — blockers SCP-018/019/020/022 done → UNBLOCKED
- **SCP-058** (Phase 3 integration test) — still blocked by SCP-051 (now done) + many others (SCP-052-057 still pending)
- **SCP-059** (Write ADR-021: UniFFI) — blocked by SCP-058
- **SCP-154** (SpendingLedger) — blocked by SCP-153 (now done), check remaining blockers
- **SCP-155** (PaymentAdapter trait) — check blockers
- **SCP-156** (x402 PaymentAdapter) — check blockers

## Notes
- PRD has duplicate entries for SCP-144, SCP-153, SCP-158. Both duplicates were updated to done where applicable.
- Subagent worktree pattern: most agents committed directly to loom/scp-protocol-core branch; SCP-153 created a separate worktree branch that was merged in Step 3a.
