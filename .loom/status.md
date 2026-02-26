# Loom Status

## Failing Tests
None. All ~2,193 workspace tests pass (1,667 scp-core + 1 scp-core integration + 158 scp-mcp + 64 scp-node + 31 scp-media + 4 scp-testing + 44 scp-platform + 215 scp-transport + doctests).

## Uncommitted Changes
None. All changes committed.

## Fixed This Iteration
No previously-failing tests.

## Tests Added / Updated
- **Phase 3 integration test** (SCP-058): `tests/integration/phase3_integration_test.py` — 13-step end-to-end Python SDK test exercising Identity, Context, Tools, UCAN, MCP, EventLog across PyO3 bridge.
- **Addressability integration tests** (SCP-148): `crates/scp-node/tests/integration.rs` — 4 scenarios: ApplicationNode lifecycle, .well-known/scp discovery, DID resolution, scp:// URI roundtrip.
- **Auto-accept policy tests** (SCP-135): Unit tests in `crates/scp-core/src/context/policy.rs` — CRUD roundtrip, persistence across restart, absent policy returns None, economic policy hard rule.
- **Standing channels tests** (SCP-138): Unit tests in `crates/scp-core/src/context/standing.rs` — idempotent get-or-create, new context creation, re-invitation on peer left, startup reconnection.
- **PaymentAdapter conformance** (SCP-151): `payment_adapter_conformance!()` macro in `crates/scp-testing/src/conformance/payment.rs` generating 8 test cases. Unit tests in `crates/scp-core/src/economy/adapter.rs`.

## Tool-Gated Stories
None.

## Subagent Outcomes
Five subagents launched in parallel with worktree isolation. All committed directly to the loom/scp-protocol-core branch.

1. **SCP-058** (Phase 3 integration test) — **DONE**. Created `tests/integration/phase3_integration_test.py` with pytest/pytest-asyncio test exercising full Python SDK surface: identity creation, context with tools, member join, UCAN-validated messaging, tool invocation, UCAN rejection, MCP server/client, event log verification, capability revocation.

2. **SCP-148** (Addressability integration test) — **DONE**. Created `crates/scp-node/tests/integration.rs` with 4 test scenarios covering ApplicationNode builder lifecycle, .well-known/scp HTTP endpoint discovery, DID-based relay discovery, and scp:// URI roundtrip parsing.

3. **SCP-135** (Auto-accept policy persistence) — **DONE**. Created `crates/scp-core/src/context/policy.rs` with AutoAcceptPolicy struct, CRUD via Storage trait (key convention `policy/{did}/auto_accept`), and hard rule blocking auto-accept for contexts with economic policy requiring payment.

4. **SCP-138** (Standing channels) — **DONE**. Created `crates/scp-core/src/context/standing.rs` with StandingChannelManager implementing 4-step get-or-create logic (check local state → return if active → create if missing → re-invite if peer left) and startup reconnection via `reconnect_all()`.

5. **SCP-151** (PaymentAdapter trait) — **DONE**. Created `crates/scp-core/src/economy/adapter.rs` with PaymentAdapter trait (#[async_trait], Send + Sync), AdapterCapabilities, PaymentAuthorization, PaymentReceipt, PaymentError, VerificationResult, RefundConfirmation, PaymentMetadata types. Created `crates/scp-testing/src/conformance/payment.rs` with `payment_adapter_conformance!()` macro generating 8 test cases.

## PRD Maintenance
- Deduplicated PRD entries: SCP-140, 142, 143, 144, 145, 146, 147, 149, 150, 153, 158 had duplicate "done"/"pending" entries. Fixed by keeping first occurrence (the "done" version). PRD reduced from ~168 to 162 stories.

## Remaining Stories
Next unblocked stories after this iteration:
- **SCP-059** (Write ADR-021: UniFFI) — blocked by SCP-058 (now done) → UNBLOCKED
- **SCP-121** (Hours-scale offline buffering) — all blockers done → UNBLOCKED
- **SCP-125** (Event log checkpoint creation) — all blockers done → UNBLOCKED
- **SCP-128** (Event log growth monitoring) — all blockers done → UNBLOCKED
- **SCP-129** (Governance interface contract) — all blockers done → UNBLOCKED
- **SCP-154** (SpendingLedger) — check if SCP-153 (done) + SCP-150 (done) unblocks it
- **SCP-155** (PaymentAdapter x402) — check if SCP-151 (now done) unblocks it
