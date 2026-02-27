# Red Hat Agent Memory

## PR #76 Assessment (2026-02-26)
- 11 exploitation chains identified (RED-001 through RED-011)
- 2 CRITICAL (shadow claiming/role escalation without sig verification)
- 3 HIGH (timestamp manipulation, governance config hash non-determinism, role escalation)
- 4 MEDIUM (TOCTOU, proposal ID collision, budget tracker concurrency, TestAdapter leakage)
- 2 LOW (economic policy bypass, MCP provenance)

## Key Attack Patterns for This Codebase
- **"Caller is responsible" pattern**: claim_shadow and upgrade_shadow_role defer signature verification to callers. Tests use vec![0u8; 64] signatures everywhere, normalizing the pattern. Look for this in future code.
- **Timestamp injection**: SenderVelocityTracker accepts arbitrary timestamps. Any new function accepting external timestamps should validate against wall clock.
- **HashSet serialization non-determinism**: ParentGovernanceConfig::content_hash() uses serde_json on HashSet -- not deterministic. Check all content_hash() functions for this.
- **TOCTOU in async lock patterns**: StandingChannelManager drops lock before async operation then re-acquires. Classic pattern to watch for.
- **Proposal ID as HashMap key**: Silent overwrite on collision. Check any HashMap<[u8; 32], _> insertions.

## Files with Security-Critical Issues
- `crates/scp-core/src/bridge/claiming.rs` -- No sig verification (RED-001)
- `crates/scp-core/src/bridge/shadow.rs` -- No governance verification (RED-002)
- `crates/scp-core/src/economy/antispam.rs` -- Timestamp injection (RED-003)
- `crates/scp-core/src/context/standing.rs` -- TOCTOU race (RED-004)
- `crates/scp-core/src/context/governance/mod.rs` -- Proposal ID collision (RED-005)
- `crates/scp-core/src/context/nesting.rs` -- HashSet hash non-determinism (RED-009)
- `crates/scp-core/src/crypto/ucan/spending.rs` -- BudgetTracker not thread-safe (RED-007)
