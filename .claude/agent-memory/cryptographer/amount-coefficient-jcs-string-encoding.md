---
name: amount-coefficient-jcs-string-encoding
description: Amount/Coefficient string-serde fix for governance JCS injectivity (@0e855a501); SOUND core but ToolCost.amount gap + lenient decode
metadata:
  type: project
---

# Amount/Coefficient JSON-string serde (fix for governance JCS non-injectivity)

Branch fu-amount @0e855a501. Fix: `Amount(u64)`/`Coefficient(i64)` given manual `Serialize`→`self.0.to_string()` (JSON **string**), manual `Deserialize`→`parse::<u64/i64>()`. Closes the CONFIRMED non-injectivity where bare JSON numbers in JCS-signed `GovernanceAction` (`ApproveSpend{amount}`, `SetEconomicPolicy{policy}`) f64-coerce >2^53 (RFC8785 §3.2.2.3) → distinct amounts share signed `action_bytes`/proposal_id.

**Core fix SOUND.** All 4 governance signing sites use `jcs::to_vec(&action)`→`compute_proposal_id`: mod.rs:1706 (SingleAdmin), majority.rs:488, multisig.rs:328? (345), unanimity.rs:328. Serialize is canonical/injective on values → distinct u64/i64 → distinct JCS bytes. Direct tests assert both the fix (`amount_jcs_is_injective_above_2_pow_53`) and the inverse defect (`bare_json_number_is_non_injective_across_f64_boundary`). No f64 anywhere in economy signed structs (integer/fixed-point by design). i64::MIN round-trips. Overflow rejected.

**Findings raised:**
- MEDIUM completeness: `ToolCost.amount: u64` (crates/scp-protocol/src/context/tools/registry.rs:74) is a MONETARY per-invocation cost, reachable in JCS-signed `RegisterTool{registration}` via `ToolRegistration.cost`. Left as bare number → SAME class + SAME reachability (10^18 token >> 2^53) as the fixed bug. Its OWN sig path (compute_tool_registration_canonical_bytes) uses `amount.to_be_bytes()` (injective, safe) but the governance proposal_id path JCS-serializes it (unsafe). Should be `Amount` or string-encoded. Spec §09/§19 notes overclaim that Amount+Coefficient encoding alone makes action_bytes injective.
- LOW: lenient decode — Rust `parse::<u64>` accepts leading zeros ("007"→7) + leading `+` ("+7"); i64 also `-0`/`-007`. Contradicts doc ("rejects... leading zeros, no +"). NOT value-confusion (serialize stays canonical; governance path re-canonicalizes) → wire-malleability + doc/code mismatch only. No test rejects non-canonical accepts.
- LOW (absurd-magnitude): bare u64 still in signed preimages — `PricingVariable::Step.thresholds Vec<(u64,Amount)>` (types.rs:439), `SubscriptionPeriod::Custom.seconds`, `ExtendTtl.additional_secs`, `ProposeContextMigration.grace_period_secs`, `HardRateLimitConfig.burst` (unbounded). All same hazard class but only collide >2^53 (unreachable with realistic values). `pricing_formula_jcs_injective_in_amounts` test covers base_cost only, not thresholds.
