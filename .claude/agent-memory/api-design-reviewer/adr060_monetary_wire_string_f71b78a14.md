---
name: adr060-monetary-wire-string-f71b78a14
description: ADR-060 monetary decimal-string JSON wire + per-SDK bigint/int/UInt64/ULong money surface + format() display helper — API review; re-review @3e241fac4 APPROVED
metadata:
  type: project
---

ADR-060 (branch fu-money). Re-review @3e241fac4 = **APPROVED** (supersedes NEEDS REVISION @f71b78a14). All 3 prior findings fixed; no regressions.

**What it does:** `Amount(u64)`/`Coefficient(i64)` hand-written serde split on `is_human_readable()` — JSON = canonical decimal STRING (strict parser: rejects bare numbers/leading-zeros/signs/whitespace; visit_str), MessagePack = native int (visit_u64). `ToolCost.amount` retyped `u64`→`Amount`. Per-SDK money surface + `format`/`formatAmount` display helper.

**PRIOR FINDINGS — ALL RESOLVED @3e241fac4:**
- MOD (ToolCost.amount lossy number): FIXED. TS `ToolCost.amount: bigint` (types.ts:597), napi `NapiToolCost.amount: BigInt` (tools.rs) via shared `amount_u64_from_bigint` helper (rejects signed/!lossless→VALID_7001), UniFFI `Amount(c.amount)` native u64 (Swift UInt64/Kotlin ULong ToolCostDefinition), PyO3 native u64 (int arbitrary-prec). Kotlin public `works.limn.scp.ToolCost.amount: ULong` + toJson→decimal string; the category-error "Phase 2 string params" comment is GONE.
- MOD-obs (sentinel harmonization): FIXED. TS `economyEstimateCost`/`economyEvaluateFormula` now return `bigint | null`, mapping napi `-1n`→null at SCP-class wrapper (scp.ts) — matches Python `int|None`, Swift `UInt64?`/Kotlin `ULong?` (UniFFI native `Result<Option<u64>>`). Tests cover 0n(real)≠-1n(sentinel) + >2^53 exact. napi sentinel is bridge-internal, hidden from SDK consumer.
- LOW (Kotlin BridgeException): FIXED. Kotlin `formatAmount` now throws `IllegalArgumentException` (idiomatic non-bridge, via `require`) with SCP-ECON-12070 in message.

**VERIFIED SOUND (do not re-flag):** decimals table byte-identical ×4 (USD2/EUR2/GBP2/BTC8/SAT0/SOL9/USDC6/ETH18, range 0..=100), literal `.` locale-safe, decimals==0→whole digits, full-u64 exact no-float ×4 identical algorithm+edge cases; provenance.paymentAmount native-wide ×4 (TS bigint|null wire-string, Swift UInt64?/Kotlin ULong? UniFFI, napi emits `a.0.to_string()`); TOOL-REGISTRATION preimage hashes raw `amount.0.to_be_bytes()` NOT wire string (byte-stability test added); receipt.rs verified_amount→string; §19.8/§19.15.1 coherent; Amount serde split correct both paths.

**RESIDUAL LOW obs (non-blocking, did not gate):**
- Swift helper named `Economy.format(amount:currency:)` vs formatAmount/format_amount ×3 — per-Swift-idiom defensible.
- Error-type asymmetry for the pure display helper: TS EconomyError / Python ScpError / Swift ScpError.Validation carry structured `code` field; Kotlin IllegalArgumentException carries SCP-ECON-12070 only in message (idiomatic tradeoff — Kotlin caller can't branch on code programmatically).
- TS `ProvenanceRecord{paymentAmount: bigint}` is a documented camelCase interface with NO decoder — provenanceAttach returns raw snake_case JSON string; a JSON.parse consumer gets `payment_amount` as a JS *string* (decimal), not bigint. Pre-existing (type never wired); type↔reachable-value now string-vs-bigint. Also PyO3 provenance_attach dict OMITS payment_amount/adapter/receipt fields entirely (pre-existing; payment_amount currently always None).
