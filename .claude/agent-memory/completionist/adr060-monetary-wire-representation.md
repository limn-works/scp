---
name: adr060-monetary-wire-representation
description: ADR-060 decimal-string-JSON/native-int-MessagePack Amount+Coefficient serde + per-SDK bigint surface + format helper — INCOMPLETE(narrow); core excellent, tool-cost+provenance amounts left bare-number at FFI+SDK
metadata:
  type: project
---

# ADR-060 monetary value wire representation — review @f71b78a14

Branch fu-money (worktree .claude/worktrees/fu-money), base origin/main, 7 commits.
VERDICT: INCOMPLETE (narrow). The ADR-060 CORE + economy-budget surface is complete,
correct, and thoroughly tested; the gap is two OTHER monetary surfaces (tool-cost,
provenance-payment) left as bare-number at the FFI+SDK layers.

**Why:** ADR-060 splits Amount(u64)/Coefficient(i64) wire form by `is_human_readable()`:
canonical decimal STRING in JSON, NATIVE int in MessagePack. SDK exposes money in native
integer type (TS bigint / Py int / Swift UInt64 / Kt ULong) + a `format(currency)` display
helper. Binary path stays native so provenance-hash Vector 35 (SHA-256 rmp_serde) is
byte-identical; JCS proposal-id (human-readable, is_human_readable defaults true) legitimately
changes but no economy-bearing proposal-id KAT is pinned (Vector 23 uses a placeholder).

**How to apply / what was verified COMPLETE:**
- Core (crates/scp-protocol/src/economy/types.rs): hand-written Serialize/Deserialize with
  is_human_readable split; strict injective parsers parse_canonical_u64_str/i64_str (reject
  empty/leading-zero/+/-0/ws/sep/decimal/exp/hex/bare-number). Coefficient binary has visit_u64
  (rmp dispatches non-neg to u64 under deserialize_i64 hint). 51 economy tests pass incl >2^53
  exact, MessagePack native-not-string, JSON-string-vs-MP-int split.
- ToolCost.amount retyped u64→Amount (registry.rs:77); TOOL-REGISTRATION preimage still hashes
  amount.0.to_be_bytes() (raw u64) so KAT byte-identical — pinned by new test.
- All monetary struct fields already Amount/Coefficient (base_cost/cap/floor/per_message/per_*,
  ApproveSpend.amount, SpendingCapability, DataProvenance.payment_amount, expected/provided).
  Bare u64 in economy/ (context_message_rate, member_count, velocity_threshold, refill_per_kilosec,
  proposed_at, grace_period_secs) are metric/time/rate values, correctly NOT money.
- FFI: napi economy budget/estimate/formula/escalated → BigInt (amount_u64_from_bigint helper,
  get_u64 signed/lossless check); PyO3 int + UniFFI UInt64/ULong already exact. Bridge JSON test
  fixtures quoted (per_message:"1"/"10"/"100").
- SDKs all 4: economy budget/etc wired to bigint (TS)/native; format helper present+exported
  (Py __all__+__init__, TS index.ts formatAmount, Swift Economy.format public, Kt top-level
  formatAmount); identical KNOWN_CURRENCY_DECIMALS table (USD2 EUR2 GBP2 BTC8 SAT0 SOL9 USDC6
  ETH18) across all 4; SCP-ECON-12070 for unknown-currency in all 4. Tests: format correctness +
  >2^53 exact + unknown-currency error each SDK; real-napi >2^53 budget round-trip; PYTHON
  through-bridge test rejects bare-number policy + accepts string ("100"). receipt.rs
  verified_amount now string.
- Spec §19.1.1/§19.8/§19.15.1 reversed consistently (no leftover numeric monetary JSON in specs);
  §25 Vector 35 annotated native-MP-uint. ADR-033 not contradicted (integer arithmetic unchanged).
- validate-prd 370 / check-sdk-coverage PASS / check-error-codes 2439 PASS. 12070 in ECON
  range 12000-12999.

**THE GAP (finding):** ADR-060 SDK-surface rule = "each SDK exposes money in its natural integer
type — TypeScript bigint"; FFI rule (a) = "marshals amount-carrying napi params/returns as JS
bigint". Two monetary surfaces NOT converted, left bare-number:
1. napi ToolCostInput.amount = i64 (crates/scp-ffi/napi/src/tools.rs:98) — amount-carrying napi
   param, unconverted.
2. TS SDK ToolCost.amount: number (bindings/typescript/src/types.ts:591) + paymentAmount:
   number|null (bindings/typescript/src/provenance.ts:47) — money exposed as precision-limited
   `number` (narrows >2^53). Kotlin Types.kt:128 hand-written ToolCost.amount: Long (Long, toJson
   emits JSON number) — but that hand type is NOT the UniFFI tool-register path (uniffi.scp.
   ToolDefinition native u64 is), so likely legacy/off-path.
Justified in code comments as "string-typed FFI params are Phase 2" — an UNDOCUMENTED phase (no
such phase in ADR-060; the ADR's only "next phase" was the format-helper+SDK-wrapper slice, which
THIS change delivered). Mitigations: Swift/Kotlin(UniFFI)/Python already exact via native u64/int;
only TS `number` is precision-limited; realistic tool costs/payments < 2^53; NO runtime break
(napi provenance manually emits `.0` as json number, TS reads number — internally consistent).

LESSON: on "split wire form + per-SDK native type" changes, the blanket SDK-surface rule ("all
money → bigint in TS") reaches BEYOND the module the ADR examples (economy budget); grep every
SDK for money-typed `number`/`Long` fields (ToolCost.amount, provenance paymentAmount) — the
economy-budget ops get converted, sibling monetary surfaces get missed and rationalized as an
undocumented "Phase 2." Also: JCS (crate::jcs, is_human_readable defaults true) makes governance
proposal-ids over SetEconomicPolicy/ApproveSpend change under decimal-string serde — verify no
economy-bearing proposal-id KAT is pinned (here Vector 23 = placeholder, safe).
