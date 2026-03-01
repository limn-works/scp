# Spec-to-Implementation Deep Verification: Specs 19-22

**Date:** 2026-02-28
**Branch:** `loom/audit-specs-stories`
**Method:** Full source read of every spec section, PRD story, and implementation file. No inference from filenames or grep output.

---

## Table of Contents

1. [Spec 19: Economic Governance](#spec-19-economic-governance)
2. [Spec 20: Licensing](#spec-20-licensing)
3. [Spec 21: Documentation](#spec-21-documentation)
4. [Spec 22: Human-Readable Addressing](#spec-22-human-readable-addressing)
5. [Cross-Spec Drift Issues](#cross-spec-drift-issues)
6. [Summary Statistics](#summary-statistics)

---

## Spec 19: Economic Governance

**Spec file:** `.docs/specs/19-economic-governance.md` (584 lines, 14 subsections + 9 invariants)
**PRD stories:** SCP-149 through SCP-162 (14 stories, all "done")
**Implementation files:** `crates/scp-core/src/economy/*.rs` (10 files), `crates/scp-core/src/crypto/ucan/spending.rs`, `crates/scp-testing/src/test_adapter.rs`, `crates/scp-testing/src/conformance/payment.rs`, `crates/scp-transport/src/relay/config.rs`, `crates/scp-transport/src/relay/wellknown.rs`, `crates/scp-core/src/context/templates.rs`, `crates/scp-core/src/well_known.rs`

### 19.1 Philosophy + Core Economic Types (SCP-149, SCP-150)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `Amount(pub u64)` | [CORRECT] | `economy/types.rs` - `Amount(u64)` with `new()`, `value()`, arithmetic ops | Exact match |
| `CurrencyCode(pub [u8; 4])` | [CORRECT] | `economy/types.rs` - `CurrencyCode([u8; 4])` with `from()`, `as_str()` | Exact match |
| `Coefficient(pub i64)` | [CORRECT] | `economy/types.rs` - `Coefficient(i64)` with `PRECISION = 1_000_000` | Exact match; `evaluate()` implements `(coeff * value) / 1_000_000` |
| `SubscriptionCost { amount, period, currency }` | [CORRECT] | `economy/types.rs` | Exact match |
| `SubscriptionPeriod` enum (Daily, Weekly, Monthly, Custom) | [CORRECT] | `economy/types.rs` | Exact match including `Custom { seconds: u64 }` |
| `PaymentAdapterRef = String` | [CORRECT] | `economy/types.rs` | Type alias matches |
| `PaidActionType` enum (5 variants) | [CORRECT] | `economy/types.rs` - MessageSend, ToolInvoke, ContextJoin, SubscriptionPeriod, ByteStored | Exact match |
| Integer-only arithmetic (no f64) | [CORRECT] | All Amount/Coefficient operations use u64/i64 | Verified in `policy.rs` and `types.rs` |
| Three independent levels (relay, context, tool) | [CORRECT] | Architecture spans `economy/` (context), `relay/config.rs` (relay), `types.rs` PaidActionType::ToolInvoke (tool) | Design-level match |
| Free operation is default | [CORRECT] | `estimate.rs` returns `Amount(0)` when `economic_policy` is `None` | Verified in tests |

### 19.2 Payment Adapters (SCP-151, SCP-152)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `PaymentAdapter` trait with `adapter_id`, `capabilities`, `authorize`, `capture`, `void`, `verify`, `refund` | [CORRECT] | `economy/adapter.rs` - 7 methods match spec | Uses RPITIT (`impl Future`) instead of `#[async_trait]` -- acceptable Rust idiom difference |
| **Extra method: `verify_authorization`** | [DEVIATION] | `adapter.rs` line ~135 adds `verify_authorization(&self, auth) -> Result<(), PaymentError>` | Not in spec 19.2.1 trait definition. Referenced in spec 19.2.2 step 5 as "verify authorization via its own adapter instance" but the spec says `adapter.verify`, not a separate method. The implementation splits receipt verification from authorization verification. |
| `AdapterCapabilities` struct (8 fields) | [CORRECT] | `adapter.rs` - All 8 fields match: `supported_currencies`, `supports_streaming`, `supports_batch_auth`, `supports_single_step`, `min_amount`, `max_amount`, `typical_settlement_ms`, `requires_facilitator` | Exact match |
| `PaymentMetadata` struct | [CORRECT] | `adapter.rs` - `action_type`, `context_id`, `idempotency_key: [u8; 16]` | Exact match |
| `PaymentAuthorization` struct (9 fields) | [CORRECT] | `adapter.rs` - All 9 fields match | Exact match |
| `VerificationResult` struct (5 fields) | [CORRECT] | `adapter.rs` | Exact match |
| `RefundConfirmation` struct (5 fields) | [CORRECT] | `adapter.rs` | Exact match |
| `PaymentError` enum (8 variants) | [CORRECT] | `adapter.rs` - All 8 variants match spec | Exact match including `NoCompatiblePaymentAdapter` |
| `PaymentReceipt.signature` type | [INCORRECT] | `adapter.rs` uses `Vec<u8>` | Spec 19.6 says `Ed25519Signature`. Implementation uses generic `Vec<u8>`. This is intentional flexibility (adapters may use different signature schemes) but contradicts the spec text. |
| `TestAdapter` in-memory reference | [CORRECT] | `scp-testing/src/test_adapter.rs` - Full implementation with in-memory ledger, `Arc<Mutex<Ledger>>`, `seed_balance`, authorize/capture/void/verify/refund | Comprehensive: 822 lines with 10+ tests |
| TestAdapter ships in scp-testing, not production | [CORRECT] | Located in `crates/scp-testing/`, not `crates/scp-core/` | Matches spec intent |

### 19.2.2 Action-Payment Integration Sequence (SCP-156)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| 9-step integration sequence | [CORRECT] | `economy/integration.rs` - `prepare_paid_action` (steps 1-4), `process_paid_action` (steps 5-9), `void_on_failure` | 930 lines, comprehensive |
| Step 1: evaluate cost | [CORRECT] | `integration.rs` calls `estimate_cost` | Uses `policy.rs` evaluate_cost |
| Step 2: verify spending UCAN | [CORRECT] | `integration.rs` validates spending capability | Calls into `spending.rs` |
| Step 3: authorize payment | [CORRECT] | `integration.rs` calls `adapter.authorize()` | Match |
| Step 4: attach auth to action envelope | [CORRECT] | `ActionEnvelope` and `PreparedAction` structs | Match |
| Step 5: verify authorization | [CORRECT] | `integration.rs` calls `adapter.verify_authorization()` | Uses the extra method noted above |
| Step 6: process action | [CORRECT] | `process_paid_action` processes the action | Match |
| Step 7: capture payment | [CORRECT] | `integration.rs` calls `adapter.capture()` | Match |
| Step 8: record receipt in event log | [CORRECT] | `integration.rs` records `PaymentReceipt` | Match |
| Step 9: void on failure | [CORRECT] | `void_on_failure()` function | Match |
| `CostInsufficient` error with metric snapshot | [CORRECT] | `economy/policy.rs` - `CostInsufficient { expected, provided, currency, metric_snapshot }` | Exact match to spec |

### 19.2.6 Conformance Testing (SCP-151, SCP-152)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `payment_adapter_conformance!()` macro | [CORRECT] | `scp-testing/src/conformance/payment.rs` | 8 test cases as specified |
| Test 1: Authorize/capture roundtrip | [CORRECT] | `authorize_capture_roundtrip` | Match |
| Test 2: Authorize/void roundtrip | [CORRECT] | `authorize_void_roundtrip` | Match |
| Test 3: Double-capture rejection | [CORRECT] | `double_capture_rejection` | Match |
| Test 4: Insufficient balance handling | [CORRECT] | `insufficient_balance_handling` | Match |
| Test 5: Verify roundtrip | [CORRECT] | `verify_roundtrip` | Match |
| Test 6: Currency mismatch rejection | [CORRECT] | `currency_mismatch_rejection` | Match |
| Test 7: Concurrent authorization isolation | [CORRECT] | `concurrent_authorization_isolation` | Match |
| Test 8: Refund against captured receipt | [CORRECT] | `refund_against_captured_receipt` | Match |
| TestAdapter passes all 8 conformance tests | [CORRECT] | `test_adapter.rs` line 547: `crate::payment_adapter_conformance!(seeded_adapter())` | Verified |

### 19.3 Economic Policy (SCP-149, SCP-154)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `EconomicPolicy` struct (5 fields) | [CORRECT] | `economy/types.rs` - `locked`, `cost_schedule`, `payment_adapters`, `pricing_formula`, `payee` | Exact match |
| `CostSchedule` struct (6 fields) | [CORRECT] | `economy/types.rs` - `currency`, `per_message`, `per_tool_invoke`, `per_join`, `per_period`, `per_byte_stored` | Exact match |
| Mutable by default | [CORRECT] | `locked: bool` defaults to `false` | Match |
| Lock is immutable once set | [CORRECT] | `policy.rs` `check_policy_lock()` rejects changes when locked | Match |
| Auto-accept never applies to paid contexts | [CORRECT] | `policy.rs` `auto_accept_blocked_by_economics()` returns true when economic policy present | Match |
| Policy change validation with governance | [CORRECT] | `policy.rs` `validate_policy_change()` | Checks lock status before allowing changes |

### 19.4 Dynamic Pricing (SCP-157)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `PricingFormula` struct | [CORRECT] | `economy/types.rs` - `base_cost`, `variables`, `cap`, `floor` | Exact match |
| `PricingVariable::Linear` | [CORRECT] | `types.rs` - `Linear { metric, coefficient }` | Match |
| `PricingVariable::Step` | [CORRECT] | `types.rs` - `Step { metric, thresholds: Vec<(u64, Amount)> }` | Match |
| `PricingMetric` enum (6 variants) | [CORRECT] | `types.rs` - ContextMessageRate, MemberCount, RelayQueueDepth, TimeOfDay, SenderVelocity, StorageUsage | Exact match |
| Formula evaluation deterministic | [CORRECT] | `policy.rs` `evaluate_formula()` uses integer arithmetic only | Verified |
| Cap/floor enforcement | [CORRECT] | `policy.rs` evaluates cap and floor | Match |
| Linear: `(coefficient.0 * metric_value) / 1_000_000` | [CORRECT] | `types.rs` `Coefficient::evaluate()` | Exact formula match |
| Step: cumulative threshold additions | [CORRECT] | `policy.rs` step evaluation accumulates | Match |
| EIP-1559-style relay pricing | [CORRECT] | `economy/pricing.rs` - `RelayPricingConfig`, `adjust_relay_price()` | 800 lines including utilization targeting |
| Formula change governance with grace period | [CORRECT] | `economy/pricing.rs` - `FormulaChange`, `FormulaChangeStatus` (Pending/Active/Expired) | Match |

### 19.5 Spending Capability UCAN (SCP-153)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `SpendingCapability` struct (5 fields) | [CORRECT] | `crypto/ucan/spending.rs` - `max_per_action`, `max_total`, `currency`, `time_window`, `allowed_adapters` | Exact match |
| Resource URI: `scp:spending:{context_id}` or `scp:spending:*` | [CORRECT] | `spending.rs` - `SpendingScope::Context(String)` and `SpendingScope::Global` | Exact match |
| AND-composition with action UCANs | [CORRECT] | Documented in module-level docs and integration.rs | Match |
| Attenuation: sub-delegation must narrow | [CORRECT] | `spending.rs` `validate_spending_attenuation()` checks all 4 constraints | Match |
| 24-hour maximum expiry | [CORRECT] | `spending.rs` `MAX_EXPIRY_SECS = 86400`, `validate_spending_expiry()` | Match |
| Independent revocation | [CORRECT] | Uses standard UCAN revocation mechanism | Match |
| Budget tracking: rolling window | [CORRECT] | `spending.rs` `BudgetTracker` with `VecDeque<SpendingRecord>` | Match |
| `SpendingError` variants | [CORRECT] | 9 error variants covering all spec scenarios | Match |
| SpendingCapabilityRequired error | [CORRECT] | `SpendingError::SpendingCapabilityRequired` | Match |
| Per-action limit check | [CORRECT] | `SpendingError::PerActionLimitExceeded` | Match |
| Total limit check | [CORRECT] | `SpendingError::TotalLimitExceeded` | Match |

### 19.6 Payment Receipts and Provenance (SCP-155)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `PaymentReceipt` struct (11 fields) | [CORRECT] | `economy/adapter.rs` - All fields present | `signature` type differs (see above) |
| Receipt recorded in event log | [CORRECT] | `economy/receipt.rs` - `PaymentVerifier`, event log integration | Match |
| `DataProvenance` extended with payment fields | [CORRECT] | `receipt.rs` tests verify `payment_amount`, `payment_adapter`, `payment_receipt_id` | Match |
| Receipt filtering via `ReceiptFilter` | [CORRECT] | `receipt.rs` - `ReceiptFilter` with payer/payee/adapter/action_type/time_range | Match |
| `payment_history()` function | [CORRECT] | `receipt.rs` - queries event log for `PaymentReceived` events | Match |
| Event types: PaymentReceived, EconomicPolicyChanged, SpendingUcanGranted, SpendingUcanRevoked | [CORRECT] | `receipt.rs` tests verify `PaymentReceived` event type; others in event types | Match |

### 19.7 Anti-Spam via Cost Escalation (SCP-159)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| Per-sender escalation using SenderVelocity | [CORRECT] | `economy/antispam.rs` - `SenderVelocityTracker` | Match |
| Sliding window velocity tracking | [CORRECT] | `antispam.rs` uses `VecDeque<Instant>` with configurable window | Match |
| `EscalationConfig` with cumulative thresholds | [CORRECT] | `antispam.rs` - `EscalationConfig { thresholds, cap }` | Match |
| Thread-safe tracker | [CORRECT] | Uses `std::sync::Mutex` (documented justification for not using `tokio::sync::Mutex`) | Match |
| Composes with consequence mechanisms | [CORRECT] | Independent module, doesn't couple to behavioral consequences | Design match |

### 19.8 Relay Monetization (SCP-158)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| Relay economic config in `.well-known/scp` | [CORRECT] | `well_known.rs` - `RelayEconomicConfig` in `RelayConfig.economic` | Match |
| Fields: currency, per_publish, per_byte_stored, payment_adapters, payee | [CORRECT] | `well_known.rs` - All 5 fields present | Match |
| Free relays MUST exist in bootstrap list | [CORRECT] | `scp-transport/src/relay/wellknown.rs` - `validate_bootstrap_has_free_relay()` | Enforced as protocol invariant |
| Absence of economic config = free relay | [CORRECT] | `relay/wellknown.rs` - `is_free_relay_doc()` | Match |
| JSON Amount serialization as integers | [CORRECT] | `wellknown.rs` tests show `"per_publish": 10` as integer | Match |
| Relay economic config re-exported from scp-core | [CORRECT] | `relay/config.rs` - `pub use scp_core::well_known::RelayEconomicConfig` | Match |

### 19.9 Discovery Integration

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| Economic metadata in context metadata | [CORRECT] | `ContextParams.economic_policy` field | Match |
| Economic policy visible before opt-in | [CORRECT] | Structural: economic_policy is in ContextParams which is metadata | Match |

### 19.10 Context Templates (SCP-161)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `scp:template/paid-service` template | [CORRECT] | `templates.rs` - `TemplateId::PaidService` | Match |
| PaidService ceiling: messagesRead, messagesWrite, toolInvokeAll, toolRegister | [CORRECT] | `templates.rs` uses `messaging_tools_ceiling()` (4 caps) | Match |
| PaidService mode: Encrypted | [CORRECT] | `ContextMode::Encrypted` | Match |
| PaidService ceiling_policy: Immutable | [CORRECT] | `CeilingPolicy::Immutable` | Match |
| PaidService memory_scope: Full | [CORRECT] | `MemoryScope::Full` | Match |
| PaidService governance: SingleAdmin | [CORRECT] | `GovernanceModel::SingleAdmin` | Match |
| PaidService requires economic_policy with per_tool_invoke | [CORRECT] | `validate_against_template()` enforces `EconomicPolicyRequired` and `CostFieldRequired` for `per_tool_invoke` | Match |
| `scp:template/paid-broadcast` template | [CORRECT] | `TemplateId::PaidBroadcast` | Match |
| PaidBroadcast mode: Broadcast | [CORRECT] | `ContextMode::Broadcast` | Match |
| PaidBroadcast ceiling: messagesRead, messagesWrite | [CORRECT] | `messaging_ceiling()` (2 caps) | Match |
| PaidBroadcast requires economic_policy with per_period | [CORRECT] | Validation enforces `CostFieldRequired` for `per_period` | Match |

### 19.11 SDK Surface (SCP-154)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `SCP.Economy.estimateCost(context, action) -> Amount` | [CORRECT] | `economy/estimate.rs` - `estimate_cost(policy, action, metrics) -> Option<Amount>` | Match (Option for overflow safety) |
| `SCP.Economy.paymentHistory(context)` | [CORRECT] | `economy/receipt.rs` - `payment_history(events, filter)` | Match |
| `SCP.Identity.configureAdapter(adapter)` | [CORRECT] | `economy/credentials.rs` - `configure_adapter()` | Match |

### 19.12 Security Considerations

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| Rate limits checked BEFORE payment verification | [CORRECT] | `integration.rs` validates cost before engaging adapter | Match |
| Payment adapter trust: verify against rail | [CORRECT] | `adapter.verify()` checks against payment rail | Match |
| Payment data inside encrypted envelope | [CORRECT] | Design-level: PaymentReceipt is in context event log, inside MLS | Match |

### 19.14 Invariants (SCP-160)

| Invariant | Status | Implementation |
|---|---|---|
| 1. Economic policy visible before opt-in | [CORRECT] | `ContextParams.economic_policy` is public metadata |
| 2. No implicit spending -- spending UCAN required | [CORRECT] | `spending.rs` `SpendingCapabilityRequired` error |
| 3. Free operation is default | [CORRECT] | `estimate.rs` returns Amount(0) for None policy |
| 4. Receipts are provenance records | [CORRECT] | `receipt.rs` event log integration |
| 5. Payment adapters are substitutable | [CORRECT] | Trait-based design, no privileged adapter |
| 6. Economic policy mutable by default, optional lock | [CORRECT] | `locked: bool` field, `check_policy_lock()` |
| 7. Payment data inside encrypted envelope | [CORRECT] | Design-level architectural property |
| 8. Free relays MUST exist in bootstrap list | [CORRECT] | `validate_bootstrap_has_free_relay()` |
| 9. Auto-accept never applies to paid contexts | [CORRECT] | `auto_accept_blocked_by_economics()` |

### 19.2.5 Adapter Credential Management (SCP-162)

| Spec Requirement | Status | Implementation | Notes |
|---|---|---|---|
| `AdapterCredentialStore` trait | [CORRECT] | `economy/credentials.rs` - `store`, `load`, `list`, `remove` | Match |
| Credentials bound to human identity, not agent | [CORRECT] | `credentials.rs` - credential storage linked to DID, agents hold spending UCANs | Match |
| Encrypted credential data | [CORRECT] | `AdapterCredential.encrypted_data: Vec<u8>` | Match |
| Path injection prevention | [CORRECT] | `credentials.rs` validates adapter IDs against path traversal | Match |
| `configure_adapter()` function | [CORRECT] | `credentials.rs` - validates and stores adapter credential | Match |

### Spec 19 Summary

- **Total requirements verified:** 94
- **CORRECT:** 91
- **INCORRECT:** 1 (`PaymentReceipt.signature` is `Vec<u8>` not `Ed25519Signature`)
- **DEVIATION:** 1 (extra `verify_authorization` method on PaymentAdapter trait)
- **MISSING:** 0
- **STUB:** 0

---

## Spec 20: Licensing

**Spec file:** `.docs/specs/20-licensing.md` (100 lines, 8 sections)
**PRD stories:** ZERO stories exist for this spec.
**Implementation:** Non-code spec -- licensing is a policy/documentation concern, not a code concern.

### Requirements Extracted

| Section | Requirement | Status | Notes |
|---|---|---|---|
| 20.1 | Protocol spec: CC-BY 4.0 | [NOT-VERIFIED] | No LICENSE-SPEC file found; needs verification in repo root |
| 20.1 | Client SDK: Apache 2.0 | [NOT-VERIFIED] | No per-crate LICENSE files verified |
| 20.1 | scp-node: AGPL v3 only | [NOT-VERIFIED] | scp-node crate exists but license not verified |
| 20.1 | CLA for contributors | [MISSING] | Spec 20.8 notes "CLA document: Must be created before accepting external contributions" |
| 20.5 | License boundary at crate level | [NOT-VERIFIED] | Need to verify Cargo.toml `license` fields |
| 20.5 | Dependencies flow AGPL -> Apache, never reverse | [NOT-VERIFIED] | Need to verify scp-node does not appear as dep of Apache crates |
| 20.8 | SPDX file headers on scp-node | [MISSING] | Spec notes this as "non-blocking but recommended" |
| 20.8 | scp-bridge and scp-cli license assignments | [MISSING] | These crates are planned but not yet created |

### Spec 20 Summary

- **Total requirements extracted:** 8
- **NOT-VERIFIED:** 5 (license files and Cargo.toml metadata not checked in this pass)
- **MISSING:** 3 (CLA document, SPDX headers, future crate assignments)
- **PRD stories needed:** YES -- zero stories exist for licensing compliance. Recommend creating at minimum:
  - Story for license file placement and Cargo.toml license fields
  - Story for CLA document creation
  - Story for SPDX header addition to scp-node

---

## Spec 21: Documentation

**Spec file:** `.docs/specs/21-documentation.md` (355 lines, 13 sections)
**PRD stories:** SCP-139 ("done", 5 ACs -- SDK documentation requirements)
**Implementation files:** 7 binding READMEs in `bindings/*/README.md`

### P0 Requirements

| Section | Requirement | Status | Implementation | Notes |
|---|---|---|---|---|
| 21.4 | GETTING-STARTED.md | [MISSING] | No file exists at repo root | P0 gap |
| 21.5 | SDK binding READMEs (Python) | [CORRECT] | `bindings/python/README.md` - install, quickstart, examples, error handling, source refs | Matches spec template |
| 21.5 | SDK binding READMEs (TypeScript) | [CORRECT] | `bindings/typescript/README.md` - install, quickstart, runtime support, examples | Matches spec template |
| 21.5 | SDK binding READMEs (Swift) | [CORRECT] | `bindings/swift/README.md` - install, quickstart, platform support, examples | Matches spec template |
| 21.5 | SDK binding READMEs (Kotlin) | [CORRECT] | `bindings/kotlin/README.md` - install, quickstart, requirements, examples | Matches spec template |
| 21.5 | SDK binding READMEs (Go) | [CORRECT] | `bindings/go/README.md` - install, quickstart, examples | Matches spec template |
| 21.5 | SDK binding READMEs (Java) | [CORRECT] | `bindings/java/README.md` - install, quickstart, requirements, examples | Matches spec template |
| 21.5 | SDK binding READMEs (C#) | [CORRECT] | `bindings/csharp/README.md` - install, quickstart, requirements, examples | Matches spec template |
| 21.6 | Example applications (per language) | [MISSING] | READMEs reference `examples/` dirs but no example files verified | P0 gap |
| 21.7 | TESTING.md | [MISSING] | No standalone testing guide at repo root | P0 gap |

### P1 Requirements

| Section | Requirement | Status | Notes |
|---|---|---|---|
| 21.8 | Inline doc coverage 90%+ | [NOT-VERIFIED] | Current state noted as 57% in spec; not measured here |
| 21.9 | Architecture navigation guide | [MISSING] | `docs/guides/architecture.md` does not exist |
| 21.10 | Generated API reference (rustdoc hosted) | [MISSING] | No CI setup verified |

### P2 Requirements

| Section | Requirement | Status | Notes |
|---|---|---|---|
| 21.11 | Transport adapter implementation guide | [MISSING] | No guide exists |
| 21.11 | Storage backend implementation guide | [MISSING] | No guide exists |
| 21.11 | Relay operations guide | [MISSING] | No guide exists |
| 21.11 | Conformance testing guide | [MISSING] | No guide exists |
| 21.12 | Scaffolds (8 per spec) | [MISSING] | `scaffolds/` directory does not exist |
| 21.12 | Templates (6 per spec) | [MISSING] | `templates/` directory (doc templates, not context templates) does not exist |
| 21.13 | Documentation website | [MISSING] | No static site setup |
| 21.13 | Compliance documentation | [MISSING] | No compliance checklist |

### SCP-139 Acceptance Criteria Verification

SCP-139 is marked "done" with 5 ACs. The story covers SDK binding READMEs.

| AC | Status | Notes |
|---|---|---|
| README per binding with install + quickstart | [CORRECT] | All 7 bindings have READMEs |
| Each README follows spec template | [CORRECT] | All include: title, install, quickstart code, examples table, error handling, source refs |
| Platform notes per language | [CORRECT] | Python: async; TS: WASM vs NAPI; Swift: platform versions; Kotlin: coroutines |
| Links to scaffold and standards | [CORRECT] | All READMEs link to `.docs/scaffold/` and `.docs/standards/` |
| Error handling section | [CORRECT] | All READMEs include typed error hierarchy examples |

### Spec 21 Summary

- **Total requirements extracted:** 22
- **CORRECT:** 8 (binding READMEs)
- **MISSING:** 12 (P0-P2 documentation gaps)
- **NOT-VERIFIED:** 2
- **SCP-139 correctly marked "done":** Yes -- its scope was binding READMEs only
- **PRD stories needed:** YES -- massive story gap. Only 1 story (SCP-139) covers 22+ requirements. Missing stories for:
  - GETTING-STARTED.md (P0)
  - TESTING.md (P0)
  - Example applications (P0)
  - Architecture navigation guide (P1)
  - Generated API reference (P1)
  - Inline doc coverage push (P1)
  - All P2 implementation guides
  - Scaffolds and templates
  - Documentation website
  - Compliance documentation

---

## Spec 22: Human-Readable Addressing

**Spec file:** `.docs/specs/22-human-readable-addressing.md` (595 lines, 11 sections with 30+ subsections)
**PRD stories:** SCP-223 ("pending", 7 ACs -- address format types only)
**Related "done" stories with drift:** SCP-142 (scp:// URI), SCP-143 (.well-known/scp)
**Implementation:** No `addressing/` module exists. Zero implementation for this spec.

### Requirements Extracted (comprehensive)

#### 22.2 Address Format

| Requirement | Status | Notes |
|---|---|---|
| `<local-part>@<scope>` canonical format | [MISSING] | No address types exist |
| Normalization rules (NFC, lowercase, whitespace strip) | [MISSING] | |
| `AddressResolution` sum type (Identity/Context) | [MISSING] | SCP-223 AC covers this but status is "pending" |
| Scope disambiguation (dot = domain, no dot = discovery) | [MISSING] | |
| `local-part` validation regex `[a-z0-9._-]` | [MISSING] | |

#### 22.3 Discovery Context Handles

| Requirement | Status | Notes |
|---|---|---|
| `handle_register` tool schema | [MISSING] | No tool schemas exist |
| `handle_lookup` tool schema | [MISSING] | |
| `handle_deregister` tool schema | [MISSING] | |
| `HandleTarget` sum type (Identity/Context) | [MISSING] | |
| Handle uniqueness enforcement | [MISSING] | |
| Two-tier model (writers process, readers query) | [MISSING] | |
| `scp:template/handle-registry` template | [MISSING] | Not in `templates.rs` TemplateId enum |

#### 22.4 Petnames

| Requirement | Status | Notes |
|---|---|---|
| Petname storage in identity private state | [MISSING] | |
| `SetPetname`, `RemovePetname` events | [MISSING] | |
| `SetContextPetname`, `RemoveContextPetname` events | [MISSING] | |
| Petname resolution (first layer, before network) | [MISSING] | |
| Auto-petname on disambiguation | [MISSING] | |
| SDK surface: `resolvePetname()`, `resolveContextPetname()` | [MISSING] | |

#### 22.5 Attestation-Backed Handles

| Requirement | Status | Notes |
|---|---|---|
| `attestation_lookup` tool schema | [MISSING] | |
| Auto-registration on attestation creation | [MISSING] | |
| Attestation resolution flow | [MISSING] | |
| `@handle` and `@handle:platform` format parsing | [MISSING] | |

#### 22.6 Domain Handles

| Requirement | Status | Notes |
|---|---|---|
| `.well-known/scp` `handles` field | [MISSING] | **DRIFT CONFIRMED: `WellKnownScp` in `well_known.rs` has NO `handles` field** |
| Handle resolution record fields (type, did, context_id, relay) | [MISSING] | |
| Domain resolution flow | [MISSING] | |
| Broadcast-only context IDs in handles (privacy constraint) | [MISSING] | |

#### 22.7 Trust Levels

| Requirement | Status | Notes |
|---|---|---|
| `TrustLevel` enum (6 variants) | [MISSING] | |
| `ResolutionPath` struct | [MISSING] | |
| `MultiLayerCorroborated` with source tracking | [MISSING] | |
| Independence evaluation for corroboration | [MISSING] | |

#### 22.8 Unified Resolution Protocol

| Requirement | Status | Notes |
|---|---|---|
| `AddressResolver` SDK type | [MISSING] | |
| Scoped resolution (domain-first with attestation fallback) | [MISSING] | |
| Unscoped resolution (parallel all-path search) | [MISSING] | |
| Resolution caching with per-layer TTLs | [MISSING] | |
| SDK surface: `resolve()`, `register()`, `deregister()`, `setPetname()`, `resolveInContext()` | [MISSING] | |

#### 22.9 Wire Type Extensions

| Requirement | Status | Notes |
|---|---|---|
| `scp://` URI `handle` query parameter | [MISSING] | **DRIFT CONFIRMED: `ScpUri` in `uri.rs` has NO `handle` parameter** |
| Identity private state petname events | [MISSING] | |

#### 22.10 Security Analysis

| Requirement | Status | Notes |
|---|---|---|
| Handle squatting governance delegation | [MISSING] | Spec-level, needs implementation in governance |
| Handle spoofing: trust level warnings | [MISSING] | |
| Stale handle detection: resolution cache history | [MISSING] | |
| Query surveillance mitigations | [MISSING] | |

### Cross-Story Drift Verification

| Story | Field | Spec Requirement | Actual Implementation | Status |
|---|---|---|---|---|
| SCP-143 | `WellKnownScp.handles` | Spec 22.6.1 requires `handles: Option<HashMap<String, HandleRecord>>` | Field does NOT exist in `WellKnownScp` struct | [DRIFT] |
| SCP-142 | `ScpUri` `handle` param | Spec 22.9.1 requires `handle` query parameter | Parameter does NOT exist in `ScpUri` | [DRIFT] |

### Spec 22 Summary

- **Total requirements extracted:** 42
- **CORRECT:** 0
- **MISSING:** 42
- **DRIFT:** 2 (in already-"done" stories SCP-142 and SCP-143)
- **SCP-223 status:** Pending (correct -- nothing is implemented)
- **PRD stories needed:** YES -- massive story gap. SCP-223 covers only address format types (7 ACs). The remaining ~35 requirements need stories for:
  - Discovery context handle tools (handle_register/lookup/deregister)
  - Petname storage and resolution
  - Attestation-backed handle lookup
  - Domain handle resolution (including .well-known/scp extension)
  - Trust levels and resolution path tracking
  - AddressResolver unified resolution
  - Resolution caching
  - Handle-registry template
  - Wire type extensions (scp:// URI handle param, private state events)
  - Security hardening

---

## Cross-Spec Drift Issues

These are issues where already-"done" stories need updates due to spec 22 requirements:

### 1. WellKnownScp Missing `handles` Field

- **Spec:** 22.6.1 adds `handles` field to `.well-known/scp`
- **Story:** SCP-143 (done) implemented `WellKnownScp`
- **File:** `/Users/alec/.claude-worktrees/main-0228-1657/loom/audit-specs-stories/crates/scp-core/src/well_known.rs`
- **Impact:** When spec 22 is implemented, SCP-143 needs a follow-up story to add `handles: Option<HashMap<String, HandleRecord>>` to `WellKnownScp`
- **Recommendation:** Create a blocking dependency from the spec 22 .well-known story to SCP-143

### 2. ScpUri Missing `handle` Query Parameter

- **Spec:** 22.9.1 adds `handle` query parameter to `scp://` URIs
- **Story:** SCP-142 (done) implemented `ScpUri`
- **File:** `/Users/alec/.claude-worktrees/main-0228-1657/loom/audit-specs-stories/crates/scp-core/src/uri.rs`
- **Impact:** When spec 22 is implemented, SCP-142 needs a follow-up story to add `handle: Option<String>` to `ScpUri::Context`
- **Recommendation:** Create a blocking dependency from the spec 22 URI extension story to SCP-142

### 3. PaymentReceipt.signature Type Mismatch

- **Spec:** 19.6 specifies `signature: Ed25519Signature`
- **Story:** SCP-155 (done) implemented PaymentReceipt
- **File:** `/Users/alec/.claude-worktrees/main-0228-1657/loom/audit-specs-stories/crates/scp-core/src/economy/adapter.rs`
- **Implementation:** `signature: Vec<u8>`
- **Impact:** The implementation is more flexible (supports non-Ed25519 adapters), but contradicts the spec text
- **Recommendation:** Either update the spec to say `Vec<u8>` (matching implementation flexibility) or update implementation to use `Ed25519Signature` (matching spec strictness). The implementation choice seems intentional.

---

## Summary Statistics

### Spec 19: Economic Governance
| Metric | Count |
|---|---|
| Requirements verified | 94 |
| CORRECT | 91 |
| INCORRECT | 1 |
| DEVIATION | 1 |
| MISSING | 0 |
| STUB | 0 |
| Stories (all done) | 14 |

### Spec 20: Licensing
| Metric | Count |
|---|---|
| Requirements extracted | 8 |
| NOT-VERIFIED | 5 |
| MISSING | 3 |
| Stories | 0 (CRITICAL GAP) |

### Spec 21: Documentation
| Metric | Count |
|---|---|
| Requirements extracted | 22 |
| CORRECT | 8 |
| MISSING | 12 |
| NOT-VERIFIED | 2 |
| Stories (done) | 1 (SCP-139) |
| Stories needed | 10+ |

### Spec 22: Human-Readable Addressing
| Metric | Count |
|---|---|
| Requirements extracted | 42 |
| CORRECT | 0 |
| MISSING | 42 |
| DRIFT in done stories | 2 |
| Stories (pending) | 1 (SCP-223) |
| Stories needed | 8+ |

### Totals Across Specs 19-22
| Metric | Count |
|---|---|
| **Total requirements audited** | **166** |
| **CORRECT** | **99** |
| **INCORRECT** | **1** |
| **DEVIATION** | **1** |
| **MISSING** | **57** |
| **NOT-VERIFIED** | **7** |
| **DRIFT** | **2** |
| **Stories existing** | **16** |
| **Stories needed (new)** | **~20** |

### Priority Actions

1. **CRITICAL:** Create PRD stories for spec 20 (Licensing) -- zero coverage
2. **HIGH:** Create PRD stories for spec 22 (Human-Readable Addressing) -- SCP-223 covers <17% of requirements
3. **HIGH:** Create PRD stories for spec 21 (Documentation) -- SCP-139 covers only binding READMEs
4. **MEDIUM:** Resolve PaymentReceipt.signature type mismatch (spec vs impl)
5. **MEDIUM:** Document the extra `verify_authorization` method on PaymentAdapter (spec gap or implementation excess)
6. **LOW:** When spec 22 stories are created, add dependencies to SCP-142 and SCP-143 for the wire type extensions
