# 19. Economic Governance

## 19.1 Philosophy

Machine payments are a rate limit that generates money. This is the modern realization of Dwork & Naor (1992) — real money instead of proof-of-work, which fixes Hashcash's botnet asymmetry problem ($0.001 costs $0.001 regardless of who pays).

**Prior art context:**
- **Dwork & Naor (1992):** Computational cost as spam prevention — the original insight that making actions non-free deters abuse.
- **Hashcash (1997):** Proof-of-work for email. Failed because botnet asymmetry: an attacker with 10,000 machines pays 1/10,000th the cost per message. The cost function is unfair.
- **Micropayments fix this:** $0.001 costs $0.001 regardless of attacker resources. No computational shortcut. No economy of scale for abuse.
- **x402, L402, Stripe machine payments (2025):** Production implementations of this principle — machine-to-machine payment at API call granularity.

SCP's existing primitives (DIDs, UCANs, contexts, governance, transport adapters) compose into an economic layer. The protocol defines the trait, structures, and integration points; implementations connect to real payment rails (x402, Lightning, Stripe, SPL tokens).

**Three independent levels of economic policy:**

1. **Relay-level:** Relay operators charge for transport (bandwidth, storage, routing). Separate trust model — relays are dumb pipes (§9.9).
2. **Context-level:** Context creators charge for participation (messages, tools, membership). Inside the encrypted envelope, invisible to relays.
3. **Tool-level:** Individual tools declare per-invocation costs. Additive with context costs.

**Free operation is the default.** No economic policy = free. The protocol never charges without explicit opt-in from both sides. Economic governance is entirely optional infrastructure for contexts and relays that choose to use it.

**What the protocol specifies vs. what implementations provide:**

| Protocol specifies | Implementations provide |
|---|---|
| `PaymentAdapter` trait | Specific payment rails (x402, Lightning, Stripe, SPL) |
| `EconomicPolicy` structure | Currencies, exchange rates, settlement timing |
| `SpendingCapability` UCAN type | Tax/compliance, payment UI |
| `PaymentReceipt` provenance record | Adapter credentials, wallet integration |
| `PricingFormula` model | Production adapter implementations |
| Integration points with contexts/relays/tools | Adapter-specific licensing/compliance |
| Conformance tests | — |

**Novel contribution:** No existing standard combines UCAN delegation chains with payment semantics. L402/Macaroons have spending caveats but not DID-based delegation. ILP/GNAP has payment authorization but not capability-chain attenuation. SCP bridges both — spending-scoped UCAN capabilities at the intersection of UCAN delegation chains, L402/Macaroon spending caveats, and ILP streaming models.

### 19.1.1 Core Economic Types

```rust
/// Amount in smallest currency unit. USD: cents (1 USD = 100). BTC: satoshis (1 BTC = 100_000_000).
/// Always integer — no floating-point in economic calculations. Cross-party determinism guaranteed.
/// Both payer and receiver evaluate the same Amount from the same inputs with identical results.
pub struct Amount(pub u64);

/// ISO 4217 currency code (USD, EUR) or protocol-defined code (BTC, SAT, SOL, USDC).
pub struct CurrencyCode(pub [u8; 4]); // 3-4 character code, null-padded

/// Fixed-point coefficient with 6 decimal places of precision.
/// Value = raw / 1_000_000. Example: 1_500_000 = 1.5, 100 = 0.0001.
/// Used in pricing formulas where fractional multipliers are needed.
/// Both sides evaluate identically — no IEEE 754 variance.
pub struct Coefficient(pub i64);

/// Subscription cost for recurring payments.
pub struct SubscriptionCost {
    pub amount: Amount,
    pub period: SubscriptionPeriod,
    pub currency: CurrencyCode,
}

pub enum SubscriptionPeriod {
    Daily,
    Weekly,
    Monthly,
    Custom { seconds: u64 },
}

/// String identifier for a payment adapter accepted by a context or relay.
/// Matches `PaymentAdapter::adapter_id()`. Example values: "x402", "lightning", "spl", "stripe".
pub type PaymentAdapterRef = String;

/// Action type for which a payment is made. Used in PaymentReceipt and cost estimation.
pub enum PaidActionType {
    MessageSend,
    ToolInvoke,
    ContextJoin,
    SubscriptionPeriod,
    ByteStored,
}
```

**Why integer amounts:** IEEE 754 floating-point arithmetic is non-associative — `(a + b) + c != a + (b + c)` in general. When payer and receiver independently evaluate a pricing formula, f64 coefficients can produce different results depending on evaluation order, platform, or compiler optimizations. Integer arithmetic is deterministic across all platforms. This follows the pattern established by Stripe (amounts in cents), Bitcoin (amounts in satoshis), and Solana (amounts in lamports).

**`PaymentAdapterRef` validation (§9.1A).** `PaymentAdapterRef` strings are validated for control characters and HTML-special characters at the FFI boundary, since they may be rendered in payment UIs. Maximum length: 256 bytes.

**Why fixed-point coefficients:** Pricing formulas need fractional multipliers (e.g., "cost increases by 0.5x per 100 messages/min"). `Coefficient` provides 6 decimal places of precision using integer arithmetic. Evaluation: `(coefficient.0 * metric_value) / 1_000_000`. Both sides compute the same result.

## 19.2 Payment Adapters

Payment adapters are the backbone of economic governance. They abstract over concrete payment rails, following the same pattern as transport adapters (ADR-005, §16.12.1): a trait that any payment rail can implement, a conformance macro that validates correctness, and a reference adapter for testing.

### 19.2.1 Adapter Trait

```rust
#[async_trait]
pub trait PaymentAdapter: Send + Sync {
    fn adapter_id(&self) -> &str;
    fn capabilities(&self) -> AdapterCapabilities;

    async fn authorize(
        &self,
        payer: &DID,
        payee: &DID,
        amount: Amount,
        currency: CurrencyCode,
        metadata: PaymentMetadata,
    ) -> Result<PaymentAuthorization, PaymentError>;

    async fn capture(
        &self,
        auth: &PaymentAuthorization,
    ) -> Result<PaymentReceipt, PaymentError>;

    async fn void(
        &self,
        auth: &PaymentAuthorization,
    ) -> Result<(), PaymentError>;

    async fn verify(
        &self,
        receipt: &PaymentReceipt,
    ) -> Result<VerificationResult, PaymentError>;

    async fn refund(
        &self,
        receipt: &PaymentReceipt,
        amount: Option<Amount>,
    ) -> Result<RefundConfirmation, PaymentError>;
}

pub struct AdapterCapabilities {
    pub supported_currencies: Vec<CurrencyCode>,
    pub supports_streaming: bool,          // continuous payment (ILP/STREAM-style)
    pub supports_batch_auth: bool,         // authorize N, capture incrementally
    pub supports_single_step: bool,        // skip authorize, capture directly (low latency)
    pub min_amount: Option<Amount>,
    pub max_amount: Option<Amount>,
    pub typical_settlement_ms: u64,        // expected settlement latency
    pub requires_facilitator: bool,        // true for x402 (facilitator verifies/settles)
}

/// Metadata attached to a payment authorization request.
/// Provides context for the payment without revealing encrypted content.
pub struct PaymentMetadata {
    pub action_type: PaidActionType,
    pub context_id: Option<ContextId>,     // None for relay-level payments
    pub idempotency_key: [u8; 16],         // prevents duplicate authorization
}

/// A reserved payment that can be captured or voided.
/// Returned by `authorize()`, consumed by `capture()` or `void()`.
pub struct PaymentAuthorization {
    pub auth_id: [u8; 32],
    pub payer: DID,
    pub payee: DID,
    pub amount: Amount,
    pub currency: CurrencyCode,
    pub adapter_id: String,
    pub created_at: u64,
    pub expires_at: u64,                   // authorization hold expiry
    pub adapter_state: Vec<u8>,            // adapter-specific opaque state (max 4096 bytes)
}
```

**Authorization hold duration.** The maximum hold duration (`expires_at - created_at`) MUST NOT exceed 3600 seconds (1 hour). This is a protocol-level maximum, not adapter-configurable. Adapters MAY use shorter hold durations appropriate to their payment rail (e.g., Lightning invoices typically expire in 60 seconds). If `expires_at > created_at + 3600`, the SDK MUST reject the authorization. After expiry, uncaptured authorizations are automatically voided — the payer's SDK calls `adapter.void(auth)` on expiry. The `adapter_state` field MUST NOT exceed 4096 bytes — the SDK rejects authorizations with larger adapter state.

```rust
/// Result of verifying a PaymentReceipt against the payment rail.
pub struct VerificationResult {
    pub valid: bool,
    pub adapter_id: String,
    pub verified_amount: Amount,
    pub verified_currency: CurrencyCode,
    pub verification_timestamp: u64,
}

/// Confirmation that a refund was processed.
pub struct RefundConfirmation {
    pub refund_id: [u8; 32],
    pub original_receipt_id: [u8; 32],
    pub refunded_amount: Amount,
    pub currency: CurrencyCode,
    pub adapter_proof: Vec<u8>,            // adapter-specific refund proof
}

/// Payment error types.
pub enum PaymentError {
    InsufficientBalance { available: Amount, requested: Amount },
    UnsupportedCurrency(CurrencyCode),
    AuthorizationExpired { auth_id: [u8; 32] },
    AlreadyCaptured { auth_id: [u8; 32] },
    AlreadyVoided { auth_id: [u8; 32] },
    InvalidReceipt(String),
    AdapterError(String),                  // adapter-specific error passthrough
    NoCompatiblePaymentAdapter,            // no adapter overlap between payer and payee
}
```

### 19.2.2 Action-Payment Integration Sequence

The critical flow — how payment interleaves with SCP actions:

```
1. Agent SDK evaluates cost (economic policy + pricing formula + observable metrics)
2. Agent SDK verifies spending UCAN covers this cost
3. Agent SDK calls adapter.authorize(payer_did, payee_did, amount, currency, metadata)
4. PaymentAuthorization attached to action envelope (inside encrypted payload)
5. Receiving side verifies authorization via its own adapter instance (adapter.verify)
6. Action is processed (message delivered, tool invoked, etc.)
7. Receiving side calls adapter.capture(auth)
8. PaymentReceipt recorded in context event log as provenance
9. On failure at step 5-7: adapter.void(auth) — funds released
```

Two primary flow patterns (documented as the canonical models):

**Authorize-then-capture** (x402, Stripe): Used by EIP-3009 `transferWithAuthorization` and Stripe PaymentIntents. Funds are reserved on authorize, moved on capture. Supports void. The x402 12-step flow maps directly onto this.

**Invoice-then-preimage** (Lightning BOLT 11/12, L402): Payee generates invoice with payment_hash, payer pays, preimage serves as cryptographic proof of payment. Preimage IS the receipt — `SHA256(preimage) == payment_hash` is unforgeable. BOLT 12 offers enable static payment endpoints (reusable, no per-transaction invoice from payer side).

Both patterns satisfy the `PaymentAdapter` trait:

| Pattern | `authorize` | `capture` | `verify` |
|---------|-------------|-----------|----------|
| x402 | Sign EIP-3009 or Permit2 transfer | Facilitator submits on-chain | Check on-chain state |
| Lightning | Generate invoice + receive preimage | No-op (preimage revelation IS capture) | Check `SHA256(preimage) == payment_hash` |
| SPL | `ApproveChecked` (single delegate per account, spending cap) | `TransferChecked` using delegate authority | Check on-chain state |

### 19.2.3 Payment Negotiation

Stateless. No handshake. Follows the SCP legibility principle (§1) — payee declares terms, payer evaluates, match or reject.

- Payee advertises accepted adapters + currencies in economic policy (visible in context metadata §5.7 before opt-in)
- Payer's SDK evaluates: compatible adapter configured? Spending UCAN sufficient? Balance adequate?
- If multiple adapters overlap: payer selects (SDK applies preference ordering — cost, speed, privacy)
- If no overlap: `NoCompatiblePaymentAdapter` error — protocol does not bridge between adapters
- Custom terms (volume discounts, personalized pricing): use a bilateral context (§5.12.6) with different economic policy

### 19.2.4 Adapter Discovery and Configuration

- Adapters configured per-identity in SDK (not per-context)
- Identity might have: x402 adapter (linked to wallet on Base/Solana), Lightning adapter (linked to node), Stripe adapter (linked to Stripe account)
- Adapter credentials are identity-private state (§3.7) — encrypted, stored alongside identity keys, never exposed to contexts or relays
- Contexts advertise accepted adapters by `adapter_id` string in their economic policy
- Relay discovery (§18.3.3 `.well-known/scp`) includes accepted adapters in `relay_config`

### 19.2.5 Adapter Credential Management

Each adapter requires credentials to operate (wallet private key, LND macaroon, Stripe API key, SPL delegate keypair). These are distinct from spending UCANs:

- **Spending UCAN** = authorization ("you may spend $X")
- **Adapter credential** = capability ("here's how to move money")
- Both required for any payment. UCAN without credential = can't pay. Credential without UCAN = not authorized to pay.

Credentials are bound to the human identity, not a separate agent identity. Under the shared-DID model (ADR-039), the agent's `#agent` verification method on the human's DID never holds raw payment credentials — it holds a spending UCAN that authorizes the SDK (which holds the credential) to execute payments on its behalf. This separation is critical: revoking the spending UCAN instantly cuts off the agent's ability to spend, without needing to rotate the underlying payment credential.

Credential rotation follows identity key rotation (§9.12). SPL-specific: human calls `ApproveChecked` granting the `#agent` verification method's keypair delegate authority on their USDC ATA — single delegate per account, amount-capped.

### 19.2.6 Conformance Testing

`payment_adapter_conformance!()` macro (mirrors `transport_conformance!()` §16.12.1 and `blob_store_conformance!()` §16.12.6):

- Authorize/capture roundtrip
- Authorize/void roundtrip
- Double-capture rejection
- Insufficient balance handling
- Verify roundtrip (receipt → verification)
- Currency mismatch rejection
- Concurrent authorization isolation
- Refund against captured receipt

Reference adapter: `TestAdapter` — in-memory ledger, no real money, ships with SDK. Protocol does NOT ship production adapters (payment rails are external dependencies with licensing/compliance considerations).

### 19.2.7 Known Adapter Patterns

Documented for implementers, not protocol-specified:

| Adapter | Rail | Auth Model | Settlement | Key Pattern |
|---------|------|-----------|------------|-------------|
| x402 | Base/Solana USDC | EIP-3009 `transferWithAuthorization` or Permit2 | Sub-second (Base), ~400ms (Solana) | Agent signs authorization, facilitator verifies + settles on-chain. `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` HTTP headers. |
| Lightning | BOLT 12 offers | Invoice → preimage | Near-instant | Static offer (`lno1...`) published by payee. Agent sends `invoice_request` via onion message, receives invoice, pays, preimage = receipt. BIP-340 Schnorr signatures. |
| L402 | Lightning + Macaroons | Macaroon + preimage | Near-instant | HTTP 402 → `WWW-Authenticate: L402 macaroon=..., invoice=...` → pay invoice → `Authorization: L402 <macaroon>:<preimage>`. Macaroon caveats for spending caps, expiry, scope. |
| SPL Token | Solana | `ApproveChecked` → `TransferChecked` | ~400ms slots | Human approves agent as delegate on USDC ATA. Agent transfers using delegate authority. Single delegate per account, spending cap enforced. USDC mint: `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`. |
| Stripe | Stripe Connect | PaymentIntent authorize → capture | Real-time | For structured commerce (ACP pattern). `SharedPaymentToken` for delegated payment. Machine payments via x402 integration on Base. |

### 19.2.8 Multi-Adapter Contexts

- Context MAY accept multiple adapters simultaneously (e.g., both x402 and Lightning)
- Each adapter independent — no cross-adapter settlement at protocol level
- Payer selects adapter; payee accepts any configured
- Reconciliation across adapters is the operator's concern, not the protocol's

## 19.3 Economic Policy

Economic policy is a context setting governed through the context's governance model (§5.9).

**Mutable by default.** Changes go through governance, are logged in the event log, visible to all members, take effect after a notification period. The minimum notification period is 86,400 seconds (24 hours) — economic policy changes MUST NOT take effect sooner than 24 hours after the `EconomicPolicyChanged` event is committed to the event log. Contexts MAY configure a longer notification period via `economic_policy_notification_period_secs` in `ContextParams` (no maximum). During the notification period, the previous policy remains in effect. This prevents surprise pricing changes that could trap agents with queued messages or active sessions. This follows the governance pattern but does NOT mirror the ceiling policy immutability default — pricing changes are normal business operations, not security boundary changes.

**Optional immutability lock.** Creator MAY lock economic policy at creation — "always free forever" or "price locked at $X forever." Voluntary commitment, not the default. The lock is itself immutable (once locked, cannot unlock). Use cases: public goods contexts, trust signals, permanent free tiers.

```rust
pub struct EconomicPolicy {
    pub locked: bool,                              // true = immutable, false = governed (default)
    pub cost_schedule: CostSchedule,
    pub payment_adapters: Vec<PaymentAdapterRef>,  // accepted payment methods
    pub pricing_formula: Option<PricingFormula>,    // for dynamic pricing (§19.4)
    pub payee: DID,                                // who receives payments
}

pub struct CostSchedule {
    pub currency: CurrencyCode,                     // currency for all Amount fields in this schedule
    pub per_message: Option<Amount>,
    pub per_outlet_call: Option<Amount>,            // default for Action outlets without own cost
    pub per_join: Option<Amount>,                   // one-time membership cost
    pub per_period: Option<SubscriptionCost>,       // recurring (carries its own currency for flexibility)
    pub per_byte_stored: Option<Amount>,            // storage costs
}
```

**Outlet-level costs**: declared in outlet registration (§5.4), additive with context costs. An outlet calling an external API can pass through its cost. Outlet costs carry their own payee DID (may differ from context payee).

**Query outlet cost contract (§5.4.2).** A Query outlet's registered cost MUST be absent or zero (`cost.is_none() || cost.amount == 0`) AND `cost.cost_formula` MUST be absent. This is a **structural floor** enforced at registration time — rejection with `OutletErrorClass::Protocol::QueryCostViolation` if violated. Action outlets (§5.4.2) have no such contract — each invocation may be charged independently subject to the normal cost schedule. Any cache-assisted "at-most-once" charge semantics are a property of future cache designs (§5.4.3 deferred per discussion [#1698](https://github.com/limn-works/scp/discussions/1698)), not of this section; the structural floor stands on its own regardless of whether a cache ever ships.

**Relay-level costs**: declared in `.well-known/scp` `relay_config` (§18.3.3 extension). Separate economic relationship from in-context pricing — relay charges for transport, context charges for participation.

**Economic policy is orthogonal to capability ceiling** (§5.3). Ceiling governs what CAN happen; economic policy governs what it COSTS. Not a new ceiling category. A context with `outlet_call:*` in its ceiling and `per_outlet_call: $0.01` in its economic policy allows Action outlet invocations that cost $0.01 each. Removing the cost doesn't expand capabilities; adding a cost doesn't restrict them.

**Child context independence:** Child contexts (§5.13) do NOT inherit parent economic policy — each child's pricing is independent. A free parent can have paid children and vice versa.

**Auto-accept hard rule:** Auto-accept (§5.12.2) NEVER applies to contexts with economic policy requiring payment. Agents never silently incur costs. This is a hard rule, not a default — no auto-accept policy configuration can override it.

## 19.4 Dynamic Pricing

Formula-based, not oracle-based. Both sides evaluate the same formula against observable metrics — deterministic, no external dependency, no new trust surface.

Directly inspired by EIP-1559: algorithmic pricing embedded in protocol rules, independently computable by all parties.

```rust
pub struct PricingFormula {
    pub base_cost: Amount,
    pub variables: Vec<PricingVariable>,
    pub cap: Option<Amount>,     // max cost regardless of formula
    pub floor: Option<Amount>,   // min cost regardless of formula
}

pub enum PricingVariable {
    /// Linear multiplier: cost += (coefficient.0 * metric_value) / 1_000_000
    /// Coefficient is fixed-point with 6 decimal places (§19.1.1).
    Linear { metric: PricingMetric, coefficient: Coefficient },
    /// Step function: cost += additional when metric_value exceeds threshold.
    /// Thresholds are integer metric values (messages/min, member count, bytes, etc.).
    Step { metric: PricingMetric, thresholds: Vec<(u64, Amount)> },
}

pub enum PricingMetric {
    ContextMessageRate,    // messages/min in this context (measurement: count of MessageSent events
                           // in the context's event log within the last 60 seconds, divided by 1.
                           // Window: trailing 60-second sliding window, evaluated at action time.)
    MemberCount,           // current member count (measurement: count of active memberships in
                           // context state at evaluation time. No window — point-in-time snapshot.)
    RelayQueueDepth,       // relay-level only (measurement: number of unacknowledged blobs for the
                           // routing_id at evaluation time. No window — point-in-time snapshot.)
    TimeOfDay,             // UTC hour (0-23), enables off-peak pricing (measurement: current UTC
                           // hour truncated to integer. No window — point-in-time.)
    SenderVelocity,        // sender's messages in sliding window (measurement: count of MessageSent
                           // events by the specific sender DID within the last 60 seconds.
                           // Window: trailing 60-second sliding window, evaluated at action time.)
    StorageUsage,          // context storage in bytes (measurement: sum of value sizes for all keys
                           // under context/{context_id}/ in ProtocolRepository. Measured on the payer's
                           // local storage. Window: point-in-time snapshot at evaluation.)
}
```

**Evaluation:** Payer SDK computes cost from observable metrics, authorizes payment, submits action with authorization. Receiver independently evaluates formula. If payer's payment is insufficient (metrics diverged), action rejected with `CostInsufficient` containing receiver's computed cost and the metric values the receiver observed. Payer can retry with updated amount.

```rust
/// Returned when payer's authorized amount is less than receiver's computed cost.
/// Includes metric snapshot so payer can see why costs diverged.
pub struct CostInsufficient {
    pub expected: Amount,              // receiver's computed cost
    pub provided: Amount,              // payer's authorized amount
    pub currency: CurrencyCode,
    pub metric_snapshot: Vec<(PricingMetric, u64)>,  // receiver's observed metric values
}
```

**Governed changes:** Formula itself is a governed setting — governance can adjust coefficients, add/remove variables, change cap/floor. Changes logged, members notified, grace period before effect.

**EIP-1559 analogy:** For relay pricing specifically, a utilization-targeting formula makes sense:
- Target: 50% relay capacity
- Below target: price decreases (capped at floor)
- Above target: price increases (capped at cap)
- Max change per evaluation period: configurable (e.g., 12.5% like EIP-1559)

## 19.5 Spending Capability (UCAN Extension)

Novel contribution — no existing standard combines UCAN delegation chains with payment semantics. L402/Macaroons have spending caveats but not DID-based delegation. ILP/GNAP has payment authorization but not capability-chain attenuation. SCP bridges both.

```rust
/// UCAN capability for spending authorization.
/// Resource URI: "scp:spending:{context_id}" or "scp:spending:*"
pub struct SpendingCapability {
    pub max_per_action: Amount,        // max single-action spend
    pub max_total: Amount,             // max total spend within time_window
    pub currency: CurrencyCode,        // ISO 4217 or protocol-defined
    pub time_window: Duration,         // rolling window for max_total
    pub allowed_adapters: Vec<String>, // empty = any configured adapter
}
```

**`time_window` semantics.** The `time_window` is a rolling window measured from the current time backwards. The running total is the sum of all `PaymentReceipt.amount` values for receipts with `timestamp >= (now - time_window.as_secs())`. The window rolls forward continuously — old receipts age out as time passes. The window starts at UCAN issuance time (not at first spend).

**Enforcement location.** `max_total` is enforced by the **payer's SDK** as a self-imposed spending limit. The payer SDK maintains a local spending ledger: a list of `(receipt_id, amount, timestamp)` tuples stored under `identity/{did}/spending_ledger/{ucan_token_id}/` in `ProtocolRepository`. Before each `authorize()` call, the SDK sums receipts within `time_window` and rejects if `running_total + new_amount > max_total` with a `SpendingLimitExceeded` error. Payees do NOT enforce `max_total` — they cannot know the payer's total spending across all payees. This is a deliberate design choice: `SpendingCapability` is a self-governance mechanism for the human delegating spending authority to their agent, not a protocol-enforced global limit. The human trusts their own SDK to enforce the limit honestly. A compromised SDK that ignores the limit can overspend, but the blast radius is bounded by the UCAN's 24-hour expiry (§9.5) and the adapter's balance.

**AND composition:** Action UCAN + spending UCAN both required for paid actions. Agent with `messages:write` but no spending UCAN cannot send paid messages. Agent with spending UCAN but no `messages:write` cannot spend on messages. Both capabilities are independently verified before any paid action proceeds.

**Delegation chain:** Human DID (`#active`) → spending UCAN (self-delegation with `fct.scp_key_scope: "#agent"`) → same DID (`#agent` scoped). Attenuation applies: sub-delegation must narrow, never widen. An agent granted $100/day can delegate $10/day to a sub-agent. UCAN standard attenuation rules (§7.2) apply unchanged.

**No implicit spending:** Protocol NEVER authorizes expenditure without explicit spending UCAN. Missing UCAN → `SpendingCapabilityRequired` error. Agent can still perform free actions in the context.

**Revocation:** Independent of other UCANs (§7.4.4). Human discovers overspending → revoke spending UCAN → agent retains other capabilities but cannot authorize payments.

**24-hour maximum expiry** (§9.5): Spending UCANs follow existing UCAN expiry rules. Short-lived by design — limits blast radius of compromised agents.

## 19.6 Payment Receipts and Provenance

Every paid action generates a `PaymentReceipt` recorded in the context event log as a provenance record (§7.7).

```rust
pub struct PaymentReceipt {
    pub receipt_id: [u8; 32],
    pub payer: DID,
    pub payee: DID,
    pub amount: Amount,
    pub currency: CurrencyCode,
    pub action_type: PaidActionType,
    pub context_id: Option<ContextId>,
    pub adapter_id: String,
    pub adapter_proof: Vec<u8>,       // adapter-specific proof:
                                      //   x402: on-chain tx hash
                                      //   Lightning: preimage
                                      //   SPL: tx signature
    pub timestamp: u64,
    pub signature: Vec<u8>,           // Ed25519 signature by payer (see signature scope below)
}
```

**PaymentReceipt signature scope.** The `signature` field is an Ed25519 signature by the payer's `#active` key (or `#agent` key if the agent initiated the payment under a spending UCAN) over the following canonical byte sequence:

```
signed_payload = receipt_id (32 bytes)
              || payer_did (UTF-8 bytes, length-prefixed with u16 big-endian)
              || payee_did (UTF-8 bytes, length-prefixed with u16 big-endian)
              || amount (u64 big-endian, 8 bytes)
              || currency (4 bytes, raw CurrencyCode)
              || action_type (u8: 0=MessageSend, 1=ToolInvoke, 2=ContextJoin,
                              3=SubscriptionPeriod, 4=ByteStored)
              || context_id (32 bytes if Some, 0x00 if None)
              || adapter_id (UTF-8 bytes, length-prefixed with u16 big-endian)
              || timestamp (u64 big-endian, 8 bytes)
```

The `adapter_proof` field is deliberately excluded from the signature scope — it is adapter-specific opaque data that may not be available at signing time (e.g., Lightning preimage is revealed after payment, not before). Verification of payment integrity uses `adapter.verify(receipt)` against the payment rail; the payer's signature proves the payer authorized this specific payment.

**Verification:** Any party calls `adapter.verify(receipt)` — adapter checks proof against the payment rail (on-chain state, preimage hash, etc.).

**Cost provenance:** When data crosses context boundaries (§7.7), payment receipts are part of the provenance chain. `DataProvenance` (§7.7.1) extended with optional `paymentAmount`, `paymentAdapter`, `paymentReceiptId`. Receiving contexts see what data cost to produce — expensive computations carry economic provenance.

**Payment data is inside encrypted envelope** (§9.10). Relays see opaque blobs. Payment metadata never leaks to transport layer. Fixed bucket padding (§9.10.3) prevents size-based inference of whether a message carries payment data.

### 19.6.1 Event Types

Economic governance introduces new event types for the verifiable event log (ADR-011):

| Event Type | Trigger | Payload |
|---|---|---|
| `PaymentReceived` | `adapter.capture()` succeeds | `PaymentReceipt` |
| `EconomicPolicyChanged` | Governance updates economic policy | Old policy hash, new `EconomicPolicy`, governance justification |
| `SpendingUcanGranted` | Human grants spending UCAN to agent | Agent key `#agent` on human's DID, `SpendingCapability` summary (amounts, window), UCAN token ID |
| `SpendingUcanRevoked` | Human revokes spending UCAN | UCAN token ID, revocation reason |

These extend the existing event type enum alongside `MessageSent`, `MemberJoined`, `RoleAssigned`, `OutletInvoked`, etc. All economic events carry the same Merkle-tree inclusion guarantees as other event types.

## 19.7 Anti-Spam via Cost Escalation

**Static cost floor:** Any non-zero cost eliminates economically irrational spam. $0.0001/message makes bulk spam a P&L decision.

**Per-sender escalation** using `SenderVelocity` metric:

```
base_cost: $0.001
variables:
  - Step { metric: SenderVelocity, thresholds: [
      (10/min,  +$0.001),     // elevated: $0.002/msg
      (50/min,  +$0.01),      // high: $0.012/msg
      (200/min, +$0.10),      // extreme: $0.112/msg
    ]}
cap: $1.00
```

Normal conversation (1-5 msg/min): negligible ($0.001). Spam rates (200+ msg/min): $0.112/msg = $1,344/hr. Self-limiting.

**Composes with consequence mechanisms** (§7.3.7): Economic tier (cost escalation) and participation tier (warning → suspension → ejection) operate independently. Agent might exhaust spending UCAN before participation consequences trigger, or vice versa.

**Sybil deterrent:** N identities = N × cost. Each identity needs its own spending UCAN, own adapter credentials, own payment capacity. Compounds with device attestation (§9.3) — Sybil attacks are expensive to create AND expensive to sustain.

**DDoS inversion:** DDoS against a priced relay is paying the operator to absorb the attack.

## 19.8 Relay Monetization

Relay economics are SEPARATE from context economics — different trust model. Relays are transport (dumb pipes, §9.9). Context pricing is application-level (inside encrypted envelope, invisible to relays).

**Relay economic config** extends `.well-known/scp` (§18.3.3):

```json
{
  "relay_config": {
    "max_blob_size": 262144,
    "max_blob_ttl": 86400,
    "rate_limit_publish": 6000,
    "economic": {
      "currency": "USD",
      "per_publish": 10,
      "per_byte_stored": 1,
      "payment_adapters": ["x402", "lightning"],
      "payee": "did:dht:z6Mk..."
    }
  }
}
```

**`per_byte_stored` billing model.** The `per_byte_stored` amount is a **one-time storage fee** charged when a blob is published to the relay. The fee is `per_byte_stored * blob_size_bytes`, charged once at publish time. There is no recurring charge — once paid, the blob is stored until its TTL expires. Example: with `per_byte_stored: 1` (1 cent) and `currency: "USD"`, a 256 KiB blob costs `1 * 262144 = 262144 cents = $2,621.44`. Relay operators SHOULD set `per_byte_stored` to values appropriate for their cost structure — the example value of `1` is illustrative, not recommended. A more realistic value for a USD-denominated relay might be `per_byte_stored: 0` (free, subsidized by `per_publish`) or use sub-cent amounts via a different currency unit (e.g., SAT with `per_byte_stored: 1` = 1 satoshi per byte = ~$0.0004 per byte at $40k/BTC).

**JSON Amount serialization:** `Amount` values in `.well-known/scp` are serialized as JSON integers in the smallest currency unit specified by `currency`. For USD (unit: cent), `10` = $0.10. For BTC (unit: satoshi), `100` = 100 satoshis. Parsers convert JSON integer → `Amount(u64)` directly. Decimal string representations are NOT valid — all amounts are integers. The `currency` field determines the interpretation scale.

**Payment flow:** Agent evaluates relay config (visible before connecting) → selects compatible adapter → authorizes per-action → relay verifies + captures.

**Free relays MUST exist.** Bootstrap relay list (§18.5, priority level 5) MUST include free relays. Self-hosted relays (§10.2, §10.4), community relays, and bundled relays remain free. Economic config is optional. Absence = free.

**Relay selection:** `TransportManager` (ADR-012) already selects by reliability + latency. Economic governance adds cost as a third criterion. Market pressure: agents prefer cheaper relays, creating competition.

**EIP-1559-style relay pricing:** For relays wanting demand-responsive pricing, the `PricingFormula` model supports utilization targeting. Target 50% capacity, price adjusts based on queue depth. Deterministic — both relay and agent compute the same price.

## 19.9 Discovery Integration

Economic metadata participates in all discovery channels:

- **Context metadata (§5.7):** Economic policy visible before opt-in. Prospective members see pricing alongside capability ceiling, governance model, and roles.
- **Context registration (§6.2.2B):** Contexts advertising in contexts with discovery tools include economic metadata in their registration.
- **DID document `SCPCapabilities` (§18.2.2):** Optional economic metadata — identities may advertise accepted payment adapters and currencies.
- **Relay config in `.well-known/scp` (§18.3.3):** Relay economic parameters visible alongside operational parameters.

All follow the legibility principle: agents see economic terms before committing to any interaction.

## 19.10 Context Templates

Two new well-known templates:

**`scp:template/paid-service`:** Outlet invocation context with per-invoke cost. `economic_policy.cost_schedule.per_outlet_call` required at creation. Single-admin governance. Extends `scp:template/outlet-interface`.

Properties:
- Ceiling: `messages:read`, `messages:write`, `outlet:register`, `outlet:query:*`, `outlet:call:*`
- Ceiling policy: `immutable`
- Economic policy: required, `per_outlet_call` must be set
- Governance: single-admin
- Memory scope: `full` (receipts are provenance)

**`scp:template/paid-broadcast`:** Subscription-based broadcast context. `economic_policy.cost_schedule.per_period` required at creation. Gated subscriber registration — admin grants `messages:read` UCAN after payment verification. Extends `scp:template/gated-broadcast` (§5.14.4).

Properties:
- Mode: `Broadcast`
- Ceiling: `messages:read`, `messages:write`
- Ceiling policy: `immutable`
- Economic policy: required, `per_period` must be set
- Subscriber admission: gated (admin-issued `messages:read` UCAN post-payment)
- Memory scope: `full`

## 19.11 SDK Surface

```
SCP.Economy.estimateCost(context, action) → Amount
SCP.Economy.paymentHistory(context) → [PaymentReceipt]

SCP.Context.create(..., economicPolicy?) → Context   // extended
SCP.Context.inspect() → { ..., economicPolicy? }     // extended

SCP.Identity.grantSpending(agent, SpendingCapability, expiry) → UcanToken
SCP.Identity.configureAdapter(adapter) → ()
```

`estimateCost` evaluates the context's pricing formula against current observable metrics. `paymentHistory` retrieves receipts from the context's event log. `grantSpending` mints a spending UCAN. `configureAdapter` registers a payment adapter with the identity's SDK instance.

## 19.12 Security Considerations

**Economic DoS:** Many small payments consuming processing time. Mitigation: per-join minimum viable amount, rate limits checked BEFORE payment verification (§9.2.1). The protocol validates action rate limits before engaging the payment adapter, so payment processing never amplifies a rate-limited attack.

**Payment adapter trust:** Malicious adapter could falsify receipts. Mitigation: `verify()` checks against the payment rail (on-chain state, preimage hash), not the adapter's word. Receipts are signed by the payer's DID key — adapter cannot forge the payer's signature.

**Spending UCAN theft:** Compromised `#agent` verification method on human's own DID spends up to `max_total` within `time_window`. Mitigation: 24-hour maximum expiry (§9.5), independent revocation (§7.4.4), conservative limits. Blast radius bounded by the UCAN's constraints — but note that under the shared-DID model (ADR-039), the blast radius extends to the human's identity reputation since agent actions are attributed to the same DID.

**Privacy:** Payment adapter sees transaction metadata but not context content. For context-level payments, payment data is inside the encrypted envelope — the adapter sees amount and DIDs but not what the payment is for. For relay-level payments, the adapter sees the relay operation but not the encrypted content. For maximum privacy, Lightning's onion routing or local-only adapters.

**Relay trust:** Paid relays remain untrusted — they see opaque blobs. Relay payment is for transport, not content access. Encryption-as-access-control (§9) unchanged. A relay that charges for storage cannot read what it stores.

**Payment-as-gatekeeper risk:** If ALL relays require payment, free users are excluded. Mitigation: free relays MUST exist in the bootstrap relay list (§18.5). This is a protocol invariant, not a suggestion. The fallback relay list shipped with the SDK MUST include at least one free relay.

## 19.13 Phase Integration

All protocol components (trait, policy, UCAN type, receipts, formulas) are **Phase 3** — they compose Phase 1 (crypto, UCAN, event log) and Phase 2 (context lifecycle, tools, governance) primitives. No new cryptographic primitives are introduced. No new transport mechanisms. Economic governance is a layer built entirely on existing protocol infrastructure.

Community payment adapters (x402, Lightning, SPL, Stripe) are **Phase 4+** — external dependencies, not protocol-blocking. The `TestAdapter` reference implementation ships with Phase 3. Production adapters are community-contributed or vendor-maintained.

## 19.14 Invariants

1. **Economic policy visible before opt-in (legibility).** Economic terms are part of context metadata (§5.7), visible to any identity that inspects the context before joining.
2. **No implicit spending — spending UCAN always required.** Protocol NEVER authorizes expenditure without an explicit, valid spending UCAN from the payer's delegation chain.
3. **Free operation is default — no economic policy = free.** Contexts without `EconomicPolicy` are free. Relays without `economic` in `relay_config` are free. Tools without cost metadata are free.
4. **Receipts are provenance records — every payment is traceable and verifiable.** Payment receipts are recorded in context event logs and participate in the provenance chain (§7.7).
5. **Payment adapters are substitutable — no single rail privileged.** The `PaymentAdapter` trait treats all payment rails equally. Protocol correctness does not depend on any specific adapter.
6. **Economic policy mutable by default, optional immutability lock is voluntary.** Unlike ceiling policy (immutable by default), economic policy is governed by default. Creators may voluntarily lock pricing at creation.
7. **Payment data inside encrypted envelope — relays never see payment metadata** for context-level economics. Relay-level payments are visible to the relay (necessary for relay to verify) but not to other relays or contexts.
8. **Free relays MUST always exist in bootstrap list.** The SDK's fallback relay list (§18.5) MUST include free relays. This is a protocol invariant that prevents economic gatekeeping of basic protocol operation.
9. **Auto-accept never applies to paid contexts.** No auto-accept policy configuration (§5.12.2) can override this. Agents never silently incur costs.

## 19.15 Wire Format Tables

This section tabulates the wire format for all economy protocol types that cross the network. All types use serde serialization (JSON for tool call payloads, MessagePack for MLS application messages and event log entries). An independent implementer MUST implement these types with exactly the field names, types, and semantics shown below.

### 19.15.1 Core Value Types

**`Amount`** — Newtype wrapping `u64`. Represents the smallest currency unit (e.g., cents for USD, satoshis for BTC). No floating-point anywhere in the economy protocol.

| Wire Representation | Type | Notes |
|---------------------|------|-------|
| JSON | `number` (unsigned integer) | e.g., `1500` = 15.00 USD |
| MessagePack | `uint 64` | Network byte order |

**`CurrencyCode`** — Newtype wrapping `[u8; 4]`. ISO 4217 currency code, null-padded to 4 bytes.

| Wire Representation | Type | Notes |
|---------------------|------|-------|
| JSON | `string` (3-4 chars) | e.g., `"USD"`, `"BTC"`, `"USDC"` |
| MessagePack | `bin 4` | 4 raw bytes, null-padded |

**JSON encoding note:** JSON representations MUST use the trimmed currency string without null-byte padding (e.g., `"USD"`, not `"USD\u0000"`). Null-padding to 4 bytes is applied only in MessagePack/binary encoding. This avoids parser-compatibility issues across implementations, since many JSON parsers reject or mishandle embedded null bytes in strings.

**`Coefficient`** — Newtype wrapping `i64`. Fixed-point with 6 decimal places: `value = raw / 1,000,000`.

| Wire Representation | Type | Notes |
|---------------------|------|-------|
| JSON | `number` (signed integer) | e.g., `1500000` = 1.5 |
| MessagePack | `int 64` | Signed |

### 19.15.2 Cost Structure

**`SubscriptionPeriod`** — Tagged enum for subscription billing periods.

| Variant | Serde Tag | Fields | Semantics |
|---------|-----------|--------|-----------|
| `Daily` | `"Daily"` | — | Billed daily. |
| `Weekly` | `"Weekly"` | — | Billed weekly. |
| `Monthly` | `"Monthly"` | — | Billed monthly. |
| `Custom` | `"Custom"` | `seconds: u64` | Custom period in seconds. |

**`SubscriptionCost`** — Cost definition for recurring subscriptions.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `amount` | `Amount` (u64) | Yes | Cost per period in smallest currency unit. |
| `period` | `SubscriptionPeriod` | Yes | Billing period. |
| `currency` | `CurrencyCode` ([u8; 4]) | Yes | Payment currency. |

**`CostSchedule`** — Per-action cost table for a context.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `currency` | `CurrencyCode` ([u8; 4]) | Yes | Currency for all costs in this schedule. |
| `per_message` | `Amount` (u64) | No | Cost per message sent. |
| `per_outlet_call` | `Amount` (u64) | No | Cost per Action outlet invocation (Query outlets MUST be absent-or-zero per §5.4.2). |
| `per_join` | `Amount` (u64) | No | One-time cost to join the context. |
| `per_period` | `SubscriptionCost` | No | Recurring subscription cost. |
| `per_byte_stored` | `Amount` (u64) | No | Cost per byte of stored data. |

**`PaidActionType`** — Enum for billable action categories.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `MessageSend` | `"MessageSend"` | Sending a message. |
| `OutletCall` | `"OutletCall"` | Invoking an Action outlet (Query outlets are absent-or-zero cost per §5.4.2). |
| `ContextJoin` | `"ContextJoin"` | Joining a context. |
| `SubscriptionPeriod` | `"SubscriptionPeriod"` | Recurring subscription payment. |
| `ByteStored` | `"ByteStored"` | Data storage. |

### 19.15.3 Dynamic Pricing

**`PricingMetric`** — Observable metrics for dynamic pricing formulas.

| Variant | Serde Tag | Measurement Semantics |
|---------|-----------|----------------------|
| `ContextMessageRate` | `"ContextMessageRate"` | Messages per second in the context (sliding window). |
| `MemberCount` | `"MemberCount"` | Current context member count. |
| `RelayQueueDepth` | `"RelayQueueDepth"` | Pending messages in relay queue. |
| `TimeOfDay` | `"TimeOfDay"` | Current hour (0-23) in UTC. |
| `SenderVelocity` | `"SenderVelocity"` | Messages per minute from the specific sender. |
| `StorageUsage` | `"StorageUsage"` | Bytes currently stored for the context. |

**`PricingVariable`** — Tagged enum for pricing formula components.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `Linear` | `"Linear"` | `metric: PricingMetric`, `coefficient: Coefficient` | `cost += coefficient * metric / 1,000,000`. |
| `Step` | `"Step"` | `metric: PricingMetric`, `thresholds: Vec<(u64, Amount)>` | Add `Amount` when `metric >= threshold`. Each threshold is `[metric_value, amount]`. |

**`PricingFormula`** — Complete dynamic pricing specification.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `base_cost` | `Amount` (u64) | Yes | Fixed cost before variable adjustments. |
| `variables` | `Vec<PricingVariable>` | Yes | Variable cost components. May be empty. |
| `cap` | `Amount` (u64) | No | Maximum total cost after all adjustments. |
| `floor` | `Amount` (u64) | No | Minimum total cost after all adjustments. |

### 19.15.4 Economic Policy

**`EconomicPolicy`** — Context-level economic configuration. Part of context metadata (§5.7).

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `locked` | `bool` | Yes | If `true`, economic policy cannot be changed by governance. |
| `cost_schedule` | `CostSchedule` | Yes | Per-action cost table. |
| `payment_adapters` | `Vec<String>` | Yes | Accepted payment adapter IDs. |
| `pricing_formula` | `PricingFormula` | No | Dynamic pricing. If absent, `cost_schedule` alone determines costs. |
| `payee` | `String` (DID) | Yes | DID that receives payments. |

### 19.15.5 Payment Authorization and Receipt

**`PaymentMetadata`** — Metadata for a payment request.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `action_type` | `PaidActionType` | Yes | What action this payment authorizes. |
| `context_id` | `String` | No | Context ID if the action is context-scoped. |
| `idempotency_key` | `[u8; 16]` | Yes | CSPRNG, prevents duplicate payments. |

**`PaymentAuthorization`** — Authorization from payer to proceed with payment.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `auth_id` | `[u8; 32]` | Yes | Unique authorization identifier. |
| `payer` | `String` (DID) | Yes | DID authorizing the payment. |
| `payee` | `String` (DID) | Yes | DID receiving the payment. |
| `amount` | `Amount` (u64) | Yes | Authorized amount. |
| `currency` | `CurrencyCode` ([u8; 4]) | Yes | Currency. |
| `adapter_id` | `String` | Yes | Payment adapter handling the transaction. |
| `created_at` | `u64` | Yes | Unix timestamp (seconds). |
| `expires_at` | `u64` | Yes | Authorization expiry. Payment must be captured before this. |
| `adapter_state` | `Vec<u8>` (serde_bytes) | Yes | Adapter-specific opaque state. |

**`PaymentReceipt`** — Proof of completed payment. Recorded in context event log.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `receipt_id` | `[u8; 32]` | Yes | Unique receipt identifier. |
| `payer` | `String` (DID) | Yes | DID that paid. |
| `payee` | `String` (DID) | Yes | DID that received payment. |
| `amount` | `Amount` (u64) | Yes | Amount paid. |
| `currency` | `CurrencyCode` ([u8; 4]) | Yes | Currency. |
| `action_type` | `PaidActionType` | Yes | What action was paid for. |
| `context_id` | `String` | No | Context if action is context-scoped. |
| `adapter_id` | `String` | Yes | Payment adapter used. |
| `adapter_proof` | `Vec<u8>` (serde_bytes) | Yes | Adapter-specific payment proof. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds) of payment. |
| `signature` | `Vec<u8>` (64 bytes) | Yes | Ed25519 signature by payer over canonical receipt fields (§19.6). |

**Receipt Signature Construction.** The receipt signature covers: `SHA-256("SCP-RECEIPT-V1:" || receipt_id || len(payer) || payer || len(payee) || payee || amount_BE || currency || action_type_tag || len(context_id) || context_id || len(adapter_id) || adapter_id || timestamp_BE)`. When `context_id` is absent, the sentinel `SHA-256(0x00)` (32 bytes) is used per §9.5.1.

**`AdapterCapabilities`** — Advertised capabilities of a payment adapter.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `supported_currencies` | `Vec<CurrencyCode>` | Yes | Currencies this adapter handles. |
| `supports_streaming` | `bool` | Yes | Whether streaming payments are supported. |
| `supports_batch_auth` | `bool` | Yes | Whether batch authorization is supported. |
| `supports_single_step` | `bool` | Yes | Whether auth+capture can be one step. |
| `min_amount` | `Amount` (u64) | No | Minimum payment amount. |
| `max_amount` | `Amount` (u64) | No | Maximum payment amount. |
| `typical_settlement_ms` | `u64` | Yes | Typical settlement time in milliseconds. |
| `requires_facilitator` | `bool` | Yes | Whether a third-party facilitator is needed. |

**`VerificationResult`** — Result of verifying a payment receipt.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `valid` | `bool` | Yes | Whether the receipt verified successfully. |
| `adapter_id` | `String` | Yes | Adapter that performed verification. |
| `verified_amount` | `Amount` (u64) | Yes | Amount confirmed by the adapter. |
| `verified_currency` | `CurrencyCode` ([u8; 4]) | Yes | Currency confirmed. |
| `verification_timestamp` | `u64` | Yes | Unix timestamp (seconds) of verification. |

**`RefundConfirmation`** — Confirmation of a payment refund.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `refund_id` | `[u8; 32]` | Yes | Unique refund identifier. |
| `original_receipt_id` | `[u8; 32]` | Yes | Receipt being refunded. |
| `refunded_amount` | `Amount` (u64) | Yes | Amount refunded. |
| `currency` | `CurrencyCode` ([u8; 4]) | Yes | Currency. |
| `adapter_proof` | `Vec<u8>` (serde_bytes) | Yes | Adapter-specific refund proof. |

**`PaymentError`** — Tagged enum for payment failure reasons.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `InsufficientBalance` | `"InsufficientBalance"` | `available: Amount`, `requested: Amount` | Payer lacks funds. |
| `UnsupportedCurrency` | `"UnsupportedCurrency"` | `currency: CurrencyCode` | Adapter does not handle this currency. |
| `AuthorizationExpired` | `"AuthorizationExpired"` | `auth_id: [u8; 32]`, `expired_at: u64` | Authorization timed out. |
| `AdapterUnavailable` | `"AdapterUnavailable"` | `adapter_id: String` | Payment adapter is unreachable. |
| `DuplicatePayment` | `"DuplicatePayment"` | `idempotency_key: [u8; 16]` | Payment already processed for this key. |

### 19.15.6 Spending Capability (UCAN Extension)

The spending UCAN `att` (attenuation) resource uses the capability URI format `scp:capability:spend/v1`. Spending delegation is constrained by the following fields in the UCAN `fct` (facts) section:

| Fact Key | Type | Semantics |
|----------|------|-----------|
| `max_amount` | `u64` | Maximum amount per transaction. |
| `currency` | `String` (4 chars) | Allowed currency code. |
| `context_id` | `String` | If present, spending restricted to this context. |
| `action_types` | `Vec<String>` | If present, restrict to these `PaidActionType` variants. |
| `expires_at` | `u64` | Absolute expiry (in addition to UCAN `exp`). |
