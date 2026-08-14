# Event-Log Convergence (Wave A/B) — Attack Surfaces

Commits: 217d14ac6 (Wave A), b3d354279 (Wave B core), 3e667ef48 (WASM parity).
Goal: make canonical Merkle log convergent (§9.9.3 equivocation detection) by
removing per-author durable leaves (MessageSent/ToolInvoked/PaymentReceived).

## CRITICAL — Consequence-leaf convergence poisoned by member-local buffer (BLACK-EL01)
- `is_convergent_trigger` (scp-protocol/src/trust/consequence.rs:130) gates whether a
  consequence mints a DURABLE leaf on the TRIGGER TYPE (WarningCount/Custom=>durable).
- But WHETHER the WarningCount consequence FIRES depends on the count from
  `event_log_entries_for_consequences` (governance_logic.rs:689) = durable log (Source 1,
  convergent) + RECEIVE BUFFER (Source 2, MEMBER-LOCAL/divergent).
- Buffer dedup `estimated_ts <= last_log_ts` (line 814) uses `estimated_ts = now -
  (buffer_len-1-idx)` where buffer_len is member-local. A busy member dedups a governance
  buffer event; a quiet member double-counts it. => WarningCount differs by 1 across honest
  members at a threshold boundary => one mints durable ConsequenceTriggered leaf, other
  doesn't => divergent roots at equal durable count => FALSE-POSITIVE EquivocationDetected
  (queries_helpers.rs:802 Equal-count+diff-root) against an honest member + divergent
  suspension state. Verified numerically.

## CRITICAL — WASM vs native durable-log divergence (BLACK-EL02)
- WASM `GovernanceActionExecuted` payload = `proposal_id.as_bytes()` (manager.rs:2738).
  Native payload = MessagePack `GovernanceActionExecutedPayload{target_did,action_type}`
  (governance_helpers.rs:3671). Different leaf hashes => native+WASM members NEVER converge
  on any context with a governance action.
- WASM `WasmConsequenceDispatcher` (consequence.rs:283) appends NO durable consequence leaf;
  native mints durable ConsequenceTriggered/Enforced (gated). More divergence.
- Cross-impl test (wasm_conformance.rs) is VACUOUS: appends identical hand-crafted leaves to
  two MerkleEventLogProviders via a shared helper; never drives the real WASM manager.rs vs
  native governance_helpers.rs append paths. Proves substrate determinism (never in doubt),
  not implementation parity.

## HIGH — Unbounded payment_receipts Vec DoS (BLACK-EL03)
- `PerContextState.payment_receipts: Vec<PaymentReceipt>` (actor/state.rs:826) pushed on every
  live paid capture (economy_helpers.rs:238, via capture_send_payment messaging_helpers.rs:1591).
  NO cap, NO eviction. receive_buffer is capped 1000 (membership.rs:31); this isn't.
  PaymentReceipt is heavy (2 DIDs + adapter_proof Vec<u8> attacker-sized + 64B sig). Grows for
  context lifetime. Also duplicates the durable store/economy.rs ReceiptStore in RAM.

## MEDIUM — ToolRateExceeded consequence rule is dead (BLACK-EL04)
- matches_trigger ToolRateExceeded requires EventType::ToolInvoked (consequence.rs:879).
  No durable ToolInvoked leaf (removed) AND no ContextEvent::ToolInvoked variant EXISTS, so
  Source 2 never yields one. Rule can never fire. (Native: pre-existing — never had prod
  ToolInvoked durable append. WASM: this commit removed its append => WASM regression that
  brings it to native parity.) Tool flooding still throttled by independent hard_rate_limit.

## anchored field — currently inert (truth-in-advertising landmine)
- PaymentReceipt.anchored UNSIGNED (adapter.rs:279). NO production consumer reads it
  (requires_merkle_proven is test-only). Flipping it in transit has no victim TODAY. Receipt
  `signature` field also never verified on runtime path (verify goes through adapter_proof).
  Landmine for ADR-051 consumers. tool_invocation_count_anchored IS in signed preimage
  (participation.rs:556) — correctly bound, cannot be transplanted/stripped. SOUND.

## Resists attack
- Static convergence (identical durable stream => identical root): sound, RFC-6962.
- Durability gate keyed on enum not string: sound.
- Per-author exclusion of MessageSent/PaymentReceived from durable log: correct premise.
- Equivocation detector ct_eq + Equal-count gating: correct mechanism.
