# Event-Log Convergence Change (Wave A/B, HEAD bfa5baf73)

Reviewed the convergence refactor: per-author events (MessageSent/ToolInvoked/PaymentReceived)
excluded from durable Merkle log; durable consequence leaves derive from convergent source only;
WASM made byte-identical to native for governance/token-revoke/consequence leaves; payment_receipts
became bounded VecDeque (cap DEFAULT_BUFFER_CAPACITY, oldest-evicted); payment_history generalized
to IntoIterator.

## Verdict: NO bugs found. All bug classes checked clean.

- **VecDeque eviction**: correct (`len() >= cap` → pop_front → push_back; never exceeds cap; no
  panic on empty; VecDeque iter is front-to-back = oldest-to-newest, no as_slices/make_contiguous needed).
- **enforce_triggered hook + WASM dispatcher**: native uses its OWN `enforce_triggered_consequences`
  (governance_logic.rs), NOT protocol's `enforce_triggered`. WASM uses `enforce_triggered`. No double-mint
  (native's default trait body is no-op). H4 ordering (leaf-before-push) honored in both. Per-branch
  EventType correct (Triggered/Enforced/EnforcementFailed/EscalatedToSuspendAll). Durability gate keyed
  on `is_convergent_trigger` (enum, not string) — WarningCount/Custom durable, MessageVelocity/ToolRateExceeded not.
- **WASM byte-parity producers**: GovernanceActionExecuted (target_did via action.target_did().unwrap_or_default(),
  action_type via variant_name() — identical to native finalize_governance_action), TokenRevoked (shared
  token_revoked_payload, identical arg order), consequence (shared consequence_event_payload). Cross-impl
  fixtures in wasm_conformance.rs match WASM expected bytes EXACTLY. Both JSON producers use serde_json::json!
  → BTreeMap → sorted keys (deterministic, no preserve_order feature).
- **EL01 source-split**: native + WASM both source convergent events ONLY from Source 1 (durable log),
  MessageSent ONLY from Source 2 (buffer). Buffer match omits convergent variants (fall to `_ => continue`).
  This is the actual convergence fix — prevents double-count on quiet members / skip on busy members.
- **IntoIterator change**: all callers pass &VecDeque / &Vec / &[] — all impl IntoIterator<Item=&T>. Compiles, tests pass.
- **complete_paid_action payer_did removal**: now derives payer from receipt.payer (was sender_did passed
  as payer; in send_message sender==payer so semantically identical and more accurate).
- **PaymentReceipt.anchored field**: NOT in any signature preimage (verification delegates to adapter.verify(),
  no whole-struct signing). Doc honestly flags it as unsigned/untrusted wire field. All construction sites set it.
- **PseudonymAnnounced EventType removal**: tag 59 retired (gap left, tags stable). No remaining
  EventType::PseudonymAnnounced refs (only ContextEvent::PseudonymAnnounced, intended local buffer surface).
  Pre-release so serde-variant removal is fine.
- **PaymentReceived ContextEvent variant added**: state.rs match is exhaustive (compiler-checked). PyO3
  convert_context_event has wildcard `other =>` Debug-formatting to scp:system message (same as PaymentCaptureFailed,
  pre-existing convention — NOT a new bug). payment_history reads state.payment_receipts, not this channel.

## Tests run (all pass)
- scp-protocol trust::consequence (48 passed)
- scp-runtime eventlog_convergence (4 passed, incl payment-capture convergence + negative controls)
- scp-runtime economy::receipt (30 passed)
- cargo check -p scp-event-log -p scp-protocol -p scp-runtime: clean

## Note (pre-existing, NOT introduced here, design assumption)
Durable consequence leaf payload includes `rule_index` into the member-local consequence_rules() vector.
Convergence requires identical rule ordering across members. Rules are context config (convergent), so this
holds by design — but if rule ordering ever diverges, leaves diverge → false equivocation. Worth tracking
if rule mutation is added.
