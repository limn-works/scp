---
name: eventlog-convergence-waveB
description: Wave A/B event-log convergence review — PaymentReceived + per-author leaf exclusion, participation anchored preimage byte, WASM consequence merge. SOUND.
metadata:
  type: project
---

# Event-Log Convergence Wave A/B (commits 217d14ac6 / b3d354279 / 3e667ef48), reviewed 2026-06-19

ADR-051 §6 / phase-2.md ADR-011 amendment exclusion taxonomy §2: a durable RFC-6962 Merkle leaf is convergent iff its trigger input is convergent. Per-author application events (MessageSent, ToolInvoked, per-payee PaymentReceived) excluded from the durable log so two honest members derive equal tree::root (§9.9.3 equivocation detection).

**Why:** native runtime event log was unified onto scp_event_log RFC-6962 substrate; per-author leaves broke cross-member root equality.
**How to apply:** any future "add a durable leaf" for a per-author/per-receiver event is a convergence BUG — surface it as a local ContextEvent + buffer instead.

## Verdict: SOUND, no blocking findings.

### Participation preimage (participation.rs:536 signable_bytes)
- New `tool_invocation_count_anchored: bool` folded into SCP-PARTICIPATION-V1 preimage as `buf.push(u8::from(bool))` (0/1, deterministic) right after tool_invocation_count u64.
- UNAMBIGUOUS: all fields fixed-width except DID (u32-length-prefixed at front). One byte after a u64 cannot collide with a field boundary. Capacity `64 + 1 + 64` correct (8 u64 + 1 byte + 2×32).
- Keeping V1 separator (not bumping) is CORRECT: pre-release, no deployed signers, no backcompat.
- Signature binding VERIFIED: signature_binds_tool_invocation_count_anchored test flips bit without re-signing → verify_strict fails. PASSES.
- Spec 07 §7.3.2.1 line 214 defines the struct field; spec defines no byte-level preimage, signable_bytes is canonical impl covering all-fields-except-signature per spec. Artifact-flow clean.

### PaymentReceipt.anchored (adapter.rs:267)
- anchored CORRECTLY EXCLUDED from signing preimage. Spec §19.6 signed_payload ends at `timestamp` (verified .docs/specs/19 ~line 466). NO in-repo PaymentReceipt signing-preimage byte construction exists — payer signs externally, verification delegates to adapter.verify(). So adding the field could not have perturbed signing scope.
- Consumers requiring Merkle-proven provenance MUST reject anchored==false (test enforces).

### Convergence / Merkle
- complete_paid_action: removed durable EventType::PaymentReceived append + checkpoint_events_since increment; now local ContextEvent + PerContextState.payment_receipts buffer. event_count == durable leaf count preserved (test asserts checkpoint_events_since stays 0).
- payment_history reads local buffer (not durable log). Old Event-scanning signature replaced; all callers updated.
- WASM manager.rs: removed MessageSent (send + broadcast) and ToolInvoked durable appends. invoke_tool lost now-unused identity_did param (sole caller tools.rs updated).
- 4 native + 2 cross-impl convergence tests PASS incl. non-vacuity negative controls (per-payee/per-author leaves WOULD diverge roots).

### WASM merged_consequence_events (consequence.rs:227) — KEY SOUNDNESS POINT
- Reads durable log + receive buffer for velocity/tool-rate evaluation. Faithful byte-for-byte port of native event_log_entries_for_consequences (same constants 3600/5/100, same skip-covered→future→stale→cap→increment→push order, same Source-1 projection arms, same Source-2 buffer arms).
- NO SOUNDNESS GAP: WASM consequence dispatcher uses push_event_pub (RECEIVE BUFFER / local ContextEvent), NEVER append_log_event. So the now_secs-estimated-timestamp non-determinism in merged_consequence_events feeds only local evaluation/enforcement — it NEVER feeds a durable Merkle leaf. Convergent consequence leaves (gated on is_convergent_trigger) are unaffected; velocity/tool-rate are non-convergent → no durable leaf in either impl.
- No double-counting: WASM never pushes MessageReceived to buffer (MessageReceived arm is dead-but-harmless defensive). No ContextEvent::ToolInvoked variant exists anywhere → tool-rate dormant equally in both impls (pre-existing parity, not a regression).

### Tests run & passing (2026-06-19)
- scp-protocol: signable_bytes_changes_*, signature_binds_* (2 pass)
- scp-runtime eventlog_convergence: 4 pass; wasm_conformance converge (--features testing): 2 pass
- scp-ffi-wasm dispatch_velocity_fires_from_receive_buffer_not_durable_log: pass
- complete_paid_action_buffers_receipt_and_mints_no_durable_leaf, receipt_anchored_round_trips: pass
