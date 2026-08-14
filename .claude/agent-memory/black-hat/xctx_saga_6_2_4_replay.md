# §6.2.4 Cross-Context Tool Invocation Saga — black-hat review (branch xctx, HEAD 73010c2a9)

## BLACK-XCTX-01 (HIGH/CRITICAL): nonce-TTL == skew-tolerance ⇒ unbounded envelope replay
- `validate_freshness` (saga.rs:879-907) checks `now.abs_diff(asserted_timestamp_ms) > skew` ⇒ reject.
  `asserted_timestamp_ms` is ATTACKER-CONTROLLED and bound to NOTHING (not signed, not nonce,
  not journal — only this one freshness check uses it; confirmed grep). Attacker asserts "now" ⇒
  freshness ALWAYS passes.
- The ONLY persistent replay gate is `xctx_nonce_dedup` (the 16-byte nonce, the dedup key + signed
  receipt field). `NonceDedup::is_replayed` prunes entries at `now-seen >= NONCE_EXPIRY_SECS=300`.
- `DEFAULT_CLOCK_SKEW_TOLERANCE_SECS = 300` == `NONCE_EXPIRY_SECS = 300` (coterminous, no margin).
- EXPLOIT: capture a `CrossContextToolInvoke` envelope; wait 300s for B's nonce entry to expire;
  replay verbatim with `timestamp_ms` bumped to now ⇒ Prepare-B re-accepts under a fresh SagaId ⇒
  tool re-executes, caller re-charged, second receipt signed. Repeat every 5 min, forever, from one
  capture. "Exactly-once execution" is really "exactly-once per SagaId / per 5-min window."
- ROOT CAUSE: freshness window must be < nonce-TTL for the nonce to cover every fresh timestamp;
  with timestamp unbound, freshness gives no replay bound at all. Fix options: (a) bind
  asserted_timestamp into the dedup key or require the nonce-TTL strictly > skew AND check the
  asserted timestamp against the FIRST-seen time, not just now; (b) make the nonce dedup permanent
  per (caller,target,tool) within a saga-lifetime, not TTL'd; (c) sign/commit the timestamp so a
  replay can't refresh it. Spec §6.2.4 leans on nonce-dedup AS the anti-replay primitive but it is
  only a 5-min freshness cache.
- PROOF: /tmp/rb3.rs — replay_OK=true at t0+300, t0+600, t0+100000 with asserted=now.

## What RESISTS attack (verified sound)
- Receipt signed types (cross_context_saga.rs): §9.5.1 length-prefixed preimage, verify_strict,
  signer-authorization is a REQUIRED key param (not receipt-named). Splice/tamper tests present.
- Confused-deputy: validate_ucan step 5 enforces token.aud == presenting_agent_did(=caller_did)
  (validate.rs:551); chain parent.aud==child.iss (863). Proof delegated to other principal ⇒
  AudienceMismatch. Re-bound to caller_did + tool_registration_id + target ctx hex.
- Crash-survival: xctx_nonce_dedup, xctx_committed_outputs, xctx_committed_invocations are Class-S
  persisted (messaging_helpers.rs:2124-2126) AND rehydrated on same-node restore
  (lifecycle_helpers.rs:2289-2299); cross-node import/export DROP to empty. BLACK-624-01 closed.
- Exactly-once: Commit-B durably captures output keyed by SagaId; replay re-emits stored bytes,
  never re-invokes; ToolInvoked append SagaId-idempotent (event_id = "ToolInvoked:{saga_id}").
- Double-settle: commit_a idempotent on xctx_committed_invocations; send_recover_on_failure
  reserves permit BEFORE building cmd ⇒ recovered-command path provably never-delivered; lost-ack
  path re-acks from durable witness (CommitACheckWitness). No double-settle.
- Divergence committed_side hardcoded Target is SOUND: A only commits after B (B-then-A ordering),
  so committed_b_tool_invoked_event_id is always Some when A could have committed; Caller-only
  commit is structurally impossible (in-process AND recovery via redrive_commit_a_witness).
- NeedsRepair: concurrency slot released, escrow HELD via hold_external_for_repair (not auto-voided
  = no free-execution); initiation budget non-refundable on every terminal incl NeedsRepair.
- Authorize-before-reserve: caller axis (is_member) + target axis (has_established_tool_interface)
  both run BEFORE try_reserve_context_set ⇒ victim-context wedge foreclosed (BLACK-624-02 closed).
- Target-context binding: prepare_b check 4 (req.target_context_id == state.context_id) before
  staging; receipt signs prepared.target_context_id.

## Residual (defense-in-depth, not exploits)
- commit_b_first_settle signs over prepared.target_context_id WITHOUT re-asserting it == state.context_id
  at settle time (relies on Prepare-B check 4 + slot being context-local). Sound today; add an assert.
- Supervisor verify_commit_b_receipt verifies against the SAME key it passed to Commit-B (circular,
  spec-acknowledged). Real authorization is at the receipt CONSUMER resolving the authorized key.
