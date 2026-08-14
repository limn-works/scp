# §6.2.4 Cross-Context Tool Invocation Saga — black-hat audit (branch §6.2.4, HEAD 2b1894e28)

Change = `git diff origin/main..HEAD`. Core files:
- `crates/scp-protocol/src/context/tools/cross_context_saga.rs` — signed receipt + divergence marker (SOLID: length-prefixed §9.5.1 preimage, signer-auth required as input, splice tests present).
- `crates/scp-runtime/src/context/actor/handlers/saga.rs` — Prepare-A/B, Commit-B settle, Commit-A, abort, divergence marker.
- `crates/scp-runtime/src/context/supervisor/supervisor.rs` — FSM, commit_with_retry (B then A), crash recovery (redrive_xctx_commit_in_progress + witness reack), NeedsRepair escrow-held.

## What RESISTS attack (verified sound)
- Receipt forgery: production Commit-A verifies B's sig against `ctx.target_signing_key` BEFORE settle (verify_commit_b_receipt, supervisor ~6058). Preimage length-prefixed (no splice). Signer-authorization is a required input, not receipt-named.
- Confused deputy (stronger UCAN to different principal): validate_ucan_rebind binds presenting_agent_did = caller_did → AudienceMismatch reject (saga.rs ~713).
- Confused deputy (generation-blind rollback into respawned instance): commit_a + abort use `rollback_tool_economy_generation_checked` (saga.rs 1368, 1480).
- Replay same nonce (default config): B-owned xctx_nonce_dedup, Class-S persisted+rehydrated across crash (from_entries_with_ttl). TTL=600s strictly > skew 300s (coterminous-gap BLACK-XCTX-01 closed) on PRODUCTION path (lifecycle_helpers 1269/1850/2295 use with_ttl(SAGA_NONCE_DEDUP_TTL_SECS)).
- Double ToolInvoked (B side): capture+persist ordered BEFORE non-idempotent event-log append, compensating re-persist on append failure (saga.rs ~1175-1252). Exactly-once.
- Crash Commit-in-progress: B replay = AlreadyCommitted (no re-invoke); A reack from durable witness; both committed ⇒ Committed, else NeedsRepair + supervisor repair record.
- NeedsRepair escrow: held (hold_external_for_repair), not auto-voided; concurrency slot released. At-initiation budget non-refundable.

## FINDINGS

### BLACK-XCTX-10 (HIGH) — eviction-replay window at legal-but-high inbound rate; no config gate
Spec §6.2.4 "Sizing relative to the configured ceiling (normative)" requires dedup capacity hold every nonce admissible within TTL at MAX configured inbound rate ×2. NOT mechanically enforced.
- Cache cap = NONCE_DEDUP_CAPACITY 10_000 (fixed). Saga TTL = 600s (10 min).
- §6.2.0.2 configurable per-interface max = 6000/min (range [1,6000]); per-caller max = 1000/min.
- 6000/min × 10 min = 60_000 nonces = 6× capacity → oldest-first eviction drops still-within-TTL victim nonce → replay under fresh SagaId + re-asserted fresh timestamp_ms passes BOTH freshness + dedup ⇒ double-execution of a side-effecting/token-minting tool.
- `accept_tool_interface` (interface.rs ~850) applies default only when None; NO upper-bound clamp on inbound max_calls_per_minute.
- `MAX_SAFE_INBOUND_CALLS_PER_MINUTE = 500` lives ONLY in saga.rs test module (~1659), referenced by no production validation. Test `nonce_dedup_replay_bound_holds` asserts a CONSTANT is safe, not the configurable ceiling.
- Per-caller self-replay: attacker IS the channel-authed caller, so the "caller_did mismatch" fallback gate does NOT stop self-replay; only the budget-below-capacity relationship foreclosed it, and that's the broken invariant.
- Fix: clamp/validate InboundPolicy.max_calls_per_minute at accept_tool_interface against a capacity-derived ceiling (mechanical), OR scale NONCE_DEDUP_CAPACITY to 2× max-rate×TTL.

### BLACK-XCTX-11 (MEDIUM) — Commit-A append-before-persist = orphan provenance / silent one-sided A-record
`commit_a` (saga.rs ~1406) appends `CrossContextToolInvoked` to the (separate, NON-idempotent, independently-durable) event log BEFORE inserting witness + persist_state_fail_closed (~1420). This is the EXACT inverse of the B-side ordering, whose own comment (~1175) documents WHY append-first is wrong.
- If the post-append Class-S persist fails: witness rolled back (1422), but the `CrossContextToolInvoked` entry is already durable.
- FSM retry → witness absent → commit_a_reack_from_witness → SCP-SAGA-13059 → NeedsRepair.
- divergence_marker_plan (supervisor ~6522) keys ONLY off committed_b_tool_invoked_event_id; an A-side orphan with B-not-committed yields plan None ⇒ "logs are clean, no marker" — but A's log has an orphan committed-call record B's log denies. Silent one-sided repudiation primitive in the reverse (A-without-B) direction the code doesn't model.
- Fix: mirror B-side ordering — insert witness + persist BEFORE the event-log append; on append failure roll back witness + re-persist (compensating), same pattern as commit_b_first_settle.

### BLACK-XCTX-12 (LOW) — doc/test TTL drift
- actor/state.rs ~1027 doc says replay guarantee holds at "NONCE_EXPIRY_SECS, 300 s" but production cache TTL is SAGA_NONCE_DEDUP_TTL_SECS=600s; cache-eviction-bound prose uses wrong window.
- new_for_test_encrypted/_with_mode (actor/state.rs 1256) builds xctx_nonce_dedup with NonceDedup::new() = 300s default, NOT the production 600s. Test fixtures diverge from prod TTL → tests relying on this fixture can't catch a coterminous-window regression. (Test-only; pub fn but only test callers.)
