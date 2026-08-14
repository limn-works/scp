---
name: adr049-chunk3-outlet-streaming
description: ADR-049/061 chunk-3 outlet-streaming actor integration review (reserve→pump→settle onto main's actor/supervisor) @ scp-wt-streaming 355f50a8c~1..c166ba953 — APPROVED w/ 2 MED
metadata:
  type: project
---

# Chunk-3 outlet-streaming actor integration (open_outlet_stream) @ scp-wt-streaming c166ba953

Re-implements the reference `ContextManager::open_outlet_stream` onto main's actor/supervisor. 3591 LOC / 5 sub-chunks (3a reserve seam, 3b counter adapter, 3c settlement sinks, 3d pump semaphore+admission registry, 3e orchestrator). Files: outlets_helpers.rs (reserve_outlet_stream_economy / settle_outlet_stream / reverse_stream_escrow / build_stream_post_input_hook / reserve_error_to_open_rejection), actor/commands.rs (+5 OutletsCommand variants), handlers/outlets.rs (+5 handlers), supervisor.rs (open_outlet_stream orchestrator + 3 via_actor wrappers + pump semaphore + admission registry), outlets/stream_counter_adapter.rs, outlets/stream_settlement_adapter.rs.

## VERDICT: APPROVED (architecturally sound) w/ 2 MED + 2 LOW. Verdict pre-transport-chunk.

## VERIFIED SOUND
- ADR-049 §3: executor (`Arc<E: OutletExecutor + ?Sized>`) runs ONLY in off-mailbox `dispatch::open_stream_session`; NEVER crosses mailbox. All 5 OutletsCommand payloads Send (DIDs/Amounts/strings/CaveatKind/Box<StreamSettlement>/generation/oneshot). Confirmed.
- reserve→pump→settle: reserve DEBITS reserved_escrow up-front (not check) → serial mailbox makes check-and-debit atomic, NO TOCTOU (the 2-concurrent-opens race the reference closed w/ arc.lock() can't occur on mailbox). Off-mailbox pump bills local billed_count against reserved ceiling; only ONE counter-reserve mailbox round-trip at pump Step 5.5 (R4 HIGH-2 ordering preserved). Settle refunds reserved−billed.
- Seam adapters hold Arc<Supervisor> but route via dispatch_outlets_command / typed via_actor wrappers (NOT reaching into internals) — identical to unary reserve_outlet_economy_via_actor. 5 cmds/handlers fit 1:1 variant→handler cleanly; standing not-registered arms + outlets_command_context_id extractor updated (dropped const for boxed StreamSettlement deref).
- CaveatCounterApi over actor-owned Class-S via commit_class_s_keep (durable §9 snapshot) — NOT the rejected repository store. Preserves value-caveat slice model. Seam justified (off-mailbox pump genuinely needs type-erased seam). clone-then-try_consume-then-insert-under-commit; reject touches nothing/no persist.
- Admission registry teardown: reap_stream_admission mirrors remove_context_floors 1:1 at ALL 4 permanent sites (supervisor.rs discard, lifecycle_helpers shutdown_all, ttl_close handle_ttl_expiry+finalize_close); NOT on transient despawn → survives respawn. Drops only registry Arc; in-flight pump's own Arc clone keeps tracker alive. Sound (twin of reviewed floor-registry pattern).
- ActorEscrowRefundSink captures tokio::runtime::Handle at CONSTRUCTION (not Handle::current() in Drop) — avoids off-runtime Drop panic. Generation captured in sink struct not payload.
- Reserve rollback discipline matches unary send path (rollback on non-member/overflow/insufficient/persist-fail).

## FINDINGS
- MED-1 base_sequence hazard: reserve allocates base_sequence via next_sequence_number (ADVANCES per-sender MLS send-seq, persisted) but open_outlet_stream NEVER reads it (discarded) and does NOT roll it back on post-reserve open_stream_session rejection — ASYMMETRIC with StreamEscrowTicket Drop-guard which DOES reverse escrow on same path. membership.rs:212 rollback_sequence_number doc: "so the sequence is not permanently burned on failure." Receive-side SequenceCheck::Ahead (messaging_helpers.rs:1561) STALLS reorder buffer on gap until timeout. So burned seq = receiver liveness degradation once transport wired. Latent (open_outlet_stream not FFI-reachable this chunk). Fix: defer base_sequence alloc to transport send (on-mailbox, consumed atomically) OR add seq-rollback guard symmetric w/ escrow ticket. EXPENSIVE-TO-REVERSE: reservation public shape + seq-authority-B-at-reserve decision.
- MED-2 H8 capture inconsistency: settle_outlet_stream generation-mismatch (respawn mid-stream) returns Dropped BEFORE reading capture_policy → skips §19.15.5 PaymentReceipt capture entirely. But no-actor fallback (settle_outlet_stream_via_actor, lookup None) DELIBERATELY captures against open-time snapshot for same "service rendered" H8 reason. Payment adapter is supervisor-level + snapshot available on mismatch too → capture SHOULD run (request_id idempotent, correct to skip only the state release/refund). Revenue leak on respawn-mid-stream. Fix: on mismatch skip release/refund but still capture vs snapshot.
- LOW-1 narrow TOCTOU: settle_outlet_stream_via_actor lookup()=Some then actor despawned before dispatch → standing SettleOutletStream arm replies Err(ContextNotRegistered), no capture. Same H8 class, narrow window.
- LOW-2 dead code: SupervisorHandle::reap_stream_admission (handle.rs:238) defined-but-uncalled, mirrors (also uncalled) SupervisorHandle::remove_context_floors. Consistent parity but dead.
