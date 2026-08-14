# #1533 Heartbeat-loop fix commits review (feat/1533-heartbeat-loop)

Commits 6b0e860f6, e194a97fa, a8cd2281e, a2f1b2b1f. Reviewed 2026-06-17. VERDICT: no real defects found.

## What was verified
- **napi context_subscribe_on teardown** (context.rs:1632): `cancel_token.cancel()` runs unconditionally after the loop; all 4 break paths (cancel/bridge_cancel/stream None/Terminated) reach it; early `return`s before scheduler spawn need no teardown. Re-subscribe swaps `*guard = CancellationToken::new()` (T2) and clones it for both loop+scheduler; old loop's captured clone is T1, so old `cancel()` can't touch T2. `subscription_active` AtomicBool prevents concurrent double-subscribe (flag resets only when prior task exits). cancel() is idempotent → no double-cancel panic.
- **scheduler_loop extraction** (heartbeat_scheduler.rs): generic `scheduler_loop<F,Fut>` preserves first-immediate-tick consume + select! cancel/bridge arms + best-effort error log. Signing key wrapped in Arc once (refcount clones per tick, not secret-scalar copies). tokio::time::interval Burst behavior unchanged from inline. No behavior change.
- **send_heartbeat auth gates** (messaging_helpers.rs:1426): require_active + MessagesWrite mirror send_message EXACTLY (broadcast skip via broadcast_context.is_none(); suspended-vs-absent split via suspended_capabilities). Gates BEFORE encrypt_and_send (no partial update). Correctly omits economy/velocity/rate-limit (heartbeat is control msg, &PerContextState immutable, sequence 0). Handler sync, forwards result verbatim, reply best-effort; dropped channel → TransportFailed → scheduler debug-logs, continues.
- **Uniform 240s threshold** (heartbeat.rs for_profile): Server/Desktop 60s×4.0=240, Mobile 120s×2.0=240. debug_assert holds for both reachable profiles; Constrained returns None before assert. Receive-side monitor built from for_profile → 240s. Cross-peer safety now via uniform receiver threshold (not matching intervals). suppression test 5×61s=305s>240s correct.
- **Application-arm liveness touch** (context.rs:1549 record_heartbeat_received on DeliverOutcome::Application): just sets last_received=now (idempotent, no counter → no double-count). One tokio::sync::Mutex acquire per app msg, uncontended, negligible vs decrypt. No perf problem.

## Non-defects noted (acceptable / pre-existing)
- After context close (not unsubscribe), scheduler keeps ticking; every tick fails require_active → Err logged at debug. No false liveness (fail-closed). Pre-existing subscribe-loop-survives-close design, not new.
