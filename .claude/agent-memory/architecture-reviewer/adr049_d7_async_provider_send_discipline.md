---
name: adr049-d7-async-provider-send-discipline
description: ADR-049 Decision 7 async-provider conversion — the sync-fn-returning-Send-future persist pattern PR-2/PR-3 must replicate
metadata:
  type: project
---

ADR-049 Decision 7 converts provider traits (`ContextPersistence`, `EventLogPersistence`, transport) from sync to `#[async_trait]`, deleting the `block_in_place`+`Handle::block_on` sync→async bridges. PR-1 (branch `chore/adr049-d7-context-persistence`, ContextPersistence) established the canonical resolution to the hard part the ADR text does NOT mention.

**The problem:** `PerContextState` is `Send + !Sync` (holds a `dyn FnMut` event-emit sink). A `&PerContextState` held across an `.await` yields a `!Send` future → fails `tokio::spawn` (the actor's `run()` future is spawned via `ActorDeps` moved by value). Once persistence is `.await`ed, any helper that both borrows `&PerContextState` and awaits the persist is `!Send`.

**The resolution (the PATTERN PR-2/3 MUST replicate):** persist terminals are **sync fns returning `impl Future<Output=…> + Send + use<'d,'c>`**, NOT `async fn`. The `&PerContextState` is consumed in a synchronous prelude (`build_snapshot_for_persist` → owned `ContextSnapshot`) and the returned `async move` captures only owned Send data + `deps`/`context_id` refs. The `use<'d,'c>` precise-capture bound (edition 2024) is LOAD-BEARING — it excludes the `state` lifetime from the returned future. See `messaging_helpers.rs`: `persist_state_fail_closed`, `persist_state_best_effort`, new split-out genuine-async terminal `persist_snapshot_fail_closed(&ContextSnapshot,…)`. Combinators (`ClassSCell::commit_class_s_keep` etc.) CAN stay plain `async fn(&mut self)` because the `&self.state`→snapshot conversion happens at future-CONSTRUCTION time (sync), dropping the shared borrow before the await; `&mut self` across await is fine (only needs Send, not Sync). Token terminals (`ClassSCommitToken::commit`) use the sync-fn-returns-future shape because they're called with shared `&*cell` where no `&mut` escape exists (`ClassSCell` has no `DerefMut`).

**Handler-level variant:** where a handler's persist is a genuine async terminal (e.g. `saga.rs::emit_divergence_marker`), the CALLER builds the snapshot holding its `&mut ClassSCell` and passes the owned snapshot + `Copy` `[u8;32]` context_id in — same discipline hoisted to the call site. Behaviour-preserving because the event-log append targets `deps.event_log`, independent of `state`.

**Send vs !Send asymmetry:** `ContextPersistence` is plain `#[async_trait]` (Send futures) because held in `ActorDeps` moved into `tokio::spawn`. Contrast `RecoveryBackend` (PR-0) = `#[async_trait(?Send)]` (never crosses a spawn). PR-2/3 must classify each trait the same way.

**Documentation GAP (my finding):** this pattern lives ONLY in in-code doc comments. ADR-049 Decision 7 says merely "async via #[async_trait]" — nothing about the `!Send` borrow problem or sync-prelude resolution. PR-2/3 authors reading the ADR will rediscover it via compile errors, or worse reach for a divergent fix (`?Send`, or Mutex-wrapping the sink — which violates Decision 12). Recommended: amend ADR-049 Decision 7 or add a lessons doc so replication is deliberate. See [[eventlog-unification-adr011]] for the EventLog side PR-2 touches.

**Ratchet:** `ratchet/block-in-place-count.json` store/context.rs 20→8, scp-runtime aggregate 34→22 (builds on PR-0's 36→34). NOTE the `_breakdown` prose says "removing 4 block_in_place + 4 block_on" (=−8) but the per-file baseline moved −12 (20→8) — raw grep confirms only −8 sites; the extra −4 is script-counted macro-wrapper/Runtime sites the prose omits. Gate is per-file "must-not-increase" (tightening the baseline is safe; a too-tight baseline fails CI, never slips through), so no risk — but the prose arithmetic should be reconciled.
