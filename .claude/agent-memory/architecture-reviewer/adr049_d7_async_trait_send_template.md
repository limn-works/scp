---
name: adr049-d7-async-trait-send-template
description: ADR-049 Decision-7 async-provider-trait conversion — the Send vs ?Send per-trait rule that governs PR-0 (RecoveryBackend) through PR-3 (transport)
metadata:
  type: project
---

# ADR-049 Decision 7 — async provider traits, `block_in_place` deleted (PR-0 → PR-3)

ADR-049 §Decision 7 (`.docs/adrs/ADR-049-actor-per-context.md:151-155`) converts all remaining
provider traits to `#[async_trait]` (dyn-compatible; RPITIT rejected as non-dyn-safe) and deletes
`block_in_place` sites. Retained exemptions ONLY: OpenMLS-storage-adapter (sync upstream) + FFI sync
boundaries (ADR line 273-274). Rolled out as a sequence of PRs, each converting one trait family; PR-0
(`RecoveryBackend`, branch chore/adr049-d7-recovery-backend, tip 73d1645e1) is the TEMPLATE.

## The load-bearing rule: Send vs ?Send is decided PER-TRAIT, not copied

**Do NOT blanket-copy PR-0's `#[async_trait(?Send)]`.** The Send-ness of each converted trait is
determined mechanically by: *does a `tokio::spawn`ed future await this trait's methods?*

- **`RecoveryBackend` = `?Send` (correct, special case):** no `Send+Sync` supertrait
  (recovery.rs:327); consumed as borrowed `&dyn RecoveryBackend` (recovery.rs:490); `execute_recovery`
  driven ONLY via `runtime().block_on(...)` at FFI entrypoints (napi scp.rs:1218, uniffi, pyo3
  identity.rs) — `block_on` imposes no Send. Never spawned. So `?Send` is right and is documented in
  the trait doc comment. Kept `#[allow(clippy::future_not_send)]` on execute_recovery.

- **Every OTHER Decision-7 trait = plain `#[async_trait]` (Send REQUIRED):**
  `ContextPersistence` (persistence.rs:31), `ContextEventLogProvider`/`ContextTransportProvider`
  (builder.rs:125/31), `EventLogPersistence` (event_log.rs:126), `RelayPersistence`
  (relay_persistence.rs:38) — ALL have `Send + Sync` supertraits and are held as `Arc<dyn …>` OWNED
  inside `ActorDeps` (deps.rs:144-148), which is moved BY VALUE into `tokio::spawn(actor.run())`
  (deps.rs:121 doc; spawn sites actor/mod.rs:1447/1465/1482/1501/1893). `tokio::spawn` requires
  `Send + 'static`. Once async, their methods are awaited inside the spawned `actor.run()` future ⇒
  futures MUST be Send ⇒ plain `#[async_trait]`. Copying `?Send` there makes `actor.run()` non-Send
  and FAILS to compile at `tokio::spawn` — or forces an architectural regression to `ActorDeps`.

The resulting `RecoveryBackend`-is-`?Send`-while-siblings-are-Send asymmetry is DELIBERATE and CORRECT.
Call it out in each downstream PR so no one "harmonizes" it.

## PR-0 verdict: APPROVED. Verified sound:
- Ratchet: recovery.rs 2→0, scp-runtime 36→34 (delta −2 = 1 block_in_place + 1 block_on in the deleted
  `block_on_async` bridge). Only residual block_on strings in recovery.rs are doc comments. No other
  file changed. `dispatch_step_error` replaces block_on_async as pure error-shaper (by-value for
  map_err fn-ptr, allow(needless_pass_by_value) justified). Removed allow(unused_async) correct (now
  genuinely awaits).
- Pre-existing OBS (not introduced): ratchet `crates.scp-runtime`=34 ≠ sum of `files` map (28); the
  6-count `tools_helpers`/`_legacy` breakdown entry lives in `_breakdown` prose, not the enforced
  `files` map. Enforcement is per-file, so harmless. Predates PR-0.
- All 6 impl sites converted (Production + 5 mocks incl 3 FFI bridge stubs + scp-testing integration).
