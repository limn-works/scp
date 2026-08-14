---
name: adr049-d7-recovery-backend
description: ADR-049 Decision-7 PR-0 — RecoveryBackend async-trait conversion review (CLEAN)
metadata:
  type: project
---

# ADR-049 D7 PR-0: RecoveryBackend → async trait (branch chore/adr049-d7-recovery-backend @73d1645e1 vs origin/main 1387f8867)

**CLEAN — no defects.** Reviewed 2026-07-07.

Change: `RecoveryBackend` trait → `#[async_trait(?Send)]`; deleted `block_on_async` helper (block_in_place+Handle::block_on bridge) in identity/recovery.rs; 6 former call sites now `.await` directly; new `dispatch_step_error(ContextError)->RecoveryStepError` replaces the bridge's error-shape conversion.

Verified:
- **Error-shape equivalence exact:** old `block_on_async` = `fut.await.map_err(|e| RecoveryStepError{step:0, description:e.to_string()})`. New `fut.await.map_err(Self::dispatch_step_error)` = identical. Per-caller `Err(mut e)=>{e.step=N}` step-overrides preserved unchanged (mls_update step 2 + "requires rejoin" Tier-3 branch intact).
- **psk logic:** `is_some_and(|p| rotate_psk(p))` → `match psk_params {Some=>...await, None=>false}` — semantically identical.
- **`?Send` correct:** all 6 impls (Production, MockRecoveryBackend, integration MockBackend, Ffi/Napi/Uniffi) carry matching `#[async_trait(?Send)]` — no Send/`?Send` mismatch. `backend:&dyn RecoveryBackend`; execute_recovery keeps `#[allow(clippy::future_not_send)]`; removed stale `#[allow(clippy::unused_async)]` (now has real await points).
- **No caller requires Send:** all 3 FFI entrypoints drive via `rt.block_on(orchestrator.execute_recovery(...))` (napi crate::runtime, pyo3 rt, uniffi crate::runtime) — no `tokio::spawn`. block_on drives !Send future on current thread = fine. Removing the nested block_in_place actually removes a latent panic risk (block_in_place inside current-thread rt).
- **async-trait dep present** in all 4 src crates (workspace) + added to scp-testing Cargo.toml for integration MockBackend.
- **Ratchet** recovery.rs 2→0, scp-runtime 36→34 matches deletion. Only tightening (allowed).
- **No missed impls:** workspace `impl RecoveryBackend for` = exactly 6, all converted. No WASM impl exists (not in scope).
