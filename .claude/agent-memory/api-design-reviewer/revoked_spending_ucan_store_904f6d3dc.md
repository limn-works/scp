---
name: revoked-spending-ucan-store-904f6d3dc
description: API review of scope-matched spending-UCAN revocation (commit 904f6d3dc) — RevokedSpendingUcanStore trait, with_providers Option param, FFI ucan_revoke, 8-arg validate fn. APPROVED.
metadata:
  type: project
---

Reviewed commit 904f6d3dc (§19.5 scope-matched spending-UCAN revocation) on worktree branch. Verdict APPROVED, no blocking issues.

**Why:** Adds a durable DID-scoped global-revocation store + union gate. API surfaces were clean and consistent.

**How to apply:** Reference these conclusions if the surface changes again.

Key API facts:
- `RevokedSpendingUcanStore` (crates/scp-runtime/src/store/revoked_spending_ucans.rs) deliberately joins the OBJECT-SAFE provider family (`#[async_trait]`, `StoreError`, held as `Arc<dyn>`), NOT the `AdapterCredentialStore` RPITIT/`CredentialError` family. This is documented in the trait doc and is the correct sibling choice (it's injected as a provider OnceLock like ContextEventLogProvider/ContextPersistence). Trait narrows to just `record`/`load_all`; `is_revoked_spending_ucan` stays inherent (tests-only).
- Item-4 non-issue: `validate_spending_ucan_or_error` is 8-arg (`#[allow(too_many_arguments)]`), but the two revocation args have DISTINCT types — `revoked_cids: &HashSet<String>` vs `global_revoked_cids: Option<&HashSet<String>>` — so a swap won't compile; AND `ContextRevocationChecker::is_revoked` UNIONs them so a hypothetical swap is a semantic no-op. Every one of the 8 params has a distinct type. Newtype/arg-struct NOT warranted (redundant with type system — over-engineering guard applies). The task prompt's premise "both &HashSet<String>" was a misread.
- FFI: all 3 native bridges pass the RAW encoded token (not a precomputed CID) to `Supervisor::revoke_spending_ucan(context_id, token, revoker)`; scope is derived internally via `spending_scope_of`. NAPI was fixed in this commit to stop precomputing the CID. Caller does NOT need to know scope. WASM N/A (no economy path).
- `with_providers` gained `revoked_spending_ucan_store: Option<Arc<dyn RevokedSpendingUcanStore>>` as last param. Option is correct + consistent with sibling Option providers (persistence/payment_adapter/event_tx/clock); on None the supervisor FAILS CLOSED (NotInitialized) for global-scope revoke rather than a silent Noop — better than a null-object sentinel. All 3 production bridges inject Some(store).

Minor observations (non-blocking):
- PyO3 reimplements store construction via a local `build_revoked_spending_ucan_store` free fn (crates/scp-ffi/src/runtime.rs ~1249) instead of the shared `BridgeStorageRepo::revoked_spending_ucan_store()` helper (crates/scp-ffi/common/src/bridge_runtime.rs ~437) that NAPI + UniFFI both use. Two construction paths for one trivial thing.
- `with_providers`/`with_providers_and_journal` now carry ~10-11 positional params incl. 5 Options — the positional-provider-bootstrap is the anti-pattern the agent-first tenet warns about; a `SupervisorProviders` struct is the clean long-term shape. Pre-existing, not introduced here. (#2069/#2070 filed out-of-scope may cover this.)
- UniFFI `ucan_revoke(handle, token, revoker_did)` uses ContextHandle; PyO3/NAPI use context_id string — pre-existing binding-convention difference, semantically identical.
