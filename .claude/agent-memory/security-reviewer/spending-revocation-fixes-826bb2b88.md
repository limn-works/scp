---
name: spending-revocation-fixes-826bb2b88
description: Round-2 re-review of scope-matched spending-UCAN revocation security fixes (826bb2b88) — both prior MEDIUMs CLOSED, one NEW MEDIUM (serde-default fail-open on upgrade)
metadata:
  type: project
---

# Spending-UCAN Revocation Security Fixes Re-Review (826bb2b88, §19.5)

Base feature 904f6d3dc (see `MEMORY.md` §Scope-Matched). Fix commit 826bb2b88 on branch
worktree-agent-a32cd09f9850dfdd7 (HEAD ddd7e1dc0). GOTCHA: this feature lives ONLY in the
worktree; absolute path `/Users/alec/Developer/limn/scp/...` = MAIN worktree (different commit,
no revoke code). Use RELATIVE paths (cwd = worktree) or the full worktree path.

## Prior findings — both CLOSED
- SEC-1 (fail-open hydration): CLOSED. `restore_on_startup` (supervisor.rs ~9210) now calls
  `hydrate_revoked_spending_ucans().await?` FIRST, before `restore_all_contexts()`. New distinct
  `ContextError::RevocationHydrationFailed` (protocol context/mod.rs). No-store path returns Ok(()).
  bridge_instance.rs:1729 has explicit fail-closed warn arm; generic arm also fail-closed (nothing
  restored). 3 direct FFI callers (uniffi 11376, napi 4489, pyo3 4773) propagate via map_err+?.
- SEC-2 (global authz): CLOSED. Global = issuer-only (`apply_global_spending_revocation`
  supervisor.rs:3665, `revoker_did != parsed.payload.iss` -> PermissionDenied SCP-ECON-12067).
  Context-scoped routed to TOKEN's scope context actor (context_id = scope_context_id, not caller's);
  handler (handlers/economy.rs Step 0) checks `revoker != issuer_did && revoker != creator_did` where
  creator_did read from actor's authoritative role_state. Non-resident scope context FAILS CLOSED
  (dispatch_economy_direct RevokeSpendingUcan arm surfaces lookup_miss_error, no gate mutation).

## Expiry-GC boundary — CORRECT
moot_after = exp + DEFAULT_CLOCK_SKEW_TOLERANCE_SECS (saturating_add). Gate rejects at
`exp + skew <= now` (validate.rs:1292). Prune at `moot_after <= now`. IDENTICAL boundary — no window
where a pruned revocation leaves an accepted token.

## NEW finding — MEDIUM (fail-open on upgrade)
`revocation_moot_after_secs` has `#[serde(default)]` => 0 for any record written by a build WITHOUT
the field (base 904f6d3dc wrote {did,cid} only). On first post-fix hydration, `0 <= now` => record
DELETED durably + omitted from cache => a global revocation persisted by the pre-GC build is silently
dropped, re-authorizing a still-live (<=24h) revoked token. Fail-OPEN direction on a security field.
FIX: default to u64::MAX (retain until a real value known), not 0. Bounded by <=24h token expiry;
same-branch/unreleased so blast radius limited, but the default direction is the bug.

## Round-3 (f9c9dc0da..fe092f890) — round-2 findings all CLOSED, ONE NEW MEDIUM
- INV1 fail-closed flag: `GlobalRevocationHydration` (Arc<AtomicU8>: NotConfigured|NeedsHydration|Hydrated|Failed, store/revoked_spending_ucans.rs:437). status_known()=true only for NotConfigured/Hydrated. Wired: construction default not_configured (supervisor 1699); mark_needs_hydration ONLY if store configured (1973); hydrate mark_hydrated on success / mark_failed on load_all Err (9311/9318). Shared Arc cloned into EVERY ActorDeps (2609) => post-startup created contexts also fail-closed. Gate chokepoint economy_logic.rs:170 `if global_scope_status_unknown {return true}`; computed = !status_known && Global-scope at BOTH prod sites (economy_logic:221, saga.rs:1175). Benign no-store stays NotConfigured=fail-open-OK. No error path leaves flag wrongly Hydrated (only load_all Err -> Failed, no unwrap/panic). CLOSED.
- serde default: now `#[serde(default = "retain_forever_moot_after")]` -> u64::MAX RETAIN (store:122). Field-less record retained not GC'd. CLOSED.
- hydrate lock gap: write_lock now held ACROSS load_all AND store (supervisor 9301-9315). CLOSED.
- empty-DID: handler Step 0a rejects empty revoker (SCP-ECON-12068); creator branch requires non-empty creator; +membership gate Step 0c (SCP-ECON-12069, must be current member OR creator). CLOSED.
- **NEW MEDIUM (regression from 15b70616f invariant-2a):** apply_global_spending_revocation re-derive TOCTOU. `store.load_for_did(&iss)` read is OUTSIDE write_lock (supervisor:3765), then cache entry REPLACED inside lock (3779). Two concurrent same-issuer global revokes: A record(CID_a)+load_for_did->{a}, B record(CID_b)+load_for_did->{a,b}, B stores {a,b}, A stores {a} last => CID_b CLOBBERED from in-memory cache (durable still has it). Gate reads cache => token_b re-authorizes spends (fail-OPEN) until next hydrate/restart. Round-2 code was additive-insert-under-lock (clobber-free); the 2a bound-the-cache rewrite replaced it with read-outside-lock+entry-replace. Global revoke is NOT mailbox-serialized (calls Supervisor directly), so concurrent same-payer revokes reachable. Self-issued tokens, <=24h bound, self-heals on hydrate. FIX: hold write_lock ACROSS load_for_did+store (exactly what 2b did for hydrate's load_all).

## Round-4 (188af5ad2) — concurrency MED CLOSED, FINAL SECURITY ZERO
- apply_global_spending_revocation (supervisor.rs:3781): write_lock now acquired BEFORE load_for_did; load+re-derive+store all under the guard; drop(guard) before audit-leaf append. Proof it's race-free: each revoke does `record` (durable, pre-lock) THEN acquires lock. Mutual exclusion => the LAST lock-holder's load_for_did runs after every earlier revoke's record committed AND after its own record => reads full durable set => stores superset. Once any revoke returns Ok, its CID is durably in cache and no later store can drop it (later holder's load_for_did sees it). Error path (load_for_did fails post-record): additive `entry(iss).or_default().insert(cid)` under lock (fail-closed, non-clobbering) then surfaces Err. CLOSED.
- Flag/cache ordering sound: hydrate stores cache THEN mark_hydrated (SeqCst) under lock; gate reading flag=HYDRATED is guaranteed (release/acquire + SeqCst) to see the hydrated cache. During NEEDS_HYDRATION/Failed the gate fails closed for ALL global tokens. No window where flag=HYDRATED but cache cold.
- FINAL: no remaining path where a revoked spending UCAN authorizes a paid action or the gate fails OPEN. All invariants hold at tip 188af5ad2. Feature = CLEAN / security zero.

## Observations (LOW / defense-in-depth)
- hydrate takes write_lock only around ArcSwap `store()`, NOT the preceding `load_all()`. A global
  revoke's RMW that lands between hydrate's load_all and store is clobbered by the wholesale replace
  (fail-open for that CID until next hydrate). Startup-only; global revoke needs no resident actor so
  not structurally impossible during resume. Narrow.
- Context-scoped handler authorizes on `revoker == creator_did`; if BOTH empty ("") they match. Relies
  on caller-contract (non-empty authenticated revoker; debug_assert only, compiled out in release) +
  the invariant that a real context's creator_did is non-empty. Reject empty explicitly for D-i-D.
