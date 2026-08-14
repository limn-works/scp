---
name: spending-ucan-revocation
description: Review notes on the scope-matched spending-UCAN revocation feature (§19.5) — global durable store, fail-closed hydration, expiry-GC, scope authz. Branch ddd7e1dc0 (NOT on main line).
metadata:
  type: project
---

# Spending-UCAN revocation (§19.5) — review round 2 (ddd7e1dc0)

Feature lives on the `ddd7e1dc0` commit line, which DIVERGED from the ceiling-work
line at e406c15c5. The worktree branch (1620de983) does NOT contain these files —
review the code via `git show ddd7e1dc0:<path>`. File: `crates/scp-runtime/src/store/revoked_spending_ucans.rs`.

**Why:** two parallel branches; the revocation store file doesn't exist at the worktree HEAD.
**How to apply:** when asked to review revocation fixes, extract files at ddd7e1dc0, not the working tree.

## Verified CLEAN (round 2)
- Expiry-GC moot-after skew == gate expiry skew (both `DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`=300);
  prune cond `moot_after<=now` coincides with gate reject `exp+skew<=now` → NO re-admit window.
- moot_after = `exp.saturating_add(skew)` → no overflow.
- Prune scoped by `identity/{did}/revoked_spending_ucans/` prefix, `/`-bounded → no cross-DID prune.
- Scope authz: global → issuer only; context → issuer OR scope-context creator (read from the actor
  routed by the VERIFIED token scope, not caller-supplied). verify→authz→insert order correct. reply
  sent exactly once per path.
- DRY helper `ActorDeps::global_revoked_cids_for` == inlined `load().get(did).cloned()`. Behavior-preserving.
- scp-node: `DurableProviders::from_encrypted_handle` derives store from same `Arc<SqliteStorage>`, wired through.

## Findings (round 2)
- MEDIUM: `resume()` default body (`CoreFields::restore_all_persisted_contexts`, bridge_instance.rs ~1731)
  SWALLOWS `RevocationHydrationFailed` (warn+continue). Instance stays up with EMPTY global cache; any
  context (re)established post-resume serves global-scope paid actions fail-OPEN. Comment overstates
  guarantee ("nothing came up serving..."). Explicit FFI startup restore (napi/pyo3/uniffi context.rs)
  DOES propagate — correct. Bounded by trusted-local model + 24h expiry.
- MEDIUM (doc): `hydrate_revoked_spending_ucans` doc says "Called from restore_on_startup AFTER saga
  replay" — commit 826 moved it to run FIRST (fail-closed). Doc documents the opposite of the invariant.
- LOW: hydrate `load_all` runs OUTSIDE write_lock, then locks to `store()` whole map → can clobber a
  concurrent revoke's cache insert (durable still has it; recovered next hydration). Comment claims lock
  prevents this — false. Startup-only in practice.
- LOW: `RevokedSpendingUcanRecord::revocation_moot_after_secs` `#[serde(default)]`=0 = immediately-moot =
  fail-OPEN direction for a security GC field. Unreachable today (new field on new type). Prefer u64::MAX.
- LOW (doc): DurableProviders field doc + `revoked_spending_ucan_store()` accessor doc both name
  `from_handle` as the store builder; actually `from_encrypted_handle` (from_handle leaves None).

## Round-3 review (branch tip fe092f890; chain ddd7e1dc0→f9c9dc0da→15b70616f→854fd24c6→1e6e744d2→fe092f890)
- HIGH (REGRESSION, fail-OPEN): `apply_global_spending_revocation` (supervisor.rs ~3765-3781) computes
  `load_for_did` OUTSIDE `write_lock`, then inside the lock does `updated.insert(iss, bounded)` which
  REPLACES (not merges) the DID's cache entry. Two concurrent revokes of the SAME payer DID's global
  tokens race: the one whose load_for_did snapshot is staler stores last and DROPS the other's CID from
  the hot cache. Durable store is correct; gate reads cache → dropped CID re-authorized until next
  restart hydration. Invariant-2a fix (15b70616f) traded unboundedness for a lost-update TOCTOU. Note
  the SAME commit's 2b fix correctly moved hydrate's `load_all` INSIDE the lock — inconsistently NOT
  applied to the incremental path. Fix: acquire write_lock BEFORE load_for_did (mirror hydrate 2b). The
  round-2 blind-insert `entry(iss).or_default().insert(cid)` was concurrency-correct (read inside lock).
- CLEAN: poison flag (f9c9dc0da). GlobalRevocationHydration Arc<AtomicU8>, SeqCst r/w (fine),
  discriminants NOT_CONFIGURED=0/NEEDS=1/HYDRATED=2/FAILED=3, status_known()=NOT_CONFIGURED||HYDRATED.
  Shared into every production ActorDeps (build_actor_deps + clone_for_spawn both share the Arc; no stray
  not_configured() copy in prod). global_scope_status_unknown = !status_known && scope==Global computed
  identically in economy_logic + saga; required field (no default) so new gates must compute it.
  Context-scoped always false (unaffected). is_revoked early-returns true when unknown. Retain default
  u64::MAX now correct.
- CLEAN: membership gate (854fd24c6). revoker_is_creator (non-empty creator) bypasses membership; issuer
  must be `cell.membership.contains` (authoritative MembershipState.members). empty revoker→12068;
  non-member issuer→12069; creator-non-member allowed. reply.send once per branch. Global path unchanged
  (issuer-only, no membership — correct).
- MEDIUM (history hygiene): 854fd24c6 breaks test `context_scoped_revocation_does_not_leak_to_other_context`;
  fixed only in tip fe092f890, with docs commit 1e6e744d2 SANDWICHED between → TWO commits (854, 1e6e)
  fail `cargo test` (compile OK, test-fail). Not adjacent. Fine for squash-merge; violates linear-history
  bisectability. Round-2 findings re resume-swallow now MITIGATED by poison flag (gate fails closed even
  if resume swallows).

## Round-4 review (tip 188af5ad2; 4bc8be843 docs + 188af5ad2 fix) — CLEAN
- Round-3 HIGH lost-update FIXED. apply_global_spending_revocation acquires write_lock BEFORE
  store.load_for_did; re-derive+ArcSwap::store atomic under guard; drop(guard) before best-effort leaf.
  No-lost-update proof: each revoke's record() happens-before its own lock acq; load runs under lock; the
  last lock-holder's load observes all prior committed records → final store has all CIDs. All 3 cache
  .store sites now under write_lock (2 apply_global, 1 hydrate). record() stays outside lock (harmless).
- Error branch (load_for_did fails after record OK): entry().or_default().insert(cid) (MERGE not replace)
  under lock, store, return Err. CID durable AND cached; error surfaced. Fail-closed correct.
- Test concurrent_global_revokes_same_did_do_not_clobber_cache: real store wrapped by YieldOnLoadStore
  (8 yields AFTER durable read in load_for_did) widens the real read→store window (not a mock bypass);
  8 iters × 8 concurrent same-payer revokes, multi_thread(4); asserts all CIDs survive. Catches regression.
  7/7 revocation tests green; clippy scp-runtime clean (tokio guard-across-await not flagged; no deadlock).
- 4bc8be843 docs-only (spec grounds invariant labels 1a/1b/2a/2b/3a/3b code cited = phantom-provenance fix;
  +1 comment). Provenance spec→code correct. Both green.

## Round-5 review (tip 60a098937; e8d4cc974 refactor + 60a098937 docs) — CLEAN
- Simplifier Q4: unified both cache-write paths into `reload_global_revoked_cache_under_lock(store,now)`
  = write_lock → load_all → ArcSwap::store. Used by hydrate AND apply_global. Deleted load_for_did +
  load_revoked_spending_ucans_for_did + trait method + impl + dedicated test (grep 0 refs at tip; both
  test doubles YieldOnLoadStore + FailingHydrationStore now impl only record+load_all — compiles).
- No lost update: load_all reads WHOLE durable under the lock; each revoke's record() happens-before its
  own reload-lock, so the last committer's load_all sees all durable records. Wholesale = simpler/safer
  than the deleted load_for_did.
- Two-lock error path (reload fails after record OK): helper locks+load_all-fails+unlocks; apply re-locks,
  ADDITIVE entry(iss).or_default().insert(cid), store, return PersistenceFailed. Safe: record is durable
  so any later successful full reload reads a superset incl cid; additive insert never clobbers; atomic
  load_all+store under lock forces the additive insert strictly before/after any reload critical section
  → cid always survives. Verified across interleavings.
- Concurrency test kept; YieldOnLoadStore yield moved into load_all (the unified path), yields AFTER the
  real inner.load_all read → widens the real read→store window; deterministically fails if load_all moved
  outside the lock. Genuine guard, not a mock bypass.
- Behavior parity: hydration poison (mark_hydrated/mark_failed) preserved; retain-default u64::MAX
  untouched; membership gate untouched; expiry-GC preserved (load_all prunes moot wholesale; record still
  prunes). Only change = full identity/-scan per global revoke (documented cold-path tradeoff) + refreshes
  all DIDs' entries (benign, cache==bounded durable). remove-empty-key defensive logic subsumed by
  wholesale rebuild (moot DID simply absent from load_all).
- 60a098937 docs-only (self_host.rs comments naming from_encrypted_handle as prod ctor — closes round-2
  LOW doc finding). Both green: 48 revocation/fail-closed/concurrency tests pass, scp-runtime all-targets
  clippy 0. Net −78 lines. VERDICT: CLEAN — ship.
