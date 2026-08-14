# ADR-049 cleanup: skeleton-retire + credentials RwLock (Jul 6 2026)

Two disjoint branches off origin/main 8b3088812. BOTH CLEAN (compiled + tested).

## Branch A — skeleton_dispatch retirement (chore/adr049-skeleton-retire @82c7020e5, −942 LOC)
- ContextActor `state:Option<ClassSCell>`→owned, `deps:Option<ActorDeps>`→owned, `shim_supervisor` field removed. `dispatch` dropped None-branch + take()/restore, now `Self::dispatch_state(&mut self.state, &self.deps, cmd)`.
- **Borrow safety CONFIRMED**: disjoint-field borrows via associated-fn call (NOT `self.method`) → compiler permits simultaneous `&mut self.state`/`&self.deps`. Full-feature clippy -D warnings CLEAN → no unsafe workaround. take/restore was never a re-entrancy guard (actor is single-task, `dispatch` holds `&mut self` exclusively across the await) — its removal loses nothing.
- Deleted new_skeleton / skeleton_dispatch(+all sub-helpers) / Supervisor::spawn_actor / SupervisorHandle::shim_supervisor. Workspace-wide grep: ZERO dangling refs. Production spawn = spawn_actor_with_state (unaffected). All deleted callers were #[cfg(test)]/dead-code.
- 3 converted run-loop tests use ContextActor::new (state-owning) not skeleton. STRENGTHENED not weakened: pause test now sends real MemberCount query post-Pause → asserts Some(0) off owned state (was skeleton NotImplemented ack). exits_on_inbox_close + shutdown_promptly both bound waits + join handle → no leak.
- `is_prepare_replace` claimed-terminal: dropped trivially-true skeleton None-branch, now `matches!(self.state.lifecycle_state, Closed)` — correct real semantics.
- Doc scrubs in governance_helpers/ttl_close_helpers/commands/handlers/mod — no broken intra-doc links (scrubbed text removed the symbols).
- 2210 tests pass (3 leaky = pre-existing, NOT the converted actor tests which fully join).

## Branch C — credentials RwLock migration (chore/adr049-credentials-rwlock @ecc87f752)
- InMemoryCredentialStore 3 fields tokio::sync::RwLock→std::sync::RwLock; `.write().await`→`.write().unwrap_or_else(std::sync::PoisonError::into_inner)`. suspend_bridge/reactivate_bridge async→sync (inherent methods; ZERO external callers workspace-wide; only in-file tests, updated).
- **Lock-across-await CONFIRMED ABSENT** (line-by-line): provision/rotate derive+encrypt BEFORE guard; retrieve holds `creds` read-guard across derive_credential_key+decrypt_credential which are SYNC free fns (no await); revoke scopes write-guard in `{}` block dropped BEFORE `.delete_bridge_credential_key(...).await`; suspended_bridges checks are temporaries in `if` condition. **Compiler-enforced backstop**: std::sync::RwLockWriteGuard is !Send → any guard held across await in a spawned async fn = hard "future cannot be sent" error; workspace compiles clean = proof.
- Poison idiom correct: `unwrap_or_else(PoisonError::into_inner)` recovers guard from PoisonError, matches repo reserved_saga_contexts pattern.
- 2212 tests pass. Full-feature clippy -D warnings CLEAN.
