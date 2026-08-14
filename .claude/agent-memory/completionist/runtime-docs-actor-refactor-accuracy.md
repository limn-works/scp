---
name: runtime-docs-actor-refactor-accuracy
description: Retroactive accuracy review of scp-runtime post-ADR-049/057 doc rewrite (#2095, c2f5314ab) — all ~45 cited symbols verified, ACCURATE
metadata:
  type: project
---

Retroactive accuracy review of merged docs @c2f5314ab (origin/main, PR #2095, salvaged stale
PR #2064 that had FABRICATED symbols). 4 files: crates/scp-runtime/README.md (rewritten),
CLAUDE.md (new), src/context/README.md (new), src/crypto/mls/README.md (new). Describe the
post-ADR-049 actor-per-context / Supervisor model + ADR-057 scp-mls sync-core extraction.

VERDICT: ACCURATE (COMPLETE). ContextManager count = 0 in all 4 (deleted type fully absent).
Sampled ~45 symbols top-to-bottom — every one exists at cited file:line with cited signature:
Supervisor(supervisor.rs:1171)+with_providers/with_providers_and_journal/create(11736)/
create_context(10419,4-arg)/send_message(11858,6-arg exact order)/restore_on_startup(8727)/
restore_all_contexts(pub(crate) 8676)/replay_unresolved_sagas(6154); test_supervisor(mod.rs:259
returns Arc<Supervisor>); RestoredContexts witness(130)+DurableProviders(1427);
MlsCryptoProvider::new(local_did:String, clock:Arc<dyn Clock>) provider.rs:501 EXACT;
all 7 ClassSCell combinators(class_s.rs) + Deref-yes/DerefMut-NONE; all 12 ContextCommand
sub-enums(commands.rs); all 12 handler dispatch fns = (&mut ClassSCell,&ActorDeps,cmd)->Outcome<()>;
scp-mls crate + all 8 sync modules(group/encrypt/ratchet/credential/key_package/error/
wrapping_extension/epoch_grace) + create_group_with_wrapping_key/ScpCredential/EpochGraceStore;
crypto/mls async bridge (backend/production_backend/provider/storage/storage_adapter) +
MlsBackend/HpkeBackend/ProductionMlsBackend/ProductionHpkeBackend/ScpMlsProvider/MlsStorageBridge/
OpenMlsStorageAdapter/SpawnBlockingStorageAdapter/with_backends; governance_helpers
try_broadcast_commit/apply_broadcast_failure/keep_broadcast_failure/acknowledge_commit_fault/
check_commit_fault_marker + constants MAX_COMMIT_RETRIES=20/MAX_COMMIT_AGE_SECS=3600/
MAX_PENDING_COMMITS=50/COMMIT_RETRY_BACKOFFS; 4 fail-close sites (execute_remove_member/
execute_rotate_content_keys/leave_context/recovery_advance_epoch) + 2 Class-C (execute_add_member/
execute_reset_member); RecoveryBackend #[async_trait(?Send)] sole exception; OwnedIdentityDid
pub(in crate::context); scp-platform Storage(traits.rs:848)/sealed EncryptedStorage/
EncryptingAdapter<S>; both enforcement scripts (check-no-shim-reexports.sh, check-block-in-place.py).
Shim-removal claim TRUE: no `fn dispatch_from_shim` def exists (prose/doc-comment mentions only,
all describing Phase-2A deletion).

2 minor imprecisions (neither fabrication/phantom): (1 LOW in-scope, context/README.md:84-87)
"Each [handler] exposes a dispatch taking (&mut ClassSCell,&ActorDeps,SubCommand)" over-generalizes
— `standing` dispatch is (deps:&ActorDeps, cmd:StandingCommand), no cell (it can't mutate state).
(2 OBS out-of-scope) pre-existing INTERNAL doc-comment handlers/governance.rs:5-9 still says dispatch
is (&mut PerContextState,...) — stale; the reviewed 4 files CORRECTLY say ClassSCell (commit even
called out this fix). Reconfirms [[verify-against-commit-not-worthree]]: HEAD 1620de983 was NOT a
descendant of reviewed c2f5314ab (on origin/main); working-tree README still had OLD ContextManager
content — MUST review via `git show c2f5314ab:path` / `git grep <rev>`, not the worktree.
