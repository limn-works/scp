---
name: adr049-skeleton-retire-and-credentials-rwlock
description: Two disjoint ADR-049 cleanup branches (skeleton_dispatch retirement @82c7020e5; credentials tokio→std RwLock @ecc87f752) — both verified COMPLETE, zero gaps
metadata:
  type: project
---

Two ADR-049 cleanup branches off origin/main 8b3088812, both **COMPLETE, zero gaps**.

**A — skeleton_dispatch retirement (chore/adr049-skeleton-retire @82c7020e5):**
Pure-deletion diff (7 files, -1040 lines, actor/mod.rs bulk). `skeleton_dispatch`+11 `skeleton_dispatch_*`
helpers + `new_skeleton` + `Supervisor::spawn_actor`(skeleton) + `SupervisorHandle::shim_supervisor` all
fully removed — `git grep skeleton_dispatch|new_skeleton|shim_supervisor -- crates/` = 0. Option-collapse
total: ContextActor.state is now `class_s::ClassSCell` (not Option), deps `deps::ActorDeps` (not Option);
zero residual None-branch. 2 removed tokio tests (`skeleton_actor_acks_query_with_not_implemented`,
`spawn_actor_registers_handle_under_write_lock`) genuinely skeleton-only; their real coverage (handle
registration + duplicate rejection) survives in `spawn_actor_with_state_registers_handle_and_accepts_commands`
+ `spawn_actor_with_state_rejects_duplicate_context_id`. **Key discriminations:** all "skeleton" grep hits
are English-word module-doc uses (actor skeleton / minimal-stub / empty role-state); all "shim" hits are the
DISTINCT `dispatch_from_shim`/"dispatch shim" migration apparatus (already retired), NOT deleted
`shim_supervisor`. Two remaining `#[allow(dead_code)]` in actor/mod.rs (context_id:111, fn new:195) are
PRE-EXISTING on main (unchanged), tied to the ongoing 12b actor migration, not skeleton retirement.
`spawn_actor_with_state` is the live prod spawn path (lifecycle_helpers 1573/2361/2906, supervisor 11456).
Sole residual refs to deleted symbols live in `.claude/agent-memory/backend/*.md` historical logs — frozen
memory records, correctly untouched; ZERO in crates/ or .docs/, zero intra-doc `[..]` links.

**C — credentials tokio→std RwLock (chore/adr049-credentials-rwlock @ecc87f752):**
Scope-clean (only bridge/credentials.rs, +57/-24). All 3 `tokio::sync::RwLock` fields (credentials,
suspended_bridges, bridge_credential_keys) → `std::sync::RwLock`; grep tokio::sync::RwLock in file = 0.
All 12 lock acquisitions uniformly poison-handled `.unwrap_or_else(std::sync::PoisonError::into_inner)`
(recover-inner, not panic — improvement, std lock can poison). Every guard-`.await` dropped; the 704 await
is on async trait method delete_bridge_credential_key (correct). suspend_bridge/reactivate_bridge async→sync;
only callers are the 2 in-file tests (both updated). No `use tokio::sync` to remove (fully-qualified paths).
#[derive(Debug)] intact (std RwLock<T:Debug> is Debug). significant_drop_tightening allow comment updated to
honest sync-critical-section wording. FFI crates (pyo3/napi/uniffi runtime.rs) hold Arc<InMemoryCredentialStore>
but call only async trait methods (unchanged sigs) — no break. `economy/credentials.rs` InMemoryCredentialStore
is a DISTINCT test-only type (own module, own tokio::sync::Mutex allow-note) — correctly untouched.

**Doc-vs-gate nuance (not a finding):** C's new doc comment cites "ADR-049 Decision 12: async tokio read-path
RwLock is banned." ADR-049 §Decision 12 (ADR line 261) DOES ban tokio::sync::RwLock on read paths as
principle, BUT crates/scp-runtime/clippy.toml line 34 says it's "intentionally NOT banned yet" mechanically
(legacy ContextHandle.inner Arc<RwLock<ContextInner>> still uses it; ban lands when that's gone). So the doc
is accurate to the ADR principle and the migration is progress toward the eventual ban; `std::sync::RwLock`
is not in disallowed-types so no gate tripped. `std::sync::Mutex` IS banned in that clippy.toml but RwLock isn't.
