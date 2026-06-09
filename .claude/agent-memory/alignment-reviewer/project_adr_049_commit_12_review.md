---
name: ADR-049 Commit 12 Alignment Review
description: Alignment review of ADR-049 commit 12 (manager/ deletion + Supervisor field lift) at HEAD 7c3137565. Verdict ALIGNED with 1 P1 + 6 P2/P3 findings.
type: project
---

# ADR-049 Commit 12 alignment review (2026-04-25)

Branch: `refactor/actor-per-context` HEAD `7c3137565`. Commit deletes `crates/scp-runtime/src/context/manager/` directory entirely + `Supervisor` field lift + bridge removal + ~18K test fixture migration.

**Verdict: ALIGNED** — 9 of 9 plan goals delivered; 1 structural P1 finding (orphaned test file); 6 P2/P3 findings (doc drift + stale annotations).

## Plan goals delivered (9/9)
1. Field lift onto Supervisor — `local_dids` (ArcSwap), `standing_contexts` (ArcSwap), `wrapping_keys` (DashMap<DID, ArcSwap>), `contexts` (Arc<DashMap>), `next_generation` (AtomicU64).
2. Actor handlers rewired — zero `attached_context_manager` references.
3. Bridge symbols deleted — `attach_context_manager`, `attached_context_manager`, `context_manager_bridge`, `cm_persistence`, `cm_contexts` all 0 grep hits.
4. `manager/` directory gone.
5. Test fixtures rewired — 9 `actor_*_shim.rs` deleted; integration tests rewired; gated files stay gated.
6. `scp-core/src/lib.rs` re-exports updated (`state`, `persistence` modules added; `manager` removed).
7. `pub mod manager;` deleted from `context/mod.rs`.
8. Hoisted-forwarder dead_code annotations gone (came with `manager/` deletion).
9. ~250 intra-doc links rewritten — `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links"` passes clean.

## Architecture-update verification (KEY)
The execution plan (`~/.claude/plans/commit-12-execution/plan.md`) conflicted with the architecture-update doc (`~/.claude/plans/commit-12-execution/architecture-update-2026-04-25.md`):
- **Execution plan said:** convert `ArcSwap → tokio::sync::RwLock/Mutex` for callsite parity.
- **Architecture-update said (binding):** REJECTED. Keep ArcSwap. Cite OpenSSL #30659/#30670 evidence (`__atomic_load_n` ≈17 cycles vs `RWLOCK_read_lock` ≈67 cycles, 4× hot-path cost).

Implementation correctly followed the architecture-update directive. ArcSwap kept on `local_dids`/`standing_contexts`/`wrapping_keys`. `write_lock` discipline applied at every mutation site (8+ verified).

## Findings
- **F1 (P1):** `crates/scp-testing/tests/integration/e2e_context_manager.rs` — 42 KB orphaned file with 19 refs to deleted symbols (ContextManager, ContextCryptoProvider, MockCrypto, attach_test_supervisor); not registered as `[[test]]` in Cargo.toml so doesn't compile. Pre-existing orphan from commit `a5171a5f3` but commit 12 plan explicitly listed it as "live | KEEP & REWIRE." Either delete or rewire+register; can't be left as broken-symbol dead file.
- **F2 (P2):** Stale doc comments at `actor/handlers/lifecycle.rs:486-495` and `messaging.rs:444-449` claim "no `*_helpers` peer; calls it directly via attached manager; future commit will hoist" — but the body actually calls the hoisted helper. Pre-hoist artifacts not updated.
- **F3 (P3):** Stale "attached manager" / "shim" prose in handler dispatch docs (messaging.rs:69, ttl_close.rs:64, tools.rs:63, governance.rs:78, standing.rs:67, trust_recovery.rs:57, lifecycle.rs:71); stale `#[allow(...)]` rationale comments referencing ContextManager.
- **F4 (P2):** Stale `#[allow(dead_code)]` on Supervisor fields. Probe (removing the annotations and running clippy) showed `actors`/`standing_contexts`/`local_dids`/`wrapping_keys`/`write_lock` are USED — only `persistence` is genuinely unused. Plan goal #8 explicitly calls these out for cleanup.
- **F5 (P3):** `.docs/specs/09-security-model.md` missing explicit ADR-049 reference. Master plan §"Specs to update" said this file should add language about actor-model eliminating lock-ordering and TOCTOU discipline. Has saga/actor language but no ADR cite.
- **F6 (P3):** 9 `Placeholder` variants in `actor/commands.rs` with doc strings claiming "Removed in commit 12 when the shim is deleted." This IS commit 12; variants survive; only test refs.
- **F7 (P3):** clippy.toml missing Decision 12 entries banning `tokio::sync::RwLock`/`tokio::sync::Mutex`. Architecture-update doc says this is OPTIONAL for commit 12, OK for commit 13 — but commit 13 scope didn't explicitly list it.

## Acceptance verification (commands run)
- `cargo fmt --all -- --check` — pass
- Full-feature `cargo clippy ... -- -D warnings` — pass
- `cargo doc --workspace --no-deps` with broken-link denial — pass
- `bash scripts/check-deleted-primitives.sh` — pass (ban list still empty per plan)
- `cargo test -p scp-runtime --features testing --lib` — 1562 pass, 6 fail (whitelisted: 2 MLS provider, 4 production_backend_*)
- `test ! -d crates/scp-runtime/src/context/manager` — pass
- `rg 'attach_context_manager'` — 0 hits
- `rg 'context_manager_bridge|attached_context_manager|cm_persistence|cm_contexts'` — 0 hits

## Patterns reusable for future commits
- The execution-plan-vs-architecture-update conflict pattern: when a planning doc conflicts with a later binding decision, verify the implementation followed the BINDING decision (ArcSwap won here).
- For "keep & rewire" plan items, also verify the test target IS registered in Cargo.toml — orphan files compile-clean only because they're never built.
- `#[allow(dead_code)]` on a struct field that's clearly used elsewhere is almost always stale; probe by removing the annotation and running clippy.
- Doc-comment drift survives mechanical sed sweeps that target markdown links — prose like "attached manager", "shim", "future commit hoists" needs separate cleanup pass.
- Acceptance probes (`rg` for symbols, `test ! -d`) catch structural completion but miss orphaned files that exist outside the build graph.
