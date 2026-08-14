---
name: saga-journal-swap-da41e0b2c
description: ADR-049 Phase 2D durable saga-journal swap @ da41e0b2c (base ef7345cd5) — ALIGNED ship, 0 findings. One-line ADR §3b helper-name correction atop a1fbe0df4 (DurableProviders newtype). Verifies live helper names exist, deleted names purged, type-enforcement text matches code.
metadata:
  type: project
---

# Saga durable-journal swap @ `da41e0b2c` (worktree /private/tmp/scp-journal-swap, base ef7345cd5 = PR#1898 broadcast-cut, ADR-049 Phase 2D) — ALIGNED, ship, 0 findings

ONE commit past [[saga-journal-swap-a1fbe0df4]] (a1fbe0df4 IS the parent). HEAD `da41e0b2c` = DOCS-ONLY, single-line ADR-049 §3b correction (.docs/adrs/ADR-049-actor-per-context.md:63, +1/-1). The rest of `git diff ef7345cd5 HEAD` is unchanged from the a1fbe0df4 pass (already 0 findings there); re-confirmed the load-bearing anchors still hold at HEAD.

## The HEAD change (da41e0b2c)
ADR §3b:63 previously named the DELETED journal-only helpers (`build_saga_journal` PyO3 / `saga_journal_from_handle` NAPI+UniFFI) and described same-backend as held "by convention". Now correctly names the LIVE `DurableProviders` derivation: "`with_providers_and_journal`, passing a `DurableProviders` whose only non-test constructor (`DurableProviders::from_handle`) derives both the `ProtocolRepositorySagaJournal` and `mls_storage` from one `Storage` handle — so the same-backend invariant is enforced by the type system, not by convention. The four seams derive it via the PyO3 reference bridge (`durable_providers_from_bi`), NAPI and UniFFI (`durable_providers_from_handle`), and `scp-node` (`build_host_site_deployer`)." This is artifact-flow-correct: ADR documents a LANDED phase the ADR anticipated; code leads, doc catches up to code (the refactor at b99b8a4e8 introduced the newtype; this is the doc sweep the refactor's commit didn't fully do).

## Verified at HEAD
- Live helpers EXIST exactly as ADR names: `durable_providers_from_bi` (scp-ffi/src/runtime.rs:1257), `durable_providers_from_handle` (napi:987 + uniffi:1195), `build_host_site_deployer` (scp-node self_host.rs:2139). All three seams + node.
- DELETED helper names purged: grep for `fn build_saga_journal|fn saga_journal_from_handle|fn mls_storage_from_handle|fn derive_mls_storage` = 0 defs; grep for `build_saga_journal|saga_journal_from_handle` across crates/ AND .docs/ = 0 hits. No stale reference anywhere.
- Type-enforcement text matches code: `DurableProviders` (supervisor.rs:1208) fields PRIVATE; `from_handle<S>(Arc<S>)` (1226) = ONLY non-test ctor, derives both halves from one handle; `for_test`(1252)/`mls_storage()`(1289) cfg(test,testing); `with_noop_journal`(1269)/`into_parts`(1301) pub(crate); `with_providers_and_journal` takes only the newtype.
- §17.16.4 key-namespace bullet present (.docs/specs/17:976) + `:020d` anchor (§17:143). Spec impl-state-free.
- `with_providers`-as-prod: NOT stale anywhere. ADR §3b:63 + 3 bridge CLAUDE.md all say `with_providers_and_journal` for prod; remaining `with_providers` refs are correctly labeled test/legacy (incl. §3b two-anchor prose at :176-177 referencing the crypto-layer init-key store wired by `with_providers` — that's the legacy/test factory, accurate).
- Broadcast/§5.14.13: touched runtime + spec + ADR files broadcast-string hits are all LIVE broadcast-mode context machinery (publish_broadcast_two_phase, BroadcastContextSnapshot, etc.) + one historical "broadcast hosting" withdrawn-arm comment (supervisor.rs:183). NO withdrawn §5.14.13 broadcast-hosting saga residue.
- Dormant-secret: closed match `saga_input_is_secret_bearing` (supervisor.rs:10826) — `CrossContextToolInvocation => false`, test-only `TestForceNeedsRepair => false`, NO wildcard → every live saga provably non-secret-bearing; §9.4.3 needs no annotation. Honest.
- Forward obligations relied-on not reimplemented: restore-ordering witness `RestoredContexts` (supervisor.rs:131) + `replay_unresolved_sagas` takes `&RestoredContexts` (5647) + `restore_all_contexts` pub(crate) → replay-before-restore doesn't compile, restore-without-replay can't be named cross-crate. Unchanged by HEAD.
- Inert-but-correct: producer still dark — `reply_saga_deferred` (actor/handlers/tools.rs:282) returns `NotImplemented` citing §6.2.4 + DEFERRED-commit-11 gap 2. Journal wired+replayed, nothing appends → empty journal, nothing to replay. Scope discipline sound.
- §17.6 strengthened: same-backend now type-enforced (from_handle derives both from one Arc<S>), not convention. ADR text now accurately says "enforced by the type system, not by convention."

## Process note (clean this time)
Working tree CLEAN for all reviewed files (`git status --porcelain` minus agent-memory = empty). No black-hat parse-guard revert mutation present (unlike the a1fbe0df4 pass). HEAD commit == reviewed content.

## LESSON
A one-line ADR doc-correction atop a landed type-refactor is still a real alignment check: verify (a) every helper name the doc now NAMES actually exists at the cited seam (grep `fn <name>`), (b) every helper name the doc REMOVED is purged from BOTH code and all .docs/ (0 hits, not just 0 defs), (c) the type-enforcement claim the doc makes ("by the type system, not by convention") is literally true of the struct (private fields + single non-test ctor taking one source). Artifact-flow is correct when a doc sweep catches the ADR up to a landed refactor's actual symbol names — that is code→doc reconciliation of a phase the ADR already anticipated, not code reshaping the ADR's decision.
