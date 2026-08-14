---
name: saga-2c-final-resume-doc-8c6e5c0ce
description: saga-2c FINAL alignment pass — HEAD 8c6e5c0ce, comment-only PyO3 resume doc fix, ALIGNED ship zero findings
metadata:
  type: project
---

saga-2c branch FINAL alignment confirmation (worktree saga-2c, HEAD 8c6e5c0ce, 2026-06-23) — ALIGNED, ship, ZERO findings.

**What:** `8c6e5c0ce docs(saga): fix stale PyO3 resume doc-comment to match reconnect behavior` — the LAST commit in the saga-2c feature, layered atop the restore-then-replay+broadcast-handshake work ([[saga-2c-restore-then-replay-d0c57bd75]]) and the prior comment-accuracy pass ([[saga-2c-final-comment-accuracy-54f937e0f]]).

**Verified comment-only:** `git show 8c6e5c0ce` = `crates/scp-ffi/src/scp.rs` only, +6/-4, every changed +/- line is a `///` doc line. Confirmed all three trailing doc commits (15c1aef9c, 54f937e0f, 8c6e5c0ce) change ONLY comment/blank lines (grep -vE for `///|//|*|#|/*` + blanks returned empty for each).

**The old doc was genuinely WRONG (inverse of reality):** `PyScp::resume` doc claimed "the caller must re-establish the relay connection explicitly — resume does not reconnect automatically." But `PyScp::resume` (scp.rs:262) delegates straight to `BridgeInstanceCore::resume(&*inner).await`, whose trait DEFAULT body (bridge_instance.rs:2544-2549) does `core().resume()` (flag flip) → `reconnect_transport_if_pending()` → `restore_all_persisted_contexts()`. So resume DOES auto-reconnect. New doc (scp.rs:250-256) now accurate.

**PyO3 was the SOLE outlier across the whole resume surface** — NAPI (napi/src/scp.rs:301-305) + UniFFI (uniffi/src/scp.rs:112-116) already said "transport reconnect from pending relay URLs, persisted-context restoration"; Python SDK wrapper (bindings/python/scp_sdk/scp.py:385-406) already documented auto-reconnect ("Callers no longer need to re-invoke connect_relay manually"). Fix removes an internal contradiction in the reference bridge.

**Out-of-scope NON-finding:** Python SDK docstring scp.py:388,400 embeds issue refs (#1678/#1549) in source — violates "no issue refs in code" but PRE-EXISTING in an unchanged file; not a finding against this commit.

**Cross-reviewer convergence (3 reviewers, all ship):** test-quality (HEAD touches no test; suite +57 net assertions, zero `#[ignore]` added; load-bearing `saga_bridge_bootstrap.rs:205-338 bridge_restore_entry_runs_restore_and_replay_legs` pins the exact restore→replay path the doc describes, non-vacuous w/ pre-condition guards). chronicler (HEAD accurate vs trait default body; correctly NOT describing the inherent flag-flip-only `CoreFields::resume` at bridge_instance.rs:1144; whole feature-diff doc-bearing changes all verified accurate — ADR-049 §9 pub(crate)/witness/NoopSagaJournal, specs 17/06 restore-then-replay, sdk-common 13100-13102 + range split, NAPI/UniFFI "override"→"default body" wording fix).

**ANOTHER pre-existing out-of-scope staleness (chronicler-found, NOT introduced/worsened by this branch, NOT a blocker):** `crates/scp-runtime/README.md` is written around `ContextManager`, a type that no longer exists (public API now rooted on `Supervisor`; mod.rs:212 "ContextManager type is gone in commit 12"). This branch's ONLY README edit (line 109: `manager.restore_all_contexts()` → `manager.restore_on_startup()`) IMPROVES verb accuracy (restore_all_contexts is now pub(crate), not callable cross-crate; restore_on_startup is the correct public startup entry per ADR-049) and merely inherited the stale `manager`/`ContextManager` receiver on the line it had to touch. FOLLOW-UP (separate PR): whole-file README rewrite ContextManager→Supervisor.

**LESSON:** for a "fix stale doc-comment to match behavior" commit, the verification is: (1) prove comment-only by grepping changed +/- lines for non-`///` content (empty = clean); (2) read the ACTUAL code path the doc describes (here: delegate → trait default body) and confirm the NEW text matches it — AND confirm it does NOT conflate the trait default body with an adjacent inherent flag-flip-only method of the same name; (3) confirm the OLD text was the inverse/stale (a real bug, not churn) by checking the sibling bridges/SDK already had the correct text — the outlier is the one that was wrong. When a one-line edit lands inside a larger stale doc block (README ContextManager), confirm via `git show origin/main:<file>` that the staleness PRE-EXISTS and the edit only improves the touched line — don't blame the PR for inherited rot.
