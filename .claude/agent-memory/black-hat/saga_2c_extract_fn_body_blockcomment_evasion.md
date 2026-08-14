---
name: saga-2c-extract-fn-body-blockcomment-evasion
description: pipeline_wiring extract_fn_body strips // and "" but NOT /* */ block comments — gate evadable (saga commit 7ff78af33)
metadata:
  type: project
---

# extract_fn_body block-comment evasion (commit 7ff78af33)

`crates/scp-testing/tests/integration/pipeline_wiring.rs` `extract_fn_body` (lines 173-258) was hardened to strip `//` line-comment text and `"..."` string-literal CONTENTS so structural `find`/`contains` gates can't false-pass on commented/stringized tokens. **It does NOT handle `/* */` block comments, char literals (`'x'`), or raw strings (`r#"..."#`).**

**CONFIRMED CRITICAL evasion (compiled + ran real gate):** Injecting `/* restore_all_contexts() */` as a decoy in the production `Supervisor::restore_on_startup` (`crates/scp-runtime/src/context/supervisor/supervisor.rs:7907`) while reordering the real calls to the BROKEN order (replay before restore — reintroducing the stranded-refund HIGH this commit fixed) makes the positive gate `restore_on_startup_runs_replay_before_restore` **PASS (ok)**. The block comment is not stripped, so the decoy `restore_all_contexts()` is seen at an earlier offset than the real `replay_unresolved_sagas()`. Mutated code compiles clean.

**Worse — defense-in-depth is absent:** both new behavioral tests (`restore_on_startup_xctx_caller_reversal_delivered_entry_terminal`, `..._deleted_caller_is_reaped_terminal`) ALSO pass against the broken order, because they pre-make the caller resident via `spawn_xctx_pair` and use a `CapturingPersistence` that lists NO contexts (`restored.is_empty()`), so `restore_all_contexts()` is a no-op regardless of order. The test comment "Replay-before-restore would strand both" is FALSE under that fixture. The structural gate is the SOLE order enforcement and it is evadable.

**Second evasion (negative gate):** `/* } */` injects a brace inside an unhandled block comment, counted as a real `}` at depth 0, truncating the extracted body early. A real bare `restore_all_contexts()` call placed AFTER `/* } */` becomes invisible to `bridge_resume_path_routes_through_restore_on_startup`'s `!fn_body_contains(...)` negative assertion → gate PASSES while bridge bypasses replay. Same root cause.

**Fail-closed variants (loud, not exploitable for false-pass):** char literal `'"'` desyncs in_string → body never balances → `None` → `.expect()` panics. `'}'` / `/* } */` in the POSITIVE gate truncates → both calls missing → `.expect()` panics. These fail the gate loudly (acceptable).

**Root fix:** track `/* */` block-comment state (and char literals + raw strings) in the brace-matcher, OR abandon source-text classification and brace-depth-track to extract the body via a real tokenizer. The non-convergent denylist (`//` then `""` then `/* */` then `''` then `r#""#`) is the AST-gate-name-resolution antipattern — prefer compile-time/type enforcement of the ordering invariant over a text gate, since an insider who edits supervisor.rs can also edit the gate.

Attack #2 (the reorder itself) and #3 (error codes, §17.16.4) are CLEAN — see final report. Reap branch `caller_context_deleted_from_persistence` (supervisor.rs:5936) correctly distinguishes `Ok(None)`=reap from `Err`=keep (no false reap on transient error).
