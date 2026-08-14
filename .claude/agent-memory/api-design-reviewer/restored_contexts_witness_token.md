---
name: restored-contexts-witness-token
description: API review of RestoredContexts ordering-witness token (saga restore→replay, §17.16.4, commit d0c57bd75) — APPROVED with nits
metadata:
  type: project
---

`RestoredContexts` witness token in `crates/scp-runtime/src/context/supervisor/supervisor.rs:122` (commit d0c57bd75, branch feat/2c-saga-dispatch). Type-encodes the §17.16.4 restore-then-replay ordering: `restore_all_contexts()` returns the token, `replay_unresolved_sagas(&RestoredContexts)` requires it. Reorder = no token = no compile.

**Verdict: APPROVED.** It mirrors the in-file `CrossContextSagaSeal` idiom and ADR-049 §5 OwnedIdentityDid discipline (private field, module-private `new`, nameable-but-not-constructible). `for_test` is `testing`-gated (compiled out of prod), well-named, well-justified (FSM suites have no persistence provider). This is a *return-value* ordering proof, NOT phantom typestate — does not violate the line-42 "Agent-first" anti-typestate tenet, because the happy path is the single `restore_on_startup` entry point and no caller hand-threads the token.

**Why no typestate-tenet violation:** the tenet forbids *phantom required-ordering a model can't track*. Here the witness is a real return value an agent gets for free by calling restore first; the canonical path (`restore_on_startup`) hides it entirely. An LLM writing a bridge calls one method.

**Non-blocking nits found:**
- The token carries `Vec<String>` ids but `replay_unresolved_sagas` uses them ONLY for a `tracing::debug!` span field (supervisor.rs:5552-5558); per-entry decisions read persistence directly. A unit witness (`RestoredContexts(())`) would prove ordering equally. The ids payload is justified only because `restore_on_startup` returns `into_ids()` to callers (the FFI bridges surface the restored id list) and scp-testing asserts on `.ids()`. So payload is load-bearing for the RETURN contract, not the WITNESS contract — acceptable but worth noting the dual role.
- `restore_all_contexts` stays `pub` (not `pub(crate)`) only for the scp-testing E2E; the `bridge_resume_path_routes_through_restore_on_startup` gate compensates. Mild surface-minimality cost, adequately documented.

**Gate (item 4):** `extract_fn_body` rewritten as a proper Rust lexer (nested block comments, raw strings w/ hash-counting, char-vs-lifetime). Bounded/sound by construction (positive span recognizer, not a denylist). 11 unit tests pin each evasion. Gate covers all 3 persistent FFI exports (PyO3/UniFFI/napi) + shared bridge core. WASM correctly exempt (ephemeral, ADR-034, different ContextManager method). Enforcement contract is clear and convergent.
