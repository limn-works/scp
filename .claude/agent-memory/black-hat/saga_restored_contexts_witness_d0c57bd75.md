# RestoredContexts witness token (commit d0c57bd75, §17.16.4 restore-then-replay) — TYPE GUARANTEE BROKEN

Black-hat probe of the "type-encode restore-then-replay ordering" fix. The
`RestoredContexts` witness in `crates/scp-runtime/src/context/supervisor/supervisor.rs`
is supposed to make replay-before-restore non-compilable. It does NOT.

## CRITICAL — derived Default is a public forge (supervisor.rs:121)
`#[derive(Debug, Clone, Default)]` on `RestoredContexts { ids: Vec<String> }`.
`Default::default()` is a PUBLIC trait method that ignores the private `new` /
testing-gated `for_test`. Any crate calls `RestoredContexts::default()` to mint a
valid witness with ZERO restore. Proven: strict-default `scp-ffi` build (the shipped
Python wheel posture, NO testing/NO allow_in_memory_custody) compiles
`sup.replay_unresolved_sagas(&RestoredContexts::default()).await` — replay before
restore. Also proven by reordering `restore_on_startup` body itself via the Default
forge (compiled + ran). `default()`/`Clone` are used NOWHERE in the tree → FIX = drop
the Default (and Clone) derive. The doc comment "ids field PRIVATE so no external crate
can forge a token" is FALSE under derive(Default).

## HIGH — for_test leaks into prod-feature builds via feature unification
`for_test` is `#[cfg(feature="testing")] pub`. Chain: `scp-ffi/allow_in_memory_custody`
→ `dep:scp-testing` → scp-testing's NON-dev `[dependencies] scp-core{features=["testing"]}`
→ `scp-runtime/testing` → `for_test` compiled in. Proven: `cargo build -p scp-ffi
--features allow_in_memory_custody` compiles `RestoredContexts::for_test(...)`. That
feature is enabled by ALL CI jobs (ci.yml clippy/nextest/doc) + E2E maturin builds.
NOT reachable in strict-default build (so shipped wheel safe from for_test, but NOT from
Default). `scp-testing` listing scp-core/testing in normal `[dependencies]` (not
dev-deps) is the root leak — Cargo.toml:18.

## compile_fail doctest is a TAUTOLOGY (supervisor.rs:5529)
Doctest only proves `sup.replay_unresolved_sagas()` (ZERO args) fails. Never tests a
forged-witness call. False confidence.

## Bridge gate evadable — UFCS + shadow (pipeline_wiring.rs:911)
`bridge_resume_path_routes_through_restore_on_startup` pins 3 named fns; positive =
contains `restore_on_startup()`, negative = !contains `.restore_all_contexts()`.
PROVEN BYPASS (compiles + gate PASSES): in PyO3 `restore_all_contexts`, add no-op
`let restore_on_startup = || (); restore_on_startup();` (satisfies positive token) +
call bare restore via UFCS `Supervisor::restore_all_contexts(&sup)` (no leading-dot
substring → evades negative). Replay SKIPPED in production. Gate is a closed denylist of
3 names + brittle substring; a 4th startup path or unpinned helper also uncovered.

## BARRIERS THAT HELD
- Lexer (extract_fn_body): escaped-quote `'\''` desync is REAL (mis-closes at inner
  quote, stray `'` re-opens) but BENIGN — only ever blanks one following char, can't hide
  a multi-char call or a real brace. byte-char `b'}'`, nested `/* */`, raw-string, string
  decoy all correctly handled. Newline-split `.restore_all_contexts()` still matches
  (rustfmt splits before the dot). No exploitable lexer desync found.
- Behavioral test `restore_on_startup_restores_caller_from_persistence_then_delivers_reversal`
  is GENUINELY order-discriminating: reordered to replay-first (via Default forge) it FAILS
  GATE 1 (refund stranded left:9000 vs right:10000, caller despawned when replay ran).

## Net
Type encoding is THEATER against an in-tree adversary (derived Default). It DOES stop
the naive zero-arg reorder. Defense rests on the behavioral test (sound) + the source gates
(evadable). Recommend: remove derive(Default)+Clone; make for_test not leak (move
scp-core/testing to scp-testing dev-deps, or gate for_test on a dedicated never-unified
feature); strengthen bridge gate or replace with a real bootstrap integration test.
