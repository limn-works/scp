---
name: saga-2c-final-pass-15c1aef9c
description: Pre-merge test-quality passes on saga-2c — SHIP at 15c1aef9c, re-confirmed SHIP at 8c6e5c0ce (delta = 2 doc/comment-only commits)
metadata:
  type: project
---

# saga-2c final test pass (HEAD 15c1aef9c, re-confirmed @ 8c6e5c0ce; §17.16.4 + §5.14.13)

## RE-CONFIRMED @ 8c6e5c0ce (2026-06-24)
Delta past the 15c1aef9c SHIP = TWO doc/comment-only commits ONLY:
`54f937e0f` (one-word comment fix actor_saga_crash_recovery.rs:149 `testing`→
`saga-witness-test-mint` to match the real gate) + `8c6e5c0ce` (PyO3 scp.rs:247
resume() doc-comment corrected to describe auto-reconnect). ZERO assertions/gates/
required-features/harness changes. All 7 named artifacts re-verified present:
from-persistence order-disc test (18694), bridge both-legs (saga_bridge_bootstrap.rs:206),
reaper-predicate (17031)+err-sibling (16994), 3 compile_fail bodies (5571/5585/5598),
pipeline_wiring gate+12 parser tests, 26 hosting_handshake tests. crash-recovery
required-features=["testing","saga-witness-test-mint"] (Cargo.toml:134) intact;
saga-witness-test-mint = dedicated empty feature (line 32). Verdict SHIP.

Verdict SHIP. The 4 commits since [[saga-bridge-bootstrap-tests]]'s d4f7a7aea snapshot
(7da90cb61, a0db45b0a, 418886d77, 15c1aef9c) are docs/comment-only + the
`restore_all_contexts` pub→pub(crate) seal — no test-logic change. See [[saga-bare-restore-seal-7da90cb61]].

## BOTH prior residual gaps now CLOSED (the headline)
[[saga-restore-replay-recovery-tests]] flagged two gaps at its lines 17-18; this delta closes both:
1. Positive restore-makes-resident-then-replay-delivers path: NOW exercised by
   `restore_on_startup_restores_caller_from_persistence_then_delivers_reversal`
   (supervisor.rs:18694). Despawns caller, `CapturingPersistence::with_restore()` lists it,
   asserts restore RESURRECTS it (`restored.contains(caller_hex)` + `lookup.is_some()`), THEN
   GATE-1 refund=full burst can only land because restore ran first. Genuinely order-discriminating.
2. Err-conservative reaper arm: NOW pinned two ways — direct unit
   `caller_context_deleted_predicate_reaps_only_on_confirmed_absence` (supervisor.rs:17031,
   all three load_context verdicts Ok(None)=reap / Err=keep / Ok(Some)=keep) +
   `xctx_corrupt_evidence_preparing_b_load_error_not_reaped` (ErringLoadPersistence). Both FAIL
   if Err arm inverted to `Err(_)=>true`.

## Tests verified GREEN (all run this pass)
- scp-protocol hosting_handshake: 26/26
- replay_unresolved_sagas 3 compile_fail doctests: 3/3 (fail-to-compile as designed)
- supervisor recovery unit set: 82/82 (incl. all 4 restore_on_startup_* + reaper trio)
- saga_bridge_bootstrap `bridge_restore_entry_runs_restore_and_replay_legs`: 1/1
- pipeline_wiring (gates + 12 extract_fn_body parser-hardening): 74/74
- actor_saga_crash_recovery fail-closed (needs --features testing,saga-witness-test-mint)

## §5.14.13 broadcast hosting-handshake (scp-protocol, NEW 1201-line file) — EXEMPLARY
Crown-jewel signing-protocol coverage, worth replicating:
- Per-field tamper detection (request 9 fields, grant 8 fields) — each field flipped, assert verify err
- Byte-exact preimage KAT: `request_preimage_is_byte_exact_gated` / `grant_preimage_is_byte_exact`
  hand-recompute the SHA-256 preimage INDEPENDENTLY of production code (domain sep + Fixed32/VarBytes/
  U64 field framing) — catches any field-order/encoding drift
- `ucan_absent_differs_from_present_empty`: OptVarBytes absent (SHA-256(0x00) sentinel) ≠ present-empty
  (00 00 00 00) — §9.5.1 optional-field collision guard
- `domain_separators_are_distinct`: cross-checks REQ vs GRANT vs broadcast-envelope vs key-deriv labels
  — cross-protocol-confusion guard
- wrong-signer rejection, serde/jcs round-trips, clamp range tests. No vacuous asserts found.

## extract_fn_body parser-hardening (pipeline_wiring.rs:489-648) — sound/bounded
12 evasion-defeat unit tests, each models a CONCRETE proven evasion: line/block/nested-comment decoy,
block-comment + char-literal + raw-string brace-truncation, escaped-quote char, lifetime-vs-char,
order-preservation through non-code. This is a whitelist-of-spans lexer test, NOT a non-convergent
denylist — passes CLAUDE.md §"non-convergent enforcement".

## RestoredContexts seal intact
`for_test` mint gated behind dedicated `saga-witness-test-mint` feature (NOT `testing`); the two
crash-recovery targets declare `required-features=["testing","saga-witness-test-mint"]`. Production
builds cannot forge the witness. 3 FFI exports (PyO3/UniFFI/napi) each call `restore_on_startup()`
directly, none calls bare `.restore_all_contexts()` — gate matrix accurate.

## No findings. No vacuous/tautological tests. No flakiness (deterministic ids/keys/ts, no sleeps/
wall-clock/random; multi_thread worker_threads=2 only where block_in_place requires it).
