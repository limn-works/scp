---
name: pr2141-trust-prefix-parity-sync
description: PR#2141 R25-B3 — UCAN trust prefix parity + pipeline-absorbed-code sync tests; source-text codes:: coupling gap + drift-chain design
metadata:
  type: project
---

# PR #2141 (fix/sdk-coverage-fail-closed-and-parity) — Round-2 Batch-3 test review

Branch worktree `/tmp/scp-review-r25`. Verdict: REVISE (no blockers).

## The drift chain (SOUND design worth replicating)
Cross-language UCAN error-prefix drift is closed by a CHAIN, not one test:
- Rust `#[error("…")]` ↔ Python prefixes: pre-existing `test_ucan_conformance.py`
  `test_each_rust_validation_prefix_covered` + `test_ucan_error_variant_count`
  (variant-count tripwire forces update when a UcanError variant is added).
- Python ↔ TS prefixes: NEW `bindings/python/tests/test_ts_prefix_parity.py`
  (parses `trust.ts` `const NAME: readonly string[] = […]` via regex, set-compares to
  imported Python `_*_PREFIXES` tuples). Transitively couples TS→Rust Display.
- TS direction table (`trust.test.ts`, 34 entries) HONESTLY disclaims it only guards
  classifier internal stability, points to conformance suite for drift. Good non-overclaim.

## KEY GAP (SHOULD-FIX) — `codes::(\w+)` couples to SPELLING not runtime returns
Both `TestPipelineAbsorbedCodesSync::test_every_emitted_code_is_absorbed` (py) and TS
`ucan_errors.rs pipeline code sync` extract emitted codes by regex `codes::IDENT` over
`crates/scp-ffi/common/src/ucan_errors.rs` source text. A future arm returning the code as
a RAW LITERAL (`=> "SCP-PERM-3008"`) or via helper/alias emits an un-absorbed code at
runtime (evaluate_trust/validateOneCapUri re-raise) while BOTH tests stay GREEN =
silent-pass-while-wrong. Exhaustive `match` compile-error guards VARIANT ADDITION only,
not CODE-VALUE coupling. Sound fix: Rust-side test that INVOKES ucan_error_code over every
variant and asserts collected real return strings ⊆ absorbed set (bypass-proof). Existing
`every_mapped_variant_currently_routes_to_perm_3001` spot-checks 6 variants only.
LESSON: a test that scrapes source text for a call-spelling can't see a value produced by a
different spelling — couple to runtime returns when the property is about returned values.

## Other findings
- SHOULD-FIX: TS sync test `expect(notAbsorbed).toEqual([])` throws first → the informative
  `if(len>0) throw new Error(...)` guidance block below is DEAD CODE (bare diff on failure).
- SHOULD-FIX(minor): `test_invalid_context_id_*` only feed `ctx\n`; boundary inputs (empty,
  len256 accept, len257 reject, ctx\x00, non-ASCII) handled by `fullmatch` but unpinned.
  `ctx\n` IS highest-value (the `$`-vs-fullmatch regression). Parametrize.
- POSITIVE: mock wiring non-vacuous — `hasattr(mock,"_mock_name")` truthy for MagicMock so
  trust.py sets `instance=mock_bridge`; `ucan_validate/event_log_query.assert_not_called()`
  target the real call site.
- CROSS-1/CROSS-2 CORRECT: both REVOCATION_PREFIXES = ["token revoked:"] only, so
  "revocation unauthorized:/failed:" → unknown (fail-closed). PERM_3007/3008 already exist
  as consts in error_codes.rs (pre-defined, held back per ucan_errors.rs fn doc).
- Path resolution correct: py `parents[3]`, ts `resolve(dirname(url),"../../..")` = repo root;
  guarded by loud `exists()` tests. Three-layer monorepo filesystem coupling (py unit test
  reads Rust + TS source) — fail-loud, acceptable.
- TS array-extraction regex `[^\]]*` body safe today (no `]` in literals, no quoted strings
  in in-array comments) but brittle to those + to a differently-annotated new *PREFIXES array
  (silently missed by test_no_extra_ts_prefix_arrays_unguarded).
