# check-owned-identity-did.py — rules I/J + cfg-test (chore/2e-gate-followup)

Reviewed commits 8bfabd3..86c50b5 (use-alias ban, rules I/J, cfg-test fix).

## Verified SOUND
- `_return_mentions_cap_by_value`: correct for bare/Option/Result/Box/Vec<Option>/tuple
  (by-value→flag), `&`/`&'a`/`Option<&>`/`&(tuple)` (borrow→pass), word-exact tail
  (OwnedIdentityDidExtra→pass). Box<dyn Fn()->Cap> flagged.
- Rule J scope: `rel.startswith(SUPERVISOR_SUBTREE_REL)` posix-normalized, trailing
  slash → sibling `supervisor_x/` excluded. Correct.
- cfg-test exemption: `#[cfg(test)] mod` (ancestor) AND `#[cfg(test)] fn` (sibling-attr)
  both exempt; `#[cfg(not(test))]` and `#[cfg(any(test,feature))]` correctly FAIL;
  attr does NOT bleed onto following production fn (stops at mod_item boundary).
- exempt_ctor requires rel==required_rel + top-level inherent cap impl + nested_mod
  ancestor None → same-name wrapper in sibling file FAILS; nested-mod re-impl FAILS
  (caught by I AND J).
- Rule I ancestor walk stops at source_file; top-level canonical impl does NOT
  false-fail. Arity: _scan_root returns 10-tuple, threaded through find_declarations/
  _enforce/main/do_self_test consistently. ruff clean. Real scan + 42-mode self-test pass.

## FINDINGS
1. **MEDIUM — negative controls J3/J3b not mechanically enforced + diag discarded on pass.**
   Fixture claims J3/J3b "verified out-of-band: orchestrator greps self-test diagnostics."
   But (a) CI (ci.yml:336/338) only runs `--self-test` + real scan, no grep; (b)
   do_self_test DISCARDS `diag` on the pass path (only printed when `missing` non-empty).
   Simulated breaking the cfg-test exemption → self-test STILL PASSES exit 0, names never
   surface. The exact fix in 86c50b530 can silently regress. Fix: add
   FORBIDDEN_FIXTURE_SUBSTRINGS = {test_only_by_value_mint, test_only_fn_by_value_mint}
   asserted absent-from-diag in do_self_test.
2. **LOW — `_return_mentions_cap_by_value` false-negative on `&dyn Fn()->Cap` /
   `&impl Fn()->Cap`.** Outer `&` marks ALL descendants under_ref, suppressing the
   inner closure-return cap. Borrowing a closure ≠ borrowing the token it yields.
   Box<dyn Fn()->Cap> IS caught; only the ref-wrapped callable slips. Contrived
   (lifetime-hostile) + still gated by pub(super) mint type-system boundary.

## PATTERN
- Self-test that only asserts PRESENT substrings + discards diagnostics on pass gives
  ZERO protection to "negative control" fixtures. The control's whole purpose (catch
  over-flagging regressions) is unrealized. Always check: are negative fixtures
  asserted-absent, and is the diag actually surfaced on the pass path?
