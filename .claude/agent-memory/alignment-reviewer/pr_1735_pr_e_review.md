---
name: PR #1735 PR-E Enforcement Hardening Review (2026-05-03)
description: Alignment review of PR-E (phantom-alias regex, empty exemption arrays, ADR-048 §1 mechanization, §7b divergence registry). Verdict ALIGNED with two cleanup items.
type: project
---

PR #1735 / branch `chore/enforcement-hardening-1543` reviewed against `/Users/alec/.claude/plans/cozy-fluttering-rose.md` PR-E section (lines 1179-1291).

**Verdict:** ALIGNED with two non-blocking cleanups.

Why: All 4 plan items fulfilled at depth. Plan-deviating choices defensible: regex refinement dropped literal `pub` requirement (PyO3 `#[pyfunction] fn` is valid without `pub`) but replaced with FFI-decoration-aware walk which covers the same threat. 22 incidental refactors of pre-existing §1 violations honor "completeness is the baseline" over allowlisting.

How to apply: For future cross-bridge enforcement-infra PRs, expect plan-vs-implementation refinements to be common — verify the *intent* is preserved, not the literal text. Check the bridge-aliases.json `_note` annotations vs the new §7b registry for staleness; PR-E added §7b without retiring the `_note` for `identity_create_link_attestation` (line 2833) which now directly contradicts §7b. Also check that any bridge-aliases.json operation where WASM uses a *different fn name* than native (e.g. `identity_verify_link_attestation_signature` vs `identity_verify_link_attestation`) is recorded in §7b or normalized — the registry covers semantic divergence but should also cover surface-name divergence so agents grepping WASM source can find the matching native op.

Notable patterns surfaced:
- `crates/scp-ffi/common/src/` is excluded from §1 gate (`ffi_conformance.rs:2276`). Trait-impl skip at line 2481 covers common's usual contents but an inherent `impl` with `#[uniffi::export]` placed in common would slip through. Watch for this if future PRs move FFI-decorated code there.
- Hook fix (anchor repo root, `pretooluse-enforcement-files.sh:85`) was forced by #27's fixture tree — defensible scope creep that sharpens, not weakens, protection.
- 22 pure-helper free-fn migrations (PyO3 8 + UniFFI 10 + minor): net -209 lines.

Files of note (absolute paths):
- `/Users/alec/Developer/limn/scp/.claude/worktrees/1543-pr-e-enforcement-hardening/crates/scp-testing/tests/integration/ffi_conformance.rs:2204-2546` (pure-helpers gate + detector tests)
- `/Users/alec/Developer/limn/scp/.claude/worktrees/1543-pr-e-enforcement-hardening/scripts/check-bridge-symmetry.sh:407-535` (decoration-aware scanner; mirrors `FfiFnCollector::impl_decorated_stack`)
- `/Users/alec/Developer/limn/scp/.claude/worktrees/1543-pr-e-enforcement-hardening/scripts/bridge-aliases.json:2833` (stale `_note` to remove)
- `/Users/alec/Developer/limn/scp/.claude/worktrees/1543-pr-e-enforcement-hardening/.docs/adrs/ADR-048-scp-multi-instance.md:217-227` (§7b registry)
