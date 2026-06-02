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

---

## Re-review at HEAD 6135f0a3b (2026-06-01) — ALIGNED

Branch advanced past the 2026-05-03 note. Both prior cleanups ADDRESSED:
- Stale `_note` at bridge-aliases.json: REWRITTEN — now says "RESOLVED 2026-04-26 by PR #1719" and references §7b (no longer contradicts).
- Surface-name divergence: `identity_verify_link_attestation_signature` RENAMED to `identity_verify_link_attestation` (wasm/src/identity.rs:3831), alias normalized in bridge-aliases.json.

§7b now has TWO entries: `identity_create_link_attestation` (RESOLVED 2026-04-26) and `identity_rotate_key` (RESOLVED 2026-05-03 by upstream #1724). Verified §7b rotate claim against actual WASM code: `rotate_active_key_inner` (identity.rs:2136) rotates ONLY `#active`; #1724 (`a97d19c41`) is in merge-base. Artifact-flow RESPECTED — living registry tracking divergence closure, not code reshaping ADR.

New MINOR findings this round:
1. The rewritten `_note` INTRODUCED `PR #1719` into tracked json data (origin/main had no #NNNN in that field). Provenance gate only checks `exemptions[].reason`, not operation `_note` — slips through. Note already cites spec §3.5.2 + §7b, so PR ref is redundant; recommend dropping.
2. §7b + CHANGELOG say inline `// SEMANTIC DIVERGENCE` comments (plural) but only ONE exists (attestation, identity.rs:3566); rotate has none. Defensible (rotate fully aligned, nothing to annotate) but prose overstates.
3. CHANGELOG "22 violations" vs enumerated 1+8+10=19; "25 cells (24 wasm + 1 napi)" conflates 24 wasm placeholder cells with the 1 napi false-exemption removal.
4. `pure-helpers-allowlist.txt` EMPTY (all 22 fixed by real migration, not allowlisted) — strong completeness signal. NAPI `migrate` export confirmed (napi/identity.rs:816); WASM `identity_migrate` confirmed (identity.rs:2448).
