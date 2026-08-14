---
name: check-sdk-coverage-failclosed-audited
description: check-sdk-coverage.py fail-closed rewrite (branch fix/sdk-coverage-fail-closed-and-parity) passed the non-convergence/over-engineering BLOCKER audit — it REMOVES a denylist, don't re-litigate.
metadata:
  type: project
---

The `scripts/check-sdk-coverage.py` rewrite on branch `fix/sdk-coverage-fail-closed-and-parity`
(HEAD 06d15bb6a) was audited for the non-convergent-enforcement BLOCKER and is CLEAN.

**Why it's the good shape, not a BLOCKER:** the rewrite REMOVES the non-convergent
matching (suffix/substring + bare-op-name candidates that let ~23 fabricated op names pass
via collision) and replaces it with (a) fail-closed: a `true` cell with no verified symbol
and no `coverage_exemptions` reason → ERROR exit 1 (was WARN/pass); (b) exact matching against
the `ALIASES` positive whitelist only; (c) an all-exempted guard so exemptions can't blanket an
op; (d) negative self-tests in `test_check_sdk_coverage.py`, one per guard. This is the sanctioned
bounded/whitelist shape (see [[sanctioned-bounded-tripwire-shape]], [[project_codebase_map_gate_audited_clean]]).
ALIASES grows with real operations, not bypass spellings — convergent by construction.

**How to apply:** do not flag this gate as over-engineered or non-convergent. The one
documented weakness (note, not blocker): several ALIASES cells map to a generic entry point
or class name (all six Governance `execute_*` → `execute_governance_action`; Lifecycle
`scp_new`/`with_storage_sqlite`/`shutdown_timeout` satisfiable by the `SCP` class / bare
`shutdown`), so those cells verify "a generic symbol exists," not the specific capability —
consciously scoped away by the new docstring ("name-existence only; semantic correctness is
human-review").

**Sibling parity code:** `trust.ts`/`trust.py` `evaluateTrust` classifies UCAN failures by
string-prefix over the Rust `UcanError` Display text (TOKEN_PARSE_PREFIXES etc.). This is the
same forced-but-CONVERGENT pattern as [[project_pr6c_saga_sdk_wrapper_convergence]] — closed set
fixed by the Rust enum, required for cross-SDK parity, NOT a BLOCKER. Latent fragility (a Display
tweak silently reclassifies to "unknown" → all-false verdict); ideal fix is the bridge surfacing
a structured error-stage code. Layers 3-4 of TrustEvaluation return empty and 3 behavioral
fields hardcode 0 — honest parity-surface ("not computed, not fabricated"), a completionist
concern not a simplifier one.

**scp.ts mapBridgeError wrapping (r25, HEAD 22ac39777):** commit d34097078 wraps ~200 methods
each in an identical `try { ... } catch (err) { throw mapBridgeError(err); }` (203 sites, only 2
deviate: module-level addon load `catch (cause)` + a custody callback swallowing to `[]`). This is
the one live REPETITION finding — collapsible into a private `#guard`/`#guardSync` HOF. NOT a
BLOCKER (uniform/greppable/convergent), a judgment-call DRY reduction. No dead code from the
att-intersection revert history (`__extractCapabilityUri` fully removed; gate extractors dispatched
via registry dict; no `_to_pascal`/`py_prefixed` leftover). Minor: test-guard.ts `isTestEnvironment()`
is consumed only by its own test — `assertTestEnvironment` reads `_IS_TEST_ENVIRONMENT` directly.

**r25 tail (HEAD 31c78ddeb, +2 commits over 22ac39777):** both CLEAN.
(1) `__decodeBase64UrlToUtf8` (trust.ts, ~12 lines) — minimal correct cross-env base64url
decoder replacing Node-only `Buffer.from(...,"base64url")`; right decomposition, not over-engineered.
(2) 34-entry direction-pinning table in trust.test.ts (`__classifyUcanError` cases) —
appropriately sized safety net for the string-classification fragility, NOT over-specified.
INFO only: its docstring overclaims ("Rust error-string changes caught immediately") — the
expected strings are hand-copied, not imported from Rust, so it pins the TS classifier's
stability, not actual cross-language Rust→category drift.
**The `_PASSED_BEFORE` + `__classifyUcanError` apparatus (TS+Python, ~250-400 lines w/ tests):**
the tables themselves are the SIMPLEST expression of their approach (table-driven, convergent,
bounded by the closed UcanError enum) — NOT a simplifier finding to rewrite. The HIGH-value
architectural finding is that the whole reconstruction only exists because the bridge's
`ucanValidate` collapses a structured pipeline result to a lossy `[SCP-PERM-3001]` string;
surfacing a structured stage code across the 4 bridges would DELETE the apparatus in both SDKs.
Convergent, already documented as ideal-fix — NOT the non-convergent stop-PR BLOCKER class.
mapBridgeError 203-site wrap: no gate greps `throw mapBridgeError` (confirmed r25) so the
`#guard`/`#guardSync` HOF collapse is safe — still the one live judgment-call DRY reduction.

**r25 CONVERGED scp.ts error-mapping (HEAD 13aecbbbb):** the earlier 203-site
blanket `try/catch → mapBridgeError` wrap was SCALED BACK to ~8 surgical sites
(identityRemove, identityExecuteRecovery, contextSend, contextMemberCount,
contextGovernancePropose, +3). Architectural finding (CONSIDER, not BLOCKER):
those 8 exist only because `this.#native.*` dispatch BYPASSES the existing
`wrapBridgeErrors` Proxy (internal/bridge.ts:822) — the ~172 OTHER `#native`
methods map no errors at all (silent inconsistency). Clean consolidation: wrap
`#native` at construction in the same generic error Proxy (extract
wrapBridgeErrors' handler into `wrapErrors<T>(obj:T):T`); deletes all 8 blocks +
gives uniform typed-error mapping. Safe re handle-affinity (Proxy returns handles
verbatim, never deep-proxies — already documented). Behavior change for 172 →
needs sign-off, hence CONSIDER. This is UNDER-abstraction, not over-engineering.
The 5 identity-lifecycle methods use `getBridge(this)` and ALREADY get Proxy
mapping for free. Lesson ucan-validate restructure = sound (principles front-
loaded, history quarantined under "Historical"); not a split candidate. 5
`startswith("_")` sites = convergent surface-shrink, optional `_is_public()`
helper. NO BLOCKER anywhere.

**r25 post-merge FINAL (HEAD 3de060e97, branch merged origin/main 156 commits):** surviving
contributions to check-sdk-coverage.py = (a) Python extractor now drops `_`-prefixed
(private/dunder) symbols in all 5 add-sites for parity with the TS `export`-required extractor —
inline `not name.startswith("_")` guard, tested by 3 negative tests (function/class/method), and
NO ALIASES target begins with `_` so it breaks nothing while shrinking the gate's satisfiable
surface (a private helper can no longer satisfy a matrix cell); (b) one-line Bridge/register
matrix fix adding `"typescript": ["bridgeRegister"]`. Both CLEAN, convergent, in-shape. Only
cosmetic nit: stray triple-blank-line ~L1218 (styler, not simplifier). Verdict unchanged: NO
COMPLEXITY ISSUES.
