# SDK coverage fail-closed + trust/test-guard hardening (branch fix/sdk-coverage-fail-closed-and-parity @ e807b3f9c) — APPROVED, no new exploitable defect

Re-audit of the same branch family as sdk_coverage_failclosed_and_perm3030_r18.md, now at HEAD e807b3f9c. Three attacker goals probed; all resist.

## GOAL 1: bypass coverage gate to ship false `true` (check-sdk-coverage.py)
- Substring/suffix matching REMOVED (`_check_operation_in_sdk` step 2 only checks domain_snake/domain_camel/`Domain.op`/`Domain.camel`). PROVEN via direct calls: `sendMessageToServer` does NOT satisfy `send_message_xyz`; bare `migrate` does NOT satisfy `Identity/migrate`. The old ~23-fabricated-op suffix-collision hole is closed.
- Residual bypasses are AUTHORING-TRUST ONLY (matrix-edit == gate-edit), all documented in docstring l.7-8/80-82:
  - ALIASES name-collision: any symbol literally named `receive` satisfies `Messaging/subscribe` python alias `["receive","context_receive"]`. Name-existence != semantic-correctness. To weaponize needs editing ALIASES (in the HUMAN-APPROVAL-PROTECTED set: CLAUDE.md l.110-111 lists both check-sdk-coverage.py AND sdk-capability-matrix.json).
  - all-null op (all 4 sdks=null) passes silently — PROVEN exit 0. NOT a false-positive vector: null = "claimed nowhere", opposite of faking a `true`. Authoring-completeness gap only.
- missing-key check (any expected sdk key absent → error) is a real tightening. Gate exit 0 on real tree, 1 coverage-exempt (Kotlin UniFFI generated, not git-tracked). 11 unit tests non-vacuous (drive real gate via subprocess + synthetic SDK trees; bare-name-rejection + alias tests are the load-bearing ones).

## GOAL 2: forge trust verdict (evaluateTrust → false-positive CapabilityValidation)
- SOUND FLOOR (both SDKs): `_PASSED_BEFORE`/`__PASSED_BEFORE` max set = `expiry` = 5 fields; `time_bounds_valid`/`timeBoundsValid` is in NO set. A thrown/forged error can elevate at most 5/6 fields; FULL all-true requires every token to actually pass ucan_validate with NO exception. Error-message-prefix classification only refines which EARLIER stages passed — can never synthesize a complete pass from a failure.
- Only UcanError (py) / `[SCP-PERM-\d+]` msg (ts) is caught; any other error propagates (no swallow). PERM-3030 (handle-affinity caller-misuse) now RE-RAISES in both SDKs (py new this diff, ts already) — prevents absorbing a programming mistake into a false all-False verdict.
- py removed hardcoded `contexts_participated=1` (was fabricating); now defaults 0. Correctness improvement.
- discovery.py discover_contexts is a pure typed wrapper over bridge.context_discover; trust_level/resolution_path are Rust-supplied, not fabricated in py. No surface.

## GOAL 3: flip test-env guard in prod to enable native-bridge swap
- Guard MIGRATED `assertTestHookAllowed` (FAIL-OPEN: throws ONLY when NODE_ENV==="production"; dev/staging/unset all passed) → `assertTestEnvironment` (FAIL-CLOSED: throws UNLESS NODE_ENV test|development OR BUN_TEST non-empty). Strictly NARROWER — now blocks staging+unset the old one permitted. No regression possible (new accept set ⊂ old accept set).
- Protects exactly 2 mutators: `__constructScpWithNativeForTests` (NATIVE_OVERRIDE swap) + `__setBridgeForTests` (bridge WeakMap swap). Both fail-closed.
- `_IS_TEST_ENVIRONMENT` FROZEN at module load from `_ENV_AT_LOAD` (captured once). PROVEN: runtime `process.env.NODE_ENV="test"` after import does NOT flip it (before===after). No post-import elevation.
- Object.hasOwn defeats prototype-pollution (Object.prototype.NODE_ENV="test" → false, tested). Side-effecting own-prop getter reads exactly once → no TOCTOU.
- Primary boundary remains the bundle: NATIVE_OVERRIDE = module-private unique Symbol() (can't be injected via new SCP(opts)); helpers not in index.ts; package.json exports map = only `.`→dist/index.js (deep-import of dist/scp.js blocked by Node exports enforcement). Env guard = DiD for non-bundled/dev-server.
- `development` accept-value: enabling swap under NODE_ENV=development needs attacker-in-process + deep-import (exports-blocked) + dev env — and the OLD guard ALSO allowed dev. Net improvement, not a new hole.

Tests green: 11 py gate, 60 ts (test-guard+trust). Gate exit 0.
