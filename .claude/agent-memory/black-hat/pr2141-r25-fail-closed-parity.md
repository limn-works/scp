---
name: pr2141-r25-fail-closed-parity
description: PR #2141 fix/sdk-coverage-fail-closed-and-parity @a3a22a7fd / @28623a226 black-hat pass — private-symbol exclusion + mapBridgeError anchoring + _coded_bridge_error + getBridge Proxy migration
metadata:
  type: project
---

# PR #2141 r25 pass-1 @28623a226 UPDATE (7 commits past a3a22a7fd): NO BLOCKER, LGTM
The prior CONSIDER (unanchored code regex) is now CLOSED on BOTH bindings:
- TS mapBridgeError (errors.ts:366) `/^\s*\[(SCP-[A-Z]+-\d+)\]/.exec` — position-0 anchored; instanceof ScpError early-return (356) keeps it idempotent; unknown→SCP-UNKNOWN-0000 fail-closed.
- Py _SCP_CODE_RE (errors.py, moved from trust.py) `re.compile(r"^\s*\[(SCP-[A-Z]+-\d+)\]")` used with .search() — `^` w/o MULTILINE = position-0; _coded_bridge_error early-returns ScpError untouched.
- CTX-2076 fold-to-zeroed-record (trust.py:997) now STRICTLY more precise: bridge stamps genuine `[{code}]` at pos0; attacker input lands after prefix → cannot forge CTX-2076 for a different error. Fail-open path unreachable by injection. RESISTANT.
- getBridge Proxy migration of 5 async methods (contextSend/contextMemberCount/contextGovernancePropose/outletInvoke/ucanValidate): wrapBridgeErrors Proxy (bridge.ts:838/851) applies mapBridgeError to sync throws + async rejections IDENTICALLY to removed manual try/catch → behavior-preserving. eventLogQuery correctly EXCLUDED (filterJson vs EventFilter shape mismatch). contextSend Uint8Array shape correct (native.ts:300 Array.from internally). identityRemove/identityExecuteRecovery (sync, 879/945) keep manual mapBridgeError guard.
- Py scp.py 8-method `except Exception → raise _coded_bridge_error(exc)`: always re-raises (never swallows); CancelledError=BaseException escapes; classification by bridge-set class name (unforgeable).
- Coverage-gate `not name.startswith("_")` at 5 extractor sites: fail-closed tightening (shrinks symbol SET → positive existence check only produces MORE errors; can't hide public gap). Parity w/ TS `export` req.

# PR #2141 r25 fail-closed + parity (@a3a22a7fd) black-hat verdict

NO BLOCKER. One CONSIDER (defense-in-depth), one documented footgun.

**Why:** absorbed 156 main commits; surviving delta = coverage-gate private-symbol
exclusion + Python/TS mapBridgeError wiring + trust routes through ucan_evaluate +
getBridge restore for identity lifecycle.
**How to apply:** these 4 surfaces are the review focus for any re-pass.

- Private-symbol exclusion (`not name.startswith("_")` at 5 Python-extractor sites,
  scripts/check-sdk-coverage.py:1145/1154/1170/1200/1211): RESISTANT / fail-closed.
  Gate is a POSITIVE existence check; shrinking the symbol set only produces MORE
  ERRORs. Renaming a public fn to `_foo` makes its matrix `true` cell FAIL (no
  symbol) — cannot hide a gap. Answer to "can `_` prefix hide a public fn?" = NO.
- getBridge restore (scp.ts:811/824/837/850/868 identityRotateKey/AddAgentKey/
  RotateAgentKey/RemoveAgentKey/Migrate): NO new surface. native.ts:248/1641/1659
  bridge.identityRotateKey(handle) ultimately calls handle.rotateKey() (&self on
  handle's OWN retained crypto — identity.rs:424/511/780) — SAME dispatch target as
  old direct handle-method call. Improvement: now wrapped by wrapBridgeErrors proxy
  → typed errors. Identity object is the bearer; foreign-instance passing worked
  before too, no new capability.
- Trust via ucan_evaluate (trust.py:987 `ucan_evaluate(ctx,token,None,subject_did)`
  / scp.ts:2881 `ucanEvaluate(handle,token,subjectDid)`): SOUND. capability=None
  intrinsic mode (step-6 grant-match skipped, documented); presenting_agent_did=
  subject fail-closed (bridge rejects empty, no aud-tautology); read-only (nonce NOT
  consumed → tokens stay replayable, documented never-authorization). AND-combine
  starts all-True only when tokens non-empty, else all-False. No transposition: TS
  public ucanEvaluate(h,tok,presenting,cap?) remaps to native (h,tok,cap,presenting).

## CONSIDER (low): mapBridgeError code regex UNANCHORED — masking vector
errors.ts:363 `/\[([A-Z]+-[A-Z]+-\d+)\]/.exec` and Python trust.py:53
`_SCP_CODE_RE.search` both take LEFTMOST `[SCP-CAT-NNNN]`. For a properly bridge-
prefixed error the genuine code is leftmost → correct. BUT a raw/unprefixed bridge
error whose message merely CONTAINS `[SCP-CTX-2076]` gets classified ContextError
code 2076 → evaluate_trust/evaluateTrust (scp.ts:2938 / trust.py:1020) SWALLOWS it
into a ZEROED behavioral record. Direction is pessimistic (subject looks factless),
diagnostic-not-authorization — so low. Fail-OPEN only for the WARNED misuse of
gating admission on `governanceActionsAgainst===0`-style "clean record." Fix:
anchor to start like mapSagaError already does (errors.ts:404
`/^\s*\[(SCP-SAGA-\d+)\]/`). The inconsistency between the two mappers is the tell.

## Documented footgun (CONSIDER): economy_verify_payment_receipts (scp.py:2170)
invalid-but-reachable receipt carries `ok==True`; callers must inspect
`valid`/`all_valid` not `ok`. Honestly documented in docstring; core behavior
surfaced, not introduced here.
