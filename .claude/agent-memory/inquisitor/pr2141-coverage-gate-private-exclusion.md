---
name: pr2141-coverage-gate-private-exclusion
description: PR#2141 surviving contribution post-merge — private-symbol exclusion in SDK coverage gate (SOUND), Bridge/register ts alias (REDUNDANT), doc provenance fixes (CORRECT)
metadata:
  type: project
---

# PR #2141 `fix/sdk-coverage-fail-closed-and-parity` — surviving unique contribution (HEAD 3de060e97)

After merging origin/main (ADR-055 WASM removal, ADR-059 typed trust), PR's unique surviving
diff reduced to: (1) private-symbol exclusion in `scripts/check-sdk-coverage.py` Python extractor,
(2) Bridge/register ALIASES ts entry, (3) doc/provenance corrections.

**Why:** interrogated whether the two gate/matrix decisions survive on merit or inertia.
**How to apply:** if this PR is re-reviewed or the gate is touched again, these verdicts hold.

## Verdicts

- **Private-symbol exclusion (`if name and not name.startswith("_")` across `_extract_python_*`): SOUND.**
  Gate is name-existence only; the ONLY way a private `_foo` could satisfy a `true` matrix cell is
  an explicit ALIASES entry listing `_foo` (auto-candidates are never underscore — domain_snake/
  domain_camel/`Domain.op`). VERIFIED zero underscore-prefixed aliases exist today, so exclusion
  changes NO current cell. It is bounded/closed-by-construction (public=non-`_`, Python convention),
  non-redundant (nothing else enforces public-ness of Python alias targets), proportionate. Closes a
  REAL future footgun: trust.py has private heuristic helpers (`_classify_ucan_error`,
  `_extract_first_capability_uri`) — aliasing a cell to one would have falsely certified private code
  as public SDK surface. Full gate + 23 self-tests pass green.

- **Bridge/register `"typescript": ["bridgeRegister"]` alias: REDUNDANT (SHOULD-FIX minor / cargo-cult).**
  Matrix cell typescript=true was ALREADY true on origin/main (unchanged by PR). Only real change is
  the ts alias. VERIFIED inert: `_to_camel("bridge_register")` = "bridgeRegister" is an auto-generated
  domain_camel candidate that already matches the real `export async function bridgeRegister` in
  bridge.ts. `_check_operation_in_sdk` returns True with OR without the ts alias. Sibling Bridge/
  evaluate_trust correctly relies on the candidate (no ts alias) — so register's ts alias is
  inconsistent + provides zero marginal robustness (both alias and candidate key off the same symbol
  name; rename breaks both identically). Python alias `["register"]` IS load-bearing (bare `def register`
  in bridge.py, no candidate matches). Fix: drop the ts alias line for consistency + CLAUDE.md
  "redundancy is negative value".

- **Doc provenance fix §3.2.1 → §9.12/ADR-003 §4b (bridge.rs:2437/2494, identity.py:113): CORRECT.**
  §3.2.1 = "Key Custody Migration Protocol" = custody move WITHOUT DID change, no DidRotationEvent.
  DID-changing Identity Key migration that emits the rotation-event-to-active-contexts is governed by
  ADR-003 §4b + §9.12 (03-identity.md:28 cross-refs this). Old cite was phantom provenance; fix is sound.
  sketch.md (+nonceValid/timeBoundsValid) and sdk-common.md (UcanPermissionError rename) are consistent
  post-merge cleanups.
