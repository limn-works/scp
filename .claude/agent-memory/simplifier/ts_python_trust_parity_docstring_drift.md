---
name: ts-python-trust-parity-docstring-drift
description: TS and Python evaluate_trust are kept in lockstep parity; when behavior changes in one, the OTHER's docstring is the thing most likely to be left stale
metadata:
  type: project
---

`evaluateTrust` (`bindings/typescript/src/trust.ts`) and `evaluate_trust` (`bindings/python/scp_sdk/trust.py`) are intentional mirror twins (same four-layer model, same per-URI AND-intersection, same fail-fast). The per-SDK error-absorption idiom legitimately differs: TS uses a closed regex allowlist absorbing only `[SCP-PERM-3001]` outside the catch; Python re-raises `[SCP-PERM-3030]` inside `except bridge.UcanError` because exception-type dispatch already matched the class. That divergence is correct per-SDK idiom, not drift.

**Why:** In PR #1867 the multi-att (validate every `att[i].with`, not just `att[0]`) change was made to BOTH, but Python's `evaluate_trust` DOCSTRING was left describing the old att[0]-only behavior and claiming "Multi-att... not yet implemented" — directly contradicting its own updated body. TS docstring was updated; Python was missed. Docstrings are the parity blind spot.

**How to apply:** When reviewing a behavior change to one of these two functions, ALWAYS diff the other's docstring too, not just its code. A behavior change that updates code in both but prose in only one is the recurring failure mode here. Also: `trust.py` carries a literal `#1549` issue ref in a docstring (violates no-issue-refs-in-code) — flag opportunistically if editing that file.

Related: [[trust-ucan-error-classifier-not-a-gate]]
