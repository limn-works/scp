---
name: pr1867-trust-failclosed
description: PR #1867 trust Layer-1 fail-closed defense review (TS + Python parity); att[0]-only as of HEAD 1861c3691
metadata:
  type: project
---

# PR #1867 — fix/sdk-coverage-fail-closed-and-parity, trust Layer-1 fail-closed

## HISTORY: design changed mid-PR
- Earlier HEAD `8909092eb` did **multi-att AND-intersection** (validate every att[i], AND the verdicts).
- Current HEAD `1861c3691` (2026-06-23) **dropped that** for **att[0]-only**. Helper renamed `__extractAllCapabilityUris`→`__extractFirstCapabilityUri` (TS) / `_extract_all_capability_uris`→`_extract_first_capability_uri` (PY); returns `string|null` / `Optional[str]`; `[0]` indexing removed at call sites. Rationale in commit: YAGNI, only att[0] ever consumed; full multi-att needs a single nonce-once bridge op that doesn't exist.

## HEAD 1861c3691 re-review (2026-06-23) — APPROVED, fail-closed sound
- Helper edge cases ALL fail-closed → null/None: <2 JWT parts, non-base64 payload, non-JSON, missing att, empty att (`att[0] if att else None`), att not a list (PY try/except; TS `Array.isArray` guard), att[0] not a dict, missing/non-str/empty `with`. Verified by reading + tests (TS 59 pass, PY 123 pass).
- `evaluateLayer1` (trust.ts:524) null capUri → `return {...ALL_LAYER1_FIELDS_FALSE}` (all 6 false), bridge NOT called. PY mirror (trust.py:826) sets all 6 false + `break`. Optimistic-all-true then narrowed on failure; fail-fast across tokens.
- Closed allowlist intact: TS absorbs ONLY `[SCP-PERM-3001]` (regex), re-throws 3000/3030/other. PY re-raises `[SCP-PERM-3030]` inside UcanError handler; unknown classify → `_PASSED_BEFORE.get(cat, set())`=∅ → all-false DENY.
- **Security IMPROVEMENT vs old multi-att**: old `extractAll` would skip a malformed att[0] and validate against att[1]; new att[0]-only returns null if att[0] is malformed → fail-closed (test trust.test.ts:110 `att:[{can},{with}]` → null). No fail-open path.
- Python root export COMPLETE: `__init__.py` imports `evaluate_trust` from `scp_sdk.trust` (L166) AND `evaluate_trust as bridge_evaluate_trust` from `scp_sdk.bridge` (L51); both in `__all__` (L268 bridge_, L277 plain). Runtime-verified: `scp_sdk.evaluate_trust is scp_sdk.trust.evaluate_trust` and distinct from bridge variant. Mirrors TS `evaluateTrust` (./trust) vs `bridgeEvaluateTrust` (./bridge).
- Doc comments now ACCURATE (prior LOW resolved): helper docstrings + `evaluate_trust` docstring (trust.py:757-768) + evaluateLayer1 docs all say att[0]-only consistently. No stale "all declared"/"array of" language remains.
- ZERO stale refs to `extractAllCapabilityUris`/`_extract_all_capability_uris` anywhere in bindings/ or crates/.
- TS `bun run check` clean; PY parses.

## Pre-existing nit (NOT this PR's diff)
- trust.py:770 docstring contains `#1549` issue-ref → violates no-issue-refs-in-code. Confirmed CONTEXT-only (not added/removed by 1f1ea7cd2..HEAD). Out of scope for this rename PR.
