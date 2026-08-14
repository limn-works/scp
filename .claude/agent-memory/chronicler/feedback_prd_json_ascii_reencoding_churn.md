---
name: prd-json-ascii-reencoding-churn
description: Adding a PRD story via Python json.dump re-escapes the whole file (ensure_ascii=True default) — 1400-line churn hazard; main.json uses raw unicode
metadata:
  type: feedback
---

When a PRD story is added to `.docs/prds/main.json` by loading + re-dumping with Python's `json.dump`/`json.dumps`, the **default `ensure_ascii=True`** rewrites every non-ASCII char in the file to `\uXXXX` escapes (`—`→`—`, `§`→`§`). `main.json` on `main` stores these characters **raw** (≈525 em-dashes, 0 escapes). Result: a 1-story addition becomes a ~1400-line insert/delete diff that pollutes `git blame` across ~350 unrelated stories and degrades on-disk readability.

**Why:** the PRD is the system of record; atomic-commit discipline (CLAUDE.md git rules) says never bundle unrelated churn. Seen concretely in PR #2141 commit 09b76c856 ("add SCP-302") — 754 insertions / 702 deletions where only ~60 lines were the real change. `scripts/validate-prd.py` still passes (semantically identical JSON), so CI does NOT catch it.

**How to apply:** When reviewing any PRD change, run `git diff --stat` — if a single-story edit shows hundreds of changed lines, suspect ASCII re-encoding. Confirm with `grep -c '\\u2014'` on HEAD vs `git show origin/main:<file> | grep -c '—'`. Flag as SHOULD-FIX; the fix is to re-serialize with `ensure_ascii=False` (or hand-edit) so the diff is only the intended story. This is a doc-hygiene defect, not a correctness one.
