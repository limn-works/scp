---
name: check-map-gate-tests
description: Coverage gaps and flakiness risks in scripts/tests/test_check_map.py (the MAP.md structural gate self-tests)
metadata:
  type: project
---

# check-map.py gate tests (scripts/tests/test_check_map.py, 26 tests)

Reviewed on branch worktree-codebase-map (new MAP.md codebase-map system).
Contract = `.docs/standards/map.md`; impl = `scripts/check-map.py`.

## Verified impl-vs-contract divergences
- **Section ORDER not enforced.** Standard §"Required sections" says "seven required `##` sections, in this order." `check_sections` builds a `set` and only checks membership — misordered AND duplicate sections PASS. Confirmed empirically. No test either pins the actual (order-agnostic) behavior or the divergence.

## Highest-value untested contract clauses
- **`--status-areas` always-exit-0 under ERROR** (Stop hook depends on it). All status tests run on valid git repos; none exercises the fail-open path (non-git dir / git failure). Confirmed exits 0 in a non-git dir, but unpinned. A regression flipping it to nonzero-on-error is uncaught by tests (hook's `|| return 0` masks it, so low blast radius but the load-bearing clause is unpinned).
- **Frontmatter parse error paths**: never-closed `---`, missing opening `---`, duplicate keys (area/verified/anchors), missing (None) area/verified keys, empty symbol after `#` (`lib.rs#`), empty path before `#` (`#Sym`), quoted-value stripping — all untested. Only wrong-VALUE cases tested.
- **Inline-comment parsing** (`verified: abc # note`) and the `path#symbol`-is-not-a-comment distinction (INLINE_COMMENT_RE) — subtle, bug-prone, zero tests. Confirmed works.
- **owning_area boundary**: sibling shared-prefix (crates/alpha must not own crates/alpha-sibling/), longest-prefix nested, exact-area-as-file — all correct, all untested. Dropping the `+"/"` guard would be uncaught.
- Empty (fileless) area dir still creates obligation; dot-prefixed crates/ subdir skipped; absent fixed-area carries no obligation; CRLF MAP.md; non-utf8 MAP.md (UnicodeDecodeError branch) — untested.
- `--diff` unrelated-history base (`no merge base`, the shallow-CI concern in ci.yml comment) fails CLOSED but shares the CalledProcessError path already tested by bad-base.

## Flakiness risk
GIT_IDENTITY only sets user.name/email. Does NOT neutralize `commit.gpgsign` or `core.hooksPath` — a dev/CI global gpgsign=true or hooksPath=<abs> makes fixture `git commit` sign/hang or run this very repo's pre-commit map hook. Add `-c commit.gpgsign=false -c core.hooksPath=/dev/null` to GIT_IDENTITY.
