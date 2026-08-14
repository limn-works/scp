---
name: class-s-gate-strip-code-precedence
description: check-class-s-fail-closed.sh strips strings/comments (strip_code) BEFORE attr-peel, so string-awareness in strip_leading_attr is dead code; fixture 60 vacuous
metadata:
  type: project
---

In `scripts/check-class-s-fail-closed.sh`, the awk scanner computes `line = strip_code(raw)` (line ~1126) which removes ALL string literals (ordinary/raw/byte), line comments, and nested block comments from each physical line BEFORE any fn-detection.

**Why:** Every caller of `peel_leading_attrs` / `strip_leading_attr` / `is_attr_prefixed_production` receives the already-stripped `line`/`remainder`, never raw `$0`. So an in-string `]` (e.g. `#[doc = "lone ] bracket"]`) is gone before `strip_leading_attr` runs — it becomes `#[doc =  ]`.

**How to apply:** Any "string-awareness" added to `strip_leading_attr` (the `in_str`/`\"`/`\\` handling, change b on branch chore/fuzz-pin-nightly @ dcf9b14c1) is UNREACHABLE in production. Its guard fixture (#60 `doc_lone_bracket`) is VACUOUS: I removed the entire `in_str` block and the full self-test still PASSED (EXIT=0); the HIT for `doc_lone_bracket_fixture` still fired because `strip_code` already neutralized the in-string `]`. The task's "revert string-aware → 60 fails" non-vacuity claim is FALSE.

By contrast change (a), the fn-anchor qualifier-run regex `((const|unsafe|async)[[:space:]]+|extern([[:space:]]+"[^"]*")?[[:space:]]+)*`, IS correct and non-vacuous: revert → fixture 59 (`pub extern "C" fn`) fails (EXIT=1). Anchor matches pub/pub(path)/const/unsafe/async/extern"ABI" in any order, extracts the right NAME, and rejects `extern crate`, `const X:`, `let extern_thing`, `unsafe impl`, `extern "C" {`.

**Lesson for this gate:** to test a fixture that depends on a literal containing `[`/`]`/`"`, the literal must SURVIVE `strip_code` to reach the attr-peel — but strip_code removes all string content, so such a fixture can never exercise attr-peel string handling. The string-aware branch should either be removed (dead) or the test must target a different layer.
